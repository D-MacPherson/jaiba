//! Fixed R4 cooperative lock wire protocol. The controller remains responsible
//! for exact Nix-store executable identity and pidfd/start-time verification.
use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use crate::app::{App, Screen};
use crate::private_fs::Dir;
use serde::{Deserialize, Serialize};

const VAULT_UID: u32 = 1503;
const RUNTIME: &str = "/run/user/1503";
const MAX_FILE: u64 = 4096;

fn nonce(bytes: &[u8]) -> io::Result<String> {
    if bytes.len() != 32
        || !bytes
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Err(io::Error::other("invalid lock request nonce"));
    }
    Ok(String::from_utf8(bytes.to_vec()).expect("validated ASCII"))
}
fn start_time() -> io::Result<String> {
    let raw = fs::read_to_string("/proc/self/stat")?;
    let (_, tail) = raw
        .rsplit_once(')')
        .ok_or_else(|| io::Error::other("invalid process stat"))?;
    let start = tail
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| io::Error::other("missing process start time"))?;
    if start.is_empty() || !start.bytes().all(|b| b.is_ascii_digit()) {
        return Err(io::Error::other("invalid process start time"));
    }
    Ok(start.into())
}
fn credentials(status: &str, runtime: Option<&OsStr>) -> io::Result<bool> {
    let row = |key: &str| -> io::Result<Vec<u32>> {
        let rows: Vec<_> = status
            .lines()
            .filter_map(|line| line.strip_prefix(key))
            .collect();
        if rows.len() != 1 {
            return Err(io::Error::other("ambiguous process credentials"));
        }
        rows[0]
            .split_whitespace()
            .map(|v| v.parse().map_err(io::Error::other))
            .collect()
    };
    let uids = row("Uid:")?;
    let gids = row("Gid:")?;
    if uids.len() != 4 || gids.len() != 4 {
        return Err(io::Error::other("incomplete process credentials"));
    }
    if !uids.contains(&VAULT_UID) {
        return Ok(false);
    }
    if uids != [VAULT_UID; 4] || gids != [VAULT_UID; 4] || runtime != Some(OsStr::new(RUNTIME)) {
        return Err(io::Error::other(
            "cooperative locking requires fixed vault credentials and runtime",
        ));
    }
    Ok(true)
}

#[derive(Serialize)]
struct Identity {
    version: u8,
    frontend: &'static str,
    pid: u32,
    start: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ack {
    nonce: String,
    locked: bool,
    draft_persisted: bool,
}

pub struct Registration {
    dir: Dir,
    registration: OsString,
    registration_file: File,
    request: OsString,
    ack: OsString,
    ack_file: Option<File>,
    seen: HashSet<String>,
    flag: Arc<AtomicBool>,
    signal: signal_hook::SigId,
    _cancellation: challenge_response::operation::Cancellation,
}

impl Registration {
    pub fn start() -> io::Result<Option<Self>> {
        if !credentials(
            &fs::read_to_string("/proc/self/status")?,
            std::env::var_os("XDG_RUNTIME_DIR").as_deref(),
        )? {
            return Ok(None);
        }
        Self::register(Path::new(RUNTIME), VAULT_UID).map(Some)
    }
    #[cfg(test)]
    pub(crate) fn for_test(root: &Path) -> io::Result<Self> {
        Self::register(root, crate::private_fs::uid())
    }

    fn register(root: &Path, uid: u32) -> io::Result<Self> {
        let runtime = Dir::open(root, uid)?;
        let dir = runtime.child(OsStr::new("vault-tui-lock"), true)?;
        let pid = std::process::id();
        let registration = OsString::from(format!("jaiba.{pid}.json"));
        let request = OsString::from(format!("jaiba.{pid}.request"));
        let ack = OsString::from(format!("jaiba.{pid}.ack"));
        let mut seen = HashSet::new();
        // Never interpret inherited request/ack content as a new request. Unsafe
        // or malformed pre-existing files reject startup; safe nonces are burned.
        match dir.read(&request, MAX_FILE) {
            Ok(data) => {
                seen.insert(nonce(&data)?);
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e),
        }
        match dir.read(&ack, MAX_FILE) {
            Ok(data) => {
                let old: Ack = serde_json::from_slice(&data).map_err(io::Error::other)?;
                seen.insert(nonce(old.nonce.as_bytes())?);
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e),
        }
        let identity = Identity {
            version: 1,
            frontend: "jaiba",
            pid,
            start: start_time()?,
        };
        let flag = Arc::new(AtomicBool::new(false));
        let signal = signal_hook::flag::register(signal_hook::consts::SIGUSR2, Arc::clone(&flag))?;
        let result = (|| {
            let mut file = dir.create(&registration)?;
            let meta = file.metadata()?;
            let written = (|| {
                serde_json::to_writer(&mut file, &identity).map_err(io::Error::other)?;
                file.sync_all()?;
                dir.sync()
            })();
            if let Err(e) = written {
                let _ = dir.remove_owned(&registration, &meta);
                return Err(e);
            }
            Ok(file)
        })();
        let registration_file = match result {
            Ok(meta) => meta,
            Err(e) => {
                signal_hook::low_level::unregister(signal);
                return Err(e);
            }
        };
        Ok(Self {
            dir,
            registration,
            registration_file,
            request,
            ack,
            ack_file: None,
            seen,
            flag: Arc::clone(&flag),
            signal,
            _cancellation: challenge_response::operation::Cancellation::install(Arc::clone(&flag)),
        })
    }

    /// The signal handler does only an atomic store. All filesystem I/O, KDBX
    /// encryption and UI transitions happen here, on the normal event loop.
    pub fn pending(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    pub fn process(&mut self, app: &mut App) -> io::Result<()> {
        if !self.flag.swap(false, Ordering::SeqCst) {
            return Ok(());
        }
        let value = nonce(&self.dir.read(&self.request, MAX_FILE)?)?;
        if !self.seen.insert(value.clone()) {
            return Ok(());
        }
        // A valid request revokes access first. New hardware-dependent draft
        // persistence cannot wait for more touches under the controller deadline.
        let durable = if app.database_yubikey().is_some() {
            let _cancel = challenge_response::operation::Cancellation::install(Arc::new(
                AtomicBool::new(true),
            ));
            app.lock_cooperatively()
        } else {
            app.lock_cooperatively()
        };
        #[cfg(test)]
        test_fault::ack_checkpoint(0);
        let ack = Ack {
            nonce: value,
            locked: app.screen == Screen::Login,
            draft_persisted: durable,
        };
        let bytes = serde_json::to_vec(&ack).map_err(io::Error::other)?;
        #[cfg(test)]
        let verifications = std::cell::Cell::new(0);
        self.dir
            .atomic_key_free(
                &self.ack,
                |file| Ok(file.write_all(&bytes)?),
                |file| {
                    let mut read = Vec::new();
                    file.take(MAX_FILE + 1).read_to_end(&mut read)?;
                    anyhow::ensure!(read == bytes, "lock acknowledgement verification failed");
                    #[cfg(test)]
                    {
                        verifications.set(verifications.get() + 1);
                        test_fault::ack_checkpoint(verifications.get());
                    }
                    Ok(())
                },
                &mut self.ack_file,
            )
            .map_err(io::Error::other)?;
        Ok(())
    }
}
impl Drop for Registration {
    fn drop(&mut self) {
        if let Ok(meta) = self.registration_file.metadata() {
            let _ = self.dir.remove_owned(&self.registration, &meta);
        }
        if let Some(file) = &self.ack_file {
            if let Ok(meta) = file.metadata() {
                let _ = self.dir.remove_owned(&self.ack, &meta);
            }
        }
        signal_hook::low_level::unregister(self.signal);
    }
}

#[cfg(test)]
mod test_fault {
    use super::*;
    thread_local! {
        pub static DUPLICATE: std::cell::RefCell<Option<(usize, Arc<AtomicBool>)>> = const { std::cell::RefCell::new(None) };
    }
    pub fn ack_checkpoint(phase: usize) {
        DUPLICATE.with(|hook| {
            let mut hook = hook.borrow_mut();
            if hook.as_ref().is_some_and(|(at, _)| *at == phase) {
                let (_, flag) = hook.take().unwrap();
                // Exactly the signal handler's action, without signalling unrelated
                // registrations concurrently alive in other unit-test threads.
                flag.store(true, Ordering::SeqCst);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{App, Screen};
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    fn wait_for(mut check: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(12);
        while !check() {
            assert!(Instant::now() < deadline, "synthetic child timed out");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    struct TestRoot(std::path::PathBuf);
    impl TestRoot {
        fn new() -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "jaiba-registry-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
        fn path(&self, suffix: &str) -> std::path::PathBuf {
            self.0
                .join("vault-tui-lock")
                .join(format!("jaiba.{}.{suffix}", std::process::id()))
        }
        fn private_write(&self, suffix: &str, bytes: &[u8]) {
            let path = self.path(suffix);
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn production_admission_requires_fixed_full_credentials_and_runtime() {
        let status = "Uid: 1503 1503 1503 1503\nGid: 1503 1503 1503 1503\n";
        assert!(credentials(status, Some(OsStr::new(RUNTIME))).unwrap());
        assert!(credentials(status, Some(OsStr::new("/different"))).is_err());
        assert!(credentials(status, None).is_err());
        assert!(
            credentials(
                &status.replace("Uid: 1503", "Uid: 0"),
                Some(OsStr::new(RUNTIME))
            )
            .is_err()
        );
        assert!(
            credentials(
                &status.replace("Gid: 1503", "Gid: 0"),
                Some(OsStr::new(RUNTIME))
            )
            .is_err()
        );
        assert!(
            !credentials("Uid: 1000 1000 1000 1000\nGid: 1000 1000 1000 1000\n", None).unwrap()
        );
        assert!(credentials("Uid: 1503 1503\nGid: 1503 1503 1503 1503\n", None).is_err());
        assert!(credentials(&(status.to_owned() + status), Some(OsStr::new(RUNTIME))).is_err());
    }

    #[test]
    fn stale_startup_and_replayed_nonces_cannot_relock_recovered_editor() {
        let root = TestRoot::new();
        fs::create_dir(root.0.join("vault-tui-lock")).unwrap();
        fs::set_permissions(
            root.0.join("vault-tui-lock"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let old = b"00000000000000000000000000000000";
        root.private_write("request", old);
        let mut reg = Registration::for_test(&root.0).unwrap();
        let mut app = App::for_test(None);
        reg.flag.store(true, Ordering::SeqCst);
        reg.process(&mut app).unwrap();
        assert_eq!(app.screen, Screen::Index);
        assert!(!root.path("ack").exists());
        let fresh = b"abcdef0123456789abcdef0123456789";
        root.private_write("request", fresh);
        reg.flag.store(true, Ordering::SeqCst);
        reg.process(&mut app).unwrap();
        assert_eq!(app.screen, Screen::Login);
        app.screen = Screen::Edit; // models authenticated recovery
        reg.flag.store(true, Ordering::SeqCst);
        reg.process(&mut app).unwrap();
        assert_eq!(app.screen, Screen::Edit);
        root.private_write("request", b"11111111111111111111111111111111");
        reg.flag.store(true, Ordering::SeqCst);
        reg.process(&mut app).unwrap();
        assert_eq!(app.screen, Screen::Login);
        let ack: Ack = serde_json::from_slice(&fs::read(root.path("ack")).unwrap()).unwrap();
        assert_eq!(ack.nonce, "11111111111111111111111111111111");
    }

    #[test]
    fn unsafe_or_malformed_requests_produce_no_success_ack() {
        use std::os::unix::fs::symlink;
        let root = TestRoot::new();
        let mut reg = Registration::for_test(&root.0).unwrap();
        let mut app = App::for_test(None);
        for invalid in [
            "",
            "abc",
            "ABCDEF0123456789ABCDEF0123456789",
            "0123456789abcdef0123456789abcdef\n",
            &"f".repeat(4097),
        ] {
            root.private_write("request", invalid.as_bytes());
            reg.flag.store(true, Ordering::SeqCst);
            assert!(reg.process(&mut app).is_err());
            assert!(!root.path("ack").exists());
        }
        root.private_write("request", b"0123456789abcdef0123456789abcdef");
        fs::set_permissions(root.path("request"), fs::Permissions::from_mode(0o644)).unwrap();
        reg.flag.store(true, Ordering::SeqCst);
        assert!(reg.process(&mut app).is_err());
        fs::remove_file(root.path("request")).unwrap();
        let target = root.0.join("target");
        fs::write(&target, b"0123456789abcdef0123456789abcdef").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, root.path("request")).unwrap();
        reg.flag.store(true, Ordering::SeqCst);
        assert!(reg.process(&mut app).is_err());
        fs::remove_file(root.path("request")).unwrap();
        fs::hard_link(&target, root.path("request")).unwrap();
        reg.flag.store(true, Ordering::SeqCst);
        assert!(reg.process(&mut app).is_err());
        fs::remove_file(root.path("request")).unwrap();
        fs::create_dir(root.path("request")).unwrap();
        reg.flag.store(true, Ordering::SeqCst);
        assert!(reg.process(&mut app).is_err());
        assert!(!root.path("ack").exists());
        assert_eq!(app.screen, Screen::Index);
    }

    #[test]
    fn startup_rejects_malformed_request_without_replacing_it() {
        let root = TestRoot::new();
        fs::create_dir(root.0.join("vault-tui-lock")).unwrap();
        fs::set_permissions(
            root.0.join("vault-tui-lock"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        root.private_write("request", b"inherited invalid request");
        assert!(Registration::for_test(&root.0).is_err());
        assert!(!root.path("json").exists());
        assert_eq!(
            fs::read(root.path("request")).unwrap(),
            b"inherited invalid request"
        );
    }

    #[test]
    fn inherited_ack_nonce_is_burned_even_without_an_inherited_request() {
        let root = TestRoot::new();
        fs::create_dir(root.0.join("vault-tui-lock")).unwrap();
        fs::set_permissions(
            root.0.join("vault-tui-lock"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        root.private_write(
            "ack",
            br#"{"nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","locked":true,"draft_persisted":true}"#,
        );
        let mut reg = Registration::for_test(&root.0).unwrap();
        root.private_write("request", b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        reg.flag.store(true, Ordering::SeqCst);
        let mut app = App::for_test(None);
        reg.process(&mut app).unwrap();
        assert_eq!(app.screen, Screen::Index);
    }

    #[test]
    fn coalesced_requests_acknowledge_only_latest_nonce_and_require_signal() {
        let root = TestRoot::new();
        let mut reg = Registration::for_test(&root.0).unwrap();
        let mut app = App::for_test(None);
        root.private_write("request", b"11111111111111111111111111111111");
        reg.flag.store(true, Ordering::SeqCst);
        root.private_write("request", b"22222222222222222222222222222222");
        reg.flag.store(true, Ordering::SeqCst);
        reg.process(&mut app).unwrap();
        let ack: Ack = serde_json::from_slice(&fs::read(root.path("ack")).unwrap()).unwrap();
        assert_eq!(ack.nonce, "22222222222222222222222222222222");
        app.screen = Screen::Index;
        root.private_write("request", b"33333333333333333333333333333333");
        reg.process(&mut app).unwrap();
        assert_eq!(app.screen, Screen::Index);
    }

    fn duplicate_during_ack(phase: usize) {
        let root = TestRoot::new();
        let mut reg = Registration::for_test(&root.0).unwrap();
        let mut app = App::for_test(None);
        let value = b"dddddddddddddddddddddddddddddddd";
        root.private_write("request", value);
        reg.flag.store(true, Ordering::SeqCst);
        test_fault::DUPLICATE.with(|hook| {
            *hook.borrow_mut() = Some((phase, Arc::clone(&reg.flag)));
        });
        let result = reg.process(&mut app);
        assert_eq!(app.screen, Screen::Login);
        assert!(app.db_key.is_none() && app.kdbx.is_none());
        assert!(reg.pending(), "duplicate signal must remain pending");
        assert!(
            result.is_ok(),
            "key-free ack must survive duplicate: {result:?}"
        );
        let bytes = fs::read(root.path("ack")).expect("current acknowledgment published");
        let ack: Ack = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(ack.nonce.as_bytes(), value);
        assert!(ack.locked && ack.draft_persisted);
        // Consume the duplicate without granting the nonce permission to lock again.
        app.screen = Screen::Index;
        reg.process(&mut app).unwrap();
        assert_eq!(app.screen, Screen::Index);
        assert!(!reg.pending());
        assert_eq!(fs::read(root.path("ack")).unwrap(), bytes);
    }

    #[test]
    fn duplicate_after_lock_cannot_suppress_acknowledgment() {
        duplicate_during_ack(0);
    }

    #[test]
    fn duplicate_before_ack_rename_cannot_suppress_acknowledgment() {
        duplicate_during_ack(1);
    }

    #[test]
    fn duplicate_after_ack_rename_cannot_suppress_acknowledgment() {
        duplicate_during_ack(2);
    }

    #[test]
    fn unsafe_ack_target_never_follows_or_overwrites_a_link() {
        let root = TestRoot::new();
        let mut reg = Registration::for_test(&root.0).unwrap();
        let target = root.0.join("unrelated");
        fs::write(&target, b"unrelated content").unwrap();
        std::os::unix::fs::symlink(&target, root.path("ack")).unwrap();
        root.private_write("request", b"cccccccccccccccccccccccccccccccc");
        reg.flag.store(true, Ordering::SeqCst);
        let mut app = App::for_test(None);
        assert!(reg.process(&mut app).is_err());
        assert_eq!(app.screen, Screen::Login);
        assert_eq!(fs::read(target).unwrap(), b"unrelated content");
        assert!(fs::symlink_metadata(root.path("ack")).unwrap().is_symlink());
    }

    #[test]
    fn registration_keeps_its_inode_pinned_until_cleanup() {
        let root = TestRoot::new();
        let reg = Registration::for_test(&root.0).unwrap();
        let meta = fs::metadata(root.path("json")).unwrap();
        fs::remove_file(root.path("json")).unwrap();
        let pinned = fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(Result::ok)
            .filter_map(|e| fs::metadata(e.path()).ok())
            .any(|m| crate::private_fs::same(&meta, &m));
        assert!(
            pinned,
            "metadata alone permits inode reuse and unsafe cleanup of replacement files"
        );
        drop(reg);
    }

    #[test]
    fn registration_is_exclusive_and_cleanup_preserves_replacements() {
        let root = TestRoot::new();
        let reg = Registration::for_test(&root.0).unwrap();
        assert!(Registration::for_test(&root.0).is_err());
        fs::remove_file(root.path("json")).unwrap();
        root.private_write("json", b"replacement must survive");
        drop(reg);
        assert_eq!(
            fs::read(root.path("json")).unwrap(),
            b"replacement must survive"
        );
    }

    /// This admission hook exists only in the Rust test binary, never release.
    #[test]
    fn protocol_child() {
        let Some(root) = std::env::var_os("JAIBA_TEST_LOCK_ROOT") else {
            return;
        };
        let root = std::path::PathBuf::from(root);
        let mut registration = Registration::for_test(&root).unwrap();
        let mode = fs::read_to_string(root.join("mode")).unwrap_or_default();
        let path = root.join("synthetic.kdbx");
        let mut app = App::for_test(if mode.is_empty() {
            None
        } else {
            Some(path.clone())
        });
        app.screen = Screen::Login;
        if mode == "draft" || mode == "failed-draft" {
            crate::db::create_database(&path, "synthetic master", None).unwrap();
            let (db, key, _, revision) =
                crate::db::unlock_database_snapshot(&path, "synthetic master", None).unwrap();
            app.kdbx = Some(db);
            app.db_key = Some(key);
            app.primary_revision = Some(revision);
            app.screen = Screen::Edit;
            app.edit_entry = Some(crate::db::Entry {
                password: "synthetic secret".into(),
                ..Default::default()
            });
            app.edit_original = Some(Default::default());
            app.edit_state.select(Some(5));
            app.editing_field = true;
            app.field_buffer = "partial synthetic notes λ".into();
            if mode == "failed-draft" {
                fs::write(crate::recovery::directory(&path), b"synthetic blocker").unwrap();
            }
        }
        fs::write(root.join("ready"), []).unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        while !root.join("stop").exists() && Instant::now() < deadline {
            registration.process(&mut app).unwrap();
            if root.join("authenticate").exists() {
                fs::remove_file(root.join("authenticate")).unwrap();
                app.password = "synthetic master".into();
                crate::input::login::handle_login_input(&mut app, crossterm::event::KeyCode::Enter);
            }
            let state = serde_json::json!({
                "locked": app.screen == Screen::Login,
                "editor": app.screen == Screen::Edit,
                "recovered": app.edit_entry.as_ref().is_some_and(|e| e.password == "synthetic secret") && app.field_buffer == "partial synthetic notes λ",
                "pending_memory": app.pending_draft.is_some()
            });
            fs::write(root.join("state"), serde_json::to_vec(&state).unwrap()).unwrap();
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    fn child(root: &Path) -> Child {
        Child(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "locking::tests::protocol_child", "--nocapture"])
                .env_clear()
                .env("JAIBA_TEST_LOCK_ROOT", root)
                .env("TMPDIR", std::env::temp_dir())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .spawn()
                .unwrap(),
        )
    }
    fn signal_request(root: &Path, pid: u32, value: &str) -> serde_json::Value {
        let registry = root.join("vault-tui-lock");
        let request = registry.join(format!("jaiba.{pid}.request"));
        fs::write(&request, value).unwrap();
        fs::set_permissions(&request, fs::Permissions::from_mode(0o600)).unwrap();
        // SAFETY: pid belongs only to the scratch child created by this test.
        assert_eq!(unsafe { libc::kill(pid as i32, libc::SIGUSR2) }, 0);
        let ack = registry.join(format!("jaiba.{pid}.ack"));
        let mut reply = None;
        wait_for(|| {
            reply = fs::read(&ack)
                .ok()
                .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                .filter(|v| v["nonce"] == value);
            reply.is_some()
        });
        reply.unwrap()
    }
    fn read_state(root: &Path, check: impl Fn(&serde_json::Value) -> bool) {
        wait_for(|| {
            fs::read(root.join("state"))
                .ok()
                .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                .is_some_and(|v| check(&v))
        });
    }

    #[test]
    fn genuine_signal_encrypts_draft_and_restart_requires_reauthentication() {
        let root = TestRoot::new();
        fs::write(root.0.join("mode"), "draft").unwrap();
        let mut process = child(&root.0);
        wait_for(|| root.0.join("ready").exists());
        let reply = signal_request(&root.0, process.0.id(), "11111111111111111111111111111111");
        assert_eq!(reply["locked"], true);
        assert_eq!(reply["draft_persisted"], true);
        read_state(&root.0, |s| s["locked"] == true && s["recovered"] == false);
        fs::write(root.0.join("stop"), []).unwrap();
        assert!(process.0.wait().unwrap().success());
        drop(process);
        fs::remove_file(root.0.join("stop")).unwrap();
        fs::remove_file(root.0.join("ready")).unwrap();
        fs::write(root.0.join("mode"), "login").unwrap();
        let mut restarted = child(&root.0);
        wait_for(|| root.0.join("ready").exists());
        read_state(&root.0, |s| s["locked"] == true && s["recovered"] == false);
        fs::write(root.0.join("authenticate"), []).unwrap();
        read_state(&root.0, |s| s["editor"] == true && s["recovered"] == true);
        fs::write(root.0.join("stop"), []).unwrap();
        assert!(restarted.0.wait().unwrap().success());
    }

    #[test]
    fn genuine_signal_reports_persistence_failure_until_real_retry() {
        let root = TestRoot::new();
        fs::write(root.0.join("mode"), "failed-draft").unwrap();
        let mut process = child(&root.0);
        wait_for(|| root.0.join("ready").exists());
        let reply = signal_request(&root.0, process.0.id(), "22222222222222222222222222222222");
        assert_eq!(reply["locked"], true);
        assert_eq!(reply["draft_persisted"], false);
        read_state(&root.0, |s| {
            s["locked"] == true && s["pending_memory"] == true
        });
        fs::remove_file(crate::recovery::directory(&root.0.join("synthetic.kdbx"))).unwrap();
        let reply = signal_request(&root.0, process.0.id(), "33333333333333333333333333333333");
        assert_eq!(reply["draft_persisted"], false);
        fs::write(root.0.join("authenticate"), []).unwrap();
        read_state(&root.0, |s| s["recovered"] == true);
        let reply = signal_request(&root.0, process.0.id(), "44444444444444444444444444444444");
        assert_eq!(reply["locked"], true);
        assert_eq!(reply["draft_persisted"], true);
        fs::write(root.0.join("stop"), []).unwrap();
        assert!(process.0.wait().unwrap().success());
    }

    #[test]
    fn genuine_signal_is_processed_in_normal_loop_and_acknowledged() {
        let root = std::env::temp_dir().join(format!("jaiba-protocol-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let mut child = child(&root);
        let pid = child.0.id();
        let registry = root.join("vault-tui-lock");
        let reg = registry.join(format!("jaiba.{pid}.json"));
        wait_for(|| reg.exists());
        let request = registry.join(format!("jaiba.{pid}.request"));
        let ack = registry.join(format!("jaiba.{pid}.ack"));
        let info: serde_json::Value = serde_json::from_slice(&fs::read(&reg).unwrap()).unwrap();
        assert_eq!(info["version"], 1);
        assert_eq!(info["frontend"], "jaiba");
        assert_eq!(info["pid"], pid);
        assert!(
            info["start"]
                .as_str()
                .unwrap()
                .bytes()
                .all(|b| b.is_ascii_digit())
        );
        assert_eq!(fs::metadata(&reg).unwrap().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(&registry).unwrap().mode() & 0o777, 0o700);
        let nonce = "0123456789abcdef0123456789abcdef";
        let mut f = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&request)
            .unwrap();
        fs::set_permissions(&request, fs::Permissions::from_mode(0o600)).unwrap();
        f.write_all(nonce.as_bytes()).unwrap();
        drop(f);
        // SAFETY: only signal the synthetic child created above, never a live vault.
        assert_eq!(unsafe { libc::kill(pid as i32, libc::SIGUSR2) }, 0);
        wait_for(|| ack.exists());
        let reply: serde_json::Value = serde_json::from_slice(&fs::read(&ack).unwrap()).unwrap();
        assert_eq!(
            reply,
            serde_json::json!({"nonce":nonce,"locked":true,"draft_persisted":true})
        );
        fs::write(root.join("stop"), []).unwrap();
        assert!(child.0.wait().unwrap().success());
        assert!(!reg.exists());
        assert!(!ack.exists());
        fs::remove_dir_all(root).unwrap();
    }
}
