//! Confidential recovery: a protected JSON editor snapshot inside a normal KDBX4.
//! The primary vault is never modified by locking. No custom cryptography.
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Context;
use keepass::{Database, DatabaseKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::app::{App, Screen};
use crate::db::Entry;
use crate::private_fs::{self, Dir};

const MAX_DRAFT: u64 = 16 * 1024 * 1024;
const PAYLOAD: &str = "JaibaR4Draft";

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    id: Option<String>,
    fields: [String; 6],
}
impl Snapshot {
    fn from_entry(e: &Entry) -> Self {
        Self {
            id: e.id.map(|id| id.to_string()),
            fields: [
                e.name.clone(),
                e.user.clone(),
                e.password.clone(),
                e.url.clone(),
                e.totp.clone(),
                e.notes.clone(),
            ],
        }
    }
    fn entry(mut self, app: &App, deleted: Option<keepass::db::EntryId>) -> anyhow::Result<Entry> {
        let id = self
            .id
            .take()
            .map(|id| {
                app.entries
                    .iter()
                    .find(|e| e.id.is_some_and(|i| i.to_string() == id))
                    .and_then(|e| e.id)
                    .or_else(|| deleted.filter(|i| i.to_string() == id))
                    .context("Draft target no longer exists; keep the recovery file")
            })
            .transpose()?;
        let [name, user, password, url, totp, notes] = std::mem::take(&mut self.fields);
        Ok(Entry {
            id,
            name,
            user,
            password,
            url,
            totp,
            notes,
            ..Entry::default()
        })
    }
}

impl Drop for Snapshot {
    fn drop(&mut self) {
        self.fields.zeroize();
        self.id.zeroize();
    }
}

/// In-memory drafts need the same vault binding as the encrypted envelope.
/// Never infer or replace this identity from a later authentication.
#[derive(Clone)]
struct Origin {
    database: PathBuf,
    root: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Draft {
    #[serde(skip)]
    origin: Option<Origin>,
    entry: Snapshot,
    original: Snapshot,
    selected: Option<usize>,
    editing: bool,
    buffer: String,
    // Committed deletions with unresolved cleanup stay memory-only. Never
    // serialize them as an ordinary editable snapshot that could resurrect data.
    #[serde(skip)]
    deletion_committed: bool,
    #[serde(skip)]
    deleted_id: Option<keepass::db::EntryId>,
}

impl Drop for Draft {
    fn drop(&mut self) {
        self.buffer.zeroize();
    }
}

impl Draft {
    pub fn capture(app: &App) -> Option<Self> {
        if app.screen != Screen::Edit {
            return None;
        }
        Some(Self {
            // Use the path authenticated at unlock, even if its pathname is
            // now missing or a configured symlink has been retargeted. A fresh
            // canonicalize here could silently bind this draft to another vault.
            // Missing provenance still captures the secrets, but never licenses
            // restoration/publication under an identity invented on later login.
            origin: app
                .primary_revision
                .as_ref()
                .zip(app.kdbx.as_ref())
                .map(|(revision, db)| Origin {
                    database: revision.database_path().to_owned(),
                    root: db.root().id().to_string(),
                }),
            entry: Snapshot::from_entry(app.edit_entry.as_ref()?),
            original: Snapshot::from_entry(app.edit_original.as_ref().unwrap_or(&Entry::default())),
            selected: app.edit_state.selected(),
            editing: app.editing_field,
            buffer: app.field_buffer.clone(),
            deletion_committed: app.edit_deleted,
            deleted_id: app
                .edit_deleted
                .then(|| app.edit_entry.as_ref().and_then(|e| e.id))
                .flatten(),
        })
    }
    fn validate_origin(&self, app: &App) -> anyhow::Result<&Origin> {
        let origin = self.origin.as_ref().context(
            "Draft origin unavailable; keep this window open and the memory draft hidden; do not attach it to another vault",
        )?;
        let path = app
            .database_path()
            .context("No authenticated draft database")?;
        let db = app
            .kdbx
            .as_ref()
            .context("No authenticated draft database")?;
        let revision = app
            .primary_revision
            .as_ref()
            .context("No authenticated draft revision")?;
        anyhow::ensure!(app.db_key.is_some(), "No authenticated draft key");
        anyhow::ensure!(
            revision.database_path() == origin.database
                && fs::canonicalize(path)? == origin.database
                && db.root().id().to_string() == origin.root,
            "Draft belongs to a different database. Restore the original vault at {} and its configured path, then authenticate again. KEEP THIS WINDOW OPEN; the draft remains only in memory",
            origin.database.display()
        );
        Ok(origin)
    }

    pub fn restore(mut self, app: &mut App) -> anyhow::Result<()> {
        self.validate_origin(app)?;
        anyhow::ensure!(
            self.selected.is_none_or(|index| index <= 6),
            "Invalid draft field"
        );
        let mut entry =
            Zeroizing::new(std::mem::take(&mut self.entry).entry(app, self.deleted_id)?);
        let mut original =
            Zeroizing::new(std::mem::take(&mut self.original).entry(app, self.deleted_id)?);
        let target = entry
            .id
            .and_then(|id| app.entries.iter().position(|entry| entry.id == Some(id)));
        app.edit_entry = Some(std::mem::take(&mut *entry));
        app.edit_original = Some(std::mem::take(&mut *original));
        app.edit_target = target;
        app.edit_deleted = self.deletion_committed;
        app.edit_state.select(self.selected);
        app.editing_field = self.editing;
        app.field_buffer = std::mem::take(&mut self.buffer);
        app.reveal_password = false;
        app.confirm_exit = false;
        app.confirm_delete = false;
        app.screen = Screen::Edit;
        app.status = Some(if self.deletion_committed {
            "Entry already deleted; recovery cleanup pending. [d] retry cleanup".into()
        } else {
            "Recovered unsaved draft; save or discard explicitly".into()
        });
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u8,
    database: PathBuf,
    root: String,
    draft: Draft,
}

pub fn directory(database: &Path) -> PathBuf {
    let canonical = fs::canonicalize(database).unwrap_or_else(|_| database.to_owned());
    let mut path = canonical.into_os_string();
    path.push(".jaiba-drafts");
    PathBuf::from(path)
}

/// Database-scoped publication/rekey mutex, distinct from each session's Slot.
/// Canonical paths coalesce symlink aliases; hard-link aliases are rejected.
/// Never unlink this file: cooperating processes must share its stable inode.
pub struct Transaction {
    pub path: PathBuf,
    _lock: File,
    _dir: Dir,
}
impl Transaction {
    pub fn begin(database: &Path) -> anyhow::Result<Self> {
        let path = fs::canonicalize(database)?;
        anyhow::ensure!(
            fs::metadata(&path)?.nlink() == 1,
            "Hard-linked primary database is not supported for recovery/rekey"
        );
        let dir = Dir::beside(&directory(&path), private_fs::uid(), true)?;
        let name = std::ffi::OsStr::new("transaction.lock");
        let lock = match dir.create(name) {
            Ok(file) => {
                dir.sync()?;
                file
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => dir.open_file(name, 0)?,
            Err(e) => return Err(e.into()),
        };
        anyhow::ensure!(
            private_fs::claim(&lock)?,
            "Draft publication/rekey transaction busy; retry after authenticating"
        );
        anyhow::ensure!(
            private_fs::same(&lock.metadata()?, &dir.open_file(name, 0)?.metadata()?),
            "Database transaction lock identity changed"
        );
        Ok(Self {
            path,
            _lock: lock,
            _dir: dir,
        })
    }
}

/// Stable companion lock survives atomic replacement of the encrypted data inode.
/// Kept until explicit save/discard, including while login hides the editor.
pub struct Slot {
    dir: Dir,
    name: OsString,
    lock_name: OsString,
    lock: File,
    data_file: Option<File>,
    ciphertext: Option<[u8; 32]>,
}
impl Slot {
    fn allocate(database: &Path) -> anyhow::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = Dir::beside(&directory(database), private_fs::uid(), true)?;
        for _ in 0..100 {
            let name = OsString::from(format!(
                "draft.{}.{}.kdbx",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let mut lock_name = name.clone();
            lock_name.push(".lock");
            let lock = match dir.create(&lock_name) {
                Ok(file) => file,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            };
            anyhow::ensure!(private_fs::claim(&lock)?, "Cannot claim new draft");
            match dir.open_file(&name, MAX_DRAFT) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    return Ok(Self {
                        dir,
                        name,
                        lock_name,
                        lock,
                        data_file: None,
                        ciphertext: None,
                    });
                }
                _ => {
                    let _ = dir.remove_owned(&lock_name, &lock.metadata()?);
                }
            }
        }
        anyhow::bail!("Cannot allocate draft slot")
    }
    fn read(&mut self, key: &DatabaseKey) -> anyhow::Result<String> {
        let mut file = self.dir.open_file(&self.name, MAX_DRAFT)?;
        if let Some(expected) = &self.data_file {
            anyhow::ensure!(
                private_fs::same(&expected.metadata()?, &file.metadata()?),
                "Recovery file identity changed"
            );
        }
        self.data_file = Some(file.try_clone()?);
        let db = crate::db::open_with_key(&mut file, key)?;
        self.ciphertext = Some(self.fingerprint()?);
        let entries: Vec<_> = db.iter_all_entries().collect();
        anyhow::ensure!(entries.len() == 1, "Invalid draft container");
        Ok(entries[0]
            .get(PAYLOAD)
            .context("Missing encrypted draft payload")?
            .to_owned())
    }
    fn persist(
        &mut self,
        value: &str,
        key: &DatabaseKey,
        config: &keepass::config::DatabaseConfig,
    ) -> anyhow::Result<()> {
        match (&self.data_file, self.dir.open_file(&self.name, MAX_DRAFT)) {
            (Some(expected), Ok(actual)) => anyhow::ensure!(
                private_fs::same(&expected.metadata()?, &actual.metadata()?),
                "Recovery file identity changed"
            ),
            (None, Err(e)) if e.kind() == io::ErrorKind::NotFound => (),
            _ => anyhow::bail!("Recovery file changed or became unsafe"),
        }
        anyhow::ensure!(
            value.len() as u64 <= MAX_DRAFT / 2,
            "Draft exceeds recovery size limit"
        );
        let mut db = Database::new();
        // Copy policy, not header seeds. keepass generates fresh seeds/IVs on save.
        // Sidecars remain KDBX4 even when the primary is an older format.
        db.config.kdf_config = config.kdf_config.clone();
        db.config.outer_cipher_config = config.outer_cipher_config.clone();
        db.config.inner_cipher_config = config.inner_cipher_config.clone();
        db.config.compression_config = config.compression_config.clone();
        db.root_mut().add_entry().set_protected(PAYLOAD, value);
        self.ciphertext = None;
        self.dir.atomic(
            &self.name,
            |file| crate::db::save_with_key(&db, file, key),
            |file| {
                let reopened = crate::db::open_with_key(file, key)?;
                let entries: Vec<_> = reopened.iter_all_entries().collect();
                anyhow::ensure!(
                    entries.len() == 1 && entries[0].get(PAYLOAD) == Some(value),
                    "Encrypted draft verification failed"
                );
                Ok(())
            },
            &mut self.data_file,
        )?;
        self.ciphertext = Some(self.fingerprint()?);
        Ok(())
    }
    // Only ciphertext is hashed; no authentication key or plaintext is retained.
    fn fingerprint(&self) -> anyhow::Result<[u8; 32]> {
        let lock = self.dir.open_file(&self.lock_name, 0)?;
        anyhow::ensure!(
            private_fs::same(&lock.metadata()?, &self.lock.metadata()?),
            "Draft lock identity changed"
        );
        let mut actual = self.dir.open_file(&self.name, MAX_DRAFT)?;
        let before = actual.metadata()?;
        let expected = self
            .data_file
            .as_ref()
            .context("No pinned recovery artifact")?
            .metadata()?;
        anyhow::ensure!(
            private_fs::same(&before, &expected) && before.len() == expected.len(),
            "Recovery file identity changed"
        );
        let mut digest = Sha256::new();
        let mut buffer = [0u8; 8192];
        let mut total = 0u64;
        loop {
            let count = actual.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            total += count as u64;
            anyhow::ensure!(total <= MAX_DRAFT, "Recovery file grew");
            digest.update(&buffer[..count]);
        }
        let after = actual.metadata()?;
        let named = self.dir.open_file(&self.name, MAX_DRAFT)?.metadata()?;
        anyhow::ensure!(
            private_fs::same(&before, &named)
                && total == before.len()
                && before.len() == after.len()
                && before.mtime() == after.mtime()
                && before.mtime_nsec() == after.mtime_nsec()
                && before.ctime() == after.ctime()
                && before.ctime_nsec() == after.ctime_nsec(),
            "Recovery artifact changed during validation"
        );
        Ok(digest.finalize().into())
    }
    pub fn revalidate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.ciphertext == Some(self.fingerprint()?),
            "Recovery ciphertext changed"
        );
        Ok(())
    }
    pub fn clear(&self) -> anyhow::Result<()> {
        match self.dir.open_file(&self.name, MAX_DRAFT) {
            Ok(_) => {
                self.revalidate()?;
                self.dir.remove_owned(
                    &self.name,
                    &self
                        .data_file
                        .as_ref()
                        .context("Unclaimed recovery file")?
                        .metadata()?,
                )?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
        self.dir
            .remove_owned(&self.lock_name, &self.lock.metadata()?)?;
        Ok(())
    }
}

pub fn persist(app: &mut App, draft: &Draft) -> anyhow::Result<()> {
    // Cancellation must revoke before starting filesystem transactions or KDFs.
    challenge_response::operation::check()?;
    let origin = draft.validate_origin(app)?;
    anyhow::ensure!(
        !draft.deletion_committed,
        "Committed deletion awaits recovery cleanup"
    );
    let key = app.db_key.as_ref().context("No database key for draft")?;
    let transaction =
        Transaction::begin(app.database_path().context("No open database for draft")?)?;
    let path = transaction.path.clone();
    anyhow::ensure!(
        path == origin.database,
        "Draft database path changed before publication; keep the memory draft"
    );
    let (policy, primary_file, primary_ciphertext) =
        verify_primary(&path, key, &origin.root, draft)?;
    #[cfg(test)]
    interleave::before_publication();
    let envelope = Envelope {
        version: 1,
        database: origin.database.clone(),
        root: origin.root.clone(),
        draft: draft.clone(),
    };
    let value = Zeroizing::new(serde_json::to_string(&envelope)?);
    if app.draft_slot.is_none() {
        app.draft_slot = Some(Slot::allocate(&path)?);
    }
    app.draft_slot
        .as_mut()
        .unwrap()
        .persist(&value, key, &policy)?;
    // Revalidate the exact authenticated primary, without another costly KDF.
    // This detects changes; it is not exclusion of non-cooperating writers.
    let mut actual = File::open(&path)?;
    anyhow::ensure!(
        private_fs::same(&primary_file.metadata()?, &actual.metadata()?),
        "Primary database identity changed during draft publication"
    );
    let mut bytes = Vec::new();
    actual.read_to_end(&mut bytes)?;
    anyhow::ensure!(
        primary_ciphertext == <[u8; 32]>::from(Sha256::digest(&bytes))
            && private_fs::same(&actual.metadata()?, &fs::metadata(&path)?),
        "Primary database changed during draft publication; keep the memory draft"
    );
    Ok(())
}

fn verify_primary(
    path: &Path,
    key: &DatabaseKey,
    root: &str,
    draft: &Draft,
) -> anyhow::Result<(keepass::config::DatabaseConfig, File, [u8; 32])> {
    let mut file = File::open(path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let ciphertext = Sha256::digest(&bytes).into();
    let current = crate::db::open_with_key(&mut io::Cursor::new(&bytes), key)
        .context("Original database credentials changed; draft must remain in memory")?;
    anyhow::ensure!(
        current.root().id().to_string() == root,
        "Original database was replaced; keep the memory draft"
    );
    for snapshot in [&draft.entry, &draft.original] {
        if let Some(id) = &snapshot.id {
            anyhow::ensure!(
                current
                    .iter_all_entries()
                    .any(|entry| entry.id().to_string() == *id),
                "Draft target no longer exists; keep the memory draft"
            );
        }
    }
    Ok((current.config.clone(), file, ciphertext))
}

/// Do not strand recovery files under obsolete credentials when changing the
/// master password in Jaiba. Concurrent external primary-vault writers remain
/// outside the application's single-writer database model.
pub fn has_pending_files(app: &App) -> anyhow::Result<bool> {
    let Some(path) = app.database_path() else {
        return Ok(false);
    };
    let path = directory(path);
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
        Ok(_) => (),
    }
    let dir = Dir::beside(&path, private_fs::uid(), false)?;
    Ok(dir.names()?.iter().any(|name| {
        name.to_str()
            .is_some_and(|n| n.starts_with("draft.") && n.ends_with(".kdbx"))
    }))
}

/// Call only after successful primary-database authentication. Locked, live
/// sessions are skipped, so concurrent Jaiba processes cannot steal a draft.
pub fn recover(app: &mut App) -> anyhow::Result<()> {
    if let Some(draft) = app.pending_draft.clone() {
        draft.restore(app)?;
        app.pending_draft = None;
        return Ok(());
    }
    let path = app.database_path().context("No open database")?.to_owned();
    let key = app.db_key.as_ref().context("No authenticated key")?;
    if app.draft_slot.is_none() {
        // Absence is not an unsafe recovery artifact. Keep ordinary/native
        // unlocks working even when their parent cannot host safe sidecars.
        match fs::symlink_metadata(directory(&path)) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
            Ok(_) => (),
        }
        let dir = match Dir::beside(&directory(&path), private_fs::uid(), false) {
            Ok(dir) => dir,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        let mut names = dir.names()?;
        names.sort();
        for name in names {
            if !name
                .to_str()
                .is_some_and(|n| n.starts_with("draft.") && n.ends_with(".kdbx"))
            {
                continue;
            }
            // Inspect data and lock separately with no-follow, type, size, owner,
            // permissions and single-link validation before touching either.
            let _ = dir.open_file(&name, MAX_DRAFT)?;
            let mut lock_name = name.clone();
            lock_name.push(".lock");
            let lock = dir.open_file(&lock_name, 0)?;
            if !private_fs::claim(&lock)? {
                continue;
            }
            app.draft_slot = Some(Slot {
                dir,
                name,
                lock_name,
                lock,
                data_file: None,
                ciphertext: None,
            });
            break;
        }
    }
    let Some(slot) = app.draft_slot.as_mut() else {
        return Ok(());
    };
    let value = Zeroizing::new(slot.read(key)?);
    let envelope: Envelope = serde_json::from_str(&value)?;
    anyhow::ensure!(
        envelope.version == 1
            && envelope.database == fs::canonicalize(&path)?
            && envelope.root == app.kdbx.as_ref().unwrap().root().id().to_string(),
        "Draft belongs to a different database"
    );
    let mut draft = envelope.draft;
    // The authenticated envelope is authoritative for disk recovery. This
    // field is intentionally not serialized a second time inside its payload.
    draft.origin = Some(Origin {
        database: envelope.database,
        root: envelope.root,
    });
    draft.restore(app)
}

/// Refuse to forget the editor if retirement of an old recovery record fails.
pub fn retire(app: &mut App) -> anyhow::Result<()> {
    app.draft_durable = false;
    if let Some(slot) = &app.draft_slot {
        slot.clear()?;
    }
    app.draft_slot = None;
    app.draft_durable = true;
    Ok(())
}

#[cfg(test)]
pub mod interleave {
    use std::{
        cell::RefCell,
        sync::mpsc::{Receiver, Sender},
        time::Duration,
    };
    pub type Pause = Option<(Sender<()>, Receiver<()>)>;
    thread_local! {
        pub static REKEY: RefCell<Pause> = const { RefCell::new(None) };
        pub static PUBLICATION: RefCell<Pause> = const { RefCell::new(None) };
    }
    fn pause(hook: &'static std::thread::LocalKey<RefCell<Pause>>) {
        hook.with(|hook| {
            if let Some((ready, resume)) = hook.borrow_mut().take() {
                ready.send(()).unwrap();
                resume.recv_timeout(Duration::from_secs(10)).unwrap();
            }
        });
    }
    pub fn before_rekey() {
        pause(&REKEY);
    }
    pub fn before_publication() {
        pause(&PUBLICATION);
    }
}
