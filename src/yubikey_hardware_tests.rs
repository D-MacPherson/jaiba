//! Opt-in real device tests: only new synthetic files beneath private TMPDIR.
//! A touch-enabled token needs MANY touches; vendored protocol budget is 30s.
use super::*;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::{Duration, Instant};

fn opt_in() -> PathBuf {
    assert_eq!(
        std::env::var("JAIBA_YUBIKEY_TEST").as_deref(),
        Ok("39269826:2"),
        "explicit hardware authorization required"
    );
    let root = PathBuf::from(std::env::var_os("TMPDIR").expect("private TMPDIR required"));
    assert!(root.is_absolute());
    assert_eq!(fs::canonicalize(&root).unwrap(), root, "no symlink TMPDIR");
    let m = fs::symlink_metadata(&root).unwrap();
    assert!(m.is_dir() && m.uid() == crate::private_fs::uid() && m.mode() & 0o077 == 0);
    let home = fs::canonicalize(std::env::var_os("HOME").expect("isolated HOME required")).unwrap();
    assert!(
        home.starts_with(&root) && home != root,
        "HOME must be isolated beneath TMPDIR"
    );
    eprintln!(
        "REAL HARDWARE serial39269826 slot2: multiple separate touches may be required. No programming. Native operation budget 30s; still use an external process timeout."
    );
    root
}
fn native_app(f: &Fixture, keyfile: Option<PathBuf>, password: &str) -> App {
    let mut app = App::for_test(Some(f.path()));
    app.screen = Screen::Login;
    app.config.yubikey = Some(TOKEN.into());
    app.config.keyfile = keyfile;
    authenticate(&mut app, password);
    assert_eq!(app.screen, Screen::Index, "{:?}", app.login_error);
    app
}
fn copy_new(source: &Path, target: &Path) {
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(target)
        .unwrap();
    std::io::copy(&mut fs::File::open(source).unwrap(), &mut output).unwrap();
    output.sync_all().unwrap();
}
fn export_for_xc(app: &mut App, root: &Path, keyfile: Option<&Path>) {
    let target = root.join("jaiba-hardware-output.kdbx");
    assert!(!target.exists(), "refuse overwriting prior output");
    app.screen = Screen::Settings;
    app.exporting_database = true;
    app.export_step = crate::app::ExportStep::Confirm;
    app.pending_export_path = Some(target.clone());
    input::settings::handle_settings_input(app, KeyCode::Enter);
    assert!(
        app.status
            .as_ref()
            .is_some_and(|s| s.starts_with("exported")),
        "{:?}",
        app.status
    );
    if let Some(keyfile) = keyfile {
        copy_new(keyfile, &root.join("jaiba-hardware-output.key"));
    }
    eprintln!(
        "XC independent readback output: {} (password: new synthetic master)",
        target.display()
    );
}

#[test]
#[ignore = "REAL YUBIKEY: explicit opt-in, private HOME/TMPDIR, many touches"]
fn disposable_hardware_lifecycle() {
    let root = opt_in();
    let faults = crate::yubikey_test_backend::Model::faults_only();
    lifecycle(&root, faults);
}

#[test]
fn hardware_lifecycle_harness_with_software_token() {
    let root = Fixture::new();
    let faults = crate::yubikey_test_backend::Model::new(TOKEN);
    lifecycle(&root.0, faults);
}

fn lifecycle(root: &Path, faults: crate::yubikey_test_backend::Model) {
    let f = Fixture::new();
    let keyfile = f.0.join("synthetic.key");
    fs::write(&keyfile, b"new synthetic hardware lifecycle keyfile").unwrap();
    let mut app = App::for_test(Some(f.path()));
    app.screen = Screen::Login;
    app.config.yubikey = Some(TOKEN.into());
    app.config.keyfile = Some(keyfile.clone());
    input::login::handle_login_input(&mut app, KeyCode::Char('n'));
    app.password = "synthetic master".into();
    input::login::handle_login_input(&mut app, KeyCode::Enter);
    app.new_db_confirm = app.password.clone();
    input::login::handle_login_input(&mut app, KeyCode::Enter);
    assert_eq!(app.screen, Screen::Index, "{:?}", app.login_error);
    assert!(db::unlock_database(&f.path(), "synthetic master", Some(&keyfile)).is_err());
    assert!(
        db::unlock_database_snapshot_with_yubikey(&f.path(), "synthetic master", None, Some(TOKEN))
            .is_err()
    );
    assert!(
        db::unlock_database_snapshot_with_yubikey(
            &f.path(),
            "wrong synthetic master",
            Some(&keyfile),
            Some(TOKEN)
        )
        .is_err()
    );
    assert!(
        db::unlock_database_snapshot_with_yubikey(
            &f.path(),
            "synthetic master",
            Some(&keyfile),
            Some(YubikeyConfig { serial: 1, ..TOKEN })
        )
        .is_err()
    );
    draft(&mut app);
    let before = fs::read(f.path()).unwrap();
    faults.fail_after(1); // real full-factor DatabaseKey retained; no substitute secret
    save_draft(&mut app);
    assert_eq!(app.screen, Screen::Edit);
    assert_eq!(fs::read(f.path()).unwrap(), before);
    faults.clear_fault();
    faults.fail_after(2); // actual hardware save; failure at staged independent read
    save_draft(&mut app);
    assert_eq!(app.screen, Screen::Edit);
    assert_eq!(fs::read(f.path()).unwrap(), before);
    faults.clear_fault();
    faults.fail_after(3); // actual save + staged decrypt; post-replacement uncertainty
    save_draft(&mut app);
    assert_eq!(app.screen, Screen::Edit);
    assert_ne!(fs::read(f.path()).unwrap(), before);
    faults.clear_fault();
    save_draft(&mut app);
    assert_eq!(app.screen, Screen::Index, "{:?}", app.status);
    draft(&mut app);
    faults.unavailable(true); // deterministic unplug boundary on actual key
    assert!(!app.lock_cooperatively());
    assert_eq!(app.screen, Screen::Login);
    assert!(app.db_key.is_none() && app.kdbx.is_none());
    assert!(app.pending_draft.is_some() && !app.draft_durable);
    assert!(!app.lock_cooperatively());
    faults.unavailable(false);
    authenticate(&mut app, "wrong synthetic master");
    assert_eq!(app.screen, Screen::Login);
    assert!(app.pending_draft.is_some());
    authenticate(&mut app, "synthetic master");
    assert_eq!(app.screen, Screen::Edit, "{:?}", app.login_error);
    assert_eq!(app.field_buffer, "synthetic partial notes");
    assert!(app.lock_cooperatively(), "durable full-factor sidecar");
    drop(app); // release recovery claim to exercise restart
    let mut app = App::for_test(Some(f.path()));
    app.config.yubikey = Some(TOKEN.into());
    app.config.keyfile = Some(keyfile.clone());
    app.screen = Screen::Login;
    authenticate(&mut app, "synthetic master");
    assert_eq!(app.screen, Screen::Edit, "{:?}", app.login_error);
    assert_eq!(app.field_buffer, "synthetic partial notes");
    save_draft(&mut app);
    assert_eq!(app.screen, Screen::Index, "{:?}", app.status);
    app.config.yubikey = None;
    app.config.keyfile = None;
    rekey(&mut app, "synthetic master", "new synthetic master");
    assert!(
        app.status
            .as_ref()
            .unwrap()
            .contains("master password changed"),
        "{:?}",
        app.status
    );
    assert!(db::unlock_database(&f.path(), "new synthetic master", Some(&keyfile)).is_err());
    export_for_xc(&mut app, root, Some(&keyfile));
    let (_, _, entries, _) = db::unlock_database_snapshot_with_yubikey(
        &root.join("jaiba-hardware-output.kdbx"),
        "new synthetic master",
        Some(&root.join("jaiba-hardware-output.key")),
        Some(TOKEN),
    )
    .unwrap();
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().all(|e| e.notes == "synthetic partial notes"));
}

fn xc_fixture(root: &Path) -> (Fixture, String) {
    let input = PathBuf::from(
        std::env::var_os("JAIBA_XC_FIXTURE").expect("explicit NEW synthetic XC fixture required"),
    );
    assert_eq!(input.file_name().unwrap(), "synthetic-xc.kdbx");
    assert_eq!(fs::canonicalize(&input).unwrap(), input);
    assert!(input.starts_with(root));
    let f = Fixture::new();
    copy_new(&input, &f.path());
    let password =
        std::env::var("JAIBA_XC_FIXTURE_PASSWORD").unwrap_or_else(|_| "synthetic master".into());
    (f, password)
}

#[test]
#[ignore = "REAL YUBIKEY: XC4.0/4.1 fixture read, and failclosed unsupported4.0 save"]
fn disposable_xc_fixture_open() {
    let root = opt_in();
    let (f, password) = xc_fixture(&root);
    assert!(db::unlock_database(&f.path(), &password, None).is_err());
    let mut app = native_app(&f, None, &password);
    if app.kdbx.as_ref().unwrap().config.version == keepass::config::DatabaseVersion::KDB4(0) {
        let before = fs::read(f.path()).unwrap();
        draft(&mut app);
        save_draft(&mut app);
        assert_eq!(
            app.screen,
            Screen::Edit,
            "KDBX4.0 must not silently convert"
        );
        assert_eq!(fs::read(f.path()).unwrap(), before);
        assert!(
            app.status
                .as_ref()
                .unwrap()
                .to_ascii_lowercase()
                .contains("unsupported"),
            "{:?}",
            app.status
        );
        eprintln!(
            "XC KDBX4.0 authenticated; native save unsupported, unchanged primary and retained editor verified. NOT full read/write interoperability."
        );
    }
}

#[test]
#[ignore = "REAL YUBIKEY: newly XC-created synthetic-xc.kdbx4.1 only; many touches"]
fn disposable_xc_fixture_roundtrip() {
    let root = opt_in();
    let (f, password) = xc_fixture(&root);
    let mut app = native_app(&f, None, &password);
    assert_eq!(
        app.kdbx.as_ref().unwrap().config.version,
        keepass::config::DatabaseVersion::KDB4(1),
        "upstream cannot save XC KDBX4.0; no implicit conversion"
    );
    draft(&mut app);
    save_draft(&mut app);
    assert_eq!(app.screen, Screen::Index, "{:?}", app.status);
    rekey(&mut app, &password, "new synthetic master");
    assert!(
        app.status
            .as_ref()
            .unwrap()
            .contains("master password changed")
    );
    export_for_xc(&mut app, &root, None);
}

fn wrong_slot_rejected(result: &anyhow::Result<keepass::Database>) -> bool {
    // KDBX4 emits IncorrectKey only at header-HMAC validation, after the
    // configured challenge has completed. USB/discovery/deadline/cancellation
    // failures cannot establish wrong-slot authentication rejection.
    matches!(
        result
            .as_ref()
            .err()
            .and_then(|err| err.downcast_ref::<keepass::error::DatabaseOpenError>()),
        Some(keepass::error::DatabaseOpenError::Key(
            keepass::error::DatabaseKeyError::IncorrectKey
        ))
    )
}

#[test]
fn wrong_slot_oracle_rejects_infrastructure_errors() {
    use challenge_response::error::ChallengeResponseError;
    use keepass::error::{ChallengeResponseKeyError, DatabaseKeyError, DatabaseOpenError};
    let mut errors: Vec<anyhow::Error> = vec![
        ChallengeResponseKeyError::NoKeys.into(),
        ChallengeResponseKeyError::KeyNotFound(TOKEN.serial).into(),
        ChallengeResponseError::Cancelled.into(),
        ChallengeResponseError::DeadlineExceeded.into(),
        std::io::Error::from(std::io::ErrorKind::PermissionDenied).into(),
        std::io::Error::from(std::io::ErrorKind::NotConnected).into(),
        DatabaseOpenError::UnexpectedEof.into(),
        DatabaseOpenError::Key(DatabaseKeyError::EmptyKey).into(),
        anyhow::anyhow!("Incorrect key"), // display text is not a typed authentication result
    ];
    errors.extend(
        [
            ChallengeResponseError::Cancelled,
            ChallengeResponseError::DeadlineExceeded,
            ChallengeResponseError::DeviceNotFound,
            ChallengeResponseError::CommandNotSupported,
        ]
        .into_iter()
        .map(|err| {
            anyhow::Error::new(DatabaseOpenError::Key(DatabaseKeyError::ChallengeResponse(
                ChallengeResponseKeyError::Api(err),
            )))
        }),
    );
    for error in errors {
        let result = Err(error.context("wrong-slot open"));
        assert!(
            !wrong_slot_rejected(&result),
            "infrastructure/malformed input must be failure/inconclusive, not acceptance: {:#}",
            result.as_ref().err().unwrap()
        );
    }
    assert!(!wrong_slot_rejected(&Ok(keepass::Database::new())));
    let incorrect = Err(
        anyhow::Error::new(DatabaseOpenError::Key(DatabaseKeyError::IncorrectKey))
            .context("wrong-slot open"),
    );
    assert!(wrong_slot_rejected(&incorrect));

    // Exercise the same typed oracle with real KDBX4 header HMAC validation:
    // a different software challenge secret completes, then fails authentication.
    // This proves oracle wiring only, not physical slot/touch behavior.
    let key = |secret: String| {
        keepass::DatabaseKey::new()
            .with_password("synthetic master")
            .with_challenge_response_key(keepass::ChallengeResponseKey::LocalChallenge(secret))
    };
    let correct = key("11".repeat(20));
    let mut bytes = Vec::new();
    db::save_with_key(&keepass::Database::new(), &mut bytes, &correct).unwrap();
    let opened = db::open_with_key(&mut &bytes[..], &correct);
    assert!(
        opened.is_ok(),
        "matching software challenge must authenticate"
    );
    assert!(!wrong_slot_rejected(&opened));
    assert!(wrong_slot_rejected(&db::open_with_key(
        &mut &bytes[..],
        &key("22".repeat(20))
    )));
    assert!(!wrong_slot_rejected(&db::open_with_key(
        &mut &bytes[..],
        &key("not hex".into())
    )));
}

#[test]
#[ignore = "REAL YUBIKEY: wrong SLOT1 needs a completed challenge; separate explicit authorization"]
fn disposable_hardware_wrong_slot() {
    opt_in();
    assert_eq!(std::env::var("JAIBA_TEST_WRONG_SLOT").as_deref(), Ok("1"));
    let f = Fixture::new();
    db::create_database_with_yubikey(&f.path(), "synthetic master", None, Some(TOKEN)).unwrap();
    let key = db::build_database_key_with_yubikey(
        "synthetic master",
        None,
        Some(YubikeyConfig { slot: 1, ..TOKEN }),
    )
    .expect("wrong-slot selection/discovery failed: INCONCLUSIVE, not wrong-key rejection");
    let result = db::open_with_key(&mut fs::File::open(f.path()).unwrap(), &key);
    assert!(
        wrong_slot_rejected(&result),
        "expected completed challenge and typed IncorrectKey; infrastructure errors are INCONCLUSIVE: {:?}",
        result.err()
    );
}

#[test]
#[ignore = "REAL YUBIKEY: withhold touch for three native 30-second deadlines; verify resource counts"]
fn disposable_hardware_no_touch_deadline() {
    opt_in();
    let f = Fixture::new();
    db::create_database_with_yubikey(&f.path(), "synthetic master", None, Some(TOKEN)).unwrap();
    let mut app = native_app(&f, None, "synthetic master");
    draft(&mut app);
    let count = |name: &str| fs::read_dir(format!("/proc/self/{name}")).unwrap().count();
    let before = (count("fd"), count("task"));
    eprintln!(
        "NO-TOUCH PHASE: release key and withhold touch for three 30-second attempts. No SIGUSR2 is sent."
    );
    std::thread::sleep(Duration::from_millis(500));
    for attempt in 1..=3 {
        let started = Instant::now();
        let result = db::open_with_key(
            &mut fs::File::open(f.path()).unwrap(),
            app.db_key.as_ref().unwrap(),
        );
        assert!(
            result.is_err(),
            "unexpected completion/touch is inconclusive"
        );
        assert!(format!("{:#}", result.err().unwrap()).contains("deadline"));
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_secs(29) && elapsed < Duration::from_secs(33),
            "unexpected native deadline timing {elapsed:?}"
        );
        assert_eq!(
            (count("fd"), count("task")),
            before,
            "native resource growth after timeout {attempt}"
        );
        assert_eq!(app.field_buffer, "synthetic partial notes");
        eprintln!("NO-TOUCH attempt {attempt}: {elapsed:?}; resources returned to baseline");
    }
}

#[test]
#[ignore = "REAL YUBIKEY: withhold touch during native open; SIGUSR2 must cancel and release interface"]
fn disposable_hardware_stalled_signal() {
    let root = opt_in();
    let f = Fixture::new();
    db::create_database_with_yubikey(&f.path(), "synthetic master", None, Some(TOKEN)).unwrap();
    let mut app = native_app(&f, None, "synthetic master");
    draft(&mut app);
    let mut registration = crate::locking::Registration::for_test(&f.0).unwrap();
    let registry = f.0.join("vault-tui-lock");
    let pid = std::process::id();
    let mut request = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(registry.join(format!("jaiba.{pid}.request")))
        .unwrap();
    request
        .write_all(b"abcdef0123456789abcdef0123456789")
        .unwrap();
    request.sync_all().unwrap();
    eprintln!("STALLED PHASE: release key and DO NOT TOUCH. SIGUSR2 arrives in 500ms.");
    let sender = std::thread::spawn(|| {
        std::thread::sleep(Duration::from_millis(500));
        assert_eq!(unsafe { libc::kill(libc::getpid(), libc::SIGUSR2) }, 0);
    });
    let started = Instant::now();
    let result = db::open_with_key(
        &mut fs::File::open(f.path()).unwrap(),
        app.db_key.as_ref().unwrap(),
    );
    sender.join().unwrap();
    assert!(
        result.is_err(),
        "a touch/unexpected completion makes this attempt inconclusive"
    );
    assert!(format!("{:#}", result.err().unwrap()).contains("cancelled"));
    registration.process(&mut app).unwrap();
    let ack: serde_json::Value =
        serde_json::from_slice(&fs::read(registry.join(format!("jaiba.{pid}.ack"))).unwrap())
            .unwrap();
    assert_eq!(ack["nonce"], "abcdef0123456789abcdef0123456789");
    assert_eq!(ack["locked"], true);
    assert_eq!(ack["draft_persisted"], false);
    assert_eq!(app.screen, Screen::Login);
    assert!(app.db_key.is_none() && app.kdbx.is_none() && app.pending_draft.is_some());
    let cancel_elapsed = started.elapsed();
    assert!(
        cancel_elapsed < Duration::from_secs(2),
        "native cancellation exceeded target; NOT a pass"
    );
    eprintln!("STALLED CANCEL COMPLETE: now provide touches for full-factor reauthentication.");
    authenticate(&mut app, "synthetic master");
    assert_eq!(app.screen, Screen::Edit, "{:?}", app.login_error);
    assert_eq!(app.field_buffer, "synthetic partial notes");
    let report = serde_json::json!({"cancel_and_lock_seconds":cancel_elapsed.as_secs_f64(), "ack":ack, "production_qualification":false});
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join(format!("jaiba-stalled-signal-{pid}.json")))
        .unwrap();
    serde_json::to_writer_pretty(&mut output, &report).unwrap();
    output.sync_all().unwrap();
}

#[test]
#[ignore = "REAL YUBIKEY: save timing and fail-closed memory-only SIGUSR2 ack timing"]
fn disposable_hardware_timing() {
    let root = opt_in();
    let f = Fixture::new();
    let key = db::build_database_key_with_yubikey("synthetic master", None, Some(TOKEN)).unwrap();
    let mut database = keepass::Database::new();
    let profile = std::env::var("JAIBA_YUBIKEY_KDF").unwrap_or_else(|_| "representative".into());
    if profile == "strong" {
        let keepass::config::KdfConfig::Argon2 { version, .. } = database.config.kdf_config else {
            panic!("default Argon2 version unavailable")
        };
        let iterations: u64 = std::env::var("JAIBA_YUBIKEY_ITERATIONS")
            .unwrap_or_else(|_| "3".into())
            .parse()
            .unwrap();
        assert!((1..=10000).contains(&iterations));
        database.config.kdf_config = keepass::config::KdfConfig::Argon2id {
            iterations,
            memory: 64 * 1024 * 1024,
            parallelism: 4,
            version,
        };
    } else {
        assert_eq!(profile, "representative");
    }
    let label = format!("{:?}", database.config.kdf_config);
    eprintln!("TIMING KDF {label}; provide separate touches for each challenge");
    db::save_database(&f.path(), &key, &mut database, &mut []).unwrap();
    drop(key);
    drop(database);
    let mut app = native_app(&f, None, "synthetic master");
    draft(&mut app);
    let started = Instant::now();
    save_draft(&mut app);
    let save_elapsed = started.elapsed();
    assert_eq!(app.screen, Screen::Index, "{:?}", app.status);
    draft(&mut app);
    let mut registration = crate::locking::Registration::for_test(&f.0).unwrap();
    let registry = f.0.join("vault-tui-lock");
    let pid = std::process::id();
    let nonce = "0123456789abcdef0123456789abcdef";
    let mut request = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(registry.join(format!("jaiba.{pid}.request")))
        .unwrap();
    request.write_all(nonce.as_bytes()).unwrap();
    request.sync_all().unwrap();
    let started = Instant::now();
    // SAFETY: for_test installed the normal async-signal-safe SIGUSR2 handler.
    assert_eq!(unsafe { libc::raise(libc::SIGUSR2) }, 0);
    registration.process(&mut app).unwrap();
    let ack: serde_json::Value =
        serde_json::from_slice(&fs::read(registry.join(format!("jaiba.{pid}.ack"))).unwrap())
            .unwrap();
    let lock_elapsed = started.elapsed();
    // Assert application state AFTER reading the exact emitted ack.
    assert_eq!(ack["nonce"], nonce);
    assert_eq!(ack["locked"], true);
    assert_eq!(ack["draft_persisted"], false);
    assert_eq!(app.screen, Screen::Login);
    assert!(app.db_key.is_none() && app.kdbx.is_none() && app.entries.is_empty());
    assert!(app.pending_draft.is_some() && !app.draft_durable);
    let report = serde_json::json!({ "lock_policy":"memory_only_no_new_hardware_at_signal_lock", "kdf":label, "save_seconds":save_elapsed.as_secs_f64(), "lock_seconds":lock_elapsed.as_secs_f64(), "controller_threshold_seconds":18, "within_threshold":lock_elapsed <= Duration::from_secs(18), "ack":ack, "production_qualification":false });
    eprintln!("TIMING {report}");
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join(format!("jaiba-hardware-timing-{pid}.json")))
        .unwrap();
    serde_json::to_writer_pretty(&mut output, &report).unwrap();
    output.sync_all().unwrap();
    assert!(
        lock_elapsed <= Duration::from_secs(18),
        "R4 18-second threshold exceeded; this is NOT successful controller qualification"
    );
}
