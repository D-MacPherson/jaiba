//! Synthetic offline regressions. Hardware tests are explicit and ignored.
#[path = "yubikey_discovery_tests.rs"]
mod discovery;
#[path = "yubikey_hardware_tests.rs"]
mod hardware;
use crate::app::{App, Screen};
use crate::config::YubikeyConfig;
use crate::{db, input};
use crossterm::event::KeyCode;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const TOKEN: YubikeyConfig = YubikeyConfig {
    slot: 2,
    serial: 39269826,
};
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt;
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "jaiba-yubi-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        Self(dir)
    }
    fn path(&self) -> PathBuf {
        self.0.join("synthetic.kdbx")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn authenticate(app: &mut App, password: &str) {
    app.password = password.into();
    input::login::handle_login_input(app, KeyCode::Enter);
}

fn synthetic_app(f: &Fixture, keyfile: Option<PathBuf>) -> App {
    let key =
        db::build_database_key_with_yubikey("synthetic master", keyfile.as_deref(), Some(TOKEN))
            .unwrap();
    let mut database = keepass::Database::new();
    db::save_database(&f.path(), &key, &mut database, &mut []).unwrap();
    let mut app = App::for_test(Some(f.path()));
    app.screen = Screen::Login;
    app.config.yubikey = Some(TOKEN);
    app.config.keyfile = keyfile;
    authenticate(&mut app, "synthetic master");
    assert_eq!(app.screen, Screen::Index, "{:?}", app.login_error);
    app
}

fn rekey(app: &mut App, old: &str, new: &str) {
    app.screen = Screen::Settings;
    app.changing_password = true;
    app.password_change_step = crate::app::PasswordChangeStep::CurrentPassword;
    app.current_password_buffer = old.into();
    input::settings::handle_settings_input(app, KeyCode::Enter);
    assert!(
        matches!(
            app.password_change_step,
            crate::app::PasswordChangeStep::NewPassword
        ),
        "{:?}",
        app.status
    );
    app.new_password_buffer = new.into();
    input::settings::handle_settings_input(app, KeyCode::Enter);
    app.new_password_confirm = new.into();
    input::settings::handle_settings_input(app, KeyCode::Enter);
}

fn draft(app: &mut App) {
    app.screen = Screen::Edit;
    app.edit_entry = Some(db::Entry {
        name: "synthetic entry".into(),
        password: "synthetic secret".into(),
        ..Default::default()
    });
    app.edit_original = Some(Default::default());
    app.edit_state.select(Some(5));
    app.editing_field = true;
    app.field_buffer = "synthetic partial notes".into();
}
fn save_draft(app: &mut App) {
    if app.editing_field {
        input::edit::handle_edit_input(app, KeyCode::Enter);
    }
    input::edit::handle_edit_input(app, KeyCode::Esc);
    input::edit::handle_edit_input(app, KeyCode::Char('y'));
}

#[test]
fn native_discovery_unreadable_candidates_do_not_hide_selected_serial() {
    use challenge_response::ChallengeResponse;
    use challenge_response::test_support::{Discovery, SerialRead};
    for reads in [
        vec![SerialRead::Denied, SerialRead::Serial(TOKEN.serial)],
        vec![SerialRead::Serial(TOKEN.serial), SerialRead::Denied],
    ] {
        let _io = Discovery::new(reads);
        let mut native = ChallengeResponse::new().unwrap();
        let all = native
            .find_all_devices()
            .expect("ordinary per-device failure is isolated");
        assert_eq!(all.len(), 2);
        assert_eq!(
            all.iter()
                .filter(|d| d.serial == Some(TOKEN.serial))
                .count(),
            1
        );
        assert_eq!(all.iter().filter(|d| d.serial.is_none()).count(), 1);
        assert_eq!(
            native.find_device_from_serial(TOKEN.serial).unwrap().serial,
            Some(TOKEN.serial)
        );
        // This is the real app builder, not the LocalChallenge model.
        assert!(db::build_database_key_with_yubikey("synthetic master", None, Some(TOKEN)).is_ok());
    }
}

#[test]
fn native_discovery_no_match_preserves_unreadable_diagnostic() {
    use challenge_response::{
        ChallengeResponse,
        error::ChallengeResponseError,
        test_support::{Discovery, SerialRead},
    };
    for reads in [
        vec![SerialRead::Denied],
        vec![SerialRead::Serial(7), SerialRead::Denied],
    ] {
        let _io = Discovery::new(reads);
        let error = ChallengeResponse::new()
            .unwrap()
            .find_device_from_serial(TOKEN.serial)
            .unwrap_err();
        assert!(
            matches!(error, ChallengeResponseError::IOError(ref e) if e.kind() == std::io::ErrorKind::PermissionDenied),
            "{error}"
        );
        let error =
            db::build_database_key_with_yubikey("synthetic master", None, Some(TOKEN)).unwrap_err();
        assert!(
            format!("{error:#}").contains("synthetic serial access denied"),
            "{error:#}"
        );
    }
}

#[test]
fn native_discovery_checks_cancellation_before_error_disposition() {
    use challenge_response::{
        operation::Cancellation,
        test_support::{Discovery, SerialRead, backend_discovery},
    };
    use std::sync::{Arc, atomic::AtomicBool};
    for serial in [None, Some(TOKEN.serial)] {
        for result in [SerialRead::Denied, SerialRead::Serial(TOKEN.serial)] {
            let flag = Arc::new(AtomicBool::new(false));
            let _cancel = Cancellation::install(Arc::clone(&flag));
            let _io = Discovery::new(vec![SerialRead::CancelDuring(flag, Box::new(result))]);
            let error = backend_discovery(serial)
                .expect_err("backend must check actual I/O before disposition");
            assert!(
                matches!(
                    error,
                    challenge_response::error::ChallengeResponseError::Cancelled
                ),
                "{error}"
            );
        }
    }
}

#[test]
fn native_discovery_checks_enumeration_before_error_disposition() {
    use challenge_response::{
        error::ChallengeResponseError,
        operation::Cancellation,
        test_support::{Discovery, SerialRead, backend_discovery},
    };
    use std::sync::{Arc, atomic::AtomicBool};
    for serial in [None, Some(TOKEN.serial)] {
        let flag = Arc::new(AtomicBool::new(false));
        let _cancel = Cancellation::install(Arc::clone(&flag));
        let _io = Discovery::with_enumeration(
            vec![SerialRead::Serial(TOKEN.serial)],
            Some(SerialRead::CancelDuring(flag, Box::new(SerialRead::Denied))),
        );
        let error = backend_discovery(serial).unwrap_err();
        assert!(
            matches!(error, ChallengeResponseError::Cancelled),
            "{error}"
        );
    }
}

#[test]
fn password_only_lock_is_not_failed_by_an_expired_unused_usb_budget() {
    let f = Fixture::new();
    db::create_database(&f.path(), "synthetic master", None).unwrap();
    let mut app = App::for_test(Some(f.path()));
    app.screen = Screen::Login;
    authenticate(&mut app, "synthetic master");
    assert_eq!(app.screen, Screen::Index);
    draft(&mut app);
    let _usb_budget =
        challenge_response::operation::Operation::new(std::time::Duration::from_millis(1));
    std::thread::sleep(std::time::Duration::from_millis(3));
    assert!(
        app.lock_cooperatively(),
        "password-only draft persistence must retain its existing verified-success behavior"
    );
    assert!(app.db_key.is_none() && app.pending_draft.is_none() && app.draft_durable);
}

#[test]
fn cancelled_lock_revokes_credentials_without_new_persistence_io() {
    use std::sync::{Arc, atomic::AtomicBool};
    let _model = crate::yubikey_test_backend::Model::new(TOKEN);
    let f = Fixture::new();
    let mut app = synthetic_app(&f, None);
    draft(&mut app);
    let names = || {
        let mut n: Vec<_> = fs::read_dir(&f.0)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        n.sort();
        n
    };
    let before = names();
    let _cancel =
        challenge_response::operation::Cancellation::install(Arc::new(AtomicBool::new(true)));
    assert!(!app.lock_cooperatively());
    assert_eq!(app.screen, Screen::Login);
    assert!(app.db_key.is_none() && app.kdbx.is_none() && app.pending_draft.is_some());
    assert_eq!(
        names(),
        before,
        "a cancelled lock must not begin a draft transaction before revocation"
    );
}

#[test]
fn late_cancellation_cannot_install_successful_authentication_over_memory_draft() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    let model = crate::yubikey_test_backend::Model::new(TOKEN);
    let f = Fixture::new();
    let mut app = synthetic_app(&f, None);
    draft(&mut app);
    model.unavailable(true);
    assert!(!app.lock_cooperatively());
    model.unavailable(false);
    let flag = Arc::new(AtomicBool::new(false));
    let _cancel = challenge_response::operation::Cancellation::install(Arc::clone(&flag));
    db::test_fault::CANCEL_UNLOCK.with(|f| *f.borrow_mut() = Some(Arc::clone(&flag)));
    authenticate(&mut app, "synthetic master");
    assert_eq!(app.screen, Screen::Login);
    assert!(app.pending_draft.is_some() && app.db_key.is_none() && app.kdbx.is_none());
    flag.store(false, Ordering::SeqCst);
    authenticate(&mut app, "synthetic master");
    assert_eq!(app.screen, Screen::Edit, "{:?}", app.login_error);
    assert_eq!(app.field_buffer, "synthetic partial notes");
}

#[test]
fn native_cancel_after_successful_transfer_cleans_all_claims_without_late_success() {
    for _ in 0..30 {
        let (error, active, closed, aborted) =
            challenge_response::test_support::cancelled_session();
        assert!(
            error.contains("cancelled"),
            "cleanup must not mask original cancellation: {error}"
        );
        assert_eq!((active, closed, aborted), (0, 1, 1));
    }
}

#[test]
fn native_nested_scopes_share_deadline_and_reject_bad_reports() {
    use challenge_response::operation::{Cancellation, Operation};
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };
    let outer = Operation::new(Duration::from_millis(15));
    std::thread::sleep(Duration::from_millis(20));
    {
        let _nested = Operation::standard();
        let (result, reads) = challenge_response::test_support::stalled_wait(Duration::ZERO, 5);
        assert!(result.unwrap_err().to_string().contains("deadline"));
        assert_eq!(reads, 0, "nested scope must not renew exhausted budget");
    }
    drop(outer);
    assert!(challenge_response::operation::check().is_ok());
    let flag = Arc::new(AtomicBool::new(true));
    let _cancel = Cancellation::install(Arc::clone(&flag));
    let mut native = challenge_response::ChallengeResponse::new().unwrap();
    assert!(
        native
            .find_device_from_serial(u32::MAX)
            .unwrap_err()
            .to_string()
            .contains("cancelled")
    );
    flag.store(false, Ordering::SeqCst);
    assert!(
        !native
            .find_device_from_serial(u32::MAX)
            .unwrap_err()
            .to_string()
            .contains("cancelled")
    );
    assert!(challenge_response::test_support::short_report().is_err());
    assert!(challenge_response::test_support::otp_interface(0, 3, 1, 1));
    for descriptor in [(1, 3, 0, 0), (2, 11, 0, 0), (0, 3, 0, 0), (1, 3, 1, 1)] {
        assert!(!challenge_response::test_support::otp_interface(
            descriptor.0,
            descriptor.1,
            descriptor.2,
            descriptor.3
        ));
    }
}

#[test]
fn native_signal_cancellation_and_lock_run_in_private_subprocess() {
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "yubikey_tests::native_signal_child",
            "--nocapture",
        ])
        .env("JAIBA_BOUNDED_CHILD", "1")
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
#[ignore = "subprocess-only signal fixture; invoked by native_signal_cancellation_and_lock_run_in_private_subprocess"]
fn native_signal_child() {
    assert_eq!(std::env::var("JAIBA_BOUNDED_CHILD").as_deref(), Ok("1"));
    use std::{
        os::unix::fs::PermissionsExt,
        time::{Duration, Instant},
    };
    let _model = crate::yubikey_test_backend::Model::new(TOKEN);
    let f = Fixture::new();
    let mut app = synthetic_app(&f, None);
    draft(&mut app);
    let mut reg = crate::locking::Registration::for_test(&f.0).unwrap();
    let registry = f.0.join("vault-tui-lock");
    let request = registry.join(format!("jaiba.{}.request", std::process::id()));
    let ack = registry.join(format!("jaiba.{}.ack", std::process::id()));
    fs::write(&request, b"1234567890abcdef1234567890abcdef").unwrap();
    fs::set_permissions(&request, fs::Permissions::from_mode(0o600)).unwrap();
    let sender = std::thread::spawn(|| {
        std::thread::sleep(Duration::from_millis(40));
        unsafe {
            libc::kill(libc::getpid(), libc::SIGUSR2);
        }
    });
    let started = Instant::now();
    // The exact vendored protocol loop, not the software HMAC hook, is stalled.
    let key_clone = app.db_key.clone();
    let (result, _) = challenge_response::test_support::stalled_wait(Duration::from_millis(2), 200);
    drop(key_clone);
    sender.join().unwrap();
    assert!(result.unwrap_err().to_string().contains("cancelled"));
    assert!(started.elapsed() < Duration::from_millis(250));
    assert!(!ack.exists(), "signal receipt is not an acknowledgement");
    reg.process(&mut app).unwrap();
    assert_eq!(app.screen, Screen::Login);
    assert!(app.db_key.is_none() && app.kdbx.is_none());
    assert!(app.pending_draft.is_some() && !app.draft_durable);
    let value: serde_json::Value = serde_json::from_slice(&fs::read(&ack).unwrap()).unwrap();
    assert_eq!(value["draft_persisted"], false);
    assert_eq!(value["locked"], true);
    assert!(started.elapsed() < Duration::from_secs(1));
    authenticate(&mut app, "synthetic master");
    assert_eq!(app.screen, Screen::Edit, "{:?}", app.login_error);
    assert_eq!(app.field_buffer, "synthetic partial notes");
    // Missing, invalid and replayed requests can interrupt work, but cannot
    // authorize a lock/ack or permanently poison subsequent authentication.
    for contents in [
        None,
        Some("malformed"),
        Some("1234567890abcdef1234567890abcdef"),
    ] {
        if let Some(text) = contents {
            fs::write(&request, text).unwrap();
        } else {
            fs::remove_file(&request).unwrap();
        }
        let sender = std::thread::spawn(|| {
            std::thread::sleep(Duration::from_millis(20));
            unsafe {
                libc::kill(libc::getpid(), libc::SIGUSR2);
            }
        });
        let (result, _) =
            challenge_response::test_support::stalled_wait(Duration::from_millis(2), 200);
        sender.join().unwrap();
        assert!(result.unwrap_err().to_string().contains("cancelled"));
        let old_ack = fs::read(&ack).unwrap();
        let _ = reg.process(&mut app);
        assert_eq!(app.screen, Screen::Edit);
        assert_eq!(fs::read(&ack).unwrap(), old_ack);
        assert!(challenge_response::operation::check().is_ok());
    }
    // Exact resource counts after warmup: no per-attempt native/application workers.
    let count = |name: &str| fs::read_dir(format!("/proc/self/{name}")).unwrap().count();
    let mut native = challenge_response::ChallengeResponse::new().unwrap();
    assert!(native.find_device_from_serial(u32::MAX).is_err()); // sandbox has no USB
    let before = (count("fd"), count("task"));
    for _ in 0..20 {
        let _budget = challenge_response::operation::Operation::new(Duration::from_millis(8));
        let (result, _) =
            challenge_response::test_support::stalled_wait(Duration::from_millis(1), 200);
        assert!(result.unwrap_err().to_string().contains("deadline"));
    }
    assert_eq!((count("fd"), count("task")), before);
}

#[test]
fn native_protocol_rejects_overlong_response_without_panicking() {
    assert!(challenge_response::test_support::overlong_response().is_err());
}

#[test]
fn native_protocol_has_a_finite_default_deadline_without_a_signal() {
    let started = std::time::Instant::now();
    let (result, reads) =
        challenge_response::test_support::stalled_wait(std::time::Duration::from_millis(350), 100);
    assert!(
        reads < 100,
        "native polling exhausted backend rather than its own deadline: {result:?}"
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(32));
}

#[test]
fn creation_receipt_distinguishes_uncommitted_and_committed_unverified() {
    for boundary in 1..=4 {
        let model = crate::yubikey_test_backend::Model::new(TOKEN);
        let f = Fixture::new();
        let mut app = App::for_test(Some(f.path()));
        app.screen = Screen::Login;
        app.config.yubikey = Some(TOKEN);
        input::login::handle_login_input(&mut app, KeyCode::Char('n'));
        app.password = "synthetic master".into();
        input::login::handle_login_input(&mut app, KeyCode::Enter);
        app.new_db_confirm = "synthetic master".into();
        model.fail_after(boundary);
        input::login::handle_login_input(&mut app, KeyCode::Enter);
        let message = app.login_error.as_deref().unwrap();
        if boundary >= 3 {
            assert!(f.path().exists());
            assert!(
                message.contains("created") && message.contains("not verified"),
                "{message}"
            );
            assert!(
                !app.creating_database,
                "must offer authentication, not create retry"
            );
            model.clear_fault();
            authenticate(&mut app, "synthetic master");
            assert_eq!(app.screen, Screen::Index, "{:?}", app.login_error);
        } else {
            assert!(!f.path().exists());
            assert!(message.contains("Couldn't create"), "{message}");
        }
    }
}

#[test]
fn export_receipt_distinguishes_uncommitted_and_committed_unverified() {
    for boundary in 1..=3 {
        let model = crate::yubikey_test_backend::Model::new(TOKEN);
        let f = Fixture::new();
        let mut app = synthetic_app(&f, None);
        let target = f.0.join("existing-export.kdbx");
        fs::write(&target, b"previous synthetic target").unwrap();
        app.screen = Screen::Settings;
        app.exporting_database = true;
        app.export_step = crate::app::ExportStep::Confirm;
        app.pending_export_path = Some(target.clone());
        model.fail_after(boundary);
        input::settings::handle_settings_input(&mut app, KeyCode::Enter);
        let message = app.status.as_deref().unwrap();
        if boundary == 3 {
            assert_ne!(fs::read(&target).unwrap(), b"previous synthetic target");
            assert!(
                message.contains("replaced") && message.contains("not verified"),
                "{message}"
            );
            model.clear_fault();
            assert!(
                db::unlock_database_snapshot_with_yubikey(
                    &target,
                    "synthetic master",
                    None,
                    Some(TOKEN)
                )
                .is_ok()
            );
        } else {
            assert_eq!(fs::read(&target).unwrap(), b"previous synthetic target");
            assert!(message.contains("couldn't export"), "{message}");
        }
    }
}

#[test]
fn malformed_outer_scalar_preserves_memory_draft_and_allows_login_retry() {
    let model = crate::yubikey_test_backend::Model::new(TOKEN);
    let f = Fixture::new();
    let mut app = synthetic_app(&f, None);
    let good = fs::read(f.path()).unwrap();
    draft(&mut app);
    model.unavailable(true);
    assert!(!app.lock_cooperatively());
    model.unavailable(false);
    // Compression scalar has zero bytes: upstream read_u32 panics.
    let mut malformed = vec![0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5, 1, 0, 4, 0];
    malformed.extend([3, 0, 0, 0, 0]);
    malformed.extend([0, 4, 0, 0, 0, 13, 10, 13, 10]);
    fs::write(f.path(), malformed).unwrap();
    authenticate(&mut app, "synthetic master");
    assert_eq!(app.screen, Screen::Login);
    assert!(app.pending_draft.is_some());
    assert!(app.db_key.is_none() && app.kdbx.is_none());
    fs::write(f.path(), good).unwrap();
    authenticate(&mut app, "synthetic master");
    assert_eq!(app.screen, Screen::Edit, "{:?}", app.login_error);
    assert_eq!(app.field_buffer, "synthetic partial notes");
}

#[test]
fn independent_save_verification_requires_available_hardware_before_replacement() {
    let model = crate::yubikey_test_backend::Model::new(TOKEN);
    let f = Fixture::new();
    let mut app = synthetic_app(&f, None);
    let original = fs::read(f.path()).unwrap();
    draft(&mut app);
    model.fail_after(2); // save succeeds; independent staged decrypt loses hardware
    save_draft(&mut app);
    assert_eq!(app.screen, Screen::Edit, "must not confirm unverified save");
    assert_eq!(fs::read(f.path()).unwrap(), original);
    assert!(app.edit_entry.is_some());
    model.clear_fault();
    save_draft(&mut app);
    assert_eq!(app.screen, Screen::Index, "{:?}", app.status);
}

#[test]
fn create_handler_preserves_all_configured_factors() {
    let _model = crate::yubikey_test_backend::Model::new(TOKEN);
    let f = Fixture::new();
    let keyfile = f.0.join("create.key");
    fs::write(&keyfile, b"synthetic creation keyfile").unwrap();
    let mut app = App::for_test(Some(f.path()));
    app.screen = Screen::Login;
    app.config.yubikey = Some(TOKEN);
    app.config.keyfile = Some(keyfile.clone());
    input::login::handle_login_input(&mut app, KeyCode::Char('n'));
    app.password = "synthetic master".into();
    input::login::handle_login_input(&mut app, KeyCode::Enter);
    app.new_db_confirm = "synthetic master".into();
    input::login::handle_login_input(&mut app, KeyCode::Enter);
    assert_eq!(app.screen, Screen::Index, "{:?}", app.login_error);
    assert!(
        db::unlock_database(&f.path(), "synthetic master", Some(&keyfile)).is_err(),
        "new vault must require hardware"
    );
    assert_eq!(app.database_yubikey(), Some(TOKEN));
    assert!(app.lock_cooperatively());
    app.config.yubikey = None;
    authenticate(&mut app, "synthetic master");
    assert_eq!(app.screen, Screen::Index, "{:?}", app.login_error);
}

#[test]
fn password_change_preserves_pinned_hardware_and_keyfile() {
    let _model = crate::yubikey_test_backend::Model::new(TOKEN);
    let f = Fixture::new();
    let keyfile = f.0.join("synthetic.key");
    fs::write(&keyfile, b"synthetic keyfile material for factor retention").unwrap();
    let mut app = synthetic_app(&f, Some(keyfile.clone()));
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
    assert!(
        db::unlock_database_snapshot_with_yubikey(
            &f.path(),
            "new synthetic master",
            Some(&keyfile),
            Some(TOKEN)
        )
        .is_ok()
    );
    assert!(db::unlock_database(&f.path(), "new synthetic master", Some(&keyfile)).is_err());
    assert!(
        db::unlock_database_snapshot_with_yubikey(
            &f.path(),
            "new synthetic master",
            None,
            Some(TOKEN)
        )
        .is_err()
    );
    assert!(
        db::unlock_database_snapshot_with_yubikey(
            &f.path(),
            "synthetic master",
            Some(&keyfile),
            Some(TOKEN)
        )
        .is_err()
    );
}

#[test]
fn reauthentication_pins_hardware_even_if_preferences_change() {
    let _model = crate::yubikey_test_backend::Model::new(TOKEN);
    let f = Fixture::new();
    let mut app = synthetic_app(&f, None);
    app.config.yubikey = None;
    assert!(app.lock_cooperatively());
    authenticate(&mut app, "wrong synthetic master");
    assert_eq!(app.screen, Screen::Login);
    authenticate(&mut app, "synthetic master");
    assert_eq!(app.screen, Screen::Index, "{:?}", app.login_error);
}

#[test]
fn missing_hardware_at_lock_retains_memory_draft_and_erases_credentials() {
    let model = crate::yubikey_test_backend::Model::new(TOKEN);
    let f = Fixture::new();
    let mut app = synthetic_app(&f, None);
    draft(&mut app);
    let before = fs::read(f.path()).unwrap();
    model.unavailable(true);
    assert!(!app.lock_cooperatively());
    assert_eq!(app.screen, Screen::Login);
    assert!(app.db_key.is_none() && app.kdbx.is_none() && app.entries.is_empty());
    assert!(app.pending_draft.is_some() && !app.draft_durable);
    assert!(!app.lock_cooperatively());
    authenticate(&mut app, "synthetic master");
    assert_eq!(app.screen, Screen::Login);
    assert!(app.pending_draft.is_some());
    assert_eq!(fs::read(f.path()).unwrap(), before);
    model.unavailable(false);
    authenticate(&mut app, "wrong synthetic master");
    assert_eq!(app.screen, Screen::Login);
    assert!(app.pending_draft.is_some());
    authenticate(&mut app, "synthetic master");
    assert_eq!(app.screen, Screen::Edit, "{:?}", app.login_error);
    assert_eq!(app.field_buffer, "synthetic partial notes");
    save_draft(&mut app);
    assert_eq!(app.screen, Screen::Index, "{:?}", app.status);
}

#[test]
fn full_factor_sidecars_survive_restart_and_refuse_wrong_selection() {
    let model = crate::yubikey_test_backend::Model::new(TOKEN);
    let f = Fixture::new();
    let keyfile = f.0.join("draft.key");
    fs::write(&keyfile, b"synthetic recovery keyfile").unwrap();
    let mut app = synthetic_app(&f, Some(keyfile.clone()));
    draft(&mut app);
    let primary = fs::read(f.path()).unwrap();
    let count = model.operations();
    assert!(app.lock_cooperatively());
    assert_eq!(
        model.operations() - count,
        4,
        "primary auth + sidecar save + two independent decryptions"
    );
    let sidecar = fs::read_dir(crate::recovery::directory(&f.path()))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|x| x == "kdbx"))
        .unwrap();
    assert!(db::unlock_database(&sidecar, "synthetic master", Some(&keyfile)).is_err());
    let full = db::build_database_key_with_yubikey("synthetic master", Some(&keyfile), Some(TOKEN))
        .unwrap();
    let side = db::open_with_key(&mut fs::File::open(sidecar).unwrap(), &full).unwrap();
    let source = db::open_with_key(&mut fs::File::open(f.path()).unwrap(), &full).unwrap();
    assert_eq!(side.config.kdf_config, source.config.kdf_config);
    assert_eq!(fs::read(f.path()).unwrap(), primary);
    drop(app);
    for selection in [
        YubikeyConfig {
            serial: 39269827,
            ..TOKEN
        },
        YubikeyConfig { slot: 1, ..TOKEN },
    ] {
        let mut restarted = App::for_test(Some(f.path()));
        restarted.screen = Screen::Login;
        restarted.config.keyfile = Some(keyfile.clone());
        restarted.config.yubikey = Some(selection);
        authenticate(&mut restarted, "synthetic master");
        assert_eq!(restarted.screen, Screen::Login);
    }
    let mut restarted = App::for_test(Some(f.path()));
    restarted.screen = Screen::Login;
    restarted.config.keyfile = Some(keyfile);
    restarted.config.yubikey = Some(TOKEN);
    authenticate(&mut restarted, "synthetic master");
    assert_eq!(
        restarted.screen,
        Screen::Edit,
        "{:?}",
        restarted.login_error
    );
    assert_eq!(restarted.field_buffer, "synthetic partial notes");
    save_draft(&mut restarted);
    assert_eq!(restarted.screen, Screen::Index, "{:?}", restarted.status);
    let saved = db::open_with_key(&mut fs::File::open(f.path()).unwrap(), &full).unwrap();
    assert_eq!(saved.iter_all_entries().count(), 1);
}

#[test]
fn post_replacement_hardware_failure_retains_uncertain_editor_and_new_revision() {
    let model = crate::yubikey_test_backend::Model::new(TOKEN);
    let f = Fixture::new();
    let mut app = synthetic_app(&f, None);
    draft(&mut app);
    let original = fs::read(f.path()).unwrap();
    model.fail_after(3); // published-file independent verification
    save_draft(&mut app);
    assert_eq!(app.screen, Screen::Edit, "{:?}", app.status);
    assert_ne!(fs::read(f.path()).unwrap(), original);
    assert!(
        app.status
            .as_ref()
            .unwrap()
            .contains("could not be confirmed"),
        "{:?}",
        app.status
    );
    assert!(app.edit_entry.is_some());
    model.clear_fault();
    app.primary_revision
        .as_ref()
        .unwrap()
        .revalidate(&f.path())
        .unwrap();
    save_draft(&mut app);
    assert_eq!(app.screen, Screen::Index, "{:?}", app.status);
    let saved =
        db::unlock_database_snapshot_with_yubikey(&f.path(), "synthetic master", None, Some(TOKEN))
            .unwrap()
            .2;
    assert_eq!(saved.len(), 1);
}

#[test]
fn repeated_saves_and_kdbx_export_keep_factors_and_rechallenge() {
    let model = crate::yubikey_test_backend::Model::new(TOKEN);
    let f = Fixture::new();
    let mut app = synthetic_app(&f, None);
    draft(&mut app);
    let count = model.operations();
    save_draft(&mut app);
    assert_eq!(app.screen, Screen::Index);
    assert_eq!(
        model.operations() - count,
        3,
        "save + staged decrypt + published decrypt"
    );
    let first = fs::read(f.path()).unwrap();
    let transaction = app.begin_primary_write().unwrap();
    db::save_database_with_revision(
        &transaction.path,
        app.db_key.as_ref().unwrap(),
        app.kdbx.as_mut().unwrap(),
        &mut app.entries,
        &mut app.primary_revision,
    )
    .unwrap();
    drop(transaction);
    assert_ne!(
        fs::read(f.path()).unwrap(),
        first,
        "fresh seed/IV on every save"
    );
    app.screen = Screen::Settings;
    app.exporting_database = true;
    app.export_step = crate::app::ExportStep::Confirm;
    app.pending_export_path = Some(f.0.join("export.kdbx"));
    input::settings::handle_settings_input(&mut app, KeyCode::Enter);
    assert!(
        app.status.as_ref().unwrap().starts_with("exported"),
        "{:?}",
        app.status
    );
    assert!(db::unlock_database(&f.0.join("export.kdbx"), "synthetic master", None).is_err());
    assert!(
        db::unlock_database_snapshot_with_yubikey(
            &f.0.join("export.kdbx"),
            "synthetic master",
            None,
            Some(TOKEN)
        )
        .is_ok()
    );
}

#[test]
fn uncertain_rekey_retains_new_full_key_and_precise_error_for_hardware_failure() {
    let model = crate::yubikey_test_backend::Model::new(TOKEN);
    let f = Fixture::new();
    let mut app = synthetic_app(&f, None);
    model.fail_after(4); // current auth, encrypt, staged decrypt, published decrypt
    rekey(&mut app, "synthetic master", "new synthetic master");
    assert!(
        app.status
            .as_ref()
            .unwrap()
            .contains("could not be confirmed"),
        "{:?}",
        app.status
    );
    assert!(app.status.as_ref().unwrap().contains("YubiKey"));
    model.clear_fault();
    assert!(
        db::open_with_key(
            &mut fs::File::open(f.path()).unwrap(),
            app.db_key.as_ref().unwrap()
        )
        .is_ok()
    );
    assert!(
        db::unlock_database_snapshot_with_yubikey(
            &f.path(),
            "new synthetic master",
            None,
            Some(TOKEN)
        )
        .is_ok()
    );
    assert!(db::unlock_database(&f.path(), "new synthetic master", None).is_err());
    assert!(
        db::unlock_database_snapshot_with_yubikey(&f.path(), "synthetic master", None, Some(TOKEN))
            .is_err()
    );
    model.unavailable(true);
    app.changing_password = true;
    app.password_change_step = crate::app::PasswordChangeStep::CurrentPassword;
    app.current_password_buffer = "new synthetic master".into();
    input::settings::handle_settings_input(&mut app, KeyCode::Enter);
    assert!(
        app.status.as_ref().unwrap().contains("YubiKey"),
        "must not mislabel device failure as wrong password"
    );
    assert!(app.current_password_buffer.is_empty());
}

#[test]
fn unsupported_kdbx4_minor_save_does_not_convert_or_discard_editor() {
    let _model = crate::yubikey_test_backend::Model::new(TOKEN);
    let f = Fixture::new();
    let mut app = synthetic_app(&f, None);
    let before = fs::read(f.path()).unwrap();
    app.kdbx.as_mut().unwrap().config.version = keepass::config::DatabaseVersion::KDB4(0);
    draft(&mut app);
    save_draft(&mut app);
    assert_eq!(app.screen, Screen::Edit);
    assert_eq!(fs::read(f.path()).unwrap(), before);
    assert!(
        app.status
            .as_ref()
            .unwrap()
            .contains("Unsupported database version")
    );
}

#[test]
fn oversized_untrusted_kdf_seed_is_rejected_before_hardware_access() {
    let f = Fixture::new();
    let mut header = vec![0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5, 1, 0, 4, 0];
    let mut dictionary = vec![0, 1, 0x42];
    dictionary.extend(1_u32.to_le_bytes());
    dictionary.push(b'S');
    dictionary.extend(65_u32.to_le_bytes());
    dictionary.extend([7_u8; 65]);
    dictionary.push(0);
    header.push(11);
    header.extend((dictionary.len() as u32).to_le_bytes());
    header.extend(dictionary);
    header.extend([0, 4, 0, 0, 0, 13, 10, 13, 10]);
    fs::write(f.path(), header).unwrap();
    let mut app = App::for_test(Some(f.path()));
    app.screen = Screen::Login;
    app.config.yubikey = Some(TOKEN);
    authenticate(&mut app, "synthetic master");
    assert_eq!(app.screen, Screen::Login);
    assert!(
        app.login_error.as_ref().unwrap().contains("challenge seed"),
        "{:?}",
        app.login_error
    );
}

#[test]
fn hardware_rejects_legacy_formats_before_device_discovery() {
    let f = Fixture::new();
    for header in [
        [0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5, 1, 0, 3, 0],
        [0x03, 0xd9, 0xa2, 0x9a, 0x65, 0xfb, 0x4b, 0xb5, 1, 0, 0, 0],
        [0x03, 0xd9, 0xa2, 0x9a, 0x66, 0xfb, 0x4b, 0xb5, 1, 0, 2, 0],
    ] {
        fs::write(f.path(), header).unwrap();
        let mut app = App::for_test(Some(f.path()));
        app.screen = Screen::Login;
        app.config.yubikey = Some(TOKEN);
        authenticate(&mut app, "synthetic master");
        assert_eq!(app.screen, Screen::Login);
        assert!(
            app.login_error.as_ref().unwrap().contains("requires KDBX4"),
            "{:?}",
            app.login_error
        );
        assert!(app.db_key.is_none());
    }
}

#[test]
fn configured_hardware_never_falls_back_to_password_only() {
    let f = Fixture::new();
    db::create_database(&f.path(), "synthetic master", None).unwrap();
    let mut app = App::for_test(Some(f.path()));
    app.screen = Screen::Login;
    app.config.yubikey = Some(TOKEN);
    authenticate(&mut app, "synthetic master");
    assert_eq!(
        app.screen,
        Screen::Login,
        "configured hardware must not be ignored"
    );
    assert!(app.db_key.is_none() && app.kdbx.is_none());
    assert!(app.password.is_empty());
    assert!(
        app.login_error.as_ref().unwrap().contains("YubiKey"),
        "{:?}",
        app.login_error
    );
}
