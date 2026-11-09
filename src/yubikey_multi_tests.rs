//! Simulated native USB sessions, real app policy and full-factor KDBX crypto.
use super::{App, Fixture, Screen, authenticate, db, input};
use crate::config::YubikeyPolicy;
use challenge_response::{
    operation::Operation,
    test_support::{Event, SerialRead as Read, Sessions},
};
use crossterm::event::KeyCode;

const A: u32 = 39269826;
const B: u32 = 39269828;
fn policy() -> YubikeyPolicy {
    YubikeyPolicy {
        slot: 2,
        serials: vec![B, A],
    }
}

fn native_app(f: &Fixture) -> App {
    db::create_database_with_policy(&f.path(), "synthetic master", None, Some(policy())).unwrap();
    let mut app = App::for_test(Some(f.path()));
    app.screen = Screen::Login;
    app.config.yubikey = Some(policy());
    authenticate(&mut app, "synthetic master");
    assert_eq!(app.screen, Screen::Index, "{:?}", app.login_error);
    app
}

#[test]
fn direct_password_commit_keeps_one_claim_through_all_save_verifications() {
    let f = Fixture::new();
    let io = Sessions::new(vec![Read::Serial(A), Read::Serial(B)]);
    let mut app = native_app(&f);
    app.screen = Screen::Settings;
    app.changing_password = true;
    app.password_change_step = crate::app::PasswordChangeStep::CurrentPassword;
    app.current_password_buffer = "synthetic master".into();
    input::settings::handle_settings_input(&mut app, KeyCode::Enter);
    app.new_password_buffer = "new synthetic master".into();
    input::settings::handle_settings_input(&mut app, KeyCode::Enter);
    app.new_password_confirm = "new synthetic master".into();
    let before = io.events().len();
    input::settings::handle_settings_input(&mut app, KeyCode::Enter);
    assert!(
        app.status
            .as_deref()
            .unwrap()
            .contains("master password changed"),
        "{:?}",
        app.status
    );
    let events = &io.events()[before..];
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e, Event::Open(_)))
            .count(),
        2,
        "new complete key and save/reads must be one physical operation"
    );
    assert_eq!(events.last(), Some(&Event::Close(0)));
}

#[test]
fn direct_draft_persistence_keeps_one_claim_through_primary_and_sidecar_reads() {
    let f = Fixture::new();
    let io = Sessions::new(vec![Read::Serial(A)]);
    let mut app = native_app(&f);
    super::draft(&mut app);
    let draft = crate::recovery::Draft::capture(&app).unwrap();
    let before = io.events().len();
    crate::recovery::persist(&mut app, &draft).unwrap();
    let events = &io.events()[before..];
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e, Event::Open(_)))
            .count(),
        1,
        "primary auth, sidecar write and reads must share the physical handle"
    );
    assert_eq!(events.last(), Some(&Event::Close(0)));
}

#[test]
fn removal_and_same_address_replacement_never_switch_inside_an_operation() {
    for replacement in [None, Some(B), Some(A), Some(123)] {
        let io = Sessions::new(vec![Read::Serial(A), Read::Serial(B)]);
        let operation = Operation::standard();
        let key =
            db::build_database_key_with_policy("synthetic master", None, Some(policy())).unwrap();
        let mut bytes = Vec::new();
        db::save_with_key(&keepass::Database::new(), &mut bytes, &key).unwrap();
        let before = io.events().len();
        match replacement {
            Some(serial) => io.replace(0, Read::Serial(serial)),
            None => io.remove(0),
        }
        let error = db::open_with_key(&mut std::io::Cursor::new(&bytes), &key).unwrap_err();
        assert!(error.to_string().contains("Can not read"), "{error:#}");
        assert_eq!(
            &io.events()[before..],
            &[Event::Hmac(0), Event::Abort(0)],
            "must use old physical handle, never the replacement or another authorized key"
        );
        let before = io.events().len();
        assert!(
            db::build_database_key_with_policy("synthetic master", None, Some(policy())).is_err(),
            "operation is poisoned after a failed exchange"
        );
        assert_eq!(
            io.events().len(),
            before,
            "no retry/discovery after failure"
        );
        drop(operation);
        // A fresh all-factor authentication operation may explicitly choose the other key.
        db::build_database_key_with_yubikey(
            "synthetic master",
            None,
            Some(crate::config::YubikeyConfig { serial: B, slot: 2 }),
        )
        .unwrap();
    }
}

#[test]
fn one_unchanged_full_factor_ciphertext_accepts_both_simulated_physical_keys() {
    let f = Fixture::new();
    let keyfile = f.0.join("synthetic.key");
    std::fs::write(&keyfile, b"synthetic multi-device keyfile").unwrap();
    {
        let _io = Sessions::new(vec![Read::Serial(A)]);
        db::create_database_with_policy(
            &f.path(),
            "synthetic master",
            Some(&keyfile),
            Some(policy()),
        )
        .unwrap();
    }
    let unchanged = std::fs::read(f.path()).unwrap();
    for serial in [A, B] {
        let io = Sessions::new(vec![Read::Serial(serial)]);
        db::unlock_database_snapshot_with_policy(
            &f.path(),
            "synthetic master",
            Some(&keyfile),
            Some(policy()),
        )
        .unwrap();
        assert_eq!(
            io.events(),
            vec![
                Event::Open(0),
                Event::Serial(0),
                Event::Hmac(0),
                Event::Close(0)
            ]
        );
        assert!(
            db::unlock_database_snapshot_with_policy(
                &f.path(),
                "wrong synthetic master",
                Some(&keyfile),
                Some(policy())
            )
            .is_err()
        );
        assert!(
            db::unlock_database_snapshot_with_policy(
                &f.path(),
                "synthetic master",
                None,
                Some(policy())
            )
            .is_err()
        );
        assert!(
            db::unlock_database_snapshot_with_policy(
                &f.path(),
                "synthetic master",
                Some(&keyfile),
                Some(YubikeyPolicy {
                    slot: 1,
                    ..policy()
                })
            )
            .is_err(),
            "slot composition must remain cryptographically effective"
        );
        assert!(
            db::unlock_database_snapshot(&f.path(), "synthetic master", Some(&keyfile)).is_err()
        );
        assert_eq!(std::fs::read(f.path()).unwrap(), unchanged);
    }
}

#[test]
fn fresh_reauthentication_uses_frozen_allowlist_not_last_selected_serial_or_preferences() {
    let f = Fixture::new();
    let mut app = {
        let _io = Sessions::new(vec![Read::Serial(A)]);
        native_app(&f)
    };
    assert!(app.lock_cooperatively());
    app.config.yubikey = None;
    let _io = Sessions::new(vec![Read::Serial(B)]);
    authenticate(&mut app, "synthetic master");
    assert_eq!(app.screen, Screen::Index, "{:?}", app.login_error);
    assert_eq!(app.database_yubikey(), Some(policy()));
    assert!(format!("{:?}", app.db_key).contains(&B.to_string()));
}

#[test]
fn neither_or_only_unauthorized_devices_never_produce_a_key() {
    for reads in [
        vec![],
        vec![Read::Serial(123)],
        vec![Read::Serial(123), Read::Serial(456)],
    ] {
        let io = Sessions::new(reads);
        assert!(
            db::build_database_key_with_policy("synthetic master", None, Some(policy())).is_err()
        );
        assert!(!io.events().iter().any(|e| matches!(e, Event::Hmac(_))));
    }
}

#[test]
fn ordinary_unreadable_neighbors_allow_an_accessible_authorized_key_but_global_errors_do_not() {
    use challenge_response::test_support::Discovery;
    for failure in [Read::Denied, Read::Busy, Read::Gone, Read::Unsupported] {
        for reads in [
            vec![failure.clone(), Read::Serial(B)],
            vec![Read::Serial(B), failure.clone()],
        ] {
            let _io = Discovery::new(reads);
            let key = db::build_database_key_with_policy("synthetic master", None, Some(policy()))
                .unwrap();
            assert!(format!("{key:?}").contains(&B.to_string()));
        }
    }
    for failure in [Read::Cancelled, Read::Deadline, Read::EnumerationFailure] {
        for reads in [
            vec![failure.clone(), Read::Serial(A)],
            vec![Read::Serial(A), failure.clone()],
        ] {
            let _io = Discovery::new(reads);
            assert!(
                db::build_database_key_with_policy("synthetic master", None, Some(policy()))
                    .is_err()
            );
        }
    }
}

#[test]
fn cancellation_and_deadline_drop_claims_without_authentication_or_fallback() {
    use std::sync::{Arc, atomic::AtomicBool};
    for cancelled in [true, false] {
        let flag = Arc::new(AtomicBool::new(false));
        let _cancel = challenge_response::operation::Cancellation::install(flag.clone());
        let action = if cancelled {
            Read::CancelDuring(flag, Box::new(Read::Serial(A)))
        } else {
            Read::ExpireDuring(Box::new(Read::Serial(A)))
        };
        let io = Sessions::new(vec![action, Read::Serial(B)]);
        let scope = Operation::new(std::time::Duration::from_millis(50));
        let error = db::build_database_key_with_policy("synthetic master", None, Some(policy()))
            .unwrap_err();
        assert!(format!("{error:#}").contains(if cancelled {
            "cancelled"
        } else {
            "deadline exceeded"
        }));
        drop(scope);
        assert_eq!(
            io.events(),
            vec![
                Event::Open(0),
                Event::Serial(0),
                Event::Abort(0),
                Event::Close(0)
            ]
        );
    }
}

#[test]
fn another_authorized_serial_cannot_be_explicitly_substituted_inside_an_operation() {
    let io = Sessions::new(vec![Read::Serial(A), Read::Serial(B)]);
    let scope = Operation::standard();
    let mut native = challenge_response::ChallengeResponse::new().unwrap();
    assert_eq!(native.select_authorized(&[A, B]).unwrap().serial, Some(A));
    let before = io.events().len();
    assert!(native.select_authorized(&[B]).is_err());
    assert!(
        native.select_authorized(&[A]).is_err(),
        "a failed substitution poisons the entire operation"
    );
    assert_eq!(
        io.events().len(),
        before,
        "substitution must never rediscover or open another physical device"
    );
    drop(scope);
    assert_eq!(
        native.select_authorized(&[B]).unwrap().serial,
        Some(B),
        "a fresh operation may authenticate another explicitly authorized device"
    );
}

#[test]
fn retained_concrete_key_cannot_silently_change_to_another_allowed_device() {
    let f = Fixture::new();
    let key = {
        let _io = Sessions::new(vec![Read::Serial(A)]);
        let (_, key, _) =
            db::create_database_with_policy(&f.path(), "synthetic master", None, Some(policy()))
                .unwrap();
        key
    };
    let io = Sessions::new(vec![Read::Serial(B)]);
    assert!(db::open_with_key(&mut std::fs::File::open(f.path()).unwrap(), &key).is_err());
    assert!(!io.events().iter().any(|e| matches!(e, Event::Hmac(_))));
    db::unlock_database_snapshot_with_policy(&f.path(), "synthetic master", None, Some(policy()))
        .unwrap();
}

#[test]
fn native_removal_at_staging_or_published_verification_preserves_commit_receipts() {
    for boundary in 1..=3 {
        let f = Fixture::new();
        let io = Sessions::new(vec![Read::Serial(A), Read::Serial(B)]);
        let mut app = native_app(&f);
        let original = std::fs::read(f.path()).unwrap();
        io.fail_hmac_after(0, boundary);
        let before = io.events().len();
        let result = db::save_database_with_revision(
            &f.path(),
            app.db_key.as_ref().unwrap(),
            app.kdbx.as_mut().unwrap(),
            &mut app.entries,
            &mut app.primary_revision,
        );
        if boundary == 3 {
            assert!(matches!(result, Err(db::SaveError::Verification(_))));
            assert_ne!(std::fs::read(f.path()).unwrap(), original);
            app.primary_revision
                .as_ref()
                .unwrap()
                .revalidate(&f.path())
                .unwrap();
        } else {
            assert!(matches!(result, Err(db::SaveError::Write(_))));
            assert_eq!(std::fs::read(f.path()).unwrap(), original);
        }
        let events = &io.events()[before..];
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, Event::Open(_)))
                .count(),
            2
        );
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, Event::Hmac(0)))
                .count(),
            boundary
        );
        assert!(!events.iter().any(|e| matches!(e, Event::Hmac(1))));
    }
}

#[test]
fn primary_unlock_and_disk_draft_recovery_share_one_claim_on_the_other_key() {
    let f = Fixture::new();
    {
        let _io = Sessions::new(vec![Read::Serial(A)]);
        let mut app = native_app(&f);
        super::draft(&mut app);
        assert!(app.lock_cooperatively());
    }
    let io = Sessions::new(vec![Read::Serial(B)]);
    let mut app = App::for_test(Some(f.path()));
    app.screen = Screen::Login;
    app.config.yubikey = Some(policy());
    authenticate(&mut app, "synthetic master");
    assert_eq!(app.screen, Screen::Edit, "{:?}", app.login_error);
    assert_eq!(app.field_buffer, "synthetic partial notes");
    assert_eq!(
        io.events(),
        vec![
            Event::Open(0),
            Event::Serial(0),
            Event::Hmac(0),
            Event::Hmac(0),
            Event::Close(0)
        ]
    );
}

#[test]
fn native_removal_between_primary_unlock_and_recovery_never_installs_a_partial_draft() {
    let f = Fixture::new();
    {
        let _io = Sessions::new(vec![Read::Serial(A)]);
        let mut app = native_app(&f);
        super::draft(&mut app);
        assert!(app.lock_cooperatively());
    }
    let io = Sessions::new(vec![Read::Serial(A), Read::Serial(B)]);
    io.fail_hmac_after(0, 2);
    let mut app = App::for_test(Some(f.path()));
    app.screen = Screen::Login;
    app.config.yubikey = Some(policy());
    authenticate(&mut app, "synthetic master");
    assert_eq!(app.screen, Screen::Login);
    assert!(app.db_key.is_none() && app.kdbx.is_none() && app.edit_entry.is_none());
    assert!(
        app.login_error
            .as_deref()
            .unwrap()
            .contains("Recovery failed")
    );
    assert_eq!(
        io.events()
            .iter()
            .filter(|e| matches!(e, Event::Open(_)))
            .count(),
        2
    );
    assert!(!io.events().iter().any(|e| matches!(e, Event::Hmac(1))));
}

#[test]
fn create_install_is_one_physical_operation_even_via_direct_handler() {
    let f = Fixture::new();
    let io = Sessions::new(vec![Read::Serial(B), Read::Serial(A)]);
    let mut app = App::for_test(Some(f.path()));
    app.screen = Screen::Login;
    app.config.yubikey = Some(policy());
    input::login::handle_login_input(&mut app, KeyCode::Char('n'));
    app.password = "synthetic master".into();
    input::login::handle_login_input(&mut app, KeyCode::Enter);
    app.new_db_confirm = "synthetic master".into();
    input::login::handle_login_input(&mut app, KeyCode::Enter);
    assert_eq!(app.screen, Screen::Index, "{:?}", app.login_error);
    assert_eq!(
        io.events()
            .iter()
            .filter(|e| matches!(e, Event::Open(_)))
            .count(),
        2,
        "creation, verification, independent unlock and install must share the original claim"
    );
    assert_eq!(
        io.events()
            .iter()
            .filter(|e| matches!(e, Event::Serial(_)))
            .count(),
        2
    );
    assert!(
        io.events()
            .iter()
            .filter_map(|e| if let Event::Hmac(id) = e {
                Some(*id)
            } else {
                None
            })
            .all(|id| id == 1)
    );
    assert_eq!(io.events().last(), Some(&Event::Close(1)));
}
