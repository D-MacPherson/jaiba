//! Synthetic independent-review regressions; never opens a display or clipboard.
use crate::{
    app::{App, Screen},
    db::{self, Entry},
    input, recovery,
};
use crossterm::event::KeyCode;
use keepass::{
    Database, DatabaseKey,
    config::{InnerCipherConfig, KdfConfig, OuterCipherConfig},
};
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "jaiba-review-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn app(&self) -> App {
        let path = self.0.join("synthetic.kdbx");
        let mut database = Database::new();
        database.config.kdf_config = KdfConfig::Aes { rounds: 128 };
        let key = DatabaseKey::new().with_password("synthetic master");
        db::save_database(&path, &key, &mut database, &mut []).unwrap();
        loaded(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn draft(app: &mut App) {
    app.screen = Screen::Edit;
    app.edit_entry = Some(Entry {
        password: "synthetic secret".into(),
        ..Default::default()
    });
    app.edit_original = Some(Default::default());
    app.edit_state.select(Some(5));
    app.editing_field = true;
    app.field_buffer = "synthetic partial notes".into();
}
fn auth(app: &mut App) {
    app.password = "synthetic master".into();
    input::login::handle_login_input(app, KeyCode::Enter);
}
fn sidecar(app: &App) -> PathBuf {
    fs::read_dir(recovery::directory(app.database_path().unwrap()))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "kdbx"))
        .unwrap()
}
fn loaded(path: PathBuf) -> App {
    let (database, key, entries, revision) =
        db::unlock_database_snapshot(&path, "synthetic master", None).unwrap();
    let mut app = App::for_test(Some(path));
    app.kdbx = Some(database);
    app.db_key = Some(key);
    app.primary_revision = Some(revision);
    app.entries = entries;
    app
}
fn rekey(app: &mut App) {
    app.screen = Screen::Settings;
    app.changing_password = true;
    app.password_change_step = crate::app::PasswordChangeStep::ConfirmNewPassword;
    app.new_password_buffer = "new synthetic master".into();
    app.new_password_confirm = app.new_password_buffer.clone();
    input::settings::handle_settings_input(app, KeyCode::Enter);
}
#[test]
fn acceptance_stale_editor_cannot_revert_rekey_or_strand_durable_draft() {
    let f = Fixture::new();
    let mut rotating = f.app();
    let path = rotating.database_path().unwrap().to_owned();
    let mut stale = App::for_test(Some(path.clone()));
    auth(&mut stale);
    rekey(&mut rotating);
    assert!(
        rotating
            .status
            .as_ref()
            .unwrap()
            .contains("master password changed")
    );
    draft(&mut rotating);
    assert!(rotating.lock_cooperatively());
    let primary = fs::read(&path).unwrap();
    let artifact = sidecar(&rotating);
    let encrypted_draft = fs::read(&artifact).unwrap();
    draft(&mut stale);
    stale.editing_field = false;
    input::edit::handle_edit_input(&mut stale, KeyCode::Esc);
    input::edit::handle_edit_input(&mut stale, KeyCode::Char('y'));
    assert_eq!(
        stale.screen,
        Screen::Edit,
        "stale editor must remain recoverable"
    );
    assert!(stale.status.as_ref().unwrap().starts_with("Not saved:"));
    assert_eq!(fs::read(&path).unwrap(), primary);
    assert_eq!(fs::read(&artifact).unwrap(), encrypted_draft);
    assert!(rotating.lock_cooperatively());
    drop(rotating);
    drop(stale);
    let mut restarted = App::for_test(Some(path));
    restarted.password = "new synthetic master".into();
    input::login::handle_login_input(&mut restarted, KeyCode::Enter);
    assert_eq!(restarted.screen, Screen::Edit);
    assert_eq!(
        restarted.edit_entry.as_ref().unwrap().password,
        "synthetic secret"
    );
}

#[test]
fn acceptance_stale_delete_preserves_primary_and_editor() {
    let f = Fixture::new();
    let mut seed = f.app();
    existing_draft(&mut seed);
    let path = seed.database_path().unwrap().to_owned();
    let mut stale = App::for_test(Some(path.clone()));
    auth(&mut stale);
    let mut rotating = loaded(path.clone());
    rekey(&mut rotating);
    assert!(
        rotating
            .status
            .as_ref()
            .unwrap()
            .contains("master password changed")
    );
    let primary = fs::read(&path).unwrap();
    stale.screen = Screen::Edit;
    stale.edit_entry = Some(stale.entries[0].clone());
    stale.edit_original = stale.edit_entry.clone();
    stale.edit_target = Some(0);
    input::edit::handle_edit_input(&mut stale, KeyCode::Char('d'));
    input::edit::handle_edit_input(&mut stale, KeyCode::Char('y'));
    assert_eq!(
        stale.screen,
        Screen::Edit,
        "stale delete must not close editor"
    );
    assert!(stale.status.as_ref().unwrap().contains("Failed to delete"));
    assert!(!stale.edit_deleted);
    assert_eq!(fs::read(&path).unwrap(), primary);
}

#[test]
fn acceptance_stale_import_cannot_revert_rekey() {
    let f = Fixture::new();
    let mut rotating = f.app();
    let path = rotating.database_path().unwrap().to_owned();
    let mut stale = App::for_test(Some(path.clone()));
    auth(&mut stale);
    rekey(&mut rotating);
    assert!(
        rotating
            .status
            .as_ref()
            .unwrap()
            .contains("master password changed")
    );
    let primary = fs::read(&path).unwrap();
    let source = f.0.join("synthetic.csv");
    fs::write(
        &source,
        "name,password\nsynthetic import,synthetic imported secret\n",
    )
    .unwrap();
    stale.screen = Screen::Settings;
    stale.importing_database = true;
    stale.import_path_buffer = source.to_string_lossy().into();
    input::settings::handle_settings_input(&mut stale, KeyCode::Enter);
    assert!(
        stale.status.as_ref().unwrap().starts_with("Not imported:"),
        "stale import must be rejected: {:?}",
        stale.status
    );
    assert!(stale.entries.is_empty());
    assert_eq!(fs::read(&path).unwrap(), primary);
    assert_eq!(stale.kdbx.as_ref().unwrap().iter_all_entries().count(), 0);
}

#[test]
fn acceptance_stale_rekey_cannot_replace_authenticated_primary() {
    let f = Fixture::new();
    let mut rotating = f.app();
    let path = rotating.database_path().unwrap().to_owned();
    let mut stale = App::for_test(Some(path.clone()));
    auth(&mut stale);
    rekey(&mut rotating);
    assert!(
        rotating
            .status
            .as_ref()
            .unwrap()
            .contains("master password changed")
    );
    let primary = fs::read(&path).unwrap();
    stale.screen = Screen::Settings;
    stale.changing_password = true;
    stale.password_change_step = crate::app::PasswordChangeStep::ConfirmNewPassword;
    stale.new_password_buffer = "third synthetic master".into();
    stale.new_password_confirm = stale.new_password_buffer.clone();
    input::settings::handle_settings_input(&mut stale, KeyCode::Enter);
    assert!(
        !stale
            .status
            .as_ref()
            .unwrap()
            .contains("master password changed"),
        "stale rekey must reject: {:?}",
        stale.status
    );
    assert_eq!(fs::read(&path).unwrap(), primary);
    assert!(db::unlock_database(&path, "new synthetic master", None).is_ok());
    assert!(db::unlock_database(&path, "third synthetic master", None).is_err());
}

#[test]
fn acceptance_export_refuses_primary_and_symlink_or_hardlink_aliases() {
    for alias in [
        "direct",
        "symlink.kdbx",
        "symlink.csv",
        "symlink.json",
        "hard.kdbx",
        "hard.csv",
    ] {
        let f = Fixture::new();
        let mut app = f.app();
        let primary = app.database_path().unwrap().to_owned();
        let target = if alias == "direct" {
            primary.clone()
        } else {
            f.0.join(alias)
        };
        if alias.starts_with("symlink") {
            std::os::unix::fs::symlink(&primary, &target).unwrap();
        }
        if alias.starts_with("hard") {
            fs::hard_link(&primary, &target).unwrap();
        }
        let before = fs::read(&primary).unwrap();
        app.screen = Screen::Settings;
        app.exporting_database = true;
        app.export_step = crate::app::ExportStep::Confirm;
        app.pending_export_path = Some(target.clone());
        input::settings::handle_settings_input(&mut app, KeyCode::Enter);
        assert!(
            app.status.as_ref().unwrap().starts_with("couldn't export:"),
            "primary alias {alias} must reject: {:?}",
            app.status
        );
        assert_eq!(fs::read(&primary).unwrap(), before, "primary alias {alias}");
        assert_eq!(fs::read(&target).unwrap(), before);
        if alias.starts_with("symlink") {
            assert!(
                fs::symlink_metadata(&target)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
        }
    }
}

fn attempt_mutation(app: &mut App, operation: &str, import_source: &std::path::Path) {
    match operation {
        "edit" | "delete" => {
            app.screen = Screen::Edit;
            app.edit_entry = Some(app.entries[0].clone());
            app.edit_original = app.edit_entry.clone();
            app.edit_target = Some(0);
            if operation == "edit" {
                app.edit_entry.as_mut().unwrap().password = "synthetic stale replacement".into();
                input::edit::handle_edit_input(app, KeyCode::Esc);
            } else {
                input::edit::handle_edit_input(app, KeyCode::Char('d'));
            }
            input::edit::handle_edit_input(app, KeyCode::Char('y'));
        }
        "import" => {
            app.screen = Screen::Settings;
            app.importing_database = true;
            app.import_path_buffer = import_source.to_string_lossy().into();
            input::settings::handle_settings_input(app, KeyCode::Enter);
        }
        "rekey" => rekey(app),
        _ => panic!("unexpected synthetic operation"),
    }
}

#[test]
fn acceptance_same_key_source_drift_rejects_all_primary_mutations_through_aliases() {
    for operation in ["edit", "delete", "import", "rekey"] {
        for alias in [false, true] {
            let f = Fixture::new();
            let mut seed = f.app();
            existing_draft(&mut seed);
            let path = seed.database_path().unwrap().to_owned();
            let open = if alias {
                let alias = f.0.join("alias.kdbx");
                std::os::unix::fs::symlink(&path, &alias).unwrap();
                alias
            } else {
                path.clone()
            };
            let mut stale = App::for_test(Some(open));
            auth(&mut stale);
            let mut current = loaded(path.clone());
            let source = f.0.join("synthetic.csv");
            fs::write(
                &source,
                "name,password\nsynthetic imported,synthetic imported value\n",
            )
            .unwrap();
            attempt_mutation(&mut current, "import", &source);
            assert!(
                current
                    .status
                    .as_ref()
                    .unwrap()
                    .starts_with("imported and verified")
            );
            let before = fs::read(&path).unwrap();
            attempt_mutation(&mut stale, operation, &source);
            assert!(
                stale
                    .status
                    .as_ref()
                    .unwrap()
                    .contains("changed since authentication"),
                "operation={operation} alias={alias}: {:?}",
                stale.status
            );
            assert_eq!(
                fs::read(&path).unwrap(),
                before,
                "operation={operation} alias={alias}"
            );
            assert_eq!(
                db::unlock_database(&path, "synthetic master", None)
                    .unwrap()
                    .2
                    .len(),
                2
            );
            if matches!(operation, "edit" | "delete") {
                assert!(stale.edit_entry.is_some());
            }
        }
    }
}

#[test]
fn acceptance_busy_transaction_rejects_every_sibling_mutation_without_waiting() {
    for operation in ["edit", "delete", "import", "rekey"] {
        let f = Fixture::new();
        let mut seed = f.app();
        existing_draft(&mut seed);
        let path = seed.database_path().unwrap().to_owned();
        let mut app = loaded(path.clone());
        let source = f.0.join("synthetic.csv");
        fs::write(
            &source,
            "name,password\nsynthetic imported,synthetic imported value\n",
        )
        .unwrap();
        let before = fs::read(&path).unwrap();
        let transaction = recovery::Transaction::begin(&path).unwrap();
        attempt_mutation(&mut app, operation, &source);
        assert!(
            app.status.as_ref().unwrap().contains("busy"),
            "{operation}: {:?}",
            app.status
        );
        assert_eq!(fs::read(&path).unwrap(), before);
        drop(transaction);
    }
}

#[test]
fn acceptance_successive_mutations_refresh_revision_without_reauthentication() {
    let f = Fixture::new();
    let mut app = f.app();
    let path = app.database_path().unwrap().to_owned();
    let source = f.0.join("synthetic.csv");
    fs::write(
        &source,
        "name,password\nsynthetic imported,synthetic imported value\n",
    )
    .unwrap();
    attempt_mutation(&mut app, "import", &source);
    assert!(
        app.status
            .as_ref()
            .unwrap()
            .starts_with("imported and verified")
    );
    attempt_mutation(&mut app, "edit", &source);
    assert_eq!(app.screen, Screen::Index, "{:?}", app.status);
    rekey(&mut app);
    assert!(
        app.status
            .as_ref()
            .unwrap()
            .contains("master password changed")
    );
    attempt_mutation(&mut app, "delete", &source);
    assert_eq!(app.screen, Screen::Index, "{:?}", app.status);
    assert!(
        db::unlock_database(&path, "new synthetic master", None)
            .unwrap()
            .2
            .is_empty()
    );
}

#[test]
fn acceptance_uncertain_edit_keeps_revision_and_assigned_id_for_single_entry_retry() {
    let f = Fixture::new();
    let mut app = f.app();
    let path = app.database_path().unwrap().to_owned();
    draft(&mut app);
    app.editing_field = false;
    db::test_fault::FINAL
        .with(|fault| *fault.borrow_mut() = Some(db::test_fault::FinalCheck::Fail));
    input::edit::handle_edit_input(&mut app, KeyCode::Esc);
    input::edit::handle_edit_input(&mut app, KeyCode::Char('y'));
    assert_eq!(app.screen, Screen::Edit);
    assert!(app.status.as_ref().unwrap().starts_with("Written, but"));
    let id = app
        .edit_entry
        .as_ref()
        .unwrap()
        .id
        .expect("uncertain replacement retains ID");
    drop(
        app.begin_primary_write()
            .expect("uncertain receipt matches the written primary"),
    );
    input::edit::handle_edit_input(&mut app, KeyCode::Esc);
    input::edit::handle_edit_input(&mut app, KeyCode::Char('y'));
    assert_eq!(app.screen, Screen::Index, "{:?}", app.status);
    let entries = db::unlock_database(&path, "synthetic master", None)
        .unwrap()
        .2;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].id, Some(id));
}

#[test]
fn acceptance_uncertain_rekey_retains_new_credentials_and_exact_revision() {
    let f = Fixture::new();
    let mut app = f.app();
    let path = app.database_path().unwrap().to_owned();
    db::test_fault::FINAL
        .with(|fault| *fault.borrow_mut() = Some(db::test_fault::FinalCheck::Fail));
    rekey(&mut app);
    assert!(
        app.status
            .as_ref()
            .unwrap()
            .starts_with("password change written")
    );
    drop(app.begin_primary_write().unwrap());
    let source = f.0.join("synthetic.csv");
    fs::write(
        &source,
        "name,password\nsynthetic imported,synthetic imported value\n",
    )
    .unwrap();
    attempt_mutation(&mut app, "import", &source);
    assert!(
        app.status
            .as_ref()
            .unwrap()
            .starts_with("imported and verified")
    );
    assert_eq!(
        db::unlock_database(&path, "new synthetic master", None)
            .unwrap()
            .2
            .len(),
        1
    );
    assert!(db::unlock_database(&path, "synthetic master", None).is_err());
}

#[test]
fn acceptance_uncertain_delete_then_lock_can_authenticate_cleanup_and_save_unrelated_entry() {
    let f = Fixture::new();
    let mut app = f.app();
    let entry = existing_draft(&mut app);
    let path = app.database_path().unwrap().to_owned();
    assert!(app.lock_cooperatively());
    auth(&mut app);
    let artifact = sidecar(&app);
    db::test_fault::FINAL
        .with(|fault| *fault.borrow_mut() = Some(db::test_fault::FinalCheck::Fail));
    input::edit::handle_edit_input(&mut app, KeyCode::Char('d'));
    input::edit::handle_edit_input(&mut app, KeyCode::Char('y'));
    assert!(
        db::unlock_database(&path, "synthetic master", None)
            .unwrap()
            .2
            .is_empty()
    );
    assert!(
        app.edit_deleted,
        "replacement committed deletion despite failed confirmation"
    );
    assert!(
        app.entries.is_empty(),
        "do not display a deleted entry as live"
    );
    assert_eq!(app.edit_entry.as_ref().unwrap().id, entry.id);
    assert!(
        artifact.exists(),
        "retain recovery until explicit confirmation and cleanup"
    );
    assert!(
        !app.lock_cooperatively(),
        "unconfirmed deletion stays fail-closed"
    );
    assert!(app.pending_draft.is_some());
    auth(&mut app);
    assert_eq!(app.screen, Screen::Edit, "{:?}", app.login_error);
    assert!(app.edit_deleted);
    // Retry must confirm the primary deletion, not just forget its sidecar.
    db::test_fault::FINAL
        .with(|fault| *fault.borrow_mut() = Some(db::test_fault::FinalCheck::Fail));
    input::edit::handle_edit_input(&mut app, KeyCode::Char('d'));
    input::edit::handle_edit_input(&mut app, KeyCode::Char('y'));
    assert_eq!(app.screen, Screen::Edit);
    assert!(app.status.as_ref().unwrap().starts_with("Deletion written"));
    assert!(artifact.exists());
    assert!(!app.lock_cooperatively());
    auth(&mut app);
    assert_eq!(app.screen, Screen::Edit, "{:?}", app.login_error);
    input::edit::handle_edit_input(&mut app, KeyCode::Char('d'));
    input::edit::handle_edit_input(&mut app, KeyCode::Char('y'));
    assert_eq!(app.screen, Screen::Index, "{:?}", app.status);
    assert!(!artifact.exists());
    // A later ordinary edit must not resurrect the committed deletion.
    draft(&mut app);
    app.editing_field = false;
    input::edit::handle_edit_input(&mut app, KeyCode::Esc);
    input::edit::handle_edit_input(&mut app, KeyCode::Char('y'));
    assert_eq!(app.screen, Screen::Index, "{:?}", app.status);
    let saved = db::unlock_database(&path, "synthetic master", None)
        .unwrap()
        .2;
    assert_eq!(saved.len(), 1);
    assert_ne!(saved[0].id, entry.id);
    assert!(app.lock_cooperatively());
    drop(app);
    let mut restarted = App::for_test(Some(path));
    auth(&mut restarted);
    assert_eq!(restarted.screen, Screen::Index);
    assert_eq!(restarted.entries.len(), 1);
}

#[test]
fn acceptance_uncertain_import_and_delete_keep_retry_receipts() {
    let f = Fixture::new();
    let mut app = f.app();
    let path = app.database_path().unwrap().to_owned();
    let source = f.0.join("synthetic.csv");
    fs::write(
        &source,
        "name,password\nsynthetic imported,synthetic imported value\n",
    )
    .unwrap();
    db::test_fault::FINAL
        .with(|fault| *fault.borrow_mut() = Some(db::test_fault::FinalCheck::Fail));
    attempt_mutation(&mut app, "import", &source);
    assert!(app.status.as_ref().unwrap().starts_with("Import written"));
    assert!(app.entries[0].id.is_some());
    drop(app.begin_primary_write().unwrap());
    attempt_mutation(&mut app, "edit", &source);
    assert_eq!(
        db::unlock_database(&path, "synthetic master", None)
            .unwrap()
            .2
            .len(),
        1
    );
    db::test_fault::FINAL
        .with(|fault| *fault.borrow_mut() = Some(db::test_fault::FinalCheck::Fail));
    attempt_mutation(&mut app, "delete", &source);
    assert_eq!(app.screen, Screen::Edit);
    assert!(app.edit_entry.is_some());
    drop(app.begin_primary_write().unwrap());
    input::edit::handle_edit_input(&mut app, KeyCode::Char('d'));
    input::edit::handle_edit_input(&mut app, KeyCode::Char('y'));
    assert_eq!(app.screen, Screen::Index, "{:?}", app.status);
    assert!(
        db::unlock_database(&path, "synthetic master", None)
            .unwrap()
            .2
            .is_empty()
    );
}

#[test]
fn acceptance_unknown_post_save_primary_does_not_bless_unrelated_ciphertext() {
    let f = Fixture::new();
    let mut app = f.app();
    let path = app.database_path().unwrap().to_owned();
    let before = fs::read(&path).unwrap();
    let old_revision = app.primary_revision.clone();
    draft(&mut app);
    app.editing_field = false;
    db::test_fault::FINAL.with(|fault| {
        *fault.borrow_mut() = Some(db::test_fault::FinalCheck::Replace(before.clone()))
    });
    input::edit::handle_edit_input(&mut app, KeyCode::Esc);
    input::edit::handle_edit_input(&mut app, KeyCode::Char('y'));
    assert_eq!(app.screen, Screen::Edit);
    assert!(app.edit_entry.as_ref().unwrap().id.is_some());
    assert_ne!(
        app.primary_revision, old_revision,
        "retain candidate receipt, not an unrelated readback"
    );
    assert!(app.begin_primary_write().is_err());
    input::edit::handle_edit_input(&mut app, KeyCode::Esc);
    input::edit::handle_edit_input(&mut app, KeyCode::Char('y'));
    assert!(
        app.status
            .as_ref()
            .unwrap()
            .contains("changed since authentication")
    );
    assert_eq!(
        app.edit_entry.as_ref().unwrap().password,
        "synthetic secret"
    );
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn acceptance_unlock_revision_comes_from_exact_authenticated_bytes() {
    let f = Fixture::new();
    let mut app = f.app();
    let path = app.database_path().unwrap().to_owned();
    let old = fs::read(&path).unwrap();
    let mut extra = Entry {
        name: "synthetic intervening entry".into(),
        ..Default::default()
    };
    db::save_database(
        &path,
        app.db_key.as_ref().unwrap(),
        app.kdbx.as_mut().unwrap(),
        std::slice::from_mut(&mut extra),
    )
    .unwrap();
    let replacement = fs::read(&path).unwrap();
    fs::write(&path, old).unwrap();
    db::test_fault::UNLOCK.with(|fault| *fault.borrow_mut() = Some(replacement.clone()));
    let (_, _, entries, revision) =
        db::unlock_database_snapshot(&path, "synthetic master", None).unwrap();
    assert!(entries.is_empty(), "authenticated original snapshot");
    assert_eq!(fs::read(&path).unwrap(), replacement);
    assert!(
        revision.revalidate(&path).is_err(),
        "do not attach intervening ciphertext to the original decrypted state"
    );
}

#[test]
fn review_logic4_rekey_wins_blocks_old_key_publication_including_aliases() {
    for alias in [false, true] {
        let f = Fixture::new();
        let mut editing = f.app();
        draft(&mut editing);
        let path = editing.database_path().unwrap().to_owned();
        let rekey_path = if alias {
            let p = f.0.join("alias.kdbx");
            std::os::unix::fs::symlink(&path, &p).unwrap();
            p
        } else {
            path.clone()
        };
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut app = loaded(rekey_path);
            recovery::interleave::REKEY.with(|h| *h.borrow_mut() = Some((ready_tx, resume_rx)));
            rekey(&mut app);
            app.status
        });
        ready_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        let reported = editing.lock_cooperatively();
        let memory = editing.pending_draft.is_some();
        resume_tx.send(()).unwrap();
        let status = worker.join().unwrap();
        assert!(
            !reported,
            "publication during checked rekey must fail nonblocking (alias={alias})"
        );
        assert!(memory);
        assert!(status.unwrap().contains("master password changed"));
        assert!(db::unlock_database(&path, "new synthetic master", None).is_ok());
        // A stale authenticated session after replacement also cannot publish old-key ciphertext.
        let mut stale = App::for_test(Some(path.clone()));
        stale.kdbx = Some(Database::new());
        stale.db_key = Some(DatabaseKey::new().with_password("synthetic master"));
        draft(&mut stale);
        assert!(!stale.lock_cooperatively());
        assert!(stale.pending_draft.is_some());
    }
}
#[test]
fn review_logic4_draft_wins_denies_rekey_before_publication_including_aliases() {
    for alias in [false, true] {
        let f = Fixture::new();
        let app = f.app();
        let path = app.database_path().unwrap().to_owned();
        drop(app);
        let editor_path = if alias {
            let p = f.0.join("alias.kdbx");
            std::os::unix::fs::symlink(&path, &p).unwrap();
            p
        } else {
            path.clone()
        };
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut editing = loaded(editor_path);
            draft(&mut editing);
            recovery::interleave::PUBLICATION
                .with(|h| *h.borrow_mut() = Some((ready_tx, resume_rx)));
            editing.lock_cooperatively()
        });
        ready_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        let mut changing = loaded(path.clone());
        rekey(&mut changing);
        let status = changing.status.clone();
        resume_tx.send(()).unwrap();
        let published = worker.join().unwrap();
        assert!(
            published,
            "draft transaction must finish under original credentials"
        );
        assert!(
            db::unlock_database(&path, "synthetic master", None).is_ok(),
            "rekey racing an unpublished draft must be denied (alias={alias}, status={status:?})"
        );
        rekey(&mut changing);
        assert!(
            changing.status.as_ref().unwrap().contains("draft"),
            "published draft also blocks rekey"
        );
        let mut recovering = App::for_test(Some(path));
        auth(&mut recovering);
        assert_eq!(recovering.screen, Screen::Edit);
    }
}
#[test]
fn review_logic4_mutex_subprocess_child() {
    let Some(path) = std::env::var_os("JAIBA_REVIEW_MUTEX_PRIMARY") else {
        return;
    };
    let path = PathBuf::from(path);
    let mut app = loaded(path.clone());
    rekey(&mut app);
    assert!(app.status.as_ref().unwrap().contains("busy"));
    draft(&mut app);
    assert!(!app.lock_cooperatively());
    assert!(app.pending_draft.is_some());
    assert!(db::unlock_database(&path, "synthetic master", None).is_ok());
}
#[test]
fn review_logic4_stable_mutex_excludes_subprocess_and_survives_rekey() {
    use std::os::unix::fs::MetadataExt;
    let f = Fixture::new();
    let mut app = f.app();
    let path = app.database_path().unwrap().to_owned();
    let alias = f.0.join("alias.kdbx");
    std::os::unix::fs::symlink(&path, &alias).unwrap();
    let transaction = recovery::Transaction::begin(&path).unwrap();
    let mutex = recovery::directory(&path).join("transaction.lock");
    let before = fs::metadata(&mutex).unwrap();
    assert_eq!(before.mode() & 0o777, 0o600);
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "r4_review_tests::review_logic4_mutex_subprocess_child",
            "--nocapture",
        ])
        .env("JAIBA_REVIEW_MUTEX_PRIMARY", &alias)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "child failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    drop(transaction);
    rekey(&mut app);
    assert!(db::unlock_database(&path, "new synthetic master", None).is_ok());
    let after = fs::metadata(&mutex).unwrap();
    assert_eq!(
        (before.dev(), before.ino()),
        (after.dev(), after.ino()),
        "never unlink transaction mutex"
    );
    let next = recovery::Transaction::begin(&alias).unwrap();
    drop(next);
}
#[test]
fn review_logic4_mutex_refuses_unsafe_files_and_hardlinked_primary() {
    let f = Fixture::new();
    let mut app = f.app();
    let path = app.database_path().unwrap().to_owned();
    drop(recovery::Transaction::begin(&path).unwrap());
    let mutex = recovery::directory(&path).join("transaction.lock");
    fs::set_permissions(&mutex, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(recovery::Transaction::begin(&path).is_err());
    fs::set_permissions(&mutex, fs::Permissions::from_mode(0o600)).unwrap();
    let saved = mutex.with_extension("saved");
    fs::rename(&mutex, &saved).unwrap();
    std::os::unix::fs::symlink(&saved, &mutex).unwrap();
    assert!(recovery::Transaction::begin(&path).is_err());
    fs::remove_file(&mutex).unwrap();
    fs::rename(&saved, &mutex).unwrap();
    let hard = f.0.join("hard.kdbx");
    fs::hard_link(&path, &hard).unwrap();
    assert!(recovery::Transaction::begin(&path).is_err());
    draft(&mut app);
    assert!(!app.lock_cooperatively());
    assert!(app.pending_draft.is_some());
}
fn existing_draft(app: &mut App) -> Entry {
    let path = app.database_path().unwrap().to_owned();
    let mut entry = Entry {
        name: "synthetic original".into(),
        ..Default::default()
    };
    db::save_database(
        &path,
        app.db_key.as_ref().unwrap(),
        app.kdbx.as_mut().unwrap(),
        std::slice::from_mut(&mut entry),
    )
    .unwrap();
    app.entries.push(entry.clone());
    app.edit_entry = Some(entry.clone());
    app.edit_original = Some(entry.clone());
    app.edit_target = Some(0);
    app.screen = Screen::Edit;
    app.edit_entry.as_mut().unwrap().password = "synthetic unsaved password".into();
    entry
}
#[test]
fn review_logic3_retirement_preserves_in_place_ciphertext_replacement() {
    let f = Fixture::new();
    let mut app = f.app();
    existing_draft(&mut app);
    assert!(app.lock_cooperatively());
    auth(&mut app);
    let file = sidecar(&app);
    fs::write(&file, b"synthetic in-place replacement").unwrap();
    input::edit::handle_edit_input(&mut app, KeyCode::Char('d'));
    input::edit::handle_edit_input(&mut app, KeyCode::Char('y'));
    assert_eq!(
        fs::read(&file).unwrap(),
        b"synthetic in-place replacement",
        "retirement must not remove changed ciphertext even on the same inode"
    );
    assert!(app.edit_entry.is_some() && app.edit_deleted);
    assert!(!app.draft_durable);
    assert!(!app.lock_cooperatively());
}
#[test]
fn review_logic3_committed_delete_with_failed_retirement_is_accurate_and_retryable() {
    let f = Fixture::new();
    let mut app = f.app();
    let entry = existing_draft(&mut app);
    let path = app.database_path().unwrap().to_owned();
    assert!(app.lock_cooperatively());
    auth(&mut app);
    assert_eq!(app.screen, Screen::Edit);
    let file = sidecar(&app);
    fs::remove_file(&file).unwrap();
    fs::write(&file, b"synthetic replacement").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    input::edit::handle_edit_input(&mut app, KeyCode::Char('d'));
    input::edit::handle_edit_input(&mut app, KeyCode::Char('y'));
    assert!(
        db::unlock_database(&path, "synthetic master", None)
            .unwrap()
            .2
            .is_empty()
    );
    assert_eq!(app.screen, Screen::Edit);
    assert_eq!(
        app.edit_entry
            .as_ref()
            .expect("keep accurate editor until cleanup")
            .id,
        entry.id
    );
    assert!(!app.draft_durable, "unresolved retirement is not durable");
    assert!(!app.lock_cooperatively());
    assert!(app.pending_draft.is_some());
    auth(&mut app);
    assert_eq!(app.screen, Screen::Edit);
    // A save shortcut must not silently resurrect a committed deletion.
    input::edit::handle_edit_input(&mut app, KeyCode::Esc);
    input::edit::handle_edit_input(&mut app, KeyCode::Char('y'));
    assert!(
        db::unlock_database(&path, "synthetic master", None)
            .unwrap()
            .2
            .is_empty()
    );
    assert_eq!(fs::read(&file).unwrap(), b"synthetic replacement");
    fs::remove_file(&file).unwrap();
    input::edit::handle_edit_input(&mut app, KeyCode::Char('d'));
    input::edit::handle_edit_input(&mut app, KeyCode::Char('y'));
    assert_eq!(app.screen, Screen::Index);
    assert!(app.edit_entry.is_none());
    assert!(
        db::unlock_database(&path, "synthetic master", None)
            .unwrap()
            .2
            .is_empty()
    );
    assert!(app.lock_cooperatively());
}
#[test]
fn review_logic2_publication_rejects_target_deleted_before_lock() {
    let f = Fixture::new();
    let mut app = f.app();
    let entry = existing_draft(&mut app);
    let path = app.database_path().unwrap().to_owned();
    let (mut external, key, _) = db::unlock_database(&path, "synthetic master", None).unwrap();
    db::delete_entry(&path, &key, &mut external, entry.id.unwrap()).unwrap();
    assert!(
        !app.lock_cooperatively(),
        "do not publish a snapshot whose existing target cannot be restored"
    );
    assert!(app.pending_draft.is_some());
}
#[test]
fn review_logic2_failed_restore_keeps_memory_and_false_durability_until_target_fixed() {
    let f = Fixture::new();
    let mut app = f.app();
    let entry = existing_draft(&mut app);
    let path = app.database_path().unwrap().to_owned();
    let mut original = app.kdbx.as_ref().unwrap().clone();
    let key = app.db_key.as_ref().unwrap().clone();
    let dir = recovery::directory(&path);
    fs::write(&dir, b"synthetic blocker").unwrap();
    assert!(!app.lock_cooperatively());
    assert!(app.pending_draft.is_some());
    let (mut external, _, _) = db::unlock_database(&path, "synthetic master", None).unwrap();
    db::delete_entry(&path, &key, &mut external, entry.id.unwrap()).unwrap();
    fs::remove_file(&dir).unwrap();
    auth(&mut app);
    assert_eq!(app.screen, Screen::Login);
    assert!(
        app.login_error
            .as_ref()
            .unwrap()
            .contains("no longer exists")
    );
    assert!(
        app.pending_draft.is_some(),
        "known unrestorable memory draft must not be dropped"
    );
    assert!(!app.draft_durable);
    assert!(!app.lock_cooperatively());
    input::login::handle_login_input(&mut app, KeyCode::Esc);
    assert!(!app.should_quit);
    assert!(
        !dir.exists(),
        "failed restore must not publish a knowingly unusable snapshot"
    );
    db::save_database(&path, &key, &mut original, &mut []).unwrap();
    auth(&mut app);
    assert_eq!(app.screen, Screen::Edit);
    assert_eq!(app.edit_entry.as_ref().unwrap().id, entry.id);
    assert_eq!(
        app.edit_entry.as_ref().unwrap().password,
        "synthetic unsaved password"
    );
    assert!(app.lock_cooperatively());
}
#[test]
fn review_logic1_repeated_lock_revalidates_exact_ciphertext_and_lock_identity() {
    for fault in [
        "corrupt", "delete", "replace", "mode", "lock", "truncate", "replay",
    ] {
        let f = Fixture::new();
        let mut app = f.app();
        draft(&mut app);
        assert!(app.lock_cooperatively());
        let file = sidecar(&app);
        let old = fs::read(&file).unwrap();
        auth(&mut app);
        assert_eq!(app.screen, Screen::Edit);
        app.field_buffer.push_str(" changed");
        assert!(app.lock_cooperatively());
        assert!(app.db_key.is_none());
        assert!(
            app.lock_cooperatively(),
            "unchanged ciphertext remains durable without a key"
        );
        match fault {
            "corrupt" => {
                let mut bytes = fs::read(&file).unwrap();
                let end = bytes.len() - 1;
                bytes[end] ^= 1;
                fs::write(&file, bytes).unwrap();
            }
            "delete" => fs::remove_file(&file).unwrap(),
            "replace" => {
                fs::remove_file(&file).unwrap();
                fs::write(&file, fs::read(app.database_path().unwrap()).unwrap()).unwrap();
                fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
            }
            "mode" => fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap(),
            "lock" => {
                let mut lock = file.as_os_str().to_os_string();
                lock.push(".lock");
                fs::remove_file(&lock).unwrap();
                fs::write(&lock, []).unwrap();
                fs::set_permissions(lock, fs::Permissions::from_mode(0o600)).unwrap();
            }
            "truncate" => fs::write(&file, []).unwrap(),
            "replay" => fs::write(&file, &old).unwrap(),
            _ => unreachable!(),
        }
        assert!(
            !app.lock_cooperatively(),
            "changed artifact {fault} must invalidate durability"
        );
        assert!(!app.draft_durable);
        assert!(
            !app.lock_cooperatively(),
            "failure cannot revert to cached true"
        );
    }
}
#[test]
fn review_sec2_lock_erases_owned_strings_and_preserves_native_expiration_without_io() {
    let mut app = App::for_test(None);
    app.password = "synthetic master".into();
    app.field_buffer = "synthetic field".into();
    app.new_password_buffer = "synthetic new master".into();
    let len = app.password.len();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(600);
    let copied_len = "synthetic clipboard secret".len();
    app.clipboard_timer = Some(crate::clipboard::ClipboardTimer {
        label: "password".into(),
        expected: "synthetic clipboard secret".into(),
        fingerprint: None,
        clear_at: deadline,
    });
    assert!(app.lock_cooperatively());
    let timer = app
        .clipboard_timer
        .as_ref()
        .expect("native expiration survives lock");
    assert_eq!(timer.clear_at, deadline);
    assert_eq!(timer.label, "password");
    assert!(
        timer.matches_text("synthetic clipboard secret"),
        "matching clipboard should clear"
    );
    assert!(
        !timer.matches_text("synthetic different content"),
        "different clipboard must be preserved"
    );
    assert!(
        !timer.matches_text(""),
        "erased plaintext is not the comparison value"
    );
    assert!(
        timer.expected.is_empty(),
        "no reachable copied plaintext after lock"
    );
    assert!(timer.expected.capacity() >= copied_len);
    let erased = unsafe { std::slice::from_raw_parts(timer.expected.as_ptr(), copied_len) };
    assert!(
        erased.iter().all(|b| *b == 0),
        "copied secret must be zeroized"
    );
    assert!(
        app.clipboard.is_none(),
        "locking must not acquire a clipboard/display"
    );
    // The retained String allocation is still live; inspect only initialized old bytes.
    assert!(app.password.capacity() >= len);
    let bytes = unsafe { std::slice::from_raw_parts(app.password.as_ptr(), len) };
    assert!(
        bytes.iter().all(|b| *b == 0),
        "String::clear is not erasure"
    );
    assert!(app.field_buffer.is_empty() && app.new_password_buffer.is_empty());
    let fingerprint = app.clipboard_timer.as_ref().unwrap().fingerprint;
    assert!(app.lock_cooperatively());
    let timer = app.clipboard_timer.as_ref().unwrap();
    assert_eq!(timer.clear_at, deadline);
    assert_eq!(
        timer.fingerprint, fingerprint,
        "repeated lock must not hash the erased empty string"
    );
    assert!(timer.matches_text("synthetic clipboard secret"));
    crate::clipboard::maybe_clear_clipboard(&mut app);
    assert!(
        app.clipboard_timer.is_some(),
        "unexpired native timer is still scheduled"
    );
    assert!(app.clipboard.is_none());
}
#[test]
fn review_sec1_changed_primary_policy_during_publication_keeps_memory() {
    let f = Fixture::new();
    let app = f.app();
    let path = app.database_path().unwrap().to_owned();
    drop(app);
    let editor_path = path.clone();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let mut editing = loaded(editor_path);
        draft(&mut editing);
        recovery::interleave::PUBLICATION.with(|h| *h.borrow_mut() = Some((ready_tx, resume_rx)));
        let durable = editing.lock_cooperatively();
        (durable, editing.pending_draft.is_some())
    });
    ready_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    let (mut external, key, _) = db::unlock_database(&path, "synthetic master", None).unwrap();
    external.config.kdf_config = KdfConfig::Aes { rounds: 4096 };
    db::save_database(&path, &key, &mut external, &mut []).unwrap();
    resume_tx.send(()).unwrap();
    let (durable, memory) = worker.join().unwrap();
    assert!(
        !durable,
        "a primary changed after authentication invalidates the publication receipt"
    );
    assert!(memory);
}
#[test]
fn review_sec1_sidecar_uses_revalidated_primary_policy_not_stale_cache() {
    let f = Fixture::new();
    let mut app = f.app();
    let path = app.database_path().unwrap().to_owned();
    let (mut external, key, _) = db::unlock_database(&path, "synthetic master", None).unwrap();
    external.config.kdf_config = KdfConfig::Aes { rounds: 1024 };
    db::save_database(&path, &key, &mut external, &mut []).unwrap();
    draft(&mut app);
    assert!(app.lock_cooperatively());
    let side = Database::open(&mut fs::File::open(sidecar(&app)).unwrap(), key).unwrap();
    assert_eq!(side.config.kdf_config, external.config.kdf_config);
}
#[test]
fn review_sec1_sidecar_preserves_kdf_and_ciphers_with_fresh_seeds() {
    let version = match Database::new().config.kdf_config {
        KdfConfig::Argon2 { version, .. } => version,
        _ => panic!("default Argon2"),
    };
    for kdf in [
        KdfConfig::Argon2id {
            iterations: 2,
            memory: 2 * 1024 * 1024,
            parallelism: 2,
            version,
        },
        KdfConfig::Aes { rounds: 257 },
    ] {
        let f = Fixture::new();
        let mut app = f.app();
        let path = app.database_path().unwrap().to_owned();
        let database = app.kdbx.as_mut().unwrap();
        database.config.kdf_config = kdf.clone();
        database.config.outer_cipher_config = OuterCipherConfig::ChaCha20;
        database.config.inner_cipher_config = InnerCipherConfig::Salsa20;
        db::save_database(&path, app.db_key.as_ref().unwrap(), database, &mut []).unwrap();
        let primary_bytes = fs::read(&path).unwrap();
        let key = app.db_key.as_ref().unwrap().clone();
        draft(&mut app);
        assert!(app.lock_cooperatively());
        let file = sidecar(&app);
        let first = fs::read(&file).unwrap();
        let saved = Database::open(&mut fs::File::open(&file).unwrap(), key.clone()).unwrap();
        assert_eq!(
            saved.config.kdf_config, kdf,
            "never create a weaker credential oracle"
        );
        assert_eq!(
            saved.config.outer_cipher_config,
            OuterCipherConfig::ChaCha20
        );
        assert_eq!(saved.config.inner_cipher_config, InnerCipherConfig::Salsa20);
        assert!(matches!(
            saved.config.version,
            keepass::config::DatabaseVersion::KDB4(_)
        ));
        auth(&mut app);
        assert_eq!(app.screen, Screen::Edit);
        assert!(app.lock_cooperatively());
        assert_ne!(
            first,
            fs::read(&file).unwrap(),
            "library generates fresh seeds on each save"
        );
        assert_eq!(
            primary_bytes,
            fs::read(&path).unwrap(),
            "no primary conversion or write"
        );
    }
}
