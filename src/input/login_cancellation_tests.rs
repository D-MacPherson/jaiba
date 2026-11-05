//! Deterministic post-helper cancellation; no USB or production files.
use super::*;
use std::cell::RefCell;
use std::fs;
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

thread_local! {
    static INJECTION: RefCell<Option<(&'static str, Arc<AtomicBool>)>> = const { RefCell::new(None) };
    static VISITED: RefCell<Vec<&'static str>> = const { RefCell::new(Vec::new()) };
}

pub(super) fn checkpoint(stage: &'static str) {
    VISITED.with(|v| v.borrow_mut().push(stage));
    INJECTION.with(|i| {
        if let Some((target, flag)) = i.borrow().as_ref() {
            if *target == stage {
                assert!(
                    challenge_response::operation::check().is_ok(),
                    "helper returned before cancellation"
                );
                flag.store(true, Ordering::SeqCst);
            }
        }
    });
}

struct Injection {
    _cancellation: challenge_response::operation::Cancellation,
}
impl Injection {
    fn at(stage: &'static str) -> Self {
        let flag = Arc::new(AtomicBool::new(false));
        VISITED.with(|v| v.borrow_mut().clear());
        INJECTION.with(|i| *i.borrow_mut() = Some((stage, Arc::clone(&flag))));
        Self {
            _cancellation: challenge_response::operation::Cancellation::install(flag),
        }
    }
}
impl Drop for Injection {
    fn drop(&mut self) {
        INJECTION.with(|i| i.borrow_mut().take());
    }
}

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        use std::os::unix::fs::DirBuilderExt;
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "jaiba-login-cancel-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        Self(root)
    }
    fn path(&self) -> PathBuf {
        self.0.join("synthetic.kdbx")
    }
    fn login(&self) -> App {
        let mut app = App::for_test(Some(self.path()));
        app.screen = Screen::Login;
        app.password = "synthetic master".into();
        app
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn assert_cancelled(app: &App, stage: &'static str) {
    VISITED.with(|v| assert!(v.borrow().contains(&stage), "injection was reached"));
    assert_eq!(
        app.screen,
        Screen::Login,
        "late cancellation must not expose decrypted UI"
    );
    assert!(app.db_key.is_none() && app.kdbx.is_none() && app.primary_revision.is_none());
    assert!(app.entries.is_empty() && app.filtered.is_empty());
    assert!(app.password.is_empty() && app.new_db_confirm.is_empty());
    assert!(
        matches!(
            challenge_response::operation::check(),
            Err(challenge_response::error::ChallengeResponseError::Cancelled)
        ),
        "coordinator still owns the pending signal flag"
    );
    assert!(
        app.login_error
            .as_ref()
            .is_some_and(|s| s.contains("cancelled")),
        "{:?}",
        app.login_error
    );
    VISITED.with(|v| {
        assert!(
            !v.borrow().contains(&"recover_started"),
            "no recovery work after cancellation"
        )
    });
}

fn cancellation_during_install(create: bool) {
    let f = Fixture::new();
    if !create {
        crate::db::create_database(&f.path(), "synthetic master", None).unwrap();
    }
    let mut app = f.login();
    app.creating_database = create;
    app.confirming_new_db_password = create;
    app.new_db_confirm = if create {
        app.password.clone()
    } else {
        String::new()
    };
    let _injection = Injection::at("installing");
    handle_login_input(&mut app, KeyCode::Enter);
    assert_cancelled(&app, "installing");
    assert!(f.path().is_file());
}

#[test]
fn unlock_cancellation_during_install_revokes_credentials() {
    cancellation_during_install(false);
}

#[test]
fn create_cancellation_during_install_revokes_credentials() {
    cancellation_during_install(true);
}

#[test]
fn cancellation_before_recovery_keeps_memory_draft_hidden() {
    let f = Fixture::new();
    crate::db::create_database(&f.path(), "synthetic master", None).unwrap();
    let mut app = f.login();
    handle_login_input(&mut app, KeyCode::Enter);
    assert_eq!(app.screen, Screen::Index);
    app.screen = Screen::Edit;
    app.edit_entry = Some(crate::db::Entry::default());
    app.edit_original = Some(crate::db::Entry::default());
    app.editing_field = true;
    app.field_buffer = "synthetic pending notes".into();
    app.pending_draft = crate::recovery::Draft::capture(&app);
    app.hide_failed_recovery();
    app.password = "synthetic master".into();
    assert!(app.pending_draft.is_some());
    let _injection = Injection::at("before_recovery");
    handle_login_input(&mut app, KeyCode::Enter);
    assert_cancelled(&app, "before_recovery");
    assert!(
        app.pending_draft.is_some(),
        "recovery must not consume hidden draft"
    );
    assert!(app.edit_entry.is_none() && app.field_buffer.is_empty());
    drop(_injection);
    app.password = "synthetic master".into();
    handle_login_input(&mut app, KeyCode::Enter);
    assert_eq!(app.screen, Screen::Edit, "{:?}", app.login_error);
    assert_eq!(app.field_buffer, "synthetic pending notes");
    assert!(app.pending_draft.is_none());
}

#[test]
fn create_cancelled_after_helper_and_config_before_install() {
    let f = Fixture::new();
    let mut app = f.login();
    app.creating_database = true;
    app.confirming_new_db_password = true;
    app.new_db_confirm = app.password.clone();
    let _injection = Injection::at("create_ready");
    handle_login_input(&mut app, KeyCode::Enter);
    assert!(f.path().is_file(), "created ciphertext must be preserved");
    assert_cancelled(&app, "create_ready");
}

#[test]
fn cancelled_unlock_without_draft_preserves_durability_receipt() {
    let f = Fixture::new();
    crate::db::create_database(&f.path(), "synthetic master", None).unwrap();
    let mut app = f.login();
    assert!(app.draft_durable);
    let _injection = Injection::at("unlock_ready");
    handle_login_input(&mut app, KeyCode::Enter);
    assert_cancelled(&app, "unlock_ready");
    assert!(
        app.draft_durable,
        "no recovery was attempted; do not invent a lost draft"
    );
    assert!(app.lock_cooperatively(), "no draft needs persistence");
}

#[test]
fn unlock_cancelled_after_helper_before_install() {
    let f = Fixture::new();
    crate::db::create_database(&f.path(), "synthetic master", None).unwrap();
    let mut app = f.login();
    let _injection = Injection::at("unlock_ready");
    handle_login_input(&mut app, KeyCode::Enter);
    assert_cancelled(&app, "unlock_ready");
}
