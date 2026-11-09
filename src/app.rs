use std::io;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use arboard::Clipboard;
use crossterm::event::{self, Event};
use keepass::{Database, DatabaseKey};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    style::Style,
    widgets::{Block, ListState, TableState},
};
use zeroize::Zeroize;

use crate::clipboard::{ClipboardTimer, maybe_clear_clipboard};
use crate::config::{Config, load_config};
use crate::db::Entry;
use crate::input::edit::handle_edit_input;
use crate::input::index::handle_index_input;
use crate::input::login::handle_login_input;
use crate::input::settings::handle_settings_input;
use crate::theme::{Theme, load_theme};
use crate::ui::edit::draw_edit;
use crate::ui::index::draw_index;
use crate::ui::login::draw_login;
use crate::ui::settings::draw_settings;

#[derive(Debug, PartialEq, Eq)]
pub enum Screen {
    Login,
    Index,
    Edit,
    Settings,
}

#[derive(PartialEq, Eq)]
pub enum PasswordChangeStep {
    CurrentPassword,
    NewPassword,
    ConfirmNewPassword,
}

#[derive(PartialEq, Eq)]
pub enum ImportStep {
    Path,
    KdbxPassword,
}

#[derive(PartialEq, Eq)]
pub enum ExportStep {
    Path,
    Confirm,
}

pub struct App {
    pub screen: Screen,
    pub password: String,
    pub query: String,
    pub max_len: usize,
    pub index_state: TableState,
    pub edit_state: ListState,
    pub reveal_password: bool,
    pub edit_entry: Option<Entry>,
    pub edit_original: Option<Entry>,
    pub edit_target: Option<usize>,
    pub edit_deleted: bool,
    pub editing_field: bool,
    pub field_buffer: String,
    pub confirm_delete: bool,
    pub confirm_exit: bool,
    pub entries: Vec<Entry>,
    pub filtered: Vec<usize>,
    pub kdbx: Option<Database>,
    pub db_key: Option<DatabaseKey>,
    pub primary_revision: Option<crate::db::Revision>,
    pub open_database: Option<PathBuf>,
    pub open_keyfile: Option<PathBuf>,
    pub open_yubikey: Option<crate::config::YubikeyPolicy>,
    pub pending_draft: Option<crate::recovery::Draft>,
    pub draft_slot: Option<crate::recovery::Slot>,
    pub draft_durable: bool,
    pub theme: Theme,
    pub config: Config,

    pub creating_database: bool,
    pub confirming_new_db_password: bool,
    pub new_db_confirm: String,

    pub available_themes: Vec<String>,
    pub settings_state: ListState,
    pub choosing_theme: bool,
    pub theme_state: ListState,

    pub changing_password: bool,
    pub password_change_step: PasswordChangeStep,
    pub current_password_buffer: String,
    pub new_password_buffer: String,
    pub new_password_confirm: String,

    pub importing_database: bool,
    pub import_step: ImportStep,
    pub import_path_buffer: String,
    pub import_kdbx_password_buffer: String,
    pub pending_import_path: Option<PathBuf>,

    pub exporting_database: bool,
    pub export_step: ExportStep,
    pub export_path_buffer: String,
    pub pending_export_path: Option<PathBuf>,

    pub login_error: Option<String>,

    pub last_activity: Instant,

    pub status: Option<String>,

    pub clipboard: Option<Clipboard>,
    pub terminal_clipboard: bool,

    pub clipboard_timer: Option<ClipboardTimer>,

    pub should_quit: bool,
    pub slim_mode: bool,
}

impl App {
    /// A clipboard-free `App` for tests: no terminal, no system clipboard.
    #[cfg(test)]
    pub fn for_test(database_path: Option<PathBuf>) -> Self {
        Self {
            screen: Screen::Index,
            password: String::new(),
            query: String::new(),
            max_len: 0,
            index_state: TableState::default().with_selected(Some(0)),
            edit_state: ListState::default(),
            reveal_password: false,
            edit_entry: None,
            edit_original: None,
            edit_target: None,
            edit_deleted: false,
            editing_field: false,
            field_buffer: String::new(),
            confirm_delete: false,
            confirm_exit: false,
            entries: Vec::new(),
            filtered: Vec::new(),
            kdbx: None,
            db_key: None,
            primary_revision: None,
            open_database: None,
            open_keyfile: None,
            open_yubikey: None,
            pending_draft: None,
            draft_slot: None,
            draft_durable: true,
            theme: Theme::default(),
            config: Config {
                default_database: database_path,
                ..Config::default()
            },
            creating_database: false,
            confirming_new_db_password: false,
            new_db_confirm: String::new(),
            available_themes: Vec::new(),
            settings_state: ListState::default(),
            choosing_theme: false,
            theme_state: ListState::default(),
            changing_password: false,
            password_change_step: PasswordChangeStep::CurrentPassword,
            current_password_buffer: String::new(),
            new_password_buffer: String::new(),
            new_password_confirm: String::new(),
            importing_database: false,
            import_step: ImportStep::Path,
            import_path_buffer: String::new(),
            import_kdbx_password_buffer: String::new(),
            pending_import_path: None,
            exporting_database: false,
            export_step: ExportStep::Path,
            export_path_buffer: String::new(),
            pending_export_path: None,
            login_error: None,
            last_activity: Instant::now(),
            status: None,
            clipboard: None,
            terminal_clipboard: false,
            clipboard_timer: None,
            should_quit: false,
            slim_mode: false,
        }
    }

    fn compute_filtered(&self) -> Vec<usize> {
        let query = self.query.to_lowercase();

        let mut indices: Vec<usize> = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                query.is_empty()
                    || entry.name.to_lowercase().contains(&query)
                    || entry.user.to_lowercase().contains(&query)
            })
            .map(|(i, _)| i)
            .collect();

        indices.sort_by(|&a, &b| {
            let ea = &self.entries[a];
            let eb = &self.entries[b];

            eb.password_reuse_count
                .cmp(&ea.password_reuse_count)
                .then_with(|| eb.duplicate_user_count.cmp(&ea.duplicate_user_count))
                .then_with(|| ea.name.to_lowercase().cmp(&eb.name.to_lowercase()))
        });

        indices
    }

    pub fn refresh_filter(&mut self) {
        self.filtered = self.compute_filtered();

        let count = self.filtered.len();
        self.index_state
            .select(if count == 0 { None } else { Some(0) });
    }

    pub fn selected_entry(&self) -> Option<&Entry> {
        let selected = self.index_state.selected()?;
        let entry_idx = *self.filtered.get(selected)?;
        self.entries.get(entry_idx)
    }
}

fn maybe_auto_lock(app: &mut App) {
    if !matches!(app.screen, Screen::Index | Screen::Edit | Screen::Settings) {
        return;
    }

    if app.last_activity.elapsed() < app.config.auto_lock {
        return;
    }

    app.lock_cooperatively();
}

impl App {
    pub fn database_path(&self) -> Option<&std::path::Path> {
        self.open_database
            .as_deref()
            .or(self.config.default_database.as_deref())
    }

    /// Keep this nonblocking guard alive from validation through replacement.
    pub fn begin_primary_write(&self) -> anyhow::Result<crate::recovery::Transaction> {
        anyhow::ensure!(
            self.kdbx.is_some() && self.db_key.is_some(),
            "database is locked"
        );
        let path = self
            .database_path()
            .ok_or_else(|| anyhow::anyhow!("no unlocked database"))?;
        let transaction = crate::recovery::Transaction::begin(path)?;
        self.primary_revision
            .as_ref()
            .ok_or_else(|| {
                anyhow::anyhow!("No authenticated primary revision; authenticate again")
            })?
            .revalidate(&transaction.path)?;
        Ok(transaction)
    }

    pub fn database_keyfile(&self) -> Option<&std::path::Path> {
        if self.open_database.is_some() {
            self.open_keyfile.as_deref()
        } else {
            self.config.keyfile.as_deref()
        }
    }

    pub fn database_yubikey(&self) -> Option<crate::config::YubikeyPolicy> {
        if self.open_database.is_some() {
            self.open_yubikey.clone()
        } else {
            self.config.yubikey.clone()
        }
    }

    /// Reject ordinary actions that could bypass unresolved memory recovery.
    /// This performs no persistence or authentication and never consumes the draft.
    pub fn protect_memory_draft(&mut self) -> bool {
        if self.pending_draft.is_none() {
            return false;
        }
        self.hide_failed_recovery();
        self.should_quit = false;
        self.login_error = Some(
            "Draft only in memory. KEEP THIS WINDOW OPEN. Restore the original vault and its configured path, then authenticate to recover before creating another vault or exiting."
                .into(),
        );
        true
    }

    /// Called only by the normal application loop, never a signal handler.
    pub fn hide_failed_recovery(&mut self) {
        // Authentication succeeded but the snapshot is not usable. Do not turn
        // that known failure into a fresh durable publication or lose memory.
        self.draft_durable = false;
        clear_unlocked_state(self);
    }

    /// Called only by the normal application loop, never a signal handler.
    pub fn lock_cooperatively(&mut self) -> bool {
        let _operation = challenge_response::operation::Operation::standard();
        if let Some(draft) = crate::recovery::Draft::capture(self) {
            self.pending_draft = Some(draft);
            self.draft_durable = false;
        }
        if self.open_database.is_none() {
            self.open_database = self.config.default_database.clone();
            self.open_keyfile = self.config.keyfile.clone();
            self.open_yubikey = self.config.yubikey.clone();
        }
        if let Some(draft) = self.pending_draft.clone() {
            if crate::recovery::persist(self, &draft).is_ok() {
                self.pending_draft = None;
                self.draft_durable = true;
            }
        }
        // No credential-bearing work remains. Revoke before any key-free
        // durability revalidation, which may itself encounter slow storage.
        clear_unlocked_state(self);
        if self.draft_durable {
            if let Some(slot) = &self.draft_slot {
                self.draft_durable = slot.revalidate().is_ok();
            }
        }
        self.login_error = Some(if self.pending_draft.is_some() {
            "Locked; draft only in memory. KEEP THIS WINDOW OPEN and authenticate to recover."
                .into()
        } else if !self.draft_durable {
            "Locked; draft durability not confirmed. KEEP THIS WINDOW OPEN and keep recovery files."
                .into()
        } else {
            "Locked; authenticate to continue".into()
        });
        self.pending_draft.is_none() && self.draft_durable
    }
}

fn clear_unlocked_state(app: &mut App) {
    // Erase buffers we own, not a claim of exhaustive heap/library erasure.
    for entry in &mut app.entries {
        entry.zeroize();
    }
    if let Some(entry) = &mut app.edit_entry {
        entry.zeroize();
    }
    if let Some(entry) = &mut app.edit_original {
        entry.zeroize();
    }
    if let Some(timer) = app.clipboard_timer.as_mut() {
        timer.forget_plaintext();
    }
    app.entries.clear();
    app.filtered.clear();
    app.password.zeroize();
    app.query.zeroize();
    app.kdbx = None;
    app.db_key = None;
    app.primary_revision = None;
    app.edit_entry = None;
    app.edit_original = None;
    app.edit_target = None;
    app.edit_deleted = false;
    app.editing_field = false;
    app.field_buffer.zeroize();
    app.confirm_delete = false;
    app.confirm_exit = false;
    app.reveal_password = false;
    app.available_themes.clear();
    app.settings_state.select(None);
    app.choosing_theme = false;
    app.theme_state.select(None);
    app.creating_database = false;
    app.confirming_new_db_password = false;
    app.new_db_confirm.zeroize();
    app.changing_password = false;
    app.password_change_step = PasswordChangeStep::CurrentPassword;
    app.current_password_buffer.zeroize();
    app.new_password_buffer.zeroize();
    app.new_password_confirm.zeroize();
    app.importing_database = false;
    app.import_step = ImportStep::Path;
    app.import_path_buffer.zeroize();
    app.import_kdbx_password_buffer.zeroize();
    app.pending_import_path = None;
    app.exporting_database = false;
    app.export_step = ExportStep::Path;
    app.export_path_buffer.zeroize();
    app.pending_export_path = None;
    app.screen = Screen::Login;
    app.status = None;
}

pub fn run(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    slim_mode: bool,
) -> io::Result<()> {
    // Authentication factors must never disappear behind default configuration.
    let mut config = load_config().map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid config: {err:#}"),
        )
    })?;
    // Refuse unsafe vault registration before reading credentials or opening a clipboard.
    let mut registration = crate::locking::Registration::start()?;
    let terminal_clipboard =
        crate::terminal_clipboard::enabled(std::env::var_os("JAIBA_CLIPBOARD_BACKEND").as_deref())?;
    let _ = crate::theme::ensure_default_themes();

    if config.default_database.is_none() {
        let default_path = crate::util::default_new_database_path();
        if default_path.is_file() {
            config.default_database = Some(default_path);
            let _ = crate::config::save_config(&config);
        }
    }

    let theme = load_theme(config.theme.as_deref()).unwrap_or_default();

    let mut app = App {
        screen: Screen::Login,
        password: String::new(),
        query: String::new(),
        max_len: 0,
        theme,
        config,
        available_themes: Vec::new(),
        settings_state: ListState::default(),
        choosing_theme: false,
        theme_state: ListState::default(),
        changing_password: false,
        password_change_step: PasswordChangeStep::CurrentPassword,
        current_password_buffer: String::new(),
        new_password_buffer: String::new(),
        new_password_confirm: String::new(),
        importing_database: false,
        import_step: ImportStep::Path,
        import_path_buffer: String::new(),
        import_kdbx_password_buffer: String::new(),
        pending_import_path: None,
        exporting_database: false,
        export_step: ExportStep::Path,
        export_path_buffer: String::new(),
        pending_export_path: None,
        login_error: None,
        last_activity: Instant::now(),
        index_state: TableState::default().with_selected(Some(0)),
        edit_state: ListState::default(),
        reveal_password: false,
        edit_entry: None,
        edit_original: None,
        edit_target: None,
        edit_deleted: false,
        editing_field: false,
        field_buffer: String::new(),
        confirm_delete: false,
        confirm_exit: false,
        entries: Vec::new(),
        filtered: Vec::new(),
        kdbx: None,
        db_key: None,
        primary_revision: None,
        open_database: None,
        open_keyfile: None,
        open_yubikey: None,
        pending_draft: None,
        draft_slot: None,
        draft_durable: true,
        creating_database: false,
        confirming_new_db_password: false,
        new_db_confirm: String::new(),
        status: None,
        clipboard: if terminal_clipboard {
            None
        } else {
            Clipboard::new().ok()
        },
        terminal_clipboard,
        clipboard_timer: None,
        should_quit: false,
        slim_mode,
    };

    const TICK_RATE: Duration = Duration::from_millis(200);

    loop {
        if let Some(registration) = registration.as_mut() {
            if registration.process(&mut app).is_err() {
                // No acknowledgement on invalid/unsafe requests or failed publication.
                // Keep the process and any recoverable memory draft alive.
                if app.screen == Screen::Login {
                    app.login_error = Some(
                        "Lock protocol failed; check the controller result. Keep this window open."
                            .into(),
                    );
                } else {
                    app.status =
                        Some("Lock protocol request rejected or acknowledgement failed".into());
                }
            }
        }
        let background = terminal
            .draw(|frame| {
                frame.render_widget(
                    Block::default().style(Style::default().bg(app.theme.background)),
                    frame.area(),
                );

                match app.screen {
                    Screen::Login => draw_login(frame, &mut app),
                    Screen::Index => draw_index(frame, &mut app),
                    Screen::Edit => draw_edit(frame, &mut app),
                    Screen::Settings => draw_settings(frame, &mut app),
                }
            })?
            .buffer
            .clone();

        if event::poll(TICK_RATE)? {
            if registration.as_ref().is_some_and(|r| r.pending()) {
                continue;
            }
            if let Event::Key(key) = event::read()? {
                if registration.as_ref().is_some_and(|r| r.pending()) {
                    continue;
                }
                app.last_activity = Instant::now();

                let _operation = challenge_response::operation::Operation::standard();
                crate::ui::touch::with_prompt(
                    terminal,
                    background,
                    Style::default()
                        .fg(app.theme.warning)
                        .bg(app.theme.background),
                    || match app.screen {
                        Screen::Login => handle_login_input(&mut app, key.code),
                        Screen::Index => handle_index_input(&mut app, key),
                        Screen::Edit => handle_edit_input(&mut app, key.code),
                        Screen::Settings => handle_settings_input(&mut app, key.code),
                    },
                )?;
            }
        }

        // A cancelled synchronous handler must not do clipboard I/O or accept
        // another key before the pending coordinator request is processed.
        if registration.as_ref().is_some_and(|r| r.pending()) {
            continue;
        }
        maybe_clear_clipboard(&mut app);
        maybe_auto_lock(&mut app);

        if app.should_quit {
            if app.protect_memory_draft() {
                continue;
            }
            break;
        }
    }

    Ok(())
}

#[cfg(test)]
mod lock_tests {
    use super::*;
    use crossterm::event::KeyCode;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    pub struct Fixture(pub PathBuf);
    impl Fixture {
        pub fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "jaiba-r4-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
        pub fn app(&self) -> App {
            let path = self.0.join("synthetic.kdbx");
            crate::db::create_database(&path, "synthetic master", None).unwrap();
            let (db, key, entries, revision) =
                crate::db::unlock_database_snapshot(&path, "synthetic master", None).unwrap();
            let mut app = App::for_test(Some(path));
            app.kdbx = Some(db);
            app.db_key = Some(key);
            app.primary_revision = Some(revision);
            app.entries = entries;
            app
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn authenticate(app: &mut App, password: &str) {
        app.password = password.into();
        handle_login_input(app, KeyCode::Enter);
    }
    fn draft(app: &mut App) {
        app.screen = Screen::Edit;
        app.edit_entry = Some(Entry {
            password: "synthetic secret".into(),
            ..Entry::default()
        });
        app.edit_original = Some(Entry::default());
        app.edit_state.select(Some(5));
        app.editing_field = true;
        app.field_buffer = "partial notes λ\n  ".into();
    }

    #[test]
    fn auto_lock_recovers_partial_new_draft_only_after_authentication() {
        let fixture = Fixture::new();
        let mut app = fixture.app();
        draft(&mut app);
        app.config.auto_lock = Duration::ZERO;
        maybe_auto_lock(&mut app);
        assert_eq!(app.screen, Screen::Login);
        assert!(app.edit_entry.is_none());
        assert!(app.field_buffer.is_empty());
        authenticate(&mut app, "wrong synthetic master");
        assert_eq!(app.screen, Screen::Login);
        authenticate(&mut app, "synthetic master");
        assert_eq!(
            app.screen,
            Screen::Edit,
            "auto-lock must not discard an editor draft"
        );
        assert_eq!(
            app.edit_entry.as_ref().unwrap().password,
            "synthetic secret"
        );
        assert!(app.editing_field);
        assert_eq!(app.field_buffer, "partial notes λ\n  ");
        assert_eq!(app.edit_state.selected(), Some(5));
    }

    #[test]
    fn failed_durability_stays_false_until_authenticated_retry_really_persists() {
        let fixture = Fixture::new();
        let mut app = fixture.app();
        let path = app.config.default_database.clone().unwrap();
        let sidecars = crate::recovery::directory(&path);
        fs::write(&sidecars, b"synthetic blocker").unwrap();
        draft(&mut app);
        assert!(!app.lock_cooperatively());
        assert_eq!(app.screen, Screen::Login);
        assert!(app.edit_entry.is_none() && app.field_buffer.is_empty());
        assert!(app.pending_draft.is_some());
        assert!(
            app.login_error
                .as_ref()
                .unwrap()
                .contains("KEEP THIS WINDOW OPEN")
        );
        fs::remove_file(&sidecars).unwrap();
        assert!(
            !app.lock_cooperatively(),
            "removing the fault does not recreate a discarded key"
        );
        assert!(!app.lock_cooperatively());
        handle_login_input(&mut app, KeyCode::Esc);
        assert!(
            !app.should_quit,
            "do not silently exit with an undurable hidden draft"
        );
        authenticate(&mut app, "wrong synthetic master");
        assert!(app.edit_entry.is_none());
        authenticate(&mut app, "synthetic master");
        assert_eq!(app.screen, Screen::Edit);
        assert_eq!(app.field_buffer, "partial notes λ\n  ");
        assert!(app.lock_cooperatively());
        assert!(app.pending_draft.is_none());
    }

    #[test]
    fn existing_entry_draft_keeps_identity_across_repeated_locks() {
        let fixture = Fixture::new();
        let mut app = fixture.app();
        let path = app.config.default_database.clone().unwrap();
        let mut entry = Entry {
            name: "original synthetic title".into(),
            password: "original synthetic password".into(),
            ..Entry::default()
        };
        crate::db::save_database(
            &path,
            app.db_key.as_ref().unwrap(),
            app.kdbx.as_mut().unwrap(),
            std::slice::from_mut(&mut entry),
        )
        .unwrap();
        let id = entry.id;
        app.entries.push(entry.clone());
        app.screen = Screen::Edit;
        app.edit_entry = Some(entry.clone());
        app.edit_original = Some(entry);
        app.edit_target = Some(0);
        app.edit_entry.as_mut().unwrap().name = "unsaved synthetic title".into();
        app.edit_state.select(Some(2));
        app.editing_field = true;
        app.field_buffer = " partial synthetic password λ ".into();
        let before = fs::read(&path).unwrap();
        for _ in 0..3 {
            assert!(app.lock_cooperatively());
            assert!(app.lock_cooperatively());
            authenticate(&mut app, "synthetic master");
            assert_eq!(app.screen, Screen::Edit);
            assert_eq!(app.edit_entry.as_ref().unwrap().id, id);
            assert_eq!(
                app.edit_original.as_ref().unwrap().name,
                "original synthetic title"
            );
            assert_eq!(app.edit_target, Some(0));
            assert_eq!(app.field_buffer, " partial synthetic password λ ");
            assert!(!app.reveal_password);
        }
        assert_eq!(fs::read(&path).unwrap(), before);
        let data_count = fs::read_dir(crate::recovery::directory(&path))
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "kdbx"))
            .count();
        assert_eq!(
            data_count, 1,
            "relocking must update one snapshot, not create duplicates"
        );
        crate::input::edit::handle_edit_input(&mut app, KeyCode::Enter);
        crate::input::edit::handle_edit_input(&mut app, KeyCode::Esc);
        crate::input::edit::handle_edit_input(&mut app, KeyCode::Char('y'));
        let (_, _, saved) = crate::db::unlock_database(&path, "synthetic master", None).unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].id, id);
        assert_eq!(saved[0].name, "unsaved synthetic title");
        assert_eq!(saved[0].password, " partial synthetic password λ ");
    }

    #[test]
    fn live_sessions_do_not_steal_each_others_durable_drafts() {
        let fixture = Fixture::new();
        let mut first = fixture.app();
        let path = first.config.default_database.clone().unwrap();
        draft(&mut first);
        assert!(first.lock_cooperatively());
        let mut second = App::for_test(Some(path));
        authenticate(&mut second, "synthetic master");
        assert_eq!(second.screen, Screen::Index);
        assert!(second.edit_entry.is_none());
        drop(first);
        assert!(second.lock_cooperatively());
        authenticate(&mut second, "synthetic master");
        assert_eq!(second.screen, Screen::Edit);
        assert_eq!(second.field_buffer, "partial notes λ\n  ");
    }

    #[test]
    fn sidecars_are_private_encrypted_kdbx_using_both_database_factors() {
        use std::os::unix::fs::MetadataExt;
        let fixture = Fixture::new();
        let path = fixture.0.join("composite.kdbx");
        let keyfile = fixture.0.join("synthetic.key");
        fs::write(&keyfile, [42u8; 32]).unwrap();
        crate::db::create_database(&path, "synthetic master", Some(&keyfile)).unwrap();
        let mut app = App::for_test(Some(path.clone()));
        app.config.keyfile = Some(keyfile.clone());
        authenticate(&mut app, "synthetic master");
        let key = app.db_key.as_ref().unwrap().clone();
        draft(&mut app);
        assert!(app.lock_cooperatively());
        let dir = crate::recovery::directory(&path);
        assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        let sidecar = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|e| e == "kdbx"))
            .unwrap();
        for file in fs::read_dir(&dir).unwrap() {
            let file = file.unwrap().path();
            assert_eq!(fs::metadata(&file).unwrap().mode() & 0o777, 0o600);
            let bytes = fs::read(file).unwrap();
            assert!(
                !bytes
                    .windows(b"synthetic secret".len())
                    .any(|w| w == b"synthetic secret")
            );
            assert!(
                !bytes
                    .windows(b"partial notes".len())
                    .any(|w| w == b"partial notes")
            );
        }
        assert!(
            Database::open(
                &mut fs::File::open(&sidecar).unwrap(),
                DatabaseKey::new().with_password("synthetic master")
            )
            .is_err()
        );
        Database::open(&mut fs::File::open(&sidecar).unwrap(), key).unwrap();
        drop(app);
        let mut restarted = App::for_test(Some(path));
        authenticate(&mut restarted, "synthetic master");
        assert!(restarted.edit_entry.is_none());
        restarted.config.keyfile = Some(keyfile);
        authenticate(&mut restarted, "synthetic master");
        assert_eq!(restarted.screen, Screen::Edit);
    }

    #[test]
    fn discarded_recovered_draft_is_not_written_or_resurrected() {
        let fixture = Fixture::new();
        let mut app = fixture.app();
        let path = app.config.default_database.clone().unwrap();
        let before = fs::read(&path).unwrap();
        draft(&mut app);
        assert!(app.lock_cooperatively());
        authenticate(&mut app, "synthetic master");
        crate::input::edit::handle_edit_input(&mut app, KeyCode::Esc);
        crate::input::edit::handle_edit_input(&mut app, KeyCode::Esc);
        crate::input::edit::handle_edit_input(&mut app, KeyCode::Char('n'));
        assert_eq!(app.screen, Screen::Index);
        drop(app);
        let mut restarted = App::for_test(Some(path.clone()));
        authenticate(&mut restarted, "synthetic master");
        assert_eq!(restarted.screen, Screen::Index);
        assert_eq!(fs::read(path).unwrap(), before);
    }

    #[test]
    fn recovery_refuses_a_different_database_even_with_identical_credentials() {
        let fixture = Fixture::new();
        let mut app = fixture.app();
        let path = app.config.default_database.clone().unwrap();
        draft(&mut app);
        assert!(app.lock_cooperatively());
        drop(app);
        let other = fixture.0.join("other.kdbx");
        crate::db::create_database(&other, "synthetic master", None).unwrap();
        let source = crate::recovery::directory(&path);
        let destination = crate::recovery::directory(&other);
        fs::rename(source, &destination).unwrap();
        let mut restarted = App::for_test(Some(other));
        authenticate(&mut restarted, "synthetic master");
        assert_eq!(restarted.screen, Screen::Login);
        assert!(restarted.edit_entry.is_none());
        assert!(
            restarted
                .login_error
                .as_ref()
                .unwrap()
                .contains("different database")
        );
        assert!(!restarted.lock_cooperatively());
        assert!(fs::read_dir(destination).unwrap().count() >= 2);
    }

    #[test]
    fn deleted_target_draft_is_not_reinterpreted_as_a_new_entry() {
        let fixture = Fixture::new();
        let mut app = fixture.app();
        let path = app.config.default_database.clone().unwrap();
        let mut entry = Entry {
            name: "synthetic target".into(),
            ..Entry::default()
        };
        crate::db::save_database(
            &path,
            app.db_key.as_ref().unwrap(),
            app.kdbx.as_mut().unwrap(),
            std::slice::from_mut(&mut entry),
        )
        .unwrap();
        app.entries.push(entry.clone());
        app.edit_entry = Some(entry.clone());
        app.edit_original = Some(entry.clone());
        app.screen = Screen::Edit;
        app.edit_entry.as_mut().unwrap().password = "unsaved synthetic replacement".into();
        assert!(app.lock_cooperatively());
        let (mut db, key, _) = crate::db::unlock_database(&path, "synthetic master", None).unwrap();
        crate::db::delete_entry(&path, &key, &mut db, entry.id.unwrap()).unwrap();
        authenticate(&mut app, "synthetic master");
        assert_eq!(app.screen, Screen::Login);
        assert!(app.edit_entry.is_none());
        assert!(
            app.login_error
                .as_ref()
                .unwrap()
                .contains("no longer exists")
        );
        assert!(!app.lock_cooperatively());
    }

    #[test]
    fn changed_database_credentials_keep_draft_in_memory_until_current_reauthentication() {
        let fixture = Fixture::new();
        let mut app = fixture.app();
        let path = app.config.default_database.clone().unwrap();
        let mut external = app.kdbx.as_ref().unwrap().clone();
        crate::db::save_database(
            &path,
            &DatabaseKey::new().with_password("new synthetic master"),
            &mut external,
            &mut [],
        )
        .unwrap();
        draft(&mut app);
        assert!(
            !app.lock_cooperatively(),
            "do not strand a draft under credentials the primary database no longer accepts"
        );
        assert!(app.pending_draft.is_some());
        authenticate(&mut app, "new synthetic master");
        assert_eq!(app.screen, Screen::Edit);
        assert!(app.lock_cooperatively());
    }

    #[test]
    fn ordinary_unlock_without_drafts_does_not_require_private_database_parent() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = Fixture::new();
        let mut app = fixture.app();
        fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o775)).unwrap();
        app.kdbx = None;
        app.db_key = None;
        app.screen = Screen::Login;
        authenticate(&mut app, "synthetic master");
        assert_eq!(
            app.screen,
            Screen::Index,
            "draft safety rules must not block an unrelated ordinary unlock"
        );
    }

    #[test]
    fn no_database_lock_clears_all_transient_credential_buffers() {
        let mut app = App::for_test(None);
        app.password = "synthetic login buffer".into();
        app.new_db_confirm = "synthetic confirmation".into();
        app.current_password_buffer = "synthetic old".into();
        app.new_password_buffer = "synthetic new".into();
        app.new_password_confirm = "synthetic new confirm".into();
        app.import_kdbx_password_buffer = "synthetic import".into();
        app.field_buffer = "synthetic settings".into();
        assert!(app.lock_cooperatively());
        assert_eq!(app.screen, Screen::Login);
        assert!(app.password.is_empty() && app.new_db_confirm.is_empty());
        assert!(app.current_password_buffer.is_empty() && app.new_password_buffer.is_empty());
        assert!(app.new_password_confirm.is_empty() && app.import_kdbx_password_buffer.is_empty());
        assert!(app.field_buffer.is_empty());
    }

    #[test]
    fn discard_refuses_to_delete_a_replaced_recovery_file() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = Fixture::new();
        let mut app = fixture.app();
        let path = app.config.default_database.clone().unwrap();
        draft(&mut app);
        assert!(app.lock_cooperatively());
        authenticate(&mut app, "synthetic master");
        let data = fs::read_dir(crate::recovery::directory(&path))
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|e| e == "kdbx"))
            .unwrap();
        fs::remove_file(&data).unwrap();
        fs::write(&data, b"unrelated replacement").unwrap();
        fs::set_permissions(&data, fs::Permissions::from_mode(0o600)).unwrap();
        crate::input::edit::handle_edit_input(&mut app, KeyCode::Esc); // cancel field
        crate::input::edit::handle_edit_input(&mut app, KeyCode::Esc); // unsaved changes
        crate::input::edit::handle_edit_input(&mut app, KeyCode::Char('n'));
        assert_eq!(
            app.screen,
            Screen::Edit,
            "unsafe cleanup must keep editor recoverable"
        );
        assert_eq!(fs::read(data).unwrap(), b"unrelated replacement");
        assert!(app.status.as_ref().unwrap().contains("Could not retire"));
    }

    #[test]
    fn settings_database_preference_cannot_redirect_an_open_edit_save() {
        let fixture = Fixture::new();
        let mut app = fixture.app();
        let original = app.config.default_database.clone().unwrap();
        app.open_database = Some(original.clone());
        app.config.default_database = Some(fixture.0.join("different.kdbx"));
        draft(&mut app);
        crate::input::edit::handle_edit_input(&mut app, KeyCode::Enter);
        crate::input::edit::handle_edit_input(&mut app, KeyCode::Esc);
        crate::input::edit::handle_edit_input(&mut app, KeyCode::Char('y'));
        assert!(
            !fixture.0.join("different.kdbx").exists(),
            "preference changes must not overwrite another vault"
        );
        let (_, _, entries) =
            crate::db::unlock_database(&original, "synthetic master", None).unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn corrupt_recovery_never_claims_durable_success_on_repeated_requests() {
        let fixture = Fixture::new();
        let mut app = fixture.app();
        let path = app.config.default_database.clone().unwrap();
        draft(&mut app);
        assert!(app.lock_cooperatively());
        let dir = crate::recovery::directory(&path);
        let data = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|e| e == "kdbx"))
            .unwrap();
        fs::write(data, b"broken synthetic recovery container").unwrap();
        authenticate(&mut app, "synthetic master");
        assert_eq!(app.screen, Screen::Login);
        assert!(
            !app.lock_cooperatively(),
            "a known failed recovery must not turn into a durable acknowledgement"
        );
        assert!(!app.lock_cooperatively());
        assert!(app.login_error.as_ref().unwrap().contains("not confirmed"));
    }

    #[test]
    fn saved_recovered_draft_is_retired_and_not_resurrected() {
        let fixture = Fixture::new();
        let mut app = fixture.app();
        let path = app.config.default_database.clone().unwrap();
        draft(&mut app);
        assert!(app.lock_cooperatively());
        authenticate(&mut app, "synthetic master");
        crate::input::edit::handle_edit_input(&mut app, KeyCode::Enter);
        crate::input::edit::handle_edit_input(&mut app, KeyCode::Esc);
        crate::input::edit::handle_edit_input(&mut app, KeyCode::Char('y'));
        assert_eq!(app.screen, Screen::Index);
        drop(app);
        let mut restarted = App::for_test(Some(path));
        authenticate(&mut restarted, "synthetic master");
        assert_eq!(
            restarted.screen,
            Screen::Index,
            "saved drafts must not resurrect"
        );
        assert_eq!(restarted.entries.len(), 1);
        assert_eq!(restarted.entries[0].notes, "partial notes λ\n  ");
    }

    #[test]
    fn encrypted_draft_survives_process_state_loss_without_touching_vault() {
        let fixture = Fixture::new();
        let mut app = fixture.app();
        let path = app.config.default_database.clone().unwrap();
        let before = fs::read(&path).unwrap();
        draft(&mut app);
        assert!(
            app.lock_cooperatively(),
            "a successful lock must durably encrypt the draft"
        );
        assert!(
            app.pending_draft.is_none(),
            "durable drafts need no plaintext memory copy"
        );
        drop(app);
        let mut restarted = App::for_test(Some(path.clone()));
        restarted.screen = Screen::Login;
        authenticate(&mut restarted, "wrong synthetic master");
        assert!(restarted.edit_entry.is_none());
        authenticate(&mut restarted, "synthetic master");
        assert_eq!(restarted.screen, Screen::Edit);
        assert_eq!(restarted.field_buffer, "partial notes λ\n  ");
        assert_eq!(
            restarted.edit_entry.as_ref().unwrap().password,
            "synthetic secret"
        );
        assert_eq!(fs::read(path).unwrap(), before);
    }
}
