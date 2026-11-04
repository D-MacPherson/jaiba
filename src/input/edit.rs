use crossterm::event::KeyCode;

use crate::app::{App, Screen};
use crate::db::{SaveError, calculate_warnings, delete_entry, save_database};

const FIELD_COUNT: usize = 7;
const LAST_MODIFIED_INDEX: usize = 6;

pub fn handle_edit_input(app: &mut App, key: KeyCode) {
    if app.editing_field {
        handle_field_input(app, key);
        return;
    }

    if app.confirm_exit {
        handle_exit_confirmation(app, key);
        return;
    }

    if app.confirm_delete {
        handle_delete_confirmation(app, key);
        return;
    }

    match crate::input::normalize_shortcut(key) {
        KeyCode::Esc => request_close_edit(app),

        KeyCode::Enter => start_editing_field(app),

        KeyCode::Char('v') => {
            app.reveal_password = !app.reveal_password;
        }

        KeyCode::Char('d') => start_delete_confirmation(app),

        KeyCode::Down => move_selection(app, 1),
        KeyCode::Up => move_selection(app, -1),

        _ => {}
    }
}

fn handle_field_input(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Esc => {
            app.editing_field = false;
            app.field_buffer.clear();
        }

        KeyCode::Enter => commit_field(app),

        KeyCode::Char(c) => app.field_buffer.push(c),

        KeyCode::Backspace => {
            app.field_buffer.pop();
        }

        _ => {}
    }
}

fn move_selection(app: &mut App, delta: i32) {
    let current = app.edit_state.selected().unwrap_or(0) as i32;
    let next = (current + delta).rem_euclid(FIELD_COUNT as i32) as usize;
    app.edit_state.select(Some(next));
}

fn start_editing_field(app: &mut App) {
    let selected = app.edit_state.selected().unwrap_or(0);

    if selected == LAST_MODIFIED_INDEX {
        app.status = Some("Last modified is set automatically".to_string());
        return;
    }

    let Some(entry) = app.edit_entry.as_ref() else {
        return;
    };

    app.field_buffer = match selected {
        0 => entry.name.clone(),
        1 => entry.user.clone(),
        2 => entry.password.clone(),
        3 => entry.url.clone(),
        4 => entry.totp.clone(),
        5 => entry.notes.clone(),
        _ => return,
    };

    app.editing_field = true;
    app.status = None;

    if selected == 2 {
        app.reveal_password = true;
    }
}

fn commit_field(app: &mut App) {
    let selected = app.edit_state.selected().unwrap_or(0);
    let value = std::mem::take(&mut app.field_buffer);

    if let Some(entry) = app.edit_entry.as_mut() {
        match selected {
            0 => entry.name = value,
            1 => entry.user = value,
            2 => entry.password = value,
            3 => entry.url = value,
            4 => entry.totp = value,
            5 => entry.notes = value,
            _ => {}
        }
    }

    app.editing_field = false;
}

fn request_close_edit(app: &mut App) {
    if has_unsaved_changes(app) {
        app.confirm_exit = true;
        app.status = Some("Save changes? [y] yes  [n] no".to_string());
    } else {
        reset_edit_state(app);
    }
}

fn has_unsaved_changes(app: &App) -> bool {
    let (Some(entry), Some(original)) = (app.edit_entry.as_ref(), app.edit_original.as_ref())
    else {
        return false;
    };

    entry.name != original.name
        || entry.user != original.user
        || entry.password != original.password
        || entry.url != original.url
        || entry.totp != original.totp
        || entry.notes != original.notes
}

fn handle_exit_confirmation(app: &mut App, key: KeyCode) {
    match crate::input::normalize_shortcut(key) {
        KeyCode::Char('y') => {
            app.confirm_exit = false;
            close_edit(app);
        }

        KeyCode::Char('n') => {
            app.confirm_exit = false;
            reset_edit_state(app);
            app.status = Some("Changes discarded".to_string());
        }

        KeyCode::Esc => {
            app.confirm_exit = false;
            app.status = None;
        }

        _ => {}
    }
}

fn close_edit(app: &mut App) {
    if save_edit(app) {
        reset_edit_state(app);
    }
}

fn reset_edit_state(app: &mut App) {
    app.edit_entry = None;
    app.edit_original = None;
    app.edit_target = None;
    app.editing_field = false;
    app.field_buffer.clear();
    app.confirm_delete = false;
    app.confirm_exit = false;
    app.reveal_password = false;
    app.edit_state.select(None);
    app.screen = Screen::Index;
}

fn save_edit(app: &mut App) -> bool {
    let Some(mut entry) = app.edit_entry.clone() else {
        return true;
    };
    let (Some(db), Some(key), Some(path)) = (
        app.kdbx.as_mut(),
        app.db_key.as_ref(),
        app.config.default_database.as_ref(),
    ) else {
        app.status = Some("Not saved: database is locked".to_string());
        return false;
    };
    let result = save_database(path, key, db, std::slice::from_mut(&mut entry));
    app.edit_entry = Some(entry.clone());
    // Only expose an entry in the list once it has reached disk. If the final
    // verification failed, its ID still identifies that uncertain write on retry.
    if !matches!(result, Err(SaveError::Write(_))) {
        let existing = entry
            .id
            .and_then(|id| app.entries.iter().position(|e| e.id == Some(id)));
        if let Some(idx) = existing.or(app.edit_target) {
            if let Some(slot) = app.entries.get_mut(idx) {
                *slot = entry;
            }
        } else {
            app.entries.push(entry);
        }
        calculate_warnings(&mut app.entries);
        app.refresh_filter();
    }
    match result {
        Ok(()) => {
            app.status = Some("Saved and verified".to_string());
            true
        }
        Err(err) => {
            let phase = match &err {
                SaveError::Write(_) => "Not saved",
                SaveError::Verification(_) => {
                    "Written, but verification or durability could not be confirmed"
                }
            };
            app.status = Some(format!("{phase}: {err}"));
            false
        }
    }
}

fn start_delete_confirmation(app: &mut App) {
    if app.edit_entry.is_none() {
        return;
    }

    app.confirm_delete = true;
    app.status = Some("Delete this entry? [y] confirm  [any other key] cancel".to_string());
}

fn handle_delete_confirmation(app: &mut App, key: KeyCode) {
    app.confirm_delete = false;
    app.status = None;

    if let KeyCode::Char('y') = crate::input::normalize_shortcut(key) {
        delete_current_entry(app);
    }
}

fn delete_current_entry(app: &mut App) {
    let Some(entry) = app.edit_entry.take() else {
        reset_edit_state(app);
        return;
    };

    if let Some(id) = entry.id {
        let (Some(db), Some(key), Some(path)) = (
            app.kdbx.as_mut(),
            app.db_key.as_ref(),
            app.config.default_database.as_ref(),
        ) else {
            app.status = Some("Not deleted: database is locked".to_string());
            app.edit_entry = Some(entry);
            return;
        };

        if let Err(err) = delete_entry(path, key, db, id) {
            app.status = Some(format!("Failed to delete: {err:#}"));
            app.edit_entry = Some(entry);
            return;
        }
    }

    let entry_idx = entry
        .id
        .and_then(|id| app.entries.iter().position(|e| e.id == Some(id)))
        .or(app.edit_target);
    if let Some(idx) = entry_idx {
        if idx < app.entries.len() {
            app.entries.remove(idx);
        }
    }

    calculate_warnings(&mut app.entries);
    app.refresh_filter();

    reset_edit_state(app);
    app.status = Some("Entry deleted".to_string());
}

#[cfg(test)]
mod tests {
    use super::handle_edit_input;
    use crate::app::{App, Screen};
    use crate::db::{create_database, unlock_database};
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    const TEST_PASSWORD: &str = "correct horse";
    const NAME_FIELD: usize = 0;
    const PASSWORD_FIELD: usize = 2;
    const NOTES_FIELD: usize = 5;

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let id = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("jaiba-edit-test-{}-{id}", std::process::id()));
            fs::create_dir_all(&path).expect("test directory should be created");
            Self(path)
        }

        fn join(&self, path: impl AsRef<Path>) -> PathBuf {
            self.0.join(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn test_app(database_path: &Path) -> App {
        let (database, key, entries) = create_database(database_path, TEST_PASSWORD, None)
            .expect("disposable database should be created");
        let mut app = App::for_test(Some(database_path.to_path_buf()));
        app.kdbx = Some(database);
        app.db_key = Some(key);
        app.entries = entries;
        app
    }

    fn start_new_entry(app: &mut App) {
        crate::input::index::handle_index_input(
            app,
            KeyEvent::new(KeyCode::Char('a'), KeyModifiers::CONTROL),
        );

        assert!(
            matches!(app.screen, Screen::Edit),
            "ctrl+a should open the edit screen"
        );
        assert_eq!(app.edit_target, None, "ctrl+a should target a new entry");
    }

    fn select_field(app: &mut App, field: usize) {
        while app.edit_state.selected() != Some(field) {
            handle_edit_input(app, KeyCode::Down);
        }
    }

    fn set_field(app: &mut App, field: usize, value: &str) {
        select_field(app, field);
        handle_edit_input(app, KeyCode::Enter);
        assert!(app.editing_field, "enter should start editing the field");

        for _ in 0..app.field_buffer.chars().count() {
            handle_edit_input(app, KeyCode::Backspace);
        }

        for character in value.chars() {
            handle_edit_input(app, KeyCode::Char(character));
        }

        handle_edit_input(app, KeyCode::Enter);
        assert!(!app.editing_field, "enter should commit the field");
    }

    fn close_and_save(app: &mut App) {
        handle_edit_input(app, KeyCode::Esc);
        assert!(
            app.confirm_exit,
            "esc should ask to save when the entry changed"
        );

        handle_edit_input(app, KeyCode::Char('y'));
        assert!(
            matches!(app.screen, Screen::Index),
            "edit screen should close"
        );
    }

    fn reopen(database_path: &Path) -> Vec<crate::db::Entry> {
        let (_, _, entries) = unlock_database(database_path, TEST_PASSWORD, None)
            .expect("database should unlock again");
        entries
    }

    #[test]
    fn saves_new_entry_with_an_empty_title() {
        let dir = TestDir::new();
        let database_path = dir.join("empty-title.kdbx");
        let mut app = test_app(&database_path);

        start_new_entry(&mut app);
        set_field(&mut app, PASSWORD_FIELD, "s3cret");
        set_field(&mut app, NOTES_FIELD, "note text");
        close_and_save(&mut app);

        assert_eq!(app.status.as_deref(), Some("Saved and verified"));
        assert_eq!(app.entries.len(), 1, "the new entry should be kept");
        assert_eq!(app.filtered.len(), 1, "the new entry should stay listed");

        let entries = reopen(&database_path);
        assert_eq!(entries.len(), 1, "the new entry should be persisted");

        let entry = &entries[0];
        assert!(entry.name.is_empty(), "the empty title should be preserved");
        assert_eq!(entry.password, "s3cret");
        assert_eq!(entry.notes, "note text");
    }

    #[test]
    fn saves_new_entry_with_a_whitespace_only_title() {
        let dir = TestDir::new();
        let database_path = dir.join("whitespace-title.kdbx");
        let mut app = test_app(&database_path);

        start_new_entry(&mut app);
        set_field(&mut app, NAME_FIELD, "   ");
        set_field(&mut app, PASSWORD_FIELD, "hunter2");
        set_field(&mut app, NOTES_FIELD, "note text");
        close_and_save(&mut app);

        assert_eq!(app.status.as_deref(), Some("Saved and verified"));
        assert_eq!(app.entries.len(), 1, "the new entry should be kept");
        assert_eq!(app.filtered.len(), 1, "the new entry should stay listed");

        let entries = reopen(&database_path);
        assert_eq!(entries.len(), 1, "the new entry should be persisted");

        let entry = &entries[0];
        assert_eq!(entry.password, "hunter2");
        assert_eq!(entry.notes, "note text");
        // The keepass crate parses values that are entirely whitespace back as
        // empty strings (StringValue uses cs_opt_string, which maps whitespace-only
        // values to None). The entry itself is kept; only the title is normalized.
        assert!(entry.name.is_empty());
    }

    fn fail_save(app: &mut App) {
        handle_edit_input(app, KeyCode::Esc);
        assert!(app.confirm_exit);
        handle_edit_input(app, KeyCode::Char('y'));
        assert!(matches!(app.screen, Screen::Edit));
        assert!(app.status.as_deref().unwrap().starts_with("Not saved:"));
    }

    #[test]
    fn failed_new_save_keeps_input_and_retry_creates_one_entry() {
        let dir = TestDir::new();
        let path = dir.join("retry.kdbx");
        let mut app = test_app(&path);
        let original = fs::read(&path).unwrap();
        start_new_entry(&mut app);
        set_field(&mut app, PASSWORD_FIELD, "synthetic retry password");
        set_field(&mut app, NOTES_FIELD, "keep these notes λ");
        app.config.default_database = Some(dir.join("missing/blocked.kdbx"));
        fail_save(&mut app);
        fail_save(&mut app);
        assert_eq!(
            app.edit_entry.as_ref().unwrap().password,
            "synthetic retry password"
        );
        assert_eq!(app.edit_entry.as_ref().unwrap().notes, "keep these notes λ");
        assert!(app.entries.is_empty());
        assert_eq!(fs::read(&path).unwrap(), original);
        app.config.default_database = Some(path.clone());
        close_and_save(&mut app);
        let stored = reopen(&path);
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].notes, "keep these notes λ");
    }

    #[test]
    fn discarding_a_failed_new_save_does_not_leak_into_a_later_save() {
        let dir = TestDir::new();
        let path = dir.join("discard.kdbx");
        let mut app = test_app(&path);
        start_new_entry(&mut app);
        set_field(&mut app, PASSWORD_FIELD, "discarded synthetic secret");
        app.config.default_database = Some(dir.join("missing/blocked.kdbx"));
        fail_save(&mut app);
        handle_edit_input(&mut app, KeyCode::Esc);
        handle_edit_input(&mut app, KeyCode::Char('n'));
        assert!(matches!(app.screen, Screen::Index));
        app.config.default_database = Some(path.clone());
        start_new_entry(&mut app);
        set_field(&mut app, NAME_FIELD, "entry to keep");
        set_field(&mut app, PASSWORD_FIELD, "kept synthetic secret");
        close_and_save(&mut app);
        let stored = reopen(&path);
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].password, "kept synthetic secret");
    }

    #[test]
    fn failed_update_and_delete_leave_the_previous_entry_intact() {
        let dir = TestDir::new();
        let path = dir.join("existing.kdbx");
        let mut app = test_app(&path);
        start_new_entry(&mut app);
        set_field(&mut app, NAME_FIELD, "previous entry");
        set_field(&mut app, PASSWORD_FIELD, "previous password");
        close_and_save(&mut app);
        let original = fs::read(&path).unwrap();
        crate::input::command::preview_entry(&mut app);
        set_field(&mut app, PASSWORD_FIELD, "replacement password");
        app.config.default_database = Some(dir.join("missing/blocked.kdbx"));
        fail_save(&mut app);
        assert_eq!(app.entries[0].password, "previous password");
        handle_edit_input(&mut app, KeyCode::Char('d'));
        handle_edit_input(&mut app, KeyCode::Char('y'));
        assert!(matches!(app.screen, Screen::Edit));
        assert_eq!(
            app.edit_entry.as_ref().unwrap().password,
            "replacement password"
        );
        assert_eq!(fs::read(&path).unwrap(), original);
        app.config.default_database = Some(path.clone());
        close_and_save(&mut app);
        let stored = reopen(&path);
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].password, "replacement password");
    }

    #[test]
    fn all_fields_survive_a_verified_save_without_trimming() {
        let dir = TestDir::new();
        let path = dir.join("fields.kdbx");
        let mut app = test_app(&path);
        start_new_entry(&mut app);
        let values = [
            "  title λ  ",
            " user ",
            "  password λ\n ",
            "https://example.test/λ",
            "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP",
            "first line\nsecond line\n",
        ];
        for (field, value) in values.iter().enumerate() {
            set_field(&mut app, field, value);
        }
        close_and_save(&mut app);
        let stored = reopen(&path);
        let entry = &stored[0];
        assert_eq!(
            [
                entry.name.as_str(),
                entry.user.as_str(),
                entry.password.as_str(),
                entry.url.as_str(),
                entry.totp.as_str(),
                entry.notes.as_str()
            ],
            values
        );
    }
}
