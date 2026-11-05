use std::time::Instant;

use crossterm::event::KeyCode;

use crate::app::{App, Screen};
use crate::config::save_config;
use crate::db::{
    calculate_warnings, create_database_with_yubikey, unlock_database_snapshot_with_yubikey,
};
use crate::util::default_new_database_path;

#[cfg(test)]
#[path = "login_cancellation_tests.rs"]
mod cancellation_tests;

pub fn handle_login_input(app: &mut App, key: KeyCode) {
    if (key == KeyCode::Esc || app.creating_database || database_missing(app))
        && app.protect_memory_draft()
    {
        return;
    }
    if app.creating_database {
        handle_create_database_input(app, key);
        return;
    }

    if database_missing(app) {
        handle_missing_database_input(app, key);
        return;
    }

    match key {
        KeyCode::Char(c) => {
            app.login_error = None;

            if app.password.len() < app.max_len {
                app.password.push(c);
            }
        }

        KeyCode::Backspace => {
            app.login_error = None;
            app.password.pop();
        }

        KeyCode::Enter => {
            attempt_unlock(app);
        }

        KeyCode::Esc => {
            app.should_quit = true;
        }

        _ => {}
    }
}

pub fn database_missing(app: &App) -> bool {
    match app.database_path() {
        None => true,
        Some(path) => !path.is_file(),
    }
}

fn handle_missing_database_input(app: &mut App, key: KeyCode) {
    match crate::input::normalize_shortcut(key) {
        KeyCode::Char('n') => start_create_database(app),

        KeyCode::Esc => {
            app.should_quit = true;
        }

        _ => {}
    }
}

fn start_create_database(app: &mut App) {
    app.creating_database = true;
    app.confirming_new_db_password = false;
    app.password.clear();
    app.new_db_confirm.clear();
    app.login_error = None;
}

fn cancel_create_database(app: &mut App) {
    app.creating_database = false;
    app.confirming_new_db_password = false;
    app.password.clear();
    app.new_db_confirm.clear();
    app.login_error = None;
}

fn handle_create_database_input(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Char(c) => {
            app.login_error = None;
            let limit = app.max_len;

            if app.confirming_new_db_password {
                if app.new_db_confirm.len() < limit {
                    app.new_db_confirm.push(c);
                }
            } else if app.password.len() < limit {
                app.password.push(c);
            }
        }

        KeyCode::Backspace => {
            app.login_error = None;

            if app.confirming_new_db_password {
                app.new_db_confirm.pop();
            } else {
                app.password.pop();
            }
        }

        KeyCode::Enter => {
            if app.confirming_new_db_password {
                finish_create_database(app);
            } else if app.password.is_empty() {
                app.login_error = Some("Master password can't be empty".to_string());
            } else {
                app.confirming_new_db_password = true;
            }
        }

        KeyCode::Esc => cancel_create_database(app),

        _ => {}
    }
}

fn finish_create_database(app: &mut App) {
    if app.new_db_confirm != app.password {
        app.login_error = Some("Passwords don't match".to_string());
        app.new_db_confirm.clear();
        app.confirming_new_db_password = false;
        return;
    }

    let path = app
        .config
        .default_database
        .clone()
        .unwrap_or_else(default_new_database_path);

    if path.is_file() {
        app.config.default_database = Some(path.clone());
        let _ = save_config(&app.config);

        app.new_db_confirm.clear();
        app.creating_database = false;
        app.confirming_new_db_password = false;
        app.login_error = Some(format!(
            "A vault already exists at {}. Press Enter to try unlocking it with this password.",
            path.display()
        ));
        return;
    }

    let yubikey = app.config.yubikey;
    match create_database_with_yubikey(&path, &app.password, app.config.keyfile.as_deref(), yubikey)
        .and_then(|_| {
            unlock_database_snapshot_with_yubikey(
                &path,
                &app.password,
                app.config.keyfile.as_deref(),
                yubikey,
            )
            .map_err(|err| anyhow::Error::new(crate::db::SaveError::Verification(err)))
        }) {
        Ok((db, key, entries, revision)) => {
            app.config.default_database = Some(path.clone());
            let save_result = save_config(&app.config);
            #[cfg(test)]
            cancellation_tests::checkpoint("create_ready");
            if authentication_cancelled(app) {
                app.login_error = Some(format!(
                    "Database created at {}, but authentication cancelled; keep the file and authenticate again with all factors.",
                    path.display()
                ));
                return;
            }

            app.kdbx = Some(db);
            app.db_key = Some(key);
            #[cfg(test)]
            cancellation_tests::checkpoint("installing");
            app.primary_revision = Some(revision);
            app.entries = entries;
            app.open_database = Some(path.clone());
            app.open_keyfile = app.config.keyfile.clone();
            app.open_yubikey = yubikey;
            app.password.clear();
            app.new_db_confirm.clear();
            app.creating_database = false;
            app.confirming_new_db_password = false;
            app.login_error = None;
            app.last_activity = Instant::now();
            app.refresh_filter();
            if authentication_cancelled(app) {
                return;
            }
            app.screen = Screen::Index;

            app.status = Some(match save_result {
                Ok(()) => format!("Created new database at {}", path.display()),
                Err(err) => format!("Database created, but couldn't save config: {err}"),
            });
        }

        Err(err) => {
            let committed = matches!(
                err.downcast_ref::<crate::db::SaveError>(),
                Some(crate::db::SaveError::Verification(_))
            );
            app.login_error = Some(if committed {
                app.config.default_database = Some(path.clone());
                app.creating_database = false;
                format!(
                    "Database created at {}, but not verified. Keep the file; authenticate with all factors to confirm before using it: {err:#}",
                    path.display()
                )
            } else {
                format!("Couldn't create database: {err:#}")
            });
            app.password.clear();
            app.new_db_confirm.clear();
            app.confirming_new_db_password = false;
        }
    }
}

/// Cooperative checkpoints, not an atomic signal/installation transaction.
/// Signals after the last checkpoint remain for the event-loop coordinator.
fn authentication_cancelled(app: &mut App) -> bool {
    if let Err(err) = challenge_response::operation::check() {
        // No persistence/recovery here: revoke partial installation and leave the
        // signal flag for the normal lock coordinator. Returned keys drop on return.
        // Unlike failed recovery, cancellation before recovery does not invalidate
        // an existing durability receipt; the coordinator still revalidates it.
        let durable = app.draft_durable;
        app.hide_failed_recovery();
        app.draft_durable = durable;
        app.login_error = Some(format!("Authentication cancelled: {err}"));
        return true;
    }
    false
}

fn attempt_unlock(app: &mut App) {
    let Some(path) = app.database_path().map(|path| path.to_owned()) else {
        app.login_error = Some("No default_database set in jaiba_config.toml".to_string());
        return;
    };

    let keyfile = if app.open_database.is_some() {
        app.open_keyfile.clone()
    } else {
        app.config.keyfile.clone()
    };
    let yubikey = app.database_yubikey();
    match unlock_database_snapshot_with_yubikey(&path, &app.password, keyfile.as_deref(), yubikey) {
        Ok((db, key, mut entries, revision)) => {
            calculate_warnings(&mut entries);
            #[cfg(test)]
            cancellation_tests::checkpoint("unlock_ready");
            if authentication_cancelled(app) {
                return;
            }
            app.entries = entries;
            app.kdbx = Some(db);
            app.db_key = Some(key);
            #[cfg(test)]
            cancellation_tests::checkpoint("installing");
            app.primary_revision = Some(revision);
            app.open_database = Some(path);
            app.open_keyfile = keyfile;
            app.open_yubikey = yubikey;
            app.password.clear();
            app.login_error = None;
            app.last_activity = Instant::now();
            app.refresh_filter();
            if authentication_cancelled(app) {
                return;
            }
            app.screen = Screen::Index;
            #[cfg(test)]
            cancellation_tests::checkpoint("before_recovery");
            if authentication_cancelled(app) {
                return;
            }
            #[cfg(test)]
            cancellation_tests::checkpoint("recover_started");
            if let Err(err) = crate::recovery::recover(app) {
                app.hide_failed_recovery();
                app.login_error = Some(format!("Recovery failed; keep recovery files: {err}"));
            }
        }
        Err(err) => {
            app.password.clear();
            app.login_error = Some(format!("{err:#}"));
        }
    }
}
