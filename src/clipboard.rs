use std::time::Instant;

use arboard::Clipboard;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::app::App;
use crate::terminal_clipboard;

pub struct ClipboardTimer {
    pub label: String,
    pub expected: String,
    pub fingerprint: Option<[u8; 32]>,
    pub clear_at: Instant,
}

impl ClipboardTimer {
    pub fn forget_plaintext(&mut self) {
        if self.fingerprint.is_none() {
            self.fingerprint = Some(Sha256::digest(self.expected.as_bytes()).into());
        }
        self.expected.zeroize();
    }

    pub fn matches_text(&self, current: &str) -> bool {
        match self.fingerprint {
            Some(expected) => expected == <[u8; 32]>::from(Sha256::digest(current.as_bytes())),
            None => current == self.expected,
        }
    }
}

fn copy_and_report(app: &mut App, label: &str, text: &str) {
    if app.terminal_clipboard {
        // A write-only backend cannot implement read/compare/clear safely.
        app.clipboard_timer = None;
        app.status = Some(match terminal_clipboard::copy(text) {
            Ok(()) => format!("Copied {label}; automatic clipboard expiration is disabled"),
            Err(err) => format!("Failed to copy {label}: {err}"),
        });
        return;
    }
    let result = match app.clipboard.as_mut() {
        Some(clipboard) => clipboard.set_text(text),
        None => match Clipboard::new() {
            Ok(mut clipboard) => {
                let result = clipboard.set_text(text);
                app.clipboard = Some(clipboard);
                result
            }
            Err(err) => Err(err),
        },
    };

    match result {
        Ok(()) => {
            app.clipboard_timer = Some(ClipboardTimer {
                label: label.to_string(),
                expected: text.to_string(),
                fingerprint: None,
                clear_at: Instant::now() + app.config.clipboard_timeout,
            });
            app.status = None;
        }
        Err(err) => {
            app.clipboard_timer = None;
            app.status = Some(format!("Failed to copy {label}: {err}"));
        }
    }
}

#[cfg(test)]
thread_local! {
    static EXPIRY_READ: std::cell::RefCell<Option<Result<String, arboard::Error>>> = const { std::cell::RefCell::new(None) };
}

fn read_native(clipboard: Option<&mut Clipboard>) -> Result<String, arboard::Error> {
    #[cfg(test)]
    if let Some(result) = EXPIRY_READ.with(|hook| hook.borrow_mut().take()) {
        return result;
    }
    clipboard
        .ok_or(arboard::Error::ClipboardNotSupported)?
        .get_text()
}

pub fn maybe_clear_clipboard(app: &mut App) {
    let Some(timer) = app.clipboard_timer.as_ref() else {
        return;
    };

    if Instant::now() < timer.clear_at {
        return;
    }

    let mut timer = app.clipboard_timer.take().unwrap();
    timer.forget_plaintext();

    let holds_ours = match read_native(app.clipboard.as_mut()) {
        Ok(mut current) => {
            let matches = timer.matches_text(&current);
            current.zeroize();
            matches
        }
        Err(err) => {
            app.status = Some(format!(
                "Clipboard clearing not verified; will retry: {err}"
            ));
            app.clipboard_timer = Some(timer);
            return;
        }
    };

    if holds_ours {
        let result = app
            .clipboard
            .as_mut()
            .ok_or(arboard::Error::ClipboardNotSupported)
            .and_then(Clipboard::clear);
        if let Err(err) = result {
            app.status = Some(format!(
                "Clipboard clearing not verified; will retry: {err}"
            ));
            app.clipboard_timer = Some(timer);
            return;
        }
    }

    app.status = Some(if holds_ours {
        "Clipboard cleared".to_string()
    } else {
        "Clipboard changed; left untouched".to_string()
    });
}

pub fn cp_user(app: &mut App) {
    if let Some(entry) = app.selected_entry() {
        let user = entry.user.clone();
        copy_and_report(app, "user", &user);
    }
}

pub fn cp_password(app: &mut App) {
    if let Some(entry) = app.selected_entry() {
        let password = entry.password.clone();
        copy_and_report(app, "password", &password);
    }
}

pub fn cp_totp(app: &mut App) {
    let Some(entry) = app.selected_entry() else {
        return;
    };

    match crate::db::current_totp_code(&entry.totp) {
        Some(totp) => copy_and_report(app, "TOTP code", &totp.code),
        None => {
            app.clipboard_timer = None;
            app.status = Some("No valid TOTP configured for this entry".to_string());
        }
    }
}

pub fn cp_url(app: &mut App) {
    if let Some(entry) = app.selected_entry() {
        let url = entry.url.clone();
        copy_and_report(app, "URL", &url);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expired() -> App {
        let mut app = App::for_test(None);
        app.clipboard_timer = Some(ClipboardTimer {
            label: "synthetic password".into(),
            expected: "synthetic clipboard secret".into(),
            fingerprint: None,
            clear_at: Instant::now(),
        });
        app
    }

    #[test]
    fn native_read_failure_retains_zeroized_expiry_for_retry() {
        let mut app = expired();
        let deadline = app.clipboard_timer.as_ref().unwrap().clear_at;
        EXPIRY_READ
            .with(|hook| *hook.borrow_mut() = Some(Err(arboard::Error::ClipboardNotSupported)));
        maybe_clear_clipboard(&mut app);
        let timer = app
            .clipboard_timer
            .as_ref()
            .expect("unverified clearing must remain pending");
        assert!(timer.expected.is_empty());
        assert!(timer.matches_text("synthetic clipboard secret"));
        assert_eq!(timer.clear_at, deadline);
        assert!(app.status.as_deref().unwrap().contains("not verified"));
        assert!(app.clipboard.is_none(), "no live clipboard acquired");
        // A subsequent successful read of different text resolves the timer but
        // must never erase the replacement value or claim it was cleared.
        EXPIRY_READ.with(|hook| *hook.borrow_mut() = Some(Ok("synthetic replacement".into())));
        maybe_clear_clipboard(&mut app);
        assert!(app.clipboard_timer.is_none());
        assert!(app.status.as_deref().unwrap().contains("changed"));
    }

    #[test]
    fn missing_native_handle_never_reports_successful_clearing() {
        let mut app = expired();
        maybe_clear_clipboard(&mut app);
        assert!(app.clipboard_timer.is_some());
        assert!(app.status.as_deref().unwrap().contains("not verified"));
    }
}
