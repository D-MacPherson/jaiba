//! Test-only hardware substitute. Never compiled into the application.
//! Uses keepass's real HMAC/KDBX implementation, not invented ciphertext.
use crate::config::YubikeyConfig;
use std::cell::RefCell;

#[derive(Default)]
struct State {
    selection: Option<YubikeyConfig>,
    unavailable: bool,
    operations: usize,
    fail_at: Option<usize>,
}
thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }

pub struct Model;
impl Model {
    /// Retain real hardware keys; inject only operation-boundary failures.
    pub fn faults_only() -> Self {
        STATE.with(|s| *s.borrow_mut() = State::default());
        Self
    }
    pub fn new(selection: YubikeyConfig) -> Self {
        STATE.with(|s| {
            *s.borrow_mut() = State {
                selection: Some(selection),
                ..State::default()
            }
        });
        Self
    }
    pub fn unavailable(&self, value: bool) {
        STATE.with(|s| s.borrow_mut().unavailable = value);
    }
    pub fn operations(&self) -> usize {
        STATE.with(|s| s.borrow().operations)
    }
    pub fn fail_after(&self, count: usize) {
        STATE.with(|s| {
            let mut s = s.borrow_mut();
            s.fail_at = Some(s.operations + count);
        });
    }
    pub fn clear_fault(&self) {
        STATE.with(|s| s.borrow_mut().fail_at = None);
    }
}
impl Drop for Model {
    fn drop(&mut self) {
        STATE.with(|s| *s.borrow_mut() = State::default());
    }
}

pub fn select(selection: YubikeyConfig) -> Option<anyhow::Result<keepass::ChallengeResponseKey>> {
    STATE.with(|s| {
        let s = s.borrow();
        s.selection.map(|expected| {
            anyhow::ensure!(
                !s.unavailable && selection == expected,
                "YubiKey unavailable or wrong serial/slot (test model)"
            );
            Ok(keepass::ChallengeResponseKey::LocalChallenge(
                "00112233445566778899aabbccddeeff00112233".into(),
            ))
        })
    })
}

pub fn operation(label: &str) -> anyhow::Result<()> {
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        s.operations += 1;
        if std::env::var("JAIBA_YUBIKEY_TEST").as_deref() == Ok("39269826:2") {
            eprintln!("KDBX TEST operation #{} {label}: library call starting; provide a touch if requested (may block)", s.operations);
        }
        anyhow::ensure!(
            !s.unavailable && s.fail_at != Some(s.operations),
            "YubiKey I/O unavailable (test model)"
        );
        Ok(())
    })
}
