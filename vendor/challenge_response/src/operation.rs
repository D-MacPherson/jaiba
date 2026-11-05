//! Cooperative, thread-local operation budget. No spawned workers or cached keys.
use crate::error::ChallengeResponseError;
use std::{
    cell::{Cell, RefCell},
    marker::PhantomData,
    rc::Rc,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
pub const TRANSFER_TIMEOUT: Duration = Duration::from_millis(100);
#[derive(Clone)]
struct State {
    deadline: Instant,
    native: Rc<Cell<bool>>,
}
thread_local! {
    static ACTIVE: RefCell<Option<State>> = const { RefCell::new(None) };
    static CANCEL: RefCell<Option<Arc<AtomicBool>>> = const { RefCell::new(None) };
}
/// Must stay on the creating thread. Nested scopes can shorten, never extend.
pub struct Operation {
    previous: Option<State>,
    _local: PhantomData<Rc<()>>,
}
impl Operation {
    pub fn new(timeout: Duration) -> Self {
        let deadline = Instant::now() + timeout;
        let previous = ACTIVE.with(|s| {
            let (deadline, native) = s.borrow().as_ref().map_or_else(
                || (deadline, Rc::new(Cell::new(false))),
                |p| (p.deadline.min(deadline), Rc::clone(&p.native)),
            );
            s.replace(Some(State { deadline, native }))
        });
        Self {
            previous,
            _local: PhantomData,
        }
    }
    pub fn standard() -> Self {
        Self::new(DEFAULT_TIMEOUT)
    }
}
impl Drop for Operation {
    fn drop(&mut self) {
        ACTIVE.with(|s| {
            s.replace(self.previous.take());
        });
    }
}
/// Install a signal-handler-owned atomic. Only the coordinator consumes it.
pub struct Cancellation {
    previous: Option<Arc<AtomicBool>>,
    _local: PhantomData<Rc<()>>,
}
impl Cancellation {
    pub fn install(flag: Arc<AtomicBool>) -> Self {
        Self {
            previous: CANCEL.with(|s| s.replace(Some(flag))),
            _local: PhantomData,
        }
    }
}
impl Drop for Cancellation {
    fn drop(&mut self) {
        CANCEL.with(|s| {
            s.replace(self.previous.take());
        });
    }
}
/// Activate deadline enforcement only when a native operation is actually used.
/// Password-only KDF/persistence retains its old behavior; cancellation always applies.
pub(crate) fn native() -> Result<(), ChallengeResponseError> {
    ACTIVE.with(|s| {
        if let Some(s) = s.borrow().as_ref() {
            s.native.set(true);
        }
    });
    check()
}
pub fn check() -> Result<(), ChallengeResponseError> {
    if CANCEL.with(|s| {
        s.borrow()
            .as_ref()
            .is_some_and(|f| f.load(Ordering::SeqCst))
    }) {
        return Err(ChallengeResponseError::Cancelled);
    }
    if ACTIVE.with(|s| {
        s.borrow()
            .as_ref()
            .is_some_and(|s| s.native.get() && Instant::now() >= s.deadline)
    }) {
        return Err(ChallengeResponseError::DeadlineExceeded);
    }
    Ok(())
}
pub(crate) fn transfer_timeout() -> Result<Duration, ChallengeResponseError> {
    check()?;
    Ok(ACTIVE
        .with(|s| {
            s.borrow().as_ref().map_or(TRANSFER_TIMEOUT, |s| {
                TRANSFER_TIMEOUT.min(s.deadline.saturating_duration_since(Instant::now()))
            })
        })
        .max(Duration::from_millis(1)))
}
