//! Presentation-only notifications. They never influence protocol results or retries.
use std::{
    cell::{Cell, RefCell},
    marker::PhantomData,
    rc::Rc,
    sync::mpsc::Sender,
};

struct State {
    sender: Sender<bool>,
    waiting: bool,
}
thread_local! {
    static OBSERVER: RefCell<Option<State>> = const { RefCell::new(None) };
    static RESPONSE: Cell<bool> = const { Cell::new(false) };
}

/// Register a UI observer on the authentication thread, without moving credentials.
pub struct Observer {
    previous: Option<State>,
    _local: PhantomData<Rc<()>>,
}
impl Observer {
    pub fn install(sender: Sender<bool>) -> Self {
        Self {
            previous: OBSERVER.with(|state| {
                state.replace(Some(State {
                    sender,
                    waiting: false,
                }))
            }),
            _local: PhantomData,
        }
    }
}
impl Drop for Observer {
    fn drop(&mut self) {
        publish(false);
        OBSERVER.with(|state| state.replace(self.previous.take()));
    }
}

pub(crate) struct ResponseWait(bool);
impl ResponseWait {
    pub(crate) fn new() -> Self {
        Self(RESPONSE.with(|active| active.replace(true)))
    }
}
impl Drop for ResponseWait {
    fn drop(&mut self) {
        publish(false);
        RESPONSE.with(|active| active.set(self.0));
    }
}

fn publish(waiting: bool) {
    OBSERVER.with(|state| {
        if let Some(state) = state.borrow_mut().as_mut() {
            if state.waiting != waiting {
                state.waiting = waiting;
                let _ = state.sender.send(waiting);
            }
        }
    });
}

pub(crate) fn status(status: u8) {
    if RESPONSE.with(Cell::get) {
        // Match the OTP SDK: response data takes priority over the touch-wait
        // flag. SLOT_WRITE_FLAG can coexist with a touch-required keepalive.
        publish(status & 0x20 != 0 && status & 0x40 == 0);
    }
}
