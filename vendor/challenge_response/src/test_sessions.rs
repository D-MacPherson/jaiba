//! Test-only physical-session I/O boundary. Policy and scope are production code.
use crate::{error::ChallengeResponseError as Error, test_support::SerialRead, usb::Device};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Open(usize),
    Serial(usize),
    Hmac(usize),
    Abort(usize),
    Close(usize),
}
struct Physical {
    id: usize,
    alive: Cell<bool>,
    hmacs: Cell<usize>,
    fail_at: Cell<Option<usize>>,
    read: SerialRead,
}
struct Io {
    devices: Vec<Rc<Physical>>,
    events: Rc<RefCell<Vec<Event>>>,
}
thread_local! { static IO: RefCell<Option<Io>> = const { RefCell::new(None) }; }
pub struct Sessions {
    previous: Option<Io>,
    events: Rc<RefCell<Vec<Event>>>,
}
impl Sessions {
    pub fn new(reads: Vec<SerialRead>) -> Self {
        let events = Rc::new(RefCell::new(Vec::new()));
        let devices = reads
            .into_iter()
            .enumerate()
            .map(|(id, read)| {
                Rc::new(Physical {
                    id,
                    alive: Cell::new(true),
                    hmacs: Cell::new(0),
                    fail_at: Cell::new(None),
                    read,
                })
            })
            .collect();
        let previous = IO.with(|s| {
            s.replace(Some(Io {
                devices,
                events: events.clone(),
            }))
        });
        Self { previous, events }
    }
    pub fn fail_hmac_after(&self, address: usize, count: usize) {
        IO.with(|s| {
            let io = s.borrow();
            let p = &io.as_ref().unwrap().devices[address];
            p.fail_at.set(Some(p.hmacs.get() + count));
        });
    }
    pub fn events(&self) -> Vec<Event> {
        self.events.borrow().clone()
    }
    pub fn remove(&self, address: usize) {
        IO.with(|s| {
            s.borrow().as_ref().unwrap().devices[address]
                .alive
                .set(false)
        });
    }
    pub fn replace(&self, address: usize, read: SerialRead) {
        IO.with(|s| {
            let mut io = s.borrow_mut();
            let io = io.as_mut().unwrap();
            io.devices[address].alive.set(false);
            let id = io.devices.iter().map(|d| d.id).max().unwrap_or(0) + 1;
            io.devices[address] = Rc::new(Physical {
                id,
                alive: Cell::new(true),
                hmacs: Cell::new(0),
                fail_at: Cell::new(None),
                read,
            });
        });
    }
}
impl Drop for Sessions {
    fn drop(&mut self) {
        IO.with(|s| s.replace(self.previous.take()));
    }
}
pub(crate) fn candidates() -> Option<Vec<Device>> {
    IO.with(|s| {
        s.borrow().as_ref().map(|io| {
            io.devices
                .iter()
                .enumerate()
                .filter(|(_, p)| p.alive.get())
                .map(|(address, _)| Device {
                    name: Some("synthetic physical device".into()),
                    serial: None,
                    vendor_id: 0x1050,
                    product_id: 0x0407,
                    bus_id: 1,
                    address_id: address as u8,
                })
                .collect()
        })
    })
}
pub(crate) struct Handle {
    physical: Rc<Physical>,
    events: Rc<RefCell<Vec<Event>>>,
}
impl Handle {
    fn check(&self) -> Result<(), Error> {
        if self.physical.alive.get() {
            Ok(())
        } else {
            Err(Error::CanNotReadFromDevice)
        }
    }
    pub(crate) fn abort(&self) {
        self.events
            .borrow_mut()
            .push(Event::Abort(self.physical.id));
    }
    pub(crate) fn serial(&self) -> Result<u32, Error> {
        self.events
            .borrow_mut()
            .push(Event::Serial(self.physical.id));
        self.check()?;
        self.physical.read.result()
    }
    pub(crate) fn hmac(
        &self,
        challenge: &[u8],
        slot: &crate::config::Slot,
    ) -> Result<crate::hmacmode::Hmac, Error> {
        self.events.borrow_mut().push(Event::Hmac(self.physical.id));
        self.physical.hmacs.set(self.physical.hmacs.get() + 1);
        if self.physical.fail_at.get() == Some(self.physical.hmacs.get()) {
            self.physical.alive.set(false);
        }
        self.check()?;
        // Same synthetic slot material on each simulated key, real HMAC computation.
        Ok(crate::hmacmode::Hmac(crate::sec::hmac_sha1(
            &crate::hmacmode::HmacKey(
                [if matches!(slot, crate::config::Slot::Slot2) {
                    0x42
                } else {
                    0x24
                }; 20],
            ),
            challenge,
        )))
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        self.events
            .borrow_mut()
            .push(Event::Close(self.physical.id));
    }
}
pub(crate) fn discovery(read: SerialRead) -> Handle {
    Handle {
        physical: Rc::new(Physical {
            id: 0,
            alive: Cell::new(true),
            hmacs: Cell::new(0),
            fail_at: Cell::new(None),
            read,
        }),
        events: Rc::new(RefCell::new(Vec::new())),
    }
}
pub(crate) fn open(address: u8) -> Option<Result<Handle, Error>> {
    IO.with(|s| {
        s.borrow().as_ref().map(|io| {
            let physical = io
                .devices
                .get(address as usize)
                .ok_or(Error::DeviceNotFound)?
                .clone();
            io.events.borrow_mut().push(Event::Open(physical.id));
            Ok(Handle {
                physical,
                events: io.events.clone(),
            })
        })
    })
}
