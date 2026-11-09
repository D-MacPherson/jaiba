//! Synthetic I/O exercising production discovery and protocol logic. No USB.
pub use crate::test_sessions::{Event, Sessions};

/// Drive only the presentation notification seam, without device I/O.
pub fn touch_wait_reports(statuses: &[u8]) {
    let _wait = crate::touch::ResponseWait::new();
    for status in statuses {
        crate::touch::status(*status);
    }
}

pub fn touch_status_outside_response(status: u8) {
    crate::touch::status(status);
}
use std::{
    cell::RefCell,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

#[derive(Clone)]
pub enum SerialRead {
    Serial(u32),
    Denied,
    Busy,
    Gone,
    Unsupported,
    Cancelled,
    Deadline,
    EnumerationFailure,
    CancelDuring(Arc<AtomicBool>, Box<SerialRead>),
    ExpireDuring(Box<SerialRead>),
    Sequence(std::rc::Rc<Cell<usize>>, Vec<SerialRead>),
}
impl SerialRead {
    pub(crate) fn result(&self) -> Result<u32, ChallengeResponseError> {
        match self {
            Self::Serial(serial) => Ok(*serial),
            Self::Sequence(next, values) => {
                let index = next.get();
                next.set(index + 1);
                values[index.min(values.len() - 1)].result()
            }
            Self::Denied => Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "synthetic serial access denied",
            )
            .into()),
            Self::Busy => Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "synthetic serial busy",
            )
            .into()),
            Self::Gone => Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "synthetic serial disconnected",
            )
            .into()),
            Self::Unsupported => crate::usb::nusb::opened_device(Ok(0), false),
            Self::Cancelled => Err(ChallengeResponseError::Cancelled),
            Self::Deadline => Err(ChallengeResponseError::DeadlineExceeded),
            Self::EnumerationFailure => crate::usb::nusb::enumerated(Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "synthetic nested enumeration denied",
            )
            .into())),
            Self::CancelDuring(flag, result) => {
                flag.store(true, Ordering::SeqCst);
                result.result()
            }
            Self::ExpireDuring(result) => {
                std::thread::sleep(Duration::from_millis(75));
                result.result()
            }
        }
    }
}
struct DiscoveryIo {
    reads: Vec<SerialRead>,
    enumeration: Option<SerialRead>,
}
thread_local! {
    static DISCOVERY: RefCell<Option<DiscoveryIo>> = const { RefCell::new(None) };
}
/// Thread-local I/O-only seam; actual native entrypoints retain selection policy.
pub struct Discovery(Option<DiscoveryIo>);
impl Discovery {
    pub fn new(reads: Vec<SerialRead>) -> Self {
        Self::with_enumeration(reads, None)
    }
    pub fn with_enumeration(reads: Vec<SerialRead>, enumeration: Option<SerialRead>) -> Self {
        Self(DISCOVERY.with(|s| s.replace(Some(DiscoveryIo { reads, enumeration }))))
    }
}
impl Drop for Discovery {
    fn drop(&mut self) {
        DISCOVERY.with(|s| s.replace(self.0.take()));
    }
}
pub(crate) fn discovery_devices() -> Option<Result<Vec<Device>, ChallengeResponseError>> {
    if let Some(devices) = crate::test_sessions::candidates() {
        return Some(Ok(devices));
    }
    DISCOVERY.with(|s| {
        s.borrow().as_ref().map(|io| {
            if let Some(action) = &io.enumeration {
                action.result()?;
            }
            Ok(io
                .reads
                .iter()
                .enumerate()
                .map(|(i, _)| Device {
                    name: Some("synthetic".into()),
                    serial: None,
                    vendor_id: 0x1050,
                    product_id: 0x0407,
                    bus_id: 1,
                    address_id: u8::try_from(i).expect("too many synthetic devices"),
                })
                .collect())
        })
    })
}
pub(crate) fn discovery_serial(address: u8) -> Option<Result<u32, ChallengeResponseError>> {
    if let Some(handle) = crate::test_sessions::open(address) {
        return Some(handle.and_then(|h| h.serial()));
    }
    DISCOVERY.with(|s| {
        s.borrow()
            .as_ref()
            .map(|io| io.reads[address as usize].result())
    })
}
/// Invoke the production backend directly too, without the public wrapper's final check.
pub(crate) fn discovery_handle(
    address: u8,
) -> Option<Result<crate::test_sessions::Handle, ChallengeResponseError>> {
    crate::test_sessions::open(address).or_else(|| {
        DISCOVERY.with(|s| {
            s.borrow().as_ref().map(|io| {
                Ok(crate::test_sessions::discovery(
                    io.reads[address as usize].clone(),
                ))
            })
        })
    })
}
pub fn backend_discovery(serial: Option<u32>) -> Result<Vec<Device>, ChallengeResponseError> {
    let mut backend = crate::usb::nusb::NUSBBackend::new()?;
    match serial {
        Some(serial) => backend.find_device_from_serial(serial).map(|d| vec![d]),
        None => backend.find_all_devices(),
    }
}
use crate::{
    error::ChallengeResponseError,
    usb::{Backend, Device, Flags},
};
use std::{cell::Cell, time::Duration};

struct Stalled<'a> {
    reads: Cell<usize>,
    delay: Duration,
    limit: usize,
    status: Cell<u8>,
    on_second_read: Option<&'a dyn Fn() -> Result<(), ChallengeResponseError>>,
}
impl Backend<(), ()> for Stalled<'_> {
    fn new() -> Result<Self, ChallengeResponseError> {
        unreachable!()
    }
    fn open_device(&mut self, _: u8, _: u8) -> Result<((), Vec<()>), ChallengeResponseError> {
        Ok(((), vec![]))
    }
    fn close_device(&self, _: (), _: Vec<()>) -> Result<(), ChallengeResponseError> {
        Ok(())
    }
    fn read(&self, _: &mut (), buf: &mut [u8]) -> Result<usize, ChallengeResponseError> {
        self.reads.set(self.reads.get() + 1);
        if self.reads.get() == 2 {
            if let Some(action) = self.on_second_read {
                action()?;
                crate::operation::native()?;
                self.status.set(0x40);
            }
        }
        if self.reads.get() >= self.limit {
            return Err(ChallengeResponseError::CanNotReadFromDevice);
        }
        std::thread::sleep(self.delay);
        buf.fill(0);
        buf[7] = self.status.get();
        Ok(buf.len())
    }
    fn raw_write(&self, _: &mut (), _: &[u8]) -> Result<(), ChallengeResponseError> {
        Ok(())
    }
    fn find_device(&mut self) -> Result<Device, ChallengeResponseError> {
        unreachable!()
    }
    fn find_device_from_serial(&mut self, _: u32) -> Result<Device, ChallengeResponseError> {
        unreachable!()
    }
    fn find_all_devices(&mut self) -> Result<Vec<Device>, ChallengeResponseError> {
        unreachable!()
    }
}

pub fn cancelled_session() -> (String, usize, usize, usize) {
    use std::{
        rc::Rc,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
    };
    struct Lease(Rc<Cell<usize>>);
    impl Lease {
        fn new(n: &Rc<Cell<usize>>) -> Self {
            n.set(n.get() + 1);
            Self(Rc::clone(n))
        }
    }
    impl Drop for Lease {
        fn drop(&mut self) {
            self.0.set(self.0.get() - 1);
        }
    }
    struct Claims {
        active: Rc<Cell<usize>>,
        closed: Cell<usize>,
        aborted: Cell<usize>,
        flag: Arc<AtomicBool>,
    }
    impl Backend<Lease, Lease> for Claims {
        fn new() -> Result<Self, ChallengeResponseError> {
            unreachable!()
        }
        fn open_device(
            &mut self,
            _: u8,
            _: u8,
        ) -> Result<(Lease, Vec<Lease>), ChallengeResponseError> {
            Ok((Lease::new(&self.active), vec![Lease::new(&self.active)]))
        }
        fn close_device(&self, _: Lease, _: Vec<Lease>) -> Result<(), ChallengeResponseError> {
            self.closed.set(self.closed.get() + 1);
            Err(ChallengeResponseError::OpenDeviceError)
        }
        fn abort(&self, _: &mut Lease) {
            self.aborted.set(self.aborted.get() + 1);
        }
        fn read(&self, _: &mut Lease, buf: &mut [u8]) -> Result<usize, ChallengeResponseError> {
            buf.fill(0);
            self.flag.store(true, Ordering::SeqCst);
            Ok(8)
        }
        fn raw_write(&self, _: &mut Lease, _: &[u8]) -> Result<(), ChallengeResponseError> {
            Ok(())
        }
        fn find_device(&mut self) -> Result<Device, ChallengeResponseError> {
            unreachable!()
        }
        fn find_device_from_serial(&mut self, _: u32) -> Result<Device, ChallengeResponseError> {
            unreachable!()
        }
        fn find_all_devices(&mut self) -> Result<Vec<Device>, ChallengeResponseError> {
            unreachable!()
        }
    }
    let flag = Arc::new(AtomicBool::new(false));
    let _cancel = crate::operation::Cancellation::install(Arc::clone(&flag));
    let mut backend = Claims {
        active: Rc::new(Cell::new(0)),
        closed: Cell::new(0),
        aborted: Cell::new(0),
        flag,
    };
    let result = backend.with_device(0, 0, |b, h| b.wait(h, |_| true, &mut [0; 8]));
    (
        result.unwrap_err().to_string(),
        backend.active.get(),
        backend.closed.get(),
        backend.aborted.get(),
    )
}

pub fn discovery_open_failure(denied: bool) -> Result<(), ChallengeResponseError> {
    let result = if denied {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "synthetic open denied",
        )
        .into())
    } else {
        Ok(())
    };
    crate::usb::nusb::opened_device(result, denied)
}

pub fn short_report() -> Result<usize, ChallengeResponseError> {
    crate::usb::nusb::copy_report(&mut [0; 8], &[0; 3])
}
pub fn otp_interface(number: u8, class: u8, subclass: u8, protocol: u8) -> bool {
    crate::usb::nusb::otp_interface(number, class, subclass, protocol)
}

pub fn overlong_response() -> Result<usize, ChallengeResponseError> {
    struct Overlong;
    impl Backend<(), ()> for Overlong {
        fn new() -> Result<Self, ChallengeResponseError> {
            Ok(Self)
        }
        fn open_device(&mut self, _: u8, _: u8) -> Result<((), Vec<()>), ChallengeResponseError> {
            unreachable!()
        }
        fn close_device(&self, _: (), _: Vec<()>) -> Result<(), ChallengeResponseError> {
            Ok(())
        }
        fn read(&self, _: &mut (), buf: &mut [u8]) -> Result<usize, ChallengeResponseError> {
            buf.fill(0);
            buf[7] = 0x41;
            Ok(8)
        }
        fn raw_write(&self, _: &mut (), _: &[u8]) -> Result<(), ChallengeResponseError> {
            Ok(())
        }
        fn find_device(&mut self) -> Result<Device, ChallengeResponseError> {
            unreachable!()
        }
        fn find_device_from_serial(&mut self, _: u32) -> Result<Device, ChallengeResponseError> {
            unreachable!()
        }
        fn find_all_devices(&mut self) -> Result<Vec<Device>, ChallengeResponseError> {
            unreachable!()
        }
    }
    Overlong.read_response(&mut (), &mut [0; 36])
}

pub fn stalled_wait(delay: Duration, limit: usize) -> (Result<(), ChallengeResponseError>, usize) {
    let backend = Stalled {
        reads: Cell::new(0),
        delay,
        limit,
        status: Cell::new(0),
        on_second_read: None,
    };
    let result = backend.wait(
        &mut (),
        |f| f.contains(Flags::RESP_PENDING_FLAG),
        &mut [0; 8],
    );
    (result, backend.reads.get())
}

/// Replay an OTP touch keepalive through the production polling loop. The
/// callback can block until the UI has actually flushed, then release the wait.
pub fn touch_wait_for(
    status: u8,
    action: impl Fn() -> Result<(), ChallengeResponseError>,
) -> Result<(), ChallengeResponseError> {
    let backend = Stalled {
        reads: Cell::new(0),
        delay: Duration::ZERO,
        limit: usize::MAX,
        status: Cell::new(status),
        on_second_read: Some(&action),
    };
    let _wait = crate::touch::ResponseWait::new();
    backend.wait(
        &mut (),
        |f| f.contains(Flags::RESP_PENDING_FLAG),
        &mut [0; 8],
    )
}
