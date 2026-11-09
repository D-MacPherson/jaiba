use crate::operation::{self, Operation};
use std::time::Duration;

use nusb::{Device as NUSBDevice, Interface, MaybeFuture};

use crate::error::ChallengeResponseError;
use crate::usb::{
    Backend, Device, HID_GET_REPORT, HID_SET_REPORT, PRODUCT_ID, REPORT_TYPE_FEATURE, VENDOR_ID,
};

pub struct NUSBBackend {}

/// Shared by all nested scopes, never stored in a retained database credential.
#[derive(Default)]
pub(crate) struct PinState {
    selected: Option<Selected>,
    attempted: bool,
    failed: bool,
}
struct Selected {
    device: Device,
    handle: Handle,
}
enum Handle {
    // Interface claims must drop before the opened device.
    Native {
        _interfaces: Vec<Interface>,
        device: NUSBDevice,
    },
    #[cfg(feature = "test-support")]
    Synthetic(crate::test_sessions::Handle),
}

impl NUSBBackend {
    pub(crate) fn pinned_hmac(
        &mut self,
        challenge: &[u8],
        conf: &crate::config::Config,
    ) -> Result<crate::hmacmode::Hmac, ChallengeResponseError> {
        let serial = conf
            .device
            .serial
            .ok_or(ChallengeResponseError::DeviceNotFound)?;
        self.select_authorized(&[serial])?;
        let shared = operation::session()?;
        let mut state = shared.borrow_mut();
        let selected = state
            .selected
            .as_mut()
            .ok_or(ChallengeResponseError::DeviceNotFound)?;
        let result = match &mut selected.handle {
            Handle::Native { device, .. } => self.hmac(device, challenge, conf),
            #[cfg(feature = "test-support")]
            Handle::Synthetic(handle) => handle.hmac(challenge, &conf.slot),
        };
        let result = operation::native().and(result);
        if result.is_err() {
            self.abort_session(&mut selected.handle);
            state.failed = true;
        }
        result
    }

    fn open_session(&mut self, device: &Device) -> Result<Handle, ChallengeResponseError> {
        #[cfg(feature = "test-support")]
        if let Some(handle) = crate::test_support::discovery_handle(device.address_id) {
            return handle.map(Handle::Synthetic);
        }
        let (device, interfaces) = self.open_device(device.bus_id, device.address_id)?;
        Ok(Handle::Native {
            _interfaces: interfaces,
            device,
        })
    }
    fn abort_session(&self, handle: &mut Handle) {
        match handle {
            Handle::Native { device, .. } => self.abort(device),
            #[cfg(feature = "test-support")]
            Handle::Synthetic(handle) => handle.abort(),
        }
    }
    fn session_serial(&self, handle: &mut Handle) -> Result<u32, ChallengeResponseError> {
        match handle {
            Handle::Native { device, .. } => self.read_serial(device),
            #[cfg(feature = "test-support")]
            Handle::Synthetic(handle) => handle.serial(),
        }
    }
    /// Deterministic authorization with identity read on the actual retained handle.
    /// Only a fresh outer Operation permits another discovery attempt.
    pub(crate) fn select_authorized(
        &mut self,
        serials: &[u32],
    ) -> Result<Device, ChallengeResponseError> {
        operation::native()?;
        let shared = operation::session()?;
        let mut state = shared.borrow_mut();
        if state.failed {
            return Err(ChallengeResponseError::OpenDeviceError);
        }
        if let Some(selected) = &state.selected {
            if serials.contains(&selected.device.serial.unwrap_or(0)) {
                return Ok(selected.device.clone());
            }
            state.failed = true;
            return Err(ChallengeResponseError::DeviceNotFound);
        }
        if state.attempted {
            return Err(ChallengeResponseError::OpenDeviceError);
        }
        state.attempted = true;
        let result = (|| {
            if serials.is_empty() || serials.contains(&0) {
                return Err(ChallengeResponseError::DeviceNotFound);
            }
            let candidates = enumerated(self.candidates())?;
            let mut chosen: Option<Selected> = None;
            let mut unreadable = None;
            for mut device in candidates {
                operation::native()?;
                if !VENDOR_ID.contains(&device.vendor_id)
                    || !PRODUCT_ID.contains(&device.product_id)
                {
                    continue;
                }
                let result = self.open_session(&device).and_then(|mut handle| {
                    let result = self.session_serial(&mut handle);
                    let serial = match operation::native().and(result) {
                        Ok(serial) => serial,
                        Err(error) => {
                            self.abort_session(&mut handle);
                            return Err(error);
                        }
                    };
                    device.serial = Some(serial);
                    Ok(Selected { device, handle })
                });
                operation::native()?;
                match result {
                    Ok(selected) => {
                        let serial = selected.device.serial.unwrap();
                        if serials.contains(&serial)
                            && chosen
                                .as_ref()
                                .is_none_or(|c| serial < c.device.serial.unwrap())
                        {
                            chosen = Some(selected);
                        }
                    }
                    Err(
                        e @ (ChallengeResponseError::Cancelled
                        | ChallengeResponseError::DeadlineExceeded
                        | ChallengeResponseError::EnumerationFailed(_)
                        | ChallengeResponseError::ListDevicesError),
                    ) => return Err(e),
                    Err(error) => {
                        if unreadable.is_none() {
                            unreadable = Some(error);
                        }
                    }
                }
            }
            operation::native()?;
            chosen.ok_or_else(|| unreadable.unwrap_or(ChallengeResponseError::DeviceNotFound))
        })();
        match result {
            Ok(selected) => {
                let device = selected.device.clone();
                state.selected = Some(selected);
                Ok(device)
            }
            Err(error) => {
                state.failed = true;
                Err(error)
            }
        }
    }
}

impl NUSBBackend {
    fn candidates(&mut self) -> Result<Vec<Device>, ChallengeResponseError> {
        #[cfg(feature = "test-support")]
        if let Some(result) = crate::test_support::discovery_devices() {
            return result;
        }
        Ok(nusb::list_devices()
            .wait()?
            .map(|info| Device {
                name: Some(info.manufacturer_string().unwrap_or("unknown").to_string()),
                serial: None,
                product_id: info.product_id(),
                vendor_id: info.vendor_id(),
                bus_id: info.busnum(),
                address_id: info.device_address(),
            })
            .collect())
    }
    fn candidate_serial(&mut self, device: &Device) -> Result<u32, ChallengeResponseError> {
        #[cfg(feature = "test-support")]
        if let Some(result) = crate::test_support::discovery_serial(device.address_id) {
            return result;
        }
        self.read_serial_from_device(device.bus_id, device.address_id)
    }
    // Both public entrypoints use this policy; the seam replaces only I/O.
    fn discover(&mut self, serial: Option<u32>) -> Result<Vec<Device>, ChallengeResponseError> {
        let _operation = Operation::standard();
        operation::native()?;
        let candidates = self.candidates();
        let candidates = enumerated(candidates)?;
        let mut devices = Vec::new();
        let mut unreadable = None;
        for mut device in candidates {
            operation::native()?;
            if !VENDOR_ID.contains(&device.vendor_id) || !PRODUCT_ID.contains(&device.product_id) {
                continue;
            }
            let serial_result = self.candidate_serial(&device);
            operation::native()?;
            device.serial = match serial_result {
                Ok(serial) => Some(serial),
                Err(
                    e @ (ChallengeResponseError::Cancelled
                    | ChallengeResponseError::DeadlineExceeded
                    | ChallengeResponseError::EnumerationFailed(_)
                    | ChallengeResponseError::ListDevicesError),
                ) => return Err(e),
                Err(error) => {
                    // Until a serial matches, an unreadable candidate may be the
                    // requested token. Retain its diagnostic, never call it absent.
                    if unreadable.is_none() {
                        unreadable = Some(error);
                    }
                    None
                }
            };
            if let Some(serial) = serial {
                if device.serial == Some(serial) {
                    return Ok(vec![device]);
                }
            } else {
                devices.push(device);
            }
        }
        if serial.is_some() {
            Err(unreadable.unwrap_or(ChallengeResponseError::DeviceNotFound))
        } else {
            Ok(devices)
        }
    }
}

// A list failure remains global even when enumeration was nested inside a
// candidate serial read/open. Never downgrade it to that candidate being unreadable.
pub(crate) fn enumerated<T>(
    result: Result<T, ChallengeResponseError>,
) -> Result<T, ChallengeResponseError> {
    operation::native()?;
    result.map_err(|error| match error {
        error @ (ChallengeResponseError::Cancelled
        | ChallengeResponseError::DeadlineExceeded
        | ChallengeResponseError::EnumerationFailed(_)) => error,
        error => ChallengeResponseError::EnumerationFailed(Box::new(error)),
    })
}

pub(crate) fn opened_device<T>(
    result: Result<T, ChallengeResponseError>,
    supported: bool,
) -> Result<T, ChallengeResponseError> {
    operation::native()?;
    let device = result?;
    if !supported {
        return Err(ChallengeResponseError::UnsupportedInterface);
    }
    Ok(device)
}

pub(crate) fn otp_interface(number: u8, class: u8, subclass: u8, protocol: u8) -> bool {
    number == 0 && class == 3 && subclass == 1 && protocol == 1
}
pub(crate) fn copy_report(buf: &mut [u8], report: &[u8]) -> Result<usize, ChallengeResponseError> {
    if buf.len() != 8 || report.len() != 8 {
        return Err(ChallengeResponseError::InvalidResponse);
    }
    buf.copy_from_slice(report);
    Ok(8)
}

impl Backend<NUSBDevice, Interface> for NUSBBackend {
    fn new() -> Result<Self, ChallengeResponseError> {
        Ok(Self {})
    }

    fn open_device(
        &mut self,
        bus_id: u8,
        address_id: u8,
    ) -> Result<(NUSBDevice, Vec<Interface>), ChallengeResponseError> {
        let _operation = Operation::standard();
        operation::native()?;
        let result = nusb::list_devices().wait().map_err(Into::into);
        let nusb_devices = enumerated(result)?;
        for device_info in nusb_devices {
            operation::native()?;
            if device_info.busnum() != bus_id || device_info.device_address() != address_id {
                continue;
            }

            // HMAC reports address interface zero. Never detach unrelated FIDO
            // or CCID interfaces, and never silently proceed without a claim.
            let supported = device_info.interfaces().any(|i| {
                otp_interface(i.interface_number(), i.class(), i.subclass(), i.protocol())
            });
            let result = device_info.open().wait().map_err(Into::into);
            let device = opened_device(result, supported)?;
            let interface = device.detach_and_claim_interface(0).wait()?;
            let interfaces = vec![interface];
            operation::native()?;
            return Ok((device, interfaces));
        }

        Err(ChallengeResponseError::DeviceNotFound)
    }

    fn abort(&self, handle: &mut NUSBDevice) {
        let reset = nusb::transfer::ControlOut {
            control_type: nusb::transfer::ControlType::Class,
            recipient: nusb::transfer::Recipient::Interface,
            request: HID_SET_REPORT,
            value: REPORT_TYPE_FEATURE << 8,
            index: 0,
            data: &crate::usb::WRITE_RESET_PAYLOAD,
        };
        let _ = handle.control_out(reset, Duration::from_millis(100)).wait();
    }

    fn close_device(
        &self,
        mut _handle: NUSBDevice,
        _interfaces: Vec<Interface>,
    ) -> Result<(), ChallengeResponseError> {
        Ok(())
    }

    fn read(
        &self,
        handle: &mut NUSBDevice,
        buf: &mut [u8],
    ) -> Result<usize, ChallengeResponseError> {
        let _operation = Operation::standard();
        operation::native()?;
        if buf.len() != 8 {
            return Err(ChallengeResponseError::InvalidResponse);
        }

        let control_type = nusb::transfer::ControlType::Class;
        let control_in = nusb::transfer::ControlIn {
            control_type,
            recipient: nusb::transfer::Recipient::Interface,
            request: HID_GET_REPORT,
            value: REPORT_TYPE_FEATURE << 8,
            index: 0,
            length: 8,
        };

        let result = handle
            .control_in(control_in, operation::transfer_timeout()?)
            .wait();
        operation::native()?;
        let r = result.map_err(|_| ChallengeResponseError::CanNotReadFromDevice)?;
        copy_report(buf, &r)
    }

    fn raw_write(
        &self,
        handle: &mut NUSBDevice,
        packet: &[u8],
    ) -> Result<(), ChallengeResponseError> {
        let _operation = Operation::standard();
        operation::native()?;
        let control_type = nusb::transfer::ControlType::Class;
        let control_out = nusb::transfer::ControlOut {
            control_type,
            recipient: nusb::transfer::Recipient::Interface,
            request: HID_SET_REPORT,
            value: REPORT_TYPE_FEATURE << 8,
            index: 0,
            data: packet,
        };

        let result = handle
            .control_out(control_out, operation::transfer_timeout()?)
            .wait();
        operation::native()?;
        result.map_err(|_| ChallengeResponseError::CanNotWriteToDevice)
    }

    fn find_device(&mut self) -> Result<Device, ChallengeResponseError> {
        match self.find_all_devices() {
            Ok(devices) => {
                if !devices.is_empty() {
                    Ok(devices[0].clone())
                } else {
                    Err(ChallengeResponseError::DeviceNotFound)
                }
            }
            Err(e) => Err(e),
        }
    }

    fn find_device_from_serial(&mut self, serial: u32) -> Result<Device, ChallengeResponseError> {
        self.discover(Some(serial))?
            .into_iter()
            .next()
            .ok_or(ChallengeResponseError::DeviceNotFound)
    }

    fn find_all_devices(&mut self) -> Result<Vec<Device>, ChallengeResponseError> {
        self.discover(None)
    }
}
