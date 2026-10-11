//! macOS virtual HID transport for CTAPHID.
//!
//! Pure pieces (`REPORT_DESCRIPTOR`, [`properties`], Block layout constants)
//! are available on every target. Creating an `IOHIDUserDevice` is macOS-only
//! and lives in [`device`]. See DESIGN.md and DEPLOY.md.
//!
//! This crate never activates a device unless [`device::run`] is called, which
//! the `se-fido-device` binary only does with an explicit `--run` flag.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::string::String;
#[cfg(feature = "std")]
use std::string::String;

#[cfg(target_os = "macos")]
pub mod block;
#[cfg(target_os = "macos")]
mod cf;
#[cfg(target_os = "macos")]
pub mod device;
#[cfg(target_os = "macos")]
pub mod ffi;
pub mod la;

/// FIDO usage page (HID Usage Tables, FIDO Alliance page).
pub const FIDO_USAGE_PAGE: u16 = 0xf1d0;
/// CTAPHID usage on the FIDO page.
pub const FIDO_USAGE_CTAPHID: u16 = 0x01;
/// Input and output report size in bytes.
pub const REPORT_SIZE: usize = 64;

/// HID report descriptor for a CTAPHID device: one application collection on
/// the FIDO page with a 64-byte input report (usage 0x20) and a 64-byte output
/// report (usage 0x21), no report IDs. Browsers find security keys by this
/// usage page and usage.
pub const REPORT_DESCRIPTOR: [u8; 34] = [
    0x06, 0xd0, 0xf1, // Usage Page (FIDO)
    0x09, 0x01, // Usage (CTAPHID)
    0xa1, 0x01, // Collection (Application)
    0x09, 0x20, //   Usage (Input Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xff, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x40, //   Report Count (64)
    0x81, 0x02, //   Input (Data, Var, Abs)
    0x09, 0x21, //   Usage (Output Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xff, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x40, //   Report Count (64)
    0x91, 0x02, //   Output (Data, Var, Abs)
    0xc0, // End Collection
];

/// Identity the virtual device presents.
///
/// VendorID/ProductID are our own placeholders, not USB-IF assignments. The
/// transport is Virtual (IOHIDKeys.h `kIOHIDTransportVirtualValue`); browsers
/// match on usage page 0xF1D0, not on these numbers. Replace them if you ever
/// register real IDs. Do not copy another vendor's IDs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub vendor_id: u32,
    pub product_id: u32,
    pub product: &'static str,
    pub manufacturer: &'static str,
    pub serial: &'static str,
    pub transport: &'static str,
}

/// Placeholder VID 0x1209 (pid.codes open domain), PID 0x51D0 (se-fido).
pub const DEFAULT_IDENTITY: DeviceIdentity = DeviceIdentity {
    vendor_id: 0x1209,
    product_id: 0x51d0,
    product: "se-fido",
    manufacturer: "se-fido",
    serial: "0",
    transport: "Virtual",
};

/// Property keys (IOHIDDeviceKeys.h).
pub mod keys {
    pub const REPORT_DESCRIPTOR: &str = "ReportDescriptor";
    pub const VENDOR_ID: &str = "VendorID";
    pub const PRODUCT_ID: &str = "ProductID";
    pub const PRODUCT: &str = "Product";
    pub const MANUFACTURER: &str = "Manufacturer";
    pub const SERIAL_NUMBER: &str = "SerialNumber";
    pub const TRANSPORT: &str = "Transport";
    pub const PRIMARY_USAGE_PAGE: &str = "PrimaryUsagePage";
    pub const PRIMARY_USAGE: &str = "PrimaryUsage";
    pub const MAX_INPUT_REPORT_SIZE: &str = "MaxInputReportSize";
    pub const MAX_OUTPUT_REPORT_SIZE: &str = "MaxOutputReportSize";
}

/// A property value before conversion to CoreFoundation types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PropValue {
    Number(u32),
    Text(&'static str),
    Data(&'static [u8]),
}

/// Property set for `IOHIDUserDeviceCreateWithProperties`.
pub fn properties(id: &DeviceIdentity) -> [(&'static str, PropValue); 11] {
    [
        (keys::REPORT_DESCRIPTOR, PropValue::Data(&REPORT_DESCRIPTOR)),
        (keys::VENDOR_ID, PropValue::Number(id.vendor_id)),
        (keys::PRODUCT_ID, PropValue::Number(id.product_id)),
        (keys::PRODUCT, PropValue::Text(id.product)),
        (keys::MANUFACTURER, PropValue::Text(id.manufacturer)),
        (keys::SERIAL_NUMBER, PropValue::Text(id.serial)),
        (keys::TRANSPORT, PropValue::Text(id.transport)),
        (
            keys::PRIMARY_USAGE_PAGE,
            PropValue::Number(FIDO_USAGE_PAGE as u32),
        ),
        (
            keys::PRIMARY_USAGE,
            PropValue::Number(FIDO_USAGE_CTAPHID as u32),
        ),
        (
            keys::MAX_INPUT_REPORT_SIZE,
            PropValue::Number(REPORT_SIZE as u32),
        ),
        (
            keys::MAX_OUTPUT_REPORT_SIZE,
            PropValue::Number(REPORT_SIZE as u32),
        ),
    ]
}

/// Stable text form of the property set (for fixtures).
pub fn properties_text(id: &DeviceIdentity) -> String {
    let mut s = String::new();
    for (k, v) in properties(id) {
        match v {
            PropValue::Number(n) => s.push_str(&format!("{k}=0x{n:04x}\n")),
            PropValue::Text(t) => s.push_str(&format!("{k}=\"{t}\"\n")),
            PropValue::Data(d) => {
                s.push_str(&format!("{k}=data[{}]=", d.len()));
                for b in d {
                    s.push_str(&format!("{b:02x}"));
                }
                s.push('\n');
            }
        }
    }
    s
}
