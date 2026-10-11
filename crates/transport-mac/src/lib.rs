//! macOS transport skeleton. See DESIGN.md.
//!
//! Holds the pieces that do not depend on how the virtual device gets
//! created: the FIDO HID report descriptor and the device property set.
//! [`ffi`] declares the IOKit user-space HID device API by hand. Nothing in
//! this crate creates a device or calls into IOKit yet.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(target_os = "macos")]
pub mod ffi;

/// FIDO usage page (HID Usage Tables, FIDO Alliance page).
pub const FIDO_USAGE_PAGE: u16 = 0xf1d0;
/// CTAPHID usage on the FIDO page.
pub const FIDO_USAGE_CTAPHID: u16 = 0x01;
/// Input and output report size in bytes.
pub const REPORT_SIZE: usize = 64;

/// HID report descriptor for a CTAPHID device: one application collection
/// on the FIDO page with a 64-byte input report (usage 0x20) and a 64-byte
/// output report (usage 0x21), no report IDs. Browsers find security keys by
/// this usage page and usage.
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

/// Identity the virtual device presents. Vendor and product IDs are 0:
/// browsers match on the usage page, and we must not claim a USB vendor ID
/// we do not own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub vendor_id: u32,
    pub product_id: u32,
    pub product: &'static str,
    pub manufacturer: &'static str,
    pub serial: &'static str,
    pub transport: &'static str,
}

pub const DEFAULT_IDENTITY: DeviceIdentity = DeviceIdentity {
    vendor_id: 0,
    product_id: 0,
    product: "se-fido",
    manufacturer: "se-fido",
    serial: "0",
    transport: "Virtual",
};

/// Property keys of the IOHIDUserDevice property dictionary (IOHIDKeys.h).
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

/// The property set passed to IOHIDUserDeviceCreateWithProperties, as plain
/// data. Converting it to a CFDictionary happens in the M4 device code.
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
