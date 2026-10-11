//! Hand-written declarations for the IOKit user-space HID device API
//! (IOKit/hid/IOHIDUserDevice.h, macOS 10.15+) and the libdispatch calls it
//! needs. Declared only; nothing calls them yet. Signatures must be checked
//! against the SDK header before first use (M4).
//!
//! Creating a device needs the com.apple.developer.hid.virtual.device
//! entitlement, or a system where the user has relaxed SIP/AMFI. See
//! DESIGN.md.
//!
//! The report callbacks take Objective-C blocks. Blocks are plain C structs
//! (Block_layout: isa, flags, reserved, invoke, descriptor); M4 builds them in
//! Rust against _NSConcreteGlobalBlock / _NSConcreteStackBlock from
//! libSystem, so no Objective-C or C source is involved.

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

use core::ffi::{c_char, c_void};

pub type CFAllocatorRef = *const c_void;
pub type CFDictionaryRef = *const c_void;
pub type CFIndex = isize;
pub type CFTypeID = usize;
pub type IOOptionBits = u32;
pub type IOReturn = i32;
pub type IOHIDReportType = u32;
pub type IOHIDUserDeviceRef = *const c_void;
pub type DispatchQueue = *const c_void;
/// Pointer to a Block_layout; see the module docs.
pub type BlockPtr = *const c_void;

pub const kIOHIDReportTypeInput: IOHIDReportType = 0;
pub const kIOHIDReportTypeOutput: IOHIDReportType = 1;
pub const kIOHIDReportTypeFeature: IOHIDReportType = 2;
pub const kIOReturnSuccess: IOReturn = 0;

#[link(name = "IOKit", kind = "framework")]
extern "C" {
    pub fn IOHIDUserDeviceGetTypeID() -> CFTypeID;
    pub fn IOHIDUserDeviceCreateWithProperties(
        allocator: CFAllocatorRef,
        properties: CFDictionaryRef,
        options: IOOptionBits,
    ) -> IOHIDUserDeviceRef;
    pub fn IOHIDUserDeviceSetDispatchQueue(device: IOHIDUserDeviceRef, queue: DispatchQueue);
    pub fn IOHIDUserDeviceSetCancelHandler(device: IOHIDUserDeviceRef, handler: BlockPtr);
    /// Block type: IOReturn (^)(IOHIDReportType type, uint32_t reportID,
    /// const uint8_t *report, CFIndex reportLength).
    pub fn IOHIDUserDeviceRegisterSetReportBlock(device: IOHIDUserDeviceRef, block: BlockPtr);
    pub fn IOHIDUserDeviceActivate(device: IOHIDUserDeviceRef);
    pub fn IOHIDUserDeviceCancel(device: IOHIDUserDeviceRef);
    pub fn IOHIDUserDeviceHandleReportWithTimeStamp(
        device: IOHIDUserDeviceRef,
        timestamp: u64,
        report: *const u8,
        report_length: CFIndex,
    ) -> IOReturn;
}

extern "C" {
    pub fn dispatch_queue_create(label: *const c_char, attr: *const c_void) -> DispatchQueue;
    pub fn dispatch_release(object: *const c_void);
    pub fn mach_absolute_time() -> u64;
    pub static _NSConcreteGlobalBlock: [*const c_void; 32];
    pub static _NSConcreteStackBlock: [*const c_void; 32];
}
