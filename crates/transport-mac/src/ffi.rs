//! Hand-written declarations for IOKit user-space HID devices, libdispatch
//! and the Block runtime. Signatures checked against the macOS 26.2 SDK.
//!
//! Header paths (Xcode SDK):
//! * IOKit.framework/Headers/hidsystem/IOHIDUserDevice.h
//! * IOKit.framework/Headers/hid/IOHIDDeviceKeys.h
//! * IOKit.framework/Headers/hid/IOHIDDeviceTypes.h
//! * IOKit.framework/Headers/hid/IOHIDKeys.h
//! * IOKit.framework/Headers/IOReturn.h
//! * usr/include/Block.h
//! * usr/include/dispatch/queue.h, source.h, time.h, object.h
//!
//! Line citations are in DESIGN.md.

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

use core::ffi::{c_char, c_void};

pub type CFAllocatorRef = *const c_void;
pub type CFDictionaryRef = *const c_void;
pub type CFStringRef = *const c_void;
pub type CFTypeRef = *const c_void;
pub type CFTypeID = usize;
pub type CFIndex = isize;
pub type CFDataRef = *const c_void;
pub type CFNumberRef = *const c_void;
pub type Boolean = u8;
pub type CFStringEncoding = u32;
pub type CFNumberType = isize;

pub type IOOptionBits = u32;
pub type IOReturn = i32;
pub type IOHIDReportType = u32;
pub type IOHIDUserDeviceRef = *mut c_void;

pub type DispatchQueue = *mut c_void;
pub type DispatchSource = *mut c_void;
pub type DispatchSourceType = *const c_void;
pub type DispatchTime = u64;
pub type DispatchObject = *mut c_void;
pub type DispatchFunction = Option<unsafe extern "C" fn(*mut c_void)>;

/// Opaque Block pointer (void (^)(...)).
pub type BlockPtr = *mut c_void;

pub const kCFStringEncodingUTF8: CFStringEncoding = 0x0800_0100;
pub const kCFNumberSInt32Type: CFNumberType = 3;

/// IOHIDDeviceTypes.h:45-48
pub const kIOHIDReportTypeInput: IOHIDReportType = 0;
pub const kIOHIDReportTypeOutput: IOHIDReportType = 1;
pub const kIOHIDReportTypeFeature: IOHIDReportType = 2;

/// IOReturn.h: kIOReturnSuccess = KERN_SUCCESS
pub const kIOReturnSuccess: IOReturn = 0;
/// IOReturn.h:109 iokit_common_err(0x2c7) = 0xe00002c7
pub const kIOReturnUnsupported: IOReturn = 0xe000_02c7u32 as i32;
/// IOReturn.h:102 iokit_common_err(0x2c2)
pub const kIOReturnBadArgument: IOReturn = 0xe000_02c2u32 as i32;
/// IOReturn.h:101 iokit_common_err(0x2c1)
pub const kIOReturnNotPrivileged: IOReturn = 0xe000_02c1u32 as i32;
/// IOReturn.h:96 iokit_common_err(0x2bc)
pub const kIOReturnError: IOReturn = 0xe000_02bcu32 as i32;

/// IOHIDUserDevice.h:99-101
pub const IOHIDUserDeviceOptionsCreateOnActivate: IOOptionBits = 1 << 0;

/// dispatch/time.h
pub const DISPATCH_TIME_NOW: DispatchTime = 0;
pub const NSEC_PER_MSEC: u64 = 1_000_000;

#[repr(C)]
pub struct CFDictionaryKeyCallBacks {
    pub version: CFIndex,
    pub retain: *const c_void,
    pub release: *const c_void,
    pub copyDescription: *const c_void,
    pub equal: *const c_void,
    pub hash: *const c_void,
}

#[repr(C)]
pub struct CFDictionaryValueCallBacks {
    pub version: CFIndex,
    pub retain: *const c_void,
    pub release: *const c_void,
    pub copyDescription: *const c_void,
    pub equal: *const c_void,
}

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    pub fn CFRelease(cf: CFTypeRef);
    pub fn CFRetain(cf: CFTypeRef) -> CFTypeRef;
    pub fn CFGetTypeID(cf: CFTypeRef) -> CFTypeID;
    pub fn CFDataCreate(allocator: CFAllocatorRef, bytes: *const u8, length: CFIndex) -> CFDataRef;
    pub fn CFDataGetLength(data: CFDataRef) -> CFIndex;
    pub fn CFDataGetBytePtr(data: CFDataRef) -> *const u8;
    pub fn CFStringCreateWithBytes(
        allocator: CFAllocatorRef,
        bytes: *const u8,
        numBytes: CFIndex,
        encoding: CFStringEncoding,
        isExternalRepresentation: Boolean,
    ) -> CFStringRef;
    pub fn CFNumberCreate(
        allocator: CFAllocatorRef,
        theType: CFNumberType,
        valuePtr: *const c_void,
    ) -> CFNumberRef;
    pub fn CFDictionaryCreate(
        allocator: CFAllocatorRef,
        keys: *const *const c_void,
        values: *const *const c_void,
        numValues: CFIndex,
        keyCallBacks: *const CFDictionaryKeyCallBacks,
        valueCallBacks: *const CFDictionaryValueCallBacks,
    ) -> CFDictionaryRef;
    pub static kCFTypeDictionaryKeyCallBacks: CFDictionaryKeyCallBacks;
    pub static kCFTypeDictionaryValueCallBacks: CFDictionaryValueCallBacks;
}

#[link(name = "IOKit", kind = "framework")]
extern "C" {
    /// IOHIDUserDevice.h:109-110
    pub fn IOHIDUserDeviceGetTypeID() -> CFTypeID;
    /// IOHIDUserDevice.h:138-143
    pub fn IOHIDUserDeviceCreateWithProperties(
        allocator: CFAllocatorRef,
        properties: CFDictionaryRef,
        options: IOOptionBits,
    ) -> IOHIDUserDeviceRef;
    /// IOHIDUserDevice.h:162-165
    pub fn IOHIDUserDeviceRegisterGetReportBlock(device: IOHIDUserDeviceRef, block: BlockPtr);
    /// IOHIDUserDevice.h:184-187
    pub fn IOHIDUserDeviceRegisterSetReportBlock(device: IOHIDUserDeviceRef, block: BlockPtr);
    /// IOHIDUserDevice.h:210-213
    pub fn IOHIDUserDeviceSetDispatchQueue(device: IOHIDUserDeviceRef, queue: DispatchQueue);
    /// IOHIDUserDevice.h:244-247
    pub fn IOHIDUserDeviceSetCancelHandler(device: IOHIDUserDeviceRef, handler: BlockPtr);
    /// IOHIDUserDevice.h:272-274
    pub fn IOHIDUserDeviceActivate(device: IOHIDUserDeviceRef);
    /// IOHIDUserDevice.h:307-309
    pub fn IOHIDUserDeviceCancel(device: IOHIDUserDeviceRef);
    /// IOHIDUserDevice.h:370-375
    pub fn IOHIDUserDeviceHandleReportWithTimeStamp(
        device: IOHIDUserDeviceRef,
        timestamp: u64,
        report: *const u8,
        report_length: CFIndex,
    ) -> IOReturn;
}

extern "C" {
    pub fn mach_absolute_time() -> u64;

    /// Block.h:31,34,43,44
    pub fn _Block_copy(block: *const c_void) -> *mut c_void;
    pub fn _Block_release(block: *const c_void);
    pub static _NSConcreteGlobalBlock: [*mut c_void; 32];
    pub static _NSConcreteStackBlock: [*mut c_void; 32];

    /// dispatch/queue.h:1091,1249
    pub fn dispatch_queue_create(label: *const c_char, attr: *const c_void) -> DispatchQueue;
    pub fn dispatch_main() -> !;
    /// dispatch/queue.h:270
    pub fn dispatch_async_f(queue: DispatchQueue, context: *mut c_void, work: DispatchFunction);
    /// dispatch/object.h
    pub fn dispatch_resume(object: DispatchObject);
    pub fn dispatch_suspend(object: DispatchObject);
    pub fn dispatch_release(object: DispatchObject);
    pub fn dispatch_retain(object: DispatchObject);
    pub fn dispatch_set_context(object: DispatchObject, context: *mut c_void);
    pub fn dispatch_get_context(object: DispatchObject) -> *mut c_void;
    /// dispatch/source.h
    pub fn dispatch_source_create(
        type_: DispatchSourceType,
        handle: usize,
        mask: usize,
        queue: DispatchQueue,
    ) -> DispatchSource;
    pub fn dispatch_source_set_timer(
        source: DispatchSource,
        start: DispatchTime,
        interval: u64,
        leeway: u64,
    );
    pub fn dispatch_source_set_event_handler_f(source: DispatchSource, handler: DispatchFunction);
    pub fn dispatch_source_cancel(source: DispatchSource);
    pub static _dispatch_source_type_timer: u8;
    /// dispatch/time.h:110
    pub fn dispatch_time(when: DispatchTime, delta: i64) -> DispatchTime;
}

/// Address of DISPATCH_SOURCE_TYPE_TIMER.
///
/// # Safety
/// Caller must only pass the returned pointer to `dispatch_source_create`.
#[inline]
pub unsafe fn dispatch_source_type_timer() -> DispatchSourceType {
    &_dispatch_source_type_timer as *const u8 as DispatchSourceType
}
