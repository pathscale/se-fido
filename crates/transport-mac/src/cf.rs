//! Minimal CoreFoundation helpers for the property dictionary.

use crate::ffi::*;
use core::ffi::c_void;
use core::ptr::null;

pub struct Cf(CFTypeRef);

impl Cf {
    pub fn create(p: CFTypeRef) -> Option<Cf> {
        if p.is_null() {
            None
        } else {
            Some(Cf(p))
        }
    }

    pub fn ptr(&self) -> CFTypeRef {
        self.0
    }

    pub fn as_dict(&self) -> CFDictionaryRef {
        self.0 as CFDictionaryRef
    }
}

impl Drop for Cf {
    fn drop(&mut self) {
        unsafe { CFRelease(self.0) };
    }
}

pub fn cf_data(b: &[u8]) -> Cf {
    Cf::create(unsafe { CFDataCreate(null(), b.as_ptr(), b.len() as CFIndex) })
        .expect("CFDataCreate")
}

pub fn cf_str(s: &str) -> Cf {
    Cf::create(unsafe {
        CFStringCreateWithBytes(
            null(),
            s.as_ptr(),
            s.len() as CFIndex,
            kCFStringEncodingUTF8,
            0,
        )
    })
    .expect("CFStringCreateWithBytes")
}

pub fn cf_u32(v: u32) -> Cf {
    let v = v as i32;
    Cf::create(unsafe {
        CFNumberCreate(
            null(),
            kCFNumberSInt32Type,
            &v as *const i32 as *const c_void,
        )
    })
    .expect("CFNumberCreate")
}

/// Build a CFDictionary from (key, value) CF objects. Retains keys and values.
pub fn cf_dict(pairs: &[(CFTypeRef, CFTypeRef)]) -> Cf {
    let keys: Vec<*const c_void> = pairs.iter().map(|p| p.0).collect();
    let values: Vec<*const c_void> = pairs.iter().map(|p| p.1).collect();
    Cf::create(unsafe {
        CFDictionaryCreate(
            null(),
            keys.as_ptr(),
            values.as_ptr(),
            pairs.len() as CFIndex,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks,
        )
    })
    .expect("CFDictionaryCreate")
}
