//! Hand-written bindings to the C APIs of CoreFoundation and Security
//! (CFBase.h, CFData.h, CFString.h, CFNumber.h, CFDictionary.h, CFError.h,
//! SecKey.h, SecItem.h, SecAccessControl.h, SecRandom.h).

#![allow(non_upper_case_globals, non_snake_case)]

use std::ffi::{c_char, c_int, c_void};

pub type CFTypeRef = *const c_void;
pub type CFAllocatorRef = *const c_void;
pub type CFDataRef = *const c_void;
pub type CFStringRef = *const c_void;
pub type CFNumberRef = *const c_void;
pub type CFBooleanRef = *const c_void;
pub type CFDictionaryRef = *const c_void;
pub type CFErrorRef = *const c_void;
pub type CFIndex = isize;
pub type CFTypeID = usize;
pub type CFOptionFlags = usize;
pub type CFStringEncoding = u32;
pub type Boolean = u8;
pub type OSStatus = i32;

pub type SecKeyRef = *const c_void;
pub type SecAccessControlRef = *const c_void;
pub type SecKeyAlgorithm = CFStringRef;

pub const kCFStringEncodingUTF8: CFStringEncoding = 0x0800_0100;
pub const kCFNumberSInt32Type: CFIndex = 3;

#[repr(C)]
pub struct CFDictionaryKeyCallBacks {
    pub version: CFIndex,
    pub retain: *const c_void,
    pub release: *const c_void,
    pub copy_description: *const c_void,
    pub equal: *const c_void,
    pub hash: *const c_void,
}

#[repr(C)]
pub struct CFDictionaryValueCallBacks {
    pub version: CFIndex,
    pub retain: *const c_void,
    pub release: *const c_void,
    pub copy_description: *const c_void,
    pub equal: *const c_void,
}

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    pub static kCFBooleanTrue: CFBooleanRef;
    pub static kCFBooleanFalse: CFBooleanRef;
    pub static kCFTypeDictionaryKeyCallBacks: CFDictionaryKeyCallBacks;
    pub static kCFTypeDictionaryValueCallBacks: CFDictionaryValueCallBacks;

    pub fn CFRelease(cf: CFTypeRef);
    pub fn CFGetTypeID(cf: CFTypeRef) -> CFTypeID;
    pub fn CFCopyDescription(cf: CFTypeRef) -> CFStringRef;
    pub fn CFDataGetTypeID() -> CFTypeID;
    pub fn CFStringGetTypeID() -> CFTypeID;
    pub fn CFDataCreate(allocator: CFAllocatorRef, bytes: *const u8, length: CFIndex) -> CFDataRef;
    pub fn CFDataGetLength(data: CFDataRef) -> CFIndex;
    pub fn CFDataGetBytePtr(data: CFDataRef) -> *const u8;
    pub fn CFStringCreateWithBytes(
        allocator: CFAllocatorRef,
        bytes: *const u8,
        num_bytes: CFIndex,
        encoding: CFStringEncoding,
        is_external_representation: Boolean,
    ) -> CFStringRef;
    pub fn CFStringGetCString(
        s: CFStringRef,
        buffer: *mut c_char,
        buffer_size: CFIndex,
        encoding: CFStringEncoding,
    ) -> Boolean;
    pub fn CFNumberCreate(
        allocator: CFAllocatorRef,
        the_type: CFIndex,
        value_ptr: *const c_void,
    ) -> CFNumberRef;
    pub fn CFDictionaryCreate(
        allocator: CFAllocatorRef,
        keys: *const *const c_void,
        values: *const *const c_void,
        num_values: CFIndex,
        key_callbacks: *const CFDictionaryKeyCallBacks,
        value_callbacks: *const CFDictionaryValueCallBacks,
    ) -> CFDictionaryRef;
    pub fn CFDictionaryGetValue(d: CFDictionaryRef, key: *const c_void) -> *const c_void;
    pub fn CFDictionaryGetCount(d: CFDictionaryRef) -> CFIndex;
    pub fn CFDictionaryGetKeysAndValues(
        d: CFDictionaryRef,
        keys: *mut *const c_void,
        values: *mut *const c_void,
    );
    pub fn CFErrorGetCode(err: CFErrorRef) -> CFIndex;
    pub fn CFErrorGetDomain(err: CFErrorRef) -> CFStringRef;
    pub fn CFErrorCopyDescription(err: CFErrorRef) -> CFStringRef;
}

// SecAccessControlCreateFlags.
pub const kSecAccessControlUserPresence: CFOptionFlags = 1 << 0;
pub const kSecAccessControlBiometryAny: CFOptionFlags = 1 << 1;
pub const kSecAccessControlBiometryCurrentSet: CFOptionFlags = 1 << 3;
pub const kSecAccessControlDevicePasscode: CFOptionFlags = 1 << 4;
pub const kSecAccessControlPrivateKeyUsage: CFOptionFlags = 1 << 30;

pub const errSecSuccess: OSStatus = 0;
pub const errSecItemNotFound: OSStatus = -25300;
pub const errSecMissingEntitlement: OSStatus = -34018;

#[link(name = "Security", kind = "framework")]
extern "C" {
    pub static kSecAttrKeyType: CFStringRef;
    pub static kSecAttrKeyTypeECSECPrimeRandom: CFStringRef;
    pub static kSecAttrKeySizeInBits: CFStringRef;
    pub static kSecAttrKeyClass: CFStringRef;
    pub static kSecAttrKeyClassPrivate: CFStringRef;
    pub static kSecAttrKeyClassPublic: CFStringRef;
    pub static kSecAttrTokenID: CFStringRef;
    pub static kSecAttrTokenIDSecureEnclave: CFStringRef;
    pub static kSecPrivateKeyAttrs: CFStringRef;
    pub static kSecAttrIsPermanent: CFStringRef;
    pub static kSecAttrApplicationTag: CFStringRef;
    pub static kSecAttrLabel: CFStringRef;
    pub static kSecAttrAccessControl: CFStringRef;
    pub static kSecAttrAccessibleWhenUnlockedThisDeviceOnly: CFStringRef;
    pub static kSecClass: CFStringRef;
    pub static kSecClassKey: CFStringRef;
    pub static kSecReturnRef: CFStringRef;
    pub static kSecMatchLimit: CFStringRef;
    pub static kSecMatchLimitOne: CFStringRef;
    pub static kSecUseDataProtectionKeychain: CFStringRef;
    pub static kSecKeyAlgorithmECDSASignatureMessageX962SHA256: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDHKeyExchangeStandard: SecKeyAlgorithm;

    pub fn SecAccessControlCreateWithFlags(
        allocator: CFAllocatorRef,
        protection: CFTypeRef,
        flags: CFOptionFlags,
        error: *mut CFErrorRef,
    ) -> SecAccessControlRef;
    pub fn SecKeyCreateRandomKey(parameters: CFDictionaryRef, error: *mut CFErrorRef) -> SecKeyRef;
    pub fn SecKeyCreateWithData(
        key_data: CFDataRef,
        attributes: CFDictionaryRef,
        error: *mut CFErrorRef,
    ) -> SecKeyRef;
    pub fn SecKeyCopyPublicKey(key: SecKeyRef) -> SecKeyRef;
    pub fn SecKeyCopyExternalRepresentation(key: SecKeyRef, error: *mut CFErrorRef) -> CFDataRef;
    pub fn SecKeyCopyAttributes(key: SecKeyRef) -> CFDictionaryRef;
    pub fn SecKeyCreateSignature(
        key: SecKeyRef,
        algorithm: SecKeyAlgorithm,
        data_to_sign: CFDataRef,
        error: *mut CFErrorRef,
    ) -> CFDataRef;
    pub fn SecKeyCopyKeyExchangeResult(
        private_key: SecKeyRef,
        algorithm: SecKeyAlgorithm,
        public_key: SecKeyRef,
        parameters: CFDictionaryRef,
        error: *mut CFErrorRef,
    ) -> CFDataRef;
    pub fn SecItemCopyMatching(query: CFDictionaryRef, result: *mut CFTypeRef) -> OSStatus;
    pub fn SecItemDelete(query: CFDictionaryRef) -> OSStatus;
    pub fn SecRandomCopyBytes(rnd: *const c_void, count: usize, bytes: *mut c_void) -> c_int;
}
