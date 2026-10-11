//! Minimal hand-written bindings to Security.framework (C API, macOS 10.12+).
//! Declarations follow Apple's public headers (SecKey.h, SecItem.h,
//! SecAccessControl.h).

#![allow(non_upper_case_globals, non_snake_case)]

use core_foundation_sys::base::{CFAllocatorRef, CFOptionFlags, CFTypeRef, OSStatus};
use core_foundation_sys::data::CFDataRef;
use core_foundation_sys::dictionary::CFDictionaryRef;
use core_foundation_sys::error::CFErrorRef;
use core_foundation_sys::string::CFStringRef;
use std::ffi::c_void;

/// `SecKeyRef` (opaque CF type).
pub type SecKeyRef = *mut c_void;
/// `SecAccessControlRef` (opaque CF type).
pub type SecAccessControlRef = *mut c_void;
/// `SecKeyAlgorithm` is a `CFStringRef`.
pub type SecKeyAlgorithm = CFStringRef;

// SecAccessControlCreateFlags (SecAccessControl.h).
pub const kSecAccessControlUserPresence: CFOptionFlags = 1 << 0;
pub const kSecAccessControlBiometryAny: CFOptionFlags = 1 << 1;
pub const kSecAccessControlBiometryCurrentSet: CFOptionFlags = 1 << 3;
pub const kSecAccessControlDevicePasscode: CFOptionFlags = 1 << 4;
pub const kSecAccessControlPrivateKeyUsage: CFOptionFlags = 1 << 30;

// Selected OSStatus values (SecBase.h).
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
}
