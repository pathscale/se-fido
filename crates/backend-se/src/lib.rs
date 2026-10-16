//! Secure Enclave backend for the `ctap2` authenticator.
//!
//! All Apple calls go through hand-written `extern "C"` declarations in
//! [`ffi`] linked against Security.framework and CoreFoundation.framework.
//! No Swift, Objective-C, CryptoKit, `-sys` crates or wrapper crates.
//!
//! Storage modes:
//! * [`StorageMode::Blob`]: in-memory probe mode. Its token object blob can
//!   appear in a credential handle, so do not use it for durable credentials.
//! * [`StorageMode::Keychain`]: permanent data-protection keychain item by
//!   application tag. Needs a keychain-access-groups entitlement; fails with
//!   -34018 for ad-hoc signed binaries.
//!
//! Results per macOS version are recorded in PLAN.md.
//!
//! Durable credential storage must use [`StorageMode::Keychain`]. Blob mode is
//! for in-memory probing only.

#[cfg(target_os = "macos")]
pub mod ffi;
#[cfg(target_os = "macos")]
mod se;
#[cfg(target_os = "macos")]
pub use se::*;
