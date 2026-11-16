//! Secure Enclave backend for the `ctap2` authenticator.
//!
//! All Apple calls go through hand-written `extern "C"` declarations in
//! [`ffi`] linked against Security.framework and CoreFoundation.framework.
//! No Swift, Objective-C, CryptoKit, `-sys` crates or wrapper crates.
//!
//! Storage modes:
//! * [`StorageMode::Blob`]: non-permanent Secure Enclave key; its
//!   SE-encrypted token object (undocumented `toid` attribute) is kept by us
//!   and reloaded with `SecKeyCreateWithData`. No entitlement needed, so it is
//!   the durable mode for ad-hoc signed builds.
//! * [`StorageMode::Keychain`]: permanent data-protection keychain item by
//!   application tag. Needs a keychain-access-groups entitlement; fails with
//!   -34018 for ad-hoc signed binaries. Opt-in.
//!
//! A data directory belongs to one mode: [`storage_key`] refuses a directory
//! written in the other mode, and there is no migration between them.
//!
//! Results per macOS version are recorded in PLAN.md.

#[cfg(target_os = "macos")]
pub mod ffi;
#[cfg(target_os = "macos")]
mod se;
#[cfg(target_os = "macos")]
pub use se::*;
