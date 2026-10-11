//! Secure Enclave backend for the `ctap2` authenticator.
//!
//! Talks to Apple's Security.framework through a small hand-written C FFI
//! ([`ffi`]); no Swift, Objective-C, CryptoKit or wrapper crates. Only the
//! CoreFoundation crates (MIT/Apache-2.0) are used for CF object lifetimes.
//!
//! Two storage modes:
//! * [`StorageMode::Blob`]: a non-permanent Secure Enclave key whose
//!   SE-encrypted "token object" blob (the undocumented `toid` attribute) is
//!   stored by us and reloaded with `SecKeyCreateWithData`. Needs no
//!   keychain entitlement.
//! * [`StorageMode::Keychain`]: a permanent keychain item found by
//!   application tag. Needs a keychain-access-groups entitlement in the
//!   data-protection keychain, so it fails for unsigned/ad-hoc binaries.
//!
//! See `PLAN.md` for which mode was verified to work on which setup.

#[cfg(target_os = "macos")]
pub mod ffi;
#[cfg(target_os = "macos")]
mod se;
#[cfg(target_os = "macos")]
pub use se::*;
