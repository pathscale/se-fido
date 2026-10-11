//! End-to-end harness without hardware: an in-memory CTAPHID host talking
//! to a [`ctaphid::Server`] in front of a [`ctap2::Authenticator`], and a
//! relying-party side verifier (WebAuthn registration and assertion checks
//! with independent p256 signature verification).

#![forbid(unsafe_code)]

pub mod host;
pub mod rp;

pub use host::{HidStats, Host};
