//! CTAP 2 authenticator core from the FIDO CTAP 2.1 and W3C WebAuthn
//! specifications.
//!
//! Transport agnostic: [`Authenticator::process`] takes a CTAPHID_CBOR
//! request (command byte + CBOR parameters) as an [`Bytes`] view of an
//! `Arc<[u8]>` and returns status byte + optional CBOR. Parsing is zero copy:
//! byte and text strings in requests and stored credentials are ranges into
//! shared buffers.
//!
//! Keys, user presence and storage are behind [`Backend`], [`UserPresence`]
//! and [`CredentialStore`]. [`soft`] has deterministic in-memory versions
//! used by the fixtures.
//!
//! `no_std` + `alloc`.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod authdata;
mod authenticator;
mod bytes;
pub mod cbor;
pub mod der;
pub mod entropy;
pub mod soft;
mod status;
mod types;

pub use authenticator::{
    AttestationFormat, Authenticator, AuthenticatorConfig, NEXT_ASSERTION_TIMEOUT_MS,
};
pub use bytes::{hex, Bytes, Text};
pub use entropy::{Entropy, TestDrbg};
pub use status::Status;
pub use types::*;

/// Our authenticator model identifier (AAGUID), sent in attestedCredentialData
/// and authenticatorGetInfo.
///
/// `c7ce4e58-6fd2-4eb8-b193-1d528be838a5`, generated once at random (UUIDv4)
/// for this project. Not registered with the FIDO Metadata Service and not a
/// certified product. If it ever collides with another model, replace these
/// 16 bytes with a fresh `uuidgen` value; this is the only definition.
/// Existing credentials keep working. Never use another vendor AAGUID here.
pub const AAGUID: [u8; 16] = [
    0xc7, 0xce, 0x4e, 0x58, 0x6f, 0xd2, 0x4e, 0xb8, 0xb1, 0x93, 0x1d, 0x52, 0x8b, 0xe8, 0x38, 0xa5,
];

/// COSE algorithm ES256 (ECDSA P-256 SHA-256).
pub const COSE_ALG_ES256: i64 = -7;

/// CTAP command bytes.
pub mod command {
    pub const MAKE_CREDENTIAL: u8 = 0x01;
    pub const GET_ASSERTION: u8 = 0x02;
    pub const GET_INFO: u8 = 0x04;
    pub const CLIENT_PIN: u8 = 0x06;
    pub const RESET: u8 = 0x07;
    pub const GET_NEXT_ASSERTION: u8 = 0x08;
    pub const SELECTION: u8 = 0x0b;
}
