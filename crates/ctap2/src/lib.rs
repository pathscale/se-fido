//! CTAP 2 authenticator core, written from the public FIDO CTAP 2.1
//! specification and the W3C WebAuthn specification.
//!
//! The core is transport-agnostic: feed it the bytes of a CTAPHID_CBOR
//! request (command byte + CBOR parameters) with
//! [`Authenticator::process`] and send back the returned bytes (status byte +
//! optional CBOR response).
//!
//! Keys, user presence/verification and credential storage are abstracted
//! behind the [`Backend`], [`UserPresence`] and [`CredentialStore`] traits.
//! [`soft`] contains in-memory implementations for tests.

#![forbid(unsafe_code)]

pub mod authdata;
mod authenticator;
pub mod cbor;
pub mod soft;
mod status;
mod types;

pub use authenticator::{AttestationFormat, Authenticator, AuthenticatorConfig};
pub use status::Status;
pub use types::*;

/// Our authenticator model identifier (AAGUID), sent in every
/// attestedCredentialData and in authenticatorGetInfo.
///
/// `c7ce4e58-6fd2-4eb8-b193-1d528be838a5` was generated once, at random
/// (UUID version 4), for this project. It is **not** registered with the FIDO
/// Metadata Service and does not identify any certified product. If it ever
/// turns out to collide with another model, replace these 16 bytes with a new
/// random UUIDv4 (e.g. from `uuidgen`) — this constant is the only place it is
/// defined. Existing credentials keep working; relying parties that recorded
/// the old AAGUID will simply see a different model for new registrations.
/// Never put another vendor's AAGUID here.
pub const AAGUID: [u8; 16] = [
    0xc7, 0xce, 0x4e, 0x58, 0x6f, 0xd2, 0x4e, 0xb8, 0xb1, 0x93, 0x1d, 0x52, 0x8b, 0xe8, 0x38, 0xa5,
];

/// COSE algorithm identifier for ECDSA w/ SHA-256 on P-256 (ES256).
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
