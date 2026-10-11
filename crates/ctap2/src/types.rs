use crate::bytes::{Bytes, Text};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

/// A stored credential. Every credential the authenticator creates is kept
/// in the store; `discoverable` marks resident ("rk") credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    /// Credential ID given to the relying party ([`CREDENTIAL_ID_LEN`] random bytes).
    pub id: Bytes,
    pub rp_id: Text,
    pub rp_name: Option<Text>,
    pub user_id: Bytes,
    pub user_name: Option<Text>,
    pub user_display_name: Option<Text>,
    /// Opaque backend reference to the private key.
    pub key_handle: Bytes,
    /// SEC1 uncompressed public key (65 bytes).
    pub public_key: Bytes,
    pub discoverable: bool,
    /// Creation order, larger is newer.
    pub created: u64,
}

pub const CREDENTIAL_ID_LEN: usize = 32;

#[derive(Debug, Clone)]
pub struct NewKey {
    pub handle: Bytes,
    pub public_key: p256::PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendError {
    KeyNotFound,
    Cancelled,
    Failed(String),
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackendError::KeyNotFound => f.write_str("key not found"),
            BackendError::Cancelled => f.write_str("cancelled by user"),
            BackendError::Failed(m) => write!(f, "backend failure: {m}"),
        }
    }
}

/// Creates and uses P-256 private keys; also the source of randomness.
pub trait Backend {
    fn random(&mut self, out: &mut [u8]);
    fn create_key(&mut self, rp_id: &str, user_id: &[u8]) -> Result<NewKey, BackendError>;
    /// ECDSA P-256 SHA-256 over `message` (the backend hashes), DER encoded.
    fn sign(&mut self, handle: &[u8], message: &[u8]) -> Result<Vec<u8>, BackendError>;
    fn delete_key(&mut self, handle: &[u8]) -> Result<(), BackendError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    Full,
    Io(String),
    Corrupt(String),
    CounterExhausted,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Full => f.write_str("store full"),
            StoreError::Io(m) => write!(f, "store I/O: {m}"),
            StoreError::Corrupt(m) => write!(f, "store corrupt or wrong key: {m}"),
            StoreError::CounterExhausted => f.write_str("signature counter exhausted"),
        }
    }
}

/// Credential index plus the global signature counter.
pub trait CredentialStore {
    fn get(&self, id: &[u8]) -> Result<Option<Arc<Credential>>, StoreError>;
    /// All credentials (discoverable or not) for an RP ID.
    fn list_rp(&self, rp_id: &str) -> Result<Vec<Arc<Credential>>, StoreError>;
    /// Insert or replace (same ID).
    fn insert(&mut self, cred: Arc<Credential>) -> Result<(), StoreError>;
    fn remove(&mut self, id: &[u8]) -> Result<Option<Arc<Credential>>, StoreError>;
    /// Remove everything and return it. The counter is not reset.
    fn clear(&mut self) -> Result<Vec<Arc<Credential>>, StoreError>;
    /// Increment, persist, return the new value. Never repeats a value.
    fn next_sign_count(&mut self) -> Result<u32, StoreError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresenceKind {
    MakeCredential,
    GetAssertion,
    /// excludeList matched; presence is collected before reporting it.
    Excluded,
    Reset,
    Selection,
    /// Zero-length pinUvAuthParam probe (platform choosing a device).
    Probe,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresenceRequest {
    pub kind: PresenceKind,
    pub rp_id: Option<Text>,
    pub user_name: Option<Text>,
    /// User verification (Touch ID) requested, not just presence.
    pub require_uv: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Presence {
    pub user_verified: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresenceError {
    Denied,
    Cancelled,
    Timeout,
    UvFailed,
}

/// Test of user presence, optionally with built-in user verification.
pub trait UserPresence {
    fn request(&mut self, req: &PresenceRequest) -> Result<Presence, PresenceError>;
}
