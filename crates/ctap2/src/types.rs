use thiserror::Error;

/// A stored credential. Every credential the authenticator creates is kept
/// in the store; `discoverable` marks resident ("rk") credentials, which can
/// be found without an allowList.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    /// Credential ID handed to the relying party (random, [`CREDENTIAL_ID_LEN`] bytes).
    pub id: Vec<u8>,
    pub rp_id: String,
    pub rp_name: Option<String>,
    pub user_id: Vec<u8>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    /// Opaque backend reference to the private key (e.g. a Secure Enclave
    /// key blob or keychain tag).
    pub key_handle: Vec<u8>,
    /// SEC1 uncompressed public key (65 bytes).
    pub public_key: Vec<u8>,
    pub discoverable: bool,
    /// Creation order (larger = newer). Used to return the most recent
    /// discoverable credential first.
    pub created: u64,
}

/// Length of generated credential IDs.
pub const CREDENTIAL_ID_LEN: usize = 32;

/// Result of creating a key in a backend.
#[derive(Debug, Clone)]
pub struct NewKey {
    pub handle: Vec<u8>,
    pub public_key: p256::PublicKey,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BackendError {
    #[error("key not found")]
    KeyNotFound,
    #[error("operation cancelled by user")]
    Cancelled,
    #[error("backend failure: {0}")]
    Failed(String),
}

/// Something that can create and use P-256 private keys.
pub trait Backend {
    /// Create a new P-256 key for this relying party / user.
    fn create_key(&mut self, rp_id: &str, user_id: &[u8]) -> Result<NewKey, BackendError>;
    /// ECDSA P-256 / SHA-256 signature over `message` (the backend hashes),
    /// returned DER-encoded as WebAuthn requires.
    fn sign(&mut self, handle: &[u8], message: &[u8]) -> Result<Vec<u8>, BackendError>;
    /// Destroy the key if the backend holds state for it.
    fn delete_key(&mut self, handle: &[u8]) -> Result<(), BackendError>;
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StoreError {
    #[error("store is full")]
    Full,
    #[error("store I/O error: {0}")]
    Io(String),
    #[error("store data corrupt or wrong key: {0}")]
    Corrupt(String),
    #[error("signature counter exhausted")]
    CounterExhausted,
}

/// Credential index plus the global signature counter.
pub trait CredentialStore {
    fn get(&self, id: &[u8]) -> Result<Option<Credential>, StoreError>;
    /// All credentials (discoverable or not) for this RP ID.
    fn list_rp(&self, rp_id: &str) -> Result<Vec<Credential>, StoreError>;
    fn insert(&mut self, cred: Credential) -> Result<(), StoreError>;
    fn remove(&mut self, id: &[u8]) -> Result<Option<Credential>, StoreError>;
    /// Remove every credential and return them (so keys can be destroyed).
    /// The signature counter is *not* reset, to keep it monotonic.
    fn clear(&mut self) -> Result<Vec<Credential>, StoreError>;
    /// Increment the global signature counter, persist it, and return the
    /// new value. Must never return the same value twice.
    fn next_sign_count(&mut self) -> Result<u32, StoreError>;
}

/// Why the authenticator is asking for the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresenceKind {
    MakeCredential,
    GetAssertion,
    /// excludeList matched; presence is collected before reporting it.
    Excluded,
    Reset,
    Selection,
    /// Zero-length pinUvAuthParam probe from a platform choosing a device.
    Probe,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresenceRequest {
    pub kind: PresenceKind,
    pub rp_id: Option<String>,
    pub user_name: Option<String>,
    /// The request asked for user verification (e.g. Touch ID), not just presence.
    pub require_uv: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Presence {
    /// User verification (biometric/passcode) was performed successfully.
    pub user_verified: bool,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum PresenceError {
    #[error("user denied")]
    Denied,
    #[error("cancelled")]
    Cancelled,
    #[error("timed out")]
    Timeout,
    #[error("user verification failed")]
    UvFailed,
}

/// Test of user presence (and optionally built-in user verification).
pub trait UserPresence {
    fn request(&mut self, req: &PresenceRequest) -> Result<Presence, PresenceError>;
}
