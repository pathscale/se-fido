//! Deterministic in-memory implementations for fixtures and tools. Not for
//! real use: keys come from the supplied entropy and vanish with the process.

use crate::bytes::Bytes;
use crate::der;
use crate::entropy::Entropy;
use crate::types::*;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};

/// Software P-256 keys. Signatures are RFC 6979 deterministic, so with a
/// deterministic [`Entropy`] every output is reproducible.
pub struct SoftBackend<E> {
    entropy: E,
    keys: BTreeMap<Vec<u8>, SigningKey>,
}

impl<E: Entropy> SoftBackend<E> {
    pub fn new(entropy: E) -> Self {
        SoftBackend {
            entropy,
            keys: BTreeMap::new(),
        }
    }

    pub fn key_count(&self) -> usize {
        self.keys.len()
    }
}

impl<E: Entropy> Backend for SoftBackend<E> {
    fn random(&mut self, out: &mut [u8]) {
        self.entropy.fill(out);
    }

    fn create_key(
        &mut self,
        _rp_id: &str,
        _user_id: &[u8],
        _uv: UvPolicy,
    ) -> Result<NewKey, BackendError> {
        let sk = loop {
            let mut b = [0u8; 32];
            self.entropy.fill(&mut b);
            if let Ok(sk) = SigningKey::from_slice(&b) {
                break sk;
            }
        };
        let mut handle = [0u8; 16];
        self.entropy.fill(&mut handle);
        let public_key = p256::PublicKey::from(sk.verifying_key());
        self.keys.insert(handle.to_vec(), sk);
        Ok(NewKey {
            handle: Bytes::copy_from_slice(&handle),
            public_key,
        })
    }

    fn sign(&mut self, handle: &[u8], message: &[u8]) -> Result<Vec<u8>, BackendError> {
        let sk = self.keys.get(handle).ok_or(BackendError::KeyNotFound)?;
        let sig: Signature = sk.sign(message);
        Ok(der::encode(&sig))
    }

    fn delete_key(&mut self, handle: &[u8]) -> Result<(), BackendError> {
        self.keys.remove(handle);
        Ok(())
    }
}

/// Credential store in memory.
#[derive(Default, Debug)]
pub struct MemoryStore {
    creds: Vec<Arc<Credential>>,
    counter: u32,
    capacity: Option<usize>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity_limit(n: usize) -> Self {
        MemoryStore {
            capacity: Some(n),
            ..Default::default()
        }
    }

    pub fn len(&self) -> usize {
        self.creds.len()
    }

    pub fn is_empty(&self) -> bool {
        self.creds.is_empty()
    }

    pub fn counter(&self) -> u32 {
        self.counter
    }
}

impl CredentialStore for MemoryStore {
    fn get(&self, id: &[u8]) -> Result<Option<Arc<Credential>>, StoreError> {
        Ok(self.creds.iter().find(|c| *c.id == *id).cloned())
    }

    fn list_rp(&self, rp_id: &str) -> Result<Vec<Arc<Credential>>, StoreError> {
        Ok(self
            .creds
            .iter()
            .filter(|c| c.rp_id.as_str() == rp_id)
            .cloned()
            .collect())
    }

    fn insert(&mut self, cred: Arc<Credential>) -> Result<(), StoreError> {
        let exists = self.creds.iter().any(|c| c.id == cred.id);
        if !exists && self.capacity.is_some_and(|n| self.creds.len() >= n) {
            return Err(StoreError::Full);
        }
        self.creds.retain(|c| c.id != cred.id);
        self.creds.push(cred);
        Ok(())
    }

    fn remove(&mut self, id: &[u8]) -> Result<Option<Arc<Credential>>, StoreError> {
        let pos = self.creds.iter().position(|c| *c.id == *id);
        Ok(pos.map(|p| self.creds.remove(p)))
    }

    fn clear(&mut self) -> Result<Vec<Arc<Credential>>, StoreError> {
        Ok(core::mem::take(&mut self.creds))
    }

    fn next_sign_count(&mut self) -> Result<u32, StoreError> {
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or(StoreError::CounterExhausted)?;
        Ok(self.counter)
    }
}

/// Presence provider with a fixed answer; records every request.
#[derive(Debug, Clone)]
pub struct ScriptedPresence {
    pub answer: Result<Presence, PresenceError>,
    pub requests: Vec<PresenceRequest>,
}

impl ScriptedPresence {
    /// Approve; report UV as performed when it was requested.
    pub fn approve() -> Self {
        ScriptedPresence {
            answer: Ok(Presence {
                user_verified: true,
            }),
            requests: Vec::new(),
        }
    }

    pub fn deny(err: PresenceError) -> Self {
        ScriptedPresence {
            answer: Err(err),
            requests: Vec::new(),
        }
    }
}

impl UserPresence for ScriptedPresence {
    fn request(&mut self, req: &PresenceRequest) -> Result<Presence, PresenceError> {
        self.requests.push(req.clone());
        self.answer.map(|p| Presence {
            user_verified: p.user_verified && req.require_uv,
        })
    }
}
