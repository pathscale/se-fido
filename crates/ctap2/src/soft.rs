//! In-memory implementations of the backend traits, for tests and tooling.
//! Not for real use: keys and credentials vanish with the process.

use crate::types::*;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashMap;

/// Software P-256 keys held in a HashMap.
#[derive(Default)]
pub struct SoftBackend {
    keys: HashMap<Vec<u8>, SigningKey>,
}

impl SoftBackend {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn key_count(&self) -> usize {
        self.keys.len()
    }
}

impl Backend for SoftBackend {
    fn create_key(&mut self, _rp_id: &str, _user_id: &[u8]) -> Result<NewKey, BackendError> {
        let sk = SigningKey::random(&mut OsRng);
        let mut handle = vec![0u8; 16];
        OsRng.fill_bytes(&mut handle);
        let public_key = p256::PublicKey::from(sk.verifying_key());
        self.keys.insert(handle.clone(), sk);
        Ok(NewKey { handle, public_key })
    }

    fn sign(&mut self, handle: &[u8], message: &[u8]) -> Result<Vec<u8>, BackendError> {
        let sk = self.keys.get(handle).ok_or(BackendError::KeyNotFound)?;
        let sig: Signature = sk.sign(message);
        Ok(sig.to_der().as_bytes().to_vec())
    }

    fn delete_key(&mut self, handle: &[u8]) -> Result<(), BackendError> {
        self.keys.remove(handle);
        Ok(())
    }
}

/// Credential store in memory.
#[derive(Default, Debug)]
pub struct MemoryStore {
    creds: Vec<Credential>,
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
    fn get(&self, id: &[u8]) -> Result<Option<Credential>, StoreError> {
        Ok(self.creds.iter().find(|c| c.id == id).cloned())
    }

    fn list_rp(&self, rp_id: &str) -> Result<Vec<Credential>, StoreError> {
        Ok(self
            .creds
            .iter()
            .filter(|c| c.rp_id == rp_id)
            .cloned()
            .collect())
    }

    fn insert(&mut self, cred: Credential) -> Result<(), StoreError> {
        if self.capacity.is_some_and(|n| self.creds.len() >= n) {
            return Err(StoreError::Full);
        }
        self.creds.retain(|c| c.id != cred.id);
        self.creds.push(cred);
        Ok(())
    }

    fn remove(&mut self, id: &[u8]) -> Result<Option<Credential>, StoreError> {
        let pos = self.creds.iter().position(|c| c.id == id);
        Ok(pos.map(|p| self.creds.remove(p)))
    }

    fn clear(&mut self) -> Result<Vec<Credential>, StoreError> {
        Ok(std::mem::take(&mut self.creds))
    }

    fn next_sign_count(&mut self) -> Result<u32, StoreError> {
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or(StoreError::CounterExhausted)?;
        Ok(self.counter)
    }
}

/// Presence provider with a fixed answer that records every request.
#[derive(Debug, Clone)]
pub struct ScriptedPresence {
    pub answer: Result<Presence, PresenceError>,
    pub requests: Vec<PresenceRequest>,
}

impl ScriptedPresence {
    /// Always approve, and report user verification as performed when asked.
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
        match self.answer {
            Ok(p) => Ok(Presence {
                user_verified: p.user_verified && req.require_uv,
            }),
            Err(e) => Err(e),
        }
    }
}
