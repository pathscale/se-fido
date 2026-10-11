//! Persistent [`CredentialStore`].
//!
//! Directory layout (runtime default `$HOME/Library/Application Support/se-fido`,
//! see [`default_dir`]):
//!
//! * `credentials.bin`: `version(1) || nonce(12) || AES-256-GCM(CBOR array)`,
//!   AAD binds file name and version, fresh nonce from the supplied
//!   [`Entropy`] on every write.
//! * `counter`: global signature counter, `SFC1 || u32 BE || FNV-1a(u32)`.
//!   Not secret, only monotonic.
//!
//! Writes go to a temp file in the same directory, fsync, rename, fsync the
//! directory: a crash leaves the old or the new file, never a torn one.
//! Single writer per directory is assumed (not enforced).
//!
//! Loaded credentials are zero copy views into the decrypted index buffer.

#![forbid(unsafe_code)]

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use ctap2::cbor::{decode, encode, Out, Value};
use ctap2::{Bytes, Credential, CredentialStore, Entropy, StoreError, Text};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const CRED_FILE: &str = "credentials.bin";
pub const COUNTER_FILE: &str = "counter";
const FORMAT_VERSION: u8 = 1;
const AAD: &[u8] = b"se-fido credentials.bin v1";
const COUNTER_MAGIC: &[u8; 4] = b"SFC1";
pub const DEFAULT_CAPACITY: usize = 1000;

/// `$HOME/Library/Application Support/se-fido`.
pub fn default_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Library/Application Support/se-fido"))
}

pub struct FileStore<E> {
    dir: PathBuf,
    cipher: Aes256Gcm,
    entropy: E,
    creds: Vec<Arc<Credential>>,
    counter: u32,
    capacity: usize,
}

fn io(e: std::io::Error) -> StoreError {
    StoreError::Io(e.to_string())
}

impl<E: Entropy> FileStore<E> {
    /// Open or create the store. A present index that does not decrypt with
    /// `key` is [`StoreError::Corrupt`].
    pub fn open(dir: impl Into<PathBuf>, key: &[u8; 32], entropy: E) -> Result<Self, StoreError> {
        let dir = dir.into();
        create_private_dir(&dir).map_err(io)?;
        let cipher =
            Aes256Gcm::new_from_slice(key).map_err(|_| StoreError::Io("bad key length".into()))?;
        let creds = match fs::read(dir.join(CRED_FILE)) {
            Ok(b) => decrypt_index(&cipher, &b)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(io(e)),
        };
        let counter = match fs::read(dir.join(COUNTER_FILE)) {
            Ok(b) => decode_counter(&b)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
            Err(e) => return Err(io(e)),
        };
        Ok(FileStore {
            dir,
            cipher,
            entropy,
            creds,
            counter,
            capacity: DEFAULT_CAPACITY,
        })
    }

    pub fn with_capacity(mut self, capacity: usize) -> Self {
        self.capacity = capacity;
        self
    }

    pub fn dir(&self) -> &Path {
        &self.dir
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

    fn persist_index(&mut self, creds: &[Arc<Credential>]) -> Result<(), StoreError> {
        let mut nonce = [0u8; 12];
        self.entropy.fill(&mut nonce);
        let blob = encrypt_index(&self.cipher, &nonce, creds)?;
        atomic_write(&self.dir, CRED_FILE, &blob).map_err(io)
    }
}

impl<E: Entropy> CredentialStore for FileStore<E> {
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
        let mut next: Vec<Arc<Credential>> = self
            .creds
            .iter()
            .filter(|c| c.id != cred.id)
            .cloned()
            .collect();
        if next.len() >= self.capacity {
            return Err(StoreError::Full);
        }
        next.push(cred);
        self.persist_index(&next)?;
        self.creds = next;
        Ok(())
    }

    fn remove(&mut self, id: &[u8]) -> Result<Option<Arc<Credential>>, StoreError> {
        let Some(pos) = self.creds.iter().position(|c| *c.id == *id) else {
            return Ok(None);
        };
        let mut next = self.creds.clone();
        let removed = next.remove(pos);
        self.persist_index(&next)?;
        self.creds = next;
        Ok(Some(removed))
    }

    fn clear(&mut self) -> Result<Vec<Arc<Credential>>, StoreError> {
        self.persist_index(&[])?;
        Ok(std::mem::take(&mut self.creds))
    }

    fn next_sign_count(&mut self) -> Result<u32, StoreError> {
        let next = self
            .counter
            .checked_add(1)
            .ok_or(StoreError::CounterExhausted)?;
        // Durable before use.
        atomic_write(&self.dir, COUNTER_FILE, &encode_counter(next)).map_err(io)?;
        self.counter = next;
        Ok(next)
    }
}

fn checksum(v: u32) -> [u8; 4] {
    let mut h: u32 = 0x811c_9dc5;
    for b in v.to_be_bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h.to_be_bytes()
}

/// Counter file bytes for value `v`.
pub fn encode_counter(v: u32) -> Vec<u8> {
    let mut out = COUNTER_MAGIC.to_vec();
    out.extend_from_slice(&v.to_be_bytes());
    out.extend_from_slice(&checksum(v));
    out
}

fn decode_counter(b: &[u8]) -> Result<u32, StoreError> {
    if b.len() != 12 || &b[0..4] != COUNTER_MAGIC {
        return Err(StoreError::Corrupt("counter file malformed".into()));
    }
    let v = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
    if b[8..12] != checksum(v) {
        return Err(StoreError::Corrupt("counter checksum mismatch".into()));
    }
    Ok(v)
}

fn opt_text(t: &Option<Text>) -> Out<'_> {
    t.as_ref().map_or(Out::Null, |t| Out::Text(t.as_str()))
}

fn encrypt_index(
    cipher: &Aes256Gcm,
    nonce: &[u8; 12],
    creds: &[Arc<Credential>],
) -> Result<Vec<u8>, StoreError> {
    let records = creds
        .iter()
        .map(|c| {
            Out::Array(vec![
                Out::Bytes(&c.id),
                Out::Text(c.rp_id.as_str()),
                opt_text(&c.rp_name),
                Out::Bytes(&c.user_id),
                opt_text(&c.user_name),
                opt_text(&c.user_display_name),
                Out::Bytes(&c.key_handle),
                Out::Bytes(&c.public_key),
                Out::Bool(c.discoverable),
                Out::Int(c.created as i64),
            ])
        })
        .collect();
    let plain = encode(&Out::Array(records));
    let ct = cipher
        .encrypt(
            &Nonce::from(*nonce),
            Payload {
                msg: &plain,
                aad: AAD,
            },
        )
        .map_err(|_| StoreError::Io("encryption failed".into()))?;
    let mut out = Vec::with_capacity(13 + ct.len());
    out.push(FORMAT_VERSION);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt_index(cipher: &Aes256Gcm, blob: &[u8]) -> Result<Vec<Arc<Credential>>, StoreError> {
    if blob.len() < 13 + 16 || blob[0] != FORMAT_VERSION {
        return Err(StoreError::Corrupt("credential index header".into()));
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&blob[1..13]);
    let plain = cipher
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &blob[13..],
                aad: AAD,
            },
        )
        .map_err(|_| {
            StoreError::Corrupt("index authentication failed (wrong key or tampered)".into())
        })?;
    let buf = Bytes::from(plain);
    let v = decode(&buf).map_err(|s| StoreError::Corrupt(format!("index CBOR: {s:?}")))?;
    let items = v
        .as_array()
        .map_err(|_| StoreError::Corrupt("index is not an array".into()))?;
    items
        .iter()
        .map(|i| cred_from_value(i).map(Arc::new))
        .collect()
}

fn cred_from_value(v: &Value) -> Result<Credential, StoreError> {
    let bad = || StoreError::Corrupt("malformed credential record".into());
    let f = v.as_array().map_err(|_| bad())?;
    if f.len() != 10 {
        return Err(bad());
    }
    let bytes = |i: usize| f[i].as_bytes().cloned().map_err(|_| bad());
    let opt = |i: usize| match &f[i] {
        Value::Null => Ok(None),
        Value::Text(t) => Ok(Some(t.clone())),
        _ => Err(bad()),
    };
    Ok(Credential {
        id: bytes(0)?,
        rp_id: f[1].as_text().cloned().map_err(|_| bad())?,
        rp_name: opt(2)?,
        user_id: bytes(3)?,
        user_name: opt(4)?,
        user_display_name: opt(5)?,
        key_handle: bytes(6)?,
        public_key: bytes(7)?,
        discoverable: f[8].as_bool().map_err(|_| bad())?,
        created: f[9]
            .as_int()
            .ok()
            .and_then(|i| u64::try_from(i).ok())
            .ok_or_else(bad)?,
    })
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Write `dir/name` atomically and durably (mode 0600).
fn atomic_write(dir: &Path, name: &str, data: &[u8]) -> std::io::Result<()> {
    let tmp = dir.join(format!(".{name}.tmp"));
    let result = (|| {
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, dir.join(name))?;
        File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}
