//! Persistent [`CredentialStore`] for the authenticator.
//!
//! Layout of the store directory (default
//! `~/Library/Application Support/se-fido/`, see [`default_dir`]):
//!
//! * `credentials.bin` – `version(1) || nonce(12) || AES-256-GCM(ciphertext+tag)`
//!   of a CBOR array of credential records. AAD binds the file name and
//!   version. A fresh random nonce is used for every write.
//! * `counter` – the global signature counter: magic `SFC1` + big-endian u32
//!   + 4-byte checksum. Not secret; it only has to be monotonic.
//!
//! Every write goes to a temporary file in the same directory, is fsynced,
//! renamed over the target and the directory is fsynced, so a crash leaves
//! either the old or the new version, never a torn file.
//!
//! The 32-byte encryption key is supplied by the caller: in production it is
//! derived from a Secure Enclave key (see `backend-se`), in tests it is a
//! fixed value.

#![forbid(unsafe_code)]

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use ciborium::value::Value;
use ctap2::{Credential, CredentialStore, StoreError};
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const CRED_FILE: &str = "credentials.bin";
const COUNTER_FILE: &str = "counter";
const FORMAT_VERSION: u8 = 1;
const AAD: &[u8] = b"se-fido credentials.bin v1";
const COUNTER_MAGIC: &[u8; 4] = b"SFC1";
/// Upper bound on stored credentials (keeps the index small to rewrite).
pub const DEFAULT_CAPACITY: usize = 1000;

/// `$HOME/Library/Application Support/se-fido`.
pub fn default_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Library/Application Support/se-fido"))
}

pub struct FileStore {
    dir: PathBuf,
    cipher: Aes256Gcm,
    creds: Vec<Credential>,
    counter: u32,
    capacity: usize,
}

impl std::fmt::Debug for FileStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileStore")
            .field("dir", &self.dir)
            .field("credentials", &self.creds.len())
            .field("counter", &self.counter)
            .finish()
    }
}

fn io(e: std::io::Error) -> StoreError {
    StoreError::Io(e.to_string())
}

impl FileStore {
    /// Open (creating if needed) the store in `dir` with the given key.
    /// Fails with [`StoreError::Corrupt`] if the file exists but cannot be
    /// decrypted with this key.
    pub fn open(dir: impl Into<PathBuf>, key: &[u8; 32]) -> Result<Self, StoreError> {
        let dir = dir.into();
        create_private_dir(&dir).map_err(io)?;
        let cipher = Aes256Gcm::new(key.into());
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

    fn persist_index(&self, creds: &[Credential]) -> Result<(), StoreError> {
        let blob = encrypt_index(&self.cipher, creds)?;
        atomic_write(&self.dir, CRED_FILE, &blob).map_err(io)
    }
}

impl CredentialStore for FileStore {
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
        let mut next: Vec<Credential> = self
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

    fn remove(&mut self, id: &[u8]) -> Result<Option<Credential>, StoreError> {
        let Some(pos) = self.creds.iter().position(|c| c.id == id) else {
            return Ok(None);
        };
        let mut next = self.creds.clone();
        let removed = next.remove(pos);
        self.persist_index(&next)?;
        self.creds = next;
        Ok(Some(removed))
    }

    fn clear(&mut self) -> Result<Vec<Credential>, StoreError> {
        self.persist_index(&[])?;
        Ok(std::mem::take(&mut self.creds))
    }

    fn next_sign_count(&mut self) -> Result<u32, StoreError> {
        let next = self
            .counter
            .checked_add(1)
            .ok_or(StoreError::CounterExhausted)?;
        // Persist before use: a value is only handed out once it is durable.
        atomic_write(&self.dir, COUNTER_FILE, &encode_counter(next)).map_err(io)?;
        self.counter = next;
        Ok(next)
    }
}

fn checksum(v: u32) -> [u8; 4] {
    // Simple corruption check (not a security property): FNV-1a over the value.
    let mut h: u32 = 0x811c_9dc5;
    for b in v.to_be_bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h.to_be_bytes()
}

fn encode_counter(v: u32) -> Vec<u8> {
    let mut out = COUNTER_MAGIC.to_vec();
    out.extend_from_slice(&v.to_be_bytes());
    out.extend_from_slice(&checksum(v));
    out
}

fn decode_counter(b: &[u8]) -> Result<u32, StoreError> {
    if b.len() != 12 || &b[0..4] != COUNTER_MAGIC {
        return Err(StoreError::Corrupt("counter file malformed".into()));
    }
    let v = u32::from_be_bytes(b[4..8].try_into().expect("4 bytes"));
    if b[8..12] != checksum(v) {
        return Err(StoreError::Corrupt("counter checksum mismatch".into()));
    }
    Ok(v)
}

fn encrypt_index(cipher: &Aes256Gcm, creds: &[Credential]) -> Result<Vec<u8>, StoreError> {
    let value = Value::Array(creds.iter().map(cred_to_value).collect());
    let mut plain = Vec::new();
    ciborium::into_writer(&value, &mut plain).map_err(|e| StoreError::Io(e.to_string()))?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &plain,
                aad: AAD,
            },
        )
        .map_err(|_| StoreError::Io("encryption failed".into()))?;
    let mut out = Vec::with_capacity(1 + 12 + ct.len());
    out.push(FORMAT_VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt_index(cipher: &Aes256Gcm, blob: &[u8]) -> Result<Vec<Credential>, StoreError> {
    if blob.len() < 1 + 12 + 16 || blob[0] != FORMAT_VERSION {
        return Err(StoreError::Corrupt("credential index header".into()));
    }
    let nonce: [u8; 12] = blob[1..13].try_into().expect("length checked");
    let plain = cipher
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &blob[13..],
                aad: AAD,
            },
        )
        .map_err(|_| {
            StoreError::Corrupt(
                "credential index authentication failed (wrong key or tampered)".into(),
            )
        })?;
    let v: Value =
        ciborium::from_reader(&plain[..]).map_err(|e| StoreError::Corrupt(e.to_string()))?;
    let Value::Array(items) = v else {
        return Err(StoreError::Corrupt("index is not an array".into()));
    };
    items.iter().map(cred_from_value).collect()
}

fn opt_text(v: &Option<String>) -> Value {
    v.as_ref().map_or(Value::Null, |s| Value::Text(s.clone()))
}

fn cred_to_value(c: &Credential) -> Value {
    Value::Array(vec![
        Value::Bytes(c.id.clone()),
        Value::Text(c.rp_id.clone()),
        opt_text(&c.rp_name),
        Value::Bytes(c.user_id.clone()),
        opt_text(&c.user_name),
        opt_text(&c.user_display_name),
        Value::Bytes(c.key_handle.clone()),
        Value::Bytes(c.public_key.clone()),
        Value::Bool(c.discoverable),
        Value::Integer(c.created.into()),
    ])
}

fn cred_from_value(v: &Value) -> Result<Credential, StoreError> {
    let bad = || StoreError::Corrupt("malformed credential record".into());
    let Value::Array(f) = v else {
        return Err(bad());
    };
    if f.len() != 10 {
        return Err(bad());
    }
    let bytes = |i: usize| f[i].as_bytes().cloned().ok_or_else(bad);
    let txt = |i: usize| f[i].as_text().map(str::to_owned).ok_or_else(bad);
    let opt = |i: usize| match &f[i] {
        Value::Null => Ok(None),
        Value::Text(t) => Ok(Some(t.clone())),
        _ => Err(bad()),
    };
    Ok(Credential {
        id: bytes(0)?,
        rp_id: txt(1)?,
        rp_name: opt(2)?,
        user_id: bytes(3)?,
        user_name: opt(4)?,
        user_display_name: opt(5)?,
        key_handle: bytes(6)?,
        public_key: bytes(7)?,
        discoverable: f[8].as_bool().ok_or_else(bad)?,
        created: f[9]
            .as_integer()
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

/// Write `data` to `dir/name` atomically and durably.
fn atomic_write(dir: &Path, name: &str, data: &[u8]) -> std::io::Result<()> {
    let mut suffix = [0u8; 8];
    OsRng.fill_bytes(&mut suffix);
    let tmp_name: String = format!(
        ".{name}.tmp-{}",
        suffix
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let tmp = dir.join(&tmp_name);
    let result = (|| {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
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
        // Make the rename itself durable.
        File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x42; 32];

    fn cred(id: u8, rp: &str, rk: bool) -> Credential {
        Credential {
            id: vec![id; 32],
            rp_id: rp.into(),
            rp_name: Some("RP".into()),
            user_id: vec![id],
            user_name: if id % 2 == 0 { Some("n".into()) } else { None },
            user_display_name: None,
            key_handle: vec![0xaa, id],
            public_key: vec![4; 65],
            discoverable: rk,
            created: id as u64,
        }
    }

    #[test]
    fn roundtrip_across_reopen() {
        let d = tempfile::tempdir().unwrap();
        {
            let mut s = FileStore::open(d.path(), &KEY).unwrap();
            assert!(s.is_empty());
            s.insert(cred(1, "a.com", true)).unwrap();
            s.insert(cred(2, "a.com", false)).unwrap();
            s.insert(cred(3, "b.com", true)).unwrap();
            assert_eq!(s.next_sign_count().unwrap(), 1);
            assert_eq!(s.next_sign_count().unwrap(), 2);
        }
        let s = FileStore::open(d.path(), &KEY).unwrap();
        assert_eq!(s.len(), 3);
        assert_eq!(s.counter(), 2);
        assert_eq!(s.get(&[2; 32]).unwrap(), Some(cred(2, "a.com", false)));
        assert_eq!(s.list_rp("a.com").unwrap().len(), 2);
        assert_eq!(s.list_rp("b.com").unwrap(), vec![cred(3, "b.com", true)]);
    }

    #[test]
    fn counter_is_monotonic_across_reopen_and_clear() {
        let d = tempfile::tempdir().unwrap();
        let mut last = 0;
        for _ in 0..3 {
            let mut s = FileStore::open(d.path(), &KEY).unwrap();
            for _ in 0..5 {
                let c = s.next_sign_count().unwrap();
                assert!(c > last);
                last = c;
            }
            s.insert(cred(1, "a", true)).unwrap();
            s.clear().unwrap();
        }
        assert_eq!(last, 15);
    }

    #[test]
    fn remove_and_clear_persist() {
        let d = tempfile::tempdir().unwrap();
        let mut s = FileStore::open(d.path(), &KEY).unwrap();
        s.insert(cred(1, "a", true)).unwrap();
        s.insert(cred(2, "a", true)).unwrap();
        assert_eq!(s.remove(&[1; 32]).unwrap(), Some(cred(1, "a", true)));
        assert_eq!(s.remove(&[1; 32]).unwrap(), None);
        assert_eq!(FileStore::open(d.path(), &KEY).unwrap().len(), 1);
        assert_eq!(s.clear().unwrap().len(), 1);
        assert!(FileStore::open(d.path(), &KEY).unwrap().is_empty());
    }

    #[test]
    fn insert_same_id_replaces() {
        let d = tempfile::tempdir().unwrap();
        let mut s = FileStore::open(d.path(), &KEY).unwrap();
        s.insert(cred(1, "a", true)).unwrap();
        let mut c = cred(1, "a", true);
        c.user_name = Some("changed".into());
        s.insert(c.clone()).unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s.get(&[1; 32]).unwrap(), Some(c));
    }

    #[test]
    fn wrong_key_is_rejected() {
        let d = tempfile::tempdir().unwrap();
        FileStore::open(d.path(), &KEY)
            .unwrap()
            .insert(cred(1, "a", true))
            .unwrap();
        let err = FileStore::open(d.path(), &[0x43; 32]).unwrap_err();
        assert!(matches!(err, StoreError::Corrupt(_)), "{err:?}");
    }

    #[test]
    fn tampering_is_detected() {
        let d = tempfile::tempdir().unwrap();
        FileStore::open(d.path(), &KEY)
            .unwrap()
            .insert(cred(1, "a", true))
            .unwrap();
        let p = d.path().join(CRED_FILE);
        let mut b = fs::read(&p).unwrap();
        let n = b.len();
        b[n - 20] ^= 1;
        fs::write(&p, b).unwrap();
        assert!(matches!(
            FileStore::open(d.path(), &KEY),
            Err(StoreError::Corrupt(_))
        ));
    }

    #[test]
    fn ciphertext_does_not_contain_plaintext_and_nonce_changes() {
        let d = tempfile::tempdir().unwrap();
        let mut s = FileStore::open(d.path(), &KEY).unwrap();
        let mut c = cred(1, "very-identifiable-rp.example", true);
        c.user_name = Some("alice@example.com".into());
        s.insert(c).unwrap();
        let b1 = fs::read(d.path().join(CRED_FILE)).unwrap();
        let hay = String::from_utf8_lossy(&b1);
        assert!(!hay.contains("very-identifiable-rp"));
        assert!(!hay.contains("alice@"));
        s.insert(cred(2, "a", true)).unwrap();
        s.remove(&[2; 32]).unwrap();
        let b2 = fs::read(d.path().join(CRED_FILE)).unwrap();
        assert_ne!(b1[1..13], b2[1..13], "fresh nonce per write");
    }

    #[test]
    fn corrupt_counter_detected() {
        let d = tempfile::tempdir().unwrap();
        FileStore::open(d.path(), &KEY)
            .unwrap()
            .next_sign_count()
            .unwrap();
        let p = d.path().join(COUNTER_FILE);
        let mut b = fs::read(&p).unwrap();
        b[7] ^= 0x10;
        fs::write(&p, b).unwrap();
        assert!(matches!(
            FileStore::open(d.path(), &KEY),
            Err(StoreError::Corrupt(_))
        ));
        fs::write(&p, b"junk").unwrap();
        assert!(matches!(
            FileStore::open(d.path(), &KEY),
            Err(StoreError::Corrupt(_))
        ));
    }

    #[test]
    fn counter_exhaustion() {
        let d = tempfile::tempdir().unwrap();
        fs::create_dir_all(d.path()).unwrap();
        fs::write(d.path().join(COUNTER_FILE), encode_counter(u32::MAX)).unwrap();
        let mut s = FileStore::open(d.path(), &KEY).unwrap();
        assert_eq!(s.next_sign_count(), Err(StoreError::CounterExhausted));
    }

    #[test]
    fn capacity_limit() {
        let d = tempfile::tempdir().unwrap();
        let mut s = FileStore::open(d.path(), &KEY).unwrap().with_capacity(2);
        s.insert(cred(1, "a", true)).unwrap();
        s.insert(cred(2, "a", true)).unwrap();
        assert_eq!(s.insert(cred(3, "a", true)), Err(StoreError::Full));
        // Replacing an existing ID is still allowed at capacity.
        s.insert(cred(2, "a", false)).unwrap();
        assert_eq!(FileStore::open(d.path(), &KEY).unwrap().len(), 2);
    }

    #[test]
    fn no_temp_files_left_and_private_permissions() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("nested/se-fido");
        let mut s = FileStore::open(&dir, &KEY).unwrap();
        s.insert(cred(1, "a", true)).unwrap();
        s.next_sign_count().unwrap();
        let names: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(sorted, [COUNTER_FILE, CRED_FILE]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(dir.join(CRED_FILE))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn default_dir_under_application_support() {
        if let Some(p) = default_dir() {
            assert!(p.ends_with("Library/Application Support/se-fido"));
        }
    }

    #[test]
    fn works_with_authenticator() {
        use ctap2::soft::{ScriptedPresence, SoftBackend};
        use ctap2::{Authenticator, AuthenticatorConfig};
        let d = tempfile::tempdir().unwrap();
        let store = FileStore::open(d.path(), &KEY).unwrap();
        let mut a = Authenticator::new(
            SoftBackend::new(),
            store,
            ScriptedPresence::approve(),
            AuthenticatorConfig::default(),
        );
        assert_eq!(a.process(&[0x0b]), [0]);
        assert_eq!(a.process(&[0x07]), [0]);
    }
}
