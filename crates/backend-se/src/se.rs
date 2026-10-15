use crate::ffi::*;
use ctap2::{Backend, BackendError, Bytes, Entropy, NewKey};
use hkdf::Hkdf;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::{Digest, Sha256};
use std::ffi::{c_char, c_void, CStr};
use std::fmt;
use std::path::Path;
use std::ptr::null;

/// Owned CoreFoundation object (released on drop).
struct Cf(CFTypeRef);

impl Cf {
    fn create(p: CFTypeRef) -> Option<Cf> {
        if p.is_null() {
            None
        } else {
            Some(Cf(p))
        }
    }

    fn ptr(&self) -> CFTypeRef {
        self.0
    }
}

impl Drop for Cf {
    fn drop(&mut self) {
        // SAFETY: we own exactly one reference.
        unsafe { CFRelease(self.0) }
    }
}

fn cf_data(b: &[u8]) -> Cf {
    // SAFETY: valid pointer and length; NULL allocator means default.
    Cf::create(unsafe { CFDataCreate(null(), b.as_ptr(), b.len() as CFIndex) })
        .expect("CFDataCreate")
}

fn cf_str(s: &str) -> Cf {
    // SAFETY: valid UTF-8 bytes.
    Cf::create(unsafe {
        CFStringCreateWithBytes(
            null(),
            s.as_ptr(),
            s.len() as CFIndex,
            kCFStringEncodingUTF8,
            0,
        )
    })
    .expect("CFStringCreateWithBytes")
}

fn cf_i32(v: i32) -> Cf {
    // SAFETY: pointer to a live i32 of the declared type.
    Cf::create(unsafe {
        CFNumberCreate(
            null(),
            kCFNumberSInt32Type,
            &v as *const i32 as *const c_void,
        )
    })
    .expect("CFNumberCreate")
}

/// Dictionary with CFType callbacks (retains keys and values).
fn cf_dict(pairs: &[(CFTypeRef, CFTypeRef)]) -> Cf {
    let keys: Vec<*const c_void> = pairs.iter().map(|p| p.0).collect();
    let values: Vec<*const c_void> = pairs.iter().map(|p| p.1).collect();
    // SAFETY: arrays of valid CF objects of equal length; static callbacks.
    Cf::create(unsafe {
        CFDictionaryCreate(
            null(),
            keys.as_ptr(),
            values.as_ptr(),
            pairs.len() as CFIndex,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks,
        )
    })
    .expect("CFDictionaryCreate")
}

fn is_data(p: CFTypeRef) -> bool {
    // SAFETY: p is a valid CF object.
    !p.is_null() && unsafe { CFGetTypeID(p) == CFDataGetTypeID() }
}

/// Copy the bytes out of a CFData (borrowed reference).
fn data_bytes(p: CFTypeRef) -> Vec<u8> {
    // SAFETY: caller checked p is CFData; pointer valid for length bytes.
    unsafe {
        let len = CFDataGetLength(p) as usize;
        let ptr = CFDataGetBytePtr(p);
        if ptr.is_null() || len == 0 {
            return Vec::new();
        }
        std::slice::from_raw_parts(ptr, len).to_vec()
    }
}

/// Rust string from a CFString (borrowed reference).
fn string_of(s: CFStringRef) -> String {
    if s.is_null() {
        return String::new();
    }
    let mut buf = vec![0 as c_char; 4096];
    // SAFETY: buffer of the declared size.
    let ok = unsafe {
        CFStringGetCString(
            s,
            buf.as_mut_ptr(),
            buf.len() as CFIndex,
            kCFStringEncodingUTF8,
        )
    };
    if ok == 0 {
        return String::from("?");
    }
    // SAFETY: CFStringGetCString NUL-terminates on success.
    unsafe { CStr::from_ptr(buf.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

fn bool_ref(b: bool) -> CFTypeRef {
    // SAFETY: immortal constants.
    unsafe {
        if b {
            kCFBooleanTrue
        } else {
            kCFBooleanFalse
        }
    }
}

/// Failure of a Security.framework call: CFError code (OSStatus domain for
/// most), domain and description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeError {
    pub op: &'static str,
    pub code: i64,
    pub domain: String,
    pub message: String,
}

impl fmt::Display for SeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} failed: code {} ({}) {}",
            self.op, self.code, self.domain, self.message
        )
    }
}

impl std::error::Error for SeError {}

impl SeError {
    fn plain(op: &'static str, message: impl Into<String>) -> Self {
        SeError {
            op,
            code: 0,
            domain: String::new(),
            message: message.into(),
        }
    }

    fn status(op: &'static str, status: OSStatus) -> Self {
        SeError {
            op,
            code: status as i64,
            domain: "OSStatus".into(),
            message: String::new(),
        }
    }

    /// Consume a +1 CFErrorRef from a Security call.
    fn from_cf(op: &'static str, err: CFErrorRef) -> Self {
        let Some(e) = Cf::create(err) else {
            return SeError::plain(op, "returned NULL without a CFError");
        };
        // SAFETY: valid CFError; domain is a get-rule reference.
        let (code, domain, desc) = unsafe {
            (
                CFErrorGetCode(e.ptr()),
                string_of(CFErrorGetDomain(e.ptr())),
                Cf::create(CFErrorCopyDescription(e.ptr())),
            )
        };
        SeError {
            op,
            code: code as i64,
            domain,
            message: desc.map(|d| string_of(d.ptr())).unwrap_or_default(),
        }
    }
}

fn to_backend(e: SeError) -> BackendError {
    if e.code == -128 || e.code == -2 {
        BackendError::Cancelled // errSecUserCanceled / LAErrorUserCancel
    } else if e.code == errSecItemNotFound as i64 {
        BackendError::KeyNotFound
    } else {
        BackendError::Failed(e.to_string())
    }
}

/// Random bytes from `SecRandomCopyBytes`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemEntropy;

impl Entropy for SystemEntropy {
    fn fill(&mut self, out: &mut [u8]) {
        // SAFETY: valid writable buffer; NULL means kSecRandomDefault.
        let rc = unsafe { SecRandomCopyBytes(null(), out.len(), out.as_mut_ptr() as *mut c_void) };
        // Without randomness no key material may be produced.
        assert_eq!(rc, 0, "SecRandomCopyBytes failed");
    }
}

/// Who must approve each use of a private key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessPolicy {
    /// No interaction: any process that can load the key can use it.
    None,
    /// Touch ID or device password on every use.
    UserPresence,
    /// Touch ID with the currently enrolled fingers only.
    BiometryCurrentSet,
}

fn access_control(policy: AccessPolicy) -> Result<Cf, SeError> {
    let flags = kSecAccessControlPrivateKeyUsage
        | match policy {
            AccessPolicy::None => 0,
            AccessPolicy::UserPresence => kSecAccessControlUserPresence,
            AccessPolicy::BiometryCurrentSet => kSecAccessControlBiometryCurrentSet,
        };
    let mut err: CFErrorRef = null();
    // SAFETY: constant protection class; valid out pointer.
    let ac = unsafe {
        SecAccessControlCreateWithFlags(
            null(),
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            &mut err,
        )
    };
    Cf::create(ac).ok_or_else(|| SeError::from_cf("SecAccessControlCreateWithFlags", err))
}

/// Where a new key lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyStorage {
    /// Non-permanent; persist via [`SecKey::token_object_blob`].
    Ephemeral,
    /// Permanent keychain item found by `tag`.
    Keychain { tag: Vec<u8>, data_protection: bool },
}

/// How to rebuild a key from its token object blob. Undocumented; se-probe
/// tests all three.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReloadVariant {
    /// `SecKeyCreateWithData(empty, {.., toid: blob})`
    EmptyDataWithToid,
    /// `SecKeyCreateWithData(blob, {.., toid: blob})`
    BlobDataWithToid,
    /// `SecKeyCreateWithData(blob, {..})`. On macOS 26.5 this returns a key
    /// with a different public key; never used to load credentials.
    BlobDataNoToid,
}

impl ReloadVariant {
    pub const ALL: [ReloadVariant; 3] = [
        ReloadVariant::EmptyDataWithToid,
        ReloadVariant::BlobDataWithToid,
        ReloadVariant::BlobDataNoToid,
    ];
}

/// Owned `SecKeyRef`.
pub struct SecKey(Cf);

const TOID: &str = "toid";

fn sec_key(p: SecKeyRef, op: &'static str, err: CFErrorRef) -> Result<SecKey, SeError> {
    Cf::create(p)
        .map(SecKey)
        .ok_or_else(|| SeError::from_cf(op, err))
}

impl SecKey {
    /// Generate a P-256 key inside the Secure Enclave.
    pub fn generate(storage: &KeyStorage, policy: AccessPolicy) -> Result<SecKey, SeError> {
        let ac = access_control(policy)?;
        let bits = cf_i32(256);
        let label = cf_str("se-fido");
        let tag_data;
        // SAFETY (all statics below): immortal framework constants.
        let mut priv_pairs = vec![(unsafe { kSecAttrAccessControl }, ac.ptr())];
        let mut pairs = vec![
            (unsafe { kSecAttrKeyType }, unsafe {
                kSecAttrKeyTypeECSECPrimeRandom
            }),
            (unsafe { kSecAttrKeySizeInBits }, bits.ptr()),
            (unsafe { kSecAttrTokenID }, unsafe {
                kSecAttrTokenIDSecureEnclave
            }),
        ];
        match storage {
            KeyStorage::Ephemeral => {
                priv_pairs.push((unsafe { kSecAttrIsPermanent }, bool_ref(false)))
            }
            KeyStorage::Keychain {
                tag,
                data_protection,
            } => {
                tag_data = cf_data(tag);
                priv_pairs.push((unsafe { kSecAttrIsPermanent }, bool_ref(true)));
                priv_pairs.push((unsafe { kSecAttrApplicationTag }, tag_data.ptr()));
                priv_pairs.push((unsafe { kSecAttrLabel }, label.ptr()));
                if *data_protection {
                    pairs.push((unsafe { kSecUseDataProtectionKeychain }, bool_ref(true)));
                }
            }
        }
        let priv_attrs = cf_dict(&priv_pairs);
        pairs.push((unsafe { kSecPrivateKeyAttrs }, priv_attrs.ptr()));
        let params = cf_dict(&pairs);
        let mut err: CFErrorRef = null();
        // SAFETY: valid dictionary and out pointer.
        let k = unsafe { SecKeyCreateRandomKey(params.ptr(), &mut err) };
        sec_key(k, "SecKeyCreateRandomKey", err)
    }

    /// Rebuild a Secure Enclave key from its token object blob.
    pub fn from_blob(blob: &[u8], variant: ReloadVariant) -> Result<SecKey, SeError> {
        let bits = cf_i32(256);
        let toid_key = cf_str(TOID);
        let blob_data = cf_data(blob);
        let empty = cf_data(&[]);
        let mut pairs = vec![
            (unsafe { kSecAttrKeyType }, unsafe {
                kSecAttrKeyTypeECSECPrimeRandom
            }),
            (unsafe { kSecAttrKeyClass }, unsafe {
                kSecAttrKeyClassPrivate
            }),
            (unsafe { kSecAttrKeySizeInBits }, bits.ptr()),
            (unsafe { kSecAttrTokenID }, unsafe {
                kSecAttrTokenIDSecureEnclave
            }),
        ];
        if variant != ReloadVariant::BlobDataNoToid {
            pairs.push((toid_key.ptr(), blob_data.ptr()));
        }
        let attrs = cf_dict(&pairs);
        let data = if variant == ReloadVariant::EmptyDataWithToid {
            &empty
        } else {
            &blob_data
        };
        let mut err: CFErrorRef = null();
        // SAFETY: valid objects and out pointer.
        let k = unsafe { SecKeyCreateWithData(data.ptr(), attrs.ptr(), &mut err) };
        sec_key(k, "SecKeyCreateWithData", err)
    }

    /// Reload with the variants verified to return the same key.
    pub fn from_blob_any(blob: &[u8]) -> Result<(SecKey, ReloadVariant), SeError> {
        let mut last = SeError::plain("SecKeyCreateWithData", "no variant tried");
        for v in [
            ReloadVariant::EmptyDataWithToid,
            ReloadVariant::BlobDataWithToid,
        ] {
            match SecKey::from_blob(blob, v) {
                Ok(k) => return Ok((k, v)),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// Software P-256 public key (SEC1 uncompressed) as a SecKey.
    pub fn public_from_sec1(sec1: &[u8]) -> Result<SecKey, SeError> {
        let bits = cf_i32(256);
        let attrs = cf_dict(&[
            (unsafe { kSecAttrKeyType }, unsafe {
                kSecAttrKeyTypeECSECPrimeRandom
            }),
            (unsafe { kSecAttrKeyClass }, unsafe {
                kSecAttrKeyClassPublic
            }),
            (unsafe { kSecAttrKeySizeInBits }, bits.ptr()),
        ]);
        let data = cf_data(sec1);
        let mut err: CFErrorRef = null();
        // SAFETY: valid objects and out pointer.
        let k = unsafe { SecKeyCreateWithData(data.ptr(), attrs.ptr(), &mut err) };
        sec_key(k, "SecKeyCreateWithData(public)", err)
    }

    fn keychain_query(tag: &[u8], data_protection: bool, find: bool) -> (Cf, Cf) {
        let tag_data = cf_data(tag);
        let mut pairs = vec![
            (unsafe { kSecClass }, unsafe { kSecClassKey }),
            (unsafe { kSecAttrApplicationTag }, tag_data.ptr()),
        ];
        if find {
            pairs.push((unsafe { kSecAttrKeyClass }, unsafe {
                kSecAttrKeyClassPrivate
            }));
            pairs.push((unsafe { kSecReturnRef }, bool_ref(true)));
            pairs.push((unsafe { kSecMatchLimit }, unsafe { kSecMatchLimitOne }));
        }
        if data_protection {
            pairs.push((unsafe { kSecUseDataProtectionKeychain }, bool_ref(true)));
        }
        (cf_dict(&pairs), tag_data)
    }

    /// Find a permanent key by application tag.
    pub fn find_in_keychain(tag: &[u8], data_protection: bool) -> Result<SecKey, SeError> {
        let (q, _tag) = SecKey::keychain_query(tag, data_protection, true);
        let mut out: CFTypeRef = null();
        // SAFETY: valid query and out pointer.
        let st = unsafe { SecItemCopyMatching(q.ptr(), &mut out) };
        if st != errSecSuccess {
            return Err(SeError::status("SecItemCopyMatching", st));
        }
        Cf::create(out)
            .map(SecKey)
            .ok_or_else(|| SeError::plain("SecItemCopyMatching", "no result"))
    }

    /// Delete permanent keys with this application tag.
    pub fn delete_from_keychain(tag: &[u8], data_protection: bool) -> Result<(), SeError> {
        let (q, _tag) = SecKey::keychain_query(tag, data_protection, false);
        // SAFETY: valid query.
        let st = unsafe { SecItemDelete(q.ptr()) };
        if st != errSecSuccess {
            return Err(SeError::status("SecItemDelete", st));
        }
        Ok(())
    }

    /// SEC1 uncompressed public key (65 bytes).
    pub fn public_key_sec1(&self) -> Result<Vec<u8>, SeError> {
        // SAFETY: valid key; returns +1 or NULL.
        let pk = Cf::create(unsafe { SecKeyCopyPublicKey(self.0.ptr()) })
            .ok_or_else(|| SeError::plain("SecKeyCopyPublicKey", "NULL"))?;
        let mut err: CFErrorRef = null();
        // SAFETY: valid key and out pointer.
        let d = unsafe { SecKeyCopyExternalRepresentation(pk.ptr(), &mut err) };
        let d = Cf::create(d)
            .ok_or_else(|| SeError::from_cf("SecKeyCopyExternalRepresentation", err))?;
        Ok(data_bytes(d.ptr()))
    }

    /// ECDSA P-256 over SHA-256(message), DER.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SeError> {
        let data = cf_data(message);
        let mut err: CFErrorRef = null();
        // SAFETY: valid key, constant algorithm, data, out pointer.
        let sig = unsafe {
            SecKeyCreateSignature(
                self.0.ptr(),
                kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
                data.ptr(),
                &mut err,
            )
        };
        let sig = Cf::create(sig).ok_or_else(|| SeError::from_cf("SecKeyCreateSignature", err))?;
        Ok(data_bytes(sig.ptr()))
    }

    /// Raw ECDH shared secret (x coordinate) with a SEC1 public key.
    pub fn ecdh(&self, peer_sec1: &[u8]) -> Result<Vec<u8>, SeError> {
        let peer = SecKey::public_from_sec1(peer_sec1)?;
        let params = cf_dict(&[]);
        let mut err: CFErrorRef = null();
        // SAFETY: valid keys, constant algorithm, params, out pointer.
        let r = unsafe {
            SecKeyCopyKeyExchangeResult(
                self.0.ptr(),
                kSecKeyAlgorithmECDHKeyExchangeStandard,
                peer.0.ptr(),
                params.ptr(),
                &mut err,
            )
        };
        let r =
            Cf::create(r).ok_or_else(|| SeError::from_cf("SecKeyCopyKeyExchangeResult", err))?;
        Ok(data_bytes(r.ptr()))
    }

    fn attributes(&self) -> Option<Cf> {
        // SAFETY: valid key; +1 or NULL.
        Cf::create(unsafe { SecKeyCopyAttributes(self.0.ptr()) })
    }

    /// Attribute names with a short value summary. Data values are shown
    /// by length only; no key material is printed.
    pub fn attribute_summary(&self) -> Vec<(String, String)> {
        let Some(d) = self.attributes() else {
            return Vec::new();
        };
        // SAFETY: valid dictionary; arrays sized to its count.
        let n = unsafe { CFDictionaryGetCount(d.ptr()) } as usize;
        let mut keys = vec![null(); n];
        let mut values = vec![null(); n];
        unsafe { CFDictionaryGetKeysAndValues(d.ptr(), keys.as_mut_ptr(), values.as_mut_ptr()) };
        let mut out = Vec::with_capacity(n);
        for (k, v) in keys.into_iter().zip(values) {
            // SAFETY: borrowed entries of a live dictionary.
            let name = if unsafe { CFGetTypeID(k) == CFStringGetTypeID() } {
                string_of(k)
            } else {
                "?".into()
            };
            let summary = if is_data(v) {
                format!("data[{}]", data_bytes(v).len())
            } else {
                // SAFETY: valid object; +1 description.
                let s = Cf::create(unsafe { CFCopyDescription(v) })
                    .map(|d| string_of(d.ptr()))
                    .unwrap_or_default();
                s.chars().take(60).collect()
            };
            out.push((name, summary));
        }
        out.sort();
        out
    }

    /// The SE-encrypted token object (`toid` attribute).
    pub fn token_object_blob(&self) -> Result<Vec<u8>, SeError> {
        let d = self
            .attributes()
            .ok_or_else(|| SeError::plain("SecKeyCopyAttributes", "NULL"))?;
        let key = cf_str(TOID);
        // SAFETY: valid dictionary and key; borrowed result.
        let v = unsafe { CFDictionaryGetValue(d.ptr(), key.ptr()) };
        if !is_data(v) {
            return Err(SeError::plain("toid", "attribute missing or not CFData"));
        }
        Ok(data_bytes(v))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageMode {
    /// In-memory probe mode. Token object blobs in handles are not durable credentials.
    Blob,
    /// Durable keys stored as permanent data-protection keychain items.
    Keychain,
}

const HANDLE_BLOB: u8 = 0x01;
const HANDLE_KEYCHAIN: u8 = 0x02;
const TAG_PREFIX: &[u8] = b"se-fido:";

/// [`ctap2::Backend`] on the Secure Enclave.
#[derive(Debug, Clone)]
pub struct SeBackend {
    pub mode: StorageMode,
    pub policy: AccessPolicy,
}

impl SeBackend {
    pub fn new(mode: StorageMode, policy: AccessPolicy) -> Self {
        SeBackend { mode, policy }
    }

    /// Create a key: (handle, SEC1 public key).
    pub fn create(&self) -> Result<(Vec<u8>, Vec<u8>), SeError> {
        match self.mode {
            StorageMode::Blob => {
                let k = SecKey::generate(&KeyStorage::Ephemeral, self.policy)?;
                let mut h = vec![HANDLE_BLOB];
                h.extend(k.token_object_blob()?);
                Ok((h, k.public_key_sec1()?))
            }
            StorageMode::Keychain => {
                let mut rnd = [0u8; 16];
                SystemEntropy.fill(&mut rnd);
                let mut tag = TAG_PREFIX.to_vec();
                tag.extend_from_slice(&rnd);
                let k = SecKey::generate(
                    &KeyStorage::Keychain {
                        tag: tag.clone(),
                        data_protection: true,
                    },
                    self.policy,
                )?;
                let mut h = vec![HANDLE_KEYCHAIN];
                h.extend(tag);
                Ok((h, k.public_key_sec1()?))
            }
        }
    }

    pub fn load(&self, handle: &[u8]) -> Result<SecKey, SeError> {
        match handle.split_first() {
            Some((&HANDLE_BLOB, blob)) if self.mode == StorageMode::Blob => {
                SecKey::from_blob_any(blob).map(|(k, _)| k)
            }
            Some((&HANDLE_KEYCHAIN, tag)) => SecKey::find_in_keychain(tag, true),
            _ => Err(SeError::status("load", errSecItemNotFound)),
        }
    }

    pub fn key_exchange(&self, handle: &[u8], peer_sec1: &[u8]) -> Result<Vec<u8>, SeError> {
        self.load(handle)?.ecdh(peer_sec1)
    }
}

impl Backend for SeBackend {
    fn random(&mut self, out: &mut [u8]) {
        SystemEntropy.fill(out);
    }

    fn create_key(
        &mut self,
        _rp_id: &str,
        _user_id: &[u8],
        uv: ctap2::UvPolicy,
    ) -> Result<NewKey, BackendError> {
        let policy = match uv {
            ctap2::UvPolicy::None => AccessPolicy::None,
            ctap2::UvPolicy::Presence => AccessPolicy::UserPresence,
            ctap2::UvPolicy::Biometry => AccessPolicy::BiometryCurrentSet,
        };
        let (handle, sec1) = SeBackend {
            mode: self.mode,
            policy,
        }
        .create()
        .map_err(to_backend)?;
        let public_key = p256::PublicKey::from_sec1_bytes(&sec1)
            .map_err(|_| BackendError::Failed("invalid SE public key".into()))?;
        Ok(NewKey {
            handle: Bytes::from(handle),
            public_key,
        })
    }

    fn sign(&mut self, handle: &[u8], message: &[u8]) -> Result<Vec<u8>, BackendError> {
        self.load(handle)
            .and_then(|k| k.sign(message))
            .map_err(to_backend)
    }

    fn delete_key(&mut self, handle: &[u8]) -> Result<(), BackendError> {
        match handle.split_first() {
            // Blob keys have no state outside the blob; dropping it deletes.
            Some((&HANDLE_BLOB, _)) => Ok(()),
            Some((&HANDLE_KEYCHAIN, tag)) => {
                SecKey::delete_from_keychain(tag, true).map_err(to_backend)
            }
            _ => Err(BackendError::KeyNotFound),
        }
    }
}

const LEGACY_STORE_KEY_HANDLE: &str = "store-key.handle";
const STORE_PEER_PUB: &str = "store-peer.pub";

/// 32-byte credential index key bound to this Mac Secure Enclave.
///
/// The permanent data-protection keychain item holds the private key. Only
/// its peer public key is written to disk.
pub fn storage_key(dir: &Path) -> Result<[u8; 32], SeError> {
    let io = |e: std::io::Error| SeError::plain("storage_key io", e.to_string());
    std::fs::create_dir_all(dir).map_err(io)?;

    let hpath = dir.join(LEGACY_STORE_KEY_HANDLE);
    let ppath = dir.join(STORE_PEER_PUB);
    if hpath.try_exists().map_err(io)? {
        return Err(SeError::plain(
            "storage_key",
            "legacy key handle file is not supported",
        ));
    }

    let canonical_dir = std::fs::canonicalize(dir).map_err(io)?;
    let mut tag = TAG_PREFIX.to_vec();
    tag.extend_from_slice(&Sha256::digest(
        canonical_dir.as_os_str().as_encoded_bytes(),
    ));

    let peer_exists = ppath.try_exists().map_err(io)?;
    let key = match SecKey::find_in_keychain(&tag, true) {
        Ok(key) if peer_exists => key,
        Ok(_) => {
            return Err(SeError::plain(
                "storage_key",
                "keychain key exists without its peer public key",
            ))
        }
        Err(e) if e.code == errSecItemNotFound as i64 && !peer_exists => {
            if dir.join("store/credentials.bin").try_exists().map_err(io)? {
                return Err(SeError::plain(
                    "storage_key",
                    "existing credential index has no storage key",
                ));
            }
            let key = SecKey::generate(
                &KeyStorage::Keychain {
                    tag,
                    data_protection: true,
                },
                AccessPolicy::None,
            )?;
            let peer_secret = loop {
                let mut bytes = [0u8; 32];
                SystemEntropy.fill(&mut bytes);
                if let Ok(secret) = p256::SecretKey::from_slice(&bytes) {
                    break secret;
                }
            };
            let peer = peer_secret
                .public_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec();
            write_public(&ppath, &peer).map_err(io)?;
            key
        }
        Err(e) if e.code == errSecItemNotFound as i64 => {
            return Err(SeError::plain(
                "storage_key",
                "peer public key exists without its keychain key",
            ))
        }
        Err(e) => return Err(e),
    };

    let peer = std::fs::read(&ppath).map_err(io)?;
    let shared = key.ecdh(&peer)?;
    let hk = Hkdf::<Sha256>::new(Some(b"se-fido store v1"), &shared);
    let mut derived = [0u8; 32];
    hk.expand(b"credentials.bin", &mut derived)
        .map_err(|_| SeError::plain("hkdf", "expand failed"))?;
    Ok(derived)
}

fn write_public(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)?;
    f.sync_all()
}
