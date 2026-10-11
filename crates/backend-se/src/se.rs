use crate::ffi::*;
use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::error::CFError;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use core_foundation_sys::base::{kCFAllocatorDefault, CFRelease, CFTypeRef, OSStatus};
use core_foundation_sys::error::CFErrorRef;
use core_foundation_sys::string::CFStringRef;
use ctap2::{Backend, BackendError, NewKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use std::fmt;
use std::path::Path;
use std::ptr::null_mut;

/// Error from a Security.framework call: the CFError code (an OSStatus for
/// the OSStatus domain), its domain and description.
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

    /// Consumes a CFErrorRef returned by a Security call (create rule).
    fn from_cf(op: &'static str, err: CFErrorRef) -> Self {
        if err.is_null() {
            return SeError::plain(op, "returned NULL without a CFError");
        }
        // SAFETY: Security functions return +1 retained CFErrors.
        let e = unsafe { CFError::wrap_under_create_rule(err) };
        SeError {
            op,
            code: e.code() as i64,
            domain: e.domain().to_string(),
            message: e.description().to_string(),
        }
    }
}

fn to_backend(e: SeError) -> BackendError {
    // -128 = errSecUserCanceled / LAErrorUserCancel style cancellations.
    if e.code == -128 || e.code == -2 {
        BackendError::Cancelled
    } else if e.code == errSecItemNotFound as i64 {
        BackendError::KeyNotFound
    } else {
        BackendError::Failed(e.to_string())
    }
}

fn cfstr(s: CFStringRef) -> CFType {
    // SAFETY: Security framework constants are valid immortal CFStrings.
    unsafe { CFString::wrap_under_get_rule(s) }.as_CFType()
}

fn dict(pairs: &[(CFType, CFType)]) -> CFDictionary<CFType, CFType> {
    CFDictionary::from_CFType_pairs(pairs)
}

/// Who must approve each use of the private key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessPolicy {
    /// No user interaction: any process that can load the key can sign.
    None,
    /// Touch ID or device password for every operation.
    UserPresence,
    /// Touch ID with the currently enrolled fingers only.
    BiometryCurrentSet,
}

fn access_control(policy: AccessPolicy) -> Result<CFType, SeError> {
    let flags = kSecAccessControlPrivateKeyUsage
        | match policy {
            AccessPolicy::None => 0,
            AccessPolicy::UserPresence => kSecAccessControlUserPresence,
            AccessPolicy::BiometryCurrentSet => kSecAccessControlBiometryCurrentSet,
        };
    let mut err = null_mut();
    // SAFETY: valid constant protection class; err is a valid out pointer.
    let ac = unsafe {
        SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly as CFTypeRef,
            flags,
            &mut err,
        )
    };
    if ac.is_null() {
        return Err(SeError::from_cf("SecAccessControlCreateWithFlags", err));
    }
    // SAFETY: +1 retained object from a Create function.
    Ok(unsafe { CFType::wrap_under_create_rule(ac as CFTypeRef) })
}

/// Where a newly created key lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyStorage {
    /// Non-permanent key; persist via [`SecKey::token_object_blob`].
    Ephemeral,
    /// Permanent keychain item identified by `tag`.
    Keychain { tag: Vec<u8>, data_protection: bool },
}

/// How to rebuild a key object from its token-object blob. Which variant
/// macOS accepts is not documented; `se-probe` tests all three.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReloadVariant {
    /// `SecKeyCreateWithData(empty, {..., toid: blob})`
    EmptyDataWithToid,
    /// `SecKeyCreateWithData(blob, {..., toid: blob})`
    BlobDataWithToid,
    /// `SecKeyCreateWithData(blob, {...})` without `toid`. Observed on macOS
    /// 26.5 to return a key object whose public key does NOT match: never use
    /// it to load credentials.
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
pub struct SecKey(SecKeyRef);

impl Drop for SecKey {
    fn drop(&mut self) {
        // SAFETY: we own one reference.
        unsafe { CFRelease(self.0 as CFTypeRef) }
    }
}

const TOID: &str = "toid";

impl SecKey {
    /// Generate a P-256 private key inside the Secure Enclave.
    pub fn generate(storage: &KeyStorage, policy: AccessPolicy) -> Result<SecKey, SeError> {
        let ac = access_control(policy)?;
        let mut priv_pairs = vec![(cfstr(unsafe { kSecAttrAccessControl }), ac)];
        let mut pairs = vec![
            (
                cfstr(unsafe { kSecAttrKeyType }),
                cfstr(unsafe { kSecAttrKeyTypeECSECPrimeRandom }),
            ),
            (
                cfstr(unsafe { kSecAttrKeySizeInBits }),
                CFNumber::from(256i32).as_CFType(),
            ),
            (
                cfstr(unsafe { kSecAttrTokenID }),
                cfstr(unsafe { kSecAttrTokenIDSecureEnclave }),
            ),
        ];
        match storage {
            KeyStorage::Ephemeral => {
                priv_pairs.push((
                    cfstr(unsafe { kSecAttrIsPermanent }),
                    CFBoolean::false_value().as_CFType(),
                ));
            }
            KeyStorage::Keychain {
                tag,
                data_protection,
            } => {
                priv_pairs.push((
                    cfstr(unsafe { kSecAttrIsPermanent }),
                    CFBoolean::true_value().as_CFType(),
                ));
                priv_pairs.push((
                    cfstr(unsafe { kSecAttrApplicationTag }),
                    CFData::from_buffer(tag).as_CFType(),
                ));
                priv_pairs.push((
                    cfstr(unsafe { kSecAttrLabel }),
                    CFString::new("se-fido").as_CFType(),
                ));
                if *data_protection {
                    pairs.push((
                        cfstr(unsafe { kSecUseDataProtectionKeychain }),
                        CFBoolean::true_value().as_CFType(),
                    ));
                }
            }
        }
        pairs.push((
            cfstr(unsafe { kSecPrivateKeyAttrs }),
            dict(&priv_pairs).as_CFType(),
        ));
        let params = dict(&pairs);
        let mut err = null_mut();
        // SAFETY: params is a valid CFDictionary; err is a valid out pointer.
        let k = unsafe { SecKeyCreateRandomKey(params.as_concrete_TypeRef(), &mut err) };
        if k.is_null() {
            return Err(SeError::from_cf("SecKeyCreateRandomKey", err));
        }
        Ok(SecKey(k))
    }

    /// Rebuild a Secure Enclave private key from its token-object blob.
    pub fn from_blob(blob: &[u8], variant: ReloadVariant) -> Result<SecKey, SeError> {
        let mut pairs = vec![
            (
                cfstr(unsafe { kSecAttrKeyType }),
                cfstr(unsafe { kSecAttrKeyTypeECSECPrimeRandom }),
            ),
            (
                cfstr(unsafe { kSecAttrKeyClass }),
                cfstr(unsafe { kSecAttrKeyClassPrivate }),
            ),
            (
                cfstr(unsafe { kSecAttrKeySizeInBits }),
                CFNumber::from(256i32).as_CFType(),
            ),
            (
                cfstr(unsafe { kSecAttrTokenID }),
                cfstr(unsafe { kSecAttrTokenIDSecureEnclave }),
            ),
        ];
        if variant != ReloadVariant::BlobDataNoToid {
            pairs.push((
                CFString::new(TOID).as_CFType(),
                CFData::from_buffer(blob).as_CFType(),
            ));
        }
        let data = if variant == ReloadVariant::EmptyDataWithToid {
            CFData::from_buffer(&[])
        } else {
            CFData::from_buffer(blob)
        };
        let attrs = dict(&pairs);
        let mut err = null_mut();
        // SAFETY: valid CF objects and out pointer.
        let k = unsafe {
            SecKeyCreateWithData(
                data.as_concrete_TypeRef(),
                attrs.as_concrete_TypeRef(),
                &mut err,
            )
        };
        if k.is_null() {
            return Err(SeError::from_cf("SecKeyCreateWithData", err));
        }
        Ok(SecKey(k))
    }

    /// Reload with the variants verified to return the *same* key (see
    /// PLAN.md, se-probe results). `BlobDataNoToid` is deliberately excluded:
    /// on macOS 26.5 it "succeeds" but yields a different key.
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

    /// A software P-256 public key (SEC1 uncompressed) as a SecKey.
    pub fn public_from_sec1(sec1: &[u8]) -> Result<SecKey, SeError> {
        let attrs = dict(&[
            (
                cfstr(unsafe { kSecAttrKeyType }),
                cfstr(unsafe { kSecAttrKeyTypeECSECPrimeRandom }),
            ),
            (
                cfstr(unsafe { kSecAttrKeyClass }),
                cfstr(unsafe { kSecAttrKeyClassPublic }),
            ),
            (
                cfstr(unsafe { kSecAttrKeySizeInBits }),
                CFNumber::from(256i32).as_CFType(),
            ),
        ]);
        let data = CFData::from_buffer(sec1);
        let mut err = null_mut();
        // SAFETY: valid CF objects and out pointer.
        let k = unsafe {
            SecKeyCreateWithData(
                data.as_concrete_TypeRef(),
                attrs.as_concrete_TypeRef(),
                &mut err,
            )
        };
        if k.is_null() {
            return Err(SeError::from_cf("SecKeyCreateWithData(public)", err));
        }
        Ok(SecKey(k))
    }

    /// Look up a permanent key by application tag.
    pub fn find_in_keychain(tag: &[u8], data_protection: bool) -> Result<SecKey, SeError> {
        let mut pairs = vec![
            (cfstr(unsafe { kSecClass }), cfstr(unsafe { kSecClassKey })),
            (
                cfstr(unsafe { kSecAttrApplicationTag }),
                CFData::from_buffer(tag).as_CFType(),
            ),
            (
                cfstr(unsafe { kSecAttrKeyClass }),
                cfstr(unsafe { kSecAttrKeyClassPrivate }),
            ),
            (
                cfstr(unsafe { kSecReturnRef }),
                CFBoolean::true_value().as_CFType(),
            ),
            (
                cfstr(unsafe { kSecMatchLimit }),
                cfstr(unsafe { kSecMatchLimitOne }),
            ),
        ];
        if data_protection {
            pairs.push((
                cfstr(unsafe { kSecUseDataProtectionKeychain }),
                CFBoolean::true_value().as_CFType(),
            ));
        }
        let q = dict(&pairs);
        let mut out: CFTypeRef = std::ptr::null();
        // SAFETY: valid query and out pointer.
        let st = unsafe { SecItemCopyMatching(q.as_concrete_TypeRef(), &mut out) };
        if st != errSecSuccess || out.is_null() {
            return Err(SeError::status("SecItemCopyMatching", st));
        }
        Ok(SecKey(out as SecKeyRef))
    }

    /// Delete permanent keys with this application tag.
    pub fn delete_from_keychain(tag: &[u8], data_protection: bool) -> Result<(), SeError> {
        let mut pairs = vec![
            (cfstr(unsafe { kSecClass }), cfstr(unsafe { kSecClassKey })),
            (
                cfstr(unsafe { kSecAttrApplicationTag }),
                CFData::from_buffer(tag).as_CFType(),
            ),
        ];
        if data_protection {
            pairs.push((
                cfstr(unsafe { kSecUseDataProtectionKeychain }),
                CFBoolean::true_value().as_CFType(),
            ));
        }
        let q = dict(&pairs);
        // SAFETY: valid query.
        let st = unsafe { SecItemDelete(q.as_concrete_TypeRef()) };
        if st != errSecSuccess {
            return Err(SeError::status("SecItemDelete", st));
        }
        Ok(())
    }

    /// SEC1 uncompressed public key (65 bytes).
    pub fn public_key_sec1(&self) -> Result<Vec<u8>, SeError> {
        // SAFETY: self.0 is a valid key.
        let pk = unsafe { SecKeyCopyPublicKey(self.0) };
        if pk.is_null() {
            return Err(SeError::plain("SecKeyCopyPublicKey", "returned NULL"));
        }
        let pk = SecKey(pk);
        let mut err = null_mut();
        // SAFETY: valid key and out pointer.
        let d = unsafe { SecKeyCopyExternalRepresentation(pk.0, &mut err) };
        if d.is_null() {
            return Err(SeError::from_cf("SecKeyCopyExternalRepresentation", err));
        }
        // SAFETY: +1 retained CFData.
        Ok(unsafe { CFData::wrap_under_create_rule(d) }
            .bytes()
            .to_vec())
    }

    /// ECDSA P-256 over SHA-256(message); DER-encoded signature.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SeError> {
        let data = CFData::from_buffer(message);
        let mut err = null_mut();
        // SAFETY: valid key, algorithm constant, data and out pointer.
        let sig = unsafe {
            SecKeyCreateSignature(
                self.0,
                kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
                data.as_concrete_TypeRef(),
                &mut err,
            )
        };
        if sig.is_null() {
            return Err(SeError::from_cf("SecKeyCreateSignature", err));
        }
        // SAFETY: +1 retained CFData.
        Ok(unsafe { CFData::wrap_under_create_rule(sig) }
            .bytes()
            .to_vec())
    }

    /// Raw ECDH shared secret (x coordinate) with a SEC1 public key.
    pub fn ecdh(&self, peer_sec1: &[u8]) -> Result<Vec<u8>, SeError> {
        let peer = SecKey::public_from_sec1(peer_sec1)?;
        let params = dict(&[]);
        let mut err = null_mut();
        // SAFETY: valid keys, constant algorithm, params and out pointer.
        let r = unsafe {
            SecKeyCopyKeyExchangeResult(
                self.0,
                kSecKeyAlgorithmECDHKeyExchangeStandard,
                peer.0,
                params.as_concrete_TypeRef(),
                &mut err,
            )
        };
        if r.is_null() {
            return Err(SeError::from_cf("SecKeyCopyKeyExchangeResult", err));
        }
        // SAFETY: +1 retained CFData.
        Ok(unsafe { CFData::wrap_under_create_rule(r) }
            .bytes()
            .to_vec())
    }

    /// Attribute names with a short value summary (diagnostics only; no
    /// key material is printed, data values are shown by length).
    pub fn attribute_summary(&self) -> Vec<(String, String)> {
        // SAFETY: valid key; returns +1 dictionary or NULL.
        let d = unsafe { SecKeyCopyAttributes(self.0) };
        if d.is_null() {
            return Vec::new();
        }
        // SAFETY: +1 retained CFDictionary.
        let d: CFDictionary<CFType, CFType> = unsafe { CFDictionary::wrap_under_create_rule(d) };
        let (keys, values) = d.get_keys_and_values();
        let mut out = Vec::new();
        for (k, v) in keys.into_iter().zip(values) {
            // SAFETY: entries are valid CF objects owned by the dictionary.
            let k = unsafe { CFType::wrap_under_get_rule(k) };
            let v = unsafe { CFType::wrap_under_get_rule(v) };
            let name = k
                .downcast::<CFString>()
                .map(|s| s.to_string())
                .unwrap_or_else(|| "?".into());
            let summary = match v.downcast::<CFData>() {
                Some(data) => format!("data[{}]", data.len()),
                None => {
                    let s = format!("{v:?}");
                    if s.len() > 60 {
                        format!(
                            "{}…",
                            &s[..s.char_indices().nth(60).map_or(s.len(), |(i, _)| i)]
                        )
                    } else {
                        s
                    }
                }
            };
            out.push((name, summary));
        }
        out.sort();
        out
    }

    /// The SE-encrypted token object (`toid` attribute), if present.
    pub fn token_object_blob(&self) -> Result<Vec<u8>, SeError> {
        // SAFETY: valid key.
        let d = unsafe { SecKeyCopyAttributes(self.0) };
        if d.is_null() {
            return Err(SeError::plain("SecKeyCopyAttributes", "returned NULL"));
        }
        // SAFETY: +1 retained CFDictionary.
        let d: CFDictionary<CFType, CFType> = unsafe { CFDictionary::wrap_under_create_rule(d) };
        let (keys, values) = d.get_keys_and_values();
        for (k, v) in keys.into_iter().zip(values) {
            // SAFETY: entries owned by the dictionary.
            let k = unsafe { CFType::wrap_under_get_rule(k) };
            if k.downcast::<CFString>()
                .is_some_and(|s| s == TOID)
            {
                let v = unsafe { CFType::wrap_under_get_rule(v) };
                return v
                    .downcast::<CFData>()
                    .map(|d| d.bytes().to_vec())
                    .ok_or_else(|| SeError::plain("toid", "attribute is not CFData"));
            }
        }
        Err(SeError::plain("toid", "attribute not present"))
    }
}

/// How the backend persists keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageMode {
    /// Token-object blob stored in the credential handle (works unsigned; see PLAN.md).
    Blob,
    /// Permanent data-protection keychain item (needs an entitlement).
    Keychain,
}

const HANDLE_BLOB: u8 = 0x01;
const HANDLE_KEYCHAIN: u8 = 0x02;
const TAG_PREFIX: &[u8] = b"se-fido:";

/// [`ctap2::Backend`] backed by the Secure Enclave.
#[derive(Debug, Clone)]
pub struct SeBackend {
    pub mode: StorageMode,
    pub policy: AccessPolicy,
}

impl SeBackend {
    pub fn new(mode: StorageMode, policy: AccessPolicy) -> Self {
        SeBackend { mode, policy }
    }

    /// Create a key and return (backend handle, SEC1 public key).
    pub fn create(&self) -> Result<(Vec<u8>, Vec<u8>), SeError> {
        match self.mode {
            StorageMode::Blob => {
                let k = SecKey::generate(&KeyStorage::Ephemeral, self.policy)?;
                let blob = k.token_object_blob()?;
                let mut h = vec![HANDLE_BLOB];
                h.extend(blob);
                Ok((h, k.public_key_sec1()?))
            }
            StorageMode::Keychain => {
                let mut tag = TAG_PREFIX.to_vec();
                let mut rnd = [0u8; 16];
                OsRng.fill_bytes(&mut rnd);
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

    /// Load the private key for a handle produced by [`SeBackend::create`].
    pub fn load(&self, handle: &[u8]) -> Result<SecKey, SeError> {
        match handle.split_first() {
            Some((&HANDLE_BLOB, blob)) => SecKey::from_blob_any(blob).map(|(k, _)| k),
            Some((&HANDLE_KEYCHAIN, tag)) => SecKey::find_in_keychain(tag, true),
            _ => Err(SeError::status("load", errSecItemNotFound)),
        }
    }

    /// ECDH between the handle's private key and a SEC1 public key.
    pub fn key_exchange(&self, handle: &[u8], peer_sec1: &[u8]) -> Result<Vec<u8>, SeError> {
        self.load(handle)?.ecdh(peer_sec1)
    }
}

impl Backend for SeBackend {
    fn create_key(&mut self, _rp_id: &str, _user_id: &[u8]) -> Result<NewKey, BackendError> {
        let (handle, sec1) = self.create().map_err(to_backend)?;
        let public_key = p256::PublicKey::from_sec1_bytes(&sec1).map_err(|_| {
            BackendError::Failed("Secure Enclave returned an invalid public key".into())
        })?;
        Ok(NewKey { handle, public_key })
    }

    fn sign(&mut self, handle: &[u8], message: &[u8]) -> Result<Vec<u8>, BackendError> {
        self.load(handle)
            .and_then(|k| k.sign(message))
            .map_err(to_backend)
    }

    fn delete_key(&mut self, handle: &[u8]) -> Result<(), BackendError> {
        match handle.split_first() {
            // A blob-mode key has no state outside the blob; forgetting the
            // blob (the store does that) is the deletion.
            Some((&HANDLE_BLOB, _)) => Ok(()),
            Some((&HANDLE_KEYCHAIN, tag)) => {
                SecKey::delete_from_keychain(tag, true).map_err(to_backend)
            }
            _ => Err(BackendError::KeyNotFound),
        }
    }
}

const STORE_KEY_HANDLE: &str = "store-key.handle";
const STORE_PEER_PUB: &str = "store-peer.pub";

/// Derive the 32-byte credential-index key from a Secure Enclave key.
///
/// On first use this creates a Secure Enclave key (no user prompt) and a
/// throw-away software key pair whose public half is saved; the index key is
/// `HKDF-SHA256(ECDH(se_private, peer_public))`. Only this Mac's Secure
/// Enclave can recompute it. Losing `store-key.handle` makes the index
/// unreadable (the credentials are lost, by design no backup).
pub fn storage_key(dir: &Path) -> Result<[u8; 32], SeError> {
    let io = |e: std::io::Error| SeError::plain("storage_key io", e.to_string());
    std::fs::create_dir_all(dir).map_err(io)?;
    let backend = SeBackend::new(StorageMode::Blob, AccessPolicy::None);
    let hpath = dir.join(STORE_KEY_HANDLE);
    let ppath = dir.join(STORE_PEER_PUB);
    let (handle, peer) = if hpath.exists() && ppath.exists() {
        (
            std::fs::read(&hpath).map_err(io)?,
            std::fs::read(&ppath).map_err(io)?,
        )
    } else {
        let (handle, _) = backend.create()?;
        let peer_secret = p256::SecretKey::random(&mut OsRng);
        let peer = p256::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(
            &peer_secret.public_key(),
            false,
        )
        .as_bytes()
        .to_vec();
        write_private(&hpath, &handle).map_err(io)?;
        write_private(&ppath, &peer).map_err(io)?;
        (handle, peer)
    };
    let shared = backend.key_exchange(&handle, &peer)?;
    let hk = Hkdf::<Sha256>::new(Some(b"se-fido store v1"), &shared);
    let mut key = [0u8; 32];
    hk.expand(b"credentials.bin", &mut key)
        .map_err(|_| SeError::plain("hkdf", "expand failed"))?;
    Ok(key)
}

fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_prefixes_are_distinct() {
        assert_ne!(HANDLE_BLOB, HANDLE_KEYCHAIN);
        let b = SeBackend::new(StorageMode::Blob, AccessPolicy::None);
        assert!(b.load(&[]).is_err());
        assert!(b.load(&[0x7f, 1, 2]).is_err());
    }

    #[test]
    fn delete_unknown_handle() {
        let mut b = SeBackend::new(StorageMode::Blob, AccessPolicy::None);
        assert_eq!(b.delete_key(&[0x7f]), Err(BackendError::KeyNotFound));
        assert_eq!(b.delete_key(&[HANDLE_BLOB, 1, 2]), Ok(()));
    }

    #[test]
    fn software_public_key_import() {
        // Pure Security.framework software-key path; does not touch the SE.
        let sk = p256::SecretKey::from_slice(&[3u8; 32]).unwrap();
        let sec1 =
            p256::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&sk.public_key(), false);
        let k = SecKey::public_from_sec1(sec1.as_bytes()).unwrap();
        assert_eq!(k.public_key_sec1().unwrap(), sec1.as_bytes());
    }

    /// Uses the real Secure Enclave without any prompt (AccessPolicy::None,
    /// blob mode). Opt-in: `cargo test -p backend-se -- --ignored`.
    #[test]
    #[ignore]
    fn se_blob_roundtrip_and_storage_key() {
        use p256::ecdsa::signature::Verifier;
        let mut b = SeBackend::new(StorageMode::Blob, AccessPolicy::None);
        let k = b.create_key("example.com", b"u").unwrap();
        let sig = b.sign(&k.handle, b"hello").unwrap();
        let vk = p256::ecdsa::VerifyingKey::from(k.public_key);
        vk.verify(b"hello", &p256::ecdsa::Signature::from_der(&sig).unwrap())
            .unwrap();
        let d = tempfile::tempdir().unwrap();
        let k1 = storage_key(d.path()).unwrap();
        let k2 = storage_key(d.path()).unwrap();
        assert_eq!(k1, k2, "storage key must be reproducible");
        let d2 = tempfile::tempdir().unwrap();
        assert_ne!(storage_key(d2.path()).unwrap(), k1);
    }
}
