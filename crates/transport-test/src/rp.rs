//! Relying-party side checks (WebAuthn sections 7.1 and 7.2, the parts an
//! authenticator controls).

use ctap2::cbor::{decode, Value};
use ctap2::{der, Bytes};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::VerifyingKey;
use sha2::{Digest, Sha256};

pub const FLAG_UP: u8 = 0x01;
pub const FLAG_UV: u8 = 0x04;
pub const FLAG_AT: u8 = 0x40;
pub const FLAG_ED: u8 = 0x80;

/// clientDataJSON as a browser would build it, and its SHA-256.
pub fn client_data(kind: &str, challenge_b64url: &str, origin: &str) -> (String, [u8; 32]) {
    let json = format!("{{\"type\":\"{kind}\",\"challenge\":\"{challenge_b64url}\",\"origin\":\"{origin}\",\"crossOrigin\":false}}");
    let hash = Sha256::digest(json.as_bytes()).into();
    (json, hash)
}

pub fn flags_str(f: u8) -> String {
    let mut parts = Vec::new();
    for (bit, name) in [
        (FLAG_UP, "UP"),
        (FLAG_UV, "UV"),
        (FLAG_AT, "AT"),
        (FLAG_ED, "ED"),
    ] {
        if f & bit != 0 {
            parts.push(name);
        }
    }
    if f & !(FLAG_UP | FLAG_UV | FLAG_AT | FLAG_ED) != 0 {
        parts.push("RESERVED");
    }
    if parts.is_empty() {
        "-".into()
    } else {
        parts.join("|")
    }
}

#[derive(Debug, Clone)]
pub struct Registration {
    pub fmt: String,
    pub flags: u8,
    pub counter: u32,
    pub aaguid: Vec<u8>,
    pub cred_id: Vec<u8>,
    /// SEC1 uncompressed.
    pub public_key: Vec<u8>,
    /// "self-valid" for packed self attestation that verified, "none".
    pub attestation: String,
}

fn body(resp: &[u8]) -> Result<Value, String> {
    decode(&Bytes::copy_from_slice(resp)).map_err(|s| format!("response CBOR: {s:?}"))
}

fn check_rp_hash(ad: &[u8], rp_id: &str) -> Result<(), String> {
    if ad.len() < 37 {
        return Err("authData too short".into());
    }
    let h: [u8; 32] = Sha256::digest(rp_id.as_bytes()).into();
    if ad[..32] != h {
        return Err("rpIdHash mismatch".into());
    }
    Ok(())
}

fn verify_sig(public_key: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), String> {
    let vk = VerifyingKey::from_sec1_bytes(public_key).map_err(|_| "invalid public key")?;
    let s = der::decode(sig).ok_or("signature is not strict DER")?;
    vk.verify(msg, &s)
        .map_err(|_| "signature does not verify".to_string())
}

/// Verify an authenticatorMakeCredential response.
pub fn verify_registration(resp: &[u8], rp_id: &str, cdh: &[u8]) -> Result<Registration, String> {
    let v = body(resp)?;
    let fmt = v
        .get(1)
        .ok_or("no fmt")?
        .as_text()
        .map_err(|_| "fmt type")?
        .as_str()
        .to_string();
    let ad = v
        .get(2)
        .ok_or("no authData")?
        .as_bytes()
        .map_err(|_| "authData type")?
        .clone();
    let att = v.get(3).ok_or("no attStmt")?;
    check_rp_hash(&ad, rp_id)?;
    let flags = ad[32];
    let counter = u32::from_be_bytes([ad[33], ad[34], ad[35], ad[36]]);
    if flags & FLAG_AT == 0 || flags & FLAG_UP == 0 {
        return Err("AT and UP flags required".into());
    }
    if ad.len() < 55 {
        return Err("attestedCredentialData truncated".into());
    }
    let aaguid = ad[37..53].to_vec();
    let id_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    let cred_id = ad
        .get(55..55 + id_len)
        .ok_or("credential id truncated")?
        .to_vec();
    let cose_bytes = ad.slice(55 + id_len..ad.len()).ok_or("no COSE key")?;
    let cose = decode(&cose_bytes).map_err(|_| "COSE key is not one CBOR item (trailing data?)")?;
    let int = |k: i64| cose.get(k).and_then(|x| x.as_int().ok());
    if int(1) != Some(2) || int(3) != Some(-7) || int(-1) != Some(1) {
        return Err("COSE key is not EC2/ES256/P-256".into());
    }
    let x = cose.get(-2).and_then(|x| x.as_bytes().ok()).ok_or("no x")?;
    let y = cose.get(-3).and_then(|x| x.as_bytes().ok()).ok_or("no y")?;
    if x.len() != 32 || y.len() != 32 {
        return Err("bad coordinate length".into());
    }
    let mut public_key = vec![4u8];
    public_key.extend_from_slice(x);
    public_key.extend_from_slice(y);
    p256::PublicKey::from_sec1_bytes(&public_key).map_err(|_| "point not on curve")?;
    let attestation = match fmt.as_str() {
        "none" => {
            if !att.as_map().map_err(|_| "attStmt type")?.is_empty() {
                return Err("none attStmt not empty".into());
            }
            "none".to_string()
        }
        "packed" => {
            if att.get_text("x5c").is_some() {
                return Err("unexpected x5c".into());
            }
            if att.get_text("alg").and_then(|a| a.as_int().ok()) != Some(-7) {
                return Err("packed alg is not -7".into());
            }
            let sig = att
                .get_text("sig")
                .and_then(|s| s.as_bytes().ok())
                .ok_or("no sig")?;
            let mut msg = ad.to_vec();
            msg.extend_from_slice(cdh);
            verify_sig(&public_key, &msg, sig)?;
            "self-valid".to_string()
        }
        other => return Err(format!("unknown fmt {other}")),
    };
    Ok(Registration {
        fmt,
        flags,
        counter,
        aaguid,
        cred_id,
        public_key,
        attestation,
    })
}

#[derive(Debug, Clone)]
pub struct Assertion {
    pub cred_id: Vec<u8>,
    pub flags: u8,
    pub counter: u32,
    pub user_id: Option<Vec<u8>>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    pub number_of_credentials: Option<i128>,
}

/// Verify an authenticatorGetAssertion / GetNextAssertion response.
/// `lookup` maps a credential ID to the registered SEC1 public key.
pub fn verify_assertion(
    resp: &[u8],
    rp_id: &str,
    cdh: &[u8],
    lookup: impl Fn(&[u8]) -> Option<Vec<u8>>,
) -> Result<Assertion, String> {
    let v = body(resp)?;
    let cred = v.get(1).ok_or("no credential")?;
    let cred_id = cred
        .get_text("id")
        .and_then(|i| i.as_bytes().ok())
        .ok_or("no credential id")?
        .to_vec();
    if cred
        .get_text("type")
        .and_then(|t| t.as_text().ok())
        .map(|t| t.as_str())
        != Some("public-key")
    {
        return Err("credential type".into());
    }
    let ad = v
        .get(2)
        .ok_or("no authData")?
        .as_bytes()
        .map_err(|_| "authData type")?;
    check_rp_hash(ad, rp_id)?;
    if ad.len() != 37 {
        return Err("assertion authData must be 37 bytes".into());
    }
    let sig = v
        .get(3)
        .ok_or("no signature")?
        .as_bytes()
        .map_err(|_| "signature type")?;
    let public_key = lookup(&cred_id).ok_or("unknown credential")?;
    let mut msg = ad.to_vec();
    msg.extend_from_slice(cdh);
    verify_sig(&public_key, &msg, sig)?;
    let user = v.get(4);
    let text = |k: &str| {
        user.and_then(|u| u.get_text(k))
            .and_then(|t| t.as_text().ok())
            .map(|t| t.as_str().to_string())
    };
    Ok(Assertion {
        cred_id,
        flags: ad[32],
        counter: u32::from_be_bytes([ad[33], ad[34], ad[35], ad[36]]),
        user_id: user
            .and_then(|u| u.get_text("id"))
            .and_then(|i| i.as_bytes().ok())
            .map(|b| b.to_vec()),
        user_name: text("name"),
        user_display_name: text("displayName"),
        number_of_credentials: v.get(5).and_then(|n| n.as_int().ok()),
    })
}
