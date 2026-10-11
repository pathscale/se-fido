//! authenticatorData and COSE key encoding (WebAuthn section 6.1).

use crate::cbor::{bytes, int, to_canonical_vec};
use crate::COSE_ALG_ES256;
use ciborium::value::Value;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::{Digest, Sha256};

pub const FLAG_UP: u8 = 0x01;
pub const FLAG_UV: u8 = 0x04;
pub const FLAG_AT: u8 = 0x40;
pub const FLAG_ED: u8 = 0x80;

pub fn rp_id_hash(rp_id: &str) -> [u8; 32] {
    Sha256::digest(rp_id.as_bytes()).into()
}

/// COSE_Key for an EC2 P-256 ES256 public key:
/// `{1: 2 (kty EC2), 3: -7 (alg ES256), -1: 1 (crv P-256), -2: x, -3: y}`.
pub fn cose_key(pk: &p256::PublicKey) -> Vec<u8> {
    let point = pk.to_encoded_point(false);
    let x = point.x().expect("uncompressed point has x");
    let y = point.y().expect("uncompressed point has y");
    to_canonical_vec(Value::Map(vec![
        (int(1), int(2)),
        (int(3), int(COSE_ALG_ES256)),
        (int(-1), int(1)),
        (int(-2), bytes(x)),
        (int(-3), bytes(y)),
    ]))
}

pub struct AttestedCredential<'a> {
    pub aaguid: &'a [u8; 16],
    pub credential_id: &'a [u8],
    pub cose_key: &'a [u8],
}

/// Serialise authenticatorData. `extensions` must already be CBOR-encoded
/// if present (sets ED).
pub fn build(
    rp_id: &str,
    mut flags: u8,
    sign_count: u32,
    attested: Option<&AttestedCredential<'_>>,
    extensions: Option<&[u8]>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(37 + 18 + 32 + 77);
    out.extend_from_slice(&rp_id_hash(rp_id));
    if attested.is_some() {
        flags |= FLAG_AT;
    }
    if extensions.is_some() {
        flags |= FLAG_ED;
    }
    out.push(flags);
    out.extend_from_slice(&sign_count.to_be_bytes());
    if let Some(a) = attested {
        out.extend_from_slice(a.aaguid);
        out.extend_from_slice(&(a.credential_id.len() as u16).to_be_bytes());
        out.extend_from_slice(a.credential_id);
        out.extend_from_slice(a.cose_key);
    }
    if let Some(e) = extensions {
        out.extend_from_slice(e);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::SecretKey;

    #[test]
    fn layout_without_attested_data() {
        let ad = build("example.com", FLAG_UP, 0x01020304, None, None);
        assert_eq!(ad.len(), 37);
        assert_eq!(&ad[..32], &rp_id_hash("example.com"));
        assert_eq!(ad[32], FLAG_UP);
        assert_eq!(&ad[33..37], &[1, 2, 3, 4]);
    }

    #[test]
    fn layout_with_attested_data_sets_at() {
        let sk = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let ck = cose_key(&sk.public_key());
        let ad = build(
            "a",
            FLAG_UP | FLAG_UV,
            5,
            Some(&AttestedCredential {
                aaguid: &[9; 16],
                credential_id: &[1, 2, 3],
                cose_key: &ck,
            }),
            None,
        );
        assert_eq!(ad[32], FLAG_UP | FLAG_UV | FLAG_AT);
        assert_eq!(&ad[37..53], &[9; 16]);
        assert_eq!(&ad[53..55], &[0, 3]);
        assert_eq!(&ad[55..58], &[1, 2, 3]);
        assert_eq!(&ad[58..], &ck[..]);
    }

    #[test]
    fn cose_key_canonical_layout() {
        let sk = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let ck = cose_key(&sk.public_key());
        // a5 01 02 03 26 20 01 21 58 20 <x> 22 58 20 <y>
        assert_eq!(ck.len(), 77);
        assert_eq!(
            &ck[..10],
            &[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]
        );
        assert_eq!(&ck[42..45], &[0x22, 0x58, 0x20]);
    }
}
