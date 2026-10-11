//! authenticatorData and COSE key encoding (WebAuthn section 6.1).

use crate::cbor::{encode, Out};
use crate::COSE_ALG_ES256;
use alloc::vec::Vec;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::{Digest, Sha256};

pub const FLAG_UP: u8 = 0x01;
pub const FLAG_UV: u8 = 0x04;
pub const FLAG_AT: u8 = 0x40;
pub const FLAG_ED: u8 = 0x80;

pub fn rp_id_hash(rp_id: &str) -> [u8; 32] {
    Sha256::digest(rp_id.as_bytes()).into()
}

/// COSE_Key `{1: 2, 3: -7, -1: 1, -2: x, -3: y}` (EC2, ES256, P-256).
pub fn cose_key(pk: &p256::PublicKey) -> Vec<u8> {
    let point = pk.to_encoded_point(false);
    let x = point.x().map(|x| &x[..]).unwrap_or(&[]);
    let y = point.y().map(|y| &y[..]).unwrap_or(&[]);
    encode(&Out::Map(alloc::vec![
        (Out::Int(1), Out::Int(2)),
        (Out::Int(3), Out::Int(COSE_ALG_ES256)),
        (Out::Int(-1), Out::Int(1)),
        (Out::Int(-2), Out::Bytes(x)),
        (Out::Int(-3), Out::Bytes(y)),
    ]))
}

pub struct AttestedCredential<'a> {
    pub aaguid: &'a [u8; 16],
    pub credential_id: &'a [u8],
    pub cose_key: &'a [u8],
}

/// Serialise authenticatorData. AT and ED flags follow the arguments.
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
