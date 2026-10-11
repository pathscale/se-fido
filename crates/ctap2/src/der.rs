//! DER encoding of ECDSA P-256 signatures (SEQUENCE of two INTEGERs), as
//! WebAuthn requires. Strict decoder: minimal lengths and integers only.

use alloc::vec::Vec;
use p256::ecdsa::Signature;

fn push_int(out: &mut Vec<u8>, v: &[u8]) {
    let mut i = 0;
    while i + 1 < v.len() && v[i] == 0 {
        i += 1;
    }
    let v = &v[i..];
    let pad = v[0] & 0x80 != 0;
    out.push(0x02);
    out.push((v.len() + pad as usize) as u8);
    if pad {
        out.push(0);
    }
    out.extend_from_slice(v);
}

pub fn encode(sig: &Signature) -> Vec<u8> {
    let raw = sig.to_bytes();
    let mut body = Vec::with_capacity(70);
    push_int(&mut body, &raw[..32]);
    push_int(&mut body, &raw[32..]);
    let mut out = Vec::with_capacity(72);
    out.push(0x30);
    out.push(body.len() as u8);
    out.extend(body);
    out
}

fn read_int(b: &[u8]) -> Option<(&[u8], &[u8])> {
    if b.len() < 2 || b[0] != 0x02 {
        return None;
    }
    let len = b[1] as usize;
    if len == 0 || len > 33 || b.len() < 2 + len {
        return None;
    }
    let v = &b[2..2 + len];
    if v[0] & 0x80 != 0 {
        return None; // negative
    }
    if len > 1 && v[0] == 0 && v[1] & 0x80 == 0 {
        return None; // non-minimal
    }
    let v = if v[0] == 0 && len > 1 { &v[1..] } else { v };
    if v.len() > 32 {
        return None;
    }
    Some((v, &b[2 + len..]))
}

pub fn decode(der: &[u8]) -> Option<Signature> {
    if der.len() < 8 || der[0] != 0x30 || der[1] as usize != der.len() - 2 || der[1] >= 0x80 {
        return None;
    }
    let (r, rest) = read_int(&der[2..])?;
    let (s, rest) = read_int(rest)?;
    if !rest.is_empty() {
        return None;
    }
    let mut raw = [0u8; 64];
    raw[32 - r.len()..32].copy_from_slice(r);
    raw[64 - s.len()..].copy_from_slice(s);
    Signature::from_slice(&raw).ok()
}
