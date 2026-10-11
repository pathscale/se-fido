//! CBOR helpers: CTAP2 canonical encoding and typed accessors.
//!
//! CTAP2 canonical CBOR (CTAP 2.1 section 8): integers and lengths in the
//! shortest form, definite lengths only, and map keys sorted by their encoded
//! bytes, shorter encodings first, then lexicographically. ciborium already
//! produces shortest-form definite-length output; [`canonicalize`] adds the
//! key ordering.

use crate::Status;
use ciborium::value::{Integer, Value};

/// Recursively sort every map's keys into CTAP2 canonical order.
pub fn canonicalize(v: Value) -> Value {
    match v {
        Value::Map(entries) => {
            let mut keyed: Vec<(Vec<u8>, Value, Value)> = entries
                .into_iter()
                .map(|(k, v)| {
                    let k = canonicalize(k);
                    let kb = encode_raw(&k);
                    (kb, k, canonicalize(v))
                })
                .collect();
            keyed.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then_with(|| a.0.cmp(&b.0)));
            Value::Map(keyed.into_iter().map(|(_, k, v)| (k, v)).collect())
        }
        Value::Array(a) => Value::Array(a.into_iter().map(canonicalize).collect()),
        Value::Tag(t, inner) => Value::Tag(t, Box::new(canonicalize(*inner))),
        other => other,
    }
}

fn encode_raw(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).expect("writing to a Vec cannot fail");
    out
}

/// Encode a value in CTAP2 canonical form.
pub fn to_canonical_vec(v: Value) -> Vec<u8> {
    encode_raw(&canonicalize(v))
}

/// Decode exactly one CBOR item; trailing bytes are rejected.
pub fn decode(bytes: &[u8]) -> Result<Value, Status> {
    let mut rest = bytes;
    let v: Value = ciborium::from_reader(&mut rest).map_err(|_| Status::InvalidCbor)?;
    if !rest.is_empty() {
        return Err(Status::InvalidCbor);
    }
    Ok(v)
}

pub fn int(i: i64) -> Value {
    Value::Integer(Integer::from(i))
}

pub fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

pub fn bytes(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec())
}

/// View of a CBOR map with typed getters that map type errors to CTAP
/// statuses.
pub struct MapView<'a>(pub &'a [(Value, Value)]);

impl<'a> MapView<'a> {
    pub fn from_value(v: &'a Value) -> Result<Self, Status> {
        match v {
            Value::Map(m) => Ok(MapView(m)),
            _ => Err(Status::CborUnexpectedType),
        }
    }

    pub fn get_int_key(&self, key: i64) -> Option<&'a Value> {
        self.0.iter().find_map(|(k, v)| match k {
            Value::Integer(i) if i128::from(*i) == key as i128 => Some(v),
            _ => None,
        })
    }

    pub fn get_text_key(&self, key: &str) -> Option<&'a Value> {
        self.0.iter().find_map(|(k, v)| match k {
            Value::Text(t) if t == key => Some(v),
            _ => None,
        })
    }
}

pub fn as_bytes(v: &Value) -> Result<&[u8], Status> {
    match v {
        Value::Bytes(b) => Ok(b),
        _ => Err(Status::CborUnexpectedType),
    }
}

pub fn as_text(v: &Value) -> Result<&str, Status> {
    match v {
        Value::Text(t) => Ok(t),
        _ => Err(Status::CborUnexpectedType),
    }
}

pub fn as_bool(v: &Value) -> Result<bool, Status> {
    match v {
        Value::Bool(b) => Ok(*b),
        _ => Err(Status::CborUnexpectedType),
    }
}

pub fn as_int(v: &Value) -> Result<i128, Status> {
    match v {
        Value::Integer(i) => Ok(i128::from(*i)),
        _ => Err(Status::CborUnexpectedType),
    }
}

pub fn as_array(v: &Value) -> Result<&[Value], Status> {
    match v {
        Value::Array(a) => Ok(a),
        _ => Err(Status::CborUnexpectedType),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shortest_integer_forms() {
        assert_eq!(to_canonical_vec(int(0)), [0x00]);
        assert_eq!(to_canonical_vec(int(23)), [0x17]);
        assert_eq!(to_canonical_vec(int(24)), [0x18, 24]);
        assert_eq!(to_canonical_vec(int(1000)), [0x19, 0x03, 0xe8]);
        assert_eq!(to_canonical_vec(int(-7)), [0x26]);
        assert_eq!(to_canonical_vec(int(-257)), [0x39, 0x01, 0x00]);
    }

    #[test]
    fn map_keys_sorted_length_first() {
        let v = Value::Map(vec![
            (text("plat"), Value::Bool(false)),
            (text("uv"), Value::Bool(true)),
            (text("rk"), Value::Bool(true)),
            (text("up"), Value::Bool(true)),
        ]);
        let enc = to_canonical_vec(v);
        let dec = decode(&enc).unwrap();
        let keys: Vec<_> = dec
            .as_map()
            .unwrap()
            .iter()
            .map(|(k, _)| k.as_text().unwrap().to_owned())
            .collect();
        assert_eq!(keys, ["rk", "up", "uv", "plat"]);
    }

    #[test]
    fn integer_keys_sorted_positive_before_negative() {
        let v = Value::Map(vec![
            (int(-2), int(0)),
            (int(3), int(0)),
            (int(-1), int(0)),
            (int(1), int(0)),
        ]);
        let enc = to_canonical_vec(v);
        // {1:0, 3:0, -1:0, -2:0}
        assert_eq!(enc, [0xa4, 0x01, 0x00, 0x03, 0x00, 0x20, 0x00, 0x21, 0x00]);
    }

    #[test]
    fn nested_maps_sorted() {
        let v = Value::Map(vec![(
            int(1),
            Value::Map(vec![(text("bb"), int(1)), (text("a"), int(2))]),
        )]);
        let enc = to_canonical_vec(v);
        assert_eq!(
            enc,
            [0xa1, 0x01, 0xa2, 0x61, b'a', 0x02, 0x62, b'b', b'b', 0x01]
        );
    }

    #[test]
    fn decode_rejects_trailing_and_garbage() {
        assert_eq!(decode(&[0x01, 0x02]), Err(Status::InvalidCbor));
        assert_eq!(decode(&[0xa1]), Err(Status::InvalidCbor));
        assert!(decode(&[0xa0]).is_ok());
    }
}
