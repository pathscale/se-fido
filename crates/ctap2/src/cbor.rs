//! Minimal CBOR for CTAP2.
//!
//! Decoder: zero copy over [`Bytes`]; byte and text strings are ranges of the
//! input. Definite lengths only, no tags, no floats, unique map keys, nesting
//! limited to [`MAX_DEPTH`]. Lengths are checked against the remaining input
//! before allocating.
//!
//! Encoder: CTAP2 canonical form (shortest heads, definite lengths, map keys
//! sorted by encoded length then bytes).

use crate::bytes::{hex, Bytes, Text};
use crate::Status;
use alloc::vec::Vec;
use core::fmt;

pub const MAX_DEPTH: usize = 16;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Value {
    Unsigned(u64),
    /// Value is `-1 - n`.
    Negative(u64),
    Bytes(Bytes),
    Text(Text),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
    Bool(bool),
    Null,
    Undefined,
}

impl Value {
    pub fn as_int(&self) -> Result<i128, Status> {
        match self {
            Value::Unsigned(n) => Ok(*n as i128),
            Value::Negative(n) => Ok(-1 - *n as i128),
            _ => Err(Status::CborUnexpectedType),
        }
    }

    pub fn as_bytes(&self) -> Result<&Bytes, Status> {
        match self {
            Value::Bytes(b) => Ok(b),
            _ => Err(Status::CborUnexpectedType),
        }
    }

    pub fn as_text(&self) -> Result<&Text, Status> {
        match self {
            Value::Text(t) => Ok(t),
            _ => Err(Status::CborUnexpectedType),
        }
    }

    pub fn as_bool(&self) -> Result<bool, Status> {
        match self {
            Value::Bool(b) => Ok(*b),
            _ => Err(Status::CborUnexpectedType),
        }
    }

    pub fn as_array(&self) -> Result<&[Value], Status> {
        match self {
            Value::Array(a) => Ok(a),
            _ => Err(Status::CborUnexpectedType),
        }
    }

    pub fn as_map(&self) -> Result<&[(Value, Value)], Status> {
        match self {
            Value::Map(m) => Ok(m),
            _ => Err(Status::CborUnexpectedType),
        }
    }

    /// Map lookup by integer key (`None` if not a map or key absent).
    pub fn get(&self, key: i64) -> Option<&Value> {
        let Value::Map(m) = self else { return None };
        m.iter()
            .find(|(k, _)| k.as_int().ok() == Some(key as i128))
            .map(|(_, v)| v)
    }

    /// Map lookup by text key.
    pub fn get_text(&self, key: &str) -> Option<&Value> {
        let Value::Map(m) = self else { return None };
        m.iter()
            .find(|(k, _)| matches!(k, Value::Text(t) if t.as_str() == key))
            .map(|(_, v)| v)
    }
}

/// CBOR diagnostic notation, used by the fixtures.
impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Unsigned(n) => write!(f, "{n}"),
            Value::Negative(n) => write!(f, "{}", -1 - *n as i128),
            Value::Bytes(b) => write!(f, "h\"{}\"", hex(b)),
            Value::Text(t) => write!(f, "{:?}", t.as_str()),
            Value::Array(a) => {
                f.write_str("[")?;
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{v}")?;
                }
                f.write_str("]")
            }
            Value::Map(m) => {
                f.write_str("{")?;
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{k}: {v}")?;
                }
                f.write_str("}")
            }
            Value::Bool(b) => write!(f, "{b}"),
            Value::Null => f.write_str("null"),
            Value::Undefined => f.write_str("undefined"),
        }
    }
}

/// Decode exactly one item spanning the whole buffer.
pub fn decode(buf: &Bytes) -> Result<Value, Status> {
    let mut d = Decoder { buf, pos: 0 };
    let v = d.item(0)?;
    if d.pos != buf.len() {
        return Err(Status::InvalidCbor);
    }
    Ok(v)
}

struct Decoder<'a> {
    buf: &'a Bytes,
    pos: usize,
}

impl Decoder<'_> {
    fn byte(&mut self) -> Result<u8, Status> {
        let b = *self.buf.get(self.pos).ok_or(Status::InvalidCbor)?;
        self.pos += 1;
        Ok(b)
    }

    fn be(&mut self, n: usize) -> Result<u64, Status> {
        let mut v = 0u64;
        for _ in 0..n {
            v = (v << 8) | self.byte()? as u64;
        }
        Ok(v)
    }

    fn arg(&mut self, info: u8) -> Result<u64, Status> {
        match info {
            0..=23 => Ok(info as u64),
            24 => self.be(1),
            25 => self.be(2),
            26 => self.be(4),
            27 => self.be(8),
            _ => Err(Status::InvalidCbor),
        }
    }

    fn remaining(&self) -> u64 {
        (self.buf.len() - self.pos) as u64
    }

    fn take(&mut self, len: u64) -> Result<Bytes, Status> {
        if len > self.remaining() {
            return Err(Status::InvalidCbor);
        }
        let start = self.pos;
        self.pos += len as usize;
        self.buf.slice(start..self.pos).ok_or(Status::InvalidCbor)
    }

    fn item(&mut self, depth: usize) -> Result<Value, Status> {
        if depth > MAX_DEPTH {
            return Err(Status::InvalidCbor);
        }
        let ib = self.byte()?;
        let (major, info) = (ib >> 5, ib & 0x1f);
        match major {
            0 => Ok(Value::Unsigned(self.arg(info)?)),
            1 => Ok(Value::Negative(self.arg(info)?)),
            2 => {
                let n = self.arg(info)?;
                Ok(Value::Bytes(self.take(n)?))
            }
            3 => {
                let n = self.arg(info)?;
                let b = self.take(n)?;
                Text::new(b).map(Value::Text).ok_or(Status::InvalidCbor)
            }
            4 => {
                let n = self.arg(info)?;
                if n > self.remaining() {
                    return Err(Status::InvalidCbor);
                }
                let mut v = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    v.push(self.item(depth + 1)?);
                }
                Ok(Value::Array(v))
            }
            5 => {
                let n = self.arg(info)?;
                if n.saturating_mul(2) > self.remaining() {
                    return Err(Status::InvalidCbor);
                }
                let mut m: Vec<(Value, Value)> = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    let k = self.item(depth + 1)?;
                    if m.iter().any(|(e, _)| *e == k) {
                        return Err(Status::InvalidCbor);
                    }
                    let v = self.item(depth + 1)?;
                    m.push((k, v));
                }
                Ok(Value::Map(m))
            }
            6 => Err(Status::InvalidCbor),
            _ => match info {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Ok(Value::Null),
                23 => Ok(Value::Undefined),
                _ => Err(Status::InvalidCbor),
            },
        }
    }
}

/// Item to encode. Borrows its data.
#[derive(Debug, Clone)]
pub enum Out<'a> {
    Int(i64),
    Bytes(&'a [u8]),
    Text(&'a str),
    Bool(bool),
    Null,
    Array(Vec<Out<'a>>),
    Map(Vec<(Out<'a>, Out<'a>)>),
}

/// Encode in CTAP2 canonical form.
pub fn encode(v: &Out<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    write(v, &mut out);
    out
}

fn head(major: u8, n: u64, out: &mut Vec<u8>) {
    let m = major << 5;
    if n < 24 {
        out.push(m | n as u8);
    } else if n <= 0xff {
        out.push(m | 24);
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(m | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= 0xffff_ffff {
        out.push(m | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

fn write(v: &Out<'_>, out: &mut Vec<u8>) {
    match v {
        Out::Int(i) if *i >= 0 => head(0, *i as u64, out),
        Out::Int(i) => head(1, (-1 - *i) as u64, out),
        Out::Bytes(b) => {
            head(2, b.len() as u64, out);
            out.extend_from_slice(b);
        }
        Out::Text(s) => {
            head(3, s.len() as u64, out);
            out.extend_from_slice(s.as_bytes());
        }
        Out::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
        Out::Null => out.push(0xf6),
        Out::Array(a) => {
            head(4, a.len() as u64, out);
            for x in a {
                write(x, out);
            }
        }
        Out::Map(m) => {
            let mut entries: Vec<(Vec<u8>, &Out<'_>)> =
                m.iter().map(|(k, v)| (encode(k), v)).collect();
            entries.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then_with(|| a.0.cmp(&b.0)));
            head(5, entries.len() as u64, out);
            for (k, v) in entries {
                out.extend_from_slice(&k);
                write(v, out);
            }
        }
    }
}
