use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

pub fn sha256_hex(b: &[u8]) -> String {
    ctap2::hex(&sha256(b))
}

pub fn unhex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err(format!("odd hex length: {s}"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| format!("bad hex: {s}")))
        .collect()
}

/// Split `a b=c d` into positional words and key=value pairs.
pub struct Args<'a> {
    pub words: Vec<&'a str>,
    pub kv: BTreeMap<&'a str, &'a str>,
}

impl<'a> Args<'a> {
    pub fn parse(tokens: &[&'a str]) -> Self {
        let mut words = Vec::new();
        let mut kv = BTreeMap::new();
        for t in tokens {
            match t.split_once("=") {
                Some((k, v)) => {
                    kv.insert(k, v);
                }
                None => words.push(*t),
            }
        }
        Args { words, kv }
    }

    pub fn flag(&self, w: &str) -> bool {
        self.words.contains(&w)
    }

    pub fn get(&self, k: &str) -> Option<&'a str> {
        self.kv.get(k).copied()
    }

    pub fn num<T: std::str::FromStr>(&self, k: &str) -> Result<Option<T>, String> {
        match self.get(k) {
            None => Ok(None),
            Some(v) => v
                .parse()
                .map(Some)
                .map_err(|_| format!("bad number {k}={v}")),
        }
    }
}

pub fn parse_u32_hex(s: &str) -> Result<u32, String> {
    u32::from_str_radix(s, 16).map_err(|_| format!("bad hex u32 {s}"))
}
