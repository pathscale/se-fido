use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::ops::{Deref, Range};

/// Cheap clonable view of a range inside a shared `Arc<[u8]>`.
#[derive(Clone)]
pub struct Bytes {
    buf: Arc<[u8]>,
    start: usize,
    end: usize,
}

impl Bytes {
    pub fn new(buf: Arc<[u8]>) -> Self {
        let end = buf.len();
        Bytes { buf, start: 0, end }
    }

    pub fn empty() -> Self {
        Bytes::new(Arc::from(&[][..]))
    }

    pub fn copy_from_slice(s: &[u8]) -> Self {
        Bytes::new(Arc::from(s))
    }

    /// Sub-range relative to this view; `None` if out of bounds.
    pub fn slice(&self, r: Range<usize>) -> Option<Bytes> {
        if r.start <= r.end && r.end <= self.len() {
            Some(Bytes {
                buf: self.buf.clone(),
                start: self.start + r.start,
                end: self.start + r.end,
            })
        } else {
            None
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf[self.start..self.end]
    }
}

impl Deref for Bytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl PartialEq for Bytes {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for Bytes {}

impl fmt::Debug for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex(self))
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(v: Vec<u8>) -> Self {
        Bytes::new(Arc::from(v))
    }
}

impl From<&[u8]> for Bytes {
    fn from(v: &[u8]) -> Self {
        Bytes::copy_from_slice(v)
    }
}

/// [`Bytes`] known to be valid UTF-8.
#[derive(Clone, PartialEq, Eq)]
pub struct Text(Bytes);

impl Text {
    pub fn new(b: Bytes) -> Option<Text> {
        core::str::from_utf8(&b).ok()?;
        Some(Text(b))
    }

    pub fn as_str(&self) -> &str {
        // Validated in the constructor.
        core::str::from_utf8(&self.0).unwrap_or_default()
    }

    pub fn bytes(&self) -> &Bytes {
        &self.0
    }

    /// Truncate to at most `max` bytes on a char boundary (zero copy).
    pub fn truncated(&self, max: usize) -> Text {
        let s = self.as_str();
        if s.len() <= max {
            return self.clone();
        }
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        Text(self.0.slice(0..end).unwrap_or_else(Bytes::empty))
    }
}

impl From<&str> for Text {
    fn from(s: &str) -> Self {
        Text(Bytes::copy_from_slice(s.as_bytes()))
    }
}

impl fmt::Debug for Text {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), f)
    }
}

impl fmt::Display for Text {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Lowercase hex.
pub fn hex(b: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(DIGITS[(x >> 4) as usize] as char);
        s.push(DIGITS[(x & 15) as usize] as char);
    }
    s
}
