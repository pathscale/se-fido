use sha2::{Digest, Sha256};

/// Source of random bytes.
pub trait Entropy {
    fn fill(&mut self, out: &mut [u8]);
}

/// Deterministic generator: block i = SHA-256(label || seed || i).
/// For fixtures only; never for real keys.
#[derive(Debug, Clone)]
pub struct TestDrbg {
    seed: [u8; 32],
    counter: u64,
}

impl TestDrbg {
    pub fn new(seed: [u8; 32]) -> Self {
        TestDrbg { seed, counter: 0 }
    }
}

impl Entropy for TestDrbg {
    fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(32) {
            let block = Sha256::new()
                .chain_update(b"se-fido test drbg")
                .chain_update(self.seed)
                .chain_update(self.counter.to_be_bytes())
                .finalize();
            self.counter += 1;
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
    }
}
