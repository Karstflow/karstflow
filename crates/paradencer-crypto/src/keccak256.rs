//! Keccak-256 hashing operations.
//!
//! Provides single-shot, multi-input, and streaming Keccak-256 hash
//! computation used for Ethereum-compatible message hashing and
//! address derivation.

use tiny_keccak::{Hasher, Keccak};

/// Size of a Keccak-256 digest in bytes.
pub const DIGEST_SIZE: usize = 32;

/// Compute the Keccak-256 hash of a single input.
pub fn hash(data: &[u8]) -> [u8; DIGEST_SIZE] {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut output = [0u8; DIGEST_SIZE];
    hasher.finalize(&mut output);
    output
}

/// Compute the Keccak-256 hash of multiple concatenated inputs.
///
/// This is more efficient than concatenating the slices first because
/// it feeds each slice directly into the hasher state.
pub fn hash_many(slices: &[&[u8]]) -> [u8; DIGEST_SIZE] {
    let mut hasher = Keccak::v256();
    for slice in slices {
        hasher.update(slice);
    }
    let mut output = [0u8; DIGEST_SIZE];
    hasher.finalize(&mut output);
    output
}

/// Streaming Keccak-256 hasher for incremental input.
///
/// Use this when data arrives in chunks or when the full input
/// is not available at once.
pub struct StreamingHasher {
    inner: Keccak,
}

impl StreamingHasher {
    /// Create a new streaming Keccak-256 hasher.
    pub fn new() -> Self {
        Self {
            inner: Keccak::v256(),
        }
    }

    /// Feed additional data into the hasher.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalize the hash and return the digest.
    ///
    /// Consumes the hasher; create a new one for another hash.
    pub fn finalize(self) -> [u8; DIGEST_SIZE] {
        let mut output = [0u8; DIGEST_SIZE];
        self.inner.finalize(&mut output);
        output
    }
}

impl Default for StreamingHasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_produces_known_digest() {
        // Keccak-256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        let digest = hash(b"");
        let expected: [u8; 32] = [
            0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7,
            0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04,
            0x5d, 0x85, 0xa4, 0x70,
        ];
        assert_eq!(digest, expected);
    }

    #[test]
    fn known_test_vector_abc() {
        // Keccak-256("abc") = 4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
        let digest = hash(b"abc");
        let expected: [u8; 32] = [
            0x4e, 0x03, 0x65, 0x7a, 0xea, 0x45, 0xa9, 0x4f, 0xc7, 0xd4, 0x7b, 0xa8, 0x26, 0xc8,
            0xd6, 0x67, 0xc0, 0xd1, 0xe6, 0xe3, 0x3a, 0x64, 0xa0, 0x36, 0xec, 0x44, 0xf5, 0x8f,
            0xa1, 0x2d, 0x6c, 0x45,
        ];
        assert_eq!(digest, expected);
    }

    #[test]
    fn hash_many_matches_concatenated() {
        let part1 = b"hello";
        let part2 = b" ";
        let part3 = b"world";
        let combined = b"hello world";

        let multi_digest = hash_many(&[part1.as_ref(), part2.as_ref(), part3.as_ref()]);
        let single_digest = hash(combined);

        assert_eq!(multi_digest, single_digest);
    }

    #[test]
    fn streaming_matches_single_shot() {
        let data = b"streaming keccak test data";

        let single = hash(data);

        let mut hasher = StreamingHasher::new();
        hasher.update(&data[..10]);
        hasher.update(&data[10..]);
        let streamed = hasher.finalize();

        assert_eq!(single, streamed);
    }

    #[test]
    fn different_inputs_produce_different_digests() {
        let d1 = hash(b"input one");
        let d2 = hash(b"input two");
        assert_ne!(d1, d2);
    }
}
