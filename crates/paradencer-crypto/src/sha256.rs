//! SHA256 cryptographic hashing
//!
//! SHA256 is a widely-used cryptographic hash function from the SHA-2 family.
//! While Blake3 is faster, SHA256 is included for legacy compatibility and
//! interoperability with systems that require it.
//!
//! # Performance
//!
//! - Single-threaded: ~500 MB/s
//! - Small messages (<1KB): ~200 MB/s
//!
//! # When to use
//!
//! - Use SHA256 when required for compatibility (Bitcoin, legacy systems)
//! - Use Blake3 for new code (better performance)
//!
//! # Example
//!
//! ```rust
//! use paradencer_crypto::sha256::Sha256Hasher;
//!
//! // One-shot hashing
//! let hash = Sha256Hasher::hash(b"hello world");
//! assert_eq!(hash.len(), 32);
//!
//! // Streaming hashing
//! use paradencer_crypto::sha256::Sha256StreamingHasher;
//! let mut hasher = Sha256StreamingHasher::new();
//! hasher.update(b"hello ");
//! hasher.update(b"world");
//! let hash = hasher.finalize();
//! ```

use crate::{CryptoError, CryptoResult, SHA256_HASH_SIZE};
use sha2::{Digest, Sha256};

/// SHA256 hash output
pub type Sha256Hash = [u8; SHA256_HASH_SIZE];

/// SHA256 hasher for one-shot operations
pub struct Sha256Hasher;

impl Sha256Hasher {
    /// Hash a message in one shot
    ///
    /// This is the most efficient way to hash a complete message.
    pub fn hash(data: &[u8]) -> Sha256Hash {
        let hash = Sha256::digest(data);
        hash.into()
    }

    /// Hash multiple chunks concatenated together
    ///
    /// More efficient than concatenating slices first.
    pub fn hash_chunks(chunks: &[&[u8]]) -> Sha256Hash {
        let mut hasher = Sha256::new();
        for chunk in chunks {
            hasher.update(chunk);
        }
        hasher.finalize().into()
    }

    /// Verify a SHA256 hash
    pub fn verify(data: &[u8], expected_hash: &Sha256Hash) -> bool {
        let actual_hash = Self::hash(data);
        constant_time_eq(&actual_hash, expected_hash)
    }

    /// Double SHA256 hash (hash of hash)
    ///
    /// This is used in Bitcoin and some other systems.
    pub fn hash_double(data: &[u8]) -> Sha256Hash {
        let first_hash = Self::hash(data);
        Self::hash(&first_hash)
    }
}

/// Streaming SHA256 hasher
///
/// Use this for hashing data incrementally or when the full message
/// is not available at once.
pub struct Sha256StreamingHasher {
    hasher: Sha256,
    bytes_hashed: u64,
}

impl Sha256StreamingHasher {
    /// Create a new streaming hasher
    pub fn new() -> Self {
        Self {
            hasher: Sha256::new(),
            bytes_hashed: 0,
        }
    }

    /// Update the hasher with more data
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
        self.bytes_hashed += data.len() as u64;
    }

    /// Update the hasher with multiple chunks
    pub fn update_chunks(&mut self, chunks: &[&[u8]]) {
        for chunk in chunks {
            self.update(chunk);
        }
    }

    /// Finalize the hash and return the result
    ///
    /// This consumes the hasher.
    pub fn finalize(self) -> Sha256Hash {
        self.hasher.finalize().into()
    }

    /// Finalize and return the hash without consuming the hasher
    ///
    /// This allows continuing to update the hasher after getting an
    /// intermediate hash result.
    pub fn finalize_peek(&self) -> Sha256Hash {
        self.hasher.clone().finalize().into()
    }

    /// Reset the hasher to its initial state
    pub fn reset(&mut self) {
        self.hasher.reset();
        self.bytes_hashed = 0;
    }

    /// Get the number of bytes hashed so far
    pub fn bytes_hashed(&self) -> u64 {
        self.bytes_hashed
    }

    /// Finalize and verify against an expected hash
    pub fn finalize_and_verify(self, expected_hash: &Sha256Hash) -> bool {
        let actual_hash = self.finalize();
        constant_time_eq(&actual_hash, expected_hash)
    }
}

impl Default for Sha256StreamingHasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Constant-time equality comparison
///
/// This prevents timing attacks when comparing hashes.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// HMAC-SHA256 for message authentication
///
/// This provides authenticated hashing using a secret key.
pub struct HmacSha256 {
    key: Vec<u8>,
}

impl HmacSha256 {
    /// Create a new HMAC-SHA256 instance with the given key
    pub fn new(key: &[u8]) -> Self {
        Self {
            key: key.to_vec(),
        }
    }

    /// Compute HMAC-SHA256 of the given data
    pub fn compute(&self, data: &[u8]) -> Sha256Hash {
        use sha2::digest::{KeyInit, Mac};
        use sha2::Hmac;

        type HmacSha256Type = Hmac<Sha256>;

        let mut mac = HmacSha256Type::new_from_slice(&self.key)
            .expect("HMAC can take key of any size");
        mac.update(data);
        mac.finalize().into_bytes().into()
    }

    /// Verify HMAC-SHA256 of the given data
    pub fn verify(&self, data: &[u8], expected_mac: &Sha256Hash) -> bool {
        let actual_mac = self.compute(data);
        constant_time_eq(&actual_mac, expected_mac)
    }
}

/// Hash a Solana blockhash
///
/// This is compatible with Solana's blockhash format.
pub fn hash_blockhash(parent_hash: &[u8; 32], slot: u64) -> Sha256Hash {
    let mut hasher = Sha256::new();
    hasher.update(parent_hash);
    hasher.update(&slot.to_le_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hash_basic() {
        let data = b"hello world";
        let hash = Sha256Hasher::hash(data);
        assert_eq!(hash.len(), SHA256_HASH_SIZE);

        // Verify deterministic
        let hash2 = Sha256Hasher::hash(data);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_sha256_hash_empty() {
        let hash = Sha256Hasher::hash(b"");
        assert_eq!(hash.len(), SHA256_HASH_SIZE);

        // Empty string has a known SHA256 hash
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha256_hash_chunks() {
        let chunks = vec![b"hello" as &[u8], b" ", b"world"];
        let hash = Sha256Hasher::hash_chunks(&chunks);

        // Should equal hashing the concatenated data
        let expected = Sha256Hasher::hash(b"hello world");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha256_verify() {
        let data = b"test data";
        let hash = Sha256Hasher::hash(data);

        assert!(Sha256Hasher::verify(data, &hash));
        assert!(!Sha256Hasher::verify(b"wrong data", &hash));
    }

    #[test]
    fn test_sha256_hash_double() {
        let data = b"test";
        let double_hash = Sha256Hasher::hash_double(data);

        // Should equal hash(hash(data))
        let first_hash = Sha256Hasher::hash(data);
        let expected = Sha256Hasher::hash(&first_hash);
        assert_eq!(double_hash, expected);
    }

    #[test]
    fn test_streaming_hasher_basic() {
        let mut hasher = Sha256StreamingHasher::new();
        hasher.update(b"hello ");
        hasher.update(b"world");
        let hash = hasher.finalize();

        // Should equal one-shot hash
        let expected = Sha256Hasher::hash(b"hello world");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_streaming_hasher_empty() {
        let hasher = Sha256StreamingHasher::new();
        let hash = hasher.finalize();

        let expected = Sha256Hasher::hash(b"");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_streaming_hasher_peek() {
        let mut hasher = Sha256StreamingHasher::new();
        hasher.update(b"hello");

        let hash1 = hasher.finalize_peek();
        hasher.update(b" world");
        let hash2 = hasher.finalize();

        // hash1 should be hash of "hello"
        let expected1 = Sha256Hasher::hash(b"hello");
        assert_eq!(hash1, expected1);

        // hash2 should be hash of "hello world"
        let expected2 = Sha256Hasher::hash(b"hello world");
        assert_eq!(hash2, expected2);
    }

    #[test]
    fn test_streaming_hasher_reset() {
        let mut hasher = Sha256StreamingHasher::new();
        hasher.update(b"first");
        hasher.reset();
        hasher.update(b"second");
        let hash = hasher.finalize();

        let expected = Sha256Hasher::hash(b"second");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_streaming_hasher_bytes_hashed() {
        let mut hasher = Sha256StreamingHasher::new();
        assert_eq!(hasher.bytes_hashed(), 0);

        hasher.update(b"hello");
        assert_eq!(hasher.bytes_hashed(), 5);

        hasher.update(b" world");
        assert_eq!(hasher.bytes_hashed(), 11);

        hasher.reset();
        assert_eq!(hasher.bytes_hashed(), 0);
    }

    #[test]
    fn test_streaming_hasher_verify() {
        let mut hasher = Sha256StreamingHasher::new();
        hasher.update(b"test data");
        let expected_hash = Sha256Hasher::hash(b"test data");

        let mut hasher = Sha256StreamingHasher::new();
        hasher.update(b"test data");
        assert!(hasher.finalize_and_verify(&expected_hash));
    }

    #[test]
    fn test_constant_time_eq() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [1u8, 2, 3, 5];
        let d = [1u8, 2, 3];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
        assert!(!constant_time_eq(&a, &d));
    }

    #[test]
    fn test_hmac_sha256() {
        let key = b"secret key";
        let hmac = HmacSha256::new(key);

        let data = b"message to authenticate";
        let mac = hmac.compute(data);
        assert_eq!(mac.len(), SHA256_HASH_SIZE);

        // Verify works
        assert!(hmac.verify(data, &mac));

        // Wrong data fails
        assert!(!hmac.verify(b"wrong message", &mac));

        // Same key and data produce same MAC
        let mac2 = hmac.compute(data);
        assert_eq!(mac, mac2);
    }

    #[test]
    fn test_hmac_sha256_different_keys() {
        let key1 = b"key1";
        let key2 = b"key2";
        let data = b"data";

        let mac1 = HmacSha256::new(key1).compute(data);
        let mac2 = HmacSha256::new(key2).compute(data);

        // Different keys should produce different MACs
        assert_ne!(mac1, mac2);
    }

    #[test]
    fn test_hash_blockhash() {
        let parent_hash = [42u8; 32];
        let slot = 12345u64;

        let hash1 = hash_blockhash(&parent_hash, slot);
        let hash2 = hash_blockhash(&parent_hash, slot);
        assert_eq!(hash1, hash2);

        // Different slot should give different hash
        let hash3 = hash_blockhash(&parent_hash, slot + 1);
        assert_ne!(hash1, hash3);

        // Different parent should give different hash
        let different_parent = [99u8; 32];
        let hash4 = hash_blockhash(&different_parent, slot);
        assert_ne!(hash1, hash4);
    }

    #[test]
    fn test_streaming_update_chunks() {
        let chunks = vec![b"hello" as &[u8], b" ", b"world"];
        let mut hasher = Sha256StreamingHasher::new();
        hasher.update_chunks(&chunks);
        let hash = hasher.finalize();

        let expected = Sha256Hasher::hash(b"hello world");
        assert_eq!(hash, expected);
    }
}
