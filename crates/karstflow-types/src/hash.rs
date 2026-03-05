/// 32-byte cryptographic hash used for blockhashes, transaction signatures,
/// and Merkle tree nodes throughout the Solana protocol.
use serde::{Deserialize, Serialize};
use std::fmt;

pub const HASH_BYTES: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
#[repr(transparent)]
pub struct Hash([u8; HASH_BYTES]);

impl Hash {
    pub const fn new(bytes: [u8; HASH_BYTES]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; HASH_BYTES] {
        &self.0
    }

    pub fn to_bytes(&self) -> [u8; HASH_BYTES] {
        self.0
    }

    pub const fn zeroed() -> Self {
        Self([0u8; HASH_BYTES])
    }

    /// Compute SHA-256 hash of the given data.
    pub fn sha256(data: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        let result = Sha256::digest(data);
        let mut bytes = [0u8; HASH_BYTES];
        bytes.copy_from_slice(&result);
        Self(bytes)
    }

    /// Compute a hash by chaining: SHA-256(previous || data).
    pub fn extend_and_hash(previous: &Hash, data: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(previous.0);
        hasher.update(data);
        let result = hasher.finalize();
        let mut bytes = [0u8; HASH_BYTES];
        bytes.copy_from_slice(&result);
        Self(bytes)
    }

    /// Generate a unique hash (for testing).
    pub fn new_unique() -> Self {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self::sha256(&count.to_le_bytes())
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash(")?;
        for (i, byte) in self.0.iter().enumerate() {
            if i > 0 && i % 4 == 0 {
                write!(f, "_")?;
            }
            write!(f, "{:02x}", byte)?;
        }
        write!(f, ")")
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", bs58::encode(&self.0).into_string())
    }
}

impl From<[u8; HASH_BYTES]> for Hash {
    fn from(bytes: [u8; HASH_BYTES]) -> Self {
        Self(bytes)
    }
}

impl From<Hash> for [u8; HASH_BYTES] {
    fn from(hash: Hash) -> Self {
        hash.0
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_deterministic() {
        let h1 = Hash::sha256(b"hello");
        let h2 = Hash::sha256(b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn sha256_different_inputs() {
        let h1 = Hash::sha256(b"hello");
        let h2 = Hash::sha256(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn extend_and_hash_chains() {
        let h1 = Hash::sha256(b"initial");
        let h2 = Hash::extend_and_hash(&h1, b"extension");
        assert_ne!(h1, h2);

        // Deterministic
        let h3 = Hash::extend_and_hash(&h1, b"extension");
        assert_eq!(h2, h3);
    }

    #[test]
    fn zeroed_is_default() {
        assert_eq!(Hash::zeroed(), Hash::default());
        assert_eq!(Hash::zeroed().0, [0u8; 32]);
    }

    #[test]
    fn roundtrip_bytes() {
        let bytes = [42u8; 32];
        let hash = Hash::new(bytes);
        assert_eq!(hash.to_bytes(), bytes);
        assert_eq!(*hash.as_bytes(), bytes);
    }

    #[test]
    fn from_array() {
        let bytes = [7u8; 32];
        let hash: Hash = bytes.into();
        let back: [u8; 32] = hash.into();
        assert_eq!(bytes, back);
    }

    #[test]
    fn unique_hashes() {
        let h1 = Hash::new_unique();
        let h2 = Hash::new_unique();
        assert_ne!(h1, h2);
    }

    #[test]
    fn display_is_base58() {
        let hash = Hash::zeroed();
        let s = format!("{}", hash);
        assert!(!s.is_empty());
        // Base58 of 32 zero bytes
        assert_eq!(s, "11111111111111111111111111111111");
    }

    #[test]
    fn serde_roundtrip() {
        let hash = Hash::sha256(b"test");
        let encoded = bincode::serialize(&hash).unwrap();
        let decoded: Hash = bincode::deserialize(&encoded).unwrap();
        assert_eq!(hash, decoded);
        // Bincode: should be exactly 32 bytes (fixed size)
        assert_eq!(encoded.len(), 32);
    }
}
