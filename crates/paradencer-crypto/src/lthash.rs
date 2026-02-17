//! Lattice-based incremental hash (LtHash).
//!
//! A 2048-byte hash value composed of 1024 u16 elements that supports
//! incremental updates via element-wise addition and subtraction with
//! wrapping arithmetic. This enables efficient state hashing where
//! individual items can be added or removed without recomputing the
//! entire hash.
//!
//! The lattice hash of an item is computed by hashing its serialized
//! representation with Blake3 in XOF mode to produce 2048 bytes.

use paradencer_constants::crypto::{LTHASH_ELEMENT_COUNT, LTHASH_VALUE_BYTES};

/// Lattice hash value — 2048 bytes stored as 1024 u16 elements.
///
/// Supports incremental hashing via element-wise wrapping u16 arithmetic:
/// - `add`: include a new item in the cumulative hash
/// - `subtract`: remove an item from the cumulative hash
///
/// These operations are commutative and associative, so items can be
/// added and removed in any order.
#[derive(Clone, PartialEq, Eq)]
#[repr(C, align(64))]
pub struct LatticeHashValue {
    elements: [u16; LTHASH_ELEMENT_COUNT],
}

impl LatticeHashValue {
    /// Create a zero-valued lattice hash (identity element for addition).
    pub fn zero() -> Self {
        Self {
            elements: [0u16; LTHASH_ELEMENT_COUNT],
        }
    }

    /// Check if this value is the zero element.
    pub fn is_zero(&self) -> bool {
        self.elements.iter().all(|&e| e == 0)
    }

    /// Add another lattice hash value element-wise with wrapping u16 arithmetic.
    pub fn add(&mut self, other: &Self) {
        for i in 0..LTHASH_ELEMENT_COUNT {
            self.elements[i] = self.elements[i].wrapping_add(other.elements[i]);
        }
    }

    /// Subtract another lattice hash value element-wise with wrapping u16 arithmetic.
    pub fn subtract(&mut self, other: &Self) {
        for i in 0..LTHASH_ELEMENT_COUNT {
            self.elements[i] = self.elements[i].wrapping_sub(other.elements[i]);
        }
    }

    /// View the raw bytes of this value (2048 bytes, little-endian u16 elements).
    pub fn as_bytes(&self) -> &[u8; LTHASH_VALUE_BYTES] {
        // SAFETY: [u16; 1024] and [u8; 2048] have the same size and alignment requirements
        // are met by repr(C, align(64)). u16 is stored in native byte order.
        unsafe { &*(self.elements.as_ptr() as *const [u8; LTHASH_VALUE_BYTES]) }
    }

    /// Get a mutable reference to the raw bytes.
    pub fn as_bytes_mut(&mut self) -> &mut [u8; LTHASH_VALUE_BYTES] {
        unsafe { &mut *(self.elements.as_mut_ptr() as *mut [u8; LTHASH_VALUE_BYTES]) }
    }

    /// Create from raw bytes (2048 bytes interpreted as little-endian u16 elements).
    pub fn from_bytes(bytes: [u8; LTHASH_VALUE_BYTES]) -> Self {
        let mut elements = [0u16; LTHASH_ELEMENT_COUNT];
        for i in 0..LTHASH_ELEMENT_COUNT {
            elements[i] = u16::from_ne_bytes([bytes[i * 2], bytes[i * 2 + 1]]);
        }
        Self { elements }
    }
}

impl std::fmt::Debug for LatticeHashValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Show a compact blake3 hash of the full 2048 bytes for readability
        let digest = crate::blake3::Blake3Hasher::hash(self.as_bytes());
        write!(f, "LatticeHash({:02x}{:02x}..{:02x}{:02x})",
            digest[0], digest[1], digest[30], digest[31])
    }
}

/// Compute the lattice hash contribution of a single account.
///
/// For accounts with non-zero lamports, computes:
///   `Blake3_XOF_2048(lamports || data || executable || owner || pubkey)`
///
/// Zero-lamport accounts produce an all-zero hash and are excluded
/// from the cumulative bank hash.
pub fn hash_account(
    pubkey: &[u8; 32],
    owner: &[u8; 32],
    lamports: u64,
    executable: bool,
    data: &[u8],
) -> LatticeHashValue {
    if lamports == 0 {
        return LatticeHashValue::zero();
    }

    let executable_byte = [if executable { 1u8 } else { 0u8 }];

    let mut hasher = ::blake3::Hasher::new();
    hasher.update(&lamports.to_le_bytes());
    hasher.update(data);
    hasher.update(&executable_byte);
    hasher.update(owner);
    hasher.update(pubkey);

    let mut value = LatticeHashValue::zero();
    let mut reader = hasher.finalize_xof();
    reader.fill(value.as_bytes_mut());
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blake3::Blake3StreamingHasher;

    #[test]
    fn zero_is_zero() {
        let v = LatticeHashValue::zero();
        assert!(v.is_zero());
    }

    #[test]
    fn nonzero_value_not_zero() {
        let mut v = LatticeHashValue::zero();
        v.elements[0] = 1;
        assert!(!v.is_zero());
    }

    #[test]
    fn add_then_subtract_is_zero() {
        let mut accumulator = LatticeHashValue::zero();
        let mut value = LatticeHashValue::zero();
        value.elements[0] = 100;
        value.elements[500] = 65535;
        value.elements[1023] = 42;

        accumulator.add(&value);
        assert!(!accumulator.is_zero());

        accumulator.subtract(&value);
        assert!(accumulator.is_zero());
    }

    #[test]
    fn add_is_commutative() {
        let mut a = LatticeHashValue::zero();
        a.elements[0] = 10;
        a.elements[100] = 200;

        let mut b = LatticeHashValue::zero();
        b.elements[0] = 20;
        b.elements[200] = 300;

        let mut result1 = LatticeHashValue::zero();
        result1.add(&a);
        result1.add(&b);

        let mut result2 = LatticeHashValue::zero();
        result2.add(&b);
        result2.add(&a);

        assert_eq!(result1, result2);
    }

    #[test]
    fn add_wraps_at_u16_max() {
        let mut a = LatticeHashValue::zero();
        a.elements[0] = u16::MAX;

        let mut b = LatticeHashValue::zero();
        b.elements[0] = 1;

        let mut result = a.clone();
        result.add(&b);
        assert_eq!(result.elements[0], 0); // wraps around
    }

    #[test]
    fn subtract_wraps_at_u16_min() {
        let mut a = LatticeHashValue::zero();
        // a.elements[0] = 0

        let mut b = LatticeHashValue::zero();
        b.elements[0] = 1;

        let mut result = a.clone();
        result.subtract(&b);
        assert_eq!(result.elements[0], u16::MAX); // wraps around
    }

    #[test]
    fn bytes_roundtrip() {
        let mut original = LatticeHashValue::zero();
        original.elements[0] = 0x1234;
        original.elements[512] = 0xABCD;
        original.elements[1023] = 0xFF00;

        let bytes = *original.as_bytes();
        let restored = LatticeHashValue::from_bytes(bytes);
        assert_eq!(original, restored);
    }

    #[test]
    fn blake3_xof_produces_2048_bytes() {
        let mut output = [0u8; LTHASH_VALUE_BYTES];
        let mut hasher = Blake3StreamingHasher::new();
        hasher.update(b"test data");
        hasher.finalize_xof(&mut output);

        // Output should not be all zeros
        assert!(output.iter().any(|&b| b != 0));
        assert_eq!(output.len(), LTHASH_VALUE_BYTES);
    }

    #[test]
    fn blake3_xof_deterministic() {
        let mut output1 = [0u8; LTHASH_VALUE_BYTES];
        let mut output2 = [0u8; LTHASH_VALUE_BYTES];

        let mut h1 = Blake3StreamingHasher::new();
        h1.update(b"deterministic");
        h1.finalize_xof(&mut output1);

        let mut h2 = Blake3StreamingHasher::new();
        h2.update(b"deterministic");
        h2.finalize_xof(&mut output2);

        assert_eq!(output1, output2);
    }

    #[test]
    fn blake3_xof_streaming_matches_chunks() {
        use crate::blake3::hash_xof;

        let mut output_streaming = [0u8; LTHASH_VALUE_BYTES];
        let mut hasher = Blake3StreamingHasher::new();
        hasher.update(b"hello ");
        hasher.update(b"world");
        hasher.finalize_xof(&mut output_streaming);

        let mut output_chunks = [0u8; LTHASH_VALUE_BYTES];
        hash_xof(&[b"hello ", b"world"], &mut output_chunks);

        assert_eq!(output_streaming, output_chunks);
    }

    #[test]
    fn debug_format_is_compact() {
        let v = LatticeHashValue::zero();
        let debug = format!("{:?}", v);
        assert!(debug.starts_with("LatticeHash("));
        assert!(debug.len() < 40); // compact representation
    }

    // --- Account hashing tests ---

    fn test_pubkey() -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = 1;
        k[31] = 0xFF;
        k
    }

    fn test_owner() -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = 0x11;
        k[1] = 0x22;
        k
    }

    #[test]
    fn zero_lamport_is_zero_hash() {
        let h = hash_account(&test_pubkey(), &test_owner(), 0, false, b"data");
        assert!(h.is_zero());
    }

    #[test]
    fn nonzero_account_produces_nonzero_hash() {
        let h = hash_account(&test_pubkey(), &test_owner(), 1000, false, b"data");
        assert!(!h.is_zero());
    }

    #[test]
    fn different_lamports_different_hash() {
        let h1 = hash_account(&test_pubkey(), &test_owner(), 1000, false, b"data");
        let h2 = hash_account(&test_pubkey(), &test_owner(), 2000, false, b"data");
        assert_ne!(h1, h2);
    }

    #[test]
    fn different_data_different_hash() {
        let h1 = hash_account(&test_pubkey(), &test_owner(), 1000, false, b"hello");
        let h2 = hash_account(&test_pubkey(), &test_owner(), 1000, false, b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn different_owner_different_hash() {
        let owner2 = [0xAAu8; 32];
        let h1 = hash_account(&test_pubkey(), &test_owner(), 1000, false, b"data");
        let h2 = hash_account(&test_pubkey(), &owner2, 1000, false, b"data");
        assert_ne!(h1, h2);
    }

    #[test]
    fn different_pubkey_different_hash() {
        let pubkey2 = [0xBBu8; 32];
        let h1 = hash_account(&test_pubkey(), &test_owner(), 1000, false, b"data");
        let h2 = hash_account(&pubkey2, &test_owner(), 1000, false, b"data");
        assert_ne!(h1, h2);
    }

    #[test]
    fn executable_flag_affects_hash() {
        let h1 = hash_account(&test_pubkey(), &test_owner(), 1000, false, b"data");
        let h2 = hash_account(&test_pubkey(), &test_owner(), 1000, true, b"data");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_deterministic() {
        let h1 = hash_account(&test_pubkey(), &test_owner(), 5000, true, b"program");
        let h2 = hash_account(&test_pubkey(), &test_owner(), 5000, true, b"program");
        assert_eq!(h1, h2);
    }
}
