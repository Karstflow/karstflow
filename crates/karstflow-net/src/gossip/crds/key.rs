//! CRDS key: uniquely identifies an entry in the gossip table.
//!
//! Each key combines a value type tag, the originator's public key,
//! and an optional sub-index for value types that allow multiple
//! entries per node (votes, epoch slots, duplicate shred proofs).

use std::hash::{Hash, Hasher};

/// Unique key for a CRDS table entry.
///
/// The key identifies an entry by its value type, the originating
/// node's public key, and an optional sub-index. This allows a
/// single node to publish multiple entries of certain types (e.g.,
/// multiple vote entries with different indices).
#[derive(Debug, Clone, Copy, Eq)]
pub struct CrdsKey {
    /// Value type discriminant (0..13).
    pub value_type: u8,
    /// Public key of the originating node (32 bytes).
    pub origin: [u8; 32],
    /// Sub-index for multi-entry types.
    /// - Vote entries: 8-bit vote index (0..255)
    /// - Epoch slots: 8-bit index (0..255)
    /// - Duplicate shred: 16-bit index (0..65535)
    /// - All other types: always 0
    pub sub_index: u16,
}

impl CrdsKey {
    /// Create a key for a single-entry value type (no sub-index).
    pub fn new(value_type: u8, origin: [u8; 32]) -> Self {
        Self {
            value_type,
            origin,
            sub_index: 0,
        }
    }

    /// Create a key with a sub-index for multi-entry value types.
    pub fn with_index(value_type: u8, origin: [u8; 32], sub_index: u16) -> Self {
        Self {
            value_type,
            origin,
            sub_index,
        }
    }
}

impl PartialEq for CrdsKey {
    fn eq(&self, other: &Self) -> bool {
        self.value_type == other.value_type
            && self.origin == other.origin
            && self.sub_index == other.sub_index
    }
}

impl Hash for CrdsKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u8(self.value_type);
        state.write(&self.origin);
        state.write_u16(self.sub_index);
    }
}

impl std::fmt::Display for CrdsKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let origin_short = bs58::encode(&self.origin).into_string();
        let prefix = if origin_short.len() >= 8 {
            &origin_short[..8]
        } else {
            &origin_short
        };
        if self.sub_index == 0 {
            write!(f, "{}:{}", self.value_type, prefix)
        } else {
            write!(f, "{}:{}:{}", self.value_type, prefix, self.sub_index)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_key_equality() {
        let origin = [1u8; 32];
        let k1 = CrdsKey::new(11, origin);
        let k2 = CrdsKey::new(11, origin);
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_key_inequality_type() {
        let origin = [1u8; 32];
        let k1 = CrdsKey::new(11, origin);
        let k2 = CrdsKey::new(7, origin);
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_key_inequality_origin() {
        let k1 = CrdsKey::new(11, [1u8; 32]);
        let k2 = CrdsKey::new(11, [2u8; 32]);
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_key_with_sub_index() {
        let origin = [1u8; 32];
        let k1 = CrdsKey::with_index(1, origin, 0);
        let k2 = CrdsKey::with_index(1, origin, 1);
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_key_hashmap_usage() {
        let mut map = HashMap::new();
        let origin = [1u8; 32];
        let k1 = CrdsKey::new(11, origin);
        map.insert(k1, 42u64);
        assert_eq!(map.get(&CrdsKey::new(11, origin)), Some(&42));
        assert_eq!(map.get(&CrdsKey::new(7, origin)), None);
    }

    #[test]
    fn test_key_display() {
        let origin = [0u8; 32];
        let k = CrdsKey::new(11, origin);
        let s = format!("{}", k);
        assert!(s.starts_with("11:"));
    }

    #[test]
    fn test_key_display_with_index() {
        let origin = [0u8; 32];
        let k = CrdsKey::with_index(1, origin, 5);
        let s = format!("{}", k);
        assert!(s.contains(":5"));
    }
}
