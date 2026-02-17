use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use thiserror::Error;

pub const PUBKEY_BYTES: usize = 32;
pub const MAX_SEED_LEN: usize = 32;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum PubkeyError {
    #[error("Max seed length exceeded")]
    MaxSeedLengthExceeded,

    #[error("Illegal owner (contains ProgramDerivedAddress marker)")]
    IllegalOwner,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct Pubkey([u8; PUBKEY_BYTES]);

impl Pubkey {
    pub const fn new(bytes: [u8; PUBKEY_BYTES]) -> Self {
        Self(bytes)
    }

    pub const fn new_from_array(bytes: [u8; PUBKEY_BYTES]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; PUBKEY_BYTES] {
        &self.0
    }

    pub fn to_bytes(&self) -> [u8; PUBKEY_BYTES] {
        self.0
    }

    pub const fn zeroed() -> Self {
        Self([0u8; PUBKEY_BYTES])
    }

    pub fn new_unique() -> Self {
        use blake3::Hasher;
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut hasher = Hasher::new();
        hasher.update(b"unique_pubkey");
        hasher.update(&count.to_le_bytes());
        hasher.update(
            &std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
                .to_le_bytes(),
        );
        let hash = hasher.finalize();
        Self(hash.as_bytes()[..PUBKEY_BYTES].try_into().unwrap())
    }

    /// Create a Pubkey from a base pubkey, seed string, and owner pubkey
    ///
    /// Computes: SHA256(base || seed || owner)
    pub fn create_with_seed(
        base: &Pubkey,
        seed: &str,
        owner: &Pubkey,
    ) -> Result<Pubkey, PubkeyError> {
        let seed_bytes = seed.as_bytes();

        // Check seed length
        if seed_bytes.len() > MAX_SEED_LEN {
            return Err(PubkeyError::MaxSeedLengthExceeded);
        }

        // Check that owner doesn't contain ProgramDerivedAddress marker
        // (prevents misuse of create_with_seed for PDA derivation)
        const PDA_MARKER: &[u8] = b"ProgramDerivedAddress";
        if owner.0.len() >= 11 + PDA_MARKER.len() {
            if &owner.0[11..11 + PDA_MARKER.len()] == PDA_MARKER {
                return Err(PubkeyError::IllegalOwner);
            }
        }

        // Compute SHA256(base || seed || owner)
        let mut hasher = Sha256::new();
        hasher.update(&base.0);
        hasher.update(seed_bytes);
        hasher.update(&owner.0);
        let hash = hasher.finalize();

        Ok(Pubkey(hash.into()))
    }
}

impl Default for Pubkey {
    fn default() -> Self {
        Self::zeroed()
    }
}

impl fmt::Debug for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pubkey(")?;
        for (i, byte) in self.0.iter().enumerate() {
            if i > 0 && i % 4 == 0 {
                write!(f, "_")?;
            }
            write!(f, "{:02x}", byte)?;
        }
        write!(f, ")")
    }
}

impl fmt::Display for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", bs58::encode(&self.0).into_string())
    }
}

impl From<[u8; PUBKEY_BYTES]> for Pubkey {
    fn from(bytes: [u8; PUBKEY_BYTES]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Pubkey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_with_seed_basic() {
        let base = Pubkey::new([1u8; 32]);
        let seed = "test_seed";
        let owner = Pubkey::new([2u8; 32]);

        let result = Pubkey::create_with_seed(&base, seed, &owner);
        assert!(result.is_ok());

        // Same inputs should produce same output
        let result2 = Pubkey::create_with_seed(&base, seed, &owner);
        assert_eq!(result.unwrap(), result2.unwrap());
    }

    #[test]
    fn create_with_seed_different_inputs() {
        let base = Pubkey::new([1u8; 32]);
        let owner = Pubkey::new([2u8; 32]);

        let result1 = Pubkey::create_with_seed(&base, "seed1", &owner).unwrap();
        let result2 = Pubkey::create_with_seed(&base, "seed2", &owner).unwrap();

        // Different seeds should produce different outputs
        assert_ne!(result1, result2);
    }

    #[test]
    fn create_with_seed_max_length() {
        let base = Pubkey::new([1u8; 32]);
        let owner = Pubkey::new([2u8; 32]);
        let max_seed = "a".repeat(MAX_SEED_LEN);

        let result = Pubkey::create_with_seed(&base, &max_seed, &owner);
        assert!(result.is_ok());
    }

    #[test]
    fn create_with_seed_exceeds_max_length() {
        let base = Pubkey::new([1u8; 32]);
        let owner = Pubkey::new([2u8; 32]);
        let too_long_seed = "a".repeat(MAX_SEED_LEN + 1);

        let result = Pubkey::create_with_seed(&base, &too_long_seed, &owner);
        assert!(matches!(result, Err(PubkeyError::MaxSeedLengthExceeded)));
    }
}
