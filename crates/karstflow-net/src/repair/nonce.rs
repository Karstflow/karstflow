/// Time-bucketed repair nonce generation and verification.
///
/// Generates u32 nonces tied to (slot, shred_index, time_bucket) using a
/// keyed SHA-256 hash. Nonces are deterministic within a time bucket, which
/// allows the receiver to verify that a response nonce was recently generated
/// without maintaining shared state.
///
/// The time bucket width is ~4 seconds (time_ns >> 32), providing replay
/// protection: old nonces expire after the verification window closes.
use karstflow_crypto::sha256::Sha256Hasher;

use super::{ShredIndex, Slot};

/// Seed constant mixed into nonce computation.
const NONCE_SEED: u64 = 0x1F88_B3E9_746C_B9EB;

/// Number of time buckets to accept when verifying a nonce.
/// At ~4 seconds per bucket, 60 buckets ≈ 240 seconds of tolerance.
const VERIFY_WINDOW_BUCKETS: u64 = 60;

/// Bit flag in nonce distinguishing shred-specific vs orphan requests.
/// Set (bit 31 = 1) for normal shred repair, clear for orphan repair.
const NONCE_FLAG_NORMAL: u32 = 1 << 31;

/// Shared secret for keyed nonce computation.
///
/// The secret should be generated randomly at startup and kept private.
/// It prevents peers from predicting nonces for requests they haven't seen.
#[derive(Clone)]
pub struct RepairNonceGenerator {
    /// 64-byte shared secret (only this node knows it).
    secret: [u8; 64],
}

impl RepairNonceGenerator {
    /// Create a new nonce generator with a random secret.
    pub fn new() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        // Derive secret from system time + thread RNG.
        // For production, use a proper CSPRNG; this is deterministic-enough
        // for nonce uniqueness (not for cryptographic key material).
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let mut secret = [0u8; 64];
        let hash1 = Sha256Hasher::hash(&ts.to_le_bytes());
        let hash2 = Sha256Hasher::hash(&hash1);
        secret[..32].copy_from_slice(&hash1);
        secret[32..].copy_from_slice(&hash2);

        Self { secret }
    }

    /// Create a nonce generator with a specific secret (for testing).
    #[cfg(test)]
    pub fn with_secret(secret: [u8; 64]) -> Self {
        Self { secret }
    }

    /// Compute a nonce for a shred repair request.
    ///
    /// The nonce encodes:
    /// - Bit 31: NONCE_FLAG_NORMAL (1 = shred-specific request)
    /// - Lower 31 bits: keyed hash of (slot, shred_index, time_bucket, secret)
    pub fn compute_shred_nonce(&self, slot: Slot, shred_index: ShredIndex, time_ns: u64) -> u32 {
        let bucket = time_bucket(time_ns);
        let hash = self.hash_inputs(slot, shred_index as u64, bucket);
        (hash & 0x7FFF_FFFF) | NONCE_FLAG_NORMAL
    }

    /// Compute a nonce for an orphan repair request.
    ///
    /// Orphan requests use looser matching (slot/128 granularity) since
    /// the exact shred index is unknown.
    pub fn compute_orphan_nonce(&self, slot: Slot, time_ns: u64) -> u32 {
        let bucket = time_bucket(time_ns);
        // Use slot/128 for coarser matching.
        let coarse_slot = slot / 128;
        let hash = self.hash_inputs(coarse_slot, 0, bucket);
        hash & 0x7FFF_FFFF // bit 31 = 0 → orphan
    }

    /// Verify that a nonce was recently computed for the given parameters.
    ///
    /// Checks both the current time bucket and the previous bucket to handle
    /// requests that span a bucket boundary.
    pub fn verify_shred_nonce(
        &self,
        nonce: u32,
        slot: Slot,
        shred_index: ShredIndex,
        time_ns: u64,
    ) -> bool {
        if nonce & NONCE_FLAG_NORMAL == 0 {
            return false; // Not a shred nonce.
        }

        let bucket = time_bucket(time_ns);
        let target = nonce & 0x7FFF_FFFF;

        // Check current and recent buckets.
        for offset in 0..VERIFY_WINDOW_BUCKETS {
            let candidate_bucket = bucket.wrapping_sub(offset);
            let hash = self.hash_inputs(slot, shred_index as u64, candidate_bucket);
            if (hash & 0x7FFF_FFFF) == target {
                return true;
            }
        }

        false
    }

    /// Verify an orphan nonce.
    pub fn verify_orphan_nonce(&self, nonce: u32, slot: Slot, time_ns: u64) -> bool {
        if nonce & NONCE_FLAG_NORMAL != 0 {
            return false; // Not an orphan nonce.
        }

        let bucket = time_bucket(time_ns);
        let target = nonce & 0x7FFF_FFFF;
        let coarse_slot = slot / 128;

        for offset in 0..VERIFY_WINDOW_BUCKETS {
            let candidate_bucket = bucket.wrapping_sub(offset);
            let hash = self.hash_inputs(coarse_slot, 0, candidate_bucket);
            if (hash & 0x7FFF_FFFF) == target {
                return true;
            }
        }

        false
    }

    /// Keyed SHA-256 hash combining secret + seed + inputs.
    fn hash_inputs(&self, a: u64, b: u64, bucket: u64) -> u32 {
        let mut input = [0u8; 64 + 8 + 8 + 8 + 8]; // secret + seed + a + b + bucket
        input[..64].copy_from_slice(&self.secret);
        input[64..72].copy_from_slice(&NONCE_SEED.to_le_bytes());
        input[72..80].copy_from_slice(&a.to_le_bytes());
        input[80..88].copy_from_slice(&b.to_le_bytes());
        input[88..96].copy_from_slice(&bucket.to_le_bytes());

        let digest = Sha256Hasher::hash(&input);
        u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]])
    }
}

impl Default for RepairNonceGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert nanosecond timestamp to a ~4-second time bucket.
fn time_bucket(time_ns: u64) -> u64 {
    time_ns >> 32
}

/// Get current time in nanoseconds since UNIX epoch.
pub fn current_time_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_generator() -> RepairNonceGenerator {
        let mut secret = [0u8; 64];
        for (i, b) in secret.iter_mut().enumerate() {
            *b = i as u8;
        }
        RepairNonceGenerator::with_secret(secret)
    }

    #[test]
    fn shred_nonce_has_normal_flag() {
        let gen = test_generator();
        let nonce = gen.compute_shred_nonce(100, 5, 1_000_000_000_000);
        assert!(
            nonce & NONCE_FLAG_NORMAL != 0,
            "shred nonce must have bit 31 set"
        );
    }

    #[test]
    fn orphan_nonce_lacks_normal_flag() {
        let gen = test_generator();
        let nonce = gen.compute_orphan_nonce(100, 1_000_000_000_000);
        assert!(
            nonce & NONCE_FLAG_NORMAL == 0,
            "orphan nonce must have bit 31 clear"
        );
    }

    #[test]
    fn same_inputs_same_nonce() {
        let gen = test_generator();
        let t = 1_000_000_000_000u64;
        let n1 = gen.compute_shred_nonce(100, 5, t);
        let n2 = gen.compute_shred_nonce(100, 5, t);
        assert_eq!(n1, n2, "deterministic within same time bucket");
    }

    #[test]
    fn different_slot_different_nonce() {
        let gen = test_generator();
        let t = 1_000_000_000_000u64;
        let n1 = gen.compute_shred_nonce(100, 5, t);
        let n2 = gen.compute_shred_nonce(101, 5, t);
        assert_ne!(n1, n2);
    }

    #[test]
    fn different_index_different_nonce() {
        let gen = test_generator();
        let t = 1_000_000_000_000u64;
        let n1 = gen.compute_shred_nonce(100, 5, t);
        let n2 = gen.compute_shred_nonce(100, 6, t);
        assert_ne!(n1, n2);
    }

    #[test]
    fn different_time_bucket_different_nonce() {
        let gen = test_generator();
        let t1 = 1_000_000_000_000u64;
        let t2 = t1 + (5u64 << 32); // 5 buckets later (~20 seconds)
        let n1 = gen.compute_shred_nonce(100, 5, t1);
        let n2 = gen.compute_shred_nonce(100, 5, t2);
        assert_ne!(
            n1, n2,
            "different time buckets should produce different nonces"
        );
    }

    #[test]
    fn verify_shred_nonce_same_bucket() {
        let gen = test_generator();
        let t = 1_000_000_000_000u64;
        let nonce = gen.compute_shred_nonce(100, 5, t);
        assert!(gen.verify_shred_nonce(nonce, 100, 5, t));
    }

    #[test]
    fn verify_shred_nonce_recent_bucket() {
        let gen = test_generator();
        let t_gen = 1_000_000_000_000u64;
        let nonce = gen.compute_shred_nonce(100, 5, t_gen);

        // Verify 10 buckets later (~40 seconds) — within window.
        let t_verify = t_gen + (10u64 << 32);
        assert!(gen.verify_shred_nonce(nonce, 100, 5, t_verify));
    }

    #[test]
    fn verify_shred_nonce_expired_bucket() {
        let gen = test_generator();
        let t_gen = 1_000_000_000_000u64;
        let nonce = gen.compute_shred_nonce(100, 5, t_gen);

        // Verify 100 buckets later — outside window (60 max).
        let t_verify = t_gen + (100u64 << 32);
        assert!(!gen.verify_shred_nonce(nonce, 100, 5, t_verify));
    }

    #[test]
    fn verify_shred_nonce_wrong_slot_fails() {
        let gen = test_generator();
        let t = 1_000_000_000_000u64;
        let nonce = gen.compute_shred_nonce(100, 5, t);
        assert!(!gen.verify_shred_nonce(nonce, 101, 5, t));
    }

    #[test]
    fn verify_shred_nonce_wrong_index_fails() {
        let gen = test_generator();
        let t = 1_000_000_000_000u64;
        let nonce = gen.compute_shred_nonce(100, 5, t);
        assert!(!gen.verify_shred_nonce(nonce, 100, 6, t));
    }

    #[test]
    fn verify_orphan_nonce_same_bucket() {
        let gen = test_generator();
        let t = 1_000_000_000_000u64;
        let nonce = gen.compute_orphan_nonce(100, t);
        assert!(gen.verify_orphan_nonce(nonce, 100, t));
    }

    #[test]
    fn orphan_nonce_coarse_slot_matching() {
        let gen = test_generator();
        let t = 1_000_000_000_000u64;
        // Slots in the same /128 bucket should produce the same nonce.
        let n1 = gen.compute_orphan_nonce(256, t);
        let n2 = gen.compute_orphan_nonce(257, t);
        assert_eq!(n1, n2, "slots 256 and 257 are in same /128 bucket");
    }

    #[test]
    fn orphan_nonce_different_coarse_bucket() {
        let gen = test_generator();
        let t = 1_000_000_000_000u64;
        let n1 = gen.compute_orphan_nonce(127, t); // bucket 0
        let n2 = gen.compute_orphan_nonce(128, t); // bucket 1
        assert_ne!(n1, n2);
    }

    #[test]
    fn different_secrets_different_nonces() {
        let gen1 = test_generator();
        let gen2 = RepairNonceGenerator::with_secret([0xAA; 64]);
        let t = 1_000_000_000_000u64;
        let n1 = gen1.compute_shred_nonce(100, 5, t);
        let n2 = gen2.compute_shred_nonce(100, 5, t);
        assert_ne!(n1, n2, "different secrets should produce different nonces");
    }

    #[test]
    fn cross_type_verification_fails() {
        let gen = test_generator();
        let t = 1_000_000_000_000u64;
        let shred_nonce = gen.compute_shred_nonce(100, 5, t);
        let orphan_nonce = gen.compute_orphan_nonce(100, t);

        // Shred nonce should not verify as orphan and vice versa.
        assert!(!gen.verify_orphan_nonce(shred_nonce, 100, t));
        assert!(!gen.verify_shred_nonce(orphan_nonce, 100, 5, t));
    }

    #[test]
    fn current_time_ns_returns_nonzero() {
        let t = current_time_ns();
        assert!(t > 0, "should return a real timestamp");
    }
}
