/// Proof of History (PoH) hashchain builder.
///
/// Provides the core hashchain operations for Solana's Proof of History:
/// - `poh_append`: perform N recursive SHA-256 hashes (slot advancement)
/// - `poh_mixin`: mix in a 32-byte value (transaction/entry recording)
///
/// The PoH hashchain is a sequential SHA-256 chain that provides a
/// cryptographic proof of passage of time between events.
use crate::sha256::{Sha256Hasher, Sha256StreamingHasher};

/// Current state of the PoH hashchain (32-byte SHA-256 hash).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PohState {
    pub hash: [u8; 32],
}

impl PohState {
    /// Create a new PoH state from a 32-byte seed.
    pub fn new(seed: [u8; 32]) -> Self {
        Self { hash: seed }
    }

    /// Create a zeroed PoH state.
    pub fn zero() -> Self {
        Self { hash: [0u8; 32] }
    }
}

/// Perform `n` recursive SHA-256 hash operations on the PoH state.
///
/// Each iteration: `state = SHA256(state)`
///
/// This is the core "tick" operation that advances the hashchain,
/// proving passage of time.
pub fn poh_append(state: &mut PohState, n: u64) {
    for _ in 0..n {
        state.hash = Sha256Hasher::hash(&state.hash);
    }
}

/// Mix in a 32-byte value into the PoH hashchain.
///
/// Computes: `state = SHA256(state || mixin)`
///
/// This records an event (transaction hash, entry hash) into the
/// hashchain, binding it to a specific point in the PoH sequence.
pub fn poh_mixin(state: &mut PohState, mixin: &[u8; 32]) {
    let mut hasher = Sha256StreamingHasher::new();
    hasher.update(&state.hash);
    hasher.update(mixin);
    state.hash = hasher.finalize();
}

/// Verify a PoH hashchain segment.
///
/// Given a starting state, number of ticks, and optional mixins,
/// verify that the chain produces the expected ending state.
pub fn poh_verify(
    start: &PohState,
    ticks_before_mixin: u64,
    mixin: Option<&[u8; 32]>,
    ticks_after_mixin: u64,
    expected_end: &PohState,
) -> bool {
    let mut state = *start;
    poh_append(&mut state, ticks_before_mixin);
    if let Some(m) = mixin {
        poh_mixin(&mut state, m);
    }
    poh_append(&mut state, ticks_after_mixin);
    state == *expected_end
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_append_is_noop() {
        let mut state = PohState::new([42u8; 32]);
        let original = state;
        poh_append(&mut state, 0);
        assert_eq!(state, original);
    }

    #[test]
    fn single_append() {
        let mut state = PohState::new([0u8; 32]);
        poh_append(&mut state, 1);
        // SHA256 of 32 zero bytes
        let expected = Sha256Hasher::hash(&[0u8; 32]);
        assert_eq!(state.hash, expected);
    }

    #[test]
    fn double_append_equals_two_single() {
        let seed = [1u8; 32];
        let mut state_single = PohState::new(seed);
        poh_append(&mut state_single, 1);
        poh_append(&mut state_single, 1);

        let mut state_double = PohState::new(seed);
        poh_append(&mut state_double, 2);

        assert_eq!(state_single, state_double);
    }

    #[test]
    fn mixin_changes_state() {
        let mut state = PohState::new([0u8; 32]);
        let before = state;
        poh_mixin(&mut state, &[1u8; 32]);
        assert_ne!(state, before);
    }

    #[test]
    fn mixin_is_deterministic() {
        let mut s1 = PohState::new([5u8; 32]);
        let mut s2 = PohState::new([5u8; 32]);
        let mixin = [99u8; 32];
        poh_mixin(&mut s1, &mixin);
        poh_mixin(&mut s2, &mixin);
        assert_eq!(s1, s2);
    }

    #[test]
    fn mixin_is_sha256_of_concat() {
        let state = PohState::new([10u8; 32]);
        let mixin = [20u8; 32];

        let mut result = state;
        poh_mixin(&mut result, &mixin);

        // Manual: SHA256(state || mixin)
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&state.hash);
        combined[32..].copy_from_slice(&mixin);
        let expected = Sha256Hasher::hash(&combined);
        assert_eq!(result.hash, expected);
    }

    #[test]
    fn append_then_mixin_differs_from_mixin_then_append() {
        let seed = [7u8; 32];
        let mixin = [42u8; 32];

        let mut s1 = PohState::new(seed);
        poh_append(&mut s1, 3);
        poh_mixin(&mut s1, &mixin);

        let mut s2 = PohState::new(seed);
        poh_mixin(&mut s2, &mixin);
        poh_append(&mut s2, 3);

        assert_ne!(s1, s2);
    }

    #[test]
    fn verify_valid_chain() {
        let start = PohState::new([0u8; 32]);
        let mixin = [1u8; 32];

        let mut end = start;
        poh_append(&mut end, 5);
        poh_mixin(&mut end, &mixin);
        poh_append(&mut end, 3);

        assert!(poh_verify(&start, 5, Some(&mixin), 3, &end));
    }

    #[test]
    fn verify_invalid_chain() {
        let start = PohState::new([0u8; 32]);
        let wrong_end = PohState::new([99u8; 32]);
        assert!(!poh_verify(&start, 5, None, 3, &wrong_end));
    }

    #[test]
    fn verify_no_mixin() {
        let start = PohState::new([50u8; 32]);
        let mut end = start;
        poh_append(&mut end, 10);
        assert!(poh_verify(&start, 10, None, 0, &end));
    }

    #[test]
    fn many_appends() {
        let mut state = PohState::new([0u8; 32]);
        poh_append(&mut state, 1000);
        // Just verify it doesn't panic and produces non-zero
        assert_ne!(state.hash, [0u8; 32]);
    }
}
