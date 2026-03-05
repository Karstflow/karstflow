/// Equivocation detection for consensus safety.
///
/// Detects when a validator produces conflicting votes for the same slot
/// (voting for two different block hashes at the same slot), which is
/// a protocol violation that threatens consensus safety.
///
/// Equivocation proofs can be used to slash the offending validator's stake.
use karstflow_constants::consensus::MAX_EQUIVOCATION_HISTORY_SLOTS;
use karstflow_storage::Pubkey;
use std::collections::HashMap;

/// Proof that a validator equivocated by voting for conflicting blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EquivocationProof {
    /// The validator that equivocated
    pub validator: Pubkey,
    /// The slot where equivocation occurred
    pub slot: u64,
    /// First block hash voted for
    pub block_hash_a: [u8; 32],
    /// Second (conflicting) block hash voted for
    pub block_hash_b: [u8; 32],
    /// Timestamp when equivocation was detected
    pub detected_at: u64,
}

/// A record of a vote cast by a validator for a specific slot.
#[derive(Debug, Clone)]
struct VoteRecord {
    /// Block hash the validator voted for
    block_hash: [u8; 32],
    /// When the vote was recorded (kept for diagnostic/slashing evidence)
    #[allow(dead_code)]
    timestamp: u64,
}

/// Tracks votes per validator per slot to detect conflicting votes.
#[derive(Debug)]
pub struct EquivocationDetector {
    /// Map of (validator, slot) -> vote record for detecting conflicts
    vote_history: HashMap<(Pubkey, u64), VoteRecord>,
    /// Detected equivocation proofs, keyed by (validator, slot)
    proofs: HashMap<(Pubkey, u64), EquivocationProof>,
    /// Current slot for pruning old history
    current_slot: u64,
    /// Maximum age in slots before history is pruned
    max_history_slots: u64,
}

impl EquivocationDetector {
    pub fn new() -> Self {
        Self {
            vote_history: HashMap::new(),
            proofs: HashMap::new(),
            current_slot: 0,
            max_history_slots: MAX_EQUIVOCATION_HISTORY_SLOTS,
        }
    }

    /// Create a detector with custom history depth.
    pub fn with_history_depth(max_history_slots: u64) -> Self {
        Self {
            vote_history: HashMap::new(),
            proofs: HashMap::new(),
            current_slot: 0,
            max_history_slots,
        }
    }

    /// Record a vote and check for equivocation.
    ///
    /// Returns `Some(EquivocationProof)` if this vote conflicts with a
    /// previously recorded vote from the same validator for the same slot.
    pub fn record_vote(
        &mut self,
        validator: Pubkey,
        slot: u64,
        block_hash: [u8; 32],
        timestamp: u64,
    ) -> Option<EquivocationProof> {
        self.current_slot = self.current_slot.max(slot);

        let key = (validator, slot);

        if let Some(existing) = self.vote_history.get(&key) {
            // Same block hash is not equivocation
            if existing.block_hash == block_hash {
                return None;
            }

            // Different block hash for same slot from same validator = equivocation
            let proof = EquivocationProof {
                validator,
                slot,
                block_hash_a: existing.block_hash,
                block_hash_b: block_hash,
                detected_at: timestamp,
            };

            self.proofs.insert(key, proof.clone());
            return Some(proof);
        }

        // First vote from this validator for this slot
        self.vote_history.insert(
            key,
            VoteRecord {
                block_hash,
                timestamp,
            },
        );

        None
    }

    /// Check if a validator has been detected equivocating at a specific slot.
    pub fn has_equivocated(&self, validator: &Pubkey, slot: u64) -> bool {
        self.proofs.contains_key(&(*validator, slot))
    }

    /// Check if a validator has any equivocation proofs.
    pub fn is_known_equivocator(&self, validator: &Pubkey) -> bool {
        self.proofs.keys().any(|(v, _)| v == validator)
    }

    /// Get an equivocation proof for a specific validator and slot.
    pub fn get_proof(&self, validator: &Pubkey, slot: u64) -> Option<&EquivocationProof> {
        self.proofs.get(&(*validator, slot))
    }

    /// Get all equivocation proofs.
    pub fn all_proofs(&self) -> Vec<&EquivocationProof> {
        self.proofs.values().collect()
    }

    /// Get all equivocation proofs for a specific validator.
    pub fn proofs_for_validator(&self, validator: &Pubkey) -> Vec<&EquivocationProof> {
        self.proofs
            .iter()
            .filter(|((v, _), _)| v == validator)
            .map(|(_, proof)| proof)
            .collect()
    }

    /// Get the number of detected equivocations.
    pub fn equivocation_count(&self) -> usize {
        self.proofs.len()
    }

    /// Get the number of unique equivocating validators.
    pub fn equivocating_validator_count(&self) -> usize {
        let mut unique: Vec<&Pubkey> = self.proofs.keys().map(|(v, _)| v).collect();
        unique.sort_by_key(|p| p.as_bytes());
        unique.dedup();
        unique.len()
    }

    /// Prune vote history and proofs older than the retention window.
    ///
    /// Keeps history for slots >= (current_slot - max_history_slots).
    pub fn prune_old_history(&mut self) {
        let cutoff = self.current_slot.saturating_sub(self.max_history_slots);

        self.vote_history.retain(|(_, slot), _| *slot >= cutoff);
        self.proofs.retain(|(_, slot), _| *slot >= cutoff);
    }

    /// Prune everything below a given root slot.
    pub fn prune_below_root(&mut self, root_slot: u64) {
        self.vote_history.retain(|(_, slot), _| *slot >= root_slot);
        self.proofs.retain(|(_, slot), _| *slot >= root_slot);
    }

    /// Update current slot and optionally trigger pruning.
    pub fn advance_slot(&mut self, slot: u64) {
        if slot > self.current_slot {
            self.current_slot = slot;
            // Prune periodically when we advance far enough
            if self
                .current_slot
                .is_multiple_of((self.max_history_slots / 4).max(1))
            {
                self.prune_old_history();
            }
        }
    }

    /// Get total number of tracked vote records.
    pub fn vote_record_count(&self) -> usize {
        self.vote_history.len()
    }
}

impl Default for EquivocationDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hash(val: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = val;
        h
    }

    #[test]
    fn detector_allows_first_vote() {
        let mut detector = EquivocationDetector::new();
        let validator = Pubkey::new_unique();
        let result = detector.record_vote(validator, 100, make_hash(1), 1000);
        assert!(result.is_none());
        assert_eq!(detector.vote_record_count(), 1);
    }

    #[test]
    fn detector_allows_duplicate_vote_same_hash() {
        let mut detector = EquivocationDetector::new();
        let validator = Pubkey::new_unique();
        let hash = make_hash(1);
        detector.record_vote(validator, 100, hash, 1000);
        let result = detector.record_vote(validator, 100, hash, 1001);
        assert!(result.is_none());
        assert_eq!(detector.equivocation_count(), 0);
    }

    #[test]
    fn detector_catches_equivocation() {
        let mut detector = EquivocationDetector::new();
        let validator = Pubkey::new_unique();
        detector.record_vote(validator, 100, make_hash(1), 1000);
        let result = detector.record_vote(validator, 100, make_hash(2), 1001);
        assert!(result.is_some());
        let proof = result.unwrap();
        assert_eq!(proof.validator, validator);
        assert_eq!(proof.slot, 100);
        assert_eq!(proof.block_hash_a, make_hash(1));
        assert_eq!(proof.block_hash_b, make_hash(2));
    }

    #[test]
    fn detector_allows_different_slots_same_validator() {
        let mut detector = EquivocationDetector::new();
        let validator = Pubkey::new_unique();
        let r1 = detector.record_vote(validator, 100, make_hash(1), 1000);
        let r2 = detector.record_vote(validator, 101, make_hash(2), 1001);
        assert!(r1.is_none());
        assert!(r2.is_none());
        assert_eq!(detector.equivocation_count(), 0);
    }

    #[test]
    fn detector_allows_same_slot_different_validators() {
        let mut detector = EquivocationDetector::new();
        let val1 = Pubkey::new_unique();
        let val2 = Pubkey::new_unique();
        let r1 = detector.record_vote(val1, 100, make_hash(1), 1000);
        let r2 = detector.record_vote(val2, 100, make_hash(2), 1001);
        assert!(r1.is_none());
        assert!(r2.is_none());
        assert_eq!(detector.equivocation_count(), 0);
    }

    #[test]
    fn detector_checks_equivocation_status() {
        let mut detector = EquivocationDetector::new();
        let validator = Pubkey::new_unique();
        detector.record_vote(validator, 100, make_hash(1), 1000);
        detector.record_vote(validator, 100, make_hash(2), 1001);

        assert!(detector.has_equivocated(&validator, 100));
        assert!(!detector.has_equivocated(&validator, 101));
        assert!(detector.is_known_equivocator(&validator));
    }

    #[test]
    fn detector_retrieves_proofs() {
        let mut detector = EquivocationDetector::new();
        let val1 = Pubkey::new_unique();
        let val2 = Pubkey::new_unique();

        detector.record_vote(val1, 100, make_hash(1), 1000);
        detector.record_vote(val1, 100, make_hash(2), 1001);
        detector.record_vote(val2, 200, make_hash(3), 2000);
        detector.record_vote(val2, 200, make_hash(4), 2001);

        assert_eq!(detector.all_proofs().len(), 2);
        assert_eq!(detector.proofs_for_validator(&val1).len(), 1);
        assert_eq!(detector.proofs_for_validator(&val2).len(), 1);
    }

    #[test]
    fn detector_counts_unique_equivocators() {
        let mut detector = EquivocationDetector::new();
        let val1 = Pubkey::new_unique();

        detector.record_vote(val1, 100, make_hash(1), 1000);
        detector.record_vote(val1, 100, make_hash(2), 1001);
        detector.record_vote(val1, 200, make_hash(3), 2000);
        detector.record_vote(val1, 200, make_hash(4), 2001);

        assert_eq!(detector.equivocation_count(), 2);
        assert_eq!(detector.equivocating_validator_count(), 1);
    }

    #[test]
    fn detector_prunes_old_history() {
        let mut detector = EquivocationDetector::with_history_depth(100);
        let validator = Pubkey::new_unique();

        detector.record_vote(validator, 10, make_hash(1), 10);
        detector.record_vote(validator, 10, make_hash(2), 11);
        detector.record_vote(validator, 50, make_hash(3), 50);
        detector.record_vote(validator, 200, make_hash(5), 200);

        assert_eq!(detector.equivocation_count(), 1);
        assert_eq!(detector.vote_record_count(), 3);

        // Advance far enough to prune slot 10 and 50
        detector.current_slot = 200;
        detector.prune_old_history();

        assert_eq!(detector.vote_record_count(), 1); // Only slot 200 remains
        assert_eq!(detector.equivocation_count(), 0); // Proof for slot 10 pruned
    }

    #[test]
    fn detector_prunes_below_root() {
        let mut detector = EquivocationDetector::new();
        let validator = Pubkey::new_unique();

        detector.record_vote(validator, 100, make_hash(1), 100);
        detector.record_vote(validator, 100, make_hash(2), 101);
        detector.record_vote(validator, 200, make_hash(3), 200);

        detector.prune_below_root(150);

        assert!(!detector.has_equivocated(&validator, 100));
        assert_eq!(detector.vote_record_count(), 1);
    }

    #[test]
    fn detector_default_creates_new() {
        let detector = EquivocationDetector::default();
        assert_eq!(detector.equivocation_count(), 0);
        assert_eq!(detector.vote_record_count(), 0);
    }

    #[test]
    fn detector_advance_slot_updates_current() {
        let mut detector = EquivocationDetector::new();
        detector.advance_slot(100);
        assert_eq!(detector.current_slot, 100);
        // Should not go backwards
        detector.advance_slot(50);
        assert_eq!(detector.current_slot, 100);
    }

    #[test]
    fn detector_get_proof_returns_correct_proof() {
        let mut detector = EquivocationDetector::new();
        let validator = Pubkey::new_unique();
        detector.record_vote(validator, 100, make_hash(1), 1000);
        detector.record_vote(validator, 100, make_hash(2), 1001);

        let proof = detector.get_proof(&validator, 100);
        assert!(proof.is_some());
        let proof = proof.unwrap();
        assert_eq!(proof.slot, 100);
        assert_eq!(proof.detected_at, 1001);
    }
}
