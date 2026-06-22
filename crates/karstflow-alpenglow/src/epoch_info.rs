//! Validator-set snapshot for one epoch.
//!
//! Part of the Alpenglow consensus engine port. The read-mostly validator list
//! (indexed by validator id), total stake, round-robin leader schedule, and
//! quorum predicates. Networking fields of the Rust `ValidatorInfo` are omitted
//! — they belong to the tile fabric, not the consensus core. The flat
//! contiguous C layout is replaced by an idiomatic `Vec`.

use crate::aggsig::PublicKey;
use crate::base::{
    is_quorum, is_strong_quorum, is_weak_quorum, is_weakest_quorum, SLOTS_PER_WINDOW,
};

/// Consensus-relevant fields of a validator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatorInfo {
    /// Validator index; must equal the position in [`EpochInfo`].
    pub id: u64,
    /// Stake weight.
    pub stake: u64,
    /// Ed25519 identity key (block / shred signatures).
    pub pubkey: [u8; 32],
    /// BLS voting key (vote aggregation).
    pub voting_pubkey: PublicKey,
}

/// Shared validator-set snapshot for one epoch.
#[derive(Clone, Debug)]
pub struct EpochInfo {
    validators: Vec<ValidatorInfo>,
    total_stake: u64,
}

impl EpochInfo {
    /// Build from the canonical validator list. Panics if `validators[i].id != i`
    /// (mirrors `EpochInfo::new`) or the list is empty. Sums total stake.
    pub fn new(validators: Vec<ValidatorInfo>) -> Self {
        assert!(
            !validators.is_empty(),
            "epoch must have at least one validator"
        );
        let mut total: u64 = 0;
        for (i, v) in validators.iter().enumerate() {
            assert_eq!(v.id, i as u64, "validator id must equal index");
            total = total.saturating_add(v.stake);
        }
        Self {
            validators,
            total_stake: total,
        }
    }

    /// Number of validators.
    pub fn validator_cnt(&self) -> u64 {
        self.validators.len() as u64
    }

    /// Total stake across the epoch.
    pub fn total_stake(&self) -> u64 {
        self.total_stake
    }

    /// The validator array.
    pub fn validators(&self) -> &[ValidatorInfo] {
        &self.validators
    }

    /// Validator info for index `id`.
    pub fn validator(&self, id: u64) -> &ValidatorInfo {
        &self.validators[id as usize]
    }

    /// Leader for `slot` (round-robin over windows by validator index).
    pub fn leader(&self, slot: u64) -> &ValidatorInfo {
        let window = slot / SLOTS_PER_WINDOW;
        let leader_id = window % self.validators.len() as u64;
        &self.validators[leader_id as usize]
    }

    /// `true` iff `stake` is at least a weakest quorum (20%).
    pub fn is_weakest_quorum(&self, stake: u64) -> bool {
        is_weakest_quorum(stake, self.total_stake)
    }
    /// `true` iff `stake` is at least a weak quorum (40%).
    pub fn is_weak_quorum(&self, stake: u64) -> bool {
        is_weak_quorum(stake, self.total_stake)
    }
    /// `true` iff `stake` is at least a standard quorum (60%).
    pub fn is_quorum(&self, stake: u64) -> bool {
        is_quorum(stake, self.total_stake)
    }
    /// `true` iff `stake` is at least a strong quorum (80%).
    pub fn is_strong_quorum(&self, stake: u64) -> bool {
        is_strong_quorum(stake, self.total_stake)
    }
}

#[cfg(test)]
pub(crate) fn test_epoch(stakes: &[u64]) -> EpochInfo {
    use crate::aggsig::SecretKey;
    let validators = stakes
        .iter()
        .enumerate()
        .map(|(i, &stake)| ValidatorInfo {
            id: i as u64,
            stake,
            pubkey: [i as u8; 32],
            voting_pubkey: SecretKey([i as u8; 32]).to_pubkey(),
        })
        .collect();
    EpochInfo::new(validators)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totals_and_leader_rotation() {
        let ei = test_epoch(&[10, 20, 30]);
        assert_eq!(ei.validator_cnt(), 3);
        assert_eq!(ei.total_stake(), 60);
        // SLOTS_PER_WINDOW = 4 → window 0 (slots 0..3) → leader 0; window 1 → leader 1.
        assert_eq!(ei.leader(0).id, 0);
        assert_eq!(ei.leader(3).id, 0);
        assert_eq!(ei.leader(4).id, 1);
        assert_eq!(ei.leader(8).id, 2);
        assert_eq!(ei.leader(12).id, 0); // wraps
    }

    #[test]
    fn quorum_predicates() {
        let ei = test_epoch(&[20, 20, 20, 20, 20]); // total 100
        assert!(ei.is_quorum(60));
        assert!(!ei.is_quorum(59));
        assert!(ei.is_strong_quorum(80));
        assert!(!ei.is_strong_quorum(79));
    }

    #[test]
    #[should_panic(expected = "id must equal index")]
    fn rejects_misindexed_validators() {
        use crate::aggsig::SecretKey;
        EpochInfo::new(vec![ValidatorInfo {
            id: 7,
            stake: 1,
            pubkey: [0; 32],
            voting_pubkey: SecretKey([0; 32]).to_pubkey(),
        }]);
    }
}
