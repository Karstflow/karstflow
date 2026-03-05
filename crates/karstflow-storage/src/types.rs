use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedFragmentRecord {
    pub fragment_id: u64,
    pub transaction_count: usize,
    pub total_cost_units: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotImage {
    pub fragment_id: u64,
    pub committed_fragments: u64,
    pub committed_transactions: u64,
    pub state_checksum: u64,
}

impl SnapshotImage {
    pub fn new(fragment_id: u64, committed_fragments: u64, committed_transactions: u64) -> Self {
        let state_checksum =
            Self::compute_state_checksum(fragment_id, committed_fragments, committed_transactions);
        Self {
            fragment_id,
            committed_fragments,
            committed_transactions,
            state_checksum,
        }
    }

    pub fn compute_state_checksum(
        fragment_id: u64,
        committed_fragments: u64,
        committed_transactions: u64,
    ) -> u64 {
        // Lightweight integrity token for catalog persistence; deterministic and stable across restarts.
        fragment_id
            .wrapping_mul(0x9E37_79B1_85EB_CA87)
            .rotate_left(17)
            ^ committed_fragments
                .wrapping_mul(0xC2B2_AE3D_27D4_EB4F)
                .rotate_left(29)
            ^ committed_transactions
                .wrapping_mul(0x1656_67B1_9E37_79F9)
                .rotate_left(41)
    }

    pub fn has_valid_checksum(&self) -> bool {
        self.state_checksum
            == Self::compute_state_checksum(
                self.fragment_id,
                self.committed_fragments,
                self.committed_transactions,
            )
    }
}
