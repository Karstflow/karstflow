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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_new_has_valid_checksum() {
        let img = SnapshotImage::new(10, 5, 100);
        assert!(img.has_valid_checksum());
    }

    #[test]
    fn snapshot_checksum_is_deterministic() {
        let a = SnapshotImage::new(42, 7, 999);
        let b = SnapshotImage::new(42, 7, 999);
        assert_eq!(a.state_checksum, b.state_checksum);
    }

    #[test]
    fn snapshot_different_inputs_different_checksums() {
        let a = SnapshotImage::new(1, 2, 3);
        let b = SnapshotImage::new(1, 2, 4);
        let c = SnapshotImage::new(1, 3, 3);
        let d = SnapshotImage::new(2, 2, 3);
        assert_ne!(a.state_checksum, b.state_checksum);
        assert_ne!(a.state_checksum, c.state_checksum);
        assert_ne!(a.state_checksum, d.state_checksum);
    }

    #[test]
    fn snapshot_tampered_checksum_detected() {
        let mut img = SnapshotImage::new(10, 5, 100);
        img.state_checksum ^= 1;
        assert!(!img.has_valid_checksum());
    }

    #[test]
    fn snapshot_tampered_fields_detected() {
        let mut img = SnapshotImage::new(10, 5, 100);
        img.fragment_id = 11;
        assert!(!img.has_valid_checksum());
    }

    #[test]
    fn snapshot_zero_inputs() {
        let img = SnapshotImage::new(0, 0, 0);
        assert!(img.has_valid_checksum());
        assert_eq!(img.state_checksum, 0);
    }

    #[test]
    fn snapshot_max_inputs() {
        let img = SnapshotImage::new(u64::MAX, u64::MAX, u64::MAX);
        assert!(img.has_valid_checksum());
    }

    #[test]
    fn snapshot_serde_roundtrip() {
        let img = SnapshotImage::new(42, 7, 999);
        let json = serde_json::to_string(&img).unwrap();
        let restored: SnapshotImage = serde_json::from_str(&json).unwrap();
        assert_eq!(img, restored);
        assert!(restored.has_valid_checksum());
    }
}
