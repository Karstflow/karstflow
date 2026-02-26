use crate::{CommittedFragmentRecord, SnapshotImage, StorageError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HotStateStore {
    pub last_fragment_id: u64,
    pub committed_fragments: u64,
    pub committed_transactions: u64,
}

impl HotStateStore {
    pub fn new() -> Self {
        Self {
            last_fragment_id: 0,
            committed_fragments: 0,
            committed_transactions: 0,
        }
    }

    pub fn apply_committed_fragment(
        &mut self,
        record: &CommittedFragmentRecord,
    ) -> Result<(), StorageError> {
        if record.fragment_id < self.last_fragment_id {
            return Err(StorageError::FragmentRegression {
                last_fragment_id: self.last_fragment_id,
                new_fragment_id: record.fragment_id,
            });
        }

        let next_committed_fragments =
            checked_add_u64(self.committed_fragments, 1, "committed_fragments")?;
        let next_committed_transactions = checked_add_u64(
            self.committed_transactions,
            checked_usize_to_u64(record.transaction_count, "committed_transactions")?,
            "committed_transactions",
        )?;
        self.last_fragment_id = record.fragment_id;
        self.committed_fragments = next_committed_fragments;
        self.committed_transactions = next_committed_transactions;
        Ok(())
    }

    pub fn restore_from_snapshot(&mut self, snapshot: &SnapshotImage) {
        self.last_fragment_id = snapshot.fragment_id;
        self.committed_fragments = snapshot.committed_fragments;
        self.committed_transactions = snapshot.committed_transactions;
    }
}

impl Default for HotStateStore {
    fn default() -> Self {
        Self::new()
    }
}

fn checked_add_u64(current: u64, delta: u64, field: &'static str) -> Result<u64, StorageError> {
    current
        .checked_add(delta)
        .ok_or(StorageError::StateCounterOverflow {
            field,
            current,
            delta,
        })
}

fn checked_usize_to_u64(value: usize, field: &'static str) -> Result<u64, StorageError> {
    u64::try_from(value).map_err(|_| StorageError::StateCounterOverflow {
        field,
        current: 0,
        delta: u64::MAX,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(fragment_id: u64, tx_count: usize) -> CommittedFragmentRecord {
        CommittedFragmentRecord {
            fragment_id,
            transaction_count: tx_count,
            total_cost_units: 0,
        }
    }

    #[test]
    fn new_state_is_zeroed() {
        let state = HotStateStore::new();
        assert_eq!(state.last_fragment_id, 0);
        assert_eq!(state.committed_fragments, 0);
        assert_eq!(state.committed_transactions, 0);
    }

    #[test]
    fn default_equals_new() {
        assert_eq!(HotStateStore::default(), HotStateStore::new());
    }

    #[test]
    fn apply_single_fragment() {
        let mut state = HotStateStore::new();
        state.apply_committed_fragment(&record(1, 10)).unwrap();
        assert_eq!(state.last_fragment_id, 1);
        assert_eq!(state.committed_fragments, 1);
        assert_eq!(state.committed_transactions, 10);
    }

    #[test]
    fn apply_multiple_fragments() {
        let mut state = HotStateStore::new();
        state.apply_committed_fragment(&record(1, 5)).unwrap();
        state.apply_committed_fragment(&record(2, 10)).unwrap();
        state.apply_committed_fragment(&record(3, 3)).unwrap();
        assert_eq!(state.last_fragment_id, 3);
        assert_eq!(state.committed_fragments, 3);
        assert_eq!(state.committed_transactions, 18);
    }

    #[test]
    fn apply_rejects_fragment_regression() {
        let mut state = HotStateStore::new();
        state.apply_committed_fragment(&record(5, 1)).unwrap();
        let err = state.apply_committed_fragment(&record(3, 1));
        assert!(err.is_err());
    }

    #[test]
    fn apply_accepts_same_fragment_id() {
        let mut state = HotStateStore::new();
        state.apply_committed_fragment(&record(5, 1)).unwrap();
        // Same fragment ID should be accepted (not regression)
        assert!(state.apply_committed_fragment(&record(5, 1)).is_ok());
    }

    #[test]
    fn restore_from_snapshot() {
        let mut state = HotStateStore::new();
        state.apply_committed_fragment(&record(10, 100)).unwrap();

        let snapshot = SnapshotImage {
            fragment_id: 5,
            committed_fragments: 3,
            committed_transactions: 50,
            state_checksum: 0,
        };
        state.restore_from_snapshot(&snapshot);
        assert_eq!(state.last_fragment_id, 5);
        assert_eq!(state.committed_fragments, 3);
        assert_eq!(state.committed_transactions, 50);
    }
}
