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
