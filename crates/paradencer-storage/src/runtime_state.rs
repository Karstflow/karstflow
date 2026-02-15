use crate::StorageError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeStateApplyRequest {
    pub fragment_id: u64,
    pub account_writes: usize,
    pub account_data_bytes: u64,
    pub rent_epoch_updates: usize,
    pub program_loads: usize,
    pub program_evictions: usize,
    pub program_invalidations: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeStateApplyReceipt {
    pub fragment_id: u64,
    pub previous_last_fragment_id: u64,
    pub account_writes: usize,
    pub account_data_bytes: u64,
    pub rent_epoch_updates: usize,
    pub program_loads: usize,
    pub program_evictions: usize,
    pub program_invalidations: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeStateSnapshot {
    pub last_fragment_id: u64,
    pub total_account_writes: u64,
    pub total_account_data_bytes: u64,
    pub total_rent_epoch_updates: u64,
    pub total_program_loads: u64,
    pub total_program_evictions: u64,
    pub total_program_invalidations: u64,
}

impl RuntimeStateSnapshot {
    pub fn new() -> Self {
        Self {
            last_fragment_id: 0,
            total_account_writes: 0,
            total_account_data_bytes: 0,
            total_rent_epoch_updates: 0,
            total_program_loads: 0,
            total_program_evictions: 0,
            total_program_invalidations: 0,
        }
    }
}

impl Default for RuntimeStateSnapshot {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeStateStore {
    snapshot: RuntimeStateSnapshot,
    applied_receipts: Vec<RuntimeStateApplyReceipt>,
    rewind_floor_fragment_id: u64,
}

impl RuntimeStateStore {
    pub fn new() -> Self {
        Self {
            snapshot: RuntimeStateSnapshot::new(),
            applied_receipts: Vec::new(),
            rewind_floor_fragment_id: 0,
        }
    }

    pub fn seed_checkpoint(&mut self, fragment_id: u64) {
        self.snapshot = RuntimeStateSnapshot {
            last_fragment_id: fragment_id,
            total_account_writes: 0,
            total_account_data_bytes: 0,
            total_rent_epoch_updates: 0,
            total_program_loads: 0,
            total_program_evictions: 0,
            total_program_invalidations: 0,
        };
        self.applied_receipts.clear();
        self.rewind_floor_fragment_id = fragment_id;
    }

    pub fn snapshot(&self) -> RuntimeStateSnapshot {
        self.snapshot
    }

    pub fn apply_effects(
        &mut self,
        request: RuntimeStateApplyRequest,
    ) -> Result<RuntimeStateApplyReceipt, StorageError> {
        if request.fragment_id <= self.snapshot.last_fragment_id {
            return Err(StorageError::FragmentRegression {
                last_fragment_id: self.snapshot.last_fragment_id,
                new_fragment_id: request.fragment_id,
            });
        }

        let previous_last_fragment_id = self.snapshot.last_fragment_id;
        let next_total_account_writes = checked_add_u64(
            self.snapshot.total_account_writes,
            checked_usize_to_u64(request.account_writes, "total_account_writes")?,
            "total_account_writes",
        )?;
        let next_total_account_data_bytes = checked_add_u64(
            self.snapshot.total_account_data_bytes,
            request.account_data_bytes,
            "total_account_data_bytes",
        )?;
        let next_total_rent_epoch_updates = checked_add_u64(
            self.snapshot.total_rent_epoch_updates,
            checked_usize_to_u64(request.rent_epoch_updates, "total_rent_epoch_updates")?,
            "total_rent_epoch_updates",
        )?;
        let next_total_program_loads = checked_add_u64(
            self.snapshot.total_program_loads,
            checked_usize_to_u64(request.program_loads, "total_program_loads")?,
            "total_program_loads",
        )?;
        let next_total_program_evictions = checked_add_u64(
            self.snapshot.total_program_evictions,
            checked_usize_to_u64(request.program_evictions, "total_program_evictions")?,
            "total_program_evictions",
        )?;
        let next_total_program_invalidations = checked_add_u64(
            self.snapshot.total_program_invalidations,
            checked_usize_to_u64(request.program_invalidations, "total_program_invalidations")?,
            "total_program_invalidations",
        )?;
        self.snapshot.last_fragment_id = request.fragment_id;
        self.snapshot.total_account_writes = next_total_account_writes;
        self.snapshot.total_account_data_bytes = next_total_account_data_bytes;
        self.snapshot.total_rent_epoch_updates = next_total_rent_epoch_updates;
        self.snapshot.total_program_loads = next_total_program_loads;
        self.snapshot.total_program_evictions = next_total_program_evictions;
        self.snapshot.total_program_invalidations = next_total_program_invalidations;

        let receipt = RuntimeStateApplyReceipt {
            fragment_id: request.fragment_id,
            previous_last_fragment_id,
            account_writes: request.account_writes,
            account_data_bytes: request.account_data_bytes,
            rent_epoch_updates: request.rent_epoch_updates,
            program_loads: request.program_loads,
            program_evictions: request.program_evictions,
            program_invalidations: request.program_invalidations,
        };
        self.applied_receipts.push(receipt);
        Ok(receipt)
    }

    pub fn rollback_effects(
        &mut self,
        receipt: RuntimeStateApplyReceipt,
    ) -> Result<(), StorageError> {
        if receipt.fragment_id != self.snapshot.last_fragment_id {
            return Err(StorageError::RuntimeStateRollbackOrderViolation {
                expected_last_fragment_id: self.snapshot.last_fragment_id,
                receipt_fragment_id: receipt.fragment_id,
            });
        }
        if receipt.previous_last_fragment_id >= receipt.fragment_id {
            return Err(StorageError::RuntimeStateReceiptInvariantViolation {
                receipt_fragment_id: receipt.fragment_id,
                previous_last_fragment_id: receipt.previous_last_fragment_id,
            });
        }
        let Some(expected_receipt) = self.applied_receipts.last().copied() else {
            return Err(StorageError::RuntimeStateReceiptMismatch {
                expected_fragment_id: self.snapshot.last_fragment_id,
                provided_fragment_id: receipt.fragment_id,
            });
        };
        if expected_receipt != receipt {
            return Err(StorageError::RuntimeStateReceiptMismatch {
                expected_fragment_id: expected_receipt.fragment_id,
                provided_fragment_id: receipt.fragment_id,
            });
        }
        self.snapshot.total_account_writes = checked_sub_u64(
            self.snapshot.total_account_writes,
            checked_usize_to_u64(receipt.account_writes, "total_account_writes")?,
            "total_account_writes",
        )?;
        self.snapshot.total_account_data_bytes = checked_sub_u64(
            self.snapshot.total_account_data_bytes,
            receipt.account_data_bytes,
            "total_account_data_bytes",
        )?;
        self.snapshot.total_rent_epoch_updates = checked_sub_u64(
            self.snapshot.total_rent_epoch_updates,
            checked_usize_to_u64(receipt.rent_epoch_updates, "total_rent_epoch_updates")?,
            "total_rent_epoch_updates",
        )?;
        self.snapshot.total_program_loads = checked_sub_u64(
            self.snapshot.total_program_loads,
            checked_usize_to_u64(receipt.program_loads, "total_program_loads")?,
            "total_program_loads",
        )?;
        self.snapshot.total_program_evictions = checked_sub_u64(
            self.snapshot.total_program_evictions,
            checked_usize_to_u64(receipt.program_evictions, "total_program_evictions")?,
            "total_program_evictions",
        )?;
        self.snapshot.total_program_invalidations = checked_sub_u64(
            self.snapshot.total_program_invalidations,
            checked_usize_to_u64(receipt.program_invalidations, "total_program_invalidations")?,
            "total_program_invalidations",
        )?;
        self.snapshot.last_fragment_id = receipt.previous_last_fragment_id;
        let _ = self.applied_receipts.pop();
        Ok(())
    }

    pub fn rewind_to_fragment(&mut self, target_fragment_id: u64) -> Result<usize, StorageError> {
        if target_fragment_id > self.snapshot.last_fragment_id {
            return Err(StorageError::RuntimeStateRewindTargetAhead {
                current_last_fragment_id: self.snapshot.last_fragment_id,
                target_fragment_id,
            });
        }
        if target_fragment_id < self.rewind_floor_fragment_id {
            return Err(StorageError::RuntimeStateRewindTargetBelowFloor {
                rewind_floor_fragment_id: self.rewind_floor_fragment_id,
                target_fragment_id,
            });
        }

        let mut rolled_back = 0usize;
        while self.snapshot.last_fragment_id > target_fragment_id {
            let Some(receipt) = self.applied_receipts.last().copied() else {
                return Err(StorageError::RuntimeStateReceiptMismatch {
                    expected_fragment_id: self.snapshot.last_fragment_id,
                    provided_fragment_id: target_fragment_id,
                });
            };
            self.rollback_effects(receipt)?;
            rolled_back = rolled_back.saturating_add(1);
        }
        Ok(rolled_back)
    }
}

impl Default for RuntimeStateStore {
    fn default() -> Self {
        Self::new()
    }
}

fn checked_sub_u64(current: u64, rollback: u64, field: &'static str) -> Result<u64, StorageError> {
    current
        .checked_sub(rollback)
        .ok_or(StorageError::RuntimeStateUnderflow {
            field,
            current,
            rollback,
        })
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
