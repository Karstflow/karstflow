use super::ExecutionEngine;
use crate::errors::ExecutionError;
use crate::types::{ExecutionBatch, ExecutionFailureClass, ExecutionOutcome};
use karstflow_storage::{AccountDatabase, TransactionId, TransactionProcessor, TransactionStatus};
use std::sync::Arc;

pub struct AccountBackedExecutionEngine {
    db: AccountDatabase,
    processor: Arc<TransactionProcessor>,
}

impl AccountBackedExecutionEngine {
    pub fn new(db: AccountDatabase) -> Self {
        let processor = Arc::new(TransactionProcessor::new(db.clone()));
        Self { db, processor }
    }

    pub fn database(&self) -> &AccountDatabase {
        &self.db
    }

    fn execute_with_transactions(
        &self,
        batch: &ExecutionBatch,
    ) -> std::result::Result<ExecutionOutcome, ExecutionError> {
        let transactions =
            batch
                .transactions
                .as_ref()
                .ok_or_else(|| ExecutionError::InvalidBatch {
                    fragment_id: batch.fragment_id,
                    detail: "ExecutionBatch missing transactions for account-backed execution"
                        .to_string(),
                })?;

        let xid = TransactionId::from_slot(batch.fragment_id);

        let results = self
            .processor
            .execute_batch(xid, transactions)
            .map_err(|storage_error| ExecutionError::StorageBackend {
                fragment_id: batch.fragment_id,
                detail: storage_error.to_string(),
            })?;

        let mut executed_transactions = 0;
        let mut failed_transactions = 0;
        let mut total_compute_units = 0u64;

        for result in &results {
            match result.status {
                TransactionStatus::Success => {
                    executed_transactions += 1;
                }
                TransactionStatus::Failed => {
                    failed_transactions += 1;
                }
            }
            total_compute_units = total_compute_units.saturating_add(result.compute_units_consumed);
        }

        let failure_class = if failed_transactions > 0 {
            if failed_transactions > executed_transactions {
                Some(ExecutionFailureClass::TransientSchedulerPressure)
            } else {
                Some(ExecutionFailureClass::DeterministicTransactionFailure)
            }
        } else {
            None
        };

        Ok(ExecutionOutcome {
            fragment_id: batch.fragment_id,
            executed_transactions,
            failed_transactions,
            total_cost_units: total_compute_units,
            failure_class,
        })
    }

    fn execute_without_transactions(
        &self,
        batch: &ExecutionBatch,
    ) -> std::result::Result<ExecutionOutcome, ExecutionError> {
        if batch.transaction_count == 0 {
            return Ok(ExecutionOutcome {
                fragment_id: batch.fragment_id,
                executed_transactions: 0,
                failed_transactions: 0,
                total_cost_units: 0,
                failure_class: None,
            });
        }
        Err(ExecutionError::InvalidBatch {
            fragment_id: batch.fragment_id,
            detail: format!(
                "AccountBackedExecutionEngine requires transaction data for {} transactions",
                batch.transaction_count
            ),
        })
    }
}

impl ExecutionEngine for AccountBackedExecutionEngine {
    fn try_execute_batch(
        &self,
        batch: &ExecutionBatch,
    ) -> std::result::Result<ExecutionOutcome, ExecutionError> {
        if batch.transactions.is_some() {
            self.execute_with_transactions(batch)
        } else {
            self.execute_without_transactions(batch)
        }
    }
}
