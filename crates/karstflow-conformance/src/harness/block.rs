//! Block-level execution harness.
//!
//! Executes a sequence of transactions as a block, finalizes the slot,
//! and returns the bank hash for comparison.

use karstflow_consensus::{SanitizedTransaction, TransactionExecutionResult};
use karstflow_control::bootstrap_from_development_genesis;
use karstflow_stages::SbpfExecutionAdapter;
use karstflow_types::{Account, Pubkey};
use std::collections::HashMap;
use std::sync::Arc;

/// Result of executing a full block.
#[derive(Debug)]
pub struct BlockExecutionResult {
    /// Per-transaction execution results.
    pub transaction_results: Vec<TransactionExecutionResult>,
    /// Slot finalization bank hash (if finalization succeeded).
    pub bank_hash: Option<[u8; 32]>,
    /// Slot number.
    pub slot: u64,
    /// Number of successful transactions.
    pub successful_count: usize,
    /// Number of failed transactions.
    pub failed_count: usize,
}

/// Execute a block of transactions against a fresh development genesis bank.
pub fn execute_block(
    pre_accounts: &HashMap<Pubkey, Account>,
    transactions: &[SanitizedTransaction],
) -> BlockExecutionResult {
    let consensus = bootstrap_from_development_genesis(None, None)
        .expect("failed to bootstrap development genesis");
    let forks = consensus.bank_forks.read().unwrap();
    let bank = forks.working_bank();
    let slot = bank.slot();

    // Inject pre-state accounts.
    for (pubkey, account) in pre_accounts {
        bank.accounts()
            .store_published_account(*pubkey, account.clone());
    }

    let backend = Arc::new(SbpfExecutionAdapter::with_defaults());

    // Execute all transactions.
    let mut transaction_results = Vec::with_capacity(transactions.len());
    let mut successful_count = 0;
    let mut failed_count = 0;

    for txn in transactions {
        let result = bank.process_transaction(
            txn,
            backend.as_ref(),
            karstflow_constants::execution::MAX_COMPUTE_UNITS,
        );
        if result.success {
            successful_count += 1;
        } else {
            failed_count += 1;
        }
        transaction_results.push(result);
    }

    // Compute bank hash before finalization.
    let bank_hash = Some(bank.hash());

    BlockExecutionResult {
        transaction_results,
        bank_hash,
        slot,
        successful_count,
        failed_count,
    }
}
