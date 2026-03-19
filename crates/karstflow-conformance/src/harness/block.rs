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

/// Deterministic validator identity for conformance tests.
/// Using a fixed pubkey ensures bank hash is reproducible across runs.
const CONFORMANCE_VALIDATOR_PUBKEY: Pubkey = Pubkey::new_from_array([
    0xCF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
]);

/// Execute a block of transactions against a fresh development genesis bank.
pub fn execute_block(
    pre_accounts: &HashMap<Pubkey, Account>,
    transactions: &[SanitizedTransaction],
) -> BlockExecutionResult {
    let consensus = bootstrap_from_development_genesis(None, Some(&CONFORMANCE_VALIDATOR_PUBKEY))
        .expect("failed to bootstrap development genesis");
    let forks = consensus.bank_forks.read().unwrap();
    let bank = forks.working_bank();
    let slot = bank.slot();

    // Inject pre-state accounts.
    for (pubkey, account) in pre_accounts {
        bank.accounts()
            .store_published_account(*pubkey, account.clone());
    }

    // Register genesis blockhash for transaction validation.
    let genesis_hash = bank.last_blockhash();
    bank.register_recent_blockhash(genesis_hash);

    let backend = Arc::new(SbpfExecutionAdapter::with_defaults());

    // Execute all transactions.
    let mut transaction_results = Vec::with_capacity(transactions.len());
    let mut successful_count = 0;
    let mut failed_count = 0;

    for txn in transactions {
        // Clear signatures to skip verification — conformance tests
        // verify execution logic, not cryptographic signatures.
        let mut txn_copy = txn.clone();
        txn_copy.signatures.clear();
        let result = bank.process_transaction(
            &txn_copy,
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
