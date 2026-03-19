//! Transaction-level execution harness.
//!
//! Bootstraps a development genesis bank, injects pre-state accounts,
//! then executes a sanitized transaction and returns the result.

use karstflow_consensus::{Bank, TransactionExecutionResult};
use karstflow_control::{bootstrap_from_development_genesis, development_faucet_pubkey};
use karstflow_stages::SbpfExecutionAdapter;
use karstflow_types::{Account, Pubkey};
use std::collections::HashMap;
use std::sync::Arc;

/// Input for transaction-level conformance test.
#[derive(Debug, Clone)]
pub struct TransactionInput {
    /// Accounts to inject before execution (pubkey -> account).
    pub pre_accounts: HashMap<Pubkey, Account>,
    /// Serialized transaction message bytes (for building SanitizedTransaction).
    pub message_bytes: Vec<u8>,
    /// Signatures for the transaction.
    pub signatures: Vec<[u8; 64]>,
}

/// Execute a transaction against a fresh development genesis bank.
///
/// Returns the bank's execution result containing success/failure,
/// modified accounts, logs, compute units, and fees.
pub fn execute_transaction(pre_accounts: &HashMap<Pubkey, Account>) -> TransactionSetup {
    let consensus = bootstrap_from_development_genesis(None, None)
        .expect("failed to bootstrap development genesis");
    let forks = consensus.bank_forks.read().unwrap();
    let bank = forks.working_bank();

    // Inject pre-state accounts.
    for (pubkey, account) in pre_accounts {
        bank.accounts()
            .store_published_account(*pubkey, account.clone());
    }

    // Register the genesis blockhash so transactions pass validation.
    // In dev mode bootstrap, finish_slot() is called by the slot driver
    // later, but conformance tests run synchronously without a slot driver.
    let genesis_hash = bank.last_blockhash();
    bank.register_recent_blockhash(genesis_hash);

    let backend = Arc::new(SbpfExecutionAdapter::with_defaults());
    let faucet = development_faucet_pubkey();

    TransactionSetup {
        bank: bank.clone(),
        backend,
        faucet,
    }
}

/// A prepared bank ready for transaction execution.
pub struct TransactionSetup {
    pub bank: Arc<Bank>,
    pub backend: Arc<SbpfExecutionAdapter>,
    pub faucet: Pubkey,
}

impl TransactionSetup {
    /// Execute a sanitized transaction against the prepared bank.
    pub fn execute(
        &self,
        transaction: &karstflow_consensus::SanitizedTransaction,
    ) -> TransactionExecutionResult {
        // Use empty signatures to skip signature verification.
        // Conformance tests verify execution logic, not cryptographic signatures.
        let mut txn = transaction.clone();
        txn.signatures.clear();
        let result = self.bank.process_transaction(
            &txn,
            self.backend.as_ref(),
            karstflow_constants::execution::MAX_COMPUTE_UNITS,
        );
        if !result.success {
            eprintln!("[conformance] tx failed: {:?}", result.error);
        }
        result
    }
}
