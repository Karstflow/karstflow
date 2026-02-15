use super::database::AccountDatabase;
use super::primitives::{Account, Pubkey};
use super::record::TransactionId;
use super::transaction::{AccountAccessMode, Transaction, TransactionResult};
use crate::StorageError;
use paradencer_sbpf::{ExecutionContext, SbpfVm, StubSbpfVm};
use std::collections::HashMap;
use std::sync::Arc;

pub struct LoadedAccounts {
    accounts: HashMap<Pubkey, Account>,
    pub(crate) writable_keys: Vec<Pubkey>,
}

impl LoadedAccounts {
    pub fn new() -> Self {
        Self {
            accounts: HashMap::new(),
            writable_keys: Vec::new(),
        }
    }

    pub fn insert(&mut self, pubkey: Pubkey, account: Account, writable: bool) {
        self.accounts.insert(pubkey, account);
        if writable {
            self.writable_keys.push(pubkey);
        }
    }

    pub fn get(&self, pubkey: &Pubkey) -> Option<&Account> {
        self.accounts.get(pubkey)
    }

    pub fn get_mut(&mut self, pubkey: &Pubkey) -> Option<&mut Account> {
        self.accounts.get_mut(pubkey)
    }

    pub fn into_writeback(self) -> Vec<(Pubkey, Account)> {
        self.writable_keys
            .into_iter()
            .filter_map(|pubkey| {
                self.accounts
                    .get(&pubkey)
                    .map(|account| (pubkey, account.clone()))
            })
            .collect()
    }
}

impl Default for LoadedAccounts {
    fn default() -> Self {
        Self::new()
    }
}

pub struct TransactionProcessor {
    db: AccountDatabase,
    vm: Arc<dyn SbpfVm>,
}

impl TransactionProcessor {
    pub fn new(db: AccountDatabase) -> Self {
        Self::with_vm(db, Arc::new(StubSbpfVm::new()))
    }

    pub fn with_vm(db: AccountDatabase, vm: Arc<dyn SbpfVm>) -> Self {
        Self { db, vm }
    }

    pub fn load_accounts(
        &self,
        xid: TransactionId,
        transaction: &Transaction,
    ) -> Result<LoadedAccounts, StorageError> {
        let mut loaded = LoadedAccounts::new();

        for instruction in &transaction.instructions {
            for account_ref in &instruction.accounts {
                if !loaded.accounts.contains_key(&account_ref.pubkey) {
                    let account = self
                        .db
                        .read_account(xid, &account_ref.pubkey)?
                        .unwrap_or_else(Account::zeroed);

                    let writable = matches!(account_ref.mode, AccountAccessMode::Writable);
                    loaded.insert(account_ref.pubkey, account, writable);
                }
            }

            if !loaded.accounts.contains_key(&instruction.program_id) {
                let program_account = self
                    .db
                    .read_account(xid, &instruction.program_id)?
                    .unwrap_or_else(Account::zeroed);
                loaded.insert(instruction.program_id, program_account, false);
            }
        }

        Ok(loaded)
    }

    pub fn execute_transaction(
        &self,
        xid: TransactionId,
        transaction: &Transaction,
    ) -> Result<TransactionResult, StorageError> {
        let loaded_accounts = self.load_accounts(xid, transaction)?;
        let signature = transaction.fee_payer().cloned().unwrap_or_default();

        let mut total_compute_units = 0u64;
        let mut all_modified_accounts = HashMap::new();

        for instruction in &transaction.instructions {
            let instruction_accounts: Vec<_> = instruction
                .accounts
                .iter()
                .filter_map(|account_ref| {
                    let account = all_modified_accounts
                        .get(&account_ref.pubkey)
                        .or_else(|| loaded_accounts.get(&account_ref.pubkey))?
                        .clone();
                    let writable = matches!(account_ref.mode, AccountAccessMode::Writable);
                    Some((account_ref.pubkey, account, writable))
                })
                .collect();

            let context = ExecutionContext::new(
                instruction.program_id,
                instruction_accounts,
                instruction.data.clone(),
            );

            match self.vm.execute(context) {
                Ok(outcome) => {
                    if !outcome.success {
                        let error_msg = outcome.logs.join("; ");
                        return Ok(TransactionResult::failed(
                            signature,
                            total_compute_units.saturating_add(outcome.compute_units_consumed),
                            error_msg,
                        ));
                    }
                    total_compute_units =
                        total_compute_units.saturating_add(outcome.compute_units_consumed);
                    all_modified_accounts.extend(outcome.modified_accounts);
                }
                Err(err) => {
                    return Ok(TransactionResult::failed(
                        signature,
                        total_compute_units,
                        err.to_string(),
                    ));
                }
            }
        }

        for (pubkey, account) in all_modified_accounts {
            if loaded_accounts.writable_keys.contains(&pubkey) {
                self.db.write_account(xid, pubkey, account)?;
            }
        }

        Ok(TransactionResult::success(signature, total_compute_units))
    }

    pub fn execute_batch(
        &self,
        xid: TransactionId,
        transactions: &[Transaction],
    ) -> Result<Vec<TransactionResult>, StorageError> {
        let mut results = Vec::with_capacity(transactions.len());

        for transaction in transactions {
            let result = self.execute_transaction(xid, transaction)?;
            results.push(result);
        }

        Ok(results)
    }
}
