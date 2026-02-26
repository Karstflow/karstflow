use super::database::AccountDatabase;
use super::primitives::{Account, Pubkey};
use super::record::TransactionId;
use super::transaction::{AccountAccessMode, Transaction, TransactionResult};
use crate::StorageError;
use paradencer_sbpf::TransactionProcessor as SbpfTransactionProcessor;
use std::collections::HashMap;

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
    sbpf_processor: SbpfTransactionProcessor,
}

impl TransactionProcessor {
    pub fn new(db: AccountDatabase) -> Self {
        Self {
            db,
            sbpf_processor: SbpfTransactionProcessor::new(),
        }
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

        // Build account state HashMap for sbpf processor
        let mut account_state = HashMap::new();
        for (pubkey, account) in &loaded_accounts.accounts {
            account_state.insert(*pubkey, account.clone());
        }

        let mut total_compute_units = 0u64;
        let mut all_modified_accounts = HashMap::new();

        // Execute each instruction using the sbpf processor
        for instruction in &transaction.instructions {
            let instruction_accounts: Vec<_> = instruction
                .accounts
                .iter()
                .filter_map(|account_ref| {
                    let account = all_modified_accounts
                        .get(&account_ref.pubkey)
                        .or_else(|| account_state.get(&account_ref.pubkey))?
                        .clone();
                    let writable = matches!(account_ref.mode, AccountAccessMode::Writable);
                    Some((account_ref.pubkey, account, writable))
                })
                .collect();

            let outcome = self.sbpf_processor.process_instruction(
                instruction.program_id,
                instruction_accounts,
                instruction.data.clone(),
            );

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

        // Write modified accounts back to database
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

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(n: u8) -> Pubkey {
        Pubkey::new([n; 32])
    }

    fn acct(lamports: u64) -> Account {
        Account::new(lamports, vec![], Pubkey::new([0u8; 32]))
    }

    #[test]
    fn loaded_accounts_new_is_empty() {
        let la = LoadedAccounts::new();
        assert!(la.writable_keys.is_empty());
        assert!(la.get(&pk(1)).is_none());
    }

    #[test]
    fn insert_read_only() {
        let mut la = LoadedAccounts::new();
        la.insert(pk(1), acct(100), false);
        assert!(la.get(&pk(1)).is_some());
        assert_eq!(la.get(&pk(1)).unwrap().meta.lamports, 100);
        assert!(la.writable_keys.is_empty());
    }

    #[test]
    fn insert_writable() {
        let mut la = LoadedAccounts::new();
        la.insert(pk(2), acct(200), true);
        assert!(la.get(&pk(2)).is_some());
        assert_eq!(la.writable_keys.len(), 1);
        assert_eq!(la.writable_keys[0], pk(2));
    }

    #[test]
    fn get_mut_modifies() {
        let mut la = LoadedAccounts::new();
        la.insert(pk(3), acct(300), true);
        la.get_mut(&pk(3)).unwrap().meta.lamports = 999;
        assert_eq!(la.get(&pk(3)).unwrap().meta.lamports, 999);
    }

    #[test]
    fn into_writeback_returns_writable_only() {
        let mut la = LoadedAccounts::new();
        la.insert(pk(1), acct(100), false); // read-only
        la.insert(pk(2), acct(200), true); // writable
        la.insert(pk(3), acct(300), true); // writable

        let writeback = la.into_writeback();
        assert_eq!(writeback.len(), 2);
        let keys: Vec<Pubkey> = writeback.iter().map(|(k, _)| *k).collect();
        assert!(keys.contains(&pk(2)));
        assert!(keys.contains(&pk(3)));
        assert!(!keys.contains(&pk(1)));
    }

    #[test]
    fn default_is_empty() {
        let la: LoadedAccounts = Default::default();
        assert!(la.writable_keys.is_empty());
    }
}
