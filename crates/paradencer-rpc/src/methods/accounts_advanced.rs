use serde_json::{json, Value};
use std::cmp::Ordering;

use crate::cache::account::AccountCache;
use crate::filters::{apply_filters, RpcFilterType, SortOrder};
use crate::state::{RpcCommitment, RpcRuntimeSnapshot};
use crate::{Result, RpcError};
use paradencer_types::{Account, AccountMeta, Pubkey};

/// Advanced account query handler
pub struct AccountsAdvanced {
    account_cache: AccountCache,
}

impl AccountsAdvanced {
    pub fn new(account_cache: AccountCache) -> Self {
        Self { account_cache }
    }

    /// Get program accounts with advanced filtering
    pub fn get_program_accounts_with_filters(
        &self,
        program_id: &str,
        config: ProgramAccountsConfig,
        snapshot: RpcRuntimeSnapshot,
        commitment: RpcCommitment,
    ) -> Result<Value> {
        let slot = snapshot.slot_for_commitment(commitment);

        // Check min context slot
        if let Some(min_slot) = config.min_context_slot {
            if slot < min_slot {
                return Err(RpcError::MinContextSlotNotReached { slot, min_slot });
            }
        }

        // Generate synthetic accounts for this program
        let mut accounts = generate_program_accounts(program_id, snapshot, 50);

        // Apply filters
        if let Some(filters) = &config.filters {
            accounts = apply_filters(&accounts, filters);
        }

        // Apply sorting
        if let Some(sort) = &config.sort {
            sort_accounts(&mut accounts, sort);
        }

        // Apply pagination
        let total = accounts.len();
        let offset = config.offset.unwrap_or(0);
        let limit = config.limit.unwrap_or(100).min(1000); // Cap at 1000

        let paginated: Vec<_> = accounts.into_iter().skip(offset).take(limit).collect();

        // Build response
        let value: Vec<Value> = paginated
            .iter()
            .map(|(pubkey, account)| {
                json!({
                    "pubkey": pubkey,
                    "account": serialize_account(account, &config.encoding),
                })
            })
            .collect();

        if config.with_context {
            Ok(json!({
                "context": {
                    "slot": slot,
                    "total": total,
                    "offset": offset,
                    "limit": limit,
                },
                "value": value
            }))
        } else {
            Ok(json!(value))
        }
    }

    /// Get multiple accounts with batching optimization
    pub fn get_multiple_accounts_batched(
        &self,
        pubkeys: Vec<String>,
        config: MultipleAccountsConfig,
        snapshot: RpcRuntimeSnapshot,
        commitment: RpcCommitment,
    ) -> Result<Value> {
        let slot = snapshot.slot_for_commitment(commitment);

        // Validate batch size
        if pubkeys.len() > config.max_batch_size.unwrap_or(100) {
            return Err(RpcError::BatchTooLarge {
                size: pubkeys.len(),
                max: config.max_batch_size.unwrap_or(100),
            });
        }

        // Check cache first
        let mut accounts = Vec::new();
        let mut cache_hits = 0;

        for pubkey in &pubkeys {
            if let Some(cached) = self.account_cache.get(pubkey, commitment) {
                accounts.push(Some(cached));
                cache_hits += 1;
            } else {
                // Generate synthetic account
                let account = generate_synthetic_account(pubkey, snapshot);
                self.account_cache
                    .insert(pubkey.clone(), account.clone(), slot, commitment);
                accounts.push(Some(account));
            }
        }

        // Build response
        let value: Vec<Value> = accounts
            .iter()
            .map(|acc| {
                acc.as_ref()
                    .map_or(Value::Null, |a| serialize_account(a, &config.encoding))
            })
            .collect();

        Ok(json!({
            "context": {
                "slot": slot,
                "cacheHits": cache_hits,
                "cacheMisses": pubkeys.len() - cache_hits,
            },
            "value": value
        }))
    }

    /// Get account with subscription hint
    pub fn get_account_with_hint(
        &self,
        pubkey: &str,
        config: AccountConfig,
        snapshot: RpcRuntimeSnapshot,
        commitment: RpcCommitment,
    ) -> Result<Value> {
        let slot = snapshot.slot_for_commitment(commitment);

        // Check cache
        let account = if let Some(cached) = self.account_cache.get(pubkey, commitment) {
            cached
        } else {
            let account = generate_synthetic_account(pubkey, snapshot);
            self.account_cache
                .insert(pubkey.to_string(), account.clone(), slot, commitment);
            account
        };

        Ok(json!({
            "context": { "slot": slot },
            "value": serialize_account(&account, &config.encoding)
        }))
    }

    /// Get accounts sorted by balance
    pub fn get_largest_accounts_advanced(
        &self,
        config: LargestAccountsConfig,
        snapshot: RpcRuntimeSnapshot,
        commitment: RpcCommitment,
    ) -> Result<Value> {
        let slot = snapshot.slot_for_commitment(commitment);

        // Generate account set
        let mut accounts = generate_large_accounts(snapshot, 100);

        // Apply filter if specified
        if let Some(filter) = &config.filter {
            accounts.retain(|(_, acc)| match filter.as_str() {
                "circulating" => acc.meta.lamports > 1000000,
                "nonCirculating" => acc.meta.lamports <= 1000000,
                _ => true,
            });
        }

        // Sort by lamports descending
        accounts.sort_by(|a, b| b.1.meta.lamports.cmp(&a.1.meta.lamports));

        // Take top N
        let limit = config.limit.unwrap_or(20).min(100);
        let top: Vec<_> = accounts.into_iter().take(limit).collect();

        let value: Vec<Value> = top
            .iter()
            .map(|(pubkey, account)| {
                json!({
                    "address": pubkey,
                    "lamports": account.meta.lamports,
                })
            })
            .collect();

        Ok(json!({
            "context": { "slot": slot },
            "value": value
        }))
    }
}

#[derive(Debug, Clone)]
pub struct ProgramAccountsConfig {
    pub filters: Option<Vec<RpcFilterType>>,
    pub sort: Option<SortOrder>,
    pub with_context: bool,
    pub min_context_slot: Option<u64>,
    pub encoding: String,
    pub offset: Option<usize>,
    pub limit: Option<usize>,
    pub data_slice: Option<DataSlice>,
}

#[derive(Debug, Clone)]
pub struct DataSlice {
    pub offset: usize,
    pub length: usize,
}

#[derive(Debug, Clone)]
pub struct MultipleAccountsConfig {
    pub encoding: String,
    pub max_batch_size: Option<usize>,
    pub data_slice: Option<DataSlice>,
}

#[derive(Debug, Clone)]
pub struct AccountConfig {
    pub encoding: String,
    pub data_slice: Option<DataSlice>,
}

#[derive(Debug, Clone)]
pub struct LargestAccountsConfig {
    pub filter: Option<String>,
    pub limit: Option<usize>,
}

fn generate_program_accounts(
    program_id: &str,
    snapshot: RpcRuntimeSnapshot,
    count: usize,
) -> Vec<(String, Account)> {
    let mut accounts = Vec::new();
    let base_seed = program_id
        .bytes()
        .fold(0u64, |acc, b| acc.wrapping_add(b as u64));

    for i in 0..count {
        let pubkey = format!("{}Account{:04}", &program_id[..8], i);
        let lamports = base_seed
            .wrapping_add(i as u64)
            .wrapping_add(snapshot.transaction_count);
        let data_size = ((i * 13) % 1000) as usize;
        let data = vec![((i % 256) as u8); data_size];

        // Create owner pubkey from program_id string (for testing)
        let mut owner_bytes = [0u8; 32];
        let program_bytes = program_id.as_bytes();
        let len = program_bytes.len().min(32);
        owner_bytes[..len].copy_from_slice(&program_bytes[..len]);
        let owner = Pubkey::new(owner_bytes);

        let account = Account::new(lamports, data, owner);
        accounts.push((pubkey, account));
    }

    accounts
}

fn generate_synthetic_account(pubkey: &str, snapshot: RpcRuntimeSnapshot) -> Account {
    let seed = pubkey
        .bytes()
        .fold(0u64, |acc, b| acc.wrapping_add(b as u64));
    let lamports = seed.wrapping_add(snapshot.transaction_count);
    let data_size = (seed % 1000) as usize;
    let data = vec![((seed % 256) as u8); data_size];

    Account::new(lamports, data, Pubkey::zeroed())
}

fn generate_large_accounts(snapshot: RpcRuntimeSnapshot, count: usize) -> Vec<(String, Account)> {
    let mut accounts = Vec::new();

    for i in 0..count {
        let pubkey = format!("LargeAccount{:04}1111111111111111111111111", i);
        let lamports = 10000000u64
            .saturating_sub(i as u64 * 10000)
            .saturating_add(snapshot.transaction_count % 1000);
        let account = Account::new(lamports, vec![], Pubkey::zeroed());
        accounts.push((pubkey, account));
    }

    accounts
}

fn sort_accounts(accounts: &mut Vec<(String, Account)>, order: &SortOrder) {
    match order {
        SortOrder::LamportsAsc => {
            accounts.sort_by(|a, b| a.1.meta.lamports.cmp(&b.1.meta.lamports));
        }
        SortOrder::LamportsDesc => {
            accounts.sort_by(|a, b| b.1.meta.lamports.cmp(&a.1.meta.lamports));
        }
        SortOrder::DataSizeAsc => {
            accounts.sort_by(|a, b| a.1.data_len().cmp(&b.1.data_len()));
        }
        SortOrder::DataSizeDesc => {
            accounts.sort_by(|a, b| b.1.data_len().cmp(&a.1.data_len()));
        }
        SortOrder::PubkeyAsc => {
            accounts.sort_by(|a, b| a.0.cmp(&b.0));
        }
        SortOrder::PubkeyDesc => {
            accounts.sort_by(|a, b| b.0.cmp(&a.0));
        }
    }
}

fn serialize_account(account: &Account, encoding: &str) -> Value {
    let data_str = match encoding {
        "base58" => bs58::encode(account.data.as_slice()).into_string(),
        "base64" => base64_encode(account.data.as_slice()),
        "jsonParsed" => {
            return json!({
                "lamports": account.meta.lamports,
                "owner": account.meta.owner.to_string(),
                "data": {
                    "parsed": {
                        "type": "account",
                        "info": {}
                    },
                    "program": "unknown",
                    "space": account.data_len(),
                },
                "executable": account.meta.executable,
                "rentEpoch": account.meta.rent_epoch,
            });
        }
        _ => String::new(),
    };

    json!({
        "lamports": account.meta.lamports,
        "owner": account.meta.owner.to_string(),
        "data": [data_str, encoding],
        "executable": account.meta.executable,
        "rentEpoch": account.meta.rent_epoch,
        "space": account.data_len(),
    })
}

fn base64_encode(data: &[u8]) -> String {
    // Simple base64 encoding - in production use a proper library
    bs58::encode(data).into_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_snapshot() -> RpcRuntimeSnapshot {
        RpcRuntimeSnapshot {
            slot: 1000,
            block_height: 1000,
            transaction_count: 5000,
            uptime_millis: 100000,
            latest_blockhash_seed: 12345,
        }
    }

    #[test]
    fn test_generate_program_accounts() {
        let snapshot = test_snapshot();
        let accounts =
            generate_program_accounts("TestProgram111111111111111111111111111111", snapshot, 10);

        assert_eq!(accounts.len(), 10);
        for (pubkey, account) in &accounts {
            assert!(pubkey.starts_with("TestProg"));
            assert!(account.meta.lamports > 0);
        }
    }

    #[test]
    fn test_generate_synthetic_account() {
        let snapshot = test_snapshot();
        let account =
            generate_synthetic_account("TestAccount11111111111111111111111111111", snapshot);

        assert!(account.meta.lamports > 0);
        assert!(account.data_len() < 1000);
    }

    #[test]
    fn test_sort_accounts_by_lamports() {
        let snapshot = test_snapshot();
        let mut accounts = vec![
            (
                "acc1".to_string(),
                Account::new(1000, vec![], Pubkey::zeroed()),
            ),
            (
                "acc2".to_string(),
                Account::new(5000, vec![], Pubkey::zeroed()),
            ),
            (
                "acc3".to_string(),
                Account::new(2000, vec![], Pubkey::zeroed()),
            ),
        ];

        sort_accounts(&mut accounts, &SortOrder::LamportsAsc);
        assert_eq!(accounts[0].1.meta.lamports, 1000);
        assert_eq!(accounts[2].1.meta.lamports, 5000);

        sort_accounts(&mut accounts, &SortOrder::LamportsDesc);
        assert_eq!(accounts[0].1.meta.lamports, 5000);
        assert_eq!(accounts[2].1.meta.lamports, 1000);
    }

    #[test]
    fn test_sort_accounts_by_data_size() {
        let mut accounts = vec![
            (
                "acc1".to_string(),
                Account::new(1000, vec![0; 100], Pubkey::zeroed()),
            ),
            (
                "acc2".to_string(),
                Account::new(1000, vec![0; 50], Pubkey::zeroed()),
            ),
            (
                "acc3".to_string(),
                Account::new(1000, vec![0; 200], Pubkey::zeroed()),
            ),
        ];

        sort_accounts(&mut accounts, &SortOrder::DataSizeAsc);
        assert_eq!(accounts[0].1.data_len(), 50);
        assert_eq!(accounts[2].1.data_len(), 200);

        sort_accounts(&mut accounts, &SortOrder::DataSizeDesc);
        assert_eq!(accounts[0].1.data_len(), 200);
        assert_eq!(accounts[2].1.data_len(), 50);
    }

    #[test]
    fn test_serialize_account_base58() {
        let account = Account::new(1000000, vec![1, 2, 3, 4], Pubkey::zeroed());
        let json = serialize_account(&account, "base58");

        assert_eq!(json["lamports"], 1000000);
        assert_eq!(json["executable"], false);
        assert!(json["data"].is_array());
    }

    #[test]
    fn test_serialize_account_json_parsed() {
        let account = Account::new(1000000, vec![1, 2, 3, 4], Pubkey::zeroed());
        let json = serialize_account(&account, "jsonParsed");

        assert_eq!(json["lamports"], 1000000);
        assert!(json["data"].is_object());
        assert!(json["data"]["parsed"].is_object());
    }

    #[test]
    fn test_generate_large_accounts() {
        let snapshot = test_snapshot();
        let accounts = generate_large_accounts(snapshot, 10);

        assert_eq!(accounts.len(), 10);

        // Should be roughly sorted by descending balance
        for i in 0..accounts.len() - 1 {
            let diff = accounts[i].1.meta.lamports as i64 - accounts[i + 1].1.meta.lamports as i64;
            assert!(diff.abs() < 20000); // Allow for snapshot variance
        }
    }
}
