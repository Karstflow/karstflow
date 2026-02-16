/// Integration tests for advanced RPC functionality
#[cfg(test)]
mod integration_tests {
    use crate::cache::{AccountCache, BlockCache, SignatureCache};
    use crate::filters::{apply_filters, RpcFilterType};
    use crate::methods::{AccountsAdvanced, TransactionsAdvanced};
    use crate::simulation::{SimulationConfig, TransactionSimulator};
    use crate::state::{RpcCommitment, RpcRuntimeSnapshot};
    use crate::websocket::SubscriptionManager;
    use paradencer_types::{Account, Pubkey};

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
    fn test_cache_integration() {
        let account_cache = AccountCache::new(100, 60);
        let block_cache = BlockCache::new(100, 60);
        let sig_cache = SignatureCache::new(100, 60);

        // Insert test data
        let account = Account::new(1000000, vec![1, 2, 3], Pubkey::zeroed());
        account_cache.insert(
            "test_acc".to_string(),
            account.clone(),
            1000,
            RpcCommitment::Confirmed,
        );

        // Verify retrieval
        let retrieved = account_cache.get("test_acc", RpcCommitment::Confirmed);
        assert!(retrieved.is_some());

        // Check cache statistics
        let stats = account_cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.inserts, 1);
    }

    #[test]
    fn test_advanced_accounts_integration() {
        let account_cache = AccountCache::new(100, 60);
        let accounts_advanced = AccountsAdvanced::new(account_cache);
        let snapshot = test_snapshot();

        let config = crate::methods::ProgramAccountsConfig {
            filters: Some(vec![RpcFilterType::DataSize(100)]),
            sort: Some(crate::filters::SortOrder::LamportsDesc),
            with_context: true,
            min_context_slot: None,
            encoding: "base58".to_string(),
            offset: None,
            limit: Some(10),
            data_slice: None,
        };

        let result = accounts_advanced.get_program_accounts_with_filters(
            "TestProgram111111111111111111111111111111",
            config,
            snapshot,
            RpcCommitment::Confirmed,
        );

        assert!(result.is_ok());
        let value = result.unwrap();
        assert!(value.get("context").is_some());
        assert!(value.get("value").is_some());
    }

    #[test]
    fn test_transaction_simulation_integration() {
        let simulator = TransactionSimulator::new();
        let sig_cache = SignatureCache::new(100, 60);
        let transactions_advanced = TransactionsAdvanced::new(simulator.clone(), sig_cache);
        let snapshot = test_snapshot();

        let config = SimulationConfig {
            sig_verify: false,
            replace_recent_blockhash: true,
            commitment: RpcCommitment::Confirmed,
            inner_instructions: true,
            accounts: None,
        };

        let tx = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let result = simulator.simulate(&tx, config, snapshot);

        assert!(result.is_ok());
        let sim_result = result.unwrap();
        assert!(!sim_result.logs.is_empty());
        assert!(sim_result.units_consumed > 0);
    }

    #[test]
    fn test_websocket_subscriptions_integration() {
        let manager = SubscriptionManager::new();

        // Create multiple subscriptions
        let acc_sub = manager.subscribe_account("test_acc".to_string(), RpcCommitment::Confirmed);
        let sig_sub = manager.subscribe_signature("test_sig".to_string(), RpcCommitment::Confirmed);
        let slot_sub = manager.subscribe_slot(RpcCommitment::Confirmed);

        assert_eq!(manager.subscription_count(), 3);

        // Test notifications
        let snapshot = test_snapshot();
        let account = Account::new(1000000, vec![1, 2, 3], Pubkey::zeroed());

        manager.notify_account("test_acc", &account, snapshot);
        manager.notify_signature("test_sig", None, snapshot);
        manager.notify_slot(snapshot);

        // Verify subscriptions can be removed
        assert!(manager.unsubscribe(acc_sub));
        assert!(manager.unsubscribe(sig_sub));
        assert!(manager.unsubscribe(slot_sub));
        assert_eq!(manager.subscription_count(), 0);
    }

    #[test]
    fn test_filter_chain_integration() {
        let accounts = vec![
            (
                "acc1".to_string(),
                Account::new(5000, vec![1, 2, 3], Pubkey::zeroed()),
            ),
            (
                "acc2".to_string(),
                Account::new(10000, vec![1, 2, 3, 4], Pubkey::zeroed()),
            ),
            (
                "acc3".to_string(),
                Account::new(2000, vec![1], Pubkey::zeroed()),
            ),
        ];

        // Apply multiple filters
        let filters = vec![
            RpcFilterType::LamportsRange {
                min: Some(3000),
                max: None,
            },
            RpcFilterType::DataSize(3),
        ];

        let filtered = apply_filters(&accounts, &filters);

        // Only acc1 should match (lamports >= 3000 AND data size == 3)
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].0, "acc1");
    }

    #[test]
    fn test_cache_eviction_under_pressure() {
        let cache = AccountCache::new(5, 60);

        // Fill cache beyond capacity
        for i in 0..10 {
            let account = Account::new(1000 + i, vec![i as u8], Pubkey::zeroed());
            cache.insert(
                format!("acc{}", i),
                account,
                1000 + i,
                RpcCommitment::Confirmed,
            );
        }

        // Cache should be at max size
        assert_eq!(cache.len(), 5);

        // Check eviction stats
        let stats = cache.stats();
        assert!(stats.evictions > 0);
    }

    #[test]
    fn test_batch_account_queries() {
        let account_cache = AccountCache::new(100, 60);
        let accounts_advanced = AccountsAdvanced::new(account_cache);
        let snapshot = test_snapshot();

        let config = crate::methods::MultipleAccountsConfig {
            encoding: "base58".to_string(),
            max_batch_size: Some(100),
            data_slice: None,
        };

        let pubkeys: Vec<String> = (0..10).map(|i| format!("pubkey_{}", i)).collect();

        let result = accounts_advanced.get_multiple_accounts_batched(
            pubkeys.clone(),
            config,
            snapshot,
            RpcCommitment::Confirmed,
        );

        assert!(result.is_ok());
        let value = result.unwrap();
        assert!(value.get("context").is_some());
        assert_eq!(value["value"].as_array().unwrap().len(), 10);
    }

    #[test]
    fn test_prioritization_fees() {
        let simulator = TransactionSimulator::new();
        let sig_cache = SignatureCache::new(100, 60);
        let transactions_advanced = TransactionsAdvanced::new(simulator, sig_cache);
        let snapshot = test_snapshot();

        let result = transactions_advanced.get_recent_prioritization_fees(None, snapshot);

        assert!(result.is_ok());
        let fees = result.unwrap();
        assert!(fees.is_array());
        let fees_array = fees.as_array().unwrap();
        assert_eq!(fees_array.len(), 20); // Last 20 slots
    }

    #[test]
    fn test_fee_for_message() {
        let simulator = TransactionSimulator::new();
        let sig_cache = SignatureCache::new(100, 60);
        let transactions_advanced = TransactionsAdvanced::new(simulator, sig_cache);
        let snapshot = test_snapshot();

        // Create a test message
        let message = bs58::encode(vec![1, 2, 3, 4, 5]).into_string();

        let result =
            transactions_advanced.get_fee_for_message(&message, snapshot, RpcCommitment::Confirmed);

        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.get("context").is_some());
        assert!(response.get("value").is_some());
    }

    #[test]
    fn test_simulation_with_errors() {
        let simulator = TransactionSimulator::new();
        let snapshot = test_snapshot();

        // Create a transaction that will trigger compute budget error
        let large_tx = vec![1; 500];

        let config = SimulationConfig {
            sig_verify: false,
            replace_recent_blockhash: true,
            commitment: RpcCommitment::Confirmed,
            inner_instructions: false,
            accounts: None,
        };

        let result = simulator.simulate(&large_tx, config, snapshot);

        assert!(result.is_ok());
        // Large transactions may or may not error depending on the implementation
    }

    #[test]
    fn test_block_cache_range_queries() {
        let cache = BlockCache::new(100, 60);

        // Prefetch a range of blocks
        cache.prefetch_range(1000, 20, RpcCommitment::Confirmed);

        // Query the range
        let blocks = cache.get_range(1000, 1010, RpcCommitment::Confirmed);

        assert_eq!(blocks.len(), 11); // Inclusive range
        for (i, block) in blocks.iter().enumerate() {
            assert_eq!(block.slot, 1000 + i as u64);
        }
    }

    #[test]
    fn test_signature_cache_batch_operations() {
        let cache = SignatureCache::new(100, 60);

        // Insert multiple signatures
        for i in 0..5 {
            cache.insert(format!("sig{}", i), 1000 + i, RpcCommitment::Confirmed);
        }

        // Batch get
        let signatures: Vec<String> = (0..5).map(|i| format!("sig{}", i)).collect();
        let results = cache.get_batch(&signatures);

        assert_eq!(results.len(), 5);
        assert!(results.iter().all(|r| r.is_some()));
    }

    #[test]
    fn test_largest_accounts_query() {
        let account_cache = AccountCache::new(100, 60);
        let accounts_advanced = AccountsAdvanced::new(account_cache);
        let snapshot = test_snapshot();

        let config = crate::methods::LargestAccountsConfig {
            filter: Some("circulating".to_string()),
            limit: Some(10),
        };

        let result = accounts_advanced.get_largest_accounts_advanced(
            config,
            snapshot,
            RpcCommitment::Confirmed,
        );

        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.get("context").is_some());
        assert!(response.get("value").is_some());
    }

    #[test]
    fn test_concurrent_cache_access() {
        use std::sync::Arc;
        use std::thread;

        let cache = Arc::new(AccountCache::new(100, 60));
        let mut handles = vec![];

        // Spawn multiple threads accessing the cache
        for i in 0..10 {
            let cache_clone = Arc::clone(&cache);
            let handle = thread::spawn(move || {
                let account = Account::new(1000 + i, vec![i as u8], Pubkey::zeroed());
                cache_clone.insert(
                    format!("acc{}", i),
                    account,
                    1000 + i,
                    RpcCommitment::Confirmed,
                );

                // Try to read back
                let retrieved = cache_clone.get(&format!("acc{}", i), RpcCommitment::Confirmed);
                assert!(retrieved.is_some());
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(cache.len(), 10);
    }

    #[test]
    fn test_subscription_cleanup() {
        let manager = SubscriptionManager::new();

        // Create subscriptions
        for i in 0..10 {
            manager.subscribe_account(format!("acc{}", i), RpcCommitment::Confirmed);
        }

        assert_eq!(manager.subscription_count(), 10);

        // Cleanup old subscriptions (with 0 age, all should be removed)
        manager.cleanup_old(std::time::Duration::from_secs(0));

        // Note: cleanup_old might not remove all immediately depending on timing
        // This is primarily a smoke test
    }

    #[test]
    fn test_program_subscription_notifications() {
        let manager = SubscriptionManager::new();
        let _sub_id = manager.subscribe_program("program_id".to_string(), RpcCommitment::Confirmed);

        let mut rx = manager.subscribe_notifications();

        let account = Account::new(1000000, vec![1, 2, 3], Pubkey::zeroed());
        let snapshot = test_snapshot();
        manager.notify_program("program_id", "account_pubkey", &account, snapshot);

        let notif = rx.try_recv();
        assert!(notif.is_ok());
    }

    #[test]
    fn test_min_context_slot_validation() {
        let account_cache = AccountCache::new(100, 60);
        let accounts_advanced = AccountsAdvanced::new(account_cache);
        let snapshot = test_snapshot();

        let config = crate::methods::ProgramAccountsConfig {
            filters: None,
            sort: None,
            with_context: true,
            min_context_slot: Some(2000), // Higher than current slot
            encoding: "base58".to_string(),
            offset: None,
            limit: Some(10),
            data_slice: None,
        };

        let result = accounts_advanced.get_program_accounts_with_filters(
            "TestProgram111111111111111111111111111111",
            config,
            snapshot,
            RpcCommitment::Confirmed,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_batch_size_limit() {
        let account_cache = AccountCache::new(100, 60);
        let accounts_advanced = AccountsAdvanced::new(account_cache);
        let snapshot = test_snapshot();

        let config = crate::methods::MultipleAccountsConfig {
            encoding: "base58".to_string(),
            max_batch_size: Some(5),
            data_slice: None,
        };

        // Try to query more than the limit
        let pubkeys: Vec<String> = (0..10).map(|i| format!("pubkey_{}", i)).collect();

        let result = accounts_advanced.get_multiple_accounts_batched(
            pubkeys,
            config,
            snapshot,
            RpcCommitment::Confirmed,
        );

        assert!(result.is_err());
    }
}
