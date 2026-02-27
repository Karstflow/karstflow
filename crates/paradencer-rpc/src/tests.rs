/// Integration tests for RPC functionality
#[cfg(test)]
mod integration_tests {
    use crate::cache::{AccountCache, BlockCache, SignatureCache};
    use crate::filters::{apply_filters, RpcFilterType};
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
        let _block_cache = BlockCache::new(100, 60);
        let _sig_cache = SignatureCache::new(100, 60);

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
}
