/// Performance benchmarks and utilities for RPC components
#[cfg(test)]
mod tests {
    use crate::cache::{AccountCache, BlockCache, SignatureCache};
    use crate::filters::{apply_filters, RpcFilterType};
    use crate::simulation::TransactionSimulator;
    use crate::state::{RpcCommitment, RpcRuntimeSnapshot};
    use crate::websocket::SubscriptionManager;
    use paradencer_types::{Account, Pubkey};
    use std::time::{Duration, Instant};

    fn test_snapshot() -> RpcRuntimeSnapshot {
        RpcRuntimeSnapshot {
            slot: 1000,
            block_height: 1000,
            transaction_count: 5000,
            uptime_millis: 100000,
            latest_blockhash_seed: 12345,
        }
    }

    struct BenchmarkResult {
        name: String,
        iterations: usize,
        total_duration: Duration,
        avg_duration: Duration,
        ops_per_sec: f64,
    }

    impl BenchmarkResult {
        fn print(&self) {
            println!("\n=== Benchmark: {} ===", self.name);
            println!("Iterations: {}", self.iterations);
            println!("Total time: {:?}", self.total_duration);
            println!("Avg time: {:?}", self.avg_duration);
            println!("Ops/sec: {:.2}", self.ops_per_sec);
        }
    }

    fn benchmark<F>(name: &str, iterations: usize, mut f: F) -> BenchmarkResult
    where
        F: FnMut(),
    {
        let start = Instant::now();
        for _ in 0..iterations {
            f();
        }
        let total_duration = start.elapsed();
        let avg_duration = total_duration / iterations as u32;
        let ops_per_sec = iterations as f64 / total_duration.as_secs_f64();

        BenchmarkResult {
            name: name.to_string(),
            iterations,
            total_duration,
            avg_duration,
            ops_per_sec,
        }
    }

    #[test]
    fn bench_account_cache_insert() {
        let cache = AccountCache::new(10000, 60);
        let account = Account::new(1000000, vec![1, 2, 3, 4], Pubkey::zeroed());

        let result = benchmark("AccountCache Insert", 10000, || {
            cache.insert(
                "test_account".to_string(),
                account.clone(),
                1000,
                RpcCommitment::Confirmed,
            );
        });

        result.print();
        assert!(result.ops_per_sec > 1000.0); // Should be fast
    }

    #[test]
    fn bench_account_cache_get() {
        let cache = AccountCache::new(10000, 60);
        let account = Account::new(1000000, vec![1, 2, 3, 4], Pubkey::zeroed());

        // Pre-populate cache
        for i in 0..1000 {
            cache.insert(
                format!("account_{}", i),
                account.clone(),
                1000,
                RpcCommitment::Confirmed,
            );
        }

        let result = benchmark("AccountCache Get", 10000, || {
            let _ = cache.get("account_500", RpcCommitment::Confirmed);
        });

        result.print();
        assert!(result.ops_per_sec > 10000.0); // Reads should be very fast
    }

    #[test]
    fn bench_account_cache_eviction() {
        let cache = AccountCache::new(100, 60);
        let account = Account::new(1000000, vec![1, 2, 3, 4], Pubkey::zeroed());

        let result = benchmark("AccountCache with Eviction", 1000, || {
            cache.insert(
                format!("account_{}", rand::random::<u32>()),
                account.clone(),
                1000,
                RpcCommitment::Confirmed,
            );
        });

        result.print();
        // With eviction, should still be reasonably fast
        assert!(result.ops_per_sec > 100.0);
    }

    #[test]
    fn bench_block_cache_operations() {
        let cache = BlockCache::new(1000, 60);

        let result = benchmark("BlockCache Prefetch Range", 100, || {
            cache.prefetch_range(1000, 50, RpcCommitment::Confirmed);
        });

        result.print();
        assert!(result.ops_per_sec > 10.0);
    }

    #[test]
    fn bench_signature_cache_batch_get() {
        let cache = SignatureCache::new(10000, 60);

        // Pre-populate
        for i in 0..1000 {
            cache.insert(format!("sig_{}", i), 1000 + i, RpcCommitment::Confirmed);
        }

        let signatures: Vec<String> = (0..100).map(|i| format!("sig_{}", i)).collect();

        let result = benchmark("SignatureCache Batch Get", 1000, || {
            let _ = cache.get_batch(&signatures);
        });

        result.print();
        assert!(result.ops_per_sec > 100.0);
    }

    #[test]
    fn bench_filter_application() {
        let accounts: Vec<_> = (0..1000)
            .map(|i| {
                (
                    format!("account_{}", i),
                    Account::new(1000 + i, vec![i as u8; 100], Pubkey::zeroed()),
                )
            })
            .collect();

        let filters = vec![
            RpcFilterType::LamportsRange {
                min: Some(5000),
                max: None,
            },
            RpcFilterType::DataSize(100),
        ];

        let result = benchmark("Filter Application", 100, || {
            let _ = apply_filters(&accounts, &filters);
        });

        result.print();
        assert!(result.ops_per_sec > 10.0);
    }

    #[test]
    fn bench_transaction_simulation() {
        let simulator = TransactionSimulator::new();
        let snapshot = test_snapshot();
        let tx = vec![1, 2, 3, 4, 5, 6, 7, 8];

        let config = crate::simulation::SimulationConfig {
            sig_verify: false,
            replace_recent_blockhash: true,
            commitment: RpcCommitment::Confirmed,
            inner_instructions: false,
            accounts: None,
        };

        let result = benchmark("Transaction Simulation", 1000, || {
            let _ = simulator.simulate(&tx, config.clone(), snapshot);
        });

        result.print();
        assert!(result.ops_per_sec > 100.0);
    }

    #[test]
    fn bench_subscription_notifications() {
        let manager = SubscriptionManager::new();
        let snapshot = test_snapshot();

        // Create subscriptions
        for _ in 0..100 {
            manager.subscribe_slot(RpcCommitment::Confirmed);
        }

        let result = benchmark("Subscription Notification Broadcast", 1000, || {
            manager.notify_slot(snapshot);
        });

        result.print();
        assert!(result.ops_per_sec > 100.0);
    }

    #[test]
    fn bench_concurrent_cache_access() {
        use std::sync::Arc;
        use std::thread;

        let cache = Arc::new(AccountCache::new(1000, 60));
        let account = Account::new(1000000, vec![1, 2, 3, 4], Pubkey::zeroed());

        // Pre-populate
        for i in 0..500 {
            cache.insert(
                format!("account_{}", i),
                account.clone(),
                1000,
                RpcCommitment::Confirmed,
            );
        }

        let start = Instant::now();
        let mut handles = vec![];

        for thread_id in 0..4 {
            let cache_clone = Arc::clone(&cache);
            let account_clone = account.clone();

            let handle = thread::spawn(move || {
                for i in 0..250 {
                    // Mix reads and writes
                    if i % 2 == 0 {
                        cache_clone.get(
                            &format!("account_{}", thread_id * 100 + i),
                            RpcCommitment::Confirmed,
                        );
                    } else {
                        cache_clone.insert(
                            format!("account_new_{}_{}", thread_id, i),
                            account_clone.clone(),
                            1000,
                            RpcCommitment::Confirmed,
                        );
                    }
                }
            });

            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let duration = start.elapsed();
        let ops_per_sec = (4 * 250) as f64 / duration.as_secs_f64();

        println!("\n=== Concurrent Cache Access ===");
        println!("Threads: 4");
        println!("Ops per thread: 250");
        println!("Total ops: {}", 4 * 250);
        println!("Duration: {:?}", duration);
        println!("Ops/sec: {:.2}", ops_per_sec);

        assert!(ops_per_sec > 1000.0);
    }

    #[test]
    fn bench_memory_usage() {
        let cache = AccountCache::new(10000, 60);
        let account = Account::new(1000000, vec![1; 1024], Pubkey::zeroed()); // 1KB data

        // Insert 1000 accounts
        for i in 0..1000 {
            cache.insert(
                format!("account_{}", i),
                account.clone(),
                1000,
                RpcCommitment::Confirmed,
            );
        }

        println!("\n=== Memory Usage Test ===");
        println!("Cache entries: {}", cache.len());
        println!("Account data size: 1KB");
        println!("Estimated memory: ~{}KB", cache.len());

        // Verify cache size
        assert_eq!(cache.len(), 1000);
    }

    #[test]
    fn bench_cache_hit_rate() {
        let cache = AccountCache::new(100, 60);
        let account = Account::new(1000000, vec![1, 2, 3], Pubkey::zeroed());

        // Populate cache
        for i in 0..100 {
            cache.insert(
                format!("account_{}", i),
                account.clone(),
                1000,
                RpcCommitment::Confirmed,
            );
        }

        // Perform mixed access (80% hits, 20% misses)
        for i in 0..1000 {
            if i % 5 == 0 {
                // Miss
                cache.get(&format!("account_{}", i + 1000), RpcCommitment::Confirmed);
            } else {
                // Hit
                cache.get(&format!("account_{}", i % 100), RpcCommitment::Confirmed);
            }
        }

        let stats = cache.stats();
        let hit_rate = stats.hit_rate();

        println!("\n=== Cache Hit Rate Test ===");
        println!("Total hits: {}", stats.hits);
        println!("Total misses: {}", stats.misses);
        println!("Hit rate: {:.2}%", hit_rate * 100.0);

        assert!(hit_rate > 0.75); // Should be around 80%
    }

    #[test]
    fn bench_large_batch_operations() {
        let cache = SignatureCache::new(10000, 60);

        // Insert large batch
        let start = Instant::now();
        for i in 0..5000 {
            cache.insert(format!("sig_{}", i), 1000 + i, RpcCommitment::Confirmed);
        }
        let insert_duration = start.elapsed();

        // Batch get
        let signatures: Vec<String> = (0..1000).map(|i| format!("sig_{}", i)).collect();
        let start = Instant::now();
        let results = cache.get_batch(&signatures);
        let get_duration = start.elapsed();

        println!("\n=== Large Batch Operations ===");
        println!("Batch insert (5000): {:?}", insert_duration);
        println!("Batch get (1000): {:?}", get_duration);
        println!(
            "Insert ops/sec: {:.2}",
            5000.0 / insert_duration.as_secs_f64()
        );
        println!("Get ops/sec: {:.2}", 1000.0 / get_duration.as_secs_f64());

        assert_eq!(results.len(), 1000);
    }

    #[test]
    fn bench_subscription_scalability() {
        let manager = SubscriptionManager::new();

        // Create many subscriptions
        let start = Instant::now();
        for i in 0..1000 {
            manager.subscribe_account(format!("account_{}", i), RpcCommitment::Confirmed);
        }
        let create_duration = start.elapsed();

        // Test notification with many subscribers
        let snapshot = test_snapshot();
        let account = Account::new(1000000, vec![1, 2, 3], Pubkey::zeroed());

        let start = Instant::now();
        for i in 0..100 {
            manager.notify_account(&format!("account_{}", i), &account, snapshot);
        }
        let notify_duration = start.elapsed();

        println!("\n=== Subscription Scalability ===");
        println!("Create 1000 subscriptions: {:?}", create_duration);
        println!("100 notifications: {:?}", notify_duration);
        println!(
            "Create rate: {:.2}/sec",
            1000.0 / create_duration.as_secs_f64()
        );
        println!(
            "Notify rate: {:.2}/sec",
            100.0 / notify_duration.as_secs_f64()
        );

        assert_eq!(manager.subscription_count(), 1000);
    }

    // Helper for random data generation
    mod rand {
        use std::sync::atomic::{AtomicU32, Ordering};

        static SEED: AtomicU32 = AtomicU32::new(12345);

        pub fn random<T>() -> T
        where
            T: From<u32>,
        {
            let x = SEED.load(Ordering::Relaxed);
            let x = x.wrapping_mul(1103515245).wrapping_add(12345);
            SEED.store(x, Ordering::Relaxed);
            T::from(x)
        }
    }
}
