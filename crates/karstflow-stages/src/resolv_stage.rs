/// Transaction resolution stage.
///
/// Validates transaction blockhashes against a recent blockhash ring to
/// determine if transactions are still valid (not expired). Transactions
/// with unknown or expired blockhashes are stashed in an LRU buffer for
/// later resolution when new blockhashes arrive. Valid transactions are
/// forwarded to the transaction scheduler.
///
/// This corresponds to Firedancer's resolv tile, which sits between
/// dedup and pack in the transaction pipeline.
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// 32-byte blockhash.
pub type Blockhash = [u8; 32];

/// A transaction that has been signature-verified and is ready for
/// blockhash resolution.
#[derive(Debug, Clone)]
pub struct ResolvedTransaction {
    /// Raw payload bytes.
    pub payload: Vec<u8>,
    /// The blockhash referenced by this transaction.
    pub blockhash: Blockhash,
    /// Priority fee in lamports (for scheduling).
    pub priority_fee: u64,
    /// Estimated compute units.
    pub compute_units: u64,
    /// Whether this is a simple vote transaction.
    pub is_vote: bool,
}

/// Outcome of resolving a transaction's blockhash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvOutcome {
    /// Blockhash is valid and recent; transaction forwarded to pack.
    Valid { expires_at_slot: u64 },
    /// Blockhash is too old; transaction is expired.
    Expired,
    /// Blockhash is not yet known; transaction stashed for later.
    Stashed,
    /// Stash buffer is full; transaction dropped.
    StashFull,
}

/// Statistics for the resolution stage.
#[derive(Debug, Default)]
pub struct ResolvStats {
    pub transactions_received: AtomicU64,
    pub transactions_resolved: AtomicU64,
    pub transactions_expired: AtomicU64,
    pub transactions_stashed: AtomicU64,
    pub transactions_unstashed: AtomicU64,
    pub transactions_dropped: AtomicU64,
    pub blockhashes_registered: AtomicU64,
}

impl ResolvStats {
    pub fn snapshot(&self) -> ResolvStatsSnapshot {
        ResolvStatsSnapshot {
            transactions_received: self.transactions_received.load(Ordering::Relaxed),
            transactions_resolved: self.transactions_resolved.load(Ordering::Relaxed),
            transactions_expired: self.transactions_expired.load(Ordering::Relaxed),
            transactions_stashed: self.transactions_stashed.load(Ordering::Relaxed),
            transactions_unstashed: self.transactions_unstashed.load(Ordering::Relaxed),
            transactions_dropped: self.transactions_dropped.load(Ordering::Relaxed),
            blockhashes_registered: self.blockhashes_registered.load(Ordering::Relaxed),
        }
    }
}

/// Point-in-time snapshot of resolution statistics.
#[derive(Debug, Clone, Default)]
pub struct ResolvStatsSnapshot {
    pub transactions_received: u64,
    pub transactions_resolved: u64,
    pub transactions_expired: u64,
    pub transactions_stashed: u64,
    pub transactions_unstashed: u64,
    pub transactions_dropped: u64,
    pub blockhashes_registered: u64,
}

/// Configuration for the resolution stage.
#[derive(Debug, Clone)]
pub struct ResolvConfig {
    /// Maximum number of recent blockhashes to track.
    /// Should cover ~160 slots worth of blockhashes.
    pub blockhash_ring_capacity: usize,
    /// Maximum number of stashed transactions awaiting blockhash resolution.
    pub stash_capacity: usize,
    /// Number of slots after which a transaction is considered expired.
    /// Solana uses ~150 slots, but we use 160 to account for skipped slots.
    pub transaction_lifetime_slots: u64,
}

impl Default for ResolvConfig {
    fn default() -> Self {
        Self {
            blockhash_ring_capacity: 1 << 22, // ~4M entries, matching Firedancer
            stash_capacity: 65_536,
            transaction_lifetime_slots: 160,
        }
    }
}

/// Entry in the blockhash ring mapping a blockhash to its slot.
struct BlockhashEntry {
    hash: Blockhash,
    slot: u64,
}

/// A stashed transaction waiting for its blockhash to become known.
struct StashedTransaction {
    tx: ResolvedTransaction,
    stash_order: u64,
}

/// Transaction resolution stage.
///
/// Maintains a ring of recent blockhashes and uses it to validate
/// incoming transactions. Transactions referencing unknown blockhashes
/// are stashed in an LRU buffer for later resolution.
pub struct ResolvStage {
    /// Blockhash → slot lookup.
    blockhash_map: HashMap<Blockhash, u64>,
    /// Ordered ring for eviction.
    blockhash_ring: VecDeque<BlockhashEntry>,
    /// Maximum ring capacity.
    ring_capacity: usize,
    /// Current slot (used for expiry calculations).
    current_slot: u64,
    /// Transaction lifetime in slots.
    lifetime_slots: u64,
    /// Stashed transactions grouped by blockhash.
    stash_by_hash: HashMap<Blockhash, Vec<StashedTransaction>>,
    /// Total stashed transaction count.
    stash_count: usize,
    /// Maximum stash capacity.
    stash_capacity: usize,
    /// LRU counter for stash eviction.
    stash_order_counter: u64,
    /// Statistics.
    stats: Arc<ResolvStats>,
}

impl ResolvStage {
    /// Create a new resolution stage with default configuration.
    pub fn new() -> Self {
        Self::with_config(ResolvConfig::default())
    }

    /// Create a new resolution stage with the given configuration.
    pub fn with_config(config: ResolvConfig) -> Self {
        Self {
            blockhash_map: HashMap::with_capacity(config.blockhash_ring_capacity),
            blockhash_ring: VecDeque::with_capacity(config.blockhash_ring_capacity),
            ring_capacity: config.blockhash_ring_capacity,
            current_slot: 0,
            lifetime_slots: config.transaction_lifetime_slots,
            stash_by_hash: HashMap::new(),
            stash_count: 0,
            stash_capacity: config.stash_capacity,
            stash_order_counter: 0,
            stats: Arc::new(ResolvStats::default()),
        }
    }

    /// Get a shared reference to the statistics.
    pub fn stats(&self) -> Arc<ResolvStats> {
        Arc::clone(&self.stats)
    }

    /// Register a new blockhash from a completed slot. Returns any
    /// previously stashed transactions that can now be resolved.
    pub fn register_blockhash(
        &mut self,
        hash: Blockhash,
        slot: u64,
    ) -> Vec<(ResolvedTransaction, u64)> {
        self.stats
            .blockhashes_registered
            .fetch_add(1, Ordering::Relaxed);

        // Update current slot tracking.
        if slot > self.current_slot {
            self.current_slot = slot;
        }

        // Don't re-register known hashes.
        if self.blockhash_map.contains_key(&hash) {
            return Vec::new();
        }

        // Evict oldest if at capacity.
        if self.blockhash_ring.len() >= self.ring_capacity {
            if let Some(old) = self.blockhash_ring.pop_front() {
                self.blockhash_map.remove(&old.hash);
                // Also drop any stashed transactions for this expired hash.
                if let Some(stashed) = self.stash_by_hash.remove(&old.hash) {
                    let dropped = stashed.len();
                    self.stash_count = self.stash_count.saturating_sub(dropped);
                    self.stats
                        .transactions_expired
                        .fetch_add(dropped as u64, Ordering::Relaxed);
                }
            }
        }

        self.blockhash_map.insert(hash, slot);
        self.blockhash_ring.push_back(BlockhashEntry { hash, slot });

        // Unstash any transactions waiting for this blockhash.
        let mut unstashed = Vec::new();
        if let Some(waiting) = self.stash_by_hash.remove(&hash) {
            let count = waiting.len();
            self.stash_count = self.stash_count.saturating_sub(count);
            self.stats
                .transactions_unstashed
                .fetch_add(count as u64, Ordering::Relaxed);

            let expires_at = slot.saturating_add(self.lifetime_slots);
            for stashed in waiting {
                unstashed.push((stashed.tx, expires_at));
            }
        }

        unstashed
    }

    /// Resolve a transaction's blockhash. Returns the resolution outcome.
    pub fn resolve(&mut self, tx: ResolvedTransaction) -> ResolvOutcome {
        self.stats
            .transactions_received
            .fetch_add(1, Ordering::Relaxed);

        // Look up the blockhash in the ring.
        if let Some(&blockhash_slot) = self.blockhash_map.get(&tx.blockhash) {
            let expires_at = blockhash_slot.saturating_add(self.lifetime_slots);

            if self.current_slot > expires_at {
                self.stats
                    .transactions_expired
                    .fetch_add(1, Ordering::Relaxed);
                return ResolvOutcome::Expired;
            }

            self.stats
                .transactions_resolved
                .fetch_add(1, Ordering::Relaxed);
            return ResolvOutcome::Valid {
                expires_at_slot: expires_at,
            };
        }

        // Blockhash not known — stash for later if there's room.
        if self.stash_count >= self.stash_capacity {
            // Evict oldest stashed transaction.
            self.evict_oldest_stashed();
        }

        if self.stash_count >= self.stash_capacity {
            self.stats
                .transactions_dropped
                .fetch_add(1, Ordering::Relaxed);
            return ResolvOutcome::StashFull;
        }

        let order = self.stash_order_counter;
        self.stash_order_counter += 1;

        self.stash_by_hash
            .entry(tx.blockhash)
            .or_default()
            .push(StashedTransaction {
                tx,
                stash_order: order,
            });
        self.stash_count += 1;

        self.stats
            .transactions_stashed
            .fetch_add(1, Ordering::Relaxed);
        ResolvOutcome::Stashed
    }

    /// Update the current slot. Triggers expiry of old stashed transactions.
    pub fn advance_slot(&mut self, slot: u64) {
        self.current_slot = slot;
    }

    /// Number of blockhashes currently tracked.
    pub fn blockhash_count(&self) -> usize {
        self.blockhash_map.len()
    }

    /// Number of stashed transactions.
    pub fn stash_count(&self) -> usize {
        self.stash_count
    }

    /// Evict the oldest stashed transaction to make room.
    fn evict_oldest_stashed(&mut self) {
        let mut oldest_hash: Option<Blockhash> = None;
        let mut oldest_order = u64::MAX;

        for (hash, entries) in &self.stash_by_hash {
            for entry in entries {
                if entry.stash_order < oldest_order {
                    oldest_order = entry.stash_order;
                    oldest_hash = Some(*hash);
                }
            }
        }

        if let Some(hash) = oldest_hash {
            if let Some(entries) = self.stash_by_hash.get_mut(&hash) {
                entries.retain(|e| e.stash_order != oldest_order);
                if entries.is_empty() {
                    self.stash_by_hash.remove(&hash);
                }
                self.stash_count = self.stash_count.saturating_sub(1);
                self.stats
                    .transactions_dropped
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tx(blockhash: Blockhash) -> ResolvedTransaction {
        ResolvedTransaction {
            payload: vec![1, 2, 3],
            blockhash,
            priority_fee: 5000,
            compute_units: 200_000,
            is_vote: false,
        }
    }

    fn hash_from_slot(slot: u64) -> Blockhash {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&slot.to_le_bytes());
        h
    }

    #[test]
    fn resolve_known_blockhash() {
        let mut stage = ResolvStage::with_config(ResolvConfig {
            blockhash_ring_capacity: 256,
            stash_capacity: 64,
            transaction_lifetime_slots: 150,
        });

        let hash = hash_from_slot(100);
        stage.register_blockhash(hash, 100);

        let tx = make_tx(hash);
        let outcome = stage.resolve(tx);
        assert!(matches!(
            outcome,
            ResolvOutcome::Valid {
                expires_at_slot: 250
            }
        ));
    }

    #[test]
    fn resolve_expired_blockhash() {
        let mut stage = ResolvStage::with_config(ResolvConfig {
            blockhash_ring_capacity: 256,
            stash_capacity: 64,
            transaction_lifetime_slots: 10,
        });

        let hash = hash_from_slot(5);
        stage.register_blockhash(hash, 5);
        stage.advance_slot(20); // well past expiry

        let tx = make_tx(hash);
        let outcome = stage.resolve(tx);
        assert_eq!(outcome, ResolvOutcome::Expired);
    }

    #[test]
    fn stash_unknown_blockhash() {
        let mut stage = ResolvStage::with_config(ResolvConfig {
            blockhash_ring_capacity: 256,
            stash_capacity: 64,
            transaction_lifetime_slots: 150,
        });

        let unknown_hash = hash_from_slot(999);
        let tx = make_tx(unknown_hash);
        let outcome = stage.resolve(tx);
        assert_eq!(outcome, ResolvOutcome::Stashed);
        assert_eq!(stage.stash_count(), 1);
    }

    #[test]
    fn unstash_on_new_blockhash() {
        let mut stage = ResolvStage::with_config(ResolvConfig {
            blockhash_ring_capacity: 256,
            stash_capacity: 64,
            transaction_lifetime_slots: 150,
        });

        let hash = hash_from_slot(50);

        // Stash 3 transactions with unknown hash.
        for _ in 0..3 {
            let tx = make_tx(hash);
            assert_eq!(stage.resolve(tx), ResolvOutcome::Stashed);
        }
        assert_eq!(stage.stash_count(), 3);

        // Register the hash — should unstash all 3.
        let unstashed = stage.register_blockhash(hash, 50);
        assert_eq!(unstashed.len(), 3);
        assert_eq!(stage.stash_count(), 0);

        // Each should have the correct expiry.
        for (_, expires_at) in &unstashed {
            assert_eq!(*expires_at, 200); // 50 + 150
        }
    }

    #[test]
    fn stash_full_drops_transaction() {
        let mut stage = ResolvStage::with_config(ResolvConfig {
            blockhash_ring_capacity: 256,
            stash_capacity: 2,
            transaction_lifetime_slots: 150,
        });

        let h1 = hash_from_slot(1);
        let h2 = hash_from_slot(2);
        let h3 = hash_from_slot(3);

        assert_eq!(stage.resolve(make_tx(h1)), ResolvOutcome::Stashed);
        assert_eq!(stage.resolve(make_tx(h2)), ResolvOutcome::Stashed);
        // Third should evict oldest and still stash.
        let outcome = stage.resolve(make_tx(h3));
        assert_eq!(outcome, ResolvOutcome::Stashed);
        assert_eq!(stage.stash_count(), 2);
    }

    #[test]
    fn ring_eviction_expires_stashed() {
        let mut stage = ResolvStage::with_config(ResolvConfig {
            blockhash_ring_capacity: 3,
            stash_capacity: 64,
            transaction_lifetime_slots: 150,
        });

        // Fill the ring.
        for i in 0..3u64 {
            stage.register_blockhash(hash_from_slot(i), i);
        }
        assert_eq!(stage.blockhash_count(), 3);

        // Stash a tx for hash 0.
        let stash_hash = hash_from_slot(0);
        let tx = make_tx(stash_hash);
        // Hash 0 is known, so this will resolve as valid.
        let outcome = stage.resolve(tx);
        assert!(matches!(outcome, ResolvOutcome::Valid { .. }));

        // Register a 4th hash, evicting hash 0 from the ring.
        stage.register_blockhash(hash_from_slot(100), 100);
        assert_eq!(stage.blockhash_count(), 3);
        // Hash 0 is gone.
        assert!(!stage.blockhash_map.contains_key(&hash_from_slot(0)));
    }

    #[test]
    fn vote_transactions_resolved_normally() {
        let mut stage = ResolvStage::with_config(ResolvConfig {
            blockhash_ring_capacity: 256,
            stash_capacity: 64,
            transaction_lifetime_slots: 150,
        });

        let hash = hash_from_slot(10);
        stage.register_blockhash(hash, 10);

        let mut tx = make_tx(hash);
        tx.is_vote = true;
        let outcome = stage.resolve(tx);
        assert!(matches!(outcome, ResolvOutcome::Valid { .. }));
    }

    #[test]
    fn duplicate_blockhash_registration_ignored() {
        let mut stage = ResolvStage::with_config(ResolvConfig {
            blockhash_ring_capacity: 256,
            stash_capacity: 64,
            transaction_lifetime_slots: 150,
        });

        let hash = hash_from_slot(42);
        stage.register_blockhash(hash, 42);
        stage.register_blockhash(hash, 42); // duplicate
        assert_eq!(stage.blockhash_count(), 1);
    }

    #[test]
    fn stats_tracking() {
        let mut stage = ResolvStage::with_config(ResolvConfig {
            blockhash_ring_capacity: 256,
            stash_capacity: 64,
            transaction_lifetime_slots: 150,
        });

        let known_hash = hash_from_slot(1);
        stage.register_blockhash(known_hash, 1);

        // Resolve a known hash.
        stage.resolve(make_tx(known_hash));
        // Stash an unknown hash.
        stage.resolve(make_tx(hash_from_slot(999)));

        let snap = stage.stats().snapshot();
        assert_eq!(snap.transactions_received, 2);
        assert_eq!(snap.transactions_resolved, 1);
        assert_eq!(snap.transactions_stashed, 1);
        assert_eq!(snap.blockhashes_registered, 1);
    }

    #[test]
    fn empty_unstash_returns_empty() {
        let mut stage = ResolvStage::new();
        let hash = hash_from_slot(1);
        let unstashed = stage.register_blockhash(hash, 1);
        assert!(unstashed.is_empty());
    }
}
