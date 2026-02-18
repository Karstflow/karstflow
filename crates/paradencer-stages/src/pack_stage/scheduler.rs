/// Transaction scheduler that produces microblocks.
///
/// Takes prioritized transactions from the queue and arranges them into
/// microblocks that can be executed in parallel. Each microblock is a
/// group of non-conflicting transactions bounded by compute unit and
/// data size limits.
use super::conflict_detector::{AccountLock, ConflictDetector, LockKind};
use super::priority_queue::{PackedTransaction, TransactionQueue};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Per-block cost limits (consensus-critical).
#[derive(Debug, Clone)]
pub struct PackLimits {
    /// Maximum total cost units per block.
    pub max_cost_per_block: u64,
    /// Maximum total vote cost per block.
    pub max_vote_cost_per_block: u64,
    /// Maximum write cost per account per block.
    pub max_write_cost_per_account: u64,
    /// Maximum data bytes per block (derived from shred limits).
    pub max_data_bytes_per_block: u64,
}

impl Default for PackLimits {
    fn default() -> Self {
        Self {
            max_cost_per_block: 48_000_000,
            max_vote_cost_per_block: 36_000_000,
            max_data_bytes_per_block: 27_995_136, // ~32K data shreds
            max_write_cost_per_account: 12_000_000,
        }
    }
}

/// Configuration for the pack scheduler.
#[derive(Debug, Clone)]
pub struct PackConfig {
    /// Maximum transactions per microblock.
    pub max_txns_per_microblock: usize,
    /// Maximum compute units per microblock.
    pub max_cus_per_microblock: u64,
    /// Fraction of block CUs to allocate to votes (0.0..1.0).
    pub vote_fraction: f32,
    /// Per-block limits.
    pub limits: PackLimits,
    /// Number of parallel execution tiles.
    pub execution_tile_count: usize,
}

impl Default for PackConfig {
    fn default() -> Self {
        Self {
            max_txns_per_microblock: 64,
            max_cus_per_microblock: 1_600_000,
            vote_fraction: 0.75,
            limits: PackLimits::default(),
            execution_tile_count: 1,
        }
    }
}

/// A microblock: a group of non-conflicting transactions.
#[derive(Debug, Clone)]
pub struct Microblock {
    /// Unique microblock identifier within this block.
    pub id: u64,
    /// Transactions in this microblock.
    pub transactions: Vec<PackedTransaction>,
    /// Total compute units in this microblock.
    pub total_compute_units: u64,
    /// Total data bytes in this microblock.
    pub total_data_bytes: u64,
    /// Whether this microblock contains only votes.
    pub is_vote_only: bool,
}

/// Outcome of a schedule attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackOutcome {
    /// Transaction was packed into a microblock.
    Scheduled { microblock_id: u64 },
    /// Transaction conflicts with in-flight microblocks; re-queued.
    Conflicted,
    /// Block cost limit reached.
    BlockFull,
    /// Per-account write cost limit reached.
    AccountWriteLimitReached,
    /// No transactions available.
    QueueEmpty,
}

/// Statistics for the pack scheduler.
#[derive(Debug, Default)]
pub struct PackStats {
    pub transactions_scheduled: AtomicU64,
    pub transactions_conflicted: AtomicU64,
    pub transactions_expired: AtomicU64,
    pub microblocks_produced: AtomicU64,
    pub blocks_completed: AtomicU64,
    pub block_cost_units_used: AtomicU64,
    pub block_vote_cost_units_used: AtomicU64,
}

impl PackStats {
    pub fn snapshot(&self) -> PackStatsSnapshot {
        PackStatsSnapshot {
            transactions_scheduled: self.transactions_scheduled.load(Ordering::Relaxed),
            transactions_conflicted: self.transactions_conflicted.load(Ordering::Relaxed),
            transactions_expired: self.transactions_expired.load(Ordering::Relaxed),
            microblocks_produced: self.microblocks_produced.load(Ordering::Relaxed),
            blocks_completed: self.blocks_completed.load(Ordering::Relaxed),
            block_cost_units_used: self.block_cost_units_used.load(Ordering::Relaxed),
            block_vote_cost_units_used: self.block_vote_cost_units_used.load(Ordering::Relaxed),
        }
    }
}

/// Point-in-time statistics snapshot.
#[derive(Debug, Clone, Default)]
pub struct PackStatsSnapshot {
    pub transactions_scheduled: u64,
    pub transactions_conflicted: u64,
    pub transactions_expired: u64,
    pub microblocks_produced: u64,
    pub blocks_completed: u64,
    pub block_cost_units_used: u64,
    pub block_vote_cost_units_used: u64,
}

/// The transaction scheduler.
pub struct PackScheduler {
    config: PackConfig,
    /// Queue of pending transactions.
    queue: TransactionQueue,
    /// Conflict detection for in-flight microblocks.
    conflict_detector: ConflictDetector,
    /// Next microblock ID.
    next_microblock_id: u64,
    /// Current block's accumulated cost units.
    block_cost_units: u64,
    /// Current block's accumulated vote cost units.
    block_vote_cost_units: u64,
    /// Current block's accumulated data bytes.
    block_data_bytes: u64,
    /// Current slot.
    current_slot: u64,
    /// Statistics.
    stats: Arc<PackStats>,
}

impl PackScheduler {
    /// Create a new scheduler with default configuration.
    pub fn new() -> Self {
        Self::with_config(PackConfig::default())
    }

    /// Create a new scheduler with the given configuration.
    pub fn with_config(config: PackConfig) -> Self {
        let max_write_cost = config.limits.max_write_cost_per_account;
        Self {
            config,
            queue: TransactionQueue::with_capacity(65_536),
            conflict_detector: ConflictDetector::new(max_write_cost),
            next_microblock_id: 0,
            block_cost_units: 0,
            block_vote_cost_units: 0,
            block_data_bytes: 0,
            current_slot: 0,
            stats: Arc::new(PackStats::default()),
        }
    }

    /// Get a shared reference to the statistics.
    pub fn stats(&self) -> Arc<PackStats> {
        Arc::clone(&self.stats)
    }

    /// Submit a transaction for scheduling.
    pub fn submit(&mut self, tx: PackedTransaction) {
        self.queue.insert(tx);
    }

    /// Produce the next microblock from queued transactions.
    /// Selects the highest-priority non-conflicting transactions up to
    /// the microblock limits.
    pub fn produce_microblock(&mut self) -> Option<Microblock> {
        if self.queue.is_empty() {
            return None;
        }

        // Check block-level limits.
        if self.block_cost_units >= self.config.limits.max_cost_per_block {
            return None;
        }
        if self.block_data_bytes >= self.config.limits.max_data_bytes_per_block {
            return None;
        }

        let microblock_id = self.next_microblock_id;
        let mut transactions = Vec::new();
        let mut total_cu = 0u64;
        let mut total_data = 0u64;
        let mut all_votes = true;
        let mut deferred = Vec::new();

        // Drain highest-priority transactions from queue.
        while let Some(tx) = self.queue.pop() {
            // Check if this tx is expired.
            if tx.expires_at_slot <= self.current_slot {
                self.stats
                    .transactions_expired
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            }

            // Check microblock limits.
            if transactions.len() >= self.config.max_txns_per_microblock {
                deferred.push(tx);
                break;
            }
            if total_cu.saturating_add(tx.compute_units) > self.config.max_cus_per_microblock {
                deferred.push(tx);
                break;
            }

            // Check block-level limits.
            if self
                .block_cost_units
                .saturating_add(total_cu)
                .saturating_add(tx.compute_units)
                > self.config.limits.max_cost_per_block
            {
                deferred.push(tx);
                break;
            }

            // Check vote cost limit.
            if tx.is_vote
                && self.block_vote_cost_units.saturating_add(tx.compute_units)
                    > self.config.limits.max_vote_cost_per_block
            {
                deferred.push(tx);
                continue;
            }

            // Check per-account write cost.
            if self
                .conflict_detector
                .would_exceed_write_cost(&tx.write_accounts, tx.compute_units)
            {
                self.stats
                    .transactions_conflicted
                    .fetch_add(1, Ordering::Relaxed);
                deferred.push(tx);
                continue;
            }

            // Build lock set and check conflicts.
            let locks = build_lock_set(&tx);
            if !self.conflict_detector.can_schedule(&locks) {
                self.stats
                    .transactions_conflicted
                    .fetch_add(1, Ordering::Relaxed);
                deferred.push(tx);
                continue;
            }

            // Transaction fits — add to microblock.
            total_cu += tx.compute_units;
            total_data += tx.data_size as u64;
            if !tx.is_vote {
                all_votes = false;
            }

            self.conflict_detector
                .record_write_cost(&tx.write_accounts, tx.compute_units);

            transactions.push(tx);
        }

        // Re-queue deferred transactions.
        for tx in deferred {
            self.queue.insert(tx);
        }

        if transactions.is_empty() {
            return None;
        }

        // Acquire locks for the microblock.
        let all_locks: Vec<AccountLock> = transactions.iter().flat_map(build_lock_set).collect();
        self.conflict_detector.acquire(microblock_id, all_locks);

        // Update block-level accumulators.
        self.block_cost_units += total_cu;
        if all_votes {
            self.block_vote_cost_units += total_cu;
        }
        self.block_data_bytes += total_data;

        self.next_microblock_id += 1;

        self.stats
            .transactions_scheduled
            .fetch_add(transactions.len() as u64, Ordering::Relaxed);
        self.stats
            .microblocks_produced
            .fetch_add(1, Ordering::Relaxed);
        self.stats
            .block_cost_units_used
            .store(self.block_cost_units, Ordering::Relaxed);

        Some(Microblock {
            id: microblock_id,
            transactions,
            total_compute_units: total_cu,
            total_data_bytes: total_data,
            is_vote_only: all_votes,
        })
    }

    /// Notify the scheduler that a microblock has been executed,
    /// releasing its account locks.
    pub fn complete_microblock(&mut self, microblock_id: u64) {
        self.conflict_detector.release(microblock_id);
    }

    /// Start a new block. Resets per-block limits and conflict state.
    pub fn new_block(&mut self, slot: u64) {
        self.current_slot = slot;
        self.block_cost_units = 0;
        self.block_vote_cost_units = 0;
        self.block_data_bytes = 0;
        self.next_microblock_id = 0;
        self.conflict_detector.reset();

        // Drain expired transactions.
        let expired = self.queue.drain_expired(slot);
        self.stats
            .transactions_expired
            .fetch_add(expired as u64, Ordering::Relaxed);
        self.stats.blocks_completed.fetch_add(1, Ordering::Relaxed);
    }

    /// Number of queued transactions.
    pub fn queue_depth(&self) -> usize {
        self.queue.len()
    }

    /// Current block's consumed cost units.
    pub fn block_cost_units(&self) -> u64 {
        self.block_cost_units
    }

    /// Current block's consumed data bytes.
    pub fn block_data_bytes(&self) -> u64 {
        self.block_data_bytes
    }

    /// Number of active (in-flight) microblocks.
    pub fn active_microblocks(&self) -> usize {
        self.conflict_detector.active_microblock_count()
    }
}

/// Build the lock set for a transaction.
fn build_lock_set(tx: &PackedTransaction) -> Vec<AccountLock> {
    let mut locks = Vec::with_capacity(tx.write_accounts.len() + tx.read_accounts.len());
    for account in &tx.write_accounts {
        locks.push(AccountLock {
            account: *account,
            kind: LockKind::Write,
        });
    }
    for account in &tx.read_accounts {
        locks.push(AccountLock {
            account: *account,
            kind: LockKind::Read,
        });
    }
    locks
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(id: u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[0] = id;
        a
    }

    fn make_tx_with_accounts(
        priority: u64,
        cus: u64,
        write_accts: Vec<[u8; 32]>,
        read_accts: Vec<[u8; 32]>,
        is_vote: bool,
    ) -> PackedTransaction {
        PackedTransaction {
            payload: vec![],
            blockhash: [0u8; 32],
            priority_fee: priority,
            compute_units: cus,
            is_vote,
            expires_at_slot: u64::MAX,
            write_accounts: write_accts,
            read_accounts: read_accts,
            data_size: 100,
            insertion_order: 0,
        }
    }

    #[test]
    fn produce_single_microblock() {
        let mut scheduler = PackScheduler::new();

        let tx = make_tx_with_accounts(5_000, 200_000, vec![account(1)], vec![], false);
        scheduler.submit(tx);

        let mb = scheduler.produce_microblock().unwrap();
        assert_eq!(mb.transactions.len(), 1);
        assert_eq!(mb.total_compute_units, 200_000);
    }

    #[test]
    fn conflicting_transactions_in_separate_microblocks() {
        let config = PackConfig {
            max_txns_per_microblock: 1,
            ..Default::default()
        };
        let mut scheduler = PackScheduler::with_config(config);

        let tx1 = make_tx_with_accounts(10_000, 200_000, vec![account(1)], vec![], false);
        let tx2 = make_tx_with_accounts(5_000, 200_000, vec![account(1)], vec![], false);
        scheduler.submit(tx1);
        scheduler.submit(tx2);

        let mb1 = scheduler.produce_microblock().unwrap();
        assert_eq!(mb1.transactions.len(), 1);

        // Second tx conflicts until first microblock completes.
        let mb2 = scheduler.produce_microblock();
        assert!(mb2.is_none());

        // Complete first microblock.
        scheduler.complete_microblock(mb1.id);

        // Now second tx can be scheduled.
        let mb3 = scheduler.produce_microblock().unwrap();
        assert_eq!(mb3.transactions.len(), 1);
    }

    #[test]
    fn non_conflicting_transactions_in_same_microblock() {
        let mut scheduler = PackScheduler::new();

        let tx1 = make_tx_with_accounts(5_000, 100_000, vec![account(1)], vec![], false);
        let tx2 = make_tx_with_accounts(5_000, 100_000, vec![account(2)], vec![], false);
        scheduler.submit(tx1);
        scheduler.submit(tx2);

        let mb = scheduler.produce_microblock().unwrap();
        assert_eq!(mb.transactions.len(), 2);
    }

    #[test]
    fn votes_scheduled_first() {
        let mut scheduler = PackScheduler::new();

        let non_vote = make_tx_with_accounts(1_000_000, 200_000, vec![account(1)], vec![], false);
        let vote = make_tx_with_accounts(5_000, 200_000, vec![account(2)], vec![], true);
        scheduler.submit(non_vote);
        scheduler.submit(vote);

        let mb = scheduler.produce_microblock().unwrap();
        assert!(mb.transactions[0].is_vote);
    }

    #[test]
    fn block_cost_limit_stops_scheduling() {
        let config = PackConfig {
            limits: PackLimits {
                max_cost_per_block: 300_000,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut scheduler = PackScheduler::with_config(config);

        let tx1 = make_tx_with_accounts(5_000, 200_000, vec![account(1)], vec![], false);
        let tx2 = make_tx_with_accounts(5_000, 200_000, vec![account(2)], vec![], false);
        scheduler.submit(tx1);
        scheduler.submit(tx2);

        let mb1 = scheduler.produce_microblock().unwrap();
        assert_eq!(mb1.transactions.len(), 1);
        assert_eq!(scheduler.block_cost_units(), 200_000);

        // Second transaction would exceed block limit.
        let mb2 = scheduler.produce_microblock();
        assert!(mb2.is_none());
    }

    #[test]
    fn new_block_resets_limits() {
        let config = PackConfig {
            limits: PackLimits {
                max_cost_per_block: 300_000,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut scheduler = PackScheduler::with_config(config);

        let tx = make_tx_with_accounts(5_000, 200_000, vec![account(1)], vec![], false);
        scheduler.submit(tx);
        scheduler.produce_microblock().unwrap();

        // Start new block.
        scheduler.new_block(1);
        assert_eq!(scheduler.block_cost_units(), 0);
        assert_eq!(scheduler.active_microblocks(), 0);
    }

    #[test]
    fn expired_transactions_drained_on_new_block() {
        let mut scheduler = PackScheduler::new();

        let mut tx = make_tx_with_accounts(5_000, 200_000, vec![account(1)], vec![], false);
        tx.expires_at_slot = 10;
        scheduler.submit(tx);

        scheduler.new_block(20);
        assert_eq!(scheduler.queue_depth(), 0);
    }

    #[test]
    fn empty_queue_returns_none() {
        let mut scheduler = PackScheduler::new();
        assert!(scheduler.produce_microblock().is_none());
    }

    #[test]
    fn stats_tracking() {
        let mut scheduler = PackScheduler::new();

        let tx1 = make_tx_with_accounts(5_000, 200_000, vec![account(1)], vec![], false);
        let tx2 = make_tx_with_accounts(5_000, 200_000, vec![account(2)], vec![], false);
        scheduler.submit(tx1);
        scheduler.submit(tx2);

        scheduler.produce_microblock().unwrap();

        let snap = scheduler.stats().snapshot();
        assert_eq!(snap.transactions_scheduled, 2);
        assert_eq!(snap.microblocks_produced, 1);
    }

    #[test]
    fn microblock_cu_limit() {
        let config = PackConfig {
            max_cus_per_microblock: 250_000,
            ..Default::default()
        };
        let mut scheduler = PackScheduler::with_config(config);

        let tx1 = make_tx_with_accounts(5_000, 200_000, vec![account(1)], vec![], false);
        let tx2 = make_tx_with_accounts(5_000, 200_000, vec![account(2)], vec![], false);
        scheduler.submit(tx1);
        scheduler.submit(tx2);

        let mb = scheduler.produce_microblock().unwrap();
        assert_eq!(mb.transactions.len(), 1); // second doesn't fit
        assert_eq!(mb.total_compute_units, 200_000);
    }
}
