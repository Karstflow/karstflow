/// Transaction scheduler that produces microblocks.
///
/// Takes prioritized transactions from the queue and arranges them into
/// microblocks that can be executed in parallel. Each microblock is a
/// group of non-conflicting transactions bounded by compute unit and
/// data size limits.
///
/// Supports CU rebate tracking (crediting back unused compute budget
/// after execution), microblock pacing (rate-limiting production to
/// avoid overwhelming execution tiles), and per-block microblock limits.
use super::conflict_detector::{AccountLock, ConflictDetector, LockKind};
use super::priority_queue::{PackedTransaction, TransactionQueue};
use karstflow_constants::block_limits;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

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
            max_cost_per_block: block_limits::MAX_BLOCK_COMPUTE_UNITS,
            max_vote_cost_per_block: block_limits::MAX_VOTE_COMPUTE_UNITS,
            max_data_bytes_per_block: block_limits::MAX_DATA_BYTES_PER_BLOCK,
            max_write_cost_per_account: block_limits::MAX_WRITABLE_ACCOUNT_COMPUTE_UNITS,
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
    /// Maximum microblocks per block (slot). Production stops after this limit.
    pub max_microblocks_per_block: u64,
}

impl Default for PackConfig {
    fn default() -> Self {
        Self {
            max_txns_per_microblock: 64,
            max_cus_per_microblock: block_limits::MAX_CUS_PER_MICROBLOCK,
            vote_fraction: 0.75,
            limits: PackLimits::default(),
            execution_tile_count: 1,
            max_microblocks_per_block: karstflow_constants::ledger::MAX_MICROBLOCKS_PER_SLOT,
        }
    }
}

/// A microblock: a group of non-conflicting transactions.
#[derive(Debug, Clone)]
pub struct Microblock {
    /// Unique microblock identifier within this block.
    pub id: u64,
    /// Target execution tile index (0-based).
    /// Used for multi-tile scheduling: each microblock is dispatched to
    /// a specific execution tile that holds its account locks.
    pub target_tile: usize,
    /// Transactions in this microblock.
    pub transactions: Vec<PackedTransaction>,
    /// Total compute units in this microblock.
    pub total_compute_units: u64,
    /// Total data bytes in this microblock.
    pub total_data_bytes: u64,
    /// Whether this microblock contains only votes.
    pub is_vote_only: bool,
}

/// Execution result summary for CU rebate tracking.
///
/// After an execution tile processes a microblock, it reports the actual
/// CU consumption. The difference between requested and consumed CUs
/// is credited back to the block budget, allowing more transactions.
#[derive(Debug, Clone, Copy)]
pub struct MicroblockRebate {
    /// Total CUs that were requested (budgeted) for the microblock.
    pub requested_cus: u64,
    /// Total CUs actually consumed during execution.
    pub consumed_cus: u64,
    /// Whether this microblock contained only vote transactions.
    pub is_vote_only: bool,
}

/// Microblock production rate limiter.
///
/// Prevents bursty microblock emission that could overwhelm execution
/// tiles. Enforces both a minimum time interval between emissions and
/// a per-slot microblock count limit.
#[derive(Debug)]
pub struct PackPacer {
    /// Minimum interval between microblock emissions (nanoseconds).
    min_interval_ns: u64,
    /// Last emission timestamp.
    last_emit: Instant,
    /// Microblocks produced this slot.
    microblocks_this_slot: u64,
    /// Maximum microblocks per slot.
    max_microblocks_per_slot: u64,
}

impl PackPacer {
    /// Create a new pacer with the given configuration.
    ///
    /// The first emission is always allowed (last_emit is set far in the past).
    pub fn new(min_interval_ns: u64, max_microblocks_per_slot: u64) -> Self {
        // Set last_emit far enough in the past that the first can_emit() returns true.
        let past = Instant::now()
            .checked_sub(std::time::Duration::from_secs(10))
            .unwrap_or_else(Instant::now);
        Self {
            min_interval_ns,
            last_emit: past,
            microblocks_this_slot: 0,
            max_microblocks_per_slot,
        }
    }

    /// Whether a microblock can be emitted now.
    ///
    /// Returns `false` if either:
    /// - The minimum interval since the last emission hasn't elapsed
    /// - The per-slot microblock limit has been reached
    pub fn can_emit(&self) -> bool {
        if self.microblocks_this_slot >= self.max_microblocks_per_slot {
            return false;
        }
        self.last_emit.elapsed().as_nanos() >= self.min_interval_ns as u128
    }

    /// Record that a microblock was emitted.
    pub fn record_emit(&mut self) {
        self.last_emit = Instant::now();
        self.microblocks_this_slot += 1;
    }

    /// Reset for a new slot.
    pub fn new_slot(&mut self) {
        self.microblocks_this_slot = 0;
        self.last_emit = Instant::now();
    }

    /// Number of microblocks produced in the current slot.
    pub fn microblocks_this_slot(&self) -> u64 {
        self.microblocks_this_slot
    }
}

/// CU-aware pacing model for slot production.
///
/// Tracks cumulative CU consumption and adjusts the number of enabled
/// execution tiles to spread work evenly across the slot time window.
/// This prevents bursty CU consumption that could leave the end of a
/// slot underutilized.
#[derive(Debug)]
pub struct CuPacer {
    /// Total CU budget for the slot.
    total_cu_budget: u64,
    /// Slot duration in nanoseconds.
    slot_duration_ns: u64,
    /// CUs consumed so far this slot.
    cus_consumed: u64,
    /// Slot start time.
    slot_start: Instant,
    /// Total execution tiles available.
    total_tiles: usize,
}

impl CuPacer {
    /// Create a new CU-aware pacer.
    pub fn new(total_cu_budget: u64, slot_duration_ns: u64, total_tiles: usize) -> Self {
        Self {
            total_cu_budget,
            slot_duration_ns,
            cus_consumed: 0,
            slot_start: Instant::now(),
            total_tiles: total_tiles.max(1),
        }
    }

    /// Report CU consumption from an executed microblock.
    pub fn report_consumed(&mut self, cus: u64) {
        self.cus_consumed += cus;
    }

    /// Get the number of execution tiles that should be enabled right now.
    ///
    /// If we're ahead of schedule (consumed more CU than expected for
    /// elapsed time), reduce enabled tiles. If behind, enable more.
    pub fn enabled_tiles(&self) -> usize {
        if self.total_cu_budget == 0 || self.slot_duration_ns == 0 {
            return self.total_tiles;
        }

        let elapsed_ns = self.slot_start.elapsed().as_nanos() as u64;
        let elapsed_fraction = (elapsed_ns as f64) / (self.slot_duration_ns as f64);
        let elapsed_fraction = elapsed_fraction.clamp(0.001, 1.0);

        // Expected CU consumption at this point in the slot
        let expected_cus = (self.total_cu_budget as f64 * elapsed_fraction) as u64;

        if self.cus_consumed > expected_cus {
            // Ahead of schedule — reduce tiles
            let ratio = expected_cus as f64 / self.cus_consumed.max(1) as f64;
            let tiles = (self.total_tiles as f64 * ratio).ceil() as usize;
            tiles.clamp(1, self.total_tiles)
        } else {
            // Behind or on schedule — all tiles enabled
            self.total_tiles
        }
    }

    /// Remaining CU budget for this slot.
    pub fn remaining_cus(&self) -> u64 {
        self.total_cu_budget.saturating_sub(self.cus_consumed)
    }

    /// Fraction of slot time elapsed (0.0 to 1.0+).
    pub fn elapsed_fraction(&self) -> f64 {
        let elapsed_ns = self.slot_start.elapsed().as_nanos() as u64;
        elapsed_ns as f64 / self.slot_duration_ns.max(1) as f64
    }

    /// Reset for a new slot.
    pub fn new_slot(&mut self) {
        self.cus_consumed = 0;
        self.slot_start = Instant::now();
    }
}

/// Conservative estimate of the smallest pending transaction.
///
/// Tracks the minimum CU cost and minimum byte size across all pending
/// transactions. Used for quick rejection: if the smallest transaction
/// in the queue exceeds the remaining block budget, no scheduling
/// attempt is needed.
#[derive(Debug, Clone, Copy)]
pub struct SmallestPending {
    /// Minimum CU cost among pending transactions (u64::MAX = unknown/empty).
    pub cus: u64,
    /// Minimum byte size among pending transactions (u64::MAX = unknown/empty).
    pub bytes: u64,
}

impl SmallestPending {
    pub fn new() -> Self {
        Self {
            cus: u64::MAX,
            bytes: u64::MAX,
        }
    }

    /// Observe a transaction's cost/size and update minimums.
    pub fn observe(&mut self, cus: u64, bytes: u64) {
        self.cus = self.cus.min(cus);
        self.bytes = self.bytes.min(bytes);
    }

    /// Reset to unknown state (e.g. on new block or after full drain).
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

impl Default for SmallestPending {
    fn default() -> Self {
        Self::new()
    }
}

/// Granular schedule outcome metrics matching reference counters.
///
/// Tracks why transactions were or were not scheduled during
/// microblock production, enabling fine-grained observability
/// into pack scheduler behavior.
#[derive(Debug, Clone, Copy, Default)]
pub struct ScheduleMetrics {
    /// Transactions successfully scheduled.
    pub taken: u64,
    /// Transactions skipped due to per-microblock CU limit.
    pub cu_limit: u64,
    /// Transactions skipped due to per-microblock byte limit.
    pub byte_limit: u64,
    /// Transactions skipped due to per-account write cost limit.
    pub write_cost_limit: u64,
    /// Transactions scheduled via fast path (no conflicts).
    pub fast_path: u64,
    /// Transactions scheduled via slow path (conflict resolution needed).
    pub slow_path: u64,
    /// Transactions deferred/skipped due to pacing or ordering.
    pub defer_skip: u64,
}

impl ScheduleMetrics {
    /// Total events across all categories.
    pub fn total(&self) -> u64 {
        self.taken
            + self.cu_limit
            + self.byte_limit
            + self.write_cost_limit
            + self.fast_path
            + self.slow_path
            + self.defer_skip
    }

    /// Reset all counters to zero.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
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
    /// Total CUs credited back via rebates.
    pub rebated_cus: AtomicU64,
    /// Number of times pacing delayed microblock production.
    pub microblocks_paced: AtomicU64,
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
            rebated_cus: self.rebated_cus.load(Ordering::Relaxed),
            microblocks_paced: self.microblocks_paced.load(Ordering::Relaxed),
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
    /// Total CUs credited back via rebates.
    pub rebated_cus: u64,
    /// Number of times pacing delayed microblock production.
    pub microblocks_paced: u64,
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
    /// Number of microblocks produced in the current block.
    microblocks_this_block: u64,
    /// Current slot.
    current_slot: u64,
    /// Statistics.
    stats: Arc<PackStats>,
    /// In-flight compute units per execution tile.
    per_tile_inflight_cus: Vec<u64>,
    /// Maps microblock ID to (target_tile, requested_cus) for tile CU tracking.
    microblock_tile_map: HashMap<u64, (usize, u64)>,
}

impl PackScheduler {
    /// Create a new scheduler with default configuration.
    pub fn new() -> Self {
        Self::with_config(PackConfig::default())
    }

    /// Create a new scheduler with the given configuration.
    pub fn with_config(config: PackConfig) -> Self {
        let max_write_cost = config.limits.max_write_cost_per_account;
        let tile_count = config.execution_tile_count.max(1);
        Self {
            per_tile_inflight_cus: vec![0u64; tile_count],
            microblock_tile_map: HashMap::new(),
            config,
            queue: TransactionQueue::with_capacity(65_536),
            conflict_detector: ConflictDetector::new(max_write_cost),
            next_microblock_id: 0,
            block_cost_units: 0,
            block_vote_cost_units: 0,
            block_data_bytes: 0,
            microblocks_this_block: 0,
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

    /// Select the execution tile with the lowest in-flight compute units.
    ///
    /// When multiple tiles are tied, picks the lowest index (deterministic).
    fn select_target_tile(&self) -> usize {
        let mut best_tile = 0;
        let mut best_cus = self.per_tile_inflight_cus[0];
        for (i, &cus) in self.per_tile_inflight_cus.iter().enumerate().skip(1) {
            if cus < best_cus {
                best_tile = i;
                best_cus = cus;
            }
        }
        best_tile
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
        if self.microblocks_this_block >= self.config.max_microblocks_per_block {
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

            let tx_cost = tx.block_cost();

            // Check microblock limits.
            if transactions.len() >= self.config.max_txns_per_microblock {
                deferred.push(tx);
                break;
            }
            if total_cu.saturating_add(tx_cost) > self.config.max_cus_per_microblock {
                deferred.push(tx);
                break;
            }

            // Check block-level limits using total cost.
            if self
                .block_cost_units
                .saturating_add(total_cu)
                .saturating_add(tx_cost)
                > self.config.limits.max_cost_per_block
            {
                deferred.push(tx);
                break;
            }

            // Check vote cost limit.
            if tx.is_vote
                && self.block_vote_cost_units.saturating_add(tx_cost)
                    > self.config.limits.max_vote_cost_per_block
            {
                deferred.push(tx);
                continue;
            }

            // Check per-account write cost.
            if self
                .conflict_detector
                .would_exceed_write_cost(&tx.write_accounts, tx_cost)
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
            total_cu += tx_cost;
            total_data += tx.data_size as u64;
            if !tx.is_vote {
                all_votes = false;
            }

            self.conflict_detector
                .record_write_cost(&tx.write_accounts, tx_cost);

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

        // Select the least-loaded execution tile.
        let target_tile = self.select_target_tile();
        self.per_tile_inflight_cus[target_tile] += total_cu;
        self.microblock_tile_map
            .insert(microblock_id, (target_tile, total_cu));

        self.next_microblock_id += 1;
        self.microblocks_this_block += 1;

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
            target_tile,
            transactions,
            total_compute_units: total_cu,
            total_data_bytes: total_data,
            is_vote_only: all_votes,
        })
    }

    /// Notify the scheduler that a microblock has been executed,
    /// releasing its account locks and per-tile CU tracking.
    pub fn complete_microblock(&mut self, microblock_id: u64) {
        if let Some((tile, cus)) = self.microblock_tile_map.remove(&microblock_id) {
            self.per_tile_inflight_cus[tile] = self.per_tile_inflight_cus[tile].saturating_sub(cus);
        }
        self.conflict_detector.release(microblock_id);
    }

    /// Complete a microblock with execution results, applying CU rebates.
    ///
    /// The difference between requested and consumed CUs is credited back
    /// to the block budget, allowing additional transactions to be packed.
    /// This is consensus-critical: it determines how many transactions
    /// fit in a block when execution consumes less than the budget.
    pub fn complete_microblock_with_rebate(
        &mut self,
        microblock_id: u64,
        rebate: MicroblockRebate,
    ) {
        let rebated_cus = rebate.requested_cus.saturating_sub(rebate.consumed_cus);
        if rebated_cus > 0 {
            self.block_cost_units = self.block_cost_units.saturating_sub(rebated_cus);
            if rebate.is_vote_only {
                self.block_vote_cost_units = self.block_vote_cost_units.saturating_sub(rebated_cus);
            }
            self.stats
                .rebated_cus
                .fetch_add(rebated_cus, Ordering::Relaxed);
        }
        if let Some((tile, cus)) = self.microblock_tile_map.remove(&microblock_id) {
            self.per_tile_inflight_cus[tile] = self.per_tile_inflight_cus[tile].saturating_sub(cus);
        }
        self.conflict_detector.release(microblock_id);
    }

    /// Start a new block. Resets per-block limits and conflict state.
    pub fn new_block(&mut self, slot: u64) {
        self.current_slot = slot;
        self.block_cost_units = 0;
        self.block_vote_cost_units = 0;
        self.block_data_bytes = 0;
        self.microblocks_this_block = 0;
        self.next_microblock_id = 0;
        self.conflict_detector.reset();
        self.per_tile_inflight_cus.fill(0);
        self.microblock_tile_map.clear();

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

    /// Number of microblocks produced in the current block.
    pub fn microblocks_this_block(&self) -> u64 {
        self.microblocks_this_block
    }

    /// In-flight compute units per execution tile.
    pub fn per_tile_inflight_cus(&self) -> &[u64] {
        &self.per_tile_inflight_cus
    }

    /// Number of configured execution tiles.
    pub fn execution_tile_count(&self) -> usize {
        self.per_tile_inflight_cus.len()
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
            total_cost: 0, // 0 = use compute_units for block cost
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

    // -----------------------------------------------------------------------
    // Rebate tests
    // -----------------------------------------------------------------------

    #[test]
    fn rebate_credits_back_cus() {
        let config = PackConfig {
            limits: PackLimits {
                max_cost_per_block: 500_000,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut scheduler = PackScheduler::with_config(config);

        let tx = make_tx_with_accounts(5_000, 200_000, vec![account(1)], vec![], false);
        scheduler.submit(tx);

        let mb = scheduler.produce_microblock().unwrap();
        assert_eq!(scheduler.block_cost_units(), 200_000);

        // Execution only consumed 150K of the 200K budgeted.
        scheduler.complete_microblock_with_rebate(
            mb.id,
            MicroblockRebate {
                requested_cus: 200_000,
                consumed_cus: 150_000,
                is_vote_only: false,
            },
        );

        // 50K should be credited back.
        assert_eq!(scheduler.block_cost_units(), 150_000);
        assert_eq!(scheduler.stats().snapshot().rebated_cus, 50_000);
    }

    #[test]
    fn rebate_allows_more_transactions() {
        let config = PackConfig {
            limits: PackLimits {
                max_cost_per_block: 300_000,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut scheduler = PackScheduler::with_config(config);

        // First tx takes 200K of 300K budget.
        let tx1 = make_tx_with_accounts(5_000, 200_000, vec![account(1)], vec![], false);
        scheduler.submit(tx1);
        let mb1 = scheduler.produce_microblock().unwrap();

        // Second tx needs 200K — would exceed 300K limit.
        let tx2 = make_tx_with_accounts(5_000, 200_000, vec![account(2)], vec![], false);
        scheduler.submit(tx2);
        assert!(scheduler.produce_microblock().is_none());

        // Rebate 150K from first microblock (only 50K consumed).
        scheduler.complete_microblock_with_rebate(
            mb1.id,
            MicroblockRebate {
                requested_cus: 200_000,
                consumed_cus: 50_000,
                is_vote_only: false,
            },
        );

        // Now budget is 50K used, 250K remaining — tx2 (200K) fits.
        let mb2 = scheduler.produce_microblock();
        assert!(mb2.is_some());
    }

    #[test]
    fn rebate_vote_cost() {
        let config = PackConfig {
            limits: PackLimits {
                max_vote_cost_per_block: 100_000,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut scheduler = PackScheduler::with_config(config);

        let tx = make_tx_with_accounts(5_000, 80_000, vec![account(1)], vec![], true);
        scheduler.submit(tx);
        let mb = scheduler.produce_microblock().unwrap();

        // Rebate as vote-only.
        scheduler.complete_microblock_with_rebate(
            mb.id,
            MicroblockRebate {
                requested_cus: 80_000,
                consumed_cus: 30_000,
                is_vote_only: true,
            },
        );

        // Vote cost should be reduced from 80K to 30K.
        assert_eq!(scheduler.block_cost_units(), 30_000);
    }

    // -----------------------------------------------------------------------
    // Pacing tests
    // -----------------------------------------------------------------------

    #[test]
    fn pacer_limits_rate() {
        let pacer = PackPacer::new(1_000_000_000, 100); // 1 second interval
                                                        // Just created, so can_emit should be true (elapsed > 0).
        assert!(pacer.can_emit());
    }

    #[test]
    fn pacer_slot_limit() {
        let mut pacer = PackPacer::new(0, 3); // no time limit, 3 per slot
        assert!(pacer.can_emit());
        pacer.record_emit();
        assert!(pacer.can_emit());
        pacer.record_emit();
        assert!(pacer.can_emit());
        pacer.record_emit();
        // 3rd emitted — now at limit.
        assert!(!pacer.can_emit());
    }

    #[test]
    fn pacer_new_slot_resets() {
        let mut pacer = PackPacer::new(0, 2);
        pacer.record_emit();
        pacer.record_emit();
        assert!(!pacer.can_emit());

        pacer.new_slot();
        assert!(pacer.can_emit());
        assert_eq!(pacer.microblocks_this_slot(), 0);
    }

    // -----------------------------------------------------------------------
    // Max microblocks per block test
    // -----------------------------------------------------------------------

    #[test]
    fn max_microblocks_per_block_enforced() {
        let config = PackConfig {
            max_microblocks_per_block: 2,
            max_txns_per_microblock: 1,
            ..Default::default()
        };
        let mut scheduler = PackScheduler::with_config(config);

        // Submit 3 transactions.
        for i in 0..3 {
            let tx = make_tx_with_accounts(5_000, 100_000, vec![account(i)], vec![], false);
            scheduler.submit(tx);
        }

        // First two microblocks succeed.
        let mb1 = scheduler.produce_microblock();
        assert!(mb1.is_some());
        scheduler.complete_microblock(mb1.unwrap().id);

        let mb2 = scheduler.produce_microblock();
        assert!(mb2.is_some());
        scheduler.complete_microblock(mb2.unwrap().id);

        // Third is blocked by max_microblocks_per_block.
        let mb3 = scheduler.produce_microblock();
        assert!(mb3.is_none());

        // New block resets.
        scheduler.new_block(1);
        let mb4 = scheduler.produce_microblock();
        assert!(mb4.is_some());
    }

    #[test]
    fn microblocks_this_block_counter() {
        let config = PackConfig {
            max_txns_per_microblock: 1,
            ..Default::default()
        };
        let mut scheduler = PackScheduler::with_config(config);

        for i in 0..3 {
            let tx = make_tx_with_accounts(5_000, 100_000, vec![account(i)], vec![], false);
            scheduler.submit(tx);
        }

        assert_eq!(scheduler.microblocks_this_block(), 0);
        scheduler.produce_microblock();
        assert_eq!(scheduler.microblocks_this_block(), 1);
        scheduler.produce_microblock();
        assert_eq!(scheduler.microblocks_this_block(), 2);

        scheduler.new_block(1);
        assert_eq!(scheduler.microblocks_this_block(), 0);
    }

    // -----------------------------------------------------------------------
    // Multi-tile scheduling tests
    // -----------------------------------------------------------------------

    #[test]
    fn multi_tile_assigns_target_tile() {
        let config = PackConfig {
            execution_tile_count: 4,
            max_txns_per_microblock: 1,
            ..Default::default()
        };
        let mut scheduler = PackScheduler::with_config(config);
        assert_eq!(scheduler.execution_tile_count(), 4);

        // Submit 4 non-conflicting transactions.
        for i in 0..4 {
            let tx = make_tx_with_accounts(5_000, 100_000, vec![account(i)], vec![], false);
            scheduler.submit(tx);
        }

        // First microblock goes to tile 0 (all empty, lowest index wins).
        let mb0 = scheduler.produce_microblock().unwrap();
        assert_eq!(mb0.target_tile, 0);

        // Second goes to tile 1 (tile 0 has 100K, rest have 0).
        let mb1 = scheduler.produce_microblock().unwrap();
        assert_eq!(mb1.target_tile, 1);

        // Third to tile 2.
        let mb2 = scheduler.produce_microblock().unwrap();
        assert_eq!(mb2.target_tile, 2);

        // Fourth to tile 3.
        let mb3 = scheduler.produce_microblock().unwrap();
        assert_eq!(mb3.target_tile, 3);

        // All tiles now have 100K in-flight.
        for cus in scheduler.per_tile_inflight_cus() {
            assert_eq!(*cus, 100_000);
        }

        // Complete tile 2 — it becomes the least loaded.
        scheduler.complete_microblock(mb2.id);
        assert_eq!(scheduler.per_tile_inflight_cus()[2], 0);
    }

    #[test]
    fn multi_tile_load_balances() {
        let config = PackConfig {
            execution_tile_count: 2,
            max_txns_per_microblock: 1,
            ..Default::default()
        };
        let mut scheduler = PackScheduler::with_config(config);

        // Submit a heavy tx and a light tx.
        let heavy = make_tx_with_accounts(5_000, 400_000, vec![account(1)], vec![], false);
        let light = make_tx_with_accounts(4_000, 100_000, vec![account(2)], vec![], false);
        scheduler.submit(heavy);
        scheduler.submit(light);

        // Heavy goes to tile 0 first (both empty).
        let mb_heavy = scheduler.produce_microblock().unwrap();
        assert_eq!(mb_heavy.target_tile, 0);
        assert_eq!(scheduler.per_tile_inflight_cus()[0], 400_000);
        assert_eq!(scheduler.per_tile_inflight_cus()[1], 0);

        // Light goes to tile 1 (less loaded).
        let mb_light = scheduler.produce_microblock().unwrap();
        assert_eq!(mb_light.target_tile, 1);
        assert_eq!(scheduler.per_tile_inflight_cus()[1], 100_000);

        // Next microblock would go to tile 1 (100K < 400K).
        let tx3 = make_tx_with_accounts(3_000, 50_000, vec![account(3)], vec![], false);
        scheduler.submit(tx3);
        let mb3 = scheduler.produce_microblock().unwrap();
        assert_eq!(mb3.target_tile, 1);
        assert_eq!(scheduler.per_tile_inflight_cus()[1], 150_000);
    }

    #[test]
    fn multi_tile_resets_on_new_block() {
        let config = PackConfig {
            execution_tile_count: 3,
            max_txns_per_microblock: 1,
            ..Default::default()
        };
        let mut scheduler = PackScheduler::with_config(config);

        let tx = make_tx_with_accounts(5_000, 200_000, vec![account(1)], vec![], false);
        scheduler.submit(tx);
        scheduler.produce_microblock();
        assert_eq!(scheduler.per_tile_inflight_cus()[0], 200_000);

        scheduler.new_block(1);
        for cus in scheduler.per_tile_inflight_cus() {
            assert_eq!(*cus, 0);
        }
    }

    #[test]
    fn single_tile_default_target_zero() {
        // Default config: 1 execution tile.
        let mut scheduler = PackScheduler::new();
        assert_eq!(scheduler.execution_tile_count(), 1);

        let tx = make_tx_with_accounts(5_000, 200_000, vec![account(1)], vec![], false);
        scheduler.submit(tx);

        let mb = scheduler.produce_microblock().unwrap();
        assert_eq!(mb.target_tile, 0);
    }

    #[test]
    fn multi_tile_complete_releases_tile_cus() {
        let config = PackConfig {
            execution_tile_count: 2,
            max_txns_per_microblock: 1,
            ..Default::default()
        };
        let mut scheduler = PackScheduler::with_config(config);

        // Two transactions → tile 0 and tile 1.
        let tx1 = make_tx_with_accounts(5_000, 300_000, vec![account(1)], vec![], false);
        let tx2 = make_tx_with_accounts(4_000, 200_000, vec![account(2)], vec![], false);
        scheduler.submit(tx1);
        scheduler.submit(tx2);

        let mb1 = scheduler.produce_microblock().unwrap();
        let mb2 = scheduler.produce_microblock().unwrap();

        assert_eq!(scheduler.per_tile_inflight_cus()[0], 300_000);
        assert_eq!(scheduler.per_tile_inflight_cus()[1], 200_000);

        // Complete with rebate — tile CUs still fully released.
        scheduler.complete_microblock_with_rebate(
            mb1.id,
            MicroblockRebate {
                requested_cus: 300_000,
                consumed_cus: 100_000,
                is_vote_only: false,
            },
        );
        assert_eq!(scheduler.per_tile_inflight_cus()[0], 0);
        assert_eq!(scheduler.per_tile_inflight_cus()[1], 200_000);

        scheduler.complete_microblock(mb2.id);
        assert_eq!(scheduler.per_tile_inflight_cus()[1], 0);
    }

    // -----------------------------------------------------------------------
    // CuPacer tests
    // -----------------------------------------------------------------------

    #[test]
    fn cu_pacer_initial_state() {
        let pacer = CuPacer::new(48_000_000, 400_000_000, 4);
        assert_eq!(pacer.remaining_cus(), 48_000_000);
        // All tiles should be enabled initially (no consumption yet).
        assert_eq!(pacer.enabled_tiles(), 4);
    }

    #[test]
    fn cu_pacer_report_consumed() {
        let mut pacer = CuPacer::new(48_000_000, 400_000_000, 4);
        pacer.report_consumed(10_000_000);
        assert_eq!(pacer.remaining_cus(), 38_000_000);
        pacer.report_consumed(8_000_000);
        assert_eq!(pacer.remaining_cus(), 30_000_000);
    }

    #[test]
    fn cu_pacer_remaining_saturates_at_zero() {
        let mut pacer = CuPacer::new(1_000, 400_000_000, 2);
        pacer.report_consumed(5_000);
        assert_eq!(pacer.remaining_cus(), 0);
    }

    #[test]
    fn cu_pacer_new_slot_resets() {
        let mut pacer = CuPacer::new(48_000_000, 400_000_000, 4);
        pacer.report_consumed(48_000_000);
        assert_eq!(pacer.remaining_cus(), 0);
        pacer.new_slot();
        assert_eq!(pacer.remaining_cus(), 48_000_000);
    }

    #[test]
    fn cu_pacer_zero_budget_enables_all_tiles() {
        let pacer = CuPacer::new(0, 400_000_000, 4);
        assert_eq!(pacer.enabled_tiles(), 4);
    }

    #[test]
    fn cu_pacer_zero_duration_enables_all_tiles() {
        let pacer = CuPacer::new(48_000_000, 0, 4);
        assert_eq!(pacer.enabled_tiles(), 4);
    }

    #[test]
    fn cu_pacer_min_one_tile() {
        // Even with zero tiles passed, should clamp to at least 1.
        let pacer = CuPacer::new(48_000_000, 400_000_000, 0);
        assert_eq!(pacer.enabled_tiles(), 1);
    }

    #[test]
    fn cu_pacer_elapsed_fraction_starts_near_zero() {
        let pacer = CuPacer::new(48_000_000, 10_000_000_000, 4); // 10 seconds
        let frac = pacer.elapsed_fraction();
        // Should be very close to 0.0 (just created).
        assert!(frac < 0.01, "elapsed_fraction={frac}, expected near 0.0");
    }

    // -----------------------------------------------------------------------
    // SmallestPending tests
    // -----------------------------------------------------------------------

    #[test]
    fn smallest_pending_initial() {
        let s = SmallestPending::new();
        assert_eq!(s.cus, u64::MAX);
        assert_eq!(s.bytes, u64::MAX);
    }

    #[test]
    fn smallest_pending_observe() {
        let mut s = SmallestPending::new();
        s.observe(50_000, 400);
        assert_eq!(s.cus, 50_000);
        assert_eq!(s.bytes, 400);
        s.observe(100_000, 200);
        assert_eq!(s.cus, 50_000); // unchanged
        assert_eq!(s.bytes, 200); // updated
        s.observe(30_000, 500);
        assert_eq!(s.cus, 30_000); // updated
        assert_eq!(s.bytes, 200); // unchanged
    }

    #[test]
    fn smallest_pending_reset() {
        let mut s = SmallestPending::new();
        s.observe(10_000, 100);
        s.reset();
        assert_eq!(s.cus, u64::MAX);
        assert_eq!(s.bytes, u64::MAX);
    }

    // -----------------------------------------------------------------------
    // ScheduleMetrics tests
    // -----------------------------------------------------------------------

    #[test]
    fn schedule_metrics_default() {
        let m = ScheduleMetrics::default();
        assert_eq!(m.taken, 0);
        assert_eq!(m.cu_limit, 0);
        assert_eq!(m.byte_limit, 0);
        assert_eq!(m.write_cost_limit, 0);
        assert_eq!(m.fast_path, 0);
        assert_eq!(m.slow_path, 0);
        assert_eq!(m.defer_skip, 0);
    }

    #[test]
    fn schedule_metrics_increment() {
        let mut m = ScheduleMetrics::default();
        m.taken += 5;
        m.cu_limit += 2;
        m.byte_limit += 1;
        m.write_cost_limit += 3;
        m.fast_path += 10;
        m.slow_path += 7;
        m.defer_skip += 4;
        assert_eq!(m.total(), 32);
    }

    #[test]
    fn schedule_metrics_reset() {
        let mut m = ScheduleMetrics::default();
        m.taken = 100;
        m.slow_path = 50;
        m.reset();
        assert_eq!(m.total(), 0);
    }
}
