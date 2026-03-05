/// Write-lock conflict detection and block-packing scheduler.
///
/// Selects transactions from the priority queue for inclusion in a block,
/// respecting compute unit limits, per-account write-lock costs, data byte
/// limits, and vote transaction quotas. Transactions that conflict on
/// write-locked accounts are deferred until the conflicting transaction
/// completes.
use super::priority::{PendingTransaction, PriorityQueue};
use karstflow_constants::block_limits::{
    MAX_BLOCK_COMPUTE_UNITS, MAX_DATA_BYTES_PER_BLOCK, MAX_VOTE_COMPUTE_UNITS,
    MAX_WRITABLE_ACCOUNT_COMPUTE_UNITS, PACK_FEE_PER_SIGNATURE,
};
use karstflow_storage::Pubkey;
use std::collections::{HashMap, HashSet};

// ---------------------------------------------------------------------------
// Block limits configuration
// ---------------------------------------------------------------------------

/// Resource limits for a single block.
#[derive(Debug, Clone)]
pub struct BlockLimits {
    /// Maximum total compute units per block.
    pub max_block_compute_units: u64,
    /// Maximum compute units for vote transactions.
    pub max_vote_compute_units: u64,
    /// Maximum compute units per writable account.
    pub max_write_cost_per_account: u64,
    /// Maximum data bytes per block (derived from shred limits).
    pub max_data_bytes: u64,
    /// Maximum transactions per microblock.
    pub max_transactions_per_microblock: usize,
}

impl Default for BlockLimits {
    fn default() -> Self {
        Self {
            max_block_compute_units: MAX_BLOCK_COMPUTE_UNITS,
            max_vote_compute_units: MAX_VOTE_COMPUTE_UNITS,
            max_write_cost_per_account: MAX_WRITABLE_ACCOUNT_COMPUTE_UNITS,
            max_data_bytes: MAX_DATA_BYTES_PER_BLOCK,
            max_transactions_per_microblock: 64,
        }
    }
}

// ---------------------------------------------------------------------------
// Block resource usage
// ---------------------------------------------------------------------------

/// Accumulated resource consumption for the current block.
#[derive(Debug, Clone, Default)]
pub struct BlockUsage {
    /// Total compute units scheduled in this block.
    pub total_compute_units: u64,
    /// Compute units from vote transactions.
    pub vote_compute_units: u64,
    /// Per-account accumulated write costs.
    pub account_write_costs: HashMap<Pubkey, u64>,
    /// Total data bytes scheduled.
    pub data_bytes: u64,
    /// Number of transactions scheduled.
    pub transaction_count: u64,
    /// Number of microblocks produced.
    pub microblock_count: u64,
}

impl BlockUsage {
    /// Whether adding a transaction would exceed block-level limits.
    pub fn would_exceed(&self, tx: &PendingTransaction, limits: &BlockLimits) -> bool {
        // Block compute limit
        if self.total_compute_units + tx.compute_units > limits.max_block_compute_units {
            return true;
        }

        // Vote compute limit
        if tx.is_vote && self.vote_compute_units + tx.compute_units > limits.max_vote_compute_units
        {
            return true;
        }

        // Data bytes limit
        if self.data_bytes + tx.data_bytes > limits.max_data_bytes {
            return true;
        }

        // Per-account write cost limit
        for acct in &tx.write_accounts {
            let current = self.account_write_costs.get(acct).copied().unwrap_or(0);
            if current + tx.compute_units > limits.max_write_cost_per_account {
                return true;
            }
        }

        false
    }

    /// Record that a transaction has been scheduled.
    pub fn add_transaction(&mut self, tx: &PendingTransaction) {
        self.total_compute_units += tx.compute_units;
        if tx.is_vote {
            self.vote_compute_units += tx.compute_units;
        }
        self.data_bytes += tx.data_bytes;
        self.transaction_count += 1;

        for acct in &tx.write_accounts {
            *self.account_write_costs.entry(*acct).or_insert(0) += tx.compute_units;
        }
    }

    /// Remaining block compute capacity.
    pub fn remaining_compute_units(&self, limits: &BlockLimits) -> u64 {
        limits
            .max_block_compute_units
            .saturating_sub(self.total_compute_units)
    }

    /// Remaining vote compute capacity.
    pub fn remaining_vote_compute_units(&self, limits: &BlockLimits) -> u64 {
        limits
            .max_vote_compute_units
            .saturating_sub(self.vote_compute_units)
    }

    /// Reset for a new block.
    pub fn reset(&mut self) {
        self.total_compute_units = 0;
        self.vote_compute_units = 0;
        self.account_write_costs.clear();
        self.data_bytes = 0;
        self.transaction_count = 0;
        self.microblock_count = 0;
    }
}

// ---------------------------------------------------------------------------
// Scheduled transaction
// ---------------------------------------------------------------------------

/// A transaction selected for block inclusion.
#[derive(Debug, Clone)]
pub struct ScheduledTransaction {
    /// The pending transaction that was selected.
    pub transaction: PendingTransaction,
    /// Estimated fee revenue (signatures × fee_per_signature).
    pub estimated_fee: u64,
}

// ---------------------------------------------------------------------------
// Microblock result
// ---------------------------------------------------------------------------

/// Result of scheduling a microblock.
#[derive(Debug, Clone)]
pub struct MicroblockSchedule {
    /// Transactions selected for this microblock.
    pub transactions: Vec<ScheduledTransaction>,
    /// Total compute units in this microblock.
    pub total_compute_units: u64,
    /// Total data bytes in this microblock.
    pub total_data_bytes: u64,
}

// ---------------------------------------------------------------------------
// Block scheduler
// ---------------------------------------------------------------------------

/// Selects transactions from the priority queue into microblocks.
///
/// Handles write-lock conflict detection, vote preference, and
/// resource limit enforcement.
pub struct BlockScheduler {
    /// Resource limits for the current block.
    limits: BlockLimits,
    /// Accumulated resource usage for the current block.
    usage: BlockUsage,
    /// Accounts currently locked by in-flight transactions.
    /// Maps account → set of transaction IDs holding the lock.
    write_locks: HashMap<Pubkey, HashSet<u64>>,
    /// Read locks: account → set of transaction IDs holding read access.
    read_locks: HashMap<Pubkey, HashSet<u64>>,
}

impl BlockScheduler {
    /// Create a new scheduler with the given limits.
    pub fn new(limits: BlockLimits) -> Self {
        Self {
            limits,
            usage: BlockUsage::default(),
            write_locks: HashMap::new(),
            read_locks: HashMap::new(),
        }
    }

    /// Create a scheduler with default block limits.
    pub fn with_defaults() -> Self {
        Self::new(BlockLimits::default())
    }

    /// Schedule the next microblock from the priority queue.
    ///
    /// Pops transactions from the queue in priority order, skipping those
    /// that conflict on write-locked accounts or would exceed block limits.
    /// Vote transactions are scheduled first (up to vote_fraction of capacity),
    /// then non-vote transactions fill the remainder.
    pub fn schedule_microblock(
        &mut self,
        queue: &mut PriorityQueue,
        vote_fraction: f64,
    ) -> MicroblockSchedule {
        let max_txns = self.limits.max_transactions_per_microblock;
        let remaining_cu = self.usage.remaining_compute_units(&self.limits);
        let remaining_vote_cu = self.usage.remaining_vote_compute_units(&self.limits);

        if remaining_cu == 0 {
            return MicroblockSchedule {
                transactions: vec![],
                total_compute_units: 0,
                total_data_bytes: 0,
            };
        }

        let vote_cu_budget =
            ((remaining_cu as f64) * vote_fraction).min(remaining_vote_cu as f64) as u64;
        let vote_txn_budget = ((max_txns as f64) * vote_fraction) as usize;

        let mut scheduled = Vec::new();
        let mut microblock_cu = 0u64;
        let mut microblock_bytes = 0u64;

        // Phase 1: Schedule votes
        let mut deferred_votes = Vec::new();
        let mut vote_count = 0usize;
        let mut vote_cu_used = 0u64;

        while vote_count < vote_txn_budget && vote_cu_used < vote_cu_budget {
            match queue.pop_vote() {
                Some(tx) => {
                    if self.usage.would_exceed(&tx, &self.limits) {
                        // Won't fit — don't put back, just skip
                        continue;
                    }
                    if self.has_write_conflict(&tx) {
                        deferred_votes.push(tx);
                        continue;
                    }
                    vote_cu_used += tx.compute_units;
                    microblock_cu += tx.compute_units;
                    microblock_bytes += tx.data_bytes;
                    self.usage.add_transaction(&tx);
                    self.acquire_locks(&tx);
                    scheduled.push(ScheduledTransaction {
                        estimated_fee: tx.signature_count * PACK_FEE_PER_SIGNATURE,
                        transaction: tx,
                    });
                    vote_count += 1;
                }
                None => break,
            }
        }

        // Return deferred votes to the queue
        for tx in deferred_votes {
            queue.insert(tx);
        }

        // Phase 2: Schedule non-vote transactions
        let remaining_slots = max_txns.saturating_sub(scheduled.len());
        let remaining_cu_after_votes = self.usage.remaining_compute_units(&self.limits);

        let mut deferred_pending = Vec::new();
        let mut pending_count = 0usize;
        let mut cu_used = 0u64;
        // Limit how many we skip before giving up to avoid O(n) scan
        let max_skip = 128;
        let mut skip_count = 0usize;

        while pending_count < remaining_slots && cu_used < remaining_cu_after_votes {
            match queue.pop_pending() {
                Some(tx) => {
                    if self.usage.would_exceed(&tx, &self.limits) {
                        skip_count += 1;
                        if skip_count >= max_skip {
                            deferred_pending.push(tx);
                            break;
                        }
                        deferred_pending.push(tx);
                        continue;
                    }
                    if self.has_write_conflict(&tx) {
                        deferred_pending.push(tx);
                        skip_count += 1;
                        if skip_count >= max_skip {
                            break;
                        }
                        continue;
                    }
                    cu_used += tx.compute_units;
                    microblock_cu += tx.compute_units;
                    microblock_bytes += tx.data_bytes;
                    self.usage.add_transaction(&tx);
                    self.acquire_locks(&tx);
                    scheduled.push(ScheduledTransaction {
                        estimated_fee: tx.signature_count * PACK_FEE_PER_SIGNATURE,
                        transaction: tx,
                    });
                    pending_count += 1;
                    skip_count = 0; // Reset skip count after a successful schedule
                }
                None => break,
            }
        }

        // Return deferred transactions to the queue
        // Drain the rest of the pending queue we haven't popped
        for tx in deferred_pending {
            queue.insert(tx);
        }

        if !scheduled.is_empty() {
            self.usage.microblock_count += 1;
        }

        MicroblockSchedule {
            transactions: scheduled,
            total_compute_units: microblock_cu,
            total_data_bytes: microblock_bytes,
        }
    }

    /// Release write/read locks held by a completed transaction.
    pub fn release_locks(&mut self, tx_id: u64) {
        self.write_locks.retain(|_, holders| {
            holders.remove(&tx_id);
            !holders.is_empty()
        });
        self.read_locks.retain(|_, holders| {
            holders.remove(&tx_id);
            !holders.is_empty()
        });
    }

    /// Reset the scheduler for a new block (clears usage and locks).
    pub fn end_block(&mut self) {
        self.usage.reset();
        self.write_locks.clear();
        self.read_locks.clear();
    }

    /// Update block limits for the next block.
    pub fn set_limits(&mut self, limits: BlockLimits) {
        self.limits = limits;
    }

    /// Get current block resource usage.
    pub fn usage(&self) -> &BlockUsage {
        &self.usage
    }

    /// Get current block limits.
    pub fn limits(&self) -> &BlockLimits {
        &self.limits
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Check if a transaction conflicts with any currently held lock.
    ///
    /// A write-write conflict occurs when two transactions write to the
    /// same account. A read-write conflict occurs when one transaction
    /// reads an account that another writes.
    fn has_write_conflict(&self, tx: &PendingTransaction) -> bool {
        // Check write accounts against existing write locks and read locks
        for acct in &tx.write_accounts {
            if self.write_locks.contains_key(acct) {
                return true;
            }
            if self.read_locks.contains_key(acct) {
                return true;
            }
        }
        // Check read accounts against existing write locks
        for acct in &tx.read_accounts {
            if self.write_locks.contains_key(acct) {
                return true;
            }
        }
        false
    }

    /// Acquire write and read locks for a scheduled transaction.
    fn acquire_locks(&mut self, tx: &PendingTransaction) {
        for acct in &tx.write_accounts {
            self.write_locks.entry(*acct).or_default().insert(tx.id);
        }
        for acct in &tx.read_accounts {
            self.read_locks.entry(*acct).or_default().insert(tx.id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tx(id: u64, price: u64, cu: u64, is_vote: bool) -> PendingTransaction {
        PendingTransaction {
            id,
            compute_unit_price: price,
            compute_units: cu,
            data_bytes: 200,
            signature_count: 1,
            is_vote,
            expires_at_slot: 1000,
            read_accounts: vec![],
            write_accounts: vec![],
            fee_payer: Pubkey::new_unique(),
            payload_index: 0,
        }
    }

    fn small_limits() -> BlockLimits {
        BlockLimits {
            max_block_compute_units: 100_000,
            max_vote_compute_units: 30_000,
            max_write_cost_per_account: 50_000,
            max_data_bytes: 1_000_000,
            max_transactions_per_microblock: 4,
        }
    }

    // --- BlockUsage tests ---

    #[test]
    fn block_usage_default_is_empty() {
        let usage = BlockUsage::default();
        assert_eq!(usage.total_compute_units, 0);
        assert_eq!(usage.transaction_count, 0);
    }

    #[test]
    fn block_usage_tracks_transactions() {
        let mut usage = BlockUsage::default();
        let acct = Pubkey::new_unique();
        let mut tx = make_tx(1, 100, 5_000, false);
        tx.write_accounts = vec![acct];

        usage.add_transaction(&tx);

        assert_eq!(usage.total_compute_units, 5_000);
        assert_eq!(usage.data_bytes, 200);
        assert_eq!(usage.transaction_count, 1);
        assert_eq!(*usage.account_write_costs.get(&acct).unwrap(), 5_000);
    }

    #[test]
    fn block_usage_tracks_votes() {
        let mut usage = BlockUsage::default();
        let tx = make_tx(1, 100, 3_000, true);
        usage.add_transaction(&tx);

        assert_eq!(usage.vote_compute_units, 3_000);
        assert_eq!(usage.total_compute_units, 3_000);
    }

    #[test]
    fn block_usage_would_exceed_block_cu_limit() {
        let mut usage = BlockUsage::default();
        let limits = small_limits();
        usage.total_compute_units = 99_000;

        let tx = make_tx(1, 100, 2_000, false);
        assert!(usage.would_exceed(&tx, &limits));
    }

    #[test]
    fn block_usage_would_exceed_vote_cu_limit() {
        let mut usage = BlockUsage::default();
        let limits = small_limits();
        usage.vote_compute_units = 29_000;

        let tx = make_tx(1, 100, 2_000, true);
        assert!(usage.would_exceed(&tx, &limits));
    }

    #[test]
    fn block_usage_would_exceed_per_account_write_cost() {
        let mut usage = BlockUsage::default();
        let limits = small_limits();
        let acct = Pubkey::new_unique();
        usage.account_write_costs.insert(acct, 49_000);

        let mut tx = make_tx(1, 100, 2_000, false);
        tx.write_accounts = vec![acct];
        assert!(usage.would_exceed(&tx, &limits));
    }

    #[test]
    fn block_usage_would_exceed_data_bytes() {
        let mut usage = BlockUsage::default();
        let limits = small_limits();
        usage.data_bytes = 999_900;

        let tx = make_tx(1, 100, 1_000, false);
        assert!(usage.would_exceed(&tx, &limits));
    }

    #[test]
    fn block_usage_remaining_compute() {
        let mut usage = BlockUsage::default();
        let limits = small_limits();
        usage.total_compute_units = 60_000;

        assert_eq!(usage.remaining_compute_units(&limits), 40_000);
    }

    #[test]
    fn block_usage_reset_clears_state() {
        let mut usage = BlockUsage::default();
        let acct = Pubkey::new_unique();
        usage.total_compute_units = 50_000;
        usage.vote_compute_units = 10_000;
        usage.data_bytes = 5_000;
        usage.transaction_count = 3;
        usage.microblock_count = 1;
        usage.account_write_costs.insert(acct, 20_000);

        usage.reset();

        assert_eq!(usage.total_compute_units, 0);
        assert_eq!(usage.vote_compute_units, 0);
        assert_eq!(usage.data_bytes, 0);
        assert_eq!(usage.transaction_count, 0);
        assert_eq!(usage.microblock_count, 0);
        assert!(usage.account_write_costs.is_empty());
    }

    // --- BlockScheduler tests ---

    #[test]
    fn schedule_empty_queue_returns_empty_microblock() {
        let mut scheduler = BlockScheduler::new(small_limits());
        let mut queue = PriorityQueue::new(100);

        let mb = scheduler.schedule_microblock(&mut queue, 0.25);
        assert!(mb.transactions.is_empty());
        assert_eq!(mb.total_compute_units, 0);
    }

    #[test]
    fn schedule_single_pending_transaction() {
        let mut scheduler = BlockScheduler::new(small_limits());
        let mut queue = PriorityQueue::new(100);
        queue.insert(make_tx(0, 500, 5_000, false));

        let mb = scheduler.schedule_microblock(&mut queue, 0.25);
        assert_eq!(mb.transactions.len(), 1);
        assert_eq!(mb.total_compute_units, 5_000);
        assert!(mb.transactions[0].estimated_fee > 0);
    }

    #[test]
    fn schedule_respects_max_transactions_per_microblock() {
        let mut scheduler = BlockScheduler::new(small_limits()); // max 4 per microblock
        let mut queue = PriorityQueue::new(100);

        for i in 0..10 {
            queue.insert(make_tx(i, 500, 1_000, false));
        }

        let mb = scheduler.schedule_microblock(&mut queue, 0.0);
        assert!(mb.transactions.len() <= 4);
    }

    #[test]
    fn schedule_votes_first_then_pending() {
        let mut scheduler = BlockScheduler::new(small_limits());
        let mut queue = PriorityQueue::new(100);

        queue.insert(make_tx(0, 100, 2_000, false));
        queue.insert(make_tx(0, 200, 2_000, true));

        let mb = scheduler.schedule_microblock(&mut queue, 0.5);
        assert!(!mb.transactions.is_empty());
        // First should be the vote
        assert!(mb.transactions[0].transaction.is_vote);
    }

    #[test]
    fn write_conflict_defers_transaction() {
        let mut scheduler = BlockScheduler::new(small_limits());
        let mut queue = PriorityQueue::new(100);

        let shared_account = Pubkey::new_unique();

        let mut tx1 = make_tx(0, 500, 2_000, false);
        tx1.write_accounts = vec![shared_account];
        let mut tx2 = make_tx(0, 400, 2_000, false);
        tx2.write_accounts = vec![shared_account];

        queue.insert(tx1);
        queue.insert(tx2);

        let mb = scheduler.schedule_microblock(&mut queue, 0.0);
        // Only one should be scheduled (the other deferred due to conflict)
        assert_eq!(mb.transactions.len(), 1);
        // The deferred one should still be in the queue
        assert_eq!(queue.pending_count(), 1);
    }

    #[test]
    fn read_write_conflict_defers_transaction() {
        let mut scheduler = BlockScheduler::new(small_limits());
        let mut queue = PriorityQueue::new(100);

        let shared_account = Pubkey::new_unique();

        let mut tx1 = make_tx(0, 500, 2_000, false);
        tx1.write_accounts = vec![shared_account];
        let mut tx2 = make_tx(0, 400, 2_000, false);
        tx2.read_accounts = vec![shared_account]; // Reads what tx1 writes

        queue.insert(tx1);
        queue.insert(tx2);

        let mb = scheduler.schedule_microblock(&mut queue, 0.0);
        assert_eq!(mb.transactions.len(), 1);
    }

    #[test]
    fn release_locks_allows_previously_conflicting() {
        let mut scheduler = BlockScheduler::new(small_limits());
        let mut queue = PriorityQueue::new(100);

        let shared_account = Pubkey::new_unique();

        let mut tx1 = make_tx(0, 500, 2_000, false);
        tx1.write_accounts = vec![shared_account];
        let mut tx2 = make_tx(0, 400, 2_000, false);
        tx2.write_accounts = vec![shared_account];

        queue.insert(tx1);
        queue.insert(tx2);

        let mb1 = scheduler.schedule_microblock(&mut queue, 0.0);
        assert_eq!(mb1.transactions.len(), 1);
        let scheduled_id = mb1.transactions[0].transaction.id;

        // Release the lock from the first transaction
        scheduler.release_locks(scheduled_id);

        // Now the second should be schedulable
        let mb2 = scheduler.schedule_microblock(&mut queue, 0.0);
        assert_eq!(mb2.transactions.len(), 1);
    }

    #[test]
    fn end_block_resets_scheduler() {
        let mut scheduler = BlockScheduler::new(small_limits());
        let mut queue = PriorityQueue::new(100);

        queue.insert(make_tx(0, 500, 50_000, false));
        scheduler.schedule_microblock(&mut queue, 0.0);

        assert!(scheduler.usage().total_compute_units > 0);

        scheduler.end_block();
        assert_eq!(scheduler.usage().total_compute_units, 0);
        assert_eq!(scheduler.usage().transaction_count, 0);
    }

    #[test]
    fn no_transactions_when_block_cu_exhausted() {
        let limits = BlockLimits {
            max_block_compute_units: 5_000,
            ..small_limits()
        };
        let mut scheduler = BlockScheduler::new(limits);
        let mut queue = PriorityQueue::new(100);

        // First microblock uses all CU
        queue.insert(make_tx(0, 500, 5_000, false));
        let mb1 = scheduler.schedule_microblock(&mut queue, 0.0);
        assert_eq!(mb1.transactions.len(), 1);

        // Second microblock should produce nothing
        queue.insert(make_tx(0, 500, 1_000, false));
        let mb2 = scheduler.schedule_microblock(&mut queue, 0.0);
        assert!(mb2.transactions.is_empty());
    }

    #[test]
    fn microblock_count_incremented() {
        let mut scheduler = BlockScheduler::new(small_limits());
        let mut queue = PriorityQueue::new(100);
        queue.insert(make_tx(0, 500, 1_000, false));

        assert_eq!(scheduler.usage().microblock_count, 0);
        scheduler.schedule_microblock(&mut queue, 0.0);
        assert_eq!(scheduler.usage().microblock_count, 1);
    }
}
