/// Priority queue for pending transactions awaiting block inclusion.
///
/// Transactions are ordered by priority (compute unit price), with
/// higher-priority transactions scheduled first. The queue has a fixed
/// capacity and evicts the lowest-priority entry when full.
use paradencer_storage::Pubkey;
use std::cmp::Ordering;
use std::collections::BinaryHeap;

// ---------------------------------------------------------------------------
// Pending transaction entry
// ---------------------------------------------------------------------------

/// A transaction waiting in the pending pool.
#[derive(Debug, Clone)]
pub struct PendingTransaction {
    /// Unique identifier for this entry (monotonic insertion order).
    pub id: u64,
    /// Priority fee per compute unit (lamports / CU).
    pub compute_unit_price: u64,
    /// Total compute units requested by this transaction.
    pub compute_units: u64,
    /// Serialized transaction size in bytes.
    pub data_bytes: u64,
    /// Number of signatures on the transaction.
    pub signature_count: u64,
    /// Whether this is a simple vote transaction.
    pub is_vote: bool,
    /// Slot at which this transaction expires (based on blockhash age).
    pub expires_at_slot: u64,
    /// Accounts that this transaction reads.
    pub read_accounts: Vec<Pubkey>,
    /// Accounts that this transaction writes.
    pub write_accounts: Vec<Pubkey>,
    /// Fee payer address.
    pub fee_payer: Pubkey,
    /// Opaque transaction payload (index into external storage or bytes).
    pub payload_index: u64,
}

impl PendingTransaction {
    /// Effective priority: compute_unit_price, breaking ties by insertion order
    /// (earlier transactions win ties).
    fn priority_key(&self) -> (u64, std::cmp::Reverse<u64>) {
        (self.compute_unit_price, std::cmp::Reverse(self.id))
    }
}

impl PartialEq for PendingTransaction {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for PendingTransaction {}

impl PartialOrd for PendingTransaction {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PendingTransaction {
    fn cmp(&self, other: &Self) -> Ordering {
        self.priority_key().cmp(&other.priority_key())
    }
}

// ---------------------------------------------------------------------------
// Priority queue
// ---------------------------------------------------------------------------

/// Fixed-capacity priority queue for pending transactions.
///
/// Maintains separate heaps for vote and non-vote transactions.
/// When capacity is reached, the lowest-priority non-vote transaction
/// is evicted to make room for a higher-priority one.
pub struct PriorityQueue {
    /// Non-vote transaction heap (max-heap by priority).
    pending: BinaryHeap<PendingTransaction>,
    /// Vote transaction heap (max-heap by priority).
    votes: BinaryHeap<PendingTransaction>,
    /// Maximum total entries (votes + non-votes).
    capacity: usize,
    /// Next unique ID to assign.
    next_id: u64,
}

impl PriorityQueue {
    /// Create a new priority queue with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            pending: BinaryHeap::with_capacity(capacity),
            votes: BinaryHeap::with_capacity(capacity / 4),
            capacity,
            next_id: 0,
        }
    }

    /// Insert a transaction into the queue.
    ///
    /// Returns the assigned ID on success, or `None` if the queue is
    /// full and this transaction's priority is too low.
    pub fn insert(&mut self, mut entry: PendingTransaction) -> Option<u64> {
        entry.id = self.next_id;
        self.next_id += 1;

        let target = if entry.is_vote {
            &mut self.votes
        } else {
            &mut self.pending
        };

        let total = self.pending.len() + self.votes.len();
        if total >= self.capacity {
            // Try to evict lowest-priority non-vote transaction
            if let Some(worst) = self.pending.peek() {
                if !entry.is_vote && entry.compute_unit_price <= worst.compute_unit_price {
                    // New transaction is no better than worst — reject
                    return None;
                }
            } else {
                // Only votes in queue, can't evict
                return None;
            }

            // Evict worst non-vote
            // BinaryHeap is max-heap, so we need to find the minimum.
            // For efficiency, we rebuild without the minimum. In a real
            // implementation we'd use a min-max heap, but for correctness
            // this works fine.
            self.evict_lowest_pending();
        }

        let id = entry.id;
        if entry.is_vote {
            self.votes.push(entry);
        } else {
            self.pending.push(entry);
        }
        Some(id)
    }

    /// Remove and return the highest-priority vote transaction.
    pub fn pop_vote(&mut self) -> Option<PendingTransaction> {
        self.votes.pop()
    }

    /// Remove and return the highest-priority non-vote transaction.
    pub fn pop_pending(&mut self) -> Option<PendingTransaction> {
        self.pending.pop()
    }

    /// Peek at the highest-priority vote transaction without removing it.
    pub fn peek_vote(&self) -> Option<&PendingTransaction> {
        self.votes.peek()
    }

    /// Peek at the highest-priority non-vote transaction without removing it.
    pub fn peek_pending(&self) -> Option<&PendingTransaction> {
        self.pending.peek()
    }

    /// Total number of pending transactions (votes + non-votes).
    pub fn len(&self) -> usize {
        self.pending.len() + self.votes.len()
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty() && self.votes.is_empty()
    }

    /// Number of non-vote transactions in the queue.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Number of vote transactions in the queue.
    pub fn vote_count(&self) -> usize {
        self.votes.len()
    }

    /// Remove all transactions with `expires_at_slot < before_slot`.
    pub fn expire_before(&mut self, before_slot: u64) -> usize {
        let before_pending = self.pending.len();
        let before_votes = self.votes.len();

        self.pending = self
            .pending
            .drain()
            .filter(|tx| tx.expires_at_slot >= before_slot)
            .collect();

        self.votes = self
            .votes
            .drain()
            .filter(|tx| tx.expires_at_slot >= before_slot)
            .collect();

        (before_pending - self.pending.len()) + (before_votes - self.votes.len())
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.pending.clear();
        self.votes.clear();
    }

    /// Drain all non-vote transactions in priority order (highest first).
    pub fn drain_pending(&mut self) -> Vec<PendingTransaction> {
        let mut result = Vec::with_capacity(self.pending.len());
        while let Some(tx) = self.pending.pop() {
            result.push(tx);
        }
        result
    }

    /// Drain all vote transactions in priority order (highest first).
    pub fn drain_votes(&mut self) -> Vec<PendingTransaction> {
        let mut result = Vec::with_capacity(self.votes.len());
        while let Some(tx) = self.votes.pop() {
            result.push(tx);
        }
        result
    }

    /// Evict the lowest-priority non-vote transaction.
    fn evict_lowest_pending(&mut self) {
        if self.pending.is_empty() {
            return;
        }

        // Rebuild heap without the minimum element.
        // We collect into a vec, find and remove the min, then rebuild.
        let mut entries: Vec<_> = self.pending.drain().collect();
        if let Some(min_idx) = entries
            .iter()
            .enumerate()
            .min_by_key(|(_, e)| e.compute_unit_price)
            .map(|(i, _)| i)
        {
            entries.swap_remove(min_idx);
        }
        self.pending = entries.into_iter().collect();
    }
}
