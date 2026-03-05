/// Priority queue for pending transactions awaiting block inclusion.
///
/// Transactions are ordered by priority (compute unit price), with
/// higher-priority transactions scheduled first. The queue has a fixed
/// capacity and evicts the lowest-priority entry when full.
use karstflow_storage::Pubkey;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tx(price: u64, is_vote: bool) -> PendingTransaction {
        PendingTransaction {
            id: 0, // Will be assigned by queue
            compute_unit_price: price,
            compute_units: 1_000,
            data_bytes: 100,
            signature_count: 1,
            is_vote,
            expires_at_slot: 1000,
            read_accounts: vec![],
            write_accounts: vec![],
            fee_payer: Pubkey::new_unique(),
            payload_index: 0,
        }
    }

    #[test]
    fn empty_queue() {
        let queue = PriorityQueue::new(100);
        assert!(queue.is_empty());
        assert_eq!(queue.len(), 0);
        assert_eq!(queue.pending_count(), 0);
        assert_eq!(queue.vote_count(), 0);
    }

    #[test]
    fn insert_and_pop_pending() {
        let mut queue = PriorityQueue::new(100);
        queue.insert(make_tx(500, false));
        queue.insert(make_tx(1000, false));
        queue.insert(make_tx(200, false));

        assert_eq!(queue.len(), 3);
        assert_eq!(queue.pending_count(), 3);

        // Should pop highest priority first
        let top = queue.pop_pending().unwrap();
        assert_eq!(top.compute_unit_price, 1000);
        let next = queue.pop_pending().unwrap();
        assert_eq!(next.compute_unit_price, 500);
        let last = queue.pop_pending().unwrap();
        assert_eq!(last.compute_unit_price, 200);
        assert!(queue.pop_pending().is_none());
    }

    #[test]
    fn insert_and_pop_votes() {
        let mut queue = PriorityQueue::new(100);
        queue.insert(make_tx(300, true));
        queue.insert(make_tx(800, true));

        assert_eq!(queue.vote_count(), 2);
        assert_eq!(queue.pending_count(), 0);

        let top = queue.pop_vote().unwrap();
        assert_eq!(top.compute_unit_price, 800);
    }

    #[test]
    fn votes_and_pending_separate() {
        let mut queue = PriorityQueue::new(100);
        queue.insert(make_tx(100, false));
        queue.insert(make_tx(200, true));

        assert_eq!(queue.pending_count(), 1);
        assert_eq!(queue.vote_count(), 1);
        assert_eq!(queue.len(), 2);

        // Pop vote doesn't affect pending
        let vote = queue.pop_vote().unwrap();
        assert!(vote.is_vote);
        assert_eq!(queue.pending_count(), 1);
    }

    #[test]
    fn capacity_evicts_lowest_pending() {
        let mut queue = PriorityQueue::new(3);
        queue.insert(make_tx(100, false));
        queue.insert(make_tx(200, false));
        queue.insert(make_tx(300, false));

        assert_eq!(queue.len(), 3);

        // Insert higher priority — should evict price=100
        let id = queue.insert(make_tx(400, false));
        assert!(id.is_some());
        assert_eq!(queue.len(), 3);

        // Drain and verify lowest (100) was evicted
        let all = queue.drain_pending();
        let prices: Vec<u64> = all.iter().map(|t| t.compute_unit_price).collect();
        assert!(!prices.contains(&100));
        assert!(prices.contains(&200));
        assert!(prices.contains(&300));
        assert!(prices.contains(&400));
    }

    #[test]
    fn capacity_rejects_low_priority() {
        let mut queue = PriorityQueue::new(2);
        queue.insert(make_tx(500, false));
        queue.insert(make_tx(600, false));

        // Insert lower priority — should be rejected
        let id = queue.insert(make_tx(400, false));
        assert!(id.is_none());
        assert_eq!(queue.len(), 2);
    }

    #[test]
    fn expire_before_removes_old_transactions() {
        let mut queue = PriorityQueue::new(100);

        let mut tx1 = make_tx(100, false);
        tx1.expires_at_slot = 50;
        queue.insert(tx1);

        let mut tx2 = make_tx(200, false);
        tx2.expires_at_slot = 100;
        queue.insert(tx2);

        let mut tx3 = make_tx(300, true);
        tx3.expires_at_slot = 50;
        queue.insert(tx3);

        let expired = queue.expire_before(100);
        assert_eq!(expired, 2); // tx1 (slot 50) and tx3 (slot 50)
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.pending_count(), 1);
    }

    #[test]
    fn clear_empties_everything() {
        let mut queue = PriorityQueue::new(100);
        queue.insert(make_tx(100, false));
        queue.insert(make_tx(200, true));
        assert_eq!(queue.len(), 2);

        queue.clear();
        assert!(queue.is_empty());
    }

    #[test]
    fn peek_does_not_remove() {
        let mut queue = PriorityQueue::new(100);
        queue.insert(make_tx(500, false));
        queue.insert(make_tx(300, true));

        assert_eq!(queue.peek_pending().unwrap().compute_unit_price, 500);
        assert_eq!(queue.peek_vote().unwrap().compute_unit_price, 300);
        assert_eq!(queue.len(), 2); // Still there
    }

    #[test]
    fn ids_are_monotonically_assigned() {
        let mut queue = PriorityQueue::new(100);
        let id1 = queue.insert(make_tx(100, false)).unwrap();
        let id2 = queue.insert(make_tx(200, false)).unwrap();
        let id3 = queue.insert(make_tx(300, true)).unwrap();
        assert!(id1 < id2);
        assert!(id2 < id3);
    }

    #[test]
    fn priority_breaks_ties_by_insertion_order() {
        let mut queue = PriorityQueue::new(100);
        // Same price, different insertion order
        queue.insert(make_tx(500, false)); // id=0
        queue.insert(make_tx(500, false)); // id=1

        let first = queue.pop_pending().unwrap();
        let second = queue.pop_pending().unwrap();
        // Earlier insertion (lower id) wins ties
        assert!(first.id < second.id);
    }

    #[test]
    fn drain_returns_in_priority_order() {
        let mut queue = PriorityQueue::new(100);
        queue.insert(make_tx(300, false));
        queue.insert(make_tx(100, false));
        queue.insert(make_tx(500, false));

        let drained = queue.drain_pending();
        assert_eq!(drained.len(), 3);
        assert_eq!(drained[0].compute_unit_price, 500);
        assert_eq!(drained[1].compute_unit_price, 300);
        assert_eq!(drained[2].compute_unit_price, 100);
    }
}
