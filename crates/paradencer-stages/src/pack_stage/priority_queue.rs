/// Priority-ordered transaction queue for the pack scheduler.
///
/// Transactions are ordered by priority fee per compute unit (descending),
/// with vote transactions given scheduling priority over non-vote
/// transactions. The queue supports efficient insertion and extraction
/// of the highest-priority transaction.
use std::cmp::Ordering;
use std::collections::BinaryHeap;

/// A transaction ready for scheduling with priority metadata.
#[derive(Debug, Clone)]
pub struct PackedTransaction {
    /// Raw transaction payload.
    pub payload: Vec<u8>,
    /// The blockhash referenced by this transaction.
    pub blockhash: [u8; 32],
    /// Priority fee in lamports.
    pub priority_fee: u64,
    /// Estimated compute units requested.
    pub compute_units: u64,
    /// Whether this is a simple vote transaction.
    pub is_vote: bool,
    /// Slot at which this transaction expires.
    pub expires_at_slot: u64,
    /// Account locks required by this transaction.
    pub write_accounts: Vec<[u8; 32]>,
    /// Read-only accounts referenced by this transaction.
    pub read_accounts: Vec<[u8; 32]>,
    /// Estimated transaction data size in bytes.
    pub data_size: usize,
    /// Insertion order for tie-breaking (set by TransactionQueue::insert).
    pub(crate) insertion_order: u64,
}

impl PackedTransaction {
    /// Priority fee per compute unit (in lamports / CU).
    pub fn fee_rate(&self) -> u64 {
        if self.compute_units == 0 {
            return self.priority_fee;
        }
        self.priority_fee / self.compute_units.max(1)
    }
}

/// Wrapper for BinaryHeap ordering.
/// Votes are always higher priority than non-votes.
/// Within the same category, higher fee_rate wins.
/// Ties broken by insertion order (FIFO).
struct PriorityEntry(PackedTransaction);

impl PartialEq for PriorityEntry {
    fn eq(&self, other: &Self) -> bool {
        self.0.is_vote == other.0.is_vote
            && self.0.fee_rate() == other.0.fee_rate()
            && self.0.insertion_order == other.0.insertion_order
    }
}

impl Eq for PriorityEntry {}

impl PartialOrd for PriorityEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PriorityEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Votes always beat non-votes.
        match (self.0.is_vote, other.0.is_vote) {
            (true, false) => return Ordering::Greater,
            (false, true) => return Ordering::Less,
            _ => {}
        }

        // Higher fee rate wins.
        match self.0.fee_rate().cmp(&other.0.fee_rate()) {
            Ordering::Equal => {}
            ord => return ord,
        }

        // Earlier insertion wins (lower order = higher priority).
        other.0.insertion_order.cmp(&self.0.insertion_order)
    }
}

/// Priority queue for pending transactions.
pub struct TransactionQueue {
    heap: BinaryHeap<PriorityEntry>,
    insertion_counter: u64,
    /// Total compute units of all queued transactions.
    total_compute_units: u64,
    /// Total data bytes of all queued transactions.
    total_data_bytes: u64,
}

impl TransactionQueue {
    /// Create a new empty transaction queue.
    pub fn new() -> Self {
        Self {
            heap: BinaryHeap::new(),
            insertion_counter: 0,
            total_compute_units: 0,
            total_data_bytes: 0,
        }
    }

    /// Create a new queue with pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            heap: BinaryHeap::with_capacity(capacity),
            insertion_counter: 0,
            total_compute_units: 0,
            total_data_bytes: 0,
        }
    }

    /// Insert a transaction into the priority queue.
    pub fn insert(&mut self, mut tx: PackedTransaction) {
        tx.insertion_order = self.insertion_counter;
        self.insertion_counter += 1;
        self.total_compute_units += tx.compute_units;
        self.total_data_bytes += tx.data_size as u64;
        self.heap.push(PriorityEntry(tx));
    }

    /// Pop the highest-priority transaction.
    pub fn pop(&mut self) -> Option<PackedTransaction> {
        self.heap.pop().map(|entry| {
            self.total_compute_units = self
                .total_compute_units
                .saturating_sub(entry.0.compute_units);
            self.total_data_bytes = self
                .total_data_bytes
                .saturating_sub(entry.0.data_size as u64);
            entry.0
        })
    }

    /// Peek at the highest-priority transaction without removing it.
    pub fn peek(&self) -> Option<&PackedTransaction> {
        self.heap.peek().map(|entry| &entry.0)
    }

    /// Number of queued transactions.
    pub fn len(&self) -> usize {
        self.heap.len()
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    /// Total compute units queued.
    pub fn total_compute_units(&self) -> u64 {
        self.total_compute_units
    }

    /// Total data bytes queued.
    pub fn total_data_bytes(&self) -> u64 {
        self.total_data_bytes
    }

    /// Drain all expired transactions for the given slot.
    /// Returns the number of transactions removed.
    pub fn drain_expired(&mut self, current_slot: u64) -> usize {
        let before = self.heap.len();
        let mut remaining = BinaryHeap::new();

        while let Some(entry) = self.heap.pop() {
            if entry.0.expires_at_slot > current_slot {
                remaining.push(entry);
            } else {
                self.total_compute_units = self
                    .total_compute_units
                    .saturating_sub(entry.0.compute_units);
                self.total_data_bytes = self
                    .total_data_bytes
                    .saturating_sub(entry.0.data_size as u64);
            }
        }

        self.heap = remaining;
        before - self.heap.len()
    }

    /// Clear all transactions.
    pub fn clear(&mut self) {
        self.heap.clear();
        self.total_compute_units = 0;
        self.total_data_bytes = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tx(priority_fee: u64, compute_units: u64, is_vote: bool) -> PackedTransaction {
        PackedTransaction {
            payload: vec![],
            blockhash: [0u8; 32],
            priority_fee,
            compute_units,
            is_vote,
            expires_at_slot: u64::MAX,
            write_accounts: vec![],
            read_accounts: vec![],
            data_size: 100,
            insertion_order: 0,
        }
    }

    #[test]
    fn votes_scheduled_before_non_votes() {
        let mut queue = TransactionQueue::new();

        queue.insert(make_tx(1_000_000, 200_000, false)); // high fee non-vote
        queue.insert(make_tx(5_000, 200_000, true)); // low fee vote

        let first = queue.pop().unwrap();
        assert!(first.is_vote);
    }

    #[test]
    fn higher_fee_rate_first() {
        let mut queue = TransactionQueue::new();

        queue.insert(make_tx(100, 200_000, false)); // fee_rate = 0
        queue.insert(make_tx(1_000_000, 200_000, false)); // fee_rate = 5

        let first = queue.pop().unwrap();
        assert_eq!(first.priority_fee, 1_000_000);
    }

    #[test]
    fn fifo_for_equal_priority() {
        let mut queue = TransactionQueue::new();

        let mut tx1 = make_tx(5_000, 200_000, false);
        tx1.payload = vec![1];
        let mut tx2 = make_tx(5_000, 200_000, false);
        tx2.payload = vec![2];

        queue.insert(tx1);
        queue.insert(tx2);

        let first = queue.pop().unwrap();
        assert_eq!(first.payload, vec![1]); // first inserted, first out
    }

    #[test]
    fn drain_expired_transactions() {
        let mut queue = TransactionQueue::new();

        let mut tx1 = make_tx(5_000, 200_000, false);
        tx1.expires_at_slot = 100;

        let mut tx2 = make_tx(5_000, 200_000, false);
        tx2.expires_at_slot = 200;

        queue.insert(tx1);
        queue.insert(tx2);

        let removed = queue.drain_expired(150);
        assert_eq!(removed, 1);
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn total_compute_units_tracking() {
        let mut queue = TransactionQueue::new();

        queue.insert(make_tx(0, 200_000, false));
        queue.insert(make_tx(0, 300_000, false));
        assert_eq!(queue.total_compute_units(), 500_000);

        let popped = queue.pop().unwrap();
        // Both have fee_rate=0, FIFO means first inserted (200K) is popped first.
        assert_eq!(popped.compute_units, 200_000);
        assert_eq!(queue.total_compute_units(), 300_000);
    }

    #[test]
    fn clear_resets_queue() {
        let mut queue = TransactionQueue::new();
        queue.insert(make_tx(0, 100_000, false));
        queue.insert(make_tx(0, 200_000, false));

        queue.clear();
        assert!(queue.is_empty());
        assert_eq!(queue.total_compute_units(), 0);
    }
}
