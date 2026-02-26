/// DAG-based parallel transaction dispatcher for replay.
///
/// Analyzes account read/write dependencies between transactions and
/// dispatches independent transactions to parallel execution lanes.
/// This eliminates unnecessary serialization when transactions touch
/// different accounts, significantly improving replay throughput.
///
/// Dependency rules:
/// - Write-After-Write (WAW): tx2 writes account A after tx1 writes A → dependency
/// - Read-After-Write (RAW): tx2 reads account A after tx1 writes A → dependency
/// - Write-After-Read (WAR): tx2 writes account A after tx1 reads A → dependency
/// - Read-Read: no dependency (concurrent reads are safe)
use paradencer_storage::Pubkey;
use std::collections::{HashMap, VecDeque};

// ---------------------------------------------------------------------------
// Transaction states
// ---------------------------------------------------------------------------

/// State of a transaction in the dispatch pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchState {
    /// Dependencies not yet satisfied — waiting on predecessors.
    Pending,
    /// All dependencies completed — ready for execution.
    Ready,
    /// Currently being executed on an execution lane.
    Dispatched { lane: usize },
    /// Execution complete.
    Completed,
}

// ---------------------------------------------------------------------------
// Dependency graph
// ---------------------------------------------------------------------------

/// A single transaction in the dispatch graph.
struct DispatchEntry {
    /// Which accounts this transaction writes.
    write_accounts: Vec<Pubkey>,
    /// Which accounts this transaction reads.
    read_accounts: Vec<Pubkey>,
    /// Current state.
    state: DispatchState,
    /// Indices of transactions that must complete before this one.
    depends_on: Vec<u32>,
    /// Indices of transactions that depend on this one.
    dependents: Vec<u32>,
    /// Number of uncompleted dependencies.
    pending_dependency_count: u32,
}

/// Dependency graph for a batch of transactions.
///
/// Tracks WAW, RAW, and WAR dependencies between transactions based on
/// their account lock sets. Maintains a ready queue of transactions
/// whose dependencies are all satisfied.
pub struct DependencyGraph {
    /// All entries in insertion order.
    entries: Vec<DispatchEntry>,
    /// Account → index of the last transaction that writes this account.
    last_writer: HashMap<Pubkey, u32>,
    /// Account → indices of transactions that read this account since the last write.
    active_readers: HashMap<Pubkey, Vec<u32>>,
    /// Indices of transactions in Ready state, in FIFO order.
    ready_queue: VecDeque<u32>,
    /// Total dependency edges in the graph.
    total_dependencies: u64,
    /// Maximum chain depth observed.
    max_depth: u32,
}

impl DependencyGraph {
    /// Create an empty dependency graph.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            last_writer: HashMap::new(),
            active_readers: HashMap::new(),
            ready_queue: VecDeque::new(),
            total_dependencies: 0,
            max_depth: 0,
        }
    }

    /// Create a graph with pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
            last_writer: HashMap::with_capacity(capacity),
            active_readers: HashMap::with_capacity(capacity / 4),
            ready_queue: VecDeque::with_capacity(capacity),
            total_dependencies: 0,
            max_depth: 0,
        }
    }

    /// Insert a transaction into the graph.
    ///
    /// Computes dependencies based on account conflicts with previously
    /// inserted transactions. If the transaction has no dependencies,
    /// it is immediately placed in the ready queue.
    pub fn insert(&mut self, write_accounts: Vec<Pubkey>, read_accounts: Vec<Pubkey>) {
        let idx = self.entries.len() as u32;
        let mut depends_on = Vec::new();

        // WAW: if we write an account that was previously written, depend on that writer.
        // RAW: if we read an account that was previously written, depend on that writer.
        // WAR: if we write an account that was previously read, depend on those readers.

        // Collect dependencies from write accounts (WAW + WAR).
        for account in &write_accounts {
            // WAW: depend on the last writer of this account.
            if let Some(&last_w) = self.last_writer.get(account) {
                if !depends_on.contains(&last_w) {
                    depends_on.push(last_w);
                }
            }
            // WAR: depend on all active readers of this account.
            if let Some(readers) = self.active_readers.get(account) {
                for &reader_idx in readers {
                    if !depends_on.contains(&reader_idx) {
                        depends_on.push(reader_idx);
                    }
                }
            }
        }

        // Collect dependencies from read accounts (RAW only).
        for account in &read_accounts {
            // RAW: depend on the last writer of this account.
            if let Some(&last_w) = self.last_writer.get(account) {
                if !depends_on.contains(&last_w) {
                    depends_on.push(last_w);
                }
            }
        }

        // Filter out already-completed dependencies.
        depends_on
            .retain(|&dep_idx| self.entries[dep_idx as usize].state != DispatchState::Completed);

        let pending_count = depends_on.len() as u32;
        self.total_dependencies += depends_on.len() as u64;

        // Register this transaction as a dependent of its predecessors.
        for &dep_idx in &depends_on {
            self.entries[dep_idx as usize].dependents.push(idx);
        }

        let state = if pending_count == 0 {
            self.ready_queue.push_back(idx);
            DispatchState::Ready
        } else {
            DispatchState::Pending
        };

        // Update last_writer and active_readers maps.
        for account in &write_accounts {
            self.last_writer.insert(*account, idx);
            // Clear active readers since this write supersedes them.
            self.active_readers.remove(account);
        }
        for account in &read_accounts {
            self.active_readers.entry(*account).or_default().push(idx);
        }

        self.entries.push(DispatchEntry {
            write_accounts,
            read_accounts,
            state,
            depends_on,
            dependents: Vec::new(),
            pending_dependency_count: pending_count,
        });
    }

    /// Dequeue the next ready transaction.
    ///
    /// Returns `(index, lane)` where `lane` is the assigned execution lane.
    /// The caller must later call `complete(index)` when execution finishes.
    pub fn next_ready(&mut self, lane: usize) -> Option<u32> {
        let idx = self.ready_queue.pop_front()?;
        self.entries[idx as usize].state = DispatchState::Dispatched { lane };
        Some(idx)
    }

    /// Mark a transaction as completed and promote its dependents.
    ///
    /// For each dependent whose pending count drops to zero, the dependent
    /// is moved from Pending to Ready and added to the ready queue.
    pub fn complete(&mut self, idx: u32) {
        self.entries[idx as usize].state = DispatchState::Completed;

        // Clone the dependents list to avoid borrowing issues.
        let dependents: Vec<u32> = self.entries[idx as usize].dependents.clone();

        for &dep_idx in &dependents {
            let entry = &mut self.entries[dep_idx as usize];
            debug_assert!(entry.pending_dependency_count > 0);
            entry.pending_dependency_count -= 1;

            if entry.pending_dependency_count == 0 && entry.state == DispatchState::Pending {
                entry.state = DispatchState::Ready;
                self.ready_queue.push_back(dep_idx);
            }
        }
    }

    /// Number of transactions in the graph.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the graph is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Number of transactions in the ready queue.
    pub fn ready_count(&self) -> usize {
        self.ready_queue.len()
    }

    /// Number of completed transactions.
    pub fn completed_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.state == DispatchState::Completed)
            .count()
    }

    /// Whether all transactions are completed.
    pub fn all_completed(&self) -> bool {
        self.entries
            .iter()
            .all(|e| e.state == DispatchState::Completed)
    }

    /// Total dependency edges in the graph.
    pub fn total_dependencies(&self) -> u64 {
        self.total_dependencies
    }

    /// Get the state of a specific transaction.
    pub fn state(&self, idx: u32) -> DispatchState {
        self.entries[idx as usize].state
    }

    /// Reset the graph for reuse.
    pub fn reset(&mut self) {
        self.entries.clear();
        self.last_writer.clear();
        self.active_readers.clear();
        self.ready_queue.clear();
        self.total_dependencies = 0;
        self.max_depth = 0;
    }
}

impl Default for DependencyGraph {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

/// Progress report from a single dispatch step.
#[derive(Debug, Clone, Copy)]
pub struct DispatchProgress {
    /// Transactions dispatched to lanes this step.
    pub dispatched: usize,
    /// Transactions completed this step.
    pub completed: usize,
    /// Transactions currently ready for dispatch.
    pub ready: usize,
    /// Transactions still waiting on dependencies.
    pub pending: usize,
    /// All transactions are completed.
    pub all_done: bool,
}

/// Statistics accumulated during dispatch.
#[derive(Debug, Clone, Default)]
pub struct DispatcherStats {
    /// Total transactions processed.
    pub total_transactions: u64,
    /// Total dependency edges.
    pub total_dependencies: u64,
    /// Maximum dependency chain depth.
    pub max_chain_depth: u64,
    /// Number of dispatch steps taken.
    pub dispatch_steps: u64,
}

/// Parallel transaction dispatcher.
///
/// Manages a dependency graph and dispatches ready transactions to
/// execution lanes. The caller drives the dispatch loop by calling
/// `dispatch_step()` repeatedly until all transactions complete.
///
/// The dispatcher is decoupled from the execution backend — it only
/// tracks which transactions are ready and which lanes are idle.
/// The caller is responsible for actually executing transactions
/// and reporting completion.
pub struct TransactionDispatcher {
    /// The dependency graph for the current batch.
    graph: DependencyGraph,
    /// Number of execution lanes.
    lane_count: usize,
    /// Which lane is executing which transaction (None = idle).
    lane_assignments: Vec<Option<u32>>,
    /// Statistics.
    stats: DispatcherStats,
}

impl TransactionDispatcher {
    /// Create a new dispatcher with the given number of execution lanes.
    pub fn new(lane_count: usize) -> Self {
        assert!(lane_count > 0, "must have at least one execution lane");
        Self {
            graph: DependencyGraph::new(),
            lane_count,
            lane_assignments: vec![None; lane_count],
            stats: DispatcherStats::default(),
        }
    }

    /// Load a batch of transactions for dispatch.
    ///
    /// Each transaction is specified by its write and read account sets.
    /// The graph computes dependencies automatically.
    pub fn load_transactions(&mut self, transactions: Vec<(Vec<Pubkey>, Vec<Pubkey>)>) {
        self.graph.reset();
        self.lane_assignments.iter_mut().for_each(|a| *a = None);
        self.stats.total_transactions = transactions.len() as u64;

        for (writes, reads) in transactions {
            self.graph.insert(writes, reads);
        }

        self.stats.total_dependencies = self.graph.total_dependencies();
    }

    /// Perform one dispatch step.
    ///
    /// Fills idle lanes with ready transactions and returns a progress
    /// report. The caller should:
    /// 1. For each dispatched transaction, execute it
    /// 2. Call `complete_transaction(idx)` when execution finishes
    /// 3. Repeat until `progress.all_done` is true
    ///
    /// Returns the indices of newly dispatched transactions along with
    /// their assigned lane numbers.
    pub fn dispatch_step(&mut self) -> (DispatchProgress, Vec<(u32, usize)>) {
        self.stats.dispatch_steps += 1;
        let mut dispatched = Vec::new();

        for lane in 0..self.lane_count {
            if self.lane_assignments[lane].is_some() {
                continue; // lane busy
            }
            if let Some(idx) = self.graph.next_ready(lane) {
                self.lane_assignments[lane] = Some(idx);
                dispatched.push((idx, lane));
            }
        }

        let progress = DispatchProgress {
            dispatched: dispatched.len(),
            completed: 0,
            ready: self.graph.ready_count(),
            pending: self.graph.len() - self.graph.completed_count() - dispatched.len(),
            all_done: self.graph.all_completed() && dispatched.is_empty(),
        };

        (progress, dispatched)
    }

    /// Mark a transaction as completed and free its lane.
    ///
    /// This updates the dependency graph, potentially making new
    /// transactions ready for dispatch.
    pub fn complete_transaction(&mut self, idx: u32) {
        // Find and free the lane.
        for lane in &mut self.lane_assignments {
            if *lane == Some(idx) {
                *lane = None;
                break;
            }
        }
        self.graph.complete(idx);
    }

    /// Whether all transactions have been completed.
    pub fn all_done(&self) -> bool {
        self.graph.all_completed()
    }

    /// Number of transactions in the current batch.
    pub fn transaction_count(&self) -> usize {
        self.graph.len()
    }

    /// Number of idle lanes.
    pub fn idle_lane_count(&self) -> usize {
        self.lane_assignments.iter().filter(|a| a.is_none()).count()
    }

    /// Get the accumulated statistics.
    pub fn stats(&self) -> &DispatcherStats {
        &self.stats
    }

    /// Reset the dispatcher for reuse.
    pub fn reset(&mut self) {
        self.graph.reset();
        self.lane_assignments.iter_mut().for_each(|a| *a = None);
        self.stats = DispatcherStats::default();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn pubkey(id: u8) -> Pubkey {
        let mut bytes = [0u8; 32];
        bytes[0] = id;
        Pubkey::from(bytes)
    }

    // --- DependencyGraph unit tests ---

    #[test]
    fn independent_transactions_all_ready() {
        let mut graph = DependencyGraph::new();

        // Three transactions touching different accounts — all independent.
        graph.insert(vec![pubkey(1)], vec![]);
        graph.insert(vec![pubkey(2)], vec![]);
        graph.insert(vec![pubkey(3)], vec![]);

        assert_eq!(graph.ready_count(), 3);
        assert_eq!(graph.total_dependencies(), 0);
    }

    #[test]
    fn write_after_write_dependency() {
        let mut graph = DependencyGraph::new();

        // tx0 writes A, tx1 writes A → tx1 depends on tx0.
        graph.insert(vec![pubkey(1)], vec![]); // tx0
        graph.insert(vec![pubkey(1)], vec![]); // tx1

        assert_eq!(graph.ready_count(), 1); // only tx0 is ready
        assert_eq!(graph.state(0), DispatchState::Ready);
        assert_eq!(graph.state(1), DispatchState::Pending);
        assert_eq!(graph.total_dependencies(), 1);
    }

    #[test]
    fn read_after_write_dependency() {
        let mut graph = DependencyGraph::new();

        // tx0 writes A, tx1 reads A → tx1 depends on tx0.
        graph.insert(vec![pubkey(1)], vec![]); // tx0 writes A
        graph.insert(vec![], vec![pubkey(1)]); // tx1 reads A

        assert_eq!(graph.ready_count(), 1);
        assert_eq!(graph.state(1), DispatchState::Pending);
    }

    #[test]
    fn write_after_read_dependency() {
        let mut graph = DependencyGraph::new();

        // tx0 reads A, tx1 writes A → tx1 depends on tx0.
        graph.insert(vec![], vec![pubkey(1)]); // tx0 reads A
        graph.insert(vec![pubkey(1)], vec![]); // tx1 writes A

        assert_eq!(graph.ready_count(), 1);
        assert_eq!(graph.state(0), DispatchState::Ready);
        assert_eq!(graph.state(1), DispatchState::Pending);
    }

    #[test]
    fn read_read_no_dependency() {
        let mut graph = DependencyGraph::new();

        // tx0 reads A, tx1 reads A → no dependency (concurrent reads safe).
        graph.insert(vec![], vec![pubkey(1)]); // tx0 reads A
        graph.insert(vec![], vec![pubkey(1)]); // tx1 reads A

        assert_eq!(graph.ready_count(), 2);
        assert_eq!(graph.total_dependencies(), 0);
    }

    #[test]
    fn chain_dependency_propagation() {
        let mut graph = DependencyGraph::new();

        // tx0 → tx1 → tx2 chain via account A.
        graph.insert(vec![pubkey(1)], vec![]); // tx0
        graph.insert(vec![pubkey(1)], vec![]); // tx1 depends on tx0
        graph.insert(vec![pubkey(1)], vec![]); // tx2 depends on tx1

        assert_eq!(graph.ready_count(), 1); // only tx0
        assert_eq!(graph.state(0), DispatchState::Ready);
        assert_eq!(graph.state(1), DispatchState::Pending);
        assert_eq!(graph.state(2), DispatchState::Pending);

        // Dispatch and complete tx0.
        let idx = graph.next_ready(0).unwrap();
        assert_eq!(idx, 0);
        graph.complete(0);

        // tx1 should now be ready.
        assert_eq!(graph.ready_count(), 1);
        assert_eq!(graph.state(1), DispatchState::Ready);
        assert_eq!(graph.state(2), DispatchState::Pending);

        // Complete tx1 → tx2 ready.
        let idx = graph.next_ready(0).unwrap();
        assert_eq!(idx, 1);
        graph.complete(1);

        assert_eq!(graph.ready_count(), 1);
        assert_eq!(graph.state(2), DispatchState::Ready);
    }

    #[test]
    fn complex_diamond_dependency() {
        let mut graph = DependencyGraph::new();

        // Diamond: tx0 → {tx1, tx2} → tx3
        //
        // tx0 writes A and B
        // tx1 writes A (depends on tx0 via WAW)
        // tx2 writes B (depends on tx0 via WAW)
        // tx3 reads A and B (depends on tx1 and tx2 via RAW)
        graph.insert(vec![pubkey(1), pubkey(2)], vec![]); // tx0: write A,B
        graph.insert(vec![pubkey(1)], vec![]); // tx1: write A → depends tx0
        graph.insert(vec![pubkey(2)], vec![]); // tx2: write B → depends tx0
        graph.insert(vec![], vec![pubkey(1), pubkey(2)]); // tx3: read A,B → depends tx1,tx2

        assert_eq!(graph.ready_count(), 1); // only tx0
        assert_eq!(graph.total_dependencies(), 4); // tx1→tx0, tx2→tx0, tx3→tx1, tx3→tx2

        // Complete tx0 → tx1 and tx2 become ready.
        graph.next_ready(0).unwrap();
        graph.complete(0);
        assert_eq!(graph.ready_count(), 2);

        // Complete tx1 → tx3 still pending (depends on tx2).
        graph.next_ready(0).unwrap();
        graph.complete(1);
        assert_eq!(graph.state(3), DispatchState::Pending);

        // Complete tx2 → tx3 becomes ready.
        graph.next_ready(0).unwrap();
        graph.complete(2);
        assert_eq!(graph.ready_count(), 1);
        assert_eq!(graph.state(3), DispatchState::Ready);
    }

    #[test]
    fn empty_graph() {
        let graph = DependencyGraph::new();
        assert!(graph.is_empty());
        assert!(graph.all_completed());
        assert_eq!(graph.ready_count(), 0);
    }

    #[test]
    fn all_completed_check() {
        let mut graph = DependencyGraph::new();
        graph.insert(vec![pubkey(1)], vec![]);
        graph.insert(vec![pubkey(2)], vec![]);

        assert!(!graph.all_completed());

        graph.next_ready(0).unwrap();
        graph.next_ready(1).unwrap();
        graph.complete(0);
        graph.complete(1);

        assert!(graph.all_completed());
    }

    // --- TransactionDispatcher tests ---

    #[test]
    fn multi_lane_dispatch() {
        let mut dispatcher = TransactionDispatcher::new(2);

        // 4 independent transactions, 2 lanes.
        let txns = vec![
            (vec![pubkey(1)], vec![]),
            (vec![pubkey(2)], vec![]),
            (vec![pubkey(3)], vec![]),
            (vec![pubkey(4)], vec![]),
        ];
        dispatcher.load_transactions(txns);

        // First step: dispatch 2 transactions to 2 lanes.
        let (progress, dispatched) = dispatcher.dispatch_step();
        assert_eq!(dispatched.len(), 2);
        assert_eq!(progress.dispatched, 2);
        assert!(!progress.all_done);

        // Complete both.
        for (idx, _lane) in &dispatched {
            dispatcher.complete_transaction(*idx);
        }

        // Second step: dispatch remaining 2.
        let (progress, dispatched) = dispatcher.dispatch_step();
        assert_eq!(dispatched.len(), 2);
        assert!(!progress.all_done);

        // Complete both.
        for (idx, _lane) in &dispatched {
            dispatcher.complete_transaction(*idx);
        }

        // Third step: all done.
        let (progress, dispatched) = dispatcher.dispatch_step();
        assert!(dispatched.is_empty());
        assert!(progress.all_done);
        assert!(dispatcher.all_done());
    }

    #[test]
    fn dispatch_respects_dependencies() {
        let mut dispatcher = TransactionDispatcher::new(2);

        // tx0 writes A, tx1 writes A → tx1 must wait for tx0.
        let txns = vec![(vec![pubkey(1)], vec![]), (vec![pubkey(1)], vec![])];
        dispatcher.load_transactions(txns);

        // Only tx0 should be dispatched (tx1 depends on it).
        let (_, dispatched) = dispatcher.dispatch_step();
        assert_eq!(dispatched.len(), 1);
        assert_eq!(dispatched[0].0, 0);

        // Complete tx0 → tx1 becomes dispatchable.
        dispatcher.complete_transaction(0);
        let (_, dispatched) = dispatcher.dispatch_step();
        assert_eq!(dispatched.len(), 1);
        assert_eq!(dispatched[0].0, 1);

        dispatcher.complete_transaction(1);
        assert!(dispatcher.all_done());
    }

    #[test]
    fn single_lane_fallback() {
        let mut dispatcher = TransactionDispatcher::new(1);

        let txns = vec![
            (vec![pubkey(1)], vec![]),
            (vec![pubkey(2)], vec![]),
            (vec![pubkey(3)], vec![]),
        ];
        dispatcher.load_transactions(txns);

        // With 1 lane, only 1 at a time.
        let (_, dispatched) = dispatcher.dispatch_step();
        assert_eq!(dispatched.len(), 1);

        dispatcher.complete_transaction(dispatched[0].0);
        let (_, dispatched) = dispatcher.dispatch_step();
        assert_eq!(dispatched.len(), 1);

        dispatcher.complete_transaction(dispatched[0].0);
        let (_, dispatched) = dispatcher.dispatch_step();
        assert_eq!(dispatched.len(), 1);

        dispatcher.complete_transaction(dispatched[0].0);
        assert!(dispatcher.all_done());
    }

    #[test]
    fn empty_batch_dispatch() {
        let mut dispatcher = TransactionDispatcher::new(4);
        dispatcher.load_transactions(vec![]);

        let (progress, dispatched) = dispatcher.dispatch_step();
        assert!(dispatched.is_empty());
        assert!(progress.all_done);
    }

    #[test]
    fn idle_lane_count() {
        let mut dispatcher = TransactionDispatcher::new(4);

        let txns = vec![(vec![pubkey(1)], vec![]), (vec![pubkey(2)], vec![])];
        dispatcher.load_transactions(txns);
        assert_eq!(dispatcher.idle_lane_count(), 4);

        dispatcher.dispatch_step();
        assert_eq!(dispatcher.idle_lane_count(), 2); // 2 lanes busy

        dispatcher.complete_transaction(0);
        assert_eq!(dispatcher.idle_lane_count(), 3);

        dispatcher.complete_transaction(1);
        assert_eq!(dispatcher.idle_lane_count(), 4);
    }

    #[test]
    fn stats_tracking() {
        let mut dispatcher = TransactionDispatcher::new(2);

        let txns = vec![
            (vec![pubkey(1)], vec![]),
            (vec![pubkey(1)], vec![]), // depends on tx0
            (vec![pubkey(2)], vec![]), // independent
        ];
        dispatcher.load_transactions(txns);

        assert_eq!(dispatcher.stats().total_transactions, 3);
        assert_eq!(dispatcher.stats().total_dependencies, 1);

        dispatcher.dispatch_step();
        assert_eq!(dispatcher.stats().dispatch_steps, 1);
    }

    #[test]
    fn mixed_read_write_dependencies() {
        let mut graph = DependencyGraph::new();

        // tx0: write A
        // tx1: read A, write B (depends on tx0 via RAW on A)
        // tx2: read A, read B (depends on tx0 via RAW on A, tx1 via RAW on B)
        // tx3: write C (independent!)
        graph.insert(vec![pubkey(1)], vec![]); // tx0: write A
        graph.insert(vec![pubkey(2)], vec![pubkey(1)]); // tx1: write B, read A
        graph.insert(vec![], vec![pubkey(1), pubkey(2)]); // tx2: read A, B
        graph.insert(vec![pubkey(3)], vec![]); // tx3: write C (independent)

        // tx0 and tx3 should be ready.
        assert_eq!(graph.ready_count(), 2);

        // Complete tx0 → tx1 becomes ready.
        graph.next_ready(0);
        graph.complete(0);
        // tx3 was already ready, tx1 just became ready.
        // tx2 still depends on tx1.
        assert_eq!(graph.ready_count(), 2); // tx1 + tx3

        // Dispatch and complete tx3 (independent).
        let idx = graph.next_ready(1).unwrap();
        assert_eq!(idx, 3);
        graph.complete(3);

        // Dispatch and complete tx1 → tx2 should become ready.
        let idx = graph.next_ready(0).unwrap();
        assert_eq!(idx, 1);
        graph.complete(1);

        assert_eq!(graph.ready_count(), 1);
        assert_eq!(graph.state(2), DispatchState::Ready);
    }

    #[test]
    fn reset_clears_state() {
        let mut dispatcher = TransactionDispatcher::new(2);

        let txns = vec![(vec![pubkey(1)], vec![]), (vec![pubkey(2)], vec![])];
        dispatcher.load_transactions(txns);
        dispatcher.dispatch_step();
        dispatcher.complete_transaction(0);
        dispatcher.complete_transaction(1);

        assert!(dispatcher.all_done());

        dispatcher.reset();
        assert_eq!(dispatcher.transaction_count(), 0);
        assert_eq!(dispatcher.idle_lane_count(), 2);
    }

    #[test]
    fn war_multiple_readers() {
        let mut graph = DependencyGraph::new();

        // tx0: read A
        // tx1: read A
        // tx2: write A (depends on BOTH tx0 and tx1 via WAR)
        graph.insert(vec![], vec![pubkey(1)]); // tx0: read A
        graph.insert(vec![], vec![pubkey(1)]); // tx1: read A
        graph.insert(vec![pubkey(1)], vec![]); // tx2: write A

        // tx0 and tx1 are ready (read-read is fine).
        assert_eq!(graph.ready_count(), 2);
        // tx2 depends on both readers.
        assert_eq!(graph.state(2), DispatchState::Pending);
        assert_eq!(graph.total_dependencies(), 2);

        // Complete tx0 → tx2 still pending (depends on tx1).
        graph.next_ready(0);
        graph.complete(0);
        assert_eq!(graph.state(2), DispatchState::Pending);

        // Complete tx1 → tx2 ready.
        graph.next_ready(0);
        graph.complete(1);
        assert_eq!(graph.state(2), DispatchState::Ready);
    }
}
