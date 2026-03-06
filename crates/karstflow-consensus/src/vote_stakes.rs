/// Fork-aware vote stake tracking across epoch boundaries.
///
/// Maintains per-vote-account T-1 and T-2 stake snapshots that can diverge
/// across forks near epoch boundaries. Uses a shared index with reference
/// counting so that identical stake entries are stored once even when
/// multiple forks reference them.
///
/// Design follows the reference multi-fork vote stakes structure:
/// - Shared index: maps (pubkey, node_account_t1, stake_t1, epoch_parity)
///   to a refcounted entry that also stores T-2 data.
/// - Per-fork stake sets: each fork maintains a set of index entry IDs
///   representing its view of vote account stakes.
/// - Root advancement: when the root fork changes, non-root forks are
///   released and their refcounts decremented.
use karstflow_types::Pubkey;
use std::collections::{HashMap, HashSet, VecDeque};

/// Unique identifier for an index entry.
type IndexId = u64;

/// Unique identifier for a fork.
pub type ForkId = u16;

/// A shared vote stake index entry.
#[derive(Debug, Clone)]
struct IndexEntry {
    pubkey: Pubkey,
    node_account_t1: Pubkey,
    node_account_t2: Pubkey,
    stake_t1: u64,
    stake_t2: u64,
    /// Epoch parity (0 or 1) to distinguish entries across epoch boundaries.
    epoch_parity: u8,
    /// Number of forks referencing this entry.
    refcount: u32,
}

/// Per-fork view: set of index entry IDs.
#[derive(Debug, Clone, Default)]
struct ForkStakes {
    /// Index entry IDs in this fork.
    entries: HashSet<IndexId>,
    /// Mapping from vote pubkey to index ID for fast lookup.
    pubkey_to_id: HashMap<Pubkey, IndexId>,
}

/// Fork-aware vote stakes tracker.
///
/// Tracks T-1 and T-2 stakes per vote account across multiple forks.
/// Concurrent reads are safe; concurrent writes are not.
#[derive(Debug)]
pub struct VoteStakes {
    /// Shared index: ID -> entry.
    index: HashMap<IndexId, IndexEntry>,
    /// Next available index ID.
    next_id: IndexId,
    /// Per-fork stake views.
    forks: HashMap<ForkId, ForkStakes>,
    /// Active fork IDs in order (root is first).
    fork_order: VecDeque<ForkId>,
    /// Next available fork ID.
    next_fork_id: ForkId,
    /// Root fork ID.
    root_id: ForkId,
}

/// Result of a vote stake query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteStakeEntry {
    pub pubkey: Pubkey,
    pub node_account_t1: Pubkey,
    pub node_account_t2: Pubkey,
    pub stake_t1: u64,
    pub stake_t2: u64,
}

impl VoteStakes {
    /// Create a new vote stakes tracker.
    pub fn new() -> Self {
        let root_id: ForkId = 0;
        let mut forks = HashMap::new();
        forks.insert(root_id, ForkStakes::default());
        let mut fork_order = VecDeque::new();
        fork_order.push_back(root_id);

        Self {
            index: HashMap::new(),
            next_id: 0,
            forks,
            fork_order,
            next_fork_id: 1,
            root_id,
        }
    }

    /// Get the root fork ID.
    pub fn root_id(&self) -> ForkId {
        self.root_id
    }

    /// Insert a T-1 key into the root fork (used during snapshot loading).
    ///
    /// Creates a new index entry with the given T-1 stake and adds it
    /// to the root fork. T-2 data is left zeroed until `root_update_meta`
    /// is called.
    pub fn root_insert_key(
        &mut self,
        pubkey: Pubkey,
        node_account_t1: Pubkey,
        stake_t1: u64,
        epoch: u64,
    ) {
        let id = self.alloc_id();
        let entry = IndexEntry {
            pubkey,
            node_account_t1,
            node_account_t2: Pubkey::default(),
            stake_t1,
            stake_t2: 0,
            epoch_parity: (epoch % 2) as u8,
            refcount: 1,
        };
        self.index.insert(id, entry);

        let root = self.forks.get_mut(&self.root_id).expect("root fork exists");
        root.entries.insert(id);
        root.pubkey_to_id.insert(pubkey, id);
    }

    /// Update T-2 metadata for a key in the root fork.
    ///
    /// If the pubkey doesn't exist yet, creates a new entry with zero T-1 stake.
    pub fn root_update_meta(
        &mut self,
        pubkey: Pubkey,
        node_account_t2: Pubkey,
        stake_t2: u64,
        epoch: u64,
    ) {
        let root_id = self.root_id;
        let root = self.forks.get(&root_id).expect("root fork exists");

        if let Some(&id) = root.pubkey_to_id.get(&pubkey) {
            // Entry exists — update T-2 data.
            let entry = self.index.get_mut(&id).expect("index entry exists");
            entry.node_account_t2 = node_account_t2;
            entry.stake_t2 = stake_t2;
        } else {
            // Create new entry with T-1 = 0.
            let id = self.alloc_id();
            let entry = IndexEntry {
                pubkey,
                node_account_t1: Pubkey::default(),
                node_account_t2,
                stake_t1: 0,
                stake_t2,
                epoch_parity: (epoch % 2) as u8,
                refcount: 1,
            };
            self.index.insert(id, entry);

            let root = self.forks.get_mut(&root_id).expect("root fork exists");
            root.entries.insert(id);
            root.pubkey_to_id.insert(pubkey, id);
        }
    }

    /// Purge a key from the root fork.
    pub fn root_purge_key(&mut self, pubkey: &Pubkey) {
        let root_id = self.root_id;
        let root = self.forks.get_mut(&root_id).expect("root fork exists");

        if let Some(id) = root.pubkey_to_id.remove(pubkey) {
            root.entries.remove(&id);
            self.release_ref(id);
        }
    }

    /// Create a new child fork. Returns the fork ID.
    pub fn new_child(&mut self) -> ForkId {
        let id = self.next_fork_id;
        self.next_fork_id = self.next_fork_id.checked_add(1).expect("fork ID overflow");
        self.forks.insert(id, ForkStakes::default());
        self.fork_order.push_back(id);
        id
    }

    /// Insert a vote account key into a non-root fork (epoch boundary).
    ///
    /// Creates a new index entry with T-1 stake initialized to 0.
    /// Call `insert_update` to accumulate T-1 stake from delegations,
    /// then `insert_fini` to deduplicate.
    pub fn insert_key(
        &mut self,
        fork_id: ForkId,
        pubkey: Pubkey,
        node_account_t1: Pubkey,
        node_account_t2: Pubkey,
        stake_t2: u64,
        epoch: u64,
    ) {
        let id = self.alloc_id();
        let entry = IndexEntry {
            pubkey,
            node_account_t1,
            node_account_t2,
            stake_t1: 0,
            stake_t2,
            epoch_parity: (epoch % 2) as u8,
            refcount: 1,
        };
        self.index.insert(id, entry);

        let fork = self.forks.get_mut(&fork_id).expect("fork exists");
        fork.entries.insert(id);
        fork.pubkey_to_id.insert(pubkey, id);
    }

    /// Accumulate T-1 stake for a vote account on a fork.
    ///
    /// Adds `stake` to the existing T-1 value for the given pubkey on
    /// the given fork.
    pub fn insert_update(&mut self, fork_id: ForkId, pubkey: &Pubkey, stake: u64) {
        let fork = self.forks.get(&fork_id).expect("fork exists");
        let &id = fork
            .pubkey_to_id
            .get(pubkey)
            .expect("pubkey exists in fork");
        let entry = self.index.get_mut(&id).expect("index entry exists");
        entry.stake_t1 = entry.stake_t1.saturating_add(stake);
    }

    /// Finalize inserts for a fork: deduplicate entries against the shared index.
    ///
    /// If an entry with identical (pubkey, node_account_t1, stake_t1, epoch_parity)
    /// already exists in another fork, the new entry is merged (refcount incremented)
    /// and the duplicate is released.
    pub fn insert_fini(&mut self, fork_id: ForkId) {
        let fork = self.forks.get(&fork_id).expect("fork exists");
        let ids: Vec<IndexId> = fork.entries.iter().copied().collect();

        for id in ids {
            let entry = self.index.get(&id).expect("entry exists");
            // Look for a matching entry by compound key.
            let matching = self.find_matching_entry(id, entry);
            if let Some(existing_id) = matching {
                // Merge: bump refcount on existing, release new.
                self.index.get_mut(&existing_id).unwrap().refcount += 1;
                // Update fork's mapping to point to existing entry.
                let fork = self.forks.get_mut(&fork_id).unwrap();
                let pubkey = self.index.get(&id).unwrap().pubkey;
                fork.entries.remove(&id);
                fork.entries.insert(existing_id);
                fork.pubkey_to_id.insert(pubkey, existing_id);
                // Release the duplicate.
                self.index.remove(&id);
            }
            // If no match, the entry is already in the index (new unique entry).
        }
    }

    /// Finalize genesis: copy T-1 data to T-2 for all entries.
    pub fn genesis_fini(&mut self) {
        for entry in self.index.values_mut() {
            entry.node_account_t2 = entry.node_account_t1;
            entry.stake_t2 = entry.stake_t1;
        }
    }

    /// Advance the root to a new fork, releasing all other forks.
    pub fn advance_root(&mut self, new_root: ForkId) {
        if new_root == self.root_id {
            return;
        }

        // Collect forks to remove.
        let to_remove: Vec<ForkId> = self
            .fork_order
            .iter()
            .copied()
            .filter(|&id| id != new_root)
            .collect();

        for fork_id in to_remove {
            if let Some(fork) = self.forks.remove(&fork_id) {
                for id in &fork.entries {
                    self.release_ref(*id);
                }
            }
        }

        self.fork_order.retain(|&id| id == new_root);
        self.root_id = new_root;
    }

    /// Query the stake for a vote account on a specific fork.
    pub fn query(&self, fork_id: ForkId, pubkey: &Pubkey) -> Option<VoteStakeEntry> {
        let fork = self.forks.get(&fork_id)?;
        let &id = fork.pubkey_to_id.get(pubkey)?;
        let entry = self.index.get(&id)?;
        Some(VoteStakeEntry {
            pubkey: entry.pubkey,
            node_account_t1: entry.node_account_t1,
            node_account_t2: entry.node_account_t2,
            stake_t1: entry.stake_t1,
            stake_t2: entry.stake_t2,
        })
    }

    /// Number of vote accounts on a fork.
    pub fn fork_len(&self, fork_id: ForkId) -> usize {
        self.forks.get(&fork_id).map_or(0, |f| f.entries.len())
    }

    /// Iterate over all vote stake entries on a fork.
    pub fn fork_iter(&self, fork_id: ForkId) -> impl Iterator<Item = VoteStakeEntry> + '_ {
        self.forks
            .get(&fork_id)
            .into_iter()
            .flat_map(move |fork| {
                fork.entries.iter().filter_map(move |id| {
                    self.index.get(id).map(|e| VoteStakeEntry {
                        pubkey: e.pubkey,
                        node_account_t1: e.node_account_t1,
                        node_account_t2: e.node_account_t2,
                        stake_t1: e.stake_t1,
                        stake_t2: e.stake_t2,
                    })
                })
            })
    }

    /// Reset the entire structure to initial state.
    pub fn reset(&mut self) {
        self.index.clear();
        self.next_id = 0;
        self.forks.clear();
        self.fork_order.clear();
        self.next_fork_id = 1;
        self.root_id = 0;
        self.forks.insert(0, ForkStakes::default());
        self.fork_order.push_back(0);
    }

    /// Allocate a new index entry ID.
    fn alloc_id(&mut self) -> IndexId {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Decrement refcount; remove entry if zero.
    fn release_ref(&mut self, id: IndexId) {
        if let Some(entry) = self.index.get_mut(&id) {
            entry.refcount = entry.refcount.saturating_sub(1);
            if entry.refcount == 0 {
                self.index.remove(&id);
            }
        }
    }

    /// Find an existing index entry that matches the compound key of the given entry.
    /// Returns `Some(existing_id)` if found, `None` otherwise.
    /// Does NOT match the entry with itself.
    fn find_matching_entry(&self, exclude_id: IndexId, entry: &IndexEntry) -> Option<IndexId> {
        for (&id, existing) in &self.index {
            if id == exclude_id {
                continue;
            }
            if existing.pubkey == entry.pubkey
                && existing.node_account_t1 == entry.node_account_t1
                && existing.stake_t1 == entry.stake_t1
                && existing.epoch_parity == entry.epoch_parity
            {
                return Some(id);
            }
        }
        None
    }
}

impl Default for VoteStakes {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(seed: u8) -> Pubkey {
        Pubkey::new([seed; 32])
    }

    #[test]
    fn root_insert_and_query() {
        let mut vs = VoteStakes::new();
        let root = vs.root_id();

        vs.root_insert_key(pk(1), pk(11), 1000, 5);
        vs.root_update_meta(pk(1), pk(21), 800, 5);

        let entry = vs.query(root, &pk(1)).unwrap();
        assert_eq!(entry.stake_t1, 1000);
        assert_eq!(entry.stake_t2, 800);
        assert_eq!(entry.node_account_t1, pk(11));
        assert_eq!(entry.node_account_t2, pk(21));
    }

    #[test]
    fn root_update_meta_creates_if_missing() {
        let mut vs = VoteStakes::new();
        let root = vs.root_id();

        vs.root_update_meta(pk(1), pk(21), 500, 3);

        let entry = vs.query(root, &pk(1)).unwrap();
        assert_eq!(entry.stake_t1, 0);
        assert_eq!(entry.stake_t2, 500);
    }

    #[test]
    fn root_purge_key() {
        let mut vs = VoteStakes::new();
        let root = vs.root_id();

        vs.root_insert_key(pk(1), pk(11), 1000, 0);
        assert!(vs.query(root, &pk(1)).is_some());

        vs.root_purge_key(&pk(1));
        assert!(vs.query(root, &pk(1)).is_none());
    }

    #[test]
    fn child_fork_insert_and_query() {
        let mut vs = VoteStakes::new();
        let child = vs.new_child();

        vs.insert_key(child, pk(1), pk(11), pk(21), 800, 5);
        vs.insert_update(child, &pk(1), 300);
        vs.insert_update(child, &pk(1), 700);
        vs.insert_fini(child);

        let entry = vs.query(child, &pk(1)).unwrap();
        assert_eq!(entry.stake_t1, 1000);
        assert_eq!(entry.stake_t2, 800);
    }

    #[test]
    fn genesis_fini_copies_t1_to_t2() {
        let mut vs = VoteStakes::new();
        let root = vs.root_id();

        vs.root_insert_key(pk(1), pk(11), 1000, 0);
        vs.genesis_fini();

        let entry = vs.query(root, &pk(1)).unwrap();
        assert_eq!(entry.stake_t1, 1000);
        assert_eq!(entry.stake_t2, 1000);
        assert_eq!(entry.node_account_t2, pk(11));
    }

    #[test]
    fn advance_root_removes_other_forks() {
        let mut vs = VoteStakes::new();
        let root = vs.root_id();

        vs.root_insert_key(pk(1), pk(11), 1000, 0);

        let child = vs.new_child();
        vs.insert_key(child, pk(2), pk(12), pk(22), 500, 1);
        vs.insert_fini(child);

        // Both forks have their own entries.
        assert!(vs.query(root, &pk(1)).is_some());
        assert!(vs.query(child, &pk(2)).is_some());

        // Advance root to child.
        vs.advance_root(child);
        assert_eq!(vs.root_id(), child);

        // Old root is gone.
        assert!(vs.query(root, &pk(1)).is_none());

        // Child data persists.
        assert!(vs.query(child, &pk(2)).is_some());
    }

    #[test]
    fn advance_root_noop_when_same() {
        let mut vs = VoteStakes::new();
        let root = vs.root_id();
        vs.root_insert_key(pk(1), pk(11), 1000, 0);

        vs.advance_root(root);
        assert!(vs.query(root, &pk(1)).is_some());
    }

    #[test]
    fn shared_entries_deduplicated() {
        let mut vs = VoteStakes::new();
        let root = vs.root_id();

        // Insert entry in root.
        vs.root_insert_key(pk(1), pk(11), 1000, 0);

        // Insert same compound key in child.
        let child = vs.new_child();
        vs.insert_key(child, pk(1), pk(11), pk(21), 500, 0);
        vs.insert_update(child, &pk(1), 1000); // matches root's T-1
        vs.insert_fini(child);

        // Both forks should be queryable.
        assert!(vs.query(root, &pk(1)).is_some());
        assert!(vs.query(child, &pk(1)).is_some());

        // The shared index should have deduplicated (only 1 entry with refcount 2).
        let entry_count = vs.index.len();
        assert_eq!(entry_count, 1);
        let entry = vs.index.values().next().unwrap();
        assert_eq!(entry.refcount, 2);
    }

    #[test]
    fn fork_len_and_iter() {
        let mut vs = VoteStakes::new();
        let root = vs.root_id();

        vs.root_insert_key(pk(1), pk(11), 1000, 0);
        vs.root_insert_key(pk(2), pk(12), 2000, 0);

        assert_eq!(vs.fork_len(root), 2);

        let mut stakes: Vec<u64> = vs.fork_iter(root).map(|e| e.stake_t1).collect();
        stakes.sort();
        assert_eq!(stakes, vec![1000, 2000]);
    }

    #[test]
    fn reset_clears_all() {
        let mut vs = VoteStakes::new();

        vs.root_insert_key(pk(1), pk(11), 1000, 0);
        let child = vs.new_child();
        vs.insert_key(child, pk(2), pk(12), pk(22), 500, 1);
        vs.insert_fini(child);

        vs.reset();

        assert_eq!(vs.fork_len(vs.root_id()), 0);
        assert!(vs.index.is_empty());
    }

    #[test]
    fn multiple_children_independent() {
        let mut vs = VoteStakes::new();

        let c1 = vs.new_child();
        let c2 = vs.new_child();

        vs.insert_key(c1, pk(1), pk(11), pk(21), 100, 0);
        vs.insert_update(c1, &pk(1), 500);
        vs.insert_fini(c1);

        vs.insert_key(c2, pk(1), pk(11), pk(21), 100, 0);
        vs.insert_update(c2, &pk(1), 700);
        vs.insert_fini(c2);

        let e1 = vs.query(c1, &pk(1)).unwrap();
        let e2 = vs.query(c2, &pk(1)).unwrap();

        assert_eq!(e1.stake_t1, 500);
        assert_eq!(e2.stake_t1, 700);
    }
}
