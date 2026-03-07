/// Repair forest: tracks slot ancestry, shred completion, and generates repair
/// requests.
///
/// The forest maintains four disjoint sets of slots:
///   - **ancestry**: connected slots with known parent chains back to root
///   - **frontier**: leaf slots in ancestry that still need shreds
///   - **orphaned**: slots whose parents are not yet in any set
///   - **subtrees**: root nodes of disconnected trees (parent unknown)
///
/// As shreds arrive and slots connect, elements promote between sets.
/// The forest generates repair requests by iterating frontier and orphan
/// slots in BFS order.
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use super::{ShredIndex, Slot};

/// Tracks shred completion state for a single slot.
#[derive(Debug, Clone)]
pub struct SlotRepairState {
    /// Slot number.
    pub slot: Slot,
    /// Parent slot (0 for genesis or unknown).
    pub parent_slot: Slot,
    /// Highest contiguous received shred index (no gaps from 0..=consumed).
    pub consumed_idx: Option<ShredIndex>,
    /// Highest received shred index (may have gaps below).
    pub buffered_idx: Option<ShredIndex>,
    /// Last shred index in slot (set when slot-complete flag seen).
    pub complete_idx: Option<ShredIndex>,
    /// Bitset of received data shred indices.
    received: ShredBitset,
    /// Bitset of FEC sets known (keyed by first shred of FEC set).
    fec_sets: HashSet<ShredIndex>,
    /// Bitset of FEC sets completed (all shreds recovered).
    fec_completed: HashSet<ShredIndex>,
    /// Whether this slot has been confirmed (>=52% stake duplicate-confirmed).
    pub confirmed: bool,
    /// Shreds received via turbine.
    pub turbine_count: u32,
    /// Shreds received via repair.
    pub repair_count: u32,
    /// Shreds recovered via FEC.
    pub recovered_count: u32,
    /// Timestamp when first shred was received (ms since epoch).
    pub first_shred_time: Option<u64>,
    /// Timestamp when first repair request was sent.
    pub first_request_time: Option<u64>,
}

impl SlotRepairState {
    pub fn new(slot: Slot, parent_slot: Slot) -> Self {
        Self {
            slot,
            parent_slot,
            consumed_idx: None,
            buffered_idx: None,
            complete_idx: None,
            received: ShredBitset::new(),
            fec_sets: HashSet::new(),
            fec_completed: HashSet::new(),
            confirmed: false,
            turbine_count: 0,
            repair_count: 0,
            recovered_count: 0,
            first_shred_time: None,
            first_request_time: None,
        }
    }

    /// Record a received data shred. Returns true if this was new.
    pub fn insert_shred(&mut self, index: ShredIndex, source: ShredSource) -> bool {
        let was_new = self.received.insert(index);
        if !was_new {
            return false;
        }

        // Update buffered_idx (highest received).
        match self.buffered_idx {
            Some(current) if index > current => self.buffered_idx = Some(index),
            None => self.buffered_idx = Some(index),
            _ => {}
        }

        // Advance consumed_idx (highest contiguous from 0).
        self.advance_consumed();

        match source {
            ShredSource::Turbine => self.turbine_count += 1,
            ShredSource::Repair => self.repair_count += 1,
            ShredSource::Recovered => self.recovered_count += 1,
        }

        true
    }

    /// Mark the slot as having a known last shred index.
    pub fn set_complete_idx(&mut self, index: ShredIndex) {
        self.complete_idx = Some(index);
    }

    /// Register a FEC set starting at the given shred index.
    pub fn register_fec_set(&mut self, first_shred: ShredIndex) {
        self.fec_sets.insert(first_shred);
    }

    /// Mark a FEC set as completed (all data shreds recovered).
    pub fn complete_fec_set(&mut self, first_shred: ShredIndex) {
        self.fec_completed.insert(first_shred);
    }

    /// True when all shreds have been received and all FEC sets completed.
    pub fn is_complete(&self) -> bool {
        let Some(complete) = self.complete_idx else {
            return false;
        };
        let Some(consumed) = self.consumed_idx else {
            return false;
        };
        if consumed < complete {
            return false;
        }
        // All known FEC sets must be completed.
        self.fec_sets.is_subset(&self.fec_completed)
    }

    /// Returns shred indices that are missing (gaps in received set).
    /// Only returns indices up to buffered_idx or complete_idx.
    pub fn missing_shreds(&self, max_count: usize) -> Vec<ShredIndex> {
        let upper = match (self.complete_idx, self.buffered_idx) {
            (Some(c), Some(b)) => c.max(b),
            (Some(c), None) => c,
            (None, Some(b)) => b,
            (None, None) => return vec![],
        };

        let mut missing = Vec::new();
        for idx in 0..=upper {
            if !self.received.contains(idx) {
                missing.push(idx);
                if missing.len() >= max_count {
                    break;
                }
            }
        }
        missing
    }

    /// Whether the complete_idx is known.
    pub fn knows_slot_length(&self) -> bool {
        self.complete_idx.is_some()
    }

    /// Total shreds received.
    pub fn total_received(&self) -> u32 {
        self.received.count()
    }

    /// Advance consumed_idx to the highest contiguous index from 0.
    fn advance_consumed(&mut self) {
        let start = match self.consumed_idx {
            Some(c) => c + 1,
            None => 0,
        };

        let mut idx = start;
        while self.received.contains(idx) {
            idx += 1;
        }

        if idx > start {
            self.consumed_idx = Some(idx - 1);
        } else if start == 0 && self.received.contains(0) {
            self.consumed_idx = Some(0);
        }
    }
}

/// Source of a received shred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShredSource {
    /// Received via turbine broadcast.
    Turbine,
    /// Received via repair request.
    Repair,
    /// Recovered via FEC decoding.
    Recovered,
}

/// Compact bitset for tracking shred indices within a slot.
/// Uses a HashMap for sparse slots, bitvec for dense.
#[derive(Debug, Clone)]
struct ShredBitset {
    /// Sparse storage for received indices.
    bits: HashSet<ShredIndex>,
}

impl ShredBitset {
    fn new() -> Self {
        Self {
            bits: HashSet::new(),
        }
    }

    fn insert(&mut self, index: ShredIndex) -> bool {
        self.bits.insert(index)
    }

    fn contains(&self, index: ShredIndex) -> bool {
        self.bits.contains(&index)
    }

    fn count(&self) -> u32 {
        self.bits.len() as u32
    }
}

/// Which set a slot belongs to in the forest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotCategory {
    /// Connected to root with known parent chain.
    Ancestry,
    /// Leaf of ancestry tree, still needs shreds.
    Frontier,
    /// Parent not yet in any set.
    Orphaned,
    /// Root of a disconnected subtree.
    Subtree,
}

/// A repair request generated by the forest iterator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepairTarget {
    /// Request a specific shred by slot and index.
    Shred { slot: Slot, index: ShredIndex },
    /// Request the highest available shred for a slot (complete_idx unknown).
    HighestShred { slot: Slot },
    /// Request ancestor chain for an orphaned slot.
    Orphan { slot: Slot },
}

/// The repair forest.
///
/// Tracks slot state across four disjoint categories and generates repair
/// requests in BFS order. Slots promote from orphaned → frontier → ancestry
/// as their parents become known and connected.
pub struct RepairForest {
    /// All slot states keyed by slot number.
    slots: HashMap<Slot, SlotRepairState>,
    /// Category membership for each slot.
    categories: HashMap<Slot, SlotCategory>,
    /// Connected slots with completed parent chains.
    ancestry: HashSet<Slot>,
    /// Leaf slots needing shreds (repair targets).
    frontier: HashSet<Slot>,
    /// Slots with unknown parents.
    orphaned: HashSet<Slot>,
    /// Root nodes of disconnected subtrees.
    subtrees: HashSet<Slot>,
    /// Parent → children mapping for tree traversal.
    children: HashMap<Slot, Vec<Slot>>,
    /// Current root slot.
    root_slot: Slot,
    /// Maximum slots to track.
    max_slots: usize,
    /// BFS queue for generating repair requests from frontier.
    repair_queue: VecDeque<Slot>,
    /// BFS queue for orphan repair requests.
    orphan_queue: VecDeque<Slot>,
    /// Completed slots (all shreds received, ready for advancement).
    completed: BTreeMap<Slot, ()>,
}

impl RepairForest {
    /// Create a new repair forest rooted at the given slot.
    pub fn new(root_slot: Slot) -> Self {
        Self {
            slots: HashMap::new(),
            categories: HashMap::new(),
            ancestry: HashSet::new(),
            frontier: HashSet::new(),
            orphaned: HashSet::new(),
            subtrees: HashSet::new(),
            children: HashMap::new(),
            root_slot,
            max_slots: karstflow_constants::repair::MAX_FOREST_SLOTS,
            repair_queue: VecDeque::new(),
            orphan_queue: VecDeque::new(),
            completed: BTreeMap::new(),
        }
    }

    /// Create with custom capacity.
    pub fn with_capacity(root_slot: Slot, max_slots: usize) -> Self {
        let mut forest = Self::new(root_slot);
        forest.max_slots = max_slots;
        forest
    }

    /// Current root slot.
    pub fn root(&self) -> Slot {
        self.root_slot
    }

    /// Number of tracked slots.
    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }

    /// Get repair state for a slot.
    pub fn get_slot(&self, slot: Slot) -> Option<&SlotRepairState> {
        self.slots.get(&slot)
    }

    /// Get mutable repair state for a slot.
    pub fn get_slot_mut(&mut self, slot: Slot) -> Option<&mut SlotRepairState> {
        self.slots.get_mut(&slot)
    }

    /// Which category a slot belongs to.
    pub fn slot_category(&self, slot: Slot) -> Option<SlotCategory> {
        self.categories.get(&slot).copied()
    }

    /// Insert or update a slot in the forest.
    ///
    /// Determines the correct category based on parent connectivity:
    /// - Parent in ancestry → slot goes to frontier
    /// - Parent in frontier → parent promoted to ancestry, slot to frontier
    /// - Parent in orphaned/subtrees → slot goes to orphaned
    /// - Parent unknown → slot goes to subtrees
    ///
    /// Also checks if any existing subtrees have this slot as parent and
    /// promotes them accordingly.
    pub fn insert_slot(&mut self, slot: Slot, parent_slot: Slot) -> InsertOutcome {
        // Don't track slots below root.
        if slot < self.root_slot {
            return InsertOutcome::BelowRoot;
        }

        // Capacity check — try eviction if full.
        let mut evicted_slot = None;
        if !self.slots.contains_key(&slot) && self.slots.len() >= self.max_slots {
            match self.find_eviction_candidate(parent_slot) {
                Some(victim) => {
                    self.remove_slot(victim);
                    evicted_slot = Some(victim);
                }
                None => return InsertOutcome::Full,
            }
        }

        // Create or update slot state.
        let state = self
            .slots
            .entry(slot)
            .or_insert_with(|| SlotRepairState::new(slot, parent_slot));
        state.parent_slot = parent_slot;

        // Already categorized — update parent reference but don't re-categorize.
        if self.categories.contains_key(&slot) {
            return InsertOutcome::Updated;
        }

        // Determine category based on parent location.
        let category = if slot == self.root_slot {
            SlotCategory::Ancestry
        } else if self.ancestry.contains(&parent_slot) {
            // Parent fully connected → this is a new frontier leaf.
            SlotCategory::Frontier
        } else if self.frontier.contains(&parent_slot) {
            // Parent was frontier → promote parent to ancestry, this becomes frontier.
            self.promote_to_ancestry(parent_slot);
            SlotCategory::Frontier
        } else if self.orphaned.contains(&parent_slot) || self.subtrees.contains(&parent_slot) {
            SlotCategory::Orphaned
        } else {
            // Parent completely unknown → new disconnected subtree.
            SlotCategory::Subtree
        };

        self.place_in_category(slot, category);
        self.children.entry(parent_slot).or_default().push(slot);

        // Check if any subtrees are children of this newly inserted slot.
        self.try_connect_subtrees(slot);

        // Add to appropriate repair queue.
        match category {
            SlotCategory::Frontier => self.repair_queue.push_back(slot),
            SlotCategory::Subtree => self.orphan_queue.push_back(slot),
            _ => {}
        }

        match evicted_slot {
            Some(victim) => InsertOutcome::Evicted {
                evicted_slot: victim,
            },
            None => InsertOutcome::Inserted(category),
        }
    }

    /// Record a received shred for a slot.
    ///
    /// If the slot doesn't exist in the forest, it's created with
    /// `parent_slot = 0` (will be updated when parent info arrives).
    pub fn receive_shred(
        &mut self,
        slot: Slot,
        index: ShredIndex,
        source: ShredSource,
        is_last_in_slot: bool,
        parent_slot: Option<Slot>,
    ) -> bool {
        if slot < self.root_slot {
            return false;
        }

        // Ensure slot exists.
        let parent = parent_slot.unwrap_or(0);
        if !self.slots.contains_key(&slot) {
            self.insert_slot(slot, parent);
        }

        let state = match self.slots.get_mut(&slot) {
            Some(s) => s,
            None => return false,
        };

        if state.first_shred_time.is_none() {
            state.first_shred_time = Some(current_time_ms());
        }

        let was_new = state.insert_shred(index, source);

        if is_last_in_slot {
            state.set_complete_idx(index);
        }

        // Check if slot just became complete.
        if was_new && state.is_complete() {
            self.completed.insert(slot, ());
        }

        was_new
    }

    /// Mark a FEC set as completed for a slot, inserting recovered shred
    /// indices.
    pub fn complete_fec_set(
        &mut self,
        slot: Slot,
        fec_start: ShredIndex,
        recovered_indices: &[ShredIndex],
    ) {
        if let Some(state) = self.slots.get_mut(&slot) {
            state.complete_fec_set(fec_start);
            for &idx in recovered_indices {
                state.insert_shred(idx, ShredSource::Recovered);
            }
            if state.is_complete() {
                self.completed.insert(slot, ());
            }
        }
    }

    /// Generate the next batch of repair requests.
    ///
    /// Returns up to `max_requests` targets, alternating between frontier
    /// (shred/highest) and orphan requests.
    pub fn next_repairs(&mut self, max_requests: usize) -> Vec<RepairTarget> {
        let mut targets = Vec::with_capacity(max_requests);

        // Generate frontier repair requests.
        let mut visited = 0;
        let queue_len = self.repair_queue.len();
        while targets.len() < max_requests && visited < queue_len {
            let Some(slot) = self.repair_queue.pop_front() else {
                break;
            };
            visited += 1;

            let needs_repair = self.generate_slot_repairs(slot, max_requests - targets.len());
            if !needs_repair.is_empty() {
                // Re-queue if slot still needs repair.
                self.repair_queue.push_back(slot);
            }
            targets.extend(needs_repair);
        }

        // Generate orphan repair requests (up to remaining capacity).
        let orphan_visited_max = self.orphan_queue.len();
        let mut orphan_visited = 0;
        while targets.len() < max_requests && orphan_visited < orphan_visited_max {
            let Some(slot) = self.orphan_queue.pop_front() else {
                break;
            };
            orphan_visited += 1;

            // Only request orphan repair if still in subtrees.
            if self.subtrees.contains(&slot) {
                targets.push(RepairTarget::Orphan { slot });
                self.orphan_queue.push_back(slot);
            }
        }

        // Record request times.
        let now = current_time_ms();
        for target in &targets {
            let slot = match target {
                RepairTarget::Shred { slot, .. } => *slot,
                RepairTarget::HighestShred { slot } => *slot,
                RepairTarget::Orphan { slot } => *slot,
            };
            if let Some(state) = self.slots.get_mut(&slot) {
                if state.first_request_time.is_none() {
                    state.first_request_time = Some(now);
                }
            }
        }

        targets
    }

    /// Advance the root to a new slot, pruning everything below.
    ///
    /// Removes all slots with `slot < new_root` from the forest and
    /// rebuilds parent-child connectivity.
    pub fn publish(&mut self, new_root: Slot) {
        if new_root <= self.root_slot {
            return;
        }

        // Collect slots to remove (below new root).
        let to_remove: Vec<Slot> = self
            .slots
            .keys()
            .filter(|&&s| s < new_root)
            .copied()
            .collect();

        for slot in &to_remove {
            self.remove_slot(*slot);
        }

        self.root_slot = new_root;

        // If new root exists, ensure it's in ancestry.
        if self.categories.contains_key(&new_root) {
            let cat = self.categories[&new_root];
            if cat != SlotCategory::Ancestry {
                self.remove_from_category(new_root, cat);
                self.place_in_category(new_root, SlotCategory::Ancestry);
            }
        }
    }

    /// Drain completed slots up to (and including) the given slot.
    /// Returns completed slots in order.
    pub fn drain_completed(&mut self, up_to: Slot) -> Vec<Slot> {
        let mut result = Vec::new();
        while let Some((&slot, _)) = self.completed.iter().next() {
            if slot > up_to {
                break;
            }
            self.completed.remove(&slot);
            result.push(slot);
        }
        result
    }

    /// All slots in the frontier (active repair targets).
    pub fn frontier_slots(&self) -> impl Iterator<Item = Slot> + '_ {
        self.frontier.iter().copied()
    }

    /// All orphaned slots.
    pub fn orphaned_slots(&self) -> impl Iterator<Item = Slot> + '_ {
        self.orphaned.iter().copied()
    }

    /// All subtree root slots (disconnected trees).
    pub fn subtree_slots(&self) -> impl Iterator<Item = Slot> + '_ {
        self.subtrees.iter().copied()
    }

    /// Number of completed slots awaiting drain.
    pub fn completed_count(&self) -> usize {
        self.completed.len()
    }

    /// Mark a slot as confirmed (>=52% stake duplicate-confirmed).
    pub fn mark_confirmed(&mut self, slot: Slot) {
        if let Some(state) = self.slots.get_mut(&slot) {
            state.confirmed = true;
        }
    }

    /// Whether a slot is a leaf (has no children in the forest).
    pub fn is_leaf(&self, slot: Slot) -> bool {
        self.children
            .get(&slot)
            .is_none_or(|children| children.is_empty())
    }

    // --- Internal methods ---

    /// Find the best eviction candidate using 4-tier priority:
    ///
    /// 1. Highest-slot unconfirmed orphan/subtree leaf
    /// 2. Highest-slot unconfirmed frontier leaf
    /// 3. Highest-slot confirmed orphan/subtree leaf
    /// 4. Confirmed frontier leaves are never evicted
    ///
    /// Cannot evict the parent of the slot being inserted.
    fn find_eviction_candidate(&self, inserting_parent: Slot) -> Option<Slot> {
        let is_eligible = |&s: &Slot| -> bool {
            // Must be a leaf (no children).
            if !self.is_leaf(s) {
                return false;
            }
            // Cannot evict the parent of the slot being inserted.
            if s == inserting_parent {
                return false;
            }
            // Cannot evict root.
            if s == self.root_slot {
                return false;
            }
            true
        };

        // Tier 1: Highest unconfirmed orphan/subtree leaf.
        let tier1 = self
            .orphaned
            .iter()
            .chain(self.subtrees.iter())
            .filter(|s| {
                is_eligible(s)
                    && self
                        .slots
                        .get(s)
                        .is_some_and(|state| !state.confirmed)
            })
            .max();
        if let Some(&victim) = tier1 {
            return Some(victim);
        }

        // Tier 2: Highest unconfirmed frontier leaf.
        let tier2 = self
            .frontier
            .iter()
            .filter(|s| {
                is_eligible(s)
                    && self
                        .slots
                        .get(s)
                        .is_some_and(|state| !state.confirmed)
            })
            .max();
        if let Some(&victim) = tier2 {
            return Some(victim);
        }

        // Tier 3: Highest confirmed orphan/subtree leaf.
        let tier3 = self
            .orphaned
            .iter()
            .chain(self.subtrees.iter())
            .filter(|s| {
                is_eligible(s)
                    && self
                        .slots
                        .get(s)
                        .is_some_and(|state| state.confirmed)
            })
            .max();
        if let Some(&victim) = tier3 {
            return Some(victim);
        }

        // Tier 4: Confirmed frontier leaves are never evicted.
        None
    }

    /// Generate repair requests for a single frontier slot.
    fn generate_slot_repairs(&self, slot: Slot, max_count: usize) -> Vec<RepairTarget> {
        let Some(state) = self.slots.get(&slot) else {
            return vec![];
        };

        if state.is_complete() {
            return vec![];
        }

        // If we don't know the slot length, request highest shred first.
        if !state.knows_slot_length() {
            return vec![RepairTarget::HighestShred { slot }];
        }

        // Generate specific shred requests for missing indices.
        state
            .missing_shreds(max_count)
            .into_iter()
            .map(|index| RepairTarget::Shred { slot, index })
            .collect()
    }

    /// Promote a slot from frontier to ancestry.
    fn promote_to_ancestry(&mut self, slot: Slot) {
        if self.frontier.remove(&slot) {
            self.ancestry.insert(slot);
            if let Some(cat) = self.categories.get_mut(&slot) {
                *cat = SlotCategory::Ancestry;
            }
        }
    }

    /// Place a slot in a category set.
    fn place_in_category(&mut self, slot: Slot, category: SlotCategory) {
        match category {
            SlotCategory::Ancestry => {
                self.ancestry.insert(slot);
            }
            SlotCategory::Frontier => {
                self.frontier.insert(slot);
            }
            SlotCategory::Orphaned => {
                self.orphaned.insert(slot);
            }
            SlotCategory::Subtree => {
                self.subtrees.insert(slot);
            }
        }
        self.categories.insert(slot, category);
    }

    /// Remove a slot from its current category set.
    fn remove_from_category(&mut self, slot: Slot, category: SlotCategory) {
        match category {
            SlotCategory::Ancestry => {
                self.ancestry.remove(&slot);
            }
            SlotCategory::Frontier => {
                self.frontier.remove(&slot);
            }
            SlotCategory::Orphaned => {
                self.orphaned.remove(&slot);
            }
            SlotCategory::Subtree => {
                self.subtrees.remove(&slot);
            }
        }
    }

    /// Remove a slot entirely from the forest.
    fn remove_slot(&mut self, slot: Slot) {
        // Read parent before removing state.
        let parent = self.slots.get(&slot).map(|s| s.parent_slot);

        if let Some(cat) = self.categories.remove(&slot) {
            self.remove_from_category(slot, cat);
        }
        self.slots.remove(&slot);
        self.completed.remove(&slot);
        self.children.remove(&slot);

        // Remove from parent's children list.
        if let Some(parent) = parent {
            if let Some(siblings) = self.children.get_mut(&parent) {
                siblings.retain(|&s| s != slot);
            }
        }

        // Clean up repair queues.
        self.repair_queue.retain(|&s| s != slot);
        self.orphan_queue.retain(|&s| s != slot);
    }

    /// Check if any subtree roots have this slot as their parent and
    /// connect them into the tree.
    fn try_connect_subtrees(&mut self, slot: Slot) {
        let category = match self.categories.get(&slot) {
            Some(c) => *c,
            None => return,
        };

        // Only connect if the newly inserted slot is in ancestry or frontier.
        if category != SlotCategory::Ancestry && category != SlotCategory::Frontier {
            return;
        }

        // Collect subtrees whose parent matches this slot.
        let to_connect: Vec<Slot> = self
            .subtrees
            .iter()
            .filter(|&&s| {
                self.slots
                    .get(&s)
                    .is_some_and(|state| state.parent_slot == slot)
            })
            .copied()
            .collect();

        for child_slot in to_connect {
            // Promote subtree root to frontier (now connected).
            self.subtrees.remove(&child_slot);
            if let Some(cat) = self.categories.get_mut(&child_slot) {
                *cat = SlotCategory::Frontier;
            }
            self.frontier.insert(child_slot);
            self.repair_queue.push_back(child_slot);

            self.children.entry(slot).or_default().push(child_slot);

            // Promote orphaned descendants of this subtree root.
            self.promote_orphaned_descendants(child_slot);
        }
    }

    /// BFS through orphaned descendants of a newly-connected slot,
    /// promoting them to frontier.
    fn promote_orphaned_descendants(&mut self, connected_slot: Slot) {
        let mut queue = VecDeque::new();

        // Find orphans whose parent is the connected slot.
        let orphans_to_promote: Vec<Slot> = self
            .orphaned
            .iter()
            .filter(|&&s| {
                self.slots
                    .get(&s)
                    .is_some_and(|state| state.parent_slot == connected_slot)
            })
            .copied()
            .collect();

        for child in orphans_to_promote {
            self.orphaned.remove(&child);
            self.frontier.insert(child);
            if let Some(cat) = self.categories.get_mut(&child) {
                *cat = SlotCategory::Frontier;
            }
            self.repair_queue.push_back(child);
            queue.push_back(child);
        }

        // BFS: promote their descendants too.
        while let Some(parent) = queue.pop_front() {
            let descendants: Vec<Slot> = self
                .orphaned
                .iter()
                .filter(|&&s| {
                    self.slots
                        .get(&s)
                        .is_some_and(|state| state.parent_slot == parent)
                })
                .copied()
                .collect();

            for child in descendants {
                self.orphaned.remove(&child);
                self.frontier.insert(child);
                if let Some(cat) = self.categories.get_mut(&child) {
                    *cat = SlotCategory::Frontier;
                }
                self.repair_queue.push_back(child);
                queue.push_back(child);
            }
        }
    }
}

/// Outcome of inserting a slot into the forest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertOutcome {
    /// Slot was inserted into the given category.
    Inserted(SlotCategory),
    /// Slot already existed and was updated.
    Updated,
    /// Slot is below the current root and was rejected.
    BelowRoot,
    /// Forest is at capacity and no eviction candidate was found.
    Full,
    /// Slot was inserted after evicting another slot.
    Evicted {
        /// The slot that was evicted to make room.
        evicted_slot: Slot,
    },
}

/// Current time in milliseconds (monotonic-ish).
fn current_time_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_forest() {
        let forest = RepairForest::new(0);
        assert_eq!(forest.root(), 0);
        assert_eq!(forest.slot_count(), 0);
        assert_eq!(forest.completed_count(), 0);
    }

    #[test]
    fn insert_root_child() {
        let mut forest = RepairForest::new(0);

        // Insert root.
        let r = forest.insert_slot(0, 0);
        assert_eq!(r, InsertOutcome::Inserted(SlotCategory::Ancestry));

        // Insert child of root → frontier.
        let r = forest.insert_slot(1, 0);
        assert_eq!(r, InsertOutcome::Inserted(SlotCategory::Frontier));
        assert!(forest.frontier.contains(&1));
    }

    #[test]
    fn frontier_promotes_to_ancestry_when_child_arrives() {
        let mut forest = RepairForest::new(0);
        forest.insert_slot(0, 0);
        forest.insert_slot(1, 0); // slot 1 in frontier

        // Insert child of slot 1 → slot 1 promoted to ancestry.
        forest.insert_slot(2, 1);
        assert!(forest.ancestry.contains(&1));
        assert!(forest.frontier.contains(&2));
    }

    #[test]
    fn orphaned_slot_when_parent_unknown() {
        let mut forest = RepairForest::new(0);
        forest.insert_slot(0, 0);

        // Slot 5 with parent 3 (unknown) → subtree.
        let r = forest.insert_slot(5, 3);
        assert_eq!(r, InsertOutcome::Inserted(SlotCategory::Subtree));
    }

    #[test]
    fn subtree_connects_when_parent_arrives() {
        let mut forest = RepairForest::new(0);
        forest.insert_slot(0, 0);
        forest.insert_slot(1, 0);

        // Slot 3 with parent 2 (unknown) → subtree.
        forest.insert_slot(3, 2);
        assert!(forest.subtrees.contains(&3));

        // Now insert slot 2 with parent 1 → slot 2 goes to frontier,
        // and slot 3 should connect (promote from subtree to frontier).
        forest.insert_slot(2, 1);
        assert!(forest.frontier.contains(&2) || forest.ancestry.contains(&2));
        assert!(
            forest.frontier.contains(&3),
            "slot 3 should be promoted to frontier"
        );
        assert!(!forest.subtrees.contains(&3));
    }

    #[test]
    fn shred_tracking() {
        let mut state = SlotRepairState::new(100, 99);

        // Insert shreds out of order.
        assert!(state.insert_shred(0, ShredSource::Turbine));
        assert!(state.insert_shred(2, ShredSource::Turbine));
        assert!(state.insert_shred(1, ShredSource::Turbine));

        // Consumed should advance to 2 (contiguous 0,1,2).
        assert_eq!(state.consumed_idx, Some(2));
        assert_eq!(state.buffered_idx, Some(2));
        assert_eq!(state.total_received(), 3);

        // Duplicate returns false.
        assert!(!state.insert_shred(1, ShredSource::Repair));
    }

    #[test]
    fn slot_completion() {
        let mut state = SlotRepairState::new(100, 99);
        state.set_complete_idx(3);

        state.insert_shred(0, ShredSource::Turbine);
        state.insert_shred(1, ShredSource::Turbine);
        state.insert_shred(2, ShredSource::Turbine);
        assert!(!state.is_complete());

        state.insert_shred(3, ShredSource::Turbine);
        assert!(state.is_complete());
    }

    #[test]
    fn missing_shreds_detection() {
        let mut state = SlotRepairState::new(100, 99);
        state.set_complete_idx(5);

        state.insert_shred(0, ShredSource::Turbine);
        state.insert_shred(1, ShredSource::Turbine);
        // Gap at 2, 3.
        state.insert_shred(4, ShredSource::Turbine);
        state.insert_shred(5, ShredSource::Turbine);

        let missing = state.missing_shreds(10);
        assert_eq!(missing, vec![2, 3]);
    }

    #[test]
    fn repair_request_generation() {
        let mut forest = RepairForest::new(0);
        forest.insert_slot(0, 0);
        forest.insert_slot(1, 0);

        // Slot 1 is in frontier with no shreds → should request highest.
        let repairs = forest.next_repairs(10);
        assert!(
            repairs.contains(&RepairTarget::HighestShred { slot: 1 }),
            "should request highest shred for unknown-length slot"
        );
    }

    #[test]
    fn repair_requests_for_known_slot_length() {
        let mut forest = RepairForest::new(0);
        forest.insert_slot(0, 0);
        forest.insert_slot(1, 0);

        // Set complete_idx for slot 1 and add some shreds.
        if let Some(state) = forest.get_slot_mut(1) {
            state.set_complete_idx(3);
            state.insert_shred(0, ShredSource::Turbine);
            state.insert_shred(2, ShredSource::Turbine);
        }

        let repairs = forest.next_repairs(10);
        // Should request specific missing shreds: 1, 3.
        assert!(repairs.contains(&RepairTarget::Shred { slot: 1, index: 1 }));
        assert!(repairs.contains(&RepairTarget::Shred { slot: 1, index: 3 }));
    }

    #[test]
    fn orphan_repair_requests() {
        let mut forest = RepairForest::new(0);
        forest.insert_slot(0, 0);

        // Slot 10 with unknown parent → subtree → orphan request.
        forest.insert_slot(10, 8);

        let repairs = forest.next_repairs(10);
        assert!(
            repairs.contains(&RepairTarget::Orphan { slot: 10 }),
            "should generate orphan request for disconnected slot"
        );
    }

    #[test]
    fn publish_prunes_old_slots() {
        let mut forest = RepairForest::new(0);
        forest.insert_slot(0, 0);
        forest.insert_slot(1, 0);
        forest.insert_slot(2, 1);
        forest.insert_slot(3, 2);

        assert_eq!(forest.slot_count(), 4);

        // Publish root at slot 2 → remove slots 0 and 1.
        forest.publish(2);
        assert_eq!(forest.root(), 2);
        assert!(forest.get_slot(0).is_none());
        assert!(forest.get_slot(1).is_none());
        assert!(forest.get_slot(2).is_some());
        assert!(forest.get_slot(3).is_some());
    }

    #[test]
    fn reject_below_root() {
        let mut forest = RepairForest::new(10);
        let r = forest.insert_slot(5, 4);
        assert_eq!(r, InsertOutcome::BelowRoot);
    }

    #[test]
    fn capacity_limit_evicts_unconfirmed_orphan() {
        let mut forest = RepairForest::with_capacity(0, 4);
        forest.insert_slot(0, 0);
        forest.insert_slot(1, 0);
        forest.insert_slot(2, 1);
        // Slot 10 with unknown parent → subtree (leaf, unconfirmed).
        forest.insert_slot(10, 8);
        assert_eq!(forest.slot_count(), 4);

        // Insert slot 3 → should evict slot 10 (tier 1: unconfirmed orphan/subtree leaf).
        let r = forest.insert_slot(3, 2);
        assert!(
            matches!(r, InsertOutcome::Evicted { evicted_slot: 10 }),
            "expected eviction of slot 10, got {:?}",
            r
        );
        assert!(forest.get_slot(10).is_none());
        assert!(forest.get_slot(3).is_some());
    }

    #[test]
    fn eviction_prefers_highest_slot() {
        let mut forest = RepairForest::with_capacity(0, 5);
        forest.insert_slot(0, 0);
        forest.insert_slot(1, 0);
        // Two orphan/subtree leaves.
        forest.insert_slot(20, 18);
        forest.insert_slot(30, 28);
        forest.insert_slot(2, 1);
        // At capacity=5, but we already have 5. Actually let me re-check...
        // 0, 1, 20, 30, 2 = 5 slots.
        assert_eq!(forest.slot_count(), 5);

        // Insert slot 3 → should evict slot 30 (highest unconfirmed orphan leaf).
        let r = forest.insert_slot(3, 2);
        assert!(
            matches!(r, InsertOutcome::Evicted { evicted_slot: 30 }),
            "expected eviction of slot 30, got {:?}",
            r
        );
    }

    #[test]
    fn eviction_tier2_unconfirmed_frontier_leaf() {
        let mut forest = RepairForest::with_capacity(0, 4);
        forest.insert_slot(0, 0);
        forest.insert_slot(1, 0);
        forest.insert_slot(2, 0);
        forest.insert_slot(3, 1);
        // Now: 0=ancestry, 1=ancestry, 2=frontier(leaf), 3=frontier(leaf)
        assert_eq!(forest.slot_count(), 4);

        // Insert slot 4 with parent 2 → should evict slot 3 (tier 2: highest unconfirmed frontier leaf).
        let r = forest.insert_slot(4, 2);
        assert!(
            matches!(r, InsertOutcome::Evicted { evicted_slot: 3 }),
            "expected eviction of slot 3, got {:?}",
            r
        );
    }

    #[test]
    fn eviction_tier3_confirmed_orphan_leaf() {
        let mut forest = RepairForest::with_capacity(0, 4);
        forest.insert_slot(0, 0);
        forest.insert_slot(1, 0);
        // Two confirmed orphan leaves — no unconfirmed leaves anywhere.
        forest.insert_slot(20, 18);
        forest.mark_confirmed(20);
        forest.insert_slot(30, 28);
        forest.mark_confirmed(30);
        assert_eq!(forest.slot_count(), 4);

        // All frontier leaves (slot 1) are confirmed too.
        forest.mark_confirmed(1);

        // Insert slot 2 → should evict slot 30 (tier 3: highest confirmed orphan leaf).
        let r = forest.insert_slot(2, 1);
        assert!(
            matches!(r, InsertOutcome::Evicted { evicted_slot: 30 }),
            "expected eviction of slot 30, got {:?}",
            r
        );
    }

    #[test]
    fn eviction_full_when_only_confirmed_frontier_leaves() {
        let mut forest = RepairForest::with_capacity(0, 3);
        forest.insert_slot(0, 0);
        forest.insert_slot(1, 0);
        forest.insert_slot(2, 0);
        // Mark all frontier leaves as confirmed.
        forest.mark_confirmed(1);
        forest.mark_confirmed(2);
        assert_eq!(forest.slot_count(), 3);

        // Insert slot 3 → no eviction candidate → Full.
        let r = forest.insert_slot(3, 1);
        assert_eq!(r, InsertOutcome::Full);
    }

    #[test]
    fn eviction_does_not_evict_parent_of_inserting_slot() {
        let mut forest = RepairForest::with_capacity(0, 3);
        forest.insert_slot(0, 0);
        forest.insert_slot(1, 0);
        // Slot 5 is an orphan leaf (parent 3).
        forest.insert_slot(5, 3);
        assert_eq!(forest.slot_count(), 3);

        // Insert slot 6 with parent 5 → cannot evict 5 (its parent),
        // should evict slot 1 instead (unconfirmed frontier leaf).
        let r = forest.insert_slot(6, 5);
        assert!(
            matches!(r, InsertOutcome::Evicted { evicted_slot: 1 }),
            "expected eviction of slot 1, got {:?}",
            r
        );
    }

    #[test]
    fn mark_confirmed_persists() {
        let mut forest = RepairForest::new(0);
        forest.insert_slot(0, 0);
        forest.insert_slot(1, 0);

        assert!(!forest.get_slot(1).unwrap().confirmed);
        forest.mark_confirmed(1);
        assert!(forest.get_slot(1).unwrap().confirmed);
    }

    #[test]
    fn is_leaf_detection() {
        let mut forest = RepairForest::new(0);
        forest.insert_slot(0, 0);
        forest.insert_slot(1, 0);
        forest.insert_slot(2, 1);

        // Slot 0 has child 1 → not a leaf.
        assert!(!forest.is_leaf(0));
        // Slot 1 has child 2 → not a leaf.
        assert!(!forest.is_leaf(1));
        // Slot 2 has no children → leaf.
        assert!(forest.is_leaf(2));
    }

    #[test]
    fn receive_shred_creates_slot() {
        let mut forest = RepairForest::new(0);
        forest.insert_slot(0, 0);

        // Receiving a shred for an unknown slot auto-creates it.
        forest.receive_shred(5, 0, ShredSource::Turbine, false, Some(4));
        assert!(forest.get_slot(5).is_some());
    }

    #[test]
    fn completed_slot_tracking() {
        let mut forest = RepairForest::new(0);
        forest.insert_slot(0, 0);
        forest.insert_slot(1, 0);

        // Complete slot 1.
        forest.receive_shred(1, 0, ShredSource::Turbine, false, Some(0));
        forest.receive_shred(1, 1, ShredSource::Turbine, false, Some(0));
        forest.receive_shred(1, 2, ShredSource::Turbine, true, Some(0));

        // Slot 1 should be completed (complete_idx=2, consumed=2).
        assert_eq!(forest.completed_count(), 1);

        let drained = forest.drain_completed(10);
        assert_eq!(drained, vec![1]);
        assert_eq!(forest.completed_count(), 0);
    }

    #[test]
    fn fec_completion_inserts_recovered_shreds() {
        let mut forest = RepairForest::new(0);
        forest.insert_slot(0, 0);
        forest.insert_slot(1, 0);

        // Add some shreds, leaving gaps.
        forest.receive_shred(1, 0, ShredSource::Turbine, false, Some(0));
        // Gap at 1.
        forest.receive_shred(1, 2, ShredSource::Turbine, true, Some(0));

        // Slot not complete yet (missing shred 1).
        assert_eq!(forest.completed_count(), 0);

        // FEC recovery fills the gap.
        if let Some(state) = forest.get_slot_mut(1) {
            state.register_fec_set(0);
        }
        forest.complete_fec_set(1, 0, &[1]);

        // Now slot should be complete.
        assert_eq!(forest.completed_count(), 1);
    }

    #[test]
    fn shred_source_counting() {
        let mut state = SlotRepairState::new(100, 99);

        state.insert_shred(0, ShredSource::Turbine);
        state.insert_shred(1, ShredSource::Repair);
        state.insert_shred(2, ShredSource::Recovered);
        state.insert_shred(3, ShredSource::Turbine);

        assert_eq!(state.turbine_count, 2);
        assert_eq!(state.repair_count, 1);
        assert_eq!(state.recovered_count, 1);
    }

    #[test]
    fn drain_completed_respects_upper_bound() {
        let mut forest = RepairForest::new(0);
        forest.insert_slot(0, 0);
        forest.insert_slot(1, 0);
        forest.insert_slot(2, 1);

        // Complete both slots.
        forest.receive_shred(1, 0, ShredSource::Turbine, true, Some(0));
        forest.receive_shred(2, 0, ShredSource::Turbine, true, Some(1));

        // Drain only up to slot 1.
        let drained = forest.drain_completed(1);
        assert_eq!(drained, vec![1]);
        assert_eq!(forest.completed_count(), 1); // slot 2 still pending
    }
}
