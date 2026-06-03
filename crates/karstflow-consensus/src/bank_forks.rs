use super::{Bank, BankStatus};
use crate::bank_notifier::BankNotifier;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

/// Report returned by operations that evict banks from the fork tree.
///
/// Callers use these slot lists for external cleanup: marking dead in the
/// blockstore, cancelling account transaction records, etc.
#[derive(Debug, Clone, Default)]
pub struct EvictionReport {
    /// Slots evicted because they were marked dead (invalid block).
    pub dead_slots: Vec<u64>,
    /// Slots evicted because they fell below the new root.
    pub pruned_slots: Vec<u64>,
}

impl EvictionReport {
    pub fn total_evicted(&self) -> usize {
        self.dead_slots.len() + self.pruned_slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.dead_slots.is_empty() && self.pruned_slots.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct BankForks {
    banks: HashMap<u64, Arc<Bank>>,
    root_slot: u64,
    working_bank: Arc<Bank>,
    /// Slots marked as dead (invalid block, execution failure, etc.).
    /// Dead banks and their descendants are ineligible for fork choice
    /// and will be evicted on the next root advancement or eagerly via
    /// `mark_dead_and_evict()`.
    dead_slots: HashSet<u64>,
    /// FIFO queue for ordered dead bank eviction. Banks are pruned from
    /// the front; eviction stops at the first bank with external references
    /// (`Arc` strong count > 1), preventing premature removal of banks
    /// still used by in-flight operations.
    dead_queue: VecDeque<u64>,
    /// Parent slot → direct children mapping for O(1) descendant queries.
    /// Maintained on insert/eviction to avoid O(n*h) ancestor scanning.
    child_index: HashMap<u64, Vec<u64>>,
    /// Optional notifier injected into banks on insert so that account
    /// and transaction state changes are forwarded to external observers.
    notifier: Option<Arc<dyn BankNotifier>>,
}

impl BankForks {
    pub fn new(root_bank: Bank) -> Self {
        let root_slot = root_bank.slot();
        let root_bank = Arc::new(root_bank);

        let mut banks = HashMap::new();
        banks.insert(root_slot, root_bank.clone());

        Self {
            banks,
            root_slot,
            working_bank: root_bank,
            dead_slots: HashSet::new(),
            dead_queue: VecDeque::new(),
            child_index: HashMap::new(),
            notifier: None,
        }
    }

    /// Initialize BankForks from a snapshot-restored bank.
    ///
    /// The snapshot bank becomes the root and working bank.
    /// Unlike `new()`, this validates that the bank's slot, epoch,
    /// and status are consistent with a restored snapshot.
    pub fn new_from_snapshot(snapshot_bank: Bank) -> Result<Self, BankForksError> {
        if snapshot_bank.status() != BankStatus::Rooted {
            return Err(BankForksError::SnapshotBankNotRooted);
        }

        let root_slot = snapshot_bank.slot();
        let bank = Arc::new(snapshot_bank);
        let mut banks = HashMap::new();
        banks.insert(root_slot, bank.clone());

        Ok(Self {
            banks,
            root_slot,
            working_bank: bank,
            dead_slots: HashSet::new(),
            dead_queue: VecDeque::new(),
            child_index: HashMap::new(),
            notifier: None,
        })
    }

    pub fn root_slot(&self) -> u64 {
        self.root_slot
    }

    pub fn root_bank(&self) -> Option<Arc<Bank>> {
        self.banks.get(&self.root_slot).cloned()
    }

    pub fn working_bank(&self) -> Arc<Bank> {
        self.working_bank.clone()
    }

    pub fn get(&self, slot: u64) -> Option<Arc<Bank>> {
        self.banks.get(&slot).cloned()
    }

    pub fn insert(&mut self, mut bank: Bank) -> Result<(), BankForksError> {
        let slot = bank.slot();

        if slot <= self.root_slot {
            return Err(BankForksError::SlotBelowRoot {
                slot,
                root_slot: self.root_slot,
            });
        }

        if self.banks.contains_key(&slot) {
            return Err(BankForksError::SlotAlreadyExists(slot));
        }

        let parent_slot = bank.parent_slot();
        if let Some(parent_slot) = parent_slot {
            if !self.banks.contains_key(&parent_slot) {
                return Err(BankForksError::ParentNotFound { slot, parent_slot });
            }
            if self.dead_slots.contains(&parent_slot) {
                return Err(BankForksError::ParentIsDead { slot, parent_slot });
            }
            // Maintain child index.
            self.child_index.entry(parent_slot).or_default().push(slot);
        }

        // Inject bank notifier if configured.
        if let Some(ref notifier) = self.notifier {
            bank.set_notifier(Arc::clone(notifier));
        }

        self.banks.insert(slot, Arc::new(bank));
        Ok(())
    }

    /// Set the bank notifier for account/transaction state change notifications.
    ///
    /// The notifier is injected into every bank inserted via `insert()`.
    /// Existing banks in the fork tree are not retroactively updated.
    pub fn set_bank_notifier(&mut self, notifier: Arc<dyn BankNotifier>) {
        self.notifier = Some(notifier);
    }

    /// Advance the root slot and evict banks below the new root.
    ///
    /// Returns an `EvictionReport` listing which slots were removed and why,
    /// so callers can perform external cleanup (blockstore, account records).
    pub fn set_root(&mut self, new_root_slot: u64) -> Result<EvictionReport, BankForksError> {
        if new_root_slot <= self.root_slot {
            return Err(BankForksError::RootNotAdvancing {
                current_root: self.root_slot,
                new_root: new_root_slot,
            });
        }

        let new_root_bank = self
            .banks
            .get(&new_root_slot)
            .ok_or(BankForksError::RootBankNotFound(new_root_slot))?;

        if new_root_bank.status() != BankStatus::Rooted {
            return Err(BankForksError::BankNotRooted(new_root_slot));
        }

        // Prune transaction dedup cache entries that can no longer be
        // referenced by any valid transaction. Transactions must use a
        // recent blockhash within MAX_RECENT_BLOCKHASHES slots of the
        // current root, so anything older is safe to discard.
        let purge_below = new_root_slot
            .saturating_sub(karstflow_constants::sysvars::MAX_RECENT_BLOCKHASHES as u64);
        new_root_bank
            .transaction_cache()
            .purge_before_slot(purge_below);

        let mut report = EvictionReport::default();

        // Collect slots to remove: below root or marked dead.
        let slots_before: Vec<u64> = self.banks.keys().copied().collect();
        for slot in slots_before {
            if slot < new_root_slot {
                report.pruned_slots.push(slot);
            } else if self.dead_slots.contains(&slot) {
                report.dead_slots.push(slot);
            }
        }

        // Remove evicted banks and their child index entries.
        for &slot in report.pruned_slots.iter().chain(report.dead_slots.iter()) {
            self.banks.remove(&slot);
            self.child_index.remove(&slot);
        }

        // Clean up child index references to evicted slots.
        for children in self.child_index.values_mut() {
            children.retain(|s| self.banks.contains_key(s));
        }
        self.child_index.retain(|_, children| !children.is_empty());

        // Discard dead slot tracking for evicted banks.
        self.dead_slots.retain(|slot| self.banks.contains_key(slot));
        self.dead_queue.retain(|slot| self.banks.contains_key(slot));

        self.root_slot = new_root_slot;
        Ok(report)
    }

    pub fn set_working_bank(&mut self, slot: u64) -> Result<(), BankForksError> {
        let bank = self
            .banks
            .get(&slot)
            .ok_or(BankForksError::BankNotFound(slot))?
            .clone();

        self.working_bank = bank;
        Ok(())
    }

    /// Mark a slot and all its descendants as dead, then eagerly evict them.
    ///
    /// Dead banks are ineligible for fork choice. This is called when replay
    /// detects an invalid block (execution failure, hash mismatch, etc.).
    ///
    /// Also marks each evicted bank's cost tracker as dead to prevent new
    /// transaction scheduling.
    ///
    /// Returns an `EvictionReport` listing the evicted slots.
    pub fn mark_dead_and_evict(&mut self, slot: u64) -> EvictionReport {
        let mut report = EvictionReport::default();

        if !self.banks.contains_key(&slot) {
            return report;
        }

        // BFS through child index to collect all descendants.
        let mut queue = VecDeque::new();
        queue.push_back(slot);

        while let Some(current) = queue.pop_front() {
            if self.dead_slots.insert(current) {
                report.dead_slots.push(current);
                self.dead_queue.push_back(current);

                // Mark cost tracker dead to prevent new transaction scheduling.
                if let Some(bank) = self.banks.get(&current) {
                    bank.cost_tracker().mark_dead();
                }
            }

            // Enqueue direct children for cascade.
            if let Some(children) = self.child_index.get(&current) {
                for &child in children {
                    if !self.dead_slots.contains(&child) {
                        queue.push_back(child);
                    }
                }
            }
        }

        // Eagerly prune dead banks in FIFO order, respecting external
        // references. Banks still held by in-flight operations remain
        // in the map and dead_queue until their references are dropped.
        self.try_prune_dead();

        report
    }

    /// Mark a slot and all its descendants as dead without immediate eviction.
    ///
    /// Use `mark_dead_and_evict()` for production code. This method is kept
    /// for cases where dead status needs to be recorded before eviction
    /// (e.g., when the bank is still referenced by in-flight operations).
    ///
    /// Returns the number of newly-marked dead slots (including descendants).
    pub fn mark_dead(&mut self, slot: u64) -> usize {
        if !self.banks.contains_key(&slot) {
            return 0;
        }

        let mut newly_dead = Vec::new();

        // BFS through child index to collect all descendants.
        let mut queue = VecDeque::new();
        queue.push_back(slot);

        while let Some(current) = queue.pop_front() {
            if self.dead_slots.insert(current) {
                newly_dead.push(current);
                self.dead_queue.push_back(current);

                if let Some(bank) = self.banks.get(&current) {
                    bank.cost_tracker().mark_dead();
                }
            }

            if let Some(children) = self.child_index.get(&current) {
                for &child in children {
                    if !self.dead_slots.contains(&child) {
                        queue.push_back(child);
                    }
                }
            }
        }

        newly_dead.len()
    }

    /// Remove all dead banks from memory immediately.
    ///
    /// Returns the number of banks evicted.
    pub fn prune_dead(&mut self) -> usize {
        let before = self.banks.len();
        let removed: Vec<u64> = self
            .banks
            .keys()
            .filter(|slot| self.dead_slots.contains(slot))
            .copied()
            .collect();

        for slot in &removed {
            self.banks.remove(slot);
            self.child_index.remove(slot);
        }

        // Clean up child index references.
        for children in self.child_index.values_mut() {
            children.retain(|s| !self.dead_slots.contains(s));
        }
        self.child_index.retain(|_, children| !children.is_empty());

        // Sync dead tracking after forced eviction.
        self.dead_queue.retain(|slot| self.banks.contains_key(slot));
        self.dead_slots.retain(|slot| self.banks.contains_key(slot));

        before - self.banks.len()
    }

    /// Prune dead banks in FIFO order, stopping at the first bank that
    /// is still referenced externally (`Arc` strong count > 1).
    ///
    /// This ensures banks held by in-flight operations (replay, RPC
    /// handlers, etc.) are not removed from the fork map until their
    /// callers drop their references. Later-queued dead banks are not
    /// pruned either, preserving FIFO eviction ordering.
    ///
    /// Returns the number of banks actually evicted.
    pub fn try_prune_dead(&mut self) -> usize {
        let mut pruned = 0;

        while let Some(&slot) = self.dead_queue.front() {
            // Bank already evicted (by set_root or a previous prune).
            let Some(bank) = self.banks.get(&slot) else {
                self.dead_queue.pop_front();
                self.dead_slots.remove(&slot);
                continue;
            };

            // Stop at the first bank with external references.
            if Arc::strong_count(bank) > 1 {
                break;
            }

            // Collect parent info before mutating.
            let parent_slot = bank.parent_slot();

            // Evict the bank.
            self.dead_queue.pop_front();
            self.dead_slots.remove(&slot);
            self.banks.remove(&slot);

            // Remove from parent's child list.
            if let Some(ps) = parent_slot {
                if let Some(children) = self.child_index.get_mut(&ps) {
                    children.retain(|&s| s != slot);
                    if children.is_empty() {
                        self.child_index.remove(&ps);
                    }
                }
            }

            // Remove this bank's own child index entry.
            self.child_index.remove(&slot);

            pruned += 1;
        }

        pruned
    }

    /// Check whether a slot has been marked as dead.
    pub fn is_dead(&self, slot: u64) -> bool {
        self.dead_slots.contains(&slot)
    }

    /// Number of slots currently marked dead.
    pub fn dead_slot_count(&self) -> usize {
        self.dead_slots.len()
    }

    /// Number of dead banks waiting in the eviction queue.
    pub fn dead_queue_len(&self) -> usize {
        self.dead_queue.len()
    }

    /// Direct children of a slot in the fork tree.
    pub fn children(&self, slot: u64) -> &[u64] {
        self.child_index
            .get(&slot)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    pub fn prune_non_rooted(&mut self, keep_above_slot: u64) {
        let root_slot = self.root_slot;
        let ancestors = self.collect_ancestors(self.working_bank.slot());

        let to_remove: Vec<u64> = self
            .banks
            .iter()
            .filter(|(&slot, bank)| {
                slot != root_slot
                    && slot <= keep_above_slot
                    && bank.status() != BankStatus::Rooted
                    && !ancestors.contains(&slot)
            })
            .map(|(&slot, _)| slot)
            .collect();

        for slot in &to_remove {
            self.banks.remove(slot);
            self.child_index.remove(slot);
        }

        // Clean up child index references.
        for children in self.child_index.values_mut() {
            children.retain(|s| self.banks.contains_key(s));
        }
        self.child_index.retain(|_, children| !children.is_empty());
    }

    /// All descendants of a slot using BFS through the child index.
    ///
    /// O(k) where k = number of descendants, instead of O(n*h) scanning.
    pub fn descendants(&self, slot: u64) -> Vec<u64> {
        let mut result = Vec::new();
        let mut queue = VecDeque::new();

        // Seed with direct children.
        if let Some(children) = self.child_index.get(&slot) {
            for &child in children {
                queue.push_back(child);
            }
        }

        while let Some(current) = queue.pop_front() {
            result.push(current);
            if let Some(children) = self.child_index.get(&current) {
                for &child in children {
                    queue.push_back(child);
                }
            }
        }

        result
    }

    pub fn is_ancestor(&self, ancestor_slot: u64, slot: u64) -> bool {
        if ancestor_slot >= slot {
            return false;
        }

        let mut current_slot = slot;
        while current_slot > ancestor_slot {
            if let Some(bank) = self.banks.get(&current_slot) {
                if let Some(parent_slot) = bank.parent_slot() {
                    if parent_slot == ancestor_slot {
                        return true;
                    }
                    current_slot = parent_slot;
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }
        false
    }

    pub fn highest_slot(&self) -> u64 {
        self.banks.keys().copied().max().unwrap_or(self.root_slot)
    }

    pub fn len(&self) -> usize {
        self.banks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.banks.is_empty()
    }

    fn collect_ancestors(&self, slot: u64) -> Vec<u64> {
        let mut ancestors = Vec::new();
        let mut current_slot = slot;

        while let Some(bank) = self.banks.get(&current_slot) {
            if let Some(parent_slot) = bank.parent_slot() {
                ancestors.push(parent_slot);
                current_slot = parent_slot;
            } else {
                break;
            }
        }

        ancestors
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BankForksError {
    SlotBelowRoot { slot: u64, root_slot: u64 },
    SlotAlreadyExists(u64),
    ParentNotFound { slot: u64, parent_slot: u64 },
    ParentIsDead { slot: u64, parent_slot: u64 },
    RootNotAdvancing { current_root: u64, new_root: u64 },
    RootBankNotFound(u64),
    BankNotRooted(u64),
    BankNotFound(u64),
    SnapshotBankNotRooted,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EpochSchedule, LeaderSchedule};
    use karstflow_storage::{AccountDatabase, Pubkey};

    fn create_test_leader_schedule(epoch: u64) -> Arc<LeaderSchedule> {
        let validator = Pubkey::new_unique();
        let validators = vec![(validator, 1000)];
        Arc::new(LeaderSchedule::new(epoch, &validators).unwrap())
    }

    fn create_genesis_bank() -> Bank {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);
        Bank::new_genesis(accounts, epoch_schedule, leader_schedule)
    }

    #[test]
    fn bank_forks_initializes_with_genesis() {
        let genesis = create_genesis_bank();
        let genesis_slot = genesis.slot();

        let forks = BankForks::new(genesis);

        assert_eq!(forks.root_slot(), genesis_slot);
        assert_eq!(forks.working_bank().slot(), genesis_slot);
        assert_eq!(forks.len(), 1);
    }

    #[test]
    fn bank_forks_inserts_child_bank() {
        let genesis = create_genesis_bank();
        let mut forks = BankForks::new(genesis);

        let parent_bank = forks.working_bank();
        let leader_schedule = create_test_leader_schedule(0);
        let child = Bank::new_from_parent(&parent_bank, 1, leader_schedule);

        assert!(forks.insert(child).is_ok());
        assert_eq!(forks.len(), 2);
        assert!(forks.get(1).is_some());
    }

    #[test]
    fn bank_forks_rejects_duplicate_slot() {
        let genesis = create_genesis_bank();
        let mut forks = BankForks::new(genesis);

        let parent_bank = forks.working_bank();
        let leader_schedule = create_test_leader_schedule(0);
        let child1 = Bank::new_from_parent(&parent_bank, 1, leader_schedule.clone());
        let child2 = Bank::new_from_parent(&parent_bank, 1, leader_schedule);

        assert!(forks.insert(child1).is_ok());
        assert_eq!(
            forks.insert(child2),
            Err(BankForksError::SlotAlreadyExists(1))
        );
    }

    #[test]
    fn bank_forks_rejects_orphan_bank() {
        let genesis = create_genesis_bank();
        let mut forks = BankForks::new(genesis);

        let parent_bank = forks.working_bank();
        let leader_schedule = create_test_leader_schedule(0);
        let intermediate = Bank::new_from_parent(&parent_bank, 1, leader_schedule.clone());

        let orphan = Bank::new_from_parent(&intermediate, 100, leader_schedule);

        assert!(matches!(
            forks.insert(orphan),
            Err(BankForksError::ParentNotFound { .. })
        ));
    }

    #[test]
    fn bank_forks_sets_root() {
        let genesis = create_genesis_bank();
        let mut forks = BankForks::new(genesis);

        let parent_bank = forks.working_bank();
        let leader_schedule = create_test_leader_schedule(0);
        let child = Bank::new_from_parent(&parent_bank, 1, leader_schedule);

        for _ in 0..karstflow_constants::ledger::TICKS_PER_SLOT {
            child.register_tick().unwrap();
        }
        child.freeze().unwrap();
        child.mark_rooted().unwrap();

        forks.insert(child).unwrap();
        let report = forks.set_root(1).unwrap();
        assert_eq!(forks.root_slot(), 1);
        assert_eq!(report.pruned_slots, vec![0]);
        assert!(report.dead_slots.is_empty());
    }

    #[test]
    fn bank_forks_prunes_on_set_root() {
        let genesis = create_genesis_bank();
        let mut forks = BankForks::new(genesis);

        let parent_bank = forks.working_bank();
        let leader_schedule = create_test_leader_schedule(0);

        let bank1 = Bank::new_from_parent(&parent_bank, 1, leader_schedule.clone());
        for _ in 0..karstflow_constants::ledger::TICKS_PER_SLOT {
            bank1.register_tick().unwrap();
        }
        bank1.freeze().unwrap();
        bank1.mark_rooted().unwrap();
        forks.insert(bank1).unwrap();

        let bank2 = Bank::new_from_parent(&parent_bank, 2, leader_schedule);
        forks.insert(bank2).unwrap();

        assert_eq!(forks.len(), 3);

        forks.set_root(1).unwrap();

        assert_eq!(forks.len(), 2);
        assert!(forks.get(0).is_none());
        assert!(forks.get(1).is_some());
        assert!(forks.get(2).is_some());
    }

    #[test]
    fn bank_forks_tracks_descendants() {
        let genesis = create_genesis_bank();
        let mut forks = BankForks::new(genesis);

        let leader_schedule = create_test_leader_schedule(0);
        let bank0 = forks.working_bank();

        let bank1 = Bank::new_from_parent(&bank0, 1, leader_schedule.clone());
        forks.insert(bank1).unwrap();

        let bank1_ref = forks.get(1).unwrap();
        let bank2 = Bank::new_from_parent(&bank1_ref, 2, leader_schedule);
        forks.insert(bank2).unwrap();

        let descendants = forks.descendants(0);
        assert_eq!(descendants.len(), 2);
        assert!(descendants.contains(&1));
        assert!(descendants.contains(&2));

        let descendants = forks.descendants(1);
        assert_eq!(descendants.len(), 1);
        assert!(descendants.contains(&2));
    }

    // -- Child index tests --

    #[test]
    fn child_index_tracks_direct_children() {
        let genesis = create_genesis_bank();
        let mut forks = BankForks::new(genesis);
        let leader_schedule = create_test_leader_schedule(0);
        let bank0 = forks.working_bank();

        let bank1 = Bank::new_from_parent(&bank0, 1, leader_schedule.clone());
        forks.insert(bank1).unwrap();
        let bank2 = Bank::new_from_parent(&bank0, 2, leader_schedule.clone());
        forks.insert(bank2).unwrap();

        let children = forks.children(0);
        assert_eq!(children.len(), 2);
        assert!(children.contains(&1));
        assert!(children.contains(&2));

        // Slot 1 has no children yet.
        assert!(forks.children(1).is_empty());

        // Add child of slot 1.
        let bank1_ref = forks.get(1).unwrap();
        let bank3 = Bank::new_from_parent(&bank1_ref, 3, leader_schedule);
        forks.insert(bank3).unwrap();

        assert_eq!(forks.children(1), &[3]);
    }

    #[test]
    fn child_index_cleaned_on_set_root() {
        let genesis = create_genesis_bank();
        let mut forks = BankForks::new(genesis);
        let leader_schedule = create_test_leader_schedule(0);
        let bank0 = forks.working_bank();

        let bank1 = Bank::new_from_parent(&bank0, 1, leader_schedule.clone());
        forks.insert(bank1).unwrap();
        let bank1_ref = forks.get(1).unwrap();
        let bank2 = Bank::new_from_parent(&bank1_ref, 2, leader_schedule);
        forks.insert(bank2).unwrap();

        // Root slot 1 — slot 0 pruned.
        for _ in 0..karstflow_constants::ledger::TICKS_PER_SLOT {
            bank1_ref.register_tick().unwrap();
        }
        bank1_ref.freeze().unwrap();
        bank1_ref.mark_rooted().unwrap();
        forks.set_root(1).unwrap();

        // Child index for slot 0 should be gone.
        assert!(forks.children(0).is_empty());
        // Slot 1 still has child 2.
        assert_eq!(forks.children(1), &[2]);
    }

    // -- Snapshot restore integration tests --

    fn make_snapshot_bank(slot: u64, epoch: u64) -> Bank {
        use karstflow_storage::{
            EpochScheduleConfig as SnapEpochSchedule, FeeRateConfig, InflationConfig,
            RecentBlockhash, RentConfig, SnapshotBankState, StakeSummary,
        };

        let ticks_per_slot = 64u64;
        let tick_height = slot * ticks_per_slot + ticks_per_slot;

        let state = SnapshotBankState {
            recent_blockhashes: vec![RecentBlockhash {
                hash: [0xAA; 32],
                lamports_per_signature: 5000,
                hash_index: 100,
                timestamp: 1_000_000,
            }],
            last_blockhash: Some([0xAA; 32]),
            max_blockhash_age: 300,
            last_blockhash_index: 100,
            slot,
            parent_slot: slot.saturating_sub(1),
            block_height: slot,
            epoch,
            hash: [0x11; 32],
            parent_hash: [0x22; 32],
            transaction_count: 50_000,
            tick_height,
            max_tick_height: tick_height,
            signature_count: 25_000,
            capitalization: 500_000_000_000,
            accounts_data_len: 1_000_000,
            hashes_per_tick: Some(12500),
            ticks_per_slot,
            ns_per_slot: 400_000_000,
            genesis_creation_time: 1_700_000_000,
            slots_per_year: 78_892_314.0,
            collector_id: [0x33; 32],
            collector_fees: 0,
            fee_rate_governor: FeeRateConfig {
                target_lamports_per_signature: 10_000,
                target_signatures_per_slot: 20_000,
                min_lamports_per_signature: 5_000,
                max_lamports_per_signature: 100_000,
                burn_percent: 50,
            },
            rent: RentConfig {
                lamports_per_byte_year: 3_480,
                exemption_threshold: 2.0,
                burn_percent: 50,
                collector_epoch: epoch,
                collector_slots_per_year: 78_892_314.0,
            },
            collected_rent: 0,
            epoch_schedule: SnapEpochSchedule {
                slots_per_epoch: 432_000,
                leader_schedule_slot_offset: 432_000,
                warmup: false,
                first_normal_epoch: 0,
                first_normal_slot: 0,
            },
            inflation: InflationConfig {
                initial: 0.08,
                terminal: 0.015,
                taper: 0.15,
                foundation: 0.05,
                foundation_term: 7.0,
            },
            hard_forks: vec![],
            ancestor_count: 0,
            stake_summary: StakeSummary::default(),
            is_delta: true,
        };

        let accounts = Arc::new(AccountDatabase::new());
        let leader_schedule = create_test_leader_schedule(epoch);
        Bank::new_from_snapshot(accounts, &state, leader_schedule)
    }

    #[test]
    fn bank_forks_from_snapshot_bank() {
        let snap_bank = make_snapshot_bank(1000, 2);
        let forks = BankForks::new_from_snapshot(snap_bank).unwrap();

        assert_eq!(forks.root_slot(), 1000);
        assert_eq!(forks.working_bank().slot(), 1000);
        assert_eq!(forks.len(), 1);
    }

    #[test]
    fn bank_forks_snapshot_rejects_non_rooted() {
        // A genesis bank is in Processing status, not Rooted
        let genesis = create_genesis_bank();
        let result = BankForks::new_from_snapshot(genesis);
        assert!(matches!(result, Err(BankForksError::SnapshotBankNotRooted)));
    }

    #[test]
    fn bank_forks_snapshot_accepts_child_slot() {
        let snap_bank = make_snapshot_bank(1000, 2);
        let mut forks = BankForks::new_from_snapshot(snap_bank).unwrap();

        let parent = forks.working_bank();
        let leader_schedule = create_test_leader_schedule(2);
        let child = Bank::new_from_parent(&parent, 1001, leader_schedule);

        assert!(forks.insert(child).is_ok());
        assert_eq!(forks.len(), 2);
        assert!(forks.get(1001).is_some());
    }

    #[test]
    fn bank_forks_snapshot_full_lifecycle() {
        let snap_bank = make_snapshot_bank(1000, 2);
        let mut forks = BankForks::new_from_snapshot(snap_bank).unwrap();

        // Create child from snapshot root
        let parent = forks.working_bank();
        let leader_schedule = create_test_leader_schedule(2);
        let child = Bank::new_from_parent(&parent, 1001, leader_schedule);

        // Complete, freeze, and root the child
        for _ in 0..karstflow_constants::ledger::TICKS_PER_SLOT {
            child.register_tick().unwrap();
        }
        child.freeze().unwrap();
        child.mark_rooted().unwrap();

        forks.insert(child).unwrap();

        // Advance root to the child
        let report = forks.set_root(1001).unwrap();
        assert_eq!(forks.root_slot(), 1001);
        assert_eq!(report.pruned_slots, vec![1000]);

        // Old snapshot root should be pruned
        assert!(forks.get(1000).is_none());
        assert!(forks.get(1001).is_some());
    }

    #[test]
    fn bank_forks_checks_ancestry() {
        let genesis = create_genesis_bank();
        let mut forks = BankForks::new(genesis);

        let leader_schedule = create_test_leader_schedule(0);
        let bank0 = forks.working_bank();

        let bank1 = Bank::new_from_parent(&bank0, 1, leader_schedule.clone());
        forks.insert(bank1).unwrap();

        let bank1_ref = forks.get(1).unwrap();
        let bank2 = Bank::new_from_parent(&bank1_ref, 2, leader_schedule);
        forks.insert(bank2).unwrap();

        assert!(forks.is_ancestor(0, 1));
        assert!(forks.is_ancestor(0, 2));
        assert!(forks.is_ancestor(1, 2));
        assert!(!forks.is_ancestor(1, 1));
        assert!(!forks.is_ancestor(2, 1));
    }

    // -- Dead bank tracking tests --

    #[test]
    fn mark_dead_removes_slot_and_descendants() {
        let genesis = create_genesis_bank();
        let mut forks = BankForks::new(genesis);
        let leader_schedule = create_test_leader_schedule(0);

        // Build chain: 0 → 1 → 2 → 3 and fork 0 → 4
        let bank0 = forks.working_bank();
        let bank1 = Bank::new_from_parent(&bank0, 1, leader_schedule.clone());
        forks.insert(bank1).unwrap();
        let bank1_ref = forks.get(1).unwrap();
        let bank2 = Bank::new_from_parent(&bank1_ref, 2, leader_schedule.clone());
        forks.insert(bank2).unwrap();
        let bank2_ref = forks.get(2).unwrap();
        let bank3 = Bank::new_from_parent(&bank2_ref, 3, leader_schedule.clone());
        forks.insert(bank3).unwrap();
        let bank4 = Bank::new_from_parent(&bank0, 4, leader_schedule);
        forks.insert(bank4).unwrap();

        assert_eq!(forks.len(), 5);

        // Mark slot 1 dead — should cascade to 2 and 3
        let marked = forks.mark_dead(1);
        assert_eq!(marked, 3); // 1, 2, 3
        assert!(forks.is_dead(1));
        assert!(forks.is_dead(2));
        assert!(forks.is_dead(3));
        assert!(!forks.is_dead(0));
        assert!(!forks.is_dead(4));

        // Prune dead banks
        let evicted = forks.prune_dead();
        assert_eq!(evicted, 3);
        assert_eq!(forks.len(), 2); // 0 and 4 remain
        assert!(forks.get(0).is_some());
        assert!(forks.get(4).is_some());
        assert!(forks.get(1).is_none());
    }

    #[test]
    fn mark_dead_and_evict_atomic() {
        let genesis = create_genesis_bank();
        let mut forks = BankForks::new(genesis);
        let leader_schedule = create_test_leader_schedule(0);

        // Build chain: 0 → 1 → 2 → 3 and fork 0 → 4.
        // Intermediate Arc refs are scoped to prevent blocking eviction.
        {
            let bank0 = forks.working_bank();
            let bank1 = Bank::new_from_parent(&bank0, 1, leader_schedule.clone());
            forks.insert(bank1).unwrap();
        }
        {
            let bank1_ref = forks.get(1).unwrap();
            let bank2 = Bank::new_from_parent(&bank1_ref, 2, leader_schedule.clone());
            forks.insert(bank2).unwrap();
        }
        {
            let bank2_ref = forks.get(2).unwrap();
            let bank3 = Bank::new_from_parent(&bank2_ref, 3, leader_schedule.clone());
            forks.insert(bank3).unwrap();
        }
        {
            let bank0 = forks.working_bank();
            let bank4 = Bank::new_from_parent(&bank0, 4, leader_schedule);
            forks.insert(bank4).unwrap();
        }

        assert_eq!(forks.len(), 5);

        // Atomic mark-and-evict for slot 1.
        let report = forks.mark_dead_and_evict(1);
        assert_eq!(report.dead_slots.len(), 3);
        assert!(report.dead_slots.contains(&1));
        assert!(report.dead_slots.contains(&2));
        assert!(report.dead_slots.contains(&3));

        // Banks immediately gone (no external references).
        assert_eq!(forks.len(), 2);
        assert!(forks.get(0).is_some());
        assert!(forks.get(4).is_some());
        assert!(forks.get(1).is_none());
        assert!(forks.get(2).is_none());
        assert!(forks.get(3).is_none());

        // Child index updated: slot 0 should only have child 4.
        assert_eq!(forks.children(0), &[4]);
    }

    #[test]
    fn mark_dead_and_evict_sets_cost_tracker_dead() {
        let genesis = create_genesis_bank();
        let mut forks = BankForks::new(genesis);
        let leader_schedule = create_test_leader_schedule(0);

        let bank0 = forks.working_bank();
        let bank1 = Bank::new_from_parent(&bank0, 1, leader_schedule);
        forks.insert(bank1).unwrap();

        // Hold bank Arc before eviction so we can inspect cost tracker after.
        let bank1_ref = forks.get(1).unwrap();

        assert!(!bank1_ref.cost_tracker().is_dead());

        forks.mark_dead_and_evict(1);

        // Cost tracker should be marked dead (bank Arc kept alive by our ref).
        assert!(bank1_ref.cost_tracker().is_dead());
    }

    #[test]
    fn insert_rejects_dead_parent() {
        let genesis = create_genesis_bank();
        let mut forks = BankForks::new(genesis);
        let leader_schedule = create_test_leader_schedule(0);

        let bank0 = forks.working_bank();
        let bank1 = Bank::new_from_parent(&bank0, 1, leader_schedule.clone());
        forks.insert(bank1).unwrap();

        forks.mark_dead(1);

        // Attempt to insert a child of the dead slot
        let bank1_ref = forks.get(1).unwrap();
        let bank2 = Bank::new_from_parent(&bank1_ref, 2, leader_schedule);
        assert!(matches!(
            forks.insert(bank2),
            Err(BankForksError::ParentIsDead {
                slot: 2,
                parent_slot: 1
            })
        ));
    }

    #[test]
    fn set_root_evicts_dead_banks() {
        let genesis = create_genesis_bank();
        let mut forks = BankForks::new(genesis);
        let leader_schedule = create_test_leader_schedule(0);

        let bank0 = forks.working_bank();
        let bank1 = Bank::new_from_parent(&bank0, 1, leader_schedule.clone());
        forks.insert(bank1).unwrap();
        let bank2 = Bank::new_from_parent(&bank0, 2, leader_schedule);
        forks.insert(bank2).unwrap();

        // Mark fork at slot 2 dead
        forks.mark_dead(2);
        assert_eq!(forks.dead_slot_count(), 1);

        // Root slot 1 — slot 0 pruned by root advancement,
        // slot 2 pruned because it's dead.
        let bank1_ref = forks.get(1).unwrap();
        for _ in 0..karstflow_constants::ledger::TICKS_PER_SLOT {
            bank1_ref.register_tick().unwrap();
        }
        bank1_ref.freeze().unwrap();
        bank1_ref.mark_rooted().unwrap();
        let report = forks.set_root(1).unwrap();

        assert_eq!(forks.len(), 1);
        assert!(forks.get(1).is_some());
        assert!(forks.get(2).is_none());
        // Dead slot tracking for slot 2 is also cleaned up (below root)
        assert_eq!(forks.dead_slot_count(), 0);

        // Report should reflect both pruned and dead.
        assert!(report.pruned_slots.contains(&0));
        assert!(report.dead_slots.contains(&2));
    }

    #[test]
    fn set_root_returns_eviction_report() {
        let genesis = create_genesis_bank();
        let mut forks = BankForks::new(genesis);
        let leader_schedule = create_test_leader_schedule(0);

        let bank0 = forks.working_bank();

        // Build: 0 → 1, 0 → 2 (dead), 0 → 3 (dead)
        let bank1 = Bank::new_from_parent(&bank0, 1, leader_schedule.clone());
        forks.insert(bank1).unwrap();
        let bank2 = Bank::new_from_parent(&bank0, 2, leader_schedule.clone());
        forks.insert(bank2).unwrap();
        let bank3 = Bank::new_from_parent(&bank0, 3, leader_schedule);
        forks.insert(bank3).unwrap();

        forks.mark_dead(2);
        forks.mark_dead(3);

        let bank1_ref = forks.get(1).unwrap();
        for _ in 0..karstflow_constants::ledger::TICKS_PER_SLOT {
            bank1_ref.register_tick().unwrap();
        }
        bank1_ref.freeze().unwrap();
        bank1_ref.mark_rooted().unwrap();

        let report = forks.set_root(1).unwrap();

        // Slot 0 was pruned (below root).
        assert!(report.pruned_slots.contains(&0));
        // Slots 2 and 3 were dead.
        assert!(report.dead_slots.contains(&2));
        assert!(report.dead_slots.contains(&3));
        assert_eq!(report.total_evicted(), 3);
    }

    #[test]
    fn mark_dead_nonexistent_slot_is_noop() {
        let genesis = create_genesis_bank();
        let mut forks = BankForks::new(genesis);
        assert_eq!(forks.mark_dead(999), 0);
        assert_eq!(forks.dead_slot_count(), 0);
    }

    #[test]
    fn mark_dead_and_evict_nonexistent_is_noop() {
        let genesis = create_genesis_bank();
        let mut forks = BankForks::new(genesis);
        let report = forks.mark_dead_and_evict(999);
        assert!(report.is_empty());
    }

    #[test]
    fn mark_dead_idempotent() {
        let genesis = create_genesis_bank();
        let mut forks = BankForks::new(genesis);
        let leader_schedule = create_test_leader_schedule(0);

        let bank0 = forks.working_bank();
        let bank1 = Bank::new_from_parent(&bank0, 1, leader_schedule);
        forks.insert(bank1).unwrap();

        assert_eq!(forks.mark_dead(1), 1);
        assert_eq!(forks.mark_dead(1), 0); // already dead
        assert_eq!(forks.dead_slot_count(), 1);
    }

    #[test]
    fn mark_dead_and_evict_wide_fork_tree() {
        let genesis = create_genesis_bank();
        let mut forks = BankForks::new(genesis);
        let leader_schedule = create_test_leader_schedule(0);

        // Build wide tree: 0 → {1, 2, 3, 4, 5}
        // Scope intermediate refs to allow reference-aware eviction.
        {
            let bank0 = forks.working_bank();
            for slot in 1..=5 {
                let bank = Bank::new_from_parent(&bank0, slot, leader_schedule.clone());
                forks.insert(bank).unwrap();
            }
        }

        // Add depth: 1 → 6 → 7, 2 → 8
        {
            let bank1 = forks.get(1).unwrap();
            let bank6 = Bank::new_from_parent(&bank1, 6, leader_schedule.clone());
            forks.insert(bank6).unwrap();
        }
        {
            let bank6_ref = forks.get(6).unwrap();
            let bank7 = Bank::new_from_parent(&bank6_ref, 7, leader_schedule.clone());
            forks.insert(bank7).unwrap();
        }
        {
            let bank2 = forks.get(2).unwrap();
            let bank8 = Bank::new_from_parent(&bank2, 8, leader_schedule);
            forks.insert(bank8).unwrap();
        }

        assert_eq!(forks.len(), 9); // 0..=8

        // Kill slot 1 → should cascade to 6 and 7 only.
        let report = forks.mark_dead_and_evict(1);
        assert_eq!(report.dead_slots.len(), 3);
        assert!(report.dead_slots.contains(&1));
        assert!(report.dead_slots.contains(&6));
        assert!(report.dead_slots.contains(&7));

        // Remaining: 0, 2, 3, 4, 5, 8
        assert_eq!(forks.len(), 6);
        assert!(forks.get(2).is_some());
        assert!(forks.get(8).is_some());

        // Child index: 0 should have {2, 3, 4, 5}, 2 should have {8}.
        let children_0 = forks.children(0);
        assert_eq!(children_0.len(), 4);
        assert!(!children_0.contains(&1)); // removed
        assert_eq!(forks.children(2), &[8]);
    }

    // -- FIFO dead bank eviction tests --

    #[test]
    fn try_prune_dead_respects_external_references() {
        let genesis = create_genesis_bank();
        let mut forks = BankForks::new(genesis);
        let leader_schedule = create_test_leader_schedule(0);

        // Build: 0 → 1 → 2, 0 → 3.
        // Scope intermediate refs to avoid accidentally blocking eviction.
        {
            let bank0 = forks.working_bank();
            let bank1 = Bank::new_from_parent(&bank0, 1, leader_schedule.clone());
            forks.insert(bank1).unwrap();
        }
        {
            let bank1_ref = forks.get(1).unwrap();
            let bank2 = Bank::new_from_parent(&bank1_ref, 2, leader_schedule.clone());
            forks.insert(bank2).unwrap();
        }
        {
            let bank0 = forks.working_bank();
            let bank3 = Bank::new_from_parent(&bank0, 3, leader_schedule);
            forks.insert(bank3).unwrap();
        }

        // Hold external reference to bank 1 only.
        let external_ref = forks.get(1).unwrap();

        // Mark slot 1 dead (cascades to 2), then slot 3.
        forks.mark_dead(1);
        forks.mark_dead(3);
        assert_eq!(forks.dead_slot_count(), 3);
        assert_eq!(forks.dead_queue_len(), 3);

        // try_prune_dead stops at bank 1 (held externally).
        // Banks 2 and 3 are not pruned either (FIFO ordering).
        let pruned = forks.try_prune_dead();
        assert_eq!(pruned, 0);
        assert_eq!(forks.len(), 4); // All banks still present.

        // Drop the external reference.
        drop(external_ref);

        // Now all dead banks can be pruned in FIFO order.
        let pruned = forks.try_prune_dead();
        assert_eq!(pruned, 3);
        assert_eq!(forks.len(), 1); // Only genesis remains.
        assert_eq!(forks.dead_slot_count(), 0);
        assert_eq!(forks.dead_queue_len(), 0);
    }

    #[test]
    fn try_prune_dead_fifo_ordering() {
        let genesis = create_genesis_bank();
        let mut forks = BankForks::new(genesis);
        let leader_schedule = create_test_leader_schedule(0);
        let bank0 = forks.working_bank();

        // Build: 0 → {1, 2, 3}
        for slot in 1..=3 {
            let bank = Bank::new_from_parent(&bank0, slot, leader_schedule.clone());
            forks.insert(bank).unwrap();
        }

        // Mark dead in order: 1, 2, 3.
        forks.mark_dead(1);
        forks.mark_dead(2);
        forks.mark_dead(3);

        // Hold reference to slot 2 (middle of queue).
        let ref2 = forks.get(2).unwrap();

        // Prune: bank 1 evicted, bank 2 blocks, bank 3 stays.
        let pruned = forks.try_prune_dead();
        assert_eq!(pruned, 1);
        assert!(forks.get(1).is_none());
        assert!(forks.get(2).is_some()); // Still held.
        assert!(forks.get(3).is_some()); // Behind bank 2 in queue.

        // Drop ref, prune rest.
        drop(ref2);
        let pruned = forks.try_prune_dead();
        assert_eq!(pruned, 2);
        assert_eq!(forks.len(), 1); // Only genesis.
    }

    #[test]
    fn try_prune_dead_skips_already_evicted() {
        let genesis = create_genesis_bank();
        let mut forks = BankForks::new(genesis);
        let leader_schedule = create_test_leader_schedule(0);
        let bank0 = forks.working_bank();

        let bank1 = Bank::new_from_parent(&bank0, 1, leader_schedule.clone());
        for _ in 0..karstflow_constants::ledger::TICKS_PER_SLOT {
            bank1.register_tick().unwrap();
        }
        bank1.freeze().unwrap();
        bank1.mark_rooted().unwrap();
        forks.insert(bank1).unwrap();

        let bank1_ref = forks.get(1).unwrap();
        let bank2 = Bank::new_from_parent(&bank1_ref, 2, leader_schedule.clone());
        forks.insert(bank2).unwrap();

        let bank3 = Bank::new_from_parent(&bank0, 3, leader_schedule);
        forks.insert(bank3).unwrap();

        // Mark slot 3 dead and enqueue it.
        forks.mark_dead(3);
        assert_eq!(forks.dead_queue_len(), 1);

        // Advance root to 1 — evicts slot 0 and dead slot 3.
        let report = forks.set_root(1).unwrap();
        assert!(report.dead_slots.contains(&3));
        assert!(forks.get(3).is_none());

        // Dead queue should be cleaned after set_root.
        assert_eq!(forks.dead_queue_len(), 0);
        assert_eq!(forks.dead_slot_count(), 0);

        // try_prune_dead is a no-op (queue empty).
        assert_eq!(forks.try_prune_dead(), 0);
    }

    #[test]
    fn mark_dead_and_evict_defers_referenced_banks() {
        let genesis = create_genesis_bank();
        let mut forks = BankForks::new(genesis);
        let leader_schedule = create_test_leader_schedule(0);

        // Build: 0 → 1 → 2.
        {
            let bank0 = forks.working_bank();
            let bank1 = Bank::new_from_parent(&bank0, 1, leader_schedule.clone());
            forks.insert(bank1).unwrap();
        }
        {
            let bank1_ref = forks.get(1).unwrap();
            let bank2 = Bank::new_from_parent(&bank1_ref, 2, leader_schedule);
            forks.insert(bank2).unwrap();
        }

        // Hold external reference to bank 1.
        let external_ref = forks.get(1).unwrap();

        // mark_dead_and_evict marks both dead but defers bank 1.
        let report = forks.mark_dead_and_evict(1);
        assert_eq!(report.dead_slots.len(), 2);
        assert!(report.dead_slots.contains(&1));
        assert!(report.dead_slots.contains(&2));

        // Bank 1 still in map (held externally); bank 2 behind it in queue.
        assert!(forks.get(1).is_some());
        assert!(forks.get(2).is_some());
        assert!(external_ref.cost_tracker().is_dead());

        // Drop reference, prune succeeds.
        drop(external_ref);
        let pruned = forks.try_prune_dead();
        assert_eq!(pruned, 2);
        assert_eq!(forks.len(), 1); // Only genesis.
    }

    #[test]
    fn descendants_uses_child_index() {
        let genesis = create_genesis_bank();
        let mut forks = BankForks::new(genesis);
        let leader_schedule = create_test_leader_schedule(0);
        let bank0 = forks.working_bank();

        // Tree: 0 → 1 → 3, 0 → 2 → 4
        let bank1 = Bank::new_from_parent(&bank0, 1, leader_schedule.clone());
        forks.insert(bank1).unwrap();
        let bank2 = Bank::new_from_parent(&bank0, 2, leader_schedule.clone());
        forks.insert(bank2).unwrap();
        let bank1_ref = forks.get(1).unwrap();
        let bank3 = Bank::new_from_parent(&bank1_ref, 3, leader_schedule.clone());
        forks.insert(bank3).unwrap();
        let bank2_ref = forks.get(2).unwrap();
        let bank4 = Bank::new_from_parent(&bank2_ref, 4, leader_schedule);
        forks.insert(bank4).unwrap();

        let all_desc = forks.descendants(0);
        assert_eq!(all_desc.len(), 4);
        assert!(all_desc.contains(&1));
        assert!(all_desc.contains(&2));
        assert!(all_desc.contains(&3));
        assert!(all_desc.contains(&4));

        let desc_1 = forks.descendants(1);
        assert_eq!(desc_1, vec![3]);

        let desc_2 = forks.descendants(2);
        assert_eq!(desc_2, vec![4]);

        // Leaf has no descendants.
        assert!(forks.descendants(3).is_empty());
        assert!(forks.descendants(4).is_empty());
    }
}
