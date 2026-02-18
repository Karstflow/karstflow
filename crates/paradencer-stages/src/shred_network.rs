/// Shred networking stage.
///
/// Handles shreds from two sources: locally produced shreds (from block
/// production) and network-received shreds (from turbine/retransmit).
/// Manages FEC set completion, triggers Reed-Solomon reconstruction when
/// enough coding shreds arrive, and makes retransmit decisions based on
/// the turbine tree structure.
///
/// This corresponds to Firedancer's shred tile and resolv tile
/// functionality for the network-facing shred pipeline.
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Source of a received shred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShredSource {
    /// Locally produced during block production.
    Local,
    /// Received from turbine protocol.
    Turbine,
    /// Received from repair protocol.
    Repair,
}

/// A network shred with its metadata.
#[derive(Debug, Clone)]
pub struct NetworkShred {
    /// Slot this shred belongs to.
    pub slot: u64,
    /// Index within the slot.
    pub index: u32,
    /// FEC set index.
    pub fec_set_index: u32,
    /// Whether this is a coding (parity) shred.
    pub is_coding: bool,
    /// Whether this is the last shred in the slot.
    pub is_last_in_slot: bool,
    /// Raw shred bytes.
    pub data: Vec<u8>,
    /// Source of this shred.
    pub source: ShredSource,
    /// Shred signature for deduplication.
    pub signature: [u8; 64],
}

/// Result of inserting a shred into the network stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShredInsertOutcome {
    /// Shred accepted, FEC set still incomplete.
    Accepted,
    /// Shred completed a FEC set (ready for assembly).
    FecSetComplete { fec_set_index: u32 },
    /// Shred triggered FEC recovery (partial data + enough coding).
    FecRecoverable { fec_set_index: u32 },
    /// Duplicate shred (already have it).
    Duplicate,
    /// Shred for a slot we're not tracking.
    Ignored,
    /// Shred is from a slot that's already been finalized/pruned.
    TooOld,
}

/// A retransmit decision for a shred.
#[derive(Debug, Clone)]
pub struct RetransmitDecision {
    /// The shred to retransmit.
    pub shred_data: Vec<u8>,
    /// Destination addresses (index into turbine tree neighbors).
    pub destination_indices: Vec<u16>,
    /// The slot this shred belongs to.
    pub slot: u64,
}

/// Tracks the state of a single FEC set.
#[derive(Debug)]
struct FecSetState {
    /// Expected number of data shreds in this FEC set.
    expected_data: u32,
    /// Expected number of coding shreds in this FEC set.
    expected_coding: u32,
    /// Set of received data shred indices.
    received_data: HashSet<u32>,
    /// Set of received coding shred indices.
    received_coding: HashSet<u32>,
}

impl FecSetState {
    fn new(expected_data: u32, expected_coding: u32) -> Self {
        Self {
            expected_data,
            expected_coding,
            received_data: HashSet::new(),
            received_coding: HashSet::new(),
        }
    }

    fn total_received(&self) -> u32 {
        self.received_data.len() as u32 + self.received_coding.len() as u32
    }

    fn is_complete(&self) -> bool {
        self.received_data.len() as u32 >= self.expected_data
    }

    fn is_recoverable(&self) -> bool {
        // Reed-Solomon can recover if we have at least `expected_data` shreds total
        self.total_received() >= self.expected_data && !self.is_complete()
    }
}

/// Tracks all FEC sets for a single slot.
#[derive(Debug)]
struct SlotState {
    fec_sets: HashMap<u32, FecSetState>,
    seen_signatures: HashSet<[u8; 64]>,
    last_shred_seen: bool,
}

impl SlotState {
    fn new() -> Self {
        Self {
            fec_sets: HashMap::new(),
            seen_signatures: HashSet::new(),
            last_shred_seen: false,
        }
    }
}

/// Configuration for the shred networking stage.
#[derive(Debug, Clone)]
pub struct ShredNetworkConfig {
    /// Maximum number of slots to track simultaneously.
    pub max_tracked_slots: usize,
    /// Default FEC set size (data shreds per set).
    pub default_data_shreds_per_fec: u32,
    /// Default FEC set coding shreds per set.
    pub default_coding_shreds_per_fec: u32,
    /// This validator's position in the turbine tree (for retransmit).
    pub turbine_layer: u16,
    /// Number of neighbors in our turbine layer.
    pub turbine_neighbor_count: u16,
    /// Minimum slot we'll accept shreds for.
    pub min_slot: u64,
}

impl Default for ShredNetworkConfig {
    fn default() -> Self {
        Self {
            max_tracked_slots: 512,
            default_data_shreds_per_fec: 32,
            default_coding_shreds_per_fec: 32,
            turbine_layer: 0,
            turbine_neighbor_count: 0,
            min_slot: 0,
        }
    }
}

/// Statistics for the shred networking stage.
#[derive(Debug, Default)]
pub struct ShredNetworkStats {
    pub shreds_received: AtomicU64,
    pub shreds_from_turbine: AtomicU64,
    pub shreds_from_repair: AtomicU64,
    pub shreds_local: AtomicU64,
    pub shreds_duplicate: AtomicU64,
    pub fec_sets_completed: AtomicU64,
    pub fec_sets_recovered: AtomicU64,
    pub retransmits_sent: AtomicU64,
    pub slots_completed: AtomicU64,
}

impl ShredNetworkStats {
    pub fn snapshot(&self) -> ShredNetworkStatsSnapshot {
        ShredNetworkStatsSnapshot {
            shreds_received: self.shreds_received.load(Ordering::Relaxed),
            shreds_from_turbine: self.shreds_from_turbine.load(Ordering::Relaxed),
            shreds_from_repair: self.shreds_from_repair.load(Ordering::Relaxed),
            shreds_local: self.shreds_local.load(Ordering::Relaxed),
            shreds_duplicate: self.shreds_duplicate.load(Ordering::Relaxed),
            fec_sets_completed: self.fec_sets_completed.load(Ordering::Relaxed),
            fec_sets_recovered: self.fec_sets_recovered.load(Ordering::Relaxed),
            retransmits_sent: self.retransmits_sent.load(Ordering::Relaxed),
            slots_completed: self.slots_completed.load(Ordering::Relaxed),
        }
    }
}

/// Point-in-time statistics snapshot.
#[derive(Debug, Clone, Default)]
pub struct ShredNetworkStatsSnapshot {
    pub shreds_received: u64,
    pub shreds_from_turbine: u64,
    pub shreds_from_repair: u64,
    pub shreds_local: u64,
    pub shreds_duplicate: u64,
    pub fec_sets_completed: u64,
    pub fec_sets_recovered: u64,
    pub retransmits_sent: u64,
    pub slots_completed: u64,
}

/// The shred networking stage.
pub struct ShredNetworkStage {
    config: ShredNetworkConfig,
    /// Per-slot tracking state.
    slots: HashMap<u64, SlotState>,
    /// LRU order for slot eviction.
    slot_order: VecDeque<u64>,
    /// Pending retransmit decisions.
    pending_retransmits: Vec<RetransmitDecision>,
    /// Statistics.
    stats: Arc<ShredNetworkStats>,
}

impl ShredNetworkStage {
    /// Create a new shred networking stage with default config.
    pub fn new() -> Self {
        Self::with_config(ShredNetworkConfig::default())
    }

    /// Create a new shred networking stage with the given config.
    pub fn with_config(config: ShredNetworkConfig) -> Self {
        Self {
            slots: HashMap::new(),
            slot_order: VecDeque::new(),
            pending_retransmits: Vec::new(),
            config,
            stats: Arc::new(ShredNetworkStats::default()),
        }
    }

    /// Get a shared reference to the statistics.
    pub fn stats(&self) -> Arc<ShredNetworkStats> {
        Arc::clone(&self.stats)
    }

    /// Insert a shred into the stage. Returns the insertion outcome.
    pub fn insert_shred(&mut self, shred: NetworkShred) -> ShredInsertOutcome {
        self.stats.shreds_received.fetch_add(1, Ordering::Relaxed);

        match shred.source {
            ShredSource::Turbine => {
                self.stats
                    .shreds_from_turbine
                    .fetch_add(1, Ordering::Relaxed);
            }
            ShredSource::Repair => {
                self.stats
                    .shreds_from_repair
                    .fetch_add(1, Ordering::Relaxed);
            }
            ShredSource::Local => {
                self.stats.shreds_local.fetch_add(1, Ordering::Relaxed);
            }
        }

        // Check minimum slot.
        if shred.slot < self.config.min_slot {
            return ShredInsertOutcome::TooOld;
        }

        // Ensure slot state exists.
        self.ensure_slot_tracked(shred.slot);

        // Schedule retransmit for turbine shreds BEFORE borrowing slot state.
        let should_retransmit =
            shred.source == ShredSource::Turbine && self.config.turbine_neighbor_count > 0;
        if should_retransmit {
            self.schedule_retransmit(shred.slot, &shred.data);
        }

        let default_data = self.config.default_data_shreds_per_fec;
        let default_coding = self.config.default_coding_shreds_per_fec;

        let slot_state = self.slots.get_mut(&shred.slot).unwrap();

        // Dedup by signature.
        if !slot_state.seen_signatures.insert(shred.signature) {
            self.stats.shreds_duplicate.fetch_add(1, Ordering::Relaxed);
            return ShredInsertOutcome::Duplicate;
        }

        if shred.is_last_in_slot {
            slot_state.last_shred_seen = true;
        }

        // Get or create FEC set state.
        let fec = slot_state
            .fec_sets
            .entry(shred.fec_set_index)
            .or_insert_with(|| FecSetState::new(default_data, default_coding));

        // Insert shred into FEC set.
        if shred.is_coding {
            fec.received_coding.insert(shred.index);
        } else {
            fec.received_data.insert(shred.index);
        }

        // Check FEC set status.
        if fec.is_complete() {
            self.stats
                .fec_sets_completed
                .fetch_add(1, Ordering::Relaxed);
            ShredInsertOutcome::FecSetComplete {
                fec_set_index: shred.fec_set_index,
            }
        } else if fec.is_recoverable() {
            self.stats
                .fec_sets_recovered
                .fetch_add(1, Ordering::Relaxed);
            ShredInsertOutcome::FecRecoverable {
                fec_set_index: shred.fec_set_index,
            }
        } else {
            ShredInsertOutcome::Accepted
        }
    }

    /// Drain pending retransmit decisions.
    pub fn drain_retransmits(&mut self) -> Vec<RetransmitDecision> {
        std::mem::take(&mut self.pending_retransmits)
    }

    /// Check if a slot has received its last shred.
    pub fn is_slot_complete(&self, slot: u64) -> bool {
        self.slots
            .get(&slot)
            .map(|s| s.last_shred_seen)
            .unwrap_or(false)
    }

    /// Number of tracked slots.
    pub fn tracked_slot_count(&self) -> usize {
        self.slots.len()
    }

    /// Number of FEC sets tracked for a slot.
    pub fn fec_set_count(&self, slot: u64) -> usize {
        self.slots.get(&slot).map(|s| s.fec_sets.len()).unwrap_or(0)
    }

    /// Set the minimum slot (prune older slots).
    pub fn set_min_slot(&mut self, min_slot: u64) {
        self.config.min_slot = min_slot;

        // Prune slots below the new minimum.
        let old_slots: Vec<u64> = self
            .slots
            .keys()
            .filter(|&&s| s < min_slot)
            .copied()
            .collect();

        for slot in old_slots {
            self.slots.remove(&slot);
        }
        self.slot_order.retain(|&s| s >= min_slot);
    }

    /// Ensure a slot is tracked, evicting the oldest if at capacity.
    fn ensure_slot_tracked(&mut self, slot: u64) {
        if self.slots.contains_key(&slot) {
            return;
        }

        // Evict oldest if at capacity.
        while self.slots.len() >= self.config.max_tracked_slots {
            if let Some(oldest) = self.slot_order.pop_front() {
                self.slots.remove(&oldest);
            } else {
                break;
            }
        }

        self.slots.insert(slot, SlotState::new());
        self.slot_order.push_back(slot);
    }

    /// Schedule a retransmit to turbine neighbors.
    fn schedule_retransmit(&mut self, slot: u64, data: &[u8]) {
        let destinations: Vec<u16> = (0..self.config.turbine_neighbor_count).collect();

        self.pending_retransmits.push(RetransmitDecision {
            shred_data: data.to_vec(),
            destination_indices: destinations,
            slot,
        });

        self.stats.retransmits_sent.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_data_shred(slot: u64, index: u32, fec_set: u32) -> NetworkShred {
        let mut sig = [0u8; 64];
        sig[..8].copy_from_slice(&slot.to_le_bytes());
        sig[8..12].copy_from_slice(&index.to_le_bytes());
        NetworkShred {
            slot,
            index,
            fec_set_index: fec_set,
            is_coding: false,
            is_last_in_slot: false,
            data: vec![0u8; 1228],
            source: ShredSource::Turbine,
            signature: sig,
        }
    }

    fn make_coding_shred(slot: u64, index: u32, fec_set: u32) -> NetworkShred {
        let mut sig = [0u8; 64];
        sig[..8].copy_from_slice(&slot.to_le_bytes());
        sig[8..12].copy_from_slice(&index.to_le_bytes());
        sig[12] = 1; // differentiate from data shred sig
        NetworkShred {
            slot,
            index,
            fec_set_index: fec_set,
            is_coding: true,
            is_last_in_slot: false,
            data: vec![0u8; 1228],
            source: ShredSource::Turbine,
            signature: sig,
        }
    }

    #[test]
    fn insert_single_shred() {
        let config = ShredNetworkConfig {
            default_data_shreds_per_fec: 4,
            default_coding_shreds_per_fec: 4,
            ..Default::default()
        };
        let mut stage = ShredNetworkStage::with_config(config);

        let shred = make_data_shred(100, 0, 0);
        let outcome = stage.insert_shred(shred);
        assert_eq!(outcome, ShredInsertOutcome::Accepted);
        assert_eq!(stage.tracked_slot_count(), 1);
    }

    #[test]
    fn fec_set_completes_with_enough_data() {
        let config = ShredNetworkConfig {
            default_data_shreds_per_fec: 2,
            default_coding_shreds_per_fec: 2,
            ..Default::default()
        };
        let mut stage = ShredNetworkStage::with_config(config);

        let s1 = make_data_shred(100, 0, 0);
        assert_eq!(stage.insert_shred(s1), ShredInsertOutcome::Accepted);

        let s2 = make_data_shred(100, 1, 0);
        let outcome = stage.insert_shred(s2);
        assert!(matches!(outcome, ShredInsertOutcome::FecSetComplete { .. }));
    }

    #[test]
    fn fec_recovery_with_coding_shreds() {
        let config = ShredNetworkConfig {
            default_data_shreds_per_fec: 3,
            default_coding_shreds_per_fec: 3,
            ..Default::default()
        };
        let mut stage = ShredNetworkStage::with_config(config);

        // Insert 2 data shreds (missing 1) + 1 coding shred = 3 total = recoverable
        stage.insert_shred(make_data_shred(100, 0, 0));
        stage.insert_shred(make_data_shred(100, 1, 0));

        let coding = make_coding_shred(100, 0, 0);
        let outcome = stage.insert_shred(coding);
        assert!(matches!(outcome, ShredInsertOutcome::FecRecoverable { .. }));
    }

    #[test]
    fn duplicate_shred_rejected() {
        let mut stage = ShredNetworkStage::new();

        let shred = make_data_shred(100, 0, 0);
        stage.insert_shred(shred.clone());

        let outcome = stage.insert_shred(shred);
        assert_eq!(outcome, ShredInsertOutcome::Duplicate);
    }

    #[test]
    fn old_slot_rejected() {
        let config = ShredNetworkConfig {
            min_slot: 50,
            ..Default::default()
        };
        let mut stage = ShredNetworkStage::with_config(config);

        let shred = make_data_shred(10, 0, 0);
        assert_eq!(stage.insert_shred(shred), ShredInsertOutcome::TooOld);
    }

    #[test]
    fn retransmit_scheduled_for_turbine() {
        let config = ShredNetworkConfig {
            turbine_neighbor_count: 3,
            ..Default::default()
        };
        let mut stage = ShredNetworkStage::with_config(config);

        let shred = make_data_shred(100, 0, 0);
        stage.insert_shred(shred);

        let retransmits = stage.drain_retransmits();
        assert_eq!(retransmits.len(), 1);
        assert_eq!(retransmits[0].destination_indices.len(), 3);
    }

    #[test]
    fn no_retransmit_for_local_shreds() {
        let config = ShredNetworkConfig {
            turbine_neighbor_count: 3,
            ..Default::default()
        };
        let mut stage = ShredNetworkStage::with_config(config);

        let mut shred = make_data_shred(100, 0, 0);
        shred.source = ShredSource::Local;
        stage.insert_shred(shred);

        let retransmits = stage.drain_retransmits();
        assert!(retransmits.is_empty());
    }

    #[test]
    fn slot_eviction_at_capacity() {
        let config = ShredNetworkConfig {
            max_tracked_slots: 2,
            ..Default::default()
        };
        let mut stage = ShredNetworkStage::with_config(config);

        stage.insert_shred(make_data_shred(1, 0, 0));
        stage.insert_shred(make_data_shred(2, 0, 0));
        assert_eq!(stage.tracked_slot_count(), 2);

        // Third slot should evict the first.
        stage.insert_shred(make_data_shred(3, 0, 0));
        assert_eq!(stage.tracked_slot_count(), 2);
        assert!(!stage.slots.contains_key(&1));
    }

    #[test]
    fn set_min_slot_prunes() {
        let mut stage = ShredNetworkStage::new();
        stage.insert_shred(make_data_shred(10, 0, 0));
        stage.insert_shred(make_data_shred(20, 0, 0));
        stage.insert_shred(make_data_shred(30, 0, 0));
        assert_eq!(stage.tracked_slot_count(), 3);

        stage.set_min_slot(25);
        assert_eq!(stage.tracked_slot_count(), 1);
        assert!(stage.slots.contains_key(&30));
    }

    #[test]
    fn last_in_slot_detection() {
        let mut stage = ShredNetworkStage::new();

        let mut shred = make_data_shred(100, 0, 0);
        shred.is_last_in_slot = true;
        stage.insert_shred(shred);

        assert!(stage.is_slot_complete(100));
        assert!(!stage.is_slot_complete(101));
    }

    #[test]
    fn stats_tracking() {
        let config = ShredNetworkConfig {
            turbine_neighbor_count: 1,
            ..Default::default()
        };
        let mut stage = ShredNetworkStage::with_config(config);

        stage.insert_shred(make_data_shred(100, 0, 0)); // turbine
        let mut repair_shred = make_data_shred(100, 1, 0);
        repair_shred.source = ShredSource::Repair;
        // Give it a unique signature
        repair_shred.signature[12] = 99;
        stage.insert_shred(repair_shred);

        let snap = stage.stats().snapshot();
        assert_eq!(snap.shreds_received, 2);
        assert_eq!(snap.shreds_from_turbine, 1);
        assert_eq!(snap.shreds_from_repair, 1);
        assert_eq!(snap.retransmits_sent, 1); // only turbine triggers retransmit
    }
}
