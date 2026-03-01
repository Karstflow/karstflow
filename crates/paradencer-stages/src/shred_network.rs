/// Shred networking stage.
///
/// Handles shreds from two sources: locally produced shreds (from block
/// production) and network-received shreds (from turbine/retransmit).
/// Manages FEC set completion via a pre-allocated resolver pool, triggers
/// Reed-Solomon reconstruction when enough coding shreds arrive, and
/// makes retransmit decisions based on the turbine tree structure.
use crate::fec_resolver::{EquivocationProof, FecResolverPool, FecSetKey, ResolverInsertResult};
use crate::shred_verifier::{self, LeaderLookup, ShredVerifyResult};
use paradencer_crypto::reed_solomon::FecReconstructor;
use paradencer_mesh::{DualReceiveError, DualReceiver, DualSender};
use paradencer_runtime::{RuntimeError, RuntimeResult, Service, ServiceContext};
use paradencer_types::shred::{
    CodingShredHeader, DataShredHeader, Shred, ShredCommonHeader, ShredVariant,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

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

/// A network shred with its source metadata.
#[derive(Debug, Clone)]
pub struct NetworkShred {
    /// The parsed shred.
    pub shred: Shred,
    /// Source of this shred.
    pub source: ShredSource,
}

/// Result of inserting a shred into the network stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShredInsertOutcome {
    /// Shred accepted, FEC set still incomplete.
    Accepted,
    /// Shred completed a FEC set (all data shreds received, ready for assembly).
    FecSetComplete { fec_set_index: u32 },
    /// Shred triggered FEC recovery (partial data + enough coding).
    FecRecoverable { fec_set_index: u32 },
    /// Duplicate shred (already have it).
    Duplicate,
    /// Shred for a slot we're not tracking.
    Ignored,
    /// Shred is from a slot that's already been finalized/pruned.
    TooOld,
    /// Shred has an invalid or zero Ed25519 signature.
    InvalidSignature,
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

/// A completed FEC set with all data shreds resolved.
#[derive(Debug, Clone)]
pub struct CompletedFecSet {
    /// Slot number.
    pub slot: u64,
    /// FEC set index within the slot.
    pub fec_set_index: u32,
    /// All data shreds in order (index-sorted).
    pub data_shreds: Vec<Shred>,
    /// Whether Reed-Solomon reconstruction was needed.
    pub was_recovered: bool,
}

/// Tracks per-slot metadata (signature dedup and last-shred-seen flag).
/// FEC set buffer management is handled by the FecResolverPool.
#[derive(Debug)]
struct SlotState {
    /// Per-slot shred signature dedup set.
    seen_signatures: HashSet<[u8; 64]>,
    /// Whether the last-in-slot flag has been seen.
    last_shred_seen: bool,
    /// FEC set indices seen for this slot (for flush_complete_slots).
    fec_set_indices: HashSet<u32>,
}

impl SlotState {
    fn new() -> Self {
        Self {
            seen_signatures: HashSet::new(),
            last_shred_seen: false,
            fec_set_indices: HashSet::new(),
        }
    }
}

/// Configuration for the shred networking stage.
#[derive(Debug, Clone)]
pub struct ShredNetworkConfig {
    /// Maximum number of slots to track simultaneously.
    pub max_tracked_slots: usize,
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
    pub shreds_signature_invalid: AtomicU64,
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
            shreds_signature_invalid: self.shreds_signature_invalid.load(Ordering::Relaxed),
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
    pub shreds_signature_invalid: u64,
    pub fec_sets_completed: u64,
    pub fec_sets_recovered: u64,
    pub retransmits_sent: u64,
    pub slots_completed: u64,
}

/// The shred networking stage.
pub struct ShredNetworkStage {
    config: ShredNetworkConfig,
    /// Per-slot tracking state (signature dedup, last-shred-seen).
    slots: HashMap<u64, SlotState>,
    /// LRU order for slot eviction.
    slot_order: VecDeque<u64>,
    /// Pre-allocated FEC set resolver pool with depth-controlled lifecycle.
    resolver_pool: FecResolverPool,
    /// Pending retransmit decisions.
    pending_retransmits: Vec<RetransmitDecision>,
    /// Completed FEC sets waiting to be drained.
    pending_completed: Vec<CompletedFecSet>,
    /// Optional leader pubkey lookup for signature verification.
    /// When `None`, signature verification is skipped.
    leader_lookup: Option<Arc<dyn LeaderLookup>>,
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
            resolver_pool: FecResolverPool::with_defaults(),
            pending_retransmits: Vec::new(),
            pending_completed: Vec::new(),
            leader_lookup: None,
            config,
            stats: Arc::new(ShredNetworkStats::default()),
        }
    }

    /// Set the leader lookup for signature verification.
    pub fn set_leader_lookup(&mut self, lookup: Arc<dyn LeaderLookup>) {
        self.leader_lookup = Some(lookup);
    }

    /// Get a shared reference to the statistics.
    pub fn stats(&self) -> Arc<ShredNetworkStats> {
        Arc::clone(&self.stats)
    }

    /// Get a shared reference to the FEC resolver atomic stats.
    pub fn fec_resolver_stats(&self) -> Arc<crate::fec_resolver::AtomicFecResolverStats> {
        Arc::clone(&self.resolver_pool.stats)
    }

    /// Insert a shred into the stage. Returns the insertion outcome.
    pub fn insert_shred(&mut self, net_shred: NetworkShred) -> ShredInsertOutcome {
        self.stats.shreds_received.fetch_add(1, Ordering::Relaxed);

        match net_shred.source {
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

        let slot = net_shred.shred.slot();
        let fec_set_index = net_shred.shred.fec_set_index();

        // Check minimum slot.
        if slot < self.config.min_slot {
            return ShredInsertOutcome::TooOld;
        }

        // Verify Ed25519 signature when a leader lookup is available.
        // Local shreds (self-produced) skip verification.
        if net_shred.source != ShredSource::Local {
            if let Some(ref lookup) = self.leader_lookup {
                match lookup.leader_for_slot(slot) {
                    Some(leader_pubkey) => {
                        let result = shred_verifier::verify_shred(&net_shred.shred, &leader_pubkey);
                        match result {
                            ShredVerifyResult::Valid | ShredVerifyResult::Deferred => {}
                            ShredVerifyResult::Invalid
                            | ShredVerifyResult::ZeroSignature
                            | ShredVerifyResult::UnknownLeader
                            | ShredVerifyResult::LegacyRejected => {
                                self.stats
                                    .shreds_signature_invalid
                                    .fetch_add(1, Ordering::Relaxed);
                                return ShredInsertOutcome::InvalidSignature;
                            }
                        }
                    }
                    None => {
                        // Leader unknown — skip verification for this slot.
                        // This can happen for slots far in the future.
                    }
                }
            }
        }

        // Ensure slot state exists.
        self.ensure_slot_tracked(slot);

        // Schedule retransmit for turbine shreds BEFORE borrowing slot state.
        // Use the original wire-format bytes (raw) when available so the
        // retransmitted packet is a valid shred. Fall back to payload if raw
        // is absent (e.g. locally constructed shreds).
        let should_retransmit =
            net_shred.source == ShredSource::Turbine && self.config.turbine_neighbor_count > 0;
        if should_retransmit {
            let wire_bytes = net_shred
                .shred
                .raw
                .as_deref()
                .unwrap_or(&net_shred.shred.payload);
            self.schedule_retransmit(slot, wire_bytes);
        }

        let slot_state = self.slots.get_mut(&slot).unwrap();

        // Dedup by signature.
        if !slot_state
            .seen_signatures
            .insert(net_shred.shred.common_header.signature)
        {
            self.stats.shreds_duplicate.fetch_add(1, Ordering::Relaxed);
            return ShredInsertOutcome::Duplicate;
        }

        if net_shred.shred.is_last_in_slot() {
            slot_state.last_shred_seen = true;
        }

        // Track FEC set index for this slot (used by flush_complete_slots).
        slot_state.fec_set_indices.insert(fec_set_index);

        // Route shred insertion through the pre-allocated resolver pool.
        let pool_result = if net_shred.shred.is_coding() {
            if let Some(coding_header) = net_shred.shred.coding_header() {
                let position = coding_header.position as u32;
                self.resolver_pool.insert_coding_shred(
                    slot,
                    fec_set_index,
                    position,
                    coding_header.num_data_shreds,
                    coding_header.num_coding_shreds,
                    net_shred.shred,
                )
            } else {
                return ShredInsertOutcome::Accepted;
            }
        } else {
            let relative_index = net_shred.shred.index().saturating_sub(fec_set_index);
            self.resolver_pool.insert_data_shred(
                slot,
                fec_set_index,
                relative_index,
                net_shred.shred,
            )
        };

        // Map pool result to stage outcome.
        match pool_result {
            ResolverInsertResult::Complete => {
                self.stats
                    .fec_sets_completed
                    .fetch_add(1, Ordering::Relaxed);

                let key = FecSetKey {
                    slot,
                    fec_set_index,
                };
                let completed =
                    Self::extract_completed_from_pool(&mut self.resolver_pool, key, false);
                self.pending_completed.push(completed);

                ShredInsertOutcome::FecSetComplete { fec_set_index }
            }
            ResolverInsertResult::Recoverable => {
                self.stats
                    .fec_sets_recovered
                    .fetch_add(1, Ordering::Relaxed);

                let key = FecSetKey {
                    slot,
                    fec_set_index,
                };
                if let Some(completed) =
                    Self::attempt_recovery_from_pool(&mut self.resolver_pool, key)
                {
                    self.pending_completed.push(completed);
                }

                ShredInsertOutcome::FecRecoverable { fec_set_index }
            }
            ResolverInsertResult::DuplicateFecSet => {
                self.stats.shreds_duplicate.fetch_add(1, Ordering::Relaxed);
                ShredInsertOutcome::Duplicate
            }
            ResolverInsertResult::DuplicateShred => {
                // Already tracked by slot-level signature dedup above; pool caught
                // a position-level duplicate that had a different signature.
                ShredInsertOutcome::Accepted
            }
            ResolverInsertResult::Equivocation => {
                // Different shred at the same (slot, index, position).
                // The equivocation proof is stored in the resolver pool.
                tracing::warn!(
                    slot,
                    fec_set_index,
                    "equivocation detected: conflicting shred at same position"
                );
                ShredInsertOutcome::Duplicate
            }
            ResolverInsertResult::Accepted => ShredInsertOutcome::Accepted,
        }
    }

    /// Flush unresolved FEC sets for slots where the last shred has been seen.
    ///
    /// When all shreds for a slot have arrived but some FEC sets lack coding
    /// shreds (so FEC params are unknown), emit those data shreds directly.
    /// This handles data-only streams and ensures block assembly can proceed
    /// even without coding shreds for Reed-Solomon recovery.
    pub fn flush_complete_slots(&mut self) {
        let complete_slots: Vec<(u64, Vec<u32>)> = self
            .slots
            .iter()
            .filter(|(_, state)| state.last_shred_seen)
            .map(|(&slot, state)| (slot, state.fec_set_indices.iter().copied().collect()))
            .collect();

        for (slot, fec_indices) in complete_slots {
            for fec_set_index in fec_indices {
                let key = FecSetKey {
                    slot,
                    fec_set_index,
                };
                // Check if the FEC set is still in-progress (not yet resolved).
                if let Some(view) = self.resolver_pool.get_buffer(&key) {
                    if !view.resolved && !view.data_shreds.is_empty() {
                        self.stats
                            .fec_sets_completed
                            .fetch_add(1, Ordering::Relaxed);
                        let completed =
                            Self::extract_completed_from_pool(&mut self.resolver_pool, key, false);
                        self.pending_completed.push(completed);
                    }
                }
            }
        }
    }

    /// Drain pending retransmit decisions.
    pub fn drain_retransmits(&mut self) -> Vec<RetransmitDecision> {
        std::mem::take(&mut self.pending_retransmits)
    }

    /// Drain completed FEC sets.
    pub fn drain_completed_sets(&mut self) -> Vec<CompletedFecSet> {
        std::mem::take(&mut self.pending_completed)
    }

    /// Drain equivocation proofs from the FEC resolver pool.
    pub fn drain_equivocations(&mut self) -> Vec<EquivocationProof> {
        self.resolver_pool.drain_equivocation_proofs()
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
        self.slots
            .get(&slot)
            .map(|s| s.fec_set_indices.len())
            .unwrap_or(0)
    }

    /// Number of data shreds received for a specific FEC set.
    pub fn fec_data_count(&self, slot: u64, fec_set_index: u32) -> usize {
        let key = FecSetKey {
            slot,
            fec_set_index,
        };
        self.resolver_pool
            .get_buffer(&key)
            .map(|v| v.data_shreds.len())
            .unwrap_or(0)
    }

    /// Number of coding shreds received for a specific FEC set.
    pub fn fec_coding_count(&self, slot: u64, fec_set_index: u32) -> usize {
        let key = FecSetKey {
            slot,
            fec_set_index,
        };
        self.resolver_pool
            .get_buffer(&key)
            .map(|v| v.coding_shreds.len())
            .unwrap_or(0)
    }

    /// Get the FEC resolver pool for inspection.
    pub fn resolver_pool(&self) -> &FecResolverPool {
        &self.resolver_pool
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

        // Also prune the resolver pool.
        self.resolver_pool.prune_slots_below(min_slot);
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

    /// Extract a completed FEC set from the resolver pool, mark it completed,
    /// and return the assembled CompletedFecSet.
    fn extract_completed_from_pool(
        pool: &mut FecResolverPool,
        key: FecSetKey,
        was_recovered: bool,
    ) -> CompletedFecSet {
        // Read data shreds from the pool buffer before marking completed.
        let data_shreds = if let Some(view) = pool.get_buffer(&key) {
            let mut indices: Vec<u32> = view.data_shreds.keys().copied().collect();
            indices.sort_unstable();
            indices
                .into_iter()
                .filter_map(|idx| view.data_shreds.get(&idx).cloned())
                .collect()
        } else {
            Vec::new()
        };

        pool.mark_completed(key);

        CompletedFecSet {
            slot: key.slot,
            fec_set_index: key.fec_set_index,
            data_shreds,
            was_recovered,
        }
    }

    /// Attempt Reed-Solomon recovery on a FEC set in the resolver pool.
    fn attempt_recovery_from_pool(
        pool: &mut FecResolverPool,
        key: FecSetKey,
    ) -> Option<CompletedFecSet> {
        // First, gather all info we need from the buffer view.
        let (
            num_data,
            num_coding,
            shard_size,
            data_array,
            coding_array,
            ref_version,
            ref_variant_byte,
            ref_parent_offset,
        ) = {
            let view = pool.get_buffer(&key)?;
            let num_data = view.num_data as usize;
            let num_coding = view.num_coding as usize;

            let shard_size = view
                .data_shreds
                .values()
                .next()
                .or_else(|| view.coding_shreds.values().next())
                .map(|s| s.payload.len())?;

            let data_array: Vec<Option<Vec<u8>>> = (0..num_data as u32)
                .map(|rel_idx| {
                    view.data_shreds.get(&rel_idx).map(|s| {
                        let mut payload = s.payload.clone();
                        payload.resize(shard_size, 0);
                        payload
                    })
                })
                .collect();

            let coding_array: Vec<Option<Vec<u8>>> = (0..num_coding as u32)
                .map(|pos| {
                    view.coding_shreds.get(&pos).map(|s| {
                        let mut payload = s.payload.clone();
                        payload.resize(shard_size, 0);
                        payload
                    })
                })
                .collect();

            let ref_shred = view
                .data_shreds
                .values()
                .next()
                .or_else(|| view.coding_shreds.values().next())?;

            let ref_version = ref_shred.common_header.version;
            let ref_variant_byte = ref_shred.common_header.variant;
            let ref_parent_offset = ref_shred
                .data_header()
                .map(|h| h.parent_offset)
                .unwrap_or(1);

            (
                num_data,
                num_coding,
                shard_size,
                data_array,
                coding_array,
                ref_version,
                ref_variant_byte,
                ref_parent_offset,
            )
        };

        let reconstructor = FecReconstructor::new(num_data, num_coding).ok()?;
        let result = reconstructor.reconstruct(data_array, coding_array).ok()?;

        // Insert recovered data shreds back into the pool buffer.
        if let Some(view_mut) = pool.get_buffer_mut(&key) {
            for (rel_idx, maybe_recovered) in result.data_shreds.into_iter().enumerate() {
                if let Some(payload) = maybe_recovered {
                    let abs_index = key.fec_set_index + rel_idx as u32;
                    let recovered_shred = Shred::new(
                        ShredCommonHeader {
                            signature: [0u8; 64],
                            variant: ref_variant_byte,
                            slot: key.slot,
                            index: abs_index,
                            version: ref_version,
                            fec_set_index: key.fec_set_index,
                        },
                        ShredVariant::LegacyData(DataShredHeader {
                            parent_offset: ref_parent_offset,
                            flags: 0,
                            size: payload.len() as u16,
                        }),
                        payload,
                    );
                    view_mut
                        .data_shreds
                        .entry(rel_idx as u32)
                        .or_insert(recovered_shred);
                }
            }
        }

        Some(Self::extract_completed_from_pool(pool, key, true))
    }
}

// ---------------------------------------------------------------------------
// ShredNetworkService — Service wrapper for pipeline integration
// ---------------------------------------------------------------------------

/// Service wrapper that drives ShredNetworkStage from mesh channels.
///
/// Receives parsed shreds from ShredFilter, feeds them into the FEC resolver,
/// and pushes completed/recovered FEC sets to ShredCollector.
/// Also drains retransmit decisions for turbine broadcasting.
pub struct ShredNetworkService {
    stage: ShredNetworkStage,
    /// Parsed shreds from the ingress filter via dual-mode link.
    incoming_shreds: DualReceiver<Shred>,
    /// Completed FEC sets sent to ShredCollector for block assembly.
    completed_output: DualSender<CompletedFecSet>,
    /// Completed FEC sets sent to ShredStoreService for blockstore persistence.
    store_output: Option<DualSender<CompletedFecSet>>,
    /// Retransmit decisions sent to turbine broadcaster.
    retransmit_output: Option<DualSender<RetransmitDecision>>,
    /// Equivocation proofs sent to consensus for slashing evidence.
    equivocation_output: Option<DualSender<EquivocationProof>>,
    /// Default source for incoming shreds (typically Turbine).
    default_source: ShredSource,
}

impl ShredNetworkService {
    /// Create a new shred network service with dual-mode shred input.
    pub fn new(
        config: ShredNetworkConfig,
        incoming_shreds: DualReceiver<Shred>,
        completed_output: DualSender<CompletedFecSet>,
    ) -> Self {
        Self {
            stage: ShredNetworkStage::with_config(config),
            incoming_shreds,
            completed_output,
            store_output: None,
            retransmit_output: None,
            equivocation_output: None,
            default_source: ShredSource::Turbine,
        }
    }

    /// Set the retransmit output channel for turbine broadcasting.
    pub fn with_retransmit_output(mut self, output: DualSender<RetransmitDecision>) -> Self {
        self.retransmit_output = Some(output);
        self
    }

    /// Set the store output channel for blockstore persistence.
    pub fn with_store_output(mut self, output: DualSender<CompletedFecSet>) -> Self {
        self.store_output = Some(output);
        self
    }

    /// Set the equivocation output channel for reporting shred conflicts.
    pub fn with_equivocation_output(mut self, output: DualSender<EquivocationProof>) -> Self {
        self.equivocation_output = Some(output);
        self
    }

    /// Set the leader lookup for shred signature verification.
    pub fn with_leader_lookup(mut self, lookup: Arc<dyn LeaderLookup>) -> Self {
        self.stage.set_leader_lookup(lookup);
        self
    }

    /// Set the default shred source (for classifying incoming shreds).
    pub fn with_default_source(mut self, source: ShredSource) -> Self {
        self.default_source = source;
        self
    }

    /// Get a shared reference to the underlying statistics.
    pub fn stats(&self) -> Arc<ShredNetworkStats> {
        self.stage.stats()
    }

    /// Get a shared reference to the FEC resolver atomic stats.
    pub fn fec_resolver_stats(&self) -> Arc<crate::fec_resolver::AtomicFecResolverStats> {
        self.stage.fec_resolver_stats()
    }

    /// Drain all available shreds from the incoming source and process them.
    fn drain_and_process(&mut self) -> Result<(), DualReceiveError> {
        let default_source = self.default_source;
        drain_shred_input(&mut self.incoming_shreds, &mut self.stage, default_source)
    }

    /// Push completed FEC sets to the output channels.
    fn flush_completed(&mut self) {
        let completed = self.stage.drain_completed_sets();
        for fec_set in completed {
            // Fan out to store service if wired.
            if let Some(ref mut store) = self.store_output {
                let _ = store.try_send(fec_set.clone());
            }
            // Best-effort send to collector — drop on backpressure.
            let _ = self.completed_output.try_send(fec_set);
        }
    }

    /// Push retransmit decisions to the output channel.
    fn flush_retransmits(&mut self) {
        if let Some(ref mut output) = self.retransmit_output {
            let retransmits = self.stage.drain_retransmits();
            for decision in retransmits {
                let _ = output.try_send(decision);
            }
        } else {
            // Discard retransmits if no output channel configured.
            self.stage.drain_retransmits();
        }
    }

    /// Push equivocation proofs to the output channel.
    fn flush_equivocations(&mut self) {
        let proofs = self.stage.drain_equivocations();
        if proofs.is_empty() {
            return;
        }
        if let Some(ref mut output) = self.equivocation_output {
            for proof in proofs {
                let _ = output.try_send(proof);
            }
        }
    }
}

/// Drain shreds from the input source into the processing stage.
///
/// Factored as a free function to avoid borrow-checker issues with
/// simultaneous mutable access to `incoming_shreds` and `stage`.
fn drain_shred_input(
    input: &mut DualReceiver<Shred>,
    stage: &mut ShredNetworkStage,
    default_source: ShredSource,
) -> Result<(), DualReceiveError> {
    loop {
        match input.try_recv() {
            Ok(Some(shred)) => {
                let net_shred = NetworkShred {
                    shred,
                    source: default_source,
                };
                stage.insert_shred(net_shred);
            }
            Ok(None) => break,
            Err(DualReceiveError::Closed) => return Err(DualReceiveError::Closed),
            Err(DualReceiveError::Overrun { .. }) => {
                // Consumer fell behind — fragments lost. Continue
                // from the recovery point (auto-advanced by the link).
            }
        }
    }
    Ok(())
}

impl Service for ShredNetworkService {
    fn name(&self) -> &'static str {
        "shred-network"
    }

    fn tick_interval(&self) -> Duration {
        Duration::from_millis(2)
    }

    fn tick(&mut self, context: &ServiceContext) -> RuntimeResult<()> {
        match self.drain_and_process() {
            Ok(()) => {}
            Err(DualReceiveError::Closed) => {
                context.shutdown.request_stop();
                return Err(RuntimeError::service_failure(
                    self.name(),
                    "shred input channel closed",
                ));
            }
            Err(DualReceiveError::Overrun { .. }) => {
                // Already handled inside drain_shred_input.
            }
        }

        // Flush data-only FEC sets for slots where the last shred arrived.
        self.stage.flush_complete_slots();

        self.flush_completed();
        self.flush_retransmits();
        self.flush_equivocations();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paradencer_types::shred::*;

    fn make_common_header(slot: u64, index: u32, fec_set_index: u32) -> ShredCommonHeader {
        let mut sig = [0u8; 64];
        sig[..8].copy_from_slice(&slot.to_le_bytes());
        sig[8..12].copy_from_slice(&index.to_le_bytes());
        sig[12..16].copy_from_slice(&fec_set_index.to_le_bytes());
        ShredCommonHeader {
            signature: sig,
            variant: SHRED_TYPE_LEGACY_DATA | SHRED_LEGACY_DATA_NIBBLE,
            slot,
            index,
            version: 1,
            fec_set_index,
        }
    }

    fn make_data_shred(slot: u64, index: u32, fec_set_index: u32) -> NetworkShred {
        let header = make_common_header(slot, index, fec_set_index);
        let shred = Shred::new(
            header,
            ShredVariant::LegacyData(DataShredHeader {
                parent_offset: 1,
                flags: 0,
                size: DATA_SHRED_PAYLOAD_SIZE as u16,
            }),
            vec![0u8; DATA_SHRED_PAYLOAD_SIZE],
        );
        NetworkShred {
            shred,
            source: ShredSource::Turbine,
        }
    }

    fn make_coding_shred(
        slot: u64,
        index: u32,
        fec_set_index: u32,
        position: u16,
        num_data: u16,
        num_coding: u16,
    ) -> NetworkShred {
        let mut header = make_common_header(slot, index, fec_set_index);
        header.variant = SHRED_CODE_FLAG;
        // Make signature unique from data shreds
        header.signature[16] = 1;
        header.signature[17..19].copy_from_slice(&position.to_le_bytes());

        let shred = Shred::new(
            header,
            ShredVariant::LegacyCoding(CodingShredHeader {
                num_data_shreds: num_data,
                num_coding_shreds: num_coding,
                position,
            }),
            vec![0u8; DATA_SHRED_PAYLOAD_SIZE],
        );
        NetworkShred {
            shred,
            source: ShredSource::Turbine,
        }
    }

    #[test]
    fn insert_single_shred() {
        let mut stage = ShredNetworkStage::new();

        let shred = make_data_shred(100, 0, 0);
        let outcome = stage.insert_shred(shred);
        assert_eq!(outcome, ShredInsertOutcome::Accepted);
        assert_eq!(stage.tracked_slot_count(), 1);
    }

    #[test]
    fn fec_set_completes_with_enough_data() {
        let mut stage = ShredNetworkStage::new();

        // Insert data shreds first (no params known yet, stays Accepted).
        let s1 = make_data_shred(100, 0, 0);
        assert_eq!(stage.insert_shred(s1), ShredInsertOutcome::Accepted);

        let s2 = make_data_shred(100, 1, 0);
        assert_eq!(stage.insert_shred(s2), ShredInsertOutcome::Accepted);

        // Insert coding shred to establish FEC params (2 data, 2 coding).
        // At this point: 2 data + 1 coding, params now known, 2 data >= 2 = complete.
        let coding = make_coding_shred(100, 2, 0, 0, 2, 2);
        let outcome = stage.insert_shred(coding);
        assert!(matches!(outcome, ShredInsertOutcome::FecSetComplete { .. }));

        // Should have a completed FEC set.
        let completed = stage.drain_completed_sets();
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].slot, 100);
        assert_eq!(completed[0].fec_set_index, 0);
        assert_eq!(completed[0].data_shreds.len(), 2);
        assert!(!completed[0].was_recovered);
    }

    #[test]
    fn fec_recovery_with_coding_shreds() {
        let mut stage = ShredNetworkStage::new();

        // FEC set: 3 data, 3 coding. Insert 2 data + 1 coding = 3 total = recoverable.
        let coding = make_coding_shred(100, 3, 0, 0, 3, 3);
        stage.insert_shred(coding);

        stage.insert_shred(make_data_shred(100, 0, 0));

        let s2 = make_data_shred(100, 1, 0);
        let outcome = stage.insert_shred(s2);
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
        if let ShredVariant::LegacyData(ref mut header) = shred.shred.variant {
            header.flags |= SHRED_LAST_IN_SLOT;
        }
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
        stage.insert_shred(repair_shred);

        let snap = stage.stats().snapshot();
        assert_eq!(snap.shreds_received, 2);
        assert_eq!(snap.shreds_from_turbine, 1);
        assert_eq!(snap.shreds_from_repair, 1);
        assert_eq!(snap.retransmits_sent, 1); // only turbine triggers retransmit
    }

    #[test]
    fn fec_params_learned_from_coding_shred() {
        let mut stage = ShredNetworkStage::new();

        // Insert data shred first (no FEC params yet — stays Accepted).
        stage.insert_shred(make_data_shred(100, 0, 0));
        assert_eq!(stage.fec_data_count(100, 0), 1);
        assert_eq!(stage.fec_coding_count(100, 0), 0);

        // Insert coding shred with FEC params (4 data, 4 coding).
        // 1 data + 1 coding = 2 total < 4 needed → Accepted.
        let coding = make_coding_shred(100, 4, 0, 0, 4, 4);
        let outcome = stage.insert_shred(coding);
        assert_eq!(outcome, ShredInsertOutcome::Accepted);
        assert_eq!(stage.fec_coding_count(100, 0), 1);

        // Add more data shreds. 2 data + 1 coding = 3 total < 4 needed.
        let outcome = stage.insert_shred(make_data_shred(100, 1, 0));
        assert_eq!(outcome, ShredInsertOutcome::Accepted);

        // 3 data + 1 coding = 4 total >= 4 needed but only 3 data < 4 → FecRecoverable.
        let outcome = stage.insert_shred(make_data_shred(100, 2, 0));
        assert!(matches!(outcome, ShredInsertOutcome::FecRecoverable { .. }));

        // FEC set was resolved via recovery, verify completed set exists.
        let completed = stage.drain_completed_sets();
        assert_eq!(completed.len(), 1);
        assert!(completed[0].was_recovered);
        assert_eq!(completed[0].data_shreds.len(), 4);
    }

    #[test]
    fn multiple_fec_sets_per_slot() {
        let mut stage = ShredNetworkStage::new();

        // FEC set 0: 2 data, 2 coding.
        let coding0 = make_coding_shred(100, 2, 0, 0, 2, 2);
        stage.insert_shred(coding0);
        stage.insert_shred(make_data_shred(100, 0, 0));
        stage.insert_shred(make_data_shred(100, 1, 0));

        // FEC set 4: 2 data, 2 coding.
        let coding4 = make_coding_shred(100, 6, 4, 0, 2, 2);
        stage.insert_shred(coding4);
        stage.insert_shred(make_data_shred(100, 4, 4));
        stage.insert_shred(make_data_shred(100, 5, 4));

        let completed = stage.drain_completed_sets();
        assert_eq!(completed.len(), 2);
        assert_eq!(stage.fec_set_count(100), 2);
    }

    #[test]
    fn completed_set_data_shreds_ordered() {
        let mut stage = ShredNetworkStage::new();

        // FEC set: 3 data, 3 coding. Insert in reverse order.
        let coding = make_coding_shred(100, 3, 0, 0, 3, 3);
        stage.insert_shred(coding);

        stage.insert_shred(make_data_shred(100, 2, 0));
        stage.insert_shred(make_data_shred(100, 0, 0));
        stage.insert_shred(make_data_shred(100, 1, 0));

        let completed = stage.drain_completed_sets();
        assert_eq!(completed.len(), 1);
        let set = &completed[0];
        assert_eq!(set.data_shreds.len(), 3);

        // Verify ordering by index.
        assert_eq!(set.data_shreds[0].index(), 0);
        assert_eq!(set.data_shreds[1].index(), 1);
        assert_eq!(set.data_shreds[2].index(), 2);
    }

    // --- Wave 2: RS Recovery tests ---

    /// Create a full FEC set (data + coding) using actual Reed-Solomon encoding.
    fn create_fec_set(
        slot: u64,
        fec_set_index: u32,
        num_data: usize,
        num_coding: usize,
    ) -> (Vec<NetworkShred>, Vec<NetworkShred>) {
        use reed_solomon_erasure::galois_8::ReedSolomon;

        let shard_size = DATA_SHRED_PAYLOAD_SIZE;
        let rs = ReedSolomon::new(num_data, num_coding).unwrap();

        // Create deterministic data payloads.
        let mut all_payloads: Vec<Vec<u8>> = Vec::with_capacity(num_data + num_coding);
        for i in 0..num_data {
            let mut payload = vec![0u8; shard_size];
            for (j, byte) in payload.iter_mut().enumerate() {
                *byte = ((i * 256 + j + 1) % 256) as u8;
            }
            all_payloads.push(payload);
        }
        for _ in 0..num_coding {
            all_payloads.push(vec![0u8; shard_size]);
        }

        // Encode RS parity.
        let mut shard_refs: Vec<&mut [u8]> =
            all_payloads.iter_mut().map(|s| s.as_mut_slice()).collect();
        rs.encode(&mut shard_refs).unwrap();

        // Build data shreds.
        let mut data_shreds = Vec::with_capacity(num_data);
        for (i, payload) in all_payloads[..num_data].iter().enumerate() {
            let abs_index = fec_set_index + i as u32;
            let mut header = make_common_header(slot, abs_index, fec_set_index);
            // Give each a unique signature.
            header.signature[20..24].copy_from_slice(&(i as u32).to_le_bytes());
            let shred = Shred::new(
                header,
                ShredVariant::LegacyData(DataShredHeader {
                    parent_offset: 1,
                    flags: 0,
                    size: shard_size as u16,
                }),
                payload.clone(),
            );
            data_shreds.push(NetworkShred {
                shred,
                source: ShredSource::Turbine,
            });
        }

        // Build coding shreds.
        let mut coding_shreds = Vec::with_capacity(num_coding);
        for (i, payload) in all_payloads[num_data..].iter().enumerate() {
            let abs_index = fec_set_index + num_data as u32 + i as u32;
            let mut header = make_common_header(slot, abs_index, fec_set_index);
            header.variant = SHRED_CODE_FLAG;
            header.signature[16] = 1;
            header.signature[20..24].copy_from_slice(&(i as u32).to_le_bytes());
            let shred = Shred::new(
                header,
                ShredVariant::LegacyCoding(CodingShredHeader {
                    num_data_shreds: num_data as u16,
                    num_coding_shreds: num_coding as u16,
                    position: i as u16,
                }),
                payload.clone(),
            );
            coding_shreds.push(NetworkShred {
                shred,
                source: ShredSource::Turbine,
            });
        }

        (data_shreds, coding_shreds)
    }

    #[test]
    fn rs_recovery_single_missing_data() {
        let mut stage = ShredNetworkStage::new();
        let (data_shreds, coding_shreds) = create_fec_set(100, 0, 4, 4);

        let original_payload = data_shreds[0].shred.payload.clone();

        // Insert data shreds 1, 2, 3 (skip 0) + coding shred 0.
        for ds in &data_shreds[1..] {
            stage.insert_shred(ds.clone());
        }
        let outcome = stage.insert_shred(coding_shreds[0].clone());
        assert!(matches!(outcome, ShredInsertOutcome::FecRecoverable { .. }));

        // Should have recovered.
        let completed = stage.drain_completed_sets();
        assert_eq!(completed.len(), 1);
        assert!(completed[0].was_recovered);
        assert_eq!(completed[0].data_shreds.len(), 4);

        // Verify recovered payload matches original.
        assert_eq!(completed[0].data_shreds[0].payload, original_payload);
    }

    #[test]
    fn rs_recovery_two_missing_data() {
        let mut stage = ShredNetworkStage::new();
        let (data_shreds, coding_shreds) = create_fec_set(100, 0, 4, 4);

        let original_0 = data_shreds[0].shred.payload.clone();
        let original_2 = data_shreds[2].shred.payload.clone();

        // Insert data 1, 3 (skip 0, 2) + coding 0, 1.
        stage.insert_shred(data_shreds[1].clone());
        stage.insert_shred(data_shreds[3].clone());
        stage.insert_shred(coding_shreds[0].clone());
        let outcome = stage.insert_shred(coding_shreds[1].clone());
        assert!(matches!(outcome, ShredInsertOutcome::FecRecoverable { .. }));

        let completed = stage.drain_completed_sets();
        assert_eq!(completed.len(), 1);
        assert!(completed[0].was_recovered);
        assert_eq!(completed[0].data_shreds.len(), 4);

        // Verify both recovered payloads.
        assert_eq!(completed[0].data_shreds[0].payload, original_0);
        assert_eq!(completed[0].data_shreds[2].payload, original_2);
    }

    #[test]
    fn rs_insufficient_shreds_no_completion() {
        let mut stage = ShredNetworkStage::new();
        let (data_shreds, coding_shreds) = create_fec_set(100, 0, 4, 4);

        // Insert only 3 shreds (need 4 for recovery): 2 data + 1 coding.
        stage.insert_shred(data_shreds[0].clone());
        stage.insert_shred(data_shreds[1].clone());
        let outcome = stage.insert_shred(coding_shreds[0].clone());
        assert_eq!(outcome, ShredInsertOutcome::Accepted);

        let completed = stage.drain_completed_sets();
        assert!(completed.is_empty());
    }

    #[test]
    fn rs_all_data_present_no_recovery_needed() {
        let mut stage = ShredNetworkStage::new();
        let (data_shreds, coding_shreds) = create_fec_set(100, 0, 4, 4);

        // Insert all data shreds (no coding needed except for params).
        for ds in &data_shreds {
            stage.insert_shred(ds.clone());
        }
        // Insert coding to establish params and trigger completion.
        let outcome = stage.insert_shred(coding_shreds[0].clone());
        assert!(matches!(outcome, ShredInsertOutcome::FecSetComplete { .. }));

        let completed = stage.drain_completed_sets();
        assert_eq!(completed.len(), 1);
        assert!(!completed[0].was_recovered);
        assert_eq!(completed[0].data_shreds.len(), 4);
    }

    #[test]
    fn rs_recovered_shred_has_correct_index() {
        let mut stage = ShredNetworkStage::new();
        let (data_shreds, coding_shreds) = create_fec_set(200, 10, 3, 3);

        // Skip data shred at index 11 (relative index 1).
        stage.insert_shred(data_shreds[0].clone());
        stage.insert_shred(data_shreds[2].clone());
        let outcome = stage.insert_shred(coding_shreds[0].clone());
        assert!(matches!(outcome, ShredInsertOutcome::FecRecoverable { .. }));

        let completed = stage.drain_completed_sets();
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].fec_set_index, 10);

        // Verify indices are correct.
        assert_eq!(completed[0].data_shreds[0].index(), 10);
        assert_eq!(completed[0].data_shreds[1].index(), 11); // recovered
        assert_eq!(completed[0].data_shreds[2].index(), 12);
    }

    #[test]
    fn rs_round_trip_encode_drop_recover() {
        // Full round-trip: encode data → create FEC set → drop some → recover → verify.
        let mut stage = ShredNetworkStage::new();
        let num_data = 8;
        let num_coding = 8;
        let (data_shreds, coding_shreds) = create_fec_set(500, 0, num_data, num_coding);

        // Save original payloads.
        let originals: Vec<Vec<u8>> = data_shreds
            .iter()
            .map(|ds| ds.shred.payload.clone())
            .collect();

        // Drop first 3 data shreds, provide 3 coding shreds to compensate.
        for ds in &data_shreds[3..] {
            stage.insert_shred(ds.clone());
        }
        for cs in &coding_shreds[..3] {
            stage.insert_shred(cs.clone());
        }

        let completed = stage.drain_completed_sets();
        assert_eq!(completed.len(), 1);
        assert!(completed[0].was_recovered);
        assert_eq!(completed[0].data_shreds.len(), num_data);

        // Verify ALL payloads match originals (both received and recovered).
        for (i, shred) in completed[0].data_shreds.iter().enumerate() {
            assert_eq!(
                shred.payload, originals[i],
                "Payload mismatch at data shred index {i}"
            );
        }
    }

    #[test]
    fn drain_completed_clears_queue() {
        let mut stage = ShredNetworkStage::new();
        let (data_shreds, coding_shreds) = create_fec_set(100, 0, 2, 2);

        // Complete a FEC set.
        stage.insert_shred(data_shreds[0].clone());
        stage.insert_shred(data_shreds[1].clone());
        stage.insert_shred(coding_shreds[0].clone());

        let completed = stage.drain_completed_sets();
        assert_eq!(completed.len(), 1);

        // Second drain should be empty.
        let completed2 = stage.drain_completed_sets();
        assert!(completed2.is_empty());
    }

    #[test]
    fn fec_sets_across_different_slots_independent() {
        let mut stage = ShredNetworkStage::new();
        let (data_100, coding_100) = create_fec_set(100, 0, 3, 3);
        let (data_200, coding_200) = create_fec_set(200, 0, 3, 3);

        // Complete slot 100.
        for ds in &data_100 {
            stage.insert_shred(ds.clone());
        }
        stage.insert_shred(coding_100[0].clone());

        // Partially fill slot 200 (not enough for completion).
        stage.insert_shred(data_200[0].clone());
        stage.insert_shred(coding_200[0].clone());

        let completed = stage.drain_completed_sets();
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].slot, 100);
    }

    // -----------------------------------------------------------------------
    // ShredNetworkService tests
    // -----------------------------------------------------------------------

    #[test]
    fn service_processes_shreds_and_emits_completed_fec_sets() {
        use paradencer_mesh::bounded_link;
        use paradencer_runtime::{ServiceContext, ShutdownSwitch};

        let (shred_tx, shred_rx) = bounded_link::<Shred>(64);
        let (fec_tx, fec_rx) = bounded_link::<CompletedFecSet>(16);

        let config = ShredNetworkConfig {
            turbine_neighbor_count: 0,
            ..Default::default()
        };
        let mut service = ShredNetworkService::new(
            config,
            DualReceiver::Channel(shred_rx),
            DualSender::Channel(fec_tx),
        );
        let context = ServiceContext::new(ShutdownSwitch::new());

        // Create a FEC set (2 data + 2 coding).
        let (data_shreds, coding_shreds) = create_fec_set(100, 0, 2, 2);

        // Send both data shreds + one coding shred (to learn params and complete).
        for ns in &data_shreds {
            shred_tx.try_send(ns.shred.clone()).unwrap();
        }
        shred_tx.try_send(coding_shreds[0].shred.clone()).unwrap();

        // Tick the service to process.
        service.tick(&context).unwrap();

        // Should have produced a CompletedFecSet.
        let fec_set = fec_rx.try_recv().unwrap();
        assert!(fec_set.is_some());
        let fec_set = fec_set.unwrap();
        assert_eq!(fec_set.slot, 100);
        assert_eq!(fec_set.data_shreds.len(), 2);
        assert!(!fec_set.was_recovered);
    }

    #[test]
    fn service_retransmits_to_output_channel() {
        use paradencer_mesh::bounded_link;
        use paradencer_runtime::{ServiceContext, ShutdownSwitch};

        let (shred_tx, shred_rx) = bounded_link::<Shred>(64);
        let (fec_tx, _fec_rx) = bounded_link::<CompletedFecSet>(16);
        let (retx_tx, retx_rx) = bounded_link::<RetransmitDecision>(16);

        let config = ShredNetworkConfig {
            turbine_neighbor_count: 3,
            ..Default::default()
        };
        let mut service = ShredNetworkService::new(
            config,
            DualReceiver::Channel(shred_rx),
            DualSender::Channel(fec_tx),
        )
        .with_retransmit_output(DualSender::Channel(retx_tx));
        let context = ServiceContext::new(ShutdownSwitch::new());

        // Send a turbine shred.
        let ns = make_data_shred(100, 0, 0);
        shred_tx.try_send(ns.shred).unwrap();

        service.tick(&context).unwrap();

        // Should have a retransmit decision.
        let decision = retx_rx.try_recv().unwrap();
        assert!(decision.is_some());
        let decision = decision.unwrap();
        assert_eq!(decision.slot, 100);
        assert_eq!(decision.destination_indices.len(), 3);
    }

    #[test]
    fn flush_complete_slots_emits_data_only_fec_sets() {
        let mut stage = ShredNetworkStage::new();

        // Insert data-only shreds (no coding) for slot 200.
        // The last shred has the last-in-slot flag.
        for idx in 0..4 {
            let mut ns = make_data_shred(200, idx, 0);
            if idx == 3 {
                // Set last-in-slot flag.
                if let ShredVariant::LegacyData(ref mut header) = ns.shred.variant {
                    header.flags |= SHRED_LAST_IN_SLOT;
                }
            }
            stage.insert_shred(ns);
        }

        // No completed sets yet (params_known=false).
        assert!(stage.drain_completed_sets().is_empty());

        // Flush complete slots should emit the data-only set.
        stage.flush_complete_slots();
        let completed = stage.drain_completed_sets();
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].slot, 200);
        assert_eq!(completed[0].data_shreds.len(), 4);
        assert!(!completed[0].was_recovered);
    }

    #[test]
    fn service_flushes_data_only_slots_on_tick() {
        use paradencer_mesh::bounded_link;
        use paradencer_runtime::{ServiceContext, ShutdownSwitch};

        let (shred_tx, shred_rx) = bounded_link::<Shred>(64);
        let (fec_tx, fec_rx) = bounded_link::<CompletedFecSet>(16);

        let config = ShredNetworkConfig {
            turbine_neighbor_count: 0,
            ..Default::default()
        };
        let mut service = ShredNetworkService::new(
            config,
            DualReceiver::Channel(shred_rx),
            DualSender::Channel(fec_tx),
        );
        let context = ServiceContext::new(ShutdownSwitch::new());

        // Send 4 data-only shreds, last one with last-in-slot flag.
        for idx in 0..4u32 {
            let mut ns = make_data_shred(300, idx, 0);
            if idx == 3 {
                if let ShredVariant::LegacyData(ref mut header) = ns.shred.variant {
                    header.flags |= SHRED_LAST_IN_SLOT;
                }
            }
            shred_tx.try_send(ns.shred).unwrap();
        }

        service.tick(&context).unwrap();

        // CompletedFecSet should appear on the output channel.
        let fec_set = fec_rx.try_recv().unwrap();
        assert!(fec_set.is_some());
        let fec_set = fec_set.unwrap();
        assert_eq!(fec_set.slot, 300);
        assert_eq!(fec_set.data_shreds.len(), 4);
    }

    // -----------------------------------------------------------------------
    // Signature verification integration tests
    // -----------------------------------------------------------------------

    /// Test leader lookup that returns a fixed pubkey for all slots.
    struct FixedLeaderLookup {
        pubkey: [u8; 32],
    }

    impl LeaderLookup for FixedLeaderLookup {
        fn leader_for_slot(&self, _slot: u64) -> Option<[u8; 32]> {
            Some(self.pubkey)
        }
    }

    /// Build a properly signed Merkle NetworkShred for testing.
    fn make_signed_network_shred(
        secret_key: &[u8; 32],
        slot: u64,
        index: u32,
        fec_set_index: u32,
        source: ShredSource,
    ) -> NetworkShred {
        let shred = crate::shred_verifier::make_signed_merkle_data_shred(
            secret_key,
            slot,
            index,
            fec_set_index,
            2, // proof_depth
        );
        NetworkShred { shred, source }
    }

    #[test]
    fn valid_signed_shred_accepted_with_leader_lookup() {
        use paradencer_crypto::ed25519_batch::generate_keypair;

        let (secret, pubkey) = generate_keypair();
        let lookup = Arc::new(FixedLeaderLookup { pubkey });

        let mut stage = ShredNetworkStage::new();
        stage.set_leader_lookup(lookup);

        let ns = make_signed_network_shred(&secret, 100, 0, 0, ShredSource::Turbine);
        let outcome = stage.insert_shred(ns);
        assert_eq!(outcome, ShredInsertOutcome::Accepted);
    }

    #[test]
    fn invalid_signed_shred_rejected_with_leader_lookup() {
        use paradencer_crypto::ed25519_batch::generate_keypair;

        let (_secret, pubkey) = generate_keypair();
        let lookup = Arc::new(FixedLeaderLookup { pubkey });

        let mut stage = ShredNetworkStage::new();
        stage.set_leader_lookup(lookup);

        // Use a shred with fake (non-zero) signature — not signed by the leader.
        let ns = make_data_shred(100, 0, 0); // fake signature
        let outcome = stage.insert_shred(ns);
        assert_eq!(outcome, ShredInsertOutcome::InvalidSignature);

        let snap = stage.stats().snapshot();
        assert_eq!(snap.shreds_signature_invalid, 1);
    }

    #[test]
    fn zero_signature_shred_rejected_with_leader_lookup() {
        use paradencer_crypto::ed25519_batch::generate_keypair;

        let (_, pubkey) = generate_keypair();
        let lookup = Arc::new(FixedLeaderLookup { pubkey });

        let mut stage = ShredNetworkStage::new();
        stage.set_leader_lookup(lookup);

        let shred = Shred::new(
            ShredCommonHeader {
                signature: [0u8; 64],
                variant: SHRED_TYPE_LEGACY_DATA | SHRED_LEGACY_DATA_NIBBLE,
                slot: 100,
                index: 0,
                version: 1,
                fec_set_index: 0,
            },
            ShredVariant::LegacyData(DataShredHeader {
                parent_offset: 1,
                flags: 0,
                size: 64,
            }),
            vec![0u8; 64],
        );
        let ns = NetworkShred {
            shred,
            source: ShredSource::Turbine,
        };
        let outcome = stage.insert_shred(ns);
        assert_eq!(outcome, ShredInsertOutcome::InvalidSignature);
    }

    #[test]
    fn local_shreds_skip_verification() {
        use paradencer_crypto::ed25519_batch::generate_keypair;

        let (_, pubkey) = generate_keypair();
        let lookup = Arc::new(FixedLeaderLookup { pubkey });

        let mut stage = ShredNetworkStage::new();
        stage.set_leader_lookup(lookup);

        // Local shred with fake signature should still be accepted.
        let mut ns = make_data_shred(100, 0, 0);
        ns.source = ShredSource::Local;
        let outcome = stage.insert_shred(ns);
        assert_eq!(outcome, ShredInsertOutcome::Accepted);

        let snap = stage.stats().snapshot();
        assert_eq!(snap.shreds_signature_invalid, 0);
    }

    #[test]
    fn no_leader_lookup_skips_verification() {
        // Without a leader lookup configured, all shreds pass (backward compat).
        let mut stage = ShredNetworkStage::new();

        let ns = make_data_shred(100, 0, 0); // fake signature
        let outcome = stage.insert_shred(ns);
        assert_eq!(outcome, ShredInsertOutcome::Accepted);
    }
}
