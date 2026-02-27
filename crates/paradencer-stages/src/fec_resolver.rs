/// Pre-allocated FEC set resolver with depth-controlled buffer lifecycle.
///
/// Manages a pool of FEC set buffers through a three-queue lifecycle:
/// free → in-progress → completed → free. Depth parameters control
/// concurrent limits and buffer retention. Signature-based duplicate
/// detection prevents processing the same FEC set twice.
use paradencer_constants::shred::{
    FEC_RESOLVER_COMPLETE_DEPTH, FEC_RESOLVER_DEPTH, FEC_RESOLVER_DONE_DEPTH,
    MAX_FEC_CODING_SHREDS, MAX_FEC_DATA_SHREDS,
};
use paradencer_types::shred::Shred;
use std::collections::{HashMap, VecDeque};

/// Unique key identifying a FEC set within the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FecSetKey {
    /// Slot number.
    pub slot: u64,
    /// FEC set index within the slot.
    pub fec_set_index: u32,
}

/// Handle to a pool-allocated FEC buffer. The index references the buffer
/// in the pool's internal storage. Valid only while held by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FecBufferHandle(usize);

/// Pre-allocated storage for a single FEC set's data and coding shreds.
#[derive(Debug)]
struct FecBuffer {
    /// Data shreds indexed by relative position within the FEC set.
    data_shreds: HashMap<u32, Shred>,
    /// Coding shreds indexed by coding position.
    coding_shreds: HashMap<u32, Shred>,
    /// Number of data shreds expected (learned from coding header).
    num_data: u32,
    /// Number of coding shreds expected (learned from coding header).
    num_coding: u32,
    /// Whether FEC parameters have been learned from a coding shred.
    params_known: bool,
    /// Whether this buffer has been resolved (completed or recovered).
    resolved: bool,
    /// Ed25519 signature of the first shred inserted (used for dedup).
    first_signature: [u8; 64],
    /// Key identifying which slot/fec_set this buffer is tracking.
    key: Option<FecSetKey>,
}

impl FecBuffer {
    fn new() -> Self {
        Self {
            data_shreds: HashMap::with_capacity(MAX_FEC_DATA_SHREDS),
            coding_shreds: HashMap::with_capacity(MAX_FEC_CODING_SHREDS),
            num_data: 0,
            num_coding: 0,
            params_known: false,
            resolved: false,
            first_signature: [0u8; 64],
            key: None,
        }
    }

    /// Reset the buffer for reuse, clearing all shred data.
    fn reset(&mut self) {
        self.data_shreds.clear();
        self.coding_shreds.clear();
        self.num_data = 0;
        self.num_coding = 0;
        self.params_known = false;
        self.resolved = false;
        self.first_signature = [0u8; 64];
        self.key = None;
    }

    /// Total number of received shreds (data + coding).
    fn total_received(&self) -> u32 {
        self.data_shreds.len() as u32 + self.coding_shreds.len() as u32
    }

    /// All data shreds received (no Reed-Solomon needed).
    fn is_complete(&self) -> bool {
        self.params_known && self.data_shreds.len() as u32 >= self.num_data && !self.resolved
    }

    /// Enough total shreds for Reed-Solomon recovery but not all data present.
    fn is_recoverable(&self) -> bool {
        self.params_known
            && self.total_received() >= self.num_data
            && (self.data_shreds.len() as u32) < self.num_data
            && !self.resolved
    }

    /// Learn FEC parameters from a coding shred header.
    fn learn_params(&mut self, num_data: u16, num_coding: u16) {
        if !self.params_known {
            self.num_data = num_data as u32;
            self.num_coding = num_coding as u32;
            self.params_known = true;
        }
    }
}

/// Information about a FEC set evicted due to depth overflow.
#[derive(Debug, Clone)]
pub struct SpilledFecSet {
    /// Slot of the evicted FEC set.
    pub slot: u64,
    /// FEC set index within the slot.
    pub fec_set_index: u32,
    /// Number of data shreds received before eviction.
    pub data_received: u32,
    /// Number of coding shreds received before eviction.
    pub coding_received: u32,
}

/// Result of inserting a shred into the resolver pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverInsertResult {
    /// Shred accepted, FEC set still incomplete.
    Accepted,
    /// All data shreds present — FEC set ready for assembly.
    Complete,
    /// Enough total shreds for Reed-Solomon recovery.
    Recoverable,
    /// Duplicate: this FEC set was already completed.
    DuplicateFecSet,
    /// Duplicate: this exact shred (by position) was already inserted.
    DuplicateShred,
}

/// Pre-allocated FEC set resolver with depth-controlled buffer lifecycle.
pub struct FecResolverPool {
    /// All buffers (pre-allocated at construction time).
    buffers: Vec<FecBuffer>,
    /// Indices of free buffers available for allocation.
    free_queue: VecDeque<usize>,
    /// Map from FecSetKey → buffer index for in-progress FEC sets.
    in_progress: HashMap<FecSetKey, usize>,
    /// FIFO order of in-progress keys for eviction.
    in_progress_order: VecDeque<FecSetKey>,
    /// Indices of completed buffers waiting for consumer to read.
    completed_queue: VecDeque<usize>,
    /// Circular buffer of recently-completed FEC set signatures for dedup.
    done_signatures: VecDeque<[u8; 64]>,
    /// Maximum concurrent in-progress FEC sets before eviction.
    depth: usize,
    /// Maximum completed buffers retained.
    complete_depth: usize,
    /// Maximum signatures tracked for duplicate detection.
    done_depth: usize,
    /// Spilled FEC set info from most recent eviction (for repair coordination).
    last_spilled: Option<SpilledFecSet>,
    /// Statistics.
    pub stats: FecResolverStats,
}

/// FEC resolver pool statistics.
#[derive(Debug, Default, Clone)]
pub struct FecResolverStats {
    /// Total shreds inserted.
    pub shreds_inserted: u64,
    /// FEC sets completed (all data shreds present).
    pub sets_completed: u64,
    /// FEC sets recoverable via Reed-Solomon.
    pub sets_recoverable: u64,
    /// FEC sets evicted due to depth overflow.
    pub sets_spilled: u64,
    /// Duplicate FEC sets rejected (already in done_map).
    pub duplicates_rejected: u64,
    /// Duplicate shreds rejected (same position in same FEC set).
    pub duplicate_shreds_rejected: u64,
}

impl FecResolverPool {
    /// Create a new resolver pool with the given depth parameters.
    ///
    /// Pre-allocates `depth + complete_depth` FEC buffers.
    pub fn new(depth: usize, complete_depth: usize, done_depth: usize) -> Self {
        let total_buffers = depth + complete_depth;
        let mut buffers = Vec::with_capacity(total_buffers);
        let mut free_queue = VecDeque::with_capacity(total_buffers);

        for i in 0..total_buffers {
            buffers.push(FecBuffer::new());
            free_queue.push_back(i);
        }

        Self {
            buffers,
            free_queue,
            in_progress: HashMap::with_capacity(depth),
            in_progress_order: VecDeque::with_capacity(depth),
            completed_queue: VecDeque::with_capacity(complete_depth),
            done_signatures: VecDeque::with_capacity(done_depth),
            depth,
            complete_depth,
            done_depth,
            last_spilled: None,
            stats: FecResolverStats::default(),
        }
    }

    /// Create a resolver pool with default depth parameters.
    pub fn with_defaults() -> Self {
        Self::new(
            FEC_RESOLVER_DEPTH,
            FEC_RESOLVER_COMPLETE_DEPTH,
            FEC_RESOLVER_DONE_DEPTH,
        )
    }

    /// Insert a data shred into the resolver pool.
    ///
    /// Returns the insert result indicating whether the FEC set is now
    /// complete, recoverable, or still in progress.
    pub fn insert_data_shred(
        &mut self,
        slot: u64,
        fec_set_index: u32,
        relative_index: u32,
        shred: Shred,
    ) -> ResolverInsertResult {
        let key = FecSetKey {
            slot,
            fec_set_index,
        };

        // Check done_map for duplicate completed FEC set.
        if self.is_fec_set_done(&shred.common_header.signature) {
            self.stats.duplicates_rejected += 1;
            return ResolverInsertResult::DuplicateFecSet;
        }

        let buf_idx = self.ensure_buffer(key);
        let buf = &mut self.buffers[buf_idx];

        // Track first signature for dedup.
        if buf.data_shreds.is_empty() && buf.coding_shreds.is_empty() {
            buf.first_signature = shred.common_header.signature;
        }

        // Reject duplicate shred position.
        if buf.data_shreds.contains_key(&relative_index) {
            self.stats.duplicate_shreds_rejected += 1;
            return ResolverInsertResult::DuplicateShred;
        }

        buf.data_shreds.insert(relative_index, shred);
        self.stats.shreds_inserted += 1;

        self.check_fec_status(buf_idx)
    }

    /// Insert a coding shred into the resolver pool.
    pub fn insert_coding_shred(
        &mut self,
        slot: u64,
        fec_set_index: u32,
        position: u32,
        num_data: u16,
        num_coding: u16,
        shred: Shred,
    ) -> ResolverInsertResult {
        let key = FecSetKey {
            slot,
            fec_set_index,
        };

        // Check done_map for duplicate completed FEC set.
        if self.is_fec_set_done(&shred.common_header.signature) {
            self.stats.duplicates_rejected += 1;
            return ResolverInsertResult::DuplicateFecSet;
        }

        let buf_idx = self.ensure_buffer(key);
        let buf = &mut self.buffers[buf_idx];

        // Track first signature for dedup.
        if buf.data_shreds.is_empty() && buf.coding_shreds.is_empty() {
            buf.first_signature = shred.common_header.signature;
        }

        // Learn FEC params.
        buf.learn_params(num_data, num_coding);

        // Reject duplicate coding position.
        if buf.coding_shreds.contains_key(&position) {
            self.stats.duplicate_shreds_rejected += 1;
            return ResolverInsertResult::DuplicateShred;
        }

        buf.coding_shreds.insert(position, shred);
        self.stats.shreds_inserted += 1;

        self.check_fec_status(buf_idx)
    }

    /// Mark a FEC set as resolved and move its buffer to the completed queue.
    ///
    /// Called after the consumer has extracted data from the buffer and
    /// performed Reed-Solomon recovery if needed.
    pub fn mark_completed(&mut self, key: FecSetKey) {
        if let Some(buf_idx) = self.in_progress.remove(&key) {
            self.in_progress_order.retain(|k| k != &key);

            self.buffers[buf_idx].resolved = true;

            // Record signature in done_map.
            let sig = self.buffers[buf_idx].first_signature;
            self.record_done_signature(sig);

            self.stats.sets_completed += 1;

            // Push to completed queue, recycling oldest completed if full.
            if self.completed_queue.len() >= self.complete_depth {
                if let Some(old_idx) = self.completed_queue.pop_front() {
                    self.buffers[old_idx].reset();
                    self.free_queue.push_back(old_idx);
                }
            }
            self.completed_queue.push_back(buf_idx);
        }
    }

    /// Release a completed buffer back to the free pool.
    ///
    /// Called after the consumer has fully processed the FEC set data.
    pub fn release_completed(&mut self) -> bool {
        if let Some(buf_idx) = self.completed_queue.pop_front() {
            self.buffers[buf_idx].reset();
            self.free_queue.push_back(buf_idx);
            true
        } else {
            false
        }
    }

    /// Access the buffer for an in-progress FEC set (read-only).
    pub fn get_buffer(&self, key: &FecSetKey) -> Option<FecSetView<'_>> {
        self.in_progress.get(key).map(|&idx| {
            let buf = &self.buffers[idx];
            FecSetView {
                data_shreds: &buf.data_shreds,
                coding_shreds: &buf.coding_shreds,
                num_data: buf.num_data,
                num_coding: buf.num_coding,
                params_known: buf.params_known,
                resolved: buf.resolved,
            }
        })
    }

    /// Access the buffer for an in-progress FEC set (mutable, for RS recovery).
    pub fn get_buffer_mut(&mut self, key: &FecSetKey) -> Option<FecSetViewMut<'_>> {
        self.in_progress.get(key).copied().map(move |idx| {
            let buf = &mut self.buffers[idx];
            FecSetViewMut {
                data_shreds: &mut buf.data_shreds,
                coding_shreds: &mut buf.coding_shreds,
                num_data: buf.num_data,
                num_coding: buf.num_coding,
                params_known: buf.params_known,
                resolved: &mut buf.resolved,
            }
        })
    }

    /// Retrieve the last spilled (evicted) FEC set info, if any.
    pub fn take_last_spilled(&mut self) -> Option<SpilledFecSet> {
        self.last_spilled.take()
    }

    /// Number of in-progress FEC sets.
    pub fn in_progress_count(&self) -> usize {
        self.in_progress.len()
    }

    /// Number of free buffers available.
    pub fn free_count(&self) -> usize {
        self.free_queue.len()
    }

    /// Number of completed buffers awaiting release.
    pub fn completed_count(&self) -> usize {
        self.completed_queue.len()
    }

    /// Total number of signatures in the done map.
    pub fn done_count(&self) -> usize {
        self.done_signatures.len()
    }

    /// Prune all FEC sets for slots below the given minimum.
    pub fn prune_slots_below(&mut self, min_slot: u64) {
        let keys_to_remove: Vec<FecSetKey> = self
            .in_progress
            .keys()
            .filter(|k| k.slot < min_slot)
            .copied()
            .collect();

        for key in keys_to_remove {
            if let Some(buf_idx) = self.in_progress.remove(&key) {
                self.buffers[buf_idx].reset();
                self.free_queue.push_back(buf_idx);
            }
        }
        self.in_progress_order.retain(|k| k.slot >= min_slot);
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Ensure a buffer is allocated for the given FEC set key.
    /// Returns the buffer index. May evict the oldest in-progress set.
    fn ensure_buffer(&mut self, key: FecSetKey) -> usize {
        // Already tracking this FEC set.
        if let Some(&idx) = self.in_progress.get(&key) {
            return idx;
        }

        // Allocate from free queue.
        let buf_idx = if let Some(idx) = self.free_queue.pop_front() {
            idx
        } else {
            // Pool exhausted — evict oldest in-progress FEC set.
            self.evict_oldest()
        };

        let buf = &mut self.buffers[buf_idx];
        buf.reset();
        buf.key = Some(key);

        self.in_progress.insert(key, buf_idx);
        self.in_progress_order.push_back(key);

        // Enforce depth limit.
        while self.in_progress.len() > self.depth {
            self.evict_oldest();
        }

        buf_idx
    }

    /// Evict the oldest in-progress FEC set, returning its buffer index to free.
    fn evict_oldest(&mut self) -> usize {
        let key = self
            .in_progress_order
            .pop_front()
            .expect("evict called with empty in-progress queue");
        let buf_idx = self
            .in_progress
            .remove(&key)
            .expect("in-progress key missing from map");

        let buf = &self.buffers[buf_idx];
        self.last_spilled = Some(SpilledFecSet {
            slot: key.slot,
            fec_set_index: key.fec_set_index,
            data_received: buf.data_shreds.len() as u32,
            coding_received: buf.coding_shreds.len() as u32,
        });
        self.stats.sets_spilled += 1;

        self.buffers[buf_idx].reset();
        // Don't push to free_queue — caller will use this index directly.
        buf_idx
    }

    /// Check whether the FEC set at the given buffer index is complete or recoverable.
    fn check_fec_status(&self, buf_idx: usize) -> ResolverInsertResult {
        let buf = &self.buffers[buf_idx];
        if buf.is_complete() {
            ResolverInsertResult::Complete
        } else if buf.is_recoverable() {
            ResolverInsertResult::Recoverable
        } else {
            ResolverInsertResult::Accepted
        }
    }

    /// Check if a signature belongs to a recently-completed FEC set.
    fn is_fec_set_done(&self, signature: &[u8; 64]) -> bool {
        // Skip zero signatures (erasure-recovered shreds have no real signature).
        if signature.iter().all(|&b| b == 0) {
            return false;
        }
        self.done_signatures.iter().any(|s| s == signature)
    }

    /// Record a completed FEC set's signature in the done map.
    fn record_done_signature(&mut self, signature: [u8; 64]) {
        // Don't record zero signatures.
        if signature.iter().all(|&b| b == 0) {
            return;
        }
        if self.done_signatures.len() >= self.done_depth {
            self.done_signatures.pop_front();
        }
        self.done_signatures.push_back(signature);
    }
}

/// Read-only view into an in-progress FEC set buffer.
pub struct FecSetView<'a> {
    pub data_shreds: &'a HashMap<u32, Shred>,
    pub coding_shreds: &'a HashMap<u32, Shred>,
    pub num_data: u32,
    pub num_coding: u32,
    pub params_known: bool,
    pub resolved: bool,
}

/// Mutable view into an in-progress FEC set buffer.
pub struct FecSetViewMut<'a> {
    pub data_shreds: &'a mut HashMap<u32, Shred>,
    pub coding_shreds: &'a mut HashMap<u32, Shred>,
    pub num_data: u32,
    pub num_coding: u32,
    pub params_known: bool,
    pub resolved: &'a mut bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use paradencer_types::shred::{
        CodingShredHeader, DataShredHeader, ShredCommonHeader, ShredVariant,
        DATA_SHRED_PAYLOAD_SIZE, SHRED_CODE_FLAG, SHRED_LEGACY_DATA_NIBBLE, SHRED_TYPE_LEGACY_DATA,
    };

    fn make_data_shred(slot: u64, index: u32, fec_set_index: u32) -> Shred {
        let mut sig = [0u8; 64];
        sig[..8].copy_from_slice(&slot.to_le_bytes());
        sig[8..12].copy_from_slice(&index.to_le_bytes());
        sig[12..16].copy_from_slice(&fec_set_index.to_le_bytes());
        // Ensure signature is non-zero for dedup tracking.
        sig[63] = 1;
        Shred::new(
            ShredCommonHeader {
                signature: sig,
                variant: SHRED_TYPE_LEGACY_DATA | SHRED_LEGACY_DATA_NIBBLE,
                slot,
                index,
                version: 1,
                fec_set_index,
            },
            ShredVariant::LegacyData(DataShredHeader {
                parent_offset: 1,
                flags: 0,
                size: DATA_SHRED_PAYLOAD_SIZE as u16,
            }),
            vec![0u8; DATA_SHRED_PAYLOAD_SIZE],
        )
    }

    fn make_coding_shred(
        slot: u64,
        index: u32,
        fec_set_index: u32,
        position: u16,
        num_data: u16,
        num_coding: u16,
    ) -> Shred {
        let mut sig = [0u8; 64];
        sig[..8].copy_from_slice(&slot.to_le_bytes());
        sig[8..12].copy_from_slice(&index.to_le_bytes());
        sig[12..16].copy_from_slice(&fec_set_index.to_le_bytes());
        sig[16] = 1;
        sig[17..19].copy_from_slice(&position.to_le_bytes());
        sig[63] = 1;
        Shred::new(
            ShredCommonHeader {
                signature: sig,
                variant: SHRED_CODE_FLAG,
                slot,
                index,
                version: 1,
                fec_set_index,
            },
            ShredVariant::LegacyCoding(CodingShredHeader {
                num_data_shreds: num_data,
                num_coding_shreds: num_coding,
                position,
            }),
            vec![0u8; DATA_SHRED_PAYLOAD_SIZE],
        )
    }

    #[test]
    fn pool_pre_allocates_buffers() {
        let pool = FecResolverPool::new(4, 8, 16);
        assert_eq!(pool.free_count(), 12); // 4 + 8
        assert_eq!(pool.in_progress_count(), 0);
        assert_eq!(pool.completed_count(), 0);
    }

    #[test]
    fn insert_data_shred_accepted() {
        let mut pool = FecResolverPool::new(4, 4, 16);
        let shred = make_data_shred(100, 0, 0);
        let result = pool.insert_data_shred(100, 0, 0, shred);
        assert_eq!(result, ResolverInsertResult::Accepted);
        assert_eq!(pool.in_progress_count(), 1);
        assert_eq!(pool.stats.shreds_inserted, 1);
    }

    #[test]
    fn insert_completes_fec_set() {
        let mut pool = FecResolverPool::new(4, 4, 16);

        // Insert 2 data shreds.
        pool.insert_data_shred(100, 0, 0, make_data_shred(100, 0, 0));
        pool.insert_data_shred(100, 0, 1, make_data_shred(100, 1, 0));

        // Insert coding shred to learn params (2 data, 2 coding).
        let result =
            pool.insert_coding_shred(100, 0, 0, 2, 2, make_coding_shred(100, 2, 0, 0, 2, 2));
        assert_eq!(result, ResolverInsertResult::Complete);
    }

    #[test]
    fn insert_triggers_recovery() {
        let mut pool = FecResolverPool::new(4, 4, 16);

        // FEC set: 3 data, 3 coding. Insert coding first.
        pool.insert_coding_shred(100, 0, 0, 3, 3, make_coding_shred(100, 3, 0, 0, 3, 3));

        // Insert 2 data shreds (need 3 for complete, but 2+1=3 total >= 3 needed).
        pool.insert_data_shred(100, 0, 0, make_data_shred(100, 0, 0));
        let result = pool.insert_data_shred(100, 0, 1, make_data_shred(100, 1, 0));
        assert_eq!(result, ResolverInsertResult::Recoverable);
    }

    #[test]
    fn duplicate_shred_rejected() {
        let mut pool = FecResolverPool::new(4, 4, 16);

        pool.insert_data_shred(100, 0, 0, make_data_shred(100, 0, 0));
        let result = pool.insert_data_shred(100, 0, 0, make_data_shred(100, 0, 0));
        assert_eq!(result, ResolverInsertResult::DuplicateShred);
        assert_eq!(pool.stats.duplicate_shreds_rejected, 1);
    }

    #[test]
    fn mark_completed_moves_to_completed_queue() {
        let mut pool = FecResolverPool::new(4, 4, 16);
        let key = FecSetKey {
            slot: 100,
            fec_set_index: 0,
        };

        pool.insert_data_shred(100, 0, 0, make_data_shred(100, 0, 0));
        assert_eq!(pool.in_progress_count(), 1);

        pool.mark_completed(key);
        assert_eq!(pool.in_progress_count(), 0);
        assert_eq!(pool.completed_count(), 1);
        assert_eq!(pool.done_count(), 1);
    }

    #[test]
    fn release_completed_returns_to_free() {
        let mut pool = FecResolverPool::new(4, 4, 16);
        let initial_free = pool.free_count();

        let key = FecSetKey {
            slot: 100,
            fec_set_index: 0,
        };
        pool.insert_data_shred(100, 0, 0, make_data_shred(100, 0, 0));
        // One buffer moved from free to in-progress.
        assert_eq!(pool.free_count(), initial_free - 1);

        pool.mark_completed(key);
        // Buffer moved from in-progress to completed.
        assert_eq!(pool.free_count(), initial_free - 1);

        pool.release_completed();
        // Buffer returned to free.
        assert_eq!(pool.free_count(), initial_free);
        assert_eq!(pool.completed_count(), 0);
    }

    #[test]
    fn depth_eviction_spills_oldest() {
        let mut pool = FecResolverPool::new(2, 2, 16);

        // Fill to depth.
        pool.insert_data_shred(100, 0, 0, make_data_shred(100, 0, 0));
        pool.insert_data_shred(200, 0, 0, make_data_shred(200, 0, 0));
        assert_eq!(pool.in_progress_count(), 2);

        // Third insertion evicts oldest (slot 100).
        pool.insert_data_shred(300, 0, 0, make_data_shred(300, 0, 0));
        assert_eq!(pool.in_progress_count(), 2);
        assert_eq!(pool.stats.sets_spilled, 1);

        let spilled = pool.take_last_spilled().unwrap();
        assert_eq!(spilled.slot, 100);
        assert_eq!(spilled.data_received, 1);
    }

    #[test]
    fn done_map_detects_duplicates() {
        let mut pool = FecResolverPool::new(4, 4, 16);

        // Insert and complete a FEC set.
        pool.insert_data_shred(100, 0, 0, make_data_shred(100, 0, 0));
        let key = FecSetKey {
            slot: 100,
            fec_set_index: 0,
        };
        pool.mark_completed(key);
        pool.release_completed();

        // Try to insert a shred with the same signature — should be rejected.
        let shred = make_data_shred(100, 0, 0);
        let result = pool.insert_data_shred(100, 0, 0, shred);
        assert_eq!(result, ResolverInsertResult::DuplicateFecSet);
        assert_eq!(pool.stats.duplicates_rejected, 1);
    }

    #[test]
    fn done_map_evicts_old_signatures() {
        let mut pool = FecResolverPool::new(4, 4, 4); // done_depth = 4

        // Complete 5 FEC sets — first signature should be evicted.
        for i in 0..5u64 {
            pool.insert_data_shred(i, 0, 0, make_data_shred(i, 0, 0));
            let key = FecSetKey {
                slot: i,
                fec_set_index: 0,
            };
            pool.mark_completed(key);
            pool.release_completed();
        }

        assert_eq!(pool.done_count(), 4); // capped at done_depth

        // Slot 0's signature should no longer be tracked.
        let old_shred = make_data_shred(0, 0, 0);
        let result = pool.insert_data_shred(0, 0, 0, old_shred);
        assert_eq!(result, ResolverInsertResult::Accepted); // Not detected as duplicate
    }

    #[test]
    fn get_buffer_returns_view() {
        let mut pool = FecResolverPool::new(4, 4, 16);
        let key = FecSetKey {
            slot: 100,
            fec_set_index: 0,
        };

        pool.insert_data_shred(100, 0, 0, make_data_shred(100, 0, 0));
        pool.insert_coding_shred(100, 0, 0, 2, 2, make_coding_shred(100, 2, 0, 0, 2, 2));

        let view = pool.get_buffer(&key).unwrap();
        assert_eq!(view.data_shreds.len(), 1);
        assert_eq!(view.coding_shreds.len(), 1);
        assert!(view.params_known);
        assert_eq!(view.num_data, 2);
        assert_eq!(view.num_coding, 2);
    }

    #[test]
    fn prune_slots_below_removes_old() {
        let mut pool = FecResolverPool::new(8, 4, 16);

        pool.insert_data_shred(10, 0, 0, make_data_shred(10, 0, 0));
        pool.insert_data_shred(20, 0, 0, make_data_shred(20, 0, 0));
        pool.insert_data_shred(30, 0, 0, make_data_shred(30, 0, 0));
        assert_eq!(pool.in_progress_count(), 3);

        pool.prune_slots_below(25);
        assert_eq!(pool.in_progress_count(), 1);

        let key30 = FecSetKey {
            slot: 30,
            fec_set_index: 0,
        };
        assert!(pool.get_buffer(&key30).is_some());
    }

    #[test]
    fn pool_lifecycle_full_cycle() {
        let mut pool = FecResolverPool::new(4, 4, 16);
        let initial_free = pool.free_count();

        // 1. Insert data shreds.
        pool.insert_data_shred(100, 0, 0, make_data_shred(100, 0, 0));
        pool.insert_data_shred(100, 0, 1, make_data_shred(100, 1, 0));

        // 2. Insert coding shred → complete.
        let result =
            pool.insert_coding_shred(100, 0, 0, 2, 2, make_coding_shred(100, 2, 0, 0, 2, 2));
        assert_eq!(result, ResolverInsertResult::Complete);

        // 3. Mark completed.
        let key = FecSetKey {
            slot: 100,
            fec_set_index: 0,
        };
        pool.mark_completed(key);
        assert_eq!(pool.in_progress_count(), 0);
        assert_eq!(pool.completed_count(), 1);

        // 4. Release back to free.
        assert!(pool.release_completed());
        assert_eq!(pool.completed_count(), 0);
        assert_eq!(pool.free_count(), initial_free);
    }

    #[test]
    fn completed_queue_recycles_oldest_when_full() {
        let mut pool = FecResolverPool::new(8, 2, 16); // complete_depth = 2

        // Complete 3 FEC sets — oldest completed should be recycled.
        for i in 0..3u64 {
            pool.insert_data_shred(i, 0, 0, make_data_shred(i, 0, 0));
            pool.mark_completed(FecSetKey {
                slot: i,
                fec_set_index: 0,
            });
        }

        // complete_depth is 2, so oldest (slot 0) was auto-recycled.
        assert_eq!(pool.completed_count(), 2);
    }

    #[test]
    fn multiple_fec_sets_per_slot() {
        let mut pool = FecResolverPool::new(8, 8, 16);

        pool.insert_data_shred(100, 0, 0, make_data_shred(100, 0, 0));
        pool.insert_data_shred(100, 4, 0, make_data_shred(100, 4, 4));

        assert_eq!(pool.in_progress_count(), 2);

        let key0 = FecSetKey {
            slot: 100,
            fec_set_index: 0,
        };
        let key4 = FecSetKey {
            slot: 100,
            fec_set_index: 4,
        };
        assert!(pool.get_buffer(&key0).is_some());
        assert!(pool.get_buffer(&key4).is_some());
    }

    #[test]
    fn with_defaults_uses_constants() {
        let pool = FecResolverPool::with_defaults();
        assert_eq!(
            pool.free_count(),
            FEC_RESOLVER_DEPTH + FEC_RESOLVER_COMPLETE_DEPTH
        );
    }
}
