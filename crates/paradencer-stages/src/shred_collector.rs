/// Collects individual shreds from the ingress filter, groups them by slot,
/// and emits assembled blocks once a slot boundary is detected.
///
/// This service sits between ShredFilter (which outputs individual parsed
/// shreds) and ReplayService (which expects assembled blocks). It maintains
/// a per-slot buffer and uses the last-in-slot flag to determine when a
/// complete slot can be assembled.
///
/// Also accepts completed FEC sets from the shred network stage, which
/// provide already-resolved data shreds (possibly recovered via Reed-Solomon).
use crate::shred_assembler::{AssembledBlock, ShredAssembler};
use crate::shred_network::CompletedFecSet;
use paradencer_mesh::{InPort, OutPort, ReceiveError, SendError};
use paradencer_runtime::{RuntimeError, RuntimeResult, Service, ServiceContext};
use paradencer_storage::Blockstore;
use paradencer_types::shred::Shred;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

/// Configuration for the shred collector.
#[derive(Debug, Clone)]
pub struct ShredCollectorConfig {
    /// Maximum number of slots to buffer concurrently.
    pub max_buffered_slots: usize,
    /// Maximum shreds per slot before forced eviction.
    pub max_shreds_per_slot: usize,
    /// Maximum age in ticks before an incomplete slot is evicted.
    pub max_slot_age_ticks: u64,
}

impl Default for ShredCollectorConfig {
    fn default() -> Self {
        Self {
            max_buffered_slots: 64,
            max_shreds_per_slot: 2048,
            max_slot_age_ticks: 200,
        }
    }
}

/// Per-slot accumulation state.
struct SlotBuffer {
    shreds: Vec<Shred>,
    last_in_slot_seen: bool,
    age_ticks: u64,
}

/// Statistics for the shred collector.
#[derive(Debug, Clone, Default)]
pub struct ShredCollectorStats {
    pub shreds_received: u64,
    pub fec_sets_received: u64,
    pub blocks_emitted: u64,
    pub slots_evicted_age: u64,
    pub slots_evicted_overflow: u64,
    pub assembly_failures: u64,
    pub downstream_backpressure: u64,
    /// Number of shreds successfully persisted to the blockstore.
    pub blockstore_writes: u64,
    /// Number of shred blockstore writes that failed.
    pub blockstore_write_errors: u64,
}

pub struct ShredCollector {
    config: ShredCollectorConfig,
    incoming_shreds: InPort<Shred>,
    /// Channel for completed FEC sets from the shred network stage.
    incoming_fec_sets: Option<InPort<CompletedFecSet>>,
    block_output: OutPort<AssembledBlock>,
    /// Optional persistent storage for write-through shred persistence.
    blockstore: Option<Arc<Blockstore>>,
    slot_buffers: BTreeMap<u64, SlotBuffer>,
    assembler: ShredAssembler,
    stats: ShredCollectorStats,
}

impl ShredCollector {
    pub fn new(incoming_shreds: InPort<Shred>, block_output: OutPort<AssembledBlock>) -> Self {
        Self::with_config(
            incoming_shreds,
            block_output,
            ShredCollectorConfig::default(),
        )
    }

    /// Create with an additional channel for FEC-resolved shred sets.
    pub fn with_fec_input(
        incoming_shreds: InPort<Shred>,
        incoming_fec_sets: InPort<CompletedFecSet>,
        block_output: OutPort<AssembledBlock>,
    ) -> Self {
        Self {
            config: ShredCollectorConfig::default(),
            incoming_shreds,
            incoming_fec_sets: Some(incoming_fec_sets),
            block_output,
            blockstore: None,
            slot_buffers: BTreeMap::new(),
            assembler: ShredAssembler::new(),
            stats: ShredCollectorStats::default(),
        }
    }

    pub fn with_config(
        incoming_shreds: InPort<Shred>,
        block_output: OutPort<AssembledBlock>,
        config: ShredCollectorConfig,
    ) -> Self {
        Self {
            config,
            incoming_shreds,
            incoming_fec_sets: None,
            block_output,
            blockstore: None,
            slot_buffers: BTreeMap::new(),
            assembler: ShredAssembler::new(),
            stats: ShredCollectorStats::default(),
        }
    }

    /// Attach persistent blockstore for write-through shred persistence.
    ///
    /// When a blockstore is attached, every received shred is written to
    /// persistent storage before block assembly. This enables the repair
    /// service to serve shreds from disk and provides crash recovery.
    pub fn set_blockstore(&mut self, blockstore: Arc<Blockstore>) {
        self.blockstore = Some(blockstore);
    }

    pub fn stats(&self) -> &ShredCollectorStats {
        &self.stats
    }

    /// Persist a shred to the blockstore if one is attached.
    ///
    /// Errors are counted but not propagated — blockstore writes must not
    /// block the real-time shred pipeline. The repair service can request
    /// missing shreds later if persistence fails.
    fn persist_shred(&mut self, shred: &Shred) {
        if let Some(ref blockstore) = self.blockstore {
            match blockstore.insert_shred(shred) {
                Ok(_) => self.stats.blockstore_writes += 1,
                Err(_) => self.stats.blockstore_write_errors += 1,
            }
        }
    }

    /// Insert a completed FEC set's data shreds into the slot buffers.
    ///
    /// This is the primary integration point with `ShredNetworkStage`.
    /// After the network stage resolves FEC sets (via direct reception or
    /// Reed-Solomon recovery), completed sets are fed here for block assembly.
    pub fn insert_completed_fec_set(&mut self, fec_set: CompletedFecSet) {
        self.stats.fec_sets_received += 1;
        let slot = fec_set.slot;
        let max_shreds = self.config.max_shreds_per_slot;

        // Persist shreds to blockstore before buffering.
        for shred in &fec_set.data_shreds {
            self.persist_shred(shred);
        }

        let buffer = self.slot_buffers.entry(slot).or_insert_with(|| SlotBuffer {
            shreds: Vec::new(),
            last_in_slot_seen: false,
            age_ticks: 0,
        });

        for shred in fec_set.data_shreds {
            self.stats.shreds_received += 1;
            let is_last = shred.is_last_in_slot();

            if buffer.shreds.len() < max_shreds {
                buffer.shreds.push(shred);
            }
            if is_last {
                buffer.last_in_slot_seen = true;
            }
        }
    }

    /// Drain completed FEC sets from the network stage channel.
    fn drain_incoming_fec_sets(&mut self) {
        // Collect FEC sets first to avoid borrow conflict.
        let mut fec_sets = Vec::new();
        if let Some(ref fec_port) = self.incoming_fec_sets {
            loop {
                match fec_port.try_recv() {
                    Ok(Some(fec_set)) => fec_sets.push(fec_set),
                    Ok(None) => break,
                    Err(ReceiveError::QueueClosed) => break,
                }
            }
        }
        for fec_set in fec_sets {
            self.insert_completed_fec_set(fec_set);
        }
    }

    /// Drain all available shreds from the input channel into slot buffers.
    fn drain_incoming(&mut self) -> Result<bool, ReceiveError> {
        // Collect shreds from the channel first, then process them.
        // This avoids borrow conflicts between the channel, persist, and buffer.
        let mut batch = Vec::new();
        loop {
            match self.incoming_shreds.try_recv() {
                Ok(Some(shred)) => batch.push(shred),
                Ok(None) => break,
                Err(ReceiveError::QueueClosed) => {
                    if batch.is_empty() {
                        return Err(ReceiveError::QueueClosed);
                    }
                    break;
                }
            }
        }

        let received_any = !batch.is_empty();
        for shred in batch {
            self.stats.shreds_received += 1;
            let slot = shred.slot();
            let is_last = shred.is_last_in_slot();

            self.persist_shred(&shred);

            let buffer = self.slot_buffers.entry(slot).or_insert_with(|| SlotBuffer {
                shreds: Vec::new(),
                last_in_slot_seen: false,
                age_ticks: 0,
            });

            if buffer.shreds.len() < self.config.max_shreds_per_slot {
                buffer.shreds.push(shred);
            }
            if is_last {
                buffer.last_in_slot_seen = true;
            }
        }
        Ok(received_any)
    }

    /// Assemble and emit blocks for any slots that have received all shreds.
    fn try_emit_complete_slots(&mut self, context: &ServiceContext) -> RuntimeResult<()> {
        let complete_slots: Vec<u64> = self
            .slot_buffers
            .iter()
            .filter(|(_, buf)| buf.last_in_slot_seen)
            .map(|(slot, _)| *slot)
            .collect();

        for slot in complete_slots {
            if let Some(buffer) = self.slot_buffers.remove(&slot) {
                self.emit_block(context, buffer.shreds)?;
            }
        }
        Ok(())
    }

    /// Age all buffered slots and evict any that exceed the age limit.
    fn age_and_evict(&mut self) {
        let max_age = self.config.max_slot_age_ticks;
        let mut evicted_slots = Vec::new();

        for (slot, buffer) in &mut self.slot_buffers {
            buffer.age_ticks += 1;
            if buffer.age_ticks > max_age {
                evicted_slots.push(*slot);
            }
        }

        for slot in evicted_slots {
            self.slot_buffers.remove(&slot);
            self.stats.slots_evicted_age += 1;
        }

        // Evict oldest slots if we exceed the max buffer count.
        while self.slot_buffers.len() > self.config.max_buffered_slots {
            if let Some(oldest_slot) = self.slot_buffers.keys().next().copied() {
                self.slot_buffers.remove(&oldest_slot);
                self.stats.slots_evicted_overflow += 1;
            }
        }
    }

    fn emit_block(&mut self, context: &ServiceContext, shreds: Vec<Shred>) -> RuntimeResult<()> {
        match self.assembler.assemble_block(shreds) {
            Ok(block) => match self.block_output.try_send(block) {
                Ok(()) => {
                    self.stats.blocks_emitted += 1;
                    Ok(())
                }
                Err(SendError::QueueFull(_)) => {
                    self.stats.downstream_backpressure += 1;
                    Ok(())
                }
                Err(SendError::QueueClosed(_)) => {
                    context.shutdown.request_stop();
                    Err(RuntimeError::service_failure(
                        self.name(),
                        "block output link closed",
                    ))
                }
            },
            Err(_) => {
                self.stats.assembly_failures += 1;
                Ok(())
            }
        }
    }
}

impl Service for ShredCollector {
    fn name(&self) -> &'static str {
        "shred-collector"
    }

    fn tick_interval(&self) -> Duration {
        Duration::from_millis(5)
    }

    fn tick(&mut self, context: &ServiceContext) -> RuntimeResult<()> {
        match self.drain_incoming() {
            Ok(_) => {}
            Err(ReceiveError::QueueClosed) => {
                context.shutdown.request_stop();
                return Err(RuntimeError::service_failure(
                    self.name(),
                    "shred input link closed",
                ));
            }
        }

        // Drain completed FEC sets from the network stage.
        self.drain_incoming_fec_sets();

        self.try_emit_complete_slots(context)?;
        self.age_and_evict();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paradencer_mesh::bounded_link;
    use paradencer_types::shred::{
        DataShredHeader, ShredCommonHeader, ShredVariant, SIGNATURE_SIZE,
    };

    fn make_data_shred(slot: u64, index: u32, last_in_slot: bool) -> Shred {
        let common = ShredCommonHeader {
            signature: [0u8; SIGNATURE_SIZE],
            variant: 0x55, // legacy data
            slot,
            index,
            version: 1,
            fec_set_index: 0,
        };
        let flags = if last_in_slot { 0x80 } else { 0 };
        let data_header = DataShredHeader {
            parent_offset: 1,
            flags,
            size: 64,
        };
        Shred::new(
            common,
            ShredVariant::LegacyData(data_header),
            vec![0xAA; 64],
        )
    }

    #[test]
    fn collector_persists_shreds_to_blockstore_on_drain() {
        let blockstore = Arc::new(Blockstore::in_memory());
        let (shred_tx, shred_rx) = bounded_link::<Shred>(64);
        let (_block_tx, block_rx) = bounded_link::<AssembledBlock>(8);

        // Swap tx/rx: collector reads from shred_rx, we write to shred_tx.
        let mut collector = ShredCollector::new(shred_rx, _block_tx);
        collector.set_blockstore(Arc::clone(&blockstore));

        // Send two shreds.
        shred_tx.try_send(make_data_shred(10, 0, false)).unwrap();
        shred_tx.try_send(make_data_shred(10, 1, false)).unwrap();

        // Drain incoming — should persist both.
        collector.drain_incoming().unwrap();

        assert_eq!(collector.stats.blockstore_writes, 2);
        assert_eq!(collector.stats.blockstore_write_errors, 0);

        // Verify data is readable from blockstore.
        assert!(blockstore.get_data_shred(10, 0).unwrap().is_some());
        assert!(blockstore.get_data_shred(10, 1).unwrap().is_some());
        assert!(blockstore.get_data_shred(10, 2).unwrap().is_none());

        // Drop unused receiver to avoid warnings.
        drop(block_rx);
    }

    #[test]
    fn collector_persists_fec_set_shreds_to_blockstore() {
        let blockstore = Arc::new(Blockstore::in_memory());
        let (shred_tx, shred_rx) = bounded_link::<Shred>(64);
        let (block_tx, _block_rx) = bounded_link::<AssembledBlock>(8);

        let mut collector = ShredCollector::new(shred_rx, block_tx);
        collector.set_blockstore(Arc::clone(&blockstore));

        let fec_set = CompletedFecSet {
            slot: 20,
            fec_set_index: 0,
            data_shreds: vec![
                make_data_shred(20, 0, false),
                make_data_shred(20, 1, false),
                make_data_shred(20, 2, true),
            ],
            was_recovered: false,
        };

        collector.insert_completed_fec_set(fec_set);

        assert_eq!(collector.stats.blockstore_writes, 3);
        assert!(blockstore.get_data_shred(20, 0).unwrap().is_some());
        assert!(blockstore.get_data_shred(20, 1).unwrap().is_some());
        assert!(blockstore.get_data_shred(20, 2).unwrap().is_some());

        // Last-in-slot flag should be recorded in slot metadata.
        let meta = blockstore.get_slot_meta(20).unwrap().unwrap();
        assert_eq!(meta.expected_data_shreds, Some(3));

        drop(shred_tx);
    }

    #[test]
    fn collector_works_without_blockstore() {
        let (shred_tx, shred_rx) = bounded_link::<Shred>(64);
        let (block_tx, _block_rx) = bounded_link::<AssembledBlock>(8);

        let mut collector = ShredCollector::new(shred_rx, block_tx);
        // No blockstore set — should still function normally.

        shred_tx.try_send(make_data_shred(5, 0, false)).unwrap();
        collector.drain_incoming().unwrap();

        assert_eq!(collector.stats.shreds_received, 1);
        assert_eq!(collector.stats.blockstore_writes, 0);
        assert_eq!(collector.stats.blockstore_write_errors, 0);

        drop(shred_tx);
    }

    #[test]
    fn collector_blockstore_and_buffer_both_populated() {
        let blockstore = Arc::new(Blockstore::in_memory());
        let (shred_tx, shred_rx) = bounded_link::<Shred>(64);
        let (block_tx, _block_rx) = bounded_link::<AssembledBlock>(8);

        let mut collector = ShredCollector::new(shred_rx, block_tx);
        collector.set_blockstore(Arc::clone(&blockstore));

        shred_tx.try_send(make_data_shred(7, 0, false)).unwrap();
        collector.drain_incoming().unwrap();

        // Blockstore has the shred.
        assert!(blockstore.get_data_shred(7, 0).unwrap().is_some());
        // In-memory buffer also has it.
        assert_eq!(collector.slot_buffers.get(&7).unwrap().shreds.len(), 1);
    }
}
