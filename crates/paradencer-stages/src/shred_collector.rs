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
use paradencer_types::shred::Shred;
use std::collections::BTreeMap;
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
}

pub struct ShredCollector {
    config: ShredCollectorConfig,
    incoming_shreds: InPort<Shred>,
    /// Channel for completed FEC sets from the shred network stage.
    incoming_fec_sets: Option<InPort<CompletedFecSet>>,
    block_output: OutPort<AssembledBlock>,
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
            slot_buffers: BTreeMap::new(),
            assembler: ShredAssembler::new(),
            stats: ShredCollectorStats::default(),
        }
    }

    pub fn stats(&self) -> &ShredCollectorStats {
        &self.stats
    }

    /// Insert a completed FEC set's data shreds into the slot buffers.
    ///
    /// This is the primary integration point with `ShredNetworkStage`.
    /// After the network stage resolves FEC sets (via direct reception or
    /// Reed-Solomon recovery), completed sets are fed here for block assembly.
    pub fn insert_completed_fec_set(&mut self, fec_set: CompletedFecSet) {
        self.stats.fec_sets_received += 1;
        let slot = fec_set.slot;

        let buffer = self.slot_buffers.entry(slot).or_insert_with(|| SlotBuffer {
            shreds: Vec::new(),
            last_in_slot_seen: false,
            age_ticks: 0,
        });

        for shred in fec_set.data_shreds {
            self.stats.shreds_received += 1;
            let is_last = shred.is_last_in_slot();

            if buffer.shreds.len() < self.config.max_shreds_per_slot {
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
        let mut received_any = false;
        loop {
            match self.incoming_shreds.try_recv() {
                Ok(Some(shred)) => {
                    received_any = true;
                    self.stats.shreds_received += 1;
                    let slot = shred.slot();
                    let is_last = shred.is_last_in_slot();

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
                Ok(None) => break,
                Err(ReceiveError::QueueClosed) => return Err(ReceiveError::QueueClosed),
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
