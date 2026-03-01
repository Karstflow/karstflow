/// Dedicated service for persisting completed FEC sets to the blockstore.
///
/// Receives `CompletedFecSet` batches from `ShredNetworkStage` and writes
/// each data shred to the blockstore. Optionally subscribes to the replay
/// `SignalBus` for root advancement signals, triggering cleanup of slots
/// below the confirmed root.
///
/// Runs on its own service loop with a 5 ms tick interval. All blockstore
/// writes go through `Arc<Blockstore>` which is internally `RwLock`-protected,
/// making concurrent reads from other services safe.
use crate::replay_stage::{ReplaySignal, SignalBus};
use crate::shred_network::CompletedFecSet;
use crossbeam_channel::Receiver;
use paradencer_mesh::{DualReceiveError, DualReceiver};
use paradencer_runtime::{RuntimeResult, Service, ServiceContext};
use paradencer_storage::Blockstore;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Configuration for the shred store service.
#[derive(Debug, Clone)]
pub struct ShredStoreConfig {
    /// Maximum FEC sets to persist per tick.
    pub max_writes_per_tick: usize,
    /// Whether to purge slot data below the confirmed root.
    pub purge_below_root: bool,
}

impl Default for ShredStoreConfig {
    fn default() -> Self {
        Self {
            max_writes_per_tick: 64,
            purge_below_root: true,
        }
    }
}

/// Statistics for the shred store service.
#[derive(Debug, Clone, Default)]
pub struct ShredStoreStats {
    /// Total FEC sets received from the input channel.
    pub fec_sets_received: u64,
    /// FEC sets successfully persisted to blockstore.
    pub fec_sets_persisted: u64,
    /// Individual shreds written to blockstore.
    pub shreds_written: u64,
    /// Total bytes of shred payload written.
    pub bytes_written: u64,
    /// Write errors encountered.
    pub write_errors: u64,
    /// Slots cleaned up (purged below root).
    pub slots_cleaned: u64,
    /// Number of root advancement signals received.
    pub root_advancements: u64,
}

/// Service that persists completed FEC sets to the blockstore.
///
/// Thread safety: all shared state is behind `Arc` with internal locking.
/// - `blockstore`: `Arc<Blockstore>` uses `RwLock` internally for column families.
/// - `signal_rx`: `crossbeam_channel::Receiver` is `Send + Sync`.
/// - `fec_input`: `DualReceiver` wraps either a channel or tile link.
///
/// The service itself runs on a single thread (poll-driven `tick()` loop),
/// so its mutable fields (`stats`, `current_root`) require no synchronization.
pub struct ShredStoreService {
    config: ShredStoreConfig,
    blockstore: Arc<Blockstore>,
    /// Receives completed FEC sets from ShredNetworkStage.
    fec_input: DualReceiver<CompletedFecSet>,
    /// Receives replay signals for root advancement.
    signal_rx: Option<Receiver<ReplaySignal>>,
    /// Current confirmed root slot for cleanup threshold.
    current_root: u64,
    stats: ShredStoreStats,
}

impl ShredStoreService {
    /// Create a new shred store service.
    pub fn new(
        config: ShredStoreConfig,
        blockstore: Arc<Blockstore>,
        fec_input: DualReceiver<CompletedFecSet>,
    ) -> Self {
        Self {
            config,
            blockstore,
            fec_input,
            signal_rx: None,
            current_root: 0,
            stats: ShredStoreStats::default(),
        }
    }

    /// Subscribe to a signal bus for root advancement notifications.
    ///
    /// When the root advances, slots below the new root can be purged
    /// from the blockstore to reclaim space.
    pub fn with_signal_bus(mut self, signal_bus: Arc<Mutex<SignalBus>>) -> Self {
        let rx = signal_bus
            .lock()
            .expect("signal bus lock poisoned")
            .subscribe();
        self.signal_rx = rx;
        self
    }

    /// Current statistics.
    pub fn stats(&self) -> &ShredStoreStats {
        &self.stats
    }

    /// Current confirmed root slot.
    pub fn current_root(&self) -> u64 {
        self.current_root
    }

    /// Drain root advancement signals from the signal bus.
    fn drain_signals(&mut self) {
        if let Some(ref rx) = self.signal_rx {
            while let Ok(signal) = rx.try_recv() {
                if let ReplaySignal::RootAdvanced(info) = signal {
                    if info.new_root > self.current_root {
                        self.current_root = info.new_root;
                        self.stats.root_advancements += 1;
                    }
                }
            }
        }
    }

    /// Drain and persist completed FEC sets from the input channel.
    fn drain_and_persist(&mut self) {
        let mut writes = 0;

        while writes < self.config.max_writes_per_tick {
            match self.fec_input.try_recv() {
                Ok(Some(fec_set)) => {
                    self.stats.fec_sets_received += 1;
                    self.persist_fec_set(&fec_set);
                    writes += 1;
                }
                Ok(None) | Err(_) => break,
            }
        }
    }

    /// Write all data shreds from a completed FEC set to the blockstore.
    fn persist_fec_set(&mut self, fec_set: &CompletedFecSet) {
        let mut all_ok = true;

        for shred in &fec_set.data_shreds {
            match self.blockstore.insert_shred(shred) {
                Ok(_) => {
                    self.stats.shreds_written += 1;
                    self.stats.bytes_written += shred.payload.len() as u64;
                }
                Err(_) => {
                    self.stats.write_errors += 1;
                    all_ok = false;
                }
            }
        }

        if all_ok {
            self.stats.fec_sets_persisted += 1;
        }
    }

    /// Purge slot data below the confirmed root.
    fn cleanup_below_root(&mut self) {
        if !self.config.purge_below_root || self.current_root == 0 {
            return;
        }

        match self.blockstore.purge_slots_below(self.current_root) {
            Ok(purged) => {
                self.stats.slots_cleaned += purged as u64;
            }
            Err(_) => {
                // Cleanup failure is non-fatal; will retry next tick.
            }
        }
    }
}

impl Service for ShredStoreService {
    fn name(&self) -> &'static str {
        "shred-store"
    }

    fn tick_interval(&self) -> Duration {
        Duration::from_millis(5)
    }

    fn tick(&mut self, _context: &ServiceContext) -> RuntimeResult<()> {
        // 1. Process root advancement signals.
        self.drain_signals();

        // 2. Persist completed FEC sets.
        self.drain_and_persist();

        // 3. Clean up old slot data if root has advanced.
        self.cleanup_below_root();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replay_stage::RootAdvancedInfo;
    use paradencer_mesh::{bounded_link, DualReceiver};
    use paradencer_runtime::ShutdownSwitch;
    use paradencer_types::shred::{
        DataShredHeader, Shred, ShredCommonHeader, ShredVariant, DATA_SHRED_PAYLOAD_SIZE,
        SHRED_LEGACY_DATA_NIBBLE, SHRED_TYPE_LEGACY_DATA,
    };

    fn make_test_shred(slot: u64, index: u32, fec_set_index: u32) -> Shred {
        let mut sig = [0u8; 64];
        sig[..8].copy_from_slice(&slot.to_le_bytes());
        sig[8..12].copy_from_slice(&index.to_le_bytes());
        sig[12..16].copy_from_slice(&fec_set_index.to_le_bytes());

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
            vec![0xAB; DATA_SHRED_PAYLOAD_SIZE],
        )
    }

    fn create_test_fec_set(slot: u64, fec_set_index: u32) -> CompletedFecSet {
        CompletedFecSet {
            slot,
            fec_set_index,
            data_shreds: vec![make_test_shred(slot, 0, fec_set_index)],
            was_recovered: false,
        }
    }

    fn create_context() -> ServiceContext {
        ServiceContext::new(ShutdownSwitch::new())
    }

    #[test]
    fn service_constructs() {
        let blockstore = Arc::new(Blockstore::in_memory());
        let (_, fec_rx) = bounded_link::<CompletedFecSet>(16);

        let service = ShredStoreService::new(
            ShredStoreConfig::default(),
            blockstore,
            DualReceiver::Channel(fec_rx),
        );

        assert_eq!(service.name(), "shred-store");
        assert_eq!(service.current_root(), 0);
        assert_eq!(service.stats().fec_sets_received, 0);
    }

    #[test]
    fn persists_completed_fec_sets() {
        let blockstore = Arc::new(Blockstore::in_memory());
        let (fec_tx, fec_rx) = bounded_link::<CompletedFecSet>(16);

        let mut service = ShredStoreService::new(
            ShredStoreConfig::default(),
            blockstore.clone(),
            DualReceiver::Channel(fec_rx),
        );

        // Send a FEC set.
        fec_tx.try_send(create_test_fec_set(1, 0)).unwrap();

        let context = create_context();
        service.tick(&context).unwrap();

        assert_eq!(service.stats().fec_sets_received, 1);
        assert_eq!(service.stats().fec_sets_persisted, 1);
        assert_eq!(service.stats().shreds_written, 1);
        assert!(service.stats().bytes_written > 0);
    }

    #[test]
    fn respects_max_writes_per_tick() {
        let blockstore = Arc::new(Blockstore::in_memory());
        let (fec_tx, fec_rx) = bounded_link::<CompletedFecSet>(32);

        let config = ShredStoreConfig {
            max_writes_per_tick: 3,
            ..Default::default()
        };
        let mut service = ShredStoreService::new(config, blockstore, DualReceiver::Channel(fec_rx));

        // Send 5 FEC sets.
        for i in 0..5 {
            fec_tx.try_send(create_test_fec_set(i + 1, 0)).unwrap();
        }

        let context = create_context();
        service.tick(&context).unwrap();

        // Only 3 should be processed per tick.
        assert_eq!(service.stats().fec_sets_received, 3);

        // Tick again to process remaining 2.
        service.tick(&context).unwrap();
        assert_eq!(service.stats().fec_sets_received, 5);
    }

    #[test]
    fn root_advancement_updates_current_root() {
        let blockstore = Arc::new(Blockstore::in_memory());
        let (_, fec_rx) = bounded_link::<CompletedFecSet>(16);

        let signal_bus = Arc::new(Mutex::new(SignalBus::new()));
        let mut service = ShredStoreService::new(
            ShredStoreConfig {
                purge_below_root: false, // don't purge in this test
                ..Default::default()
            },
            blockstore,
            DualReceiver::Channel(fec_rx),
        )
        .with_signal_bus(Arc::clone(&signal_bus));

        // Emit root advancement.
        signal_bus
            .lock()
            .unwrap()
            .emit(ReplaySignal::RootAdvanced(RootAdvancedInfo {
                new_root: 50,
                previous_root: 0,
                pruned_slot_count: 0,
            }));

        let context = create_context();
        service.tick(&context).unwrap();

        assert_eq!(service.current_root(), 50);
        assert_eq!(service.stats().root_advancements, 1);

        // Higher root should update, lower should not.
        signal_bus
            .lock()
            .unwrap()
            .emit(ReplaySignal::RootAdvanced(RootAdvancedInfo {
                new_root: 30,
                previous_root: 0,
                pruned_slot_count: 0,
            }));
        signal_bus
            .lock()
            .unwrap()
            .emit(ReplaySignal::RootAdvanced(RootAdvancedInfo {
                new_root: 100,
                previous_root: 50,
                pruned_slot_count: 0,
            }));

        service.tick(&context).unwrap();
        assert_eq!(service.current_root(), 100);
        assert_eq!(service.stats().root_advancements, 2);
    }

    #[test]
    fn stats_tracking() {
        let blockstore = Arc::new(Blockstore::in_memory());
        let (fec_tx, fec_rx) = bounded_link::<CompletedFecSet>(16);

        let mut service = ShredStoreService::new(
            ShredStoreConfig::default(),
            blockstore,
            DualReceiver::Channel(fec_rx),
        );

        let context = create_context();

        // Multiple FEC sets.
        fec_tx.try_send(create_test_fec_set(1, 0)).unwrap();
        fec_tx.try_send(create_test_fec_set(2, 0)).unwrap();
        fec_tx.try_send(create_test_fec_set(3, 0)).unwrap();

        service.tick(&context).unwrap();

        let stats = service.stats();
        assert_eq!(stats.fec_sets_received, 3);
        assert_eq!(stats.fec_sets_persisted, 3);
        assert_eq!(stats.shreds_written, 3);
        assert!(stats.bytes_written > 0);
        assert_eq!(stats.write_errors, 0);
    }

    #[test]
    fn handles_empty_tick() {
        let blockstore = Arc::new(Blockstore::in_memory());
        let (_, fec_rx) = bounded_link::<CompletedFecSet>(16);

        let mut service = ShredStoreService::new(
            ShredStoreConfig::default(),
            blockstore,
            DualReceiver::Channel(fec_rx),
        );

        let context = create_context();

        // Empty tick should not error.
        service.tick(&context).unwrap();

        assert_eq!(service.stats().fec_sets_received, 0);
        assert_eq!(service.stats().fec_sets_persisted, 0);
    }
}
