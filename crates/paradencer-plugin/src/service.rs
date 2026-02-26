use std::path::Path;
use std::sync::{Arc, RwLock};
use std::thread;

use crossbeam_channel::Receiver;
use tracing::{error, info, warn};

use crate::error::PluginResult;
use crate::manager::{PluginManager, SharedPluginManager};
use crate::types::{BlockMetadata, SlotStatus};

/// Orchestrates plugin lifecycle and notification delivery.
///
/// The service owns the plugin manager and runs a background thread that
/// translates replay signals into plugin notifications (slot status, block
/// metadata). Account and transaction notifications are delivered directly
/// by the calling components via the shared plugin manager.
///
/// # Startup Flow
///
/// 1. Create `PluginService` with config file paths
/// 2. Plugins are loaded and `on_load()` is called
/// 3. Call `start_slot_observer()` with the signal receiver from replay stage
/// 4. Validator components call `manager()` to get the shared manager for
///    direct account/transaction notifications
/// 5. On shutdown, call `shutdown()` to stop the observer and unload plugins
pub struct PluginService {
    manager: SharedPluginManager,
    observer_handle: Option<thread::JoinHandle<()>>,
    shutdown_signal: Option<crossbeam_channel::Sender<()>>,
}

/// Slot status events received by the observer from the replay pipeline.
///
/// These map to the internal replay signals and are translated into
/// plugin `notify_slot_status()` and `notify_block_metadata()` calls.
#[derive(Debug, Clone)]
pub enum PluginEvent {
    /// Slot completed replay and bank was frozen.
    SlotCompleted {
        slot: u64,
        parent_slot: u64,
        bank_hash: [u8; 32],
        block_hash: [u8; 32],
        transaction_count: u64,
        executed_count: u64,
        fee_collected: u64,
        capitalization: u64,
        entry_count: u64,
        compute_units: u64,
        priority_fee: u64,
    },
    /// Slot marked dead.
    SlotDead { slot: u64, reason: String },
    /// Root advanced.
    RootAdvanced { new_root: u64, previous_root: u64 },
    /// Slot reached optimistic confirmation.
    OptimisticConfirmation { slot: u64 },
}

impl PluginService {
    /// Create a new plugin service and load plugins from config files.
    pub fn new(config_files: &[&Path]) -> PluginResult<Self> {
        let mut manager = PluginManager::new();
        for config_file in config_files {
            manager.load_plugin(config_file)?;
        }

        let count = manager.plugin_count();
        if count > 0 {
            info!(count, "plugin service initialized with active plugins");
        }

        Ok(Self {
            manager: Arc::new(RwLock::new(manager)),
            observer_handle: None,
            shutdown_signal: None,
        })
    }

    /// Create a plugin service with no plugins (for validators that don't use plugins).
    pub fn empty() -> Self {
        Self {
            manager: Arc::new(RwLock::new(PluginManager::new())),
            observer_handle: None,
            shutdown_signal: None,
        }
    }

    /// Get the shared plugin manager for direct notification delivery.
    ///
    /// Components like the account database and transaction processor use
    /// this to call `notify_account_update()` and `notify_transaction()` directly.
    pub fn manager(&self) -> SharedPluginManager {
        Arc::clone(&self.manager)
    }

    /// Start the background observer that translates replay events into plugin notifications.
    ///
    /// The observer reads from `event_receiver` and dispatches slot status and
    /// block metadata notifications to all loaded plugins.
    pub fn start_slot_observer(&mut self, event_receiver: Receiver<PluginEvent>) {
        let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded::<()>(1);
        let manager = Arc::clone(&self.manager);

        let handle = thread::Builder::new()
            .name("plugin-observer".into())
            .spawn(move || {
                Self::observer_loop(manager, event_receiver, shutdown_rx);
            })
            .expect("failed to spawn plugin observer thread");

        self.observer_handle = Some(handle);
        self.shutdown_signal = Some(shutdown_tx);
        info!("plugin slot observer started");
    }

    fn observer_loop(
        manager: SharedPluginManager,
        events: Receiver<PluginEvent>,
        shutdown: Receiver<()>,
    ) {
        loop {
            crossbeam_channel::select! {
                recv(shutdown) -> _ => {
                    info!("plugin observer received shutdown signal");
                    break;
                }
                recv(events) -> event => {
                    match event {
                        Ok(ev) => Self::handle_event(&manager, ev),
                        Err(_) => {
                            info!("plugin event channel closed — observer exiting");
                            break;
                        }
                    }
                }
            }
        }
    }

    fn handle_event(manager: &SharedPluginManager, event: PluginEvent) {
        let mgr = match manager.read() {
            Ok(m) => m,
            Err(e) => {
                error!("plugin manager lock poisoned: {e}");
                return;
            }
        };

        match event {
            PluginEvent::SlotCompleted {
                slot,
                parent_slot,
                bank_hash: _,
                block_hash,
                transaction_count: _,
                executed_count,
                fee_collected,
                capitalization: _,
                entry_count,
                compute_units,
                priority_fee,
            } => {
                // Notify slot processed.
                mgr.notify_slot_status(slot, Some(parent_slot), &SlotStatus::Processed);

                // Notify block metadata.
                let block = BlockMetadata {
                    slot,
                    parent_slot,
                    blockhash: block_hash,
                    parent_blockhash: [0; 32], // TODO: look up parent blockhash from BankForks
                    block_time: None,          // TODO: clock timestamp from Bank
                    block_height: None,        // TODO: block height from Bank
                    executed_transaction_count: executed_count,
                    entry_count,
                    total_compute_units: compute_units,
                    transaction_fee: fee_collected,
                    priority_fee,
                };
                mgr.notify_block_metadata(&block);
            }

            PluginEvent::SlotDead { slot, reason } => {
                mgr.notify_slot_status(slot, None, &SlotStatus::Dead(reason));
            }

            PluginEvent::RootAdvanced {
                new_root,
                previous_root: _,
            } => {
                mgr.notify_slot_status(new_root, None, &SlotStatus::Rooted);
            }

            PluginEvent::OptimisticConfirmation { slot } => {
                mgr.notify_slot_status(slot, None, &SlotStatus::Confirmed);
            }
        }
    }

    /// Shut down the plugin service: stop the observer and unload all plugins.
    pub fn shutdown(&mut self) {
        // Signal observer to stop.
        if let Some(tx) = self.shutdown_signal.take() {
            let _ = tx.send(());
        }

        // Wait for observer thread.
        if let Some(handle) = self.observer_handle.take() {
            if let Err(e) = handle.join() {
                warn!("plugin observer thread panicked: {e:?}");
            }
        }

        // Unload all plugins.
        match self.manager.write() {
            Ok(mut mgr) => mgr.unload_all(),
            Err(e) => error!("failed to lock plugin manager for shutdown: {e}"),
        }

        info!("plugin service shut down");
    }
}

impl Drop for PluginService {
    fn drop(&mut self) {
        if self.observer_handle.is_some() || self.shutdown_signal.is_some() {
            self.shutdown();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_service_creates_without_error() {
        let service = PluginService::empty();
        let mgr = service.manager();
        assert_eq!(mgr.read().unwrap().plugin_count(), 0);
    }

    #[test]
    fn observer_processes_events_and_shuts_down() {
        let mut service = PluginService::empty();
        let (tx, rx) = crossbeam_channel::bounded(64);

        service.start_slot_observer(rx);

        // Send some events.
        tx.send(PluginEvent::SlotCompleted {
            slot: 100,
            parent_slot: 99,
            bank_hash: [1; 32],
            block_hash: [2; 32],
            transaction_count: 50,
            executed_count: 48,
            fee_collected: 5000,
            capitalization: 1_000_000,
            entry_count: 10,
            compute_units: 200_000,
            priority_fee: 100,
        })
        .unwrap();

        tx.send(PluginEvent::RootAdvanced {
            new_root: 95,
            previous_root: 90,
        })
        .unwrap();

        tx.send(PluginEvent::OptimisticConfirmation { slot: 98 })
            .unwrap();

        tx.send(PluginEvent::SlotDead {
            slot: 97,
            reason: "test".into(),
        })
        .unwrap();

        // Shutdown cleanly.
        service.shutdown();
    }

    #[test]
    fn observer_exits_when_channel_closed() {
        let mut service = PluginService::empty();
        let (tx, rx) = crossbeam_channel::bounded(16);

        service.start_slot_observer(rx);

        // Drop sender — observer should detect and exit.
        drop(tx);

        // Shutdown waits for observer to finish.
        service.shutdown();
    }

    #[test]
    fn new_with_no_configs_succeeds() {
        let service = PluginService::new(&[]).unwrap();
        assert_eq!(service.manager().read().unwrap().plugin_count(), 0);
    }

    #[test]
    fn new_with_invalid_config_returns_error() {
        let result = PluginService::new(&[Path::new("/nonexistent/config.json")]);
        assert!(result.is_err());
    }
}
