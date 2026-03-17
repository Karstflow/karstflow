use tracing::info;

use crate::shredding::shred_produced_entries;

/// Spawn the leader orchestrator thread.
///
/// Subscribes to replay signals and drives the pipeline handle when this
/// validator becomes leader. After each leader slot completes, entries are
/// shredded and broadcast to the turbine tree, stored in the blockstore,
/// and fed back to the shred collector for self-replay.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_leader_orchestrator(
    signal_bus: &std::sync::Arc<std::sync::Mutex<karstflow_stages::SignalBus>>,
    handle: std::sync::Arc<karstflow_stages::PipelineHandle>,
    leader_pubkey: karstflow_storage::Pubkey,
    leader_signing_key: ed25519_dalek::SigningKey,
    shred_version: u16,
    orchestrator_retransmit: std::sync::Arc<
        std::sync::RwLock<Option<std::sync::Arc<karstflow_net::RetransmitService>>>,
    >,
    orchestrator_blockstore: Option<std::sync::Arc<karstflow_storage::Blockstore>>,
    mut orchestrator_shred_sender: Option<
        karstflow_mesh::DualSender<karstflow_types::shred::Shred>,
    >,
) {
    let leader_signal_rx = signal_bus
        .lock()
        .expect("signal_bus lock poisoned")
        .subscribe()
        .expect("signal bus subscriber limit not reached");

    std::thread::Builder::new()
        .name("leader-orchestrator".into())
        .spawn(move || {
            while let Ok(signal) = leader_signal_rx.recv() {
                match signal {
                    karstflow_stages::ReplaySignal::BecameLeader(info) => {
                        info!(
                            start_slot = info.start_slot,
                            end_slot = info.end_slot,
                            epoch = info.epoch,
                            "activating block production for leader range",
                        );
                        handle.begin_slot(info.start_slot);
                    }
                    karstflow_stages::ReplaySignal::SlotCompleted(info) => {
                        if handle.is_leading() && info.slot == handle.current_slot() {
                            let slot = info.slot;
                            handle.end_slot();
                            // Register the new blockhash so the resolv
                            // stage can validate transactions referencing it.
                            handle.register_blockhash(info.bank_hash, slot);

                            // Extract produced entries and shred them.
                            // The take_entries() call blocks briefly until
                            // the pipeline service processes the request.
                            let entry_batches = handle.take_entries();
                            if !entry_batches.is_empty() {
                                shred_produced_entries(
                                    slot,
                                    &entry_batches,
                                    leader_pubkey,
                                    &leader_signing_key,
                                    shred_version,
                                    orchestrator_blockstore.as_ref(),
                                    &mut orchestrator_shred_sender,
                                    orchestrator_retransmit
                                        .read()
                                        .ok()
                                        .and_then(|g| g.as_ref().cloned())
                                        .as_ref(),
                                );
                            }
                        }
                    }
                    karstflow_stages::ReplaySignal::RootAdvanced(info) => {
                        // Advance the resolv slot so stale transactions
                        // referencing blockhashes older than the root are
                        // expired.
                        handle.advance_slot(info.new_root);
                    }
                    _ => {}
                }
            }
        })
        .expect("failed to spawn leader orchestrator thread");
}
