//! Cluster bootstrap — one-time initialization for genesis-based startup.
//!
//! Ticks and freezes the genesis bank, creates the first leader bank if
//! this node is the scheduled leader, and emits the initial BecameLeader
//! signal to start block production.
//!
//! After bootstrap, all slot advancement is driven by PoH (continuous
//! hashing) + Replay (block processing) + Leader Orchestrator (entries
//! → shredding → begin next slot). No separate slot driver thread.

use karstflow_consensus::EpochSchedule;
use tracing::{info, warn};

/// Bootstrap the cluster from genesis.
///
/// This is a one-time operation called during node startup for genesis-file
/// cluster mode. After this function returns, the runtime services (PoH,
/// replay, orchestrator) take over all slot management.
pub(crate) fn bootstrap_genesis_and_start_leading(
    identity_pubkey: karstflow_storage::Pubkey,
    bank_forks: &std::sync::Arc<std::sync::RwLock<karstflow_consensus::BankForks>>,
    fork_choice: &std::sync::Arc<std::sync::Mutex<karstflow_consensus::ForkChoice>>,
    signal_bus: &std::sync::Arc<std::sync::Mutex<karstflow_stages::SignalBus>>,
    _pipeline_handle: &std::sync::Arc<karstflow_stages::PipelineHandle>,
) {
    // Step 1: Tick and freeze the genesis bank.
    {
        let forks = bank_forks.read().expect("bank_forks lock poisoned");
        let genesis_bank = forks.working_bank();
        let ticks_needed = genesis_bank
            .max_tick_height()
            .saturating_sub(genesis_bank.tick_height());
        for _ in 0..ticks_needed {
            if let Err(e) = genesis_bank.register_tick() {
                warn!(error = ?e, "cluster-bootstrap: failed to register genesis tick");
                return;
            }
        }
        if let Err(e) = genesis_bank.finish_slot() {
            warn!(error = ?e, "cluster-bootstrap: failed to finalize genesis");
            return;
        }
        // Mark genesis rooted so set_root works when Tower advances.
        let _ = genesis_bank.mark_rooted();
        let genesis_slot = genesis_bank.slot();
        let genesis_hash = genesis_bank.last_blockhash();
        info!(
            slot = genesis_slot,
            "cluster-bootstrap: genesis bank finalized"
        );
        drop(forks);

        // Register genesis in fork choice.
        fork_choice
            .lock()
            .expect("fork_choice lock poisoned")
            .add_fork(genesis_slot, None);

        // Emit SlotCompleted for genesis so resolv-blockhash thread
        // registers the genesis hash.
        let mut bus = signal_bus.lock().expect("signal_bus lock poisoned");
        bus.emit(karstflow_stages::ReplaySignal::SlotCompleted(
            karstflow_stages::SlotCompletedInfo {
                slot: genesis_slot,
                parent_slot: 0,
                bank_hash: genesis_hash,
                block_hash: genesis_hash,
                parent_blockhash: [0u8; 32],
                epoch: 0,
                is_epoch_boundary: false,
                transaction_count: 0,
                executed_count: 0,
                fee_lamports_collected: 0,
                capitalization: 0,
                timestamp: 0,
            },
        ));
    }

    // Step 2: Determine first leader slot.
    let first_leader_slot = {
        let forks = bank_forks.read().expect("bank_forks lock poisoned");
        let bank = forks.working_bank();
        let schedule = bank.leader_schedule();
        let es_config = bank.epoch_schedule().config();
        let es = EpochSchedule::new(*es_config);

        // Scan forward from slot 1 to find our first leader slot.
        let mut leader_slot = None;
        for slot in 1..=64 {
            if let Some(leader) = schedule.leader_for_absolute_slot(slot, &es) {
                if leader == identity_pubkey {
                    leader_slot = Some(slot);
                    break;
                }
            }
        }
        leader_slot
    };

    // Step 3: If we're leader for the first slot, create bank and emit BecameLeader.
    if let Some(slot) = first_leader_slot {
        if slot == 1 {
            // We're leader immediately after genesis — create bank now.
            let mut forks = bank_forks.write().expect("bank_forks lock poisoned");
            let parent = forks.working_bank();
            let ls = parent.leader_schedule();
            let child = karstflow_consensus::Bank::new_from_parent(&parent, slot, ls.clone());
            if let Err(e) = forks.insert(child) {
                warn!(error = ?e, "cluster-bootstrap: insert first leader bank failed");
                return;
            }
            let _ = forks.set_working_bank(slot);
            drop(forks);

            // Register in fork choice so consensus can vote for this slot.
            fork_choice
                .lock()
                .expect("fork_choice lock poisoned")
                .add_fork(slot, Some(0));

            // Find the end of our leader range.
            let end_slot = {
                let forks = bank_forks.read().expect("bank_forks lock poisoned");
                let bank = forks.working_bank();
                let schedule = bank.leader_schedule();
                let es_config = bank.epoch_schedule().config();
                let es = EpochSchedule::new(*es_config);
                let mut end = slot + 1;
                while schedule
                    .leader_for_absolute_slot(end, &es)
                    .map(|l| l == identity_pubkey)
                    .unwrap_or(false)
                {
                    end += 1;
                }
                end
            };

            let parent_hash = {
                let forks = bank_forks.read().expect("bank_forks lock poisoned");
                forks.working_bank().last_blockhash()
            };

            info!(
                start_slot = slot,
                end_slot = end_slot,
                "cluster-bootstrap: leader for first slot, emitting BecameLeader",
            );
            let mut bus = signal_bus.lock().expect("signal_bus lock poisoned");
            bus.emit(karstflow_stages::ReplaySignal::BecameLeader(
                karstflow_stages::BecameLeaderInfo {
                    start_slot: slot,
                    end_slot,
                    epoch: 0,
                    identity_pubkey: *identity_pubkey.as_bytes(),
                    parent_blockhash: parent_hash,
                },
            ));
        } else {
            info!(
                first_leader = slot,
                "cluster-bootstrap: not leader for slot 1, waiting for blocks from peer",
            );
        }
    } else {
        info!("cluster-bootstrap: no leader slot found in first 64 slots");
    }

    // After bootstrap, PoH + Replay + Orchestrator handle everything:
    // - PoH hashes continuously, produces ticks and entries
    // - Orchestrator on SlotCompleted: end_slot → shred → begin_slot(next)
    // - When orchestrator finishes leader range, PoH transitions to follower
    // - Replay processes blocks from turbine → freeze → check schedule →
    //   emit BecameLeader if next slot is ours
    // - Orchestrator on BecameLeader: begin_slot → PoH starts leading
}
