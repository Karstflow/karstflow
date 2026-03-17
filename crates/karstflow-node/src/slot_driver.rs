use tracing::{info, warn};

/// Spawn the cluster slot driver thread.
///
/// Analogous to the dev slot driver but with leader schedule awareness:
/// - Ticks genesis bank and freezes it
/// - Enters timer loop that advances slots every 400ms
/// - Only produces blocks when this validator is the scheduled leader
/// - Non-leader slots are still ticked to keep bank state advancing
pub(crate) fn spawn_cluster_slot_driver(
    identity_pubkey: karstflow_storage::Pubkey,
    bank_forks: std::sync::Arc<std::sync::RwLock<karstflow_consensus::BankForks>>,
    signal_bus: std::sync::Arc<std::sync::Mutex<karstflow_stages::SignalBus>>,
    cluster_handle: std::sync::Arc<karstflow_stages::PipelineHandle>,
) {
    std::thread::Builder::new()
        .name("cluster-slot-driver".into())
        .spawn(move || {
            // Small delay to let leader orchestrator subscribe to signal bus.
            std::thread::sleep(std::time::Duration::from_millis(100));

            // Step 1: Tick and freeze the genesis bank.
            let forks = bank_forks.read().expect("bank_forks lock poisoned");
            let genesis_bank = forks.working_bank();
            let ticks_needed = genesis_bank
                .max_tick_height()
                .saturating_sub(genesis_bank.tick_height());
            for _ in 0..ticks_needed {
                if let Err(e) = genesis_bank.register_tick() {
                    warn!(error = ?e, "cluster-slot-driver: failed to register tick");
                    return;
                }
            }
            if let Err(e) = genesis_bank.freeze() {
                warn!(error = ?e, "cluster-slot-driver: failed to freeze genesis");
                return;
            }
            let genesis_slot = genesis_bank.slot();
            info!(slot = genesis_slot, "cluster-slot-driver: genesis bank frozen");
            drop(forks);

            // Step 2: Create child bank for slot 1.
            let mut current_slot = genesis_slot + 1;
            {
                let mut forks = bank_forks.write().expect("bank_forks lock poisoned");
                let parent = forks.working_bank();
                let ls = parent.leader_schedule();
                let child = karstflow_consensus::Bank::new_from_parent(
                    &parent, current_slot, ls.clone(),
                );
                if let Err(e) = forks.insert(child) {
                    warn!(error = ?e, "cluster-slot-driver: insert child failed");
                    return;
                }
                let _ = forks.set_working_bank(current_slot);
            }

            // Helper: check if identity is leader for a slot.
            let is_leader_for = |slot: u64| -> bool {
                let forks = bank_forks.read().expect("bank_forks lock poisoned");
                let bank = forks.working_bank();
                let schedule = bank.leader_schedule();
                let es_config = bank.epoch_schedule().config();
                let es = karstflow_consensus::EpochSchedule::new(*es_config);
                schedule
                    .leader_for_absolute_slot(slot, &es)
                    .map(|l| l == identity_pubkey)
                    .unwrap_or(false)
            };

            // Step 3: If leader for slot 1, emit BecameLeader.
            if is_leader_for(current_slot) {
                let mut end = current_slot + 1;
                while is_leader_for(end) { end += 1; }
                info!(
                    start_slot = current_slot, end_slot = end,
                    "cluster-slot-driver: leader for first slot, emitting BecameLeader",
                );
                let mut bus = signal_bus.lock().expect("signal_bus lock poisoned");
                bus.emit(karstflow_stages::ReplaySignal::BecameLeader(
                    karstflow_stages::BecameLeaderInfo {
                        start_slot: current_slot,
                        end_slot: end,
                        epoch: 0,
                        identity_pubkey: *identity_pubkey.as_bytes(),
                    },
                ));
            }

            // Step 4: Slot timer loop — advance slots every 400ms.
            let slot_duration = std::time::Duration::from_millis(400);
            loop {
                std::thread::sleep(slot_duration);

                let completed_slot = current_slot;

                // Track if we were leading — orchestrator handles end_slot on
                // SlotCompleted, but we need to know for signal emission.
                let was_leading = cluster_handle.is_leading();

                // Tick, finalize, and root the bank for the completed slot.
                {
                    let forks = bank_forks.read().expect("bank_forks lock poisoned");
                    let bank = forks.working_bank();
                    let ticks_needed =
                        bank.max_tick_height().saturating_sub(bank.tick_height());
                    for _ in 0..ticks_needed {
                        let _ = bank.register_tick();
                    }
                    if let Err(e) = bank.finish_slot() {
                        warn!(error = ?e, slot = completed_slot, "cluster-slot-driver: finish_slot failed");
                    }
                    let bank_hash = bank.last_blockhash();
                    let _ = bank.mark_rooted();

                    // Emit SlotCompleted so leader orchestrator shreds + broadcasts.
                    if was_leading {
                        let mut bus = signal_bus.lock().expect("signal_bus lock poisoned");
                        bus.emit(karstflow_stages::ReplaySignal::SlotCompleted(
                            karstflow_stages::SlotCompletedInfo {
                                slot: completed_slot,
                                parent_slot: completed_slot.saturating_sub(1),
                                bank_hash,
                                block_hash: bank_hash,
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
                }

                // Create child bank for next slot.
                current_slot = completed_slot + 1;
                {
                    let mut forks = bank_forks.write().expect("bank_forks lock poisoned");
                    let parent = forks.working_bank();
                    let ls = parent.leader_schedule();
                    let child = karstflow_consensus::Bank::new_from_parent(
                        &parent, current_slot, ls.clone(),
                    );
                    if let Err(e) = forks.insert(child) {
                        warn!(error = ?e, slot = current_slot, "cluster-slot-driver: insert failed");
                        break;
                    }
                    let _ = forks.set_working_bank(current_slot);
                    if let Err(e) = forks.set_root(completed_slot) {
                        warn!(error = ?e, "cluster-slot-driver: set_root failed");
                    }
                }

                // Check if this validator is leader for the new slot.
                if is_leader_for(current_slot) {
                    let mut end = current_slot + 1;
                    while is_leader_for(end) { end += 1; }
                    info!(
                        completed = completed_slot, next = current_slot, end_slot = end,
                        "cluster-slot-driver: became leader",
                    );
                    cluster_handle.begin_slot(current_slot);
                    let mut bus = signal_bus.lock().expect("signal_bus lock poisoned");
                    bus.emit(karstflow_stages::ReplaySignal::BecameLeader(
                        karstflow_stages::BecameLeaderInfo {
                            start_slot: current_slot,
                            end_slot: end,
                            epoch: 0,
                            identity_pubkey: *identity_pubkey.as_bytes(),
                        },
                    ));
                } else {
                    info!(
                        completed = completed_slot, next = current_slot,
                        "cluster-slot-driver: not leader, waiting",
                    );
                }
            }
        })
        .expect("failed to spawn cluster-slot-driver thread");
}

/// Spawn the dev mode slot driver thread.
///
/// Dev mode genesis completion: tick + freeze genesis bank, then emit
/// BecameLeader to bootstrap the block production cycle. Without this,
/// the leader orchestrator never receives a signal because SlotCompleted
/// is only emitted after replay_block(), and no blocks exist at genesis.
pub(crate) fn spawn_dev_slot_driver(
    identity_pubkey: karstflow_storage::Pubkey,
    bank_forks: std::sync::Arc<std::sync::RwLock<karstflow_consensus::BankForks>>,
    signal_bus: std::sync::Arc<std::sync::Mutex<karstflow_stages::SignalBus>>,
    dev_handle: std::sync::Arc<karstflow_stages::PipelineHandle>,
) {
    std::thread::Builder::new()
        .name("dev-slot-driver".into())
        .spawn(move || {
            // Small delay to let leader orchestrator subscribe to signal bus.
            std::thread::sleep(std::time::Duration::from_millis(100));

            // Step 1: Tick the genesis bank to completion (TICKS_PER_SLOT ticks).
            let forks = bank_forks.read().expect("bank_forks lock poisoned");
            let genesis_bank = forks.working_bank();
            let ticks_needed = genesis_bank
                .max_tick_height()
                .saturating_sub(genesis_bank.tick_height());
            for _ in 0..ticks_needed {
                if let Err(e) = genesis_bank.register_tick() {
                    warn!(error = ?e, "failed to register genesis tick");
                    return;
                }
            }

            // Step 2: Freeze the genesis bank.
            if let Err(e) = genesis_bank.freeze() {
                warn!(error = ?e, "failed to freeze genesis bank");
                return;
            }
            let genesis_slot = genesis_bank.slot();
            info!(
                slot = genesis_slot,
                tick_height = genesis_bank.tick_height(),
                "dev mode: genesis bank ticked and frozen",
            );
            drop(forks);

            // Step 3: Create child bank for slot 1 and start leading.
            let mut current_slot = genesis_slot + 1;
            {
                let mut forks = bank_forks.write().expect("bank_forks lock poisoned");
                let parent = forks.working_bank();
                let leader_schedule = parent.leader_schedule();
                let child = karstflow_consensus::Bank::new_from_parent(
                    &parent,
                    current_slot,
                    leader_schedule.clone(),
                );
                if let Err(e) = forks.insert(child) {
                    warn!(error = ?e, slot = current_slot, "failed to insert child bank");
                    return;
                }
                if let Err(e) = forks.set_working_bank(current_slot) {
                    warn!(error = ?e, slot = current_slot, "failed to set working bank");
                    return;
                }
                info!(
                    slot = current_slot,
                    "dev mode: created child bank for first leader slot"
                );
            }

            // Step 4: Emit initial BecameLeader to bootstrap block production.
            {
                info!(
                    start_slot = current_slot,
                    "dev mode: emitting BecameLeader to bootstrap block production",
                );
                let mut bus = signal_bus.lock().expect("signal_bus lock poisoned");
                bus.emit(karstflow_stages::ReplaySignal::BecameLeader(
                    karstflow_stages::BecameLeaderInfo {
                        start_slot: current_slot,
                        end_slot: current_slot + 1,
                        epoch: 0,
                        identity_pubkey: *identity_pubkey.as_bytes(),
                    },
                ));
            }

            // Step 5: Dev slot driver loop — complete slots on a timer.
            // The pipeline service advances PoH each tick. This thread
            // periodically completes the slot and starts the next one.
            let slot_duration = std::time::Duration::from_millis(400);
            loop {
                std::thread::sleep(slot_duration);

                if !dev_handle.is_leading() {
                    continue;
                }

                let completed_slot = current_slot;

                // End the current slot — pipeline service will call
                // finish_slot() and collect entries.
                dev_handle.end_slot();

                // Tick, finalize, and root the bank for the completed slot.
                {
                    let forks = bank_forks.read().expect("bank_forks lock poisoned");
                    let bank = forks.working_bank();
                    let ticks_needed =
                        bank.max_tick_height().saturating_sub(bank.tick_height());
                    for _ in 0..ticks_needed {
                        let _ = bank.register_tick();
                    }
                    if let Err(e) = bank.finish_slot() {
                        warn!(error = ?e, slot = completed_slot, "dev slot driver: finish_slot failed");
                    }
                    let _ = bank.mark_rooted();
                }

                // Create child bank for next slot and advance root.
                current_slot = completed_slot + 1;
                {
                    let mut forks = bank_forks.write().expect("bank_forks lock poisoned");
                    let parent = forks.working_bank();
                    let leader_schedule = parent.leader_schedule();
                    let child = karstflow_consensus::Bank::new_from_parent(
                        &parent,
                        current_slot,
                        leader_schedule.clone(),
                    );
                    if let Err(e) = forks.insert(child) {
                        warn!(
                            error = ?e,
                            slot = current_slot,
                            "dev slot driver: failed to insert bank"
                        );
                        break;
                    }
                    let _ = forks.set_working_bank(current_slot);

                    // Advance root to the completed slot so RPC
                    // sees finalized/confirmed state progressing.
                    if let Err(e) = forks.set_root(completed_slot) {
                        warn!(
                            error = ?e,
                            slot = completed_slot,
                            "dev slot driver: failed to set root"
                        );
                    }
                }

                info!(
                    completed = completed_slot,
                    next = current_slot,
                    "dev mode: slot completed, starting next"
                );

                // Begin next slot.
                dev_handle.begin_slot(current_slot);
            }
        })
        .expect("failed to spawn dev slot driver thread");
}
