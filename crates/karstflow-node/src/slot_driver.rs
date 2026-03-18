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
    pipeline_handle: std::sync::Arc<karstflow_stages::PipelineHandle>,
    hashes_per_tick: u64,
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
            if let Err(e) = genesis_bank.finish_slot() {
                warn!(error = ?e, "cluster-slot-driver: failed to finalize genesis");
                return;
            }
            let genesis_slot = genesis_bank.slot();
            let genesis_hash = genesis_bank.last_blockhash();
            info!(slot = genesis_slot, "cluster-slot-driver: genesis bank frozen");
            drop(forks);

            // Emit SlotCompleted for genesis so the resolv-blockhash thread
            // registers the genesis hash in the blockhash ring.
            {
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

            // Step 2: Create child bank for slot 1 only if we are leader.
            // Non-leader slots are handled by replay when blocks arrive
            // from the leader peer via turbine.
            let mut current_slot = genesis_slot + 1;
            if is_leader_for(current_slot) {
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

                // Step 3: Emit BecameLeader for our leader range.
                let mut end = current_slot + 1;
                while is_leader_for(end) {
                    end += 1;
                }
                let parent_hash = {
                    let forks = bank_forks.read().expect("bank_forks lock poisoned");
                    forks.working_bank().last_blockhash()
                };
                info!(
                    start_slot = current_slot,
                    end_slot = end,
                    "cluster-slot-driver: leader for first slot, emitting BecameLeader",
                );
                let mut bus = signal_bus.lock().expect("signal_bus lock poisoned");
                bus.emit(karstflow_stages::ReplaySignal::BecameLeader(
                    karstflow_stages::BecameLeaderInfo {
                        start_slot: current_slot,
                        end_slot: end,
                        epoch: 0,
                        identity_pubkey: *identity_pubkey.as_bytes(),
                        parent_blockhash: parent_hash,
                    },
                ));
            } else {
                info!(
                    slot = current_slot,
                    "cluster-slot-driver: not leader for slot 1, waiting for blocks from peer",
                );
            }

            // Step 4: Slot timer loop — advance slots every 400ms.
            //
            // Only creates banks for leader slots. Non-leader slot banks
            // are created by replay when blocks arrive from peers.
            // This follows the reference implementation pattern where replay
            // owns bank lifecycle for received blocks.
            //
            // With production PoH (hashes_per_tick > 1), the pipeline's PoH
            // service provides the ~400ms slot timing via SHA-256 hashing.
            // The slot driver uses a short poll interval to check completion.
            // With dev PoH (hashes_per_tick=1), the driver provides the
            // 400ms timing via sleep.
            let slot_duration = if hashes_per_tick > 1 {
                std::time::Duration::from_millis(50)
            } else {
                std::time::Duration::from_millis(400)
            };
            let mut currently_leading = is_leader_for(current_slot);
            loop {
                std::thread::sleep(slot_duration);

                let completed_slot = current_slot;

                // Leader slot: tick → finish_slot (freeze) → emit SlotCompleted.
                if currently_leading {
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
                    let hash = bank.last_blockhash();
                    drop(forks);

                    // Emit SlotCompleted — the resolv-blockhash thread picks
                    // this up and registers the hash in the blockhash ring.
                    let mut bus = signal_bus.lock().expect("signal_bus lock poisoned");
                    bus.emit(karstflow_stages::ReplaySignal::SlotCompleted(
                        karstflow_stages::SlotCompletedInfo {
                            slot: completed_slot,
                            parent_slot: completed_slot.saturating_sub(1),
                            bank_hash: hash,
                            block_hash: hash,
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
                // Non-leader: do NOT create a bank or freeze. Replay will
                // create the bank when the block arrives from the leader
                // peer via turbine. This prevents slot driver from blocking
                // replay's bank creation and ensures the parent chain stays
                // consistent (frozen parent → child).

                let next_slot = completed_slot + 1;
                let next_is_leader = is_leader_for(next_slot);

                // Create child bank ONLY for leader slots.
                if next_is_leader {
                    // Wait for the direct parent to be replayed and frozen.
                    // The parent was produced by another leader; replay
                    // creates and freezes its bank when shreds arrive via
                    // turbine. We poll briefly, but if the parent isn't
                    // ready, we DON'T advance current_slot — we retry on
                    // the next timer tick. This handles startup delays
                    // (gossip discovery, turbine delivery).
                    let parent_slot = next_slot.saturating_sub(1);
                    let mut parent_ready = false;
                    for wait in 0..20 {
                        let forks = bank_forks.read().expect("bank_forks lock poisoned");
                        if let Some(bank) = forks.get(parent_slot) {
                            if bank.is_frozen() {
                                parent_ready = true;
                                break;
                            }
                        }
                        drop(forks);
                        if wait < 19 {
                            std::thread::sleep(std::time::Duration::from_millis(50));
                        }
                    }

                    if !parent_ready {
                        // Don't advance — retry this slot on next tick.
                        // Parent will arrive via turbine when gossip
                        // discovers the peer.
                        continue;
                    }

                    current_slot = next_slot;
                    let created = {
                        let mut forks = bank_forks.write().expect("bank_forks lock poisoned");
                        let parent_bank = forks.get(parent_slot).expect("parent confirmed above");
                        let ls = parent_bank.leader_schedule();
                        let child = karstflow_consensus::Bank::new_from_parent(
                            &parent_bank, current_slot, ls.clone(),
                        );
                        if let Err(e) = forks.insert(child) {
                            warn!(error = ?e, slot = current_slot, "cluster-slot-driver: insert failed");
                            false
                        } else {
                            let _ = forks.set_working_bank(current_slot);
                            let child_hash = forks
                                .working_bank()
                                .last_blockhash();
                            pipeline_handle.register_blockhash(child_hash, current_slot);
                            true
                        }
                    };

                    if created && !currently_leading {
                        let mut end = current_slot + 1;
                        while is_leader_for(end) {
                            end += 1;
                        }
                        let parent_hash = {
                            let forks = bank_forks.read().expect("bank_forks lock poisoned");
                            forks.working_bank().last_blockhash()
                        };
                        info!(
                            completed = completed_slot,
                            next = current_slot,
                            end_slot = end,
                            "cluster-slot-driver: became leader",
                        );
                        let mut bus = signal_bus.lock().expect("signal_bus lock poisoned");
                        bus.emit(karstflow_stages::ReplaySignal::BecameLeader(
                            karstflow_stages::BecameLeaderInfo {
                                start_slot: current_slot,
                                end_slot: end,
                                epoch: 0,
                                identity_pubkey: *identity_pubkey.as_bytes(),
                                parent_blockhash: parent_hash,
                            },
                        ));
                    }
                } else {
                    // Non-leader slot: advance counter, replay handles banks.
                    current_slot = next_slot;
                    if currently_leading {
                        info!(
                            completed = completed_slot,
                            next = current_slot,
                            "cluster-slot-driver: no longer leader",
                        );
                    }
                }
                currently_leading = next_is_leader;
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
            let genesis_hash = genesis_bank.last_blockhash();
            info!(
                slot = genesis_slot,
                tick_height = genesis_bank.tick_height(),
                "dev mode: genesis bank ticked and frozen",
            );
            drop(forks);

            // Emit SlotCompleted for genesis so resolv registers the genesis
            // blockhash. Transactions signed with the genesis hash must be
            // resolvable from the first leader slot.
            {
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
                        parent_blockhash: [0u8; 32],
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
                let completed_hash = {
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
                    bank.last_blockhash()
                };

                // Emit SlotCompleted so the resolv-blockhash thread registers
                // this slot's hash in the blockhash ring. Without this, resolv
                // would never learn about dev-mode slot hashes and transactions
                // would fail blockhash validation.
                {
                    let mut bus = signal_bus.lock().expect("signal_bus lock poisoned");
                    bus.emit(karstflow_stages::ReplaySignal::SlotCompleted(
                        karstflow_stages::SlotCompletedInfo {
                            slot: completed_slot,
                            parent_slot: completed_slot.saturating_sub(1),
                            bank_hash: completed_hash,
                            block_hash: completed_hash,
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
