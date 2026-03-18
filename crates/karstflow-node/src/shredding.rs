use tracing::{info, warn};

/// Shred produced entries, store in blockstore, and feed to self-replay.
///
/// Called by the leader orchestrator after a slot completes. Converts
/// PohEntries into data + coding shreds, persists them in the blockstore
/// for repair serving, and sends data shreds to the ShredCollector for
/// self-replay of the produced block.
#[allow(clippy::too_many_arguments)]
pub(crate) fn shred_produced_entries(
    slot: u64,
    entry_batches: &[Vec<karstflow_stages::PohEntry>],
    leader_pubkey: karstflow_storage::Pubkey,
    signing_key: &ed25519_dalek::SigningKey,
    shred_version: u16,
    blockstore: Option<&std::sync::Arc<karstflow_storage::Blockstore>>,
    direct_shred_sender: &mut Option<karstflow_mesh::DualSender<karstflow_types::shred::Shred>>,
    turbine_retransmit: Option<&std::sync::Arc<karstflow_net::RetransmitService>>,
) {
    let config = karstflow_stages::ShredderConfig {
        shred_version,
        ..Default::default()
    };
    let mut shredder = match karstflow_stages::EntryShredder::new(
        leader_pubkey,
        Some(signing_key.clone()),
        slot,
        config,
    ) {
        Ok(s) => s,
        Err(e) => {
            warn!(slot, error = %e, "failed to create shredder for produced block");
            return;
        }
    };

    let mut total_data = 0u64;
    let mut total_coding = 0u64;

    for batch in entry_batches {
        if batch.is_empty() {
            continue;
        }

        let data_shreds = match shredder.create_data_shreds(batch) {
            Ok(shreds) => shreds,
            Err(e) => {
                warn!(slot, error = %e, "failed to create data shreds");
                continue;
            }
        };
        let coding_shreds = match shredder.create_coding_shreds(&data_shreds) {
            Ok(shreds) => shreds,
            Err(e) => {
                warn!(slot, error = %e, "failed to create coding shreds");
                // Still process data shreds even if coding fails.
                for shred in &data_shreds {
                    if let Some(bs) = blockstore {
                        if let Err(e) = bs.insert_shred(shred) {
                            warn!(slot, error = %e, "blockstore insert failed for produced shred");
                        }
                    }
                    if let Some(ref mut sender) = direct_shred_sender {
                        if let Err(e) = sender.try_send(shred.clone()) {
                            warn!(slot, error = ?e, "self-replay channel full, shred dropped");
                        }
                    }
                }
                total_data += data_shreds.len() as u64;
                continue;
            }
        };

        total_data += data_shreds.len() as u64;
        total_coding += coding_shreds.len() as u64;

        // Store all shreds in blockstore for repair serving.
        if let Some(bs) = blockstore {
            for shred in data_shreds.iter().chain(coding_shreds.iter()) {
                if let Err(e) = bs.insert_shred(shred) {
                    warn!(slot, error = %e, "blockstore insert failed for produced shred");
                }
            }
        }

        // Feed data shreds to ShredCollector for self-replay.
        // This closes the loop: leader produces -> shreds -> block assembled -> replay.
        if let Some(ref mut sender) = direct_shred_sender {
            for shred in &data_shreds {
                if let Err(e) = sender.try_send(shred.clone()) {
                    warn!(slot, error = ?e, "self-replay channel full, shred dropped");
                }
            }
        }

        // Broadcast data shreds to turbine tree peers.
        // Use payload bytes as wire format. Coding shreds excluded for now
        // (receiver's ShredParser handles data shred format only).
        if let Some(retransmit) = turbine_retransmit {
            for shred in &data_shreds {
                retransmit.forward_raw(&shred.payload);
            }
        }
    }

    if total_data > 0 || total_coding > 0 {
        info!(
            slot,
            data_shreds = total_data,
            coding_shreds = total_coding,
            "produced and broadcast block shreds",
        );
    }
}
