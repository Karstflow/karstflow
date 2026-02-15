use super::params::{
    AccountDataEncoding, AccountSubscriptionConfig, BlockDataEncoding, BlockSubscriptionConfig,
    BlockSubscriptionFilter, BlockTransactionDetails, DataSlice, LogsSubscriptionFilter,
    ProgramAccountFilter, ProgramSubscriptionConfig, SignatureSubscriptionConfig,
};
use crate::state::{RpcCommitment, RpcRuntimeSnapshot};
use jsonrpsee::{core::SubscriptionResult, SubscriptionMessage};
use serde_json::json;
use tokio::sync::broadcast;

pub(super) async fn run_slot_subscription_loop(
    sink: jsonrpsee::SubscriptionSink,
    snapshot_updates: &mut broadcast::Receiver<RpcRuntimeSnapshot>,
    commitment: RpcCommitment,
) -> SubscriptionResult {
    let mut last_emitted_slot: Option<u64> = None;
    loop {
        tokio::select! {
            _ = sink.closed() => return Ok(()),
            snapshot = snapshot_updates.recv() => {
                let snapshot = match snapshot {
                    Ok(snapshot) => snapshot,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                };
                let slot = snapshot.slot_for_commitment(commitment);
                if last_emitted_slot == Some(slot) {
                    continue;
                }
                last_emitted_slot = Some(slot);
                let message = SubscriptionMessage::from_json(&json!({
                    "parent": slot.saturating_sub(1),
                    "slot": slot,
                    "root": snapshot.slot_for_commitment(RpcCommitment::Finalized),
                }))?;
                sink.send(message).await?;
            }
        }
    }
}

pub(super) async fn run_root_subscription_loop(
    sink: jsonrpsee::SubscriptionSink,
    snapshot_updates: &mut broadcast::Receiver<RpcRuntimeSnapshot>,
) -> SubscriptionResult {
    let mut last_emitted_root: Option<u64> = None;
    loop {
        tokio::select! {
            _ = sink.closed() => return Ok(()),
            snapshot = snapshot_updates.recv() => {
                let snapshot = match snapshot {
                    Ok(snapshot) => snapshot,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                };
                let root_slot = snapshot.slot_for_commitment(RpcCommitment::Finalized);
                if last_emitted_root == Some(root_slot) {
                    continue;
                }
                last_emitted_root = Some(root_slot);
                let message = SubscriptionMessage::from_json(&root_slot)?;
                sink.send(message).await?;
            }
        }
    }
}

pub(super) async fn run_account_subscription_loop(
    sink: jsonrpsee::SubscriptionSink,
    snapshot_updates: &mut broadcast::Receiver<RpcRuntimeSnapshot>,
    pubkey: String,
    config: AccountSubscriptionConfig,
) -> SubscriptionResult {
    let pubkey_checksum = pubkey
        .bytes()
        .fold(0_u64, |sum, byte| sum.wrapping_add(u64::from(byte)));
    let mut last_emitted_slot: Option<u64> = None;
    loop {
        tokio::select! {
            _ = sink.closed() => return Ok(()),
            snapshot = snapshot_updates.recv() => {
                let snapshot = match snapshot {
                    Ok(snapshot) => snapshot,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                };
                let slot = snapshot.slot_for_commitment(config.commitment());
                if last_emitted_slot == Some(slot) {
                    continue;
                }
                last_emitted_slot = Some(slot);
                let lamports = 1_000_000_u64
                    .saturating_add(pubkey_checksum % 50_000)
                    .saturating_add(slot % 1_000);
                let full_data = format!("{:016x}", pubkey_checksum.wrapping_add(slot));
                let sliced_data = apply_data_slice(&full_data, config.data_slice());
                let data_payload = match config.data_encoding() {
                    AccountDataEncoding::Base58 => json!([sliced_data, "base58"]),
                    AccountDataEncoding::Base64 => json!([sliced_data, "base64"]),
                    AccountDataEncoding::Base64Zstd => json!([sliced_data, "base64+zstd"]),
                    AccountDataEncoding::JsonParsed => json!({
                        "program": "system",
                        "parsed": {
                            "type": "account",
                            "info": {
                                "data": sliced_data,
                            }
                        },
                        "space": full_data.len(),
                    }),
                };
                let message = SubscriptionMessage::from_json(&json!({
                    "context": {"slot": slot},
                    "value": {
                        "lamports": lamports,
                        "owner": "11111111111111111111111111111111",
                        "data": data_payload,
                        "executable": false,
                        "rentEpoch": 0_u64,
                        "pubkey": pubkey
                    }
                }))?;
                sink.send(message).await?;
            }
        }
    }
}

fn apply_data_slice(full_data: &str, data_slice: Option<DataSlice>) -> String {
    let Some(data_slice) = data_slice else {
        return full_data.to_string();
    };
    let start = data_slice.offset.min(full_data.len());
    let end = start.saturating_add(data_slice.length).min(full_data.len());
    full_data[start..end].to_string()
}

pub(super) async fn run_signature_subscription_loop(
    sink: jsonrpsee::SubscriptionSink,
    snapshot_updates: &mut broadcast::Receiver<RpcRuntimeSnapshot>,
    signature: String,
    config: SignatureSubscriptionConfig,
) -> SubscriptionResult {
    let signature_checksum = signature
        .bytes()
        .fold(0_u64, |sum, byte| sum.wrapping_add(u64::from(byte)));
    let mut last_emitted_status_slot: Option<u64> = None;
    loop {
        tokio::select! {
            _ = sink.closed() => return Ok(()),
            snapshot = snapshot_updates.recv() => {
                let snapshot = match snapshot {
                    Ok(snapshot) => snapshot,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                };
                let commitment = config.commitment();
                let commitment_slot = snapshot.slot_for_commitment(commitment);
                let status_slot = commitment_slot.saturating_sub(signature_checksum % 16);
                if last_emitted_status_slot == Some(status_slot) {
                    continue;
                }
                last_emitted_status_slot = Some(status_slot);
                let value = if config.enable_received_notification()
                    && matches!(commitment, RpcCommitment::Processed)
                {
                    serde_json::Value::String("receivedSignature".to_string())
                } else {
                    json!({
                        "err": serde_json::Value::Null,
                        "confirmationStatus": match commitment {
                            RpcCommitment::Processed => "processed",
                            RpcCommitment::Confirmed => "confirmed",
                            RpcCommitment::Finalized => "finalized",
                        },
                        "signature": signature
                    })
                };
                let message = SubscriptionMessage::from_json(&json!({
                    "context": {"slot": status_slot},
                    "value": value
                }))?;
                sink.send(message).await?;
            }
        }
    }
}

pub(super) async fn run_vote_subscription_loop(
    sink: jsonrpsee::SubscriptionSink,
    snapshot_updates: &mut broadcast::Receiver<RpcRuntimeSnapshot>,
    commitment: RpcCommitment,
) -> SubscriptionResult {
    let mut last_emitted_slot: Option<u64> = None;
    loop {
        tokio::select! {
            _ = sink.closed() => return Ok(()),
            snapshot = snapshot_updates.recv() => {
                let snapshot = match snapshot {
                    Ok(snapshot) => snapshot,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                };
                let slot = snapshot.slot_for_commitment(commitment);
                if last_emitted_slot == Some(slot) {
                    continue;
                }
                last_emitted_slot = Some(slot);
                let message = SubscriptionMessage::from_json(&json!({
                    "hash": format!("{:016x}", snapshot.blockhash_seed_for_commitment(commitment)),
                    "slots": [slot.saturating_sub(1), slot, slot.saturating_add(1)],
                    "timestamp": snapshot.uptime_millis,
                }))?;
                sink.send(message).await?;
            }
        }
    }
}

pub(super) async fn run_logs_subscription_loop(
    sink: jsonrpsee::SubscriptionSink,
    snapshot_updates: &mut broadcast::Receiver<RpcRuntimeSnapshot>,
    filter: LogsSubscriptionFilter,
    commitment: RpcCommitment,
) -> SubscriptionResult {
    let filter_name = match &filter {
        LogsSubscriptionFilter::All => "all".to_string(),
        LogsSubscriptionFilter::AllWithVotes => "allWithVotes".to_string(),
        LogsSubscriptionFilter::Mentions(pubkey) => format!("mentions:{pubkey}"),
    };
    let filter_checksum = filter_name
        .bytes()
        .fold(0_u64, |sum, byte| sum.wrapping_add(u64::from(byte)));
    let mut last_emitted_slot: Option<u64> = None;
    loop {
        tokio::select! {
            _ = sink.closed() => return Ok(()),
            snapshot = snapshot_updates.recv() => {
                let snapshot = match snapshot {
                    Ok(snapshot) => snapshot,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                };
                let slot = snapshot.slot_for_commitment(commitment);
                if last_emitted_slot == Some(slot) {
                    continue;
                }
                last_emitted_slot = Some(slot);
                let signature = format!(
                    "{:016x}{:016x}",
                    snapshot.blockhash_seed_for_commitment(commitment),
                    filter_checksum ^ slot
                );
                let message = SubscriptionMessage::from_json(&json!({
                    "context": {"slot": slot},
                    "value": {
                        "signature": signature,
                        "err": serde_json::Value::Null,
                        "logsFilter": filter_name,
                        "logs": [
                            format!("Program log: filter={filter_name}"),
                            format!("Program log: slot={slot}"),
                        ]
                    }
                }))?;
                sink.send(message).await?;
            }
        }
    }
}

pub(super) async fn run_program_subscription_loop(
    sink: jsonrpsee::SubscriptionSink,
    snapshot_updates: &mut broadcast::Receiver<RpcRuntimeSnapshot>,
    program_id: String,
    config: ProgramSubscriptionConfig,
) -> SubscriptionResult {
    let program_checksum = program_id
        .bytes()
        .fold(0_u64, |sum, byte| sum.wrapping_add(u64::from(byte)));
    let filters_applied = render_program_filters(config.filters());
    let mut last_emitted_slot: Option<u64> = None;
    loop {
        tokio::select! {
            _ = sink.closed() => return Ok(()),
            snapshot = snapshot_updates.recv() => {
                let snapshot = match snapshot {
                    Ok(snapshot) => snapshot,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                };
                let commitment = config.commitment();
                let slot = snapshot.slot_for_commitment(commitment);
                if last_emitted_slot == Some(slot) {
                    continue;
                }
                last_emitted_slot = Some(slot);
                let account_pubkey = format!(
                    "{:016x}{:016x}",
                    program_checksum.rotate_left(7),
                    slot ^ program_checksum
                );
                let full_data = format!("{:016x}", program_checksum.wrapping_add(slot));
                let sliced_data = apply_data_slice(&full_data, config.data_slice());
                let data_payload = match config.data_encoding() {
                    AccountDataEncoding::Base58 => json!([sliced_data, "base58"]),
                    AccountDataEncoding::Base64 => json!([sliced_data, "base64"]),
                    AccountDataEncoding::Base64Zstd => json!([sliced_data, "base64+zstd"]),
                    AccountDataEncoding::JsonParsed => json!({
                        "program": "spl-token",
                        "parsed": {
                            "type": "account",
                            "info": {
                                "data": sliced_data,
                            }
                        },
                        "space": full_data.len(),
                    }),
                };
                let message = SubscriptionMessage::from_json(&json!({
                    "context": {"slot": slot},
                    "value": {
                        "pubkey": account_pubkey,
                        "filtersApplied": filters_applied,
                        "account": {
                            "lamports": 1_000_000_u64.saturating_add(program_checksum % 25_000).saturating_add(slot % 2_000),
                            "owner": program_id,
                            "data": data_payload,
                            "executable": false,
                            "rentEpoch": 0_u64,
                        }
                    }
                }))?;
                sink.send(message).await?;
            }
        }
    }
}

fn render_program_filters(filters: &[ProgramAccountFilter]) -> serde_json::Value {
    let rendered: Vec<serde_json::Value> = filters
        .iter()
        .map(|filter| match filter {
            ProgramAccountFilter::DataSize(data_size) => json!({"dataSize": data_size}),
            ProgramAccountFilter::Memcmp { offset, bytes } => {
                json!({"memcmp": {"offset": offset, "bytes": bytes}})
            }
        })
        .collect();
    serde_json::Value::Array(rendered)
}

pub(super) async fn run_slots_updates_subscription_loop(
    sink: jsonrpsee::SubscriptionSink,
    snapshot_updates: &mut broadcast::Receiver<RpcRuntimeSnapshot>,
) -> SubscriptionResult {
    let mut last_emitted_slot: Option<u64> = None;
    loop {
        tokio::select! {
            _ = sink.closed() => return Ok(()),
            snapshot = snapshot_updates.recv() => {
                let snapshot = match snapshot {
                    Ok(snapshot) => snapshot,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                };
                let slot = snapshot.slot;
                if last_emitted_slot == Some(slot) {
                    continue;
                }
                last_emitted_slot = Some(slot);
                let message = SubscriptionMessage::from_json(&json!({
                    "type": "completed",
                    "slot": slot,
                    "parent": slot.saturating_sub(1),
                    "timestamp": snapshot.uptime_millis,
                }))?;
                sink.send(message).await?;
            }
        }
    }
}

pub(super) async fn run_block_subscription_loop(
    sink: jsonrpsee::SubscriptionSink,
    snapshot_updates: &mut broadcast::Receiver<RpcRuntimeSnapshot>,
    filter: BlockSubscriptionFilter,
    config: BlockSubscriptionConfig,
) -> SubscriptionResult {
    let mut last_emitted_slot: Option<u64> = None;
    loop {
        tokio::select! {
            _ = sink.closed() => return Ok(()),
            snapshot = snapshot_updates.recv() => {
                let snapshot = match snapshot {
                    Ok(snapshot) => snapshot,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                };
                let commitment = config.commitment();
                let slot = snapshot.slot_for_commitment(commitment);
                if last_emitted_slot == Some(slot) {
                    continue;
                }
                last_emitted_slot = Some(slot);
                let blockhash = format!("{:016x}", snapshot.blockhash_seed_for_commitment(commitment));
                let transactions = match config.transaction_details() {
                    BlockTransactionDetails::Full => json!([{
                        "meta": {
                            "err": serde_json::Value::Null,
                            "status": {"Ok": serde_json::Value::Null}
                        },
                        "transaction": match config.encoding() {
                            BlockDataEncoding::Base64 => json!(["AQIDBAUGBwg=", "base64"]),
                            BlockDataEncoding::Base58 => json!("3MwrYj"),
                            BlockDataEncoding::Json => json!({
                                "signatures": ["3bxs9v7f5JfWHqK9x2q8f9QkR9nA3eJr7c4D2w1m6pT"],
                                "message": {"accountKeys": []}
                            }),
                            BlockDataEncoding::JsonParsed => json!({
                                "signatures": ["3bxs9v7f5JfWHqK9x2q8f9QkR9nA3eJr7c4D2w1m6pT"],
                                "message": {"accountKeys": [], "instructions": []}
                            }),
                        }
                    }]),
                    BlockTransactionDetails::Signatures => {
                        json!(["3bxs9v7f5JfWHqK9x2q8f9QkR9nA3eJr7c4D2w1m6pT"])
                    }
                    BlockTransactionDetails::None => json!([]),
                };
                let rewards = if config.show_rewards() {
                    json!([{
                        "pubkey": "Vote111111111111111111111111111111111111111",
                        "lamports": 1000,
                        "postBalance": 1000000,
                        "rewardType": "Fee"
                    }])
                } else {
                    json!([])
                };
                let message = SubscriptionMessage::from_json(&json!({
                    "slot": slot,
                    "block": {
                        "blockHeight": snapshot.block_height_for_commitment(commitment),
                        "blockhash": blockhash,
                        "parentSlot": slot.saturating_sub(1),
                        "previousBlockhash": format!("{:016x}", snapshot.blockhash_seed_for_commitment(commitment).wrapping_sub(1)),
                        "transactions": transactions,
                        "rewards": rewards,
                        "maxSupportedTransactionVersion": config.max_supported_transaction_version(),
                        "encoding": match config.encoding() {
                            BlockDataEncoding::Base64 => "base64",
                            BlockDataEncoding::Base58 => "base58",
                            BlockDataEncoding::Json => "json",
                            BlockDataEncoding::JsonParsed => "jsonParsed",
                        },
                        "transactionDetails": match config.transaction_details() {
                            BlockTransactionDetails::Full => "full",
                            BlockTransactionDetails::Signatures => "signatures",
                            BlockTransactionDetails::None => "none",
                        }
                    },
                    "filter": match &filter {
                        BlockSubscriptionFilter::All => serde_json::Value::String("all".to_string()),
                        BlockSubscriptionFilter::MentionsAccountOrProgram(value) => serde_json::json!({
                            "mentionsAccountOrProgram": value
                        }),
                    }
                }))?;
                sink.send(message).await?;
            }
        }
    }
}
