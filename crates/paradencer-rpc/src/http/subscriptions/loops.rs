use super::params::{
    AccountDataEncoding, AccountSubscriptionConfig, BlockDataEncoding, BlockSubscriptionConfig,
    BlockSubscriptionFilter, BlockTransactionDetails, DataSlice, LogsSubscriptionFilter,
    ProgramAccountFilter, ProgramSubscriptionConfig, SignatureSubscriptionConfig,
};
use crate::http::methods::types::{
    self, AccountData, AccountNotificationValue, LogsNotificationValue, ProgramNotificationAccount,
    ProgramNotificationSyntheticValue, ProgramNotificationValue, RpcResponse,
    SignatureNotificationValue, SlotNotification, SlotsUpdateNotification, VoteNotification,
};
use crate::state::{BankAccessProvider, RpcCommitment, RpcRuntimeSnapshot};
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
                let notification = SlotNotification {
                    parent: slot.saturating_sub(1),
                    slot,
                    root: snapshot.slot_for_commitment(RpcCommitment::Finalized),
                };
                let message = SubscriptionMessage::from_json(&notification)?;
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
    bank_access: Option<&dyn BankAccessProvider>,
) -> SubscriptionResult {
    let parsed_pubkey = parse_pubkey_bytes(&pubkey);
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
                let commitment = config.commitment();
                let slot = snapshot.slot_for_commitment(commitment);
                if last_emitted_slot == Some(slot) {
                    continue;
                }
                last_emitted_slot = Some(slot);

                // Try real account data from bank access.
                if let (Some(bank), Some(ref pk)) = (bank_access, &parsed_pubkey) {
                    if let Some(account) = bank.get_account(pk, commitment) {
                        let owner = account.meta.owner.to_string();
                        let data_bytes = account.data.as_slice();
                        let encoded = encode_account_data_typed(data_bytes, config.data_encoding(), config.data_slice());
                        let notification = RpcResponse::new(slot, AccountNotificationValue {
                            lamports: account.meta.lamports,
                            owner,
                            data: encoded,
                            executable: account.meta.executable,
                            rent_epoch: account.meta.rent_epoch,
                            pubkey: pubkey.clone(),
                            space: data_bytes.len(),
                        });
                        let message = SubscriptionMessage::from_json(&notification)?;
                        sink.send(message).await?;
                        continue;
                    }
                }

                // Synthetic fallback.
                let lamports = 1_000_000_u64
                    .saturating_add(pubkey_checksum % 50_000)
                    .saturating_add(slot % 1_000);
                let full_data = format!("{:016x}", pubkey_checksum.wrapping_add(slot));
                let sliced_data = apply_data_slice(&full_data, config.data_slice());
                let data_payload = match config.data_encoding() {
                    AccountDataEncoding::Base58 => AccountData::Encoded(sliced_data, "base58".into()),
                    AccountDataEncoding::Base64 => AccountData::Encoded(sliced_data, "base64".into()),
                    AccountDataEncoding::Base64Zstd => AccountData::Encoded(sliced_data, "base64+zstd".into()),
                    AccountDataEncoding::JsonParsed => AccountData::JsonParsed {
                        program: "system".into(),
                        parsed: json!({
                            "type": "account",
                            "info": { "data": sliced_data }
                        }),
                    },
                };
                let notification = RpcResponse::new(slot, AccountNotificationValue {
                    lamports,
                    owner: "11111111111111111111111111111111".into(),
                    data: data_payload,
                    executable: false,
                    rent_epoch: 0,
                    pubkey: pubkey.clone(),
                    space: full_data.len(),
                });
                let message = SubscriptionMessage::from_json(&notification)?;
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
    bank_access: Option<&dyn BankAccessProvider>,
) -> SubscriptionResult {
    let sig_bytes = parse_signature_bytes(&signature);
    let signature_checksum = signature
        .bytes()
        .fold(0_u64, |sum, byte| sum.wrapping_add(u64::from(byte)));
    let mut last_emitted_status_slot: Option<u64> = None;
    let mut confirmed = false;
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

                // Try real signature status from bank access.
                if let (Some(bank), Some(ref sig)) = (bank_access, &sig_bytes) {
                    let statuses = bank.get_signature_statuses(std::slice::from_ref(sig));
                    if let Some(Some(status)) = statuses.first() {
                        if confirmed {
                            continue; // Already sent confirmation
                        }
                        confirmed = true;
                        let err = status.error.as_ref()
                            .map(|e| json!({"InstructionError": e}))
                            .unwrap_or(serde_json::Value::Null);
                        let notification = RpcResponse::new(status.slot, SignatureNotificationValue {
                            err,
                            confirmation_status: commitment_str(commitment),
                            signature: signature.clone(),
                        });
                        let message = SubscriptionMessage::from_json(&notification)?;
                        sink.send(message).await?;
                        continue;
                    }
                }

                // Synthetic fallback.
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
                    types::to_value(&SignatureNotificationValue {
                        err: serde_json::Value::Null,
                        confirmation_status: commitment_str(commitment),
                        signature: signature.clone(),
                    })
                };
                let notification = RpcResponse::new(status_slot, value);
                let message = SubscriptionMessage::from_json(&notification)?;
                sink.send(message).await?;
            }
        }
    }
}

fn commitment_str(commitment: RpcCommitment) -> &'static str {
    match commitment {
        RpcCommitment::Processed => "processed",
        RpcCommitment::Confirmed => "confirmed",
        RpcCommitment::Finalized => "finalized",
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
                let notification = VoteNotification {
                    hash: format!("{:016x}", snapshot.blockhash_seed_for_commitment(commitment)),
                    slots: vec![slot.saturating_sub(1), slot, slot.saturating_add(1)],
                    timestamp: snapshot.uptime_millis,
                };
                let message = SubscriptionMessage::from_json(&notification)?;
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
                let notification = RpcResponse::new(slot, LogsNotificationValue {
                    signature,
                    err: serde_json::Value::Null,
                    logs_filter: filter_name.clone(),
                    logs: vec![
                        format!("Program log: filter={filter_name}"),
                        format!("Program log: slot={slot}"),
                    ],
                });
                let message = SubscriptionMessage::from_json(&notification)?;
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
    bank_access: Option<&dyn BankAccessProvider>,
) -> SubscriptionResult {
    let parsed_owner = parse_pubkey_bytes(&program_id);
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

                // Try real program accounts from bank access.
                if let (Some(bank), Some(ref owner)) = (bank_access, &parsed_owner) {
                    let accounts = bank.get_accounts_by_owner(owner, commitment);
                    if !accounts.is_empty() {
                        if let Some((pubkey, account)) = accounts.first() {
                            let data_bytes = account.data.as_slice();
                            let encoded = encode_account_data_typed(data_bytes, config.data_encoding(), config.data_slice());
                            let notification = RpcResponse::new(slot, ProgramNotificationValue {
                                pubkey: pubkey.to_string(),
                                account: ProgramNotificationAccount {
                                    lamports: account.meta.lamports,
                                    owner: program_id.clone(),
                                    data: encoded,
                                    executable: account.meta.executable,
                                    rent_epoch: account.meta.rent_epoch,
                                },
                            });
                            let message = SubscriptionMessage::from_json(&notification)?;
                            sink.send(message).await?;
                            continue;
                        }
                    }
                }

                // Synthetic fallback.
                let account_pubkey = format!(
                    "{:016x}{:016x}",
                    program_checksum.rotate_left(7),
                    slot ^ program_checksum
                );
                let full_data = format!("{:016x}", program_checksum.wrapping_add(slot));
                let sliced_data = apply_data_slice(&full_data, config.data_slice());
                let data_payload = match config.data_encoding() {
                    AccountDataEncoding::Base58 => AccountData::Encoded(sliced_data, "base58".into()),
                    AccountDataEncoding::Base64 => AccountData::Encoded(sliced_data, "base64".into()),
                    AccountDataEncoding::Base64Zstd => AccountData::Encoded(sliced_data, "base64+zstd".into()),
                    AccountDataEncoding::JsonParsed => AccountData::JsonParsed {
                        program: "spl-token".into(),
                        parsed: json!({
                            "type": "account",
                            "info": { "data": sliced_data }
                        }),
                    },
                };
                let lamports = 1_000_000_u64
                    .saturating_add(program_checksum % 25_000)
                    .saturating_add(slot % 2_000);
                let notification = RpcResponse::new(slot, ProgramNotificationSyntheticValue {
                    pubkey: account_pubkey,
                    filters_applied: filters_applied.clone(),
                    account: ProgramNotificationAccount {
                        lamports,
                        owner: program_id.clone(),
                        data: data_payload,
                        executable: false,
                        rent_epoch: 0,
                    },
                });
                let message = SubscriptionMessage::from_json(&notification)?;
                sink.send(message).await?;
            }
        }
    }
}

fn parse_pubkey_bytes(encoded: &str) -> Option<paradencer_types::Pubkey> {
    let bytes = bs58::decode(encoded.trim()).into_vec().ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Some(paradencer_types::Pubkey::from(key))
}

fn parse_signature_bytes(encoded: &str) -> Option<[u8; 64]> {
    let bytes = bs58::decode(encoded.trim()).into_vec().ok()?;
    if bytes.len() != 64 {
        return None;
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&bytes);
    Some(sig)
}

fn encode_account_data_typed(
    data: &[u8],
    encoding: AccountDataEncoding,
    data_slice: Option<DataSlice>,
) -> AccountData {
    use base64::Engine;
    let sliced = if let Some(slice) = data_slice {
        let start = slice.offset.min(data.len());
        let end = start.saturating_add(slice.length).min(data.len());
        &data[start..end]
    } else {
        data
    };
    match encoding {
        AccountDataEncoding::Base58 => {
            AccountData::Encoded(bs58::encode(sliced).into_string(), "base58".into())
        }
        AccountDataEncoding::Base64 | AccountDataEncoding::Base64Zstd => {
            let label = if matches!(encoding, AccountDataEncoding::Base64Zstd) {
                "base64+zstd"
            } else {
                "base64"
            };
            AccountData::Encoded(
                base64::engine::general_purpose::STANDARD.encode(sliced),
                label.into(),
            )
        }
        AccountDataEncoding::JsonParsed => AccountData::Encoded(
            base64::engine::general_purpose::STANDARD.encode(sliced),
            "base64".into(),
        ),
    }
}

fn render_program_filters(filters: &[ProgramAccountFilter]) -> serde_json::Value {
    let rendered: Vec<serde_json::Value> = filters
        .iter()
        .map(|filter| match filter {
            ProgramAccountFilter::DataSize(data_size) => {
                types::to_value(&types::ProgramFilterDataSize {
                    data_size: *data_size,
                })
            }
            ProgramAccountFilter::Memcmp { offset, bytes } => {
                types::to_value(&types::ProgramFilterMemcmp {
                    memcmp: types::ProgramFilterMemcmpInner {
                        offset: *offset,
                        bytes: bytes.clone(),
                    },
                })
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
                let notification = SlotsUpdateNotification {
                    update_type: "completed",
                    slot,
                    parent: slot.saturating_sub(1),
                    timestamp: snapshot.uptime_millis,
                };
                let message = SubscriptionMessage::from_json(&notification)?;
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
                        BlockSubscriptionFilter::MentionsAccountOrProgram(value) => json!({
                            "mentionsAccountOrProgram": value
                        }),
                    }
                }))?;
                sink.send(message).await?;
            }
        }
    }
}
