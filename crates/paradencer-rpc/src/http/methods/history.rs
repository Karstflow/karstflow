use serde_json::json;
use std::sync::Arc;

use crate::state::{BankAccessProvider, RpcCommitment, RpcRuntimeSnapshot};
use paradencer_constants::economics::{BASE_NETWORK_SUPPLY_LAMPORTS, LAMPORTS_PER_SIGNATURE};
use paradencer_constants::rpc::{DEFAULT_BLOCKS_END_OFFSET, MAX_BLOCKS_RANGE_LEN};

use super::super::method_error::RpcMethodError;
use super::super::registry::RpcMethod;
use super::params;
use super::shared;
use super::types::{self, BlockCommitmentResponse};

const ALLOWED_ENCODINGS: &[&str] = &["json", "jsonParsed", "base58", "base64"];
const ALLOWED_BLOCK_TRANSACTION_DETAILS: &[&str] = &["full", "accounts", "signatures", "none"];
const TRANSACTION_VERSION_LEGACY: i64 = -1;
const BLOCK_REQUEST_ALLOWED_KEYS: &[&str] = &[
    "commitment",
    "encoding",
    "transactionDetails",
    "rewards",
    "maxSupportedTransactionVersion",
    "minContextSlot",
];
const TRANSACTION_REQUEST_ALLOWED_KEYS: &[&str] = &[
    "commitment",
    "encoding",
    "maxSupportedTransactionVersion",
    "minContextSlot",
];
const QUERY_REQUEST_ALLOWED_KEYS: &[&str] = &["commitment", "minContextSlot"];

#[derive(Clone, Copy, PartialEq, Eq)]
enum ResponseEncoding {
    Json,
    JsonParsed,
    Base58,
    Base64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BlockTransactionDetails {
    Full,
    Accounts,
    Signatures,
    None,
}

#[derive(Clone, Copy)]
struct BlockRequestConfig {
    encoding: ResponseEncoding,
    transaction_details: BlockTransactionDetails,
    include_rewards: bool,
    max_supported_transaction_version: Option<u64>,
}

#[derive(Clone, Copy)]
struct TransactionRequestConfig {
    encoding: ResponseEncoding,
    max_supported_transaction_version: Option<u64>,
}

pub(super) fn handle(
    method: RpcMethod,
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    match method {
        RpcMethod::GetBlocks | RpcMethod::GetConfirmedBlocks => {
            build_blocks_response(request, snapshot, commitment, bank_access)
        }
        RpcMethod::GetBlocksWithLimit => {
            build_blocks_with_limit_response(request, snapshot, commitment, bank_access)
        }
        RpcMethod::GetBlockCommitment => {
            build_block_commitment_response(request, snapshot, commitment, bank_access)
        }
        RpcMethod::GetBlock | RpcMethod::GetConfirmedBlock => {
            build_block_response(request, snapshot, commitment, bank_access)
        }
        RpcMethod::GetBlockTime => {
            build_block_time_response(request, snapshot, commitment, bank_access)
        }
        RpcMethod::GetTransaction | RpcMethod::GetConfirmedTransaction => {
            build_transaction_response(request, snapshot, commitment, bank_access)
        }
        _ => Err(RpcMethodError::MethodNotFound),
    }
}

fn build_blocks_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    let params = params::params_array(request)?;
    if params.len() > 3 {
        return Err(RpcMethodError::InvalidParams);
    }
    let start_slot = params::first_param_u64(request)?;
    if let Some(end_slot_raw) = params.get(1) {
        if !end_slot_raw.is_u64() {
            return Err(RpcMethodError::InvalidParams);
        }
    }
    let raw_config = params.get(2);
    ensure_query_config_shape(raw_config, QUERY_REQUEST_ALLOWED_KEYS)?;
    let max_readable_slot = bank_access
        .map(|bank| bank.get_slot(commitment))
        .unwrap_or_else(|| snapshot.slot_for_commitment(commitment));
    ensure_min_context_slot(min_context_slot_from_config(raw_config)?, max_readable_slot)?;
    let requested_end_slot = params
        .get(1)
        .and_then(|value| value.as_u64())
        .unwrap_or(start_slot.saturating_add(DEFAULT_BLOCKS_END_OFFSET));
    if requested_end_slot < start_slot {
        return Err(RpcMethodError::InvalidParams);
    }

    if start_slot > max_readable_slot {
        return Ok(json!([]));
    }

    let clamped_end_slot = requested_end_slot.min(max_readable_slot);
    let range_len = clamped_end_slot
        .saturating_sub(start_slot)
        .saturating_add(1)
        .min(MAX_BLOCKS_RANGE_LEN);
    let end_slot = start_slot.saturating_add(range_len.saturating_sub(1));

    // When blockstore is available, return only confirmed/rooted slots.
    if let Some(bank) = bank_access {
        let confirmed = bank.get_confirmed_blocks(start_slot, end_slot);
        if !confirmed.is_empty() {
            return Ok(json!(confirmed));
        }
    }

    // Synthetic fallback: all slots in range are reported as confirmed.
    Ok(json!((start_slot..=end_slot).collect::<Vec<u64>>()))
}

fn build_block_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    let config = parse_block_config(request)?;
    let max_readable_slot = bank_access
        .map(|bank| bank.get_slot(commitment))
        .unwrap_or_else(|| snapshot.slot_for_commitment(commitment));

    let min_context_slot = params::min_context_slot_from_params(request)?;
    ensure_min_context_slot(min_context_slot, max_readable_slot)?;

    let requested_slot = params::first_param_u64(request)?;
    if requested_slot > max_readable_slot {
        return Ok(serde_json::Value::Null);
    }

    // Try real block data from blockstore when available.
    if let Some(bank) = bank_access {
        if let Some(block_data) = bank.get_block_data(requested_slot) {
            return Ok(format_real_block_response(
                &block_data,
                &config,
                bank.get_block_height(commitment),
                snapshot,
                commitment,
            ));
        }
    }

    // Synthetic fallback when blockstore data is unavailable.
    let block_time = bank_access
        .and_then(|bank| bank.get_block_time(requested_slot))
        .unwrap_or_else(|| shared::synthetic_block_time(snapshot.uptime_millis, requested_slot));
    let parent_slot = bank_access
        .and_then(|bank| bank.get_parent_slot(requested_slot))
        .unwrap_or_else(|| requested_slot.saturating_sub(1));
    let block_height = bank_access
        .map(|bank| bank.get_block_height(commitment))
        .unwrap_or(requested_slot);

    let blockhash_seed = snapshot
        .blockhash_seed_for_commitment(commitment)
        .wrapping_add(requested_slot.rotate_left(11));

    let blockhash = shared::format_blockhash_from_seed(blockhash_seed);
    let transaction = block_transaction_payload(
        &blockhash,
        config.encoding,
        config.max_supported_transaction_version,
    );
    let transactions = match config.transaction_details {
        BlockTransactionDetails::None => serde_json::Value::Array(Vec::new()),
        BlockTransactionDetails::Full
        | BlockTransactionDetails::Accounts
        | BlockTransactionDetails::Signatures => serde_json::Value::Array(vec![transaction]),
    };
    let rewards = if config.include_rewards {
        serde_json::Value::Array(Vec::new())
    } else {
        serde_json::Value::Null
    };

    Ok(json!({
        "blockHeight": block_height,
        "blockTime": block_time,
        "blockhash": blockhash,
        "parentSlot": parent_slot,
        "previousBlockhash": shared::format_blockhash_from_seed(blockhash_seed.wrapping_sub(1)),
        "transactions": transactions,
        "rewards": rewards
    }))
}

fn build_block_commitment_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    let params = params::params_array(request)?;
    if params.len() > 2 {
        return Err(RpcMethodError::InvalidParams);
    }
    let raw_config = params.get(1);
    ensure_query_config_shape(raw_config, QUERY_REQUEST_ALLOWED_KEYS)?;
    let max_readable_slot = bank_access
        .map(|bank| bank.get_slot(commitment))
        .unwrap_or_else(|| snapshot.slot_for_commitment(commitment));
    ensure_min_context_slot(min_context_slot_from_config(raw_config)?, max_readable_slot)?;

    let requested_slot = params::first_param_u64(request)?;
    if requested_slot > max_readable_slot {
        return Ok(serde_json::Value::Null);
    }

    // Try real commitment data from the commitment tracker.
    if let Some(bank) = bank_access {
        if let Some(bc) = bank.get_block_commitment(requested_slot) {
            let response = BlockCommitmentResponse {
                commitment: Some(bc.commitment),
                total_stake: bc.total_stake,
            };
            return Ok(types::to_value(&response));
        }
    }

    // Synthetic fallback.
    let finalized_depth = max_readable_slot.saturating_sub(requested_slot).min(32);
    let confirmation_bucket = (31_u64.saturating_sub(finalized_depth)) as usize;
    let confirmation_stake = BASE_NETWORK_SUPPLY_LAMPORTS.saturating_sub(
        (confirmation_bucket as u64).saturating_mul(BASE_NETWORK_SUPPLY_LAMPORTS / 64),
    );

    let mut commitment_levels = vec![0_u64; 32];
    commitment_levels[confirmation_bucket] = confirmation_stake;

    let response = BlockCommitmentResponse {
        commitment: Some(commitment_levels),
        total_stake: BASE_NETWORK_SUPPLY_LAMPORTS,
    };
    Ok(types::to_value(&response))
}

fn build_blocks_with_limit_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    let params = params::params_array(request)?;
    if params.len() > 3 {
        return Err(RpcMethodError::InvalidParams);
    }
    let start_slot = params::first_param_u64(request)?;
    let limit = params
        .get(1)
        .and_then(serde_json::Value::as_u64)
        .ok_or(RpcMethodError::InvalidParams)?;
    let raw_config = params.get(2);
    ensure_query_config_shape(raw_config, QUERY_REQUEST_ALLOWED_KEYS)?;
    let max_readable_slot = bank_access
        .map(|bank| bank.get_slot(commitment))
        .unwrap_or_else(|| snapshot.slot_for_commitment(commitment));
    ensure_min_context_slot(min_context_slot_from_config(raw_config)?, max_readable_slot)?;
    if limit == 0 || limit > MAX_BLOCKS_RANGE_LEN {
        return Err(RpcMethodError::InvalidParams);
    }

    if start_slot > max_readable_slot {
        return Ok(json!([]));
    }

    let requested_end_slot = start_slot.saturating_add(limit.saturating_sub(1));
    let clamped_end_slot = requested_end_slot.min(max_readable_slot);
    let range_len = clamped_end_slot
        .saturating_sub(start_slot)
        .saturating_add(1)
        .min(MAX_BLOCKS_RANGE_LEN);
    let end_slot = start_slot.saturating_add(range_len.saturating_sub(1));

    // When blockstore is available, return only confirmed/rooted slots.
    if let Some(bank) = bank_access {
        let confirmed = bank.get_confirmed_blocks(start_slot, end_slot);
        if !confirmed.is_empty() {
            return Ok(json!(confirmed));
        }
    }

    Ok(json!((start_slot..=end_slot).collect::<Vec<u64>>()))
}

fn build_block_time_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    let params = params::params_array(request)?;
    if params.len() > 2 {
        return Err(RpcMethodError::InvalidParams);
    }
    let raw_config = params.get(1);
    ensure_query_config_shape(raw_config, QUERY_REQUEST_ALLOWED_KEYS)?;
    let max_readable_slot = bank_access
        .map(|bank| bank.get_slot(commitment))
        .unwrap_or_else(|| snapshot.slot_for_commitment(commitment));
    ensure_min_context_slot(min_context_slot_from_config(raw_config)?, max_readable_slot)?;

    let requested_slot = params::first_param_u64(request)?;
    if requested_slot > max_readable_slot {
        return Ok(serde_json::Value::Null);
    }

    // Use real block time from blockstore when available.
    if let Some(bank) = bank_access {
        if let Some(ts) = bank.get_block_time(requested_slot) {
            return Ok(json!(ts));
        }
    }

    Ok(json!(shared::synthetic_block_time(
        snapshot.uptime_millis,
        requested_slot,
    )))
}

fn build_transaction_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;
    let config = parse_transaction_config(request)?;
    let signature = params::first_param_non_empty_string(request)?;

    // Try real transaction lookup first.
    if let Some(bank) = bank_access {
        if let Some(sig_bytes) = decode_signature(&signature) {
            if let Some(tx_data) = bank.get_transaction(&sig_bytes) {
                return Ok(format_real_transaction_response(
                    &tx_data, &config, snapshot, commitment,
                ));
            }
        }
    }

    // Synthetic fallback.
    let signature_checksum = signature.bytes().fold(0_u64, |accumulator, byte| {
        accumulator.wrapping_add(u64::from(byte))
    });
    let current_slot = snapshot.slot_for_commitment(commitment);
    let slot = current_slot.saturating_sub(signature_checksum % 64);

    Ok(json!({
        "slot": slot,
        "blockTime": shared::synthetic_block_time(snapshot.uptime_millis, slot),
        "meta": {
            "err": serde_json::Value::Null,
            "fee": LAMPORTS_PER_SIGNATURE,
            "preBalances": [1_000_000_u64, 500_000_u64],
            "postBalances": [995_000_u64, 500_000_u64],
            "status": {"Ok": serde_json::Value::Null}
        },
        "transaction": {
            "signatures": [signature],
            "message": transaction_message_payload(
                &shared::format_blockhash_from_seed(snapshot.blockhash_seed_for_commitment(commitment)),
                config.encoding
            )
        },
        "version": transaction_version_payload(config.max_supported_transaction_version)
    }))
}

fn decode_signature(sig_str: &str) -> Option<[u8; 64]> {
    let bytes = bs58::decode(sig_str).into_vec().ok()?;
    if bytes.len() != 64 {
        return None;
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&bytes);
    Some(sig)
}

fn format_real_transaction_response(
    tx_data: &crate::state::RpcTransactionData,
    config: &TransactionRequestConfig,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> serde_json::Value {
    let block_time = tx_data
        .block_time
        .unwrap_or_else(|| shared::synthetic_block_time(snapshot.uptime_millis, tx_data.slot));

    let err = if tx_data.succeeded {
        serde_json::Value::Null
    } else {
        tx_data
            .error
            .as_ref()
            .map(|e| json!({"InstructionError": e}))
            .unwrap_or(serde_json::Value::Null)
    };

    let status = if tx_data.succeeded {
        json!({"Ok": serde_json::Value::Null})
    } else {
        json!({"Err": &err})
    };

    let transaction = if tx_data.raw_bytes.is_empty() {
        // No raw data available — use signature-only format.
        let blockhash = shared::format_blockhash_from_seed(
            snapshot
                .blockhash_seed_for_commitment(commitment)
                .wrapping_add(tx_data.slot.rotate_left(11)),
        );
        json!({
            "signatures": tx_data.signatures,
            "message": transaction_message_payload(&blockhash, config.encoding)
        })
    } else {
        match config.encoding {
            ResponseEncoding::Base64 => {
                use base64::Engine;
                json!([
                    base64::engine::general_purpose::STANDARD.encode(&tx_data.raw_bytes),
                    "base64"
                ])
            }
            ResponseEncoding::Base58 => {
                json!([bs58::encode(&tx_data.raw_bytes).into_string(), "base58"])
            }
            ResponseEncoding::Json | ResponseEncoding::JsonParsed => {
                let blockhash = shared::format_blockhash_from_seed(
                    snapshot
                        .blockhash_seed_for_commitment(commitment)
                        .wrapping_add(tx_data.slot.rotate_left(11)),
                );
                json!({
                    "signatures": tx_data.signatures,
                    "message": {
                        "accountKeys": [],
                        "recentBlockhash": blockhash,
                        "instructions": []
                    }
                })
            }
        }
    };

    json!({
        "slot": tx_data.slot,
        "blockTime": block_time,
        "meta": {
            "err": err,
            "fee": LAMPORTS_PER_SIGNATURE,
            "preBalances": [],
            "postBalances": [],
            "status": status
        },
        "transaction": transaction,
        "version": transaction_version_payload(config.max_supported_transaction_version)
    })
}

fn ensure_min_context_slot_satisfied(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> Result<(), RpcMethodError> {
    let min_context_slot = params::min_context_slot_from_params(request)?;
    if let Some(min_context_slot) = min_context_slot {
        let committed_slot = snapshot.slot_for_commitment(commitment);
        if min_context_slot > committed_slot {
            return Err(RpcMethodError::MinimumContextSlotNotReached);
        }
    }
    Ok(())
}

fn ensure_min_context_slot(
    min_context_slot: Option<u64>,
    committed_slot: u64,
) -> Result<(), RpcMethodError> {
    if let Some(min_context_slot) = min_context_slot {
        if min_context_slot > committed_slot {
            return Err(RpcMethodError::MinimumContextSlotNotReached);
        }
    }
    Ok(())
}

fn parse_block_config(request: &serde_json::Value) -> Result<BlockRequestConfig, RpcMethodError> {
    let params = params::params_array_or_empty(request);
    if params.len() > 2 {
        return Err(RpcMethodError::InvalidParams);
    }
    let config = match params.get(1).and_then(serde_json::Value::as_object) {
        Some(config) => config,
        None => {
            return Ok(BlockRequestConfig {
                encoding: ResponseEncoding::Json,
                transaction_details: BlockTransactionDetails::Full,
                include_rewards: true,
                max_supported_transaction_version: None,
            })
        }
    };
    ensure_no_unknown_keys(config, BLOCK_REQUEST_ALLOWED_KEYS)?;

    validate_commitment_value(config.get("commitment"))?;
    let encoding = parse_encoding_value(config.get("encoding"))?;

    let transaction_details = parse_block_transaction_details(config.get("transactionDetails"))?;

    let include_rewards = parse_bool_value(config.get("rewards"), true)?;
    let max_supported_transaction_version =
        parse_u64_value(config.get("maxSupportedTransactionVersion"))?;

    Ok(BlockRequestConfig {
        encoding,
        transaction_details,
        include_rewards,
        max_supported_transaction_version,
    })
}

fn parse_transaction_config(
    request: &serde_json::Value,
) -> Result<TransactionRequestConfig, RpcMethodError> {
    let params = params::params_array_or_empty(request);
    if params.len() > 2 {
        return Err(RpcMethodError::InvalidParams);
    }
    let config = match params.get(1).and_then(serde_json::Value::as_object) {
        Some(config) => config,
        None => {
            return Ok(TransactionRequestConfig {
                encoding: ResponseEncoding::Json,
                max_supported_transaction_version: None,
            })
        }
    };
    ensure_no_unknown_keys(config, TRANSACTION_REQUEST_ALLOWED_KEYS)?;

    validate_commitment_value(config.get("commitment"))?;
    let encoding = parse_encoding_value(config.get("encoding"))?;
    let max_supported_transaction_version =
        parse_u64_value(config.get("maxSupportedTransactionVersion"))?;

    Ok(TransactionRequestConfig {
        encoding,
        max_supported_transaction_version,
    })
}

fn validate_commitment_value(value: Option<&serde_json::Value>) -> Result<(), RpcMethodError> {
    if let Some(commitment) = value {
        let commitment = commitment
            .as_str()
            .ok_or(RpcMethodError::InvalidParams)?
            .to_ascii_lowercase();
        match commitment.as_str() {
            "processed" | "confirmed" | "finalized" => {}
            _ => return Err(RpcMethodError::InvalidParams),
        }
    }
    Ok(())
}

fn parse_encoding_value(
    value: Option<&serde_json::Value>,
) -> Result<ResponseEncoding, RpcMethodError> {
    let encoding = match value {
        Some(value) => value.as_str().ok_or(RpcMethodError::InvalidParams)?,
        None => "json",
    };
    if !ALLOWED_ENCODINGS.contains(&encoding) {
        return Err(RpcMethodError::InvalidParams);
    }
    match encoding {
        "json" => Ok(ResponseEncoding::Json),
        "jsonParsed" => Ok(ResponseEncoding::JsonParsed),
        "base58" => Ok(ResponseEncoding::Base58),
        "base64" => Ok(ResponseEncoding::Base64),
        _ => Err(RpcMethodError::InvalidParams),
    }
}

fn parse_block_transaction_details(
    value: Option<&serde_json::Value>,
) -> Result<BlockTransactionDetails, RpcMethodError> {
    let details = match value {
        Some(value) => value.as_str().ok_or(RpcMethodError::InvalidParams)?,
        None => "full",
    };
    if !ALLOWED_BLOCK_TRANSACTION_DETAILS.contains(&details) {
        return Err(RpcMethodError::InvalidParams);
    }
    match details {
        "full" => Ok(BlockTransactionDetails::Full),
        "accounts" => Ok(BlockTransactionDetails::Accounts),
        "signatures" => Ok(BlockTransactionDetails::Signatures),
        "none" => Ok(BlockTransactionDetails::None),
        _ => Err(RpcMethodError::InvalidParams),
    }
}

fn parse_bool_value(
    value: Option<&serde_json::Value>,
    default: bool,
) -> Result<bool, RpcMethodError> {
    match value {
        Some(value) => value.as_bool().ok_or(RpcMethodError::InvalidParams),
        None => Ok(default),
    }
}

fn ensure_no_unknown_keys(
    config: &serde_json::Map<String, serde_json::Value>,
    allowed_keys: &[&str],
) -> Result<(), RpcMethodError> {
    for key in config.keys() {
        if !allowed_keys.contains(&key.as_str()) {
            return Err(RpcMethodError::InvalidParams);
        }
    }
    Ok(())
}

fn ensure_query_config_shape(
    raw_config: Option<&serde_json::Value>,
    allowed_keys: &[&str],
) -> Result<(), RpcMethodError> {
    let Some(raw_config) = raw_config else {
        return Ok(());
    };
    let config = raw_config
        .as_object()
        .ok_or(RpcMethodError::InvalidParams)?;
    ensure_no_unknown_keys(config, allowed_keys)
}

fn min_context_slot_from_config(
    raw_config: Option<&serde_json::Value>,
) -> Result<Option<u64>, RpcMethodError> {
    let Some(raw_config) = raw_config else {
        return Ok(None);
    };
    let config = raw_config
        .as_object()
        .ok_or(RpcMethodError::InvalidParams)?;
    config
        .get("minContextSlot")
        .map(|value| value.as_u64().ok_or(RpcMethodError::InvalidParams))
        .transpose()
}

fn parse_u64_value(value: Option<&serde_json::Value>) -> Result<Option<u64>, RpcMethodError> {
    match value {
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or(RpcMethodError::InvalidParams),
        None => Ok(None),
    }
}

fn transaction_version_payload(
    max_supported_transaction_version: Option<u64>,
) -> serde_json::Value {
    match max_supported_transaction_version {
        Some(0) => json!(0_u64),
        Some(_) => json!(TRANSACTION_VERSION_LEGACY),
        None => json!(0_u64),
    }
}

fn transaction_message_payload(
    recent_blockhash: &str,
    encoding: ResponseEncoding,
) -> serde_json::Value {
    match encoding {
        ResponseEncoding::Json | ResponseEncoding::JsonParsed => json!({
            "accountKeys": [],
            "recentBlockhash": recent_blockhash,
            "instructions": []
        }),
        ResponseEncoding::Base58 | ResponseEncoding::Base64 => json!(recent_blockhash),
    }
}

fn format_real_block_response(
    block_data: &crate::state::RpcBlockData,
    config: &BlockRequestConfig,
    block_height: u64,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> serde_json::Value {
    // Use real blockhash from bank when available, otherwise synthetic.
    let blockhash_seed = snapshot
        .blockhash_seed_for_commitment(commitment)
        .wrapping_add(block_data.slot.rotate_left(11));
    let blockhash = block_data
        .blockhash
        .clone()
        .unwrap_or_else(|| shared::format_blockhash_from_seed(blockhash_seed));
    let prev_blockhash = block_data
        .previous_blockhash
        .clone()
        .unwrap_or_else(|| shared::format_blockhash_from_seed(blockhash_seed.wrapping_sub(1)));
    let block_height = block_data.block_height.unwrap_or(block_height);

    let block_time = block_data
        .block_time
        .unwrap_or_else(|| shared::synthetic_block_time(snapshot.uptime_millis, block_data.slot));

    let transactions = match config.transaction_details {
        BlockTransactionDetails::None => serde_json::Value::Array(Vec::new()),
        BlockTransactionDetails::Signatures => {
            let tx_list: Vec<serde_json::Value> = block_data
                .transactions
                .iter()
                .map(|tx| {
                    json!({
                        "meta": serde_json::Value::Null,
                        "transaction": {"signatures": tx.signatures},
                        "version": transaction_version_payload(config.max_supported_transaction_version)
                    })
                })
                .collect();
            serde_json::Value::Array(tx_list)
        }
        BlockTransactionDetails::Full | BlockTransactionDetails::Accounts => {
            let tx_list: Vec<serde_json::Value> = block_data
                .transactions
                .iter()
                .map(|tx| {
                    let encoded_data = match config.encoding {
                        ResponseEncoding::Base64 => {
                            use base64::Engine;
                            json!([
                                base64::engine::general_purpose::STANDARD.encode(&tx.raw_bytes),
                                "base64"
                            ])
                        }
                        ResponseEncoding::Base58 => {
                            json!([bs58::encode(&tx.raw_bytes).into_string(), "base58"])
                        }
                        ResponseEncoding::Json | ResponseEncoding::JsonParsed => {
                            json!({
                                "signatures": tx.signatures,
                                "message": {
                                    "accountKeys": [],
                                    "recentBlockhash": &blockhash,
                                    "instructions": []
                                }
                            })
                        }
                    };
                    json!({
                        "meta": {
                            "err": serde_json::Value::Null,
                            "fee": LAMPORTS_PER_SIGNATURE,
                            "status": {"Ok": serde_json::Value::Null}
                        },
                        "transaction": encoded_data,
                        "version": transaction_version_payload(config.max_supported_transaction_version)
                    })
                })
                .collect();
            serde_json::Value::Array(tx_list)
        }
    };

    let rewards = if config.include_rewards {
        serde_json::Value::Array(Vec::new())
    } else {
        serde_json::Value::Null
    };

    json!({
        "blockHeight": block_height,
        "blockTime": block_time,
        "blockhash": blockhash,
        "parentSlot": block_data.parent_slot,
        "previousBlockhash": prev_blockhash,
        "transactions": transactions,
        "rewards": rewards
    })
}

fn block_transaction_payload(
    recent_blockhash: &str,
    encoding: ResponseEncoding,
    max_supported_transaction_version: Option<u64>,
) -> serde_json::Value {
    json!({
        "meta": {
            "err": serde_json::Value::Null,
            "fee": LAMPORTS_PER_SIGNATURE,
            "status": {"Ok": serde_json::Value::Null}
        },
        "transaction": {
            "signatures": [],
            "message": transaction_message_payload(recent_blockhash, encoding)
        },
        "version": transaction_version_payload(max_supported_transaction_version)
    })
}
