use serde_json::json;
use std::sync::Arc;

use crate::state::{BankAccessProvider, RpcCommitment, RpcRuntimeSnapshot};
use paradencer_constants::economics::LAMPORTS_PER_SIGNATURE;
use paradencer_constants::ledger::{MAX_PERFORMANCE_SAMPLES, RECENT_BLOCKHASH_VALIDITY_WINDOW};

use super::super::method_error::RpcMethodError;
use super::super::registry::RpcMethod;
use super::params;
use super::shared;

pub(super) fn handle(
    method: RpcMethod,
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    match method {
        RpcMethod::GetSlot => build_slot_response(request, snapshot, commitment, bank_access),
        RpcMethod::GetBlockHeight => {
            build_block_height_response(request, snapshot, commitment, bank_access)
        }
        RpcMethod::GetBlockCount => build_block_count_response(request, snapshot, commitment),
        RpcMethod::GetTransactionCount => {
            build_transaction_count_response(request, snapshot, commitment, bank_access)
        }
        RpcMethod::IsBlockhashValid => {
            build_is_blockhash_valid_response(request, snapshot, commitment, bank_access)
        }
        RpcMethod::GetFeeForMessage => {
            build_fee_for_message_response(request, snapshot, commitment, bank_access)
        }
        RpcMethod::GetFees => build_fees_response(request, snapshot, commitment, bank_access),
        RpcMethod::GetFeeCalculatorForBlockhash => {
            build_fee_calculator_for_blockhash_response(request, snapshot, commitment, bank_access)
        }
        RpcMethod::GetRecentBlockhash => {
            build_recent_blockhash_response(request, snapshot, commitment, bank_access)
        }
        RpcMethod::GetLatestBlockhash => {
            build_latest_blockhash_response(request, snapshot, commitment, bank_access)
        }
        RpcMethod::GetRecentPerformanceSamples => {
            let requested_limit = parse_performance_sample_limit(request)?.unwrap_or(1);
            Ok(json!(build_performance_samples(
                snapshot,
                requested_limit,
                commitment
            )))
        }
        _ => Err(RpcMethodError::MethodNotFound),
    }
}

fn parse_performance_sample_limit(
    request: &serde_json::Value,
) -> Result<Option<u64>, RpcMethodError> {
    let params = params::params_array_or_empty(request);
    let first_param = match params.first() {
        Some(first_param) => first_param,
        None => return Ok(None),
    };
    let limit = first_param.as_u64().ok_or(RpcMethodError::InvalidParams)?;
    if limit == 0 {
        return Err(RpcMethodError::InvalidParams);
    }
    Ok(Some(limit))
}

fn build_performance_samples(
    snapshot: RpcRuntimeSnapshot,
    requested_limit: u64,
    commitment: RpcCommitment,
) -> Vec<serde_json::Value> {
    let limit = requested_limit.clamp(1, MAX_PERFORMANCE_SAMPLES);
    let sample_period_secs = 1_u64;
    let nonzero_uptime_secs = (snapshot.uptime_millis.max(1) / 1000).max(1) as u64;
    let committed_slot = snapshot.slot_for_commitment(commitment);
    let estimated_slots_per_second = committed_slot.max(1) / nonzero_uptime_secs;
    let num_slots = estimated_slots_per_second.max(1);

    (0..limit)
        .map(|index| {
            json!({
                "slot": committed_slot.saturating_sub(index),
                "numTransactions": snapshot.transaction_count,
                "numSlots": num_slots,
                "samplePeriodSecs": sample_period_secs,
                "numNonVoteTransactions": snapshot.transaction_count,
            })
        })
        .collect()
}

fn build_transaction_count_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;
    let count = bank_access
        .map(|bank| bank.get_transaction_count(commitment))
        .unwrap_or(snapshot.transaction_count);
    Ok(json!(count))
}

fn build_slot_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;
    let slot = bank_access
        .map(|bank| bank.get_slot(commitment))
        .unwrap_or_else(|| snapshot.slot_for_commitment(commitment));
    Ok(json!(slot))
}

fn build_block_height_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;
    let height = bank_access
        .map(|bank| bank.get_block_height(commitment))
        .unwrap_or_else(|| snapshot.block_height_for_commitment(commitment));
    Ok(json!(height))
}

fn build_block_count_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;
    Ok(json!(snapshot.block_height_for_commitment(commitment)))
}

fn build_is_blockhash_valid_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;
    let blockhash_str = parse_blockhash_param(request)?;

    let (context_slot, is_valid) = if let Some(bank) = bank_access {
        let hash_bytes = decode_blockhash(&blockhash_str)?;
        let slot = bank.get_slot(commitment);
        let valid = bank.is_blockhash_valid(&hash_bytes, commitment);
        (slot, valid)
    } else {
        let context_slot = snapshot.slot_for_commitment(commitment);
        let reference_blockhash =
            shared::format_blockhash_from_seed(snapshot.blockhash_seed_for_commitment(commitment));
        (context_slot, blockhash_str == reference_blockhash)
    };

    Ok(json!({
        "context": {"slot": context_slot},
        "value": is_valid
    }))
}

fn build_fee_for_message_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;
    let message = parse_message_param(request)?;

    let (context_slot, fee) = if let Some(bank) = bank_access {
        let slot = bank.get_slot(commitment);
        let base_fee = bank.get_lamports_per_signature(commitment);
        let message_units = message.len() as u64;
        (
            slot,
            base_fee.saturating_add(message_units.saturating_mul(10)),
        )
    } else {
        let context_slot = snapshot.slot_for_commitment(commitment);
        let message_units = message.len() as u64;
        let fee = LAMPORTS_PER_SIGNATURE.saturating_add(message_units.saturating_mul(10));
        (context_slot, fee)
    };

    Ok(json!({
        "context": {"slot": context_slot},
        "value": fee
    }))
}

fn build_recent_blockhash_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;

    let (context_slot, blockhash, fee) = if let Some(bank) = bank_access {
        let slot = bank.get_slot(commitment);
        let hash = bs58::encode(bank.get_latest_blockhash(commitment)).into_string();
        let fee = bank.get_lamports_per_signature(commitment);
        (slot, hash, fee)
    } else {
        let slot = snapshot.slot_for_commitment(commitment);
        let hash =
            shared::format_blockhash_from_seed(snapshot.blockhash_seed_for_commitment(commitment));
        (slot, hash, LAMPORTS_PER_SIGNATURE)
    };

    Ok(json!({
        "context": {"slot": context_slot},
        "value": {
            "blockhash": blockhash,
            "feeCalculator": {"lamportsPerSignature": fee}
        }
    }))
}

fn build_latest_blockhash_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;

    let (committed_slot, blockhash, last_valid_block_height) = if let Some(bank) = bank_access {
        let slot = bank.get_slot(commitment);
        let hash = bs58::encode(bank.get_latest_blockhash(commitment)).into_string();
        let last_valid = bank.get_last_valid_block_height(commitment);
        (slot, hash, last_valid)
    } else {
        let slot = snapshot.slot_for_commitment(commitment);
        let hash =
            shared::format_blockhash_from_seed(snapshot.blockhash_seed_for_commitment(commitment));
        let height = snapshot.block_height_for_commitment(commitment);
        (
            slot,
            hash,
            height.saturating_add(RECENT_BLOCKHASH_VALIDITY_WINDOW),
        )
    };

    Ok(json!({
        "context": {"slot": committed_slot},
        "value": {
            "blockhash": blockhash,
            "lastValidBlockHeight": last_valid_block_height
        }
    }))
}

fn build_fees_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;

    let (context_slot, blockhash, fee, last_valid_block_height) = if let Some(bank) = bank_access {
        let slot = bank.get_slot(commitment);
        let hash = bs58::encode(bank.get_latest_blockhash(commitment)).into_string();
        let fee = bank.get_lamports_per_signature(commitment);
        let last_valid = bank.get_last_valid_block_height(commitment);
        (slot, hash, fee, last_valid)
    } else {
        let slot = snapshot.slot_for_commitment(commitment);
        let hash =
            shared::format_blockhash_from_seed(snapshot.blockhash_seed_for_commitment(commitment));
        let height = snapshot.block_height_for_commitment(commitment);
        (
            slot,
            hash,
            LAMPORTS_PER_SIGNATURE,
            height.saturating_add(RECENT_BLOCKHASH_VALIDITY_WINDOW),
        )
    };

    Ok(json!({
        "context": {"slot": context_slot},
        "value": {
            "blockhash": blockhash,
            "feeCalculator": {"lamportsPerSignature": fee},
            "lastValidSlot": context_slot.saturating_add(RECENT_BLOCKHASH_VALIDITY_WINDOW),
            "lastValidBlockHeight": last_valid_block_height
        }
    }))
}

fn build_fee_calculator_for_blockhash_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;
    let requested_blockhash = parse_blockhash_param(request)?;

    let (context_slot, fee_calculator) = if let Some(bank) = bank_access {
        let slot = bank.get_slot(commitment);
        let hash_bytes = decode_blockhash(&requested_blockhash)?;
        let is_valid = bank.is_blockhash_valid(&hash_bytes, commitment);
        let calc = if is_valid {
            let fee = bank.get_lamports_per_signature(commitment);
            json!({"lamportsPerSignature": fee})
        } else {
            serde_json::Value::Null
        };
        (slot, calc)
    } else {
        let current_blockhash =
            shared::format_blockhash_from_seed(snapshot.blockhash_seed_for_commitment(commitment));
        let context_slot = snapshot.slot_for_commitment(commitment);
        let calc = if requested_blockhash == current_blockhash {
            json!({"lamportsPerSignature": LAMPORTS_PER_SIGNATURE})
        } else {
            serde_json::Value::Null
        };
        (context_slot, calc)
    };

    Ok(json!({
        "context": {"slot": context_slot},
        "value": fee_calculator
    }))
}

fn parse_blockhash_param(request: &serde_json::Value) -> Result<String, RpcMethodError> {
    params::first_param_non_empty_string(request)
}

fn parse_message_param(request: &serde_json::Value) -> Result<String, RpcMethodError> {
    params::first_param_non_empty_string(request)
}

fn parse_min_context_slot(request: &serde_json::Value) -> Result<Option<u64>, RpcMethodError> {
    params::min_context_slot_from_params(request)
}

fn decode_blockhash(encoded: &str) -> Result<[u8; 32], RpcMethodError> {
    let bytes = bs58::decode(encoded)
        .into_vec()
        .map_err(|_| RpcMethodError::InvalidParams)?;
    bytes.try_into().map_err(|_| RpcMethodError::InvalidParams)
}

fn ensure_min_context_slot_satisfied(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> Result<(), RpcMethodError> {
    let committed_slot = snapshot.slot_for_commitment(commitment);
    let min_context_slot = parse_min_context_slot(request)?;
    if let Some(min_context_slot) = min_context_slot {
        if min_context_slot > committed_slot {
            return Err(RpcMethodError::MinimumContextSlotNotReached);
        }
    }
    Ok(())
}
