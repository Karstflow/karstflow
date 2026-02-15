use serde_json::json;

use crate::state::{RpcCommitment, RpcRuntimeSnapshot};
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
) -> Result<serde_json::Value, RpcMethodError> {
    match method {
        RpcMethod::GetSlot => build_slot_response(request, snapshot, commitment),
        RpcMethod::GetBlockHeight => build_block_height_response(request, snapshot, commitment),
        RpcMethod::GetBlockCount => build_block_count_response(request, snapshot, commitment),
        RpcMethod::GetTransactionCount => {
            build_transaction_count_response(request, snapshot, commitment)
        }
        RpcMethod::IsBlockhashValid => {
            build_is_blockhash_valid_response(request, snapshot, commitment)
        }
        RpcMethod::GetFeeForMessage => {
            build_fee_for_message_response(request, snapshot, commitment)
        }
        RpcMethod::GetFees => build_fees_response(request, snapshot, commitment),
        RpcMethod::GetFeeCalculatorForBlockhash => {
            build_fee_calculator_for_blockhash_response(request, snapshot, commitment)
        }
        RpcMethod::GetRecentBlockhash => {
            build_recent_blockhash_response(request, snapshot, commitment)
        }
        RpcMethod::GetLatestBlockhash => {
            build_latest_blockhash_response(request, snapshot, commitment)
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
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;
    Ok(json!(snapshot.transaction_count))
}

fn build_slot_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;
    Ok(json!(snapshot.slot_for_commitment(commitment)))
}

fn build_block_height_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;
    Ok(json!(snapshot.block_height_for_commitment(commitment)))
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
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;

    let blockhash = parse_blockhash_param(request)?;
    let context_slot = snapshot.slot_for_commitment(commitment);
    let reference_blockhash =
        shared::format_blockhash_from_seed(snapshot.blockhash_seed_for_commitment(commitment));
    let is_valid = blockhash == reference_blockhash;
    Ok(json!({
        "context": {"slot": context_slot},
        "value": is_valid
    }))
}

fn build_fee_for_message_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;

    let message = parse_message_param(request)?;
    let context_slot = snapshot.slot_for_commitment(commitment);
    let message_units = message.len() as u64;
    let fee = LAMPORTS_PER_SIGNATURE.saturating_add(message_units.saturating_mul(10));
    Ok(json!({
        "context": {"slot": context_slot},
        "value": fee
    }))
}

fn build_recent_blockhash_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;

    let context_slot = snapshot.slot_for_commitment(commitment);
    Ok(json!({
        "context": {"slot": context_slot},
        "value": {
            "blockhash": shared::format_blockhash_from_seed(snapshot.blockhash_seed_for_commitment(commitment)),
            "feeCalculator": {"lamportsPerSignature": LAMPORTS_PER_SIGNATURE}
        }
    }))
}

fn build_latest_blockhash_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;

    let committed_slot = snapshot.slot_for_commitment(commitment);
    let committed_height = snapshot.block_height_for_commitment(commitment);
    Ok(json!({
        "context": {"slot": committed_slot},
        "value": {
            "blockhash": shared::format_blockhash_from_seed(snapshot.blockhash_seed_for_commitment(commitment)),
            "lastValidBlockHeight": committed_height
                .saturating_add(RECENT_BLOCKHASH_VALIDITY_WINDOW)
        }
    }))
}

fn build_fees_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;

    let context_slot = snapshot.slot_for_commitment(commitment);
    let block_height = snapshot.block_height_for_commitment(commitment);
    Ok(json!({
        "context": {"slot": context_slot},
        "value": {
            "blockhash": shared::format_blockhash_from_seed(snapshot.blockhash_seed_for_commitment(commitment)),
            "feeCalculator": {"lamportsPerSignature": LAMPORTS_PER_SIGNATURE},
            "lastValidSlot": context_slot.saturating_add(RECENT_BLOCKHASH_VALIDITY_WINDOW),
            "lastValidBlockHeight": block_height.saturating_add(RECENT_BLOCKHASH_VALIDITY_WINDOW)
        }
    }))
}

fn build_fee_calculator_for_blockhash_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;

    let requested_blockhash = parse_blockhash_param(request)?;
    let current_blockhash =
        shared::format_blockhash_from_seed(snapshot.blockhash_seed_for_commitment(commitment));
    let context_slot = snapshot.slot_for_commitment(commitment);
    let fee_calculator = if requested_blockhash == current_blockhash {
        json!({"lamportsPerSignature": LAMPORTS_PER_SIGNATURE})
    } else {
        serde_json::Value::Null
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
