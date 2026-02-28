use serde_json::json;
use std::sync::Arc;

use paradencer_constants::economics::{
    MIN_STAKE_DELEGATION_LAMPORTS, RENT_EXEMPTION_BASE_LAMPORTS, RENT_EXEMPTION_LAMPORTS_PER_BYTE,
};
use paradencer_constants::ledger::SLOTS_PER_EPOCH;

use crate::state::{BankAccessProvider, RpcCommitment, RpcRuntimeSnapshot};

use super::super::method_error::RpcMethodError;
use super::super::registry::RpcMethod;
use super::params;

pub(super) fn handle(
    method: RpcMethod,
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    full_api: bool,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    match method {
        RpcMethod::GetHealth => Ok(json!("ok")),
        RpcMethod::GetVersion => Ok(json!({
            "paradencer-core": env!("CARGO_PKG_VERSION"),
            "feature-set": if full_api { "full_api" } else { "subset_api" }
        })),
        RpcMethod::GetGenesisHash => {
            let hash = bank_access
                .and_then(|bank| bank.get_genesis_hash())
                .unwrap_or_else(|| "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp6H6r6Q4QvJf4".to_string());
            Ok(json!(hash))
        }
        RpcMethod::GetIdentity => {
            let identity = bank_access
                .and_then(|bank| bank.get_identity())
                .unwrap_or_else(|| "ParaDancer11111111111111111111111111111111".to_string());
            Ok(json!({"identity": identity}))
        }
        RpcMethod::GetEpochSchedule => Ok(json!({
            "slotsPerEpoch": SLOTS_PER_EPOCH,
            "leaderScheduleSlotOffset": SLOTS_PER_EPOCH,
            "warmup": false,
            "firstNormalEpoch": 0_u64,
            "firstNormalSlot": 0_u64
        })),
        RpcMethod::GetMinimumBalanceForRentExemption => {
            build_minimum_balance_for_rent_exemption_response(request)
        }
        RpcMethod::GetStakeMinimumDelegation => {
            build_stake_minimum_delegation_response(request, snapshot, commitment)
        }
        RpcMethod::GetEpochInfo => Ok(build_epoch_info_response(snapshot, commitment, bank_access)),
        RpcMethod::GetFirstAvailableBlock => Ok(json!(0_u64)),
        RpcMethod::MinimumLedgerSlot => Ok(json!(0_u64)),
        RpcMethod::GetMaxShredInsertSlot => {
            let slot = bank_access
                .map(|bank| bank.get_slot(commitment))
                .unwrap_or_else(|| snapshot.slot_for_commitment(commitment));
            Ok(json!(slot))
        }
        RpcMethod::GetHighestSnapshotSlot => Ok(build_highest_snapshot_slot_response(
            snapshot,
            commitment,
            bank_access,
        )),
        RpcMethod::GetMaxRetransmitSlot => {
            let slot = bank_access
                .map(|bank| bank.get_slot(commitment))
                .unwrap_or_else(|| snapshot.slot_for_commitment(commitment));
            Ok(json!(slot))
        }
        _ => Err(RpcMethodError::MethodNotFound),
    }
}

fn build_minimum_balance_for_rent_exemption_response(
    request: &serde_json::Value,
) -> Result<serde_json::Value, RpcMethodError> {
    let data_len = params::first_param_u64(request)?;
    let required_lamports = RENT_EXEMPTION_BASE_LAMPORTS
        .saturating_add(data_len.saturating_mul(RENT_EXEMPTION_LAMPORTS_PER_BYTE));
    Ok(json!(required_lamports))
}

fn build_stake_minimum_delegation_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> Result<serde_json::Value, RpcMethodError> {
    let committed_slot = snapshot.slot_for_commitment(commitment);
    if let Some(min_context_slot) = params::min_context_slot_from_params(request)? {
        if min_context_slot > committed_slot {
            return Err(RpcMethodError::MinimumContextSlotNotReached);
        }
    }

    Ok(json!({
        "context": {"slot": committed_slot},
        "value": MIN_STAKE_DELEGATION_LAMPORTS
    }))
}

fn build_epoch_info_response(
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> serde_json::Value {
    let absolute_slot = bank_access
        .map(|bank| bank.get_slot(commitment))
        .unwrap_or_else(|| snapshot.slot_for_commitment(commitment));
    let block_height = bank_access
        .map(|bank| bank.get_block_height(commitment))
        .unwrap_or_else(|| snapshot.block_height_for_commitment(commitment));
    let transaction_count = bank_access
        .map(|bank| bank.get_transaction_count(commitment))
        .unwrap_or(snapshot.transaction_count);
    let epoch = absolute_slot / SLOTS_PER_EPOCH;
    let slot_index = absolute_slot % SLOTS_PER_EPOCH;
    json!({
        "absoluteSlot": absolute_slot,
        "blockHeight": block_height,
        "epoch": epoch,
        "slotIndex": slot_index,
        "slotsInEpoch": SLOTS_PER_EPOCH,
        "transactionCount": transaction_count
    })
}

fn build_highest_snapshot_slot_response(
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> serde_json::Value {
    let committed_slot = bank_access
        .map(|bank| bank.get_slot(commitment))
        .unwrap_or_else(|| snapshot.slot_for_commitment(commitment));
    json!({
        "full": committed_slot,
        "incremental": committed_slot.saturating_sub(1)
    })
}
