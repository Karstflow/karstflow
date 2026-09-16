use std::sync::Arc;

use karstflow_constants::economics::{
    RENT_EXEMPTION_BASE_LAMPORTS, RENT_EXEMPTION_LAMPORTS_PER_BYTE,
};
use karstflow_constants::ledger::SLOTS_PER_EPOCH;

use crate::state::{BankAccessProvider, RpcCommitment, RpcRuntimeSnapshot};

use super::super::method_error::RpcMethodError;
use super::super::registry::RpcMethod;
use super::params;
use super::types::{
    self, EpochInfo, EpochSchedule, GetIdentityResponse, GetVersionResponse, HighestSnapshotSlot,
    RpcResponse,
};

pub(super) fn handle(
    method: RpcMethod,
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    _full_api: bool,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    match method {
        RpcMethod::GetHealth => {
            let healthy = bank_access.is_none_or(|b| b.is_healthy());
            if healthy {
                Ok(types::to_value(&"ok"))
            } else {
                Err(RpcMethodError::node_unhealthy(None))
            }
        }
        RpcMethod::GetVersion => {
            let response = GetVersionResponse {
                solana_core: "2.2.0".to_string(),
                feature_set: 4_215_500_110,
            };
            Ok(types::to_value(&response))
        }
        RpcMethod::GetGenesisHash => {
            let hash = bank_access
                .and_then(|bank| bank.get_genesis_hash())
                .unwrap_or_else(|| "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp6H6r6Q4QvJf4".to_string());
            Ok(types::to_value(&hash))
        }
        RpcMethod::GetIdentity => {
            let identity = bank_access
                .and_then(|bank| bank.get_identity())
                .unwrap_or_else(|| "Karstflow111111111111111111111111111111111".to_string());
            let response = GetIdentityResponse { identity };
            Ok(types::to_value(&response))
        }
        RpcMethod::GetEpochSchedule => {
            let (
                slots_per_epoch,
                leader_schedule_slot_offset,
                warmup,
                first_normal_epoch,
                first_normal_slot,
            ) = bank_access
                .and_then(|bank| bank.get_epoch_schedule())
                .unwrap_or((SLOTS_PER_EPOCH, SLOTS_PER_EPOCH, false, 0, 0));
            let response = EpochSchedule {
                slots_per_epoch,
                leader_schedule_slot_offset,
                warmup,
                first_normal_epoch,
                first_normal_slot,
            };
            Ok(types::to_value(&response))
        }
        RpcMethod::GetMinimumBalanceForRentExemption => {
            build_minimum_balance_for_rent_exemption_response(request)
        }
        RpcMethod::GetStakeMinimumDelegation => {
            build_stake_minimum_delegation_response(request, snapshot, commitment, bank_access)
        }
        RpcMethod::GetEpochInfo => Ok(build_epoch_info_response(snapshot, commitment, bank_access)),
        RpcMethod::GetFirstAvailableBlock => {
            let slot = bank_access
                .map(|bank| bank.get_first_available_block())
                .unwrap_or(0);
            Ok(types::to_value(&slot))
        }
        RpcMethod::MinimumLedgerSlot => {
            let slot = bank_access
                .map(|bank| bank.get_first_available_block())
                .unwrap_or(0);
            Ok(types::to_value(&slot))
        }
        RpcMethod::GetMaxShredInsertSlot => {
            let slot = bank_access
                .map(|bank| bank.get_slot(commitment))
                .unwrap_or_else(|| snapshot.slot_for_commitment(commitment));
            Ok(types::to_value(&slot))
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
            Ok(types::to_value(&slot))
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
    Ok(types::to_value(&required_lamports))
}

fn build_stake_minimum_delegation_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    let committed_slot = snapshot.slot_for_commitment(commitment);
    if let Some(min_context_slot) = params::min_context_slot_from_params(request)? {
        if min_context_slot > committed_slot {
            return Err(RpcMethodError::MinimumContextSlotNotReached);
        }
    }

    // The answer is feature-dependent: `upgrade_bpf_stake_program_to_v5` raises the
    // minimum from 1 lamport to 1 SOL. Report what the runtime would enforce, not a
    // fixed value — a client that sizes a delegation from this number and then has
    // the transaction rejected is worse served than one told nothing.
    let raised = bank_access
        .map(|bank| {
            bank.is_feature_active(
                &karstflow_ids::features::UPGRADE_BPF_STAKE_PROGRAM_TO_V5,
                commitment,
            )
        })
        .unwrap_or(false);
    let response = RpcResponse::new(
        committed_slot,
        karstflow_constants::stake_program::minimum_delegation_lamports(raised),
    );
    Ok(types::to_value(&response))
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

    let response = EpochInfo {
        absolute_slot,
        block_height,
        epoch,
        slot_index,
        slots_in_epoch: SLOTS_PER_EPOCH,
        transaction_count,
    };
    types::to_value(&response)
}

fn build_highest_snapshot_slot_response(
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> serde_json::Value {
    let committed_slot = bank_access
        .map(|bank| bank.get_slot(commitment))
        .unwrap_or_else(|| snapshot.slot_for_commitment(commitment));
    let response = HighestSnapshotSlot {
        full: committed_slot,
        incremental: committed_slot.saturating_sub(1),
    };
    types::to_value(&response)
}
