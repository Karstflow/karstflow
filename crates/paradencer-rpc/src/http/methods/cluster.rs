use serde_json::json;

use crate::state::{RpcCommitment, RpcRuntimeSnapshot};
use paradencer_constants::economics::DEFAULT_VOTE_COMMISSION_PERCENT;
use paradencer_constants::ledger::SLOTS_PER_EPOCH;
use paradencer_constants::rpc::{
    LEADER_SCHEDULE_ROTATION, PRIORITIZATION_FEE_BASE, PRIORITIZATION_FEE_PER_ACCOUNT_STEP,
    PRIORITIZATION_FEE_PER_ROW_STEP, PRIORITIZATION_FEE_ROWS, SIGNATURES_FOR_ADDRESS_DEFAULT_LIMIT,
    SIGNATURES_FOR_ADDRESS_MAX_LIMIT, SIGNATURES_FOR_ADDRESS_RESPONSE_MAX_ROWS,
    SLOT_LEADERS_MAX_LIMIT, TVU_BASE_PORT, TVU_PORT_SLOT_MODULUS, VOTE_ROOT_SLOT_BACKTRACK,
};

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
        RpcMethod::GetSignaturesForAddress | RpcMethod::GetConfirmedSignaturesForAddress2 => {
            build_signatures_for_address_response(request, snapshot, commitment)
        }
        RpcMethod::GetClusterNodes => Ok(build_cluster_nodes_response(snapshot, commitment)),
        RpcMethod::GetVoteAccounts => build_vote_accounts_response(request, snapshot, commitment),
        RpcMethod::GetSlotLeader => Ok(build_slot_leader_response(snapshot, commitment)),
        RpcMethod::GetSlotLeaders => build_slot_leaders_response(request, snapshot, commitment),
        RpcMethod::GetLeaderSchedule => {
            build_leader_schedule_response(request, snapshot, commitment)
        }
        RpcMethod::GetBlockProduction => {
            build_block_production_response(request, snapshot, commitment)
        }
        RpcMethod::GetRecentPrioritizationFees => {
            build_recent_prioritization_fees_response(request, snapshot, commitment)
        }
        _ => Err(RpcMethodError::MethodNotFound),
    }
}

#[derive(Clone)]
struct VoteAccountsConfig {
    vote_pubkey: Option<String>,
    keep_unstaked_delinquents: bool,
    delinquent_slot_distance: u64,
    min_context_slot: Option<u64>,
}

fn build_slot_leader_response(
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> serde_json::Value {
    let slot = snapshot.slot_for_commitment(commitment);
    json!(synthetic_leader_identity(slot))
}

fn build_slot_leaders_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> Result<serde_json::Value, RpcMethodError> {
    let params = params::params_array(request)?;
    let start_slot = params::first_param_u64(request)?;
    let limit = params
        .get(1)
        .and_then(serde_json::Value::as_u64)
        .ok_or(RpcMethodError::InvalidParams)?;
    if limit == 0 || limit > SLOT_LEADERS_MAX_LIMIT {
        return Err(RpcMethodError::InvalidParams);
    }

    let max_readable_slot = snapshot.slot_for_commitment(commitment);
    if start_slot > max_readable_slot {
        return Ok(json!([]));
    }

    let max_count = max_readable_slot
        .saturating_sub(start_slot)
        .saturating_add(1);
    let leaders = (0_u64..limit.min(max_count))
        .map(|index| synthetic_leader_identity(start_slot.saturating_add(index)))
        .collect::<Vec<_>>();
    Ok(json!(leaders))
}

fn build_signatures_for_address_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> Result<serde_json::Value, RpcMethodError> {
    let (address, before, until, limit, min_context_slot) =
        parse_signatures_for_address_params(request)?;
    let committed_slot = snapshot.slot_for_commitment(commitment);
    ensure_optional_min_context_slot(min_context_slot, committed_slot)?;
    let entry_count = limit.min(SIGNATURES_FOR_ADDRESS_RESPONSE_MAX_ROWS);
    let start_slot = before
        .as_deref()
        .map(signature_anchor_slot)
        .map(|delta| committed_slot.saturating_sub(delta.saturating_add(1)))
        .unwrap_or(committed_slot);
    let until_slot = until
        .as_deref()
        .map(signature_anchor_slot)
        .map(|delta| committed_slot.saturating_sub(delta));

    let values = (0_u64..entry_count)
        .filter_map(|index| {
            let slot = start_slot.saturating_sub(index);
            if until_slot.map(|boundary| slot < boundary).unwrap_or(false) {
                return None;
            }
            let signature_seed = snapshot
                .latest_blockhash_seed
                .wrapping_add(slot)
                .wrapping_add(
                    address
                        .bytes()
                        .fold(0_u64, |sum, byte| sum.wrapping_add(u64::from(byte))),
                );
            Some(json!({
                "signature": format!("{signature_seed:064x}"),
                "slot": slot,
                "err": serde_json::Value::Null,
                "memo": serde_json::Value::Null,
                "blockTime": shared::synthetic_block_time(snapshot.uptime_millis, slot),
                "confirmationStatus": confirmation_status_label(commitment),
                "sourceAddress": address,
                "before": before,
                "until": until
            }))
        })
        .collect::<Vec<_>>();
    Ok(json!(values))
}

fn build_cluster_nodes_response(
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> serde_json::Value {
    let slot = snapshot.slot_for_commitment(commitment);
    let tvu_port = TVU_BASE_PORT.saturating_add((slot % TVU_PORT_SLOT_MODULUS) as u16);
    json!([
        {
            "pubkey": "ParaDancer11111111111111111111111111111111",
            "gossip": "203.0.113.10:8001",
            "tpu": "203.0.113.10:8003",
            "rpc": "203.0.113.10:8899",
            "tvu": format!("203.0.113.10:{tvu_port}"),
            "version": env!("CARGO_PKG_VERSION"),
            "featureSet": 1_u64,
            "shredVersion": 1_u64
        }
    ])
}

fn build_vote_accounts_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> Result<serde_json::Value, RpcMethodError> {
    let config = parse_vote_accounts_config(request)?;
    let slot = snapshot.slot_for_commitment(commitment);
    ensure_optional_min_context_slot(config.min_context_slot, slot)?;
    let activated_stake = snapshot
        .transaction_count
        .saturating_mul(1_000)
        .saturating_add(1_000_000);

    let current_vote_pubkey = "Vote111111111111111111111111111111111111111";
    let current = json!({
            "votePubkey": current_vote_pubkey,
            "nodePubkey": "ParaDancer11111111111111111111111111111111",
            "activatedStake": activated_stake,
            "commission": DEFAULT_VOTE_COMMISSION_PERCENT,
            "epochVoteAccount": true,
            "epochCredits": [[slot / SLOTS_PER_EPOCH, slot, 0]],
            "lastVote": slot,
            "rootSlot": slot.saturating_sub(VOTE_ROOT_SLOT_BACKTRACK)
    });
    let current_accounts = match config.vote_pubkey.as_deref() {
        Some(pubkey) if pubkey != current_vote_pubkey => Vec::new(),
        _ => vec![current],
    };

    let delinquent = if config.keep_unstaked_delinquents {
        vec![json!({
            "votePubkey": "VoteDelinq11111111111111111111111111111111111",
            "nodePubkey": "ParaDancer33333333333333333333333333333333",
            "activatedStake": 0_u64,
            "commission": DEFAULT_VOTE_COMMISSION_PERCENT,
            "epochVoteAccount": false,
            "epochCredits": [[slot / SLOTS_PER_EPOCH, slot.saturating_sub(config.delinquent_slot_distance), 0]],
            "lastVote": slot.saturating_sub(config.delinquent_slot_distance),
            "rootSlot": slot.saturating_sub(config.delinquent_slot_distance.saturating_add(VOTE_ROOT_SLOT_BACKTRACK))
        })]
    } else {
        Vec::new()
    };

    Ok(json!({
        "current": current_accounts,
        "delinquent": delinquent
    }))
}

fn parse_vote_accounts_config(
    request: &serde_json::Value,
) -> Result<VoteAccountsConfig, RpcMethodError> {
    let params = params::params_array_or_empty(request);
    let config_object = params::first_config_object(params);

    let vote_pubkey = config_object
        .and_then(|cfg| cfg.get("votePubkey"))
        .map(|value| {
            value
                .as_str()
                .map(str::trim)
                .filter(|pubkey| !pubkey.is_empty())
                .map(str::to_string)
                .ok_or(RpcMethodError::InvalidParams)
        })
        .transpose()?;

    let keep_unstaked_delinquents = config_object
        .and_then(|cfg| cfg.get("keepUnstakedDelinquents"))
        .map(|value| value.as_bool().ok_or(RpcMethodError::InvalidParams))
        .transpose()?
        .unwrap_or(false);

    let delinquent_slot_distance = config_object
        .and_then(|cfg| cfg.get("delinquentSlotDistance"))
        .map(|value| value.as_u64().ok_or(RpcMethodError::InvalidParams))
        .transpose()?
        .unwrap_or(128);

    let min_context_slot = config_object
        .and_then(|cfg| cfg.get("minContextSlot"))
        .map(|value| value.as_u64().ok_or(RpcMethodError::InvalidParams))
        .transpose()?;

    Ok(VoteAccountsConfig {
        vote_pubkey,
        keep_unstaked_delinquents,
        delinquent_slot_distance,
        min_context_slot,
    })
}

fn build_leader_schedule_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;
    let identity_filter = parse_identity_filter_from_params(request)?;
    let base_slot = snapshot.slot_for_commitment(commitment);
    let slot_offset = base_slot % LEADER_SCHEDULE_ROTATION;
    let schedule = vec![
        base_slot.saturating_add(slot_offset),
        base_slot.saturating_add(slot_offset + LEADER_SCHEDULE_ROTATION),
        base_slot.saturating_add(slot_offset + LEADER_SCHEDULE_ROTATION * 2),
    ];

    let mut by_identity = serde_json::Map::new();
    let default_identity = "ParaDancer11111111111111111111111111111111";
    let fallback_identity = "ParaDancer22222222222222222222222222222222";
    match identity_filter {
        Some(identity) => {
            by_identity.insert(identity, json!(schedule));
        }
        None => {
            by_identity.insert(default_identity.to_string(), json!(schedule));
            by_identity.insert(
                fallback_identity.to_string(),
                json!([
                    base_slot.saturating_add(slot_offset + 1),
                    base_slot.saturating_add(slot_offset + LEADER_SCHEDULE_ROTATION + 1),
                ]),
            );
        }
    }
    Ok(json!(serde_json::Value::Object(by_identity)))
}

fn build_block_production_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;
    let current_slot = snapshot.slot_for_commitment(commitment);
    let (requested_first, requested_last) = parse_slot_range_from_params(request)?;
    let first_slot = requested_first.unwrap_or(current_slot.saturating_sub(31));
    let last_slot = requested_last.unwrap_or(current_slot);
    if last_slot < first_slot {
        return Err(RpcMethodError::InvalidParams);
    }

    let effective_last_slot = last_slot.min(current_slot);
    if effective_last_slot < first_slot {
        return Ok(json!({
            "byIdentity": {},
            "range": {"firstSlot": first_slot, "lastSlot": first_slot}
        }));
    }

    let produced_count = effective_last_slot
        .saturating_sub(first_slot)
        .saturating_add(1);
    let identity = "ParaDancer11111111111111111111111111111111";
    Ok(json!({
        "byIdentity": {
            identity: [produced_count, produced_count]
        },
        "range": {"firstSlot": first_slot, "lastSlot": effective_last_slot}
    }))
}

fn build_recent_prioritization_fees_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;
    let account_count = parse_optional_account_list_len(request)?;
    let current_slot = snapshot.slot_for_commitment(commitment);
    let base_fee = PRIORITIZATION_FEE_BASE
        .saturating_add(account_count as u64 * PRIORITIZATION_FEE_PER_ACCOUNT_STEP);

    let rows = (0_u64..PRIORITIZATION_FEE_ROWS)
        .map(|index| {
            json!({
                "slot": current_slot.saturating_sub(index),
                "prioritizationFee": base_fee.saturating_add(index * PRIORITIZATION_FEE_PER_ROW_STEP)
            })
        })
        .collect::<Vec<_>>();
    Ok(json!(rows))
}

type SignaturesForAddressParams = (String, Option<String>, Option<String>, u64, Option<u64>);

fn parse_signatures_for_address_params(
    request: &serde_json::Value,
) -> Result<SignaturesForAddressParams, RpcMethodError> {
    let params = params::params_array(request)?;
    let address = params::first_param_non_empty_string(request)?;

    let config_object = params::first_config_object(params);
    let before = config_object
        .and_then(|cfg| cfg.get("before"))
        .map(|value| {
            value
                .as_str()
                .map(str::trim)
                .filter(|sig| !sig.is_empty())
                .map(str::to_string)
                .ok_or(RpcMethodError::InvalidParams)
        })
        .transpose()?;
    let until = config_object
        .and_then(|cfg| cfg.get("until"))
        .map(|value| {
            value
                .as_str()
                .map(str::trim)
                .filter(|sig| !sig.is_empty())
                .map(str::to_string)
                .ok_or(RpcMethodError::InvalidParams)
        })
        .transpose()?;
    let limit = config_object
        .and_then(|cfg| cfg.get("limit"))
        .map(|value| value.as_u64().ok_or(RpcMethodError::InvalidParams))
        .transpose()?
        .unwrap_or(SIGNATURES_FOR_ADDRESS_DEFAULT_LIMIT)
        .clamp(1, SIGNATURES_FOR_ADDRESS_MAX_LIMIT);
    let min_context_slot = config_object
        .and_then(|cfg| cfg.get("minContextSlot"))
        .map(|value| value.as_u64().ok_or(RpcMethodError::InvalidParams))
        .transpose()?;
    Ok((address, before, until, limit, min_context_slot))
}

fn parse_identity_filter_from_params(
    request: &serde_json::Value,
) -> Result<Option<String>, RpcMethodError> {
    let params = params::params_array_or_empty(request);
    let config_object = params::first_config_object(params);
    let maybe_identity = config_object
        .and_then(|cfg| cfg.get("identity"))
        .map(|value| {
            value
                .as_str()
                .map(str::trim)
                .filter(|identity| !identity.is_empty())
                .map(str::to_string)
                .ok_or(RpcMethodError::InvalidParams)
        })
        .transpose()?;
    Ok(maybe_identity)
}

fn parse_slot_range_from_params(
    request: &serde_json::Value,
) -> Result<(Option<u64>, Option<u64>), RpcMethodError> {
    let params = params::params_array_or_empty(request);
    let config_object = params::first_config_object(params);
    let range = config_object
        .and_then(|cfg| cfg.get("range"))
        .and_then(serde_json::Value::as_object);

    let first_slot = range
        .and_then(|range| range.get("firstSlot"))
        .map(|value| value.as_u64().ok_or(RpcMethodError::InvalidParams))
        .transpose()?;
    let last_slot = range
        .and_then(|range| range.get("lastSlot"))
        .map(|value| value.as_u64().ok_or(RpcMethodError::InvalidParams))
        .transpose()?;
    Ok((first_slot, last_slot))
}

fn parse_optional_account_list_len(request: &serde_json::Value) -> Result<usize, RpcMethodError> {
    let params = params::params_array_or_empty(request);
    let first_param = match params.first() {
        Some(value) => value,
        None => return Ok(0),
    };
    if first_param.is_null() {
        return Ok(0);
    }
    let accounts = first_param
        .as_array()
        .ok_or(RpcMethodError::InvalidParams)?;
    for account in accounts {
        let valid = account
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_some();
        if !valid {
            return Err(RpcMethodError::InvalidParams);
        }
    }
    Ok(accounts.len())
}

fn ensure_min_context_slot_satisfied(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> Result<(), RpcMethodError> {
    let min_context_slot = params::min_context_slot_from_params(request)?;
    ensure_optional_min_context_slot(min_context_slot, snapshot.slot_for_commitment(commitment))
}

fn confirmation_status_label(commitment: RpcCommitment) -> &'static str {
    match commitment {
        RpcCommitment::Processed => "processed",
        RpcCommitment::Confirmed => "confirmed",
        RpcCommitment::Finalized => "finalized",
    }
}

fn synthetic_leader_identity(slot: u64) -> String {
    format!("ParaLeader{:032x}", slot)
}

fn signature_anchor_slot(signature: &str) -> u64 {
    signature
        .bytes()
        .fold(0_u64, |sum, byte| sum.wrapping_add(u64::from(byte)))
        % 64
}

fn ensure_optional_min_context_slot(
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
