use serde_json::json;
use std::sync::Arc;

use crate::state::{BankAccessProvider, RpcCommitment, RpcRuntimeSnapshot};
use karstflow_constants::economics::DEFAULT_VOTE_COMMISSION_PERCENT;
use karstflow_constants::ledger::SLOTS_PER_EPOCH;
use karstflow_constants::rpc::{
    LEADER_SCHEDULE_ROTATION, PRIORITIZATION_FEE_BASE, PRIORITIZATION_FEE_PER_ACCOUNT_STEP,
    PRIORITIZATION_FEE_PER_ROW_STEP, PRIORITIZATION_FEE_ROWS, SIGNATURES_FOR_ADDRESS_DEFAULT_LIMIT,
    SIGNATURES_FOR_ADDRESS_MAX_LIMIT, SIGNATURES_FOR_ADDRESS_RESPONSE_MAX_ROWS,
    SLOT_LEADERS_MAX_LIMIT, TVU_BASE_PORT, TVU_PORT_SLOT_MODULUS, VOTE_ROOT_SLOT_BACKTRACK,
};

use super::super::method_error::RpcMethodError;
use super::super::registry::RpcMethod;
use super::params;
use super::shared;
use super::types::{
    self, BlockProductionRange, BlockProductionValue, ClusterNode, PrioritizationFee, RpcResponse,
    SignatureForAddress, VoteAccountInfo, VoteAccountsResponse,
};

pub(super) fn handle(
    method: RpcMethod,
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    match method {
        RpcMethod::GetSignaturesForAddress | RpcMethod::GetConfirmedSignaturesForAddress2 => {
            build_signatures_for_address_response(request, snapshot, commitment, bank_access)
        }
        RpcMethod::GetClusterNodes => Ok(build_cluster_nodes_response(
            snapshot,
            commitment,
            bank_access,
        )),
        RpcMethod::GetVoteAccounts => {
            build_vote_accounts_response(request, snapshot, commitment, bank_access)
        }
        RpcMethod::GetSlotLeader => Ok(build_slot_leader_response(
            snapshot,
            commitment,
            bank_access,
        )),
        RpcMethod::GetSlotLeaders => {
            build_slot_leaders_response(request, snapshot, commitment, bank_access)
        }
        RpcMethod::GetLeaderSchedule => {
            build_leader_schedule_response(request, snapshot, commitment, bank_access)
        }
        RpcMethod::GetBlockProduction => {
            build_block_production_response(request, snapshot, commitment, bank_access)
        }
        RpcMethod::GetRecentPrioritizationFees => {
            build_recent_prioritization_fees_response(request, snapshot, commitment, bank_access)
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
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> serde_json::Value {
    let slot = bank_access
        .map(|bank| bank.get_slot(commitment))
        .unwrap_or_else(|| snapshot.slot_for_commitment(commitment));
    if let Some(bank) = bank_access {
        if let Some(leader) = bank.get_slot_leader(slot, commitment) {
            return types::to_value(&leader.to_string());
        }
    }
    types::to_value(&synthetic_leader_identity(slot))
}

fn build_slot_leaders_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
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

    let max_readable_slot = bank_access
        .map(|bank| bank.get_slot(commitment))
        .unwrap_or_else(|| snapshot.slot_for_commitment(commitment));
    if start_slot > max_readable_slot {
        let empty: Vec<String> = Vec::new();
        return Ok(types::to_value(&empty));
    }

    let max_count = max_readable_slot
        .saturating_sub(start_slot)
        .saturating_add(1);
    let effective_limit = limit.min(max_count);

    if let Some(bank) = bank_access {
        let leaders_range = bank.get_slot_leaders(start_slot, effective_limit, commitment);
        let leaders: Vec<String> = leaders_range
            .into_iter()
            .map(|(slot, leader)| {
                leader
                    .map(|pk| pk.to_string())
                    .unwrap_or_else(|| synthetic_leader_identity(slot))
            })
            .collect();
        return Ok(types::to_value(&leaders));
    }

    let leaders: Vec<String> = (0_u64..effective_limit)
        .map(|index| synthetic_leader_identity(start_slot.saturating_add(index)))
        .collect();
    Ok(types::to_value(&leaders))
}

fn build_signatures_for_address_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    let (address, before, until, limit, min_context_slot) =
        parse_signatures_for_address_params(request)?;
    let committed_slot = snapshot.slot_for_commitment(commitment);
    ensure_optional_min_context_slot(min_context_slot, committed_slot)?;
    let entry_count = limit.min(SIGNATURES_FOR_ADDRESS_RESPONSE_MAX_ROWS) as usize;

    // Try real data from bank access provider.
    if let Some(bank) = bank_access {
        let address_pubkey =
            parse_pubkey_from_base58(&address).ok_or(RpcMethodError::InvalidParams)?;

        let before_sig = before.as_deref().and_then(decode_signature_bytes);
        let until_sig = until.as_deref().and_then(decode_signature_bytes);

        let entries = bank.get_signatures_for_address(
            &address_pubkey,
            entry_count,
            before_sig.as_ref(),
            until_sig.as_ref(),
            commitment,
        );

        if !entries.is_empty() {
            let values: Vec<SignatureForAddress> = entries
                .into_iter()
                .map(|e| {
                    let err = e
                        .error
                        .as_ref()
                        .map(|msg| json!({"InstructionError": msg}))
                        .unwrap_or(serde_json::Value::Null);
                    SignatureForAddress {
                        signature: e.signature,
                        slot: e.slot,
                        err,
                        memo: serde_json::Value::Null,
                        block_time: e.block_time,
                        confirmation_status: confirmation_status_label(commitment).to_string(),
                    }
                })
                .collect();
            return Ok(types::to_value(&values));
        }
    }

    // Synthetic fallback.
    let start_slot = before
        .as_deref()
        .map(signature_anchor_slot)
        .map(|delta| committed_slot.saturating_sub(delta.saturating_add(1)))
        .unwrap_or(committed_slot);
    let until_slot = until
        .as_deref()
        .map(signature_anchor_slot)
        .map(|delta| committed_slot.saturating_sub(delta));

    let values = (0_u64..entry_count as u64)
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

fn decode_signature_bytes(sig_str: &str) -> Option<[u8; 64]> {
    let bytes = bs58::decode(sig_str).into_vec().ok()?;
    if bytes.len() != 64 {
        return None;
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&bytes);
    Some(sig)
}

fn parse_pubkey_from_base58(encoded: &str) -> Option<karstflow_types::Pubkey> {
    let bytes = bs58::decode(encoded.trim()).into_vec().ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Some(karstflow_types::Pubkey::from(key))
}

fn build_cluster_nodes_response(
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> serde_json::Value {
    if let Some(bank) = bank_access {
        let nodes = bank.get_cluster_nodes();
        if !nodes.is_empty() {
            let entries: Vec<ClusterNode> = nodes
                .into_iter()
                .map(|node| ClusterNode {
                    pubkey: node.pubkey,
                    gossip: node.gossip,
                    tpu: node.tpu,
                    rpc: node.rpc,
                    version: node.version,
                    feature_set: None,
                    shred_version: 0,
                })
                .collect();
            return types::to_value(&entries);
        }
    }

    // Synthetic fallback
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
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    let config = parse_vote_accounts_config(request)?;
    let slot = bank_access
        .map(|bank| bank.get_slot(commitment))
        .unwrap_or_else(|| snapshot.slot_for_commitment(commitment));
    ensure_optional_min_context_slot(config.min_context_slot, slot)?;

    if let Some(bank) = bank_access {
        // Scan vote program accounts for real vote state
        if let Ok(vote_program_id) = parse_vote_program_pubkey() {
            let vote_accounts = bank.get_accounts_by_owner(&vote_program_id, commitment);
            if !vote_accounts.is_empty() {
                let mut current = Vec::new();
                let delinquent: Vec<VoteAccountInfo> = Vec::new();
                for (vote_pubkey, account) in &vote_accounts {
                    let vote_pubkey_str = vote_pubkey.to_string();
                    if let Some(ref filter) = config.vote_pubkey {
                        if *filter != vote_pubkey_str {
                            continue;
                        }
                    }
                    let data = account.data.as_slice();
                    let (node_pubkey, last_vote, root_slot, commission) =
                        parse_vote_state_summary(data, slot);
                    current.push(VoteAccountInfo {
                        vote_pubkey: vote_pubkey_str,
                        node_pubkey,
                        activated_stake: account.meta.lamports,
                        epoch_vote_account: true,
                        commission,
                        last_vote,
                        root_slot,
                        epoch_credits: vec![(slot / SLOTS_PER_EPOCH, slot, 0)],
                    });
                }
                let response = VoteAccountsResponse {
                    current,
                    delinquent,
                };
                return Ok(types::to_value(&response));
            }
        }
    }

    // Synthetic fallback
    let activated_stake = snapshot
        .transaction_count
        .saturating_mul(1_000)
        .saturating_add(1_000_000);

    let current_vote_pubkey = "Vote111111111111111111111111111111111111111";
    let current_entry = VoteAccountInfo {
        vote_pubkey: current_vote_pubkey.to_string(),
        node_pubkey: "ParaDancer11111111111111111111111111111111".to_string(),
        activated_stake,
        epoch_vote_account: true,
        commission: DEFAULT_VOTE_COMMISSION_PERCENT,
        last_vote: slot,
        root_slot: slot.saturating_sub(VOTE_ROOT_SLOT_BACKTRACK),
        epoch_credits: vec![(slot / SLOTS_PER_EPOCH, slot, 0)],
    };
    let current_accounts = match config.vote_pubkey.as_deref() {
        Some(pubkey) if pubkey != current_vote_pubkey => Vec::new(),
        _ => vec![current_entry],
    };

    let delinquent = if config.keep_unstaked_delinquents {
        vec![VoteAccountInfo {
            vote_pubkey: "VoteDelinq11111111111111111111111111111111111".to_string(),
            node_pubkey: "ParaDancer33333333333333333333333333333333".to_string(),
            activated_stake: 0,
            epoch_vote_account: false,
            commission: DEFAULT_VOTE_COMMISSION_PERCENT,
            last_vote: slot.saturating_sub(config.delinquent_slot_distance),
            root_slot: slot.saturating_sub(
                config
                    .delinquent_slot_distance
                    .saturating_add(VOTE_ROOT_SLOT_BACKTRACK),
            ),
            epoch_credits: vec![(
                slot / SLOTS_PER_EPOCH,
                slot.saturating_sub(config.delinquent_slot_distance),
                0,
            )],
        }]
    } else {
        Vec::new()
    };

    let response = VoteAccountsResponse {
        current: current_accounts,
        delinquent,
    };
    Ok(types::to_value(&response))
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
        .map(params::optional_bool)
        .transpose()?
        .flatten()
        .unwrap_or(false);

    let delinquent_slot_distance = config_object
        .and_then(|cfg| cfg.get("delinquentSlotDistance"))
        .map(params::optional_u64)
        .transpose()?
        .flatten()
        .unwrap_or(128);

    let min_context_slot = config_object
        .and_then(|cfg| cfg.get("minContextSlot"))
        .map(params::optional_u64)
        .transpose()?
        .flatten();

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
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;
    let identity_filter = parse_identity_filter_from_params(request)?;
    let base_slot = bank_access
        .map(|bank| bank.get_slot(commitment))
        .unwrap_or_else(|| snapshot.slot_for_commitment(commitment));

    if let Some(bank) = bank_access {
        if let Some(schedule_entries) = bank.get_leader_schedule(base_slot, commitment) {
            let mut by_identity = serde_json::Map::new();
            for (validator, slots) in schedule_entries {
                let key = validator.to_string();
                if let Some(ref filter) = identity_filter {
                    if *filter != key {
                        continue;
                    }
                }
                by_identity.insert(key, types::to_value(&slots));
            }
            return Ok(serde_json::Value::Object(by_identity));
        }
    }

    // Synthetic fallback
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
            by_identity.insert(identity, types::to_value(&schedule));
        }
        None => {
            by_identity.insert(default_identity.to_string(), types::to_value(&schedule));
            by_identity.insert(
                fallback_identity.to_string(),
                types::to_value(&vec![
                    base_slot.saturating_add(slot_offset + 1),
                    base_slot.saturating_add(slot_offset + LEADER_SCHEDULE_ROTATION + 1),
                ]),
            );
        }
    }
    Ok(serde_json::Value::Object(by_identity))
}

fn build_block_production_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;
    let current_slot = bank_access
        .map(|bank| bank.get_slot(commitment))
        .unwrap_or_else(|| snapshot.slot_for_commitment(commitment));
    let (requested_first, requested_last) = parse_slot_range_from_params(request)?;
    let first_slot = requested_first.unwrap_or(current_slot.saturating_sub(31));
    let last_slot = requested_last.unwrap_or(current_slot);
    if last_slot < first_slot {
        return Err(RpcMethodError::InvalidParams);
    }

    let effective_last_slot = last_slot.min(current_slot);
    if effective_last_slot < first_slot {
        let value = BlockProductionValue {
            by_identity: types::to_value(&serde_json::Map::new()),
            range: BlockProductionRange {
                first_slot,
                last_slot: first_slot,
            },
        };
        let response = RpcResponse::new(current_slot, value);
        return Ok(types::to_value(&response));
    }

    // Use real leader schedule to count slot assignments per validator.
    if let Some(bank) = bank_access {
        let leaders = bank.get_slot_leaders(
            first_slot,
            effective_last_slot
                .saturating_sub(first_slot)
                .saturating_add(1),
            commitment,
        );
        let mut by_identity: std::collections::HashMap<String, [u64; 2]> =
            std::collections::HashMap::new();
        for (_slot, leader_opt) in &leaders {
            if let Some(leader) = leader_opt {
                let entry = by_identity.entry(leader.to_string()).or_insert([0, 0]);
                entry[0] += 1;
                entry[1] += 1;
            }
        }
        if !by_identity.is_empty() {
            let by_identity_json: serde_json::Map<String, serde_json::Value> = by_identity
                .into_iter()
                .map(|(k, v)| (k, types::to_value(&v)))
                .collect();
            let value = BlockProductionValue {
                by_identity: serde_json::Value::Object(by_identity_json),
                range: BlockProductionRange {
                    first_slot,
                    last_slot: effective_last_slot,
                },
            };
            let response = RpcResponse::new(current_slot, value);
            return Ok(types::to_value(&response));
        }
    }

    // Synthetic fallback
    let produced_count = effective_last_slot
        .saturating_sub(first_slot)
        .saturating_add(1);
    let identity = "ParaDancer11111111111111111111111111111111";
    let mut by_identity_map = serde_json::Map::new();
    by_identity_map.insert(
        identity.to_string(),
        types::to_value(&[produced_count, produced_count]),
    );
    let value = BlockProductionValue {
        by_identity: serde_json::Value::Object(by_identity_map),
        range: BlockProductionRange {
            first_slot,
            last_slot: effective_last_slot,
        },
    };
    let response = RpcResponse::new(current_slot, value);
    Ok(types::to_value(&response))
}

fn build_recent_prioritization_fees_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;

    // Try real data from bank access provider.
    if let Some(bank) = bank_access {
        let fees = bank.get_recent_prioritization_fees(commitment);
        if !fees.is_empty() {
            let rows: Vec<PrioritizationFee> = fees
                .into_iter()
                .map(|f| PrioritizationFee {
                    slot: f.slot,
                    prioritization_fee: f.prioritization_fee,
                })
                .collect();
            return Ok(types::to_value(&rows));
        }
    }

    // Synthetic fallback.
    let account_count = parse_optional_account_list_len(request)?;
    let current_slot = snapshot.slot_for_commitment(commitment);
    let base_fee = PRIORITIZATION_FEE_BASE
        .saturating_add(account_count as u64 * PRIORITIZATION_FEE_PER_ACCOUNT_STEP);

    let rows: Vec<PrioritizationFee> = (0_u64..PRIORITIZATION_FEE_ROWS)
        .map(|index| PrioritizationFee {
            slot: current_slot.saturating_sub(index),
            prioritization_fee: base_fee.saturating_add(index * PRIORITIZATION_FEE_PER_ROW_STEP),
        })
        .collect();
    Ok(types::to_value(&rows))
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
        .filter(|v| !v.is_null())
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
        .filter(|v| !v.is_null())
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
        .map(params::optional_u64)
        .transpose()?
        .flatten()
        .unwrap_or(SIGNATURES_FOR_ADDRESS_DEFAULT_LIMIT)
        .clamp(1, SIGNATURES_FOR_ADDRESS_MAX_LIMIT);
    let min_context_slot = config_object
        .and_then(|cfg| cfg.get("minContextSlot"))
        .map(params::optional_u64)
        .transpose()?
        .flatten();
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
        .map(params::optional_u64)
        .transpose()?
        .flatten();
    let last_slot = range
        .and_then(|range| range.get("lastSlot"))
        .map(params::optional_u64)
        .transpose()?
        .flatten();
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

fn parse_vote_program_pubkey() -> Result<karstflow_types::Pubkey, ()> {
    let bytes = bs58::decode("Vote111111111111111111111111111111111111111")
        .into_vec()
        .map_err(|_| ())?;
    let array: [u8; 32] = bytes.try_into().map_err(|_| ())?;
    Ok(karstflow_types::Pubkey::new(array))
}

/// Extract a summary of vote state from raw account data.
///
/// Serialization layout:
/// - bytes 0..32: node pubkey (32 bytes)
/// - bytes 32..64: authorized voter pubkey (32 bytes)
/// - bytes 64..96: authorized withdrawer pubkey (32 bytes)
/// - byte 96: commission (u8)
/// - bytes 97..101: vote count (u32 LE)
/// - then vote_count entries of 12 bytes each (slot u64 LE + confirmation_count u32 LE)
/// - after votes: root option (1 byte: 0=None, 1=Some) + root slot (u64 LE if present)
///
/// Returns (node_pubkey_string, last_vote_slot, root_slot, commission).
fn parse_vote_state_summary(data: &[u8], current_slot: u64) -> (String, u64, u64, u8) {
    // Minimum size: 32 (node) + 32 (voter) + 32 (withdrawer) + 1 (commission) + 4 (vote_count) = 101
    if data.len() < 101 {
        return (
            "11111111111111111111111111111111".to_string(),
            current_slot,
            current_slot.saturating_sub(VOTE_ROOT_SLOT_BACKTRACK),
            DEFAULT_VOTE_COMMISSION_PERCENT,
        );
    }

    let node_pubkey = bs58::encode(&data[0..32]).into_string();
    let commission = data[96];

    // Parse vote count
    let vote_count = u32::from_le_bytes([data[97], data[98], data[99], data[100]]) as usize;

    // Extract last vote slot from the vote history
    let votes_start = 101;
    let vote_entry_size = 12; // u64 slot + u32 confirmation_count
    let last_vote = if vote_count > 0 {
        let last_vote_offset = votes_start + (vote_count - 1) * vote_entry_size;
        if last_vote_offset + 8 <= data.len() {
            let mut slot_bytes = [0u8; 8];
            slot_bytes.copy_from_slice(&data[last_vote_offset..last_vote_offset + 8]);
            u64::from_le_bytes(slot_bytes)
        } else {
            current_slot
        }
    } else {
        0
    };

    // Extract root slot after the votes section
    let root_offset = votes_start + vote_count * vote_entry_size;
    let root_slot = if root_offset < data.len() && data[root_offset] == 1 {
        let root_value_offset = root_offset + 1;
        if root_value_offset + 8 <= data.len() {
            let mut root_bytes = [0u8; 8];
            root_bytes.copy_from_slice(&data[root_value_offset..root_value_offset + 8]);
            u64::from_le_bytes(root_bytes)
        } else {
            current_slot.saturating_sub(VOTE_ROOT_SLOT_BACKTRACK)
        }
    } else {
        // No root or data too short — use 0 when no root is set
        0
    };

    (node_pubkey, last_vote, root_slot, commission)
}
