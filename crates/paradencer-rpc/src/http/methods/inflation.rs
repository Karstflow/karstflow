use serde_json::json;

use paradencer_constants::economics::{
    DEFAULT_VOTE_COMMISSION_PERCENT, INFLATION_EPOCH_DECAY_STEP, INFLATION_FOUNDATION_RATE,
    INFLATION_FOUNDATION_TERM, INFLATION_INITIAL_RATE, INFLATION_REWARD_BASE_AMOUNT,
    INFLATION_REWARD_MODULUS, INFLATION_TAPER_RATE, INFLATION_TERMINAL_RATE,
    INFLATION_TOTAL_BASE_RATE,
};
use paradencer_constants::ledger::SLOTS_PER_EPOCH;

use crate::state::{RpcCommitment, RpcRuntimeSnapshot};

use super::super::method_error::RpcMethodError;
use super::super::registry::RpcMethod;
use super::params;

pub(super) fn handle(
    method: RpcMethod,
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> Result<serde_json::Value, RpcMethodError> {
    match method {
        RpcMethod::GetInflationGovernor => Ok(build_inflation_governor_response()),
        RpcMethod::GetInflationRate => Ok(build_inflation_rate_response(snapshot, commitment)),
        RpcMethod::GetInflationReward => {
            build_inflation_reward_response(request, snapshot, commitment)
        }
        _ => Err(RpcMethodError::MethodNotFound),
    }
}

fn build_inflation_governor_response() -> serde_json::Value {
    json!({
        "foundation": INFLATION_FOUNDATION_RATE,
        "foundationTerm": INFLATION_FOUNDATION_TERM,
        "initial": INFLATION_INITIAL_RATE,
        "taper": INFLATION_TAPER_RATE,
        "terminal": INFLATION_TERMINAL_RATE
    })
}

fn build_inflation_rate_response(
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> serde_json::Value {
    let slot = snapshot.slot_for_commitment(commitment);
    let epoch = slot / SLOTS_PER_EPOCH;
    let total = INFLATION_TOTAL_BASE_RATE
        .max(0.02_f64 - (epoch as f64 * INFLATION_EPOCH_DECAY_STEP))
        .max(INFLATION_TERMINAL_RATE);
    json!({
        "total": total,
        "validator": total * 0.9_f64,
        "foundation": total * 0.1_f64,
        "epoch": epoch
    })
}

fn build_inflation_reward_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> Result<serde_json::Value, RpcMethodError> {
    let addresses = parse_pubkey_list_param(request)?;
    let slot = snapshot.slot_for_commitment(commitment);
    let epoch = slot / SLOTS_PER_EPOCH;
    let rewards = addresses
        .iter()
        .map(|address| {
            let checksum = address
                .bytes()
                .fold(0_u64, |sum, byte| sum.wrapping_add(u64::from(byte)));
            let amount =
                (checksum % INFLATION_REWARD_MODULUS) as i64 + INFLATION_REWARD_BASE_AMOUNT;
            json!({
                "epoch": epoch,
                "effectiveSlot": slot,
                "amount": amount,
                "postBalance": snapshot.transaction_count.saturating_add(checksum),
                "commission": DEFAULT_VOTE_COMMISSION_PERCENT
            })
        })
        .collect::<Vec<_>>();
    Ok(json!(rewards))
}

fn parse_pubkey_list_param(request: &serde_json::Value) -> Result<Vec<String>, RpcMethodError> {
    params::first_param_non_empty_string_array(request)
}
