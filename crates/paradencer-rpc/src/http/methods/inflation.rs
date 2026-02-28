use std::sync::Arc;

use paradencer_constants::economics::{
    DEFAULT_VOTE_COMMISSION_PERCENT, INFLATION_EPOCH_DECAY_STEP, INFLATION_FOUNDATION_RATE,
    INFLATION_FOUNDATION_TERM, INFLATION_INITIAL_RATE, INFLATION_REWARD_BASE_AMOUNT,
    INFLATION_REWARD_MODULUS, INFLATION_TAPER_RATE, INFLATION_TERMINAL_RATE,
    INFLATION_TOTAL_BASE_RATE,
};
use paradencer_constants::ledger::SLOTS_PER_EPOCH;

use crate::state::{BankAccessProvider, RpcCommitment, RpcRuntimeSnapshot};

use super::super::method_error::RpcMethodError;
use super::super::registry::RpcMethod;
use super::params;
use super::types::{self, InflationGovernor, InflationRate, InflationReward};

pub(super) fn handle(
    method: RpcMethod,
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    match method {
        RpcMethod::GetInflationGovernor => Ok(build_inflation_governor_response()),
        RpcMethod::GetInflationRate => Ok(build_inflation_rate_response(
            snapshot,
            commitment,
            bank_access,
        )),
        RpcMethod::GetInflationReward => {
            build_inflation_reward_response(request, snapshot, commitment, bank_access)
        }
        _ => Err(RpcMethodError::MethodNotFound),
    }
}

fn build_inflation_governor_response() -> serde_json::Value {
    let response = InflationGovernor {
        foundation: INFLATION_FOUNDATION_RATE,
        foundation_term: INFLATION_FOUNDATION_TERM,
        initial: INFLATION_INITIAL_RATE,
        taper: INFLATION_TAPER_RATE,
        terminal: INFLATION_TERMINAL_RATE,
    };
    types::to_value(&response)
}

fn build_inflation_rate_response(
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> serde_json::Value {
    let slot = bank_access
        .map(|bank| bank.get_slot(commitment))
        .unwrap_or_else(|| snapshot.slot_for_commitment(commitment));
    let epoch = bank_access
        .map(|bank| bank.get_epoch_for_slot(slot))
        .unwrap_or_else(|| slot / SLOTS_PER_EPOCH);

    // Try real inflation from bank's configured parameters.
    if let Some(bank) = bank_access {
        if let Some((total, validator, foundation)) = bank.get_inflation_rate(epoch) {
            let response = InflationRate {
                total,
                validator,
                foundation,
                epoch,
            };
            return types::to_value(&response);
        }
    }

    // Synthetic fallback.
    let total = INFLATION_TOTAL_BASE_RATE
        .max(0.02_f64 - (epoch as f64 * INFLATION_EPOCH_DECAY_STEP))
        .max(INFLATION_TERMINAL_RATE);
    let response = InflationRate {
        total,
        validator: total * 0.9_f64,
        foundation: total * 0.1_f64,
        epoch,
    };
    types::to_value(&response)
}

fn build_inflation_reward_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    let addresses = parse_pubkey_list_param(request)?;
    let slot = bank_access
        .map(|bank| bank.get_slot(commitment))
        .unwrap_or_else(|| snapshot.slot_for_commitment(commitment));
    let epoch = bank_access
        .map(|bank| bank.get_epoch_for_slot(slot))
        .unwrap_or_else(|| slot / SLOTS_PER_EPOCH);

    // Synthetic rewards — real epoch reward tracking is a future enhancement.
    let rewards: Vec<InflationReward> = addresses
        .iter()
        .map(|address| {
            let checksum = address
                .bytes()
                .fold(0_u64, |sum, byte| sum.wrapping_add(u64::from(byte)));
            let amount =
                (checksum % INFLATION_REWARD_MODULUS) as i64 + INFLATION_REWARD_BASE_AMOUNT;
            InflationReward {
                epoch,
                effective_slot: slot,
                amount,
                post_balance: snapshot.transaction_count.saturating_add(checksum),
                commission: DEFAULT_VOTE_COMMISSION_PERCENT,
            }
        })
        .collect();
    Ok(types::to_value(&rewards))
}

fn parse_pubkey_list_param(request: &serde_json::Value) -> Result<Vec<String>, RpcMethodError> {
    params::first_param_non_empty_string_array(request)
}
