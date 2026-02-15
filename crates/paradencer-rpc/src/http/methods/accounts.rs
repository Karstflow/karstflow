use serde_json::json;

use crate::state::{RpcCommitment, RpcRuntimeSnapshot};
use paradencer_constants::economics::{BASE_NETWORK_SUPPLY_LAMPORTS, TOKEN_UI_DECIMALS_DIVISOR};
use paradencer_constants::rpc::{DEFAULT_TOKEN_ACCOUNT_SPACE, MAX_SIGNATURE_CONFIRMATIONS};

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
        RpcMethod::GetBalance => build_balance_response(request, snapshot, commitment),
        RpcMethod::GetSupply => build_supply_response(request, snapshot, commitment),
        RpcMethod::GetTokenSupply => build_token_supply_response(request, snapshot, commitment),
        RpcMethod::GetTokenAccountBalance => {
            build_token_account_balance_response(request, snapshot, commitment)
        }
        RpcMethod::GetLargestAccounts => {
            build_largest_accounts_response(request, snapshot, commitment)
        }
        RpcMethod::GetTokenLargestAccounts => {
            build_token_largest_accounts_response(request, snapshot, commitment)
        }
        RpcMethod::GetProgramAccounts => {
            build_program_accounts_response(request, snapshot, commitment)
        }
        RpcMethod::GetTokenAccountsByOwner => {
            build_token_accounts_by_owner_response(request, snapshot, commitment)
        }
        RpcMethod::GetTokenAccountsByDelegate => {
            build_token_accounts_by_delegate_response(request, snapshot, commitment)
        }
        RpcMethod::GetAccountInfo => build_account_info_response(request, snapshot, commitment),
        RpcMethod::GetMultipleAccounts => {
            build_multiple_accounts_response(request, snapshot, commitment)
        }
        RpcMethod::GetSignatureStatuses => {
            build_signature_statuses_response(request, snapshot, commitment)
        }
        _ => Err(RpcMethodError::MethodNotFound),
    }
}

fn build_supply_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;
    let exclude_non_circulating = parse_supply_exclude_non_circulating_flag(request)?;
    let slot = snapshot.slot_for_commitment(commitment);
    let total = snapshot
        .transaction_count
        .saturating_mul(10)
        .saturating_add(BASE_NETWORK_SUPPLY_LAMPORTS);
    let non_circulating = total / 20;
    let non_circulating_accounts = if exclude_non_circulating {
        Vec::new()
    } else {
        vec!["ParaDancerReserve11111111111111111111111111111"]
    };
    Ok(json!({
        "context": {"slot": slot},
        "value": {
            "total": total,
            "circulating": total.saturating_sub(non_circulating),
            "nonCirculating": non_circulating,
            "nonCirculatingAccounts": non_circulating_accounts
        }
    }))
}

fn build_token_supply_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;
    let mint = parse_mint_param(request)?;
    let amount = synthetic_token_amount(&mint, snapshot.transaction_count);
    let slot = snapshot.slot_for_commitment(commitment);
    Ok(json!({
        "context": {"slot": slot},
        "value": token_amount_payload(amount)
    }))
}

fn build_token_account_balance_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;
    let token_account = params::first_param_non_empty_string(request)?;
    let amount = synthetic_token_amount(&token_account, snapshot.transaction_count / 2);
    let slot = snapshot.slot_for_commitment(commitment);
    Ok(json!({
        "context": {"slot": slot},
        "value": token_amount_payload(amount)
    }))
}

fn build_largest_accounts_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;
    let _ = parse_largest_accounts_filter(request)?;
    let slot = snapshot.slot_for_commitment(commitment);
    let base = snapshot.transaction_count.saturating_add(100_000);
    let accounts = (0_u64..5)
        .map(|index| {
            json!({
                "address": format!("ParaLargest{:02}111111111111111111111111111111111", index),
                "lamports": base.saturating_sub(index * 1_000)
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "context": {"slot": slot},
        "value": accounts
    }))
}

fn build_token_largest_accounts_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;
    let mint = parse_mint_param(request)?;
    let slot = snapshot.slot_for_commitment(commitment);
    let base = snapshot.transaction_count.saturating_add(50_000);
    let accounts = (0_u64..5)
        .map(|index| {
            json!({
                "address": format!("ParaToken{:02}11111111111111111111111111111111", index),
                "amount": base.saturating_sub(index * 500).to_string(),
                "decimals": 9,
                "uiAmount": (base.saturating_sub(index * 500)) as f64 / TOKEN_UI_DECIMALS_DIVISOR,
                "uiAmountString": format!("0.{:09}", base.saturating_sub(index * 500))
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "context": {"slot": slot},
        "value": accounts,
        "mint": mint
    }))
}

fn build_program_accounts_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> Result<serde_json::Value, RpcMethodError> {
    let (program_id, with_context, min_context_slot) = parse_program_accounts_request(request)?;
    ensure_optional_min_context_slot(min_context_slot, snapshot, commitment)?;
    let slot = snapshot.slot_for_commitment(commitment);
    let accounts = (0_u64..2)
        .map(|index| {
            json!({
                "pubkey": format!("ParaProgAcct{index:02}111111111111111111111111111111"),
                "account": {
                    "lamports": snapshot.transaction_count.saturating_add(10_000 + index),
                    "owner": program_id,
                    "executable": false,
                    "rentEpoch": 0,
                    "data": ["", "base64"],
                    "space": 0
                }
            })
        })
        .collect::<Vec<_>>();

    if with_context {
        Ok(json!({
            "context": {"slot": slot},
            "value": accounts
        }))
    } else {
        Ok(json!(accounts))
    }
}

fn build_token_accounts_by_owner_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> Result<serde_json::Value, RpcMethodError> {
    let (owner, selector, min_context_slot) = parse_token_accounts_query(request)?;
    ensure_optional_min_context_slot(min_context_slot, snapshot, commitment)?;
    let slot = snapshot.slot_for_commitment(commitment);
    let value = (0_u64..2)
        .map(|index| {
            json!({
                "pubkey": format!("ParaOwnerAcct{index:02}111111111111111111111111111111"),
                "account": {
                    "lamports": snapshot.transaction_count.saturating_add(20_000 + index),
                    "owner": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                    "executable": false,
                    "rentEpoch": 0,
                    "data": ["", "base64"],
                    "space": DEFAULT_TOKEN_ACCOUNT_SPACE
                },
                "tokenOwner": owner,
                "selector": selector
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "context": {"slot": slot},
        "value": value
    }))
}

fn build_token_accounts_by_delegate_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> Result<serde_json::Value, RpcMethodError> {
    let (delegate, selector, min_context_slot) = parse_token_accounts_query(request)?;
    ensure_optional_min_context_slot(min_context_slot, snapshot, commitment)?;
    let slot = snapshot.slot_for_commitment(commitment);
    let value = (0_u64..2)
        .map(|index| {
            json!({
                "pubkey": format!("ParaDelegAcct{index:02}111111111111111111111111111111"),
                "account": {
                    "lamports": snapshot.transaction_count.saturating_add(30_000 + index),
                    "owner": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                    "executable": false,
                    "rentEpoch": 0,
                    "data": ["", "base64"],
                    "space": DEFAULT_TOKEN_ACCOUNT_SPACE
                },
                "delegate": delegate,
                "selector": selector
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "context": {"slot": slot},
        "value": value
    }))
}

fn build_account_info_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;
    let pubkey = params::first_param_non_empty_string(request)?;

    let synthetic_lamports = synthetic_lamports_from_pubkey(&pubkey, snapshot.transaction_count);
    Ok(json!({
        "context": {"slot": snapshot.slot_for_commitment(commitment)},
        "value": {
            "lamports": synthetic_lamports,
            "owner": "11111111111111111111111111111111",
            "executable": false,
            "rentEpoch": 0,
            "data": ["", "base64"],
            "space": 0
        }
    }))
}

fn build_multiple_accounts_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;
    let pubkeys = params::first_param_non_empty_string_array(request)?;
    let accounts = pubkeys
        .iter()
        .map(|pubkey| {
            let lamports = synthetic_lamports_from_pubkey(pubkey, snapshot.transaction_count);
            json!({
                "lamports": lamports,
                "owner": "11111111111111111111111111111111",
                "executable": false,
                "rentEpoch": 0,
                "data": ["", "base64"],
                "space": 0
            })
        })
        .collect::<Vec<_>>();

    Ok(json!({
        "context": {"slot": snapshot.slot_for_commitment(commitment)},
        "value": accounts
    }))
}

fn build_balance_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;
    let pubkey = params::first_param_non_empty_string(request)?;

    let lamports = synthetic_lamports_from_pubkey(&pubkey, snapshot.transaction_count);
    Ok(json!({
        "context": {"slot": snapshot.slot_for_commitment(commitment)},
        "value": lamports
    }))
}

fn build_signature_statuses_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> Result<serde_json::Value, RpcMethodError> {
    let config = parse_signature_statuses_config(request)?;
    ensure_optional_min_context_slot(config.min_context_slot, snapshot, commitment)?;
    let signatures = params::first_param_non_empty_string_array(request)?;
    let statuses = signatures
        .iter()
        .map(|signature| {
            let checksum = signature.bytes().fold(0_u64, |accumulator, byte| {
                accumulator.wrapping_add(u64::from(byte))
            });

            if !config.search_transaction_history && checksum % 5 == 0 {
                return serde_json::Value::Null;
            }

            let confirmations = checksum % MAX_SIGNATURE_CONFIRMATIONS;
            json!({
                "slot": snapshot.slot_for_commitment(commitment).saturating_sub(confirmations),
                "confirmations": confirmations,
                "err": serde_json::Value::Null,
                "confirmationStatus": confirmation_status_label(commitment)
            })
        })
        .collect::<Vec<_>>();

    Ok(json!({
        "context": {"slot": snapshot.slot_for_commitment(commitment)},
        "value": statuses
    }))
}

#[derive(Clone, Copy)]
struct SignatureStatusesConfig {
    search_transaction_history: bool,
    min_context_slot: Option<u64>,
}

fn synthetic_lamports_from_pubkey(pubkey: &str, transaction_count: u64) -> u64 {
    let checksum = pubkey.as_bytes().iter().fold(0_u64, |accumulator, byte| {
        accumulator.wrapping_add(u64::from(*byte))
    });
    checksum.saturating_add(transaction_count)
}

fn synthetic_token_amount(key: &str, seed: u64) -> u64 {
    key.as_bytes()
        .iter()
        .fold(seed.saturating_add(1_000_000), |accumulator, byte| {
            accumulator.wrapping_add(u64::from(*byte))
        })
}

fn token_amount_payload(amount: u64) -> serde_json::Value {
    json!({
        "amount": amount.to_string(),
        "decimals": 9_u8,
        "uiAmount": amount as f64 / TOKEN_UI_DECIMALS_DIVISOR,
        "uiAmountString": format!("0.{amount:09}")
    })
}

fn parse_program_accounts_request(
    request: &serde_json::Value,
) -> Result<(String, bool, Option<u64>), RpcMethodError> {
    let params = params::params_array(request)?;
    let program_id = params::first_param_non_empty_string(request)?;

    let config_object = params.get(1).and_then(serde_json::Value::as_object);
    if let Some(filters) = config_object
        .and_then(|cfg| cfg.get("filters"))
        .and_then(serde_json::Value::as_array)
    {
        for filter in filters {
            let object = filter.as_object().ok_or(RpcMethodError::InvalidParams)?;
            if let Some(data_size) = object.get("dataSize") {
                if data_size.as_u64().is_none() {
                    return Err(RpcMethodError::InvalidParams);
                }
            } else if let Some(memcmp) = object.get("memcmp") {
                let memcmp_obj = memcmp.as_object().ok_or(RpcMethodError::InvalidParams)?;
                let _offset = memcmp_obj
                    .get("offset")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or(RpcMethodError::InvalidParams)?;
                let _bytes = memcmp_obj
                    .get("bytes")
                    .and_then(serde_json::Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .ok_or(RpcMethodError::InvalidParams)?;
            } else {
                return Err(RpcMethodError::InvalidParams);
            }
        }
    }

    let with_context = config_object
        .and_then(|cfg| cfg.get("withContext"))
        .map(|value| value.as_bool().ok_or(RpcMethodError::InvalidParams))
        .transpose()?
        .unwrap_or(false);
    let min_context_slot = config_object
        .and_then(|cfg| cfg.get("minContextSlot"))
        .map(|value| value.as_u64().ok_or(RpcMethodError::InvalidParams))
        .transpose()?;
    Ok((program_id, with_context, min_context_slot))
}

fn parse_token_accounts_query(
    request: &serde_json::Value,
) -> Result<(String, String, Option<u64>), RpcMethodError> {
    let params = params::params_array(request)?;
    let account_key = params::first_param_non_empty_string(request)?;

    let selector_object = params
        .get(1)
        .and_then(serde_json::Value::as_object)
        .ok_or(RpcMethodError::InvalidParams)?;
    let selector = if let Some(mint) = selector_object.get("mint") {
        let mint = mint
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or(RpcMethodError::InvalidParams)?;
        format!("mint:{mint}")
    } else if let Some(program_id) = selector_object.get("programId") {
        let program_id = program_id
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or(RpcMethodError::InvalidParams)?;
        format!("programId:{program_id}")
    } else {
        return Err(RpcMethodError::InvalidParams);
    };

    let config_object = params.get(2).and_then(serde_json::Value::as_object);
    let min_context_slot = config_object
        .and_then(|cfg| cfg.get("minContextSlot"))
        .map(|value| value.as_u64().ok_or(RpcMethodError::InvalidParams))
        .transpose()?;
    Ok((account_key, selector, min_context_slot))
}

fn ensure_min_context_slot_satisfied(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> Result<(), RpcMethodError> {
    let min_context_slot = params::min_context_slot_from_params(request)?;
    ensure_optional_min_context_slot(min_context_slot, snapshot, commitment)
}

fn ensure_optional_min_context_slot(
    min_context_slot: Option<u64>,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> Result<(), RpcMethodError> {
    if let Some(min_context_slot) = min_context_slot {
        let committed_slot = snapshot.slot_for_commitment(commitment);
        if min_context_slot > committed_slot {
            return Err(RpcMethodError::MinimumContextSlotNotReached);
        }
    }
    Ok(())
}

fn parse_largest_accounts_filter(
    request: &serde_json::Value,
) -> Result<Option<String>, RpcMethodError> {
    let params = params::params_array_or_empty(request);
    let config_object = params::first_config_object(params);
    let filter = config_object
        .and_then(|cfg| cfg.get("filter"))
        .map(|value| {
            value
                .as_str()
                .map(str::trim)
                .filter(|filter| !filter.is_empty())
                .map(str::to_string)
                .ok_or(RpcMethodError::InvalidParams)
        })
        .transpose()?;
    Ok(filter)
}

fn parse_mint_param(request: &serde_json::Value) -> Result<String, RpcMethodError> {
    params::first_param_non_empty_string(request)
}

fn confirmation_status_label(commitment: RpcCommitment) -> &'static str {
    match commitment {
        RpcCommitment::Processed => "processed",
        RpcCommitment::Confirmed => "confirmed",
        RpcCommitment::Finalized => "finalized",
    }
}

fn parse_supply_exclude_non_circulating_flag(
    request: &serde_json::Value,
) -> Result<bool, RpcMethodError> {
    let params = params::params_array_or_empty(request);
    let config_object = params::first_config_object(params);
    let exclude_non_circulating_accounts = config_object
        .and_then(|cfg| cfg.get("excludeNonCirculatingAccountsList"))
        .map(|value| value.as_bool().ok_or(RpcMethodError::InvalidParams))
        .transpose()?
        .unwrap_or(false);
    Ok(exclude_non_circulating_accounts)
}

fn parse_signature_statuses_config(
    request: &serde_json::Value,
) -> Result<SignatureStatusesConfig, RpcMethodError> {
    let params = params::params_array_or_empty(request);
    let config_object = params.get(1).and_then(serde_json::Value::as_object);

    let search_transaction_history = config_object
        .and_then(|cfg| cfg.get("searchTransactionHistory"))
        .map(|value| value.as_bool().ok_or(RpcMethodError::InvalidParams))
        .transpose()?
        .unwrap_or(false);
    let min_context_slot = config_object
        .and_then(|cfg| cfg.get("minContextSlot"))
        .map(|value| value.as_u64().ok_or(RpcMethodError::InvalidParams))
        .transpose()?;

    Ok(SignatureStatusesConfig {
        search_transaction_history,
        min_context_slot,
    })
}
