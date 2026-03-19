use serde_json::json;
use std::sync::Arc;

use crate::state::{BankAccessProvider, RpcCommitment, RpcRuntimeSnapshot};
use karstflow_constants::economics::{BASE_NETWORK_SUPPLY_LAMPORTS, TOKEN_UI_DECIMALS_DIVISOR};
use karstflow_constants::rpc::{
    DEFAULT_TOKEN_ACCOUNT_SPACE, MAX_SIGNATURE_CONFIRMATIONS, SPL_MINT_DECIMALS_OFFSET,
    SPL_MINT_MIN_LEN, SPL_MINT_SUPPLY_OFFSET, SPL_TOKEN_ACCOUNT_AMOUNT_OFFSET,
    SPL_TOKEN_ACCOUNT_MINT_OFFSET, SPL_TOKEN_ACCOUNT_MIN_LEN,
};

use super::super::method_error::RpcMethodError;
use super::super::registry::RpcMethod;
use super::params;
use super::types::{
    self, AccountData, AccountValue, LargestAccount, ProgramAccount, RpcResponse, SignatureStatus,
    SupplyValue, TokenAmount, TokenLargestAccount,
};

pub(super) fn handle(
    method: RpcMethod,
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    match method {
        RpcMethod::GetBalance => build_balance_response(request, snapshot, commitment, bank_access),
        RpcMethod::GetSupply => build_supply_response(request, snapshot, commitment, bank_access),
        RpcMethod::GetTokenSupply => {
            build_token_supply_response(request, snapshot, commitment, bank_access)
        }
        RpcMethod::GetTokenAccountBalance => {
            build_token_account_balance_response(request, snapshot, commitment, bank_access)
        }
        RpcMethod::GetLargestAccounts => {
            build_largest_accounts_response(request, snapshot, commitment, bank_access)
        }
        RpcMethod::GetTokenLargestAccounts => {
            build_token_largest_accounts_response(request, snapshot, commitment, bank_access)
        }
        RpcMethod::GetProgramAccounts => {
            build_program_accounts_response(request, snapshot, commitment, bank_access)
        }
        RpcMethod::GetTokenAccountsByOwner => {
            build_token_accounts_by_owner_response(request, snapshot, commitment, bank_access)
        }
        RpcMethod::GetTokenAccountsByDelegate => {
            build_token_accounts_by_delegate_response(request, snapshot, commitment, bank_access)
        }
        RpcMethod::GetAccountInfo => {
            build_account_info_response(request, snapshot, commitment, bank_access)
        }
        RpcMethod::GetMultipleAccounts => {
            build_multiple_accounts_response(request, snapshot, commitment, bank_access)
        }
        RpcMethod::GetSignatureStatuses => {
            build_signature_statuses_response(request, snapshot, commitment, bank_access)
        }
        _ => Err(RpcMethodError::MethodNotFound),
    }
}

fn build_supply_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;
    let exclude_non_circulating = parse_supply_exclude_non_circulating_flag(request)?;
    let slot = resolve_slot(snapshot, commitment, bank_access);

    let total = if let Some(bank) = bank_access {
        bank.get_capitalization(commitment)
    } else {
        snapshot
            .transaction_count
            .saturating_mul(10)
            .saturating_add(BASE_NETWORK_SUPPLY_LAMPORTS)
    };

    let non_circulating = bank_access
        .map(|bank| bank.get_non_circulating_supply(commitment))
        .unwrap_or_else(|| total / 20);
    let _ = exclude_non_circulating;
    let value = SupplyValue {
        total,
        circulating: total.saturating_sub(non_circulating),
        non_circulating,
        non_circulating_accounts: Vec::new(),
    };
    let response = RpcResponse::new(slot, value);
    Ok(types::to_value(&response))
}

fn build_token_supply_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;
    let mint_str = parse_mint_param(request)?;
    let slot = resolve_slot(snapshot, commitment, bank_access);

    if let Some(bank) = bank_access {
        let pubkey = parse_pubkey(&mint_str)?;
        if let Some(account) = bank.get_account(&pubkey, commitment) {
            if let Some((supply, decimals)) = parse_spl_mint_supply(account.data.as_slice()) {
                let value = token_amount_with_decimals(supply, decimals);
                let response = RpcResponse::new(slot, value);
                return Ok(types::to_value(&response));
            }
        }
        let value = token_amount(0);
        let response = RpcResponse::new(slot, value);
        Ok(types::to_value(&response))
    } else {
        let amount = synthetic_token_amount(&mint_str, snapshot.transaction_count);
        let value = token_amount(amount);
        let response = RpcResponse::new(slot, value);
        Ok(types::to_value(&response))
    }
}

fn build_token_account_balance_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;
    let token_account_str = params::first_param_non_empty_string(request)?;
    let slot = resolve_slot(snapshot, commitment, bank_access);

    if let Some(bank) = bank_access {
        let pubkey = parse_pubkey(&token_account_str)?;
        if let Some(account) = bank.get_account(&pubkey, commitment) {
            let data = account.data.as_slice();
            if let Some(amount) = parse_spl_token_account_amount(data) {
                // Look up the mint account to get decimals
                let decimals = parse_spl_token_account_mint(data)
                    .and_then(|mint_pk| bank.get_account(&mint_pk, commitment))
                    .and_then(|mint_acct| parse_spl_mint_supply(mint_acct.data.as_slice()))
                    .map(|(_, d)| d)
                    .unwrap_or(0);
                let value = token_amount_with_decimals(amount, decimals);
                let response = RpcResponse::new(slot, value);
                return Ok(types::to_value(&response));
            }
        }
        let value = token_amount(0);
        let response = RpcResponse::new(slot, value);
        Ok(types::to_value(&response))
    } else {
        let amount = synthetic_token_amount(&token_account_str, snapshot.transaction_count / 2);
        let value = token_amount(amount);
        let response = RpcResponse::new(slot, value);
        Ok(types::to_value(&response))
    }
}

fn build_largest_accounts_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;
    let _ = parse_largest_accounts_filter(request)?;
    let slot = resolve_slot(snapshot, commitment, bank_access);

    // Try real account data.
    if let Some(bank) = bank_access {
        let largest = bank.get_largest_accounts(20, commitment);
        if !largest.is_empty() {
            let accounts: Vec<LargestAccount> = largest
                .into_iter()
                .map(|(pubkey, lamports)| LargestAccount {
                    address: pubkey.to_string(),
                    lamports,
                })
                .collect();
            let response = RpcResponse::new(slot, accounts);
            return Ok(types::to_value(&response));
        }
    }

    // Synthetic fallback.
    let base = snapshot.transaction_count.saturating_add(100_000);
    let accounts: Vec<LargestAccount> = (0_u64..5)
        .map(|index| LargestAccount {
            address: format!("ParaLargest{:02}111111111111111111111111111111111", index),
            lamports: base.saturating_sub(index * 1_000),
        })
        .collect();
    let response = RpcResponse::new(slot, accounts);
    Ok(types::to_value(&response))
}

fn build_token_largest_accounts_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;
    let mint = parse_mint_param(request)?;
    let slot = resolve_slot(snapshot, commitment, bank_access);

    // Try real token account data.
    if let Some(bank) = bank_access {
        let mint_pubkey = parse_pubkey(&mint)?;
        let token_program = parse_pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?;
        let all_token_accounts = bank.get_accounts_by_owner(&token_program, commitment);

        // Filter by mint (bytes 0..32) and extract amounts (bytes 64..72).
        let mut matching: Vec<(String, u64)> = all_token_accounts
            .into_iter()
            .filter(|(_, account)| {
                let data = account.data.as_slice();
                data.len() >= SPL_TOKEN_ACCOUNT_MIN_LEN && data[..32] == *mint_pubkey.as_bytes()
            })
            .map(|(pubkey, account)| {
                let data = account.data.as_slice();
                let amount = u64::from_le_bytes(
                    data[SPL_TOKEN_ACCOUNT_AMOUNT_OFFSET..SPL_TOKEN_ACCOUNT_AMOUNT_OFFSET + 8]
                        .try_into()
                        .unwrap_or([0u8; 8]),
                );
                (pubkey.to_string(), amount)
            })
            .collect();

        if !matching.is_empty() {
            matching.sort_by(|a, b| b.1.cmp(&a.1));
            matching.truncate(20);

            // Read decimals from mint account.
            let decimals = bank
                .get_account(&mint_pubkey, commitment)
                .and_then(|acct| {
                    let data = acct.data.as_slice();
                    if data.len() >= SPL_MINT_MIN_LEN {
                        Some(data[SPL_MINT_DECIMALS_OFFSET])
                    } else {
                        None
                    }
                })
                .unwrap_or(9);
            let divisor = 10_f64.powi(decimals as i32);

            let accounts: Vec<TokenLargestAccount> = matching
                .into_iter()
                .map(|(address, amount)| TokenLargestAccount {
                    address,
                    amount: amount.to_string(),
                    decimals,
                    ui_amount: amount as f64 / divisor,
                    ui_amount_string: format_token_ui_amount(amount, decimals),
                })
                .collect();
            let response = RpcResponse::new(slot, accounts);
            return Ok(types::to_value(&response));
        }
    }

    // Synthetic fallback.
    let base = snapshot.transaction_count.saturating_add(50_000);
    let accounts: Vec<TokenLargestAccount> = (0_u64..5)
        .map(|index| {
            let amount = base.saturating_sub(index * 500);
            TokenLargestAccount {
                address: format!("ParaToken{:02}11111111111111111111111111111111", index),
                amount: amount.to_string(),
                decimals: 9,
                ui_amount: amount as f64 / TOKEN_UI_DECIMALS_DIVISOR,
                ui_amount_string: format!("0.{:09}", amount),
            }
        })
        .collect();
    // Synthetic includes mint field — use raw json for backward compat.
    Ok(json!({
        "context": {"slot": slot},
        "value": types::to_value(&accounts),
        "mint": mint
    }))
}

fn format_token_ui_amount(amount: u64, decimals: u8) -> String {
    if decimals == 0 {
        return amount.to_string();
    }
    let divisor = 10_u64.pow(decimals as u32);
    let whole = amount / divisor;
    let frac = amount % divisor;
    format!("{whole}.{frac:0>width$}", width = decimals as usize)
}

fn build_program_accounts_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    let (program_id, with_context, min_context_slot) = parse_program_accounts_request(request)?;
    ensure_optional_min_context_slot(min_context_slot, snapshot, commitment)?;
    let slot = resolve_slot(snapshot, commitment, bank_access);
    let encoding = parse_encoding(request);

    let accounts: Vec<ProgramAccount> = if let Some(bank) = bank_access {
        let owner = parse_pubkey(&program_id)?;
        bank.get_accounts_by_owner(&owner, commitment)
            .into_iter()
            .map(|(pubkey, account)| ProgramAccount {
                pubkey: pubkey.to_string(),
                account: format_account_value(&account, &encoding),
            })
            .collect()
    } else {
        (0_u64..2)
            .map(|index| ProgramAccount {
                pubkey: format!("ParaProgAcct{index:02}111111111111111111111111111111"),
                account: AccountValue {
                    lamports: snapshot.transaction_count.saturating_add(10_000 + index),
                    owner: program_id.clone(),
                    executable: false,
                    rent_epoch: 0,
                    data: AccountData::Encoded(String::new(), "base64".to_string()),
                    space: 0,
                },
            })
            .collect()
    };

    if with_context {
        let response = RpcResponse::new(slot, &accounts);
        Ok(types::to_value(&response))
    } else {
        Ok(types::to_value(&accounts))
    }
}

fn build_token_accounts_by_owner_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    let (owner, selector, min_context_slot) = parse_token_accounts_query(request)?;
    ensure_optional_min_context_slot(min_context_slot, snapshot, commitment)?;
    let slot = resolve_slot(snapshot, commitment, bank_access);
    let encoding = parse_encoding(request);

    if let Some(bank) = bank_access {
        let owner_pubkey = parse_pubkey(&owner)?;
        let token_program = parse_pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?;
        let all_token_accounts = bank.get_accounts_by_owner(&token_program, commitment);
        let value: Vec<ProgramAccount> = all_token_accounts
            .into_iter()
            .filter(|(_, account)| {
                // SPL Token account: owner is at bytes 32..64
                let data = account.data.as_slice();
                data.len() >= 64 && data[32..64] == *owner_pubkey.as_bytes()
            })
            .map(|(pubkey, account)| ProgramAccount {
                pubkey: pubkey.to_string(),
                account: format_account_value(&account, &encoding),
            })
            .collect();
        let response = RpcResponse::new(slot, value);
        Ok(types::to_value(&response))
    } else {
        let value: Vec<serde_json::Value> = (0_u64..2)
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
            .collect();
        Ok(json!({
            "context": {"slot": slot},
            "value": value
        }))
    }
}

fn build_token_accounts_by_delegate_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    let (delegate, selector, min_context_slot) = parse_token_accounts_query(request)?;
    ensure_optional_min_context_slot(min_context_slot, snapshot, commitment)?;
    let slot = resolve_slot(snapshot, commitment, bank_access);
    let encoding = parse_encoding(request);

    if let Some(bank) = bank_access {
        // Look up all SPL Token accounts, filter by delegate field (bytes 76..108).
        let delegate_pubkey = parse_pubkey(&delegate)?;
        let token_program = parse_pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?;
        let all_token_accounts = bank.get_accounts_by_owner(&token_program, commitment);
        let value: Vec<ProgramAccount> = all_token_accounts
            .into_iter()
            .filter(|(_, account)| {
                let data = account.data.as_slice();
                data.len() >= 108 && data[76..108] == *delegate_pubkey.as_bytes()
            })
            .map(|(pubkey, account)| ProgramAccount {
                pubkey: pubkey.to_string(),
                account: format_account_value(&account, &encoding),
            })
            .collect();
        let response = RpcResponse::new(slot, value);
        return Ok(types::to_value(&response));
    }

    // Synthetic fallback.
    let value: Vec<serde_json::Value> = (0_u64..2)
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
        .collect();
    Ok(json!({
        "context": {"slot": slot},
        "value": value
    }))
}

fn build_account_info_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;
    let pubkey_str = params::first_param_non_empty_string(request)?;
    let encoding = parse_encoding(request);
    let data_slice = parse_data_slice(request);
    let slot = resolve_slot(snapshot, commitment, bank_access);

    if let Some(bank) = bank_access {
        let pubkey = parse_pubkey(&pubkey_str)?;
        let value: Option<AccountValue> = bank
            .get_account(&pubkey, commitment)
            .map(|account| format_account_value_with_slice(&account, &encoding, data_slice));
        let response = RpcResponse::new(slot, value);
        Ok(types::to_value(&response))
    } else {
        let synthetic_lamports =
            synthetic_lamports_from_pubkey(&pubkey_str, snapshot.transaction_count);
        let value = AccountValue {
            lamports: synthetic_lamports,
            owner: "11111111111111111111111111111111".to_string(),
            executable: false,
            rent_epoch: 0,
            data: AccountData::Encoded(String::new(), "base64".to_string()),
            space: 0,
        };
        let response = RpcResponse::new(slot, value);
        Ok(types::to_value(&response))
    }
}

fn build_multiple_accounts_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;
    let pubkeys = params::first_param_string_array(request)?;
    let encoding = parse_encoding(request);
    let data_slice = parse_data_slice(request);
    let slot = resolve_slot(snapshot, commitment, bank_access);

    let accounts: Vec<Option<AccountValue>> = if let Some(bank) = bank_access {
        pubkeys
            .iter()
            .map(|pubkey_str| {
                let pubkey = parse_pubkey(pubkey_str)?;
                Ok(bank.get_account(&pubkey, commitment).map(|account| {
                    format_account_value_with_slice(&account, &encoding, data_slice)
                }))
            })
            .collect::<Result<Vec<_>, RpcMethodError>>()?
    } else {
        pubkeys
            .iter()
            .map(|pubkey| {
                let lamports = synthetic_lamports_from_pubkey(pubkey, snapshot.transaction_count);
                Some(AccountValue {
                    lamports,
                    owner: "11111111111111111111111111111111".to_string(),
                    executable: false,
                    rent_epoch: 0,
                    data: AccountData::Encoded(String::new(), "base64".to_string()),
                    space: 0,
                })
            })
            .collect()
    };

    let response = RpcResponse::new(slot, accounts);
    Ok(types::to_value(&response))
}

fn build_balance_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    ensure_min_context_slot_satisfied(request, snapshot, commitment)?;
    let pubkey_str = params::first_param_non_empty_string(request)?;
    let slot = resolve_slot(snapshot, commitment, bank_access);

    let lamports = if let Some(bank) = bank_access {
        let pubkey = parse_pubkey(&pubkey_str)?;
        bank.get_balance(&pubkey, commitment)
    } else {
        synthetic_lamports_from_pubkey(&pubkey_str, snapshot.transaction_count)
    };

    let response = RpcResponse::new(slot, lamports);
    Ok(types::to_value(&response))
}

fn build_signature_statuses_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    let config = parse_signature_statuses_config(request)?;
    ensure_optional_min_context_slot(config.min_context_slot, snapshot, commitment)?;
    let signatures = params::first_param_non_empty_string_array(request)?;
    let slot = resolve_slot(snapshot, commitment, bank_access);

    // Try real signature lookup first.
    if let Some(bank) = bank_access {
        let decoded: Vec<Option<[u8; 64]>> = signatures
            .iter()
            .map(|s| {
                let bytes = bs58::decode(s).into_vec().ok()?;
                if bytes.len() != 64 {
                    return None;
                }
                let mut sig = [0u8; 64];
                sig.copy_from_slice(&bytes);
                Some(sig)
            })
            .collect();

        // Only proceed with real lookup if all signatures decoded successfully.
        let all_decoded = decoded.iter().all(|d| d.is_some());
        if all_decoded {
            let sig_array: Vec<[u8; 64]> = decoded.into_iter().flatten().collect();
            let results = bank.get_signature_statuses(&sig_array);

            if results.iter().any(|r| r.is_some()) {
                let statuses: Vec<Option<SignatureStatus>> = results
                    .into_iter()
                    .map(|opt| {
                        opt.map(|status| {
                            let confirmations = slot.saturating_sub(status.slot);
                            let confirmation_status = if confirmations >= 32 {
                                "finalized"
                            } else if confirmations >= 1 {
                                "confirmed"
                            } else {
                                "processed"
                            };
                            let err = if status.succeeded {
                                serde_json::Value::Null
                            } else {
                                status
                                    .error
                                    .map(|e| json!({"InstructionError": e}))
                                    .unwrap_or(serde_json::Value::Null)
                            };
                            let status_value = if status.succeeded {
                                serde_json::json!({"Ok": null})
                            } else {
                                serde_json::json!({"Err": err.clone()})
                            };
                            SignatureStatus {
                                slot: status.slot,
                                confirmations: if confirmation_status == "finalized" {
                                    None
                                } else {
                                    Some(confirmations)
                                },
                                status: status_value,
                                err,
                                confirmation_status: confirmation_status.to_string(),
                            }
                        })
                    })
                    .collect();

                let response = RpcResponse::new(slot, statuses);
                return Ok(types::to_value(&response));
            }

            // Bank is available but none of the signatures were found in the
            // real transaction cache. Fall through to synthetic fallback —
            // airdrop signatures are synthetic and never in the real tx cache,
            // so they need the synthetic fallback to return "confirmed" status.
        }
    }

    // Synthetic fallback (no bank access).
    let statuses: Vec<Option<SignatureStatus>> = signatures
        .iter()
        .map(|signature| {
            let checksum = signature.bytes().fold(0_u64, |accumulator, byte| {
                accumulator.wrapping_add(u64::from(byte))
            });

            if !config.search_transaction_history && checksum % 5 == 0 {
                return None;
            }

            let confirmations = checksum % MAX_SIGNATURE_CONFIRMATIONS;
            let status_label = confirmation_status_label(commitment);
            Some(SignatureStatus {
                slot: snapshot
                    .slot_for_commitment(commitment)
                    .saturating_sub(confirmations),
                confirmations: if status_label == "finalized" {
                    None
                } else {
                    Some(confirmations)
                },
                status: serde_json::json!({"Ok": null}),
                err: serde_json::Value::Null,
                confirmation_status: status_label.to_string(),
            })
        })
        .collect();

    let response = RpcResponse::new(snapshot.slot_for_commitment(commitment), statuses);
    Ok(types::to_value(&response))
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

fn token_amount(amount: u64) -> TokenAmount {
    TokenAmount {
        amount: amount.to_string(),
        decimals: 9,
        ui_amount: amount as f64 / TOKEN_UI_DECIMALS_DIVISOR,
        ui_amount_string: format!("0.{amount:09}"),
    }
}

/// Format a token amount with real decimals from on-chain data.
fn token_amount_with_decimals(amount: u64, decimals: u8) -> TokenAmount {
    let divisor = 10_u64.pow(u32::from(decimals));
    let ui_amount = amount as f64 / divisor as f64;
    let ui_string = if decimals == 0 {
        amount.to_string()
    } else {
        format!("{ui_amount:.prec$}", prec = usize::from(decimals))
    };
    TokenAmount {
        amount: amount.to_string(),
        decimals,
        ui_amount,
        ui_amount_string: ui_string,
    }
}

/// Parse the token balance from an SPL Token account's raw data.
fn parse_spl_token_account_amount(data: &[u8]) -> Option<u64> {
    if data.len() < SPL_TOKEN_ACCOUNT_MIN_LEN {
        return None;
    }
    let amount_bytes: [u8; 8] = data
        [SPL_TOKEN_ACCOUNT_AMOUNT_OFFSET..SPL_TOKEN_ACCOUNT_AMOUNT_OFFSET + 8]
        .try_into()
        .ok()?;
    Some(u64::from_le_bytes(amount_bytes))
}

fn parse_spl_token_account_mint(data: &[u8]) -> Option<karstflow_types::Pubkey> {
    if data.len() < SPL_TOKEN_ACCOUNT_MIN_LEN {
        return None;
    }
    let mint_bytes: [u8; 32] = data
        [SPL_TOKEN_ACCOUNT_MINT_OFFSET..SPL_TOKEN_ACCOUNT_MINT_OFFSET + 32]
        .try_into()
        .ok()?;
    Some(karstflow_types::Pubkey::new(mint_bytes))
}

/// Parse supply and decimals from an SPL Mint account's raw data.
fn parse_spl_mint_supply(data: &[u8]) -> Option<(u64, u8)> {
    if data.len() < SPL_MINT_MIN_LEN {
        return None;
    }
    let supply_bytes: [u8; 8] = data[SPL_MINT_SUPPLY_OFFSET..SPL_MINT_SUPPLY_OFFSET + 8]
        .try_into()
        .ok()?;
    let supply = u64::from_le_bytes(supply_bytes);
    let decimals = data[SPL_MINT_DECIMALS_OFFSET];
    Some((supply, decimals))
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
        .map(params::optional_bool)
        .transpose()?
        .flatten()
        .unwrap_or(false);
    let min_context_slot = config_object
        .and_then(|cfg| cfg.get("minContextSlot"))
        .map(params::optional_u64)
        .transpose()?
        .flatten();
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
        .map(params::optional_u64)
        .transpose()?
        .flatten();
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
        .map(params::optional_bool)
        .transpose()?
        .flatten()
        .unwrap_or(false);
    Ok(exclude_non_circulating_accounts)
}

fn parse_pubkey(encoded: &str) -> Result<karstflow_types::Pubkey, RpcMethodError> {
    let bytes = bs58::decode(encoded)
        .into_vec()
        .map_err(|_| RpcMethodError::InvalidParams)?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| RpcMethodError::InvalidParams)?;
    Ok(karstflow_types::Pubkey::new(array))
}

fn parse_encoding(request: &serde_json::Value) -> String {
    let params = params::params_array_or_empty(request);
    params::first_config_object(params)
        .and_then(|cfg| cfg.get("encoding"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("base64")
        .to_string()
}

fn parse_data_slice(request: &serde_json::Value) -> Option<(usize, usize)> {
    let params = params::params_array_or_empty(request);
    let cfg = params::first_config_object(params)?;
    let ds = cfg.get("dataSlice")?;
    let offset = ds.get("offset")?.as_u64()? as usize;
    let length = ds.get("length")?.as_u64()? as usize;
    Some((offset, length))
}

fn resolve_slot(
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> u64 {
    bank_access
        .map(|bank| bank.get_slot(commitment))
        .unwrap_or_else(|| snapshot.slot_for_commitment(commitment))
}

fn format_account_value(account: &karstflow_types::Account, encoding: &str) -> AccountValue {
    format_account_value_with_slice(account, encoding, None)
}

fn format_account_value_with_slice(
    account: &karstflow_types::Account,
    encoding: &str,
    data_slice: Option<(usize, usize)>,
) -> AccountValue {
    let full_data = account.data.as_slice();
    let sliced = if let Some((offset, length)) = data_slice {
        let start = offset.min(full_data.len());
        let end = start.saturating_add(length).min(full_data.len());
        &full_data[start..end]
    } else {
        full_data
    };
    let data = encode_account_data(sliced, encoding);
    AccountValue {
        lamports: account.meta.lamports,
        owner: account.meta.owner.to_string(),
        executable: account.meta.executable,
        rent_epoch: account.meta.rent_epoch,
        data,
        space: account.data.len(),
    }
}

fn encode_account_data(data: &[u8], encoding: &str) -> AccountData {
    use base64::Engine;
    match encoding {
        "base58" => {
            let encoded = bs58::encode(data).into_string();
            AccountData::Encoded(encoded, "base58".to_string())
        }
        _ => {
            let encoded = base64::engine::general_purpose::STANDARD.encode(data);
            AccountData::Encoded(encoded, "base64".to_string())
        }
    }
}

fn parse_signature_statuses_config(
    request: &serde_json::Value,
) -> Result<SignatureStatusesConfig, RpcMethodError> {
    let params = params::params_array_or_empty(request);
    let config_object = params.get(1).and_then(serde_json::Value::as_object);

    let search_transaction_history = config_object
        .and_then(|cfg| cfg.get("searchTransactionHistory"))
        .map(params::optional_bool)
        .transpose()?
        .flatten()
        .unwrap_or(false);
    let min_context_slot = config_object
        .and_then(|cfg| cfg.get("minContextSlot"))
        .map(params::optional_u64)
        .transpose()?
        .flatten();

    Ok(SignatureStatusesConfig {
        search_transaction_history,
        min_context_slot,
    })
}
