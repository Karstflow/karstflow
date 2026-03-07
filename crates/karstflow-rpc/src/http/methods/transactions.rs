use serde_json::{Map, Value};
use std::sync::Arc;

use crate::state::{BankAccessProvider, RpcCommitment, RpcRuntimeSnapshot, TransactionSubmitter};
use karstflow_constants::rpc::{
    SEND_TX_COMMITMENT_BIAS_CONFIRMED, SEND_TX_COMMITMENT_BIAS_FINALIZED,
    SEND_TX_COMMITMENT_BIAS_PROCESSED, SEND_TX_ENCODING_BONUS_BASE58,
    SEND_TX_ENCODING_BONUS_BASE64, SEND_TX_MAX_RETRIES_CAP, SEND_TX_PREFLIGHT_PENALTY_CHECK,
    SEND_TX_PREFLIGHT_PENALTY_SKIP, SEND_TX_SIGNATURE_HASH_MULTIPLIER, SIMULATE_ACCOUNT_LAMPORTS,
    SIMULATE_MAX_ACCOUNTS, SIMULATE_REPLACEMENT_BLOCKHASH_VALIDITY_OFFSET,
    SIMULATE_UNITS_CONSUMED_BASE, SIMULATE_UNITS_CONSUMED_SIG_VERIFY_BONUS,
    SIMULATE_UNITS_ENCODING_BASE58, SIMULATE_UNITS_ENCODING_BASE64,
    SIMULATE_UNITS_PER_TRANSACTION_CHAR, TRANSACTION_ENCODING_BASE58, TRANSACTION_ENCODING_BASE64,
    TRANSACTION_ENCODING_JSON, TRANSACTION_ENCODING_JSON_PARSED,
};

use super::super::method_error::RpcMethodError;
use super::super::registry::RpcMethod;
use super::params;
use super::types::{
    self, AccountData, ReplacementBlockhash, ReturnData, RpcResponse, SimulateAccountValue,
    SimulateTransactionValue,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum TransactionEncoding {
    Base58,
    Base64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AccountEncoding {
    Base58,
    Base64,
    JsonParsed,
}

struct SendTransactionConfig {
    skip_preflight: bool,
    max_retries: Option<u64>,
    min_context_slot: Option<u64>,
    encoding: TransactionEncoding,
}

struct SimulateAccountsConfig {
    encoding: AccountEncoding,
    addresses: Vec<String>,
}

struct SimulateTransactionConfig {
    sig_verify: bool,
    replace_recent_blockhash: bool,
    min_context_slot: Option<u64>,
    encoding: TransactionEncoding,
    accounts: Option<SimulateAccountsConfig>,
}

const SEND_TRANSACTION_CONFIG_ALLOWED_KEYS: &[&str] =
    &["skipPreflight", "maxRetries", "minContextSlot", "encoding"];
const SIMULATE_TRANSACTION_CONFIG_ALLOWED_KEYS: &[&str] = &[
    "sigVerify",
    "replaceRecentBlockhash",
    "minContextSlot",
    "encoding",
    "accounts",
];
const SIMULATE_ACCOUNTS_CONFIG_ALLOWED_KEYS: &[&str] = &["encoding", "addresses"];

pub(super) fn handle(
    method: RpcMethod,
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
    tx_submitter: Option<&Arc<dyn TransactionSubmitter>>,
) -> Result<serde_json::Value, RpcMethodError> {
    match method {
        RpcMethod::SendTransaction => {
            build_send_transaction_response(request, snapshot, commitment, tx_submitter)
        }
        RpcMethod::SimulateTransaction => {
            build_simulate_transaction_response(request, snapshot, commitment, bank_access)
        }
        _ => Err(RpcMethodError::MethodNotFound),
    }
}

fn build_send_transaction_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    tx_submitter: Option<&Arc<dyn TransactionSubmitter>>,
) -> Result<serde_json::Value, RpcMethodError> {
    let transaction = params::first_param_non_empty_string(request)?;
    let config = parse_send_transaction_config(request)?;
    ensure_min_context_slot(
        config.min_context_slot,
        snapshot.slot_for_commitment(commitment),
    )?;

    // When a real transaction submitter is available, decode and forward
    if let Some(submitter) = tx_submitter {
        use base64::Engine;

        let tx_bytes = match config.encoding {
            TransactionEncoding::Base58 => bs58::decode(&transaction)
                .into_vec()
                .map_err(|_| RpcMethodError::InvalidParams)?,
            TransactionEncoding::Base64 => base64::engine::general_purpose::STANDARD
                .decode(&transaction)
                .map_err(|_| RpcMethodError::InvalidParams)?,
        };

        let sig_bytes = submitter
            .submit_transaction(&tx_bytes)
            .map_err(|_| RpcMethodError::TransactionSubmissionFailed)?;

        let sig_str = bs58::encode(sig_bytes).into_string();
        return Ok(types::to_value(&sig_str));
    }

    // Synthetic fallback when no submitter is available
    let encoding_bonus = match config.encoding {
        TransactionEncoding::Base58 => SEND_TX_ENCODING_BONUS_BASE58,
        TransactionEncoding::Base64 => SEND_TX_ENCODING_BONUS_BASE64,
    };
    let preflight_penalty = if config.skip_preflight {
        SEND_TX_PREFLIGHT_PENALTY_SKIP
    } else {
        SEND_TX_PREFLIGHT_PENALTY_CHECK
    };
    let retry_bonus = config.max_retries.unwrap_or(0).min(SEND_TX_MAX_RETRIES_CAP);
    let commitment_bias = match commitment {
        RpcCommitment::Processed => SEND_TX_COMMITMENT_BIAS_PROCESSED,
        RpcCommitment::Confirmed => SEND_TX_COMMITMENT_BIAS_CONFIRMED,
        RpcCommitment::Finalized => SEND_TX_COMMITMENT_BIAS_FINALIZED,
    };

    let signature_seed = transaction.bytes().fold(0_u64, |acc, byte| {
        acc.wrapping_mul(SEND_TX_SIGNATURE_HASH_MULTIPLIER)
            .wrapping_add(u64::from(byte))
    });
    let signature = format!(
        "{:016x}{:016x}{:016x}{:016x}",
        signature_seed,
        snapshot
            .blockhash_seed_for_commitment(commitment)
            .wrapping_add(encoding_bonus),
        snapshot
            .slot_for_commitment(commitment)
            .wrapping_add(preflight_penalty)
            .wrapping_add(retry_bonus),
        snapshot.transaction_count.wrapping_add(commitment_bias)
    );
    Ok(types::to_value(&signature))
}

fn build_simulate_transaction_response(
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    let transaction = params::first_param_non_empty_string(request)?;
    let config = parse_simulate_transaction_config(request)?;
    let slot = bank_access
        .map(|bank| bank.get_slot(commitment))
        .unwrap_or_else(|| snapshot.slot_for_commitment(commitment));
    ensure_min_context_slot(config.min_context_slot, slot)?;

    // When bank access is available, run real transaction simulation
    if let Some(bank) = bank_access {
        return build_real_simulation_response(&transaction, config, commitment, bank, slot);
    }

    // Synthetic fallback when no bank access is available
    build_synthetic_simulation_response(&transaction, config, snapshot, commitment, slot)
}

fn build_real_simulation_response(
    transaction: &str,
    config: SimulateTransactionConfig,
    commitment: RpcCommitment,
    bank_access: &Arc<dyn BankAccessProvider>,
    slot: u64,
) -> Result<serde_json::Value, RpcMethodError> {
    use base64::Engine;

    // Decode transaction bytes from the encoding
    let raw_bytes = match config.encoding {
        TransactionEncoding::Base58 => bs58::decode(transaction)
            .into_vec()
            .map_err(|_| RpcMethodError::InvalidParams)?,
        TransactionEncoding::Base64 => base64::engine::general_purpose::STANDARD
            .decode(transaction)
            .map_err(|_| RpcMethodError::InvalidParams)?,
    };

    // Run simulation via the bank access provider
    let sim_result = bank_access.simulate_transaction(
        &raw_bytes,
        config.sig_verify,
        config.replace_recent_blockhash,
        commitment,
    );

    // Format error (null for success)
    let err_value = sim_result
        .error
        .as_ref()
        .map(|e| serde_json::to_value(e).unwrap_or(serde_json::Value::Null))
        .unwrap_or(serde_json::Value::Null);

    // Format accounts if requested
    let account_payload = config
        .accounts
        .map(|accounts| {
            let list: Vec<serde_json::Value> = accounts
                .addresses
                .into_iter()
                .map(|address| {
                    if let Some(real_account) =
                        parse_pubkey_and_lookup(bank_access, &address, commitment)
                    {
                        let acct =
                            format_simulate_account(&real_account, &address, accounts.encoding);
                        types::to_value(&acct)
                    } else {
                        serde_json::Value::Null
                    }
                })
                .collect();
            serde_json::Value::Array(list)
        })
        .unwrap_or(serde_json::Value::Null);

    // Format return data
    let return_data_value = sim_result
        .return_data
        .map(|(program_id, data)| {
            let encoded = base64::engine::general_purpose::STANDARD.encode(&data);
            let rd = ReturnData {
                program_id,
                data: (encoded, "base64".to_string()),
            };
            types::to_value(&rd)
        })
        .unwrap_or(serde_json::Value::Null);

    // Format replacement blockhash
    let replacement_blockhash_value = if config.replace_recent_blockhash {
        let hash = bs58::encode(bank_access.get_latest_blockhash(commitment)).into_string();
        let last_valid = bank_access.get_last_valid_block_height(commitment);
        let rb = ReplacementBlockhash {
            blockhash: hash,
            last_valid_block_height: last_valid,
        };
        types::to_value(&rb)
    } else {
        serde_json::Value::Null
    };

    let value = SimulateTransactionValue {
        err: err_value,
        logs: types::to_value(&sim_result.logs),
        units_consumed: sim_result.units_consumed,
        accounts: account_payload,
        return_data: return_data_value,
        replacement_blockhash: replacement_blockhash_value,
    };
    let response = RpcResponse::new(slot, value);
    Ok(types::to_value(&response))
}

fn build_synthetic_simulation_response(
    transaction: &str,
    config: SimulateTransactionConfig,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    slot: u64,
) -> Result<serde_json::Value, RpcMethodError> {
    let base_units = SIMULATE_UNITS_CONSUMED_BASE
        .saturating_add(
            (transaction.len() as u64).saturating_mul(SIMULATE_UNITS_PER_TRANSACTION_CHAR),
        )
        .saturating_add(match config.encoding {
            TransactionEncoding::Base58 => SIMULATE_UNITS_ENCODING_BASE58,
            TransactionEncoding::Base64 => SIMULATE_UNITS_ENCODING_BASE64,
        })
        .saturating_add(if config.sig_verify {
            SIMULATE_UNITS_CONSUMED_SIG_VERIFY_BONUS
        } else {
            0
        });

    let account_payload = config
        .accounts
        .map(|accounts| {
            let list: Vec<serde_json::Value> = accounts
                .addresses
                .into_iter()
                .map(|address| {
                    let data = match accounts.encoding {
                        AccountEncoding::Base58 => AccountData::Encoded(
                            address.clone(),
                            TRANSACTION_ENCODING_BASE58.to_string(),
                        ),
                        AccountEncoding::Base64 => AccountData::Encoded(
                            address.clone(),
                            TRANSACTION_ENCODING_BASE64.to_string(),
                        ),
                        AccountEncoding::JsonParsed => AccountData::JsonParsed {
                            program: "system".to_string(),
                            parsed: serde_json::json!({"pubkey": address}),
                        },
                    };
                    let acct = SimulateAccountValue {
                        lamports: SIMULATE_ACCOUNT_LAMPORTS,
                        owner: "11111111111111111111111111111111".to_string(),
                        executable: false,
                        rent_epoch: 0,
                        space: 0,
                        data,
                    };
                    types::to_value(&acct)
                })
                .collect();
            serde_json::Value::Array(list)
        })
        .unwrap_or(serde_json::Value::Null);

    let replacement_blockhash_value = if config.replace_recent_blockhash {
        let rb = ReplacementBlockhash {
            blockhash: format!(
                "{:064x}",
                snapshot.blockhash_seed_for_commitment(commitment)
            ),
            last_valid_block_height: snapshot
                .block_height_for_commitment(commitment)
                .saturating_add(SIMULATE_REPLACEMENT_BLOCKHASH_VALIDITY_OFFSET),
        };
        types::to_value(&rb)
    } else {
        serde_json::Value::Null
    };

    let logs = vec![
        "Program 11111111111111111111111111111111 invoke [1]".to_string(),
        "Program 11111111111111111111111111111111 success".to_string(),
    ];

    let value = SimulateTransactionValue {
        err: serde_json::Value::Null,
        logs: types::to_value(&logs),
        units_consumed: base_units,
        accounts: account_payload,
        return_data: serde_json::Value::Null,
        replacement_blockhash: replacement_blockhash_value,
    };
    let response = RpcResponse::new(slot, value);
    Ok(types::to_value(&response))
}

fn parse_send_transaction_config(
    request: &serde_json::Value,
) -> Result<SendTransactionConfig, RpcMethodError> {
    let params = params::params_array_or_empty(request);
    if params.len() > 2 {
        return Err(RpcMethodError::InvalidParams);
    }
    let config = params.get(1).and_then(serde_json::Value::as_object);
    if let Some(config) = config {
        ensure_no_unknown_keys(config, SEND_TRANSACTION_CONFIG_ALLOWED_KEYS)?;
    }

    let skip_preflight = config
        .and_then(|config| config.get("skipPreflight"))
        .map(params::optional_bool)
        .transpose()?
        .flatten()
        .unwrap_or(false);

    let max_retries = config
        .and_then(|config| config.get("maxRetries"))
        .map(params::optional_u64)
        .transpose()?
        .flatten();

    let min_context_slot = config
        .and_then(|config| config.get("minContextSlot"))
        .map(params::optional_u64)
        .transpose()?
        .flatten();

    let encoding = parse_transaction_encoding(
        config.and_then(|config| config.get("encoding")),
        TransactionEncoding::Base58,
    )?;

    Ok(SendTransactionConfig {
        skip_preflight,
        max_retries,
        min_context_slot,
        encoding,
    })
}

fn parse_simulate_transaction_config(
    request: &serde_json::Value,
) -> Result<SimulateTransactionConfig, RpcMethodError> {
    let params = params::params_array_or_empty(request);
    if params.len() > 2 {
        return Err(RpcMethodError::InvalidParams);
    }
    let config = params.get(1).and_then(serde_json::Value::as_object);
    if let Some(config) = config {
        ensure_no_unknown_keys(config, SIMULATE_TRANSACTION_CONFIG_ALLOWED_KEYS)?;
    }

    let sig_verify = config
        .and_then(|config| config.get("sigVerify"))
        .map(params::optional_bool)
        .transpose()?
        .flatten()
        .unwrap_or(false);
    let replace_recent_blockhash = config
        .and_then(|config| config.get("replaceRecentBlockhash"))
        .map(params::optional_bool)
        .transpose()?
        .flatten()
        .unwrap_or(false);
    let min_context_slot = config
        .and_then(|config| config.get("minContextSlot"))
        .map(params::optional_u64)
        .transpose()?
        .flatten();
    let encoding = parse_transaction_encoding(
        config.and_then(|config| config.get("encoding")),
        TransactionEncoding::Base64,
    )?;
    let accounts = parse_simulate_accounts_config(config)?;

    Ok(SimulateTransactionConfig {
        sig_verify,
        replace_recent_blockhash,
        min_context_slot,
        encoding,
        accounts,
    })
}

fn parse_simulate_accounts_config(
    config: Option<&serde_json::Map<String, serde_json::Value>>,
) -> Result<Option<SimulateAccountsConfig>, RpcMethodError> {
    let accounts = match config.and_then(|config| config.get("accounts")) {
        Some(accounts) => accounts.as_object().ok_or(RpcMethodError::InvalidParams)?,
        None => return Ok(None),
    };
    ensure_no_unknown_keys(accounts, SIMULATE_ACCOUNTS_CONFIG_ALLOWED_KEYS)?;

    let encoding = parse_account_encoding(accounts.get("encoding"))?;
    let raw_addresses = accounts
        .get("addresses")
        .map(|raw| raw.as_array().ok_or(RpcMethodError::InvalidParams))
        .transpose()?;
    let addresses = raw_addresses
        .map(|addresses| addresses.as_slice())
        .unwrap_or(&[])
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::trim)
                .filter(|address| !address.is_empty())
                .map(str::to_string)
                .ok_or(RpcMethodError::InvalidParams)
        })
        .collect::<Result<Vec<_>, RpcMethodError>>()?;
    if addresses.len() > SIMULATE_MAX_ACCOUNTS {
        return Err(RpcMethodError::InvalidParams);
    }

    Ok(Some(SimulateAccountsConfig {
        encoding,
        addresses,
    }))
}

fn parse_transaction_encoding(
    raw: Option<&serde_json::Value>,
    default: TransactionEncoding,
) -> Result<TransactionEncoding, RpcMethodError> {
    let encoding = match raw {
        Some(raw) => raw.as_str().ok_or(RpcMethodError::InvalidParams)?,
        None => return Ok(default),
    };
    match encoding {
        TRANSACTION_ENCODING_BASE58 => Ok(TransactionEncoding::Base58),
        TRANSACTION_ENCODING_BASE64 => Ok(TransactionEncoding::Base64),
        _ => Err(RpcMethodError::InvalidParams),
    }
}

fn parse_account_encoding(
    raw: Option<&serde_json::Value>,
) -> Result<AccountEncoding, RpcMethodError> {
    let encoding = match raw {
        Some(raw) => raw.as_str().ok_or(RpcMethodError::InvalidParams)?,
        None => return Ok(AccountEncoding::Base64),
    };
    match encoding {
        TRANSACTION_ENCODING_BASE58 => Ok(AccountEncoding::Base58),
        TRANSACTION_ENCODING_BASE64 => Ok(AccountEncoding::Base64),
        TRANSACTION_ENCODING_JSON | TRANSACTION_ENCODING_JSON_PARSED => {
            Ok(AccountEncoding::JsonParsed)
        }
        _ => Err(RpcMethodError::InvalidParams),
    }
}

fn ensure_min_context_slot(
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

fn ensure_no_unknown_keys(
    config: &Map<String, Value>,
    allowed_keys: &[&str],
) -> Result<(), RpcMethodError> {
    for key in config.keys() {
        if !allowed_keys.contains(&key.as_str()) {
            return Err(RpcMethodError::InvalidParams);
        }
    }
    Ok(())
}

fn parse_pubkey_and_lookup(
    bank: &Arc<dyn BankAccessProvider>,
    address: &str,
    commitment: RpcCommitment,
) -> Option<karstflow_types::Account> {
    let bytes = bs58::decode(address).into_vec().ok()?;
    let array: [u8; 32] = bytes.try_into().ok()?;
    let pubkey = karstflow_types::Pubkey::new(array);
    bank.get_account(&pubkey, commitment)
}

fn format_simulate_account(
    account: &karstflow_types::Account,
    _address: &str,
    encoding: AccountEncoding,
) -> SimulateAccountValue {
    use base64::Engine;
    let data = match encoding {
        AccountEncoding::Base58 => {
            let encoded = bs58::encode(account.data.as_slice()).into_string();
            AccountData::Encoded(encoded, TRANSACTION_ENCODING_BASE58.to_string())
        }
        AccountEncoding::Base64 => {
            let encoded = base64::engine::general_purpose::STANDARD.encode(account.data.as_slice());
            AccountData::Encoded(encoded, TRANSACTION_ENCODING_BASE64.to_string())
        }
        AccountEncoding::JsonParsed => AccountData::JsonParsed {
            program: "system".to_string(),
            parsed: serde_json::json!({"pubkey": _address}),
        },
    };
    SimulateAccountValue {
        lamports: account.meta.lamports,
        owner: account.meta.owner.to_string(),
        executable: account.meta.executable,
        rent_epoch: account.meta.rent_epoch,
        space: account.data.len(),
        data,
    }
}
