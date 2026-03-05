use std::sync::Arc;

use crate::state::{BankAccessProvider, RpcCommitment, RpcRuntimeSnapshot};

use super::super::method_error::RpcMethodError;
use super::super::registry::RpcMethod;
use super::params;
use super::types;

pub(super) fn handle(
    method: RpcMethod,
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    match method {
        RpcMethod::RequestAirdrop => {
            build_request_airdrop_response(request, snapshot, commitment, bank_access)
        }
        _ => Err(RpcMethodError::MethodNotFound),
    }
}

fn build_request_airdrop_response(
    request: &serde_json::Value,
    _snapshot: RpcRuntimeSnapshot,
    _commitment: RpcCommitment,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
) -> Result<serde_json::Value, RpcMethodError> {
    let params = params::params_array_or_empty(request);
    if params.len() < 2 {
        return Err(RpcMethodError::InvalidParams);
    }

    let pubkey_str = params
        .first()
        .and_then(|v| v.as_str())
        .ok_or(RpcMethodError::InvalidParams)?;

    let lamports = params
        .get(1)
        .and_then(|v| v.as_u64())
        .ok_or(RpcMethodError::InvalidParams)?;

    // Decode base58 pubkey
    let pubkey_bytes = bs58::decode(pubkey_str)
        .into_vec()
        .map_err(|_| RpcMethodError::InvalidParams)?;
    let pubkey_array: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| RpcMethodError::InvalidParams)?;
    let pubkey = karstflow_types::Pubkey::new(pubkey_array);

    let bank = bank_access.ok_or(RpcMethodError::Internal)?;

    let sig_bytes = bank
        .request_airdrop(&pubkey, lamports)
        .map_err(|_| RpcMethodError::Internal)?;

    let signature = bs58::encode(sig_bytes).into_string();
    Ok(types::to_value(&signature))
}
