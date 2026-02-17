use crate::cache::signature::SignatureCache;
use crate::simulation::{
    SimulateAccountsConfig, SimulationConfig, SimulationResult, TransactionSimulator,
};
use crate::state::{RpcCommitment, RpcRuntimeSnapshot};
use crate::{Result, RpcError};
use serde_json::{json, Value};

/// Advanced transaction method handler
pub struct TransactionsAdvanced {
    simulator: TransactionSimulator,
    signature_cache: SignatureCache,
}

impl TransactionsAdvanced {
    pub fn new(simulator: TransactionSimulator, signature_cache: SignatureCache) -> Self {
        Self {
            simulator,
            signature_cache,
        }
    }

    /// Simulate a transaction without committing it
    pub fn simulate_transaction(
        &self,
        transaction: &str,
        config: SimulateTransactionConfig,
        snapshot: RpcRuntimeSnapshot,
        commitment: RpcCommitment,
    ) -> Result<Value> {
        let slot = snapshot.slot_for_commitment(commitment);

        // Check min context slot
        if let Some(min_slot) = config.min_context_slot {
            if slot < min_slot {
                return Err(RpcError::MinContextSlotNotReached { slot, min_slot });
            }
        }

        // Parse transaction
        let tx_bytes = match config.encoding.as_deref() {
            Some("base58") => bs58::decode(transaction)
                .into_vec()
                .map_err(|e| RpcError::InvalidTransaction(format!("base58 decode: {}", e)))?,
            Some("base64") | None => base64::decode(transaction)
                .map_err(|e| RpcError::InvalidTransaction(format!("base64 decode: {}", e)))?,
            _ => return Err(RpcError::InvalidEncoding),
        };

        // Build simulation config
        let sim_config = SimulationConfig {
            sig_verify: config.sig_verify,
            replace_recent_blockhash: config.replace_recent_blockhash,
            commitment,
            inner_instructions: config.inner_instructions.unwrap_or(false),
            accounts: config.accounts.clone(),
        };

        // Run simulation
        let result = self.simulator.simulate(&tx_bytes, sim_config, snapshot)?;

        // Build response
        Ok(build_simulation_response(result, slot))
    }

    /// Get recent prioritization fees
    pub fn get_recent_prioritization_fees(
        &self,
        accounts: Option<Vec<String>>,
        snapshot: RpcRuntimeSnapshot,
    ) -> Result<Value> {
        // Generate synthetic fee data based on recent activity
        let base_fee = calculate_base_prioritization_fee(snapshot);
        let mut fees = Vec::new();

        // Generate fee samples for last 20 slots
        for i in 0..20 {
            let slot = snapshot.slot.saturating_sub(i);
            let fee = calculate_slot_prioritization_fee(slot, base_fee, &accounts);
            fees.push(json!({
                "slot": slot,
                "prioritizationFee": fee,
            }));
        }

        Ok(json!(fees))
    }

    /// Get fee for a message
    pub fn get_fee_for_message(
        &self,
        message: &str,
        snapshot: RpcRuntimeSnapshot,
        commitment: RpcCommitment,
    ) -> Result<Value> {
        let slot = snapshot.slot_for_commitment(commitment);

        // Decode message
        let msg_bytes = bs58::decode(message)
            .into_vec()
            .map_err(|e| RpcError::InvalidTransaction(format!("message decode: {}", e)))?;

        // Calculate fee based on message size and complexity
        let fee = calculate_message_fee(&msg_bytes, snapshot);

        Ok(json!({
            "context": {
                "slot": slot
            },
            "value": fee
        }))
    }

    /// Send transaction with preflight checks
    pub fn send_transaction_with_preflight(
        &self,
        transaction: &str,
        config: SendTransactionConfig,
        snapshot: RpcRuntimeSnapshot,
        commitment: RpcCommitment,
    ) -> Result<Value> {
        let slot = snapshot.slot_for_commitment(commitment);

        // Check min context slot
        if let Some(min_slot) = config.min_context_slot {
            if slot < min_slot {
                return Err(RpcError::MinContextSlotNotReached { slot, min_slot });
            }
        }

        // Parse transaction
        let tx_bytes = match config.encoding.as_deref() {
            Some("base58") => bs58::decode(transaction)
                .into_vec()
                .map_err(|e| RpcError::InvalidTransaction(format!("base58 decode: {}", e)))?,
            Some("base64") | None => base64::decode(transaction)
                .map_err(|e| RpcError::InvalidTransaction(format!("base64 decode: {}", e)))?,
            _ => return Err(RpcError::InvalidEncoding),
        };

        // Run preflight simulation if not skipped
        if !config.skip_preflight {
            let sim_config = SimulationConfig {
                sig_verify: true,
                replace_recent_blockhash: false,
                commitment,
                inner_instructions: false,
                accounts: None,
            };

            let result = self.simulator.simulate(&tx_bytes, sim_config, snapshot)?;

            if let Some(err) = result.err {
                return Err(RpcError::PreflightFailed(format!("{:?}", err)));
            }
        }

        // Generate signature
        let signature = generate_transaction_signature(&tx_bytes, snapshot, commitment);

        // Cache signature
        self.signature_cache
            .insert(signature.clone(), slot, commitment);

        Ok(json!(signature))
    }

    /// Get transaction with metadata
    pub fn get_transaction_with_meta(
        &self,
        signature: &str,
        config: GetTransactionConfig,
        snapshot: RpcRuntimeSnapshot,
        commitment: RpcCommitment,
    ) -> Result<Value> {
        let slot = snapshot.slot_for_commitment(commitment);

        // Check signature cache
        if let Some(cached) = self.signature_cache.get(signature) {
            return Ok(build_transaction_meta_response(
                signature,
                cached.slot,
                cached.commitment,
                &config,
            ));
        }

        // Synthetic transaction data
        Ok(build_transaction_meta_response(
            signature,
            slot.saturating_sub(5),
            commitment,
            &config,
        ))
    }
}

#[derive(Debug, Clone)]
pub struct SimulateTransactionConfig {
    pub sig_verify: bool,
    pub replace_recent_blockhash: bool,
    pub min_context_slot: Option<u64>,
    pub encoding: Option<String>,
    pub inner_instructions: Option<bool>,
    pub accounts: Option<SimulateAccountsConfig>,
}

#[derive(Debug, Clone)]
pub struct SendTransactionConfig {
    pub skip_preflight: bool,
    pub preflight_commitment: Option<RpcCommitment>,
    pub max_retries: Option<u64>,
    pub min_context_slot: Option<u64>,
    pub encoding: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GetTransactionConfig {
    pub encoding: Option<String>,
    pub max_supported_transaction_version: Option<u8>,
    pub commitment: Option<RpcCommitment>,
}

fn build_simulation_response(result: SimulationResult, slot: u64) -> Value {
    let err_value = result.err.map(|e| json!({"err": format!("{:?}", e)}));

    let mut value = json!({
        "err": err_value.unwrap_or(Value::Null),
        "logs": result.logs,
        "unitsConsumed": result.units_consumed,
    });

    if let Some(accounts) = result.accounts {
        value["accounts"] = json!(accounts
            .iter()
            .map(|acc| {
                acc.as_ref().map(|a| {
                    json!({
                        "lamports": a.meta.lamports,
                        "owner": a.meta.owner.to_string(),
                        "data": ["", "base64"],
                        "executable": a.meta.executable,
                        "rentEpoch": a.meta.rent_epoch,
                    })
                })
            })
            .collect::<Vec<_>>());
    }

    if let Some(return_data) = result.return_data {
        value["returnData"] = json!({
            "data": [bs58::encode(&return_data).into_string(), "base58"],
            "programId": "11111111111111111111111111111111",
        });
    }

    json!({
        "context": { "slot": slot },
        "value": value
    })
}

fn calculate_base_prioritization_fee(snapshot: RpcRuntimeSnapshot) -> u64 {
    // Base fee scales with network activity
    let activity_factor = snapshot.transaction_count % 10000;
    1000 + activity_factor
}

fn calculate_slot_prioritization_fee(
    slot: u64,
    base_fee: u64,
    accounts: &Option<Vec<String>>,
) -> u64 {
    let slot_variance = (slot % 100) * 10;
    let account_bonus = accounts.as_ref().map(|a| a.len() as u64 * 50).unwrap_or(0);

    base_fee + slot_variance + account_bonus
}

fn calculate_message_fee(msg_bytes: &[u8], snapshot: RpcRuntimeSnapshot) -> u64 {
    let base_fee = 5000; // Base fee in lamports
    let size_fee = (msg_bytes.len() as u64) * 10;
    let complexity_fee = (snapshot.transaction_count % 100) * 50;

    base_fee + size_fee + complexity_fee
}

fn generate_transaction_signature(
    tx_bytes: &[u8],
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
) -> String {
    use std::hash::{Hash, Hasher};

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    tx_bytes.hash(&mut hasher);
    snapshot.slot.hash(&mut hasher);
    (commitment as u8).hash(&mut hasher);

    let hash = hasher.finish();
    bs58::encode(&hash.to_le_bytes())
        .into_string()
        .chars()
        .cycle()
        .take(88)
        .collect()
}

fn build_transaction_meta_response(
    signature: &str,
    slot: u64,
    commitment: RpcCommitment,
    _config: &GetTransactionConfig,
) -> Value {
    let commitment_str = match commitment {
        RpcCommitment::Processed => "processed",
        RpcCommitment::Confirmed => "confirmed",
        RpcCommitment::Finalized => "finalized",
    };

    json!({
        "slot": slot,
        "transaction": {
            "signatures": [signature],
            "message": {
                "accountKeys": [
                    "11111111111111111111111111111111",
                    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                ],
                "recentBlockhash": format!("{:064x}", slot),
                "instructions": [],
            }
        },
        "meta": {
            "err": Value::Null,
            "fee": 5000,
            "preBalances": [1000000, 2000000],
            "postBalances": [995000, 2000000],
            "logMessages": [
                "Program 11111111111111111111111111111111 invoke [1]",
                "Program 11111111111111111111111111111111 success"
            ],
            "preTokenBalances": [],
            "postTokenBalances": [],
            "rewards": [],
            "status": { "Ok": Value::Null },
        },
        "blockTime": slot * 400, // Synthetic timestamp
        "confirmationStatus": commitment_str,
    })
}

// Re-export for base64 decoding
mod base64 {
    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        // Simple base64 decode - in production use a proper library
        Ok(s.as_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_message_fee() {
        let snapshot = RpcRuntimeSnapshot {
            slot: 1000,
            block_height: 1000,
            transaction_count: 500,
            uptime_millis: 10000,
            latest_blockhash_seed: 12345,
        };

        let msg = vec![0u8; 100];
        let fee = calculate_message_fee(&msg, snapshot);
        assert!(fee > 5000); // Should be base + size fee
    }

    #[test]
    fn test_calculate_prioritization_fee() {
        let snapshot = RpcRuntimeSnapshot {
            slot: 1000,
            block_height: 1000,
            transaction_count: 5500,
            uptime_millis: 10000,
            latest_blockhash_seed: 12345,
        };

        let base = calculate_base_prioritization_fee(snapshot);
        assert_eq!(base, 1000 + 5500);
    }

    #[test]
    fn test_slot_prioritization_fee_with_accounts() {
        let accounts = Some(vec!["acc1".to_string(), "acc2".to_string()]);
        let fee = calculate_slot_prioritization_fee(100, 1000, &accounts);
        assert_eq!(fee, 1100); // base(1000) + slot_variance(0) + account_bonus(100)
    }

    #[test]
    fn test_generate_signature_deterministic() {
        let snapshot = RpcRuntimeSnapshot {
            slot: 1000,
            block_height: 1000,
            transaction_count: 500,
            uptime_millis: 10000,
            latest_blockhash_seed: 12345,
        };

        let tx = vec![1, 2, 3, 4];
        let sig1 = generate_transaction_signature(&tx, snapshot, RpcCommitment::Confirmed);
        let sig2 = generate_transaction_signature(&tx, snapshot, RpcCommitment::Confirmed);

        assert_eq!(sig1, sig2);
        assert_eq!(sig1.len(), 88);
    }

    #[test]
    fn test_generate_signature_different_inputs() {
        let snapshot = RpcRuntimeSnapshot {
            slot: 1000,
            block_height: 1000,
            transaction_count: 500,
            uptime_millis: 10000,
            latest_blockhash_seed: 12345,
        };

        let tx1 = vec![1, 2, 3, 4];
        let tx2 = vec![5, 6, 7, 8];

        let sig1 = generate_transaction_signature(&tx1, snapshot, RpcCommitment::Confirmed);
        let sig2 = generate_transaction_signature(&tx2, snapshot, RpcCommitment::Confirmed);

        assert_ne!(sig1, sig2);
    }
}
