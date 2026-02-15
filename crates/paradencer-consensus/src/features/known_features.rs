//! Known feature gate identifiers.
//!
//! Each feature is identified by a unique pubkey derived deterministically
//! from a descriptive name via SHA-256. Features control runtime behavior
//! changes and are activated on-chain through governance.

use super::FeatureActivation;
use paradencer_types::Pubkey;
use sha2::{Digest, Sha256};

/// Derive a deterministic feature ID from a descriptive name.
///
/// Computes `SHA-256(name)` and uses the 32-byte digest as the pubkey.
pub fn feature_id(name: &str) -> Pubkey {
    let hash = Sha256::digest(name.as_bytes());
    let bytes: [u8; 32] = hash.into();
    Pubkey::new(bytes)
}

// --- Named feature accessors for programmatic use ---

/// Require that program IDs in instructions are statically known.
pub fn require_static_program_ids() -> Pubkey {
    feature_id("require_static_program_ids_in_transaction")
}

/// Award vote credits proportional to stake dequeue position.
pub fn vote_state_update_credit_per_dequeue() -> Pubkey {
    feature_id("vote_state_update_credit_per_dequeue")
}

/// Enable partitioned distribution of epoch rewards.
pub fn enable_partitioned_epoch_reward() -> Pubkey {
    feature_id("enable_partitioned_epoch_reward")
}

/// Remove deprecated rewards sysvar.
pub fn deprecate_rewards_sysvar() -> Pubkey {
    feature_id("deprecate_rewards_sysvar")
}

/// Allow zero-lamport accounts under certain conditions.
pub fn enable_zero_lamport_accounts() -> Pubkey {
    feature_id("enable_zero_lamport_accounts")
}

/// Reduce required stake warmup and cooldown period.
pub fn reduce_stake_warmup_cooldown() -> Pubkey {
    feature_id("reduce_stake_warmup_cooldown")
}

/// Charge transaction fees to the first writable signer account.
pub fn charge_fee_to_first_writable_signer() -> Pubkey {
    feature_id("charge_fee_to_first_writable_signer")
}

/// Enable the BPF Loader v4 program.
pub fn enable_loader_v4() -> Pubkey {
    feature_id("enable_loader_v4_program")
}

/// Enable CPI guard for inner instructions.
pub fn enable_cpi_guard() -> Pubkey {
    feature_id("enable_cpi_guard")
}

/// Enable Address Lookup Table program for v0 transactions.
pub fn enable_address_lookup_table() -> Pubkey {
    feature_id("enable_address_lookup_table_program")
}

/// Drop legacy shred support.
pub fn drop_legacy_shreds() -> Pubkey {
    feature_id("drop_legacy_shreds")
}

/// Enable Tower BFT synchronization.
pub fn enable_tower_sync() -> Pubkey {
    feature_id("enable_tower_sync")
}

/// Switch to vote state v3 layout.
pub fn enable_vote_state_v3() -> Pubkey {
    feature_id("enable_vote_state_v3")
}

/// Allow programs to resize account data.
pub fn enable_program_realloc() -> Pubkey {
    feature_id("enable_program_realloc")
}

/// Restrict commission updates to the first half of an epoch.
pub fn commission_updates_first_half_only() -> Pubkey {
    feature_id("commission_updates_only_allowed_in_first_half_of_epoch")
}

/// Enable durable transaction nonces.
pub fn enable_durable_nonce() -> Pubkey {
    feature_id("enable_durable_nonce")
}

/// Enable secp256r1 precompile program.
pub fn enable_secp256r1_precompile() -> Pubkey {
    feature_id("enable_secp256r1_precompile")
}

/// Enable stake move instructions.
pub fn enable_stake_move() -> Pubkey {
    feature_id("enable_stake_move_instructions")
}

/// Simplify writable program account ownership check.
pub fn simplify_writable_program_account_check() -> Pubkey {
    feature_id("simplify_writable_program_account_check")
}

/// Last restart slot sysvar.
pub fn last_restart_slot_sysvar() -> Pubkey {
    feature_id("last_restart_slot_sysvar")
}

/// Increase CPI call depth limit.
pub fn increase_cpi_depth_limit() -> Pubkey {
    feature_id("increase_cpi_call_depth_limit")
}

/// Partitioned epoch rewards superfeature.
pub fn partitioned_epoch_rewards_superfeature() -> Pubkey {
    feature_id("partitioned_epoch_rewards_superfeature")
}

/// Updated bank hash algorithm.
pub fn update_bank_hash_algorithm() -> Pubkey {
    feature_id("update_bank_hash_algorithm")
}

/// Remove deprecated vote instructions.
pub fn remove_deprecated_vote_instructions() -> Pubkey {
    feature_id("remove_deprecated_vote_instructions")
}

/// Enable ZK Token proof program.
pub fn enable_zk_token_proof() -> Pubkey {
    feature_id("enable_zk_token_sdk")
}

/// Enable Token-2022 program with extensions.
pub fn enable_token_2022() -> Pubkey {
    feature_id("enable_token_2022_program")
}

/// Enable priority fees via compute budget instructions.
pub fn enable_priority_fees() -> Pubkey {
    feature_id("enable_priority_fees")
}

/// Validate fee payer balance before execution.
pub fn validate_fee_payer_balance() -> Pubkey {
    feature_id("validate_fee_collector_account")
}

/// Enable loaded accounts data size tracking.
pub fn enable_loaded_accounts_data_size() -> Pubkey {
    feature_id("enable_loaded_accounts_data_size_limit")
}

/// Feature name strings for all known features.
///
/// Used to build FeatureActivation lists and to populate the FeatureSet.
const KNOWN_FEATURE_NAMES: &[&str] = &[
    "require_static_program_ids_in_transaction",
    "vote_state_update_credit_per_dequeue",
    "enable_partitioned_epoch_reward",
    "deprecate_rewards_sysvar",
    "enable_zero_lamport_accounts",
    "reduce_stake_warmup_cooldown",
    "charge_fee_to_first_writable_signer",
    "enable_loader_v4_program",
    "enable_cpi_guard",
    "enable_address_lookup_table_program",
    "drop_legacy_shreds",
    "enable_tower_sync",
    "enable_vote_state_v3",
    "enable_program_realloc",
    "commission_updates_only_allowed_in_first_half_of_epoch",
    "enable_durable_nonce",
    "enable_secp256r1_precompile",
    "enable_stake_move_instructions",
    "simplify_writable_program_account_check",
    "last_restart_slot_sysvar",
    "increase_cpi_call_depth_limit",
    "partitioned_epoch_rewards_superfeature",
    "update_bank_hash_algorithm",
    "remove_deprecated_vote_instructions",
    "enable_zk_token_sdk",
    "enable_token_2022_program",
    "enable_priority_fees",
    "validate_fee_collector_account",
    "enable_loaded_accounts_data_size_limit",
];

/// Placeholder used by FeatureSet constructors. Returns all known feature
/// activations as a freshly allocated vector.
pub fn all_known_features() -> Vec<FeatureActivation> {
    KNOWN_FEATURE_NAMES
        .iter()
        .map(|name| FeatureActivation {
            feature_id: feature_id(name),
            activation_slot: None,
            description: name,
        })
        .collect()
}
