//! Constants for the feature gate system.
//!
//! Features control runtime behavior changes across the network.
//! Once activated at a given slot, a feature cannot be deactivated.

/// Number of slots after activation before a feature takes effect.
pub const FEATURE_ACTIVATION_DELAY_SLOTS: u64 = 0;

/// Maximum number of concurrently active features.
pub const MAX_ACTIVE_FEATURES: usize = 1000;

// ---------------------------------------------------------------------------
// VM-related feature gate names
// ---------------------------------------------------------------------------

/// Feature: enable the sol_alt_bn128_group_op syscall (BN254 G1 add/sub/mul/pairing).
pub const FEATURE_ENABLE_ALT_BN128_SYSCALL: &str = "enable_alt_bn128_syscall";

/// Feature: enable the sol_alt_bn128_compression syscall (compress/decompress G1/G2).
pub const FEATURE_ENABLE_ALT_BN128_COMPRESSION: &str = "enable_alt_bn128_compression_syscall";

/// Feature: enable the sol_poseidon syscall (Poseidon hash).
pub const FEATURE_ENABLE_POSEIDON_SYSCALL: &str = "enable_poseidon_syscall";

/// Feature: enable the sol_get_sysvar generic syscall (SIMD-0127).
pub const FEATURE_GET_SYSVAR_SYSCALL: &str = "get_sysvar_syscall_enabled";

/// Feature: enable the sol_get_epoch_stake syscall.
pub const FEATURE_ENABLE_GET_EPOCH_STAKE: &str = "enable_get_epoch_stake_syscall";

/// Feature: enable the BLS12-381 curve syscalls (decompress, pairing).
pub const FEATURE_ENABLE_BLS12_381_SYSCALL: &str = "enable_bls12_381_syscall";

// ---------------------------------------------------------------------------
// Vote / consensus feature gate names
// ---------------------------------------------------------------------------

/// Feature: V4 vote state format with landed votes.
pub const FEATURE_VOTE_STATE_V4: &str = "vote_state_v4";

/// Feature: enable TowerSync vote instruction.
pub const FEATURE_ENABLE_TOWER_SYNC_IX: &str = "enable_tower_sync_ix";

/// Feature: deprecate legacy vote instructions.
pub const FEATURE_DEPRECATE_LEGACY_VOTE_IXS: &str = "deprecate_legacy_vote_ixs";

/// Feature: vote-address-based leader schedule (VAT / SIMD-0387).
pub const FEATURE_ENABLE_VOTE_ADDRESS_LEADER_SCHEDULE: &str = "enable_vote_address_leader_schedule";

/// Feature: BLS proof-of-possession key management in vote accounts.
pub const FEATURE_BLS_PUBKEY_MANAGEMENT: &str = "bls_pubkey_management_in_vote_account";

// ---------------------------------------------------------------------------
// Block limit feature gate names
// ---------------------------------------------------------------------------

/// Feature: raise block CU limit to 60M (SIMD-0256).
pub const FEATURE_RAISE_BLOCK_LIMITS_TO_60M: &str = "raise_block_limits_to_60m";

/// Feature: raise block CU limit to 100M (SIMD-0286).
pub const FEATURE_RAISE_BLOCK_LIMITS_TO_100M: &str = "raise_block_limits_to_100m";

/// Feature: raise per-account CU limit to 40% of block limit (SIMD-0306).
pub const FEATURE_RAISE_ACCOUNT_CU_LIMIT: &str = "raise_account_cu_limit";

/// Feature: remove simple vote special-case from cost model.
pub const FEATURE_REMOVE_SIMPLE_VOTE_FROM_COST_MODEL: &str = "remove_simple_vote_from_cost_model";

// ---------------------------------------------------------------------------
// Runtime feature gate names
// ---------------------------------------------------------------------------

/// Feature: limit the number of accounts per instruction.
pub const FEATURE_LIMIT_INSTRUCTION_ACCOUNTS: &str = "limit_instruction_accounts";

/// Feature: relax programdata account ownership check during BPF migration.
pub const FEATURE_RELAX_PROGRAMDATA_ACCOUNT_CHECK: &str =
    "relax_programdata_account_check_migration";
