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
