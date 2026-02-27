//! Constants for syscall operations in the sBPF virtual machine.
//!
//! These define compute costs, limits, and thresholds for all syscalls
//! available to on-chain programs during execution.

// CPI limits
pub const MAX_CPI_DEPTH: usize = 4;
pub const MAX_CPI_INSTRUCTION_SIZE: usize = 1280;
pub const MAX_CPI_INSTRUCTION_ACCOUNTS: usize = 255;
pub const MAX_CPI_ACCOUNT_INFOS: usize = 128;
pub const MAX_RETURN_DATA_SIZE: usize = 1024;
pub const MAX_SIGNER_SEEDS: usize = 16;
pub const MAX_SEED_BYTES: usize = 32;
/// Maximum number of PDA signers per CPI call.
pub const MAX_CPI_SIGNERS: usize = 16;

// Compute costs for cryptographic hash operations
pub const SHA256_BASE_COST: u64 = 100;
pub const SHA256_PER_BYTE_COST: u64 = 2;
pub const KECCAK256_BASE_COST: u64 = 100;
pub const KECCAK256_PER_BYTE_COST: u64 = 2;
pub const BLAKE3_BASE_COST: u64 = 100;
pub const BLAKE3_PER_BYTE_COST: u64 = 2;
pub const SECP256K1_RECOVER_COST: u64 = 25_000;

// Compute costs for PDA operations
pub const CREATE_PROGRAM_ADDRESS_COST: u64 = 1500;
pub const FIND_PROGRAM_ADDRESS_COST: u64 = 1500;
pub const FIND_PROGRAM_ADDRESS_PER_ITERATION: u64 = 550;

// Compute costs for CPI
pub const CPI_BASE_COST: u64 = 1000;
pub const CPI_PER_ACCOUNT_COST: u64 = 100;
pub const CPI_PER_DATA_BYTE_COST: u64 = 1;

// Compute costs for memory operations
pub const MEMCPY_BASE_COST: u64 = 10;
pub const MEMCPY_PER_BYTE_COST: u64 = 1;
pub const MEMCMP_BASE_COST: u64 = 10;
pub const MEMCMP_PER_BYTE_COST: u64 = 1;
pub const MEMSET_BASE_COST: u64 = 10;
pub const MEMSET_PER_BYTE_COST: u64 = 1;

// Compute costs for logging
pub const LOG_BASE_COST: u64 = 100;
pub const LOG_PER_BYTE_COST: u64 = 1;
pub const LOG_DATA_BASE_COST: u64 = 100;
pub const LOG_COMPUTE_UNITS_COST: u64 = 100;
/// Maximum total bytes of log messages per transaction before truncation.
pub const MAX_LOG_COLLECTOR_SIZE: usize = 10_000;

// Compute costs for sysvar access
pub const GET_SYSVAR_COST: u64 = 100;

// Compute costs for return data
pub const SET_RETURN_DATA_COST: u64 = 100;
pub const SET_RETURN_DATA_PER_BYTE: u64 = 1;
pub const GET_RETURN_DATA_COST: u64 = 100;

// Miscellaneous syscall costs
pub const GET_STACK_HEIGHT_COST: u64 = 5;
pub const GET_PROCESSED_SIBLING_INSTRUCTION_COST: u64 = 100;
pub const LOG_PUBKEY_COST: u64 = 100;
pub const GET_EPOCH_REWARDS_SYSVAR_COST: u64 = 100;
pub const GET_GENERIC_SYSVAR_BASE_COST: u64 = 100;
pub const GET_GENERIC_SYSVAR_PER_BYTE_COST: u64 = 1;
pub const GET_EPOCH_STAKE_COST: u64 = 100;
pub const GET_REMAINING_COMPUTE_UNITS_COST: u64 = 100;

/// Maximum length for a single generic sysvar read.
pub const MAX_GENERIC_SYSVAR_READ_LEN: usize = 10 * 1024;

// alt_bn128 (BN254) curve operation costs — G1
pub const ALT_BN128_G1_ADD_COST: u64 = 334;
pub const ALT_BN128_G1_MUL_COST: u64 = 3_840;

// alt_bn128 (BN254) curve operation costs — G2
pub const ALT_BN128_G2_ADD_COST: u64 = 535;
pub const ALT_BN128_G2_MUL_COST: u64 = 15_670;

// alt_bn128 pairing costs
pub const ALT_BN128_PAIRING_FIRST_PAIR_COST: u64 = 36_364;
pub const ALT_BN128_PAIRING_EACH_ADDITIONAL_PAIR_COST: u64 = 12_121;

// alt_bn128 compression/decompression costs
pub const ALT_BN128_G1_COMPRESS_COST: u64 = 30;
pub const ALT_BN128_G1_DECOMPRESS_COST: u64 = 398;
pub const ALT_BN128_G2_COMPRESS_COST: u64 = 86;
pub const ALT_BN128_G2_DECOMPRESS_COST: u64 = 13_610;

// Backwards-compatible aliases used by existing code
pub const ALT_BN128_ADD_COST: u64 = ALT_BN128_G1_ADD_COST;
pub const ALT_BN128_MUL_COST: u64 = ALT_BN128_G1_MUL_COST;
pub const ALT_BN128_PAIRING_BASE_COST: u64 = ALT_BN128_PAIRING_FIRST_PAIR_COST;
pub const ALT_BN128_PAIRING_PER_PAIR_COST: u64 = ALT_BN128_PAIRING_EACH_ADDITIONAL_PAIR_COST;

// alt_bn128 group operation IDs (big-endian variants)
pub const ALT_BN128_G1_ADD_BE: u64 = 0;
pub const ALT_BN128_G1_SUB_BE: u64 = 1;
pub const ALT_BN128_G1_MUL_BE: u64 = 2;
pub const ALT_BN128_PAIRING_BE: u64 = 3;
pub const ALT_BN128_G2_ADD_BE: u64 = 4;
pub const ALT_BN128_G2_SUB_BE: u64 = 5;
pub const ALT_BN128_G2_MUL_BE: u64 = 6;

/// Bit flag that converts a big-endian op ID to its little-endian variant (SIMD-0284).
pub const ALT_BN128_LITTLE_ENDIAN_FLAG: u64 = 0x80;

// alt_bn128 compression operation IDs (big-endian variants)
pub const ALT_BN128_G1_COMPRESS_BE: u64 = 0;
pub const ALT_BN128_G1_DECOMPRESS_BE: u64 = 1;
pub const ALT_BN128_G2_COMPRESS_BE: u64 = 2;
pub const ALT_BN128_G2_DECOMPRESS_BE: u64 = 3;

// alt_bn128 point sizes
pub const ALT_BN128_G1_POINT_SIZE: usize = 64;
pub const ALT_BN128_G1_COMPRESSED_SIZE: usize = 32;
pub const ALT_BN128_G2_POINT_SIZE: usize = 128;
pub const ALT_BN128_G2_COMPRESSED_SIZE: usize = 64;
pub const ALT_BN128_SCALAR_SIZE: usize = 32;
pub const ALT_BN128_PAIRING_PAIR_SIZE: usize = 192;
pub const ALT_BN128_PAIRING_OUTPUT_SIZE: usize = 32;

// Poseidon hash costs: cost = A * n^2 + C, where n = number of inputs
pub const POSEIDON_COST_COEFFICIENT_A: u64 = 61;
pub const POSEIDON_COST_COEFFICIENT_C: u64 = 542;
/// Maximum number of input values for a single Poseidon hash.
pub const POSEIDON_MAX_INPUTS: usize = 12;
/// Poseidon parameter set: Light protocol BN254 x5.
pub const POSEIDON_PARAMS_LIGHT: u64 = 0;
/// Poseidon endianness: big-endian input.
pub const POSEIDON_ENDIAN_BIG: u64 = 0;
/// Poseidon endianness: little-endian input.
pub const POSEIDON_ENDIAN_LITTLE: u64 = 1;

// Syscall base cost (used by compression syscall)
pub const SYSCALL_BASE_COST: u64 = 100;

// Curve25519 (ed25519 / ristretto255) operation costs
pub const CURVE25519_EDWARDS_VALIDATE_POINT_COST: u64 = 159;
pub const CURVE25519_EDWARDS_ADD_COST: u64 = 473;
pub const CURVE25519_EDWARDS_SUB_COST: u64 = 473;
pub const CURVE25519_EDWARDS_MUL_COST: u64 = 2_177;
pub const CURVE25519_EDWARDS_MSM_BASE_COST: u64 = 2_177;
pub const CURVE25519_EDWARDS_MSM_INCREMENTAL_COST: u64 = 788;
pub const CURVE25519_RISTRETTO_VALIDATE_POINT_COST: u64 = 169;
pub const CURVE25519_RISTRETTO_ADD_COST: u64 = 521;
pub const CURVE25519_RISTRETTO_SUB_COST: u64 = 521;
pub const CURVE25519_RISTRETTO_MUL_COST: u64 = 2_208;
pub const CURVE25519_RISTRETTO_MSM_BASE_COST: u64 = 2_208;
pub const CURVE25519_RISTRETTO_MSM_INCREMENTAL_COST: u64 = 788;

// Curve IDs for sol_curve_* syscalls
pub const CURVE_ID_ED25519: u64 = 0;
pub const CURVE_ID_RISTRETTO255: u64 = 1;

// Group operation IDs for sol_curve_group_op
pub const CURVE_OP_ADD: u64 = 0;
pub const CURVE_OP_SUB: u64 = 1;
pub const CURVE_OP_MUL: u64 = 2;

// BLS12-381 curve IDs for sol_curve_decompress and sol_curve_pairing_map
pub const CURVE_ID_BLS12_381_G1: u64 = 4;
pub const CURVE_ID_BLS12_381_G2: u64 = 6;
/// Bit flag for little-endian byte order on BLS12-381 operations.
pub const BLS12_381_LITTLE_ENDIAN_FLAG: u64 = 0x80;

// BLS12-381 point sizes (uncompressed)
pub const BLS12_381_G1_POINT_SIZE: usize = 96;
pub const BLS12_381_G2_POINT_SIZE: usize = 192;
pub const BLS12_381_GT_ELEMENT_SIZE: usize = 576;
// BLS12-381 point sizes (compressed)
pub const BLS12_381_G1_COMPRESSED_SIZE: usize = 48;
pub const BLS12_381_G2_COMPRESSED_SIZE: usize = 96;
/// Maximum number of pairs in a single pairing batch operation.
pub const BLS12_381_MAX_PAIRING_PAIRS: usize = 8;

// BLS12-381 compute costs
pub const BLS12_381_G1_DECOMPRESS_COST: u64 = 1_000;
pub const BLS12_381_G2_DECOMPRESS_COST: u64 = 2_500;
pub const BLS12_381_PAIRING_BASE_COST: u64 = 75_000;
pub const BLS12_381_PAIRING_PER_PAIR_COST: u64 = 45_000;

// Panic syscall cost (per byte of message)
pub const PANIC_PER_BYTE_COST: u64 = 1;
