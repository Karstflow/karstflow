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

// Compute costs for sysvar access
pub const GET_SYSVAR_COST: u64 = 100;

// Compute costs for return data
pub const SET_RETURN_DATA_COST: u64 = 100;
pub const SET_RETURN_DATA_PER_BYTE: u64 = 1;
pub const GET_RETURN_DATA_COST: u64 = 100;

// Miscellaneous syscall costs
pub const GET_STACK_HEIGHT_COST: u64 = 5;
pub const GET_PROCESSED_SIBLING_INSTRUCTION_COST: u64 = 100;

// alt_bn128 curve operation costs
pub const ALT_BN128_ADD_COST: u64 = 334;
pub const ALT_BN128_MUL_COST: u64 = 3_840;
pub const ALT_BN128_PAIRING_BASE_COST: u64 = 36_364;
pub const ALT_BN128_PAIRING_PER_PAIR_COST: u64 = 12_121;

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
