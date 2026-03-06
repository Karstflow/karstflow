/// Transaction cost model for the pack scheduler.
///
/// Computes the total block-space cost of a transaction, including:
/// - Per-signature costs (transaction + precompile signatures)
/// - Per-writable-account costs
/// - Instruction data byte costs
/// - Built-in program execution costs
/// - Loaded accounts data costs
///
/// Simple vote transactions use a fixed cost regardless of content.
use karstflow_ids::{
    BPF_LOADER_DEPRECATED_PROGRAM_ID, BPF_LOADER_V2_PROGRAM_ID, COMPUTE_BUDGET_PROGRAM_ID,
    ED25519_PRECOMPILE_PROGRAM_ID, LOADER_V4_PROGRAM_ID, SECP256K1_PRECOMPILE_PROGRAM_ID,
    SECP256R1_PRECOMPILE_PROGRAM_ID, SYSTEM_PROGRAM_ID, UPGRADEABLE_LOADER_PROGRAM_ID,
    VOTE_PROGRAM_ID,
};
use karstflow_types::Pubkey;

/// Cost per transaction signature (fee payer + additional signers).
pub const COST_PER_SIGNATURE: u64 = 720;

/// Cost per Ed25519 precompile signature verification.
pub const COST_PER_ED25519_SIGNATURE: u64 = 2_400;

/// Cost per secp256k1 precompile signature verification.
pub const COST_PER_SECP256K1_SIGNATURE: u64 = 6_690;

/// Cost per secp256r1 precompile signature verification.
pub const COST_PER_SECP256R1_SIGNATURE: u64 = 4_800;

/// Cost per writable account in the transaction.
pub const COST_PER_WRITABLE_ACCOUNT: u64 = 300;

/// Instruction data cost = data_bytes / INV_COST_PER_INSTR_DATA_BYTE (i.e. 0.25 CU per byte).
pub const INV_COST_PER_INSTR_DATA_BYTE: u64 = 4;

/// Default execution cost for built-in programs (post-SIMD-170).
pub const MAX_BUILTIN_CU_LIMIT: u64 = 200_000;

/// Default loaded accounts data cost (64 MiB default → 16384 CUs).
pub const DEFAULT_LOADED_ACCOUNTS_DATA_COST: u64 = 16_384;

/// Default compute units for a vote program instruction.
pub const VOTE_DEFAULT_COMPUTE_UNITS: u64 = 2_100;

/// Minimum transaction cost: one signature + one writable account.
pub const MIN_TXN_COST: u64 = COST_PER_SIGNATURE + COST_PER_WRITABLE_ACCOUNT;

/// Fixed cost for a simple vote transaction.
pub const SIMPLE_VOTE_COST: u64 =
    COST_PER_SIGNATURE + 2 * COST_PER_WRITABLE_ACCOUNT + VOTE_DEFAULT_COMPUTE_UNITS + 8;

/// Maximum theoretical transaction cost.
pub const MAX_TXN_COST: u64 = 1_573_166;

/// Check if a program ID is a known built-in program.
pub fn is_builtin_program(program_id: &Pubkey) -> bool {
    let builtins: &[Pubkey] = &[
        VOTE_PROGRAM_ID,
        SYSTEM_PROGRAM_ID,
        COMPUTE_BUDGET_PROGRAM_ID,
        UPGRADEABLE_LOADER_PROGRAM_ID,
        BPF_LOADER_DEPRECATED_PROGRAM_ID,
        BPF_LOADER_V2_PROGRAM_ID,
        LOADER_V4_PROGRAM_ID,
        SECP256K1_PRECOMPILE_PROGRAM_ID,
        ED25519_PRECOMPILE_PROGRAM_ID,
        SECP256R1_PRECOMPILE_PROGRAM_ID,
    ];
    builtins.contains(program_id)
}

/// Get the execution cost for a built-in program instruction.
/// Returns `Some(cost)` if the program is a known built-in, `None` otherwise.
pub fn builtin_execution_cost(program_id: &Pubkey) -> Option<u64> {
    if is_builtin_program(program_id) {
        Some(MAX_BUILTIN_CU_LIMIT)
    } else {
        None
    }
}

/// Input for cost computation.
#[derive(Debug, Clone)]
pub struct CostInput {
    /// Number of transaction signatures (signers).
    pub signature_count: u64,
    /// Number of writable accounts.
    pub writable_account_count: u64,
    /// Total instruction data bytes across all instructions.
    pub instruction_data_bytes: u64,
    /// Number of Ed25519 precompile signatures.
    pub ed25519_signature_count: u64,
    /// Number of secp256k1 precompile signatures.
    pub secp256k1_signature_count: u64,
    /// Number of secp256r1 precompile signatures.
    pub secp256r1_signature_count: u64,
    /// Execution cost (BPF + built-in).
    pub execution_cost: u64,
    /// Loaded accounts data cost.
    pub loaded_accounts_data_cost: u64,
    /// Whether this is a simple vote transaction.
    pub is_simple_vote: bool,
}

/// Result of cost computation.
#[derive(Debug, Clone, Copy)]
pub struct CostResult {
    /// Total transaction cost for block limit accounting.
    pub total_cost: u64,
    /// Execution cost component.
    pub execution_cost: u64,
    /// Whether this is a simple vote transaction.
    pub is_simple_vote: bool,
}

/// Compute the total cost of a transaction.
pub fn compute_cost(input: &CostInput) -> CostResult {
    if input.is_simple_vote {
        return CostResult {
            total_cost: SIMPLE_VOTE_COST,
            execution_cost: VOTE_DEFAULT_COMPUTE_UNITS,
            is_simple_vote: true,
        };
    }

    let signature_cost = COST_PER_SIGNATURE * input.signature_count
        + COST_PER_ED25519_SIGNATURE * input.ed25519_signature_count
        + COST_PER_SECP256K1_SIGNATURE * input.secp256k1_signature_count
        + COST_PER_SECP256R1_SIGNATURE * input.secp256r1_signature_count;

    let writable_cost = COST_PER_WRITABLE_ACCOUNT * input.writable_account_count;
    let instr_data_cost = input.instruction_data_bytes / INV_COST_PER_INSTR_DATA_BYTE;

    let total = signature_cost
        + writable_cost
        + input.execution_cost
        + instr_data_cost
        + input.loaded_accounts_data_cost;

    CostResult {
        total_cost: total,
        execution_cost: input.execution_cost,
        is_simple_vote: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_vote_has_fixed_cost() {
        let input = CostInput {
            signature_count: 1,
            writable_account_count: 2,
            instruction_data_bytes: 100,
            ed25519_signature_count: 0,
            secp256k1_signature_count: 0,
            secp256r1_signature_count: 0,
            execution_cost: 0,
            loaded_accounts_data_cost: 0,
            is_simple_vote: true,
        };
        let result = compute_cost(&input);
        assert_eq!(result.total_cost, SIMPLE_VOTE_COST);
        assert_eq!(result.execution_cost, VOTE_DEFAULT_COMPUTE_UNITS);
        assert!(result.is_simple_vote);
    }

    #[test]
    fn simple_vote_cost_matches_reference() {
        // 720 + 2*300 + 2100 + 8 = 3428
        assert_eq!(SIMPLE_VOTE_COST, 3_428);
    }

    #[test]
    fn minimum_cost_is_one_sig_one_writable() {
        assert_eq!(MIN_TXN_COST, 1_020);
    }

    #[test]
    fn signature_cost_breakdown() {
        let input = CostInput {
            signature_count: 2,
            writable_account_count: 1,
            instruction_data_bytes: 0,
            ed25519_signature_count: 3,
            secp256k1_signature_count: 1,
            secp256r1_signature_count: 0,
            execution_cost: 0,
            loaded_accounts_data_cost: 0,
            is_simple_vote: false,
        };
        let result = compute_cost(&input);
        // 2*720 + 3*2400 + 1*6690 + 1*300 = 1440 + 7200 + 6690 + 300 = 15630
        assert_eq!(result.total_cost, 15_630);
    }

    #[test]
    fn instruction_data_cost() {
        let input = CostInput {
            signature_count: 1,
            writable_account_count: 1,
            instruction_data_bytes: 100,
            ed25519_signature_count: 0,
            secp256k1_signature_count: 0,
            secp256r1_signature_count: 0,
            execution_cost: 0,
            loaded_accounts_data_cost: 0,
            is_simple_vote: false,
        };
        let result = compute_cost(&input);
        // 720 + 300 + 100/4 = 1045
        assert_eq!(result.total_cost, 1_045);
    }

    #[test]
    fn loaded_accounts_data_cost() {
        let input = CostInput {
            signature_count: 1,
            writable_account_count: 1,
            instruction_data_bytes: 0,
            ed25519_signature_count: 0,
            secp256k1_signature_count: 0,
            secp256r1_signature_count: 0,
            execution_cost: 200_000,
            loaded_accounts_data_cost: DEFAULT_LOADED_ACCOUNTS_DATA_COST,
            is_simple_vote: false,
        };
        let result = compute_cost(&input);
        // 720 + 300 + 200000 + 16384 = 217404
        assert_eq!(result.total_cost, 217_404);
    }

    #[test]
    fn builtin_program_detection() {
        assert!(is_builtin_program(&VOTE_PROGRAM_ID));
        assert!(is_builtin_program(&SYSTEM_PROGRAM_ID));
        assert!(is_builtin_program(&COMPUTE_BUDGET_PROGRAM_ID));
        assert!(is_builtin_program(&UPGRADEABLE_LOADER_PROGRAM_ID));
        assert!(is_builtin_program(&SECP256K1_PRECOMPILE_PROGRAM_ID));
        assert!(is_builtin_program(&ED25519_PRECOMPILE_PROGRAM_ID));
        assert!(is_builtin_program(&SECP256R1_PRECOMPILE_PROGRAM_ID));
        assert!(!is_builtin_program(&Pubkey::new([0xFF; 32])));
    }

    #[test]
    fn builtin_execution_cost_returns_max() {
        assert_eq!(
            builtin_execution_cost(&VOTE_PROGRAM_ID),
            Some(MAX_BUILTIN_CU_LIMIT)
        );
        assert_eq!(builtin_execution_cost(&Pubkey::new([0xFF; 32])), None);
    }

    #[test]
    fn secp256r1_signature_cost() {
        let input = CostInput {
            signature_count: 1,
            writable_account_count: 1,
            instruction_data_bytes: 0,
            ed25519_signature_count: 0,
            secp256k1_signature_count: 0,
            secp256r1_signature_count: 2,
            execution_cost: 0,
            loaded_accounts_data_cost: 0,
            is_simple_vote: false,
        };
        let result = compute_cost(&input);
        // 720 + 300 + 2*4800 = 10620
        assert_eq!(result.total_cost, 10_620);
    }

    #[test]
    fn combined_precompile_signatures() {
        let input = CostInput {
            signature_count: 1,
            writable_account_count: 1,
            instruction_data_bytes: 0,
            ed25519_signature_count: 1,
            secp256k1_signature_count: 1,
            secp256r1_signature_count: 1,
            execution_cost: 0,
            loaded_accounts_data_cost: 0,
            is_simple_vote: false,
        };
        let result = compute_cost(&input);
        // 720 + 300 + 2400 + 6690 + 4800 = 14910
        assert_eq!(result.total_cost, 14_910);
    }
}
