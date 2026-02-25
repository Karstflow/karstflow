/// Transaction cost calculator for the pack scheduler.
///
/// Computes a detailed cost breakdown for each transaction before it enters
/// the scheduling queue. The cost model is consensus-critical — every
/// validator must compute identical costs for the same transaction.
///
/// Cost components:
/// - Signature verification cost
/// - Writable account lock cost
/// - Instruction data cost (proportional to instruction payload size)
/// - Execution cost (from ComputeBudget program or per-builtin defaults)
/// - Loaded accounts data cost
/// - Precompile verification cost (Ed25519, secp256k1, secp256r1)
use paradencer_constants::block_limits::{
    COST_PER_WRITABLE_ACCOUNT, ED25519_PRECOMPILE_COST_PER_SIGNATURE, HEAP_COST_PER_KILOBYTE,
    INSTRUCTION_DATA_BYTES_PER_CU, LOADED_ACCOUNTS_DATA_COST_DIVISOR,
    LOADED_ACCOUNTS_DATA_PAGE_COST, MAX_BUILTIN_PROGRAM_COST,
    SECP256K1_PRECOMPILE_COST_PER_SIGNATURE, SECP256R1_PRECOMPILE_COST_PER_SIGNATURE,
    SIGNATURE_COST, SIMPLE_VOTE_EXECUTION_COST,
};
use paradencer_constants::compute_budget_program::{
    INSTRUCTION_REQUEST_HEAP_FRAME, INSTRUCTION_SET_COMPUTE_UNIT_LIMIT,
    INSTRUCTION_SET_COMPUTE_UNIT_PRICE, INSTRUCTION_SET_LOADED_ACCOUNTS_DATA_SIZE_LIMIT,
};
use paradencer_constants::execution::{
    DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT, MAX_COMPUTE_UNIT_LIMIT,
};
use paradencer_ids::{
    COMPUTE_BUDGET_PROGRAM_ID, ED25519_PROGRAM_ID, SECP256K1_PROGRAM_ID, SECP256R1_PROGRAM_ID,
    VOTE_PROGRAM_ID,
};
use paradencer_types::Pubkey;

// ---------------------------------------------------------------------------
// Cost breakdown result
// ---------------------------------------------------------------------------

/// Detailed cost breakdown for a single transaction.
///
/// All fields are in compute units (CU). The `total_cost` equals the sum
/// of all individual cost components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionCost {
    /// Total transaction cost (sum of all components).
    pub total_cost: u64,
    /// Cost of verifying transaction signatures.
    pub signature_cost: u64,
    /// Cost of acquiring writable account locks.
    pub writable_account_cost: u64,
    /// Cost proportional to total instruction data size.
    pub instruction_data_cost: u64,
    /// Requested execution compute units (from ComputeBudget or defaults).
    pub execution_cost: u64,
    /// Cost of loading account data from storage.
    pub loaded_accounts_data_cost: u64,
    /// Priority fee per compute unit (micro-lamports).
    pub compute_unit_price: u64,
    /// Whether this transaction qualifies as a simple vote.
    pub is_simple_vote: bool,
    /// Total number of transaction signatures.
    pub num_transaction_signatures: u64,
    /// Number of precompile verification signatures.
    pub num_precompile_signatures: u64,
}

impl TransactionCost {
    /// Non-execution cost (everything except execution_cost and loaded_accounts_data_cost).
    pub fn non_execution_cost(&self) -> u64 {
        self.signature_cost
            .saturating_add(self.writable_account_cost)
            .saturating_add(self.instruction_data_cost)
    }

    /// Execution plus loaded accounts data cost combined.
    pub fn execution_and_data_cost(&self) -> u64 {
        self.execution_cost
            .saturating_add(self.loaded_accounts_data_cost)
    }

    /// Total fee in lamports (signature fees + priority fee).
    pub fn total_fee_lamports(&self, fee_per_signature: u64) -> u64 {
        let sig_fee = self
            .num_transaction_signatures
            .saturating_add(self.num_precompile_signatures)
            .saturating_mul(fee_per_signature);
        let priority_fee = self.execution_cost.saturating_mul(self.compute_unit_price);
        // Priority fee is in micro-lamports per CU, convert to lamports.
        let priority_fee_lamports = priority_fee / 1_000_000;
        sig_fee.saturating_add(priority_fee_lamports)
    }
}

// ---------------------------------------------------------------------------
// Instruction reference (lightweight view into transaction)
// ---------------------------------------------------------------------------

/// Lightweight reference to an instruction within a transaction.
///
/// Used by the cost model to inspect instructions without copying.
#[derive(Debug, Clone)]
pub struct InstructionView<'a> {
    /// Program ID that processes this instruction.
    pub program_id: &'a Pubkey,
    /// Instruction data payload.
    pub data: &'a [u8],
}

// ---------------------------------------------------------------------------
// Cost calculator
// ---------------------------------------------------------------------------

/// Compute the full cost breakdown for a transaction.
///
/// Parameters:
/// - `instructions`: Slice of instruction views from the transaction
/// - `num_signatures`: Number of transaction signatures
/// - `num_writable_accounts`: Number of writable accounts (excluding fee payer duplicates)
/// - `is_vote`: Whether the transaction targets the vote program
///
/// The function parses ComputeBudget program instructions to extract
/// custom CU limits and prices, counts precompile signatures, and
/// computes the consensus-correct cost for pack scheduling.
pub fn compute_transaction_cost(
    instructions: &[InstructionView<'_>],
    num_signatures: u64,
    num_writable_accounts: usize,
    is_vote: bool,
) -> TransactionCost {
    // Simple vote fast path: fixed cost, skip detailed analysis.
    if is_vote && is_simple_vote(instructions) {
        let signature_cost = num_signatures.saturating_mul(SIGNATURE_COST);
        let writable_cost =
            (num_writable_accounts as u64).saturating_mul(COST_PER_WRITABLE_ACCOUNT);
        let total = signature_cost
            .saturating_add(writable_cost)
            .saturating_add(SIMPLE_VOTE_EXECUTION_COST);

        return TransactionCost {
            total_cost: total,
            signature_cost,
            writable_account_cost: writable_cost,
            instruction_data_cost: 0,
            execution_cost: SIMPLE_VOTE_EXECUTION_COST,
            loaded_accounts_data_cost: 0,
            compute_unit_price: 0,
            is_simple_vote: true,
            num_transaction_signatures: num_signatures,
            num_precompile_signatures: 0,
        };
    }

    // Parse ComputeBudget instructions for overrides.
    let budget_params = parse_compute_budget_instructions(instructions);

    // Signature cost.
    let signature_cost = num_signatures.saturating_mul(SIGNATURE_COST);

    // Writable account cost.
    let writable_cost = (num_writable_accounts as u64).saturating_mul(COST_PER_WRITABLE_ACCOUNT);

    // Instruction data cost.
    let total_data_bytes: u64 = instructions.iter().map(|ix| ix.data.len() as u64).sum();
    let instruction_data_cost = total_data_bytes / INSTRUCTION_DATA_BYTES_PER_CU;

    // Execution cost: use ComputeBudget override or count per-instruction defaults.
    let execution_cost = if let Some(limit) = budget_params.compute_unit_limit {
        limit
    } else {
        compute_default_execution_cost(instructions)
    };

    // Precompile signature costs.
    let precompile_sigs = count_precompile_signatures(instructions);
    let precompile_cost = precompile_sigs
        .ed25519
        .saturating_mul(ED25519_PRECOMPILE_COST_PER_SIGNATURE)
        .saturating_add(
            precompile_sigs
                .secp256k1
                .saturating_mul(SECP256K1_PRECOMPILE_COST_PER_SIGNATURE),
        )
        .saturating_add(
            precompile_sigs
                .secp256r1
                .saturating_mul(SECP256R1_PRECOMPILE_COST_PER_SIGNATURE),
        );

    // Loaded accounts data cost: ceil(declared_size / page_size) * page_cost.
    let loaded_accounts_data_cost =
        if let Some(declared_size) = budget_params.loaded_accounts_data_size {
            let pages = declared_size.saturating_add(LOADED_ACCOUNTS_DATA_COST_DIVISOR - 1)
                / LOADED_ACCOUNTS_DATA_COST_DIVISOR;
            pages.saturating_mul(LOADED_ACCOUNTS_DATA_PAGE_COST)
        } else {
            0
        };

    // Heap cost (included in execution cost implicitly, but tracked).
    let _heap_cost = budget_params
        .heap_size_bytes
        .map(|h| (h as u64 / 1024).saturating_mul(HEAP_COST_PER_KILOBYTE))
        .unwrap_or(0);

    let total_precompile_sigs =
        precompile_sigs.ed25519 + precompile_sigs.secp256k1 + precompile_sigs.secp256r1;

    let total_cost = signature_cost
        .saturating_add(writable_cost)
        .saturating_add(instruction_data_cost)
        .saturating_add(execution_cost)
        .saturating_add(precompile_cost)
        .saturating_add(loaded_accounts_data_cost);

    TransactionCost {
        total_cost,
        signature_cost,
        writable_account_cost: writable_cost,
        instruction_data_cost,
        execution_cost,
        loaded_accounts_data_cost,
        compute_unit_price: budget_params.compute_unit_price.unwrap_or(0),
        is_simple_vote: false,
        num_transaction_signatures: num_signatures,
        num_precompile_signatures: total_precompile_sigs,
    }
}

// ---------------------------------------------------------------------------
// ComputeBudget instruction parser
// ---------------------------------------------------------------------------

/// Parsed parameters from ComputeBudget program instructions.
#[derive(Debug, Clone, Default)]
struct ComputeBudgetParams {
    /// Explicit compute unit limit (from SetComputeUnitLimit).
    compute_unit_limit: Option<u64>,
    /// Compute unit price in micro-lamports (from SetComputeUnitPrice).
    compute_unit_price: Option<u64>,
    /// Requested heap size in bytes (from RequestHeapFrame).
    heap_size_bytes: Option<u32>,
    /// Declared loaded accounts data size (from SetLoadedAccountsDataSizeLimit).
    loaded_accounts_data_size: Option<u64>,
}

/// Parse ComputeBudget program instructions from a transaction.
///
/// Only the first occurrence of each instruction type is honored.
/// Duplicate instructions are ignored (matches Solana behavior).
fn parse_compute_budget_instructions(instructions: &[InstructionView<'_>]) -> ComputeBudgetParams {
    let mut params = ComputeBudgetParams::default();

    for ix in instructions {
        if *ix.program_id != COMPUTE_BUDGET_PROGRAM_ID {
            continue;
        }

        if ix.data.is_empty() {
            continue;
        }

        match ix.data[0] {
            INSTRUCTION_SET_COMPUTE_UNIT_LIMIT => {
                if params.compute_unit_limit.is_none() && ix.data.len() >= 5 {
                    let limit =
                        u32::from_le_bytes([ix.data[1], ix.data[2], ix.data[3], ix.data[4]]);
                    params.compute_unit_limit = Some((limit as u64).min(MAX_COMPUTE_UNIT_LIMIT));
                }
            }
            INSTRUCTION_SET_COMPUTE_UNIT_PRICE => {
                if params.compute_unit_price.is_none() && ix.data.len() >= 9 {
                    let price = u64::from_le_bytes([
                        ix.data[1], ix.data[2], ix.data[3], ix.data[4], ix.data[5], ix.data[6],
                        ix.data[7], ix.data[8],
                    ]);
                    params.compute_unit_price = Some(price);
                }
            }
            INSTRUCTION_REQUEST_HEAP_FRAME => {
                if params.heap_size_bytes.is_none() && ix.data.len() >= 5 {
                    let size = u32::from_le_bytes([ix.data[1], ix.data[2], ix.data[3], ix.data[4]]);
                    params.heap_size_bytes = Some(size);
                }
            }
            INSTRUCTION_SET_LOADED_ACCOUNTS_DATA_SIZE_LIMIT => {
                if params.loaded_accounts_data_size.is_none() && ix.data.len() >= 5 {
                    let size = u32::from_le_bytes([ix.data[1], ix.data[2], ix.data[3], ix.data[4]]);
                    params.loaded_accounts_data_size = Some(size as u64);
                }
            }
            _ => {}
        }
    }

    params
}

// ---------------------------------------------------------------------------
// Simple vote detection
// ---------------------------------------------------------------------------

/// Check if a transaction is a simple vote (one vote instruction, optional
/// ComputeBudget instructions, nothing else).
fn is_simple_vote(instructions: &[InstructionView<'_>]) -> bool {
    let mut vote_count = 0u32;
    let mut other_count = 0u32;

    for ix in instructions {
        if *ix.program_id == VOTE_PROGRAM_ID {
            vote_count += 1;
        } else if *ix.program_id == COMPUTE_BUDGET_PROGRAM_ID {
            // ComputeBudget instructions are allowed in simple votes.
        } else {
            other_count += 1;
        }
    }

    vote_count == 1 && other_count == 0
}

// ---------------------------------------------------------------------------
// Default execution cost (no ComputeBudget override)
// ---------------------------------------------------------------------------

/// Compute default execution cost when no SetComputeUnitLimit is present.
///
/// Each non-ComputeBudget instruction gets a default allocation. Builtin
/// programs (those in the known set) get MAX_BUILTIN_PROGRAM_COST.
/// User programs get DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT.
fn compute_default_execution_cost(instructions: &[InstructionView<'_>]) -> u64 {
    let mut total = 0u64;

    for ix in instructions {
        if *ix.program_id == COMPUTE_BUDGET_PROGRAM_ID {
            // ComputeBudget instructions don't contribute to execution cost.
            continue;
        }

        if is_builtin_program(ix.program_id) || is_precompile_program(ix.program_id) {
            total = total.saturating_add(MAX_BUILTIN_PROGRAM_COST);
        } else {
            total = total.saturating_add(DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT);
        }
    }

    total.min(MAX_COMPUTE_UNIT_LIMIT)
}

/// Check if a program ID is a known builtin program.
fn is_builtin_program(program_id: &Pubkey) -> bool {
    *program_id == paradencer_ids::SYSTEM_PROGRAM_ID
        || *program_id == paradencer_ids::VOTE_PROGRAM_ID
        || *program_id == paradencer_ids::STAKE_PROGRAM_ID
        || *program_id == paradencer_ids::CONFIG_PROGRAM_ID
        || *program_id == paradencer_ids::BPF_LOADER_PROGRAM_ID
        || *program_id == paradencer_ids::BPF_LOADER_DEPRECATED_PROGRAM_ID
        || *program_id == paradencer_ids::UPGRADEABLE_LOADER_PROGRAM_ID
        || *program_id == paradencer_ids::LOADER_V4_PROGRAM_ID
        || *program_id == paradencer_ids::COMPUTE_BUDGET_PROGRAM_ID
        || *program_id == paradencer_ids::ADDRESS_LOOKUP_TABLE_PROGRAM_ID
}

/// Check if a program ID is a precompile.
fn is_precompile_program(program_id: &Pubkey) -> bool {
    *program_id == ED25519_PROGRAM_ID
        || *program_id == SECP256K1_PROGRAM_ID
        || *program_id == SECP256R1_PROGRAM_ID
}

// ---------------------------------------------------------------------------
// Precompile signature counting
// ---------------------------------------------------------------------------

/// Counts of signatures verified by each precompile program.
#[derive(Debug, Clone, Default)]
struct PrecompileSignatureCounts {
    ed25519: u64,
    secp256k1: u64,
    secp256r1: u64,
}

/// Count the number of precompile verification signatures in a transaction.
///
/// Each precompile program stores its signature count as the first byte
/// of its instruction data.
fn count_precompile_signatures(instructions: &[InstructionView<'_>]) -> PrecompileSignatureCounts {
    let mut counts = PrecompileSignatureCounts::default();

    for ix in instructions {
        if ix.data.is_empty() {
            continue;
        }

        let sig_count = ix.data[0] as u64;

        if *ix.program_id == ED25519_PROGRAM_ID {
            counts.ed25519 = counts.ed25519.saturating_add(sig_count);
        } else if *ix.program_id == SECP256K1_PROGRAM_ID {
            counts.secp256k1 = counts.secp256k1.saturating_add(sig_count);
        } else if *ix.program_id == SECP256R1_PROGRAM_ID {
            counts.secp256r1 = counts.secp256r1.saturating_add(sig_count);
        }
    }

    counts
}

// ---------------------------------------------------------------------------
// CU rebate tracking
// ---------------------------------------------------------------------------

/// Tracks compute unit rebates after microblock execution.
///
/// When a transaction uses fewer CUs than it requested, the difference
/// is rebated back to the block's remaining capacity. This enables
/// more transactions to fit in the block.
#[derive(Debug, Clone, Default)]
pub struct CostRebateTracker {
    /// Total CUs rebated across all transactions in this block.
    pub total_rebated_cus: u64,
    /// Total CUs rebated from vote transactions.
    pub vote_rebated_cus: u64,
    /// Number of transactions that received rebates.
    pub rebate_count: u64,
}

impl CostRebateTracker {
    /// Record a rebate for a completed transaction.
    ///
    /// `requested_cus` is the cost used for scheduling.
    /// `actual_cus` is the compute units actually consumed during execution.
    pub fn record_rebate(&mut self, requested_cus: u64, actual_cus: u64, is_vote: bool) {
        let rebate = requested_cus.saturating_sub(actual_cus);
        if rebate > 0 {
            self.total_rebated_cus = self.total_rebated_cus.saturating_add(rebate);
            if is_vote {
                self.vote_rebated_cus = self.vote_rebated_cus.saturating_add(rebate);
            }
            self.rebate_count += 1;
        }
    }

    /// Reset for a new block.
    pub fn reset(&mut self) {
        self.total_rebated_cus = 0;
        self.vote_rebated_cus = 0;
        self.rebate_count = 0;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn vote_program_id() -> Pubkey {
        VOTE_PROGRAM_ID
    }

    fn system_program_id() -> Pubkey {
        paradencer_ids::SYSTEM_PROGRAM_ID
    }

    fn compute_budget_id() -> Pubkey {
        COMPUTE_BUDGET_PROGRAM_ID
    }

    fn ed25519_id() -> Pubkey {
        ED25519_PROGRAM_ID
    }

    fn secp256k1_id() -> Pubkey {
        SECP256K1_PROGRAM_ID
    }

    fn random_program_id() -> Pubkey {
        let mut id = [0u8; 32];
        id[0] = 0xAA;
        id[1] = 0xBB;
        id[2] = 0xCC;
        Pubkey::new(id)
    }

    // -- Simple vote tests --

    #[test]
    fn simple_vote_has_fixed_cost() {
        let vote_id = vote_program_id();
        let instructions = [InstructionView {
            program_id: &vote_id,
            data: &[2, 0, 0, 0], // Vote instruction
        }];

        let cost = compute_transaction_cost(&instructions, 1, 2, true);

        assert!(cost.is_simple_vote);
        assert_eq!(cost.signature_cost, SIGNATURE_COST); // 720
        assert_eq!(cost.writable_account_cost, 2 * COST_PER_WRITABLE_ACCOUNT); // 600
        assert_eq!(cost.execution_cost, SIMPLE_VOTE_EXECUTION_COST); // 2100
        assert_eq!(cost.instruction_data_cost, 0);
        assert_eq!(cost.total_cost, 720 + 600 + 2100); // 3420
    }

    #[test]
    fn simple_vote_with_compute_budget_still_simple() {
        let vote_id = vote_program_id();
        let cb_id = compute_budget_id();

        let instructions = [
            InstructionView {
                program_id: &cb_id,
                data: &[3, 0x10, 0x27, 0, 0, 0, 0, 0, 0], // SetComputeUnitPrice(10000)
            },
            InstructionView {
                program_id: &vote_id,
                data: &[2, 0, 0, 0],
            },
        ];

        let cost = compute_transaction_cost(&instructions, 1, 2, true);
        assert!(cost.is_simple_vote);
        assert_eq!(cost.execution_cost, SIMPLE_VOTE_EXECUTION_COST);
    }

    #[test]
    fn non_vote_is_not_simple() {
        let sys_id = system_program_id();
        let instructions = [InstructionView {
            program_id: &sys_id,
            data: &[0, 0, 0, 0],
        }];

        let cost = compute_transaction_cost(&instructions, 1, 1, false);
        assert!(!cost.is_simple_vote);
    }

    #[test]
    fn vote_with_extra_instruction_is_not_simple() {
        let vote_id = vote_program_id();
        let sys_id = system_program_id();

        let instructions = [
            InstructionView {
                program_id: &vote_id,
                data: &[2, 0, 0, 0],
            },
            InstructionView {
                program_id: &sys_id,
                data: &[0, 0, 0, 0],
            },
        ];

        let cost = compute_transaction_cost(&instructions, 1, 2, true);
        assert!(!cost.is_simple_vote);
    }

    // -- ComputeBudget parsing tests --

    #[test]
    fn parses_set_compute_unit_limit() {
        let cb_id = compute_budget_id();
        let sys_id = system_program_id();

        // SetComputeUnitLimit(500_000) = discriminant 2 + u32 LE
        let limit_bytes = 500_000u32.to_le_bytes();
        let mut data = vec![INSTRUCTION_SET_COMPUTE_UNIT_LIMIT];
        data.extend_from_slice(&limit_bytes);

        let instructions = [
            InstructionView {
                program_id: &cb_id,
                data: &data,
            },
            InstructionView {
                program_id: &sys_id,
                data: &[0; 10],
            },
        ];

        let cost = compute_transaction_cost(&instructions, 1, 1, false);
        assert_eq!(cost.execution_cost, 500_000);
    }

    #[test]
    fn parses_set_compute_unit_price() {
        let cb_id = compute_budget_id();
        let sys_id = system_program_id();

        // SetComputeUnitPrice(42) = discriminant 3 + u64 LE
        let price_bytes = 42u64.to_le_bytes();
        let mut data = vec![INSTRUCTION_SET_COMPUTE_UNIT_PRICE];
        data.extend_from_slice(&price_bytes);

        let instructions = [
            InstructionView {
                program_id: &cb_id,
                data: &data,
            },
            InstructionView {
                program_id: &sys_id,
                data: &[0; 10],
            },
        ];

        let cost = compute_transaction_cost(&instructions, 1, 1, false);
        assert_eq!(cost.compute_unit_price, 42);
    }

    #[test]
    fn caps_compute_unit_limit_at_max() {
        let cb_id = compute_budget_id();
        let sys_id = system_program_id();

        // SetComputeUnitLimit(u32::MAX) should be capped at MAX_COMPUTE_UNIT_LIMIT
        let limit_bytes = u32::MAX.to_le_bytes();
        let mut data = vec![INSTRUCTION_SET_COMPUTE_UNIT_LIMIT];
        data.extend_from_slice(&limit_bytes);

        let instructions = [
            InstructionView {
                program_id: &cb_id,
                data: &data,
            },
            InstructionView {
                program_id: &sys_id,
                data: &[0; 4],
            },
        ];

        let cost = compute_transaction_cost(&instructions, 1, 1, false);
        assert_eq!(cost.execution_cost, MAX_COMPUTE_UNIT_LIMIT);
    }

    // -- Default execution cost tests --

    #[test]
    fn default_cost_for_builtin() {
        let sys_id = system_program_id();
        let instructions = [InstructionView {
            program_id: &sys_id,
            data: &[0; 4],
        }];

        let cost = compute_transaction_cost(&instructions, 1, 1, false);
        assert_eq!(cost.execution_cost, MAX_BUILTIN_PROGRAM_COST);
    }

    #[test]
    fn default_cost_for_user_program() {
        let user_id = random_program_id();
        let instructions = [InstructionView {
            program_id: &user_id,
            data: &[0; 100],
        }];

        let cost = compute_transaction_cost(&instructions, 1, 1, false);
        assert_eq!(cost.execution_cost, DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT);
    }

    #[test]
    fn default_cost_multiple_instructions_capped() {
        let user_id = random_program_id();
        let instructions = [
            InstructionView {
                program_id: &user_id,
                data: &[0; 10],
            },
            InstructionView {
                program_id: &user_id,
                data: &[0; 10],
            },
            InstructionView {
                program_id: &user_id,
                data: &[0; 10],
            },
            InstructionView {
                program_id: &user_id,
                data: &[0; 10],
            },
            InstructionView {
                program_id: &user_id,
                data: &[0; 10],
            },
            InstructionView {
                program_id: &user_id,
                data: &[0; 10],
            },
            InstructionView {
                program_id: &user_id,
                data: &[0; 10],
            },
            InstructionView {
                program_id: &user_id,
                data: &[0; 10],
            },
        ];

        let cost = compute_transaction_cost(&instructions, 1, 1, false);
        // 8 * 200_000 = 1_600_000, capped at 1_400_000
        assert_eq!(cost.execution_cost, MAX_COMPUTE_UNIT_LIMIT);
    }

    // -- Signature and writable account cost tests --

    #[test]
    fn multiple_signatures_cost() {
        let sys_id = system_program_id();
        let instructions = [InstructionView {
            program_id: &sys_id,
            data: &[0; 4],
        }];

        let cost = compute_transaction_cost(&instructions, 3, 2, false);
        assert_eq!(cost.signature_cost, 3 * SIGNATURE_COST);
        assert_eq!(cost.writable_account_cost, 2 * COST_PER_WRITABLE_ACCOUNT);
    }

    // -- Instruction data cost tests --

    #[test]
    fn instruction_data_cost_proportional() {
        let sys_id = system_program_id();
        // 100 bytes of instruction data → 100/4 = 25 CU
        let instructions = [InstructionView {
            program_id: &sys_id,
            data: &[0; 100],
        }];

        let cost = compute_transaction_cost(&instructions, 1, 1, false);
        assert_eq!(cost.instruction_data_cost, 25);
    }

    #[test]
    fn instruction_data_cost_sums_across_instructions() {
        let sys_id = system_program_id();
        let instructions = [
            InstructionView {
                program_id: &sys_id,
                data: &[0; 40], // 40 bytes
            },
            InstructionView {
                program_id: &sys_id,
                data: &[0; 60], // 60 bytes
            },
        ];

        let cost = compute_transaction_cost(&instructions, 1, 2, false);
        assert_eq!(cost.instruction_data_cost, 25); // (40+60)/4
    }

    // -- Precompile signature tests --

    #[test]
    fn ed25519_precompile_signature_cost() {
        let ed_id = ed25519_id();
        // First byte = number of signatures
        let instructions = [InstructionView {
            program_id: &ed_id,
            data: &[2], // 2 ed25519 signatures
        }];

        let cost = compute_transaction_cost(&instructions, 1, 0, false);
        assert_eq!(cost.num_precompile_signatures, 2);
        // 2 * 2400 = 4800 CU for precompile sigs
        let expected_precompile_cost = 2 * ED25519_PRECOMPILE_COST_PER_SIGNATURE;
        assert!(cost.total_cost >= expected_precompile_cost);
    }

    #[test]
    fn secp256k1_precompile_signature_cost() {
        let secp_id = secp256k1_id();
        let instructions = [InstructionView {
            program_id: &secp_id,
            data: &[3], // 3 secp256k1 signatures
        }];

        let cost = compute_transaction_cost(&instructions, 1, 0, false);
        assert_eq!(cost.num_precompile_signatures, 3);
    }

    #[test]
    fn mixed_precompile_signatures() {
        let ed_id = ed25519_id();
        let secp_id = secp256k1_id();

        let instructions = [
            InstructionView {
                program_id: &ed_id,
                data: &[1], // 1 ed25519
            },
            InstructionView {
                program_id: &secp_id,
                data: &[2], // 2 secp256k1
            },
        ];

        let cost = compute_transaction_cost(&instructions, 1, 0, false);
        assert_eq!(cost.num_precompile_signatures, 3); // 1 + 2
    }

    // -- Loaded accounts data cost tests --

    #[test]
    fn loaded_accounts_data_cost() {
        let cb_id = compute_budget_id();
        let sys_id = system_program_id();

        // SetLoadedAccountsDataSizeLimit(65536) = 64KB
        let size_bytes = 65536u32.to_le_bytes();
        let mut data = vec![INSTRUCTION_SET_LOADED_ACCOUNTS_DATA_SIZE_LIMIT];
        data.extend_from_slice(&size_bytes);

        let instructions = [
            InstructionView {
                program_id: &cb_id,
                data: &data,
            },
            InstructionView {
                program_id: &sys_id,
                data: &[0; 4],
            },
        ];

        let cost = compute_transaction_cost(&instructions, 1, 1, false);
        // 64KB = 2 pages of 32KB × 8 CU/page = 16 CU
        assert_eq!(cost.loaded_accounts_data_cost, 16);
    }

    // -- Total cost composition test --

    #[test]
    fn total_cost_is_sum_of_components() {
        let sys_id = system_program_id();
        let instructions = [InstructionView {
            program_id: &sys_id,
            data: &[0; 80], // 80 bytes → 20 CU data cost
        }];

        let cost = compute_transaction_cost(&instructions, 2, 3, false);

        let expected = cost.signature_cost
            + cost.writable_account_cost
            + cost.instruction_data_cost
            + cost.execution_cost
            + cost.loaded_accounts_data_cost;

        assert_eq!(cost.total_cost, expected);
    }

    // -- CU rebate tracker tests --

    #[test]
    fn rebate_tracker_records_difference() {
        let mut tracker = CostRebateTracker::default();

        tracker.record_rebate(200_000, 150_000, false);
        assert_eq!(tracker.total_rebated_cus, 50_000);
        assert_eq!(tracker.rebate_count, 1);
        assert_eq!(tracker.vote_rebated_cus, 0);
    }

    #[test]
    fn rebate_tracker_tracks_vote_rebates() {
        let mut tracker = CostRebateTracker::default();

        tracker.record_rebate(3_000, 2_100, true);
        assert_eq!(tracker.total_rebated_cus, 900);
        assert_eq!(tracker.vote_rebated_cus, 900);
    }

    #[test]
    fn rebate_tracker_no_rebate_when_overused() {
        let mut tracker = CostRebateTracker::default();

        // Actual > requested shouldn't happen, but handle gracefully
        tracker.record_rebate(100_000, 150_000, false);
        assert_eq!(tracker.total_rebated_cus, 0);
        assert_eq!(tracker.rebate_count, 0);
    }

    #[test]
    fn rebate_tracker_reset() {
        let mut tracker = CostRebateTracker::default();

        tracker.record_rebate(200_000, 150_000, false);
        tracker.record_rebate(100_000, 80_000, true);

        tracker.reset();
        assert_eq!(tracker.total_rebated_cus, 0);
        assert_eq!(tracker.vote_rebated_cus, 0);
        assert_eq!(tracker.rebate_count, 0);
    }

    // -- Fee calculation tests --

    #[test]
    fn total_fee_lamports_calculation() {
        let sys_id = system_program_id();
        let cb_id = compute_budget_id();

        // SetComputeUnitPrice(1_000_000) = 1 lamport per CU
        let price_bytes = 1_000_000u64.to_le_bytes();
        let mut price_data = vec![INSTRUCTION_SET_COMPUTE_UNIT_PRICE];
        price_data.extend_from_slice(&price_bytes);

        // SetComputeUnitLimit(100_000)
        let limit_bytes = 100_000u32.to_le_bytes();
        let mut limit_data = vec![INSTRUCTION_SET_COMPUTE_UNIT_LIMIT];
        limit_data.extend_from_slice(&limit_bytes);

        let instructions = [
            InstructionView {
                program_id: &cb_id,
                data: &price_data,
            },
            InstructionView {
                program_id: &cb_id,
                data: &limit_data,
            },
            InstructionView {
                program_id: &sys_id,
                data: &[0; 4],
            },
        ];

        let cost = compute_transaction_cost(&instructions, 1, 1, false);

        // Sig fee = 1 * 5000 = 5000 lamports
        // Priority fee = 100_000 CU * 1_000_000 micro-lamports / 1_000_000 = 100_000 lamports
        let fee = cost.total_fee_lamports(5000);
        assert_eq!(fee, 5_000 + 100_000);
    }

    #[test]
    fn non_execution_cost_helper() {
        let sys_id = system_program_id();
        let instructions = [InstructionView {
            program_id: &sys_id,
            data: &[0; 40],
        }];

        let cost = compute_transaction_cost(&instructions, 2, 3, false);
        let expected_non_exec =
            cost.signature_cost + cost.writable_account_cost + cost.instruction_data_cost;
        assert_eq!(cost.non_execution_cost(), expected_non_exec);
    }
}
