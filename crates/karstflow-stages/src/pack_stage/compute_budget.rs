/// Compute Budget Program instruction parser for pack scheduling.
///
/// Parses ComputeBudgetProgram instructions from transactions to determine:
/// - Requested compute unit limit
/// - Prioritization fee (micro-lamports per CU)
/// - Heap frame size
/// - Loaded accounts data size limit
///
/// Each instruction type can appear at most once per transaction.
/// Duplicates cause the transaction to be rejected as malformed.

/// Compute Budget Program ID bytes.
pub const COMPUTE_BUDGET_PROGRAM_ID: [u8; 32] = [
    0x03, 0x06, 0x46, 0x6f, 0xe5, 0x21, 0x17, 0x32, 0xff, 0xec, 0xad, 0xba, 0x72, 0xc3, 0x9b,
    0xe7, 0xbc, 0x8c, 0xe5, 0xbb, 0xc5, 0xf7, 0x12, 0x6b, 0x2c, 0x43, 0x9b, 0x3a, 0x40, 0x00,
    0x00, 0x00,
];

// Consensus-critical constants.
const HEAP_FRAME_GRANULARITY: u32 = 1024;
const MICRO_LAMPORTS_PER_LAMPORT: u64 = 1_000_000;
const MAX_BUILTIN_CU_LIMIT: u64 = 3_000;
const DEFAULT_INSTR_CU_LIMIT: u64 = 200_000;
const MAX_CU_LIMIT: u64 = 1_400_000;
const HEAP_COST: u64 = 8;
const ACCOUNT_DATA_COST_PAGE_SIZE: u64 = 32 * 1024;
const MAX_LOADED_DATA_SZ: u64 = 64 * 1024 * 1024;

/// Flags tracking which instructions have been parsed.
const FLAG_SET_CU: u16 = 0x01;
const FLAG_SET_FEE: u16 = 0x02;
const FLAG_SET_HEAP: u16 = 0x04;
const FLAG_SET_LOADED_DATA_SZ: u16 = 0x08;

/// Stateful parser for compute budget instructions in a transaction.
#[derive(Debug, Clone, Default)]
pub struct ComputeBudgetState {
    flags: u16,
    compute_budget_instr_cnt: u16,
    compute_units: u32,
    loaded_acct_data_sz: u32,
    heap_size: u32,
    micro_lamports_per_cu: u64,
}

/// Result of finalizing compute budget parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComputeBudgetResult {
    /// Priority rewards in lamports (not counting base signature fee).
    pub priority_rewards: u64,
    /// Maximum compute units this transaction can consume.
    pub compute_limit: u32,
    /// Cost of loaded accounts data in compute units.
    pub loaded_accounts_data_cost: u64,
}

impl ComputeBudgetState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse a single ComputeBudgetProgram instruction.
    ///
    /// Returns `true` if the instruction was valid, `false` if the
    /// transaction should be rejected as malformed.
    pub fn parse_instruction(&mut self, instr_data: &[u8]) -> bool {
        if instr_data.len() < 5 {
            // All valid instructions need at least 5 bytes (1 discriminator + 4 data)
            // except SetComputeUnitPrice which needs 9
            return instr_data.is_empty() || self.try_parse(instr_data);
        }
        self.try_parse(instr_data)
    }

    fn try_parse(&mut self, data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }
        match data[0] {
            0 => {
                // RequestUnitsDeprecated — always invalid
                false
            }
            1 => {
                // RequestHeapFrame
                if data.len() < 5 {
                    return false;
                }
                if self.flags & FLAG_SET_HEAP != 0 {
                    return false;
                }
                self.heap_size = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
                if self.heap_size % HEAP_FRAME_GRANULARITY != 0 {
                    return false;
                }
                self.flags |= FLAG_SET_HEAP;
                self.compute_budget_instr_cnt += 1;
                true
            }
            2 => {
                // SetComputeUnitLimit
                if data.len() < 5 {
                    return false;
                }
                if self.flags & FLAG_SET_CU != 0 {
                    return false;
                }
                self.compute_units = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
                self.compute_units = self.compute_units.min(MAX_CU_LIMIT as u32);
                self.flags |= FLAG_SET_CU;
                self.compute_budget_instr_cnt += 1;
                true
            }
            3 => {
                // SetComputeUnitPrice
                if data.len() < 9 {
                    return false;
                }
                if self.flags & FLAG_SET_FEE != 0 {
                    return false;
                }
                self.micro_lamports_per_cu = u64::from_le_bytes([
                    data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
                ]);
                self.flags |= FLAG_SET_FEE;
                self.compute_budget_instr_cnt += 1;
                true
            }
            4 => {
                // SetLoadedAccountsDataSizeLimit
                if data.len() < 5 {
                    return false;
                }
                if self.flags & FLAG_SET_LOADED_DATA_SZ != 0 {
                    return false;
                }
                self.loaded_acct_data_sz =
                    u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
                if self.loaded_acct_data_sz == 0 {
                    return false;
                }
                self.loaded_acct_data_sz =
                    self.loaded_acct_data_sz.min(MAX_LOADED_DATA_SZ as u32);
                self.flags |= FLAG_SET_LOADED_DATA_SZ;
                self.compute_budget_instr_cnt += 1;
                true
            }
            _ => false,
        }
    }

    /// Number of compute budget instructions parsed so far.
    pub fn instruction_count(&self) -> u16 {
        self.compute_budget_instr_cnt
    }

    /// Finalize parsing and compute priority rewards and limits.
    ///
    /// `instr_cnt` is the total number of instructions in the transaction.
    /// `builtin_instr_cnt` is the number of builtin program instructions.
    pub fn finalize(
        &self,
        instr_cnt: u64,
        builtin_instr_cnt: u64,
    ) -> ComputeBudgetResult {
        // Compute CU limit
        let cu_limit = if self.flags & FLAG_SET_CU == 0 {
            let non_builtin = instr_cnt.saturating_sub(builtin_instr_cnt);
            (non_builtin * DEFAULT_INSTR_CU_LIMIT + builtin_instr_cnt * MAX_BUILTIN_CU_LIMIT)
                .min(MAX_CU_LIMIT)
        } else {
            (self.compute_units as u64).min(MAX_CU_LIMIT)
        };

        // Compute loaded accounts data cost
        let loaded_data_sz = if self.flags & FLAG_SET_LOADED_DATA_SZ == 0 {
            MAX_LOADED_DATA_SZ
        } else {
            self.loaded_acct_data_sz as u64
        };
        let loaded_accounts_data_cost =
            HEAP_COST * ((loaded_data_sz + ACCOUNT_DATA_COST_PAGE_SIZE - 1) / ACCOUNT_DATA_COST_PAGE_SIZE);

        // Compute priority fee using careful overflow-safe arithmetic.
        // cu_limit * micro_lamports_per_cu can overflow u64.
        // Use the split multiplication approach from the reference.
        let priority_rewards = compute_priority_fee(cu_limit, self.micro_lamports_per_cu);

        ComputeBudgetResult {
            priority_rewards,
            compute_limit: cu_limit as u32,
            loaded_accounts_data_cost,
        }
    }
}

/// Compute priority fee with overflow-safe arithmetic.
///
/// Computes ceil(cu_limit * micro_lamports_per_cu / 10^6) without overflow.
fn compute_priority_fee(cu_limit: u64, micro_lamports_per_cu: u64) -> u64 {
    if micro_lamports_per_cu == 0 {
        return 0;
    }

    let c_h = cu_limit / MICRO_LAMPORTS_PER_LAMPORT;
    let c_l = cu_limit % MICRO_LAMPORTS_PER_LAMPORT;
    let p_h = micro_lamports_per_cu / MICRO_LAMPORTS_PER_LAMPORT;
    let p_l = micro_lamports_per_cu % MICRO_LAMPORTS_PER_LAMPORT;

    let hh = c_h * p_h;
    if hh > u64::MAX / MICRO_LAMPORTS_PER_LAMPORT {
        return u64::MAX;
    }
    let hh = hh * MICRO_LAMPORTS_PER_LAMPORT;

    let hl = c_h * p_l + c_l * p_h;
    let ll = (c_l * p_l + MICRO_LAMPORTS_PER_LAMPORT - 1) / MICRO_LAMPORTS_PER_LAMPORT;
    let right = hl + ll;

    match hh.checked_add(right) {
        Some(total) => total,
        None => u64::MAX,
    }
}

/// Check if an account address is the Compute Budget Program.
pub fn is_compute_budget_program(program_id: &[u8; 32]) -> bool {
    *program_id == COMPUTE_BUDGET_PROGRAM_ID
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_set_cu_limit(limit: u32) -> Vec<u8> {
        let mut data = vec![2u8];
        data.extend_from_slice(&limit.to_le_bytes());
        data
    }

    fn make_set_cu_price(micro_lamports: u64) -> Vec<u8> {
        let mut data = vec![3u8];
        data.extend_from_slice(&micro_lamports.to_le_bytes());
        data
    }

    fn make_request_heap(size: u32) -> Vec<u8> {
        let mut data = vec![1u8];
        data.extend_from_slice(&size.to_le_bytes());
        data
    }

    fn make_set_loaded_data_sz(sz: u32) -> Vec<u8> {
        let mut data = vec![4u8];
        data.extend_from_slice(&sz.to_le_bytes());
        data
    }

    #[test]
    fn deprecated_instruction_rejected() {
        let mut state = ComputeBudgetState::new();
        assert!(!state.parse_instruction(&[0, 0, 0, 0, 0]));
    }

    #[test]
    fn set_cu_limit_basic() {
        let mut state = ComputeBudgetState::new();
        assert!(state.parse_instruction(&make_set_cu_limit(500_000)));
        let result = state.finalize(3, 0);
        assert_eq!(result.compute_limit, 500_000);
    }

    #[test]
    fn set_cu_limit_clamped_to_max() {
        let mut state = ComputeBudgetState::new();
        assert!(state.parse_instruction(&make_set_cu_limit(2_000_000)));
        let result = state.finalize(1, 0);
        assert_eq!(result.compute_limit, MAX_CU_LIMIT as u32);
    }

    #[test]
    fn set_cu_price() {
        let mut state = ComputeBudgetState::new();
        assert!(state.parse_instruction(&make_set_cu_limit(100_000)));
        assert!(state.parse_instruction(&make_set_cu_price(1_000_000))); // 1 lamport per CU
        let result = state.finalize(2, 1);
        // 100_000 CUs * 1_000_000 micro-lamports / 1_000_000 = 100_000 lamports
        assert_eq!(result.priority_rewards, 100_000);
    }

    #[test]
    fn default_cu_limit_no_builtins() {
        let state = ComputeBudgetState::new();
        // 3 instructions, 0 builtin = 3 * 200_000 = 600_000
        let result = state.finalize(3, 0);
        assert_eq!(result.compute_limit, 600_000);
    }

    #[test]
    fn default_cu_limit_with_builtins() {
        let state = ComputeBudgetState::new();
        // 3 instructions, 2 builtin: 1*200_000 + 2*3_000 = 206_000
        let result = state.finalize(3, 2);
        assert_eq!(result.compute_limit, 206_000);
    }

    #[test]
    fn default_cu_limit_clamped() {
        let state = ComputeBudgetState::new();
        // 10 non-builtin instructions: 10*200_000 = 2_000_000 > 1_400_000
        let result = state.finalize(10, 0);
        assert_eq!(result.compute_limit, MAX_CU_LIMIT as u32);
    }

    #[test]
    fn duplicate_cu_limit_rejected() {
        let mut state = ComputeBudgetState::new();
        assert!(state.parse_instruction(&make_set_cu_limit(100_000)));
        assert!(!state.parse_instruction(&make_set_cu_limit(200_000)));
    }

    #[test]
    fn duplicate_cu_price_rejected() {
        let mut state = ComputeBudgetState::new();
        assert!(state.parse_instruction(&make_set_cu_price(1000)));
        assert!(!state.parse_instruction(&make_set_cu_price(2000)));
    }

    #[test]
    fn heap_frame_valid() {
        let mut state = ComputeBudgetState::new();
        assert!(state.parse_instruction(&make_request_heap(256 * 1024)));
        assert_eq!(state.heap_size, 256 * 1024);
    }

    #[test]
    fn heap_frame_not_aligned() {
        let mut state = ComputeBudgetState::new();
        assert!(!state.parse_instruction(&make_request_heap(1000)));
    }

    #[test]
    fn loaded_data_sz_valid() {
        let mut state = ComputeBudgetState::new();
        assert!(state.parse_instruction(&make_set_loaded_data_sz(1024 * 1024)));
    }

    #[test]
    fn loaded_data_sz_zero_rejected() {
        let mut state = ComputeBudgetState::new();
        assert!(!state.parse_instruction(&make_set_loaded_data_sz(0)));
    }

    #[test]
    fn loaded_data_sz_clamped() {
        let mut state = ComputeBudgetState::new();
        assert!(state.parse_instruction(&make_set_loaded_data_sz(u32::MAX)));
        // Clamped to MAX_LOADED_DATA_SZ
        assert_eq!(state.loaded_acct_data_sz, MAX_LOADED_DATA_SZ as u32);
    }

    #[test]
    fn too_short_data_rejected() {
        let mut state = ComputeBudgetState::new();
        assert!(!state.parse_instruction(&[2, 0, 0])); // SetCU needs 5 bytes
        assert!(!state.parse_instruction(&[3, 0, 0, 0, 0])); // SetPrice needs 9 bytes
    }

    #[test]
    fn unknown_discriminator_rejected() {
        let mut state = ComputeBudgetState::new();
        assert!(!state.parse_instruction(&[5, 0, 0, 0, 0]));
        assert!(!state.parse_instruction(&[255, 0, 0, 0, 0]));
    }

    #[test]
    fn priority_fee_overflow_saturates() {
        let fee = compute_priority_fee(1_400_000, u64::MAX);
        assert_eq!(fee, u64::MAX);
    }

    #[test]
    fn priority_fee_zero_price() {
        let fee = compute_priority_fee(1_000_000, 0);
        assert_eq!(fee, 0);
    }

    #[test]
    fn priority_fee_exact() {
        // 100 CUs * 2_000_000 micro-lamports/CU = 200_000_000 micro-lamports = 200 lamports
        let fee = compute_priority_fee(100, 2_000_000);
        assert_eq!(fee, 200);
    }

    #[test]
    fn default_loaded_accounts_data_cost() {
        let state = ComputeBudgetState::new();
        let result = state.finalize(1, 0);
        // 64 MiB / 32 KiB pages = 2048 pages * 8 cost = 16384
        assert_eq!(result.loaded_accounts_data_cost, 16384);
    }

    #[test]
    fn all_four_instructions() {
        let mut state = ComputeBudgetState::new();
        assert!(state.parse_instruction(&make_request_heap(32768)));
        assert!(state.parse_instruction(&make_set_cu_limit(300_000)));
        assert!(state.parse_instruction(&make_set_cu_price(5_000_000)));
        assert!(state.parse_instruction(&make_set_loaded_data_sz(1024 * 1024)));
        assert_eq!(state.instruction_count(), 4);

        let result = state.finalize(5, 1);
        assert_eq!(result.compute_limit, 300_000);
        // 300_000 * 5_000_000 / 1_000_000 = 1_500_000 lamports
        assert_eq!(result.priority_rewards, 1_500_000);
    }

    #[test]
    fn program_id_check() {
        assert!(is_compute_budget_program(&COMPUTE_BUDGET_PROGRAM_ID));
        assert!(!is_compute_budget_program(&[0u8; 32]));
    }
}
