//! Compute Budget program implementation.
//!
//! Processes compute budget instructions to set per-transaction limits:
//! - Compute unit limit (maximum CUs the transaction may consume)
//! - Compute unit price (priority fee in micro-lamports per CU)
//! - Heap frame size (BPF heap allocation size)
//! - Loaded accounts data size limit

use crate::{ExecutionContext, ExecutionOutcome};
use karstflow_constants::compute_budget_program as constants;
use karstflow_constants::execution;
use karstflow_types::Pubkey;

/// Compute Budget program execution errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComputeBudgetError {
    InvalidInstruction,
    DuplicateInstruction,
    InvalidHeapFrameSize,
    InvalidComputeUnitLimit,
}

impl ComputeBudgetError {
    fn message(&self) -> &'static str {
        match self {
            Self::InvalidInstruction => "Invalid compute budget instruction",
            Self::DuplicateInstruction => "Duplicate compute budget instruction type",
            Self::InvalidHeapFrameSize => "Invalid heap frame size",
            Self::InvalidComputeUnitLimit => "Invalid compute unit limit",
        }
    }
}

/// Executor for Compute Budget program instructions.
pub struct ComputeBudgetProgramExecutor {
    base_cost: u64,
}

impl ComputeBudgetProgramExecutor {
    pub fn new(base_cost: u64) -> Self {
        Self { base_cost }
    }

    pub fn execute(&self, ctx: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if ctx.instruction_data.is_empty() {
            return Err(ComputeBudgetError::InvalidInstruction.message().to_string());
        }

        let instruction_type = ctx.instruction_data[0];
        let compute_used = self.base_cost.saturating_add(constants::COMPUTE_COST_BASE);

        match instruction_type {
            constants::INSTRUCTION_REQUEST_HEAP_FRAME => self.request_heap_frame(ctx, compute_used),
            constants::INSTRUCTION_SET_COMPUTE_UNIT_LIMIT => {
                self.set_compute_unit_limit(ctx, compute_used)
            }
            constants::INSTRUCTION_SET_COMPUTE_UNIT_PRICE => {
                self.set_compute_unit_price(ctx, compute_used)
            }
            constants::INSTRUCTION_SET_LOADED_ACCOUNTS_DATA_SIZE_LIMIT => {
                self.set_loaded_accounts_data_size_limit(ctx, compute_used)
            }
            _ => Err(format!(
                "Unknown compute budget instruction: {}",
                instruction_type
            )),
        }
    }

    /// Request a specific heap frame size for BPF programs.
    ///
    /// Instruction data: [1 byte type] [4 bytes heap_size]
    fn request_heap_frame(
        &self,
        ctx: &ExecutionContext,
        compute_used: u64,
    ) -> Result<ExecutionOutcome, String> {
        if ctx.instruction_data.len() < 5 {
            return Err(ComputeBudgetError::InvalidInstruction.message().to_string());
        }

        let heap_size = u32::from_le_bytes(
            ctx.instruction_data[1..5]
                .try_into()
                .map_err(|_| "Failed to parse heap size")?,
        );

        if !(execution::MIN_HEAP_FRAME_BYTES..=execution::MAX_HEAP_FRAME_BYTES).contains(&heap_size)
            || heap_size % execution::HEAP_FRAME_BYTES_GRANULARITY != 0
        {
            return Err(ComputeBudgetError::InvalidHeapFrameSize
                .message()
                .to_string());
        }

        let mut outcome = ExecutionOutcome::success(compute_used);
        outcome.return_data = Some(ctx.instruction_data.clone());
        outcome
            .logs
            .push(format!("Requested heap frame: {} bytes", heap_size));
        Ok(outcome)
    }

    /// Set the maximum compute units for this transaction.
    ///
    /// Instruction data: [1 byte type] [4 bytes limit]
    fn set_compute_unit_limit(
        &self,
        ctx: &ExecutionContext,
        compute_used: u64,
    ) -> Result<ExecutionOutcome, String> {
        if ctx.instruction_data.len() < 5 {
            return Err(ComputeBudgetError::InvalidInstruction.message().to_string());
        }

        let limit = u32::from_le_bytes(
            ctx.instruction_data[1..5]
                .try_into()
                .map_err(|_| "Failed to parse compute unit limit")?,
        );

        // Clamp to the maximum allowed
        let effective_limit = (limit as u64).min(execution::MAX_COMPUTE_UNIT_LIMIT);

        let mut outcome = ExecutionOutcome::success(compute_used);
        outcome.return_data = Some(ctx.instruction_data.clone());
        outcome
            .logs
            .push(format!("Set compute unit limit: {}", effective_limit));
        Ok(outcome)
    }

    /// Set the compute unit price (priority fee) for this transaction.
    ///
    /// Instruction data: [1 byte type] [8 bytes micro_lamports_per_cu]
    fn set_compute_unit_price(
        &self,
        ctx: &ExecutionContext,
        compute_used: u64,
    ) -> Result<ExecutionOutcome, String> {
        if ctx.instruction_data.len() < 9 {
            return Err(ComputeBudgetError::InvalidInstruction.message().to_string());
        }

        let micro_lamports = u64::from_le_bytes(
            ctx.instruction_data[1..9]
                .try_into()
                .map_err(|_| "Failed to parse compute unit price")?,
        );

        let mut outcome = ExecutionOutcome::success(compute_used);
        outcome.return_data = Some(ctx.instruction_data.clone());
        outcome.logs.push(format!(
            "Set compute unit price: {} micro-lamports",
            micro_lamports
        ));
        Ok(outcome)
    }

    /// Set the maximum loaded accounts data size for this transaction.
    ///
    /// Instruction data: [1 byte type] [4 bytes limit]
    fn set_loaded_accounts_data_size_limit(
        &self,
        ctx: &ExecutionContext,
        compute_used: u64,
    ) -> Result<ExecutionOutcome, String> {
        if ctx.instruction_data.len() < 5 {
            return Err(ComputeBudgetError::InvalidInstruction.message().to_string());
        }

        let limit = u32::from_le_bytes(
            ctx.instruction_data[1..5]
                .try_into()
                .map_err(|_| "Failed to parse data size limit")?,
        );

        let effective_limit = (limit as u64).min(execution::MAX_LOADED_ACCOUNTS_DATA_SIZE);

        let mut outcome = ExecutionOutcome::success(compute_used);
        outcome.return_data = Some(ctx.instruction_data.clone());
        outcome.logs.push(format!(
            "Set loaded accounts data size limit: {} bytes",
            effective_limit
        ));
        Ok(outcome)
    }
}

/// Parameters extracted from compute budget instructions within a transaction.
///
/// This is used by the transaction processor before execution to determine
/// the resource limits for a transaction.
#[derive(Debug, Clone, Default)]
pub struct ExtractedComputeBudget {
    pub compute_unit_limit: Option<u64>,
    pub compute_unit_price: Option<u64>,
    pub heap_size: Option<u32>,
    pub loaded_accounts_data_size_limit: Option<u64>,
}

/// Scan a list of instructions and extract any compute budget parameters.
///
/// Each instruction is represented as `(program_id, instruction_data)`.
/// Only instructions addressed to the Compute Budget program are examined.
/// Returns an error string if duplicate budget instructions of the same
/// type are found.
pub fn extract_compute_budget(
    instructions: &[(Pubkey, Vec<u8>)],
    compute_budget_program_id: &Pubkey,
) -> Result<ExtractedComputeBudget, String> {
    let mut budget = ExtractedComputeBudget::default();

    for (program_id, data) in instructions {
        if program_id != compute_budget_program_id {
            continue;
        }

        if data.is_empty() {
            return Err(ComputeBudgetError::InvalidInstruction.message().to_string());
        }

        match data[0] {
            constants::INSTRUCTION_REQUEST_HEAP_FRAME => {
                if budget.heap_size.is_some() {
                    return Err(ComputeBudgetError::DuplicateInstruction
                        .message()
                        .to_string());
                }
                if data.len() < 5 {
                    return Err(ComputeBudgetError::InvalidInstruction.message().to_string());
                }
                let size = u32::from_le_bytes(
                    data[1..5]
                        .try_into()
                        .map_err(|_| "Failed to parse heap size")?,
                );
                budget.heap_size = Some(size);
            }
            constants::INSTRUCTION_SET_COMPUTE_UNIT_LIMIT => {
                if budget.compute_unit_limit.is_some() {
                    return Err(ComputeBudgetError::DuplicateInstruction
                        .message()
                        .to_string());
                }
                if data.len() < 5 {
                    return Err(ComputeBudgetError::InvalidInstruction.message().to_string());
                }
                let limit = u32::from_le_bytes(
                    data[1..5]
                        .try_into()
                        .map_err(|_| "Failed to parse compute unit limit")?,
                );
                budget.compute_unit_limit =
                    Some((limit as u64).min(execution::MAX_COMPUTE_UNIT_LIMIT));
            }
            constants::INSTRUCTION_SET_COMPUTE_UNIT_PRICE => {
                if budget.compute_unit_price.is_some() {
                    return Err(ComputeBudgetError::DuplicateInstruction
                        .message()
                        .to_string());
                }
                if data.len() < 9 {
                    return Err(ComputeBudgetError::InvalidInstruction.message().to_string());
                }
                let price = u64::from_le_bytes(
                    data[1..9]
                        .try_into()
                        .map_err(|_| "Failed to parse compute unit price")?,
                );
                budget.compute_unit_price = Some(price);
            }
            constants::INSTRUCTION_SET_LOADED_ACCOUNTS_DATA_SIZE_LIMIT => {
                if budget.loaded_accounts_data_size_limit.is_some() {
                    return Err(ComputeBudgetError::DuplicateInstruction
                        .message()
                        .to_string());
                }
                if data.len() < 5 {
                    return Err(ComputeBudgetError::InvalidInstruction.message().to_string());
                }
                let limit = u32::from_le_bytes(
                    data[1..5]
                        .try_into()
                        .map_err(|_| "Failed to parse data size limit")?,
                );
                budget.loaded_accounts_data_size_limit =
                    Some((limit as u64).min(execution::MAX_LOADED_ACCOUNTS_DATA_SIZE));
            }
            _ => {
                return Err(ComputeBudgetError::InvalidInstruction.message().to_string());
            }
        }
    }

    Ok(budget)
}

#[cfg(test)]
mod tests {
    use super::*;
    use karstflow_ids::COMPUTE_BUDGET_PROGRAM_ID;

    #[test]
    fn extract_compute_unit_limit() {
        let mut data = vec![constants::INSTRUCTION_SET_COMPUTE_UNIT_LIMIT];
        data.extend_from_slice(&500_000u32.to_le_bytes());

        let instructions = vec![(COMPUTE_BUDGET_PROGRAM_ID, data)];
        let budget = extract_compute_budget(&instructions, &COMPUTE_BUDGET_PROGRAM_ID).unwrap();
        assert_eq!(budget.compute_unit_limit, Some(500_000));
    }

    #[test]
    fn extract_compute_unit_price() {
        let mut data = vec![constants::INSTRUCTION_SET_COMPUTE_UNIT_PRICE];
        data.extend_from_slice(&1_000_000u64.to_le_bytes());

        let instructions = vec![(COMPUTE_BUDGET_PROGRAM_ID, data)];
        let budget = extract_compute_budget(&instructions, &COMPUTE_BUDGET_PROGRAM_ID).unwrap();
        assert_eq!(budget.compute_unit_price, Some(1_000_000));
    }

    #[test]
    fn extract_heap_frame_request() {
        let mut data = vec![constants::INSTRUCTION_REQUEST_HEAP_FRAME];
        data.extend_from_slice(&(64 * 1024u32).to_le_bytes());

        let instructions = vec![(COMPUTE_BUDGET_PROGRAM_ID, data)];
        let budget = extract_compute_budget(&instructions, &COMPUTE_BUDGET_PROGRAM_ID).unwrap();
        assert_eq!(budget.heap_size, Some(64 * 1024));
    }

    #[test]
    fn extract_loaded_accounts_data_size_limit() {
        let mut data = vec![constants::INSTRUCTION_SET_LOADED_ACCOUNTS_DATA_SIZE_LIMIT];
        data.extend_from_slice(&(32 * 1024 * 1024u32).to_le_bytes());

        let instructions = vec![(COMPUTE_BUDGET_PROGRAM_ID, data)];
        let budget = extract_compute_budget(&instructions, &COMPUTE_BUDGET_PROGRAM_ID).unwrap();
        assert_eq!(
            budget.loaded_accounts_data_size_limit,
            Some(32 * 1024 * 1024)
        );
    }

    #[test]
    fn extract_multiple_budget_instructions() {
        let mut limit_data = vec![constants::INSTRUCTION_SET_COMPUTE_UNIT_LIMIT];
        limit_data.extend_from_slice(&300_000u32.to_le_bytes());

        let mut price_data = vec![constants::INSTRUCTION_SET_COMPUTE_UNIT_PRICE];
        price_data.extend_from_slice(&5_000u64.to_le_bytes());

        let instructions = vec![
            (COMPUTE_BUDGET_PROGRAM_ID, limit_data),
            (COMPUTE_BUDGET_PROGRAM_ID, price_data),
        ];
        let budget = extract_compute_budget(&instructions, &COMPUTE_BUDGET_PROGRAM_ID).unwrap();
        assert_eq!(budget.compute_unit_limit, Some(300_000));
        assert_eq!(budget.compute_unit_price, Some(5_000));
    }

    #[test]
    fn extract_rejects_duplicate_instruction_type() {
        let mut data1 = vec![constants::INSTRUCTION_SET_COMPUTE_UNIT_LIMIT];
        data1.extend_from_slice(&300_000u32.to_le_bytes());

        let mut data2 = vec![constants::INSTRUCTION_SET_COMPUTE_UNIT_LIMIT];
        data2.extend_from_slice(&400_000u32.to_le_bytes());

        let instructions = vec![
            (COMPUTE_BUDGET_PROGRAM_ID, data1),
            (COMPUTE_BUDGET_PROGRAM_ID, data2),
        ];
        let result = extract_compute_budget(&instructions, &COMPUTE_BUDGET_PROGRAM_ID);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Duplicate"));
    }

    #[test]
    fn extract_rejects_invalid_instruction() {
        let data = vec![255u8]; // Unknown instruction type

        let instructions = vec![(COMPUTE_BUDGET_PROGRAM_ID, data)];
        let result = extract_compute_budget(&instructions, &COMPUTE_BUDGET_PROGRAM_ID);
        assert!(result.is_err());
    }

    #[test]
    fn execute_set_compute_unit_limit() {
        let executor = ComputeBudgetProgramExecutor::new(150);

        let mut instruction_data = vec![constants::INSTRUCTION_SET_COMPUTE_UNIT_LIMIT];
        instruction_data.extend_from_slice(&500_000u32.to_le_bytes());

        let ctx = ExecutionContext::new(COMPUTE_BUDGET_PROGRAM_ID, vec![], instruction_data);

        let outcome = executor.execute(&ctx).unwrap();
        assert!(outcome.success);
        assert!(outcome.logs[0].contains("500000"));
    }

    #[test]
    fn execute_set_compute_unit_price() {
        let executor = ComputeBudgetProgramExecutor::new(150);

        let mut instruction_data = vec![constants::INSTRUCTION_SET_COMPUTE_UNIT_PRICE];
        instruction_data.extend_from_slice(&1_000_000u64.to_le_bytes());

        let ctx = ExecutionContext::new(COMPUTE_BUDGET_PROGRAM_ID, vec![], instruction_data);

        let outcome = executor.execute(&ctx).unwrap();
        assert!(outcome.success);
        assert!(outcome.logs[0].contains("1000000"));
    }

    #[test]
    fn execute_request_heap_frame_valid() {
        let executor = ComputeBudgetProgramExecutor::new(150);

        let mut instruction_data = vec![constants::INSTRUCTION_REQUEST_HEAP_FRAME];
        instruction_data.extend_from_slice(&(64 * 1024u32).to_le_bytes());

        let ctx = ExecutionContext::new(COMPUTE_BUDGET_PROGRAM_ID, vec![], instruction_data);

        let outcome = executor.execute(&ctx).unwrap();
        assert!(outcome.success);
        assert!(outcome.logs[0].contains("65536"));
    }

    #[test]
    fn execute_request_heap_frame_invalid_size() {
        let executor = ComputeBudgetProgramExecutor::new(150);

        // Not aligned to HEAP_FRAME_BYTES_GRANULARITY
        let mut instruction_data = vec![constants::INSTRUCTION_REQUEST_HEAP_FRAME];
        instruction_data.extend_from_slice(&100u32.to_le_bytes());

        let ctx = ExecutionContext::new(COMPUTE_BUDGET_PROGRAM_ID, vec![], instruction_data);

        let result = executor.execute(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("heap frame"));
    }

    #[test]
    fn compute_unit_limit_clamped_to_max() {
        let mut data = vec![constants::INSTRUCTION_SET_COMPUTE_UNIT_LIMIT];
        data.extend_from_slice(&u32::MAX.to_le_bytes());

        let instructions = vec![(COMPUTE_BUDGET_PROGRAM_ID, data)];
        let budget = extract_compute_budget(&instructions, &COMPUTE_BUDGET_PROGRAM_ID).unwrap();
        assert_eq!(
            budget.compute_unit_limit,
            Some(execution::MAX_COMPUTE_UNIT_LIMIT)
        );
    }
}
