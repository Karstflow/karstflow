/// Bridges the consensus execution backend trait to the sBPF transaction processor.
///
/// `SbpfExecutionAdapter` implements `ExecutionBackend` (defined in consensus)
/// by delegating instruction execution to `TransactionProcessor` (defined in sbpf).
/// This keeps `paradencer-consensus` independent of `paradencer-sbpf` while
/// enabling real program execution in the validator pipeline.
use paradencer_consensus::{ExecutionBackend, InstructionInfo, InstructionResult};
use paradencer_sbpf::TransactionProcessor;
use std::sync::Arc;

/// Adapter that routes consensus instruction execution to the sBPF runtime.
pub struct SbpfExecutionAdapter {
    processor: Arc<TransactionProcessor>,
}

impl SbpfExecutionAdapter {
    /// Create a new adapter wrapping the given transaction processor.
    pub fn new(processor: Arc<TransactionProcessor>) -> Self {
        Self { processor }
    }

    /// Create an adapter with a default transaction processor.
    pub fn with_defaults() -> Self {
        Self {
            processor: Arc::new(TransactionProcessor::new()),
        }
    }
}

impl ExecutionBackend for SbpfExecutionAdapter {
    fn execute_instruction(
        &self,
        instruction: &InstructionInfo,
        remaining_compute_units: u64,
    ) -> InstructionResult {
        let outcome = self.processor.process_instruction(
            instruction.program_id,
            instruction.accounts.clone(),
            instruction.data.clone(),
        );

        let error = if outcome.success {
            None
        } else {
            Some(
                outcome
                    .logs
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "instruction failed".to_string()),
            )
        };

        InstructionResult {
            success: outcome.success,
            compute_units_consumed: outcome.compute_units_consumed,
            modified_accounts: outcome.modified_accounts,
            logs: outcome.logs,
            error,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paradencer_constants::execution::MAX_COMPUTE_UNITS;
    use paradencer_ids::SYSTEM_PROGRAM_ID;
    use paradencer_types::{Account, AccountData, AccountMeta, Pubkey};

    #[test]
    fn adapter_routes_system_program() {
        let adapter = SbpfExecutionAdapter::with_defaults();

        let from = Pubkey::new_unique();
        let to = Pubkey::new_unique();

        let from_account = Account {
            meta: AccountMeta {
                lamports: 1_000,
                owner: SYSTEM_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };

        let to_account = Account {
            meta: AccountMeta {
                lamports: 500,
                owner: SYSTEM_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };

        // Transfer instruction (type 2) - transfer 100 lamports
        let mut data = vec![2, 0, 0, 0];
        data.extend_from_slice(&100u64.to_le_bytes());

        let info = InstructionInfo {
            program_id: SYSTEM_PROGRAM_ID,
            accounts: vec![(from, from_account, true), (to, to_account, true)],
            data,
        };

        let result = adapter.execute_instruction(&info, MAX_COMPUTE_UNITS);

        assert!(result.success);
        assert_eq!(result.modified_accounts.len(), 2);
        assert!(result.compute_units_consumed > 0);
        assert!(result.error.is_none());
    }

    #[test]
    fn adapter_propagates_failure() {
        let adapter = SbpfExecutionAdapter::with_defaults();
        let unknown_program = Pubkey::new_unique();

        let info = InstructionInfo {
            program_id: unknown_program,
            accounts: vec![],
            data: vec![],
        };

        let result = adapter.execute_instruction(&info, MAX_COMPUTE_UNITS);

        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[test]
    fn adapter_routes_bpf_program() {
        use paradencer_ids::BPF_LOADER_PROGRAM_ID;
        use paradencer_sbpf::elf_loader::TestElfBuilder;
        use paradencer_sbpf::instruction::{Instruction, Opcode};

        let adapter = SbpfExecutionAdapter::with_defaults();
        let program_id = Pubkey::new_unique();

        // Build minimal ELF: mov r0, 0; exit (success)
        let mut text = Vec::new();
        for insn in &[
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 0),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ] {
            text.extend_from_slice(&insn.encode().to_le_bytes());
        }
        let elf = TestElfBuilder::new().text(text).build();

        let program_account = Account {
            meta: AccountMeta {
                lamports: 1,
                owner: BPF_LOADER_PROGRAM_ID,
                executable: true,
                rent_epoch: 0,
            },
            data: AccountData::new(elf),
        };

        let info = InstructionInfo {
            program_id,
            accounts: vec![(program_id, program_account, false)],
            data: vec![],
        };

        let result = adapter.execute_instruction(&info, MAX_COMPUTE_UNITS);

        assert!(result.success, "BPF program via adapter should succeed");
        assert!(result.compute_units_consumed > 0);
    }
}
