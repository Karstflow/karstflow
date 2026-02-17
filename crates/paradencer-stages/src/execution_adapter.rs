/// Bridges the consensus execution backend trait to the sBPF transaction processor.
///
/// `SbpfExecutionAdapter` implements `ExecutionBackend` (defined in consensus)
/// by delegating instruction execution to `TransactionProcessor` (defined in sbpf).
/// This keeps `paradencer-consensus` independent of `paradencer-sbpf` while
/// enabling real program execution in the validator pipeline.
use paradencer_consensus::{ExecutionBackend, InstructionInfo, InstructionResult, SlotContext};
use paradencer_sbpf::{SysvarSnapshot, TransactionProcessor};
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

/// Convert consensus slot context to sBPF sysvar snapshot.
fn to_sysvar_snapshot(ctx: &SlotContext) -> SysvarSnapshot {
    SysvarSnapshot {
        slot: ctx.slot,
        epoch: ctx.epoch,
        unix_timestamp: ctx.unix_timestamp,
        epoch_start_timestamp: ctx.epoch_start_timestamp,
        leader_schedule_epoch: ctx.leader_schedule_epoch,
        slots_per_epoch: ctx.slots_per_epoch,
        leader_schedule_slot_offset: ctx.leader_schedule_slot_offset,
        warmup: ctx.warmup,
        first_normal_epoch: ctx.first_normal_epoch,
        first_normal_slot: ctx.first_normal_slot,
        lamports_per_byte_year: ctx.lamports_per_byte_year,
        exemption_threshold: ctx.exemption_threshold,
        burn_percent: ctx.burn_percent,
        last_restart_slot: ctx.last_restart_slot,
        recent_blockhash: ctx.recent_blockhash,
        lamports_per_signature: ctx.lamports_per_signature,
        ..SysvarSnapshot::default()
    }
}

impl ExecutionBackend for SbpfExecutionAdapter {
    fn execute_instruction(
        &self,
        instruction: &InstructionInfo,
        remaining_compute_units: u64,
    ) -> InstructionResult {
        use paradencer_sbpf::ExecutionContext;

        let snapshot = to_sysvar_snapshot(&instruction.slot_context);
        let context = ExecutionContext::new(
            instruction.program_id,
            instruction.accounts.clone(),
            instruction.data.clone(),
        )
        .with_compute_budget(remaining_compute_units)
        .with_sysvar_snapshot(snapshot);

        let outcome = self.processor.execute_instruction(&context);

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
            slot_context: SlotContext::default(),
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
            slot_context: SlotContext::default(),
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
            slot_context: SlotContext::default(),
        };

        let result = adapter.execute_instruction(&info, MAX_COMPUTE_UNITS);

        assert!(result.success, "BPF program via adapter should succeed");
        assert!(result.compute_units_consumed > 0);
    }
}
