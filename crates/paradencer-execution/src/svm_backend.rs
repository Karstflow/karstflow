/// Adapter bridging the consensus `ExecutionBackend` trait to the sBPF
/// `TransactionProcessor`.
///
/// Consensus defines `ExecutionBackend` so that it stays independent of the
/// concrete VM implementation. This module provides `SbpfBackend`, a thin
/// adapter that converts consensus types (`InstructionInfo`, `SlotContext`)
/// into sBPF types (`ExecutionContext`, `SysvarSnapshot`) and maps execution
/// results back.
use paradencer_consensus::{ExecutionBackend, InstructionInfo, InstructionResult, SlotContext};
use paradencer_sbpf::{ExecutionContext, ExecutionOutcome, SysvarSnapshot, TransactionProcessor};

/// Instruction execution backend backed by the sBPF `TransactionProcessor`.
///
/// Wraps all 14 builtin program executors plus the `BytecodeVm` for deployed
/// BPF programs behind the consensus-defined `ExecutionBackend` trait.
pub struct SbpfBackend {
    processor: TransactionProcessor,
}

impl SbpfBackend {
    /// Create a backend with default compute limits.
    pub fn new() -> Self {
        Self {
            processor: TransactionProcessor::new(),
        }
    }

    /// Create a backend with a custom compute unit ceiling.
    pub fn with_compute_limit(max_compute_units: u64) -> Self {
        Self {
            processor: TransactionProcessor::new().with_compute_limit(max_compute_units),
        }
    }
}

impl Default for SbpfBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecutionBackend for SbpfBackend {
    fn execute_instruction(
        &self,
        instruction: &InstructionInfo,
        remaining_compute_units: u64,
    ) -> InstructionResult {
        let context = to_execution_context(instruction, remaining_compute_units);
        let outcome = self.processor.execute_instruction(&context);
        to_instruction_result(outcome, instruction.program_id)
    }
}

// ---------------------------------------------------------------------------
// Type conversions: consensus ↔ sbpf
// ---------------------------------------------------------------------------

/// Convert a consensus `SlotContext` into an sBPF `SysvarSnapshot`.
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
        active_features: ctx.active_features.clone(),
        ..SysvarSnapshot::default()
    }
}

/// Convert a consensus `InstructionInfo` into an sBPF `ExecutionContext`.
fn to_execution_context(
    instruction: &InstructionInfo,
    remaining_compute_units: u64,
) -> ExecutionContext {
    let snapshot = to_sysvar_snapshot(&instruction.slot_context);
    let accounts = instruction
        .accounts
        .iter()
        .map(|(k, a, w, _signer)| (*k, a.clone(), *w))
        .collect();
    ExecutionContext::new(instruction.program_id, accounts, instruction.data.clone())
        .with_compute_budget(remaining_compute_units)
        .with_sysvar_snapshot(snapshot)
}

/// Convert an sBPF `ExecutionOutcome` into a consensus `InstructionResult`.
fn to_instruction_result(
    outcome: ExecutionOutcome,
    program_id: paradencer_storage::Pubkey,
) -> InstructionResult {
    let error = if outcome.success {
        None
    } else {
        // Surface the first log line as an error message, or a generic one.
        Some(
            outcome
                .logs
                .first()
                .cloned()
                .unwrap_or_else(|| "instruction execution failed".to_string()),
        )
    };
    InstructionResult {
        success: outcome.success,
        compute_units_consumed: outcome.compute_units_consumed,
        modified_accounts: outcome.modified_accounts,
        logs: outcome.logs,
        error,
        return_data: outcome.return_data.map(|data| (program_id, data)),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use paradencer_types::{Account, Pubkey};
    use std::collections::HashMap;

    fn test_slot_context() -> SlotContext {
        SlotContext {
            slot: 42,
            epoch: 3,
            unix_timestamp: 1_700_000_000,
            epoch_start_timestamp: 1_699_000_000,
            leader_schedule_epoch: 4,
            slots_per_epoch: 432_000,
            leader_schedule_slot_offset: 432_000,
            warmup: false,
            first_normal_epoch: 14,
            first_normal_slot: 524_256,
            lamports_per_byte_year: 3_480,
            exemption_threshold: 2.0,
            burn_percent: 50,
            last_restart_slot: 10,
            recent_blockhash: [0xAB; 32],
            lamports_per_signature: 5_000,
            active_features: std::collections::HashSet::new(),
        }
    }

    #[test]
    fn slot_context_to_sysvar_snapshot_preserves_fields() {
        let ctx = test_slot_context();
        let snap = to_sysvar_snapshot(&ctx);

        assert_eq!(snap.slot, ctx.slot);
        assert_eq!(snap.epoch, ctx.epoch);
        assert_eq!(snap.unix_timestamp, ctx.unix_timestamp);
        assert_eq!(snap.epoch_start_timestamp, ctx.epoch_start_timestamp);
        assert_eq!(snap.leader_schedule_epoch, ctx.leader_schedule_epoch);
        assert_eq!(snap.slots_per_epoch, ctx.slots_per_epoch);
        assert_eq!(
            snap.leader_schedule_slot_offset,
            ctx.leader_schedule_slot_offset
        );
        assert_eq!(snap.warmup, ctx.warmup);
        assert_eq!(snap.first_normal_epoch, ctx.first_normal_epoch);
        assert_eq!(snap.first_normal_slot, ctx.first_normal_slot);
        assert_eq!(snap.lamports_per_byte_year, ctx.lamports_per_byte_year);
        assert_eq!(snap.exemption_threshold, ctx.exemption_threshold);
        assert_eq!(snap.burn_percent, ctx.burn_percent);
        assert_eq!(snap.last_restart_slot, ctx.last_restart_slot);
        assert_eq!(snap.recent_blockhash, ctx.recent_blockhash);
        assert_eq!(snap.lamports_per_signature, ctx.lamports_per_signature);
    }

    #[test]
    fn to_execution_context_maps_all_fields() {
        let program_id = Pubkey::new_unique();
        let account_key = Pubkey::new_unique();
        let account = Account::default();
        let data = vec![1, 2, 3, 4];

        let instruction = InstructionInfo {
            program_id,
            accounts: vec![(account_key, account.clone(), true, false)],
            data: data.clone(),
            slot_context: test_slot_context(),
        };

        let ctx = to_execution_context(&instruction, 200_000);

        assert_eq!(ctx.program_id, program_id);
        assert_eq!(ctx.accounts.len(), 1);
        assert_eq!(ctx.accounts[0].0, account_key);
        assert!(ctx.accounts[0].2); // is_writable
        assert_eq!(ctx.instruction_data, data);
        assert_eq!(ctx.compute_budget, 200_000);
        assert!(ctx.sysvar_snapshot.is_some());
        assert_eq!(ctx.sysvar_snapshot.as_ref().unwrap().slot, 42);
    }

    #[test]
    fn outcome_success_maps_to_result() {
        let mut modified = HashMap::new();
        let key = Pubkey::new_unique();
        modified.insert(key, Account::default());

        let outcome = ExecutionOutcome {
            success: true,
            compute_units_consumed: 1_500,
            modified_accounts: modified.clone(),
            logs: vec!["ok".to_string()],
            return_data: Some(vec![0xFF]),
        };

        let result = to_instruction_result(outcome, Pubkey::default());

        assert!(result.success);
        assert_eq!(result.compute_units_consumed, 1_500);
        assert_eq!(result.modified_accounts.len(), 1);
        assert!(result.modified_accounts.contains_key(&key));
        assert_eq!(result.logs, vec!["ok".to_string()]);
        assert!(result.error.is_none());
    }

    #[test]
    fn outcome_failure_maps_error_from_first_log() {
        let outcome = ExecutionOutcome {
            success: false,
            compute_units_consumed: 500,
            modified_accounts: HashMap::new(),
            logs: vec![
                "Program failed: custom error".to_string(),
                "extra log".to_string(),
            ],
            return_data: None,
        };

        let result = to_instruction_result(outcome, Pubkey::default());

        assert!(!result.success);
        assert_eq!(result.compute_units_consumed, 500);
        assert_eq!(
            result.error,
            Some("Program failed: custom error".to_string())
        );
    }

    #[test]
    fn outcome_failure_with_no_logs_gives_generic_error() {
        let outcome = ExecutionOutcome {
            success: false,
            compute_units_consumed: 0,
            modified_accounts: HashMap::new(),
            logs: vec![],
            return_data: None,
        };

        let result = to_instruction_result(outcome, Pubkey::default());

        assert!(!result.success);
        assert_eq!(
            result.error,
            Some("instruction execution failed".to_string())
        );
    }

    #[test]
    fn backend_executes_system_transfer() {
        use paradencer_ids::SYSTEM_PROGRAM_ID;

        let backend = SbpfBackend::new();

        let sender = Pubkey::new_unique();
        let receiver = Pubkey::new_unique();

        let mut sender_account = Account::default();
        sender_account.meta.lamports = 1_000_000;

        let receiver_account = Account::default();

        // System program Transfer instruction: discriminant 2 (u32 LE) + amount (u64 LE)
        let mut data = Vec::with_capacity(12);
        data.extend_from_slice(&2u32.to_le_bytes()); // Transfer
        data.extend_from_slice(&500_000u64.to_le_bytes()); // amount

        let instruction = InstructionInfo {
            program_id: SYSTEM_PROGRAM_ID,
            accounts: vec![
                (sender, sender_account, true, true),
                (receiver, receiver_account, true, false),
            ],
            data,
            slot_context: SlotContext::default(),
        };

        let result = backend.execute_instruction(&instruction, 200_000);

        assert!(
            result.success,
            "transfer should succeed: {:?}",
            result.error
        );
        assert!(result.compute_units_consumed > 0);
        // Verify balance changes
        if let Some(sender_after) = result.modified_accounts.get(&sender) {
            assert_eq!(sender_after.meta.lamports, 500_000);
        }
        if let Some(receiver_after) = result.modified_accounts.get(&receiver) {
            assert_eq!(receiver_after.meta.lamports, 500_000);
        }
    }

    #[test]
    fn backend_returns_failure_for_insufficient_funds() {
        use paradencer_ids::SYSTEM_PROGRAM_ID;

        let backend = SbpfBackend::new();

        let sender = Pubkey::new_unique();
        let receiver = Pubkey::new_unique();

        let mut sender_account = Account::default();
        sender_account.meta.lamports = 100; // too little

        // Transfer 1_000_000
        let mut data = Vec::with_capacity(12);
        data.extend_from_slice(&2u32.to_le_bytes());
        data.extend_from_slice(&1_000_000u64.to_le_bytes());

        let instruction = InstructionInfo {
            program_id: SYSTEM_PROGRAM_ID,
            accounts: vec![
                (sender, sender_account, true, true),
                (receiver, Account::default(), true, false),
            ],
            data,
            slot_context: SlotContext::default(),
        };

        let result = backend.execute_instruction(&instruction, 200_000);

        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[test]
    fn backend_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SbpfBackend>();
    }

    #[test]
    fn backend_usable_as_trait_object() {
        let backend: Box<dyn ExecutionBackend> = Box::new(SbpfBackend::new());
        let instruction = InstructionInfo {
            program_id: Pubkey::default(),
            accounts: vec![],
            data: vec![],
            slot_context: SlotContext::default(),
        };
        // Verify trait object dispatch works without panicking.
        let _result = backend.execute_instruction(&instruction, 100_000);
    }
}
