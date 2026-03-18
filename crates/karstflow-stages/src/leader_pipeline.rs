/// Leader block production pipeline.
///
/// Coordinates the Pack -> Exec -> PoH flow during leader slots:
///
/// 1. `PackScheduler` selects highest-priority non-conflicting transactions
/// 2. `ExecStage` executes microblock through the sBPF runtime
/// 3. Mixin hash (SHA-256 of signatures) is fed to `PohService`
/// 4. Account locks are released back to pack after execution
/// 5. Entries (ticks + microblocks) accumulate for shredding
///
/// The pipeline also manages the tick cadence: between microblock executions,
/// the PoH service advances the hash chain to produce tick entries.
use crate::block_producer::{Entry, MicroblockEntry, PohEntry, PohService, PohState};
use crate::exec_stage::{
    ExecStage, ExecutionEngine, MicroblockExecResult, TransactionErrorCode, TransactionExecResult,
    TransactionLanded,
};
use crate::pack_stage::{MicroblockRebate, PackPacer, PackScheduler, PackedTransaction};
use karstflow_sbpf::TransactionProcessor;
use karstflow_types::{Account, Pubkey};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// SbpfExecutionEngine -- real sBPF backend for ExecStage
// ---------------------------------------------------------------------------

/// Execution engine backed by the sBPF `TransactionProcessor`.
///
/// Parses `PackedTransaction` payloads to extract program ID, accounts, and
/// instruction data, then delegates to the full builtin + BPF runtime.
///
/// Account state for execution is provided via `set_account_state()` before
/// each block. After execution, modified accounts are returned in the result
/// and should be applied to the account database.
pub struct SbpfExecutionEngine {
    processor: Arc<TransactionProcessor>,
    /// Current account state for the executing slot.
    account_state: HashMap<Pubkey, Account>,
}

impl SbpfExecutionEngine {
    pub fn new() -> Self {
        Self {
            processor: TransactionProcessor::new_with_cpi(),
            account_state: HashMap::new(),
        }
    }

    pub fn with_processor(processor: Arc<TransactionProcessor>) -> Self {
        Self {
            processor,
            account_state: HashMap::new(),
        }
    }

    /// Set the account state snapshot for the current block.
    /// Called once at the start of each leader slot with accounts loaded
    /// from the bank/account database.
    pub fn set_account_state(&mut self, state: HashMap<Pubkey, Account>) {
        self.account_state = state;
    }

    /// Apply modified accounts from execution results back into the
    /// working state so subsequent instructions in the same block see
    /// updated balances and data.
    pub fn apply_modifications(&mut self, modifications: &[(Pubkey, Account)]) {
        for (pubkey, account) in modifications {
            self.account_state.insert(*pubkey, account.clone());
        }
    }

    /// Parse a packed transaction payload and execute via the sBPF runtime.
    fn parse_and_execute(&self, tx: &PackedTransaction) -> TransactionExecResult {
        use karstflow_sbpf::{
            CompiledInstruction as SbpfCompiledInstruction, Transaction as SbpfTransaction,
            TransactionMessage as SbpfTransactionMessage,
        };

        // Parse the wire-format transaction.
        match karstflow_types::parse_transaction(&tx.payload) {
            Ok(parsed) => {
                // Account keys are already Pubkey in karstflow-types.
                let account_keys: &[Pubkey] = &parsed.message.account_keys;

                let instructions: Vec<SbpfCompiledInstruction> = parsed
                    .message
                    .instructions
                    .iter()
                    .map(|ix| SbpfCompiledInstruction {
                        program_id_index: ix.program_id_index,
                        accounts: ix.accounts.clone(),
                        data: ix.data.clone(),
                    })
                    .collect();

                let sbpf_tx = SbpfTransaction {
                    signatures: parsed.signatures.iter().map(|s| s.to_bytes()).collect(),
                    message: SbpfTransactionMessage {
                        header: karstflow_sbpf::MessageHeader {
                            num_required_signatures: parsed.message.header.num_required_signatures,
                            num_readonly_signed: parsed.message.header.num_readonly_signed_accounts,
                            num_readonly_unsigned: parsed
                                .message
                                .header
                                .num_readonly_unsigned_accounts,
                        },
                        account_keys: account_keys.to_vec(),
                        recent_blockhash: parsed.message.recent_blockhash.to_bytes(),
                        instructions,
                    },
                };

                // Build account state map for this transaction.
                let tx_account_state: HashMap<Pubkey, Account> = account_keys
                    .iter()
                    .filter_map(|key| {
                        self.account_state
                            .get(key)
                            .map(|account| (*key, account.clone()))
                    })
                    .collect();

                let result = self
                    .processor
                    .process_transaction(&sbpf_tx, &tx_account_state);

                // Convert modified accounts to raw byte pairs for ExecStage.
                let modified: Vec<([u8; 32], Vec<u8>)> = result
                    .modified_accounts
                    .iter()
                    .map(|(k, account)| (k.to_bytes(), account.data.as_slice().to_vec()))
                    .collect();

                let consumed = result.compute_units_consumed;
                let rebated = tx.compute_units.saturating_sub(consumed);
                let (landed, error_code) = if result.success {
                    (TransactionLanded::Landed, TransactionErrorCode::Success)
                } else {
                    (
                        TransactionLanded::LandedFeesOnly,
                        TransactionErrorCode::InstructionError,
                    )
                };

                TransactionExecResult {
                    payload: tx.payload.clone(),
                    success: result.success,
                    compute_units_consumed: consumed,
                    compute_units_rebated: rebated,
                    fee_paid: if result.success { tx.priority_fee } else { 0 },
                    landed,
                    error_code,
                    error: result.error,
                    logs: result.logs,
                    modified_accounts: modified,
                }
            }
            Err(_) => {
                // Unparseable transaction -- fail gracefully.
                TransactionExecResult {
                    payload: tx.payload.clone(),
                    success: false,
                    compute_units_consumed: 0,
                    compute_units_rebated: tx.compute_units,
                    fee_paid: 0,
                    landed: TransactionLanded::Unlanded,
                    error_code: TransactionErrorCode::DeserializationError,
                    error: Some("failed to parse transaction payload".to_string()),
                    logs: vec![],
                    modified_accounts: vec![],
                }
            }
        }
    }
}

impl ExecutionEngine for SbpfExecutionEngine {
    fn execute(&self, tx: &PackedTransaction) -> TransactionExecResult {
        self.parse_and_execute(tx)
    }
}

// ---------------------------------------------------------------------------
// LeaderPipeline -- Pack -> Exec -> PoH coordinator
// ---------------------------------------------------------------------------

/// Outcome of a single pipeline step (one microblock produced and executed).
#[derive(Debug)]
pub struct PipelineStepResult {
    /// The executed microblock result.
    pub exec_result: MicroblockExecResult,
    /// PoH mixin entry (None if PoH is not in Leading state).
    pub poh_entry: Option<MicroblockEntry>,
    /// Microblock ID (for releasing pack locks).
    pub microblock_id: u64,
}

/// Accumulated statistics for one leader slot.
#[derive(Debug, Clone, Default)]
pub struct LeaderPipelineStats {
    /// Total microblocks produced and executed.
    pub microblocks_produced: u64,
    /// Total transactions executed (success + failure).
    pub transactions_executed: u64,
    /// Total successfully executed transactions.
    pub transactions_succeeded: u64,
    /// Total failed transactions.
    pub transactions_failed: u64,
    /// Total compute units consumed across all microblocks.
    pub compute_units_consumed: u64,
    /// Total compute units budgeted (before rebate).
    pub compute_units_budgeted: u64,
    /// Total CUs rebated back to block budget.
    pub compute_units_rebated: u64,
    /// Total fees collected.
    pub fees_collected: u64,
    /// Number of times the pacer delayed microblock emission.
    pub pacing_delays: u64,
}

/// The leader block production pipeline.
///
/// Call `step()` repeatedly during a leader slot to produce and execute
/// microblocks. Between steps, call `advance_poh()` to produce tick entries.
/// When the slot is complete, call `finish_slot()`.
///
/// Integrates `PackPacer` for rate-limiting microblock emission and
/// CU rebate tracking for accurate block budget accounting.
pub struct LeaderPipeline {
    pack: PackScheduler,
    exec: ExecStage,
    poh: PohService,
    /// Optional microblock emission rate limiter.
    pacer: Option<PackPacer>,
    /// Accumulated entries for the current slot.
    entries: Vec<Entry>,
    /// Accumulated PohEntries with full transaction data for shredding.
    /// Mirrors `entries` but includes serialized transaction payloads.
    shred_entries: Vec<PohEntry>,
    /// Count of microblocks executed in this slot.
    microblocks_executed: u64,
    /// Per-slot statistics.
    stats: LeaderPipelineStats,
}

impl LeaderPipeline {
    /// Create a new pipeline with the given components (no pacing).
    pub fn new(pack: PackScheduler, exec: ExecStage, poh: PohService) -> Self {
        Self {
            pack,
            exec,
            poh,
            pacer: None,
            entries: Vec::new(),
            shred_entries: Vec::new(),
            microblocks_executed: 0,
            stats: LeaderPipelineStats::default(),
        }
    }

    /// Create a pipeline with microblock pacing enabled.
    ///
    /// The pacer enforces a minimum interval between microblock emissions
    /// and a per-slot microblock count limit.
    pub fn with_pacer(
        pack: PackScheduler,
        exec: ExecStage,
        poh: PohService,
        pacer: PackPacer,
    ) -> Self {
        Self {
            pack,
            exec,
            poh,
            pacer: Some(pacer),
            entries: Vec::new(),
            shred_entries: Vec::new(),
            microblocks_executed: 0,
            stats: LeaderPipelineStats::default(),
        }
    }

    /// Start a new leader slot. Resets pack limits and configures PoH.
    pub fn begin_slot(&mut self, slot: u64) {
        self.pack.new_block(slot);
        self.poh.begin_leader(slot);
        self.entries.clear();
        self.shred_entries.clear();
        self.microblocks_executed = 0;
        self.stats = LeaderPipelineStats::default();
        if let Some(ref mut pacer) = self.pacer {
            pacer.new_slot();
        }
    }

    /// Submit a transaction for scheduling.
    pub fn submit_transaction(&mut self, tx: PackedTransaction) {
        self.pack.submit(tx);
    }

    /// Try to produce and execute one microblock.
    ///
    /// Returns `None` if:
    /// - No transactions are available
    /// - Block is full
    /// - Pacer is throttling emission (minimum interval not elapsed)
    ///
    /// On success, the microblock is executed, CU rebates are computed,
    /// the mixin hash is fed to PoH, and pack locks are released.
    pub fn step(&mut self) -> Option<PipelineStepResult> {
        // 0. Check pacer: is emission allowed?
        if let Some(ref pacer) = self.pacer {
            if !pacer.can_emit() {
                self.stats.pacing_delays += 1;
                return None;
            }
        }

        // 1. Pack: produce next microblock
        let microblock = self.pack.produce_microblock()?;
        let microblock_id = microblock.id;
        let is_vote_only = microblock.is_vote_only;
        let budgeted_cus = microblock.total_compute_units;

        // 2. Exec: execute the microblock
        let exec_result = self.exec.execute_microblock(&microblock);

        // 3. Compute mixin hash: SHA-256 of all transaction signatures
        let mixin_hash = compute_mixin_hash(&exec_result);

        // 4. PoH: mix in the microblock hash
        let poh_entry = self
            .poh
            .mixin(&mixin_hash, exec_result.transaction_results.len() as u32);

        // If PoH accepted the mixin, record the entry.
        if let Some(ref entry) = poh_entry {
            self.entries.push(Entry::Microblock(entry.clone()));
            // Build a PohEntry with the full transaction payloads for shredding.
            let transactions: Vec<Vec<u8>> = exec_result
                .transaction_results
                .iter()
                .map(|r| r.payload.clone())
                .collect();
            self.shred_entries
                .push(PohEntry::new(entry.num_hashes, entry.hash, transactions));
        }

        // 5. Compute CU rebate and release pack locks
        let consumed_cus = exec_result.total_compute_units;
        let rebate = MicroblockRebate {
            requested_cus: budgeted_cus,
            consumed_cus,
            is_vote_only,
        };
        self.pack
            .complete_microblock_with_rebate(microblock_id, rebate);

        // 6. Record pacer emission
        if let Some(ref mut pacer) = self.pacer {
            pacer.record_emit();
        }

        // 7. Update statistics
        self.microblocks_executed += 1;
        self.stats.microblocks_produced += 1;
        self.stats.compute_units_budgeted += budgeted_cus;
        self.stats.compute_units_consumed += consumed_cus;
        if budgeted_cus > consumed_cus {
            self.stats.compute_units_rebated += budgeted_cus - consumed_cus;
        }
        self.stats.transactions_executed += exec_result.transaction_results.len() as u64;
        self.stats.transactions_succeeded += exec_result.success_count as u64;
        self.stats.transactions_failed += exec_result.failure_count as u64;
        for tx_result in &exec_result.transaction_results {
            self.stats.fees_collected += tx_result.fee_paid;
        }

        Some(PipelineStepResult {
            exec_result,
            poh_entry,
            microblock_id,
        })
    }

    /// Advance PoH by the given number of hashes, collecting tick entries.
    pub fn advance_poh(&mut self, target_hashes: u64) {
        let new_entries = self.poh.advance(target_hashes);
        // Build PohEntries for ticks (no transactions).
        for entry in &new_entries {
            if let Entry::Tick(ref tick) = entry {
                self.shred_entries
                    .push(PohEntry::new(tick.num_hashes, tick.hash, Vec::new()));
            }
        }
        self.entries.extend(new_entries);
    }

    /// Finish the current slot. Returns all accumulated entries and the
    /// slot completion signal.
    pub fn finish_slot(&mut self) -> Vec<Entry> {
        let (final_entries, _slot_complete) = self.poh.finish_slot();
        // Build PohEntries for final tick entries.
        for entry in &final_entries {
            if let Entry::Tick(ref tick) = entry {
                self.shred_entries
                    .push(PohEntry::new(tick.num_hashes, tick.hash, Vec::new()));
            }
        }
        self.entries.extend(final_entries);
        std::mem::take(&mut self.entries)
    }

    /// Take the accumulated PohEntries for shredding.
    ///
    /// These entries include full transaction payloads needed by the
    /// EntryShredder. Call after `finish_slot()`.
    pub fn take_shred_entries(&mut self) -> Vec<PohEntry> {
        std::mem::take(&mut self.shred_entries)
    }

    /// Number of queued transactions.
    pub fn queue_depth(&self) -> usize {
        self.pack.queue_depth()
    }

    /// Number of microblocks executed in this slot.
    pub fn microblocks_executed(&self) -> u64 {
        self.microblocks_executed
    }

    /// Whether PoH is in Leading state.
    pub fn is_leading(&self) -> bool {
        self.poh.state() == PohState::Leading
    }

    /// Per-slot accumulated statistics.
    pub fn stats(&self) -> &LeaderPipelineStats {
        &self.stats
    }

    /// Access the PoH service for reset/state transitions.
    pub fn poh(&self) -> &PohService {
        &self.poh
    }

    /// Mutable access to PoH for reset signals from replay.
    pub fn poh_mut(&mut self) -> &mut PohService {
        &mut self.poh
    }

    /// Access to the pack scheduler.
    pub fn pack(&self) -> &PackScheduler {
        &self.pack
    }

    /// Mutable access to the pack scheduler.
    pub fn pack_mut(&mut self) -> &mut PackScheduler {
        &mut self.pack
    }
}

/// Compute the mixin hash for a microblock: SHA-256 of all transaction
/// signatures concatenated. This is what gets mixed into the PoH chain.
fn compute_mixin_hash(result: &MicroblockExecResult) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for tx_result in &result.transaction_results {
        // Signature is the first 64 bytes of the payload.
        if tx_result.payload.len() >= 64 {
            hasher.update(&tx_result.payload[..64]);
        } else {
            hasher.update(&tx_result.payload);
        }
    }
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_producer::PohService;
    use crate::exec_stage::MockExecutionEngine;
    use crate::pack_stage::{PackConfig, PackScheduler};
    use karstflow_types::Hash;

    fn make_tx(id: u8, priority: u64, cu: u64) -> PackedTransaction {
        PackedTransaction {
            payload: vec![id; 128], // 128 bytes so signature extraction works
            blockhash: [0u8; 32],
            priority_fee: priority,
            compute_units: cu,
            total_cost: 0,
            is_vote: false,
            expires_at_slot: u64::MAX,
            write_accounts: vec![{
                let mut a = [0u8; 32];
                a[0] = id;
                a
            }],
            read_accounts: vec![],
            data_size: 128,
            insertion_order: 0,
        }
    }

    fn make_pipeline() -> LeaderPipeline {
        let pack = PackScheduler::new();
        let engine = MockExecutionEngine::new(50_000);
        let exec = ExecStage::new(Box::new(engine));
        let poh = PohService::new(Hash::default());
        LeaderPipeline::new(pack, exec, poh)
    }

    #[test]
    fn empty_pipeline_step_returns_none() {
        let mut pipeline = make_pipeline();
        pipeline.begin_slot(1);
        assert!(pipeline.step().is_none());
    }

    #[test]
    fn submit_and_step_produces_result() {
        let mut pipeline = make_pipeline();
        pipeline.begin_slot(1);

        pipeline.submit_transaction(make_tx(1, 5_000, 200_000));

        // PoH starts as Uninitialized, so mixin will be None.
        // The exec result should still be produced.
        let result = pipeline.step().unwrap();
        assert_eq!(result.exec_result.success_count, 1);
        assert_eq!(result.microblock_id, 0);
    }

    #[test]
    fn multiple_microblocks_in_slot() {
        let config = PackConfig {
            max_txns_per_microblock: 1,
            ..Default::default()
        };
        let pack = PackScheduler::with_config(config);
        let engine = MockExecutionEngine::new(50_000);
        let exec = ExecStage::new(Box::new(engine));
        let poh = PohService::new(Hash::default());
        let mut pipeline = LeaderPipeline::new(pack, exec, poh);

        pipeline.begin_slot(1);

        // Submit two non-conflicting transactions.
        pipeline.submit_transaction(make_tx(1, 5_000, 100_000));
        pipeline.submit_transaction(make_tx(2, 3_000, 100_000));

        let r1 = pipeline.step().unwrap();
        assert_eq!(r1.microblock_id, 0);

        let r2 = pipeline.step().unwrap();
        assert_eq!(r2.microblock_id, 1);

        assert_eq!(pipeline.microblocks_executed(), 2);
    }

    #[test]
    fn begin_slot_resets_state() {
        let mut pipeline = make_pipeline();
        pipeline.begin_slot(1);
        pipeline.submit_transaction(make_tx(1, 5_000, 100_000));
        pipeline.step();

        // Start new slot.
        pipeline.begin_slot(2);
        assert_eq!(pipeline.microblocks_executed(), 0);
        assert_eq!(pipeline.queue_depth(), 0);
    }

    #[test]
    fn mixin_hash_is_deterministic() {
        use crate::exec_stage::RebateSummary;
        let result = MicroblockExecResult {
            microblock_id: 0,
            transaction_results: vec![TransactionExecResult {
                payload: vec![0xAA; 128],
                success: true,
                compute_units_consumed: 100,
                compute_units_rebated: 0,
                fee_paid: 50,
                landed: TransactionLanded::Landed,
                error_code: TransactionErrorCode::Success,
                error: None,
                logs: vec![],
                modified_accounts: vec![],
            }],
            total_compute_units: 100,
            success_count: 1,
            failure_count: 0,
            landed_count: 1,
            fees_only_count: 0,
            entry_hash: [0u8; 32],
            rebate_summary: RebateSummary::default(),
        };

        let hash1 = compute_mixin_hash(&result);
        let hash2 = compute_mixin_hash(&result);
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, [0u8; 32]); // Not all zeros.
    }

    #[test]
    fn mixin_hash_differs_by_signature() {
        use crate::exec_stage::RebateSummary;
        let make_result = |payload: Vec<u8>| MicroblockExecResult {
            microblock_id: 0,
            transaction_results: vec![TransactionExecResult {
                payload,
                success: true,
                compute_units_consumed: 100,
                compute_units_rebated: 0,
                fee_paid: 50,
                landed: TransactionLanded::Landed,
                error_code: TransactionErrorCode::Success,
                error: None,
                logs: vec![],
                modified_accounts: vec![],
            }],
            total_compute_units: 100,
            success_count: 1,
            failure_count: 0,
            landed_count: 1,
            fees_only_count: 0,
            entry_hash: [0u8; 32],
            rebate_summary: RebateSummary::default(),
        };

        let h1 = compute_mixin_hash(&make_result(vec![0xAA; 128]));
        let h2 = compute_mixin_hash(&make_result(vec![0xBB; 128]));
        assert_ne!(h1, h2);
    }

    #[test]
    fn sbpf_engine_is_constructable() {
        let engine = SbpfExecutionEngine::new();
        // Verify it can be created and used as a trait object.
        let _: Box<dyn ExecutionEngine> = Box::new(engine);
    }

    #[test]
    fn sbpf_engine_unparseable_payload_fails_gracefully() {
        let engine = SbpfExecutionEngine::new();
        let tx = PackedTransaction {
            payload: vec![0xFF, 0xFF], // garbage
            blockhash: [0u8; 32],
            priority_fee: 0,
            compute_units: 100_000,
            total_cost: 0,
            is_vote: false,
            expires_at_slot: u64::MAX,
            write_accounts: vec![],
            read_accounts: vec![],
            data_size: 2,
            insertion_order: 0,
        };

        let result = engine.execute(&tx);
        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[test]
    fn stats_track_execution_results() {
        let config = PackConfig {
            max_txns_per_microblock: 1,
            ..Default::default()
        };
        let pack = PackScheduler::with_config(config);
        let engine = MockExecutionEngine::new(50_000);
        let exec = ExecStage::new(Box::new(engine));
        let poh = PohService::new(Hash::default());
        let mut pipeline = LeaderPipeline::new(pack, exec, poh);

        pipeline.begin_slot(1);

        pipeline.submit_transaction(make_tx(1, 5_000, 200_000));
        pipeline.submit_transaction(make_tx(2, 3_000, 100_000));

        pipeline.step();
        pipeline.step();

        let stats = pipeline.stats();
        assert_eq!(stats.microblocks_produced, 2);
        assert_eq!(stats.transactions_executed, 2);
        assert!(stats.compute_units_consumed > 0);
    }

    #[test]
    fn stats_reset_on_begin_slot() {
        let mut pipeline = make_pipeline();
        pipeline.begin_slot(1);

        pipeline.submit_transaction(make_tx(1, 5_000, 200_000));
        pipeline.step();

        assert_eq!(pipeline.stats().microblocks_produced, 1);

        pipeline.begin_slot(2);
        assert_eq!(pipeline.stats().microblocks_produced, 0);
        assert_eq!(pipeline.stats().transactions_executed, 0);
    }

    #[test]
    fn rebate_tracking_credits_unused_cus() {
        let mut pipeline = make_pipeline();
        pipeline.begin_slot(1);

        // MockExecutionEngine consumes 50_000 CUs per transaction.
        // Submit a transaction with 200_000 CU budget.
        pipeline.submit_transaction(make_tx(1, 5_000, 200_000));
        pipeline.step();

        let stats = pipeline.stats();
        // Budgeted 200K, consumed 50K, rebated 150K.
        assert_eq!(stats.compute_units_budgeted, 200_000);
        assert_eq!(stats.compute_units_consumed, 50_000);
        assert_eq!(stats.compute_units_rebated, 150_000);
    }

    #[test]
    fn pacer_throttles_emission() {
        let config = PackConfig {
            max_txns_per_microblock: 1,
            ..Default::default()
        };
        let pack = PackScheduler::with_config(config);
        let engine = MockExecutionEngine::new(50_000);
        let exec = ExecStage::new(Box::new(engine));
        let poh = PohService::new(Hash::default());
        // Very long interval (10 seconds) to ensure throttling.
        let pacer = PackPacer::new(10_000_000_000, u64::MAX);
        let mut pipeline = LeaderPipeline::with_pacer(pack, exec, poh, pacer);

        // Don't call begin_slot to avoid new_slot() resetting last_emit.
        // Instead, submit directly. The PackPacer::new() sets last_emit
        // far in the past, so the first call will succeed.
        pipeline.pack.new_block(1);
        pipeline.entries.clear();
        pipeline.microblocks_executed = 0;
        pipeline.stats = LeaderPipelineStats::default();

        pipeline.submit_transaction(make_tx(1, 5_000, 100_000));
        pipeline.submit_transaction(make_tx(2, 3_000, 100_000));

        // First step should succeed (pacer initialized with past timestamp).
        let r1 = pipeline.step();
        assert!(r1.is_some());

        // Second step should be throttled (10s interval not elapsed).
        let r2 = pipeline.step();
        assert!(r2.is_none());

        assert_eq!(pipeline.stats().pacing_delays, 1);
    }

    #[test]
    fn pacer_per_slot_limit() {
        let config = PackConfig {
            max_txns_per_microblock: 1,
            ..Default::default()
        };
        let pack = PackScheduler::with_config(config);
        let engine = MockExecutionEngine::new(50_000);
        let exec = ExecStage::new(Box::new(engine));
        let poh = PohService::new(Hash::default());
        // Allow max 1 microblock per slot, with zero interval.
        let pacer = PackPacer::new(0, 1);
        let mut pipeline = LeaderPipeline::with_pacer(pack, exec, poh, pacer);

        // Manually init to avoid new_slot() timestamp issues.
        pipeline.pack.new_block(1);
        pipeline.entries.clear();
        pipeline.microblocks_executed = 0;
        pipeline.stats = LeaderPipelineStats::default();

        pipeline.submit_transaction(make_tx(1, 5_000, 100_000));
        pipeline.submit_transaction(make_tx(2, 3_000, 100_000));

        // First step succeeds.
        assert!(pipeline.step().is_some());

        // Second step blocked by per-slot limit.
        assert!(pipeline.step().is_none());
        assert!(pipeline.stats().pacing_delays >= 1);
    }

    #[test]
    fn pipeline_without_pacer_produces_freely() {
        let config = PackConfig {
            max_txns_per_microblock: 1,
            ..Default::default()
        };
        let pack = PackScheduler::with_config(config);
        let engine = MockExecutionEngine::new(50_000);
        let exec = ExecStage::new(Box::new(engine));
        let poh = PohService::new(Hash::default());
        let mut pipeline = LeaderPipeline::new(pack, exec, poh);
        pipeline.begin_slot(1);

        for i in 0..5u8 {
            pipeline.submit_transaction(make_tx(i, 5_000, 100_000));
        }

        // All 5 should be produced without pacing delays (one per microblock).
        let mut count = 0;
        while pipeline.step().is_some() {
            count += 1;
        }
        assert_eq!(count, 5);
        assert_eq!(pipeline.stats().pacing_delays, 0);
    }

    #[test]
    fn fees_collected_tracks_priority_fees() {
        let config = PackConfig {
            max_txns_per_microblock: 1,
            ..Default::default()
        };
        let pack = PackScheduler::with_config(config);
        let engine = MockExecutionEngine::new(50_000);
        let exec = ExecStage::new(Box::new(engine));
        let poh = PohService::new(Hash::default());
        let mut pipeline = LeaderPipeline::new(pack, exec, poh);
        pipeline.begin_slot(1);

        pipeline.submit_transaction(make_tx(1, 5_000, 100_000));
        pipeline.submit_transaction(make_tx(2, 3_000, 100_000));

        pipeline.step();
        pipeline.step();

        // MockExecutionEngine succeeds, so fees = priority_fee per tx.
        assert_eq!(pipeline.stats().fees_collected, 8_000);
    }
}
