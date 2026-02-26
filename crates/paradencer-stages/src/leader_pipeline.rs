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
use crate::block_producer::{Entry, MicroblockEntry, PohService, PohState};
use crate::exec_stage::{ExecStage, ExecutionEngine, MicroblockExecResult, TransactionExecResult};
use crate::pack_stage::{PackScheduler, PackedTransaction};
use paradencer_sbpf::TransactionProcessor;
use paradencer_types::{Account, Pubkey};
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
            processor: Arc::new(TransactionProcessor::new()),
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
        use paradencer_sbpf::{
            CompiledInstruction as SbpfCompiledInstruction, Transaction as SbpfTransaction,
            TransactionMessage as SbpfTransactionMessage,
        };

        // Parse the wire-format transaction.
        match paradencer_types::parse_transaction(&tx.payload) {
            Ok(parsed) => {
                // Account keys are already Pubkey in paradencer-types.
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
                        header: paradencer_sbpf::MessageHeader {
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
                    .keys()
                    .map(|k| (k.to_bytes(), Vec::new()))
                    .collect();

                TransactionExecResult {
                    payload: tx.payload.clone(),
                    success: result.success,
                    compute_units_consumed: result.compute_units_consumed,
                    fee_paid: if result.success { tx.priority_fee } else { 0 },
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
                    fee_paid: 0,
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

/// The leader block production pipeline.
///
/// Call `step()` repeatedly during a leader slot to produce and execute
/// microblocks. Between steps, call `advance_poh()` to produce tick entries.
/// When the slot is complete, call `finish_slot()`.
pub struct LeaderPipeline {
    pack: PackScheduler,
    exec: ExecStage,
    poh: PohService,
    /// Accumulated entries for the current slot.
    entries: Vec<Entry>,
    /// Count of microblocks executed in this slot.
    microblocks_executed: u64,
}

impl LeaderPipeline {
    /// Create a new pipeline with the given components.
    pub fn new(pack: PackScheduler, exec: ExecStage, poh: PohService) -> Self {
        Self {
            pack,
            exec,
            poh,
            entries: Vec::new(),
            microblocks_executed: 0,
        }
    }

    /// Start a new leader slot. Resets pack limits and configures PoH.
    pub fn begin_slot(&mut self, slot: u64) {
        self.pack.new_block(slot);
        self.entries.clear();
        self.microblocks_executed = 0;
    }

    /// Submit a transaction for scheduling.
    pub fn submit_transaction(&mut self, tx: PackedTransaction) {
        self.pack.submit(tx);
    }

    /// Try to produce and execute one microblock.
    ///
    /// Returns `None` if no transactions are available or block is full.
    /// On success, the microblock is executed, the mixin hash is fed to PoH,
    /// and pack locks are released.
    pub fn step(&mut self) -> Option<PipelineStepResult> {
        // 1. Pack: produce next microblock
        let microblock = self.pack.produce_microblock()?;
        let microblock_id = microblock.id;

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
        }

        // 5. Release pack locks for this microblock
        self.pack.complete_microblock(microblock_id);

        self.microblocks_executed += 1;

        Some(PipelineStepResult {
            exec_result,
            poh_entry,
            microblock_id,
        })
    }

    /// Advance PoH by the given number of hashes, collecting tick entries.
    pub fn advance_poh(&mut self, target_hashes: u64) {
        let new_entries = self.poh.advance(target_hashes);
        self.entries.extend(new_entries);
    }

    /// Finish the current slot. Returns all accumulated entries and the
    /// slot completion signal.
    pub fn finish_slot(&mut self) -> Vec<Entry> {
        let (final_entries, _slot_complete) = self.poh.finish_slot();
        self.entries.extend(final_entries);
        std::mem::take(&mut self.entries)
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
    use paradencer_types::Hash;

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
        let result = MicroblockExecResult {
            microblock_id: 0,
            transaction_results: vec![TransactionExecResult {
                payload: vec![0xAA; 128],
                success: true,
                compute_units_consumed: 100,
                fee_paid: 50,
                error: None,
                logs: vec![],
                modified_accounts: vec![],
            }],
            total_compute_units: 100,
            success_count: 1,
            failure_count: 0,
            entry_hash: [0u8; 32],
        };

        let hash1 = compute_mixin_hash(&result);
        let hash2 = compute_mixin_hash(&result);
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, [0u8; 32]); // Not all zeros.
    }

    #[test]
    fn mixin_hash_differs_by_signature() {
        let make_result = |payload: Vec<u8>| MicroblockExecResult {
            microblock_id: 0,
            transaction_results: vec![TransactionExecResult {
                payload,
                success: true,
                compute_units_consumed: 100,
                fee_paid: 50,
                error: None,
                logs: vec![],
                modified_accounts: vec![],
            }],
            total_compute_units: 100,
            success_count: 1,
            failure_count: 0,
            entry_hash: [0u8; 32],
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
}
