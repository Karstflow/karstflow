use crate::{AssembledBlock, Entry};
use paradencer_consensus::{
    Bank, CommitmentLevel, CommitmentTracker, CompiledInstruction, ExecutionBackend,
    SanitizedTransaction, TransactionExecutionResult, VoteUpdate,
};
use paradencer_constants::execution::MAX_COMPUTE_UNITS;
use paradencer_constants::transaction as tx_const;
use paradencer_execution::ExecutionBridge;
use paradencer_storage::Pubkey;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};

/// Result of processing a single transaction
#[derive(Debug, Clone)]
pub struct TransactionResult {
    /// Transaction index in block
    pub index: usize,
    /// Whether transaction executed successfully
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
    /// Compute units consumed
    pub compute_units: u64,
}

impl TransactionResult {
    pub fn success(index: usize, compute_units: u64) -> Self {
        Self {
            index,
            success: true,
            error: None,
            compute_units,
        }
    }

    pub fn failure(index: usize, error: String) -> Self {
        Self {
            index,
            success: false,
            error: Some(error),
            compute_units: 0,
        }
    }

    /// Convert a Bank execution result into a BlockProcessor transaction result.
    pub fn from_execution(index: usize, result: &TransactionExecutionResult) -> Self {
        if result.success {
            Self::success(index, result.compute_units_consumed)
        } else {
            let error_msg = result
                .error
                .as_ref()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "unknown execution error".to_string());
            Self {
                index,
                success: false,
                error: Some(error_msg),
                compute_units: result.compute_units_consumed,
            }
        }
    }
}

/// Fallback execution backend that rejects all instructions.
///
/// Used when no real backend is provided (e.g., during testing with
/// `BlockProcessor::new()`). In production, `SbpfExecutionAdapter`
/// should be passed via `BlockProcessor::with_backend()`.
struct NoopBackend;

impl ExecutionBackend for NoopBackend {
    fn execute_instruction(
        &self,
        _instruction: &paradencer_consensus::InstructionInfo,
        _remaining_compute_units: u64,
    ) -> paradencer_consensus::InstructionResult {
        paradencer_consensus::InstructionResult {
            success: false,
            compute_units_consumed: 0,
            modified_accounts: std::collections::HashMap::new(),
            logs: vec!["no execution backend configured".to_string()],
            error: Some("no execution backend configured".to_string()),
        }
    }
}

/// Outcome of processing a complete block
#[derive(Debug, Clone)]
pub struct BlockOutcome {
    /// Slot number
    pub slot: u64,
    /// Number of entries processed
    pub entry_count: usize,
    /// Transaction results
    pub transactions: Vec<TransactionResult>,
    /// Number of successfully executed transactions
    pub executed_count: usize,
    /// Number of failed transactions
    pub failed_count: usize,
    /// Total compute units consumed
    pub total_compute_units: u64,
    /// Hash of the final bank state
    pub final_hash: [u8; 32],
    /// Vote updates extracted from successful vote transactions.
    pub vote_updates: Vec<VoteUpdate>,
}

impl BlockOutcome {
    pub fn new(slot: u64, final_hash: [u8; 32]) -> Self {
        Self {
            slot,
            entry_count: 0,
            transactions: Vec::new(),
            executed_count: 0,
            failed_count: 0,
            total_compute_units: 0,
            final_hash,
            vote_updates: Vec::new(),
        }
    }

    pub fn add_transaction_result(&mut self, result: TransactionResult) {
        if result.success {
            self.executed_count += 1;
        } else {
            self.failed_count += 1;
        }
        self.total_compute_units += result.compute_units;
        self.transactions.push(result);
    }

    pub fn success_rate(&self) -> f64 {
        if self.transactions.is_empty() {
            return 1.0;
        }
        self.executed_count as f64 / self.transactions.len() as f64
    }
}

/// Errors that can occur during block processing
#[derive(Debug, Clone)]
pub enum BlockProcessorError {
    /// Bank is not in processing state
    BankNotProcessing(u64),
    /// Bank is frozen
    BankFrozen(u64),
    /// Entry processing failed
    EntryProcessingFailed { entry_index: usize, error: String },
    /// Transaction execution failed
    TransactionExecutionFailed { tx_index: usize, error: String },
    /// Tick registration failed
    TickRegistrationFailed { slot: u64, error: String },
    /// Invalid entry data
    InvalidEntry { entry_index: usize, reason: String },
    /// Entry hash does not match the expected PoH chain value
    EntryHashMismatch {
        entry_index: usize,
        expected: [u8; 32],
        actual: [u8; 32],
    },
    /// Commitment tracking error
    CommitmentError(String),
}

/// Processes blocks by applying transactions and managing state
///
/// Orchestrates:
/// - Entry processing
/// - Transaction execution via Bank + ExecutionBackend
/// - Tick registration
/// - Commitment tracking updates
pub struct BlockProcessor {
    /// Execution bridge for batch-level execution policies
    pub execution_bridge: Arc<ExecutionBridge>,
    /// Backend for instruction-level execution (routes to sBPF runtime)
    backend: Arc<dyn ExecutionBackend>,
    /// Commitment tracker for finality
    pub commitment_tracker: Arc<Mutex<CommitmentTracker>>,
}

impl BlockProcessor {
    pub fn new(
        execution_bridge: Arc<ExecutionBridge>,
        commitment_tracker: Arc<Mutex<CommitmentTracker>>,
    ) -> Self {
        Self::with_backend(
            execution_bridge,
            commitment_tracker,
            Arc::new(NoopBackend),
        )
    }

    pub fn with_backend(
        execution_bridge: Arc<ExecutionBridge>,
        commitment_tracker: Arc<Mutex<CommitmentTracker>>,
        backend: Arc<dyn ExecutionBackend>,
    ) -> Self {
        Self {
            execution_bridge,
            backend,
            commitment_tracker,
        }
    }

    /// Process a complete block
    ///
    /// Applies all entries and transactions to the bank, registers ticks,
    /// and updates commitment tracking.
    pub fn process_block(
        &mut self,
        block: AssembledBlock,
        bank: Arc<Bank>,
    ) -> Result<BlockOutcome, BlockProcessorError> {
        // Verify bank is in processing state
        if bank.is_frozen() {
            return Err(BlockProcessorError::BankFrozen(block.slot));
        }

        let mut outcome = BlockOutcome::new(block.slot, [0u8; 32]);
        outcome.entry_count = block.entries.len();

        // Process each entry in the block
        for (entry_index, entry) in block.entries.iter().enumerate() {
            self.process_entry(entry, entry_index, &bank, &mut outcome)?;
        }

        // Register any remaining ticks to complete the slot
        self.complete_slot_ticks(&bank, &block)?;

        // Get final bank hash
        outcome.final_hash = bank.hash();

        // Update commitment tracker
        self.update_commitment(&block, &outcome)?;

        Ok(outcome)
    }

    /// Process a single entry
    fn process_entry(
        &mut self,
        entry: &Entry,
        entry_index: usize,
        bank: &Arc<Bank>,
        outcome: &mut BlockOutcome,
    ) -> Result<(), BlockProcessorError> {
        // Register ticks for this entry
        for _ in 0..entry.num_hashes {
            if let Err(e) = bank.register_tick() {
                return Err(BlockProcessorError::TickRegistrationFailed {
                    slot: bank.slot(),
                    error: format!("{:?}", e),
                });
            }
        }

        // Process transactions in this entry
        if !entry.transactions.is_empty() {
            let tx_results = self.apply_transactions(
                &entry.transactions,
                bank,
                outcome.transactions.len(),
                &mut outcome.vote_updates,
            )?;
            for result in tx_results {
                outcome.add_transaction_result(result);
            }
        }

        Ok(())
    }

    /// Apply transactions from an entry
    pub fn apply_transactions(
        &mut self,
        transactions: &[Vec<u8>],
        bank: &Arc<Bank>,
        starting_index: usize,
        vote_updates: &mut Vec<VoteUpdate>,
    ) -> Result<Vec<TransactionResult>, BlockProcessorError> {
        let mut results = Vec::with_capacity(transactions.len());

        for (i, tx_data) in transactions.iter().enumerate() {
            let tx_index = starting_index + i;
            let result = self.execute_transaction(tx_data, tx_index, bank, vote_updates)?;
            results.push(result);
        }

        Ok(results)
    }

    /// Execute a single transaction through the Bank execution pipeline.
    ///
    /// Deserializes raw transaction bytes into a SanitizedTransaction,
    /// then delegates to Bank::process_transaction() for full execution
    /// including blockhash validation, signature verification, fee
    /// collection, and instruction execution via the backend.
    fn execute_transaction(
        &mut self,
        tx_data: &[u8],
        tx_index: usize,
        bank: &Arc<Bank>,
        vote_updates: &mut Vec<VoteUpdate>,
    ) -> Result<TransactionResult, BlockProcessorError> {
        if bank.is_frozen() {
            return Err(BlockProcessorError::BankFrozen(bank.slot()));
        }

        // Deserialize transaction from wire format
        let sanitized = match deserialize_transaction(tx_data) {
            Ok(tx) => tx,
            Err(msg) => {
                return Ok(TransactionResult::failure(tx_index, msg));
            }
        };

        // Execute through Bank pipeline (blockhash, sig verify, dedup, fees, instructions)
        let exec_result =
            bank.process_transaction(&sanitized, self.backend.as_ref(), MAX_COMPUTE_UNITS);

        // Collect vote updates from successful vote transactions
        if exec_result.success {
            vote_updates.extend(exec_result.vote_updates.iter().cloned());
        }

        Ok(TransactionResult::from_execution(tx_index, &exec_result))
    }

    /// Complete remaining ticks for a slot
    fn complete_slot_ticks(
        &self,
        bank: &Arc<Bank>,
        block: &AssembledBlock,
    ) -> Result<(), BlockProcessorError> {
        // Register any remaining ticks to complete the slot
        while !bank.is_complete() {
            if let Err(e) = bank.register_tick() {
                return Err(BlockProcessorError::TickRegistrationFailed {
                    slot: block.slot,
                    error: format!("{:?}", e),
                });
            }
        }

        Ok(())
    }

    /// Update commitment tracker with block outcome
    fn update_commitment(
        &mut self,
        block: &AssembledBlock,
        outcome: &BlockOutcome,
    ) -> Result<(), BlockProcessorError> {
        let mut tracker = self.commitment_tracker.lock().unwrap();

        // Mark slot as processed with execution metrics
        let executed = outcome.executed_count as u64;
        let total = outcome.transactions.len().max(1) as u64;
        tracker.mark_processed(block.slot, executed, total);

        Ok(())
    }

    /// Process a tick entry (entry with no transactions)
    pub fn process_tick(&self, bank: &Arc<Bank>) -> Result<(), BlockProcessorError> {
        bank.register_tick()
            .map_err(|e| BlockProcessorError::TickRegistrationFailed {
                slot: bank.slot(),
                error: format!("{:?}", e),
            })
    }

    /// Verify the PoH hash chain of entries in a block.
    ///
    /// Each entry's hash is produced by iterating SHA-256 `num_hashes` times
    /// starting from the previous entry's hash. For entries with transactions,
    /// the transaction data is mixed in before the final hash iteration.
    /// This ensures PoH continuity and prevents block tampering.
    pub fn verify_entry_chain(
        &self,
        entries: &[Entry],
        initial_hash: [u8; 32],
    ) -> Result<(), BlockProcessorError> {
        if entries.is_empty() {
            return Ok(());
        }

        let mut prev_hash = initial_hash;

        for (i, entry) in entries.iter().enumerate() {
            let expected = compute_entry_hash(&prev_hash, entry.num_hashes, &entry.transactions);

            if entry.hash != expected {
                return Err(BlockProcessorError::EntryHashMismatch {
                    entry_index: i,
                    expected,
                    actual: entry.hash,
                });
            }

            prev_hash = entry.hash;
        }

        Ok(())
    }

    /// Verify block structure and metadata
    pub fn verify_block(&self, block: &AssembledBlock) -> Result<(), BlockProcessorError> {
        // Check for empty block
        if block.entries.is_empty() {
            return Err(BlockProcessorError::InvalidEntry {
                entry_index: 0,
                reason: "Block has no entries".to_string(),
            });
        }

        // Verify entry structure
        for (i, entry) in block.entries.iter().enumerate() {
            if entry.hash == [0u8; 32] && i > 0 {
                return Err(BlockProcessorError::InvalidEntry {
                    entry_index: i,
                    reason: "Entry has zero hash".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Get statistics about processed blocks
    pub fn get_processing_stats(&self) -> BlockProcessingStats {
        // In a real implementation, this would track cumulative statistics
        BlockProcessingStats {
            total_blocks_processed: 0,
            total_transactions_executed: 0,
            total_compute_units: 0,
            average_success_rate: 0.0,
        }
    }
}

// ---------------------------------------------------------------------------
// Transaction wire-format deserialization
// ---------------------------------------------------------------------------

/// Decode a Solana compact-u16 value from the given byte slice.
///
/// Returns (decoded_value, bytes_consumed) or an error message.
fn decode_compact_u16(data: &[u8]) -> Result<(usize, usize), String> {
    if data.is_empty() {
        return Err("unexpected end of data for compact-u16".to_string());
    }

    let first = data[0] as usize;
    if first <= 0x7F {
        Ok((first, 1))
    } else {
        if data.len() < 2 {
            return Err("truncated compact-u16".to_string());
        }
        let value = ((first & 0x7F) << 8) | (data[1] as usize);
        Ok((value, 2))
    }
}

/// Deserialize a Solana binary transaction into a `SanitizedTransaction`.
///
/// Wire format (legacy transactions):
///   [compact-u16: signature_count]
///   [signature_count * 64 bytes: signatures]
///   [message bytes]:
///     [1 byte: num_required_signatures]
///     [1 byte: num_readonly_signed]
///     [1 byte: num_readonly_unsigned]
///     [compact-u16: num_account_keys]
///     [num_account_keys * 32 bytes: account keys]
///     [32 bytes: recent_blockhash]
///     [compact-u16: num_instructions]
///     per instruction:
///       [1 byte: program_id_index]
///       [compact-u16: num_account_indices]
///       [num_account_indices bytes: account indices]
///       [compact-u16: data_length]
///       [data_length bytes: instruction data]
fn deserialize_transaction(data: &[u8]) -> Result<SanitizedTransaction, String> {
    if data.len() < tx_const::MIN_TRANSACTION_SIZE {
        return Err(format!(
            "transaction too small: {} bytes (minimum {})",
            data.len(),
            tx_const::MIN_TRANSACTION_SIZE
        ));
    }
    if data.len() > tx_const::MAX_TRANSACTION_SIZE {
        return Err(format!(
            "transaction too large: {} bytes (maximum {})",
            data.len(),
            tx_const::MAX_TRANSACTION_SIZE
        ));
    }

    let mut offset = 0;

    // --- Signatures ---
    let (sig_count, compact_len) = decode_compact_u16(&data[offset..])?;
    offset += compact_len;

    if sig_count == 0 || sig_count > tx_const::MAX_SIGNATURES {
        return Err(format!("invalid signature count: {}", sig_count));
    }

    let sigs_len = sig_count * tx_const::SIGNATURE_SIZE;
    if data.len() < offset + sigs_len {
        return Err("truncated signature data".to_string());
    }

    let mut signatures = Vec::with_capacity(sig_count);
    for i in 0..sig_count {
        let start = offset + i * tx_const::SIGNATURE_SIZE;
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&data[start..start + tx_const::SIGNATURE_SIZE]);
        signatures.push(sig);
    }
    offset += sigs_len;

    // --- Message ---
    let message_start = offset;
    let message_bytes = data[message_start..].to_vec();

    if data.len() < offset + 3 {
        return Err("truncated message header".to_string());
    }

    let num_required_signatures = data[offset] as u64;
    let _num_readonly_signed = data[offset + 1];
    let _num_readonly_unsigned = data[offset + 2];
    offset += 3;

    // Account keys
    let (account_count, compact_len) = decode_compact_u16(&data[offset..])?;
    offset += compact_len;

    if account_count > tx_const::MAX_ACCOUNTS {
        return Err(format!("too many accounts: {}", account_count));
    }

    let keys_len = account_count * tx_const::PUBKEY_SIZE;
    if data.len() < offset + keys_len {
        return Err("truncated account keys".to_string());
    }

    let mut account_keys = Vec::with_capacity(account_count);
    for i in 0..account_count {
        let start = offset + i * tx_const::PUBKEY_SIZE;
        let mut key = [0u8; 32];
        key.copy_from_slice(&data[start..start + tx_const::PUBKEY_SIZE]);
        account_keys.push(Pubkey::from(key));
    }
    offset += keys_len;

    // Recent blockhash
    if data.len() < offset + tx_const::BLOCKHASH_SIZE {
        return Err("truncated blockhash".to_string());
    }
    let mut recent_blockhash = [0u8; 32];
    recent_blockhash.copy_from_slice(&data[offset..offset + tx_const::BLOCKHASH_SIZE]);
    offset += tx_const::BLOCKHASH_SIZE;

    // Instructions
    let (instruction_count, compact_len) = decode_compact_u16(&data[offset..])?;
    offset += compact_len;

    if instruction_count > tx_const::MAX_INSTRUCTIONS {
        return Err(format!("too many instructions: {}", instruction_count));
    }

    let mut instructions = Vec::with_capacity(instruction_count);
    for _ in 0..instruction_count {
        if offset >= data.len() {
            return Err("truncated instruction".to_string());
        }

        let program_id_index = data[offset];
        offset += 1;

        let (num_accounts, compact_len) = decode_compact_u16(&data[offset..])?;
        offset += compact_len;

        if data.len() < offset + num_accounts {
            return Err("truncated instruction account indices".to_string());
        }
        let account_indices = data[offset..offset + num_accounts].to_vec();
        offset += num_accounts;

        let (data_len, compact_len) = decode_compact_u16(&data[offset..])?;
        offset += compact_len;

        if data.len() < offset + data_len {
            return Err("truncated instruction data".to_string());
        }
        let instr_data = data[offset..offset + data_len].to_vec();
        offset += data_len;

        instructions.push(CompiledInstruction {
            program_id_index,
            account_indices,
            data: instr_data,
        });
    }

    Ok(SanitizedTransaction {
        account_keys,
        recent_blockhash,
        instructions,
        num_signatures: num_required_signatures,
        signatures,
        message_bytes,
    })
}

/// Serialize a `SanitizedTransaction` into Solana wire format bytes.
///
/// Used in tests to create properly-formatted transaction data for
/// the deserialization pipeline.
#[cfg(test)]
fn serialize_transaction(tx: &SanitizedTransaction) -> Vec<u8> {
    let mut data = Vec::new();

    // Signature count (compact-u16)
    encode_compact_u16(&mut data, tx.signatures.len());

    // Signatures
    for sig in &tx.signatures {
        data.extend_from_slice(sig);
    }

    // Message header
    data.push(tx.num_signatures as u8);
    data.push(0); // num_readonly_signed
    data.push(0); // num_readonly_unsigned

    // Account keys (compact-u16 count + keys)
    encode_compact_u16(&mut data, tx.account_keys.len());
    for key in &tx.account_keys {
        data.extend_from_slice(key.as_bytes());
    }

    // Recent blockhash
    data.extend_from_slice(&tx.recent_blockhash);

    // Instructions
    encode_compact_u16(&mut data, tx.instructions.len());
    for ix in &tx.instructions {
        data.push(ix.program_id_index);
        encode_compact_u16(&mut data, ix.account_indices.len());
        data.extend_from_slice(&ix.account_indices);
        encode_compact_u16(&mut data, ix.data.len());
        data.extend_from_slice(&ix.data);
    }

    data
}

/// Encode a value as Solana compact-u16.
#[cfg(test)]
fn encode_compact_u16(buf: &mut Vec<u8>, value: usize) {
    if value <= 0x7F {
        buf.push(value as u8);
    } else {
        buf.push(((value >> 8) & 0x7F) as u8 | 0x80);
        buf.push((value & 0xFF) as u8);
    }
}

/// Compute the expected PoH hash for an entry.
///
/// If the entry has no transactions, the hash is produced by iterating
/// SHA-256 `num_hashes` times starting from `prev_hash`.
///
/// If the entry has transactions, the transaction bytes are mixed into
/// the hash before the final iteration:
///   1. Hash prev_hash `num_hashes - 1` times
///   2. Mix in SHA-256(all transaction bytes)
///   3. Perform the final hash iteration
fn compute_entry_hash(prev_hash: &[u8; 32], num_hashes: u64, transactions: &[Vec<u8>]) -> [u8; 32] {
    let mut hash = *prev_hash;

    if transactions.is_empty() {
        // Tick entry — pure PoH hash chain
        for _ in 0..num_hashes {
            let mut hasher = Sha256::new();
            hasher.update(hash);
            hash = hasher.finalize().into();
        }
    } else {
        // Transaction entry — mix in transaction data
        let poh_iterations = num_hashes.saturating_sub(1);
        for _ in 0..poh_iterations {
            let mut hasher = Sha256::new();
            hasher.update(hash);
            hash = hasher.finalize().into();
        }

        // Mix transactions: SHA256(hash || SHA256(tx1 || tx2 || ...))
        let mut tx_hasher = Sha256::new();
        for tx in transactions {
            tx_hasher.update(tx);
        }
        let tx_hash: [u8; 32] = tx_hasher.finalize().into();

        let mut final_hasher = Sha256::new();
        final_hasher.update(hash);
        final_hasher.update(tx_hash);
        hash = final_hasher.finalize().into();
    }

    hash
}

/// Statistics for block processing
#[derive(Debug, Clone, Default)]
pub struct BlockProcessingStats {
    pub total_blocks_processed: u64,
    pub total_transactions_executed: u64,
    pub total_compute_units: u64,
    pub average_success_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use paradencer_consensus::{EpochSchedule, LeaderSchedule};
    use paradencer_storage::{AccountDatabase, Pubkey};

    fn create_test_bank() -> Arc<Bank> {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let validator = Pubkey::new_unique();
        let validators = vec![(validator, 1000)];
        let leader_schedule = Arc::new(LeaderSchedule::new(0, &validators).unwrap());
        Arc::new(Bank::new_genesis(accounts, epoch_schedule, leader_schedule))
    }

    fn create_test_block(slot: u64) -> AssembledBlock {
        AssembledBlock {
            slot,
            parent_slot: 0,
            entries: vec![Entry {
                num_hashes: 1,
                hash: [1u8; 32],
                transactions: vec![],
            }],
            transaction_count: 0,
            total_bytes: 100,
            shred_count: 1,
        }
    }

    #[test]
    fn block_processor_initializes() {
        let execution_bridge = Arc::new(ExecutionBridge::new());
        let commitment_tracker = Arc::new(Mutex::new(CommitmentTracker::default()));
        let _processor = BlockProcessor::new(execution_bridge, commitment_tracker);
    }

    #[test]
    fn block_outcome_tracks_results() {
        let mut outcome = BlockOutcome::new(100, [1u8; 32]);

        outcome.add_transaction_result(TransactionResult::success(0, 1000));
        outcome.add_transaction_result(TransactionResult::success(1, 2000));
        outcome.add_transaction_result(TransactionResult::failure(2, "Error".to_string()));

        assert_eq!(outcome.executed_count, 2);
        assert_eq!(outcome.failed_count, 1);
        assert_eq!(outcome.total_compute_units, 3000);
        assert!((outcome.success_rate() - 0.666).abs() < 0.01);
    }

    #[test]
    fn block_processor_verifies_blocks() {
        let execution_bridge = Arc::new(ExecutionBridge::new());
        let commitment_tracker = Arc::new(Mutex::new(CommitmentTracker::default()));
        let processor = BlockProcessor::new(execution_bridge, commitment_tracker);

        let valid_block = create_test_block(100);
        assert!(processor.verify_block(&valid_block).is_ok());

        let empty_block = AssembledBlock {
            slot: 100,
            parent_slot: 0,
            entries: vec![],
            transaction_count: 0,
            total_bytes: 0,
            shred_count: 0,
        };
        assert!(processor.verify_block(&empty_block).is_err());
    }

    #[test]
    fn transaction_result_creation() {
        let success = TransactionResult::success(0, 5000);
        assert!(success.success);
        assert_eq!(success.compute_units, 5000);
        assert!(success.error.is_none());

        let failure = TransactionResult::failure(1, "Out of compute".to_string());
        assert!(!failure.success);
        assert_eq!(failure.compute_units, 0);
        assert!(failure.error.is_some());
    }

    // --- Entry hash chain verification tests ---

    fn make_entry_chain(initial_hash: [u8; 32], count: usize) -> Vec<Entry> {
        let mut entries = Vec::with_capacity(count);
        let mut prev = initial_hash;
        for _ in 0..count {
            let hash = compute_entry_hash(&prev, 1, &[]);
            entries.push(Entry {
                num_hashes: 1,
                hash,
                transactions: vec![],
            });
            prev = hash;
        }
        entries
    }

    #[test]
    fn valid_entry_chain_passes_verification() {
        let processor = BlockProcessor::new(
            Arc::new(ExecutionBridge::new()),
            Arc::new(Mutex::new(CommitmentTracker::default())),
        );

        let initial_hash = [0xABu8; 32];
        let entries = make_entry_chain(initial_hash, 5);

        let result = processor.verify_entry_chain(&entries, initial_hash);
        assert!(result.is_ok());
    }

    #[test]
    fn corrupted_entry_hash_rejected() {
        let processor = BlockProcessor::new(
            Arc::new(ExecutionBridge::new()),
            Arc::new(Mutex::new(CommitmentTracker::default())),
        );

        let initial_hash = [0xABu8; 32];
        let mut entries = make_entry_chain(initial_hash, 3);

        // Corrupt the second entry's hash
        entries[1].hash = [0xFFu8; 32];

        let result = processor.verify_entry_chain(&entries, initial_hash);
        assert!(result.is_err());
        match result.unwrap_err() {
            BlockProcessorError::EntryHashMismatch { entry_index, .. } => {
                assert_eq!(entry_index, 1);
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn empty_block_passes_verification() {
        let processor = BlockProcessor::new(
            Arc::new(ExecutionBridge::new()),
            Arc::new(Mutex::new(CommitmentTracker::default())),
        );

        let result = processor.verify_entry_chain(&[], [0u8; 32]);
        assert!(result.is_ok());
    }

    #[test]
    fn single_entry_block_verified() {
        let processor = BlockProcessor::new(
            Arc::new(ExecutionBridge::new()),
            Arc::new(Mutex::new(CommitmentTracker::default())),
        );

        let initial_hash = [0u8; 32];
        let entries = make_entry_chain(initial_hash, 1);

        let result = processor.verify_entry_chain(&entries, initial_hash);
        assert!(result.is_ok());
    }

    #[test]
    fn entry_with_transactions_hash_verified() {
        let processor = BlockProcessor::new(
            Arc::new(ExecutionBridge::new()),
            Arc::new(Mutex::new(CommitmentTracker::default())),
        );

        let initial_hash = [0u8; 32];
        let txns = vec![vec![1, 2, 3], vec![4, 5, 6]];
        let expected_hash = compute_entry_hash(&initial_hash, 2, &txns);

        let entries = vec![Entry {
            num_hashes: 2,
            hash: expected_hash,
            transactions: txns,
        }];

        let result = processor.verify_entry_chain(&entries, initial_hash);
        assert!(result.is_ok());
    }

    #[test]
    fn wrong_initial_hash_fails() {
        let processor = BlockProcessor::new(
            Arc::new(ExecutionBridge::new()),
            Arc::new(Mutex::new(CommitmentTracker::default())),
        );

        let initial_hash = [0xABu8; 32];
        let entries = make_entry_chain(initial_hash, 3);

        // Verify with a different initial hash
        let wrong_initial = [0xCDu8; 32];
        let result = processor.verify_entry_chain(&entries, wrong_initial);
        assert!(result.is_err());
    }

    // --- Transaction deserialization tests ---

    use ed25519_dalek::{Signer, SigningKey};

    /// Build a signed serialized transaction for testing.
    ///
    /// Creates a real Ed25519 signature over the message bytes so that
    /// Bank::process_transaction() signature verification passes.
    fn build_signed_wire_tx(
        signing_key: &SigningKey,
        program: &Pubkey,
        blockhash: [u8; 32],
        instruction_data: Vec<u8>,
    ) -> Vec<u8> {
        build_signed_wire_tx_with_keys(
            signing_key,
            &[*program],
            blockhash,
            vec![CompiledInstruction {
                program_id_index: 1,
                account_indices: vec![0],
                data: instruction_data,
            }],
        )
    }

    /// Build a signed wire transaction with custom account keys and instructions.
    fn build_signed_wire_tx_with_keys(
        signing_key: &SigningKey,
        extra_keys: &[Pubkey],
        blockhash: [u8; 32],
        instructions: Vec<CompiledInstruction>,
    ) -> Vec<u8> {
        let payer = Pubkey::from(signing_key.verifying_key().to_bytes());
        let mut account_keys = vec![payer];
        account_keys.extend_from_slice(extra_keys);

        // Build message bytes first (what gets signed)
        let mut message_bytes = Vec::new();
        // Header
        message_bytes.push(1); // num_required_signatures
        message_bytes.push(0); // num_readonly_signed
        message_bytes.push(0); // num_readonly_unsigned
        // Account keys
        encode_compact_u16(&mut message_bytes, account_keys.len());
        for key in &account_keys {
            message_bytes.extend_from_slice(key.as_bytes());
        }
        // Blockhash
        message_bytes.extend_from_slice(&blockhash);
        // Instructions
        encode_compact_u16(&mut message_bytes, instructions.len());
        for ix in &instructions {
            message_bytes.push(ix.program_id_index);
            encode_compact_u16(&mut message_bytes, ix.account_indices.len());
            message_bytes.extend_from_slice(&ix.account_indices);
            encode_compact_u16(&mut message_bytes, ix.data.len());
            message_bytes.extend_from_slice(&ix.data);
        }

        // Sign the message
        let signature = signing_key.sign(&message_bytes);

        // Build full wire-format transaction
        let mut wire = Vec::new();
        encode_compact_u16(&mut wire, 1); // 1 signature
        wire.extend_from_slice(&signature.to_bytes());
        wire.extend_from_slice(&message_bytes);

        wire
    }

    #[test]
    fn compact_u16_roundtrip() {
        for &value in &[0usize, 1, 127, 128, 255, 300, 1000, 16383] {
            let mut buf = Vec::new();
            encode_compact_u16(&mut buf, value);
            let (decoded, _len) = decode_compact_u16(&buf).unwrap();
            assert_eq!(decoded, value, "compact-u16 roundtrip failed for {}", value);
        }
    }

    #[test]
    fn deserialize_roundtrip() {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let payer = Pubkey::from(signing_key.verifying_key().to_bytes());
        let program = Pubkey::new_unique();
        let blockhash = [0x42u8; 32];
        let instr_data = vec![1, 2, 3, 4, 5];

        let wire_bytes =
            build_signed_wire_tx(&signing_key, &program, blockhash, instr_data.clone());
        let tx = deserialize_transaction(&wire_bytes).unwrap();

        assert_eq!(tx.account_keys.len(), 2);
        assert_eq!(tx.account_keys[0], payer);
        assert_eq!(tx.account_keys[1], program);
        assert_eq!(tx.recent_blockhash, blockhash);
        assert_eq!(tx.num_signatures, 1);
        assert_eq!(tx.signatures.len(), 1);
        assert_eq!(tx.instructions.len(), 1);
        assert_eq!(tx.instructions[0].program_id_index, 1);
        assert_eq!(tx.instructions[0].account_indices, vec![0]);
        assert_eq!(tx.instructions[0].data, instr_data);
    }

    #[test]
    fn deserialize_rejects_truncated_data() {
        // Way too short
        assert!(deserialize_transaction(&[0u8; 10]).is_err());
    }

    #[test]
    fn deserialize_rejects_zero_signatures() {
        // compact-u16 value 0 for signature count
        let mut data = vec![0u8; 200];
        data[0] = 0; // sig count = 0
        assert!(deserialize_transaction(&data).is_err());
    }

    #[test]
    fn deserialize_multiple_instructions() {
        let payer = Pubkey::new_unique();
        let program = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();

        let tx = SanitizedTransaction {
            account_keys: vec![payer, program, recipient],
            recent_blockhash: [0u8; 32],
            instructions: vec![
                CompiledInstruction {
                    program_id_index: 1,
                    account_indices: vec![0, 2],
                    data: vec![10, 20],
                },
                CompiledInstruction {
                    program_id_index: 1,
                    account_indices: vec![2],
                    data: vec![30],
                },
            ],
            num_signatures: 1,
            signatures: vec![[0u8; 64]],
            message_bytes: vec![],
        };
        let wire = serialize_transaction(&tx);
        let parsed = deserialize_transaction(&wire).unwrap();

        assert_eq!(parsed.instructions.len(), 2);
        assert_eq!(parsed.instructions[0].account_indices, vec![0, 2]);
        assert_eq!(parsed.instructions[0].data, vec![10, 20]);
        assert_eq!(parsed.instructions[1].account_indices, vec![2]);
        assert_eq!(parsed.instructions[1].data, vec![30]);
    }

    // --- Live execution tests ---

    use paradencer_consensus::{
        BlockhashInfo, ExecutionBackend as ConsensusExecutionBackend, InstructionInfo,
        InstructionResult,
    };
    use paradencer_storage::{Account, TransactionId};
    use std::collections::HashMap;

    /// Backend that passes all accounts through as modified (always succeeds).
    struct TestPassthroughBackend;

    impl ConsensusExecutionBackend for TestPassthroughBackend {
        fn execute_instruction(
            &self,
            instruction: &InstructionInfo,
            _remaining: u64,
        ) -> InstructionResult {
            let modified: HashMap<Pubkey, Account> = instruction
                .accounts
                .iter()
                .map(|(k, a, _)| (*k, a.clone()))
                .collect();
            InstructionResult {
                success: true,
                compute_units_consumed: 200,
                modified_accounts: modified,
                logs: vec!["ok".to_string()],
                error: None,
            }
        }
    }

    fn create_test_bank_with_blockhash(blockhash: [u8; 32]) -> Arc<Bank> {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let validator = Pubkey::new_unique();
        let validators = vec![(validator, 1000)];
        let leader_schedule = Arc::new(LeaderSchedule::new(0, &validators).unwrap());
        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);
        // Register the given blockhash so transactions using it pass validation
        let info = BlockhashInfo::new(Pubkey::from(blockhash), 5000, 0);
        bank.blockhash_queue().write().unwrap().register_hash(info);
        Arc::new(bank)
    }

    fn store_test_account(bank: &Bank, pubkey: &Pubkey, account: &Account) {
        let db = bank.accounts();
        let xid = TransactionId::new([0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]);
        db.write_account(xid, *pubkey, account.clone()).unwrap();
        db.publish_transaction(xid).unwrap();
    }

    #[test]
    fn execute_transaction_with_real_backend() {
        let blockhash = [0u8; 32];
        let bank = create_test_bank_with_blockhash(blockhash);

        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let payer = Pubkey::from(signing_key.verifying_key().to_bytes());
        let program = Pubkey::new_unique();
        let payer_account = Account::new(1_000_000, vec![], Pubkey::default());
        store_test_account(&bank, &payer, &payer_account);

        let backend: Arc<dyn ConsensusExecutionBackend> = Arc::new(TestPassthroughBackend);
        let mut processor = BlockProcessor::with_backend(
            Arc::new(ExecutionBridge::new()),
            Arc::new(Mutex::new(CommitmentTracker::default())),
            backend,
        );

        let wire_tx = build_signed_wire_tx(&signing_key, &program, blockhash, vec![42]);
        let mut vote_updates = Vec::new();
        let result = processor
            .execute_transaction(&wire_tx, 0, &bank, &mut vote_updates)
            .unwrap();

        assert!(result.success, "should succeed: {:?}", result.error);
        assert!(result.compute_units > 0);
    }

    #[test]
    fn execute_transaction_fails_with_bad_blockhash() {
        let bank = create_test_bank_with_blockhash([0u8; 32]);

        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let payer = Pubkey::from(signing_key.verifying_key().to_bytes());
        let program = Pubkey::new_unique();
        let payer_account = Account::new(1_000_000, vec![], Pubkey::default());
        store_test_account(&bank, &payer, &payer_account);

        let backend: Arc<dyn ConsensusExecutionBackend> = Arc::new(TestPassthroughBackend);
        let mut processor = BlockProcessor::with_backend(
            Arc::new(ExecutionBridge::new()),
            Arc::new(Mutex::new(CommitmentTracker::default())),
            backend,
        );

        // Use a blockhash that is NOT registered
        let bad_blockhash = [0xFFu8; 32];
        let wire_tx = build_signed_wire_tx(&signing_key, &program, bad_blockhash, vec![]);
        let mut vote_updates = Vec::new();
        let result = processor
            .execute_transaction(&wire_tx, 0, &bank, &mut vote_updates)
            .unwrap();

        assert!(!result.success);
        assert!(
            result.error.as_ref().unwrap().contains("blockhash"),
            "error should mention blockhash: {:?}",
            result.error
        );
    }

    #[test]
    fn apply_transactions_processes_batch() {
        let blockhash = [0u8; 32];
        let bank = create_test_bank_with_blockhash(blockhash);

        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let payer = Pubkey::from(signing_key.verifying_key().to_bytes());
        let program = Pubkey::new_unique();
        let payer_account = Account::new(100_000_000, vec![], Pubkey::default());
        store_test_account(&bank, &payer, &payer_account);

        let backend: Arc<dyn ConsensusExecutionBackend> = Arc::new(TestPassthroughBackend);
        let mut processor = BlockProcessor::with_backend(
            Arc::new(ExecutionBridge::new()),
            Arc::new(Mutex::new(CommitmentTracker::default())),
            backend,
        );

        let txs: Vec<Vec<u8>> = (0..3)
            .map(|i| build_signed_wire_tx(&signing_key, &program, blockhash, vec![i]))
            .collect();

        let mut vote_updates = Vec::new();
        let results = processor
            .apply_transactions(&txs, &bank, 0, &mut vote_updates)
            .unwrap();

        assert_eq!(results.len(), 3);
        // First transaction should always succeed; others may be rejected
        // as duplicates since they use the same signing key
        assert!(
            results[0].success,
            "first tx should succeed: {:?}",
            results[0].error
        );
    }

    #[test]
    fn block_with_transactions_executes_through_bank() {
        let blockhash = [0u8; 32];
        let bank = create_test_bank_with_blockhash(blockhash);

        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let payer = Pubkey::from(signing_key.verifying_key().to_bytes());
        let program = Pubkey::new_unique();
        let payer_account = Account::new(100_000_000, vec![], Pubkey::default());
        store_test_account(&bank, &payer, &payer_account);

        let backend: Arc<dyn ConsensusExecutionBackend> = Arc::new(TestPassthroughBackend);
        let mut processor = BlockProcessor::with_backend(
            Arc::new(ExecutionBridge::new()),
            Arc::new(Mutex::new(CommitmentTracker::default())),
            backend,
        );

        let wire_tx = build_signed_wire_tx(&signing_key, &program, blockhash, vec![1, 2, 3]);
        let block = AssembledBlock {
            slot: 0,
            parent_slot: 0,
            entries: vec![Entry {
                num_hashes: 1,
                hash: [1u8; 32], // skip PoH verification for this test
                transactions: vec![wire_tx],
            }],
            transaction_count: 1,
            total_bytes: 200,
            shred_count: 1,
        };

        let outcome = processor.process_block(block, bank).unwrap();
        assert_eq!(outcome.transactions.len(), 1);

        let first = &outcome.transactions[0];
        assert!(first.success, "tx should succeed: {:?}", first.error);
        assert!(outcome.total_compute_units > 0);
    }

    #[test]
    fn deserialization_failure_returns_transaction_failure() {
        let bank = create_test_bank_with_blockhash([0u8; 32]);

        let backend: Arc<dyn ConsensusExecutionBackend> = Arc::new(TestPassthroughBackend);
        let mut processor = BlockProcessor::with_backend(
            Arc::new(ExecutionBridge::new()),
            Arc::new(Mutex::new(CommitmentTracker::default())),
            backend,
        );

        // Garbage data that can't be deserialized
        let garbage = vec![0xFF; 50];
        let mut vote_updates = Vec::new();
        let result = processor
            .execute_transaction(&garbage, 0, &bank, &mut vote_updates)
            .unwrap();

        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[test]
    fn vote_updates_propagated_from_block_execution() {
        use paradencer_ids::VOTE_PROGRAM_ID;

        let blockhash = [0u8; 32];
        let bank = create_test_bank_with_blockhash(blockhash);

        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let payer = Pubkey::from(signing_key.verifying_key().to_bytes());
        let vote_account = Pubkey::new_unique();
        let payer_account = Account::new(100_000_000, vec![], Pubkey::default());
        store_test_account(&bank, &payer, &payer_account);

        let backend: Arc<dyn ConsensusExecutionBackend> = Arc::new(TestPassthroughBackend);
        let mut processor = BlockProcessor::with_backend(
            Arc::new(ExecutionBridge::new()),
            Arc::new(Mutex::new(CommitmentTracker::default())),
            backend,
        );

        // Build a vote transaction (instruction type 2 = Vote)
        let mut vote_data = Vec::new();
        vote_data.extend_from_slice(&2u32.to_le_bytes()); // Vote instruction type
        vote_data.extend_from_slice(&1u64.to_le_bytes()); // 1 slot
        vote_data.extend_from_slice(&42u64.to_le_bytes()); // slot 42
        vote_data.extend_from_slice(&[0u8; 32]); // hash

        let wire_tx = build_signed_wire_tx_with_keys(
            &signing_key,
            &[VOTE_PROGRAM_ID, vote_account],
            blockhash,
            vec![CompiledInstruction {
                program_id_index: 1,
                account_indices: vec![2],
                data: vote_data,
            }],
        );

        let block = AssembledBlock {
            slot: 0,
            parent_slot: 0,
            entries: vec![Entry {
                num_hashes: 1,
                hash: [1u8; 32],
                transactions: vec![wire_tx],
            }],
            transaction_count: 1,
            total_bytes: 300,
            shred_count: 1,
        };

        let outcome = processor.process_block(block, bank).unwrap();

        assert_eq!(outcome.transactions.len(), 1);
        assert!(
            outcome.transactions[0].success,
            "vote tx should succeed: {:?}",
            outcome.transactions[0].error
        );
        assert!(
            !outcome.vote_updates.is_empty(),
            "should have extracted vote updates"
        );
        assert_eq!(outcome.vote_updates[0].vote_account, vote_account);
        assert_eq!(outcome.vote_updates[0].voted_slot, Some(42));
    }
}
