use crate::{AssembledBlock, Entry};
use paradencer_consensus::{Bank, CommitmentLevel, CommitmentTracker};
use paradencer_execution::ExecutionBridge;
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
/// - Transaction execution via ExecutionBridge
/// - Tick registration
/// - Commitment tracking updates
pub struct BlockProcessor {
    /// Execution bridge for transaction processing
    pub execution_bridge: Arc<ExecutionBridge>,
    /// Commitment tracker for finality
    pub commitment_tracker: Arc<Mutex<CommitmentTracker>>,
}

impl BlockProcessor {
    pub fn new(
        execution_bridge: Arc<ExecutionBridge>,
        commitment_tracker: Arc<Mutex<CommitmentTracker>>,
    ) -> Self {
        Self {
            execution_bridge,
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
            let tx_results =
                self.apply_transactions(&entry.transactions, bank, outcome.transactions.len())?;
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
    ) -> Result<Vec<TransactionResult>, BlockProcessorError> {
        let mut results = Vec::with_capacity(transactions.len());

        for (i, tx_data) in transactions.iter().enumerate() {
            let tx_index = starting_index + i;

            // In a real implementation, this would:
            // 1. Deserialize transaction from bytes
            // 2. Validate transaction
            // 3. Execute via ExecutionBridge
            // 4. Update bank state

            // For now, we simulate successful execution
            // In production, this would use ExecutionBridge.try_execute_batch()
            let result = self.execute_transaction(tx_data, tx_index, bank)?;
            results.push(result);
        }

        Ok(results)
    }

    /// Execute a single transaction
    fn execute_transaction(
        &mut self,
        _tx_data: &[u8],
        tx_index: usize,
        bank: &Arc<Bank>,
    ) -> Result<TransactionResult, BlockProcessorError> {
        // Verify bank can accept transactions
        if bank.is_frozen() {
            return Err(BlockProcessorError::BankFrozen(bank.slot()));
        }

        // In a real implementation:
        // 1. Deserialize transaction
        // 2. Verify signatures
        // 3. Execute via ExecutionBridge
        // 4. Collect fees
        // 5. Update accounts

        // For now, simulate successful execution
        let compute_units = 1000; // Mock compute units
        Ok(TransactionResult::success(tx_index, compute_units))
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

        // Mark slot as processed
        tracker.mark_processed(block.slot, 0, 1000); // Mock stake values

        // Update based on success rate
        if outcome.success_rate() >= 0.9 {
            // High success rate - potentially confirmable
            tracker.update_stake(block.slot, 700, 1000); // Mock supermajority
        }

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
}
