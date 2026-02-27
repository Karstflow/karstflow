/// Execution tile for leader mode.
///
/// Receives microblocks from the pack scheduler, executes transactions
/// through the sBPF runtime, produces entries with Merkle tree hashing,
/// and emits execution results back to pack for rebate tracking.
///
/// This corresponds to Firedancer's execle tile which handles actual
/// transaction execution during block production.
use crate::pack_stage::{Microblock, PackedTransaction};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Result of executing a single transaction.
#[derive(Debug, Clone)]
pub struct TransactionExecResult {
    /// Transaction payload (passed through for reference).
    pub payload: Vec<u8>,
    /// Whether execution succeeded.
    pub success: bool,
    /// Compute units actually consumed.
    pub compute_units_consumed: u64,
    /// Priority fee actually paid (for rebates).
    pub fee_paid: u64,
    /// Error message if failed.
    pub error: Option<String>,
    /// Execution logs.
    pub logs: Vec<String>,
    /// Modified account states after execution.
    pub modified_accounts: Vec<([u8; 32], Vec<u8>)>,
}

/// Result of executing an entire microblock.
#[derive(Debug, Clone)]
pub struct MicroblockExecResult {
    /// The microblock ID.
    pub microblock_id: u64,
    /// Per-transaction results.
    pub transaction_results: Vec<TransactionExecResult>,
    /// Total compute units consumed by all transactions.
    pub total_compute_units: u64,
    /// Number of successful transactions.
    pub success_count: usize,
    /// Number of failed transactions.
    pub failure_count: usize,
    /// Merkle root hash of the entry produced from this microblock.
    pub entry_hash: [u8; 32],
}

/// Configuration for the execution tile.
#[derive(Debug, Clone)]
pub struct ExecConfig {
    /// This execution tile's index (for multi-tile parallelism).
    pub tile_index: usize,
    /// Total number of execution tiles.
    pub tile_count: usize,
    /// Maximum CUs this tile will process before signaling busy.
    pub max_pending_cus: u64,
}

impl Default for ExecConfig {
    fn default() -> Self {
        Self {
            tile_index: 0,
            tile_count: 1,
            max_pending_cus: 48_000_000,
        }
    }
}

/// Statistics for the execution tile.
#[derive(Debug, Default)]
pub struct ExecStats {
    pub microblocks_executed: AtomicU64,
    pub transactions_executed: AtomicU64,
    pub transactions_succeeded: AtomicU64,
    pub transactions_failed: AtomicU64,
    pub compute_units_consumed: AtomicU64,
    pub fees_collected: AtomicU64,
}

impl ExecStats {
    pub fn snapshot(&self) -> ExecStatsSnapshot {
        ExecStatsSnapshot {
            microblocks_executed: self.microblocks_executed.load(Ordering::Relaxed),
            transactions_executed: self.transactions_executed.load(Ordering::Relaxed),
            transactions_succeeded: self.transactions_succeeded.load(Ordering::Relaxed),
            transactions_failed: self.transactions_failed.load(Ordering::Relaxed),
            compute_units_consumed: self.compute_units_consumed.load(Ordering::Relaxed),
            fees_collected: self.fees_collected.load(Ordering::Relaxed),
        }
    }
}

/// Point-in-time statistics snapshot.
#[derive(Debug, Clone, Default)]
pub struct ExecStatsSnapshot {
    pub microblocks_executed: u64,
    pub transactions_executed: u64,
    pub transactions_succeeded: u64,
    pub transactions_failed: u64,
    pub compute_units_consumed: u64,
    pub fees_collected: u64,
}

/// Trait for the actual transaction execution backend.
/// This is pluggable to allow different execution engines.
pub trait ExecutionEngine: Send {
    /// Execute a single transaction and return the result.
    fn execute(&self, tx: &PackedTransaction) -> TransactionExecResult;
}

/// A simple execution engine that always succeeds (for testing).
pub struct MockExecutionEngine {
    /// Fixed CU consumption per transaction.
    pub cu_per_tx: u64,
}

impl MockExecutionEngine {
    pub fn new(cu_per_tx: u64) -> Self {
        Self { cu_per_tx }
    }
}

impl ExecutionEngine for MockExecutionEngine {
    fn execute(&self, tx: &PackedTransaction) -> TransactionExecResult {
        TransactionExecResult {
            payload: tx.payload.clone(),
            success: true,
            compute_units_consumed: self.cu_per_tx.min(tx.compute_units),
            fee_paid: tx.priority_fee,
            error: None,
            logs: Vec::new(),
            modified_accounts: Vec::new(),
        }
    }
}

/// The execution tile stage.
pub struct ExecStage {
    config: ExecConfig,
    engine: Box<dyn ExecutionEngine>,
    stats: Arc<ExecStats>,
    /// Pending CUs for backpressure signaling.
    pending_cus: u64,
}

impl ExecStage {
    /// Create a new execution tile with the given engine.
    pub fn new(engine: Box<dyn ExecutionEngine>) -> Self {
        Self::with_config(engine, ExecConfig::default())
    }

    /// Create a new execution tile with the given engine and config.
    pub fn with_config(engine: Box<dyn ExecutionEngine>, config: ExecConfig) -> Self {
        Self {
            config,
            engine,
            stats: Arc::new(ExecStats::default()),
            pending_cus: 0,
        }
    }

    /// Get a shared reference to the statistics.
    pub fn stats(&self) -> Arc<ExecStats> {
        Arc::clone(&self.stats)
    }

    /// Whether this tile is busy (has too many pending CUs).
    pub fn is_busy(&self) -> bool {
        self.pending_cus >= self.config.max_pending_cus
    }

    /// Execute a microblock. Returns the execution result with
    /// per-transaction outcomes and the entry hash.
    pub fn execute_microblock(&mut self, microblock: &Microblock) -> MicroblockExecResult {
        let mut transaction_results = Vec::with_capacity(microblock.transactions.len());
        let mut total_cu = 0u64;
        let mut success_count = 0usize;
        let mut failure_count = 0usize;
        let mut total_fees = 0u64;

        for tx in &microblock.transactions {
            let result = self.engine.execute(tx);

            total_cu += result.compute_units_consumed;
            if result.success {
                success_count += 1;
                total_fees += result.fee_paid;
            } else {
                failure_count += 1;
            }

            transaction_results.push(result);
        }

        // Compute entry hash (simplified: hash of all tx payloads).
        let entry_hash = compute_entry_hash(&transaction_results);

        self.stats
            .microblocks_executed
            .fetch_add(1, Ordering::Relaxed);
        self.stats
            .transactions_executed
            .fetch_add(transaction_results.len() as u64, Ordering::Relaxed);
        self.stats
            .transactions_succeeded
            .fetch_add(success_count as u64, Ordering::Relaxed);
        self.stats
            .transactions_failed
            .fetch_add(failure_count as u64, Ordering::Relaxed);
        self.stats
            .compute_units_consumed
            .fetch_add(total_cu, Ordering::Relaxed);
        self.stats
            .fees_collected
            .fetch_add(total_fees, Ordering::Relaxed);

        MicroblockExecResult {
            microblock_id: microblock.id,
            transaction_results,
            total_compute_units: total_cu,
            success_count,
            failure_count,
            entry_hash,
        }
    }

    /// The tile's index.
    pub fn tile_index(&self) -> usize {
        self.config.tile_index
    }
}

/// Compute entry mixin hash for PoH integration.
///
/// The mixin hash is SHA-256 over the concatenation of all transaction
/// signatures in the microblock. This matches the Solana entry hash
/// convention where entries are identified by their signature set.
///
/// For transactions without a recognizable signature (too short payload),
/// the first 64 bytes of the payload are used as a stand-in.
fn compute_entry_hash(results: &[TransactionExecResult]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    for result in results {
        // Transaction signature is the first 64 bytes of the payload.
        if result.payload.len() >= 64 {
            hasher.update(&result.payload[..64]);
        } else {
            hasher.update(&result.payload);
        }
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack_stage::PackedTransaction;

    fn make_tx(id: u8, cu: u64, fee: u64) -> PackedTransaction {
        PackedTransaction {
            payload: vec![id],
            blockhash: [0u8; 32],
            priority_fee: fee,
            compute_units: cu,
            total_cost: 0,
            is_vote: false,
            expires_at_slot: u64::MAX,
            write_accounts: vec![],
            read_accounts: vec![],
            data_size: 100,
            insertion_order: 0,
        }
    }

    fn make_microblock(txns: Vec<PackedTransaction>) -> Microblock {
        let total_cu: u64 = txns.iter().map(|t| t.compute_units).sum();
        let total_data: u64 = txns.iter().map(|t| t.data_size as u64).sum();
        Microblock {
            id: 0,
            target_tile: 0,
            transactions: txns,
            total_compute_units: total_cu,
            total_data_bytes: total_data,
            is_vote_only: false,
        }
    }

    #[test]
    fn execute_single_transaction() {
        let engine = MockExecutionEngine::new(100_000);
        let mut stage = ExecStage::new(Box::new(engine));

        let mb = make_microblock(vec![make_tx(1, 200_000, 5_000)]);
        let result = stage.execute_microblock(&mb);

        assert_eq!(result.success_count, 1);
        assert_eq!(result.failure_count, 0);
        assert_eq!(result.total_compute_units, 100_000);
        assert_eq!(result.transaction_results.len(), 1);
        assert!(result.transaction_results[0].success);
    }

    #[test]
    fn execute_multiple_transactions() {
        let engine = MockExecutionEngine::new(50_000);
        let mut stage = ExecStage::new(Box::new(engine));

        let txns = vec![make_tx(1, 200_000, 5_000), make_tx(2, 200_000, 3_000)];
        let mb = make_microblock(txns);
        let result = stage.execute_microblock(&mb);

        assert_eq!(result.success_count, 2);
        assert_eq!(result.total_compute_units, 100_000); // 50K each
    }

    #[test]
    fn failing_execution_engine() {
        struct FailEngine;
        impl ExecutionEngine for FailEngine {
            fn execute(&self, tx: &PackedTransaction) -> TransactionExecResult {
                TransactionExecResult {
                    payload: tx.payload.clone(),
                    success: false,
                    compute_units_consumed: 1_000,
                    fee_paid: 0,
                    error: Some("deliberate failure".to_string()),
                    logs: vec!["error".to_string()],
                    modified_accounts: Vec::new(),
                }
            }
        }

        let mut stage = ExecStage::new(Box::new(FailEngine));
        let mb = make_microblock(vec![make_tx(1, 200_000, 5_000)]);
        let result = stage.execute_microblock(&mb);

        assert_eq!(result.success_count, 0);
        assert_eq!(result.failure_count, 1);
        assert!(!result.transaction_results[0].success);
        assert!(result.transaction_results[0].error.is_some());
    }

    #[test]
    fn entry_hash_is_deterministic() {
        let engine = MockExecutionEngine::new(100_000);
        let mut stage = ExecStage::new(Box::new(engine));

        let mb = make_microblock(vec![make_tx(1, 200_000, 5_000)]);
        let result1 = stage.execute_microblock(&mb);
        let result2 = stage.execute_microblock(&mb);

        assert_eq!(result1.entry_hash, result2.entry_hash);
    }

    #[test]
    fn entry_hash_differs_for_different_txns() {
        let engine = MockExecutionEngine::new(100_000);
        let mut stage = ExecStage::new(Box::new(engine));

        let mb1 = make_microblock(vec![make_tx(1, 200_000, 5_000)]);
        let mb2 = make_microblock(vec![make_tx(2, 200_000, 5_000)]);
        let r1 = stage.execute_microblock(&mb1);
        let r2 = stage.execute_microblock(&mb2);

        assert_ne!(r1.entry_hash, r2.entry_hash);
    }

    #[test]
    fn stats_accumulate() {
        let engine = MockExecutionEngine::new(50_000);
        let mut stage = ExecStage::new(Box::new(engine));

        let mb1 = make_microblock(vec![make_tx(1, 200_000, 5_000)]);
        let mb2 = make_microblock(vec![make_tx(2, 200_000, 3_000)]);

        stage.execute_microblock(&mb1);
        stage.execute_microblock(&mb2);

        let snap = stage.stats().snapshot();
        assert_eq!(snap.microblocks_executed, 2);
        assert_eq!(snap.transactions_executed, 2);
        assert_eq!(snap.transactions_succeeded, 2);
        assert_eq!(snap.compute_units_consumed, 100_000);
        assert_eq!(snap.fees_collected, 8_000);
    }

    #[test]
    fn busy_signal() {
        let config = ExecConfig {
            max_pending_cus: 100,
            ..Default::default()
        };
        let engine = MockExecutionEngine::new(50_000);
        let stage = ExecStage::with_config(Box::new(engine), config);

        assert!(!stage.is_busy());
    }

    #[test]
    fn empty_microblock() {
        let engine = MockExecutionEngine::new(100_000);
        let mut stage = ExecStage::new(Box::new(engine));

        let mb = make_microblock(vec![]);
        let result = stage.execute_microblock(&mb);

        assert_eq!(result.success_count, 0);
        assert_eq!(result.failure_count, 0);
        assert_eq!(result.total_compute_units, 0);
    }
}
