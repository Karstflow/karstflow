use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RpcCommitment {
    Processed,
    Confirmed,
    Finalized,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RpcRuntimeSnapshot {
    pub slot: u64,
    pub block_height: u64,
    pub transaction_count: u64,
    pub uptime_millis: u128,
    pub latest_blockhash_seed: u64,
}

impl RpcRuntimeSnapshot {
    pub fn slot_for_commitment(self, commitment: RpcCommitment) -> u64 {
        match commitment {
            RpcCommitment::Processed => self.slot,
            RpcCommitment::Confirmed => self.slot.saturating_sub(1),
            RpcCommitment::Finalized => self.slot.saturating_sub(32),
        }
    }

    pub fn block_height_for_commitment(self, commitment: RpcCommitment) -> u64 {
        self.slot_for_commitment(commitment)
    }

    pub fn blockhash_seed_for_commitment(self, commitment: RpcCommitment) -> u64 {
        self.latest_blockhash_seed
            .wrapping_add(self.slot_for_commitment(commitment).rotate_left(7))
    }
}

pub trait RuntimeSnapshotProvider: Send + Sync {
    fn latest_snapshot(&self) -> Option<RpcRuntimeSnapshot>;
}

/// Provides access to bank state for RPC methods that need real account data.
///
/// Implementors resolve commitment levels internally (processed = working bank,
/// confirmed = optimistically confirmed bank, finalized = root bank) and return
/// account data from the appropriate fork.
pub trait BankAccessProvider: Send + Sync {
    /// Look up a single account by pubkey at the given commitment level.
    fn get_account(
        &self,
        pubkey: &paradencer_types::Pubkey,
        commitment: RpcCommitment,
    ) -> Option<paradencer_types::Account>;

    /// Get the lamport balance for a pubkey.
    fn get_balance(&self, pubkey: &paradencer_types::Pubkey, commitment: RpcCommitment) -> u64;

    /// Get the slot number for a commitment level.
    fn get_slot(&self, commitment: RpcCommitment) -> u64;

    /// Get the block height for a commitment level.
    fn get_block_height(&self, commitment: RpcCommitment) -> u64;

    /// Get the latest blockhash as a 32-byte array.
    fn get_latest_blockhash(&self, commitment: RpcCommitment) -> [u8; 32];

    /// Check whether a blockhash is still valid (in the recent blockhash queue).
    fn is_blockhash_valid(&self, blockhash: &[u8; 32], commitment: RpcCommitment) -> bool;

    /// Get the current lamports-per-signature fee.
    fn get_lamports_per_signature(&self, commitment: RpcCommitment) -> u64;

    /// Get the last valid block height for the latest blockhash.
    fn get_last_valid_block_height(&self, commitment: RpcCommitment) -> u64;

    /// Get the transaction count.
    fn get_transaction_count(&self, commitment: RpcCommitment) -> u64;

    /// Get the total capitalization (supply) in lamports.
    fn get_capitalization(&self, commitment: RpcCommitment) -> u64;

    /// Get all accounts owned by the given program at the specified commitment level.
    fn get_accounts_by_owner(
        &self,
        owner: &paradencer_types::Pubkey,
        commitment: RpcCommitment,
    ) -> Vec<(paradencer_types::Pubkey, paradencer_types::Account)>;

    /// Get the leader for a specific absolute slot.
    ///
    /// Returns `None` if the slot is outside the known leader schedule range.
    fn get_slot_leader(
        &self,
        slot: u64,
        commitment: RpcCommitment,
    ) -> Option<paradencer_types::Pubkey>;

    /// Get leaders for a range of consecutive slots starting at `start_slot`.
    fn get_slot_leaders(
        &self,
        start_slot: u64,
        count: u64,
        commitment: RpcCommitment,
    ) -> Vec<(u64, Option<paradencer_types::Pubkey>)>;

    /// Get the leader schedule for the epoch containing the given slot,
    /// grouped by validator pubkey → list of absolute slot numbers.
    fn get_leader_schedule(
        &self,
        slot: u64,
        commitment: RpcCommitment,
    ) -> Option<Vec<(paradencer_types::Pubkey, Vec<u64>)>>;

    /// Simulate a transaction without committing state changes.
    ///
    /// Deserializes the raw transaction bytes, loads accounts, executes
    /// instructions, and returns the result without persisting any changes.
    fn simulate_transaction(
        &self,
        raw_tx: &[u8],
        sig_verify: bool,
        replace_recent_blockhash: bool,
        commitment: RpcCommitment,
    ) -> TransactionSimulationResponse;

    /// Get the validator identity pubkey as a base58 string.
    ///
    /// Returns `None` if the identity is not known (e.g., metrics-only mode).
    fn get_identity(&self) -> Option<String> {
        None
    }

    /// Get cluster node contact info from the gossip network.
    ///
    /// Returns a list of known cluster nodes with their pubkey and socket
    /// addresses. Returns empty if cluster info is unavailable.
    fn get_cluster_nodes(&self) -> Vec<RpcClusterNode> {
        Vec::new()
    }

    /// Get confirmed/rooted slots within a range.
    ///
    /// Returns slot numbers that have been confirmed in the blockstore.
    /// When blockstore is unavailable, returns empty.
    fn get_confirmed_blocks(&self, _start_slot: u64, _end_slot: u64) -> Vec<u64> {
        Vec::new()
    }

    /// Get the block time (unix timestamp) for a given slot.
    ///
    /// Returns the timestamp recorded when the first shred for this slot
    /// was received. Returns `None` if the slot is not in the blockstore.
    fn get_block_time(&self, _slot: u64) -> Option<i64> {
        None
    }

    /// Check whether a slot exists in the blockstore.
    fn has_slot(&self, _slot: u64) -> bool {
        false
    }

    /// Get the parent slot for a given slot from the blockstore.
    fn get_parent_slot(&self, _slot: u64) -> Option<u64> {
        None
    }

    /// Get the genesis hash as a base58-encoded string.
    ///
    /// Returns `None` if the genesis hash is not configured.
    fn get_genesis_hash(&self) -> Option<String> {
        None
    }

    /// Get a parsed block from the blockstore.
    ///
    /// Assembles the block from stored shreds, parses entries, and extracts
    /// transaction signatures. Returns `None` if the slot is unavailable
    /// or incomplete.
    fn get_block_data(&self, _slot: u64) -> Option<RpcBlockData> {
        None
    }

    /// Get the largest accounts by lamport balance.
    ///
    /// Returns up to `limit` accounts sorted by descending balance.
    fn get_largest_accounts(
        &self,
        _limit: usize,
        _commitment: RpcCommitment,
    ) -> Vec<(paradencer_types::Pubkey, u64)> {
        Vec::new()
    }

    /// Get the lowest slot with block data available in the blockstore.
    ///
    /// Returns 0 if no blockstore is available or no roots exist.
    fn get_first_available_block(&self) -> u64 {
        0
    }

    /// Compute the non-circulating supply: total lamports locked in vote
    /// and stake accounts.
    fn get_non_circulating_supply(&self, _commitment: RpcCommitment) -> u64 {
        0
    }

    /// Get the block commitment for a given slot.
    ///
    /// Returns the commitment stake array (32 entries) and total stake.
    /// Returns `None` if commitment data is unavailable.
    fn get_block_commitment(&self, _slot: u64) -> Option<RpcBlockCommitment> {
        None
    }

    /// Get the epoch number for a given slot.
    fn get_epoch_for_slot(&self, _slot: u64) -> u64 {
        0
    }

    /// Get the inflation rate components for the given epoch.
    ///
    /// Returns (total, validator, foundation) inflation rates.
    /// Returns `None` when real inflation config is unavailable.
    fn get_inflation_rate(&self, _epoch: u64) -> Option<(f64, f64, f64)> {
        None
    }

    /// Look up transaction statuses by their first signature.
    ///
    /// Returns a vector of `Option<RpcSignatureStatus>` in the same order
    /// as the input signatures. `None` means the signature was not found.
    fn get_signature_statuses(&self, _signatures: &[[u8; 64]]) -> Vec<Option<RpcSignatureStatus>> {
        Vec::new()
    }

    /// Look up a single transaction by its signature.
    ///
    /// Resolves the slot from the signature status cache, then fetches the
    /// full block data and finds the matching transaction. Returns `None`
    /// if the signature is unknown or the block data is unavailable.
    fn get_transaction(&self, _signature: &[u8; 64]) -> Option<RpcTransactionData> {
        None
    }

    /// Get recent transaction signatures that touched the given address.
    ///
    /// Returns up to `limit` entries sorted most-recent-first.
    /// `before` and `until` are base58-encoded signature cursors for pagination.
    fn get_signatures_for_address(
        &self,
        _address: &paradencer_types::Pubkey,
        _limit: usize,
        _before: Option<&[u8; 64]>,
        _until: Option<&[u8; 64]>,
        _commitment: RpcCommitment,
    ) -> Vec<RpcAddressSignatureEntry> {
        Vec::new()
    }

    /// Get priority fees from recent slots.
    ///
    /// Returns per-slot priority fee data for the last N slots.
    fn get_recent_prioritization_fees(
        &self,
        _commitment: RpcCommitment,
    ) -> Vec<RpcPrioritizationFee> {
        Vec::new()
    }

    /// Get performance samples from recent slots.
    ///
    /// Returns per-sample data with transaction counts and timing.
    fn get_recent_performance_samples(
        &self,
        _limit: usize,
        _commitment: RpcCommitment,
    ) -> Vec<RpcPerformanceSample> {
        Vec::new()
    }
}

/// Parsed block data returned by `get_block_data`.
#[derive(Debug, Clone)]
pub struct RpcBlockData {
    /// Slot number.
    pub slot: u64,
    /// Parent slot number.
    pub parent_slot: u64,
    /// Block time (unix timestamp), if known.
    pub block_time: Option<i64>,
    /// Blockhash for this slot (PoH hash), base58-encoded.
    pub blockhash: Option<String>,
    /// Previous blockhash (parent slot's hash), base58-encoded.
    pub previous_blockhash: Option<String>,
    /// Block height (may differ from slot if some slots were skipped).
    pub block_height: Option<u64>,
    /// Transactions extracted from block entries.
    pub transactions: Vec<RpcBlockTransaction>,
}

/// A single transaction from a parsed block.
#[derive(Debug, Clone)]
pub struct RpcBlockTransaction {
    /// Ed25519 signatures (base58-encoded).
    pub signatures: Vec<String>,
    /// Raw transaction bytes.
    pub raw_bytes: Vec<u8>,
}

/// Status of a transaction identified by its signature.
#[derive(Debug, Clone)]
pub struct RpcSignatureStatus {
    /// Slot in which the transaction was processed.
    pub slot: u64,
    /// Whether the transaction succeeded.
    pub succeeded: bool,
    /// Error description for failed transactions.
    pub error: Option<String>,
}

/// Block commitment data returned by `get_block_commitment`.
#[derive(Debug, Clone)]
pub struct RpcBlockCommitment {
    /// Commitment stake for each confirmation depth bucket (0..31).
    pub commitment: Vec<u64>,
    /// Total active stake in the cluster.
    pub total_stake: u64,
}

/// Full transaction data returned by `get_transaction`.
#[derive(Debug, Clone)]
pub struct RpcTransactionData {
    /// Slot in which the transaction was processed.
    pub slot: u64,
    /// Block time (unix timestamp), if known.
    pub block_time: Option<i64>,
    /// Whether the transaction succeeded.
    pub succeeded: bool,
    /// Error description for failed transactions.
    pub error: Option<String>,
    /// Ed25519 signatures (base58-encoded).
    pub signatures: Vec<String>,
    /// Raw transaction bytes.
    pub raw_bytes: Vec<u8>,
}

/// A signature entry for `getSignaturesForAddress` responses.
#[derive(Debug, Clone)]
pub struct RpcAddressSignatureEntry {
    /// Transaction signature (base58-encoded).
    pub signature: String,
    /// Slot in which the transaction was processed.
    pub slot: u64,
    /// Whether the transaction succeeded.
    pub succeeded: bool,
    /// Error description for failed transactions.
    pub error: Option<String>,
    /// Block time (unix timestamp), if known.
    pub block_time: Option<i64>,
}

/// Per-slot prioritization fee data.
#[derive(Debug, Clone)]
pub struct RpcPrioritizationFee {
    /// Slot number.
    pub slot: u64,
    /// Prioritization fee for this slot (in micro-lamports per CU).
    pub prioritization_fee: u64,
}

/// Performance sample for a recent time period.
#[derive(Debug, Clone)]
pub struct RpcPerformanceSample {
    /// Slot at the end of the sample period.
    pub slot: u64,
    /// Number of transactions processed.
    pub num_transactions: u64,
    /// Number of slots in the sample period.
    pub num_slots: u64,
    /// Sample period in seconds.
    pub sample_period_secs: u64,
    /// Number of non-vote transactions.
    pub num_non_vote_transactions: u64,
}

/// Contact information for a cluster node, returned by `get_cluster_nodes`.
#[derive(Debug, Clone)]
pub struct RpcClusterNode {
    /// Node identity pubkey (base58).
    pub pubkey: String,
    /// Gossip socket address, if known.
    pub gossip: Option<String>,
    /// TPU socket address, if known.
    pub tpu: Option<String>,
    /// RPC socket address, if known.
    pub rpc: Option<String>,
    /// Software version, if advertised.
    pub version: Option<String>,
}

/// Result of simulating a transaction via `BankAccessProvider`.
#[derive(Debug, Clone)]
pub struct TransactionSimulationResponse {
    /// Error description when the transaction fails, `None` on success.
    pub error: Option<String>,
    /// Execution logs from all instructions.
    pub logs: Vec<String>,
    /// Total compute units consumed.
    pub units_consumed: u64,
    /// Post-simulation account states for requested accounts.
    /// Keyed by pubkey, value is the account after execution (or None if not found).
    pub accounts: Vec<(paradencer_types::Pubkey, Option<paradencer_types::Account>)>,
    /// Return data from the last instruction that set it.
    /// Contains (program_id_base58, data_base64).
    pub return_data: Option<(String, Vec<u8>)>,
}

/// Handles real transaction submission for `sendTransaction`.
///
/// Implementors decode the transaction, extract the signature,
/// forward the raw bytes to the current leader's TPU socket,
/// and return the transaction signature.
pub trait TransactionSubmitter: Send + Sync {
    /// Submit a transaction for processing.
    ///
    /// Takes the raw transaction bytes (already decoded from base58/base64),
    /// forwards them to the current leader via TPU, and returns the first
    /// signature from the transaction.
    ///
    /// Returns `Err` if the transaction is malformed or forwarding fails.
    fn submit_transaction(&self, tx_bytes: &[u8]) -> Result<[u8; 64], String>;
}

pub struct MetricsFileRuntimeSnapshotProvider {
    metrics_file_path: PathBuf,
}

impl MetricsFileRuntimeSnapshotProvider {
    pub fn from_path(metrics_file_path: PathBuf) -> Self {
        Self { metrics_file_path }
    }
}

impl RuntimeSnapshotProvider for MetricsFileRuntimeSnapshotProvider {
    fn latest_snapshot(&self) -> Option<RpcRuntimeSnapshot> {
        read_runtime_snapshot_from_metrics_file(&self.metrics_file_path)
    }
}

pub fn metrics_file_provider(metrics_file_path: PathBuf) -> Arc<dyn RuntimeSnapshotProvider> {
    Arc::new(MetricsFileRuntimeSnapshotProvider::from_path(
        metrics_file_path,
    ))
}

fn read_runtime_snapshot_from_metrics_file(metrics_file_path: &Path) -> Option<RpcRuntimeSnapshot> {
    let content = fs::read_to_string(metrics_file_path).ok()?;
    let latest_json_line = content
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty() && line.trim_start().starts_with('{'))?;
    let value = serde_json::from_str::<serde_json::Value>(latest_json_line).ok()?;

    let block_assembly = value.get("block_assembly");
    let committed_fragments = block_assembly
        .and_then(|scope| scope.get("committed_fragments"))
        .and_then(|raw| raw.as_u64())
        .unwrap_or(0);
    let replay_window_rewinds = block_assembly
        .and_then(|scope| scope.get("replay_window_rewinds"))
        .and_then(|raw| raw.as_u64())
        .unwrap_or(0);
    let transaction_count = value
        .get("ingress_filter")
        .and_then(|scope| scope.get("accepted_transactions"))
        .and_then(|raw| raw.as_u64())
        .unwrap_or(0);
    let uptime_millis = value
        .get("uptime_millis")
        .and_then(|raw| raw.as_u64())
        .map(u128::from)
        .unwrap_or(0);

    Some(RpcRuntimeSnapshot {
        slot: committed_fragments,
        block_height: committed_fragments,
        transaction_count,
        uptime_millis,
        latest_blockhash_seed: committed_fragments ^ replay_window_rewinds.rotate_left(13),
    })
}

#[cfg(test)]
pub fn read_metrics_snapshot_for_test(path: &Path) -> Option<RpcRuntimeSnapshot> {
    read_runtime_snapshot_from_metrics_file(path)
}
