/// Information about an account update delivered to plugins.
///
/// Contains the full account state at the time of the update, including
/// the public key, balance, owner program, data, and an optional reference
/// to the transaction that triggered the change.
#[derive(Debug, Clone)]
pub struct AccountUpdate<'a> {
    /// Account public key (32 bytes).
    pub pubkey: &'a [u8; 32],
    /// Account balance in lamports.
    pub lamports: u64,
    /// Owner program public key (32 bytes).
    pub owner: &'a [u8; 32],
    /// Whether the account contains an executable program.
    pub executable: bool,
    /// Next epoch at which rent is due.
    pub rent_epoch: u64,
    /// Raw account data bytes.
    pub data: &'a [u8],
    /// Monotonically increasing version counter for this account.
    pub write_version: u64,
    /// First signature of the transaction that caused this update, if available.
    pub txn_signature: Option<&'a [u8; 64]>,
}

/// Information about a processed transaction delivered to plugins.
///
/// Contains the transaction signature, execution result, and summary
/// metrics. Delivered after the transaction has been executed within a slot.
#[derive(Debug, Clone)]
pub struct TransactionNotification<'a> {
    /// First signature of the transaction (64 bytes).
    pub signature: &'a [u8; 64],
    /// Whether this is a vote transaction.
    pub is_vote: bool,
    /// Position of this transaction within the block.
    pub index: usize,
    /// Public keys of all accounts referenced by the transaction.
    pub account_keys: &'a [[u8; 32]],
    /// Serialized transaction message bytes.
    pub message_data: &'a [u8],
    /// Whether execution succeeded.
    pub success: bool,
    /// Error description if execution failed.
    pub error: Option<&'a str>,
    /// Compute units consumed during execution.
    pub compute_units_consumed: u64,
    /// Base fee charged for the transaction.
    pub fee: u64,
}

/// Slot processing lifecycle status.
///
/// Tracks a slot through the consensus pipeline from initial shred receipt
/// through to finalized root status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotStatus {
    /// Slot reached the tip of the heaviest fork (processed by this node).
    Processed,
    /// Slot reached optimistic confirmation threshold (supermajority vote lockout).
    Confirmed,
    /// Slot finalized with supermajority root votes (irreversible).
    Rooted,
    /// First shred for this slot was received from the network.
    FirstShredReceived,
    /// All shreds for this slot have been received.
    Completed,
    /// A new bank fork was created for this slot.
    CreatedBank,
    /// Slot was marked dead and will not be replayed.
    Dead(String),
}

impl std::fmt::Display for SlotStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Processed => write!(f, "processed"),
            Self::Confirmed => write!(f, "confirmed"),
            Self::Rooted => write!(f, "rooted"),
            Self::FirstShredReceived => write!(f, "first_shred_received"),
            Self::Completed => write!(f, "completed"),
            Self::CreatedBank => write!(f, "created_bank"),
            Self::Dead(reason) => write!(f, "dead: {reason}"),
        }
    }
}

/// Block-level metadata delivered to plugins after replay completes.
///
/// Summarizes the entire block including execution metrics, timing,
/// and parent chain information.
#[derive(Debug, Clone)]
pub struct BlockMetadata {
    /// Slot number of this block.
    pub slot: u64,
    /// Parent slot number.
    pub parent_slot: u64,
    /// Block hash (32 bytes).
    pub blockhash: [u8; 32],
    /// Parent block hash (32 bytes).
    pub parent_blockhash: [u8; 32],
    /// Unix timestamp of block production, if available.
    pub block_time: Option<i64>,
    /// Absolute block height, if available.
    pub block_height: Option<u64>,
    /// Number of transactions executed in this block.
    pub executed_transaction_count: u64,
    /// Number of entries (tick + transaction batches) in this block.
    pub entry_count: u64,
    /// Total compute units consumed across all transactions.
    pub total_compute_units: u64,
    /// Total base transaction fees collected.
    pub transaction_fee: u64,
    /// Total priority fees collected.
    pub priority_fee: u64,
}
