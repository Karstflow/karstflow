use paradencer_constants::block_limits::{SIGNATURE_COST, TRANSACTION_BASE_COST, WRITE_LOCK_COST};
use paradencer_storage::Pubkey;

/// Cost breakdown for a single transaction.
///
/// Captures compute units, write-lock costs, signature verification costs,
/// and account data growth so the block-level tracker can enforce limits.
#[derive(Debug, Clone)]
pub struct TransactionCost {
    /// Total compute units requested or consumed.
    pub compute_units: u64,
    /// Whether this is a vote transaction.
    pub is_vote: bool,
    /// Accounts with write access and their individual costs.
    pub writable_accounts: Vec<(Pubkey, u64)>,
    /// Account data size delta (positive = growth, negative = shrink).
    pub data_size_delta: i64,
    /// Number of signatures on the transaction.
    pub signature_count: u64,
}

impl TransactionCost {
    /// Create a new transaction cost record.
    pub fn new(compute_units: u64, is_vote: bool) -> Self {
        Self {
            compute_units,
            is_vote,
            writable_accounts: Vec::new(),
            data_size_delta: 0,
            signature_count: 1,
        }
    }

    /// Calculate total cost including write locks, signatures, and base overhead.
    pub fn total_cost(&self) -> u64 {
        let write_lock_total: u64 = self
            .writable_accounts
            .iter()
            .map(|(_, cost)| *cost)
            .sum::<u64>()
            .saturating_add((self.writable_accounts.len() as u64).saturating_mul(WRITE_LOCK_COST));
        let signature_total = self.signature_count.saturating_mul(SIGNATURE_COST);

        self.compute_units
            .saturating_add(TRANSACTION_BASE_COST)
            .saturating_add(write_lock_total)
            .saturating_add(signature_total)
    }

    /// Add a writable account and its associated cost.
    pub fn add_writable_account(&mut self, pubkey: Pubkey, cost: u64) {
        self.writable_accounts.push((pubkey, cost));
    }
}
