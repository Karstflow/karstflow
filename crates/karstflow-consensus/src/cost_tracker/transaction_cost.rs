use karstflow_constants::block_limits::{SIGNATURE_COST, TRANSACTION_BASE_COST, WRITE_LOCK_COST};
use karstflow_storage::Pubkey;

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
    /// Pre-execution estimate of account data this transaction requests to
    /// allocate (bytes), enforced against the per-block allocation limit.
    pub allocated_accounts_data_size: u64,
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
            allocated_accounts_data_size: 0,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(n: u8) -> Pubkey {
        Pubkey::new([n; 32])
    }

    #[test]
    fn new_defaults() {
        let cost = TransactionCost::new(1000, false);
        assert_eq!(cost.compute_units, 1000);
        assert!(!cost.is_vote);
        assert!(cost.writable_accounts.is_empty());
        assert_eq!(cost.data_size_delta, 0);
        assert_eq!(cost.signature_count, 1);
        assert_eq!(cost.allocated_accounts_data_size, 0);
    }

    #[test]
    fn new_vote_tx() {
        let cost = TransactionCost::new(500, true);
        assert!(cost.is_vote);
    }

    #[test]
    fn total_cost_compute_only() {
        let cost = TransactionCost::new(10_000, false);
        // total = compute + base + sig_cost * 1
        let expected = 10_000 + TRANSACTION_BASE_COST + SIGNATURE_COST;
        assert_eq!(cost.total_cost(), expected);
    }

    #[test]
    fn total_cost_with_write_locks() {
        let mut cost = TransactionCost::new(5000, false);
        cost.add_writable_account(pk(1), 100);
        cost.add_writable_account(pk(2), 200);
        // write_lock_total = (100 + 200) + 2 * WRITE_LOCK_COST
        let write_total = 300 + 2 * WRITE_LOCK_COST;
        let expected = 5000 + TRANSACTION_BASE_COST + SIGNATURE_COST + write_total;
        assert_eq!(cost.total_cost(), expected);
    }

    #[test]
    fn total_cost_multiple_signatures() {
        let mut cost = TransactionCost::new(1000, false);
        cost.signature_count = 3;
        let expected = 1000 + TRANSACTION_BASE_COST + 3 * SIGNATURE_COST;
        assert_eq!(cost.total_cost(), expected);
    }

    #[test]
    fn add_writable_account() {
        let mut cost = TransactionCost::new(0, false);
        cost.add_writable_account(pk(1), 50);
        assert_eq!(cost.writable_accounts.len(), 1);
        assert_eq!(cost.writable_accounts[0].1, 50);
    }
}
