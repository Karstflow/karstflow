use karstflow_storage::Pubkey;

/// Cost of a single transaction, as the block-level tracker sees it.
///
/// `total_cost` is the whole quantity the block limit is measured in — the
/// reference sums signature, write-lock, instruction-data, execution and
/// loaded-accounts-data costs into one figure, and that same figure is what
/// each writable account is charged. The cost model in `pack::cost_model`
/// produces it; this type only carries it and the quantities enforced against
/// their own separate limits.
#[derive(Debug, Clone)]
pub struct TransactionCost {
    /// Compute units this transaction costs the block.
    pub total_cost: u64,
    /// Whether this is a vote transaction.
    pub is_vote: bool,
    /// Accounts this transaction write-locks. Each is charged `total_cost`.
    pub writable_accounts: Vec<Pubkey>,
    /// Account data size delta (positive = growth, negative = shrink).
    pub data_size_delta: i64,
    /// Pre-execution estimate of account data this transaction requests to
    /// allocate (bytes), enforced against the per-block allocation limit.
    pub allocated_accounts_data_size: u64,
}

impl TransactionCost {
    /// Create a new transaction cost record.
    pub fn new(total_cost: u64, is_vote: bool) -> Self {
        Self {
            total_cost,
            is_vote,
            writable_accounts: Vec::new(),
            data_size_delta: 0,
            allocated_accounts_data_size: 0,
        }
    }

    /// Record an account this transaction write-locks.
    pub fn add_writable_account(&mut self, pubkey: Pubkey) {
        self.writable_accounts.push(pubkey);
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
        assert_eq!(cost.total_cost, 1000);
        assert!(!cost.is_vote);
        assert!(cost.writable_accounts.is_empty());
        assert_eq!(cost.data_size_delta, 0);
        assert_eq!(cost.allocated_accounts_data_size, 0);
    }

    #[test]
    fn new_vote_tx() {
        let cost = TransactionCost::new(500, true);
        assert!(cost.is_vote);
    }

    #[test]
    fn add_writable_account() {
        let mut cost = TransactionCost::new(0, false);
        cost.add_writable_account(pk(1));
        assert_eq!(cost.writable_accounts, vec![pk(1)]);
    }
}
