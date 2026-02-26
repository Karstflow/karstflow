use paradencer_constants::block_limits::{
    MAX_ACCOUNT_DATA_SIZE_DELTA, MAX_BLOCK_COMPUTE_UNITS, MAX_VOTE_COMPUTE_UNITS,
    MAX_WRITABLE_ACCOUNT_COMPUTE_UNITS,
};
use paradencer_storage::Pubkey;

use super::transaction_cost::TransactionCost;
use super::CostTrackerError;

/// Pre-check whether a transaction can fit within block limits.
///
/// Returns `Ok(())` if the transaction would not violate any limit, or a
/// specific error describing which limit would be exceeded.
pub fn check_limits(
    current_block_cost: u64,
    current_vote_cost: u64,
    current_data_delta: i64,
    account_cost_fn: &dyn Fn(&Pubkey) -> u64,
    tx_cost: &TransactionCost,
) -> Result<(), CostTrackerError> {
    // Block compute-unit limit.
    let new_block_cost = current_block_cost.saturating_add(tx_cost.compute_units);
    if new_block_cost > MAX_BLOCK_COMPUTE_UNITS {
        return Err(CostTrackerError::BlockCostLimitExceeded {
            current: current_block_cost,
            requested: tx_cost.compute_units,
            limit: MAX_BLOCK_COMPUTE_UNITS,
        });
    }

    // Vote compute-unit limit.
    if tx_cost.is_vote {
        let new_vote_cost = current_vote_cost.saturating_add(tx_cost.compute_units);
        if new_vote_cost > MAX_VOTE_COMPUTE_UNITS {
            return Err(CostTrackerError::VoteCostLimitExceeded {
                current: current_vote_cost,
                requested: tx_cost.compute_units,
                limit: MAX_VOTE_COMPUTE_UNITS,
            });
        }
    }

    // Per-account write-lock limit.
    for (pubkey, cost) in &tx_cost.writable_accounts {
        let current_account_cost = account_cost_fn(pubkey);
        let new_account_cost = current_account_cost.saturating_add(*cost);
        if new_account_cost > MAX_WRITABLE_ACCOUNT_COMPUTE_UNITS {
            return Err(CostTrackerError::AccountCostLimitExceeded {
                account: *pubkey,
                current: current_account_cost,
                requested: *cost,
                limit: MAX_WRITABLE_ACCOUNT_COMPUTE_UNITS,
            });
        }
    }

    // Account data size delta.
    let new_delta = current_data_delta.saturating_add(tx_cost.data_size_delta);
    if new_delta > MAX_ACCOUNT_DATA_SIZE_DELTA {
        return Err(CostTrackerError::AccountDataSizeLimitExceeded {
            current: current_data_delta,
            requested: tx_cost.data_size_delta,
            limit: MAX_ACCOUNT_DATA_SIZE_DELTA,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_account_cost(_: &Pubkey) -> u64 {
        0
    }

    fn simple_tx(cu: u64) -> TransactionCost {
        TransactionCost::new(cu, false)
    }

    #[test]
    fn within_all_limits() {
        let tx = simple_tx(1_000);
        let result = check_limits(0, 0, 0, &no_account_cost, &tx);
        assert!(result.is_ok());
    }

    #[test]
    fn exceeds_block_compute_limit() {
        let tx = simple_tx(1_000);
        let result = check_limits(MAX_BLOCK_COMPUTE_UNITS, 0, 0, &no_account_cost, &tx);
        assert!(matches!(
            result,
            Err(CostTrackerError::BlockCostLimitExceeded { .. })
        ));
    }

    #[test]
    fn vote_exceeds_vote_limit() {
        let mut tx = TransactionCost::new(1_000, true);
        tx.is_vote = true;
        let result = check_limits(0, MAX_VOTE_COMPUTE_UNITS, 0, &no_account_cost, &tx);
        assert!(matches!(
            result,
            Err(CostTrackerError::VoteCostLimitExceeded { .. })
        ));
    }

    #[test]
    fn non_vote_ignores_vote_limit() {
        let tx = simple_tx(1_000);
        // Even if vote cost is at max, non-vote tx should pass
        let result = check_limits(0, MAX_VOTE_COMPUTE_UNITS, 0, &no_account_cost, &tx);
        assert!(result.is_ok());
    }

    #[test]
    fn exceeds_per_account_write_cost() {
        let mut tx = simple_tx(1_000);
        let acct = Pubkey::new_unique();
        tx.add_writable_account(acct, 1_000);

        let cost_fn = |p: &Pubkey| {
            if *p == acct {
                MAX_WRITABLE_ACCOUNT_COMPUTE_UNITS
            } else {
                0
            }
        };
        let result = check_limits(0, 0, 0, &cost_fn, &tx);
        assert!(matches!(
            result,
            Err(CostTrackerError::AccountCostLimitExceeded { .. })
        ));
    }

    #[test]
    fn exceeds_data_size_delta() {
        let mut tx = simple_tx(1_000);
        tx.data_size_delta = 1;
        let result = check_limits(0, 0, MAX_ACCOUNT_DATA_SIZE_DELTA, &no_account_cost, &tx);
        assert!(matches!(
            result,
            Err(CostTrackerError::AccountDataSizeLimitExceeded { .. })
        ));
    }

    #[test]
    fn transaction_cost_total_includes_overhead() {
        let mut tx = TransactionCost::new(10_000, false);
        tx.signature_count = 2;
        tx.add_writable_account(Pubkey::new_unique(), 500);

        let total = tx.total_cost();
        // Should include: compute_units + TRANSACTION_BASE_COST + signature costs + write lock costs
        assert!(total > 10_000);
    }
}
