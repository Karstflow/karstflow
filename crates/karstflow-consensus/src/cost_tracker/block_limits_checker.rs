use karstflow_storage::Pubkey;

use super::transaction_cost::TransactionCost;
use super::{CostLimits, CostTrackerError};

/// Pre-check whether a transaction can fit within block limits.
///
/// Returns `Ok(())` if the transaction would not violate any limit, or a
/// specific error describing which limit would be exceeded.
#[allow(clippy::too_many_arguments)]
pub fn check_limits(
    current_block_cost: u64,
    current_vote_cost: u64,
    current_data_delta: i64,
    current_allocated_data_size: u64,
    account_cost_fn: &dyn Fn(&Pubkey) -> u64,
    tx_cost: &TransactionCost,
    limits: &CostLimits,
    check_vote_limit: bool,
) -> Result<(), CostTrackerError> {
    // Block compute-unit limit.
    let new_block_cost = current_block_cost.saturating_add(tx_cost.compute_units);
    if new_block_cost > limits.block_cost_limit {
        return Err(CostTrackerError::BlockCostLimitExceeded {
            current: current_block_cost,
            requested: tx_cost.compute_units,
            limit: limits.block_cost_limit,
        });
    }

    // Vote compute-unit limit (skipped when remove_simple_vote_from_cost_model active).
    if check_vote_limit {
        let new_vote_cost = current_vote_cost.saturating_add(tx_cost.compute_units);
        if new_vote_cost > limits.vote_cost_limit {
            return Err(CostTrackerError::VoteCostLimitExceeded {
                current: current_vote_cost,
                requested: tx_cost.compute_units,
                limit: limits.vote_cost_limit,
            });
        }
    }

    // Per-account write-lock limit.
    for (pubkey, cost) in &tx_cost.writable_accounts {
        let current_account_cost = account_cost_fn(pubkey);
        let new_account_cost = current_account_cost.saturating_add(*cost);
        if new_account_cost > limits.account_cost_limit {
            return Err(CostTrackerError::AccountCostLimitExceeded {
                account: *pubkey,
                current: current_account_cost,
                requested: *cost,
                limit: limits.account_cost_limit,
            });
        }
    }

    // Account data size delta.
    let new_delta = current_data_delta.saturating_add(tx_cost.data_size_delta);
    if new_delta > limits.account_data_size_limit {
        return Err(CostTrackerError::AccountDataSizeLimitExceeded {
            current: current_data_delta,
            requested: tx_cost.data_size_delta,
            limit: limits.account_data_size_limit,
        });
    }

    // Per-block allocated account data limit (pre-execution estimate).
    let new_allocated =
        current_allocated_data_size.saturating_add(tx_cost.allocated_accounts_data_size);
    if new_allocated > limits.block_accounts_data_size_limit {
        return Err(CostTrackerError::BlockAccountsDataSizeLimitExceeded {
            current: current_allocated_data_size,
            requested: tx_cost.allocated_accounts_data_size,
            limit: limits.block_accounts_data_size_limit,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use karstflow_constants::block_limits::{
        MAX_ACCOUNT_DATA_SIZE_DELTA, MAX_BLOCK_COMPUTE_UNITS, MAX_VOTE_COMPUTE_UNITS,
        MAX_WRITABLE_ACCOUNT_COMPUTE_UNITS,
    };

    fn default_limits() -> CostLimits {
        CostLimits::default()
    }

    fn no_account_cost(_: &Pubkey) -> u64 {
        0
    }

    fn simple_tx(cu: u64) -> TransactionCost {
        TransactionCost::new(cu, false)
    }

    #[test]
    fn within_all_limits() {
        let tx = simple_tx(1_000);
        let result = check_limits(
            0,
            0,
            0,
            0,
            &no_account_cost,
            &tx,
            &default_limits(),
            tx.is_vote,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn exceeds_block_compute_limit() {
        let tx = simple_tx(1_000);
        let result = check_limits(
            MAX_BLOCK_COMPUTE_UNITS,
            0,
            0,
            0,
            &no_account_cost,
            &tx,
            &default_limits(),
            tx.is_vote,
        );
        assert!(matches!(
            result,
            Err(CostTrackerError::BlockCostLimitExceeded { .. })
        ));
    }

    #[test]
    fn vote_exceeds_vote_limit() {
        let mut tx = TransactionCost::new(1_000, true);
        tx.is_vote = true;
        let result = check_limits(
            0,
            MAX_VOTE_COMPUTE_UNITS,
            0,
            0,
            &no_account_cost,
            &tx,
            &default_limits(),
            tx.is_vote,
        );
        assert!(matches!(
            result,
            Err(CostTrackerError::VoteCostLimitExceeded { .. })
        ));
    }

    #[test]
    fn non_vote_ignores_vote_limit() {
        let tx = simple_tx(1_000);
        let result = check_limits(
            0,
            MAX_VOTE_COMPUTE_UNITS,
            0,
            0,
            &no_account_cost,
            &tx,
            &default_limits(),
            tx.is_vote,
        );
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
        let result = check_limits(0, 0, 0, 0, &cost_fn, &tx, &default_limits(), tx.is_vote);
        assert!(matches!(
            result,
            Err(CostTrackerError::AccountCostLimitExceeded { .. })
        ));
    }

    #[test]
    fn exceeds_data_size_delta() {
        let mut tx = simple_tx(1_000);
        tx.data_size_delta = 1;
        let result = check_limits(
            0,
            0,
            MAX_ACCOUNT_DATA_SIZE_DELTA,
            0,
            &no_account_cost,
            &tx,
            &default_limits(),
            tx.is_vote,
        );
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
        assert!(total > 10_000);
    }

    #[test]
    fn feature_gated_100m_block_limit() {
        let limits = CostLimits::from_features(true, false, false);
        assert_eq!(limits.block_cost_limit, 100_000_000);

        // A tx fitting under 100M but not 50M should pass
        let tx = simple_tx(60_000_000);
        let result = check_limits(0, 0, 0, 0, &no_account_cost, &tx, &limits, tx.is_vote);
        assert!(result.is_ok());

        // Same tx would fail under default 50M
        let result = check_limits(
            0,
            0,
            0,
            0,
            &no_account_cost,
            &tx,
            &default_limits(),
            tx.is_vote,
        );
        assert!(matches!(
            result,
            Err(CostTrackerError::BlockCostLimitExceeded { .. })
        ));
    }

    #[test]
    fn feature_gated_60m_block_limit() {
        let limits = CostLimits::from_features(false, true, false);
        assert_eq!(limits.block_cost_limit, 60_000_000);
    }

    #[test]
    fn raise_account_cu_limit_sets_40_percent() {
        let limits = CostLimits::from_features(true, false, true);
        // 100M * 40% = 40M
        assert_eq!(limits.account_cost_limit, 40_000_000);
    }

    #[test]
    fn raise_account_cu_limit_with_60m() {
        let limits = CostLimits::from_features(false, true, true);
        // 60M * 40% = 24M
        assert_eq!(limits.account_cost_limit, 24_000_000);
    }

    #[test]
    fn exceeds_block_allocated_data_size() {
        let mut tx = simple_tx(1_000);
        tx.allocated_accounts_data_size = 1;
        let limits = default_limits();
        let result = check_limits(
            0,
            0,
            0,
            limits.block_accounts_data_size_limit,
            &no_account_cost,
            &tx,
            &limits,
            tx.is_vote,
        );
        assert!(matches!(
            result,
            Err(CostTrackerError::BlockAccountsDataSizeLimitExceeded { .. })
        ));
    }

    #[test]
    fn allocated_data_within_limit_ok() {
        let mut tx = simple_tx(1_000);
        tx.allocated_accounts_data_size = 1_000;
        let result = check_limits(
            0,
            0,
            0,
            0,
            &no_account_cost,
            &tx,
            &default_limits(),
            tx.is_vote,
        );
        assert!(result.is_ok());
    }
}
