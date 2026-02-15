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
