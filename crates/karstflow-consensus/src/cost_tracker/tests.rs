use super::*;
use karstflow_constants::block_limits::{
    MAX_ACCOUNT_DATA_SIZE_DELTA, MAX_BLOCK_COMPUTE_UNITS, MAX_VOTE_COMPUTE_UNITS,
    MAX_WRITABLE_ACCOUNT_COMPUTE_UNITS, SIGNATURE_COST, TRANSACTION_BASE_COST, WRITE_LOCK_COST,
};
use karstflow_storage::Pubkey;

// ── try_add within limits ───────────────────────────────────────────

#[test]
fn try_add_within_limits_succeeds() {
    let tracker = CostTracker::new();
    let cost = TransactionCost::new(1000, false);

    assert!(tracker.try_add(&cost).is_ok());
    assert_eq!(tracker.block_cost(), 1000);
    assert_eq!(tracker.transaction_count(), 1);
}

// ── block cost limit exceeded ───────────────────────────────────────

#[test]
fn block_cost_limit_exceeded() {
    let tracker = CostTracker::new();

    // Saturate block cost.
    let large = TransactionCost::new(MAX_BLOCK_COMPUTE_UNITS, false);
    tracker.try_add(&large).unwrap();

    // Next transaction should fail.
    let small = TransactionCost::new(1, false);
    let err = tracker.try_add(&small).unwrap_err();
    assert!(matches!(
        err,
        CostTrackerError::BlockCostLimitExceeded { .. }
    ));
}

// ── vote cost limit exceeded ────────────────────────────────────────

#[test]
fn vote_cost_limit_exceeded() {
    let tracker = CostTracker::new();

    let vote = TransactionCost::new(MAX_VOTE_COMPUTE_UNITS, true);
    tracker.try_add(&vote).unwrap();

    let one_more = TransactionCost::new(1, true);
    let err = tracker.try_add(&one_more).unwrap_err();
    assert!(matches!(
        err,
        CostTrackerError::VoteCostLimitExceeded { .. }
    ));
}

#[test]
fn non_vote_does_not_count_toward_vote_limit() {
    let tracker = CostTracker::new();

    let non_vote = TransactionCost::new(MAX_VOTE_COMPUTE_UNITS, false);
    tracker.try_add(&non_vote).unwrap();

    // Vote limit should still allow votes.
    let vote = TransactionCost::new(1000, true);
    assert!(tracker.try_add(&vote).is_ok());
    assert_eq!(tracker.vote_cost(), 1000);
}

// ── account cost limit exceeded ─────────────────────────────────────

#[test]
fn account_cost_limit_exceeded() {
    let tracker = CostTracker::new();
    let account = Pubkey::new_unique();

    let mut cost = TransactionCost::new(1000, false);
    cost.add_writable_account(account, MAX_WRITABLE_ACCOUNT_COMPUTE_UNITS);
    tracker.try_add(&cost).unwrap();

    let mut cost2 = TransactionCost::new(1000, false);
    cost2.add_writable_account(account, 1);
    let err = tracker.try_add(&cost2).unwrap_err();
    assert!(matches!(
        err,
        CostTrackerError::AccountCostLimitExceeded { .. }
    ));
}

// ── data size delta limit exceeded ──────────────────────────────────

#[test]
fn data_size_delta_limit_exceeded() {
    let tracker = CostTracker::new();

    let mut cost = TransactionCost::new(1000, false);
    cost.data_size_delta = MAX_ACCOUNT_DATA_SIZE_DELTA;
    tracker.try_add(&cost).unwrap();

    let mut cost2 = TransactionCost::new(1000, false);
    cost2.data_size_delta = 1;
    let err = tracker.try_add(&cost2).unwrap_err();
    assert!(matches!(
        err,
        CostTrackerError::AccountDataSizeLimitExceeded { .. }
    ));
}

// ── remove cost after failure ───────────────────────────────────────

#[test]
fn remove_cost_after_failure() {
    let tracker = CostTracker::new();
    let cost = TransactionCost::new(5000, false);

    tracker.try_add(&cost).unwrap();
    assert_eq!(tracker.block_cost(), 5000);
    assert_eq!(tracker.transaction_count(), 1);

    tracker.remove(&cost);
    assert_eq!(tracker.block_cost(), 0);
    assert_eq!(tracker.transaction_count(), 0);
}

#[test]
fn remove_vote_cost() {
    let tracker = CostTracker::new();
    let cost = TransactionCost::new(2000, true);

    tracker.try_add(&cost).unwrap();
    assert_eq!(tracker.vote_cost(), 2000);

    tracker.remove(&cost);
    assert_eq!(tracker.vote_cost(), 0);
}

// ── dead block rejects all ──────────────────────────────────────────

#[test]
fn dead_block_rejects_all() {
    let tracker = CostTracker::new();
    tracker.mark_dead();

    let cost = TransactionCost::new(1, false);
    let err = tracker.try_add(&cost).unwrap_err();
    assert_eq!(err, CostTrackerError::BlockDead);
}

// ── mark dead ───────────────────────────────────────────────────────

#[test]
fn mark_dead_persists() {
    let tracker = CostTracker::new();

    assert!(!tracker.is_dead());
    tracker.mark_dead();
    assert!(tracker.is_dead());
}

// ── remaining capacity ──────────────────────────────────────────────

#[test]
fn remaining_capacity_calculation() {
    let tracker = CostTracker::new();
    assert_eq!(tracker.remaining_capacity(), MAX_BLOCK_COMPUTE_UNITS);

    let cost = TransactionCost::new(10_000, false);
    tracker.try_add(&cost).unwrap();
    assert_eq!(
        tracker.remaining_capacity(),
        MAX_BLOCK_COMPUTE_UNITS - 10_000
    );
}

// ── multiple transactions accumulate ────────────────────────────────

#[test]
fn multiple_transactions_accumulate() {
    let tracker = CostTracker::new();

    for i in 0..10 {
        let cost = TransactionCost::new(1000, i % 3 == 0);
        tracker.try_add(&cost).unwrap();
    }

    assert_eq!(tracker.block_cost(), 10_000);
    assert_eq!(tracker.transaction_count(), 10);
    // Votes at i=0,3,6,9 => 4 votes * 1000 = 4000
    assert_eq!(tracker.vote_cost(), 4000);
}

// ── concurrent try_add from threads ─────────────────────────────────

#[test]
fn concurrent_try_add() {
    use std::sync::Arc;
    use std::thread;

    let tracker = Arc::new(CostTracker::new());
    let num_threads = 8;
    let per_thread = 100;

    let mut handles = Vec::new();
    for _ in 0..num_threads {
        let tracker = Arc::clone(&tracker);
        handles.push(thread::spawn(move || {
            for _ in 0..per_thread {
                let cost = TransactionCost::new(10, false);
                // May occasionally fail due to limit race but should not panic.
                let _ = tracker.try_add(&cost);
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    // All 800 transactions with 10 CU each = 8000 total, well within limits.
    assert_eq!(tracker.block_cost(), 8000);
    assert_eq!(tracker.transaction_count(), 800);
}

// ── transaction cost total calculation ──────────────────────────────

#[test]
fn transaction_cost_total_with_no_writable_accounts() {
    let cost = TransactionCost::new(5000, false);
    // 5000 (compute) + 3000 (base) + 720 (1 sig) = 8720
    assert_eq!(
        cost.total_cost(),
        5000 + TRANSACTION_BASE_COST + SIGNATURE_COST
    );
}

#[test]
fn transaction_cost_total_with_writable_accounts() {
    let mut cost = TransactionCost::new(5000, false);
    cost.add_writable_account(Pubkey::new_unique(), 200);
    cost.add_writable_account(Pubkey::new_unique(), 300);
    // 5000 (compute) + 3000 (base) + 720 (1 sig)
    //   + (200 + 300) (account costs) + 2 * 300 (write lock overhead)
    let expected = 5000 + TRANSACTION_BASE_COST + SIGNATURE_COST + 200 + 300 + 2 * WRITE_LOCK_COST;
    assert_eq!(cost.total_cost(), expected);
}

#[test]
fn transaction_cost_total_with_multiple_signatures() {
    let mut cost = TransactionCost::new(1000, false);
    cost.signature_count = 3;
    // 1000 + 3000 + 3*720 = 6160
    assert_eq!(
        cost.total_cost(),
        1000 + TRANSACTION_BASE_COST + 3 * SIGNATURE_COST
    );
}

// ── write lock cost included ────────────────────────────────────────

#[test]
fn write_lock_cost_per_account() {
    let mut cost = TransactionCost::new(0, false);
    cost.add_writable_account(Pubkey::new_unique(), 0);
    // 0 (compute) + 3000 (base) + 720 (1 sig) + 0 (account cost) + 300 (lock)
    assert_eq!(
        cost.total_cost(),
        TRANSACTION_BASE_COST + SIGNATURE_COST + WRITE_LOCK_COST
    );
}

// ── account_cost accessor on tracker ────────────────────────────────

#[test]
fn account_cost_accessor() {
    let tracker = CostTracker::new();
    let key = Pubkey::new_unique();

    assert_eq!(tracker.account_cost(&key), 0);

    let mut cost = TransactionCost::new(500, false);
    cost.add_writable_account(key, 1234);
    tracker.try_add(&cost).unwrap();

    assert_eq!(tracker.account_cost(&key), 1234);
}

// ── data size delta tracking ────────────────────────────────────────

#[test]
fn data_size_delta_tracks_growth_and_shrink() {
    let tracker = CostTracker::new();

    let mut grow = TransactionCost::new(100, false);
    grow.data_size_delta = 5000;
    tracker.try_add(&grow).unwrap();
    assert_eq!(tracker.account_data_size_delta(), 5000);

    let mut shrink = TransactionCost::new(100, false);
    shrink.data_size_delta = -2000;
    tracker.try_add(&shrink).unwrap();
    assert_eq!(tracker.account_data_size_delta(), 3000);
}

// ── remove restores data delta ──────────────────────────────────────

#[test]
fn remove_restores_data_delta() {
    let tracker = CostTracker::new();

    let mut cost = TransactionCost::new(100, false);
    cost.data_size_delta = 500;
    tracker.try_add(&cost).unwrap();
    assert_eq!(tracker.account_data_size_delta(), 500);

    tracker.remove(&cost);
    assert_eq!(tracker.account_data_size_delta(), 0);
}
