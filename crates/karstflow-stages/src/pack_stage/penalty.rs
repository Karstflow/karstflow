/// Per-account penalty tracking for the pack scheduler.
///
/// When an account becomes "hot" (many transactions contending for it),
/// subsequent transactions writing to that account are deferred to a
/// penalty queue rather than the main scheduling queue. This prevents
/// a single hot account from dominating scheduling decisions.
///
/// Penalty transactions are periodically drained back into the main
/// queue, ensuring fairness without starvation.
use std::collections::{BTreeMap, HashMap, VecDeque};

/// Configuration for penalty tracking.
#[derive(Debug, Clone)]
pub struct PenaltyConfig {
    /// Number of consecutive conflicts before an account is considered hot.
    pub hot_threshold: u32,
    /// Maximum transactions held in penalty per account.
    pub max_penalty_per_account: usize,
    /// How many transactions to release per drain cycle.
    pub drain_batch_size: usize,
}

impl Default for PenaltyConfig {
    fn default() -> Self {
        Self {
            hot_threshold: 3,
            max_penalty_per_account: 64,
            drain_batch_size: 4,
        }
    }
}

/// Tracks penalty state for a single account.
struct AccountPenalty {
    /// Number of recent conflicts for this account.
    conflict_count: u32,
    /// Deferred transaction indices (insertion order preserved).
    deferred: VecDeque<u64>,
}

/// Penalty tracker across all accounts.
pub struct PenaltyTracker {
    config: PenaltyConfig,
    accounts: HashMap<[u8; 32], AccountPenalty>,
    /// Total transactions currently in penalty queues.
    total_deferred: usize,
}

impl PenaltyTracker {
    /// Create a new penalty tracker with the given config.
    pub fn new(config: PenaltyConfig) -> Self {
        Self {
            config,
            accounts: HashMap::new(),
            total_deferred: 0,
        }
    }

    /// Record a conflict for the given account.
    /// Returns `true` if the account is now considered "hot".
    pub fn record_conflict(&mut self, account: &[u8; 32]) -> bool {
        let entry = self.accounts.entry(*account).or_insert(AccountPenalty {
            conflict_count: 0,
            deferred: VecDeque::new(),
        });
        entry.conflict_count += 1;
        entry.conflict_count >= self.config.hot_threshold
    }

    /// Check if an account is currently hot.
    pub fn is_hot(&self, account: &[u8; 32]) -> bool {
        self.accounts
            .get(account)
            .map(|p| p.conflict_count >= self.config.hot_threshold)
            .unwrap_or(false)
    }

    /// Defer a transaction (by index/id) for a hot account.
    /// Returns `true` if accepted, `false` if the penalty queue is full.
    pub fn defer(&mut self, account: &[u8; 32], txn_id: u64) -> bool {
        let entry = self.accounts.entry(*account).or_insert(AccountPenalty {
            conflict_count: self.config.hot_threshold,
            deferred: VecDeque::new(),
        });
        if entry.deferred.len() >= self.config.max_penalty_per_account {
            return false;
        }
        entry.deferred.push_back(txn_id);
        self.total_deferred += 1;
        true
    }

    /// Drain up to `drain_batch_size` transactions from each hot account.
    /// Returns transaction IDs that should be re-queued into the main queue.
    pub fn drain(&mut self) -> Vec<u64> {
        let mut released = Vec::new();
        for penalty in self.accounts.values_mut() {
            for _ in 0..self.config.drain_batch_size {
                if let Some(txn_id) = penalty.deferred.pop_front() {
                    released.push(txn_id);
                    self.total_deferred = self.total_deferred.saturating_sub(1);
                } else {
                    break;
                }
            }
        }
        released
    }

    /// Total transactions currently deferred across all accounts.
    pub fn total_deferred(&self) -> usize {
        self.total_deferred
    }

    /// Number of accounts currently tracked (hot or warming up).
    pub fn tracked_account_count(&self) -> usize {
        self.accounts.len()
    }

    /// Number of hot accounts (at or above threshold).
    pub fn hot_account_count(&self) -> usize {
        self.accounts
            .values()
            .filter(|p| p.conflict_count >= self.config.hot_threshold)
            .count()
    }

    /// Reset all penalty state (e.g., for a new block).
    pub fn reset(&mut self) {
        self.accounts.clear();
        self.total_deferred = 0;
    }
}

/// Per-account write cost rebate tracker.
///
/// Tracks write cost per account and supports crediting back unused
/// write CUs after execution, separate from the total block rebate.
pub struct WriteRebateTracker {
    /// account → accumulated write cost.
    costs: HashMap<[u8; 32], u64>,
    /// Maximum write cost per account per block.
    max_per_account: u64,
}

impl WriteRebateTracker {
    /// Create a new tracker with the given per-account limit.
    pub fn new(max_per_account: u64) -> Self {
        Self {
            costs: HashMap::new(),
            max_per_account,
        }
    }

    /// Record write cost for an account.
    pub fn record(&mut self, account: &[u8; 32], cost: u64) {
        *self.costs.entry(*account).or_insert(0) += cost;
    }

    /// Check if adding `cost` to an account would exceed the limit.
    pub fn would_exceed(&self, account: &[u8; 32], cost: u64) -> bool {
        let current = self.costs.get(account).copied().unwrap_or(0);
        current.saturating_add(cost) > self.max_per_account
    }

    /// Apply a rebate (credit back) for an account.
    pub fn rebate(&mut self, account: &[u8; 32], amount: u64) {
        if let Some(cost) = self.costs.get_mut(account) {
            *cost = cost.saturating_sub(amount);
        }
    }

    /// Get current write cost for an account.
    pub fn current_cost(&self, account: &[u8; 32]) -> u64 {
        self.costs.get(account).copied().unwrap_or(0)
    }

    /// Reset for a new block.
    pub fn reset(&mut self) {
        self.costs.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(id: u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[0] = id;
        a
    }

    // ── PenaltyTracker tests ──

    #[test]
    fn account_becomes_hot_after_threshold() {
        let mut tracker = PenaltyTracker::new(PenaltyConfig {
            hot_threshold: 3,
            ..Default::default()
        });
        assert!(!tracker.record_conflict(&account(1)));
        assert!(!tracker.record_conflict(&account(1)));
        assert!(tracker.record_conflict(&account(1)));
        assert!(tracker.is_hot(&account(1)));
    }

    #[test]
    fn non_hot_account() {
        let tracker = PenaltyTracker::new(PenaltyConfig::default());
        assert!(!tracker.is_hot(&account(1)));
    }

    #[test]
    fn defer_and_drain() {
        let mut tracker = PenaltyTracker::new(PenaltyConfig {
            hot_threshold: 1,
            drain_batch_size: 2,
            ..Default::default()
        });
        tracker.record_conflict(&account(1));
        tracker.defer(&account(1), 100);
        tracker.defer(&account(1), 200);
        tracker.defer(&account(1), 300);

        assert_eq!(tracker.total_deferred(), 3);

        let released = tracker.drain();
        assert_eq!(released.len(), 2); // drain_batch_size=2
        assert_eq!(released[0], 100);
        assert_eq!(released[1], 200);
        assert_eq!(tracker.total_deferred(), 1);
    }

    #[test]
    fn defer_rejects_when_full() {
        let mut tracker = PenaltyTracker::new(PenaltyConfig {
            hot_threshold: 1,
            max_penalty_per_account: 2,
            ..Default::default()
        });
        tracker.record_conflict(&account(1));
        assert!(tracker.defer(&account(1), 1));
        assert!(tracker.defer(&account(1), 2));
        assert!(!tracker.defer(&account(1), 3));
    }

    #[test]
    fn reset_clears_all() {
        let mut tracker = PenaltyTracker::new(PenaltyConfig::default());
        tracker.record_conflict(&account(1));
        tracker.record_conflict(&account(1));
        tracker.record_conflict(&account(1));
        tracker.defer(&account(1), 1);

        tracker.reset();
        assert!(!tracker.is_hot(&account(1)));
        assert_eq!(tracker.total_deferred(), 0);
        assert_eq!(tracker.tracked_account_count(), 0);
    }

    #[test]
    fn hot_account_count() {
        let mut tracker = PenaltyTracker::new(PenaltyConfig {
            hot_threshold: 2,
            ..Default::default()
        });
        tracker.record_conflict(&account(1));
        tracker.record_conflict(&account(1)); // hot
        tracker.record_conflict(&account(2)); // not hot yet
        assert_eq!(tracker.hot_account_count(), 1);
    }

    // ── WriteRebateTracker tests ──

    #[test]
    fn write_cost_tracking() {
        let mut tracker = WriteRebateTracker::new(1_000_000);
        tracker.record(&account(1), 500_000);
        assert_eq!(tracker.current_cost(&account(1)), 500_000);
        assert!(!tracker.would_exceed(&account(1), 400_000));
        assert!(tracker.would_exceed(&account(1), 600_000));
    }

    #[test]
    fn write_rebate_reduces_cost() {
        let mut tracker = WriteRebateTracker::new(1_000_000);
        tracker.record(&account(1), 800_000);
        tracker.rebate(&account(1), 300_000);
        assert_eq!(tracker.current_cost(&account(1)), 500_000);
        assert!(!tracker.would_exceed(&account(1), 400_000));
    }

    #[test]
    fn write_rebate_saturates_at_zero() {
        let mut tracker = WriteRebateTracker::new(1_000_000);
        tracker.record(&account(1), 100_000);
        tracker.rebate(&account(1), 500_000);
        assert_eq!(tracker.current_cost(&account(1)), 0);
    }

    #[test]
    fn write_tracker_reset() {
        let mut tracker = WriteRebateTracker::new(1_000_000);
        tracker.record(&account(1), 500_000);
        tracker.reset();
        assert_eq!(tracker.current_cost(&account(1)), 0);
    }

    #[test]
    fn unknown_account_has_zero_cost() {
        let tracker = WriteRebateTracker::new(1_000_000);
        assert_eq!(tracker.current_cost(&account(99)), 0);
        assert!(!tracker.would_exceed(&account(99), 500_000));
    }
}
