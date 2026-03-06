use dashmap::DashMap;
use karstflow_storage::Pubkey;

/// Track per-account write costs for write-lock contention limits.
///
/// Uses a concurrent map so multiple scheduling threads can read
/// and update account costs without coarse-grained locking.
pub struct AccountCostTracker {
    costs: DashMap<Pubkey, u64>,
}

impl AccountCostTracker {
    /// Create an empty tracker.
    pub fn new() -> Self {
        Self {
            costs: DashMap::new(),
        }
    }

    /// Add cost for a specific account.
    pub fn add(&self, pubkey: &Pubkey, cost: u64) {
        self.costs
            .entry(*pubkey)
            .and_modify(|v| *v = v.saturating_add(cost))
            .or_insert(cost);
    }

    /// Subtract cost for a specific account.
    pub fn remove(&self, pubkey: &Pubkey, cost: u64) {
        if let Some(mut entry) = self.costs.get_mut(pubkey) {
            *entry = entry.saturating_sub(cost);
        }
    }

    /// Get the current accumulated cost for an account.
    pub fn get(&self, pubkey: &Pubkey) -> u64 {
        self.costs.get(pubkey).map_or(0, |v| *v)
    }
}

impl Default for AccountCostTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(n: u8) -> Pubkey {
        Pubkey::new([n; 32])
    }

    #[test]
    fn add_and_get() {
        let tracker = AccountCostTracker::new();
        let key = pk(1);
        tracker.add(&key, 500);
        assert_eq!(tracker.get(&key), 500);
    }

    #[test]
    fn add_accumulates() {
        let tracker = AccountCostTracker::new();
        let key = pk(1);
        tracker.add(&key, 100);
        tracker.add(&key, 200);
        assert_eq!(tracker.get(&key), 300);
    }

    #[test]
    fn remove_subtracts() {
        let tracker = AccountCostTracker::new();
        let key = pk(1);
        tracker.add(&key, 500);
        tracker.remove(&key, 200);
        assert_eq!(tracker.get(&key), 300);
    }

    #[test]
    fn remove_saturates_at_zero() {
        let tracker = AccountCostTracker::new();
        let key = pk(1);
        tracker.add(&key, 100);
        tracker.remove(&key, 999);
        assert_eq!(tracker.get(&key), 0);
    }

    #[test]
    fn get_unknown_returns_zero() {
        let tracker = AccountCostTracker::new();
        assert_eq!(tracker.get(&pk(99)), 0);
    }

    #[test]
    fn remove_unknown_is_noop() {
        let tracker = AccountCostTracker::new();
        tracker.remove(&pk(1), 100);
        assert_eq!(tracker.get(&pk(1)), 0);
    }

    #[test]
    fn multiple_accounts_independent() {
        let tracker = AccountCostTracker::new();
        tracker.add(&pk(1), 100);
        tracker.add(&pk(2), 200);
        assert_eq!(tracker.get(&pk(1)), 100);
        assert_eq!(tracker.get(&pk(2)), 200);
    }

    #[test]
    fn add_saturates_at_max() {
        let tracker = AccountCostTracker::new();
        let key = pk(1);
        tracker.add(&key, u64::MAX);
        tracker.add(&key, 1);
        assert_eq!(tracker.get(&key), u64::MAX);
    }
}
