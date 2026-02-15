use dashmap::DashMap;
use paradencer_storage::Pubkey;

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
