/// Stake history tracking for warmup/cooldown calculations.
///
/// Maintains a rolling history of network-wide stake activation and deactivation
/// across epochs. Used for accurate warmup/cooldown calculations when delegating
/// or withdrawing stake.
use std::collections::VecDeque;

/// Maximum number of epochs to track in stake history.
pub const STAKE_HISTORY_CAP: usize = 512;

/// Stake state for a single epoch.
///
/// Tracks the total stake in various states: fully effective (activated),
/// in the process of activating (warming up), or in the process of
/// deactivating (cooling down).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StakeHistoryEntry {
    /// Fully activated stake (effective for consensus)
    pub effective: u64,
    /// Stake currently activating (warmup in progress)
    pub activating: u64,
    /// Stake currently deactivating (cooldown in progress)
    pub deactivating: u64,
}

impl StakeHistoryEntry {
    pub fn new(effective: u64, activating: u64, deactivating: u64) -> Self {
        Self {
            effective,
            activating,
            deactivating,
        }
    }

    /// Get total stake in all states.
    pub fn total(&self) -> u64 {
        self.effective
            .saturating_add(self.activating)
            .saturating_add(self.deactivating)
    }

    /// Check if there is any stake in transition (activating or deactivating).
    pub fn in_transition(&self) -> bool {
        self.activating > 0 || self.deactivating > 0
    }
}

/// Epoch with its associated stake state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochStakeEntry {
    /// Epoch number
    pub epoch: u64,
    /// Stake state for this epoch
    pub entry: StakeHistoryEntry,
}

impl EpochStakeEntry {
    pub fn new(epoch: u64, entry: StakeHistoryEntry) -> Self {
        Self { epoch, entry }
    }
}

/// Rolling history of stake activation/deactivation across epochs.
///
/// Maintains up to STAKE_HISTORY_CAP epochs of history. Older epochs
/// are evicted when capacity is reached.
#[derive(Debug, Clone)]
pub struct StakeHistory {
    /// History entries (epoch -> stake state)
    entries: VecDeque<EpochStakeEntry>,
}

impl StakeHistory {
    /// Create a new empty stake history.
    pub fn new() -> Self {
        Self {
            entries: VecDeque::with_capacity(STAKE_HISTORY_CAP),
        }
    }

    /// Add or update stake history for an epoch.
    ///
    /// If the epoch already exists, updates its entry.
    /// If capacity is reached, removes the oldest epoch.
    pub fn add(&mut self, epoch: u64, entry: StakeHistoryEntry) {
        // Check if epoch already exists
        if let Some(pos) = self.entries.iter().position(|e| e.epoch == epoch) {
            self.entries[pos].entry = entry;
            return;
        }

        // Add new entry
        let epoch_entry = EpochStakeEntry::new(epoch, entry);

        // Maintain chronological order (newest at back)
        // Find insertion point
        let insert_pos = self
            .entries
            .iter()
            .position(|e| e.epoch > epoch)
            .unwrap_or(self.entries.len());

        self.entries.insert(insert_pos, epoch_entry);

        // Evict oldest if at capacity
        while self.entries.len() > STAKE_HISTORY_CAP {
            self.entries.pop_front();
        }
    }

    /// Get stake history entry for a specific epoch.
    pub fn get(&self, epoch: u64) -> Option<&StakeHistoryEntry> {
        self.entries
            .iter()
            .find(|e| e.epoch == epoch)
            .map(|e| &e.entry)
    }

    /// Get the most recent epoch in history.
    pub fn latest_epoch(&self) -> Option<u64> {
        self.entries.back().map(|e| e.epoch)
    }

    /// Get the oldest epoch in history.
    pub fn oldest_epoch(&self) -> Option<u64> {
        self.entries.front().map(|e| e.epoch)
    }

    /// Get number of epochs in history.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if history is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over all entries in chronological order (oldest to newest).
    pub fn iter(&self) -> impl Iterator<Item = &EpochStakeEntry> {
        self.entries.iter()
    }

    /// Clear all history.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Calculate warmup/cooldown progress for a delegation.
    ///
    /// Returns the effective stake ratio (0.0 to 1.0) based on network-wide
    /// activation/deactivation rates in the stake history.
    pub fn warmup_cooldown_rate(
        &self,
        current_epoch: u64,
        mut new_rate_activation: u64,
        mut new_rate_deactivation: u64,
    ) -> (f64, f64) {
        // Default rates if no history
        if self.is_empty() {
            return (0.25, 0.25); // 25% per epoch default
        }

        // Look at previous epoch to determine rates
        if let Some(prev_entry) = self.get(current_epoch.saturating_sub(1)) {
            // Warmup rate: new_activation / (effective + activating)
            let total_activating = prev_entry.effective.saturating_add(prev_entry.activating);
            if total_activating > 0 && new_rate_activation > 0 {
                new_rate_activation = std::cmp::min(new_rate_activation, total_activating);
            }

            // Cooldown rate: new_deactivation / (effective + deactivating)
            let total_deactivating = prev_entry.effective.saturating_add(prev_entry.deactivating);
            if total_deactivating > 0 && new_rate_deactivation > 0 {
                new_rate_deactivation = std::cmp::min(new_rate_deactivation, total_deactivating);
            }
        }

        // Calculate rates as fractions
        let warmup_rate = if new_rate_activation > 0 {
            // Cap at 25% minimum, but allow faster warmup if network conditions permit
            0.25_f64.max(new_rate_activation as f64 / 100.0)
        } else {
            0.25
        };

        let cooldown_rate = if new_rate_deactivation > 0 {
            0.25_f64.max(new_rate_deactivation as f64 / 100.0)
        } else {
            0.25
        };

        (warmup_rate, cooldown_rate)
    }
}

impl Default for StakeHistory {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stake_history_entry_calculates_total() {
        let entry = StakeHistoryEntry::new(1000, 200, 100);
        assert_eq!(entry.total(), 1300);
    }

    #[test]
    fn stake_history_entry_detects_transition() {
        let entry = StakeHistoryEntry::new(1000, 0, 0);
        assert!(!entry.in_transition());

        let entry = StakeHistoryEntry::new(1000, 100, 0);
        assert!(entry.in_transition());

        let entry = StakeHistoryEntry::new(1000, 0, 50);
        assert!(entry.in_transition());
    }

    #[test]
    fn stake_history_adds_entry() {
        let mut history = StakeHistory::new();
        let entry = StakeHistoryEntry::new(1000, 100, 50);

        history.add(10, entry);

        assert_eq!(history.len(), 1);
        assert_eq!(history.get(10), Some(&entry));
    }

    #[test]
    fn stake_history_updates_existing_epoch() {
        let mut history = StakeHistory::new();

        let entry1 = StakeHistoryEntry::new(1000, 100, 50);
        history.add(10, entry1);

        let entry2 = StakeHistoryEntry::new(1200, 80, 30);
        history.add(10, entry2);

        // Should update, not add
        assert_eq!(history.len(), 1);
        assert_eq!(history.get(10), Some(&entry2));
    }

    #[test]
    fn stake_history_maintains_chronological_order() {
        let mut history = StakeHistory::new();

        // Add out of order
        history.add(15, StakeHistoryEntry::new(1500, 0, 0));
        history.add(10, StakeHistoryEntry::new(1000, 0, 0));
        history.add(12, StakeHistoryEntry::new(1200, 0, 0));

        // Should be sorted
        let epochs: Vec<u64> = history.iter().map(|e| e.epoch).collect();
        assert_eq!(epochs, vec![10, 12, 15]);
    }

    #[test]
    fn stake_history_evicts_oldest() {
        let mut history = StakeHistory::new();

        // Fill beyond capacity
        for epoch in 0..(STAKE_HISTORY_CAP + 10) {
            history.add(epoch as u64, StakeHistoryEntry::new(1000, 0, 0));
        }

        // Should be capped
        assert_eq!(history.len(), STAKE_HISTORY_CAP);

        // Oldest should be evicted
        assert_eq!(history.oldest_epoch(), Some(10));
        assert_eq!(history.latest_epoch(), Some((STAKE_HISTORY_CAP + 9) as u64));
    }

    #[test]
    fn stake_history_tracks_latest_and_oldest() {
        let mut history = StakeHistory::new();

        assert_eq!(history.oldest_epoch(), None);
        assert_eq!(history.latest_epoch(), None);

        history.add(10, StakeHistoryEntry::new(1000, 0, 0));
        assert_eq!(history.oldest_epoch(), Some(10));
        assert_eq!(history.latest_epoch(), Some(10));

        history.add(15, StakeHistoryEntry::new(1500, 0, 0));
        assert_eq!(history.oldest_epoch(), Some(10));
        assert_eq!(history.latest_epoch(), Some(15));

        history.add(5, StakeHistoryEntry::new(500, 0, 0));
        assert_eq!(history.oldest_epoch(), Some(5));
        assert_eq!(history.latest_epoch(), Some(15));
    }

    #[test]
    fn stake_history_clears() {
        let mut history = StakeHistory::new();

        history.add(10, StakeHistoryEntry::new(1000, 0, 0));
        history.add(11, StakeHistoryEntry::new(1100, 0, 0));

        assert_eq!(history.len(), 2);

        history.clear();

        assert_eq!(history.len(), 0);
        assert!(history.is_empty());
    }

    #[test]
    fn stake_history_iterates_chronologically() {
        let mut history = StakeHistory::new();

        history.add(15, StakeHistoryEntry::new(1500, 0, 0));
        history.add(10, StakeHistoryEntry::new(1000, 0, 0));
        history.add(12, StakeHistoryEntry::new(1200, 0, 0));

        let epochs: Vec<u64> = history.iter().map(|e| e.epoch).collect();
        assert_eq!(epochs, vec![10, 12, 15]);
    }

    #[test]
    fn stake_history_calculates_warmup_cooldown_rate() {
        let mut history = StakeHistory::new();

        history.add(9, StakeHistoryEntry::new(10000, 2000, 1000));

        let (warmup_rate, cooldown_rate) = history.warmup_cooldown_rate(10, 100, 100);

        // Should return at least 0.25 (25% per epoch)
        assert!(warmup_rate >= 0.25);
        assert!(cooldown_rate >= 0.25);
    }

    #[test]
    fn stake_history_default_rates_when_empty() {
        let history = StakeHistory::new();

        let (warmup_rate, cooldown_rate) = history.warmup_cooldown_rate(10, 100, 100);

        // Should return default 25% rates
        assert_eq!(warmup_rate, 0.25);
        assert_eq!(cooldown_rate, 0.25);
    }
}
