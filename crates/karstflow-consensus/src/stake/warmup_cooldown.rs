/// Warmup and cooldown rate calculations for stake activation/deactivation.
///
/// Stake activates and deactivates gradually over multiple epochs, with the
/// rate determined by the network-wide stake activity. The default rate is
/// 25% per epoch, with a newer rate of 9% activated by feature gate.
use crate::stake_history::StakeHistoryEntry;
use karstflow_constants::stake_program as constants;

/// Summary of activation state for a delegation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivationStatus {
    /// Stake that is fully effective for consensus
    pub effective: u64,
    /// Stake still in the process of activating (warming up)
    pub activating: u64,
    /// Stake in the process of deactivating (cooling down)
    pub deactivating: u64,
}

impl ActivationStatus {
    pub fn new(effective: u64, activating: u64, deactivating: u64) -> Self {
        Self {
            effective,
            activating,
            deactivating,
        }
    }

    /// Total stake in all states.
    pub fn total(&self) -> u64 {
        self.effective
            .saturating_add(self.activating)
            .saturating_add(self.deactivating)
    }

    /// Whether there is any stake in transition.
    pub fn in_transition(&self) -> bool {
        self.activating > 0 || self.deactivating > 0
    }

    /// Convert to a history entry.
    pub fn to_history_entry(&self) -> StakeHistoryEntry {
        StakeHistoryEntry::new(self.effective, self.activating, self.deactivating)
    }

    /// Create from a history entry.
    pub fn from_history_entry(entry: &StakeHistoryEntry) -> Self {
        Self {
            effective: entry.effective,
            activating: entry.activating,
            deactivating: entry.deactivating,
        }
    }
}

/// Determine the warmup/cooldown rate for a given epoch.
///
/// Returns the default rate (25%) for epochs before the new rate activation,
/// and the new rate (9%) for epochs at or after activation.
pub fn warmup_cooldown_rate(current_epoch: u64, new_rate_activation_epoch: Option<u64>) -> f64 {
    match new_rate_activation_epoch {
        Some(activation_epoch) if current_epoch >= activation_epoch => {
            constants::NEW_WARMUP_COOLDOWN_RATE
        }
        _ => constants::DEFAULT_WARMUP_COOLDOWN_RATE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_rate_when_no_activation_epoch() {
        let rate = warmup_cooldown_rate(100, None);
        assert!((rate - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn default_rate_before_activation_epoch() {
        let rate = warmup_cooldown_rate(99, Some(100));
        assert!((rate - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn new_rate_at_activation_epoch() {
        let rate = warmup_cooldown_rate(100, Some(100));
        assert!((rate - 0.09).abs() < f64::EPSILON);
    }

    #[test]
    fn new_rate_after_activation_epoch() {
        let rate = warmup_cooldown_rate(200, Some(100));
        assert!((rate - 0.09).abs() < f64::EPSILON);
    }

    #[test]
    fn activation_status_total() {
        let status = ActivationStatus::new(100, 50, 25);
        assert_eq!(status.total(), 175);
    }

    #[test]
    fn activation_status_in_transition() {
        assert!(ActivationStatus::new(100, 50, 0).in_transition());
        assert!(ActivationStatus::new(100, 0, 25).in_transition());
        assert!(!ActivationStatus::new(100, 0, 0).in_transition());
    }

    #[test]
    fn activation_status_history_roundtrip() {
        let status = ActivationStatus::new(100, 50, 25);
        let entry = status.to_history_entry();
        let back = ActivationStatus::from_history_entry(&entry);
        assert_eq!(status, back);
    }
}
