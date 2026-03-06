/// Initializer bundle state machine for the pack scheduler.
///
/// Manages the lifecycle of the "initializer bundle" — a special bundle
/// that must succeed before any other bundles can be scheduled in a slot.
/// The state machine ensures that:
/// - Only one initializer bundle is in-flight at a time
/// - Bundle scheduling is blocked until initialization succeeds
/// - Failed initializations can be retried
///
/// State transitions:
///   NotInitialized → Pending (when IB is scheduled)
///   Pending → Ready (on IB execution success)
///   Pending → Failed (on IB execution failure)
///   Failed → Pending (when a new IB is scheduled)

/// Maximum number of transactions in a single bundle.
pub const MAX_TXN_PER_BUNDLE: usize = 5;

/// Initializer bundle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IbState {
    /// No initializer bundle has been scheduled this slot.
    NotInitialized,
    /// An initializer bundle has been scheduled but not yet completed.
    Pending,
    /// The most recently scheduled initializer bundle failed.
    Failed,
    /// The initializer bundle succeeded; bundles can now be scheduled.
    Ready,
}

/// Bundle metadata attached to a group of transactions.
#[derive(Debug, Clone)]
pub struct BundleMeta {
    /// Number of transactions in this bundle.
    pub txn_count: usize,
    /// Whether this is the initializer bundle.
    pub is_initializer: bool,
    /// Opaque application-specific metadata.
    pub app_data: Vec<u8>,
}

/// Tracks the initializer bundle state machine per slot.
pub struct BundleTracker {
    state: IbState,
    /// How many IB attempts have been made this slot.
    attempt_count: u32,
    /// Whether bundle support is enabled.
    enabled: bool,
}

impl BundleTracker {
    /// Create a new tracker. If `enabled` is false, all bundle operations are no-ops.
    pub fn new(enabled: bool) -> Self {
        Self {
            state: IbState::NotInitialized,
            attempt_count: 0,
            enabled,
        }
    }

    /// Current state of the initializer bundle.
    pub fn state(&self) -> IbState {
        self.state
    }

    /// Whether bundle scheduling is allowed (IB succeeded).
    pub fn can_schedule_bundles(&self) -> bool {
        self.enabled && self.state == IbState::Ready
    }

    /// Whether the initializer bundle needs to be (re)scheduled.
    pub fn needs_initializer(&self) -> bool {
        self.enabled && matches!(self.state, IbState::NotInitialized | IbState::Failed)
    }

    /// Whether an initializer bundle is currently in-flight.
    pub fn is_pending(&self) -> bool {
        self.state == IbState::Pending
    }

    /// Mark the initializer bundle as scheduled (transition to Pending).
    ///
    /// Returns `true` if the transition was valid, `false` if already Pending or Ready.
    pub fn schedule_initializer(&mut self) -> bool {
        if !self.enabled {
            return false;
        }
        match self.state {
            IbState::NotInitialized | IbState::Failed => {
                self.state = IbState::Pending;
                self.attempt_count += 1;
                true
            }
            IbState::Pending | IbState::Ready => false,
        }
    }

    /// Report that the initializer bundle succeeded.
    ///
    /// Returns `true` if the transition was valid (from Pending).
    pub fn report_success(&mut self) -> bool {
        if self.state == IbState::Pending {
            self.state = IbState::Ready;
            true
        } else {
            false
        }
    }

    /// Report that the initializer bundle failed.
    ///
    /// Returns `true` if the transition was valid (from Pending).
    pub fn report_failure(&mut self) -> bool {
        if self.state == IbState::Pending {
            self.state = IbState::Failed;
            true
        } else {
            false
        }
    }

    /// Number of initializer bundle attempts this slot.
    pub fn attempt_count(&self) -> u32 {
        self.attempt_count
    }

    /// Whether bundle support is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Reset state for a new slot.
    pub fn reset(&mut self) {
        self.state = IbState::NotInitialized;
        self.attempt_count = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_state_is_not_initialized() {
        let tracker = BundleTracker::new(true);
        assert_eq!(tracker.state(), IbState::NotInitialized);
        assert!(!tracker.can_schedule_bundles());
        assert!(tracker.needs_initializer());
    }

    #[test]
    fn schedule_transitions_to_pending() {
        let mut tracker = BundleTracker::new(true);
        assert!(tracker.schedule_initializer());
        assert_eq!(tracker.state(), IbState::Pending);
        assert!(tracker.is_pending());
        assert!(!tracker.can_schedule_bundles());
    }

    #[test]
    fn success_transitions_to_ready() {
        let mut tracker = BundleTracker::new(true);
        tracker.schedule_initializer();
        assert!(tracker.report_success());
        assert_eq!(tracker.state(), IbState::Ready);
        assert!(tracker.can_schedule_bundles());
    }

    #[test]
    fn failure_transitions_to_failed() {
        let mut tracker = BundleTracker::new(true);
        tracker.schedule_initializer();
        assert!(tracker.report_failure());
        assert_eq!(tracker.state(), IbState::Failed);
        assert!(!tracker.can_schedule_bundles());
        assert!(tracker.needs_initializer());
    }

    #[test]
    fn failed_can_reschedule() {
        let mut tracker = BundleTracker::new(true);
        tracker.schedule_initializer();
        tracker.report_failure();
        assert!(tracker.schedule_initializer());
        assert_eq!(tracker.state(), IbState::Pending);
        assert_eq!(tracker.attempt_count(), 2);
    }

    #[test]
    fn cannot_schedule_when_pending() {
        let mut tracker = BundleTracker::new(true);
        tracker.schedule_initializer();
        assert!(!tracker.schedule_initializer());
    }

    #[test]
    fn cannot_schedule_when_ready() {
        let mut tracker = BundleTracker::new(true);
        tracker.schedule_initializer();
        tracker.report_success();
        assert!(!tracker.schedule_initializer());
    }

    #[test]
    fn success_only_from_pending() {
        let mut tracker = BundleTracker::new(true);
        assert!(!tracker.report_success());
    }

    #[test]
    fn failure_only_from_pending() {
        let mut tracker = BundleTracker::new(true);
        assert!(!tracker.report_failure());
    }

    #[test]
    fn disabled_tracker() {
        let mut tracker = BundleTracker::new(false);
        assert!(!tracker.can_schedule_bundles());
        assert!(!tracker.needs_initializer());
        assert!(!tracker.schedule_initializer());
    }

    #[test]
    fn reset_returns_to_initial() {
        let mut tracker = BundleTracker::new(true);
        tracker.schedule_initializer();
        tracker.report_success();
        tracker.reset();
        assert_eq!(tracker.state(), IbState::NotInitialized);
        assert_eq!(tracker.attempt_count(), 0);
    }

    #[test]
    fn attempt_count_tracks_schedules() {
        let mut tracker = BundleTracker::new(true);
        assert_eq!(tracker.attempt_count(), 0);
        tracker.schedule_initializer();
        assert_eq!(tracker.attempt_count(), 1);
        tracker.report_failure();
        tracker.schedule_initializer();
        assert_eq!(tracker.attempt_count(), 2);
    }
}
