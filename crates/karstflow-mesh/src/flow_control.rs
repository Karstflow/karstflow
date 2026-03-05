//! Credit-based flow control for one producer with multiple reliable receivers.
//!
//! Extends the single-consumer `FlowSequence` to support one-producer,
//! N-consumer (SPMC) topologies. The producer can only advance as fast
//! as the **slowest** reliable consumer allows.
//!
//! ## Hysteresis
//!
//! To prevent start/stop oscillation, the flow controller uses two
//! thresholds:
//!
//! - `cr_refill`: When credits drop below this level, the producer
//!   queries all receivers to recalculate available credits.
//! - `cr_resume`: Credits must reach this level before the producer
//!   resumes publishing. (`cr_resume` > `cr_refill`).
//!
//! This hysteresis gap prevents the producer from alternating between
//! "nearly out of credits → refill → immediately publish → nearly out"
//! on every iteration.
//!
//! ## Credit Model
//!
//! Each receiver exposes a sequence number (via `FlowSequence`) indicating
//! how far it has consumed. The producer's available credits are:
//!
//! ```text
//! cr_avail = min(cr_max, min_over_receivers(rx_seq - tx_seq + rx_cr_max))
//! ```
//!
//! The producer decrements credits on each publish. When `cr_avail`
//! drops below `cr_refill`, it re-queries all receivers.

/// Maximum number of reliable receivers.
pub const MAX_RECEIVERS: usize = 64;

/// Flow control configuration for one producer.
#[derive(Debug, Clone)]
pub struct FlowControlConfig {
    /// Maximum burst size (fragments published without checking credits).
    pub cr_burst: u64,
    /// Maximum total credits across all receivers.
    pub cr_max: u64,
    /// Credit level at which to re-query receivers.
    pub cr_refill: u64,
    /// Credit level at which to resume publishing after a refill.
    pub cr_resume: u64,
}

impl FlowControlConfig {
    /// Create a config with automatic threshold computation.
    ///
    /// Given a link depth and burst size, computes appropriate
    /// refill and resume thresholds.
    pub fn from_depth(depth: u64, burst: u64) -> Self {
        let cr_max = depth;
        let cr_burst = burst.min(cr_max);
        // Refill at 25% of max.
        let cr_refill = cr_max / 4;
        // Resume at 50% of max.
        let cr_resume = cr_max / 2;
        Self {
            cr_burst,
            cr_max,
            cr_refill,
            cr_resume,
        }
    }
}

/// Per-receiver tracking state.
struct Receiver {
    /// Pointer to the receiver's flow sequence (their current consumption position).
    /// The producer reads this to determine how far the receiver has consumed.
    seq_fn: Box<dyn Fn() -> u64 + Send>,
    /// Maximum credits this receiver can provide.
    cr_max: u64,
    /// Slow-receiver diagnostic counter. Incremented when this receiver
    /// is the bottleneck during a credit query.
    slow_count: u64,
}

/// Multi-receiver credit-based flow controller.
///
/// Manages credit accounting for one producer publishing to N reliable
/// receivers. Each receiver independently tracks its consumption via
/// a sequence counter. The producer's effective credit limit is the
/// minimum across all receivers.
pub struct FlowControl {
    config: FlowControlConfig,
    receivers: Vec<Receiver>,
    /// Current available credits.
    cr_avail: u64,
    /// Whether we're in the "refilling" state (waiting for cr_resume).
    in_refill: bool,
    /// Current producer sequence number.
    tx_seq: u64,
}

impl FlowControl {
    /// Create a new flow controller with no receivers.
    pub fn new(config: FlowControlConfig) -> Self {
        Self {
            cr_avail: config.cr_max,
            config,
            receivers: Vec::new(),
            in_refill: false,
            tx_seq: 0,
        }
    }

    /// Register a reliable receiver.
    ///
    /// `seq_fn` is called to read the receiver's current sequence position.
    /// `cr_max` is the maximum credits this receiver's link depth provides.
    ///
    /// # Panics
    ///
    /// Panics if `MAX_RECEIVERS` would be exceeded.
    pub fn add_receiver<F>(&mut self, seq_fn: F, cr_max: u64)
    where
        F: Fn() -> u64 + Send + 'static,
    {
        assert!(
            self.receivers.len() < MAX_RECEIVERS,
            "exceeded MAX_RECEIVERS ({MAX_RECEIVERS})"
        );
        self.receivers.push(Receiver {
            seq_fn: Box::new(seq_fn),
            cr_max,
            slow_count: 0,
        });
    }

    /// Number of registered receivers.
    pub fn receiver_count(&self) -> usize {
        self.receivers.len()
    }

    /// Current available credits.
    #[inline]
    pub fn cr_avail(&self) -> u64 {
        self.cr_avail
    }

    /// Whether the producer has credits to publish.
    ///
    /// When in the refill state, this returns false until credits
    /// reach `cr_resume`.
    #[inline]
    pub fn has_credits(&self) -> bool {
        if self.in_refill {
            self.cr_avail >= self.config.cr_resume
        } else {
            self.cr_avail > 0
        }
    }

    /// Consume one credit (call after publishing one fragment).
    #[inline]
    pub fn spend(&mut self, amount: u64) {
        self.cr_avail = self.cr_avail.saturating_sub(amount);
        self.tx_seq = self.tx_seq.wrapping_add(amount);
    }

    /// Update the producer's sequence number.
    pub fn set_tx_seq(&mut self, seq: u64) {
        self.tx_seq = seq;
    }

    /// Query all receivers and recalculate available credits.
    ///
    /// This is the "slow path" called when credits drop below `cr_refill`.
    /// Returns the index of the slowest receiver (or `None` if no receivers).
    pub fn query_credits(&mut self) -> Option<usize> {
        if self.receivers.is_empty() {
            self.cr_avail = self.config.cr_max;
            self.in_refill = false;
            return None;
        }

        let mut min_cr = u64::MAX;
        let mut slowest_idx = 0;

        for (i, rx) in self.receivers.iter().enumerate() {
            let rx_seq = (rx.seq_fn)();
            // Credits from this receiver: how far ahead we can be.
            // cr = rx_cr_max - (tx_seq - rx_seq)
            // Using wrapping arithmetic for sequence numbers.
            let consumed = self.tx_seq.wrapping_sub(rx_seq);
            let cr = rx.cr_max.saturating_sub(consumed);
            if cr < min_cr {
                min_cr = cr;
                slowest_idx = i;
            }
        }

        // Clamp to our configured max.
        self.cr_avail = min_cr.min(self.config.cr_max);

        // Track slow receiver.
        self.receivers[slowest_idx].slow_count += 1;

        // Check hysteresis.
        if self.cr_avail >= self.config.cr_resume {
            self.in_refill = false;
        }

        Some(slowest_idx)
    }

    /// Check and optionally refill credits.
    ///
    /// Call this in the tile's service loop. If credits are below
    /// `cr_refill`, queries all receivers.
    #[inline]
    pub fn check_credits(&mut self) {
        if self.cr_avail < self.config.cr_refill || self.in_refill {
            self.in_refill = true;
            self.query_credits();
        }
    }

    /// Read the slow-receiver diagnostic counter for a receiver.
    pub fn slow_count(&self, rx_idx: usize) -> u64 {
        self.receivers[rx_idx].slow_count
    }

    /// Configuration.
    pub fn config(&self) -> &FlowControlConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    fn make_config(depth: u64) -> FlowControlConfig {
        FlowControlConfig::from_depth(depth, 4)
    }

    #[test]
    fn no_receivers_full_credits() {
        let config = make_config(100);
        let mut fctl = FlowControl::new(config);

        assert_eq!(fctl.cr_avail(), 100);
        assert!(fctl.has_credits());

        fctl.query_credits();
        assert_eq!(fctl.cr_avail(), 100);
    }

    #[test]
    fn single_receiver_credit_tracking() {
        let rx_seq = Arc::new(AtomicU64::new(0));
        let rx_seq_clone = rx_seq.clone();

        let config = make_config(32);
        let mut fctl = FlowControl::new(config);
        fctl.add_receiver(move || rx_seq_clone.load(Ordering::Relaxed), 32);

        // Initially: tx_seq=0, rx_seq=0, cr = 32 - (0-0) = 32.
        fctl.query_credits();
        assert_eq!(fctl.cr_avail(), 32);

        // Publish 10 fragments.
        fctl.spend(10);
        assert_eq!(fctl.cr_avail(), 22);

        // Receiver hasn't advanced — query confirms.
        fctl.set_tx_seq(10);
        fctl.query_credits();
        assert_eq!(fctl.cr_avail(), 22);

        // Receiver advances to seq 5.
        rx_seq.store(5, Ordering::Relaxed);
        fctl.query_credits();
        assert_eq!(fctl.cr_avail(), 27);
    }

    #[test]
    fn multi_receiver_bottleneck() {
        let fast_seq = Arc::new(AtomicU64::new(100));
        let slow_seq = Arc::new(AtomicU64::new(50));

        let fast_clone = fast_seq.clone();
        let slow_clone = slow_seq.clone();

        let config = make_config(128);
        let mut fctl = FlowControl::new(config);

        fctl.add_receiver(move || fast_clone.load(Ordering::Relaxed), 128);
        fctl.add_receiver(move || slow_clone.load(Ordering::Relaxed), 128);

        // tx_seq = 100.
        fctl.set_tx_seq(100);
        let slowest = fctl.query_credits();

        // Fast: 128 - (100-100) = 128
        // Slow: 128 - (100-50) = 78
        // min = 78 → receiver 1 is slowest.
        assert_eq!(fctl.cr_avail(), 78);
        assert_eq!(slowest, Some(1));
    }

    #[test]
    fn hysteresis_prevents_oscillation() {
        let rx_seq = Arc::new(AtomicU64::new(0));
        let rx_clone = rx_seq.clone();

        let config = FlowControlConfig {
            cr_burst: 4,
            cr_max: 100,
            cr_refill: 25, // re-query below 25
            cr_resume: 50, // resume above 50
        };
        let mut fctl = FlowControl::new(config);
        fctl.add_receiver(move || rx_clone.load(Ordering::Relaxed), 100);

        // Spend down to below cr_refill.
        // spend() both decrements cr_avail and advances tx_seq.
        fctl.spend(80);
        assert_eq!(fctl.cr_avail(), 20);

        // check_credits enters refill state.
        fctl.check_credits();
        assert!(fctl.in_refill);

        // Receiver at 0, so cr = 100 - 80 = 20.
        // Still below cr_resume (50) — not ready.
        assert!(!fctl.has_credits());

        // Receiver advances to 60 → cr = 100 - (80-60) = 80.
        rx_seq.store(60, Ordering::Relaxed);
        fctl.check_credits();
        assert_eq!(fctl.cr_avail(), 80);
        assert!(!fctl.in_refill);
        assert!(fctl.has_credits());
    }

    #[test]
    fn slow_receiver_counter() {
        let fast_seq = Arc::new(AtomicU64::new(100));
        let slow_seq = Arc::new(AtomicU64::new(50));

        let fast_clone = fast_seq.clone();
        let slow_clone = slow_seq.clone();

        let config = make_config(128);
        let mut fctl = FlowControl::new(config);
        fctl.add_receiver(move || fast_clone.load(Ordering::Relaxed), 128);
        fctl.add_receiver(move || slow_clone.load(Ordering::Relaxed), 128);

        fctl.set_tx_seq(100);

        // Query 5 times.
        for _ in 0..5 {
            fctl.query_credits();
        }

        // Receiver 1 (slow) should be the bottleneck every time.
        assert_eq!(fctl.slow_count(0), 0);
        assert_eq!(fctl.slow_count(1), 5);
    }

    #[test]
    fn config_from_depth() {
        let config = FlowControlConfig::from_depth(1024, 64);
        assert_eq!(config.cr_max, 1024);
        assert_eq!(config.cr_burst, 64);
        assert_eq!(config.cr_refill, 256); // 1024/4
        assert_eq!(config.cr_resume, 512); // 1024/2
    }

    #[test]
    fn spend_saturates_at_zero() {
        let config = make_config(10);
        let mut fctl = FlowControl::new(config);

        fctl.spend(100); // more than cr_avail
        assert_eq!(fctl.cr_avail(), 0);
        assert!(!fctl.has_credits());
    }
}
