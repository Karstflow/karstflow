//! Clock sysvar for network time tracking.
//!
//! The Clock sysvar provides an approximate measure of network time based on:
//! - Current slot number
//! - Current epoch and epoch boundaries
//! - Stake-weighted timestamp estimates from validators
//!
//! This is a critical sysvar accessed by many programs to determine time-based logic.

/// Default ticks per second (Solana mainnet setting).
pub const DEFAULT_TICKS_PER_SECOND: u64 = 160;

/// Default hashes per tick (PoH rate).
pub const DEFAULT_HASHES_PER_TICK: u64 = 12500;

/// Maximum number of stake weights to process in clock timestamp calculation.
pub const STAKE_WEIGHTS_MAX: usize = 10240;

/// Clock sysvar state.
///
/// Provides network time information to programs running on-chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Clock {
    /// Current slot number
    pub slot: u64,
    /// Unix timestamp when current epoch started
    pub epoch_start_timestamp: i64,
    /// Current epoch number
    pub epoch: u64,
    /// Epoch for which the current leader schedule is valid
    pub leader_schedule_epoch: u64,
    /// Estimated current network time (stake-weighted from validators)
    pub unix_timestamp: i64,
}

impl Clock {
    /// Create a new clock at genesis.
    pub fn new(genesis_timestamp: i64) -> Self {
        Self {
            slot: 0,
            epoch_start_timestamp: genesis_timestamp,
            epoch: 0,
            leader_schedule_epoch: 0,
            unix_timestamp: genesis_timestamp,
        }
    }

    /// Update clock for a new slot.
    ///
    /// Updates slot, epoch (if crossed boundary), and timestamp estimate.
    pub fn advance_slot(&mut self, new_slot: u64, slots_per_epoch: u64, estimated_timestamp: i64) {
        self.slot = new_slot;

        // Calculate new epoch
        let new_epoch = new_slot / slots_per_epoch;

        // Check if we crossed an epoch boundary
        if new_epoch > self.epoch {
            self.epoch = new_epoch;
            self.epoch_start_timestamp = estimated_timestamp;
            // Leader schedule advances one epoch ahead
            self.leader_schedule_epoch = new_epoch.saturating_add(1);
        }

        self.unix_timestamp = estimated_timestamp;
    }

    /// Set a new estimated timestamp (stake-weighted from validators).
    pub fn set_timestamp(&mut self, timestamp: i64) {
        self.unix_timestamp = timestamp;
    }

    /// Get elapsed time in current epoch (seconds).
    pub fn epoch_elapsed_seconds(&self) -> i64 {
        self.unix_timestamp
            .saturating_sub(self.epoch_start_timestamp)
    }

    /// Calculate estimated slot time in seconds (approximate).
    pub fn slot_duration_secs(&self, slots_per_epoch: u64) -> f64 {
        if self.slot == 0 || slots_per_epoch == 0 {
            return 0.4; // Default ~400ms slot time
        }

        // Estimate based on epoch elapsed time and slot progress
        let slots_in_epoch = self.slot % slots_per_epoch;
        if slots_in_epoch == 0 {
            return 0.4;
        }

        let elapsed = self.epoch_elapsed_seconds();
        if elapsed <= 0 {
            return 0.4;
        }

        (elapsed as f64) / (slots_in_epoch as f64)
    }
}

impl Default for Clock {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Calculate stake-weighted timestamp estimate.
///
/// Takes validator vote timestamps weighted by their stake to compute
/// a network-wide time estimate. This prevents any single validator from
/// manipulating the on-chain clock.
pub fn calculate_stake_weighted_timestamp(
    mut vote_timestamps: Vec<(i64, u64)>, // (timestamp, stake)
    total_stake: u64,
) -> i64 {
    if vote_timestamps.is_empty() || total_stake == 0 {
        // No estimate available. Return a deterministic 0 rather than
        // wall-clock time; callers treat "no estimate" by keeping the
        // previous clock value (wall-clock here would be non-deterministic
        // across nodes and diverge consensus).
        return 0;
    }

    // Limit to max stake weights
    if vote_timestamps.len() > STAKE_WEIGHTS_MAX {
        vote_timestamps.truncate(STAKE_WEIGHTS_MAX);
    }

    // Sort by timestamp
    vote_timestamps.sort_by_key(|(ts, _)| *ts);

    // Find median weighted by stake
    let mut cumulative_stake = 0u64;
    let half_stake = total_stake / 2;

    for &(timestamp, stake) in &vote_timestamps {
        cumulative_stake = cumulative_stake.saturating_add(stake);
        if cumulative_stake >= half_stake {
            return timestamp;
        }
    }

    // Fallback to last timestamp
    vote_timestamps.last().map(|(ts, _)| *ts).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_creates_at_genesis() {
        let clock = Clock::new(1000000);

        assert_eq!(clock.slot, 0);
        assert_eq!(clock.epoch, 0);
        assert_eq!(clock.epoch_start_timestamp, 1000000);
        assert_eq!(clock.unix_timestamp, 1000000);
        assert_eq!(clock.leader_schedule_epoch, 0);
    }

    #[test]
    fn clock_advances_slot() {
        let mut clock = Clock::new(1000000);

        clock.advance_slot(10, 100, 1000010);

        assert_eq!(clock.slot, 10);
        assert_eq!(clock.epoch, 0); // Still in epoch 0
        assert_eq!(clock.unix_timestamp, 1000010);
    }

    #[test]
    fn clock_advances_epoch() {
        let mut clock = Clock::new(1000000);

        // Advance to slot 100 (start of epoch 1)
        clock.advance_slot(100, 100, 1000100);

        assert_eq!(clock.slot, 100);
        assert_eq!(clock.epoch, 1);
        assert_eq!(clock.epoch_start_timestamp, 1000100);
        assert_eq!(clock.leader_schedule_epoch, 2); // One ahead
    }

    #[test]
    fn clock_updates_timestamp() {
        let mut clock = Clock::new(1000000);

        clock.set_timestamp(1000050);

        assert_eq!(clock.unix_timestamp, 1000050);
    }

    #[test]
    fn clock_calculates_epoch_elapsed() {
        let mut clock = Clock::new(1000000);

        clock.advance_slot(50, 100, 1000025);

        let elapsed = clock.epoch_elapsed_seconds();
        assert_eq!(elapsed, 25); // 25 seconds elapsed
    }

    #[test]
    fn clock_estimates_slot_duration() {
        let mut clock = Clock::new(1000000);

        // Advance 50 slots in 20 seconds
        clock.advance_slot(50, 100, 1000020);

        let duration = clock.slot_duration_secs(100);
        // Should be ~0.4 seconds per slot (20s / 50 slots)
        assert!((duration - 0.4).abs() < 0.01);
    }

    #[test]
    fn stake_weighted_timestamp_finds_median() {
        let votes = vec![
            (1000, 300), // 30% stake votes 1000
            (1005, 400), // 40% stake votes 1005
            (1010, 300), // 30% stake votes 1010
        ];

        let timestamp = calculate_stake_weighted_timestamp(votes, 1000);

        // Median with 50% stake threshold is 1005
        assert_eq!(timestamp, 1005);
    }

    #[test]
    fn stake_weighted_timestamp_handles_single_vote() {
        let votes = vec![(1000, 100)];

        let timestamp = calculate_stake_weighted_timestamp(votes, 100);

        assert_eq!(timestamp, 1000);
    }

    #[test]
    fn stake_weighted_timestamp_handles_empty_votes() {
        let votes = vec![];

        let timestamp = calculate_stake_weighted_timestamp(votes, 0);

        // No estimate available → deterministic 0 (never wall-clock).
        assert_eq!(timestamp, 0);
    }

    #[test]
    fn stake_weighted_timestamp_weighted_by_stake() {
        let votes = vec![
            (1000, 100), // 10% stake
            (1005, 800), // 80% stake
            (1010, 100), // 10% stake
        ];

        let timestamp = calculate_stake_weighted_timestamp(votes, 1000);

        // Should pick 1005 (80% stake pushes past 50% threshold)
        assert_eq!(timestamp, 1005);
    }

    #[test]
    fn stake_weighted_timestamp_sorts_votes() {
        let votes = vec![
            (1010, 300), // Latest
            (1000, 300), // Earliest
            (1005, 400), // Middle
        ];

        let timestamp = calculate_stake_weighted_timestamp(votes, 1000);

        // Should still find correct median after sorting
        assert_eq!(timestamp, 1005);
    }

    #[test]
    fn stake_weighted_timestamp_truncates_excess_votes() {
        let mut votes = Vec::new();

        // Create more than STAKE_WEIGHTS_MAX votes
        for i in 0..STAKE_WEIGHTS_MAX + 100 {
            votes.push((1000 + i as i64, 1));
        }

        let total_stake = votes.iter().map(|(_, s)| s).sum();
        let timestamp = calculate_stake_weighted_timestamp(votes, total_stake);

        // Should still return a valid timestamp
        assert!(timestamp >= 1000);
    }
}
