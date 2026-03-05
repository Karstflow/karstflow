/// Commitment level tracking for finalization and confirmation.
///
/// Tracks both external-facing commitment levels (Processed/Confirmed/Finalized)
/// and internal confirmation thresholds (Propagated/DuplicateConfirmed/
/// OptimisticallyConfirmed/SuperConfirmed) based on stake-weighted voting.
///
/// Confirmation thresholds progress as stake accumulates:
/// - Propagated: 1/3+ stake voted for the slot
/// - Duplicate confirmed: 52%+ stake (safe against equivocation)
/// - Optimistically confirmed: 2/3+ stake (won't rollback)
/// - Super confirmed: 4/5+ stake (strongest pre-finalization guarantee)
use karstflow_constants::consensus::{
    DUPLICATE_CONFIRMATION_THRESHOLD, PROPAGATED_THRESHOLD, SUPERMAJORITY_THRESHOLD,
    SUPER_CONFIRMATION_THRESHOLD,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// External-facing commitment levels for slots.
///
/// These are the levels visible to RPC clients and downstream consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CommitmentLevel {
    /// Block has been processed by this validator.
    Processed,
    /// Block has been optimistically confirmed (2/3+ stake).
    Confirmed,
    /// Block has been finalized (rooted, irreversible).
    Finalized,
}

impl CommitmentLevel {
    /// Get all commitment levels in order.
    pub fn all() -> [CommitmentLevel; 3] {
        [
            CommitmentLevel::Processed,
            CommitmentLevel::Confirmed,
            CommitmentLevel::Finalized,
        ]
    }

    /// Check if this commitment level is at least as strong as another.
    pub fn is_at_least(&self, other: CommitmentLevel) -> bool {
        *self >= other
    }
}

/// Internal confirmation status based on stake thresholds.
///
/// Tracks finer-grained confirmation progress than the external CommitmentLevel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ConfirmationStatus {
    /// No threshold reached yet.
    Unconfirmed,
    /// 1/3+ stake has voted — slot is propagated (safe to vote on).
    Propagated,
    /// 52%+ stake has voted — duplicate confirmed (equivocation safe).
    DuplicateConfirmed,
    /// 2/3+ stake has voted — optimistically confirmed (won't rollback).
    OptimisticallyConfirmed,
    /// 4/5+ stake has voted — strongest pre-finalization guarantee.
    SuperConfirmed,
}

impl ConfirmationStatus {
    /// Compute confirmation status from a stake ratio (0.0 to 1.0).
    pub fn from_stake_ratio(ratio: f64) -> Self {
        if ratio >= SUPER_CONFIRMATION_THRESHOLD {
            ConfirmationStatus::SuperConfirmed
        } else if ratio >= SUPERMAJORITY_THRESHOLD {
            ConfirmationStatus::OptimisticallyConfirmed
        } else if ratio >= DUPLICATE_CONFIRMATION_THRESHOLD {
            ConfirmationStatus::DuplicateConfirmed
        } else if ratio >= PROPAGATED_THRESHOLD {
            ConfirmationStatus::Propagated
        } else {
            ConfirmationStatus::Unconfirmed
        }
    }

    /// Check if this status meets the optimistic confirmation threshold.
    pub fn is_optimistically_confirmed(&self) -> bool {
        *self >= ConfirmationStatus::OptimisticallyConfirmed
    }
}

/// Event emitted when a slot crosses a confirmation threshold.
#[derive(Debug, Clone, PartialEq)]
pub struct ConfirmationEvent {
    /// Slot that reached the threshold.
    pub slot: u64,
    /// The new confirmation status.
    pub status: ConfirmationStatus,
    /// Stake ratio at the time of crossing (0.0 to 1.0).
    pub stake_ratio: f64,
}

/// Configuration for commitment tracking.
#[derive(Debug, Clone)]
pub struct CommitmentConfig {
    /// Minimum depth for optimistic confirmation (typically 8).
    pub optimistic_confirmation_depth: usize,
    /// Minimum depth for finalization consideration (typically 32).
    pub finalization_depth: usize,
}

impl Default for CommitmentConfig {
    fn default() -> Self {
        Self {
            optimistic_confirmation_depth: 8,
            finalization_depth: 32,
        }
    }
}

/// Commitment information for a specific slot.
#[derive(Debug, Clone)]
pub struct SlotCommitment {
    /// Slot number.
    pub slot: u64,
    /// External-facing commitment level.
    pub level: CommitmentLevel,
    /// Internal confirmation status based on stake thresholds.
    pub confirmation_status: ConfirmationStatus,
    /// Stake that has voted for this slot.
    pub stake: u64,
    /// Total network stake at time of evaluation.
    pub total_stake: u64,
    /// Confirmation depth (number of descendants).
    pub confirmation_depth: usize,
    /// Whether propagation (1/3) notification has been sent.
    propagated_notified: bool,
    /// Whether duplicate confirmation (52%) notification has been sent.
    duplicate_confirmed_notified: bool,
    /// Whether optimistic confirmation (2/3) notification has been sent.
    optimistically_confirmed_notified: bool,
    /// Whether super confirmation (4/5) notification has been sent.
    super_confirmed_notified: bool,
}

impl SlotCommitment {
    pub fn new(slot: u64, stake: u64, total_stake: u64) -> Self {
        let ratio = if total_stake > 0 {
            stake as f64 / total_stake as f64
        } else {
            0.0
        };
        Self {
            slot,
            level: CommitmentLevel::Processed,
            confirmation_status: ConfirmationStatus::from_stake_ratio(ratio),
            stake,
            total_stake,
            confirmation_depth: 0,
            propagated_notified: false,
            duplicate_confirmed_notified: false,
            optimistically_confirmed_notified: false,
            super_confirmed_notified: false,
        }
    }

    /// Get the stake ratio (0.0 to 1.0).
    pub fn stake_ratio(&self) -> f64 {
        if self.total_stake == 0 {
            return 0.0;
        }
        self.stake as f64 / self.total_stake as f64
    }

    /// Check if this slot has supermajority stake (2/3+).
    pub fn has_supermajority(&self, threshold: f64) -> bool {
        self.stake_ratio() >= threshold
    }

    /// Update stake and recalculate confirmation status.
    ///
    /// Returns confirmation events for any newly crossed thresholds.
    fn update_stake(&mut self, stake: u64, total_stake: u64) -> Vec<ConfirmationEvent> {
        self.stake = stake;
        self.total_stake = total_stake;

        let ratio = self.stake_ratio();
        let new_status = ConfirmationStatus::from_stake_ratio(ratio);
        let mut events = Vec::new();

        // Emit events for each newly crossed threshold (in order).
        if new_status >= ConfirmationStatus::Propagated && !self.propagated_notified {
            self.propagated_notified = true;
            events.push(ConfirmationEvent {
                slot: self.slot,
                status: ConfirmationStatus::Propagated,
                stake_ratio: ratio,
            });
        }

        if new_status >= ConfirmationStatus::DuplicateConfirmed
            && !self.duplicate_confirmed_notified
        {
            self.duplicate_confirmed_notified = true;
            events.push(ConfirmationEvent {
                slot: self.slot,
                status: ConfirmationStatus::DuplicateConfirmed,
                stake_ratio: ratio,
            });
        }

        if new_status >= ConfirmationStatus::OptimisticallyConfirmed
            && !self.optimistically_confirmed_notified
        {
            self.optimistically_confirmed_notified = true;
            events.push(ConfirmationEvent {
                slot: self.slot,
                status: ConfirmationStatus::OptimisticallyConfirmed,
                stake_ratio: ratio,
            });
        }

        if new_status >= ConfirmationStatus::SuperConfirmed && !self.super_confirmed_notified {
            self.super_confirmed_notified = true;
            events.push(ConfirmationEvent {
                slot: self.slot,
                status: ConfirmationStatus::SuperConfirmed,
                stake_ratio: ratio,
            });
        }

        self.confirmation_status = new_status;
        events
    }
}

/// Tracks commitment levels for slots across the fork tree.
///
/// Manages progression from processed -> confirmed -> finalized
/// based on stake votes and confirmation depth. Emits confirmation
/// events when slots cross stake thresholds.
#[derive(Debug)]
pub struct CommitmentTracker {
    /// Configuration.
    config: CommitmentConfig,
    /// Commitment information by slot.
    commitments: HashMap<u64, SlotCommitment>,
    /// Processed slots (all slots we've seen).
    processed_slots: HashSet<u64>,
    /// Confirmed slots (optimistically confirmed).
    confirmed_slots: HashSet<u64>,
    /// Finalized slots (rooted).
    finalized_slots: HashSet<u64>,
    /// Current root slot.
    root_slot: Option<u64>,
    /// Highest processed slot.
    highest_processed: Option<u64>,
    /// Highest confirmed slot.
    highest_confirmed: Option<u64>,
}

impl CommitmentTracker {
    pub fn new(config: CommitmentConfig) -> Self {
        Self {
            config,
            commitments: HashMap::new(),
            processed_slots: HashSet::new(),
            confirmed_slots: HashSet::new(),
            finalized_slots: HashSet::new(),
            root_slot: None,
            highest_processed: None,
            highest_confirmed: None,
        }
    }

    /// Mark a slot as processed.
    pub fn mark_processed(&mut self, slot: u64, stake: u64, total_stake: u64) {
        self.processed_slots.insert(slot);

        let commitment = self
            .commitments
            .entry(slot)
            .or_insert_with(|| SlotCommitment::new(slot, stake, total_stake));

        commitment.stake = stake;
        commitment.total_stake = total_stake;

        // Update highest processed
        self.highest_processed = Some(self.highest_processed.map(|h| h.max(slot)).unwrap_or(slot));
    }

    /// Update stake for a slot and check for confirmation threshold crossings.
    ///
    /// Returns events for any newly crossed thresholds. Automatically promotes
    /// to Confirmed commitment level when optimistic confirmation is reached.
    pub fn update_stake(
        &mut self,
        slot: u64,
        stake: u64,
        total_stake: u64,
    ) -> Vec<ConfirmationEvent> {
        if let Some(commitment) = self.commitments.get_mut(&slot) {
            let events = commitment.update_stake(stake, total_stake);

            // Auto-promote to Confirmed when optimistically confirmed
            if commitment.confirmation_status >= ConfirmationStatus::OptimisticallyConfirmed
                && commitment.level < CommitmentLevel::Confirmed
            {
                commitment.level = CommitmentLevel::Confirmed;
                self.confirmed_slots.insert(slot);
                self.highest_confirmed =
                    Some(self.highest_confirmed.map(|h| h.max(slot)).unwrap_or(slot));
            }

            events
        } else {
            // Create new commitment if slot wasn't tracked yet
            self.mark_processed(slot, stake, total_stake);
            // Recompute events for the newly created commitment
            if let Some(commitment) = self.commitments.get_mut(&slot) {
                let events = commitment.update_stake(stake, total_stake);
                if commitment.confirmation_status >= ConfirmationStatus::OptimisticallyConfirmed
                    && commitment.level < CommitmentLevel::Confirmed
                {
                    commitment.level = CommitmentLevel::Confirmed;
                    self.confirmed_slots.insert(slot);
                    self.highest_confirmed =
                        Some(self.highest_confirmed.map(|h| h.max(slot)).unwrap_or(slot));
                }
                events
            } else {
                Vec::new()
            }
        }
    }

    /// Update confirmation depth for a slot.
    pub fn update_confirmation_depth(&mut self, slot: u64, depth: usize) {
        if let Some(commitment) = self.commitments.get_mut(&slot) {
            commitment.confirmation_depth = depth;
        }
    }

    /// Check if a slot meets optimistic confirmation criteria.
    ///
    /// Requires both supermajority stake (2/3+) and minimum confirmation depth.
    pub fn check_optimistic_confirmation(
        &self,
        slot: u64,
        descendants_with_supermajority: usize,
    ) -> bool {
        let commitment = match self.commitments.get(&slot) {
            Some(c) => c,
            None => return false,
        };

        // Must be at least optimistically confirmed by stake
        if commitment.confirmation_status < ConfirmationStatus::OptimisticallyConfirmed {
            return false;
        }

        // Must have required depth of supermajority descendants
        descendants_with_supermajority >= self.config.optimistic_confirmation_depth
    }

    /// Get the confirmation status for a slot.
    pub fn get_confirmation_status(&self, slot: u64) -> Option<ConfirmationStatus> {
        self.commitments.get(&slot).map(|c| c.confirmation_status)
    }

    /// Check if a slot is propagated (1/3+ stake has voted).
    pub fn is_propagated(&self, slot: u64) -> bool {
        self.commitments
            .get(&slot)
            .map(|c| c.confirmation_status >= ConfirmationStatus::Propagated)
            .unwrap_or(false)
    }

    /// Check if a slot is duplicate confirmed (52%+ stake).
    pub fn is_duplicate_confirmed(&self, slot: u64) -> bool {
        self.commitments
            .get(&slot)
            .map(|c| c.confirmation_status >= ConfirmationStatus::DuplicateConfirmed)
            .unwrap_or(false)
    }

    /// Check if a slot is optimistically confirmed (2/3+ stake).
    pub fn is_optimistically_confirmed(&self, slot: u64) -> bool {
        self.commitments
            .get(&slot)
            .map(|c| c.confirmation_status >= ConfirmationStatus::OptimisticallyConfirmed)
            .unwrap_or(false)
    }

    /// Check if a slot is super confirmed (4/5+ stake).
    pub fn is_super_confirmed(&self, slot: u64) -> bool {
        self.commitments
            .get(&slot)
            .map(|c| c.confirmation_status >= ConfirmationStatus::SuperConfirmed)
            .unwrap_or(false)
    }

    /// Mark a slot as optimistically confirmed.
    pub fn mark_confirmed(&mut self, slot: u64) {
        if !self.processed_slots.contains(&slot) {
            return;
        }

        self.confirmed_slots.insert(slot);

        if let Some(commitment) = self.commitments.get_mut(&slot) {
            if commitment.level < CommitmentLevel::Confirmed {
                commitment.level = CommitmentLevel::Confirmed;
            }
            if commitment.confirmation_status < ConfirmationStatus::OptimisticallyConfirmed {
                commitment.confirmation_status = ConfirmationStatus::OptimisticallyConfirmed;
            }
        }

        // Update highest confirmed
        self.highest_confirmed = Some(self.highest_confirmed.map(|h| h.max(slot)).unwrap_or(slot));
    }

    /// Mark a slot as finalized (rooted).
    pub fn mark_finalized(&mut self, slot: u64) {
        if !self.processed_slots.contains(&slot) {
            return;
        }

        self.finalized_slots.insert(slot);
        self.confirmed_slots.insert(slot); // Finalized implies confirmed

        if let Some(commitment) = self.commitments.get_mut(&slot) {
            commitment.level = CommitmentLevel::Finalized;
        }

        // Update root
        self.root_slot = Some(self.root_slot.map(|r| r.max(slot)).unwrap_or(slot));
    }

    /// Get commitment level for a slot.
    pub fn get_commitment_level(&self, slot: u64) -> Option<CommitmentLevel> {
        if self.finalized_slots.contains(&slot) {
            return Some(CommitmentLevel::Finalized);
        }
        if self.confirmed_slots.contains(&slot) {
            return Some(CommitmentLevel::Confirmed);
        }
        if self.processed_slots.contains(&slot) {
            return Some(CommitmentLevel::Processed);
        }
        None
    }

    /// Get commitment information for a slot.
    pub fn get_commitment(&self, slot: u64) -> Option<&SlotCommitment> {
        self.commitments.get(&slot)
    }

    /// Check if a slot has at least a given commitment level.
    pub fn has_commitment(&self, slot: u64, level: CommitmentLevel) -> bool {
        match self.get_commitment_level(slot) {
            Some(slot_level) => slot_level.is_at_least(level),
            None => false,
        }
    }

    /// Get the current root slot.
    pub fn root_slot(&self) -> Option<u64> {
        self.root_slot
    }

    /// Get the highest slot at a given commitment level.
    pub fn highest_slot_with_commitment(&self, level: CommitmentLevel) -> Option<u64> {
        match level {
            CommitmentLevel::Processed => self.highest_processed,
            CommitmentLevel::Confirmed => self.highest_confirmed,
            CommitmentLevel::Finalized => self.root_slot,
        }
    }

    /// Get all slots at a specific commitment level.
    pub fn slots_at_level(&self, level: CommitmentLevel) -> Vec<u64> {
        match level {
            CommitmentLevel::Processed => self.processed_slots.iter().copied().collect(),
            CommitmentLevel::Confirmed => self.confirmed_slots.iter().copied().collect(),
            CommitmentLevel::Finalized => self.finalized_slots.iter().copied().collect(),
        }
    }

    /// Get count of slots at each commitment level.
    pub fn commitment_counts(&self) -> CommitmentCounts {
        CommitmentCounts {
            processed: self.processed_slots.len(),
            confirmed: self.confirmed_slots.len(),
            finalized: self.finalized_slots.len(),
        }
    }

    /// Get count of slots at each confirmation status.
    pub fn confirmation_counts(&self) -> ConfirmationCounts {
        let mut propagated = 0;
        let mut duplicate_confirmed = 0;
        let mut optimistically_confirmed = 0;
        let mut super_confirmed = 0;

        for commitment in self.commitments.values() {
            match commitment.confirmation_status {
                ConfirmationStatus::Unconfirmed => {}
                ConfirmationStatus::Propagated => propagated += 1,
                ConfirmationStatus::DuplicateConfirmed => duplicate_confirmed += 1,
                ConfirmationStatus::OptimisticallyConfirmed => optimistically_confirmed += 1,
                ConfirmationStatus::SuperConfirmed => super_confirmed += 1,
            }
        }

        ConfirmationCounts {
            propagated,
            duplicate_confirmed,
            optimistically_confirmed,
            super_confirmed,
        }
    }

    /// Prune commitments below a root slot.
    pub fn prune_below_root(&mut self, root_slot: u64) {
        self.processed_slots.retain(|&s| s >= root_slot);
        self.confirmed_slots.retain(|&s| s >= root_slot);
        self.finalized_slots.retain(|&s| s >= root_slot);
        self.commitments.retain(|&s, _| s >= root_slot);

        // Update root
        if let Some(current_root) = self.root_slot {
            self.root_slot = Some(current_root.max(root_slot));
        } else {
            self.root_slot = Some(root_slot);
        }
    }

    /// Update root from finalization detection.
    ///
    /// Returns the new root slot if it changed.
    pub fn update_root(&mut self, new_root: u64) -> Option<u64> {
        let old_root = self.root_slot;

        // Only update if new root is higher
        let should_update = match old_root {
            Some(old) => new_root > old,
            None => true,
        };

        if should_update {
            self.mark_finalized(new_root);
            self.prune_below_root(new_root);
            Some(new_root)
        } else {
            None
        }
    }

    /// Get slots ready for root promotion.
    ///
    /// Returns slots that have been confirmed for long enough to be finalized.
    pub fn slots_ready_for_finalization(&self) -> Vec<u64> {
        self.confirmed_slots
            .iter()
            .filter(|&&slot| {
                if let Some(commitment) = self.commitments.get(&slot) {
                    commitment.confirmation_depth >= self.config.finalization_depth
                } else {
                    false
                }
            })
            .copied()
            .collect()
    }

    /// Check if we can finalize up to a given slot based on votes.
    ///
    /// Returns the highest slot that can be finalized, if any.
    pub fn find_finalization_candidate(
        &self,
        slot_stakes: &HashMap<u64, u64>,
        total_stake: u64,
    ) -> Option<u64> {
        let mut candidate = self.root_slot;

        for (&slot, &stake) in slot_stakes {
            // Must be above current root
            if let Some(root) = self.root_slot {
                if slot <= root {
                    continue;
                }
            }

            // Must have supermajority
            let ratio = stake as f64 / total_stake as f64;
            if ratio < SUPERMAJORITY_THRESHOLD {
                continue;
            }

            // Must be confirmed
            if !self.confirmed_slots.contains(&slot) {
                continue;
            }

            // Check if sufficient depth
            if let Some(commitment) = self.commitments.get(&slot) {
                if commitment.confirmation_depth >= self.config.finalization_depth {
                    candidate = Some(candidate.map(|c| c.max(slot)).unwrap_or(slot));
                }
            }
        }

        candidate
    }

    /// Get statistics about commitment tracking.
    pub fn stats(&self) -> CommitmentStats {
        let avg_confirmation_depth = if !self.commitments.is_empty() {
            let total: usize = self
                .commitments
                .values()
                .map(|c| c.confirmation_depth)
                .sum();
            total as f64 / self.commitments.len() as f64
        } else {
            0.0
        };

        CommitmentStats {
            counts: self.commitment_counts(),
            confirmation_counts: self.confirmation_counts(),
            root_slot: self.root_slot,
            highest_processed: self.highest_processed,
            highest_confirmed: self.highest_confirmed,
            avg_confirmation_depth,
        }
    }
}

/// Counts of slots at each external commitment level.
#[derive(Debug, Clone, Copy)]
pub struct CommitmentCounts {
    pub processed: usize,
    pub confirmed: usize,
    pub finalized: usize,
}

/// Counts of slots at each internal confirmation status.
#[derive(Debug, Clone, Copy)]
pub struct ConfirmationCounts {
    pub propagated: usize,
    pub duplicate_confirmed: usize,
    pub optimistically_confirmed: usize,
    pub super_confirmed: usize,
}

/// Statistics about commitment tracking.
#[derive(Debug, Clone)]
pub struct CommitmentStats {
    pub counts: CommitmentCounts,
    pub confirmation_counts: ConfirmationCounts,
    pub root_slot: Option<u64>,
    pub highest_processed: Option<u64>,
    pub highest_confirmed: Option<u64>,
    pub avg_confirmation_depth: f64,
}

impl Default for CommitmentTracker {
    fn default() -> Self {
        Self::new(CommitmentConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_level_ordering() {
        assert!(CommitmentLevel::Finalized > CommitmentLevel::Confirmed);
        assert!(CommitmentLevel::Confirmed > CommitmentLevel::Processed);

        assert!(CommitmentLevel::Finalized.is_at_least(CommitmentLevel::Processed));
        assert!(CommitmentLevel::Confirmed.is_at_least(CommitmentLevel::Processed));
        assert!(!CommitmentLevel::Processed.is_at_least(CommitmentLevel::Confirmed));
    }

    #[test]
    fn confirmation_status_ordering() {
        assert!(ConfirmationStatus::SuperConfirmed > ConfirmationStatus::OptimisticallyConfirmed);
        assert!(
            ConfirmationStatus::OptimisticallyConfirmed > ConfirmationStatus::DuplicateConfirmed
        );
        assert!(ConfirmationStatus::DuplicateConfirmed > ConfirmationStatus::Propagated);
        assert!(ConfirmationStatus::Propagated > ConfirmationStatus::Unconfirmed);
    }

    #[test]
    fn confirmation_status_from_stake_ratio() {
        assert_eq!(
            ConfirmationStatus::from_stake_ratio(0.0),
            ConfirmationStatus::Unconfirmed
        );
        assert_eq!(
            ConfirmationStatus::from_stake_ratio(0.2),
            ConfirmationStatus::Unconfirmed
        );
        assert_eq!(
            ConfirmationStatus::from_stake_ratio(0.34),
            ConfirmationStatus::Propagated
        );
        assert_eq!(
            ConfirmationStatus::from_stake_ratio(0.53),
            ConfirmationStatus::DuplicateConfirmed
        );
        assert_eq!(
            ConfirmationStatus::from_stake_ratio(0.67),
            ConfirmationStatus::OptimisticallyConfirmed
        );
        assert_eq!(
            ConfirmationStatus::from_stake_ratio(0.81),
            ConfirmationStatus::SuperConfirmed
        );
        assert_eq!(
            ConfirmationStatus::from_stake_ratio(1.0),
            ConfirmationStatus::SuperConfirmed
        );
    }

    #[test]
    fn commitment_tracker_marks_processed() {
        let mut tracker = CommitmentTracker::default();

        tracker.mark_processed(100, 500, 1000);

        assert_eq!(
            tracker.get_commitment_level(100),
            Some(CommitmentLevel::Processed)
        );
        assert_eq!(tracker.highest_processed, Some(100));
    }

    #[test]
    fn commitment_tracker_marks_confirmed() {
        let mut tracker = CommitmentTracker::default();

        tracker.mark_processed(100, 700, 1000);
        tracker.mark_confirmed(100);

        assert_eq!(
            tracker.get_commitment_level(100),
            Some(CommitmentLevel::Confirmed)
        );
        assert_eq!(tracker.highest_confirmed, Some(100));
    }

    #[test]
    fn commitment_tracker_marks_finalized() {
        let mut tracker = CommitmentTracker::default();

        tracker.mark_processed(100, 700, 1000);
        tracker.mark_confirmed(100);
        tracker.mark_finalized(100);

        assert_eq!(
            tracker.get_commitment_level(100),
            Some(CommitmentLevel::Finalized)
        );
        assert_eq!(tracker.root_slot(), Some(100));
    }

    #[test]
    fn commitment_tracker_updates_stake_emits_events() {
        let mut tracker = CommitmentTracker::default();
        tracker.mark_processed(100, 0, 1000);

        // Update to 40% — crosses propagated (1/3)
        let events = tracker.update_stake(100, 400, 1000);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].status, ConfirmationStatus::Propagated);
        assert!(tracker.is_propagated(100));

        // Update to 55% — crosses duplicate confirmed (52%)
        let events = tracker.update_stake(100, 550, 1000);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].status, ConfirmationStatus::DuplicateConfirmed);
        assert!(tracker.is_duplicate_confirmed(100));

        // Update to 70% — crosses optimistic confirmed (2/3)
        let events = tracker.update_stake(100, 700, 1000);
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].status,
            ConfirmationStatus::OptimisticallyConfirmed
        );
        assert!(tracker.is_optimistically_confirmed(100));
        // Should also auto-promote to Confirmed commitment level
        assert_eq!(
            tracker.get_commitment_level(100),
            Some(CommitmentLevel::Confirmed)
        );

        // Update to 85% — crosses super confirmed (4/5)
        let events = tracker.update_stake(100, 850, 1000);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].status, ConfirmationStatus::SuperConfirmed);
        assert!(tracker.is_super_confirmed(100));
    }

    #[test]
    fn commitment_tracker_no_duplicate_events() {
        let mut tracker = CommitmentTracker::default();
        tracker.mark_processed(100, 0, 1000);

        // Cross all thresholds at once
        let events = tracker.update_stake(100, 900, 1000);
        assert_eq!(events.len(), 4); // All four thresholds crossed

        // Updating with same stake should produce no new events
        let events = tracker.update_stake(100, 950, 1000);
        assert_eq!(events.len(), 0);
    }

    #[test]
    fn commitment_tracker_bulk_threshold_crossing() {
        let mut tracker = CommitmentTracker::default();
        tracker.mark_processed(100, 0, 1000);

        // Jump straight to 90% — all thresholds at once
        let events = tracker.update_stake(100, 900, 1000);
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].status, ConfirmationStatus::Propagated);
        assert_eq!(events[1].status, ConfirmationStatus::DuplicateConfirmed);
        assert_eq!(
            events[2].status,
            ConfirmationStatus::OptimisticallyConfirmed
        );
        assert_eq!(events[3].status, ConfirmationStatus::SuperConfirmed);
    }

    #[test]
    fn commitment_tracker_checks_optimistic_confirmation() {
        let config = CommitmentConfig {
            optimistic_confirmation_depth: 8,
            finalization_depth: 32,
        };
        let mut tracker = CommitmentTracker::new(config);

        tracker.mark_processed(100, 700, 1000);
        tracker.update_stake(100, 700, 1000);

        // Insufficient depth
        assert!(!tracker.check_optimistic_confirmation(100, 5));

        // Sufficient depth
        assert!(tracker.check_optimistic_confirmation(100, 8));

        // Insufficient stake — update to below 2/3
        tracker.mark_processed(101, 600, 1000);
        tracker.update_stake(101, 600, 1000);
        assert!(!tracker.check_optimistic_confirmation(101, 8));
    }

    #[test]
    fn commitment_tracker_has_commitment() {
        let mut tracker = CommitmentTracker::default();

        tracker.mark_processed(100, 700, 1000);
        tracker.mark_confirmed(100);

        assert!(tracker.has_commitment(100, CommitmentLevel::Processed));
        assert!(tracker.has_commitment(100, CommitmentLevel::Confirmed));
        assert!(!tracker.has_commitment(100, CommitmentLevel::Finalized));
    }

    #[test]
    fn commitment_tracker_lists_slots_at_level() {
        let mut tracker = CommitmentTracker::default();

        tracker.mark_processed(100, 500, 1000);
        tracker.mark_processed(101, 600, 1000);
        tracker.mark_processed(102, 700, 1000);

        tracker.mark_confirmed(101);
        tracker.mark_confirmed(102);

        tracker.mark_finalized(101);

        assert_eq!(tracker.slots_at_level(CommitmentLevel::Processed).len(), 3);
        assert_eq!(tracker.slots_at_level(CommitmentLevel::Confirmed).len(), 2);
        assert_eq!(tracker.slots_at_level(CommitmentLevel::Finalized).len(), 1);
    }

    #[test]
    fn commitment_tracker_prunes_below_root() {
        let mut tracker = CommitmentTracker::default();

        tracker.mark_processed(100, 500, 1000);
        tracker.mark_processed(101, 600, 1000);
        tracker.mark_processed(102, 700, 1000);
        tracker.mark_finalized(101);

        tracker.prune_below_root(101);

        assert_eq!(tracker.get_commitment_level(100), None);
        assert_eq!(
            tracker.get_commitment_level(101),
            Some(CommitmentLevel::Finalized)
        );
        assert_eq!(
            tracker.get_commitment_level(102),
            Some(CommitmentLevel::Processed)
        );
    }

    #[test]
    fn commitment_tracker_updates_root() {
        let mut tracker = CommitmentTracker::default();

        tracker.mark_processed(100, 700, 1000);
        tracker.mark_processed(101, 700, 1000);

        let result = tracker.update_root(100);
        assert_eq!(result, Some(100));
        assert_eq!(tracker.root_slot(), Some(100));

        // Can't go backwards
        let result = tracker.update_root(99);
        assert_eq!(result, None);

        // Can go forward
        let result = tracker.update_root(101);
        assert_eq!(result, Some(101));
    }

    #[test]
    fn commitment_tracker_finds_slots_ready_for_finalization() {
        let config = CommitmentConfig {
            optimistic_confirmation_depth: 8,
            finalization_depth: 32,
        };
        let mut tracker = CommitmentTracker::new(config);

        tracker.mark_processed(100, 700, 1000);
        tracker.mark_confirmed(100);
        tracker.update_confirmation_depth(100, 40); // Above threshold

        tracker.mark_processed(101, 700, 1000);
        tracker.mark_confirmed(101);
        tracker.update_confirmation_depth(101, 20); // Below threshold

        let ready = tracker.slots_ready_for_finalization();
        assert_eq!(ready.len(), 1);
        assert!(ready.contains(&100));
        assert!(!ready.contains(&101));
    }

    #[test]
    fn commitment_tracker_finds_finalization_candidate() {
        let config = CommitmentConfig {
            optimistic_confirmation_depth: 8,
            finalization_depth: 32,
        };
        let mut tracker = CommitmentTracker::new(config);

        tracker.mark_processed(100, 700, 1000);
        tracker.mark_confirmed(100);
        tracker.update_confirmation_depth(100, 40);

        tracker.mark_processed(101, 700, 1000);
        tracker.mark_confirmed(101);
        tracker.update_confirmation_depth(101, 35);

        let mut slot_stakes = HashMap::new();
        slot_stakes.insert(100, 700);
        slot_stakes.insert(101, 700);

        let candidate = tracker.find_finalization_candidate(&slot_stakes, 1000);
        assert_eq!(candidate, Some(101)); // Highest valid slot
    }

    #[test]
    fn commitment_tracker_calculates_stake_ratio() {
        let commitment = SlotCommitment::new(100, 700, 1000);
        assert!((commitment.stake_ratio() - 0.7).abs() < 0.01);

        assert!(commitment.has_supermajority(2.0 / 3.0));
        assert!(!commitment.has_supermajority(0.75));
    }

    #[test]
    fn commitment_tracker_provides_stats() {
        let mut tracker = CommitmentTracker::default();

        tracker.mark_processed(100, 500, 1000);
        tracker.update_confirmation_depth(100, 10);

        tracker.mark_processed(101, 600, 1000);
        tracker.mark_confirmed(101);
        tracker.update_confirmation_depth(101, 20);

        tracker.mark_processed(102, 700, 1000);
        tracker.mark_confirmed(102);
        tracker.mark_finalized(102);
        tracker.update_confirmation_depth(102, 30);

        let stats = tracker.stats();
        assert_eq!(stats.counts.processed, 3);
        assert_eq!(stats.counts.confirmed, 2);
        assert_eq!(stats.counts.finalized, 1);
        assert_eq!(stats.root_slot, Some(102));
        assert_eq!(stats.highest_processed, Some(102));
        assert_eq!(stats.highest_confirmed, Some(102));
        assert!((stats.avg_confirmation_depth - 20.0).abs() < 0.1);
    }

    #[test]
    fn commitment_tracker_handles_highest_slots() {
        let mut tracker = CommitmentTracker::default();

        tracker.mark_processed(100, 500, 1000);
        tracker.mark_processed(105, 600, 1000);
        tracker.mark_processed(102, 700, 1000);

        assert_eq!(
            tracker.highest_slot_with_commitment(CommitmentLevel::Processed),
            Some(105)
        );

        tracker.mark_confirmed(102);
        tracker.mark_confirmed(100);

        assert_eq!(
            tracker.highest_slot_with_commitment(CommitmentLevel::Confirmed),
            Some(102)
        );
    }

    #[test]
    fn confirmation_counts_tracks_status_distribution() {
        let mut tracker = CommitmentTracker::default();

        // 35% — propagated
        tracker.mark_processed(100, 350, 1000);
        tracker.update_stake(100, 350, 1000);

        // 55% — duplicate confirmed
        tracker.mark_processed(101, 550, 1000);
        tracker.update_stake(101, 550, 1000);

        // 70% — optimistically confirmed
        tracker.mark_processed(102, 700, 1000);
        tracker.update_stake(102, 700, 1000);

        // 85% — super confirmed
        tracker.mark_processed(103, 850, 1000);
        tracker.update_stake(103, 850, 1000);

        let counts = tracker.confirmation_counts();
        assert_eq!(counts.propagated, 1);
        assert_eq!(counts.duplicate_confirmed, 1);
        assert_eq!(counts.optimistically_confirmed, 1);
        assert_eq!(counts.super_confirmed, 1);
    }

    #[test]
    fn update_stake_auto_promotes_to_confirmed() {
        let mut tracker = CommitmentTracker::default();
        tracker.mark_processed(100, 0, 1000);

        // Below 2/3 — should stay Processed
        tracker.update_stake(100, 600, 1000);
        assert_eq!(
            tracker.get_commitment_level(100),
            Some(CommitmentLevel::Processed)
        );

        // Above 2/3 — should auto-promote to Confirmed
        tracker.update_stake(100, 700, 1000);
        assert_eq!(
            tracker.get_commitment_level(100),
            Some(CommitmentLevel::Confirmed)
        );
    }

    #[test]
    fn update_stake_for_untracked_slot_creates_and_tracks() {
        let mut tracker = CommitmentTracker::default();

        // Update stake for a slot that was never mark_processed'd
        let events = tracker.update_stake(200, 850, 1000);

        // Should have created the commitment and emitted events
        assert!(!events.is_empty());
        assert!(tracker.is_super_confirmed(200));
        assert_eq!(
            tracker.get_commitment_level(200),
            Some(CommitmentLevel::Confirmed)
        );
    }
}
