/// Structured inter-stage signals emitted by the replay pipeline.
///
/// Each signal carries the minimum data needed for consumers to act
/// without re-reading shared state. Signals are emitted after the
/// corresponding event completes (not before).
///
/// Consumers subscribe via `SignalBus::subscribe()` and receive signals
/// through a bounded crossbeam channel. If a subscriber falls behind,
/// new signals are dropped for that subscriber (non-blocking send).
use crossbeam_channel::{Receiver, Sender, TrySendError};
use paradencer_constants::replay::{MAX_SIGNAL_SUBSCRIBERS, SIGNAL_CHANNEL_CAPACITY};

// ---------------------------------------------------------------------------
// Signal types
// ---------------------------------------------------------------------------

/// A replay pipeline signal.
#[derive(Debug, Clone)]
pub enum ReplaySignal {
    /// A slot completed replay successfully and the bank is frozen.
    SlotCompleted(SlotCompletedInfo),
    /// A slot was marked dead (invalid block, ancestry failure, etc.).
    SlotDead(SlotDeadInfo),
    /// The root slot advanced. Banks below the old root can be pruned.
    RootAdvanced(RootAdvancedInfo),
    /// PoH/leader schedule reset triggered (e.g., after long fork switch).
    PohReset(PohResetInfo),
    /// This validator became leader for a slot range.
    BecameLeader(BecameLeaderInfo),
    /// Optimistic confirmation threshold reached for a slot.
    OptimisticConfirmation(OptimisticConfirmationInfo),
}

/// Summary emitted when a slot finishes replay and the bank is frozen.
///
/// Carries enough data for downstream consumers (metrics, commitment,
/// snapshot, forwarding) to act without re-reading shared state.
#[derive(Debug, Clone)]
pub struct SlotCompletedInfo {
    /// Slot that completed.
    pub slot: u64,
    /// Parent slot.
    pub parent_slot: u64,
    /// Bank hash after freeze.
    pub bank_hash: [u8; 32],
    /// Block hash (last entry hash of the block).
    pub block_hash: [u8; 32],
    /// Epoch this slot belongs to.
    pub epoch: u64,
    /// Whether this slot is the first slot of a new epoch.
    pub is_epoch_boundary: bool,
    /// Total transactions in the block (including failed).
    pub transaction_count: u64,
    /// Successfully executed transactions.
    pub executed_count: u64,
    /// Total fees collected in lamports.
    pub fee_lamports_collected: u64,
    /// Bank capitalization after all changes.
    pub capitalization: u64,
    /// Wall-clock timestamp of the slot.
    pub timestamp: i64,
}

/// Emitted when a slot is marked dead.
#[derive(Debug, Clone)]
pub struct SlotDeadInfo {
    /// The dead slot.
    pub slot: u64,
    /// Parent of the dead slot.
    pub parent_slot: u64,
    /// Why the slot was marked dead.
    pub reason: SlotDeadReason,
}

/// Reasons a slot can be marked dead.
#[derive(Debug, Clone)]
pub enum SlotDeadReason {
    /// Block ancestry does not match the expected parent.
    AncestryFailure,
    /// PoH entry chain verification failed.
    PohVerificationFailed,
    /// Transaction execution produced an unrecoverable error.
    ExecutionFailed(String),
    /// Bank freeze operation failed.
    BankFreezeError,
    /// Block structure is invalid (missing entries, malformed data).
    InvalidBlock,
}

/// Emitted when the root slot advances.
#[derive(Debug, Clone)]
pub struct RootAdvancedInfo {
    /// The new root slot.
    pub new_root: u64,
    /// The previous root slot.
    pub previous_root: u64,
    /// Number of slots pruned by this root advancement.
    pub pruned_slot_count: u64,
}

/// Emitted when a PoH reset is triggered.
///
/// This happens during fork switches when the validator needs to
/// reset its PoH chain to a different fork tip.
#[derive(Debug, Clone)]
pub struct PohResetInfo {
    /// Slot at which the reset occurs.
    pub slot: u64,
    /// Bank hash of the slot being reset to.
    pub bank_hash: [u8; 32],
}

/// Emitted when this validator becomes leader for a slot range.
#[derive(Debug, Clone)]
pub struct BecameLeaderInfo {
    /// First slot in the leader range.
    pub start_slot: u64,
    /// Last slot in the leader range (inclusive).
    pub end_slot: u64,
    /// Epoch of the leader range.
    pub epoch: u64,
    /// Validator identity pubkey.
    pub identity_pubkey: [u8; 32],
}

/// Emitted when optimistic confirmation threshold is reached.
///
/// A slot is optimistically confirmed when >2/3 of stake has voted
/// for it or one of its descendants.
#[derive(Debug, Clone)]
pub struct OptimisticConfirmationInfo {
    /// The optimistically confirmed slot.
    pub slot: u64,
    /// Percentage of total stake that has confirmed.
    pub stake_percentage: f64,
}

// ---------------------------------------------------------------------------
// SignalBus — broadcast channel for replay signals
// ---------------------------------------------------------------------------

/// Broadcast bus for replay signals.
///
/// Supports multiple subscribers, each receiving signals through their
/// own bounded channel. Emission is non-blocking: if any subscriber's
/// channel is full, the signal is dropped for that subscriber only.
pub struct SignalBus {
    /// One sender per subscriber.
    senders: Vec<Sender<ReplaySignal>>,
}

impl SignalBus {
    /// Create a new signal bus with no subscribers.
    pub fn new() -> Self {
        Self {
            senders: Vec::new(),
        }
    }

    /// Add a subscriber and return their receiving end.
    ///
    /// Returns `None` if the maximum number of subscribers is reached.
    pub fn subscribe(&mut self) -> Option<Receiver<ReplaySignal>> {
        if self.senders.len() >= MAX_SIGNAL_SUBSCRIBERS {
            return None;
        }
        let (tx, rx) = crossbeam_channel::bounded(SIGNAL_CHANNEL_CAPACITY);
        self.senders.push(tx);
        Some(rx)
    }

    /// Emit a signal to all subscribers.
    ///
    /// Non-blocking: if a subscriber's channel is full, the signal is
    /// dropped for that subscriber. Disconnected subscribers are removed.
    ///
    /// Returns the number of subscribers whose channel was full (drops).
    pub fn emit(&mut self, signal: ReplaySignal) -> usize {
        let mut drops = 0;
        self.senders.retain(|sender| {
            match sender.try_send(signal.clone()) {
                Ok(()) => true,
                Err(TrySendError::Full(_)) => {
                    drops += 1;
                    true // keep subscriber, just skip
                }
                Err(TrySendError::Disconnected(_)) => false, // remove dead subscriber
            }
        });
        drops
    }

    /// Number of active subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.senders.len()
    }
}

impl Default for SignalBus {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_bus_single_subscriber() {
        let mut bus = SignalBus::new();
        let rx = bus.subscribe().unwrap();

        let info = SlotCompletedInfo {
            slot: 42,
            parent_slot: 41,
            bank_hash: [1u8; 32],
            block_hash: [2u8; 32],
            epoch: 0,
            is_epoch_boundary: false,
            transaction_count: 100,
            executed_count: 95,
            fee_lamports_collected: 500_000,
            capitalization: 1_000_000_000,
            timestamp: 1700000000,
        };
        bus.emit(ReplaySignal::SlotCompleted(info));

        let received = rx.try_recv().unwrap();
        match received {
            ReplaySignal::SlotCompleted(info) => {
                assert_eq!(info.slot, 42);
                assert_eq!(info.transaction_count, 100);
                assert_eq!(info.executed_count, 95);
            }
            _ => panic!("Expected SlotCompleted signal"),
        }
    }

    #[test]
    fn signal_bus_multiple_subscribers() {
        let mut bus = SignalBus::new();
        let rx1 = bus.subscribe().unwrap();
        let rx2 = bus.subscribe().unwrap();
        let rx3 = bus.subscribe().unwrap();

        bus.emit(ReplaySignal::RootAdvanced(RootAdvancedInfo {
            new_root: 100,
            previous_root: 50,
            pruned_slot_count: 45,
        }));

        // All subscribers receive the signal.
        for rx in [&rx1, &rx2, &rx3] {
            let received = rx.try_recv().unwrap();
            match received {
                ReplaySignal::RootAdvanced(info) => {
                    assert_eq!(info.new_root, 100);
                    assert_eq!(info.previous_root, 50);
                    assert_eq!(info.pruned_slot_count, 45);
                }
                _ => panic!("Expected RootAdvanced signal"),
            }
        }
    }

    #[test]
    fn signal_bus_full_channel_non_blocking() {
        let mut bus = SignalBus::new();
        let rx = bus.subscribe().unwrap();

        // Fill the channel to capacity.
        for i in 0..SIGNAL_CHANNEL_CAPACITY {
            bus.emit(ReplaySignal::SlotDead(SlotDeadInfo {
                slot: i as u64,
                parent_slot: 0,
                reason: SlotDeadReason::InvalidBlock,
            }));
        }

        // Emitting one more should not block — just drop for this subscriber.
        bus.emit(ReplaySignal::SlotDead(SlotDeadInfo {
            slot: 9999,
            parent_slot: 0,
            reason: SlotDeadReason::InvalidBlock,
        }));

        // Subscriber still has exactly SIGNAL_CHANNEL_CAPACITY signals.
        let mut count = 0;
        while rx.try_recv().is_ok() {
            count += 1;
        }
        assert_eq!(count, SIGNAL_CHANNEL_CAPACITY);
    }

    #[test]
    fn signal_bus_removes_disconnected_subscribers() {
        let mut bus = SignalBus::new();
        let rx1 = bus.subscribe().unwrap();
        let _rx2 = bus.subscribe().unwrap();
        assert_eq!(bus.subscriber_count(), 2);

        // Drop rx1's receiver.
        drop(rx1);

        // Emit — should detect disconnected subscriber and remove it.
        bus.emit(ReplaySignal::PohReset(PohResetInfo {
            slot: 10,
            bank_hash: [0u8; 32],
        }));

        assert_eq!(bus.subscriber_count(), 1);
    }

    #[test]
    fn signal_bus_max_subscribers() {
        let mut bus = SignalBus::new();
        let mut receivers = Vec::new();

        for _ in 0..MAX_SIGNAL_SUBSCRIBERS {
            receivers.push(bus.subscribe().unwrap());
        }

        // Next subscribe should fail.
        assert!(bus.subscribe().is_none());
        assert_eq!(bus.subscriber_count(), MAX_SIGNAL_SUBSCRIBERS);
    }

    #[test]
    fn slot_completed_info_fields() {
        let info = SlotCompletedInfo {
            slot: 100,
            parent_slot: 99,
            bank_hash: [0xAA; 32],
            block_hash: [0xBB; 32],
            epoch: 5,
            is_epoch_boundary: true,
            transaction_count: 2000,
            executed_count: 1950,
            fee_lamports_collected: 10_000_000,
            capitalization: 500_000_000_000,
            timestamp: 1700000000,
        };

        assert_eq!(info.slot, 100);
        assert_eq!(info.parent_slot, 99);
        assert!(info.is_epoch_boundary);
        assert_eq!(info.epoch, 5);
        assert_eq!(info.transaction_count, 2000);
        assert_eq!(info.executed_count, 1950);
    }

    #[test]
    fn slot_dead_reason_variants() {
        let reasons = vec![
            SlotDeadReason::AncestryFailure,
            SlotDeadReason::PohVerificationFailed,
            SlotDeadReason::ExecutionFailed("test error".to_string()),
            SlotDeadReason::BankFreezeError,
            SlotDeadReason::InvalidBlock,
        ];

        // Verify all variants are constructible and debuggable.
        for reason in &reasons {
            let _ = format!("{:?}", reason);
        }
        assert_eq!(reasons.len(), 5);
    }

    #[test]
    fn became_leader_info() {
        let info = BecameLeaderInfo {
            start_slot: 1000,
            end_slot: 1003,
            epoch: 2,
            identity_pubkey: [0x42; 32],
        };

        assert_eq!(info.start_slot, 1000);
        assert_eq!(info.end_slot, 1003);
        assert_eq!(info.epoch, 2);
    }

    #[test]
    fn optimistic_confirmation_info() {
        let info = OptimisticConfirmationInfo {
            slot: 500,
            stake_percentage: 72.5,
        };

        assert_eq!(info.slot, 500);
        assert!(info.stake_percentage > 66.6);
    }
}
