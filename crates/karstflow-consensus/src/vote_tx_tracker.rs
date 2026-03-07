/// Tracks recently sent vote transaction signatures to detect when
/// our own votes have landed on-chain.
///
/// Used to implement the "wait to become leader until our vote is seen
/// on the root bank" optimization. Maintains a bounded ring buffer of
/// recent vote signatures mapped to the identity that signed them.
use karstflow_storage::Pubkey;
use std::collections::{HashMap, VecDeque};

/// Maximum number of vote signatures tracked.
const MAX_TRACKED_VOTES: usize = 512;

/// A tracked vote transaction entry.
#[derive(Debug, Clone)]
struct TrackedVoteTx {
    /// Transaction signature (64 bytes).
    signature: [u8; 64],
    /// Identity pubkey that signed the vote.
    identity: Pubkey,
}

/// Tracks vote transaction signatures for landing detection.
#[derive(Debug)]
pub struct VoteTxTracker {
    /// Ring buffer of recent vote transactions (FIFO).
    entries: VecDeque<TrackedVoteTx>,
    /// Fast lookup by signature.
    sig_to_idx: HashMap<[u8; 64], usize>,
    /// Logical index counter for the ring buffer.
    head_idx: usize,
}

impl VoteTxTracker {
    /// Create a new vote transaction tracker.
    pub fn new() -> Self {
        Self {
            entries: VecDeque::with_capacity(MAX_TRACKED_VOTES),
            sig_to_idx: HashMap::with_capacity(MAX_TRACKED_VOTES),
            head_idx: 0,
        }
    }

    /// Record a vote transaction that was sent to the network.
    pub fn insert(&mut self, identity: Pubkey, signature: [u8; 64]) {
        // Evict oldest if full.
        if self.entries.len() >= MAX_TRACKED_VOTES {
            if let Some(old) = self.entries.pop_front() {
                self.sig_to_idx.remove(&old.signature);
            }
            self.head_idx += 1;
        }

        let idx = self.head_idx + self.entries.len();
        self.sig_to_idx.insert(signature, idx);
        self.entries.push_back(TrackedVoteTx {
            signature,
            identity,
        });
    }

    /// Query whether a vote signature is tracked and get the signer identity.
    pub fn query_signature(&self, signature: &[u8; 64]) -> Option<&Pubkey> {
        let &idx = self.sig_to_idx.get(signature)?;
        let offset = idx.checked_sub(self.head_idx)?;
        self.entries.get(offset).map(|e| &e.identity)
    }

    /// Check if a vote signature is tracked.
    pub fn contains(&self, signature: &[u8; 64]) -> bool {
        self.sig_to_idx.contains_key(signature)
    }

    /// Number of tracked vote transactions.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the tracker is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Reset the tracker, removing all entries.
    pub fn reset(&mut self) {
        self.entries.clear();
        self.sig_to_idx.clear();
        self.head_idx = 0;
    }
}

impl Default for VoteTxTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(seed: u8) -> Pubkey {
        Pubkey::new([seed; 32])
    }

    fn sig(seed: u8) -> [u8; 64] {
        [seed; 64]
    }

    #[test]
    fn insert_and_query() {
        let mut tracker = VoteTxTracker::new();
        tracker.insert(pk(1), sig(10));
        tracker.insert(pk(2), sig(20));

        assert_eq!(tracker.len(), 2);
        assert!(tracker.contains(&sig(10)));
        assert!(tracker.contains(&sig(20)));
        assert!(!tracker.contains(&sig(30)));

        assert_eq!(tracker.query_signature(&sig(10)), Some(&pk(1)));
        assert_eq!(tracker.query_signature(&sig(20)), Some(&pk(2)));
        assert_eq!(tracker.query_signature(&sig(30)), None);
    }

    #[test]
    fn evicts_oldest_when_full() {
        let mut tracker = VoteTxTracker::new();
        for i in 0..MAX_TRACKED_VOTES {
            tracker.insert(pk(0), sig(i as u8));
        }
        assert_eq!(tracker.len(), MAX_TRACKED_VOTES);
        assert!(tracker.contains(&sig(0)));

        // Insert one more — should evict sig(0).
        tracker.insert(pk(0), sig(255));
        assert_eq!(tracker.len(), MAX_TRACKED_VOTES);
        assert!(!tracker.contains(&sig(0)));
        assert!(tracker.contains(&sig(1)));
        assert!(tracker.contains(&sig(255)));
    }

    #[test]
    fn reset_clears_all() {
        let mut tracker = VoteTxTracker::new();
        tracker.insert(pk(1), sig(10));
        tracker.insert(pk(2), sig(20));
        tracker.reset();

        assert!(tracker.is_empty());
        assert!(!tracker.contains(&sig(10)));
    }
}
