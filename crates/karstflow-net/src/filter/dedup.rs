use super::domain::DedupDecision;
use std::collections::{HashSet, VecDeque};

pub struct SignatureDeduplicator {
    recent_fingerprints: VecDeque<u64>,
    unique_fingerprints: HashSet<u64>,
    window_capacity: usize,
}

impl SignatureDeduplicator {
    pub fn new(window_capacity: usize) -> Self {
        let bounded_capacity = window_capacity.max(1);
        Self {
            recent_fingerprints: VecDeque::with_capacity(bounded_capacity),
            unique_fingerprints: HashSet::with_capacity(bounded_capacity),
            window_capacity: bounded_capacity,
        }
    }

    pub fn register(&mut self, dedup_fingerprint: u64) -> DedupDecision {
        if self.unique_fingerprints.contains(&dedup_fingerprint) {
            return DedupDecision::Duplicate;
        }

        self.unique_fingerprints.insert(dedup_fingerprint);
        self.recent_fingerprints.push_back(dedup_fingerprint);
        self.evict_if_needed();
        DedupDecision::Accepted
    }

    fn evict_if_needed(&mut self) {
        while self.recent_fingerprints.len() > self.window_capacity {
            if let Some(expired_fingerprint) = self.recent_fingerprints.pop_front() {
                self.unique_fingerprints.remove(&expired_fingerprint);
            }
        }
    }
}
