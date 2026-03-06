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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_dedup_accepts_first_fingerprint() {
        let mut dedup = SignatureDeduplicator::new(10);
        assert_eq!(dedup.register(42), DedupDecision::Accepted);
    }

    #[test]
    fn duplicate_is_rejected() {
        let mut dedup = SignatureDeduplicator::new(10);
        dedup.register(42);
        assert_eq!(dedup.register(42), DedupDecision::Duplicate);
    }

    #[test]
    fn distinct_fingerprints_accepted() {
        let mut dedup = SignatureDeduplicator::new(10);
        assert_eq!(dedup.register(1), DedupDecision::Accepted);
        assert_eq!(dedup.register(2), DedupDecision::Accepted);
        assert_eq!(dedup.register(3), DedupDecision::Accepted);
    }

    #[test]
    fn window_eviction_allows_reuse() {
        let mut dedup = SignatureDeduplicator::new(3);
        dedup.register(1);
        dedup.register(2);
        dedup.register(3);
        // Window full: [1, 2, 3]. Adding 4 evicts 1.
        dedup.register(4);
        // 1 was evicted, so it should be accepted again.
        assert_eq!(dedup.register(1), DedupDecision::Accepted);
    }

    #[test]
    fn window_preserves_recent() {
        let mut dedup = SignatureDeduplicator::new(3);
        dedup.register(1);
        dedup.register(2);
        dedup.register(3);
        dedup.register(4); // evicts 1
                           // 2 and 3 should still be in window.
        assert_eq!(dedup.register(2), DedupDecision::Duplicate);
        assert_eq!(dedup.register(3), DedupDecision::Duplicate);
    }

    #[test]
    fn zero_capacity_clamped_to_one() {
        let mut dedup = SignatureDeduplicator::new(0);
        assert_eq!(dedup.register(1), DedupDecision::Accepted);
        assert_eq!(dedup.register(1), DedupDecision::Duplicate);
        // Window of 1: adding 2 evicts 1.
        assert_eq!(dedup.register(2), DedupDecision::Accepted);
        assert_eq!(dedup.register(1), DedupDecision::Accepted);
    }

    #[test]
    fn large_window_no_eviction() {
        let mut dedup = SignatureDeduplicator::new(1000);
        for i in 0..100 {
            assert_eq!(dedup.register(i), DedupDecision::Accepted);
        }
        for i in 0..100 {
            assert_eq!(dedup.register(i), DedupDecision::Duplicate);
        }
    }

    #[test]
    fn sequential_eviction_fifo() {
        // Window of 2: oldest entry is evicted first.
        let mut dedup = SignatureDeduplicator::new(2);
        dedup.register(10); // [10]
        dedup.register(20); // [10, 20]
        dedup.register(30); // evicts 10 → [20, 30]
                            // 10 was evicted.
        assert_eq!(dedup.register(10), DedupDecision::Accepted); // evicts 20 → [30, 10]
                                                                 // 20 was evicted by the previous insert.
        assert_eq!(dedup.register(20), DedupDecision::Accepted); // evicts 30 → [10, 20]
    }
}
