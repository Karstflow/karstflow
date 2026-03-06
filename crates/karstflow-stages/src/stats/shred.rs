use crate::stats::ShredFilterMetrics;
use karstflow_net::DropReason;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct ShredFilterStats {
    accepted_shreds: AtomicU64,
    duplicate_shreds: AtomicU64,
    dropped_empty_payload: AtomicU64,
    dropped_oversized_payload: AtomicU64,
    dropped_disallowed_source: AtomicU64,
    parse_failures: AtomicU64,
}

impl ShredFilterStats {
    pub(crate) fn increment_accepted(&self) {
        self.accepted_shreds.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_duplicates(&self) {
        self.duplicate_shreds.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_parse_failures(&self) {
        self.parse_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_drop_reason(&self, drop_reason: DropReason) {
        match drop_reason {
            DropReason::EmptyPayload => {
                self.dropped_empty_payload.fetch_add(1, Ordering::Relaxed);
            }
            DropReason::OversizedPayload => {
                self.dropped_oversized_payload
                    .fetch_add(1, Ordering::Relaxed);
            }
            DropReason::SourceNotAllowed => {
                self.dropped_disallowed_source
                    .fetch_add(1, Ordering::Relaxed);
            }
            DropReason::SourceRateLimited
            | DropReason::SourceCostBudgetExceeded
            | DropReason::DownstreamBackpressure => {}
        }
    }

    pub(crate) fn snapshot(&self) -> ShredFilterMetrics {
        ShredFilterMetrics {
            accepted_shreds: self.accepted_shreds.load(Ordering::Relaxed),
            duplicate_shreds: self.duplicate_shreds.load(Ordering::Relaxed),
            dropped_empty_payload: self.dropped_empty_payload.load(Ordering::Relaxed),
            dropped_oversized_payload: self.dropped_oversized_payload.load(Ordering::Relaxed),
            dropped_disallowed_source: self.dropped_disallowed_source.load(Ordering::Relaxed),
            parse_failures: self.parse_failures.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_snapshot_is_all_zeros() {
        let stats = ShredFilterStats::default();
        let snap = stats.snapshot();
        assert_eq!(snap.accepted_shreds, 0);
        assert_eq!(snap.duplicate_shreds, 0);
        assert_eq!(snap.dropped_empty_payload, 0);
        assert_eq!(snap.parse_failures, 0);
    }

    #[test]
    fn increment_accepted_and_duplicates() {
        let stats = ShredFilterStats::default();
        stats.increment_accepted();
        stats.increment_accepted();
        stats.increment_duplicates();
        let snap = stats.snapshot();
        assert_eq!(snap.accepted_shreds, 2);
        assert_eq!(snap.duplicate_shreds, 1);
    }

    #[test]
    fn increment_parse_failures() {
        let stats = ShredFilterStats::default();
        stats.increment_parse_failures();
        stats.increment_parse_failures();
        let snap = stats.snapshot();
        assert_eq!(snap.parse_failures, 2);
    }

    #[test]
    fn drop_reasons_increment_correct_counters() {
        let stats = ShredFilterStats::default();
        stats.increment_drop_reason(DropReason::EmptyPayload);
        stats.increment_drop_reason(DropReason::OversizedPayload);
        stats.increment_drop_reason(DropReason::SourceNotAllowed);
        // These should be no-ops for shred filter
        stats.increment_drop_reason(DropReason::SourceRateLimited);
        stats.increment_drop_reason(DropReason::SourceCostBudgetExceeded);
        stats.increment_drop_reason(DropReason::DownstreamBackpressure);
        let snap = stats.snapshot();
        assert_eq!(snap.dropped_empty_payload, 1);
        assert_eq!(snap.dropped_oversized_payload, 1);
        assert_eq!(snap.dropped_disallowed_source, 1);
    }
}
