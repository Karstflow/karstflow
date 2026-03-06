use crate::stats::IngressFilterMetrics;
use karstflow_net::{DropReason, IngressSource};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct IngressFilterStats {
    accepted_transactions: AtomicU64,
    accepted_quic_source: AtomicU64,
    accepted_gossip_source: AtomicU64,
    accepted_bundle_source: AtomicU64,
    accepted_rpc_source: AtomicU64,
    duplicate_transactions: AtomicU64,
    duplicate_quic_source: AtomicU64,
    duplicate_gossip_source: AtomicU64,
    duplicate_bundle_source: AtomicU64,
    duplicate_rpc_source: AtomicU64,
    dropped_empty_payload: AtomicU64,
    dropped_oversized_payload: AtomicU64,
    dropped_disallowed_source: AtomicU64,
    dropped_rate_limited_source: AtomicU64,
    dropped_cost_budget_source: AtomicU64,
    dropped_downstream_backpressure: AtomicU64,
}

impl IngressFilterStats {
    pub(crate) fn increment_accepted(&self, source: IngressSource) {
        self.accepted_transactions.fetch_add(1, Ordering::Relaxed);
        match source {
            IngressSource::Quic => self.accepted_quic_source.fetch_add(1, Ordering::Relaxed),
            IngressSource::Gossip => self.accepted_gossip_source.fetch_add(1, Ordering::Relaxed),
            IngressSource::Bundle => self.accepted_bundle_source.fetch_add(1, Ordering::Relaxed),
            IngressSource::Rpc => self.accepted_rpc_source.fetch_add(1, Ordering::Relaxed),
        };
    }

    pub(crate) fn increment_duplicates(&self, source: IngressSource) {
        self.duplicate_transactions.fetch_add(1, Ordering::Relaxed);
        match source {
            IngressSource::Quic => self.duplicate_quic_source.fetch_add(1, Ordering::Relaxed),
            IngressSource::Gossip => self.duplicate_gossip_source.fetch_add(1, Ordering::Relaxed),
            IngressSource::Bundle => self.duplicate_bundle_source.fetch_add(1, Ordering::Relaxed),
            IngressSource::Rpc => self.duplicate_rpc_source.fetch_add(1, Ordering::Relaxed),
        };
    }

    pub(crate) fn increment_drop_reason(&self, drop_reason: DropReason, _source: IngressSource) {
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
            DropReason::SourceRateLimited => {
                self.dropped_rate_limited_source
                    .fetch_add(1, Ordering::Relaxed);
            }
            DropReason::SourceCostBudgetExceeded => {
                self.dropped_cost_budget_source
                    .fetch_add(1, Ordering::Relaxed);
            }
            DropReason::DownstreamBackpressure => {
                self.dropped_downstream_backpressure
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub(crate) fn snapshot(&self) -> IngressFilterMetrics {
        IngressFilterMetrics {
            accepted_transactions: self.accepted_transactions.load(Ordering::Relaxed),
            accepted_quic_source: self.accepted_quic_source.load(Ordering::Relaxed),
            accepted_gossip_source: self.accepted_gossip_source.load(Ordering::Relaxed),
            accepted_bundle_source: self.accepted_bundle_source.load(Ordering::Relaxed),
            accepted_rpc_source: self.accepted_rpc_source.load(Ordering::Relaxed),
            duplicate_transactions: self.duplicate_transactions.load(Ordering::Relaxed),
            duplicate_quic_source: self.duplicate_quic_source.load(Ordering::Relaxed),
            duplicate_gossip_source: self.duplicate_gossip_source.load(Ordering::Relaxed),
            duplicate_bundle_source: self.duplicate_bundle_source.load(Ordering::Relaxed),
            duplicate_rpc_source: self.duplicate_rpc_source.load(Ordering::Relaxed),
            dropped_empty_payload: self.dropped_empty_payload.load(Ordering::Relaxed),
            dropped_oversized_payload: self.dropped_oversized_payload.load(Ordering::Relaxed),
            dropped_disallowed_source: self.dropped_disallowed_source.load(Ordering::Relaxed),
            dropped_rate_limited_source: self.dropped_rate_limited_source.load(Ordering::Relaxed),
            dropped_cost_budget_source: self.dropped_cost_budget_source.load(Ordering::Relaxed),
            dropped_downstream_backpressure: self
                .dropped_downstream_backpressure
                .load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_snapshot_is_all_zeros() {
        let stats = IngressFilterStats::default();
        let snap = stats.snapshot();
        assert_eq!(snap.accepted_transactions, 0);
        assert_eq!(snap.duplicate_transactions, 0);
        assert_eq!(snap.dropped_empty_payload, 0);
    }

    #[test]
    fn increment_accepted_by_source() {
        let stats = IngressFilterStats::default();
        stats.increment_accepted(IngressSource::Quic);
        stats.increment_accepted(IngressSource::Gossip);
        stats.increment_accepted(IngressSource::Bundle);
        stats.increment_accepted(IngressSource::Rpc);
        let snap = stats.snapshot();
        assert_eq!(snap.accepted_transactions, 4);
        assert_eq!(snap.accepted_quic_source, 1);
        assert_eq!(snap.accepted_gossip_source, 1);
        assert_eq!(snap.accepted_bundle_source, 1);
        assert_eq!(snap.accepted_rpc_source, 1);
    }

    #[test]
    fn increment_duplicates_by_source() {
        let stats = IngressFilterStats::default();
        stats.increment_duplicates(IngressSource::Quic);
        stats.increment_duplicates(IngressSource::Quic);
        stats.increment_duplicates(IngressSource::Gossip);
        let snap = stats.snapshot();
        assert_eq!(snap.duplicate_transactions, 3);
        assert_eq!(snap.duplicate_quic_source, 2);
        assert_eq!(snap.duplicate_gossip_source, 1);
    }

    #[test]
    fn increment_drop_reasons() {
        let stats = IngressFilterStats::default();
        stats.increment_drop_reason(DropReason::EmptyPayload, IngressSource::Quic);
        stats.increment_drop_reason(DropReason::OversizedPayload, IngressSource::Quic);
        stats.increment_drop_reason(DropReason::SourceNotAllowed, IngressSource::Quic);
        stats.increment_drop_reason(DropReason::SourceRateLimited, IngressSource::Quic);
        stats.increment_drop_reason(DropReason::SourceCostBudgetExceeded, IngressSource::Quic);
        stats.increment_drop_reason(DropReason::DownstreamBackpressure, IngressSource::Quic);
        let snap = stats.snapshot();
        assert_eq!(snap.dropped_empty_payload, 1);
        assert_eq!(snap.dropped_oversized_payload, 1);
        assert_eq!(snap.dropped_disallowed_source, 1);
        assert_eq!(snap.dropped_rate_limited_source, 1);
        assert_eq!(snap.dropped_cost_budget_source, 1);
        assert_eq!(snap.dropped_downstream_backpressure, 1);
    }

    #[test]
    fn multiple_increments_accumulate() {
        let stats = IngressFilterStats::default();
        for _ in 0..5 {
            stats.increment_accepted(IngressSource::Quic);
        }
        let snap = stats.snapshot();
        assert_eq!(snap.accepted_transactions, 5);
        assert_eq!(snap.accepted_quic_source, 5);
    }
}
