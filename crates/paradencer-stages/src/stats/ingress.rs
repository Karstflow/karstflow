use crate::stats::IngressFilterMetrics;
use paradencer_ingress::{DropReason, IngressSource};
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
