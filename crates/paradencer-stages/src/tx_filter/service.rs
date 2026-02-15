use super::TxFilter;
use paradencer_ingress::{DecodeOutcome, DedupDecision};
use paradencer_mesh::ReceiveError;
use paradencer_runtime::{RuntimeError, RuntimeResult, Service, ServiceContext};
use std::time::Duration;

impl Service for TxFilter {
    fn name(&self) -> &'static str {
        "tx-filter"
    }

    fn tick_interval(&self) -> Duration {
        Duration::from_millis(2)
    }

    fn tick(&mut self, context: &ServiceContext) -> RuntimeResult<()> {
        self.tick_counter = self.tick_counter.saturating_add(1);
        self.flush_pending_egress(context)?;
        match self.incoming_packets.try_recv() {
            Ok(Some(packet)) => {
                let transaction = match self.packet_decoder.decode(&packet) {
                    DecodeOutcome::Accepted(transaction) => transaction,
                    DecodeOutcome::Dropped(drop_reason) => {
                        self.ingress_filter_stats
                            .increment_drop_reason(drop_reason, packet.source);
                        return Ok(());
                    }
                };

                let min_gap_ticks = self.ingress_policy.source_min_gap_ticks(transaction.source);
                let burst_capacity = self
                    .ingress_policy
                    .source_burst_capacity(transaction.source);
                let burst_refill_ticks = self
                    .ingress_policy
                    .source_burst_refill_ticks(transaction.source);
                if !self.source_rate_limiter.try_accept(
                    transaction.source,
                    self.tick_counter,
                    min_gap_ticks,
                    burst_capacity,
                    burst_refill_ticks,
                ) {
                    self.ingress_filter_stats.increment_drop_reason(
                        paradencer_ingress::DropReason::SourceRateLimited,
                        transaction.source,
                    );
                    return Ok(());
                }
                let cost_budget_per_window = self
                    .ingress_policy
                    .source_cost_budget_per_window(transaction.source);
                let cost_budget_window_ticks = self
                    .ingress_policy
                    .source_cost_budget_window_ticks(transaction.source);
                if !self.source_cost_budget_limiter.try_consume(
                    transaction.source,
                    self.tick_counter,
                    transaction.estimated_cost_units,
                    cost_budget_per_window,
                    cost_budget_window_ticks,
                ) {
                    self.ingress_filter_stats.increment_drop_reason(
                        paradencer_ingress::DropReason::SourceCostBudgetExceeded,
                        transaction.source,
                    );
                    return Ok(());
                }

                if self
                    .signature_deduplicator
                    .register(transaction.dedup_fingerprint)
                    == DedupDecision::Duplicate
                {
                    self.ingress_filter_stats
                        .increment_duplicates(transaction.source);
                    return Ok(());
                }
                self.ingress_filter_stats
                    .increment_accepted(transaction.source);
                self.try_send_or_buffer(transaction)
            }
            Ok(None) => Ok(()),
            Err(ReceiveError::QueueClosed) => {
                context.shutdown.request_stop();
                Err(RuntimeError::service_failure(
                    self.name(),
                    "input packet link closed",
                ))
            }
        }
    }
}
