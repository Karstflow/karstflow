mod format;
mod sink;

use crate::errors::StageError;
use crate::health::SharedHealthStatus;
use crate::metrics_aggregator::MetricsAggregator;
use crate::metrics_http::MetricsContent;
use crate::{
    BlockAssemblyStats, IngressFilterStats, MetricsOutputFormat, MetricsOutputTarget,
    ShredFilterStats,
};
use paradencer_consensus::BankForks;
use paradencer_mesh::{ChannelSnapshot, ChannelStats};
use paradencer_runtime::{RuntimeError, RuntimeResult, Service, ServiceContext};
use std::sync::{Arc, RwLock};
use std::time::Duration;

pub struct MetricsReporter {
    packet_link_stats: Vec<ChannelStats>,
    shred_link_stats: Vec<ChannelStats>,
    transaction_link_stats: Vec<ChannelStats>,
    output_format: MetricsOutputFormat,
    output_target: MetricsOutputTarget,
    ingress_filter_stats: Arc<IngressFilterStats>,
    shred_filter_stats: Arc<ShredFilterStats>,
    block_assembly_stats: Arc<BlockAssemblyStats>,
    /// Shared buffer for HTTP metrics serving. Only used when
    /// `output_target` is `MetricsOutputTarget::Http`.
    http_content: Option<MetricsContent>,
    /// Optional pipeline stage metrics aggregator.
    aggregator: Option<MetricsAggregator>,
    /// Shared health status for probe endpoints.
    health: Option<SharedHealthStatus>,
    /// Bank forks for slot/block_height/transaction_count in health status.
    bank_forks: Option<Arc<RwLock<BankForks>>>,
}

pub struct LinkTelemetryStats {
    pub packet_link_stats: Vec<ChannelStats>,
    pub shred_link_stats: Vec<ChannelStats>,
    pub transaction_link_stats: Vec<ChannelStats>,
}

pub struct StageTelemetryStats {
    pub ingress_filter_stats: Arc<IngressFilterStats>,
    pub shred_filter_stats: Arc<ShredFilterStats>,
    pub block_assembly_stats: Arc<BlockAssemblyStats>,
}

impl MetricsReporter {
    pub fn new(
        packet_link_stats: ChannelStats,
        shred_link_stats: ChannelStats,
        transaction_link_stats: ChannelStats,
    ) -> Self {
        Self::with_output_format_and_stats(
            LinkTelemetryStats {
                packet_link_stats: vec![packet_link_stats],
                shred_link_stats: vec![shred_link_stats],
                transaction_link_stats: vec![transaction_link_stats],
            },
            MetricsOutputFormat::JsonLines,
            MetricsOutputTarget::Stdout,
            StageTelemetryStats {
                ingress_filter_stats: Arc::new(IngressFilterStats::default()),
                shred_filter_stats: Arc::new(ShredFilterStats::default()),
                block_assembly_stats: Arc::new(BlockAssemblyStats::default()),
            },
        )
    }

    pub fn with_output_format(
        packet_link_stats: ChannelStats,
        shred_link_stats: ChannelStats,
        transaction_link_stats: ChannelStats,
        output_format: MetricsOutputFormat,
    ) -> Self {
        Self::with_output_format_and_stats(
            LinkTelemetryStats {
                packet_link_stats: vec![packet_link_stats],
                shred_link_stats: vec![shred_link_stats],
                transaction_link_stats: vec![transaction_link_stats],
            },
            output_format,
            MetricsOutputTarget::Stdout,
            StageTelemetryStats {
                ingress_filter_stats: Arc::new(IngressFilterStats::default()),
                shred_filter_stats: Arc::new(ShredFilterStats::default()),
                block_assembly_stats: Arc::new(BlockAssemblyStats::default()),
            },
        )
    }

    pub fn with_output_format_and_stats(
        link_stats: LinkTelemetryStats,
        output_format: MetricsOutputFormat,
        output_target: MetricsOutputTarget,
        stage_stats: StageTelemetryStats,
    ) -> Self {
        Self {
            packet_link_stats: link_stats.packet_link_stats,
            shred_link_stats: link_stats.shred_link_stats,
            transaction_link_stats: link_stats.transaction_link_stats,
            output_format,
            output_target,
            ingress_filter_stats: stage_stats.ingress_filter_stats,
            shred_filter_stats: stage_stats.shred_filter_stats,
            block_assembly_stats: stage_stats.block_assembly_stats,
            http_content: None,
            aggregator: None,
            health: None,
            bank_forks: None,
        }
    }

    /// Set the shared HTTP content buffer for Prometheus scraping.
    ///
    /// When the output target is `Http`, each tick updates this buffer
    /// with the latest Prometheus text. A `MetricsHttpServer` serves
    /// this content on `GET /metrics`.
    pub fn with_http_content(mut self, content: MetricsContent) -> Self {
        self.http_content = Some(content);
        self
    }

    /// Set the shared health status for probe endpoints.
    ///
    /// When set, each metrics reporter tick updates the health state with
    /// the current uptime and tile count. The HTTP server reads this for
    /// `/health`, `/ready`, and `/alive` responses.
    pub fn with_health(mut self, health: SharedHealthStatus) -> Self {
        self.health = Some(health);
        self
    }

    /// Set the bank forks for slot/block_height data in health probes.
    pub fn with_bank_forks(mut self, bank_forks: Arc<RwLock<BankForks>>) -> Self {
        self.bank_forks = Some(bank_forks);
        self
    }

    /// Set the pipeline stage metrics aggregator.
    ///
    /// When set, aggregated tile stats are appended to Prometheus output
    /// alongside link and filter metrics.
    pub fn with_aggregator(mut self, aggregator: MetricsAggregator) -> Self {
        self.aggregator = Some(aggregator);
        self
    }

    /// Mutable access to the aggregator for updating non-atomic stats.
    pub fn aggregator_mut(&mut self) -> Option<&mut MetricsAggregator> {
        self.aggregator.as_mut()
    }

    fn to_runtime_error(&self, error: StageError) -> RuntimeError {
        RuntimeError::service_failure(self.name(), &error.to_string())
    }

    fn aggregate_link_snapshot(stats: &[ChannelStats]) -> ChannelSnapshot {
        let mut aggregated = ChannelSnapshot {
            queue_depth: 0,
            queue_capacity: Some(0),
            enqueued_messages: 0,
            dequeued_messages: 0,
            blocked_sends: 0,
            closed_sends: 0,
            empty_receives: 0,
            closed_receives: 0,
        };
        for channel_stats in stats {
            let snapshot = channel_stats.snapshot(0, None);
            aggregated.queue_depth = aggregated.queue_depth.saturating_add(snapshot.queue_depth);
            aggregated.queue_capacity = match (aggregated.queue_capacity, snapshot.queue_capacity) {
                (Some(total), Some(capacity)) => Some(total.saturating_add(capacity)),
                _ => None,
            };
            aggregated.enqueued_messages = aggregated
                .enqueued_messages
                .saturating_add(snapshot.enqueued_messages);
            aggregated.dequeued_messages = aggregated
                .dequeued_messages
                .saturating_add(snapshot.dequeued_messages);
            aggregated.blocked_sends = aggregated
                .blocked_sends
                .saturating_add(snapshot.blocked_sends);
            aggregated.closed_sends = aggregated
                .closed_sends
                .saturating_add(snapshot.closed_sends);
            aggregated.empty_receives = aggregated
                .empty_receives
                .saturating_add(snapshot.empty_receives);
            aggregated.closed_receives = aggregated
                .closed_receives
                .saturating_add(snapshot.closed_receives);
        }
        aggregated
    }
}

impl Service for MetricsReporter {
    fn name(&self) -> &'static str {
        "metrics-reporter"
    }

    fn tick_interval(&self) -> Duration {
        Duration::from_secs(1)
    }

    fn tick(&mut self, context: &ServiceContext) -> RuntimeResult<()> {
        let packet_snapshot = Self::aggregate_link_snapshot(&self.packet_link_stats);
        let shred_snapshot = Self::aggregate_link_snapshot(&self.shred_link_stats);
        let transaction_snapshot = Self::aggregate_link_snapshot(&self.transaction_link_stats);
        let ingress_filter_snapshot = self.ingress_filter_stats.snapshot();
        let shred_filter_snapshot = self.shred_filter_stats.snapshot();
        let block_assembly_snapshot = self.block_assembly_stats.snapshot();
        let uptime_millis = context.launch_time.elapsed().as_millis();

        // Update health status for probe endpoints.
        if let Some(ref health) = self.health {
            let tile_count = self.packet_link_stats.len()
                + self.shred_link_stats.len()
                + self.transaction_link_stats.len();
            let (slot, block_height, tx_count) = self
                .bank_forks
                .as_ref()
                .and_then(|bf| bf.read().ok())
                .map(|forks| {
                    let bank = forks.working_bank();
                    (bank.slot(), bank.tick_height(), bank.transaction_count())
                })
                .unwrap_or((0, 0, 0));
            health.update(
                slot,
                block_height,
                tx_count,
                tile_count as u64,
                uptime_millis as u64,
            );
            health.set_status("running");
        }

        match self.output_format {
            MetricsOutputFormat::JsonLines => {
                let json_line = format::build_json_line(
                    uptime_millis,
                    &packet_snapshot,
                    &shred_snapshot,
                    &transaction_snapshot,
                    ingress_filter_snapshot,
                    shred_filter_snapshot,
                    block_assembly_snapshot,
                )
                .map_err(|error| self.to_runtime_error(error))?;
                sink::emit_line(&self.output_target, &json_line)
                    .map_err(|error| self.to_runtime_error(error))?;
            }
            MetricsOutputFormat::PrometheusText => {
                let mut lines = format::build_prometheus_lines(
                    uptime_millis,
                    &packet_snapshot,
                    &shred_snapshot,
                    &transaction_snapshot,
                    ingress_filter_snapshot,
                    shred_filter_snapshot,
                    block_assembly_snapshot,
                );

                // Append aggregated tile stats if available.
                if let Some(ref agg) = self.aggregator {
                    let snap = agg.snapshot();
                    lines.extend(snap.to_prometheus_lines());
                }

                // For Http target, join all lines and write to the shared buffer.
                if matches!(self.output_target, MetricsOutputTarget::Http) {
                    if let Some(ref content) = self.http_content {
                        let full_text = lines.join("\n");
                        if let Ok(mut guard) = content.lock() {
                            *guard = full_text;
                        }
                    }
                } else {
                    for line in lines {
                        sink::emit_line(&self.output_target, &line)
                            .map_err(|error| self.to_runtime_error(error))?;
                    }
                }
            }
        }

        Ok(())
    }
}
