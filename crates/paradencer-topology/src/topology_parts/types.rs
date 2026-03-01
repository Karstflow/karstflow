use paradencer_core::{IpcMode, TopologySpec};
use paradencer_mesh::{DualReceiver, DualSender};
use paradencer_runtime::Service;
use paradencer_stages::{
    AssembledBlock, AtomicFecResolverStats, CompletedFecSet, DeferredLeaderLookup, MetricsContent,
    MetricsReporter, RawTransaction, RetransmitDecision, SharedHealthStatus, ShredArrival,
    ShredNetworkStats,
};
use paradencer_types::shred::Shred;
use std::sync::Arc;

pub struct MaterializedTopology {
    pub topology_spec: TopologySpec,
    /// IPC mode used for dual-mode links within this topology.
    pub ipc_mode: IpcMode,
    pub services: Vec<Box<dyn Service>>,
    /// Receiver for assembled blocks from the shred pipeline.
    /// Connect this to a ReplayService block input to close the shred path.
    pub shred_block_receiver: Option<DualReceiver<AssembledBlock>>,
    /// Input receivers for the validator pipeline (one per TransactionSanitizer worker).
    /// Connect these to PipelineServiceBuilder::add_input() in bootstrap.
    pub pipeline_inputs: Vec<DualReceiver<RawTransaction>>,
    /// Direct shred injection point for ShredCollector (bypasses FEC resolver).
    /// Used by repair/catch-up paths to inject already-verified shreds directly.
    /// Must be kept alive to prevent the ShredCollector's input channel from closing.
    pub direct_shred_sender: Option<DualSender<Shred>>,
    /// Receiver for shred arrival notifications from the ShredCollector.
    /// Connect this to the repair coordinator so it tracks which shreds
    /// have been received via turbine and avoids redundant requests.
    pub shred_arrival_receiver: Option<crossbeam_channel::Receiver<ShredArrival>>,
    /// Shared metrics content buffer for HTTP metrics serving.
    /// Present when metrics output target is `Http`. Pass this to
    /// `MetricsHttpServer` to serve Prometheus metrics over HTTP.
    pub metrics_http_content: Option<MetricsContent>,
    /// Shared health status for `/health`, `/ready`, `/alive` probe endpoints.
    /// Pass this to `MetricsHttpServer` via `.with_health()`.
    pub health_status: Option<SharedHealthStatus>,
    /// Metrics reporter stored separately for aggregator injection.
    /// Push into `services` after attaching a `MetricsAggregator`.
    pub reporter: Option<MetricsReporter>,
    /// Shred network stats for pipeline metrics aggregation.
    pub shred_network_stats: Option<Arc<ShredNetworkStats>>,
    /// FEC resolver atomic stats for pipeline metrics aggregation.
    pub fec_resolver_stats: Option<Arc<AtomicFecResolverStats>>,
    /// Receiver for retransmit decisions from the shred network service.
    /// Connect this to the turbine retransmit service for shred propagation.
    pub retransmit_receiver: Option<DualReceiver<RetransmitDecision>>,
    /// Handle to the deferred leader lookup for shred signature verification.
    /// Set the inner provider after consensus boots via `handle.set(provider)`.
    pub leader_lookup_handle: Option<Arc<DeferredLeaderLookup>>,
    /// Receiver for completed FEC sets destined for blockstore persistence.
    /// Wire to ShredStoreService when a blockstore is available.
    pub fec_store_receiver: Option<DualReceiver<CompletedFecSet>>,
    /// Ownership handles for shared-memory tile links. These must be kept
    /// alive for the lifetime of all `DualSender::Link` / `DualReceiver::Link`
    /// endpoints created during materialization. Empty when `IpcMode::Channel`.
    #[allow(dead_code)]
    pub link_ownership: Vec<Box<dyn Send>>,
}
