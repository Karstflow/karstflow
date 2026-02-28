use paradencer_core::{IpcMode, TopologySpec};
use paradencer_mesh::{InPort, OutPort};
use paradencer_runtime::Service;
use paradencer_stages::{
    AssembledBlock, MetricsContent, RawTransaction, SharedHealthStatus, ShredArrival,
};
use paradencer_types::shred::Shred;

pub struct MaterializedTopology {
    pub topology_spec: TopologySpec,
    /// IPC mode used for dual-mode links within this topology.
    pub ipc_mode: IpcMode,
    pub services: Vec<Box<dyn Service>>,
    /// Receiver for assembled blocks from the shred pipeline.
    /// Connect this to a ReplayService block input to close the shred path.
    pub shred_block_receiver: Option<InPort<AssembledBlock>>,
    /// Input receivers for the validator pipeline (one per TransactionSanitizer worker).
    /// Connect these to PipelineServiceBuilder::add_input() in bootstrap.
    pub pipeline_inputs: Vec<InPort<RawTransaction>>,
    /// Direct shred injection point for ShredCollector (bypasses FEC resolver).
    /// Used by repair/catch-up paths to inject already-verified shreds directly.
    /// Must be kept alive to prevent the ShredCollector's input channel from closing.
    pub direct_shred_sender: Option<OutPort<Shred>>,
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
}
