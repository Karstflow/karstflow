use paradencer_core::TopologySpec;
use paradencer_mesh::InPort;
use paradencer_runtime::Service;
use paradencer_stages::AssembledBlock;

pub struct MaterializedTopology {
    pub topology_spec: TopologySpec,
    pub services: Vec<Box<dyn Service>>,
    /// Receiver for assembled blocks from the shred pipeline.
    /// Connect this to a ReplayService block input to close the shred path.
    pub shred_block_receiver: Option<InPort<AssembledBlock>>,
}
