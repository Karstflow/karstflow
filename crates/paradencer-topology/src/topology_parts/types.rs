use paradencer_core::TopologySpec;
use paradencer_runtime::Service;

pub struct MaterializedTopology {
    pub topology_spec: TopologySpec,
    pub services: Vec<Box<dyn Service>>,
}
