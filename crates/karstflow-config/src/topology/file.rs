use super::validation::finalize_topology;
use crate::{ConfigError, Result};
use karstflow_core::TopologySpec;
use std::fs;
use std::path::Path;

pub(super) fn load_topology_from_file(topology_path: &Path) -> Result<TopologySpec> {
    let topology_toml =
        fs::read_to_string(topology_path).map_err(|source| ConfigError::FileRead {
            kind: "topology",
            path: topology_path.to_path_buf(),
            source,
        })?;
    let topology_spec: TopologySpec =
        toml::from_str(&topology_toml).map_err(|source| ConfigError::FileTomlParse {
            kind: "topology",
            path: topology_path.to_path_buf(),
            message: source.to_string(),
        })?;
    finalize_topology(topology_spec)
}
