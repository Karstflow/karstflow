use crate::errors::{Result, TopologyError};
use crate::topology_parts::validation::validate_topology_requirements;
use karstflow_core::TopologySpec;
use std::fs;
use std::path::Path;

pub fn load_topology_from_file(topology_path: &Path) -> Result<TopologySpec> {
    let topology_toml =
        fs::read_to_string(topology_path).map_err(|source| TopologyError::TopologyRead {
            path: topology_path.to_path_buf(),
            source,
        })?;

    let topology_spec: TopologySpec =
        toml::from_str(&topology_toml).map_err(|source| TopologyError::TopologyParse {
            path: topology_path.to_path_buf(),
            source,
        })?;

    validate_topology_requirements(&topology_spec)?;
    Ok(topology_spec)
}
