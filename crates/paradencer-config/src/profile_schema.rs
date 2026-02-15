use crate::profile_types::NodeProfileToml;
use crate::{ConfigError, Result};

pub const NODE_CONFIG_SCHEMA_VERSION: u32 = 1;
pub const INGRESS_POLICY_SCHEMA_VERSION: u32 = 1;

pub fn migrate_node_profile_schema(mut profile: NodeProfileToml) -> Result<NodeProfileToml> {
    let schema_version = profile.schema_version.unwrap_or(NODE_CONFIG_SCHEMA_VERSION);
    match schema_version {
        NODE_CONFIG_SCHEMA_VERSION => Ok(profile),
        0 => {
            eprintln!(
                "[config] migrating node config schema_version 0 -> {}",
                NODE_CONFIG_SCHEMA_VERSION
            );
            profile.schema_version = Some(NODE_CONFIG_SCHEMA_VERSION);
            Ok(profile)
        }
        _ => Err(ConfigError::UnsupportedNodeConfigSchemaVersion {
            found: schema_version,
            expected: NODE_CONFIG_SCHEMA_VERSION,
        }),
    }
}
