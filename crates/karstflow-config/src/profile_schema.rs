use crate::profile_types::NodeProfileToml;
use crate::{ConfigError, Result};
use tracing::info;

pub const NODE_CONFIG_SCHEMA_VERSION: u32 = 1;
pub const INGRESS_POLICY_SCHEMA_VERSION: u32 = 1;

pub fn migrate_node_profile_schema(mut profile: NodeProfileToml) -> Result<NodeProfileToml> {
    let schema_version = profile.schema_version.unwrap_or(NODE_CONFIG_SCHEMA_VERSION);
    match schema_version {
        NODE_CONFIG_SCHEMA_VERSION => Ok(profile),
        0 => {
            info!(
                from = 0,
                to = NODE_CONFIG_SCHEMA_VERSION,
                "migrating node config schema",
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

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_profile() -> NodeProfileToml {
        toml::from_str("").unwrap()
    }

    #[test]
    fn migrate_current_version_is_noop() {
        let mut profile = empty_profile();
        profile.schema_version = Some(NODE_CONFIG_SCHEMA_VERSION);
        let result = migrate_node_profile_schema(profile).unwrap();
        assert_eq!(result.schema_version, Some(NODE_CONFIG_SCHEMA_VERSION));
    }

    #[test]
    fn migrate_none_treated_as_current() {
        let profile = empty_profile();
        assert!(profile.schema_version.is_none());
        // None defaults to current version — passes through unchanged.
        let result = migrate_node_profile_schema(profile).unwrap();
        assert!(result.schema_version.is_none());
    }

    #[test]
    fn migrate_v0_upgrades_to_current() {
        let mut profile = empty_profile();
        profile.schema_version = Some(0);
        let result = migrate_node_profile_schema(profile).unwrap();
        assert_eq!(result.schema_version, Some(NODE_CONFIG_SCHEMA_VERSION));
    }

    #[test]
    fn migrate_unsupported_version_errors() {
        let mut profile = empty_profile();
        profile.schema_version = Some(999);
        assert!(migrate_node_profile_schema(profile).is_err());
    }
}
