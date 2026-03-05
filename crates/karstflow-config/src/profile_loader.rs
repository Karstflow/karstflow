use crate::profile_schema::migrate_node_profile_schema;
use crate::profile_types::NodeProfileToml;
use crate::{ConfigError, Result};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::info;

pub fn load_node_profile_from_env() -> Result<Option<NodeProfileToml>> {
    match std::env::var("KARSTFLOW_NODE_CONFIG_PATH") {
        Ok(path_value) => {
            let profile_path = PathBuf::from(path_value);
            info!(path = %profile_path.display(), "loading node profile");
            let profile = load_node_profile_from_file(&profile_path)?;
            Ok(Some(profile))
        }
        Err(_) => Ok(None),
    }
}

pub fn load_node_profile_from_file(path: &Path) -> Result<NodeProfileToml> {
    let profile_toml = fs::read_to_string(path).map_err(|source| ConfigError::FileRead {
        kind: "node config",
        path: path.to_path_buf(),
        source,
    })?;
    let profile = toml::from_str::<NodeProfileToml>(&profile_toml).map_err(|source| {
        ConfigError::FileTomlParse {
            kind: "node config",
            path: path.to_path_buf(),
            message: source.to_string(),
        }
    })?;
    migrate_node_profile_schema(profile)
}

#[cfg(test)]
pub fn parse_node_profile_toml(profile_toml: &str) -> Result<NodeProfileToml> {
    toml::from_str::<NodeProfileToml>(profile_toml).map_err(|source| ConfigError::InlineTomlParse {
        kind: "node config",
        message: source.to_string(),
    })
}
