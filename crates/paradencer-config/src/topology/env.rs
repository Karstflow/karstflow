use crate::{ConfigError, Result};

pub(super) fn resolve_topology_path(profile_path: Option<&str>) -> Option<std::path::PathBuf> {
    let mut topology_path = profile_path.map(std::path::PathBuf::from);

    if let Ok(path_value) = std::env::var("PARADENCER_TOPOLOGY_PATH") {
        topology_path = Some(std::path::PathBuf::from(path_value));
    }

    topology_path
}

pub(super) fn parse_optional_usize_env(name: &str) -> Result<Option<usize>> {
    match std::env::var(name).ok() {
        Some(raw) => {
            let value = raw
                .parse::<usize>()
                .map_err(|source| ConfigError::EnvParseInt {
                    name: name.to_string(),
                    ty: "usize",
                    source,
                })?;
            if value == 0 {
                Err(ConfigError::NonPositiveValue {
                    name: name.to_string(),
                })
            } else {
                Ok(Some(value))
            }
        }
        None => Ok(None),
    }
}

pub(super) fn ensure_nonzero_usize(name: &str, value: usize) -> Result<usize> {
    if value == 0 {
        return Err(ConfigError::NonPositiveValue {
            name: name.to_string(),
        });
    }
    Ok(value)
}
