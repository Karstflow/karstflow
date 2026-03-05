use std::path::{Path, PathBuf};

use crate::error::{PluginError, PluginResult};

/// Parsed plugin configuration from a JSON file.
///
/// Each plugin config file must contain at least a `"libpath"` field pointing
/// to the shared library. All other fields are plugin-specific and passed
/// through to the plugin's `on_load()` method.
#[derive(Debug, Clone)]
pub struct PluginConfig {
    /// Path to the shared library (.so / .dylib).
    pub lib_path: PathBuf,
    /// Optional display name override. If absent, the plugin's `name()` is used.
    pub name: Option<String>,
    /// Path to the original config file (passed to plugin's on_load).
    pub config_file: PathBuf,
}

impl PluginConfig {
    /// Parse a plugin configuration from a JSON file.
    ///
    /// The JSON must contain a `"libpath"` string field. If `libpath` is relative,
    /// it is resolved relative to the config file's directory.
    pub fn from_file(config_path: &Path) -> PluginResult<Self> {
        let content = std::fs::read_to_string(config_path)?;
        let parsed: serde_json::Value =
            serde_json::from_str(&content).map_err(|e| PluginError::ConfigParse(e.to_string()))?;

        let lib_path_str = parsed
            .get("libpath")
            .and_then(|v| v.as_str())
            .ok_or(PluginError::LibraryPathMissing)?;

        let mut lib_path = PathBuf::from(lib_path_str);

        // Resolve relative paths against config file directory.
        if lib_path.is_relative() {
            if let Some(config_dir) = config_path.parent() {
                lib_path = config_dir.join(lib_path);
            }
        }

        let name = parsed
            .get("name")
            .and_then(|v| v.as_str())
            .map(String::from);

        Ok(Self {
            lib_path,
            name,
            config_file: config_path.to_path_buf(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn parse_config_with_absolute_libpath() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(
            f,
            r#"{{"libpath": "/usr/lib/libmyplugin.so", "name": "test"}}"#
        )
        .unwrap();

        let cfg = PluginConfig::from_file(f.path()).unwrap();
        assert_eq!(cfg.lib_path, PathBuf::from("/usr/lib/libmyplugin.so"));
        assert_eq!(cfg.name.as_deref(), Some("test"));
    }

    #[test]
    fn parse_config_with_relative_libpath() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("plugin.json");
        std::fs::write(&config_path, r#"{"libpath": "libs/plugin.so"}"#).unwrap();

        let cfg = PluginConfig::from_file(&config_path).unwrap();
        assert_eq!(cfg.lib_path, dir.path().join("libs/plugin.so"));
        assert!(cfg.name.is_none());
    }

    #[test]
    fn missing_libpath_returns_error() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, r#"{{"name": "no-lib"}}"#).unwrap();

        let result = PluginConfig::from_file(f.path());
        assert!(matches!(result, Err(PluginError::LibraryPathMissing)));
    }

    #[test]
    fn invalid_json_returns_error() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "not json").unwrap();

        let result = PluginConfig::from_file(f.path());
        assert!(matches!(result, Err(PluginError::ConfigParse(_))));
    }
}
