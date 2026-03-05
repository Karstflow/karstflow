use serde::Deserialize;
use std::collections::HashSet;

/// Feature activation configuration from TOML profile.
#[derive(Debug, Default, Deserialize)]
pub struct FeaturesProfileToml {
    /// Override mode: "none" (default), "all_enabled", "all_disabled".
    pub override_mode: Option<String>,
    /// Feature pubkeys (base58) to explicitly enable.
    pub enabled: Option<Vec<String>>,
    /// Feature pubkeys (base58) to explicitly disable.
    pub disabled: Option<Vec<String>>,
}

/// Parsed feature activation configuration.
#[derive(Debug, Clone)]
pub struct FeatureActivationConfig {
    /// How to handle feature activation relative to the on-chain state.
    pub override_mode: FeatureOverrideMode,
    /// Explicit feature pubkeys to enable (base58 strings).
    pub enabled_features: HashSet<String>,
    /// Explicit feature pubkeys to disable (base58 strings).
    pub disabled_features: HashSet<String>,
}

/// Feature override mode determines how config-specified features interact
/// with on-chain activation state loaded from snapshots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeatureOverrideMode {
    /// Use on-chain activation state from snapshot (default).
    NoOverrides,
    /// Force all known features enabled (for testing).
    AllEnabled,
    /// Force all features disabled (for testing minimal feature set).
    AllDisabled,
}

impl Default for FeatureActivationConfig {
    fn default() -> Self {
        Self {
            override_mode: FeatureOverrideMode::NoOverrides,
            enabled_features: HashSet::new(),
            disabled_features: HashSet::new(),
        }
    }
}

pub fn build_feature_activation_config(
    profile: Option<&FeaturesProfileToml>,
) -> FeatureActivationConfig {
    let mut config = FeatureActivationConfig::default();

    // Env override takes priority.
    if let Ok(mode) = std::env::var("KARSTFLOW_FEATURE_OVERRIDE_MODE") {
        config.override_mode = parse_override_mode(&mode);
    } else if let Some(p) = profile {
        if let Some(ref mode) = p.override_mode {
            config.override_mode = parse_override_mode(mode);
        }
    }

    // Enabled features: env → TOML.
    if let Ok(enabled) = std::env::var("KARSTFLOW_FEATURE_ENABLED") {
        config.enabled_features = parse_feature_list(&enabled);
    } else if let Some(p) = profile {
        if let Some(ref list) = p.enabled {
            config.enabled_features = list.iter().cloned().collect();
        }
    }

    // Disabled features: env → TOML.
    if let Ok(disabled) = std::env::var("KARSTFLOW_FEATURE_DISABLED") {
        config.disabled_features = parse_feature_list(&disabled);
    } else if let Some(p) = profile {
        if let Some(ref list) = p.disabled {
            config.disabled_features = list.iter().cloned().collect();
        }
    }

    config
}

fn parse_override_mode(s: &str) -> FeatureOverrideMode {
    match s.to_ascii_lowercase().as_str() {
        "all" | "all_enabled" => FeatureOverrideMode::AllEnabled,
        "none_enabled" | "all_disabled" => FeatureOverrideMode::AllDisabled,
        _ => FeatureOverrideMode::NoOverrides,
    }
}

fn parse_feature_list(s: &str) -> HashSet<String> {
    s.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let config = FeatureActivationConfig::default();
        assert_eq!(config.override_mode, FeatureOverrideMode::NoOverrides);
        assert!(config.enabled_features.is_empty());
        assert!(config.disabled_features.is_empty());
    }

    #[test]
    fn build_from_none() {
        let config = build_feature_activation_config(None);
        assert_eq!(config.override_mode, FeatureOverrideMode::NoOverrides);
    }

    #[test]
    fn build_from_profile() {
        let profile = FeaturesProfileToml {
            override_mode: Some("all_enabled".to_string()),
            enabled: Some(vec![
                "Feature111111111111111111111111111111111111111".to_string(),
            ]),
            disabled: None,
        };
        let config = build_feature_activation_config(Some(&profile));
        assert_eq!(config.override_mode, FeatureOverrideMode::AllEnabled);
        assert!(config
            .enabled_features
            .contains("Feature111111111111111111111111111111111111111"));
    }

    #[test]
    fn build_all_disabled_mode() {
        let profile = FeaturesProfileToml {
            override_mode: Some("all_disabled".to_string()),
            enabled: None,
            disabled: Some(vec!["SomeFeature".to_string()]),
        };
        let config = build_feature_activation_config(Some(&profile));
        assert_eq!(config.override_mode, FeatureOverrideMode::AllDisabled);
        assert!(config.disabled_features.contains("SomeFeature"));
    }

    #[test]
    fn parse_feature_list_comma_separated() {
        let result = parse_feature_list("feat1, feat2 , feat3");
        assert_eq!(result.len(), 3);
        assert!(result.contains("feat1"));
        assert!(result.contains("feat2"));
        assert!(result.contains("feat3"));
    }

    #[test]
    fn parse_feature_list_empty() {
        let result = parse_feature_list("");
        assert!(result.is_empty());
    }

    #[test]
    fn unknown_override_mode_defaults_to_none() {
        assert_eq!(
            parse_override_mode("garbage"),
            FeatureOverrideMode::NoOverrides
        );
    }
}
