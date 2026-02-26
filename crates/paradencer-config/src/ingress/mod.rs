mod env;
mod profile;
mod types;

pub use types::IngressPolicyToml;

use crate::profile_schema::INGRESS_POLICY_SCHEMA_VERSION;
use crate::profile_types::NodeProfileToml;
use crate::{ConfigError, Result};
use env::apply_env_overrides;
use paradencer_net::IngressPolicy;
use profile::{apply_profile, load_ingress_policy_from_file};
use std::path::PathBuf;
use tracing::info;

pub fn build_ingress_policy(profile: Option<&NodeProfileToml>) -> Result<IngressPolicy> {
    let mut ingress_policy = IngressPolicy::default();

    if let Some(profile_ingress_policy) =
        profile.and_then(|profile| profile.ingress_policy.as_ref())
    {
        apply_profile(&mut ingress_policy, profile_ingress_policy)?;
    }

    if let Ok(path_value) = std::env::var("PARADENCER_INGRESS_POLICY_PATH") {
        let policy_path = PathBuf::from(path_value);
        info!(path = %policy_path.display(), "loading ingress policy profile");
        let policy_profile = load_ingress_policy_from_file(&policy_path)?;
        apply_profile(&mut ingress_policy, &policy_profile)?;
    }

    apply_env_overrides(&mut ingress_policy)?;
    ingress_policy
        .validate()
        .map_err(|error| ConfigError::InvalidScope {
            scope: "ingress policy",
            message: error.to_string(),
        })?;

    Ok(ingress_policy)
}

#[cfg(test)]
pub fn parse_ingress_policy_toml(policy_toml: &str) -> Result<IngressPolicyToml> {
    toml::from_str::<IngressPolicyToml>(policy_toml).map_err(|source| {
        ConfigError::InlineTomlParse {
            kind: "ingress policy",
            message: source.to_string(),
        }
    })
}

pub fn migrate_ingress_policy_schema(mut profile: IngressPolicyToml) -> Result<IngressPolicyToml> {
    let schema_version = profile
        .schema_version
        .unwrap_or(INGRESS_POLICY_SCHEMA_VERSION);
    match schema_version {
        INGRESS_POLICY_SCHEMA_VERSION => Ok(profile),
        0 => {
            info!(
                from = 0,
                to = INGRESS_POLICY_SCHEMA_VERSION,
                "migrating ingress policy schema",
            );
            profile.schema_version = Some(INGRESS_POLICY_SCHEMA_VERSION);
            Ok(profile)
        }
        _ => Err(ConfigError::UnsupportedIngressPolicySchemaVersion {
            found: schema_version,
            expected: INGRESS_POLICY_SCHEMA_VERSION,
        }),
    }
}
