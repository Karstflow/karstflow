mod env;
mod parsers;
mod profile;
mod types;

#[cfg(test)]
pub use parsers::{map_legacy_core_sharing_flag, parse_execution_mode, parse_pinned_core_policy};
pub use types::RuntimeProfileToml;

use crate::profile_types::NodeProfileToml;
use crate::Result;
use env::apply_env_overrides;
use karstflow_core::{ExecutionMode, PinnedCorePolicy, RuntimeSpec};
use profile::apply_profile;

pub fn build_runtime_spec(profile: Option<&NodeProfileToml>) -> Result<RuntimeSpec> {
    let mut runtime_spec = RuntimeSpec {
        mode: ExecutionMode::Tokio,
        workers: 4,
        run_for_seconds: Some(10),
        pinned_core_policy: PinnedCorePolicy::Adaptive,
        pinned_allow_core_sharing: true,
        pinned_service_core_ids: None,
    };

    if let Some(runtime_profile) = profile.and_then(|node_profile| node_profile.runtime.as_ref()) {
        apply_profile(&mut runtime_spec, runtime_profile)?;
    }

    apply_env_overrides(&mut runtime_spec)?;
    Ok(runtime_spec)
}
