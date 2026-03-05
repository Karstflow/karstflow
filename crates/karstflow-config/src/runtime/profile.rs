use super::parsers::{
    ensure_nonzero_usize, map_legacy_core_sharing_flag, parse_execution_mode,
    parse_pinned_core_policy, parse_pinned_service_core_ids,
};
use super::types::RuntimeProfileToml;
use crate::Result;
use karstflow_core::RuntimeSpec;

pub(super) fn apply_profile(
    runtime_spec: &mut RuntimeSpec,
    runtime_profile: &RuntimeProfileToml,
) -> Result<()> {
    if let Some(mode_value) = runtime_profile.mode.as_deref() {
        runtime_spec.mode = parse_execution_mode(Some(mode_value.to_string()))?;
    }
    if let Some(workers) = runtime_profile.workers {
        runtime_spec.workers = ensure_nonzero_usize("workers", workers)?;
    }
    if let Some(run_for_seconds) = runtime_profile.run_for_seconds {
        runtime_spec.run_for_seconds = Some(run_for_seconds);
    }
    if let Some(allow_core_sharing) = runtime_profile.pinned_allow_core_sharing {
        runtime_spec.pinned_allow_core_sharing = allow_core_sharing;
        runtime_spec.pinned_core_policy = map_legacy_core_sharing_flag(allow_core_sharing);
    }
    if let Some(policy_value) = runtime_profile.pinned_core_policy.as_deref() {
        runtime_spec.pinned_core_policy = parse_pinned_core_policy(Some(policy_value.to_string()))?;
    }
    if let Some(core_ids) = runtime_profile.pinned_service_core_ids.as_deref() {
        runtime_spec.pinned_service_core_ids = Some(parse_pinned_service_core_ids(
            core_ids,
            "runtime.pinned_service_core_ids",
        )?);
    }

    Ok(())
}
