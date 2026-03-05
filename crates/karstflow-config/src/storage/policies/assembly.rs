use super::common::{ensure_nonzero_u32, ensure_nonzero_u64, ensure_nonzero_usize};
use super::types::{StorageEnvOverrides, StorageProfileToml};
use crate::Result;
use karstflow_stages::AssemblyPolicy;

pub(crate) fn apply_assembly_policy_toml(
    assembly_policy: &mut AssemblyPolicy,
    storage_profile: &StorageProfileToml,
) -> Result<()> {
    if let Some(value) = storage_profile.assembly_max_fragment_transactions {
        ensure_nonzero_usize("storage.assembly_max_fragment_transactions", value)?;
        assembly_policy.max_fragment_transactions = value;
    }
    if let Some(value) = storage_profile.assembly_max_fragment_cost_units {
        ensure_nonzero_u64("storage.assembly_max_fragment_cost_units", value)?;
        assembly_policy.max_fragment_cost_units = value;
    }
    if let Some(value) = storage_profile.assembly_max_fragment_wait_ticks {
        ensure_nonzero_u32("storage.assembly_max_fragment_wait_ticks", value)?;
        assembly_policy.max_fragment_wait_ticks = value;
    }
    Ok(())
}

pub(crate) fn apply_assembly_policy_env(
    assembly_policy: &mut AssemblyPolicy,
    env_overrides: &StorageEnvOverrides,
) -> Result<()> {
    if let Some(value) = env_overrides.assembly_max_fragment_transactions {
        ensure_nonzero_usize(
            "KARSTFLOW_STORAGE_ASSEMBLY_MAX_FRAGMENT_TRANSACTIONS",
            value,
        )?;
        assembly_policy.max_fragment_transactions = value;
    }
    if let Some(value) = env_overrides.assembly_max_fragment_cost_units {
        ensure_nonzero_u64("KARSTFLOW_STORAGE_ASSEMBLY_MAX_FRAGMENT_COST_UNITS", value)?;
        assembly_policy.max_fragment_cost_units = value;
    }
    if let Some(value) = env_overrides.assembly_max_fragment_wait_ticks {
        ensure_nonzero_u32("KARSTFLOW_STORAGE_ASSEMBLY_MAX_FRAGMENT_WAIT_TICKS", value)?;
        assembly_policy.max_fragment_wait_ticks = value;
    }
    Ok(())
}
