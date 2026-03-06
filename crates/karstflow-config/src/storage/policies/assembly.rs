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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toml_noop_when_all_none() {
        let mut policy = AssemblyPolicy::default();
        let original = policy;
        let profile = StorageProfileToml::default();
        apply_assembly_policy_toml(&mut policy, &profile).unwrap();
        assert_eq!(policy, original);
    }

    #[test]
    fn toml_applies_values() {
        let mut policy = AssemblyPolicy::default();
        let profile = StorageProfileToml {
            assembly_max_fragment_transactions: Some(128),
            assembly_max_fragment_cost_units: Some(512_000),
            assembly_max_fragment_wait_ticks: Some(16),
            ..Default::default()
        };
        apply_assembly_policy_toml(&mut policy, &profile).unwrap();
        assert_eq!(policy.max_fragment_transactions, 128);
        assert_eq!(policy.max_fragment_cost_units, 512_000);
        assert_eq!(policy.max_fragment_wait_ticks, 16);
    }

    #[test]
    fn toml_rejects_zero_transactions() {
        let mut policy = AssemblyPolicy::default();
        let profile = StorageProfileToml {
            assembly_max_fragment_transactions: Some(0),
            ..Default::default()
        };
        assert!(apply_assembly_policy_toml(&mut policy, &profile).is_err());
    }

    #[test]
    fn toml_rejects_zero_cost_units() {
        let mut policy = AssemblyPolicy::default();
        let profile = StorageProfileToml {
            assembly_max_fragment_cost_units: Some(0),
            ..Default::default()
        };
        assert!(apply_assembly_policy_toml(&mut policy, &profile).is_err());
    }

    #[test]
    fn env_applies_values() {
        let mut policy = AssemblyPolicy::default();
        let env = StorageEnvOverrides {
            assembly_max_fragment_transactions: Some(256),
            assembly_max_fragment_cost_units: Some(1_024_000),
            assembly_max_fragment_wait_ticks: Some(32),
            ..Default::default()
        };
        apply_assembly_policy_env(&mut policy, &env).unwrap();
        assert_eq!(policy.max_fragment_transactions, 256);
        assert_eq!(policy.max_fragment_cost_units, 1_024_000);
        assert_eq!(policy.max_fragment_wait_ticks, 32);
    }

    #[test]
    fn env_rejects_zero_wait_ticks() {
        let mut policy = AssemblyPolicy::default();
        let env = StorageEnvOverrides {
            assembly_max_fragment_wait_ticks: Some(0),
            ..Default::default()
        };
        assert!(apply_assembly_policy_env(&mut policy, &env).is_err());
    }
}
