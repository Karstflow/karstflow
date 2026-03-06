use super::common::ensure_nonzero_u64;
use super::types::{StorageEnvOverrides, StorageProfileToml};
use crate::Result;
use karstflow_stages::{LeaderSchedulePolicy, SchedulerRuntimePolicy};

pub(crate) fn apply_leader_schedule_policy_toml(
    leader_schedule_policy: &mut LeaderSchedulePolicy,
    storage_profile: &StorageProfileToml,
) -> Result<()> {
    if let Some(value) = storage_profile.leader_schedule_enabled {
        leader_schedule_policy.enabled = value;
    }
    if let Some(value) = storage_profile.leader_slot_cycle_length {
        ensure_nonzero_u64("storage.leader_slot_cycle_length", value)?;
        leader_schedule_policy.slot_cycle_length = value;
    }
    if let Some(value) = storage_profile.leader_slots_per_cycle {
        ensure_nonzero_u64("storage.leader_slots_per_cycle", value)?;
        leader_schedule_policy.leader_slots_per_cycle = value;
    }
    if let Some(value) = storage_profile.leader_initial_slot {
        leader_schedule_policy.initial_slot = value;
    }
    if let Some(value) = storage_profile.leader_hold_retry_delay_millis {
        ensure_nonzero_u64("storage.leader_hold_retry_delay_millis", value)?;
        leader_schedule_policy.hold_retry_delay_millis = value;
    }
    Ok(())
}

pub(crate) fn apply_leader_schedule_policy_env(
    leader_schedule_policy: &mut LeaderSchedulePolicy,
    env_overrides: &StorageEnvOverrides,
) -> Result<()> {
    if let Some(value) = env_overrides.leader_schedule_enabled {
        leader_schedule_policy.enabled = value;
    }
    if let Some(value) = env_overrides.leader_slot_cycle_length {
        ensure_nonzero_u64("KARSTFLOW_STORAGE_LEADER_SLOT_CYCLE_LENGTH", value)?;
        leader_schedule_policy.slot_cycle_length = value;
    }
    if let Some(value) = env_overrides.leader_slots_per_cycle {
        ensure_nonzero_u64("KARSTFLOW_STORAGE_LEADER_SLOTS_PER_CYCLE", value)?;
        leader_schedule_policy.leader_slots_per_cycle = value;
    }
    if let Some(value) = env_overrides.leader_initial_slot {
        leader_schedule_policy.initial_slot = value;
    }
    if let Some(value) = env_overrides.leader_hold_retry_delay_millis {
        ensure_nonzero_u64("KARSTFLOW_STORAGE_LEADER_HOLD_RETRY_DELAY_MILLIS", value)?;
        leader_schedule_policy.hold_retry_delay_millis = value;
    }
    Ok(())
}

pub(crate) fn apply_scheduler_runtime_policy_toml(
    scheduler_runtime_policy: &mut SchedulerRuntimePolicy,
    storage_profile: &StorageProfileToml,
) -> Result<()> {
    if let Some(value) = storage_profile.scheduler_enabled {
        scheduler_runtime_policy.enabled = value;
    }
    if let Some(value) = storage_profile.scheduler_slot_duration_millis {
        ensure_nonzero_u64("storage.scheduler_slot_duration_millis", value)?;
        scheduler_runtime_policy.slot_duration_millis = value;
    }
    if let Some(value) = storage_profile.scheduler_priority_penalty_class_2_millis {
        scheduler_runtime_policy.priority_penalty_class_2_millis = value;
    }
    if let Some(value) = storage_profile.scheduler_priority_penalty_class_3_millis {
        scheduler_runtime_policy.priority_penalty_class_3_millis = value;
    }
    Ok(())
}

pub(crate) fn apply_scheduler_runtime_policy_env(
    scheduler_runtime_policy: &mut SchedulerRuntimePolicy,
    env_overrides: &StorageEnvOverrides,
) -> Result<()> {
    if let Some(value) = env_overrides.scheduler_enabled {
        scheduler_runtime_policy.enabled = value;
    }
    if let Some(value) = env_overrides.scheduler_slot_duration_millis {
        ensure_nonzero_u64("KARSTFLOW_STORAGE_SCHEDULER_SLOT_DURATION_MILLIS", value)?;
        scheduler_runtime_policy.slot_duration_millis = value;
    }
    if let Some(value) = env_overrides.scheduler_priority_penalty_class_2_millis {
        scheduler_runtime_policy.priority_penalty_class_2_millis = value;
    }
    if let Some(value) = env_overrides.scheduler_priority_penalty_class_3_millis {
        scheduler_runtime_policy.priority_penalty_class_3_millis = value;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leader_toml_noop_when_all_none() {
        let mut policy = LeaderSchedulePolicy::default();
        let original = policy;
        let profile = StorageProfileToml::default();
        apply_leader_schedule_policy_toml(&mut policy, &profile).unwrap();
        assert_eq!(policy, original);
    }

    #[test]
    fn leader_toml_applies_values() {
        let mut policy = LeaderSchedulePolicy::default();
        let profile = StorageProfileToml {
            leader_schedule_enabled: Some(true),
            leader_slot_cycle_length: Some(8),
            leader_slots_per_cycle: Some(2),
            leader_initial_slot: Some(100),
            leader_hold_retry_delay_millis: Some(50),
            ..Default::default()
        };
        apply_leader_schedule_policy_toml(&mut policy, &profile).unwrap();
        assert!(policy.enabled);
        assert_eq!(policy.slot_cycle_length, 8);
        assert_eq!(policy.leader_slots_per_cycle, 2);
        assert_eq!(policy.initial_slot, 100);
        assert_eq!(policy.hold_retry_delay_millis, 50);
    }

    #[test]
    fn leader_toml_rejects_zero_cycle_length() {
        let mut policy = LeaderSchedulePolicy::default();
        let profile = StorageProfileToml {
            leader_slot_cycle_length: Some(0),
            ..Default::default()
        };
        assert!(apply_leader_schedule_policy_toml(&mut policy, &profile).is_err());
    }

    #[test]
    fn leader_env_applies_values() {
        let mut policy = LeaderSchedulePolicy::default();
        let env = StorageEnvOverrides {
            leader_schedule_enabled: Some(true),
            leader_slot_cycle_length: Some(16),
            leader_slots_per_cycle: Some(4),
            leader_initial_slot: Some(0),
            leader_hold_retry_delay_millis: Some(100),
            ..Default::default()
        };
        apply_leader_schedule_policy_env(&mut policy, &env).unwrap();
        assert!(policy.enabled);
        assert_eq!(policy.slot_cycle_length, 16);
        assert_eq!(policy.leader_slots_per_cycle, 4);
    }

    #[test]
    fn scheduler_toml_noop_when_all_none() {
        let mut policy = SchedulerRuntimePolicy::default();
        let original = policy;
        let profile = StorageProfileToml::default();
        apply_scheduler_runtime_policy_toml(&mut policy, &profile).unwrap();
        assert_eq!(policy, original);
    }

    #[test]
    fn scheduler_toml_applies_values() {
        let mut policy = SchedulerRuntimePolicy::default();
        let profile = StorageProfileToml {
            scheduler_enabled: Some(true),
            scheduler_slot_duration_millis: Some(100),
            scheduler_priority_penalty_class_2_millis: Some(50),
            scheduler_priority_penalty_class_3_millis: Some(150),
            ..Default::default()
        };
        apply_scheduler_runtime_policy_toml(&mut policy, &profile).unwrap();
        assert!(policy.enabled);
        assert_eq!(policy.slot_duration_millis, 100);
        assert_eq!(policy.priority_penalty_class_2_millis, 50);
        assert_eq!(policy.priority_penalty_class_3_millis, 150);
    }

    #[test]
    fn scheduler_toml_rejects_zero_slot_duration() {
        let mut policy = SchedulerRuntimePolicy::default();
        let profile = StorageProfileToml {
            scheduler_slot_duration_millis: Some(0),
            ..Default::default()
        };
        assert!(apply_scheduler_runtime_policy_toml(&mut policy, &profile).is_err());
    }

    #[test]
    fn scheduler_env_applies_values() {
        let mut policy = SchedulerRuntimePolicy::default();
        let env = StorageEnvOverrides {
            scheduler_enabled: Some(true),
            scheduler_slot_duration_millis: Some(200),
            ..Default::default()
        };
        apply_scheduler_runtime_policy_env(&mut policy, &env).unwrap();
        assert!(policy.enabled);
        assert_eq!(policy.slot_duration_millis, 200);
    }
}
