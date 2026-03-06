use super::common::{ensure_nonzero_u32, ensure_nonzero_u64, ensure_nonzero_usize};
use super::types::{StorageEnvOverrides, StorageProfileToml};
use crate::Result;
use karstflow_stages::ReplayControllerPolicy;

pub(crate) fn apply_replay_controller_policy_toml(
    replay_controller_policy: &mut ReplayControllerPolicy,
    storage_profile: &StorageProfileToml,
) -> Result<()> {
    if let Some(value) = storage_profile.replay_controller_candidate_confirmation_threshold {
        ensure_nonzero_u32(
            "storage.replay_controller_candidate_confirmation_threshold",
            value,
        )?;
        replay_controller_policy.candidate_confirmation_threshold = value;
    }
    if let Some(value) =
        storage_profile.replay_controller_candidate_confirmation_max_failed_ratio_bps
    {
        ensure_nonzero_u32(
            "storage.replay_controller_candidate_confirmation_max_failed_ratio_bps",
            value,
        )?;
        replay_controller_policy.candidate_confirmation_max_failed_ratio_bps = value;
    }
    if let Some(value) = storage_profile.replay_controller_max_candidates {
        ensure_nonzero_usize("storage.replay_controller_max_candidates", value)?;
        replay_controller_policy.max_candidates = value;
    }
    if let Some(value) = storage_profile.replay_controller_reorg_signal_weight {
        ensure_nonzero_u64("storage.replay_controller_reorg_signal_weight", value)?;
        replay_controller_policy.reorg_signal_weight = value;
    }
    if let Some(value) = storage_profile.replay_controller_fragment_recency_weight {
        ensure_nonzero_u64("storage.replay_controller_fragment_recency_weight", value)?;
        replay_controller_policy.fragment_recency_weight = value;
    }
    if let Some(value) = storage_profile.replay_controller_failed_transaction_ratio_penalty_weight {
        ensure_nonzero_u64(
            "storage.replay_controller_failed_transaction_ratio_penalty_weight",
            value,
        )?;
        replay_controller_policy.failed_transaction_ratio_penalty_weight = value;
    }
    if let Some(value) = storage_profile.replay_controller_candidate_stale_fragment_lag {
        ensure_nonzero_u64(
            "storage.replay_controller_candidate_stale_fragment_lag",
            value,
        )?;
        replay_controller_policy.candidate_stale_fragment_lag = value;
    }
    if let Some(value) = storage_profile.replay_controller_candidate_switch_min_score_delta {
        ensure_nonzero_u64(
            "storage.replay_controller_candidate_switch_min_score_delta",
            value,
        )?;
        replay_controller_policy.candidate_switch_min_score_delta = value;
    }
    Ok(())
}

pub(crate) fn apply_replay_controller_policy_env(
    replay_controller_policy: &mut ReplayControllerPolicy,
    env_overrides: &StorageEnvOverrides,
) -> Result<()> {
    if let Some(value) = env_overrides.replay_controller_candidate_confirmation_threshold {
        ensure_nonzero_u32(
            "KARSTFLOW_STORAGE_REPLAY_CONTROLLER_CANDIDATE_CONFIRMATION_THRESHOLD",
            value,
        )?;
        replay_controller_policy.candidate_confirmation_threshold = value;
    }
    if let Some(value) = env_overrides.replay_controller_candidate_confirmation_max_failed_ratio_bps
    {
        ensure_nonzero_u32(
            "KARSTFLOW_STORAGE_REPLAY_CONTROLLER_CANDIDATE_CONFIRMATION_MAX_FAILED_RATIO_BPS",
            value,
        )?;
        replay_controller_policy.candidate_confirmation_max_failed_ratio_bps = value;
    }
    if let Some(value) = env_overrides.replay_controller_max_candidates {
        ensure_nonzero_usize("KARSTFLOW_STORAGE_REPLAY_CONTROLLER_MAX_CANDIDATES", value)?;
        replay_controller_policy.max_candidates = value;
    }
    if let Some(value) = env_overrides.replay_controller_reorg_signal_weight {
        ensure_nonzero_u64(
            "KARSTFLOW_STORAGE_REPLAY_CONTROLLER_REORG_SIGNAL_WEIGHT",
            value,
        )?;
        replay_controller_policy.reorg_signal_weight = value;
    }
    if let Some(value) = env_overrides.replay_controller_fragment_recency_weight {
        ensure_nonzero_u64(
            "KARSTFLOW_STORAGE_REPLAY_CONTROLLER_FRAGMENT_RECENCY_WEIGHT",
            value,
        )?;
        replay_controller_policy.fragment_recency_weight = value;
    }
    if let Some(value) = env_overrides.replay_controller_failed_transaction_ratio_penalty_weight {
        ensure_nonzero_u64(
            "KARSTFLOW_STORAGE_REPLAY_CONTROLLER_FAILED_TRANSACTION_RATIO_PENALTY_WEIGHT",
            value,
        )?;
        replay_controller_policy.failed_transaction_ratio_penalty_weight = value;
    }
    if let Some(value) = env_overrides.replay_controller_candidate_stale_fragment_lag {
        ensure_nonzero_u64(
            "KARSTFLOW_STORAGE_REPLAY_CONTROLLER_CANDIDATE_STALE_FRAGMENT_LAG",
            value,
        )?;
        replay_controller_policy.candidate_stale_fragment_lag = value;
    }
    if let Some(value) = env_overrides.replay_controller_candidate_switch_min_score_delta {
        ensure_nonzero_u64(
            "KARSTFLOW_STORAGE_REPLAY_CONTROLLER_CANDIDATE_SWITCH_MIN_SCORE_DELTA",
            value,
        )?;
        replay_controller_policy.candidate_switch_min_score_delta = value;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toml_noop_when_all_none() {
        let mut policy = ReplayControllerPolicy::default();
        let original = policy;
        let profile = StorageProfileToml::default();
        apply_replay_controller_policy_toml(&mut policy, &profile).unwrap();
        assert_eq!(policy, original);
    }

    #[test]
    fn toml_applies_values() {
        let mut policy = ReplayControllerPolicy::default();
        let profile = StorageProfileToml {
            replay_controller_candidate_confirmation_threshold: Some(4),
            replay_controller_candidate_confirmation_max_failed_ratio_bps: Some(8_000),
            replay_controller_max_candidates: Some(16),
            replay_controller_reorg_signal_weight: Some(2_000_000),
            replay_controller_fragment_recency_weight: Some(5),
            replay_controller_failed_transaction_ratio_penalty_weight: Some(100),
            replay_controller_candidate_stale_fragment_lag: Some(256),
            replay_controller_candidate_switch_min_score_delta: Some(50_000),
            ..Default::default()
        };
        apply_replay_controller_policy_toml(&mut policy, &profile).unwrap();
        assert_eq!(policy.candidate_confirmation_threshold, 4);
        assert_eq!(policy.candidate_confirmation_max_failed_ratio_bps, 8_000);
        assert_eq!(policy.max_candidates, 16);
        assert_eq!(policy.reorg_signal_weight, 2_000_000);
        assert_eq!(policy.fragment_recency_weight, 5);
        assert_eq!(policy.failed_transaction_ratio_penalty_weight, 100);
        assert_eq!(policy.candidate_stale_fragment_lag, 256);
        assert_eq!(policy.candidate_switch_min_score_delta, 50_000);
    }

    #[test]
    fn toml_rejects_zero_confirmation_threshold() {
        let mut policy = ReplayControllerPolicy::default();
        let profile = StorageProfileToml {
            replay_controller_candidate_confirmation_threshold: Some(0),
            ..Default::default()
        };
        assert!(apply_replay_controller_policy_toml(&mut policy, &profile).is_err());
    }

    #[test]
    fn toml_rejects_zero_max_candidates() {
        let mut policy = ReplayControllerPolicy::default();
        let profile = StorageProfileToml {
            replay_controller_max_candidates: Some(0),
            ..Default::default()
        };
        assert!(apply_replay_controller_policy_toml(&mut policy, &profile).is_err());
    }

    #[test]
    fn env_applies_values() {
        let mut policy = ReplayControllerPolicy::default();
        let env = StorageEnvOverrides {
            replay_controller_candidate_confirmation_threshold: Some(3),
            replay_controller_max_candidates: Some(12),
            replay_controller_reorg_signal_weight: Some(500_000),
            ..Default::default()
        };
        apply_replay_controller_policy_env(&mut policy, &env).unwrap();
        assert_eq!(policy.candidate_confirmation_threshold, 3);
        assert_eq!(policy.max_candidates, 12);
        assert_eq!(policy.reorg_signal_weight, 500_000);
    }

    #[test]
    fn env_rejects_zero_reorg_signal_weight() {
        let mut policy = ReplayControllerPolicy::default();
        let env = StorageEnvOverrides {
            replay_controller_reorg_signal_weight: Some(0),
            ..Default::default()
        };
        assert!(apply_replay_controller_policy_env(&mut policy, &env).is_err());
    }
}
