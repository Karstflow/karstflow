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
