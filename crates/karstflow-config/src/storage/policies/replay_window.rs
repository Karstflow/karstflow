use super::common::ensure_nonzero_usize;
use super::types::{StorageEnvOverrides, StorageProfileToml};
use crate::Result;
use karstflow_stages::ReplayWindowPolicy;

pub(crate) fn apply_replay_window_policy_toml(
    replay_window_policy: &mut ReplayWindowPolicy,
    storage_profile: &StorageProfileToml,
) -> Result<()> {
    if let Some(value) = storage_profile.replay_window_max_checkpoints {
        ensure_nonzero_usize("storage.replay_window_max_checkpoints", value)?;
        replay_window_policy.max_checkpoints = value;
    }
    if let Some(value) = storage_profile.replay_window_rewind_on_confirmed_reorg {
        replay_window_policy.rewind_on_confirmed_reorg = value;
    }
    Ok(())
}

pub(crate) fn apply_replay_window_policy_env(
    replay_window_policy: &mut ReplayWindowPolicy,
    env_overrides: &StorageEnvOverrides,
) -> Result<()> {
    if let Some(value) = env_overrides.replay_window_max_checkpoints {
        ensure_nonzero_usize("KARSTFLOW_STORAGE_REPLAY_WINDOW_MAX_CHECKPOINTS", value)?;
        replay_window_policy.max_checkpoints = value;
    }
    if let Some(value) = env_overrides.replay_window_rewind_on_confirmed_reorg {
        replay_window_policy.rewind_on_confirmed_reorg = value;
    }
    Ok(())
}
