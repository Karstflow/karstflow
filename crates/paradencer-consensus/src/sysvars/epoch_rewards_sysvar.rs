/// EpochRewards sysvar serialization wrapper.
///
/// Wraps the existing `EpochRewards` type to provide account-level
/// serialization. This sysvar is active only during partitioned reward
/// distribution and signals to programs that epoch rewards are still
/// being distributed (preventing certain stake operations).

use crate::EpochRewards;

/// Serializable wrapper for the EpochRewards sysvar.
///
/// When rewards are being distributed across multiple blocks, this sysvar
/// is present and populated. Once distribution completes, it is cleared.
#[derive(Debug, Clone, PartialEq)]
pub struct EpochRewardsSysvar {
    /// Active reward state, or `None` when rewards are not being distributed.
    pub rewards: Option<EpochRewards>,
}

impl EpochRewardsSysvar {
    pub fn active(rewards: EpochRewards) -> Self {
        Self {
            rewards: Some(rewards),
        }
    }

    pub fn inactive() -> Self {
        Self { rewards: None }
    }

    /// Whether epoch rewards distribution is currently active.
    pub fn is_active(&self) -> bool {
        self.rewards.is_some()
    }

    /// Serialize to bytes for sysvar account data.
    ///
    /// Format: active(u8) + if active: total_rewards(u64) + validator_rewards(u64)
    ///         + foundation_rewards(u64) + capitalization(u64)
    ///         + epoch_duration_years(f64) + validator_rate(f64) + foundation_rate(f64).
    pub fn to_bytes(&self) -> Vec<u8> {
        match &self.rewards {
            None => vec![0u8],
            Some(r) => {
                let mut buf = Vec::with_capacity(57);
                buf.push(1u8);
                buf.extend_from_slice(&r.total_rewards.to_le_bytes());
                buf.extend_from_slice(&r.validator_rewards.to_le_bytes());
                buf.extend_from_slice(&r.foundation_rewards.to_le_bytes());
                buf.extend_from_slice(&r.capitalization.to_le_bytes());
                buf.extend_from_slice(&r.epoch_duration_years.to_le_bytes());
                buf.extend_from_slice(&r.validator_rate.to_le_bytes());
                buf.extend_from_slice(&r.foundation_rate.to_le_bytes());
                buf
            }
        }
    }

    /// Deserialize from sysvar account data bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }
        if data[0] == 0 {
            return Some(Self::inactive());
        }
        if data.len() < 57 {
            return None;
        }
        let total_rewards = u64::from_le_bytes(data[1..9].try_into().ok()?);
        let validator_rewards = u64::from_le_bytes(data[9..17].try_into().ok()?);
        let foundation_rewards = u64::from_le_bytes(data[17..25].try_into().ok()?);
        let capitalization = u64::from_le_bytes(data[25..33].try_into().ok()?);
        let epoch_duration_years = f64::from_le_bytes(data[33..41].try_into().ok()?);
        let validator_rate = f64::from_le_bytes(data[41..49].try_into().ok()?);
        let foundation_rate = f64::from_le_bytes(data[49..57].try_into().ok()?);
        Some(Self::active(EpochRewards {
            total_rewards,
            validator_rewards,
            foundation_rewards,
            capitalization,
            epoch_duration_years,
            validator_rate,
            foundation_rate,
        }))
    }
}

impl Default for EpochRewardsSysvar {
    fn default() -> Self {
        Self::inactive()
    }
}
