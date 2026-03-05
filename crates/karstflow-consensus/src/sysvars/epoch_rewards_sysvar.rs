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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_rewards() -> EpochRewards {
        EpochRewards {
            total_rewards: 1_000_000,
            validator_rewards: 800_000,
            foundation_rewards: 200_000,
            capitalization: 500_000_000_000,
            epoch_duration_years: 0.002,
            validator_rate: 0.05,
            foundation_rate: 0.01,
        }
    }

    #[test]
    fn inactive_is_not_active() {
        let sysvar = EpochRewardsSysvar::inactive();
        assert!(!sysvar.is_active());
        assert!(sysvar.rewards.is_none());
    }

    #[test]
    fn active_is_active() {
        let sysvar = EpochRewardsSysvar::active(sample_rewards());
        assert!(sysvar.is_active());
        assert!(sysvar.rewards.is_some());
    }

    #[test]
    fn active_preserves_fields() {
        let rewards = sample_rewards();
        let sysvar = EpochRewardsSysvar::active(rewards.clone());
        let r = sysvar.rewards.unwrap();
        assert_eq!(r.total_rewards, rewards.total_rewards);
        assert_eq!(r.validator_rewards, rewards.validator_rewards);
        assert_eq!(r.foundation_rewards, rewards.foundation_rewards);
        assert_eq!(r.capitalization, rewards.capitalization);
        assert!((r.epoch_duration_years - rewards.epoch_duration_years).abs() < f64::EPSILON);
        assert!((r.validator_rate - rewards.validator_rate).abs() < f64::EPSILON);
        assert!((r.foundation_rate - rewards.foundation_rate).abs() < f64::EPSILON);
    }

    #[test]
    fn serialization_roundtrip_inactive() {
        let sysvar = EpochRewardsSysvar::inactive();
        let bytes = sysvar.to_bytes();
        assert_eq!(bytes.len(), 1);
        assert_eq!(bytes[0], 0);

        let restored = EpochRewardsSysvar::from_bytes(&bytes).unwrap();
        assert!(!restored.is_active());
    }

    #[test]
    fn serialization_roundtrip_active() {
        let rewards = sample_rewards();
        let sysvar = EpochRewardsSysvar::active(rewards.clone());
        let bytes = sysvar.to_bytes();
        assert_eq!(bytes.len(), 57); // 1 + 7*8

        let restored = EpochRewardsSysvar::from_bytes(&bytes).unwrap();
        assert!(restored.is_active());
        let r = restored.rewards.unwrap();
        assert_eq!(r.total_rewards, rewards.total_rewards);
        assert_eq!(r.validator_rewards, rewards.validator_rewards);
        assert_eq!(r.foundation_rewards, rewards.foundation_rewards);
        assert_eq!(r.capitalization, rewards.capitalization);
        assert!((r.epoch_duration_years - rewards.epoch_duration_years).abs() < f64::EPSILON);
        assert!((r.validator_rate - rewards.validator_rate).abs() < f64::EPSILON);
        assert!((r.foundation_rate - rewards.foundation_rate).abs() < f64::EPSILON);
    }

    #[test]
    fn from_bytes_rejects_empty() {
        assert!(EpochRewardsSysvar::from_bytes(&[]).is_none());
    }

    #[test]
    fn from_bytes_rejects_truncated_active() {
        // Active flag = 1, but not enough data for all fields
        let mut data = vec![1u8; 20];
        data[0] = 1;
        assert!(EpochRewardsSysvar::from_bytes(&data).is_none());
    }

    #[test]
    fn default_is_inactive() {
        let d = EpochRewardsSysvar::default();
        assert!(!d.is_active());
    }
}
