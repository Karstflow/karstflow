//! Binary serialization and deserialization for stake state.
//!
//! Stake accounts store their state as bincode-encoded data. The format
//! starts with a u32 discriminant identifying the variant, followed by
//! variant-specific fields.

#[allow(deprecated)]
use crate::stake::{
    Authorized, Delegation, Lockup, Meta, StakeAccount, StakeError, StakeFlags, StakeState,
};
use karstflow_constants::stake_program as constants;
use karstflow_storage::Pubkey;

/// Minimum data length required for a serialized stake state.
const MIN_DISCRIMINANT_SIZE: usize = 4;

/// Deserialize a StakeState from account data bytes.
///
/// The data format follows Solana's bincode encoding:
/// - Bytes 0..4: u32 discriminant (little-endian)
/// - Remaining bytes: variant-specific fields
pub fn deserialize_stake_state(data: &[u8]) -> Result<StakeState, StakeError> {
    if data.len() < MIN_DISCRIMINANT_SIZE {
        return Err(StakeError::AccountDataTooSmall);
    }

    let discriminant = u32::from_le_bytes(
        data[0..4]
            .try_into()
            .map_err(|_| StakeError::InvalidAccountData)?,
    );

    match discriminant {
        constants::STATE_UNINITIALIZED => Ok(StakeState::Uninitialized),
        constants::STATE_INITIALIZED => deserialize_initialized(&data[4..]),
        constants::STATE_DELEGATED => deserialize_delegated(&data[4..]),
        constants::STATE_REWARDS_POOL => Ok(StakeState::RewardsPool),
        _ => Err(StakeError::InvalidAccountData),
    }
}

/// Serialize a StakeState into a byte vector.
///
/// Produces bincode-compatible encoding with the discriminant prefix.
pub fn serialize_stake_state(state: &StakeState) -> Vec<u8> {
    let mut buf = Vec::with_capacity(constants::STAKE_STATE_V2_SIZE);

    buf.extend_from_slice(&state.discriminant().to_le_bytes());

    match state {
        StakeState::Uninitialized => {
            // Pad to full size
            buf.resize(constants::STAKE_STATE_V2_SIZE, 0);
        }
        StakeState::Initialized(meta) => {
            serialize_meta(&mut buf, meta);
            buf.resize(constants::STAKE_STATE_V2_SIZE, 0);
        }
        StakeState::Delegated(meta, stake, flags) => {
            serialize_meta(&mut buf, meta);
            serialize_stake_account(&mut buf, stake);
            buf.push(flags.bits);
            buf.resize(constants::STAKE_STATE_V2_SIZE, 0);
        }
        StakeState::RewardsPool => {
            buf.resize(constants::STAKE_STATE_V2_SIZE, 0);
        }
    }

    buf
}

// -- Internal serialization helpers --

fn serialize_pubkey(buf: &mut Vec<u8>, pubkey: &Pubkey) {
    buf.extend_from_slice(pubkey.as_bytes());
}

fn deserialize_pubkey(data: &[u8], offset: &mut usize) -> Result<Pubkey, StakeError> {
    if *offset + 32 > data.len() {
        return Err(StakeError::AccountDataTooSmall);
    }
    let bytes: [u8; 32] = data[*offset..*offset + 32]
        .try_into()
        .map_err(|_| StakeError::InvalidAccountData)?;
    *offset += 32;
    Ok(Pubkey::new(bytes))
}

fn serialize_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn deserialize_u64(data: &[u8], offset: &mut usize) -> Result<u64, StakeError> {
    if *offset + 8 > data.len() {
        return Err(StakeError::AccountDataTooSmall);
    }
    let bytes: [u8; 8] = data[*offset..*offset + 8]
        .try_into()
        .map_err(|_| StakeError::InvalidAccountData)?;
    *offset += 8;
    Ok(u64::from_le_bytes(bytes))
}

fn serialize_i64(buf: &mut Vec<u8>, value: i64) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn deserialize_i64(data: &[u8], offset: &mut usize) -> Result<i64, StakeError> {
    if *offset + 8 > data.len() {
        return Err(StakeError::AccountDataTooSmall);
    }
    let bytes: [u8; 8] = data[*offset..*offset + 8]
        .try_into()
        .map_err(|_| StakeError::InvalidAccountData)?;
    *offset += 8;
    Ok(i64::from_le_bytes(bytes))
}

fn serialize_f64(buf: &mut Vec<u8>, value: f64) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn deserialize_f64(data: &[u8], offset: &mut usize) -> Result<f64, StakeError> {
    if *offset + 8 > data.len() {
        return Err(StakeError::AccountDataTooSmall);
    }
    let bytes: [u8; 8] = data[*offset..*offset + 8]
        .try_into()
        .map_err(|_| StakeError::InvalidAccountData)?;
    *offset += 8;
    Ok(f64::from_le_bytes(bytes))
}

fn serialize_authorized(buf: &mut Vec<u8>, authorized: &Authorized) {
    serialize_pubkey(buf, &authorized.staker);
    serialize_pubkey(buf, &authorized.withdrawer);
}

fn deserialize_authorized(data: &[u8], offset: &mut usize) -> Result<Authorized, StakeError> {
    let staker = deserialize_pubkey(data, offset)?;
    let withdrawer = deserialize_pubkey(data, offset)?;
    Ok(Authorized::new(staker, withdrawer))
}

fn serialize_lockup(buf: &mut Vec<u8>, lockup: &Lockup) {
    serialize_i64(buf, lockup.unix_timestamp);
    serialize_u64(buf, lockup.epoch);
    serialize_pubkey(buf, &lockup.custodian);
}

fn deserialize_lockup(data: &[u8], offset: &mut usize) -> Result<Lockup, StakeError> {
    let unix_timestamp = deserialize_i64(data, offset)?;
    let epoch = deserialize_u64(data, offset)?;
    let custodian = deserialize_pubkey(data, offset)?;
    Ok(Lockup::new(unix_timestamp, epoch, custodian))
}

fn serialize_meta(buf: &mut Vec<u8>, meta: &Meta) {
    serialize_u64(buf, meta.rent_exempt_reserve);
    serialize_authorized(buf, &meta.authorized);
    serialize_lockup(buf, &meta.lockup);
}

fn deserialize_meta(data: &[u8], offset: &mut usize) -> Result<Meta, StakeError> {
    let rent_exempt_reserve = deserialize_u64(data, offset)?;
    let authorized = deserialize_authorized(data, offset)?;
    let lockup = deserialize_lockup(data, offset)?;
    Ok(Meta::new(rent_exempt_reserve, authorized, lockup))
}

#[allow(deprecated)]
fn serialize_delegation(buf: &mut Vec<u8>, delegation: &Delegation) {
    serialize_pubkey(buf, &delegation.voter_pubkey);
    serialize_u64(buf, delegation.stake_amount);
    serialize_u64(buf, delegation.activation_epoch);
    serialize_u64(buf, delegation.deactivation_epoch);
    serialize_f64(buf, delegation.warmup_cooldown_rate);
}

#[allow(deprecated)]
fn deserialize_delegation(data: &[u8], offset: &mut usize) -> Result<Delegation, StakeError> {
    let voter_pubkey = deserialize_pubkey(data, offset)?;
    let stake_amount = deserialize_u64(data, offset)?;
    let activation_epoch = deserialize_u64(data, offset)?;
    let deactivation_epoch = deserialize_u64(data, offset)?;
    let warmup_cooldown_rate = deserialize_f64(data, offset)?;
    Ok(Delegation {
        voter_pubkey,
        stake_amount,
        activation_epoch,
        deactivation_epoch,
        warmup_cooldown_rate,
    })
}

fn serialize_stake_account(buf: &mut Vec<u8>, stake: &StakeAccount) {
    serialize_delegation(buf, &stake.delegation);
    serialize_u64(buf, stake.credits_observed);
}

fn deserialize_stake_account(data: &[u8], offset: &mut usize) -> Result<StakeAccount, StakeError> {
    let delegation = deserialize_delegation(data, offset)?;
    let credits_observed = deserialize_u64(data, offset)?;
    Ok(StakeAccount::new(delegation, credits_observed))
}

fn deserialize_initialized(data: &[u8]) -> Result<StakeState, StakeError> {
    let mut offset = 0;
    let meta = deserialize_meta(data, &mut offset)?;
    Ok(StakeState::Initialized(meta))
}

fn deserialize_delegated(data: &[u8]) -> Result<StakeState, StakeError> {
    let mut offset = 0;
    let meta = deserialize_meta(data, &mut offset)?;
    let stake = deserialize_stake_account(data, &mut offset)?;

    let flags = if offset < data.len() {
        StakeFlags { bits: data[offset] }
    } else {
        StakeFlags::EMPTY
    };

    Ok(StakeState::Delegated(meta, stake, flags))
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    fn test_meta() -> Meta {
        Meta::new(
            2_282_880,
            Authorized::new(Pubkey::new([1u8; 32]), Pubkey::new([2u8; 32])),
            Lockup::new(1_000_000, 50, Pubkey::new([3u8; 32])),
        )
    }

    fn test_delegation() -> Delegation {
        Delegation::new(Pubkey::new([4u8; 32]), 500_000, 10)
    }

    fn test_stake_account() -> StakeAccount {
        StakeAccount::new(test_delegation(), 12345)
    }

    // --- Uninitialized ---

    #[test]
    fn roundtrip_uninitialized() {
        let state = StakeState::Uninitialized;
        let bytes = serialize_stake_state(&state);
        assert_eq!(bytes.len(), constants::STAKE_STATE_V2_SIZE);

        let restored = deserialize_stake_state(&bytes).unwrap();
        assert!(matches!(restored, StakeState::Uninitialized));
    }

    // --- RewardsPool ---

    #[test]
    fn roundtrip_rewards_pool() {
        let state = StakeState::RewardsPool;
        let bytes = serialize_stake_state(&state);
        assert_eq!(bytes.len(), constants::STAKE_STATE_V2_SIZE);

        let restored = deserialize_stake_state(&bytes).unwrap();
        assert!(matches!(restored, StakeState::RewardsPool));
    }

    // --- Initialized ---

    #[test]
    fn roundtrip_initialized() {
        let meta = test_meta();
        let state = StakeState::Initialized(meta.clone());
        let bytes = serialize_stake_state(&state);
        assert_eq!(bytes.len(), constants::STAKE_STATE_V2_SIZE);

        let restored = deserialize_stake_state(&bytes).unwrap();
        if let StakeState::Initialized(m) = restored {
            assert_eq!(m.rent_exempt_reserve, meta.rent_exempt_reserve);
            assert_eq!(m.authorized.staker, meta.authorized.staker);
            assert_eq!(m.authorized.withdrawer, meta.authorized.withdrawer);
            assert_eq!(m.lockup.unix_timestamp, meta.lockup.unix_timestamp);
            assert_eq!(m.lockup.epoch, meta.lockup.epoch);
            assert_eq!(m.lockup.custodian, meta.lockup.custodian);
        } else {
            panic!("expected Initialized variant");
        }
    }

    // --- Delegated ---

    #[test]
    fn roundtrip_delegated() {
        let meta = test_meta();
        let stake = test_stake_account();
        let flags = StakeFlags::MUST_FULLY_ACTIVATE_BEFORE_DEACTIVATION;
        let state = StakeState::Delegated(meta.clone(), stake.clone(), flags);
        let bytes = serialize_stake_state(&state);
        assert_eq!(bytes.len(), constants::STAKE_STATE_V2_SIZE);

        let restored = deserialize_stake_state(&bytes).unwrap();
        if let StakeState::Delegated(m, s, f) = restored {
            assert_eq!(m.rent_exempt_reserve, meta.rent_exempt_reserve);
            assert_eq!(s.delegation.voter_pubkey, stake.delegation.voter_pubkey);
            assert_eq!(s.delegation.stake_amount, stake.delegation.stake_amount);
            assert_eq!(
                s.delegation.activation_epoch,
                stake.delegation.activation_epoch
            );
            assert_eq!(s.delegation.deactivation_epoch, u64::MAX);
            assert_eq!(s.credits_observed, 12345);
            assert_eq!(f.bits, flags.bits);
        } else {
            panic!("expected Delegated variant");
        }
    }

    #[test]
    fn roundtrip_delegated_empty_flags() {
        let state = StakeState::Delegated(test_meta(), test_stake_account(), StakeFlags::EMPTY);
        let bytes = serialize_stake_state(&state);
        let restored = deserialize_stake_state(&bytes).unwrap();
        if let StakeState::Delegated(_, _, f) = restored {
            assert_eq!(f.bits, 0);
        } else {
            panic!("expected Delegated variant");
        }
    }

    // --- Discriminant checks ---

    #[test]
    fn discriminants_are_correct() {
        assert_eq!(
            StakeState::Uninitialized.discriminant(),
            constants::STATE_UNINITIALIZED
        );
        assert_eq!(
            StakeState::Initialized(test_meta()).discriminant(),
            constants::STATE_INITIALIZED
        );
        assert_eq!(
            StakeState::Delegated(test_meta(), test_stake_account(), StakeFlags::EMPTY)
                .discriminant(),
            constants::STATE_DELEGATED
        );
        assert_eq!(
            StakeState::RewardsPool.discriminant(),
            constants::STATE_REWARDS_POOL
        );
    }

    #[test]
    fn first_four_bytes_are_discriminant() {
        let bytes = serialize_stake_state(&StakeState::Uninitialized);
        assert_eq!(&bytes[0..4], &0u32.to_le_bytes());

        let bytes = serialize_stake_state(&StakeState::Initialized(test_meta()));
        assert_eq!(&bytes[0..4], &1u32.to_le_bytes());

        let bytes = serialize_stake_state(&StakeState::Delegated(
            test_meta(),
            test_stake_account(),
            StakeFlags::EMPTY,
        ));
        assert_eq!(&bytes[0..4], &2u32.to_le_bytes());

        let bytes = serialize_stake_state(&StakeState::RewardsPool);
        assert_eq!(&bytes[0..4], &3u32.to_le_bytes());
    }

    // --- Error cases ---

    #[test]
    fn deserialize_too_short() {
        let result = deserialize_stake_state(&[0; 3]);
        assert!(matches!(result, Err(StakeError::AccountDataTooSmall)));
    }

    #[test]
    fn deserialize_invalid_discriminant() {
        let mut data = vec![0u8; constants::STAKE_STATE_V2_SIZE];
        data[0..4].copy_from_slice(&99u32.to_le_bytes());
        let result = deserialize_stake_state(&data);
        assert!(matches!(result, Err(StakeError::InvalidAccountData)));
    }

    #[test]
    fn deserialize_initialized_truncated_meta() {
        // Valid discriminant but not enough data for meta fields
        let mut data = vec![0u8; 8]; // 4 discriminant + 4 extra (not enough for meta)
        data[0..4].copy_from_slice(&constants::STATE_INITIALIZED.to_le_bytes());
        let result = deserialize_stake_state(&data);
        assert!(result.is_err());
    }

    #[test]
    fn output_size_is_always_v2() {
        let states = [
            StakeState::Uninitialized,
            StakeState::Initialized(test_meta()),
            StakeState::Delegated(test_meta(), test_stake_account(), StakeFlags::EMPTY),
            StakeState::RewardsPool,
        ];
        for state in &states {
            let bytes = serialize_stake_state(state);
            assert_eq!(bytes.len(), constants::STAKE_STATE_V2_SIZE);
        }
    }

    // --- Warmup/cooldown rate preservation ---

    #[test]
    fn warmup_cooldown_rate_survives_roundtrip() {
        let d = Delegation {
            voter_pubkey: Pubkey::new([5u8; 32]),
            stake_amount: 1_000_000,
            activation_epoch: 42,
            deactivation_epoch: u64::MAX,
            warmup_cooldown_rate: 0.25,
        };
        let stake = StakeAccount::new(d, 999);
        let state = StakeState::Delegated(test_meta(), stake, StakeFlags::EMPTY);

        let bytes = serialize_stake_state(&state);
        let restored = deserialize_stake_state(&bytes).unwrap();
        if let StakeState::Delegated(_, s, _) = restored {
            assert!((s.delegation.warmup_cooldown_rate - 0.25).abs() < f64::EPSILON);
        } else {
            panic!("expected Delegated variant");
        }
    }
}
