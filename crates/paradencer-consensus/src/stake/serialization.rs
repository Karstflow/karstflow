//! Binary serialization and deserialization for stake state.
//!
//! Stake accounts store their state as bincode-encoded data. The format
//! starts with a u32 discriminant identifying the variant, followed by
//! variant-specific fields.

#[allow(deprecated)]
use crate::stake::{
    Authorized, Delegation, Lockup, Meta, StakeAccount, StakeError, StakeFlags, StakeState,
};
use paradencer_constants::stake_program as constants;
use paradencer_storage::Pubkey;

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
