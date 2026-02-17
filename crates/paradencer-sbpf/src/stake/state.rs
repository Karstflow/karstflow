/// Stake account state types and binary serialization.
///
/// Defines the on-chain representation of stake accounts including
/// initialization, authorization, lockup, delegation, and state
/// transitions. Binary format matches the consensus crate exactly.
use paradencer_constants::stake_program as constants;
use paradencer_types::Pubkey;

// ---------------------------------------------------------------------------
// Authority types
// ---------------------------------------------------------------------------

/// Authority type for stake account operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityType {
    /// Can delegate, deactivate, split, merge, and set lockup
    Staker,
    /// Can withdraw and change authorities
    Withdrawer,
}

impl AuthorityType {
    pub fn from_discriminant(value: u32) -> Option<Self> {
        match value {
            constants::AUTHORIZE_STAKER => Some(Self::Staker),
            constants::AUTHORIZE_WITHDRAWER => Some(Self::Withdrawer),
            _ => None,
        }
    }

    pub fn to_discriminant(self) -> u32 {
        match self {
            Self::Staker => constants::AUTHORIZE_STAKER,
            Self::Withdrawer => constants::AUTHORIZE_WITHDRAWER,
        }
    }
}

/// Authorized parties for a stake account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorized {
    pub staker: Pubkey,
    pub withdrawer: Pubkey,
}

impl Authorized {
    pub fn new(staker: Pubkey, withdrawer: Pubkey) -> Self {
        Self { staker, withdrawer }
    }

    /// Create with the same key for both authorities.
    pub fn auto(pubkey: Pubkey) -> Self {
        Self {
            staker: pubkey,
            withdrawer: pubkey,
        }
    }

    /// Check if a pubkey is authorized for the given authority type.
    pub fn check(&self, signers: &[Pubkey], authority_type: AuthorityType) -> bool {
        let required = match authority_type {
            AuthorityType::Staker => &self.staker,
            AuthorityType::Withdrawer => &self.withdrawer,
        };
        signers.contains(required)
    }

    /// Update authority. Staker can be changed by staker or withdrawer.
    /// Withdrawer can only be changed by withdrawer.
    pub fn authorize(
        &mut self,
        signers: &[Pubkey],
        new_authority: Pubkey,
        authority_type: AuthorityType,
    ) -> Result<(), StakeError> {
        match authority_type {
            AuthorityType::Staker => {
                if !signers.contains(&self.staker) && !signers.contains(&self.withdrawer) {
                    return Err(StakeError::MissingRequiredSignature);
                }
                self.staker = new_authority;
            }
            AuthorityType::Withdrawer => {
                if !signers.contains(&self.withdrawer) {
                    return Err(StakeError::MissingRequiredSignature);
                }
                self.withdrawer = new_authority;
            }
        }
        Ok(())
    }
}

impl Default for Authorized {
    fn default() -> Self {
        Self {
            staker: Pubkey::zeroed(),
            withdrawer: Pubkey::zeroed(),
        }
    }
}

// ---------------------------------------------------------------------------
// Lockup
// ---------------------------------------------------------------------------

/// Lockup conditions preventing withdrawal before a specified time/epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lockup {
    pub unix_timestamp: i64,
    pub epoch: u64,
    pub custodian: Pubkey,
}

impl Lockup {
    pub fn new(unix_timestamp: i64, epoch: u64, custodian: Pubkey) -> Self {
        Self {
            unix_timestamp,
            epoch,
            custodian,
        }
    }

    /// Check if the lockup is currently enforced.
    pub fn is_in_force(
        &self,
        current_timestamp: i64,
        current_epoch: u64,
        custodian: Option<&Pubkey>,
    ) -> bool {
        if let Some(signer) = custodian {
            if *signer == self.custodian {
                return false;
            }
        }
        self.unix_timestamp > current_timestamp || self.epoch > current_epoch
    }
}

impl Default for Lockup {
    fn default() -> Self {
        Self {
            unix_timestamp: 0,
            epoch: 0,
            custodian: Pubkey::zeroed(),
        }
    }
}

// ---------------------------------------------------------------------------
// Meta
// ---------------------------------------------------------------------------

/// Metadata common to all initialized stake states.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Meta {
    pub rent_exempt_reserve: u64,
    pub authorized: Authorized,
    pub lockup: Lockup,
}

impl Meta {
    pub fn new(rent_exempt_reserve: u64, authorized: Authorized, lockup: Lockup) -> Self {
        Self {
            rent_exempt_reserve,
            authorized,
            lockup,
        }
    }

    pub fn with_authorized(rent_exempt_reserve: u64, authorized: Authorized) -> Self {
        Self {
            rent_exempt_reserve,
            authorized,
            lockup: Lockup::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// StakeFlags
// ---------------------------------------------------------------------------

/// Bitflags for stake account behavior modifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StakeFlags {
    pub bits: u8,
}

impl StakeFlags {
    pub const EMPTY: Self = Self {
        bits: constants::STAKE_FLAG_EMPTY,
    };
    pub const MUST_FULLY_ACTIVATE_BEFORE_DEACTIVATION: Self = Self {
        bits: constants::STAKE_FLAG_MUST_FULLY_ACTIVATE_BEFORE_DEACTIVATION,
    };

    pub fn contains(self, flag: Self) -> bool {
        (self.bits & flag.bits) == flag.bits
    }

    pub fn insert(&mut self, flag: Self) {
        self.bits |= flag.bits;
    }

    pub fn remove(&mut self, flag: Self) {
        self.bits &= !flag.bits;
    }

    pub fn union(self, other: Self) -> Self {
        Self {
            bits: self.bits | other.bits,
        }
    }
}

// ---------------------------------------------------------------------------
// Delegation
// ---------------------------------------------------------------------------

/// Active delegation to a validator's vote account.
#[derive(Debug, Clone, PartialEq)]
pub struct Delegation {
    pub voter_pubkey: Pubkey,
    pub stake_amount: u64,
    pub activation_epoch: u64,
    pub deactivation_epoch: u64,
    /// Deprecated field kept for serialization compatibility.
    pub warmup_cooldown_rate: f64,
}

impl Delegation {
    pub fn new(voter_pubkey: Pubkey, stake_amount: u64, activation_epoch: u64) -> Self {
        Self {
            voter_pubkey,
            stake_amount,
            activation_epoch,
            deactivation_epoch: u64::MAX,
            warmup_cooldown_rate: constants::DEFAULT_WARMUP_COOLDOWN_RATE,
        }
    }

    pub fn deactivate(&mut self, epoch: u64) {
        self.deactivation_epoch = epoch;
    }

    pub fn is_deactivated(&self) -> bool {
        self.deactivation_epoch != u64::MAX
    }
}

/// A stake account with delegation and credits tracking.
#[derive(Debug, Clone, PartialEq)]
pub struct StakeAccount {
    pub delegation: Delegation,
    pub credits_observed: u64,
}

impl StakeAccount {
    pub fn new(delegation: Delegation, credits_observed: u64) -> Self {
        Self {
            delegation,
            credits_observed,
        }
    }
}

// ---------------------------------------------------------------------------
// StakeState
// ---------------------------------------------------------------------------

/// The four possible states of a stake account.
#[derive(Debug, Clone, PartialEq)]
pub enum StakeState {
    Uninitialized,
    Initialized(Meta),
    Delegated(Meta, StakeAccount, StakeFlags),
    RewardsPool,
}

impl StakeState {
    pub fn meta(&self) -> Option<&Meta> {
        match self {
            Self::Initialized(meta) | Self::Delegated(meta, _, _) => Some(meta),
            _ => None,
        }
    }

    pub fn meta_mut(&mut self) -> Option<&mut Meta> {
        match self {
            Self::Initialized(meta) | Self::Delegated(meta, _, _) => Some(meta),
            _ => None,
        }
    }

    pub fn stake(&self) -> Option<&StakeAccount> {
        match self {
            Self::Delegated(_, stake, _) => Some(stake),
            _ => None,
        }
    }

    pub fn stake_mut(&mut self) -> Option<&mut StakeAccount> {
        match self {
            Self::Delegated(_, stake, _) => Some(stake),
            _ => None,
        }
    }

    pub fn flags(&self) -> Option<&StakeFlags> {
        match self {
            Self::Delegated(_, _, flags) => Some(flags),
            _ => None,
        }
    }

    pub fn flags_mut(&mut self) -> Option<&mut StakeFlags> {
        match self {
            Self::Delegated(_, _, flags) => Some(flags),
            _ => None,
        }
    }

    pub fn is_uninitialized(&self) -> bool {
        matches!(self, Self::Uninitialized)
    }

    pub fn is_initialized(&self) -> bool {
        !matches!(self, Self::Uninitialized)
    }

    pub fn is_delegated(&self) -> bool {
        matches!(self, Self::Delegated(..))
    }

    pub fn discriminant(&self) -> u32 {
        match self {
            Self::Uninitialized => constants::STATE_UNINITIALIZED,
            Self::Initialized(_) => constants::STATE_INITIALIZED,
            Self::Delegated(..) => constants::STATE_DELEGATED,
            Self::RewardsPool => constants::STATE_REWARDS_POOL,
        }
    }
}

// ---------------------------------------------------------------------------
// StakeError
// ---------------------------------------------------------------------------

/// Errors that can occur during stake operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StakeError {
    NoCreditsToRedeem,
    LockupInForce,
    AlreadyDeactivated,
    TooSoonToRedelegate,
    InsufficientStake,
    MergeTransientStake,
    MergeMismatch,
    CustodianMissing,
    CustodianSignatureMissing,
    InsufficientReferenceVotes,
    VoteAddressMismatch,
    MinimumDelinquentEpochsNotMet,
    InsufficientDelegation,
    RedelegateTransientOrInactive,
    RedelegateToSameVoteAccount,
    RedelegatedStakeMustActivate,
    EpochRewardsActive,
    MissingRequiredSignature,
    InvalidAccountData,
    InvalidAccountOwner,
    AccountNotWritable,
    InsufficientFunds,
    AccountDataTooSmall,
}

impl StakeError {
    pub fn to_error_code(self) -> u32 {
        match self {
            Self::NoCreditsToRedeem => constants::ERR_NO_CREDITS_TO_REDEEM,
            Self::LockupInForce => constants::ERR_LOCKUP_IN_FORCE,
            Self::AlreadyDeactivated => constants::ERR_ALREADY_DEACTIVATED,
            Self::TooSoonToRedelegate => constants::ERR_TOO_SOON_TO_REDELEGATE,
            Self::InsufficientStake => constants::ERR_INSUFFICIENT_STAKE,
            Self::MergeTransientStake => constants::ERR_MERGE_TRANSIENT_STAKE,
            Self::MergeMismatch => constants::ERR_MERGE_MISMATCH,
            Self::CustodianMissing => constants::ERR_CUSTODIAN_MISSING,
            Self::CustodianSignatureMissing => constants::ERR_CUSTODIAN_SIGNATURE_MISSING,
            Self::InsufficientReferenceVotes => constants::ERR_INSUFFICIENT_REFERENCE_VOTES,
            Self::VoteAddressMismatch => constants::ERR_VOTE_ADDRESS_MISMATCH,
            Self::MinimumDelinquentEpochsNotMet => constants::ERR_MINIMUM_DELINQUENT_EPOCHS_NOT_MET,
            Self::InsufficientDelegation => constants::ERR_INSUFFICIENT_DELEGATION,
            Self::RedelegateTransientOrInactive => constants::ERR_REDELEGATE_TRANSIENT_OR_INACTIVE,
            Self::RedelegateToSameVoteAccount => constants::ERR_REDELEGATE_TO_SAME_VOTE_ACCOUNT,
            Self::RedelegatedStakeMustActivate => constants::ERR_REDELEGATED_STAKE_MUST_ACTIVATE,
            Self::EpochRewardsActive => constants::ERR_EPOCH_REWARDS_ACTIVE,
            Self::MissingRequiredSignature => u32::MAX - 1,
            Self::InvalidAccountData => u32::MAX - 2,
            Self::InvalidAccountOwner => u32::MAX - 3,
            Self::AccountNotWritable => u32::MAX - 4,
            Self::InsufficientFunds => u32::MAX - 5,
            Self::AccountDataTooSmall => u32::MAX - 6,
        }
    }
}

impl std::fmt::Display for StakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoCreditsToRedeem => write!(f, "no credits to redeem"),
            Self::LockupInForce => write!(f, "lockup in force"),
            Self::AlreadyDeactivated => write!(f, "already deactivated"),
            Self::TooSoonToRedelegate => write!(f, "too soon to redelegate"),
            Self::InsufficientStake => write!(f, "insufficient stake"),
            Self::MergeTransientStake => write!(f, "cannot merge transient stake"),
            Self::MergeMismatch => write!(f, "merge mismatch"),
            Self::CustodianMissing => write!(f, "custodian missing"),
            Self::CustodianSignatureMissing => write!(f, "custodian signature missing"),
            Self::InsufficientReferenceVotes => write!(f, "insufficient reference votes"),
            Self::VoteAddressMismatch => write!(f, "vote address mismatch"),
            Self::MinimumDelinquentEpochsNotMet => write!(f, "minimum delinquent epochs not met"),
            Self::InsufficientDelegation => write!(f, "insufficient delegation"),
            Self::RedelegateTransientOrInactive => write!(f, "redelegate transient or inactive"),
            Self::RedelegateToSameVoteAccount => write!(f, "redelegate to same vote account"),
            Self::RedelegatedStakeMustActivate => write!(f, "redelegated stake must activate"),
            Self::EpochRewardsActive => write!(f, "epoch rewards active"),
            Self::MissingRequiredSignature => write!(f, "missing required signature"),
            Self::InvalidAccountData => write!(f, "invalid account data"),
            Self::InvalidAccountOwner => write!(f, "invalid account owner"),
            Self::AccountNotWritable => write!(f, "account not writable"),
            Self::InsufficientFunds => write!(f, "insufficient funds"),
            Self::AccountDataTooSmall => write!(f, "account data too small"),
        }
    }
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

/// Deserialize a StakeState from account data bytes.
pub fn deserialize_stake_state(data: &[u8]) -> Result<StakeState, StakeError> {
    if data.len() < 4 {
        return Err(StakeError::AccountDataTooSmall);
    }

    let discriminant = read_u32_le(data, 0)?;

    match discriminant {
        constants::STATE_UNINITIALIZED => Ok(StakeState::Uninitialized),
        constants::STATE_INITIALIZED => deserialize_initialized(&data[4..]),
        constants::STATE_DELEGATED => deserialize_delegated(&data[4..]),
        constants::STATE_REWARDS_POOL => Ok(StakeState::RewardsPool),
        _ => Err(StakeError::InvalidAccountData),
    }
}

/// Serialize a StakeState into a byte vector.
pub fn serialize_stake_state(state: &StakeState) -> Vec<u8> {
    let mut buf = Vec::with_capacity(constants::STAKE_STATE_V2_SIZE);

    buf.extend_from_slice(&state.discriminant().to_le_bytes());

    match state {
        StakeState::Uninitialized | StakeState::RewardsPool => {}
        StakeState::Initialized(meta) => {
            serialize_meta(&mut buf, meta);
        }
        StakeState::Delegated(meta, stake, flags) => {
            serialize_meta(&mut buf, meta);
            serialize_stake_account(&mut buf, stake);
            buf.push(flags.bits);
        }
    }

    buf.resize(constants::STAKE_STATE_V2_SIZE, 0);
    buf
}

// -- Internal helpers --

fn read_u32_le(data: &[u8], offset: usize) -> Result<u32, StakeError> {
    if offset + 4 > data.len() {
        return Err(StakeError::AccountDataTooSmall);
    }
    Ok(u32::from_le_bytes(
        data[offset..offset + 4]
            .try_into()
            .map_err(|_| StakeError::InvalidAccountData)?,
    ))
}

fn read_u64_le(data: &[u8], offset: &mut usize) -> Result<u64, StakeError> {
    if *offset + 8 > data.len() {
        return Err(StakeError::AccountDataTooSmall);
    }
    let val = u64::from_le_bytes(
        data[*offset..*offset + 8]
            .try_into()
            .map_err(|_| StakeError::InvalidAccountData)?,
    );
    *offset += 8;
    Ok(val)
}

fn read_i64_le(data: &[u8], offset: &mut usize) -> Result<i64, StakeError> {
    if *offset + 8 > data.len() {
        return Err(StakeError::AccountDataTooSmall);
    }
    let val = i64::from_le_bytes(
        data[*offset..*offset + 8]
            .try_into()
            .map_err(|_| StakeError::InvalidAccountData)?,
    );
    *offset += 8;
    Ok(val)
}

fn read_f64_le(data: &[u8], offset: &mut usize) -> Result<f64, StakeError> {
    if *offset + 8 > data.len() {
        return Err(StakeError::AccountDataTooSmall);
    }
    let val = f64::from_le_bytes(
        data[*offset..*offset + 8]
            .try_into()
            .map_err(|_| StakeError::InvalidAccountData)?,
    );
    *offset += 8;
    Ok(val)
}

fn read_pubkey(data: &[u8], offset: &mut usize) -> Result<Pubkey, StakeError> {
    if *offset + 32 > data.len() {
        return Err(StakeError::AccountDataTooSmall);
    }
    let bytes: [u8; 32] = data[*offset..*offset + 32]
        .try_into()
        .map_err(|_| StakeError::InvalidAccountData)?;
    *offset += 32;
    Ok(Pubkey::new(bytes))
}

fn write_u64(buf: &mut Vec<u8>, val: u64) {
    buf.extend_from_slice(&val.to_le_bytes());
}

fn write_i64(buf: &mut Vec<u8>, val: i64) {
    buf.extend_from_slice(&val.to_le_bytes());
}

fn write_f64(buf: &mut Vec<u8>, val: f64) {
    buf.extend_from_slice(&val.to_le_bytes());
}

fn write_pubkey(buf: &mut Vec<u8>, pubkey: &Pubkey) {
    buf.extend_from_slice(pubkey.as_bytes());
}

fn serialize_authorized(buf: &mut Vec<u8>, auth: &Authorized) {
    write_pubkey(buf, &auth.staker);
    write_pubkey(buf, &auth.withdrawer);
}

fn deserialize_authorized(data: &[u8], offset: &mut usize) -> Result<Authorized, StakeError> {
    let staker = read_pubkey(data, offset)?;
    let withdrawer = read_pubkey(data, offset)?;
    Ok(Authorized::new(staker, withdrawer))
}

fn serialize_lockup(buf: &mut Vec<u8>, lockup: &Lockup) {
    write_i64(buf, lockup.unix_timestamp);
    write_u64(buf, lockup.epoch);
    write_pubkey(buf, &lockup.custodian);
}

fn deserialize_lockup(data: &[u8], offset: &mut usize) -> Result<Lockup, StakeError> {
    let unix_timestamp = read_i64_le(data, offset)?;
    let epoch = read_u64_le(data, offset)?;
    let custodian = read_pubkey(data, offset)?;
    Ok(Lockup::new(unix_timestamp, epoch, custodian))
}

fn serialize_meta(buf: &mut Vec<u8>, meta: &Meta) {
    write_u64(buf, meta.rent_exempt_reserve);
    serialize_authorized(buf, &meta.authorized);
    serialize_lockup(buf, &meta.lockup);
}

fn deserialize_meta(data: &[u8], offset: &mut usize) -> Result<Meta, StakeError> {
    let rent_exempt_reserve = read_u64_le(data, offset)?;
    let authorized = deserialize_authorized(data, offset)?;
    let lockup = deserialize_lockup(data, offset)?;
    Ok(Meta::new(rent_exempt_reserve, authorized, lockup))
}

fn serialize_delegation(buf: &mut Vec<u8>, delegation: &Delegation) {
    write_pubkey(buf, &delegation.voter_pubkey);
    write_u64(buf, delegation.stake_amount);
    write_u64(buf, delegation.activation_epoch);
    write_u64(buf, delegation.deactivation_epoch);
    write_f64(buf, delegation.warmup_cooldown_rate);
}

fn deserialize_delegation(data: &[u8], offset: &mut usize) -> Result<Delegation, StakeError> {
    let voter_pubkey = read_pubkey(data, offset)?;
    let stake_amount = read_u64_le(data, offset)?;
    let activation_epoch = read_u64_le(data, offset)?;
    let deactivation_epoch = read_u64_le(data, offset)?;
    let warmup_cooldown_rate = read_f64_le(data, offset)?;
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
    write_u64(buf, stake.credits_observed);
}

fn deserialize_stake_account(data: &[u8], offset: &mut usize) -> Result<StakeAccount, StakeError> {
    let delegation = deserialize_delegation(data, offset)?;
    let credits_observed = read_u64_le(data, offset)?;
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_authorized() -> Authorized {
        Authorized::new(Pubkey::new_unique(), Pubkey::new_unique())
    }

    fn make_test_lockup() -> Lockup {
        Lockup::new(1_000_000, 50, Pubkey::new_unique())
    }

    fn make_test_meta() -> Meta {
        Meta::new(2_282_880, make_test_authorized(), make_test_lockup())
    }

    fn make_test_delegation() -> Delegation {
        Delegation::new(Pubkey::new_unique(), 5_000_000_000, 10)
    }

    // -- Roundtrip serialization tests --

    #[test]
    fn roundtrip_uninitialized() {
        let state = StakeState::Uninitialized;
        let data = serialize_stake_state(&state);
        assert_eq!(data.len(), constants::STAKE_STATE_V2_SIZE);
        let decoded = deserialize_stake_state(&data).unwrap();
        assert!(decoded.is_uninitialized());
    }

    #[test]
    fn roundtrip_initialized() {
        let meta = make_test_meta();
        let state = StakeState::Initialized(meta.clone());
        let data = serialize_stake_state(&state);
        assert_eq!(data.len(), constants::STAKE_STATE_V2_SIZE);
        let decoded = deserialize_stake_state(&data).unwrap();
        assert_eq!(
            decoded.meta().unwrap().rent_exempt_reserve,
            meta.rent_exempt_reserve
        );
        assert_eq!(decoded.meta().unwrap().authorized, meta.authorized);
        assert_eq!(decoded.meta().unwrap().lockup, meta.lockup);
        assert!(!decoded.is_delegated());
    }

    #[test]
    fn roundtrip_delegated() {
        let meta = make_test_meta();
        let delegation = make_test_delegation();
        let stake = StakeAccount::new(delegation.clone(), 42);
        let flags = StakeFlags::MUST_FULLY_ACTIVATE_BEFORE_DEACTIVATION;
        let state = StakeState::Delegated(meta.clone(), stake, flags);

        let data = serialize_stake_state(&state);
        assert_eq!(data.len(), constants::STAKE_STATE_V2_SIZE);

        let decoded = deserialize_stake_state(&data).unwrap();
        assert!(decoded.is_delegated());
        assert_eq!(
            decoded.meta().unwrap().rent_exempt_reserve,
            meta.rent_exempt_reserve
        );
        let s = decoded.stake().unwrap();
        assert_eq!(s.delegation.voter_pubkey, delegation.voter_pubkey);
        assert_eq!(s.delegation.stake_amount, delegation.stake_amount);
        assert_eq!(s.delegation.activation_epoch, 10);
        assert_eq!(s.delegation.deactivation_epoch, u64::MAX);
        assert_eq!(s.credits_observed, 42);
        assert_eq!(*decoded.flags().unwrap(), flags);
    }

    #[test]
    fn roundtrip_rewards_pool() {
        let state = StakeState::RewardsPool;
        let data = serialize_stake_state(&state);
        let decoded = deserialize_stake_state(&data).unwrap();
        assert_eq!(decoded.discriminant(), constants::STATE_REWARDS_POOL);
    }

    #[test]
    fn deserialize_too_short_data() {
        let result = deserialize_stake_state(&[0, 0]);
        assert_eq!(result, Err(StakeError::AccountDataTooSmall));
    }

    #[test]
    fn deserialize_invalid_discriminant() {
        let mut data = vec![0u8; constants::STAKE_STATE_V2_SIZE];
        data[0..4].copy_from_slice(&99u32.to_le_bytes());
        assert_eq!(
            deserialize_stake_state(&data),
            Err(StakeError::InvalidAccountData)
        );
    }

    // -- Authority tests --

    #[test]
    fn authorized_check_staker() {
        let auth = make_test_authorized();
        assert!(auth.check(&[auth.staker], AuthorityType::Staker));
        assert!(!auth.check(&[auth.withdrawer], AuthorityType::Staker));
        assert!(!auth.check(&[Pubkey::new_unique()], AuthorityType::Staker));
    }

    #[test]
    fn authorized_check_withdrawer() {
        let auth = make_test_authorized();
        assert!(auth.check(&[auth.withdrawer], AuthorityType::Withdrawer));
        assert!(!auth.check(&[auth.staker], AuthorityType::Withdrawer));
    }

    #[test]
    fn authorize_staker_by_withdrawer() {
        let mut auth = make_test_authorized();
        let new_staker = Pubkey::new_unique();
        auth.authorize(&[auth.withdrawer], new_staker, AuthorityType::Staker)
            .unwrap();
        assert_eq!(auth.staker, new_staker);
    }

    #[test]
    fn authorize_withdrawer_requires_withdrawer() {
        let mut auth = make_test_authorized();
        let new = Pubkey::new_unique();
        let result = auth.authorize(&[auth.staker], new, AuthorityType::Withdrawer);
        assert_eq!(result, Err(StakeError::MissingRequiredSignature));
    }

    // -- Lockup tests --

    #[test]
    fn lockup_in_force_by_timestamp() {
        let lockup = Lockup::new(1_000_000, 0, Pubkey::zeroed());
        assert!(lockup.is_in_force(500_000, 100, None));
        assert!(!lockup.is_in_force(1_000_001, 100, None));
    }

    #[test]
    fn lockup_in_force_by_epoch() {
        let lockup = Lockup::new(0, 50, Pubkey::zeroed());
        assert!(lockup.is_in_force(999_999, 49, None));
        assert!(!lockup.is_in_force(999_999, 50, None));
    }

    #[test]
    fn lockup_custodian_bypass() {
        let custodian = Pubkey::new_unique();
        let lockup = Lockup::new(1_000_000, 50, custodian);
        assert!(lockup.is_in_force(0, 0, None));
        assert!(!lockup.is_in_force(0, 0, Some(&custodian)));
    }

    // -- StakeFlags tests --

    #[test]
    fn stake_flags_operations() {
        let mut flags = StakeFlags::EMPTY;
        assert!(!flags.contains(StakeFlags::MUST_FULLY_ACTIVATE_BEFORE_DEACTIVATION));
        flags.insert(StakeFlags::MUST_FULLY_ACTIVATE_BEFORE_DEACTIVATION);
        assert!(flags.contains(StakeFlags::MUST_FULLY_ACTIVATE_BEFORE_DEACTIVATION));
        flags.remove(StakeFlags::MUST_FULLY_ACTIVATE_BEFORE_DEACTIVATION);
        assert!(!flags.contains(StakeFlags::MUST_FULLY_ACTIVATE_BEFORE_DEACTIVATION));
    }

    // -- Delegation tests --

    #[test]
    fn delegation_deactivate() {
        let mut d = make_test_delegation();
        assert!(!d.is_deactivated());
        d.deactivate(20);
        assert!(d.is_deactivated());
        assert_eq!(d.deactivation_epoch, 20);
    }

    // -- Error code tests --

    #[test]
    fn error_codes_map_correctly() {
        assert_eq!(
            StakeError::LockupInForce.to_error_code(),
            constants::ERR_LOCKUP_IN_FORCE
        );
        assert_eq!(
            StakeError::AlreadyDeactivated.to_error_code(),
            constants::ERR_ALREADY_DEACTIVATED
        );
        assert_eq!(
            StakeError::InsufficientDelegation.to_error_code(),
            constants::ERR_INSUFFICIENT_DELEGATION
        );
    }
}
