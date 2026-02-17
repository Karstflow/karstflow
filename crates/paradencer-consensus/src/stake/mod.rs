/// Stake account state types and delegation management.
///
/// Provides the on-chain stake state representation including initialization,
/// authorization, lockup, and active delegation tracking. Stake accounts
/// transition through states: Uninitialized -> Initialized -> Delegated,
/// with warmup/cooldown periods governing activation and deactivation.
mod delegation;
mod rewards;
mod serialization;
mod tracker;
mod warmup_cooldown;

#[cfg(test)]
mod tests;

pub use delegation::{Delegation, StakeAccount};
pub use rewards::{
    calculate_points_and_credits, calculate_stake_rewards, calculate_total_points,
    split_commission, CommissionSplit, EpochCreditEntry, PointsCalculation, StakeRewardResult,
};
pub use serialization::{deserialize_stake_state, serialize_stake_state};
pub use tracker::StakeTracker;
pub use warmup_cooldown::{warmup_cooldown_rate, ActivationStatus};

use paradencer_constants::stake_program as constants;
use paradencer_storage::Pubkey;

/// Authority type for stake account operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityType {
    /// Can delegate, deactivate, split, merge, and set lockup
    Staker,
    /// Can withdraw and change authorities
    Withdrawer,
}

impl AuthorityType {
    /// Decode from the on-chain u32 discriminant.
    pub fn from_discriminant(value: u32) -> Option<Self> {
        match value {
            constants::AUTHORIZE_STAKER => Some(Self::Staker),
            constants::AUTHORIZE_WITHDRAWER => Some(Self::Withdrawer),
            _ => None,
        }
    }

    /// Encode to the on-chain u32 discriminant.
    pub fn to_discriminant(self) -> u32 {
        match self {
            Self::Staker => constants::AUTHORIZE_STAKER,
            Self::Withdrawer => constants::AUTHORIZE_WITHDRAWER,
        }
    }
}

/// Authorized parties for a stake account.
///
/// The staker can perform delegation operations while the withdrawer
/// can withdraw funds and change both authorities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorized {
    /// Public key authorized to delegate and deactivate
    pub staker: Pubkey,
    /// Public key authorized to withdraw and change authorities
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

    /// Check if a signer is authorized for the given authority type.
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

/// Lockup conditions preventing withdrawal before a specified time/epoch.
///
/// When a lockup is active, withdrawals require the custodian's signature.
/// Either a Unix timestamp or epoch threshold can be set (or both).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lockup {
    /// Unix timestamp after which withdrawal is allowed
    pub unix_timestamp: i64,
    /// Epoch after which withdrawal is allowed
    pub epoch: u64,
    /// Custodian who can override the lockup
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
    ///
    /// Returns true if the current time/epoch has not yet passed the lockup
    /// thresholds and the provided signer is not the custodian.
    pub fn is_in_force(
        &self,
        current_timestamp: i64,
        current_epoch: u64,
        custodian: Option<&Pubkey>,
    ) -> bool {
        // Custodian can bypass lockup
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

/// Metadata common to all initialized stake states.
///
/// Contains the rent-exempt reserve, authorization info, and lockup conditions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Meta {
    /// Minimum lamports that must remain in the account for rent exemption
    pub rent_exempt_reserve: u64,
    /// Authorized staker and withdrawer
    pub authorized: Authorized,
    /// Lockup conditions for withdrawal
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

    /// Create with default lockup (no restrictions).
    pub fn with_authorized(rent_exempt_reserve: u64, authorized: Authorized) -> Self {
        Self {
            rent_exempt_reserve,
            authorized,
            lockup: Lockup::default(),
        }
    }
}

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

    /// Check if a flag is set.
    pub fn contains(self, flag: Self) -> bool {
        (self.bits & flag.bits) == flag.bits
    }

    /// Set a flag.
    pub fn insert(&mut self, flag: Self) {
        self.bits |= flag.bits;
    }

    /// Clear a flag.
    pub fn remove(&mut self, flag: Self) {
        self.bits &= !flag.bits;
    }

    /// Union of two flag sets.
    pub fn union(self, other: Self) -> Self {
        Self {
            bits: self.bits | other.bits,
        }
    }
}

/// The four possible states of a stake account.
///
/// Accounts progress through: Uninitialized -> Initialized -> Delegated.
/// RewardsPool is a special state for the rewards pool account.
#[derive(Debug, Clone, PartialEq)]
pub enum StakeState {
    /// Account has been created but not yet initialized with authorities
    Uninitialized,
    /// Initialized with authorities and lockup but not yet delegated
    Initialized(Meta),
    /// Actively delegated to a validator's vote account
    Delegated(Meta, StakeAccount, StakeFlags),
    /// Special rewards pool account (not used by normal stake accounts)
    RewardsPool,
}

impl StakeState {
    /// Get the meta if this state has one.
    pub fn meta(&self) -> Option<&Meta> {
        match self {
            Self::Initialized(meta) => Some(meta),
            Self::Delegated(meta, _, _) => Some(meta),
            _ => None,
        }
    }

    /// Get a mutable reference to meta if this state has one.
    pub fn meta_mut(&mut self) -> Option<&mut Meta> {
        match self {
            Self::Initialized(meta) => Some(meta),
            Self::Delegated(meta, _, _) => Some(meta),
            _ => None,
        }
    }

    /// Get the stake account if this is a delegated state.
    pub fn stake(&self) -> Option<&StakeAccount> {
        match self {
            Self::Delegated(_, stake, _) => Some(stake),
            _ => None,
        }
    }

    /// Get mutable stake account if delegated.
    pub fn stake_mut(&mut self) -> Option<&mut StakeAccount> {
        match self {
            Self::Delegated(_, stake, _) => Some(stake),
            _ => None,
        }
    }

    /// Get the stake flags if delegated.
    pub fn flags(&self) -> Option<&StakeFlags> {
        match self {
            Self::Delegated(_, _, flags) => Some(flags),
            _ => None,
        }
    }

    /// Get mutable flags if delegated.
    pub fn flags_mut(&mut self) -> Option<&mut StakeFlags> {
        match self {
            Self::Delegated(_, _, flags) => Some(flags),
            _ => None,
        }
    }

    /// Check if the account is in an uninitialized state.
    pub fn is_uninitialized(&self) -> bool {
        matches!(self, Self::Uninitialized)
    }

    /// Check if the account is initialized (including delegated).
    pub fn is_initialized(&self) -> bool {
        !matches!(self, Self::Uninitialized)
    }

    /// Check if the account has an active delegation.
    pub fn is_delegated(&self) -> bool {
        matches!(self, Self::Delegated(..))
    }

    /// Get the discriminant value for serialization.
    pub fn discriminant(&self) -> u32 {
        match self {
            Self::Uninitialized => constants::STATE_UNINITIALIZED,
            Self::Initialized(_) => constants::STATE_INITIALIZED,
            Self::Delegated(..) => constants::STATE_DELEGATED,
            Self::RewardsPool => constants::STATE_REWARDS_POOL,
        }
    }
}

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
    /// Convert to the on-chain custom error code.
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
            // Generic errors map to sentinel values
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
