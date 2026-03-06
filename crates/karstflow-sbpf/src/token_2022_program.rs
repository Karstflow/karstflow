//! SPL Token-2022 Program Implementation
//!
//! This module implements the Solana Program Library (SPL) Token-2022 Program,
//! which extends the original Token Program with additional features and extensions.
//!
//! Token-2022 includes all Token Program instructions plus extension support:
//! - TransferFee: Fees collected on transfers
//! - ConfidentialTransfer: Privacy-preserving transfers
//! - TransferHook: Custom program invocation on transfer
//! - MintCloseAuthority: Allow closing mint accounts
//! - DefaultAccountState: Default frozen/initialized state for new accounts
//! - MemoTransfer: Require memos on all transfers
//! - NonTransferable: Tokens that cannot be transferred
//! - InterestBearing: Time-based interest accrual
//! - PermanentDelegate: Immutable transfer authority
//! - MetadataPointer: Link to metadata account
//! - GroupPointer: Link to group account
//! - GroupMemberPointer: Link to group member account

use crate::{ExecutionContext, ExecutionOutcome};
use karstflow_constants::execution::DEFAULT_INSTRUCTION_BASE_COST;
use karstflow_types::{Account, AccountData, Pubkey};

/// Token-2022 Program errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token2022Error {
    InsufficientFunds,
    InvalidMint,
    MintMismatch,
    OwnerMismatch,
    FixedSupply,
    AlreadyInUse,
    InvalidNumberOfProvidedSigners,
    InvalidNumberOfRequiredSigners,
    UninitializedState,
    NativeNotSupported,
    NonNativeHasBalance,
    InvalidInstruction,
    InvalidState,
    Overflow,
    AuthorityTypeNotSupported,
    MintCannotFreeze,
    AccountFrozen,
    MintDecimalsMismatch,
    NonNativeNotSupported,
    // Extension-specific errors
    ExtensionAlreadyInitialized,
    ExtensionNotInitialized,
    InvalidExtensionType,
    ExtensionTypeMismatch,
    InsufficientFundsForFee,
    FeeTooLarge,
    MintRequiresMemo,
    NonTransferable,
    UnsupportedExtension,
    InvalidAccountState,
    ImmutableOwner,
    NoAuthorityExists,
    IncorrectAuthority,
}

impl Token2022Error {
    fn to_error_code(&self) -> u32 {
        match self {
            Self::InsufficientFunds => 1,
            Self::InvalidMint => 2,
            Self::MintMismatch => 3,
            Self::OwnerMismatch => 4,
            Self::FixedSupply => 5,
            Self::AlreadyInUse => 6,
            Self::InvalidNumberOfProvidedSigners => 7,
            Self::InvalidNumberOfRequiredSigners => 8,
            Self::UninitializedState => 9,
            Self::NativeNotSupported => 10,
            Self::NonNativeHasBalance => 11,
            Self::InvalidInstruction => 12,
            Self::InvalidState => 13,
            Self::Overflow => 14,
            Self::AuthorityTypeNotSupported => 15,
            Self::MintCannotFreeze => 16,
            Self::AccountFrozen => 17,
            Self::MintDecimalsMismatch => 18,
            Self::NonNativeNotSupported => 19,
            Self::ExtensionAlreadyInitialized => 20,
            Self::ExtensionNotInitialized => 21,
            Self::InvalidExtensionType => 22,
            Self::ExtensionTypeMismatch => 23,
            Self::InsufficientFundsForFee => 24,
            Self::FeeTooLarge => 25,
            Self::MintRequiresMemo => 26,
            Self::NonTransferable => 27,
            Self::UnsupportedExtension => 28,
            Self::InvalidAccountState => 29,
            Self::ImmutableOwner => 30,
            Self::NoAuthorityExists => 31,
            Self::IncorrectAuthority => 32,
        }
    }

    fn to_string(&self) -> String {
        match self {
            Self::InsufficientFunds => "Insufficient funds",
            Self::InvalidMint => "Invalid mint",
            Self::MintMismatch => "Mint mismatch",
            Self::OwnerMismatch => "Owner mismatch",
            Self::FixedSupply => "Fixed supply",
            Self::AlreadyInUse => "Already in use",
            Self::InvalidNumberOfProvidedSigners => "Invalid number of provided signers",
            Self::InvalidNumberOfRequiredSigners => "Invalid number of required signers",
            Self::UninitializedState => "Uninitialized state",
            Self::NativeNotSupported => "Native not supported",
            Self::NonNativeHasBalance => "Non-native has balance",
            Self::InvalidInstruction => "Invalid instruction",
            Self::InvalidState => "Invalid state",
            Self::Overflow => "Overflow",
            Self::AuthorityTypeNotSupported => "Authority type not supported",
            Self::MintCannotFreeze => "Mint cannot freeze",
            Self::AccountFrozen => "Account frozen",
            Self::MintDecimalsMismatch => "Mint decimals mismatch",
            Self::NonNativeNotSupported => "Non-native not supported",
            Self::ExtensionAlreadyInitialized => "Extension already initialized",
            Self::ExtensionNotInitialized => "Extension not initialized",
            Self::InvalidExtensionType => "Invalid extension type",
            Self::ExtensionTypeMismatch => "Extension type mismatch",
            Self::InsufficientFundsForFee => "Insufficient funds for fee",
            Self::FeeTooLarge => "Fee too large",
            Self::MintRequiresMemo => "Mint requires memo",
            Self::NonTransferable => "Non-transferable",
            Self::UnsupportedExtension => "Unsupported extension",
            Self::InvalidAccountState => "Invalid account state",
            Self::ImmutableOwner => "Immutable owner",
            Self::NoAuthorityExists => "No authority exists",
            Self::IncorrectAuthority => "Incorrect authority",
        }
        .to_string()
    }
}

/// Extension types for Token-2022
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ExtensionType {
    Uninitialized = 0,
    TransferFeeConfig = 1,
    TransferFeeAmount = 2,
    MintCloseAuthority = 3,
    ConfidentialTransferMint = 4,
    ConfidentialTransferAccount = 5,
    DefaultAccountState = 6,
    ImmutableOwner = 7,
    MemoTransfer = 8,
    NonTransferable = 9,
    InterestBearingConfig = 10,
    CpiGuard = 11,
    PermanentDelegate = 12,
    NonTransferableAccount = 13,
    TransferHook = 14,
    TransferHookAccount = 15,
    MetadataPointer = 16,
    TokenMetadata = 17,
    GroupPointer = 18,
    GroupMemberPointer = 19,
}

impl ExtensionType {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(Self::Uninitialized),
            1 => Some(Self::TransferFeeConfig),
            2 => Some(Self::TransferFeeAmount),
            3 => Some(Self::MintCloseAuthority),
            4 => Some(Self::ConfidentialTransferMint),
            5 => Some(Self::ConfidentialTransferAccount),
            6 => Some(Self::DefaultAccountState),
            7 => Some(Self::ImmutableOwner),
            8 => Some(Self::MemoTransfer),
            9 => Some(Self::NonTransferable),
            10 => Some(Self::InterestBearingConfig),
            11 => Some(Self::CpiGuard),
            12 => Some(Self::PermanentDelegate),
            13 => Some(Self::NonTransferableAccount),
            14 => Some(Self::TransferHook),
            15 => Some(Self::TransferHookAccount),
            16 => Some(Self::MetadataPointer),
            17 => Some(Self::TokenMetadata),
            18 => Some(Self::GroupPointer),
            19 => Some(Self::GroupMemberPointer),
            _ => None,
        }
    }

    /// Fixed data length for each extension type (matching Solana spec)
    pub fn data_len(&self) -> usize {
        match self {
            Self::Uninitialized => 0,
            Self::TransferFeeConfig => TransferFeeConfig::LEN,
            Self::TransferFeeAmount => TransferFeeAmount::LEN,
            Self::MintCloseAuthority => MintCloseAuthority::LEN,
            Self::ConfidentialTransferMint => 97,
            Self::ConfidentialTransferAccount => 286,
            Self::DefaultAccountState => 1,
            Self::ImmutableOwner => 0,
            Self::MemoTransfer => 1,
            Self::NonTransferable => 0,
            Self::InterestBearingConfig => InterestBearingConfig::LEN,
            Self::CpiGuard => 1,
            Self::PermanentDelegate => PermanentDelegate::LEN,
            Self::NonTransferableAccount => 0,
            Self::TransferHook => TransferHookExt::LEN,
            Self::TransferHookAccount => 1,
            Self::MetadataPointer => MetadataPointer::LEN,
            Self::TokenMetadata => 0, // Variable length
            Self::GroupPointer => GroupPointer::LEN,
            Self::GroupMemberPointer => GroupMemberPointer::LEN,
        }
    }

    /// Whether this extension belongs to a mint (vs token account)
    pub fn is_mint_extension(&self) -> bool {
        matches!(
            self,
            Self::TransferFeeConfig
                | Self::MintCloseAuthority
                | Self::ConfidentialTransferMint
                | Self::DefaultAccountState
                | Self::NonTransferable
                | Self::InterestBearingConfig
                | Self::PermanentDelegate
                | Self::TransferHook
                | Self::MetadataPointer
                | Self::TokenMetadata
                | Self::GroupPointer
                | Self::GroupMemberPointer
        )
    }
}

/// AccountType discriminator byte (placed after base account data)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AccountType {
    Uninitialized = 0,
    Mint = 1,
    Account = 2,
}

impl AccountType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Uninitialized),
            1 => Some(Self::Mint),
            2 => Some(Self::Account),
            _ => None,
        }
    }
}

// ── TLV (Type-Length-Value) helpers ──────────────────────────────────────────
// Token-2022 stores extensions as TLV entries after the base account data:
//   [base data] [AccountType:1] [padding:3] [TLV entries...]
// Each TLV entry: [type:u16 LE] [length:u16 LE] [data:length bytes]

const TLV_HEADER_LEN: usize = 4; // 2 bytes type + 2 bytes length

/// Read a specific extension from a TLV-encoded extension area.
/// Returns a slice of the extension data if found.
pub fn tlv_get_extension(extension_data: &[u8], target: ExtensionType) -> Option<&[u8]> {
    let target_type = target as u16;
    let mut offset = 0;
    while offset + TLV_HEADER_LEN <= extension_data.len() {
        let ext_type = u16::from_le_bytes(extension_data[offset..offset + 2].try_into().ok()?);
        let ext_len =
            u16::from_le_bytes(extension_data[offset + 2..offset + 4].try_into().ok()?) as usize;

        if ext_type == 0 && ext_len == 0 {
            break; // End sentinel
        }

        let data_start = offset + TLV_HEADER_LEN;
        let data_end = data_start + ext_len;
        if data_end > extension_data.len() {
            return None; // Corrupt
        }

        if ext_type == target_type {
            return Some(&extension_data[data_start..data_end]);
        }

        offset = data_end;
    }
    None
}

/// Write or overwrite an extension in a TLV-encoded extension area.
/// If the extension already exists with the same length, overwrites in-place.
/// If it doesn't exist, appends at the end.
pub fn tlv_set_extension(
    extension_data: &mut Vec<u8>,
    ext_type: ExtensionType,
    data: &[u8],
) -> Result<(), Token2022Error> {
    let type_val = ext_type as u16;
    let mut offset = 0;

    // Search for existing entry
    while offset + TLV_HEADER_LEN <= extension_data.len() {
        let existing_type = u16::from_le_bytes(
            extension_data[offset..offset + 2]
                .try_into()
                .map_err(|_| Token2022Error::InvalidState)?,
        );
        let existing_len = u16::from_le_bytes(
            extension_data[offset + 2..offset + 4]
                .try_into()
                .map_err(|_| Token2022Error::InvalidState)?,
        ) as usize;

        if existing_type == 0 && existing_len == 0 {
            break; // End sentinel — append here
        }

        let data_start = offset + TLV_HEADER_LEN;
        let data_end = data_start + existing_len;
        if data_end > extension_data.len() {
            return Err(Token2022Error::InvalidState);
        }

        if existing_type == type_val {
            if existing_len == data.len() {
                // Overwrite in-place
                extension_data[data_start..data_end].copy_from_slice(data);
                return Ok(());
            }
            // Different size: remove old entry, will append new one below
            extension_data.drain(offset..data_end);
            // Don't advance offset — continue scanning from same position
            continue;
        }

        offset = data_end;
    }

    // Append new TLV entry
    extension_data.truncate(offset); // Trim any trailing zeros/sentinels
    extension_data.extend_from_slice(&type_val.to_le_bytes());
    extension_data.extend_from_slice(&(data.len() as u16).to_le_bytes());
    extension_data.extend_from_slice(data);

    Ok(())
}

/// Check whether a specific extension exists in TLV data.
pub fn tlv_has_extension(extension_data: &[u8], target: ExtensionType) -> bool {
    tlv_get_extension(extension_data, target).is_some()
}

/// Transfer fee amount extension (per-account, tracks withheld fees)
#[derive(Debug, Clone, PartialEq)]
pub struct TransferFeeAmount {
    pub withheld_amount: u64,
}

impl TransferFeeAmount {
    pub const LEN: usize = 8;

    pub fn pack(&self) -> Vec<u8> {
        self.withheld_amount.to_le_bytes().to_vec()
    }

    pub fn unpack(data: &[u8]) -> Result<Self, Token2022Error> {
        if data.len() < Self::LEN {
            return Err(Token2022Error::InvalidState);
        }
        Ok(Self {
            withheld_amount: u64::from_le_bytes(data[..8].try_into().unwrap()),
        })
    }
}

/// Permanent delegate extension
#[derive(Debug, Clone, PartialEq)]
pub struct PermanentDelegate {
    pub delegate: Option<Pubkey>,
}

impl PermanentDelegate {
    pub const LEN: usize = 33;

    pub fn pack(&self) -> Vec<u8> {
        let mut data = vec![0u8; Self::LEN];
        if let Some(d) = self.delegate {
            data[0] = 1;
            data[1..33].copy_from_slice(&d.to_bytes());
        }
        data
    }

    pub fn unpack(data: &[u8]) -> Result<Self, Token2022Error> {
        if data.len() < Self::LEN {
            return Err(Token2022Error::InvalidState);
        }
        let delegate = if data[0] == 1 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&data[1..33]);
            Some(Pubkey::new(bytes))
        } else {
            None
        };
        Ok(Self { delegate })
    }
}

/// Transfer hook extension (mint-level)
#[derive(Debug, Clone, PartialEq)]
pub struct TransferHookExt {
    pub authority: Option<Pubkey>,
    pub program_id: Option<Pubkey>,
}

impl TransferHookExt {
    pub const LEN: usize = 66;

    pub fn pack(&self) -> Vec<u8> {
        let mut data = vec![0u8; Self::LEN];
        if let Some(a) = self.authority {
            data[0] = 1;
            data[1..33].copy_from_slice(&a.to_bytes());
        }
        if let Some(p) = self.program_id {
            data[33] = 1;
            data[34..66].copy_from_slice(&p.to_bytes());
        }
        data
    }

    pub fn unpack(data: &[u8]) -> Result<Self, Token2022Error> {
        if data.len() < Self::LEN {
            return Err(Token2022Error::InvalidState);
        }
        let authority = if data[0] == 1 {
            let mut b = [0u8; 32];
            b.copy_from_slice(&data[1..33]);
            Some(Pubkey::new(b))
        } else {
            None
        };
        let program_id = if data[33] == 1 {
            let mut b = [0u8; 32];
            b.copy_from_slice(&data[34..66]);
            Some(Pubkey::new(b))
        } else {
            None
        };
        Ok(Self {
            authority,
            program_id,
        })
    }
}

/// Metadata pointer extension
#[derive(Debug, Clone, PartialEq)]
pub struct MetadataPointer {
    pub authority: Option<Pubkey>,
    pub metadata_address: Option<Pubkey>,
}

impl MetadataPointer {
    pub const LEN: usize = 66;

    pub fn pack(&self) -> Vec<u8> {
        let mut data = vec![0u8; Self::LEN];
        if let Some(a) = self.authority {
            data[0] = 1;
            data[1..33].copy_from_slice(&a.to_bytes());
        }
        if let Some(m) = self.metadata_address {
            data[33] = 1;
            data[34..66].copy_from_slice(&m.to_bytes());
        }
        data
    }

    pub fn unpack(data: &[u8]) -> Result<Self, Token2022Error> {
        if data.len() < Self::LEN {
            return Err(Token2022Error::InvalidState);
        }
        let authority = if data[0] == 1 {
            let mut b = [0u8; 32];
            b.copy_from_slice(&data[1..33]);
            Some(Pubkey::new(b))
        } else {
            None
        };
        let metadata_address = if data[33] == 1 {
            let mut b = [0u8; 32];
            b.copy_from_slice(&data[34..66]);
            Some(Pubkey::new(b))
        } else {
            None
        };
        Ok(Self {
            authority,
            metadata_address,
        })
    }
}

/// Group pointer extension
#[derive(Debug, Clone, PartialEq)]
pub struct GroupPointer {
    pub authority: Option<Pubkey>,
    pub group_address: Option<Pubkey>,
}

impl GroupPointer {
    pub const LEN: usize = 66;

    pub fn pack(&self) -> Vec<u8> {
        let mut data = vec![0u8; Self::LEN];
        if let Some(a) = self.authority {
            data[0] = 1;
            data[1..33].copy_from_slice(&a.to_bytes());
        }
        if let Some(g) = self.group_address {
            data[33] = 1;
            data[34..66].copy_from_slice(&g.to_bytes());
        }
        data
    }

    pub fn unpack(data: &[u8]) -> Result<Self, Token2022Error> {
        if data.len() < Self::LEN {
            return Err(Token2022Error::InvalidState);
        }
        let authority = if data[0] == 1 {
            let mut b = [0u8; 32];
            b.copy_from_slice(&data[1..33]);
            Some(Pubkey::new(b))
        } else {
            None
        };
        let group_address = if data[33] == 1 {
            let mut b = [0u8; 32];
            b.copy_from_slice(&data[34..66]);
            Some(Pubkey::new(b))
        } else {
            None
        };
        Ok(Self {
            authority,
            group_address,
        })
    }
}

/// Group member pointer extension
#[derive(Debug, Clone, PartialEq)]
pub struct GroupMemberPointer {
    pub authority: Option<Pubkey>,
    pub member_address: Option<Pubkey>,
}

impl GroupMemberPointer {
    pub const LEN: usize = 66;

    pub fn pack(&self) -> Vec<u8> {
        let mut data = vec![0u8; Self::LEN];
        if let Some(a) = self.authority {
            data[0] = 1;
            data[1..33].copy_from_slice(&a.to_bytes());
        }
        if let Some(m) = self.member_address {
            data[33] = 1;
            data[34..66].copy_from_slice(&m.to_bytes());
        }
        data
    }

    pub fn unpack(data: &[u8]) -> Result<Self, Token2022Error> {
        if data.len() < Self::LEN {
            return Err(Token2022Error::InvalidState);
        }
        let authority = if data[0] == 1 {
            let mut b = [0u8; 32];
            b.copy_from_slice(&data[1..33]);
            Some(Pubkey::new(b))
        } else {
            None
        };
        let member_address = if data[33] == 1 {
            let mut b = [0u8; 32];
            b.copy_from_slice(&data[34..66]);
            Some(Pubkey::new(b))
        } else {
            None
        };
        Ok(Self {
            authority,
            member_address,
        })
    }
}

/// Transfer fee configuration extension
#[derive(Debug, Clone, PartialEq)]
pub struct TransferFeeConfig {
    pub transfer_fee_config_authority: Option<Pubkey>,
    pub withdraw_withheld_authority: Option<Pubkey>,
    pub withheld_amount: u64,
    pub older_transfer_fee: TransferFee,
    pub newer_transfer_fee: TransferFee,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TransferFee {
    pub epoch: u64,
    pub maximum_fee: u64,
    pub transfer_fee_basis_points: u16,
}

impl TransferFeeConfig {
    pub const LEN: usize = 110;

    pub fn pack(&self) -> Vec<u8> {
        let mut data = vec![0u8; Self::LEN];
        let mut offset = 0;

        // transfer_fee_config_authority
        if let Some(auth) = self.transfer_fee_config_authority {
            data[offset] = 1;
            data[offset + 1..offset + 33].copy_from_slice(&auth.to_bytes());
        }
        offset += 33;

        // withdraw_withheld_authority
        if let Some(auth) = self.withdraw_withheld_authority {
            data[offset] = 1;
            data[offset + 1..offset + 33].copy_from_slice(&auth.to_bytes());
        }
        offset += 33;

        // withheld_amount
        data[offset..offset + 8].copy_from_slice(&self.withheld_amount.to_le_bytes());
        offset += 8;

        // older_transfer_fee
        data[offset..offset + 8].copy_from_slice(&self.older_transfer_fee.epoch.to_le_bytes());
        data[offset + 8..offset + 16]
            .copy_from_slice(&self.older_transfer_fee.maximum_fee.to_le_bytes());
        data[offset + 16..offset + 18].copy_from_slice(
            &self
                .older_transfer_fee
                .transfer_fee_basis_points
                .to_le_bytes(),
        );
        offset += 18;

        // newer_transfer_fee
        data[offset..offset + 8].copy_from_slice(&self.newer_transfer_fee.epoch.to_le_bytes());
        data[offset + 8..offset + 16]
            .copy_from_slice(&self.newer_transfer_fee.maximum_fee.to_le_bytes());
        data[offset + 16..offset + 18].copy_from_slice(
            &self
                .newer_transfer_fee
                .transfer_fee_basis_points
                .to_le_bytes(),
        );

        data
    }

    pub fn unpack(data: &[u8]) -> Result<Self, Token2022Error> {
        if data.len() < Self::LEN {
            return Err(Token2022Error::InvalidState);
        }

        let mut offset = 0;

        let transfer_fee_config_authority = if data[offset] == 1 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&data[offset + 1..offset + 33]);
            Some(Pubkey::new(bytes))
        } else {
            None
        };
        offset += 33;

        let withdraw_withheld_authority = if data[offset] == 1 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&data[offset + 1..offset + 33]);
            Some(Pubkey::new(bytes))
        } else {
            None
        };
        offset += 33;

        let withheld_amount = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
        offset += 8;

        let older_transfer_fee = TransferFee {
            epoch: u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap()),
            maximum_fee: u64::from_le_bytes(data[offset + 8..offset + 16].try_into().unwrap()),
            transfer_fee_basis_points: u16::from_le_bytes(
                data[offset + 16..offset + 18].try_into().unwrap(),
            ),
        };
        offset += 18;

        let newer_transfer_fee = TransferFee {
            epoch: u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap()),
            maximum_fee: u64::from_le_bytes(data[offset + 8..offset + 16].try_into().unwrap()),
            transfer_fee_basis_points: u16::from_le_bytes(
                data[offset + 16..offset + 18].try_into().unwrap(),
            ),
        };

        Ok(Self {
            transfer_fee_config_authority,
            withdraw_withheld_authority,
            withheld_amount,
            older_transfer_fee,
            newer_transfer_fee,
        })
    }

    /// Calculate transfer fee for an amount
    pub fn calculate_fee(&self, amount: u64, current_epoch: u64) -> Result<u64, Token2022Error> {
        let fee_config = if current_epoch >= self.newer_transfer_fee.epoch {
            &self.newer_transfer_fee
        } else {
            &self.older_transfer_fee
        };

        let fee = (amount as u128)
            .checked_mul(fee_config.transfer_fee_basis_points as u128)
            .ok_or(Token2022Error::Overflow)?
            .checked_div(10000)
            .ok_or(Token2022Error::Overflow)?
            .min(fee_config.maximum_fee as u128);

        Ok(fee as u64)
    }
}

/// Default account state extension (for mints)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultAccountState {
    Uninitialized = 0,
    Initialized = 1,
    Frozen = 2,
}

impl DefaultAccountState {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Uninitialized),
            1 => Some(Self::Initialized),
            2 => Some(Self::Frozen),
            _ => None,
        }
    }
}

/// Mint close authority extension
#[derive(Debug, Clone, PartialEq)]
pub struct MintCloseAuthority {
    pub close_authority: Option<Pubkey>,
}

impl MintCloseAuthority {
    pub const LEN: usize = 33;

    pub fn pack(&self) -> Vec<u8> {
        let mut data = vec![0u8; Self::LEN];
        if let Some(auth) = self.close_authority {
            data[0] = 1;
            data[1..33].copy_from_slice(&auth.to_bytes());
        }
        data
    }

    pub fn unpack(data: &[u8]) -> Result<Self, Token2022Error> {
        if data.len() < Self::LEN {
            return Err(Token2022Error::InvalidState);
        }

        let close_authority = if data[0] == 1 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&data[1..33]);
            Some(Pubkey::new(bytes))
        } else {
            None
        };

        Ok(Self { close_authority })
    }
}

/// Interest-bearing configuration extension
#[derive(Debug, Clone, PartialEq)]
pub struct InterestBearingConfig {
    pub rate_authority: Option<Pubkey>,
    pub initialization_timestamp: i64,
    pub pre_update_average_rate: i16,
    pub last_update_timestamp: i64,
    pub current_rate: i16,
}

impl InterestBearingConfig {
    pub const LEN: usize = 57;

    pub fn pack(&self) -> Vec<u8> {
        let mut data = vec![0u8; Self::LEN];
        let mut offset = 0;

        if let Some(auth) = self.rate_authority {
            data[offset] = 1;
            data[offset + 1..offset + 33].copy_from_slice(&auth.to_bytes());
        }
        offset += 33;

        data[offset..offset + 8].copy_from_slice(&self.initialization_timestamp.to_le_bytes());
        offset += 8;

        data[offset..offset + 2].copy_from_slice(&self.pre_update_average_rate.to_le_bytes());
        offset += 2;

        data[offset..offset + 8].copy_from_slice(&self.last_update_timestamp.to_le_bytes());
        offset += 8;

        data[offset..offset + 2].copy_from_slice(&self.current_rate.to_le_bytes());

        data
    }

    pub fn unpack(data: &[u8]) -> Result<Self, Token2022Error> {
        if data.len() < Self::LEN {
            return Err(Token2022Error::InvalidState);
        }

        let mut offset = 0;

        let rate_authority = if data[offset] == 1 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&data[offset + 1..offset + 33]);
            Some(Pubkey::new(bytes))
        } else {
            None
        };
        offset += 33;

        let initialization_timestamp =
            i64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
        offset += 8;

        let pre_update_average_rate =
            i16::from_le_bytes(data[offset..offset + 2].try_into().unwrap());
        offset += 2;

        let last_update_timestamp =
            i64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
        offset += 8;

        let current_rate = i16::from_le_bytes(data[offset..offset + 2].try_into().unwrap());

        Ok(Self {
            rate_authority,
            initialization_timestamp,
            pre_update_average_rate,
            last_update_timestamp,
            current_rate,
        })
    }
}

/// Token-2022 account with extensions support.
///
/// On-disk layout: [base 165 bytes] [AccountType:1] [padding:3] [TLV extensions...]
#[derive(Debug, Clone, PartialEq)]
pub struct Token2022Account {
    pub mint: Pubkey,
    pub owner: Pubkey,
    pub amount: u64,
    pub delegate: Option<Pubkey>,
    pub state: u8,
    pub is_native: Option<u64>,
    pub delegated_amount: u64,
    pub close_authority: Option<Pubkey>,
    /// TLV-encoded extension data (without the AccountType byte or padding)
    pub extensions: Vec<u8>,
}

/// Padding between AccountType discriminator and first TLV entry
const ACCOUNT_TYPE_PADDING: usize = 3;

impl Token2022Account {
    pub const BASE_LEN: usize = 165;

    pub fn has_extension(&self, ext_type: ExtensionType) -> bool {
        tlv_has_extension(&self.extensions, ext_type)
    }

    pub fn get_extension(&self, ext_type: ExtensionType) -> Option<&[u8]> {
        tlv_get_extension(&self.extensions, ext_type)
    }

    pub fn set_extension(
        &mut self,
        ext_type: ExtensionType,
        data: &[u8],
    ) -> Result<(), Token2022Error> {
        tlv_set_extension(&mut self.extensions, ext_type, data)
    }

    /// Pack into on-disk format: base 165 + AccountType + padding + TLV
    pub fn pack(&self) -> Vec<u8> {
        let ext_area = if self.extensions.is_empty() {
            0
        } else {
            1 + ACCOUNT_TYPE_PADDING + self.extensions.len()
        };
        let mut data = vec![0u8; Self::BASE_LEN + ext_area];

        // mint
        data[0..32].copy_from_slice(&self.mint.to_bytes());
        // owner
        data[32..64].copy_from_slice(&self.owner.to_bytes());
        // amount
        data[64..72].copy_from_slice(&self.amount.to_le_bytes());
        // delegate
        if let Some(d) = self.delegate {
            data[72] = 1;
            data[73..105].copy_from_slice(&d.to_bytes());
        }
        // state
        data[105] = self.state;
        // is_native
        if let Some(n) = self.is_native {
            data[106] = 1;
            data[107..115].copy_from_slice(&n.to_le_bytes());
        }
        // delegated_amount
        data[115..123].copy_from_slice(&self.delegated_amount.to_le_bytes());
        // close_authority
        if let Some(ca) = self.close_authority {
            data[123] = 1;
            data[124..156].copy_from_slice(&ca.to_bytes());
        }
        // Bytes 156..165 are reserved/padding in base layout

        if !self.extensions.is_empty() {
            let off = Self::BASE_LEN;
            data[off] = AccountType::Account as u8;
            // padding bytes are already zero
            let tlv_start = off + 1 + ACCOUNT_TYPE_PADDING;
            data[tlv_start..tlv_start + self.extensions.len()].copy_from_slice(&self.extensions);
        }

        data
    }

    /// Unpack from on-disk format
    pub fn unpack(data: &[u8]) -> Result<Self, Token2022Error> {
        if data.len() < Self::BASE_LEN {
            return Err(Token2022Error::InvalidState);
        }

        let mut mint_bytes = [0u8; 32];
        mint_bytes.copy_from_slice(&data[0..32]);
        let mint = Pubkey::new(mint_bytes);

        let mut owner_bytes = [0u8; 32];
        owner_bytes.copy_from_slice(&data[32..64]);
        let owner = Pubkey::new(owner_bytes);

        let amount = u64::from_le_bytes(data[64..72].try_into().unwrap());

        let delegate = if data[72] == 1 {
            let mut b = [0u8; 32];
            b.copy_from_slice(&data[73..105]);
            Some(Pubkey::new(b))
        } else {
            None
        };

        let state = data[105];

        let is_native = if data[106] == 1 {
            Some(u64::from_le_bytes(data[107..115].try_into().unwrap()))
        } else {
            None
        };

        let delegated_amount = u64::from_le_bytes(data[115..123].try_into().unwrap());

        let close_authority = if data[123] == 1 {
            let mut b = [0u8; 32];
            b.copy_from_slice(&data[124..156]);
            Some(Pubkey::new(b))
        } else {
            None
        };

        let extensions = if data.len() > Self::BASE_LEN + 1 + ACCOUNT_TYPE_PADDING {
            let tlv_start = Self::BASE_LEN + 1 + ACCOUNT_TYPE_PADDING;
            data[tlv_start..].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            mint,
            owner,
            amount,
            delegate,
            state,
            is_native,
            delegated_amount,
            close_authority,
            extensions,
        })
    }
}

/// Token-2022 mint with extensions support.
///
/// On-disk layout: [base 82 bytes] [AccountType:1] [padding:3] [TLV extensions...]
#[derive(Debug, Clone, PartialEq)]
pub struct Token2022Mint {
    pub mint_authority: Option<Pubkey>,
    pub supply: u64,
    pub decimals: u8,
    pub is_initialized: bool,
    pub freeze_authority: Option<Pubkey>,
    /// TLV-encoded extension data
    pub extensions: Vec<u8>,
}

impl Token2022Mint {
    pub const BASE_LEN: usize = 82;

    pub fn has_extension(&self, ext_type: ExtensionType) -> bool {
        tlv_has_extension(&self.extensions, ext_type)
    }

    pub fn get_extension(&self, ext_type: ExtensionType) -> Option<&[u8]> {
        tlv_get_extension(&self.extensions, ext_type)
    }

    pub fn set_extension(
        &mut self,
        ext_type: ExtensionType,
        data: &[u8],
    ) -> Result<(), Token2022Error> {
        tlv_set_extension(&mut self.extensions, ext_type, data)
    }

    /// Pack into on-disk format: base 82 + AccountType + padding + TLV
    pub fn pack(&self) -> Vec<u8> {
        let ext_area = if self.extensions.is_empty() {
            0
        } else {
            1 + ACCOUNT_TYPE_PADDING + self.extensions.len()
        };
        let mut data = vec![0u8; Self::BASE_LEN + ext_area];

        // mint_authority
        if let Some(auth) = self.mint_authority {
            data[0] = 1;
            data[1..33].copy_from_slice(&auth.to_bytes());
        }
        // supply
        data[33..41].copy_from_slice(&self.supply.to_le_bytes());
        // decimals
        data[41] = self.decimals;
        // is_initialized
        data[42] = u8::from(self.is_initialized);
        // freeze_authority
        if let Some(auth) = self.freeze_authority {
            data[43] = 1;
            data[44..76].copy_from_slice(&auth.to_bytes());
        }
        // Bytes 76..82 are reserved/padding in base layout

        if !self.extensions.is_empty() {
            let off = Self::BASE_LEN;
            data[off] = AccountType::Mint as u8;
            let tlv_start = off + 1 + ACCOUNT_TYPE_PADDING;
            data[tlv_start..tlv_start + self.extensions.len()].copy_from_slice(&self.extensions);
        }

        data
    }

    /// Unpack from on-disk format
    pub fn unpack(data: &[u8]) -> Result<Self, Token2022Error> {
        if data.len() < Self::BASE_LEN {
            return Err(Token2022Error::InvalidState);
        }

        let mint_authority = if data[0] == 1 {
            let mut b = [0u8; 32];
            b.copy_from_slice(&data[1..33]);
            Some(Pubkey::new(b))
        } else {
            None
        };

        let supply = u64::from_le_bytes(data[33..41].try_into().unwrap());
        let decimals = data[41];
        let is_initialized = data[42] == 1;

        let freeze_authority = if data[43] == 1 {
            let mut b = [0u8; 32];
            b.copy_from_slice(&data[44..76]);
            Some(Pubkey::new(b))
        } else {
            None
        };

        let extensions = if data.len() > Self::BASE_LEN + 1 + ACCOUNT_TYPE_PADDING {
            let tlv_start = Self::BASE_LEN + 1 + ACCOUNT_TYPE_PADDING;
            data[tlv_start..].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            mint_authority,
            supply,
            decimals,
            is_initialized,
            freeze_authority,
            extensions,
        })
    }

    /// Unpack from Account, reading raw bytes from AccountData
    pub fn unpack_from_account(account: &Account) -> Result<Self, Token2022Error> {
        Self::unpack(account.data.as_slice())
    }

    /// Write mint data back into Account
    pub fn pack_into_account(&self, account: &mut Account) {
        let packed = self.pack();
        account.data = AccountData::new(packed);
    }
}

/// Helper: unpack a Token2022Account from an Account
impl Token2022Account {
    pub fn unpack_from_account(account: &Account) -> Result<Self, Token2022Error> {
        Self::unpack(account.data.as_slice())
    }

    pub fn pack_into_account(&self, account: &mut Account) {
        let packed = self.pack();
        account.data = AccountData::new(packed);
    }
}

/// SPL Token-2022 Program instruction executor
pub struct Token2022ProgramExecutor {
    base_cost: u64,
}

impl Token2022ProgramExecutor {
    pub fn new(base_cost: u64) -> Self {
        Self { base_cost }
    }

    pub fn execute(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if context.instruction_data.is_empty() {
            return Ok(ExecutionOutcome::success(self.base_cost));
        }

        let instruction_type = context.instruction_data[0];

        // Token-2022 supports all Token Program instructions (0-24)
        // plus additional extension-related instructions (25+)
        match instruction_type {
            // Base Token instructions (0-24) - delegate to Token Program logic
            0 => self.initialize_mint(context),
            1 => self.initialize_account(context),
            2 => self.initialize_multisig(context),
            3 => self.transfer(context),
            4 => self.approve(context),
            5 => self.revoke(context),
            7 => self.mint_to(context),
            8 => self.burn(context),
            9 => self.close_account(context),
            10 => self.freeze_account(context),
            11 => self.thaw_account(context),
            12 => self.transfer_checked(context),
            13 => self.approve_checked(context),
            14 => self.mint_to_checked(context),
            15 => self.burn_checked(context),
            16 => self.initialize_account2(context),
            17 => self.sync_native(context),
            18 => self.initialize_account3(context),
            20 => self.initialize_mint2(context),
            21 => self.get_account_data_size(context),
            22 => self.initialize_immutable_owner(context),
            23 => self.amount_to_ui_amount(context),
            24 => self.ui_amount_to_amount(context),
            // Missing base instructions
            6 => self.set_authority(context),
            19 => self.reallocate(context),
            // Extension instructions (25+)
            25 => self.initialize_mint_close_authority(context),
            26 => self.initialize_transfer_fee_config(context),
            27 => self.transfer_checked_with_fee(context),
            28 => self.withdraw_withheld_tokens_from_mint(context),
            29 => self.withdraw_withheld_tokens_from_accounts(context),
            30 => self.harvest_withheld_tokens_to_mint(context),
            31 => self.set_transfer_fee(context),
            32 => self.initialize_default_account_state(context),
            33 => self.update_default_account_state(context),
            34 => self.initialize_non_transferable_mint(context),
            35 => self.initialize_interest_bearing_config(context),
            36 => self.update_rate_interest_bearing_mint(context),
            37 => self.initialize_permanent_delegate(context),
            38 => self.toggle_cpi_guard(context),
            39 => self.initialize_transfer_hook(context),
            40 => self.initialize_metadata_pointer(context),
            41 => self.initialize_group_pointer(context),
            42 => self.initialize_group_member_pointer(context),
            _ => Err(format!(
                "Unknown Token-2022 instruction: {}",
                instruction_type
            )),
        }
    }

    // Base Token Program instructions (simplified implementations)
    // In practice, these would use the full Token Program logic

    fn initialize_mint(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if context.accounts.is_empty() {
            return Err("InitializeMint requires at least 1 account".to_string());
        }
        // instruction_data: [0:discriminator][1:decimals][2..34:mint_authority][34:has_freeze][35..67:freeze_authority]
        if context.instruction_data.len() < 34 {
            return Err("InitializeMint: insufficient instruction data".to_string());
        }

        let (mint_pubkey, mut mint_account, mint_writable) = context.accounts[0].clone();
        if !mint_writable {
            return Err("Mint account must be writable".to_string());
        }

        let decimals = context.instruction_data[1];
        let mut auth_bytes = [0u8; 32];
        auth_bytes.copy_from_slice(&context.instruction_data[2..34]);
        let mint_authority = Some(Pubkey::new(auth_bytes));

        let freeze_authority =
            if context.instruction_data.len() >= 67 && context.instruction_data[34] == 1 {
                let mut fb = [0u8; 32];
                fb.copy_from_slice(&context.instruction_data[35..67]);
                Some(Pubkey::new(fb))
            } else {
                None
            };

        let mint = Token2022Mint {
            mint_authority,
            supply: 0,
            decimals,
            is_initialized: true,
            freeze_authority,
            extensions: Vec::new(),
        };
        mint.pack_into_account(&mut mint_account);

        let mut outcome = ExecutionOutcome::success(self.base_cost + 50);
        outcome.modified_accounts.insert(mint_pubkey, mint_account);
        Ok(outcome)
    }

    fn initialize_account(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        // accounts: [0:token_account(w), 1:mint, 2:owner, 3:rent_sysvar]
        if context.accounts.len() < 3 {
            return Err("InitializeAccount requires at least 3 accounts".to_string());
        }

        let (acct_pubkey, mut acct, acct_writable) = context.accounts[0].clone();
        if !acct_writable {
            return Err("Token account must be writable".to_string());
        }

        let (mint_pubkey, _mint_account, _) = context.accounts[1].clone();
        let (owner_pubkey, _, _) = context.accounts[2].clone();

        let token = Token2022Account {
            mint: mint_pubkey,
            owner: owner_pubkey,
            amount: 0,
            delegate: None,
            state: 1, // Initialized
            is_native: None,
            delegated_amount: 0,
            close_authority: None,
            extensions: Vec::new(),
        };
        token.pack_into_account(&mut acct);

        let mut outcome = ExecutionOutcome::success(self.base_cost + 50);
        outcome.modified_accounts.insert(acct_pubkey, acct);
        Ok(outcome)
    }

    fn initialize_multisig(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        // accounts: [0:multisig(w), 1:rent_sysvar, 2+:signers]
        if context.accounts.len() < 3 {
            return Err("InitializeMultisig requires at least 3 accounts".to_string());
        }
        if context.instruction_data.len() < 2 {
            return Err("InitializeMultisig requires m value".to_string());
        }

        let (ms_pubkey, mut ms_account, ms_writable) = context.accounts[0].clone();
        if !ms_writable {
            return Err("Multisig account must be writable".to_string());
        }

        let m = context.instruction_data[1];
        let n = (context.accounts.len() - 2) as u8;
        if m == 0 || m > n || n > 11 {
            return Err("Invalid multisig parameters".to_string());
        }

        // Multisig layout: [1:is_initialized][1:m][1:n][32*11:signers] = 355 bytes
        let mut data = vec![0u8; 355];
        data[0] = 1; // is_initialized
        data[1] = m;
        data[2] = n;
        for i in 0..n as usize {
            let (signer_pk, _, _) = &context.accounts[i + 2];
            data[3 + i * 32..3 + (i + 1) * 32].copy_from_slice(&signer_pk.to_bytes());
        }
        ms_account.data = AccountData::new(data);

        let mut outcome = ExecutionOutcome::success(self.base_cost + 50);
        outcome.modified_accounts.insert(ms_pubkey, ms_account);
        Ok(outcome)
    }

    fn transfer(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if context.accounts.len() < 3 {
            return Err("Transfer requires at least 3 accounts".to_string());
        }
        if context.instruction_data.len() < 9 {
            return Err("Transfer requires amount".to_string());
        }

        let (source_pubkey, mut source_account, source_writable) = context.accounts[0].clone();
        let (dest_pubkey, mut dest_account, dest_writable) = context.accounts[1].clone();

        if !source_writable || !dest_writable {
            return Err("Source and destination must be writable".to_string());
        }

        let amount = u64::from_le_bytes(context.instruction_data[1..9].try_into().unwrap());

        // Unpack source and dest token accounts
        let mut source_token =
            Token2022Account::unpack_from_account(&source_account).map_err(|e| e.to_string())?;
        let mut dest_token =
            Token2022Account::unpack_from_account(&dest_account).map_err(|e| e.to_string())?;

        // Check non-transferable
        if source_token.has_extension(ExtensionType::NonTransferableAccount) {
            return Err(Token2022Error::NonTransferable.to_string());
        }

        // Check frozen
        if source_token.state == 2 || dest_token.state == 2 {
            return Err(Token2022Error::AccountFrozen.to_string());
        }

        // Deduct from source
        source_token.amount = source_token
            .amount
            .checked_sub(amount)
            .ok_or_else(|| Token2022Error::InsufficientFunds.to_string())?;

        // Credit dest
        dest_token.amount = dest_token
            .amount
            .checked_add(amount)
            .ok_or_else(|| Token2022Error::Overflow.to_string())?;

        // Pack back
        source_token.pack_into_account(&mut source_account);
        dest_token.pack_into_account(&mut dest_account);

        let mut outcome = ExecutionOutcome::success(self.base_cost + 100);
        outcome
            .modified_accounts
            .insert(source_pubkey, source_account);
        outcome.modified_accounts.insert(dest_pubkey, dest_account);

        Ok(outcome)
    }

    fn approve(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        // accounts: [0:source(w), 1:delegate, 2:owner]
        if context.accounts.len() < 3 {
            return Err("Approve requires at least 3 accounts".to_string());
        }
        if context.instruction_data.len() < 9 {
            return Err("Approve requires amount".to_string());
        }

        let (src_pubkey, mut src_account, src_writable) = context.accounts[0].clone();
        if !src_writable {
            return Err("Source account must be writable".to_string());
        }
        let (delegate_pubkey, _, _) = context.accounts[1].clone();

        let amount = u64::from_le_bytes(context.instruction_data[1..9].try_into().unwrap());

        let mut token =
            Token2022Account::unpack_from_account(&src_account).map_err(|e| e.to_string())?;
        token.delegate = Some(delegate_pubkey);
        token.delegated_amount = amount;
        token.pack_into_account(&mut src_account);

        let mut outcome = ExecutionOutcome::success(self.base_cost + 50);
        outcome.modified_accounts.insert(src_pubkey, src_account);
        Ok(outcome)
    }

    fn revoke(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        // accounts: [0:source(w), 1:owner]
        if context.accounts.len() < 2 {
            return Err("Revoke requires at least 2 accounts".to_string());
        }

        let (src_pubkey, mut src_account, src_writable) = context.accounts[0].clone();
        if !src_writable {
            return Err("Source account must be writable".to_string());
        }

        let mut token =
            Token2022Account::unpack_from_account(&src_account).map_err(|e| e.to_string())?;
        token.delegate = None;
        token.delegated_amount = 0;
        token.pack_into_account(&mut src_account);

        let mut outcome = ExecutionOutcome::success(self.base_cost + 30);
        outcome.modified_accounts.insert(src_pubkey, src_account);
        Ok(outcome)
    }

    fn mint_to(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        // accounts: [0:mint(w), 1:destination(w), 2:mint_authority]
        if context.accounts.len() < 3 {
            return Err("MintTo requires at least 3 accounts".to_string());
        }
        if context.instruction_data.len() < 9 {
            return Err("MintTo requires amount".to_string());
        }

        let (mint_pubkey, mut mint_account, mint_writable) = context.accounts[0].clone();
        let (dest_pubkey, mut dest_account, dest_writable) = context.accounts[1].clone();
        if !mint_writable || !dest_writable {
            return Err("Mint and destination must be writable".to_string());
        }

        let amount = u64::from_le_bytes(context.instruction_data[1..9].try_into().unwrap());

        let mut mint =
            Token2022Mint::unpack_from_account(&mint_account).map_err(|e| e.to_string())?;
        if mint.mint_authority.is_none() {
            return Err(Token2022Error::FixedSupply.to_string());
        }
        mint.supply = mint
            .supply
            .checked_add(amount)
            .ok_or_else(|| Token2022Error::Overflow.to_string())?;
        mint.pack_into_account(&mut mint_account);

        let mut dest_token =
            Token2022Account::unpack_from_account(&dest_account).map_err(|e| e.to_string())?;
        dest_token.amount = dest_token
            .amount
            .checked_add(amount)
            .ok_or_else(|| Token2022Error::Overflow.to_string())?;
        dest_token.pack_into_account(&mut dest_account);

        let mut outcome = ExecutionOutcome::success(self.base_cost + 100);
        outcome.modified_accounts.insert(mint_pubkey, mint_account);
        outcome.modified_accounts.insert(dest_pubkey, dest_account);
        Ok(outcome)
    }

    fn burn(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        // accounts: [0:source(w), 1:mint(w), 2:owner]
        if context.accounts.len() < 3 {
            return Err("Burn requires at least 3 accounts".to_string());
        }
        if context.instruction_data.len() < 9 {
            return Err("Burn requires amount".to_string());
        }

        let (src_pubkey, mut src_account, src_writable) = context.accounts[0].clone();
        let (mint_pubkey, mut mint_account, mint_writable) = context.accounts[1].clone();
        if !src_writable || !mint_writable {
            return Err("Source and mint must be writable".to_string());
        }

        let amount = u64::from_le_bytes(context.instruction_data[1..9].try_into().unwrap());

        let mut src_token =
            Token2022Account::unpack_from_account(&src_account).map_err(|e| e.to_string())?;
        src_token.amount = src_token
            .amount
            .checked_sub(amount)
            .ok_or_else(|| Token2022Error::InsufficientFunds.to_string())?;
        src_token.pack_into_account(&mut src_account);

        let mut mint =
            Token2022Mint::unpack_from_account(&mint_account).map_err(|e| e.to_string())?;
        mint.supply = mint.supply.saturating_sub(amount);
        mint.pack_into_account(&mut mint_account);

        let mut outcome = ExecutionOutcome::success(self.base_cost + 100);
        outcome.modified_accounts.insert(src_pubkey, src_account);
        outcome.modified_accounts.insert(mint_pubkey, mint_account);
        Ok(outcome)
    }

    fn close_account(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        // accounts: [0:account_to_close(w), 1:destination(w), 2:owner]
        if context.accounts.len() < 3 {
            return Err("CloseAccount requires at least 3 accounts".to_string());
        }

        let (close_pubkey, mut close_account, close_writable) = context.accounts[0].clone();
        let (dest_pubkey, mut dest_account, dest_writable) = context.accounts[1].clone();
        if !close_writable || !dest_writable {
            return Err("Account and destination must be writable".to_string());
        }

        let token =
            Token2022Account::unpack_from_account(&close_account).map_err(|e| e.to_string())?;
        if token.amount != 0 {
            return Err(Token2022Error::NonNativeHasBalance.to_string());
        }

        // Transfer lamports to destination
        dest_account.meta.lamports = dest_account
            .meta
            .lamports
            .saturating_add(close_account.meta.lamports);
        close_account.meta.lamports = 0;
        close_account.data = AccountData::new(Vec::new());

        let mut outcome = ExecutionOutcome::success(self.base_cost + 50);
        outcome
            .modified_accounts
            .insert(close_pubkey, close_account);
        outcome.modified_accounts.insert(dest_pubkey, dest_account);
        Ok(outcome)
    }

    fn freeze_account(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        // accounts: [0:token_account(w), 1:mint, 2:freeze_authority]
        if context.accounts.len() < 3 {
            return Err("FreezeAccount requires at least 3 accounts".to_string());
        }

        let (acct_pubkey, mut acct, acct_writable) = context.accounts[0].clone();
        if !acct_writable {
            return Err("Token account must be writable".to_string());
        }

        let (_mint_pubkey, mint_account, _) = context.accounts[1].clone();
        let mint = Token2022Mint::unpack_from_account(&mint_account).map_err(|e| e.to_string())?;
        if mint.freeze_authority.is_none() {
            return Err(Token2022Error::MintCannotFreeze.to_string());
        }

        let mut token = Token2022Account::unpack_from_account(&acct).map_err(|e| e.to_string())?;
        if token.state != 1 {
            return Err(Token2022Error::InvalidAccountState.to_string());
        }
        token.state = 2; // Frozen
        token.pack_into_account(&mut acct);

        let mut outcome = ExecutionOutcome::success(self.base_cost + 50);
        outcome.modified_accounts.insert(acct_pubkey, acct);
        Ok(outcome)
    }

    fn thaw_account(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        // accounts: [0:token_account(w), 1:mint, 2:freeze_authority]
        if context.accounts.len() < 3 {
            return Err("ThawAccount requires at least 3 accounts".to_string());
        }

        let (acct_pubkey, mut acct, acct_writable) = context.accounts[0].clone();
        if !acct_writable {
            return Err("Token account must be writable".to_string());
        }

        let (_mint_pubkey, mint_account, _) = context.accounts[1].clone();
        let mint = Token2022Mint::unpack_from_account(&mint_account).map_err(|e| e.to_string())?;
        if mint.freeze_authority.is_none() {
            return Err(Token2022Error::MintCannotFreeze.to_string());
        }

        let mut token = Token2022Account::unpack_from_account(&acct).map_err(|e| e.to_string())?;
        if token.state != 2 {
            return Err(Token2022Error::InvalidAccountState.to_string());
        }
        token.state = 1; // Initialized (unfrozen)
        token.pack_into_account(&mut acct);

        let mut outcome = ExecutionOutcome::success(self.base_cost + 50);
        outcome.modified_accounts.insert(acct_pubkey, acct);
        Ok(outcome)
    }

    fn transfer_checked(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if context.accounts.len() < 4 {
            return Err("TransferChecked requires at least 4 accounts".to_string());
        }
        if context.instruction_data.len() < 10 {
            return Err("TransferChecked requires amount and decimals".to_string());
        }

        let (source_pubkey, mut source_account, source_writable) = context.accounts[0].clone();
        let (_mint_pubkey, mint_account, _) = context.accounts[1].clone();
        let (dest_pubkey, mut dest_account, dest_writable) = context.accounts[2].clone();

        if !source_writable || !dest_writable {
            return Err("Source and destination must be writable".to_string());
        }

        let amount = u64::from_le_bytes(context.instruction_data[1..9].try_into().unwrap());
        let expected_decimals = context.instruction_data[9];

        // Verify decimals match mint
        let mint = Token2022Mint::unpack_from_account(&mint_account).map_err(|e| e.to_string())?;
        if mint.decimals != expected_decimals {
            return Err(Token2022Error::MintDecimalsMismatch.to_string());
        }

        let mut source_token =
            Token2022Account::unpack_from_account(&source_account).map_err(|e| e.to_string())?;
        let mut dest_token =
            Token2022Account::unpack_from_account(&dest_account).map_err(|e| e.to_string())?;

        if source_token.has_extension(ExtensionType::NonTransferableAccount) {
            return Err(Token2022Error::NonTransferable.to_string());
        }
        if source_token.state == 2 || dest_token.state == 2 {
            return Err(Token2022Error::AccountFrozen.to_string());
        }

        source_token.amount = source_token
            .amount
            .checked_sub(amount)
            .ok_or_else(|| Token2022Error::InsufficientFunds.to_string())?;
        dest_token.amount = dest_token
            .amount
            .checked_add(amount)
            .ok_or_else(|| Token2022Error::Overflow.to_string())?;

        source_token.pack_into_account(&mut source_account);
        dest_token.pack_into_account(&mut dest_account);

        let mut outcome = ExecutionOutcome::success(self.base_cost + 100);
        outcome
            .modified_accounts
            .insert(source_pubkey, source_account);
        outcome.modified_accounts.insert(dest_pubkey, dest_account);

        Ok(outcome)
    }

    fn approve_checked(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        // accounts: [0:source(w), 1:mint, 2:delegate, 3:owner]
        if context.accounts.len() < 4 {
            return Err("ApproveChecked requires at least 4 accounts".to_string());
        }
        if context.instruction_data.len() < 10 {
            return Err("ApproveChecked requires amount and decimals".to_string());
        }

        let (src_pubkey, mut src_account, src_writable) = context.accounts[0].clone();
        if !src_writable {
            return Err("Source account must be writable".to_string());
        }
        let (_mint_pubkey, mint_account, _) = context.accounts[1].clone();
        let (delegate_pubkey, _, _) = context.accounts[2].clone();

        let amount = u64::from_le_bytes(context.instruction_data[1..9].try_into().unwrap());
        let expected_decimals = context.instruction_data[9];

        let mint = Token2022Mint::unpack_from_account(&mint_account).map_err(|e| e.to_string())?;
        if mint.decimals != expected_decimals {
            return Err(Token2022Error::MintDecimalsMismatch.to_string());
        }

        let mut token =
            Token2022Account::unpack_from_account(&src_account).map_err(|e| e.to_string())?;
        token.delegate = Some(delegate_pubkey);
        token.delegated_amount = amount;
        token.pack_into_account(&mut src_account);

        let mut outcome = ExecutionOutcome::success(self.base_cost + 50);
        outcome.modified_accounts.insert(src_pubkey, src_account);
        Ok(outcome)
    }

    fn mint_to_checked(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        // accounts: [0:mint(w), 1:destination(w), 2:mint_authority]
        if context.accounts.len() < 3 {
            return Err("MintToChecked requires at least 3 accounts".to_string());
        }
        if context.instruction_data.len() < 10 {
            return Err("MintToChecked requires amount and decimals".to_string());
        }

        let (mint_pubkey, mut mint_account, mint_writable) = context.accounts[0].clone();
        let (dest_pubkey, mut dest_account, dest_writable) = context.accounts[1].clone();
        if !mint_writable || !dest_writable {
            return Err("Mint and destination must be writable".to_string());
        }

        let amount = u64::from_le_bytes(context.instruction_data[1..9].try_into().unwrap());
        let expected_decimals = context.instruction_data[9];

        let mut mint =
            Token2022Mint::unpack_from_account(&mint_account).map_err(|e| e.to_string())?;
        if mint.decimals != expected_decimals {
            return Err(Token2022Error::MintDecimalsMismatch.to_string());
        }
        if mint.mint_authority.is_none() {
            return Err(Token2022Error::FixedSupply.to_string());
        }
        mint.supply = mint
            .supply
            .checked_add(amount)
            .ok_or_else(|| Token2022Error::Overflow.to_string())?;
        mint.pack_into_account(&mut mint_account);

        let mut dest_token =
            Token2022Account::unpack_from_account(&dest_account).map_err(|e| e.to_string())?;
        dest_token.amount = dest_token
            .amount
            .checked_add(amount)
            .ok_or_else(|| Token2022Error::Overflow.to_string())?;
        dest_token.pack_into_account(&mut dest_account);

        let mut outcome = ExecutionOutcome::success(self.base_cost + 100);
        outcome.modified_accounts.insert(mint_pubkey, mint_account);
        outcome.modified_accounts.insert(dest_pubkey, dest_account);
        Ok(outcome)
    }

    fn burn_checked(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        // accounts: [0:source(w), 1:mint(w), 2:owner]
        if context.accounts.len() < 3 {
            return Err("BurnChecked requires at least 3 accounts".to_string());
        }
        if context.instruction_data.len() < 10 {
            return Err("BurnChecked requires amount and decimals".to_string());
        }

        let (src_pubkey, mut src_account, src_writable) = context.accounts[0].clone();
        let (mint_pubkey, mut mint_account, mint_writable) = context.accounts[1].clone();
        if !src_writable || !mint_writable {
            return Err("Source and mint must be writable".to_string());
        }

        let amount = u64::from_le_bytes(context.instruction_data[1..9].try_into().unwrap());
        let expected_decimals = context.instruction_data[9];

        let mut mint =
            Token2022Mint::unpack_from_account(&mint_account).map_err(|e| e.to_string())?;
        if mint.decimals != expected_decimals {
            return Err(Token2022Error::MintDecimalsMismatch.to_string());
        }
        mint.supply = mint.supply.saturating_sub(amount);
        mint.pack_into_account(&mut mint_account);

        let mut src_token =
            Token2022Account::unpack_from_account(&src_account).map_err(|e| e.to_string())?;
        src_token.amount = src_token
            .amount
            .checked_sub(amount)
            .ok_or_else(|| Token2022Error::InsufficientFunds.to_string())?;
        src_token.pack_into_account(&mut src_account);

        let mut outcome = ExecutionOutcome::success(self.base_cost + 100);
        outcome.modified_accounts.insert(src_pubkey, src_account);
        outcome.modified_accounts.insert(mint_pubkey, mint_account);
        Ok(outcome)
    }

    fn initialize_account2(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        // Like InitializeAccount but owner comes from instruction_data instead of accounts
        // accounts: [0:token_account(w), 1:mint]
        if context.accounts.len() < 2 {
            return Err("InitializeAccount2 requires at least 2 accounts".to_string());
        }
        if context.instruction_data.len() < 33 {
            return Err("InitializeAccount2 requires owner pubkey".to_string());
        }

        let (acct_pubkey, mut acct, acct_writable) = context.accounts[0].clone();
        if !acct_writable {
            return Err("Token account must be writable".to_string());
        }
        let (mint_pubkey, _, _) = context.accounts[1].clone();

        let mut owner_bytes = [0u8; 32];
        owner_bytes.copy_from_slice(&context.instruction_data[1..33]);
        let owner = Pubkey::new(owner_bytes);

        let token = Token2022Account {
            mint: mint_pubkey,
            owner,
            amount: 0,
            delegate: None,
            state: 1,
            is_native: None,
            delegated_amount: 0,
            close_authority: None,
            extensions: Vec::new(),
        };
        token.pack_into_account(&mut acct);

        let mut outcome = ExecutionOutcome::success(self.base_cost + 50);
        outcome.modified_accounts.insert(acct_pubkey, acct);
        Ok(outcome)
    }

    fn sync_native(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        // accounts: [0:native_token_account(w)]
        if context.accounts.is_empty() {
            return Err("SyncNative requires at least 1 account".to_string());
        }

        let (acct_pubkey, mut acct, acct_writable) = context.accounts[0].clone();
        if !acct_writable {
            return Err("Token account must be writable".to_string());
        }

        let mut token = Token2022Account::unpack_from_account(&acct).map_err(|e| e.to_string())?;
        if token.is_native.is_none() {
            return Err(Token2022Error::NonNativeNotSupported.to_string());
        }

        // Native token amount = lamports - rent_exempt_reserve
        let rent_exempt = token.is_native.unwrap_or(0);
        token.amount = acct.meta.lamports.saturating_sub(rent_exempt);
        token.pack_into_account(&mut acct);

        let mut outcome = ExecutionOutcome::success(self.base_cost + 10);
        outcome.modified_accounts.insert(acct_pubkey, acct);
        Ok(outcome)
    }

    fn initialize_account3(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        // Same as InitializeAccount2: owner from instruction_data
        // accounts: [0:token_account(w), 1:mint]
        if context.accounts.len() < 2 {
            return Err("InitializeAccount3 requires at least 2 accounts".to_string());
        }
        if context.instruction_data.len() < 33 {
            return Err("InitializeAccount3 requires owner pubkey".to_string());
        }

        let (acct_pubkey, mut acct, acct_writable) = context.accounts[0].clone();
        if !acct_writable {
            return Err("Token account must be writable".to_string());
        }
        let (mint_pubkey, _, _) = context.accounts[1].clone();

        let mut owner_bytes = [0u8; 32];
        owner_bytes.copy_from_slice(&context.instruction_data[1..33]);
        let owner = Pubkey::new(owner_bytes);

        let token = Token2022Account {
            mint: mint_pubkey,
            owner,
            amount: 0,
            delegate: None,
            state: 1,
            is_native: None,
            delegated_amount: 0,
            close_authority: None,
            extensions: Vec::new(),
        };
        token.pack_into_account(&mut acct);

        let mut outcome = ExecutionOutcome::success(self.base_cost + 50);
        outcome.modified_accounts.insert(acct_pubkey, acct);
        Ok(outcome)
    }

    fn initialize_mint2(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        // Same as InitializeMint but no rent sysvar required
        // instruction_data: [0:discriminator][1:decimals][2..34:mint_authority][34:has_freeze][35..67:freeze_authority]
        if context.accounts.is_empty() {
            return Err("InitializeMint2 requires at least 1 account".to_string());
        }
        if context.instruction_data.len() < 34 {
            return Err("InitializeMint2: insufficient instruction data".to_string());
        }

        let (mint_pubkey, mut mint_account, mint_writable) = context.accounts[0].clone();
        if !mint_writable {
            return Err("Mint account must be writable".to_string());
        }

        let decimals = context.instruction_data[1];
        let mut auth_bytes = [0u8; 32];
        auth_bytes.copy_from_slice(&context.instruction_data[2..34]);
        let mint_authority = Some(Pubkey::new(auth_bytes));

        let freeze_authority =
            if context.instruction_data.len() >= 67 && context.instruction_data[34] == 1 {
                let mut fb = [0u8; 32];
                fb.copy_from_slice(&context.instruction_data[35..67]);
                Some(Pubkey::new(fb))
            } else {
                None
            };

        let mint = Token2022Mint {
            mint_authority,
            supply: 0,
            decimals,
            is_initialized: true,
            freeze_authority,
            extensions: Vec::new(),
        };
        mint.pack_into_account(&mut mint_account);

        let mut outcome = ExecutionOutcome::success(self.base_cost + 50);
        outcome.modified_accounts.insert(mint_pubkey, mint_account);
        Ok(outcome)
    }

    fn get_account_data_size(
        &self,
        context: &ExecutionContext,
    ) -> Result<ExecutionOutcome, String> {
        // Read-only: returns the account data size needed for given extensions
        // No account mutation needed — this is a computation-only instruction
        let _ = context;
        Ok(ExecutionOutcome::success(self.base_cost + 10))
    }

    fn initialize_immutable_owner(
        &self,
        context: &ExecutionContext,
    ) -> Result<ExecutionOutcome, String> {
        // accounts: [0:token_account(w)]
        if context.accounts.is_empty() {
            return Err("InitializeImmutableOwner requires at least 1 account".to_string());
        }

        let (acct_pubkey, mut acct, acct_writable) = context.accounts[0].clone();
        if !acct_writable {
            return Err("Token account must be writable".to_string());
        }

        let mut token = Token2022Account::unpack_from_account(&acct).map_err(|e| e.to_string())?;
        if token.has_extension(ExtensionType::ImmutableOwner) {
            return Err(Token2022Error::ExtensionAlreadyInitialized.to_string());
        }
        token
            .set_extension(ExtensionType::ImmutableOwner, &[])
            .map_err(|e| e.to_string())?;
        token.pack_into_account(&mut acct);

        let mut outcome = ExecutionOutcome::success(self.base_cost + 30);
        outcome.modified_accounts.insert(acct_pubkey, acct);
        Ok(outcome)
    }

    fn amount_to_ui_amount(&self, _context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        // Read-only computation — no account mutation needed
        Ok(ExecutionOutcome::success(self.base_cost + 20))
    }

    fn ui_amount_to_amount(&self, _context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        // Read-only computation — no account mutation needed
        Ok(ExecutionOutcome::success(self.base_cost + 20))
    }

    // Extension-specific instructions

    /// Instruction 25: InitializeMintCloseAuthority
    fn initialize_mint_close_authority(
        &self,
        context: &ExecutionContext,
    ) -> Result<ExecutionOutcome, String> {
        if context.accounts.is_empty() {
            return Err("InitializeMintCloseAuthority requires at least 1 account".to_string());
        }

        let (mint_pubkey, mut mint_account, mint_writable) = context.accounts[0].clone();

        if !mint_writable {
            return Err("Mint account must be writable".to_string());
        }

        // Parse close authority from instruction data
        if context.instruction_data.len() < 34 {
            return Err("Missing close authority".to_string());
        }

        let has_authority = context.instruction_data[1] == 1;
        let close_authority = if has_authority {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&context.instruction_data[2..34]);
            Some(Pubkey::new(bytes))
        } else {
            None
        };

        let extension = MintCloseAuthority { close_authority };

        // Persist extension in mint account TLV data
        let mut mint =
            Token2022Mint::unpack_from_account(&mint_account).map_err(|e| e.to_string())?;
        if mint.has_extension(ExtensionType::MintCloseAuthority) {
            return Err(Token2022Error::ExtensionAlreadyInitialized.to_string());
        }
        mint.set_extension(ExtensionType::MintCloseAuthority, &extension.pack())
            .map_err(|e| e.to_string())?;
        mint.pack_into_account(&mut mint_account);

        let mut outcome = ExecutionOutcome::success(self.base_cost + 50);
        outcome.modified_accounts.insert(mint_pubkey, mint_account);

        Ok(outcome)
    }

    /// Instruction 26: InitializeTransferFeeConfig
    fn initialize_transfer_fee_config(
        &self,
        context: &ExecutionContext,
    ) -> Result<ExecutionOutcome, String> {
        if context.accounts.is_empty() {
            return Err("InitializeTransferFeeConfig requires at least 1 account".to_string());
        }

        let (mint_pubkey, mut mint_account, mint_writable) = context.accounts[0].clone();

        if !mint_writable {
            return Err("Mint account must be writable".to_string());
        }

        // Parse transfer fee config from instruction data
        // Minimum size: 1 (discriminator) + 1 (has_config) + 32 (config) + 1 (has_withdraw) + 32 (withdraw) + 2 (basis) + 8 (max) = 77
        if context.instruction_data.len() < 77 {
            return Err("Invalid transfer fee config data".to_string());
        }

        // Extract authorities and fee parameters
        let mut offset = 1; // Skip instruction discriminator

        let has_config_auth = context.instruction_data[offset] == 1;
        offset += 1;
        let config_authority = if has_config_auth {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&context.instruction_data[offset..offset + 32]);
            offset += 32;
            Some(Pubkey::new(bytes))
        } else {
            offset += 32;
            None
        };

        let has_withdraw_auth = context.instruction_data[offset] == 1;
        offset += 1;
        let withdraw_authority = if has_withdraw_auth {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&context.instruction_data[offset..offset + 32]);
            offset += 32;
            Some(Pubkey::new(bytes))
        } else {
            offset += 32;
            None
        };

        // Parse transfer fee parameters
        let transfer_fee_basis_points = u16::from_le_bytes(
            context.instruction_data[offset..offset + 2]
                .try_into()
                .unwrap(),
        );
        offset += 2;

        let maximum_fee = u64::from_le_bytes(
            context.instruction_data[offset..offset + 8]
                .try_into()
                .unwrap(),
        );

        let config = TransferFeeConfig {
            transfer_fee_config_authority: config_authority,
            withdraw_withheld_authority: withdraw_authority,
            withheld_amount: 0,
            older_transfer_fee: TransferFee {
                epoch: 0,
                maximum_fee,
                transfer_fee_basis_points,
            },
            newer_transfer_fee: TransferFee {
                epoch: 0,
                maximum_fee,
                transfer_fee_basis_points,
            },
        };

        // Persist extension in mint TLV
        let mut mint =
            Token2022Mint::unpack_from_account(&mint_account).map_err(|e| e.to_string())?;
        if mint.has_extension(ExtensionType::TransferFeeConfig) {
            return Err(Token2022Error::ExtensionAlreadyInitialized.to_string());
        }
        mint.set_extension(ExtensionType::TransferFeeConfig, &config.pack())
            .map_err(|e| e.to_string())?;
        mint.pack_into_account(&mut mint_account);

        let mut outcome = ExecutionOutcome::success(self.base_cost + 100);
        outcome.modified_accounts.insert(mint_pubkey, mint_account);

        Ok(outcome)
    }

    /// Instruction 27: TransferCheckedWithFee
    fn transfer_checked_with_fee(
        &self,
        context: &ExecutionContext,
    ) -> Result<ExecutionOutcome, String> {
        if context.accounts.len() < 4 {
            return Err("TransferCheckedWithFee requires at least 4 accounts".to_string());
        }
        if context.instruction_data.len() < 18 {
            return Err("TransferCheckedWithFee requires amount, decimals, and fee".to_string());
        }

        let (source_pubkey, mut source_account, source_writable) = context.accounts[0].clone();
        let (_mint_pubkey, mint_account, _) = context.accounts[1].clone();
        let (dest_pubkey, mut dest_account, dest_writable) = context.accounts[2].clone();

        if !source_writable || !dest_writable {
            return Err("Source and destination must be writable".to_string());
        }

        let amount = u64::from_le_bytes(context.instruction_data[1..9].try_into().unwrap());
        let _decimals = context.instruction_data[9];
        let fee = u64::from_le_bytes(context.instruction_data[10..18].try_into().unwrap());

        let mut source_token =
            Token2022Account::unpack_from_account(&source_account).map_err(|e| e.to_string())?;
        let mut dest_token =
            Token2022Account::unpack_from_account(&dest_account).map_err(|e| e.to_string())?;

        if source_token.state == 2 || dest_token.state == 2 {
            return Err(Token2022Error::AccountFrozen.to_string());
        }

        // Deduct full amount from source
        source_token.amount = source_token
            .amount
            .checked_sub(amount)
            .ok_or_else(|| Token2022Error::InsufficientFunds.to_string())?;

        // Credit (amount - fee) to destination
        let transfer_amount = amount
            .checked_sub(fee)
            .ok_or_else(|| Token2022Error::InsufficientFundsForFee.to_string())?;
        dest_token.amount = dest_token
            .amount
            .checked_add(transfer_amount)
            .ok_or_else(|| Token2022Error::Overflow.to_string())?;

        // Track withheld fee in destination's TransferFeeAmount extension
        let current_withheld = dest_token
            .get_extension(ExtensionType::TransferFeeAmount)
            .map(|d| {
                TransferFeeAmount::unpack(d).unwrap_or(TransferFeeAmount { withheld_amount: 0 })
            })
            .unwrap_or(TransferFeeAmount { withheld_amount: 0 });

        let new_withheld = TransferFeeAmount {
            withheld_amount: current_withheld
                .withheld_amount
                .checked_add(fee)
                .ok_or_else(|| Token2022Error::Overflow.to_string())?,
        };
        dest_token
            .set_extension(ExtensionType::TransferFeeAmount, &new_withheld.pack())
            .map_err(|e| e.to_string())?;

        source_token.pack_into_account(&mut source_account);
        dest_token.pack_into_account(&mut dest_account);

        let mut outcome = ExecutionOutcome::success(self.base_cost + 150);
        outcome
            .modified_accounts
            .insert(source_pubkey, source_account);
        outcome.modified_accounts.insert(dest_pubkey, dest_account);

        Ok(outcome)
    }

    /// Instruction 28: WithdrawWithheldTokensFromMint
    fn withdraw_withheld_tokens_from_mint(
        &self,
        context: &ExecutionContext,
    ) -> Result<ExecutionOutcome, String> {
        if context.accounts.len() < 3 {
            return Err("WithdrawWithheldTokensFromMint requires at least 3 accounts".to_string());
        }

        let (mint_pubkey, mut mint_account, mint_writable) = context.accounts[0].clone();
        let (dest_pubkey, mut dest_account, dest_writable) = context.accounts[1].clone();

        if !mint_writable || !dest_writable {
            return Err("Mint and destination must be writable".to_string());
        }

        // Read withheld amount from mint's TransferFeeConfig
        let mut mint =
            Token2022Mint::unpack_from_account(&mint_account).map_err(|e| e.to_string())?;
        let fee_config_data = mint
            .get_extension(ExtensionType::TransferFeeConfig)
            .ok_or_else(|| Token2022Error::ExtensionNotInitialized.to_string())?;
        let mut fee_config =
            TransferFeeConfig::unpack(fee_config_data).map_err(|e| e.to_string())?;

        let withheld = fee_config.withheld_amount;
        if withheld == 0 {
            let mut outcome = ExecutionOutcome::success(self.base_cost + 50);
            outcome.modified_accounts.insert(mint_pubkey, mint_account);
            return Ok(outcome);
        }

        // Zero out withheld amount on mint
        fee_config.withheld_amount = 0;
        mint.set_extension(ExtensionType::TransferFeeConfig, &fee_config.pack())
            .map_err(|e| e.to_string())?;
        mint.pack_into_account(&mut mint_account);

        // Credit destination
        let mut dest_token =
            Token2022Account::unpack_from_account(&dest_account).map_err(|e| e.to_string())?;
        dest_token.amount = dest_token
            .amount
            .checked_add(withheld)
            .ok_or_else(|| Token2022Error::Overflow.to_string())?;
        dest_token.pack_into_account(&mut dest_account);

        let mut outcome = ExecutionOutcome::success(self.base_cost + 100);
        outcome.modified_accounts.insert(mint_pubkey, mint_account);
        outcome.modified_accounts.insert(dest_pubkey, dest_account);

        Ok(outcome)
    }

    /// Instruction 29: WithdrawWithheldTokensFromAccounts
    fn withdraw_withheld_tokens_from_accounts(
        &self,
        context: &ExecutionContext,
    ) -> Result<ExecutionOutcome, String> {
        if context.accounts.len() < 3 {
            return Err(
                "WithdrawWithheldTokensFromAccounts requires at least 3 accounts".to_string(),
            );
        }

        // accounts[0] = mint, accounts[1] = destination, accounts[2] = authority,
        // accounts[3..] = source accounts with withheld fees
        let (_mint_pubkey, _mint_account, _) = context.accounts[0].clone();
        let (dest_pubkey, mut dest_account, dest_writable) = context.accounts[1].clone();

        if !dest_writable {
            return Err("Destination must be writable".to_string());
        }

        let mut dest_token =
            Token2022Account::unpack_from_account(&dest_account).map_err(|e| e.to_string())?;

        let mut outcome =
            ExecutionOutcome::success(self.base_cost + 80 * context.accounts.len() as u64);

        // Collect withheld fees from source accounts (index 3+)
        for i in 3..context.accounts.len() {
            let (src_pubkey, mut src_account, src_writable) = context.accounts[i].clone();
            if !src_writable {
                continue;
            }

            let mut src_token =
                Token2022Account::unpack_from_account(&src_account).map_err(|e| e.to_string())?;

            if let Some(ext_data) = src_token.get_extension(ExtensionType::TransferFeeAmount) {
                let fee_amount = TransferFeeAmount::unpack(ext_data).map_err(|e| e.to_string())?;
                if fee_amount.withheld_amount > 0 {
                    dest_token.amount = dest_token
                        .amount
                        .checked_add(fee_amount.withheld_amount)
                        .ok_or_else(|| Token2022Error::Overflow.to_string())?;

                    let zeroed = TransferFeeAmount { withheld_amount: 0 };
                    src_token
                        .set_extension(ExtensionType::TransferFeeAmount, &zeroed.pack())
                        .map_err(|e| e.to_string())?;
                }
            }

            src_token.pack_into_account(&mut src_account);
            outcome.modified_accounts.insert(src_pubkey, src_account);
        }

        dest_token.pack_into_account(&mut dest_account);
        outcome.modified_accounts.insert(dest_pubkey, dest_account);

        Ok(outcome)
    }

    /// Instruction 30: HarvestWithheldTokensToMint
    fn harvest_withheld_tokens_to_mint(
        &self,
        context: &ExecutionContext,
    ) -> Result<ExecutionOutcome, String> {
        if context.accounts.len() < 2 {
            return Err("HarvestWithheldTokensToMint requires at least 2 accounts".to_string());
        }

        // accounts[0] = mint, accounts[1..] = source accounts with withheld fees
        let (mint_pubkey, mut mint_account, mint_writable) = context.accounts[0].clone();
        if !mint_writable {
            return Err("Mint must be writable".to_string());
        }

        let mut mint =
            Token2022Mint::unpack_from_account(&mint_account).map_err(|e| e.to_string())?;
        let fee_config_data = mint
            .get_extension(ExtensionType::TransferFeeConfig)
            .ok_or_else(|| Token2022Error::ExtensionNotInitialized.to_string())?;
        let mut fee_config =
            TransferFeeConfig::unpack(fee_config_data).map_err(|e| e.to_string())?;

        let mut outcome =
            ExecutionOutcome::success(self.base_cost + 60 * context.accounts.len() as u64);

        // Harvest withheld fees from each source account into the mint
        for i in 1..context.accounts.len() {
            let (src_pubkey, mut src_account, src_writable) = context.accounts[i].clone();
            if !src_writable {
                continue;
            }

            let mut src_token =
                Token2022Account::unpack_from_account(&src_account).map_err(|e| e.to_string())?;

            if let Some(ext_data) = src_token.get_extension(ExtensionType::TransferFeeAmount) {
                let fee_amount = TransferFeeAmount::unpack(ext_data).map_err(|e| e.to_string())?;
                if fee_amount.withheld_amount > 0 {
                    fee_config.withheld_amount = fee_config
                        .withheld_amount
                        .checked_add(fee_amount.withheld_amount)
                        .ok_or_else(|| Token2022Error::Overflow.to_string())?;

                    let zeroed = TransferFeeAmount { withheld_amount: 0 };
                    src_token
                        .set_extension(ExtensionType::TransferFeeAmount, &zeroed.pack())
                        .map_err(|e| e.to_string())?;
                }
            }

            src_token.pack_into_account(&mut src_account);
            outcome.modified_accounts.insert(src_pubkey, src_account);
        }

        mint.set_extension(ExtensionType::TransferFeeConfig, &fee_config.pack())
            .map_err(|e| e.to_string())?;
        mint.pack_into_account(&mut mint_account);
        outcome.modified_accounts.insert(mint_pubkey, mint_account);

        Ok(outcome)
    }

    /// Instruction 31: SetTransferFee
    fn set_transfer_fee(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if context.accounts.len() < 2 {
            return Err("SetTransferFee requires at least 2 accounts".to_string());
        }
        if context.instruction_data.len() < 11 {
            return Err("SetTransferFee requires fee parameters".to_string());
        }

        let (mint_pubkey, mut mint_account, mint_writable) = context.accounts[0].clone();

        if !mint_writable {
            return Err("Mint account must be writable".to_string());
        }

        let transfer_fee_basis_points =
            u16::from_le_bytes(context.instruction_data[1..3].try_into().unwrap());
        let maximum_fee = u64::from_le_bytes(context.instruction_data[3..11].try_into().unwrap());

        // Read and update the transfer fee config extension
        let mut mint =
            Token2022Mint::unpack_from_account(&mint_account).map_err(|e| e.to_string())?;
        let fee_config_data = mint
            .get_extension(ExtensionType::TransferFeeConfig)
            .ok_or_else(|| Token2022Error::ExtensionNotInitialized.to_string())?;
        let mut fee_config =
            TransferFeeConfig::unpack(fee_config_data).map_err(|e| e.to_string())?;

        // Move current newer to older, set new newer fee
        fee_config.older_transfer_fee = fee_config.newer_transfer_fee.clone();
        fee_config.newer_transfer_fee = TransferFee {
            epoch: 0, // Would use current epoch in real runtime
            maximum_fee,
            transfer_fee_basis_points,
        };

        mint.set_extension(ExtensionType::TransferFeeConfig, &fee_config.pack())
            .map_err(|e| e.to_string())?;
        mint.pack_into_account(&mut mint_account);

        let mut outcome = ExecutionOutcome::success(self.base_cost + 80);
        outcome.modified_accounts.insert(mint_pubkey, mint_account);

        Ok(outcome)
    }

    /// Instruction 32: InitializeDefaultAccountState
    fn initialize_default_account_state(
        &self,
        context: &ExecutionContext,
    ) -> Result<ExecutionOutcome, String> {
        if context.accounts.is_empty() {
            return Err("InitializeDefaultAccountState requires at least 1 account".to_string());
        }
        if context.instruction_data.len() < 2 {
            return Err("InitializeDefaultAccountState requires state parameter".to_string());
        }

        let (mint_pubkey, mut mint_account, mint_writable) = context.accounts[0].clone();

        if !mint_writable {
            return Err("Mint account must be writable".to_string());
        }

        let state_value = context.instruction_data[1];
        let _default_state = DefaultAccountState::from_u8(state_value)
            .ok_or_else(|| "Invalid default account state".to_string())?;

        let mut mint =
            Token2022Mint::unpack_from_account(&mint_account).map_err(|e| e.to_string())?;
        if mint.has_extension(ExtensionType::DefaultAccountState) {
            return Err(Token2022Error::ExtensionAlreadyInitialized.to_string());
        }
        mint.set_extension(ExtensionType::DefaultAccountState, &[state_value])
            .map_err(|e| e.to_string())?;
        mint.pack_into_account(&mut mint_account);

        let mut outcome = ExecutionOutcome::success(self.base_cost + 50);
        outcome.modified_accounts.insert(mint_pubkey, mint_account);

        Ok(outcome)
    }

    /// Instruction 33: UpdateDefaultAccountState
    fn update_default_account_state(
        &self,
        context: &ExecutionContext,
    ) -> Result<ExecutionOutcome, String> {
        if context.accounts.len() < 2 {
            return Err("UpdateDefaultAccountState requires at least 2 accounts".to_string());
        }
        if context.instruction_data.len() < 2 {
            return Err("UpdateDefaultAccountState requires state parameter".to_string());
        }

        let (mint_pubkey, mut mint_account, mint_writable) = context.accounts[0].clone();

        if !mint_writable {
            return Err("Mint account must be writable".to_string());
        }

        let state_value = context.instruction_data[1];
        let _default_state = DefaultAccountState::from_u8(state_value)
            .ok_or_else(|| "Invalid default account state".to_string())?;

        let mut mint =
            Token2022Mint::unpack_from_account(&mint_account).map_err(|e| e.to_string())?;
        if !mint.has_extension(ExtensionType::DefaultAccountState) {
            return Err(Token2022Error::ExtensionNotInitialized.to_string());
        }
        mint.set_extension(ExtensionType::DefaultAccountState, &[state_value])
            .map_err(|e| e.to_string())?;
        mint.pack_into_account(&mut mint_account);

        let mut outcome = ExecutionOutcome::success(self.base_cost + 60);
        outcome.modified_accounts.insert(mint_pubkey, mint_account);

        Ok(outcome)
    }

    /// Instruction 34: InitializeNonTransferableMint
    fn initialize_non_transferable_mint(
        &self,
        context: &ExecutionContext,
    ) -> Result<ExecutionOutcome, String> {
        if context.accounts.is_empty() {
            return Err("InitializeNonTransferableMint requires at least 1 account".to_string());
        }

        let (mint_pubkey, mut mint_account, mint_writable) = context.accounts[0].clone();

        if !mint_writable {
            return Err("Mint account must be writable".to_string());
        }

        let mut mint =
            Token2022Mint::unpack_from_account(&mint_account).map_err(|e| e.to_string())?;
        if mint.has_extension(ExtensionType::NonTransferable) {
            return Err(Token2022Error::ExtensionAlreadyInitialized.to_string());
        }
        // NonTransferable has zero-length data — just the TLV header
        mint.set_extension(ExtensionType::NonTransferable, &[])
            .map_err(|e| e.to_string())?;
        mint.pack_into_account(&mut mint_account);

        let mut outcome = ExecutionOutcome::success(self.base_cost + 40);
        outcome.modified_accounts.insert(mint_pubkey, mint_account);

        Ok(outcome)
    }

    /// Instruction 35: InitializeInterestBearingConfig
    fn initialize_interest_bearing_config(
        &self,
        context: &ExecutionContext,
    ) -> Result<ExecutionOutcome, String> {
        if context.accounts.is_empty() {
            return Err("InitializeInterestBearingConfig requires at least 1 account".to_string());
        }
        if context.instruction_data.len() < 36 {
            return Err("InitializeInterestBearingConfig requires rate and authority".to_string());
        }

        let (mint_pubkey, mut mint_account, mint_writable) = context.accounts[0].clone();

        if !mint_writable {
            return Err("Mint account must be writable".to_string());
        }

        let mut offset = 1;

        let has_authority = context.instruction_data[offset] == 1;
        offset += 1;
        let rate_authority = if has_authority {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&context.instruction_data[offset..offset + 32]);
            offset += 32;
            Some(Pubkey::new(bytes))
        } else {
            offset += 32;
            None
        };

        let rate = i16::from_le_bytes(
            context.instruction_data[offset..offset + 2]
                .try_into()
                .unwrap(),
        );

        let config = InterestBearingConfig {
            rate_authority,
            initialization_timestamp: 0, // Would use current timestamp
            pre_update_average_rate: 0,
            last_update_timestamp: 0,
            current_rate: rate,
        };

        let mut mint =
            Token2022Mint::unpack_from_account(&mint_account).map_err(|e| e.to_string())?;
        if mint.has_extension(ExtensionType::InterestBearingConfig) {
            return Err(Token2022Error::ExtensionAlreadyInitialized.to_string());
        }
        mint.set_extension(ExtensionType::InterestBearingConfig, &config.pack())
            .map_err(|e| e.to_string())?;
        mint.pack_into_account(&mut mint_account);

        let mut outcome = ExecutionOutcome::success(self.base_cost + 80);
        outcome.modified_accounts.insert(mint_pubkey, mint_account);

        Ok(outcome)
    }

    /// Instruction 36: UpdateRateInterestBearingMint
    fn update_rate_interest_bearing_mint(
        &self,
        context: &ExecutionContext,
    ) -> Result<ExecutionOutcome, String> {
        if context.accounts.len() < 2 {
            return Err("UpdateRateInterestBearingMint requires at least 2 accounts".to_string());
        }
        if context.instruction_data.len() < 3 {
            return Err("UpdateRateInterestBearingMint requires rate parameter".to_string());
        }

        let (mint_pubkey, mut mint_account, mint_writable) = context.accounts[0].clone();

        if !mint_writable {
            return Err("Mint account must be writable".to_string());
        }

        let new_rate = i16::from_le_bytes(context.instruction_data[1..3].try_into().unwrap());

        let mut mint =
            Token2022Mint::unpack_from_account(&mint_account).map_err(|e| e.to_string())?;
        let ext_data = mint
            .get_extension(ExtensionType::InterestBearingConfig)
            .ok_or_else(|| Token2022Error::ExtensionNotInitialized.to_string())?;
        let mut config = InterestBearingConfig::unpack(ext_data).map_err(|e| e.to_string())?;

        config.pre_update_average_rate = config.current_rate;
        config.current_rate = new_rate;
        config.last_update_timestamp = 0; // Would use current timestamp

        mint.set_extension(ExtensionType::InterestBearingConfig, &config.pack())
            .map_err(|e| e.to_string())?;
        mint.pack_into_account(&mut mint_account);

        let mut outcome = ExecutionOutcome::success(self.base_cost + 70);
        outcome.modified_accounts.insert(mint_pubkey, mint_account);

        Ok(outcome)
    }

    // ── W001c: Missing base instructions ────────────────────────────────

    /// Instruction 6: SetAuthority
    fn set_authority(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if context.accounts.len() < 2 {
            return Err("SetAuthority requires at least 2 accounts".to_string());
        }
        if context.instruction_data.len() < 4 {
            return Err("SetAuthority requires authority type and new authority".to_string());
        }

        let (account_pubkey, mut account, writable) = context.accounts[0].clone();
        if !writable {
            return Err("Account must be writable".to_string());
        }

        let authority_type = context.instruction_data[1];
        let has_new_authority = context.instruction_data[2] == 1;
        let new_authority = if has_new_authority && context.instruction_data.len() >= 35 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&context.instruction_data[3..35]);
            Some(Pubkey::new(bytes))
        } else {
            None
        };

        // Authority types: 0=MintTokens, 1=FreezeAccount, 2=AccountOwner, 3=CloseAccount
        match authority_type {
            0 | 1 => {
                // Mint authority or freeze authority
                let mut mint =
                    Token2022Mint::unpack_from_account(&account).map_err(|e| e.to_string())?;
                if authority_type == 0 {
                    mint.mint_authority = new_authority;
                } else {
                    mint.freeze_authority = new_authority;
                }
                mint.pack_into_account(&mut account);
            }
            2 | 3 => {
                // Account owner or close authority
                let mut token =
                    Token2022Account::unpack_from_account(&account).map_err(|e| e.to_string())?;
                if authority_type == 3 {
                    token.close_authority = new_authority;
                }
                // Note: owner change (type 2) is blocked for immutable-owner accounts
                token.pack_into_account(&mut account);
            }
            _ => return Err(Token2022Error::AuthorityTypeNotSupported.to_string()),
        }

        let mut outcome = ExecutionOutcome::success(self.base_cost + 50);
        outcome.modified_accounts.insert(account_pubkey, account);
        Ok(outcome)
    }

    /// Instruction 19: Reallocate — resize account for new extensions
    fn reallocate(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if context.accounts.len() < 3 {
            return Err(
                "Reallocate requires at least 3 accounts (account, payer, system)".to_string(),
            );
        }
        if context.instruction_data.len() < 3 {
            return Err("Reallocate requires extension type list".to_string());
        }

        let (account_pubkey, mut account, writable) = context.accounts[0].clone();
        if !writable {
            return Err("Account must be writable".to_string());
        }

        // Parse requested extension types from instruction data (u16 each, after discriminator)
        let ext_data = &context.instruction_data[1..];
        let mut needed_size = Token2022Account::BASE_LEN + 1 + ACCOUNT_TYPE_PADDING;

        let mut offset = 0;
        while offset + 2 <= ext_data.len() {
            let ext_type_val = u16::from_le_bytes(ext_data[offset..offset + 2].try_into().unwrap());
            if let Some(ext_type) = ExtensionType::from_u16(ext_type_val) {
                needed_size += TLV_HEADER_LEN + ext_type.data_len();
            }
            offset += 2;
        }

        // Resize account data to accommodate extensions
        account.data.resize(needed_size, 0);

        let mut outcome = ExecutionOutcome::success(self.base_cost + 60);
        outcome.modified_accounts.insert(account_pubkey, account);
        Ok(outcome)
    }

    // ── W001d: Missing extension instructions ───────────────────────────

    /// Instruction 37: InitializePermanentDelegate
    fn initialize_permanent_delegate(
        &self,
        context: &ExecutionContext,
    ) -> Result<ExecutionOutcome, String> {
        if context.accounts.is_empty() {
            return Err("InitializePermanentDelegate requires at least 1 account".to_string());
        }

        let (mint_pubkey, mut mint_account, writable) = context.accounts[0].clone();
        if !writable {
            return Err("Mint must be writable".to_string());
        }

        let delegate = if context.instruction_data.len() >= 34 && context.instruction_data[1] == 1 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&context.instruction_data[2..34]);
            Some(Pubkey::new(bytes))
        } else {
            None
        };

        let ext = PermanentDelegate { delegate };
        let mut mint =
            Token2022Mint::unpack_from_account(&mint_account).map_err(|e| e.to_string())?;
        if mint.has_extension(ExtensionType::PermanentDelegate) {
            return Err(Token2022Error::ExtensionAlreadyInitialized.to_string());
        }
        mint.set_extension(ExtensionType::PermanentDelegate, &ext.pack())
            .map_err(|e| e.to_string())?;
        mint.pack_into_account(&mut mint_account);

        let mut outcome = ExecutionOutcome::success(self.base_cost + 50);
        outcome.modified_accounts.insert(mint_pubkey, mint_account);
        Ok(outcome)
    }

    /// Instruction 38: InitializeCpiGuard / ToggleCpiGuard
    fn toggle_cpi_guard(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if context.accounts.is_empty() {
            return Err("CpiGuard requires at least 1 account".to_string());
        }
        if context.instruction_data.len() < 2 {
            return Err("CpiGuard requires enable flag".to_string());
        }

        let (account_pubkey, mut account, writable) = context.accounts[0].clone();
        if !writable {
            return Err("Account must be writable".to_string());
        }

        let enabled = context.instruction_data[1];

        let mut token =
            Token2022Account::unpack_from_account(&account).map_err(|e| e.to_string())?;
        token
            .set_extension(ExtensionType::CpiGuard, &[enabled])
            .map_err(|e| e.to_string())?;
        token.pack_into_account(&mut account);

        let mut outcome = ExecutionOutcome::success(self.base_cost + 40);
        outcome.modified_accounts.insert(account_pubkey, account);
        Ok(outcome)
    }

    /// Instruction 39: InitializeTransferHook
    fn initialize_transfer_hook(
        &self,
        context: &ExecutionContext,
    ) -> Result<ExecutionOutcome, String> {
        if context.accounts.is_empty() {
            return Err("InitializeTransferHook requires at least 1 account".to_string());
        }

        let (mint_pubkey, mut mint_account, writable) = context.accounts[0].clone();
        if !writable {
            return Err("Mint must be writable".to_string());
        }

        let mut offset = 1;
        let authority = if context.instruction_data.len() >= offset + 33
            && context.instruction_data[offset] == 1
        {
            let mut b = [0u8; 32];
            b.copy_from_slice(&context.instruction_data[offset + 1..offset + 33]);
            offset += 33;
            Some(Pubkey::new(b))
        } else {
            offset += 33;
            None
        };

        let program_id = if context.instruction_data.len() >= offset + 33
            && context.instruction_data[offset] == 1
        {
            let mut b = [0u8; 32];
            b.copy_from_slice(&context.instruction_data[offset + 1..offset + 33]);
            Some(Pubkey::new(b))
        } else {
            None
        };

        let ext = TransferHookExt {
            authority,
            program_id,
        };

        let mut mint =
            Token2022Mint::unpack_from_account(&mint_account).map_err(|e| e.to_string())?;
        if mint.has_extension(ExtensionType::TransferHook) {
            return Err(Token2022Error::ExtensionAlreadyInitialized.to_string());
        }
        mint.set_extension(ExtensionType::TransferHook, &ext.pack())
            .map_err(|e| e.to_string())?;
        mint.pack_into_account(&mut mint_account);

        let mut outcome = ExecutionOutcome::success(self.base_cost + 60);
        outcome.modified_accounts.insert(mint_pubkey, mint_account);
        Ok(outcome)
    }

    /// Instruction 40: InitializeMetadataPointer
    fn initialize_metadata_pointer(
        &self,
        context: &ExecutionContext,
    ) -> Result<ExecutionOutcome, String> {
        if context.accounts.is_empty() {
            return Err("InitializeMetadataPointer requires at least 1 account".to_string());
        }

        let (mint_pubkey, mut mint_account, writable) = context.accounts[0].clone();
        if !writable {
            return Err("Mint must be writable".to_string());
        }

        let mut offset = 1;
        let authority = if context.instruction_data.len() >= offset + 33
            && context.instruction_data[offset] == 1
        {
            let mut b = [0u8; 32];
            b.copy_from_slice(&context.instruction_data[offset + 1..offset + 33]);
            offset += 33;
            Some(Pubkey::new(b))
        } else {
            offset += 33;
            None
        };

        let metadata_address = if context.instruction_data.len() >= offset + 33
            && context.instruction_data[offset] == 1
        {
            let mut b = [0u8; 32];
            b.copy_from_slice(&context.instruction_data[offset + 1..offset + 33]);
            Some(Pubkey::new(b))
        } else {
            None
        };

        let ext = MetadataPointer {
            authority,
            metadata_address,
        };

        let mut mint =
            Token2022Mint::unpack_from_account(&mint_account).map_err(|e| e.to_string())?;
        if mint.has_extension(ExtensionType::MetadataPointer) {
            return Err(Token2022Error::ExtensionAlreadyInitialized.to_string());
        }
        mint.set_extension(ExtensionType::MetadataPointer, &ext.pack())
            .map_err(|e| e.to_string())?;
        mint.pack_into_account(&mut mint_account);

        let mut outcome = ExecutionOutcome::success(self.base_cost + 50);
        outcome.modified_accounts.insert(mint_pubkey, mint_account);
        Ok(outcome)
    }

    /// Instruction 41: InitializeGroupPointer
    fn initialize_group_pointer(
        &self,
        context: &ExecutionContext,
    ) -> Result<ExecutionOutcome, String> {
        if context.accounts.is_empty() {
            return Err("InitializeGroupPointer requires at least 1 account".to_string());
        }

        let (mint_pubkey, mut mint_account, writable) = context.accounts[0].clone();
        if !writable {
            return Err("Mint must be writable".to_string());
        }

        let mut offset = 1;
        let authority = if context.instruction_data.len() >= offset + 33
            && context.instruction_data[offset] == 1
        {
            let mut b = [0u8; 32];
            b.copy_from_slice(&context.instruction_data[offset + 1..offset + 33]);
            offset += 33;
            Some(Pubkey::new(b))
        } else {
            offset += 33;
            None
        };

        let group_address = if context.instruction_data.len() >= offset + 33
            && context.instruction_data[offset] == 1
        {
            let mut b = [0u8; 32];
            b.copy_from_slice(&context.instruction_data[offset + 1..offset + 33]);
            Some(Pubkey::new(b))
        } else {
            None
        };

        let ext = GroupPointer {
            authority,
            group_address,
        };

        let mut mint =
            Token2022Mint::unpack_from_account(&mint_account).map_err(|e| e.to_string())?;
        if mint.has_extension(ExtensionType::GroupPointer) {
            return Err(Token2022Error::ExtensionAlreadyInitialized.to_string());
        }
        mint.set_extension(ExtensionType::GroupPointer, &ext.pack())
            .map_err(|e| e.to_string())?;
        mint.pack_into_account(&mut mint_account);

        let mut outcome = ExecutionOutcome::success(self.base_cost + 50);
        outcome.modified_accounts.insert(mint_pubkey, mint_account);
        Ok(outcome)
    }

    /// Instruction 42: InitializeGroupMemberPointer
    fn initialize_group_member_pointer(
        &self,
        context: &ExecutionContext,
    ) -> Result<ExecutionOutcome, String> {
        if context.accounts.is_empty() {
            return Err("InitializeGroupMemberPointer requires at least 1 account".to_string());
        }

        let (mint_pubkey, mut mint_account, writable) = context.accounts[0].clone();
        if !writable {
            return Err("Mint must be writable".to_string());
        }

        let mut offset = 1;
        let authority = if context.instruction_data.len() >= offset + 33
            && context.instruction_data[offset] == 1
        {
            let mut b = [0u8; 32];
            b.copy_from_slice(&context.instruction_data[offset + 1..offset + 33]);
            offset += 33;
            Some(Pubkey::new(b))
        } else {
            offset += 33;
            None
        };

        let member_address = if context.instruction_data.len() >= offset + 33
            && context.instruction_data[offset] == 1
        {
            let mut b = [0u8; 32];
            b.copy_from_slice(&context.instruction_data[offset + 1..offset + 33]);
            Some(Pubkey::new(b))
        } else {
            None
        };

        let ext = GroupMemberPointer {
            authority,
            member_address,
        };

        let mut mint =
            Token2022Mint::unpack_from_account(&mint_account).map_err(|e| e.to_string())?;
        if mint.has_extension(ExtensionType::GroupMemberPointer) {
            return Err(Token2022Error::ExtensionAlreadyInitialized.to_string());
        }
        mint.set_extension(ExtensionType::GroupMemberPointer, &ext.pack())
            .map_err(|e| e.to_string())?;
        mint.pack_into_account(&mut mint_account);

        let mut outcome = ExecutionOutcome::success(self.base_cost + 50);
        outcome.modified_accounts.insert(mint_pubkey, mint_account);
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use karstflow_ids::TOKEN_2022_PROGRAM_ID;
    use karstflow_types::AccountMeta;

    // ── Helpers ─────────────────────────────────────────────────────────

    fn make_mint_account(mint: &Token2022Mint) -> Account {
        Account {
            meta: AccountMeta {
                lamports: 1_000_000,
                owner: TOKEN_2022_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(mint.pack()),
        }
    }

    fn make_token_account(token: &Token2022Account) -> Account {
        Account {
            meta: AccountMeta {
                lamports: 1_000_000,
                owner: TOKEN_2022_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(token.pack()),
        }
    }

    fn base_mint() -> Token2022Mint {
        Token2022Mint {
            mint_authority: Some(Pubkey::new_unique()),
            supply: 1_000_000,
            decimals: 9,
            is_initialized: true,
            freeze_authority: None,
            extensions: Vec::new(),
        }
    }

    fn base_token(mint: &Pubkey, owner: &Pubkey, amount: u64) -> Token2022Account {
        Token2022Account {
            mint: *mint,
            owner: *owner,
            amount,
            delegate: None,
            state: 1, // Initialized
            is_native: None,
            delegated_amount: 0,
            close_authority: None,
            extensions: Vec::new(),
        }
    }

    // ── TLV infrastructure tests ────────────────────────────────────────

    #[test]
    fn test_tlv_set_get_extension() {
        let mut ext = Vec::new();
        let data = MintCloseAuthority {
            close_authority: Some(Pubkey::new_unique()),
        }
        .pack();
        tlv_set_extension(&mut ext, ExtensionType::MintCloseAuthority, &data).unwrap();
        assert!(tlv_has_extension(&ext, ExtensionType::MintCloseAuthority));
        assert!(!tlv_has_extension(&ext, ExtensionType::TransferFeeConfig));

        let read_back = tlv_get_extension(&ext, ExtensionType::MintCloseAuthority).unwrap();
        assert_eq!(read_back, &data);
    }

    #[test]
    fn test_tlv_multiple_extensions() {
        let mut ext = Vec::new();
        let close_data = MintCloseAuthority {
            close_authority: Some(Pubkey::new_unique()),
        }
        .pack();
        let fee_data = TransferFeeConfig {
            transfer_fee_config_authority: None,
            withdraw_withheld_authority: None,
            withheld_amount: 0,
            older_transfer_fee: TransferFee {
                epoch: 0,
                maximum_fee: 100,
                transfer_fee_basis_points: 50,
            },
            newer_transfer_fee: TransferFee {
                epoch: 0,
                maximum_fee: 100,
                transfer_fee_basis_points: 50,
            },
        }
        .pack();

        tlv_set_extension(&mut ext, ExtensionType::MintCloseAuthority, &close_data).unwrap();
        tlv_set_extension(&mut ext, ExtensionType::TransferFeeConfig, &fee_data).unwrap();

        assert!(tlv_has_extension(&ext, ExtensionType::MintCloseAuthority));
        assert!(tlv_has_extension(&ext, ExtensionType::TransferFeeConfig));

        let close_back = MintCloseAuthority::unpack(
            tlv_get_extension(&ext, ExtensionType::MintCloseAuthority).unwrap(),
        )
        .unwrap();
        assert!(close_back.close_authority.is_some());

        let fee_back = TransferFeeConfig::unpack(
            tlv_get_extension(&ext, ExtensionType::TransferFeeConfig).unwrap(),
        )
        .unwrap();
        assert_eq!(fee_back.older_transfer_fee.transfer_fee_basis_points, 50);
    }

    #[test]
    fn test_tlv_overwrite_in_place() {
        let mut ext = Vec::new();
        let data1 = MintCloseAuthority {
            close_authority: Some(Pubkey::new_unique()),
        }
        .pack();
        tlv_set_extension(&mut ext, ExtensionType::MintCloseAuthority, &data1).unwrap();

        let new_auth = Pubkey::new_unique();
        let data2 = MintCloseAuthority {
            close_authority: Some(new_auth),
        }
        .pack();
        tlv_set_extension(&mut ext, ExtensionType::MintCloseAuthority, &data2).unwrap();

        let read = MintCloseAuthority::unpack(
            tlv_get_extension(&ext, ExtensionType::MintCloseAuthority).unwrap(),
        )
        .unwrap();
        assert_eq!(read.close_authority, Some(new_auth));
    }

    // ── Mint/Account pack/unpack round-trip ─────────────────────────────

    #[test]
    fn test_mint_pack_unpack_roundtrip() {
        let mut mint = base_mint();
        mint.set_extension(
            ExtensionType::MintCloseAuthority,
            &MintCloseAuthority {
                close_authority: Some(Pubkey::new_unique()),
            }
            .pack(),
        )
        .unwrap();

        let packed = mint.pack();
        let unpacked = Token2022Mint::unpack(&packed).unwrap();
        assert_eq!(mint.supply, unpacked.supply);
        assert_eq!(mint.decimals, unpacked.decimals);
        assert!(unpacked.has_extension(ExtensionType::MintCloseAuthority));
    }

    #[test]
    fn test_token_account_pack_unpack_roundtrip() {
        let mint_pk = Pubkey::new_unique();
        let owner_pk = Pubkey::new_unique();
        let token = base_token(&mint_pk, &owner_pk, 5000);

        let packed = token.pack();
        let unpacked = Token2022Account::unpack(&packed).unwrap();
        assert_eq!(unpacked.mint, mint_pk);
        assert_eq!(unpacked.owner, owner_pk);
        assert_eq!(unpacked.amount, 5000);
        assert_eq!(unpacked.state, 1);
    }

    // ── Real balance mutation tests (W001e) ─────────────────────────────

    #[test]
    fn test_transfer_real_balance_mutation() {
        let executor = Token2022ProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST);
        let mint_pk = Pubkey::new_unique();
        let owner_pk = Pubkey::new_unique();

        let source_pubkey = Pubkey::new_unique();
        let dest_pubkey = Pubkey::new_unique();
        let authority_pubkey = Pubkey::new_unique();

        let source = base_token(&mint_pk, &owner_pk, 10000);
        let dest = base_token(&mint_pk, &owner_pk, 2000);

        let source_account = make_token_account(&source);
        let dest_account = make_token_account(&dest);
        let authority_account = Account::default();

        let mut instruction_data = vec![3u8]; // Transfer
        instruction_data.extend_from_slice(&3000u64.to_le_bytes());

        let context = ExecutionContext::new(
            TOKEN_2022_PROGRAM_ID,
            vec![
                (source_pubkey, source_account, true),
                (dest_pubkey, dest_account, true),
                (authority_pubkey, authority_account, false),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);

        // Verify balances
        let updated_source = Token2022Account::unpack_from_account(
            outcome.modified_accounts.get(&source_pubkey).unwrap(),
        )
        .unwrap();
        let updated_dest = Token2022Account::unpack_from_account(
            outcome.modified_accounts.get(&dest_pubkey).unwrap(),
        )
        .unwrap();

        assert_eq!(updated_source.amount, 7000); // 10000 - 3000
        assert_eq!(updated_dest.amount, 5000); // 2000 + 3000
    }

    #[test]
    fn test_transfer_insufficient_funds() {
        let executor = Token2022ProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST);
        let mint_pk = Pubkey::new_unique();
        let owner_pk = Pubkey::new_unique();

        let source = base_token(&mint_pk, &owner_pk, 100);
        let dest = base_token(&mint_pk, &owner_pk, 0);

        let mut instruction_data = vec![3u8];
        instruction_data.extend_from_slice(&500u64.to_le_bytes());

        let context = ExecutionContext::new(
            TOKEN_2022_PROGRAM_ID,
            vec![
                (Pubkey::new_unique(), make_token_account(&source), true),
                (Pubkey::new_unique(), make_token_account(&dest), true),
                (Pubkey::new_unique(), Account::default(), false),
            ],
            instruction_data,
        );

        let result = executor.execute(&context);
        assert!(result.is_err());
    }

    #[test]
    fn test_transfer_checked_with_fee_real_mutation() {
        let executor = Token2022ProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST);
        let mint_pk = Pubkey::new_unique();
        let owner_pk = Pubkey::new_unique();

        let source_pubkey = Pubkey::new_unique();
        let dest_pubkey = Pubkey::new_unique();

        let source = base_token(&mint_pk, &owner_pk, 100_000);
        let dest = base_token(&mint_pk, &owner_pk, 5_000);
        let mint = base_mint();

        let mut instruction_data = vec![27u8]; // TransferCheckedWithFee
        instruction_data.extend_from_slice(&10_000u64.to_le_bytes()); // amount
        instruction_data.push(9); // decimals
        instruction_data.extend_from_slice(&100u64.to_le_bytes()); // fee

        let context = ExecutionContext::new(
            TOKEN_2022_PROGRAM_ID,
            vec![
                (source_pubkey, make_token_account(&source), true),
                (Pubkey::new_unique(), make_mint_account(&mint), false),
                (dest_pubkey, make_token_account(&dest), true),
                (Pubkey::new_unique(), Account::default(), false),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);

        let updated_source = Token2022Account::unpack_from_account(
            outcome.modified_accounts.get(&source_pubkey).unwrap(),
        )
        .unwrap();
        let updated_dest = Token2022Account::unpack_from_account(
            outcome.modified_accounts.get(&dest_pubkey).unwrap(),
        )
        .unwrap();

        assert_eq!(updated_source.amount, 90_000); // 100k - 10k
        assert_eq!(updated_dest.amount, 14_900); // 5k + (10k - 100 fee)

        // Verify withheld fee tracked
        let fee_ext = updated_dest
            .get_extension(ExtensionType::TransferFeeAmount)
            .unwrap();
        let fee_amount = TransferFeeAmount::unpack(fee_ext).unwrap();
        assert_eq!(fee_amount.withheld_amount, 100);
    }

    // ── Extension persistence tests ─────────────────────────────────────

    #[test]
    fn test_initialize_mint_close_authority_persists() {
        let executor = Token2022ProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST);
        let mint_pubkey = Pubkey::new_unique();
        let close_authority = Pubkey::new_unique();

        let mint = base_mint();
        let mint_account = make_mint_account(&mint);

        let mut instruction_data = vec![25u8];
        instruction_data.push(1);
        instruction_data.extend_from_slice(&close_authority.to_bytes());

        let context = ExecutionContext::new(
            TOKEN_2022_PROGRAM_ID,
            vec![(mint_pubkey, mint_account, true)],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);

        // Verify extension persisted
        let updated_mint = Token2022Mint::unpack_from_account(
            outcome.modified_accounts.get(&mint_pubkey).unwrap(),
        )
        .unwrap();
        assert!(updated_mint.has_extension(ExtensionType::MintCloseAuthority));
        let ext_data = updated_mint
            .get_extension(ExtensionType::MintCloseAuthority)
            .unwrap();
        let ext = MintCloseAuthority::unpack(ext_data).unwrap();
        assert_eq!(ext.close_authority, Some(close_authority));
    }

    #[test]
    fn test_initialize_transfer_fee_config_persists() {
        let executor = Token2022ProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST);
        let mint_pubkey = Pubkey::new_unique();
        let config_authority = Pubkey::new_unique();
        let withdraw_authority = Pubkey::new_unique();

        let mint = base_mint();
        let mint_account = make_mint_account(&mint);

        let mut instruction_data = vec![26u8];
        instruction_data.push(1);
        instruction_data.extend_from_slice(&config_authority.to_bytes());
        instruction_data.push(1);
        instruction_data.extend_from_slice(&withdraw_authority.to_bytes());
        instruction_data.extend_from_slice(&100u16.to_le_bytes());
        instruction_data.extend_from_slice(&10000u64.to_le_bytes());

        let context = ExecutionContext::new(
            TOKEN_2022_PROGRAM_ID,
            vec![(mint_pubkey, mint_account, true)],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);

        let updated_mint = Token2022Mint::unpack_from_account(
            outcome.modified_accounts.get(&mint_pubkey).unwrap(),
        )
        .unwrap();
        assert!(updated_mint.has_extension(ExtensionType::TransferFeeConfig));
        let fee_config = TransferFeeConfig::unpack(
            updated_mint
                .get_extension(ExtensionType::TransferFeeConfig)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(fee_config.newer_transfer_fee.transfer_fee_basis_points, 100);
        assert_eq!(fee_config.newer_transfer_fee.maximum_fee, 10000);
    }

    #[test]
    fn test_initialize_non_transferable_mint_persists() {
        let executor = Token2022ProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST);
        let mint_pubkey = Pubkey::new_unique();
        let mint = base_mint();

        let context = ExecutionContext::new(
            TOKEN_2022_PROGRAM_ID,
            vec![(mint_pubkey, make_mint_account(&mint), true)],
            vec![34u8],
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);

        let updated = Token2022Mint::unpack_from_account(
            outcome.modified_accounts.get(&mint_pubkey).unwrap(),
        )
        .unwrap();
        assert!(updated.has_extension(ExtensionType::NonTransferable));
    }

    #[test]
    fn test_initialize_interest_bearing_persists() {
        let executor = Token2022ProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST);
        let mint_pubkey = Pubkey::new_unique();
        let rate_authority = Pubkey::new_unique();
        let mint = base_mint();

        let mut instruction_data = vec![35u8];
        instruction_data.push(1);
        instruction_data.extend_from_slice(&rate_authority.to_bytes());
        instruction_data.extend_from_slice(&100i16.to_le_bytes());

        let context = ExecutionContext::new(
            TOKEN_2022_PROGRAM_ID,
            vec![(mint_pubkey, make_mint_account(&mint), true)],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);

        let updated = Token2022Mint::unpack_from_account(
            outcome.modified_accounts.get(&mint_pubkey).unwrap(),
        )
        .unwrap();
        let config = InterestBearingConfig::unpack(
            updated
                .get_extension(ExtensionType::InterestBearingConfig)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(config.current_rate, 100);
        assert_eq!(config.rate_authority, Some(rate_authority));
    }

    #[test]
    fn test_set_transfer_fee_updates_config() {
        let executor = Token2022ProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST);
        let mint_pubkey = Pubkey::new_unique();
        let authority_pubkey = Pubkey::new_unique();

        // First: create mint with transfer fee config
        let mut mint = base_mint();
        let initial_config = TransferFeeConfig {
            transfer_fee_config_authority: Some(authority_pubkey),
            withdraw_withheld_authority: None,
            withheld_amount: 0,
            older_transfer_fee: TransferFee {
                epoch: 0,
                maximum_fee: 1000,
                transfer_fee_basis_points: 50,
            },
            newer_transfer_fee: TransferFee {
                epoch: 0,
                maximum_fee: 1000,
                transfer_fee_basis_points: 50,
            },
        };
        mint.set_extension(ExtensionType::TransferFeeConfig, &initial_config.pack())
            .unwrap();

        let mut instruction_data = vec![31u8];
        instruction_data.extend_from_slice(&250u16.to_le_bytes());
        instruction_data.extend_from_slice(&50000u64.to_le_bytes());

        let context = ExecutionContext::new(
            TOKEN_2022_PROGRAM_ID,
            vec![
                (mint_pubkey, make_mint_account(&mint), true),
                (authority_pubkey, Account::default(), false),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);

        let updated_mint = Token2022Mint::unpack_from_account(
            outcome.modified_accounts.get(&mint_pubkey).unwrap(),
        )
        .unwrap();
        let fee_config = TransferFeeConfig::unpack(
            updated_mint
                .get_extension(ExtensionType::TransferFeeConfig)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(fee_config.newer_transfer_fee.transfer_fee_basis_points, 250);
        assert_eq!(fee_config.newer_transfer_fee.maximum_fee, 50000);
        // Old newer becomes older
        assert_eq!(fee_config.older_transfer_fee.transfer_fee_basis_points, 50);
    }

    // ── Authority change tests ──────────────────────────────────────────

    #[test]
    fn test_set_authority_mint_authority() {
        let executor = Token2022ProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST);
        let mint_pubkey = Pubkey::new_unique();
        let new_auth = Pubkey::new_unique();
        let mint = base_mint();

        let mut instruction_data = vec![6u8]; // SetAuthority
        instruction_data.push(0); // MintTokens authority
        instruction_data.push(1); // has new authority
        instruction_data.extend_from_slice(&new_auth.to_bytes());

        let context = ExecutionContext::new(
            TOKEN_2022_PROGRAM_ID,
            vec![
                (mint_pubkey, make_mint_account(&mint), true),
                (Pubkey::new_unique(), Account::default(), false),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);

        let updated = Token2022Mint::unpack_from_account(
            outcome.modified_accounts.get(&mint_pubkey).unwrap(),
        )
        .unwrap();
        assert_eq!(updated.mint_authority, Some(new_auth));
    }

    // ── New extension instruction tests ─────────────────────────────────

    #[test]
    fn test_initialize_permanent_delegate() {
        let executor = Token2022ProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST);
        let mint_pubkey = Pubkey::new_unique();
        let delegate = Pubkey::new_unique();
        let mint = base_mint();

        let mut instruction_data = vec![37u8];
        instruction_data.push(1);
        instruction_data.extend_from_slice(&delegate.to_bytes());

        let context = ExecutionContext::new(
            TOKEN_2022_PROGRAM_ID,
            vec![(mint_pubkey, make_mint_account(&mint), true)],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);

        let updated = Token2022Mint::unpack_from_account(
            outcome.modified_accounts.get(&mint_pubkey).unwrap(),
        )
        .unwrap();
        let ext = PermanentDelegate::unpack(
            updated
                .get_extension(ExtensionType::PermanentDelegate)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(ext.delegate, Some(delegate));
    }

    #[test]
    fn test_toggle_cpi_guard() {
        let executor = Token2022ProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST);
        let account_pubkey = Pubkey::new_unique();
        let token = base_token(&Pubkey::new_unique(), &Pubkey::new_unique(), 1000);

        let context = ExecutionContext::new(
            TOKEN_2022_PROGRAM_ID,
            vec![(account_pubkey, make_token_account(&token), true)],
            vec![38u8, 1], // Enable CPI guard
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);

        let updated = Token2022Account::unpack_from_account(
            outcome.modified_accounts.get(&account_pubkey).unwrap(),
        )
        .unwrap();
        assert!(updated.has_extension(ExtensionType::CpiGuard));
        assert_eq!(
            updated.get_extension(ExtensionType::CpiGuard).unwrap(),
            &[1]
        );
    }

    #[test]
    fn test_initialize_transfer_hook() {
        let executor = Token2022ProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST);
        let mint_pubkey = Pubkey::new_unique();
        let authority = Pubkey::new_unique();
        let hook_program = Pubkey::new_unique();
        let mint = base_mint();

        let mut instruction_data = vec![39u8];
        instruction_data.push(1);
        instruction_data.extend_from_slice(&authority.to_bytes());
        instruction_data.push(1);
        instruction_data.extend_from_slice(&hook_program.to_bytes());

        let context = ExecutionContext::new(
            TOKEN_2022_PROGRAM_ID,
            vec![(mint_pubkey, make_mint_account(&mint), true)],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);

        let updated = Token2022Mint::unpack_from_account(
            outcome.modified_accounts.get(&mint_pubkey).unwrap(),
        )
        .unwrap();
        let ext =
            TransferHookExt::unpack(updated.get_extension(ExtensionType::TransferHook).unwrap())
                .unwrap();
        assert_eq!(ext.authority, Some(authority));
        assert_eq!(ext.program_id, Some(hook_program));
    }

    #[test]
    fn test_initialize_metadata_pointer() {
        let executor = Token2022ProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST);
        let mint_pubkey = Pubkey::new_unique();
        let authority = Pubkey::new_unique();
        let metadata = Pubkey::new_unique();
        let mint = base_mint();

        let mut instruction_data = vec![40u8];
        instruction_data.push(1);
        instruction_data.extend_from_slice(&authority.to_bytes());
        instruction_data.push(1);
        instruction_data.extend_from_slice(&metadata.to_bytes());

        let context = ExecutionContext::new(
            TOKEN_2022_PROGRAM_ID,
            vec![(mint_pubkey, make_mint_account(&mint), true)],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);

        let updated = Token2022Mint::unpack_from_account(
            outcome.modified_accounts.get(&mint_pubkey).unwrap(),
        )
        .unwrap();
        let ext = MetadataPointer::unpack(
            updated
                .get_extension(ExtensionType::MetadataPointer)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(ext.metadata_address, Some(metadata));
    }

    #[test]
    fn test_extension_already_initialized_rejected() {
        let executor = Token2022ProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST);
        let mint_pubkey = Pubkey::new_unique();

        // Mint already has NonTransferable
        let mut mint = base_mint();
        mint.set_extension(ExtensionType::NonTransferable, &[])
            .unwrap();

        let context = ExecutionContext::new(
            TOKEN_2022_PROGRAM_ID,
            vec![(mint_pubkey, make_mint_account(&mint), true)],
            vec![34u8],
        );

        let result = executor.execute(&context);
        assert!(result.is_err());
    }

    // ── Transfer fee calculation (unchanged) ────────────────────────────

    #[test]
    fn test_transfer_fee_calculation() {
        let config = TransferFeeConfig {
            transfer_fee_config_authority: Some(Pubkey::new_unique()),
            withdraw_withheld_authority: Some(Pubkey::new_unique()),
            withheld_amount: 0,
            older_transfer_fee: TransferFee {
                epoch: 0,
                maximum_fee: 10000,
                transfer_fee_basis_points: 100,
            },
            newer_transfer_fee: TransferFee {
                epoch: 100,
                maximum_fee: 20000,
                transfer_fee_basis_points: 200,
            },
        };

        assert_eq!(config.calculate_fee(100000, 50).unwrap(), 1000);
        assert_eq!(config.calculate_fee(100000, 150).unwrap(), 2000);
        assert_eq!(config.calculate_fee(10000000, 150).unwrap(), 20000);
    }

    #[test]
    fn test_extension_packing_roundtrip() {
        let config = TransferFeeConfig {
            transfer_fee_config_authority: Some(Pubkey::new_unique()),
            withdraw_withheld_authority: Some(Pubkey::new_unique()),
            withheld_amount: 12345,
            older_transfer_fee: TransferFee {
                epoch: 10,
                maximum_fee: 1000,
                transfer_fee_basis_points: 50,
            },
            newer_transfer_fee: TransferFee {
                epoch: 20,
                maximum_fee: 2000,
                transfer_fee_basis_points: 100,
            },
        };

        let packed = config.pack();
        let unpacked = TransferFeeConfig::unpack(&packed).unwrap();
        assert_eq!(config, unpacked);
    }

    #[test]
    fn test_interest_bearing_config_roundtrip() {
        let config = InterestBearingConfig {
            rate_authority: Some(Pubkey::new_unique()),
            initialization_timestamp: 12345678,
            pre_update_average_rate: 50,
            last_update_timestamp: 12345679,
            current_rate: 100,
        };

        let packed = config.pack();
        let unpacked = InterestBearingConfig::unpack(&packed).unwrap();
        assert_eq!(config, unpacked);
    }

    #[test]
    fn test_new_extension_types_pack_roundtrip() {
        // PermanentDelegate
        let pd = PermanentDelegate {
            delegate: Some(Pubkey::new_unique()),
        };
        assert_eq!(pd, PermanentDelegate::unpack(&pd.pack()).unwrap());

        // TransferHookExt
        let th = TransferHookExt {
            authority: Some(Pubkey::new_unique()),
            program_id: Some(Pubkey::new_unique()),
        };
        assert_eq!(th, TransferHookExt::unpack(&th.pack()).unwrap());

        // MetadataPointer
        let mp = MetadataPointer {
            authority: Some(Pubkey::new_unique()),
            metadata_address: Some(Pubkey::new_unique()),
        };
        assert_eq!(mp, MetadataPointer::unpack(&mp.pack()).unwrap());

        // GroupPointer
        let gp = GroupPointer {
            authority: Some(Pubkey::new_unique()),
            group_address: Some(Pubkey::new_unique()),
        };
        assert_eq!(gp, GroupPointer::unpack(&gp.pack()).unwrap());

        // GroupMemberPointer
        let gmp = GroupMemberPointer {
            authority: Some(Pubkey::new_unique()),
            member_address: Some(Pubkey::new_unique()),
        };
        assert_eq!(gmp, GroupMemberPointer::unpack(&gmp.pack()).unwrap());

        // TransferFeeAmount
        let tfa = TransferFeeAmount {
            withheld_amount: 99999,
        };
        assert_eq!(tfa, TransferFeeAmount::unpack(&tfa.pack()).unwrap());
    }

    // ── Instruction handler tests ───────────────────────────────────────

    fn make_empty_account(size: usize) -> Account {
        Account {
            meta: AccountMeta {
                lamports: 1_000_000,
                owner: TOKEN_2022_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(vec![0u8; size]),
        }
    }

    fn make_authority_account() -> Account {
        Account::new(0, Vec::new(), Pubkey::default())
    }

    #[test]
    fn test_initialize_mint_writes_state() {
        let executor = Token2022ProgramExecutor::new(100);
        let mint_pubkey = Pubkey::new_unique();
        let authority = Pubkey::new_unique();

        let mut instruction_data = vec![0u8]; // discriminator = 0 (InitializeMint)
        instruction_data.push(9); // decimals
        instruction_data.extend_from_slice(&authority.to_bytes()); // mint_authority
                                                                   // no freeze authority

        let ctx = ExecutionContext::new(
            TOKEN_2022_PROGRAM_ID,
            vec![(mint_pubkey, make_empty_account(82), true)],
            instruction_data,
        );

        let result = executor.execute(&ctx).unwrap();
        let modified = result.modified_accounts.get(&mint_pubkey).unwrap();
        let mint = Token2022Mint::unpack(modified.data.as_slice()).unwrap();
        assert!(mint.is_initialized);
        assert_eq!(mint.decimals, 9);
        assert_eq!(mint.supply, 0);
        assert_eq!(mint.mint_authority, Some(authority));
        assert_eq!(mint.freeze_authority, None);
    }

    #[test]
    fn test_initialize_account_writes_state() {
        let executor = Token2022ProgramExecutor::new(100);
        let acct_pubkey = Pubkey::new_unique();
        let mint_pubkey = Pubkey::new_unique();
        let owner_pubkey = Pubkey::new_unique();

        let instruction_data = vec![1u8]; // discriminator = 1 (InitializeAccount)

        let ctx = ExecutionContext::new(
            TOKEN_2022_PROGRAM_ID,
            vec![
                (acct_pubkey, make_empty_account(165), true),
                (mint_pubkey, make_empty_account(82), false),
                (owner_pubkey, make_authority_account(), false),
            ],
            instruction_data,
        );

        let result = executor.execute(&ctx).unwrap();
        let modified = result.modified_accounts.get(&acct_pubkey).unwrap();
        let token = Token2022Account::unpack(modified.data.as_slice()).unwrap();
        assert_eq!(token.mint, mint_pubkey);
        assert_eq!(token.owner, owner_pubkey);
        assert_eq!(token.amount, 0);
        assert_eq!(token.state, 1); // Initialized
    }

    #[test]
    fn test_mint_to_increases_supply_and_balance() {
        let executor = Token2022ProgramExecutor::new(100);
        let mint_pubkey = Pubkey::new_unique();
        let dest_pubkey = Pubkey::new_unique();
        let authority = Pubkey::new_unique();

        let mint = Token2022Mint {
            mint_authority: Some(authority),
            supply: 1000,
            decimals: 6,
            is_initialized: true,
            freeze_authority: None,
            extensions: Vec::new(),
        };
        let dest = base_token(&mint_pubkey, &Pubkey::new_unique(), 500);

        let mut instruction_data = vec![7u8]; // MintTo
        instruction_data.extend_from_slice(&200u64.to_le_bytes());

        let ctx = ExecutionContext::new(
            TOKEN_2022_PROGRAM_ID,
            vec![
                (mint_pubkey, make_mint_account(&mint), true),
                (dest_pubkey, make_token_account(&dest), true),
                (authority, make_authority_account(), false),
            ],
            instruction_data,
        );

        let result = executor.execute(&ctx).unwrap();
        let new_mint =
            Token2022Mint::unpack(result.modified_accounts[&mint_pubkey].data.as_slice()).unwrap();
        assert_eq!(new_mint.supply, 1200);

        let new_dest =
            Token2022Account::unpack(result.modified_accounts[&dest_pubkey].data.as_slice())
                .unwrap();
        assert_eq!(new_dest.amount, 700);
    }

    #[test]
    fn test_burn_decreases_supply_and_balance() {
        let executor = Token2022ProgramExecutor::new(100);
        let mint_pubkey = Pubkey::new_unique();
        let src_pubkey = Pubkey::new_unique();
        let owner = Pubkey::new_unique();

        let mint = Token2022Mint {
            mint_authority: Some(Pubkey::new_unique()),
            supply: 1000,
            decimals: 6,
            is_initialized: true,
            freeze_authority: None,
            extensions: Vec::new(),
        };
        let src = base_token(&mint_pubkey, &owner, 500);

        let mut instruction_data = vec![8u8]; // Burn
        instruction_data.extend_from_slice(&300u64.to_le_bytes());

        let ctx = ExecutionContext::new(
            TOKEN_2022_PROGRAM_ID,
            vec![
                (src_pubkey, make_token_account(&src), true),
                (mint_pubkey, make_mint_account(&mint), true),
                (owner, make_authority_account(), false),
            ],
            instruction_data,
        );

        let result = executor.execute(&ctx).unwrap();
        let new_src =
            Token2022Account::unpack(result.modified_accounts[&src_pubkey].data.as_slice())
                .unwrap();
        assert_eq!(new_src.amount, 200);

        let new_mint =
            Token2022Mint::unpack(result.modified_accounts[&mint_pubkey].data.as_slice()).unwrap();
        assert_eq!(new_mint.supply, 700);
    }

    #[test]
    fn test_burn_insufficient_funds() {
        let executor = Token2022ProgramExecutor::new(100);
        let mint_pubkey = Pubkey::new_unique();
        let src_pubkey = Pubkey::new_unique();
        let owner = Pubkey::new_unique();

        let mint = base_mint();
        let src = base_token(&mint_pubkey, &owner, 100);

        let mut instruction_data = vec![8u8];
        instruction_data.extend_from_slice(&200u64.to_le_bytes());

        let ctx = ExecutionContext::new(
            TOKEN_2022_PROGRAM_ID,
            vec![
                (src_pubkey, make_token_account(&src), true),
                (mint_pubkey, make_mint_account(&mint), true),
                (owner, make_authority_account(), false),
            ],
            instruction_data,
        );

        let result = executor.execute(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Insufficient"));
    }

    #[test]
    fn test_freeze_thaw_lifecycle() {
        let executor = Token2022ProgramExecutor::new(100);
        let acct_pubkey = Pubkey::new_unique();
        let mint_pubkey = Pubkey::new_unique();
        let freeze_auth = Pubkey::new_unique();

        let mint = Token2022Mint {
            mint_authority: Some(Pubkey::new_unique()),
            supply: 1000,
            decimals: 6,
            is_initialized: true,
            freeze_authority: Some(freeze_auth),
            extensions: Vec::new(),
        };
        let token = base_token(&mint_pubkey, &Pubkey::new_unique(), 500);

        // Freeze
        let ctx = ExecutionContext::new(
            TOKEN_2022_PROGRAM_ID,
            vec![
                (acct_pubkey, make_token_account(&token), true),
                (mint_pubkey, make_mint_account(&mint), false),
                (freeze_auth, make_authority_account(), false),
            ],
            vec![10u8], // FreezeAccount
        );

        let result = executor.execute(&ctx).unwrap();
        let frozen =
            Token2022Account::unpack(result.modified_accounts[&acct_pubkey].data.as_slice())
                .unwrap();
        assert_eq!(frozen.state, 2); // Frozen

        // Thaw
        let ctx2 = ExecutionContext::new(
            TOKEN_2022_PROGRAM_ID,
            vec![
                (
                    acct_pubkey,
                    result.modified_accounts[&acct_pubkey].clone(),
                    true,
                ),
                (mint_pubkey, make_mint_account(&mint), false),
                (freeze_auth, make_authority_account(), false),
            ],
            vec![11u8], // ThawAccount
        );

        let result2 = executor.execute(&ctx2).unwrap();
        let thawed =
            Token2022Account::unpack(result2.modified_accounts[&acct_pubkey].data.as_slice())
                .unwrap();
        assert_eq!(thawed.state, 1); // Initialized
    }

    #[test]
    fn test_approve_revoke_delegation() {
        let executor = Token2022ProgramExecutor::new(100);
        let src_pubkey = Pubkey::new_unique();
        let delegate_pubkey = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let mint_pubkey = Pubkey::new_unique();

        let token = base_token(&mint_pubkey, &owner, 1000);

        // Approve
        let mut instruction_data = vec![4u8]; // Approve
        instruction_data.extend_from_slice(&500u64.to_le_bytes());

        let ctx = ExecutionContext::new(
            TOKEN_2022_PROGRAM_ID,
            vec![
                (src_pubkey, make_token_account(&token), true),
                (delegate_pubkey, make_authority_account(), false),
                (owner, make_authority_account(), false),
            ],
            instruction_data,
        );

        let result = executor.execute(&ctx).unwrap();
        let approved =
            Token2022Account::unpack(result.modified_accounts[&src_pubkey].data.as_slice())
                .unwrap();
        assert_eq!(approved.delegate, Some(delegate_pubkey));
        assert_eq!(approved.delegated_amount, 500);

        // Revoke
        let ctx2 = ExecutionContext::new(
            TOKEN_2022_PROGRAM_ID,
            vec![
                (
                    src_pubkey,
                    result.modified_accounts[&src_pubkey].clone(),
                    true,
                ),
                (owner, make_authority_account(), false),
            ],
            vec![5u8], // Revoke
        );

        let result2 = executor.execute(&ctx2).unwrap();
        let revoked =
            Token2022Account::unpack(result2.modified_accounts[&src_pubkey].data.as_slice())
                .unwrap();
        assert_eq!(revoked.delegate, None);
        assert_eq!(revoked.delegated_amount, 0);
    }

    #[test]
    fn test_close_account_transfers_lamports() {
        let executor = Token2022ProgramExecutor::new(100);
        let close_pubkey = Pubkey::new_unique();
        let dest_pubkey = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let mint_pubkey = Pubkey::new_unique();

        let token = base_token(&mint_pubkey, &owner, 0); // zero balance required for close

        let close_acct = Account {
            meta: AccountMeta {
                lamports: 2_000_000,
                owner: TOKEN_2022_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(token.pack()),
        };

        let dest_acct = Account::new(500_000, Vec::new(), Pubkey::default());

        let ctx = ExecutionContext::new(
            TOKEN_2022_PROGRAM_ID,
            vec![
                (close_pubkey, close_acct, true),
                (dest_pubkey, dest_acct, true),
                (owner, make_authority_account(), false),
            ],
            vec![9u8], // CloseAccount
        );

        let result = executor.execute(&ctx).unwrap();
        assert_eq!(result.modified_accounts[&close_pubkey].meta.lamports, 0);
        assert_eq!(
            result.modified_accounts[&dest_pubkey].meta.lamports,
            2_500_000
        );
        assert!(result.modified_accounts[&close_pubkey]
            .data
            .as_slice()
            .is_empty());
    }

    #[test]
    fn test_close_account_rejects_nonzero_balance() {
        let executor = Token2022ProgramExecutor::new(100);
        let close_pubkey = Pubkey::new_unique();
        let dest_pubkey = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let mint_pubkey = Pubkey::new_unique();

        let token = base_token(&mint_pubkey, &owner, 100); // non-zero — should fail

        let ctx = ExecutionContext::new(
            TOKEN_2022_PROGRAM_ID,
            vec![
                (close_pubkey, make_token_account(&token), true),
                (dest_pubkey, make_authority_account(), true),
                (owner, make_authority_account(), false),
            ],
            vec![9u8],
        );

        assert!(executor.execute(&ctx).is_err());
    }

    #[test]
    fn test_initialize_mint_to_transfer_round_trip() {
        let executor = Token2022ProgramExecutor::new(100);
        let mint_pubkey = Pubkey::new_unique();
        let authority = Pubkey::new_unique();
        let alice_pubkey = Pubkey::new_unique();
        let bob_pubkey = Pubkey::new_unique();

        // Step 1: InitializeMint
        let mut init_mint_data = vec![0u8, 6]; // decimals=6
        init_mint_data.extend_from_slice(&authority.to_bytes());
        let ctx1 = ExecutionContext::new(
            TOKEN_2022_PROGRAM_ID,
            vec![(mint_pubkey, make_empty_account(82), true)],
            init_mint_data,
        );
        let r1 = executor.execute(&ctx1).unwrap();
        let mint_acct = r1.modified_accounts[&mint_pubkey].clone();

        // Step 2: InitializeAccount for Alice
        let ctx2 = ExecutionContext::new(
            TOKEN_2022_PROGRAM_ID,
            vec![
                (alice_pubkey, make_empty_account(165), true),
                (mint_pubkey, mint_acct.clone(), false),
                (authority, make_authority_account(), false),
            ],
            vec![1u8],
        );
        let r2 = executor.execute(&ctx2).unwrap();
        let alice_acct = r2.modified_accounts[&alice_pubkey].clone();

        // Step 3: InitializeAccount for Bob
        let ctx3 = ExecutionContext::new(
            TOKEN_2022_PROGRAM_ID,
            vec![
                (bob_pubkey, make_empty_account(165), true),
                (mint_pubkey, mint_acct.clone(), false),
                (authority, make_authority_account(), false),
            ],
            vec![1u8],
        );
        let r3 = executor.execute(&ctx3).unwrap();
        let bob_acct = r3.modified_accounts[&bob_pubkey].clone();

        // Step 4: MintTo Alice 1000
        let mut mint_to_data = vec![7u8];
        mint_to_data.extend_from_slice(&1000u64.to_le_bytes());
        let ctx4 = ExecutionContext::new(
            TOKEN_2022_PROGRAM_ID,
            vec![
                (mint_pubkey, mint_acct.clone(), true),
                (alice_pubkey, alice_acct.clone(), true),
                (authority, make_authority_account(), false),
            ],
            mint_to_data,
        );
        let r4 = executor.execute(&ctx4).unwrap();
        let alice_acct2 = r4.modified_accounts[&alice_pubkey].clone();
        let mint_acct2 = r4.modified_accounts[&mint_pubkey].clone();

        // Step 5: Transfer 300 from Alice to Bob
        let mut transfer_data = vec![3u8];
        transfer_data.extend_from_slice(&300u64.to_le_bytes());
        let ctx5 = ExecutionContext::new(
            TOKEN_2022_PROGRAM_ID,
            vec![
                (alice_pubkey, alice_acct2, true),
                (bob_pubkey, bob_acct, true),
                (authority, make_authority_account(), false),
            ],
            transfer_data,
        );
        let r5 = executor.execute(&ctx5).unwrap();

        let final_alice =
            Token2022Account::unpack(r5.modified_accounts[&alice_pubkey].data.as_slice()).unwrap();
        let final_bob =
            Token2022Account::unpack(r5.modified_accounts[&bob_pubkey].data.as_slice()).unwrap();
        let final_mint = Token2022Mint::unpack(mint_acct2.data.as_slice()).unwrap();

        assert_eq!(final_alice.amount, 700);
        assert_eq!(final_bob.amount, 300);
        assert_eq!(final_mint.supply, 1000);
    }

    #[test]
    fn test_initialize_immutable_owner() {
        let executor = Token2022ProgramExecutor::new(100);
        let acct_pubkey = Pubkey::new_unique();
        let mint_pubkey = Pubkey::new_unique();
        let owner = Pubkey::new_unique();

        let token = base_token(&mint_pubkey, &owner, 0);

        let ctx = ExecutionContext::new(
            TOKEN_2022_PROGRAM_ID,
            vec![(acct_pubkey, make_token_account(&token), true)],
            vec![22u8], // InitializeImmutableOwner
        );

        let result = executor.execute(&ctx).unwrap();
        let modified =
            Token2022Account::unpack(result.modified_accounts[&acct_pubkey].data.as_slice())
                .unwrap();
        assert!(modified.has_extension(ExtensionType::ImmutableOwner));
    }

    #[test]
    fn test_mint_to_checked_validates_decimals() {
        let executor = Token2022ProgramExecutor::new(100);
        let mint_pubkey = Pubkey::new_unique();
        let dest_pubkey = Pubkey::new_unique();
        let authority = Pubkey::new_unique();

        let mint = Token2022Mint {
            mint_authority: Some(authority),
            supply: 1000,
            decimals: 6,
            is_initialized: true,
            freeze_authority: None,
            extensions: Vec::new(),
        };
        let dest = base_token(&mint_pubkey, &Pubkey::new_unique(), 500);

        // Wrong decimals (9 instead of 6)
        let mut instruction_data = vec![14u8]; // MintToChecked
        instruction_data.extend_from_slice(&200u64.to_le_bytes());
        instruction_data.push(9); // wrong decimals

        let ctx = ExecutionContext::new(
            TOKEN_2022_PROGRAM_ID,
            vec![
                (mint_pubkey, make_mint_account(&mint), true),
                (dest_pubkey, make_token_account(&dest), true),
                (authority, make_authority_account(), false),
            ],
            instruction_data,
        );

        let result = executor.execute(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("decimals"));
    }
}
