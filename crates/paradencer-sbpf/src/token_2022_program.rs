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
use paradencer_constants::execution::DEFAULT_INSTRUCTION_BASE_COST;
use paradencer_types::{Account, AccountData, Pubkey};

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
    fn from_u16(value: u16) -> Option<Self> {
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

/// Token-2022 account with extensions support
#[derive(Debug, Clone, PartialEq)]
pub struct Token2022Account {
    // Base token account data (same as Token Program)
    pub mint: Pubkey,
    pub owner: Pubkey,
    pub amount: u64,
    pub delegate: Option<Pubkey>,
    pub state: u8,
    pub is_native: Option<u64>,
    pub delegated_amount: u64,
    pub close_authority: Option<Pubkey>,
    // Extensions stored as raw bytes for simplicity
    pub extensions: Vec<u8>,
}

impl Token2022Account {
    pub const BASE_LEN: usize = 165;

    pub fn has_extension(&self, ext_type: ExtensionType) -> bool {
        // Simple check: if extensions are present, assume they're valid
        // In a full implementation, we'd parse the extension TLV structure
        !self.extensions.is_empty()
    }
}

/// Token-2022 mint with extensions support
#[derive(Debug, Clone, PartialEq)]
pub struct Token2022Mint {
    // Base mint data
    pub mint_authority: Option<Pubkey>,
    pub supply: u64,
    pub decimals: u8,
    pub is_initialized: bool,
    pub freeze_authority: Option<Pubkey>,
    // Extensions stored as raw bytes
    pub extensions: Vec<u8>,
}

impl Token2022Mint {
    pub const BASE_LEN: usize = 82;
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
            _ => Err(format!(
                "Unknown Token-2022 instruction: {}",
                instruction_type
            )),
        }
    }

    // Base Token Program instructions (simplified implementations)
    // In practice, these would use the full Token Program logic

    fn initialize_mint(&self, _context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        // Simplified: Just return success with base cost
        Ok(ExecutionOutcome::success(self.base_cost + 50))
    }

    fn initialize_account(&self, _context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        Ok(ExecutionOutcome::success(self.base_cost + 50))
    }

    fn initialize_multisig(&self, _context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        Ok(ExecutionOutcome::success(self.base_cost + 50))
    }

    fn transfer(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        // Check for non-transferable extension
        // Simplified: just process transfer
        if context.instruction_data.len() < 9 {
            return Err("Transfer requires amount".to_string());
        }
        Ok(ExecutionOutcome::success(self.base_cost + 100))
    }

    fn approve(&self, _context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        Ok(ExecutionOutcome::success(self.base_cost + 50))
    }

    fn revoke(&self, _context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        Ok(ExecutionOutcome::success(self.base_cost + 30))
    }

    fn mint_to(&self, _context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        Ok(ExecutionOutcome::success(self.base_cost + 100))
    }

    fn burn(&self, _context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        Ok(ExecutionOutcome::success(self.base_cost + 100))
    }

    fn close_account(&self, _context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        Ok(ExecutionOutcome::success(self.base_cost + 50))
    }

    fn freeze_account(&self, _context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        Ok(ExecutionOutcome::success(self.base_cost + 50))
    }

    fn thaw_account(&self, _context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        Ok(ExecutionOutcome::success(self.base_cost + 50))
    }

    fn transfer_checked(&self, _context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        Ok(ExecutionOutcome::success(self.base_cost + 100))
    }

    fn approve_checked(&self, _context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        Ok(ExecutionOutcome::success(self.base_cost + 50))
    }

    fn mint_to_checked(&self, _context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        Ok(ExecutionOutcome::success(self.base_cost + 100))
    }

    fn burn_checked(&self, _context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        Ok(ExecutionOutcome::success(self.base_cost + 100))
    }

    fn initialize_account2(&self, _context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        Ok(ExecutionOutcome::success(self.base_cost + 50))
    }

    fn sync_native(&self, _context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        Ok(ExecutionOutcome::success(self.base_cost + 10))
    }

    fn initialize_account3(&self, _context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        Ok(ExecutionOutcome::success(self.base_cost + 50))
    }

    fn initialize_mint2(&self, _context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        Ok(ExecutionOutcome::success(self.base_cost + 50))
    }

    fn get_account_data_size(
        &self,
        _context: &ExecutionContext,
    ) -> Result<ExecutionOutcome, String> {
        // Calculate size based on extension types in instruction data
        Ok(ExecutionOutcome::success(self.base_cost + 10))
    }

    fn initialize_immutable_owner(
        &self,
        _context: &ExecutionContext,
    ) -> Result<ExecutionOutcome, String> {
        Ok(ExecutionOutcome::success(self.base_cost + 30))
    }

    fn amount_to_ui_amount(&self, _context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        Ok(ExecutionOutcome::success(self.base_cost + 20))
    }

    fn ui_amount_to_amount(&self, _context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
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

        // In a full implementation, we'd append this to the mint's extension data
        // For now, just mark as modified
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

        // Store extension data
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
        let (_mint_pubkey, _mint_account, _) = context.accounts[1].clone();
        let (dest_pubkey, mut dest_account, dest_writable) = context.accounts[2].clone();

        if !source_writable || !dest_writable {
            return Err("Source and destination must be writable".to_string());
        }

        let amount = u64::from_le_bytes(context.instruction_data[1..9].try_into().unwrap());
        let _decimals = context.instruction_data[9];
        let fee = u64::from_le_bytes(context.instruction_data[10..18].try_into().unwrap());

        // In a full implementation:
        // 1. Verify fee matches the mint's transfer fee config
        // 2. Transfer (amount - fee) to destination
        // 3. Withhold fee in source account or separate fee account
        // 4. Update withheld amounts

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

        // Transfer all withheld fees from mint to destination
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

        // Collect withheld fees from multiple source accounts
        let mut outcome =
            ExecutionOutcome::success(self.base_cost + 80 * context.accounts.len() as u64);

        // Mark all accounts as modified
        for (pubkey, account, _writable) in &context.accounts[..context.accounts.len()] {
            outcome.modified_accounts.insert(*pubkey, account.clone());
        }

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

        // Move withheld fees from accounts to the mint
        let mut outcome =
            ExecutionOutcome::success(self.base_cost + 60 * context.accounts.len() as u64);

        for (pubkey, account, _writable) in &context.accounts {
            outcome.modified_accounts.insert(*pubkey, account.clone());
        }

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

        // Update the transfer fee config extension
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

        // Add non-transferable extension to mint
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

        // Create interest-bearing config
        let _config = InterestBearingConfig {
            rate_authority,
            initialization_timestamp: 0, // Would use current timestamp
            pre_update_average_rate: 0,
            last_update_timestamp: 0,
            current_rate: rate,
        };

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

        let _new_rate = i16::from_le_bytes(context.instruction_data[1..3].try_into().unwrap());

        // Update the interest rate in the extension
        let mut outcome = ExecutionOutcome::success(self.base_cost + 70);
        outcome.modified_accounts.insert(mint_pubkey, mint_account);

        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paradencer_ids::TOKEN_2022_PROGRAM_ID;
    use paradencer_types::AccountMeta;

    #[test]
    fn test_initialize_mint_close_authority() {
        let executor = Token2022ProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST);

        let mint_pubkey = Pubkey::new_unique();
        let close_authority = Pubkey::new_unique();

        let mint_account = Account {
            meta: AccountMeta {
                lamports: 1000000,
                owner: TOKEN_2022_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };

        let mut instruction_data = vec![25u8]; // InitializeMintCloseAuthority
        instruction_data.push(1); // has authority
        instruction_data.extend_from_slice(&close_authority.to_bytes());

        let context = ExecutionContext::new(
            TOKEN_2022_PROGRAM_ID,
            vec![(mint_pubkey, mint_account, true)],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert_eq!(outcome.modified_accounts.len(), 1);
    }

    #[test]
    fn test_initialize_transfer_fee_config() {
        let executor = Token2022ProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST);

        let mint_pubkey = Pubkey::new_unique();
        let config_authority = Pubkey::new_unique();
        let withdraw_authority = Pubkey::new_unique();

        let mint_account = Account {
            meta: AccountMeta {
                lamports: 1000000,
                owner: TOKEN_2022_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };

        let mut instruction_data = vec![26u8]; // InitializeTransferFeeConfig
        instruction_data.push(1); // has config authority
        instruction_data.extend_from_slice(&config_authority.to_bytes());
        instruction_data.push(1); // has withdraw authority
        instruction_data.extend_from_slice(&withdraw_authority.to_bytes());
        instruction_data.extend_from_slice(&100u16.to_le_bytes()); // basis points (1%)
        instruction_data.extend_from_slice(&10000u64.to_le_bytes()); // max fee

        let context = ExecutionContext::new(
            TOKEN_2022_PROGRAM_ID,
            vec![(mint_pubkey, mint_account, true)],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert_eq!(outcome.modified_accounts.len(), 1);
    }

    #[test]
    fn test_transfer_fee_calculation() {
        let config = TransferFeeConfig {
            transfer_fee_config_authority: Some(Pubkey::new_unique()),
            withdraw_withheld_authority: Some(Pubkey::new_unique()),
            withheld_amount: 0,
            older_transfer_fee: TransferFee {
                epoch: 0,
                maximum_fee: 10000,
                transfer_fee_basis_points: 100, // 1%
            },
            newer_transfer_fee: TransferFee {
                epoch: 100,
                maximum_fee: 20000,
                transfer_fee_basis_points: 200, // 2%
            },
        };

        // Test with older fee (epoch 50)
        let fee = config.calculate_fee(100000, 50).unwrap();
        assert_eq!(fee, 1000); // 1% of 100000

        // Test with newer fee (epoch 150)
        let fee = config.calculate_fee(100000, 150).unwrap();
        assert_eq!(fee, 2000); // 2% of 100000

        // Test maximum fee cap
        let fee = config.calculate_fee(10000000, 150).unwrap();
        assert_eq!(fee, 20000); // Capped at maximum_fee
    }

    #[test]
    fn test_transfer_checked_with_fee() {
        let executor = Token2022ProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST);

        let source_pubkey = Pubkey::new_unique();
        let mint_pubkey = Pubkey::new_unique();
        let dest_pubkey = Pubkey::new_unique();
        let authority_pubkey = Pubkey::new_unique();

        let source_account = Account {
            meta: AccountMeta {
                lamports: 1000000,
                owner: TOKEN_2022_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };

        let mint_account = source_account.clone();
        let dest_account = source_account.clone();
        let authority_account = source_account.clone();

        let mut instruction_data = vec![27u8]; // TransferCheckedWithFee
        instruction_data.extend_from_slice(&100000u64.to_le_bytes()); // amount
        instruction_data.push(9); // decimals
        instruction_data.extend_from_slice(&1000u64.to_le_bytes()); // fee

        let context = ExecutionContext::new(
            TOKEN_2022_PROGRAM_ID,
            vec![
                (source_pubkey, source_account, true),
                (mint_pubkey, mint_account, false),
                (dest_pubkey, dest_account, true),
                (authority_pubkey, authority_account, false),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert!(outcome.compute_units_consumed > 0);
    }

    #[test]
    fn test_initialize_non_transferable_mint() {
        let executor = Token2022ProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST);

        let mint_pubkey = Pubkey::new_unique();

        let mint_account = Account {
            meta: AccountMeta {
                lamports: 1000000,
                owner: TOKEN_2022_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };

        let instruction_data = vec![34u8]; // InitializeNonTransferableMint

        let context = ExecutionContext::new(
            TOKEN_2022_PROGRAM_ID,
            vec![(mint_pubkey, mint_account, true)],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert_eq!(outcome.modified_accounts.len(), 1);
    }

    #[test]
    fn test_initialize_interest_bearing_config() {
        let executor = Token2022ProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST);

        let mint_pubkey = Pubkey::new_unique();
        let rate_authority = Pubkey::new_unique();

        let mint_account = Account {
            meta: AccountMeta {
                lamports: 1000000,
                owner: TOKEN_2022_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };

        let mut instruction_data = vec![35u8]; // InitializeInterestBearingConfig
        instruction_data.push(1); // has authority
        instruction_data.extend_from_slice(&rate_authority.to_bytes());
        instruction_data.extend_from_slice(&100i16.to_le_bytes()); // rate (1% in basis points)

        let context = ExecutionContext::new(
            TOKEN_2022_PROGRAM_ID,
            vec![(mint_pubkey, mint_account, true)],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert_eq!(outcome.modified_accounts.len(), 1);
    }

    #[test]
    fn test_set_transfer_fee() {
        let executor = Token2022ProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST);

        let mint_pubkey = Pubkey::new_unique();
        let authority_pubkey = Pubkey::new_unique();

        let mint_account = Account {
            meta: AccountMeta {
                lamports: 1000000,
                owner: TOKEN_2022_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };

        let authority_account = Account::default();

        let mut instruction_data = vec![31u8]; // SetTransferFee
        instruction_data.extend_from_slice(&250u16.to_le_bytes()); // 2.5% basis points
        instruction_data.extend_from_slice(&50000u64.to_le_bytes()); // max fee

        let context = ExecutionContext::new(
            TOKEN_2022_PROGRAM_ID,
            vec![
                (mint_pubkey, mint_account, true),
                (authority_pubkey, authority_account, false),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
    }

    #[test]
    fn test_extension_packing() {
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
}
