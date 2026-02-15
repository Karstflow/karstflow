use crate::{ExecutionContext, ExecutionOutcome};
use paradencer_constants::execution::DEFAULT_INSTRUCTION_BASE_COST;
use paradencer_types::{Account, AccountData, AccountMeta, Pubkey};
use std::collections::HashMap;

/// SPL Token Program errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenProgramError {
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
}

impl TokenProgramError {
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
        }
        .to_string()
    }
}

/// Mint account data (82 bytes)
#[derive(Debug, Clone, PartialEq)]
pub struct Mint {
    pub mint_authority: Option<Pubkey>,
    pub supply: u64,
    pub decimals: u8,
    pub is_initialized: bool,
    pub freeze_authority: Option<Pubkey>,
}

impl Mint {
    pub const LEN: usize = 82;

    pub fn pack(&self) -> Vec<u8> {
        let mut data = vec![0u8; Self::LEN];

        // mint_authority option
        if let Some(authority) = self.mint_authority {
            data[0] = 1;
            data[1..33].copy_from_slice(&authority.to_bytes());
        }

        // supply
        data[33..41].copy_from_slice(&self.supply.to_le_bytes());

        // decimals
        data[41] = self.decimals;

        // is_initialized
        data[42] = if self.is_initialized { 1 } else { 0 };

        // freeze_authority option
        if let Some(authority) = self.freeze_authority {
            data[43] = 1;
            data[44..76].copy_from_slice(&authority.to_bytes());
        }

        data
    }

    pub fn unpack(data: &[u8]) -> Result<Self, TokenProgramError> {
        if data.len() < Self::LEN {
            return Err(TokenProgramError::InvalidState);
        }

        let mint_authority = if data[0] == 1 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&data[1..33]);
            Some(Pubkey::new(bytes))
        } else {
            None
        };

        let supply = u64::from_le_bytes(data[33..41].try_into().unwrap());
        let decimals = data[41];
        let is_initialized = data[42] == 1;

        let freeze_authority = if data[43] == 1 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&data[44..76]);
            Some(Pubkey::new(bytes))
        } else {
            None
        };

        Ok(Self {
            mint_authority,
            supply,
            decimals,
            is_initialized,
            freeze_authority,
        })
    }
}

/// Token account data (165 bytes)
#[derive(Debug, Clone, PartialEq)]
pub struct TokenAccount {
    pub mint: Pubkey,
    pub owner: Pubkey,
    pub amount: u64,
    pub delegate: Option<Pubkey>,
    pub state: AccountState,
    pub is_native: Option<u64>,
    pub delegated_amount: u64,
    pub close_authority: Option<Pubkey>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountState {
    Uninitialized,
    Initialized,
    Frozen,
}

impl TokenAccount {
    pub const LEN: usize = 165;

    pub fn pack(&self) -> Vec<u8> {
        let mut data = vec![0u8; Self::LEN];

        // mint
        data[0..32].copy_from_slice(&self.mint.to_bytes());

        // owner
        data[32..64].copy_from_slice(&self.owner.to_bytes());

        // amount
        data[64..72].copy_from_slice(&self.amount.to_le_bytes());

        // delegate option
        if let Some(delegate) = self.delegate {
            data[72] = 1;
            data[73..105].copy_from_slice(&delegate.to_bytes());
        }

        // state
        data[105] = match self.state {
            AccountState::Uninitialized => 0,
            AccountState::Initialized => 1,
            AccountState::Frozen => 2,
        };

        // is_native option
        if let Some(native_amount) = self.is_native {
            data[106] = 1;
            data[107..115].copy_from_slice(&native_amount.to_le_bytes());
        }

        // delegated_amount
        data[115..123].copy_from_slice(&self.delegated_amount.to_le_bytes());

        // close_authority option
        if let Some(authority) = self.close_authority {
            data[123] = 1;
            data[124..156].copy_from_slice(&authority.to_bytes());
        }

        data
    }

    pub fn unpack(data: &[u8]) -> Result<Self, TokenProgramError> {
        if data.len() < Self::LEN {
            return Err(TokenProgramError::InvalidState);
        }

        let mut mint_bytes = [0u8; 32];
        mint_bytes.copy_from_slice(&data[0..32]);
        let mint = Pubkey::new(mint_bytes);

        let mut owner_bytes = [0u8; 32];
        owner_bytes.copy_from_slice(&data[32..64]);
        let owner = Pubkey::new(owner_bytes);

        let amount = u64::from_le_bytes(data[64..72].try_into().unwrap());

        let delegate = if data[72] == 1 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&data[73..105]);
            Some(Pubkey::new(bytes))
        } else {
            None
        };

        let state = match data[105] {
            0 => AccountState::Uninitialized,
            1 => AccountState::Initialized,
            2 => AccountState::Frozen,
            _ => return Err(TokenProgramError::InvalidState),
        };

        let is_native = if data[106] == 1 {
            Some(u64::from_le_bytes(data[107..115].try_into().unwrap()))
        } else {
            None
        };

        let delegated_amount = u64::from_le_bytes(data[115..123].try_into().unwrap());

        let close_authority = if data[123] == 1 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&data[124..156]);
            Some(Pubkey::new(bytes))
        } else {
            None
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
        })
    }
}

/// SPL Token Program instruction executor
pub struct TokenProgramExecutor {
    base_cost: u64,
}

impl TokenProgramExecutor {
    pub fn new(base_cost: u64) -> Self {
        Self { base_cost }
    }

    pub fn execute(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if context.instruction_data.is_empty() {
            return Ok(ExecutionOutcome::success(self.base_cost));
        }

        let instruction_type = context.instruction_data[0];

        match instruction_type {
            0 => self.initialize_mint(context),
            1 => self.initialize_account(context),
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
            _ => Err(format!("Unknown token instruction: {}", instruction_type)),
        }
    }

    // Instruction 0: InitializeMint
    fn initialize_mint(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if context.accounts.len() < 2 {
            return Err("InitializeMint requires at least 2 accounts".to_string());
        }
        if context.instruction_data.len() < 3 {
            return Err("InitializeMint requires decimals and mint_authority".to_string());
        }

        let (mint_pubkey, mut mint_account, mint_writable) = context.accounts[0].clone();

        if !mint_writable {
            return Err("Mint account must be writable".to_string());
        }

        // Check if already initialized
        if !mint_account.data.is_empty() {
            if let Ok(existing_mint) = Mint::unpack(mint_account.data.as_slice()) {
                if existing_mint.is_initialized {
                    return Err(TokenProgramError::AlreadyInUse.to_string());
                }
            }
        }

        let decimals = context.instruction_data[1];

        // Parse mint_authority (32 bytes)
        if context.instruction_data.len() < 34 {
            return Err("Missing mint_authority in instruction data".to_string());
        }
        let mut mint_authority_bytes = [0u8; 32];
        mint_authority_bytes.copy_from_slice(&context.instruction_data[2..34]);
        let mint_authority = Pubkey::new(mint_authority_bytes);

        // Parse optional freeze_authority
        let freeze_authority = if context.instruction_data.len() >= 67 && context.instruction_data[34] == 1 {
            let mut freeze_authority_bytes = [0u8; 32];
            freeze_authority_bytes.copy_from_slice(&context.instruction_data[35..67]);
            Some(Pubkey::new(freeze_authority_bytes))
        } else {
            None
        };

        let mint = Mint {
            mint_authority: Some(mint_authority),
            supply: 0,
            decimals,
            is_initialized: true,
            freeze_authority,
        };

        mint_account.data = AccountData::new(mint.pack());

        let mut outcome = ExecutionOutcome::success(self.base_cost + 50);
        outcome.modified_accounts.insert(mint_pubkey, mint_account);

        Ok(outcome)
    }

    // Instruction 1: InitializeAccount
    fn initialize_account(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if context.accounts.len() < 4 {
            return Err("InitializeAccount requires at least 4 accounts".to_string());
        }

        let (account_pubkey, mut token_account, account_writable) = context.accounts[0].clone();
        let (mint_pubkey, mint_account, _) = context.accounts[1].clone();
        let (owner_pubkey, _, _) = context.accounts[2].clone();

        if !account_writable {
            return Err("Token account must be writable".to_string());
        }

        // Verify mint
        if mint_account.data.is_empty() {
            return Err(TokenProgramError::InvalidMint.to_string());
        }

        let _mint = Mint::unpack(mint_account.data.as_slice())
            .map_err(|e| e.to_string())?;

        // Check if already initialized
        if !token_account.data.is_empty() {
            if let Ok(existing_account) = TokenAccount::unpack(token_account.data.as_slice()) {
                if existing_account.state != AccountState::Uninitialized {
                    return Err(TokenProgramError::AlreadyInUse.to_string());
                }
            }
        }

        let account = TokenAccount {
            mint: mint_pubkey,
            owner: owner_pubkey,
            amount: 0,
            delegate: None,
            state: AccountState::Initialized,
            is_native: None,
            delegated_amount: 0,
            close_authority: None,
        };

        token_account.data = AccountData::new(account.pack());

        let mut outcome = ExecutionOutcome::success(self.base_cost + 50);
        outcome.modified_accounts.insert(account_pubkey, token_account);

        Ok(outcome)
    }

    // Instruction 3: Transfer
    fn transfer(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if context.accounts.len() < 3 {
            return Err("Transfer requires at least 3 accounts".to_string());
        }
        if context.instruction_data.len() < 9 {
            return Err("Transfer requires amount".to_string());
        }

        let (source_pubkey, mut source_account, source_writable) = context.accounts[0].clone();
        let (dest_pubkey, mut dest_account, dest_writable) = context.accounts[1].clone();
        let (authority_pubkey, _, _) = context.accounts[2].clone();

        if !source_writable || !dest_writable {
            return Err("Source and destination must be writable".to_string());
        }

        let amount = u64::from_le_bytes(context.instruction_data[1..9].try_into().unwrap());

        let mut source_token = TokenAccount::unpack(source_account.data.as_slice())
            .map_err(|e| e.to_string())?;
        let mut dest_token = TokenAccount::unpack(dest_account.data.as_slice())
            .map_err(|e| e.to_string())?;

        // Verify same mint
        if source_token.mint != dest_token.mint {
            return Err(TokenProgramError::MintMismatch.to_string());
        }

        // Verify authority
        if source_token.owner != authority_pubkey && source_token.delegate != Some(authority_pubkey) {
            return Err(TokenProgramError::OwnerMismatch.to_string());
        }

        // Check frozen
        if source_token.state == AccountState::Frozen || dest_token.state == AccountState::Frozen {
            return Err(TokenProgramError::AccountFrozen.to_string());
        }

        // Check sufficient funds
        if source_token.amount < amount {
            return Err(TokenProgramError::InsufficientFunds.to_string());
        }

        // Perform transfer
        source_token.amount = source_token.amount.checked_sub(amount)
            .ok_or_else(|| TokenProgramError::Overflow.to_string())?;
        dest_token.amount = dest_token.amount.checked_add(amount)
            .ok_or_else(|| TokenProgramError::Overflow.to_string())?;

        // If using delegate, reduce delegated amount
        if source_token.delegate == Some(authority_pubkey) {
            source_token.delegated_amount = source_token.delegated_amount.saturating_sub(amount);
            if source_token.delegated_amount == 0 {
                source_token.delegate = None;
            }
        }

        source_account.data = AccountData::new(source_token.pack());
        dest_account.data = AccountData::new(dest_token.pack());

        let mut outcome = ExecutionOutcome::success(self.base_cost + 100);
        outcome.modified_accounts.insert(source_pubkey, source_account);
        outcome.modified_accounts.insert(dest_pubkey, dest_account);

        Ok(outcome)
    }

    // Instruction 4: Approve
    fn approve(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if context.accounts.len() < 3 {
            return Err("Approve requires at least 3 accounts".to_string());
        }
        if context.instruction_data.len() < 9 {
            return Err("Approve requires amount".to_string());
        }

        let (source_pubkey, mut source_account, source_writable) = context.accounts[0].clone();
        let (delegate_pubkey, _, _) = context.accounts[1].clone();
        let (owner_pubkey, _, _) = context.accounts[2].clone();

        if !source_writable {
            return Err("Source account must be writable".to_string());
        }

        let amount = u64::from_le_bytes(context.instruction_data[1..9].try_into().unwrap());

        let mut source_token = TokenAccount::unpack(source_account.data.as_slice())
            .map_err(|e| e.to_string())?;

        // Verify owner
        if source_token.owner != owner_pubkey {
            return Err(TokenProgramError::OwnerMismatch.to_string());
        }

        // Check frozen
        if source_token.state == AccountState::Frozen {
            return Err(TokenProgramError::AccountFrozen.to_string());
        }

        source_token.delegate = Some(delegate_pubkey);
        source_token.delegated_amount = amount;

        source_account.data = AccountData::new(source_token.pack());

        let mut outcome = ExecutionOutcome::success(self.base_cost + 50);
        outcome.modified_accounts.insert(source_pubkey, source_account);

        Ok(outcome)
    }

    // Instruction 5: Revoke
    fn revoke(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if context.accounts.len() < 2 {
            return Err("Revoke requires at least 2 accounts".to_string());
        }

        let (source_pubkey, mut source_account, source_writable) = context.accounts[0].clone();
        let (owner_pubkey, _, _) = context.accounts[1].clone();

        if !source_writable {
            return Err("Source account must be writable".to_string());
        }

        let mut source_token = TokenAccount::unpack(source_account.data.as_slice())
            .map_err(|e| e.to_string())?;

        // Verify owner
        if source_token.owner != owner_pubkey {
            return Err(TokenProgramError::OwnerMismatch.to_string());
        }

        source_token.delegate = None;
        source_token.delegated_amount = 0;

        source_account.data = AccountData::new(source_token.pack());

        let mut outcome = ExecutionOutcome::success(self.base_cost + 30);
        outcome.modified_accounts.insert(source_pubkey, source_account);

        Ok(outcome)
    }

    // Instruction 7: MintTo
    fn mint_to(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if context.accounts.len() < 3 {
            return Err("MintTo requires at least 3 accounts".to_string());
        }
        if context.instruction_data.len() < 9 {
            return Err("MintTo requires amount".to_string());
        }

        let (mint_pubkey, mut mint_account, mint_writable) = context.accounts[0].clone();
        let (dest_pubkey, mut dest_account, dest_writable) = context.accounts[1].clone();
        let (authority_pubkey, _, _) = context.accounts[2].clone();

        if !mint_writable || !dest_writable {
            return Err("Mint and destination must be writable".to_string());
        }

        let amount = u64::from_le_bytes(context.instruction_data[1..9].try_into().unwrap());

        let mut mint = Mint::unpack(mint_account.data.as_slice())
            .map_err(|e| e.to_string())?;
        let mut dest_token = TokenAccount::unpack(dest_account.data.as_slice())
            .map_err(|e| e.to_string())?;

        // Verify mint authority
        if mint.mint_authority != Some(authority_pubkey) {
            return Err(TokenProgramError::OwnerMismatch.to_string());
        }

        // Verify mint matches
        if dest_token.mint != mint_pubkey {
            return Err(TokenProgramError::MintMismatch.to_string());
        }

        // Check frozen
        if dest_token.state == AccountState::Frozen {
            return Err(TokenProgramError::AccountFrozen.to_string());
        }

        // Update supply and amount
        mint.supply = mint.supply.checked_add(amount)
            .ok_or_else(|| TokenProgramError::Overflow.to_string())?;
        dest_token.amount = dest_token.amount.checked_add(amount)
            .ok_or_else(|| TokenProgramError::Overflow.to_string())?;

        mint_account.data = AccountData::new(mint.pack());
        dest_account.data = AccountData::new(dest_token.pack());

        let mut outcome = ExecutionOutcome::success(self.base_cost + 100);
        outcome.modified_accounts.insert(mint_pubkey, mint_account);
        outcome.modified_accounts.insert(dest_pubkey, dest_account);

        Ok(outcome)
    }

    // Instruction 8: Burn
    fn burn(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if context.accounts.len() < 3 {
            return Err("Burn requires at least 3 accounts".to_string());
        }
        if context.instruction_data.len() < 9 {
            return Err("Burn requires amount".to_string());
        }

        let (account_pubkey, mut token_account, account_writable) = context.accounts[0].clone();
        let (mint_pubkey, mut mint_account, mint_writable) = context.accounts[1].clone();
        let (authority_pubkey, _, _) = context.accounts[2].clone();

        if !account_writable || !mint_writable {
            return Err("Account and mint must be writable".to_string());
        }

        let amount = u64::from_le_bytes(context.instruction_data[1..9].try_into().unwrap());

        let mut token = TokenAccount::unpack(token_account.data.as_slice())
            .map_err(|e| e.to_string())?;
        let mut mint = Mint::unpack(mint_account.data.as_slice())
            .map_err(|e| e.to_string())?;

        // Verify authority
        if token.owner != authority_pubkey && token.delegate != Some(authority_pubkey) {
            return Err(TokenProgramError::OwnerMismatch.to_string());
        }

        // Verify mint matches
        if token.mint != mint_pubkey {
            return Err(TokenProgramError::MintMismatch.to_string());
        }

        // Check sufficient funds
        if token.amount < amount {
            return Err(TokenProgramError::InsufficientFunds.to_string());
        }

        // Update amount and supply
        token.amount = token.amount.checked_sub(amount)
            .ok_or_else(|| TokenProgramError::Overflow.to_string())?;
        mint.supply = mint.supply.checked_sub(amount)
            .ok_or_else(|| TokenProgramError::Overflow.to_string())?;

        // If using delegate, reduce delegated amount
        if token.delegate == Some(authority_pubkey) {
            token.delegated_amount = token.delegated_amount.saturating_sub(amount);
            if token.delegated_amount == 0 {
                token.delegate = None;
            }
        }

        token_account.data = AccountData::new(token.pack());
        mint_account.data = AccountData::new(mint.pack());

        let mut outcome = ExecutionOutcome::success(self.base_cost + 100);
        outcome.modified_accounts.insert(account_pubkey, token_account);
        outcome.modified_accounts.insert(mint_pubkey, mint_account);

        Ok(outcome)
    }

    // Instruction 9: CloseAccount
    fn close_account(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if context.accounts.len() < 3 {
            return Err("CloseAccount requires at least 3 accounts".to_string());
        }

        let (account_pubkey, mut token_account, account_writable) = context.accounts[0].clone();
        let (dest_pubkey, mut dest_account, dest_writable) = context.accounts[1].clone();
        let (authority_pubkey, _, _) = context.accounts[2].clone();

        if !account_writable || !dest_writable {
            return Err("Account and destination must be writable".to_string());
        }

        let token = TokenAccount::unpack(token_account.data.as_slice())
            .map_err(|e| e.to_string())?;

        // Verify authority
        let close_authority = token.close_authority.unwrap_or(token.owner);
        if close_authority != authority_pubkey {
            return Err(TokenProgramError::OwnerMismatch.to_string());
        }

        // Check balance is zero
        if token.amount != 0 {
            return Err(TokenProgramError::NonNativeHasBalance.to_string());
        }

        // Transfer lamports to destination
        let lamports = token_account.meta.lamports;
        dest_account.meta.lamports = dest_account.meta.lamports.checked_add(lamports)
            .ok_or_else(|| TokenProgramError::Overflow.to_string())?;
        token_account.meta.lamports = 0;
        token_account.data = AccountData::empty();

        let mut outcome = ExecutionOutcome::success(self.base_cost + 50);
        outcome.modified_accounts.insert(account_pubkey, token_account);
        outcome.modified_accounts.insert(dest_pubkey, dest_account);

        Ok(outcome)
    }

    // Instruction 10: FreezeAccount
    fn freeze_account(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if context.accounts.len() < 3 {
            return Err("FreezeAccount requires at least 3 accounts".to_string());
        }

        let (account_pubkey, mut token_account, account_writable) = context.accounts[0].clone();
        let (mint_pubkey, mint_account, _) = context.accounts[1].clone();
        let (authority_pubkey, _, _) = context.accounts[2].clone();

        if !account_writable {
            return Err("Token account must be writable".to_string());
        }

        let mut token = TokenAccount::unpack(token_account.data.as_slice())
            .map_err(|e| e.to_string())?;
        let mint = Mint::unpack(mint_account.data.as_slice())
            .map_err(|e| e.to_string())?;

        // Verify freeze authority
        if mint.freeze_authority != Some(authority_pubkey) {
            return Err(TokenProgramError::MintCannotFreeze.to_string());
        }

        // Verify mint matches
        if token.mint != mint_pubkey {
            return Err(TokenProgramError::MintMismatch.to_string());
        }

        token.state = AccountState::Frozen;
        token_account.data = AccountData::new(token.pack());

        let mut outcome = ExecutionOutcome::success(self.base_cost + 50);
        outcome.modified_accounts.insert(account_pubkey, token_account);

        Ok(outcome)
    }

    // Instruction 11: ThawAccount
    fn thaw_account(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if context.accounts.len() < 3 {
            return Err("ThawAccount requires at least 3 accounts".to_string());
        }

        let (account_pubkey, mut token_account, account_writable) = context.accounts[0].clone();
        let (mint_pubkey, mint_account, _) = context.accounts[1].clone();
        let (authority_pubkey, _, _) = context.accounts[2].clone();

        if !account_writable {
            return Err("Token account must be writable".to_string());
        }

        let mut token = TokenAccount::unpack(token_account.data.as_slice())
            .map_err(|e| e.to_string())?;
        let mint = Mint::unpack(mint_account.data.as_slice())
            .map_err(|e| e.to_string())?;

        // Verify freeze authority
        if mint.freeze_authority != Some(authority_pubkey) {
            return Err(TokenProgramError::MintCannotFreeze.to_string());
        }

        // Verify mint matches
        if token.mint != mint_pubkey {
            return Err(TokenProgramError::MintMismatch.to_string());
        }

        token.state = AccountState::Initialized;
        token_account.data = AccountData::new(token.pack());

        let mut outcome = ExecutionOutcome::success(self.base_cost + 50);
        outcome.modified_accounts.insert(account_pubkey, token_account);

        Ok(outcome)
    }

    // Instruction 12: TransferChecked
    fn transfer_checked(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if context.instruction_data.len() < 10 {
            return Err("TransferChecked requires amount and decimals".to_string());
        }

        let amount = u64::from_le_bytes(context.instruction_data[1..9].try_into().unwrap());
        let decimals = context.instruction_data[9];

        // Verify decimals match mint
        if context.accounts.len() >= 2 {
            let (_, mint_account, _) = &context.accounts[2];
            if !mint_account.data.is_empty() {
                let mint = Mint::unpack(mint_account.data.as_slice())
                    .map_err(|e| e.to_string())?;
                if mint.decimals != decimals {
                    return Err(TokenProgramError::MintDecimalsMismatch.to_string());
                }
            }
        }

        // Call regular transfer
        self.transfer(context)
    }

    // Instruction 13: ApproveChecked
    fn approve_checked(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if context.instruction_data.len() < 10 {
            return Err("ApproveChecked requires amount and decimals".to_string());
        }

        let decimals = context.instruction_data[9];

        // Verify decimals match mint
        if context.accounts.len() >= 2 {
            let (_, mint_account, _) = &context.accounts[2];
            if !mint_account.data.is_empty() {
                let mint = Mint::unpack(mint_account.data.as_slice())
                    .map_err(|e| e.to_string())?;
                if mint.decimals != decimals {
                    return Err(TokenProgramError::MintDecimalsMismatch.to_string());
                }
            }
        }

        // Call regular approve
        self.approve(context)
    }

    // Instruction 14: MintToChecked
    fn mint_to_checked(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if context.instruction_data.len() < 10 {
            return Err("MintToChecked requires amount and decimals".to_string());
        }

        let decimals = context.instruction_data[9];

        // Verify decimals match mint
        if !context.accounts.is_empty() {
            let (_, mint_account, _) = &context.accounts[0];
            if !mint_account.data.is_empty() {
                let mint = Mint::unpack(mint_account.data.as_slice())
                    .map_err(|e| e.to_string())?;
                if mint.decimals != decimals {
                    return Err(TokenProgramError::MintDecimalsMismatch.to_string());
                }
            }
        }

        // Call regular mint_to
        self.mint_to(context)
    }

    // Instruction 15: BurnChecked
    fn burn_checked(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if context.instruction_data.len() < 10 {
            return Err("BurnChecked requires amount and decimals".to_string());
        }

        let decimals = context.instruction_data[9];

        // Verify decimals match mint
        if context.accounts.len() >= 2 {
            let (_, mint_account, _) = &context.accounts[1];
            if !mint_account.data.is_empty() {
                let mint = Mint::unpack(mint_account.data.as_slice())
                    .map_err(|e| e.to_string())?;
                if mint.decimals != decimals {
                    return Err(TokenProgramError::MintDecimalsMismatch.to_string());
                }
            }
        }

        // Call regular burn
        self.burn(context)
    }

    // Instruction 16: InitializeAccount2
    fn initialize_account2(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if context.instruction_data.len() < 33 {
            return Err("InitializeAccount2 requires owner pubkey".to_string());
        }

        // Extract owner from instruction data instead of accounts
        let mut owner_bytes = [0u8; 32];
        owner_bytes.copy_from_slice(&context.instruction_data[1..33]);
        let owner_pubkey = Pubkey::new(owner_bytes);

        if context.accounts.len() < 2 {
            return Err("InitializeAccount2 requires at least 2 accounts".to_string());
        }

        let (account_pubkey, mut token_account, account_writable) = context.accounts[0].clone();
        let (mint_pubkey, mint_account, _) = context.accounts[1].clone();

        if !account_writable {
            return Err("Token account must be writable".to_string());
        }

        // Verify mint
        if mint_account.data.is_empty() {
            return Err(TokenProgramError::InvalidMint.to_string());
        }

        let _mint = Mint::unpack(mint_account.data.as_slice())
            .map_err(|e| e.to_string())?;

        let account = TokenAccount {
            mint: mint_pubkey,
            owner: owner_pubkey,
            amount: 0,
            delegate: None,
            state: AccountState::Initialized,
            is_native: None,
            delegated_amount: 0,
            close_authority: None,
        };

        token_account.data = AccountData::new(account.pack());

        let mut outcome = ExecutionOutcome::success(self.base_cost + 50);
        outcome.modified_accounts.insert(account_pubkey, token_account);

        Ok(outcome)
    }

    // Instruction 17: SyncNative (no-op for non-native accounts)
    fn sync_native(&self, _context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        Ok(ExecutionOutcome::success(self.base_cost + 10))
    }

    // Instruction 18: InitializeAccount3
    fn initialize_account3(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        // Same as InitializeAccount2 but enforces immutable owner
        self.initialize_account2(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paradencer_ids::TOKEN_PROGRAM_ID;

    #[test]
    fn test_initialize_mint() {
        let executor = TokenProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST);

        let mint_pubkey = Pubkey::new_unique();
        let authority = Pubkey::new_unique();
        let rent_sysvar = Pubkey::new_unique();

        let mint_account = Account {
            meta: AccountMeta {
                lamports: 1000000,
                owner: TOKEN_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };

        let rent_account = Account::default();

        let mut instruction_data = vec![0u8]; // InitializeMint
        instruction_data.push(9); // decimals
        instruction_data.extend_from_slice(&authority.to_bytes());
        instruction_data.push(0); // no freeze authority

        let context = ExecutionContext::new(
            TOKEN_PROGRAM_ID,
            vec![
                (mint_pubkey, mint_account, true),
                (rent_sysvar, rent_account, false),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert_eq!(outcome.modified_accounts.len(), 1);

        let modified_mint = outcome.modified_accounts.get(&mint_pubkey).unwrap();
        let mint = Mint::unpack(modified_mint.data.as_slice()).unwrap();
        assert_eq!(mint.decimals, 9);
        assert_eq!(mint.supply, 0);
        assert!(mint.is_initialized);
    }

    #[test]
    fn test_transfer() {
        let executor = TokenProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST);

        let source_pubkey = Pubkey::new_unique();
        let dest_pubkey = Pubkey::new_unique();
        let owner_pubkey = Pubkey::new_unique();
        let mint_pubkey = Pubkey::new_unique();

        let source_token = TokenAccount {
            mint: mint_pubkey,
            owner: owner_pubkey,
            amount: 1000,
            delegate: None,
            state: AccountState::Initialized,
            is_native: None,
            delegated_amount: 0,
            close_authority: None,
        };

        let dest_token = TokenAccount {
            mint: mint_pubkey,
            owner: Pubkey::new_unique(),
            amount: 500,
            delegate: None,
            state: AccountState::Initialized,
            is_native: None,
            delegated_amount: 0,
            close_authority: None,
        };

        let source_account = Account {
            meta: AccountMeta {
                lamports: 1000000,
                owner: TOKEN_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(source_token.pack()),
        };

        let dest_account = Account {
            meta: AccountMeta {
                lamports: 1000000,
                owner: TOKEN_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(dest_token.pack()),
        };

        let mut instruction_data = vec![3u8]; // Transfer
        instruction_data.extend_from_slice(&100u64.to_le_bytes());

        let context = ExecutionContext::new(
            TOKEN_PROGRAM_ID,
            vec![
                (source_pubkey, source_account, true),
                (dest_pubkey, dest_account, true),
                (owner_pubkey, Account::default(), false),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert_eq!(outcome.modified_accounts.len(), 2);

        let modified_source = outcome.modified_accounts.get(&source_pubkey).unwrap();
        let source_after = TokenAccount::unpack(modified_source.data.as_slice()).unwrap();
        assert_eq!(source_after.amount, 900);

        let modified_dest = outcome.modified_accounts.get(&dest_pubkey).unwrap();
        let dest_after = TokenAccount::unpack(modified_dest.data.as_slice()).unwrap();
        assert_eq!(dest_after.amount, 600);
    }
}
