//! SPL Associated Token Account Program Implementation
//!
//! This module implements the Solana Program Library (SPL) Associated Token Account Program.
//! The program manages deterministic token account addresses derived from a user's wallet
//! and the token mint.
//!
//! Key features:
//! - Deterministic address derivation using PDAs (Program Derived Addresses)
//! - Create: Create a new associated token account
//! - CreateIdempotent: Create if not exists, succeed if already exists
//! - RecoverNested: Recover tokens from a nested associated token account

use crate::{ExecutionContext, ExecutionOutcome};
use paradencer_constants::execution::DEFAULT_INSTRUCTION_BASE_COST;
use paradencer_types::{Account, AccountData, AccountMeta, Pubkey};

/// Associated Token Account Program errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssociatedTokenError {
    InvalidInstruction,
    InvalidSeeds,
    InvalidAccountOwner,
    AccountAlreadyExists,
    InsufficientFunds,
    InvalidMint,
    InvalidOwner,
    NotRentExempt,
}

impl AssociatedTokenError {
    fn to_error_code(&self) -> u32 {
        match self {
            Self::InvalidInstruction => 0,
            Self::InvalidSeeds => 1,
            Self::InvalidAccountOwner => 2,
            Self::AccountAlreadyExists => 3,
            Self::InsufficientFunds => 4,
            Self::InvalidMint => 5,
            Self::InvalidOwner => 6,
            Self::NotRentExempt => 7,
        }
    }

    fn to_string(&self) -> String {
        match self {
            Self::InvalidInstruction => "Invalid instruction",
            Self::InvalidSeeds => "Invalid seeds for PDA derivation",
            Self::InvalidAccountOwner => "Invalid account owner",
            Self::AccountAlreadyExists => "Account already exists",
            Self::InsufficientFunds => "Insufficient funds",
            Self::InvalidMint => "Invalid mint",
            Self::InvalidOwner => "Invalid owner",
            Self::NotRentExempt => "Not rent exempt",
        }
        .to_string()
    }
}

/// Associated Token Account Program instruction types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AssociatedTokenInstruction {
    /// Create an associated token account
    ///
    /// Accounts expected:
    /// 0. `[writable, signer]` Funding account (must be a system account)
    /// 1. `[writable]` Associated token account address to be created
    /// 2. `[]` Wallet address for the new associated token account
    /// 3. `[]` The token mint for the new associated token account
    /// 4. `[]` System program
    /// 5. `[]` SPL Token program
    Create = 0,

    /// Create an associated token account idempotently
    ///
    /// If the account already exists, succeeds without error.
    /// Same account layout as Create instruction.
    CreateIdempotent = 1,

    /// Recover tokens from a nested associated token account
    ///
    /// A nested ATA is an ATA owned by another ATA. This can happen if someone
    /// accidentally sends tokens to an ATA instead of a wallet.
    ///
    /// Accounts expected:
    /// 0. `[writable]` Nested associated token account (must be owned by 1)
    /// 1. `[writable]` Wallet's associated token account
    /// 2. `[]` Owner of the wallet
    /// 3. `[]` Token mint
    /// 4. `[]` SPL Token program
    RecoverNested = 2,
}

impl AssociatedTokenInstruction {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Create),
            1 => Some(Self::CreateIdempotent),
            2 => Some(Self::RecoverNested),
            _ => None,
        }
    }
}

/// SPL Associated Token Account Program instruction executor
pub struct AssociatedTokenProgramExecutor {
    base_cost: u64,
}

impl AssociatedTokenProgramExecutor {
    pub fn new(base_cost: u64) -> Self {
        Self { base_cost }
    }

    pub fn execute(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if context.instruction_data.is_empty() {
            // No instruction discriminator, treat as Create (backwards compatibility)
            return self.create(context, false);
        }

        let instruction_type = AssociatedTokenInstruction::from_u8(context.instruction_data[0])
            .ok_or_else(|| AssociatedTokenError::InvalidInstruction.to_string())?;

        match instruction_type {
            AssociatedTokenInstruction::Create => self.create(context, false),
            AssociatedTokenInstruction::CreateIdempotent => self.create(context, true),
            AssociatedTokenInstruction::RecoverNested => self.recover_nested(context),
        }
    }

    /// Derive the associated token account address for a wallet and mint
    ///
    /// The address is derived as:
    /// PDA(wallet, token_program, mint) with seed = [wallet, token_program_id, mint]
    pub fn get_associated_token_address(
        wallet: &Pubkey,
        mint: &Pubkey,
        token_program_id: &Pubkey,
        associated_token_program_id: &Pubkey,
    ) -> Pubkey {
        // In a real implementation, this would use find_program_address
        // For this simplified version, we'll create a deterministic hash

        let mut seeds = Vec::new();
        seeds.extend_from_slice(&wallet.to_bytes());
        seeds.extend_from_slice(&token_program_id.to_bytes());
        seeds.extend_from_slice(&mint.to_bytes());

        // Simple deterministic derivation (in real Solana, uses ed25519 curve arithmetic)
        let mut hash = [0u8; 32];
        for (i, chunk) in seeds.chunks(32).enumerate() {
            for (j, &byte) in chunk.iter().enumerate() {
                hash[j % 32] ^= byte.wrapping_add(i as u8);
            }
        }

        // Mix in program ID
        for (i, &byte) in associated_token_program_id.to_bytes().iter().enumerate() {
            hash[i] ^= byte;
        }

        Pubkey::new(hash)
    }

    /// Instruction 0/1: Create or CreateIdempotent
    fn create(
        &self,
        context: &ExecutionContext,
        idempotent: bool,
    ) -> Result<ExecutionOutcome, String> {
        // Expected accounts:
        // 0. Funding account (payer)
        // 1. Associated token account (to be created)
        // 2. Wallet address (owner of the ATA)
        // 3. Token mint
        // 4. System program
        // 5. Token program

        if context.accounts.len() < 6 {
            return Err("Create requires at least 6 accounts".to_string());
        }

        let (payer_pubkey, mut payer_account, payer_writable) = context.accounts[0].clone();
        let (ata_pubkey, mut ata_account, ata_writable) = context.accounts[1].clone();
        let (wallet_pubkey, _wallet_account, _) = context.accounts[2].clone();
        let (mint_pubkey, mint_account, _) = context.accounts[3].clone();
        let (_system_program_id, _, _) = context.accounts[4].clone();
        let (token_program_id, _, _) = context.accounts[5].clone();

        if !payer_writable || !ata_writable {
            return Err("Payer and ATA must be writable".to_string());
        }

        // Check if account already exists
        if !ata_account.data.is_empty() {
            if idempotent {
                // CreateIdempotent: succeed if account already exists
                return Ok(ExecutionOutcome::success(self.base_cost + 10));
            } else {
                // Create: fail if account already exists
                return Err(AssociatedTokenError::AccountAlreadyExists.to_string());
            }
        }

        // Verify mint exists and is valid
        if mint_account.data.is_empty() {
            return Err(AssociatedTokenError::InvalidMint.to_string());
        }

        // Calculate rent exemption (simplified: fixed amount)
        let rent_exempt_lamports = 2_000_000u64; // ~2 SOL for rent exemption

        // Check payer has sufficient funds
        if payer_account.meta.lamports < rent_exempt_lamports {
            return Err(AssociatedTokenError::InsufficientFunds.to_string());
        }

        // Verify derived address matches
        let expected_ata = Self::get_associated_token_address(
            &wallet_pubkey,
            &mint_pubkey,
            &token_program_id,
            &context.program_id,
        );

        if expected_ata != ata_pubkey {
            return Err(AssociatedTokenError::InvalidSeeds.to_string());
        }

        // Transfer lamports from payer to ATA
        payer_account.meta.lamports = payer_account
            .meta
            .lamports
            .checked_sub(rent_exempt_lamports)
            .ok_or_else(|| AssociatedTokenError::InsufficientFunds.to_string())?;

        ata_account.meta.lamports = rent_exempt_lamports;
        ata_account.meta.owner = token_program_id;

        // Initialize token account data (165 bytes)
        // Format: [mint(32), owner(32), amount(8), ...]
        let mut ata_data = vec![0u8; 165];

        // Set mint
        ata_data[0..32].copy_from_slice(&mint_pubkey.to_bytes());

        // Set owner (wallet)
        ata_data[32..64].copy_from_slice(&wallet_pubkey.to_bytes());

        // amount = 0 (bytes 64..72 already zero)

        // delegate = None (byte 72 already zero)

        // state = Initialized (1)
        ata_data[105] = 1;

        // is_native = None (byte 106 already zero)

        // delegated_amount = 0 (bytes 115..123 already zero)

        // close_authority = None (byte 123 already zero)

        ata_account.data = AccountData::new(ata_data);

        let mut outcome = ExecutionOutcome::success(self.base_cost + 200);
        outcome
            .modified_accounts
            .insert(payer_pubkey, payer_account);
        outcome.modified_accounts.insert(ata_pubkey, ata_account);

        Ok(outcome)
    }

    /// Instruction 2: RecoverNested
    fn recover_nested(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        // Expected accounts:
        // 0. Nested ATA (source)
        // 1. Wallet's ATA (destination)
        // 2. Owner wallet
        // 3. Token mint
        // 4. Token program

        if context.accounts.len() < 5 {
            return Err("RecoverNested requires at least 5 accounts".to_string());
        }

        let (nested_ata_pubkey, mut nested_ata_account, nested_writable) =
            context.accounts[0].clone();
        let (wallet_ata_pubkey, mut wallet_ata_account, wallet_writable) =
            context.accounts[1].clone();
        let (owner_pubkey, _, _) = context.accounts[2].clone();
        let (mint_pubkey, _, _) = context.accounts[3].clone();
        let (_token_program_id, _, _) = context.accounts[4].clone();

        if !nested_writable || !wallet_writable {
            return Err("Nested ATA and wallet ATA must be writable".to_string());
        }

        // Verify nested ATA is owned by wallet ATA
        if nested_ata_account.data.len() < 64 {
            return Err("Invalid nested ATA data".to_string());
        }

        let mut nested_owner_bytes = [0u8; 32];
        nested_owner_bytes.copy_from_slice(&nested_ata_account.data.as_slice()[32..64]);
        let nested_owner = Pubkey::new(nested_owner_bytes);

        if nested_owner != wallet_ata_pubkey {
            return Err("Nested ATA not owned by wallet ATA".to_string());
        }

        // Verify wallet ATA is owned by the owner
        if wallet_ata_account.data.len() < 64 {
            return Err("Invalid wallet ATA data".to_string());
        }

        let mut wallet_owner_bytes = [0u8; 32];
        wallet_owner_bytes.copy_from_slice(&wallet_ata_account.data.as_slice()[32..64]);
        let wallet_owner = Pubkey::new(wallet_owner_bytes);

        if wallet_owner != owner_pubkey {
            return Err("Wallet ATA not owned by owner".to_string());
        }

        // Verify both ATAs have same mint
        let mut nested_mint_bytes = [0u8; 32];
        nested_mint_bytes.copy_from_slice(&nested_ata_account.data.as_slice()[0..32]);
        let nested_mint = Pubkey::new(nested_mint_bytes);

        let mut wallet_mint_bytes = [0u8; 32];
        wallet_mint_bytes.copy_from_slice(&wallet_ata_account.data.as_slice()[0..32]);
        let wallet_mint = Pubkey::new(wallet_mint_bytes);

        if nested_mint != wallet_mint || nested_mint != mint_pubkey {
            return Err("Mint mismatch".to_string());
        }

        // Get balance from nested ATA
        let nested_amount = u64::from_le_bytes(
            nested_ata_account.data.as_slice()[64..72]
                .try_into()
                .unwrap(),
        );

        // Get balance from wallet ATA
        let wallet_amount = u64::from_le_bytes(
            wallet_ata_account.data.as_slice()[64..72]
                .try_into()
                .unwrap(),
        );

        // Transfer all tokens from nested to wallet
        let new_wallet_amount = wallet_amount
            .checked_add(nested_amount)
            .ok_or_else(|| "Overflow".to_string())?;

        // Update wallet ATA balance
        let mut wallet_data = wallet_ata_account.data.as_slice().to_vec();
        wallet_data[64..72].copy_from_slice(&new_wallet_amount.to_le_bytes());
        wallet_ata_account.data = AccountData::new(wallet_data);

        // Zero out nested ATA balance
        let mut nested_data = nested_ata_account.data.as_slice().to_vec();
        nested_data[64..72].copy_from_slice(&0u64.to_le_bytes());
        nested_ata_account.data = AccountData::new(nested_data);

        // Close nested ATA by transferring lamports to wallet ATA
        let nested_lamports = nested_ata_account.meta.lamports;
        wallet_ata_account.meta.lamports = wallet_ata_account
            .meta
            .lamports
            .checked_add(nested_lamports)
            .ok_or_else(|| "Overflow".to_string())?;

        nested_ata_account.meta.lamports = 0;
        nested_ata_account.data = AccountData::empty();

        let mut outcome = ExecutionOutcome::success(self.base_cost + 150);
        outcome
            .modified_accounts
            .insert(nested_ata_pubkey, nested_ata_account);
        outcome
            .modified_accounts
            .insert(wallet_ata_pubkey, wallet_ata_account);

        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paradencer_ids::{ASSOCIATED_TOKEN_PROGRAM_ID, SYSTEM_PROGRAM_ID, TOKEN_PROGRAM_ID};

    fn create_test_mint_account() -> Account {
        // Simple mint account with minimal data
        let mut mint_data = vec![0u8; 82];
        mint_data[42] = 1; // is_initialized = true
        mint_data[41] = 9; // decimals = 9

        Account {
            meta: AccountMeta {
                lamports: 1_000_000,
                owner: TOKEN_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(mint_data),
        }
    }

    #[test]
    fn test_get_associated_token_address_deterministic() {
        let wallet = Pubkey::new_unique();
        let mint = Pubkey::new_unique();

        let ata1 = AssociatedTokenProgramExecutor::get_associated_token_address(
            &wallet,
            &mint,
            &TOKEN_PROGRAM_ID,
            &ASSOCIATED_TOKEN_PROGRAM_ID,
        );

        let ata2 = AssociatedTokenProgramExecutor::get_associated_token_address(
            &wallet,
            &mint,
            &TOKEN_PROGRAM_ID,
            &ASSOCIATED_TOKEN_PROGRAM_ID,
        );

        // Should be deterministic
        assert_eq!(ata1, ata2);

        // Different wallet should produce different address
        let wallet2 = Pubkey::new_unique();
        let ata3 = AssociatedTokenProgramExecutor::get_associated_token_address(
            &wallet2,
            &mint,
            &TOKEN_PROGRAM_ID,
            &ASSOCIATED_TOKEN_PROGRAM_ID,
        );

        assert_ne!(ata1, ata3);
    }

    #[test]
    fn test_create() {
        let executor = AssociatedTokenProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST);

        let payer = Pubkey::new_unique();
        let wallet = Pubkey::new_unique();
        let mint = Pubkey::new_unique();

        let ata = AssociatedTokenProgramExecutor::get_associated_token_address(
            &wallet,
            &mint,
            &TOKEN_PROGRAM_ID,
            &ASSOCIATED_TOKEN_PROGRAM_ID,
        );

        let payer_account = Account {
            meta: AccountMeta {
                lamports: 5_000_000,
                owner: SYSTEM_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };

        let ata_account = Account {
            meta: AccountMeta {
                lamports: 0,
                owner: SYSTEM_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };

        let wallet_account = Account::default();
        let mint_account = create_test_mint_account();
        let system_account = Account::default();
        let token_account = Account::default();

        let instruction_data = vec![0u8]; // Create

        let context = ExecutionContext::new(
            ASSOCIATED_TOKEN_PROGRAM_ID,
            vec![
                (payer, payer_account.clone(), true),
                (ata, ata_account, true),
                (wallet, wallet_account, false),
                (mint, mint_account, false),
                (SYSTEM_PROGRAM_ID, system_account, false),
                (TOKEN_PROGRAM_ID, token_account, false),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert_eq!(outcome.modified_accounts.len(), 2);

        // Verify payer was charged
        let modified_payer = outcome.modified_accounts.get(&payer).unwrap();
        assert!(modified_payer.meta.lamports < payer_account.meta.lamports);

        // Verify ATA was created with correct data
        let modified_ata = outcome.modified_accounts.get(&ata).unwrap();
        assert!(modified_ata.meta.lamports > 0);
        assert_eq!(modified_ata.meta.owner, TOKEN_PROGRAM_ID);
        assert_eq!(modified_ata.data.len(), 165);

        // Verify mint is set correctly
        let mut mint_bytes = [0u8; 32];
        mint_bytes.copy_from_slice(&modified_ata.data.as_slice()[0..32]);
        assert_eq!(Pubkey::new(mint_bytes), mint);

        // Verify owner is set correctly
        let mut owner_bytes = [0u8; 32];
        owner_bytes.copy_from_slice(&modified_ata.data.as_slice()[32..64]);
        assert_eq!(Pubkey::new(owner_bytes), wallet);

        // Verify state is Initialized
        assert_eq!(modified_ata.data.as_slice()[105], 1);
    }

    #[test]
    fn test_create_already_exists() {
        let executor = AssociatedTokenProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST);

        let payer = Pubkey::new_unique();
        let wallet = Pubkey::new_unique();
        let mint = Pubkey::new_unique();

        let ata = AssociatedTokenProgramExecutor::get_associated_token_address(
            &wallet,
            &mint,
            &TOKEN_PROGRAM_ID,
            &ASSOCIATED_TOKEN_PROGRAM_ID,
        );

        let payer_account = Account {
            meta: AccountMeta {
                lamports: 5_000_000,
                owner: SYSTEM_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };

        // ATA already exists with data
        let mut ata_data = vec![0u8; 165];
        ata_data[0..32].copy_from_slice(&mint.to_bytes());
        ata_data[32..64].copy_from_slice(&wallet.to_bytes());
        ata_data[105] = 1; // state = Initialized

        let ata_account = Account {
            meta: AccountMeta {
                lamports: 2_000_000,
                owner: TOKEN_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(ata_data),
        };

        let wallet_account = Account::default();
        let mint_account = create_test_mint_account();

        let instruction_data = vec![0u8]; // Create

        let context = ExecutionContext::new(
            ASSOCIATED_TOKEN_PROGRAM_ID,
            vec![
                (payer, payer_account, true),
                (ata, ata_account, true),
                (wallet, wallet_account, false),
                (mint, mint_account, false),
                (SYSTEM_PROGRAM_ID, Account::default(), false),
                (TOKEN_PROGRAM_ID, Account::default(), false),
            ],
            instruction_data,
        );

        let result = executor.execute(&context);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already exists"));
    }

    #[test]
    fn test_create_idempotent() {
        let executor = AssociatedTokenProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST);

        let payer = Pubkey::new_unique();
        let wallet = Pubkey::new_unique();
        let mint = Pubkey::new_unique();

        let ata = AssociatedTokenProgramExecutor::get_associated_token_address(
            &wallet,
            &mint,
            &TOKEN_PROGRAM_ID,
            &ASSOCIATED_TOKEN_PROGRAM_ID,
        );

        let payer_account = Account {
            meta: AccountMeta {
                lamports: 5_000_000,
                owner: SYSTEM_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };

        // ATA already exists
        let mut ata_data = vec![0u8; 165];
        ata_data[0..32].copy_from_slice(&mint.to_bytes());
        ata_data[32..64].copy_from_slice(&wallet.to_bytes());
        ata_data[105] = 1;

        let ata_account = Account {
            meta: AccountMeta {
                lamports: 2_000_000,
                owner: TOKEN_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(ata_data),
        };

        let instruction_data = vec![1u8]; // CreateIdempotent

        let context = ExecutionContext::new(
            ASSOCIATED_TOKEN_PROGRAM_ID,
            vec![
                (payer, payer_account, true),
                (ata, ata_account, true),
                (wallet, Account::default(), false),
                (mint, create_test_mint_account(), false),
                (SYSTEM_PROGRAM_ID, Account::default(), false),
                (TOKEN_PROGRAM_ID, Account::default(), false),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        // Should succeed even though account exists
    }

    #[test]
    fn test_recover_nested() {
        let executor = AssociatedTokenProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST);

        let owner = Pubkey::new_unique();
        let mint = Pubkey::new_unique();

        let wallet_ata = Pubkey::new_unique();
        let nested_ata = Pubkey::new_unique();

        // Nested ATA data (owned by wallet_ata, has 1000 tokens)
        let mut nested_data = vec![0u8; 165];
        nested_data[0..32].copy_from_slice(&mint.to_bytes());
        nested_data[32..64].copy_from_slice(&wallet_ata.to_bytes()); // owner = wallet_ata
        nested_data[64..72].copy_from_slice(&1000u64.to_le_bytes()); // amount = 1000
        nested_data[105] = 1; // state = Initialized

        let nested_account = Account {
            meta: AccountMeta {
                lamports: 2_000_000,
                owner: TOKEN_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(nested_data),
        };

        // Wallet ATA data (owned by owner, has 500 tokens)
        let mut wallet_data = vec![0u8; 165];
        wallet_data[0..32].copy_from_slice(&mint.to_bytes());
        wallet_data[32..64].copy_from_slice(&owner.to_bytes()); // owner = owner
        wallet_data[64..72].copy_from_slice(&500u64.to_le_bytes()); // amount = 500
        wallet_data[105] = 1;

        let wallet_account = Account {
            meta: AccountMeta {
                lamports: 2_000_000,
                owner: TOKEN_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(wallet_data),
        };

        let instruction_data = vec![2u8]; // RecoverNested

        let context = ExecutionContext::new(
            ASSOCIATED_TOKEN_PROGRAM_ID,
            vec![
                (nested_ata, nested_account, true),
                (wallet_ata, wallet_account, true),
                (owner, Account::default(), false),
                (mint, create_test_mint_account(), false),
                (TOKEN_PROGRAM_ID, Account::default(), false),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert_eq!(outcome.modified_accounts.len(), 2);

        // Verify nested ATA was closed
        let modified_nested = outcome.modified_accounts.get(&nested_ata).unwrap();
        assert_eq!(modified_nested.meta.lamports, 0);
        assert!(modified_nested.data.is_empty());

        // Verify wallet ATA received tokens and lamports
        let modified_wallet = outcome.modified_accounts.get(&wallet_ata).unwrap();
        assert_eq!(modified_wallet.meta.lamports, 4_000_000); // 2M + 2M

        let wallet_amount =
            u64::from_le_bytes(modified_wallet.data.as_slice()[64..72].try_into().unwrap());
        assert_eq!(wallet_amount, 1500); // 500 + 1000
    }

    #[test]
    fn test_recover_nested_wrong_owner() {
        let executor = AssociatedTokenProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST);

        let owner = Pubkey::new_unique();
        let wrong_owner = Pubkey::new_unique();
        let mint = Pubkey::new_unique();

        let wallet_ata = Pubkey::new_unique();
        let nested_ata = Pubkey::new_unique();

        // Nested ATA owned by wrong_owner (not wallet_ata)
        let mut nested_data = vec![0u8; 165];
        nested_data[0..32].copy_from_slice(&mint.to_bytes());
        nested_data[32..64].copy_from_slice(&wrong_owner.to_bytes());
        nested_data[64..72].copy_from_slice(&1000u64.to_le_bytes());
        nested_data[105] = 1;

        let nested_account = Account {
            meta: AccountMeta {
                lamports: 2_000_000,
                owner: TOKEN_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(nested_data),
        };

        let mut wallet_data = vec![0u8; 165];
        wallet_data[0..32].copy_from_slice(&mint.to_bytes());
        wallet_data[32..64].copy_from_slice(&owner.to_bytes());
        wallet_data[64..72].copy_from_slice(&500u64.to_le_bytes());
        wallet_data[105] = 1;

        let wallet_account = Account {
            meta: AccountMeta {
                lamports: 2_000_000,
                owner: TOKEN_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(wallet_data),
        };

        let instruction_data = vec![2u8]; // RecoverNested

        let context = ExecutionContext::new(
            ASSOCIATED_TOKEN_PROGRAM_ID,
            vec![
                (nested_ata, nested_account, true),
                (wallet_ata, wallet_account, true),
                (owner, Account::default(), false),
                (mint, create_test_mint_account(), false),
                (TOKEN_PROGRAM_ID, Account::default(), false),
            ],
            instruction_data,
        );

        let result = executor.execute(&context);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not owned"));
    }
}
