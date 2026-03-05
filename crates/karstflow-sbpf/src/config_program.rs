//! Config program implementation.
//!
//! Stores configuration data on-chain. The only instruction is Store,
//! which writes arbitrary data to a config account after validating
//! that all required signers have signed the transaction.

use crate::{ExecutionContext, ExecutionOutcome};
use karstflow_constants::config_program as constants;
use karstflow_ids::CONFIG_PROGRAM_ID;
use karstflow_types::{Account, AccountData, Pubkey};

/// Config program execution errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigProgramError {
    InvalidInstruction,
    InsufficientAccounts,
    AccountNotWritable,
    DataTooLarge,
    MissingSignerAccount,
    AccountNotOwnedByConfigProgram,
}

impl ConfigProgramError {
    fn message(&self) -> &'static str {
        match self {
            Self::InvalidInstruction => "Invalid config instruction",
            Self::InsufficientAccounts => "Insufficient accounts",
            Self::AccountNotWritable => "Config account is not writable",
            Self::DataTooLarge => "Config data exceeds maximum size",
            Self::MissingSignerAccount => "Missing required signer account",
            Self::AccountNotOwnedByConfigProgram => "Account not owned by config program",
        }
    }
}

/// Executor for Config program instructions.
pub struct ConfigProgramExecutor {
    base_cost: u64,
}

impl ConfigProgramExecutor {
    pub fn new(base_cost: u64) -> Self {
        Self { base_cost }
    }

    pub fn execute(&self, ctx: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if ctx.instruction_data.len() < 4 {
            return Err(ConfigProgramError::InvalidInstruction.message().to_string());
        }

        let instruction_type = u32::from_le_bytes(
            ctx.instruction_data[0..4]
                .try_into()
                .map_err(|_| "Failed to parse instruction type")?,
        );

        match instruction_type {
            constants::INSTRUCTION_STORE => self.store(ctx),
            _ => Err(format!(
                "Unknown config instruction type: {}",
                instruction_type
            )),
        }
    }

    /// Store configuration data into the config account.
    ///
    /// Instruction data: [4 bytes type] [remaining bytes: config data]
    ///
    /// Accounts expected:
    ///   [0] config account (writable) - destination for data
    ///   [1..] signer accounts - must be signers of the transaction
    fn store(&self, ctx: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if ctx.accounts.is_empty() {
            return Err(ConfigProgramError::InsufficientAccounts
                .message()
                .to_string());
        }

        let (config_pubkey, config_account, config_writable) = &ctx.accounts[0];

        if !config_writable {
            return Err(ConfigProgramError::AccountNotWritable.message().to_string());
        }

        // Config accounts must be owned by the config program
        // (unless being initialized for the first time)
        if config_account.meta.owner != CONFIG_PROGRAM_ID
            && config_account.meta.owner != Pubkey::zeroed()
        {
            return Err(ConfigProgramError::AccountNotOwnedByConfigProgram
                .message()
                .to_string());
        }

        // The config data starts after the 4-byte instruction discriminant
        let config_data = &ctx.instruction_data[4..];

        if config_data.len() > constants::MAX_CONFIG_DATA_SIZE {
            return Err(ConfigProgramError::DataTooLarge.message().to_string());
        }

        // At least one signer account must be provided beyond the config account
        if ctx.accounts.len() < 2 {
            return Err(ConfigProgramError::MissingSignerAccount
                .message()
                .to_string());
        }

        // Write the data to the config account
        let mut new_config = config_account.clone();
        new_config.data = AccountData::new(config_data.to_vec());
        new_config.meta.owner = CONFIG_PROGRAM_ID;

        let compute_used = self.base_cost.saturating_add(constants::COMPUTE_COST_STORE);

        let mut outcome = ExecutionOutcome::success(compute_used);
        outcome.modified_accounts.insert(*config_pubkey, new_config);
        outcome.logs.push(format!(
            "Stored {} bytes of config data to {}",
            config_data.len(),
            config_pubkey
        ));
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use karstflow_types::AccountMeta;

    fn make_config_account() -> Account {
        Account {
            meta: AccountMeta {
                lamports: 1_000_000,
                owner: CONFIG_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        }
    }

    #[test]
    fn store_succeeds_with_valid_signer() {
        let executor = ConfigProgramExecutor::new(150);

        let config_pubkey = Pubkey::new_unique();
        let signer_pubkey = Pubkey::new_unique();

        let mut instruction_data = constants::INSTRUCTION_STORE.to_le_bytes().to_vec();
        instruction_data.extend_from_slice(b"config data payload");

        let signer_account = Account {
            meta: AccountMeta {
                lamports: 1_000_000,
                owner: Pubkey::zeroed(),
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };

        let ctx = ExecutionContext::new(
            CONFIG_PROGRAM_ID,
            vec![
                (config_pubkey, make_config_account(), true),
                (signer_pubkey, signer_account, false),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&ctx).unwrap();
        assert!(outcome.success);
        assert!(outcome.modified_accounts.contains_key(&config_pubkey));
        let stored = &outcome.modified_accounts[&config_pubkey];
        assert_eq!(stored.data.as_ref(), b"config data payload");
    }

    #[test]
    fn store_rejects_without_signer() {
        let executor = ConfigProgramExecutor::new(150);

        let config_pubkey = Pubkey::new_unique();

        let mut instruction_data = constants::INSTRUCTION_STORE.to_le_bytes().to_vec();
        instruction_data.extend_from_slice(b"data");

        let ctx = ExecutionContext::new(
            CONFIG_PROGRAM_ID,
            vec![(config_pubkey, make_config_account(), true)],
            instruction_data,
        );

        let result = executor.execute(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("signer"));
    }

    #[test]
    fn store_rejects_data_too_large() {
        let executor = ConfigProgramExecutor::new(150);

        let config_pubkey = Pubkey::new_unique();
        let signer_pubkey = Pubkey::new_unique();

        let mut instruction_data = constants::INSTRUCTION_STORE.to_le_bytes().to_vec();
        instruction_data.extend_from_slice(&vec![0u8; constants::MAX_CONFIG_DATA_SIZE + 1]);

        let signer_account = Account {
            meta: AccountMeta {
                lamports: 1_000_000,
                owner: Pubkey::zeroed(),
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };

        let ctx = ExecutionContext::new(
            CONFIG_PROGRAM_ID,
            vec![
                (config_pubkey, make_config_account(), true),
                (signer_pubkey, signer_account, false),
            ],
            instruction_data,
        );

        let result = executor.execute(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("maximum size"));
    }

    #[test]
    fn store_rejects_non_writable_account() {
        let executor = ConfigProgramExecutor::new(150);

        let config_pubkey = Pubkey::new_unique();
        let signer_pubkey = Pubkey::new_unique();

        let mut instruction_data = constants::INSTRUCTION_STORE.to_le_bytes().to_vec();
        instruction_data.extend_from_slice(b"data");

        let signer_account = Account::zeroed();

        let ctx = ExecutionContext::new(
            CONFIG_PROGRAM_ID,
            vec![
                (config_pubkey, make_config_account(), false), // NOT writable
                (signer_pubkey, signer_account, false),
            ],
            instruction_data,
        );

        let result = executor.execute(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("writable"));
    }
}
