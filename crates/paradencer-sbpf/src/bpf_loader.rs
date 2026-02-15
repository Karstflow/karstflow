use super::{ExecutionContext, ExecutionOutcome};
use paradencer_ids::BPF_LOADER_PROGRAM_ID;
use paradencer_types::{Account, AccountData, Pubkey};
use std::collections::HashMap;

/// BPF Loader instruction discriminants
pub const BPF_LOADER_WRITE: u32 = 0;
pub const BPF_LOADER_FINALIZE: u32 = 1;
pub const BPF_LOADER_DEPLOY: u32 = 2;
pub const BPF_LOADER_UPGRADE: u32 = 3;
pub const BPF_LOADER_SET_AUTHORITY: u32 = 4;
pub const BPF_LOADER_CLOSE: u32 = 5;

/// BPF Loader execution errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfLoaderError {
    InvalidInstruction,
    InvalidAccountData,
    AccountNotWritable,
    AccountAlreadyInitialized,
    AccountNotInitialized,
    InvalidAuthority,
    ProgramNotFinalized,
    ProgramAlreadyDeployed,
    BufferTooSmall,
    InvalidProgramData,
    InsufficientFunds,
}

impl BpfLoaderError {
    fn to_string(&self) -> String {
        match self {
            Self::InvalidInstruction => "Invalid instruction".to_string(),
            Self::InvalidAccountData => "Invalid account data".to_string(),
            Self::AccountNotWritable => "Account not writable".to_string(),
            Self::AccountAlreadyInitialized => "Account already initialized".to_string(),
            Self::AccountNotInitialized => "Account not initialized".to_string(),
            Self::InvalidAuthority => "Invalid authority".to_string(),
            Self::ProgramNotFinalized => "Program not finalized".to_string(),
            Self::ProgramAlreadyDeployed => "Program already deployed".to_string(),
            Self::BufferTooSmall => "Buffer too small".to_string(),
            Self::InvalidProgramData => "Invalid program data".to_string(),
            Self::InsufficientFunds => "Insufficient funds".to_string(),
        }
    }
}

/// Program account state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgramAccountState {
    /// Uninitialized account
    Uninitialized,
    /// Buffer account - holds program data during upload
    Buffer {
        authority: Pubkey,
        data: Vec<u8>,
    },
    /// Program account - finalized and ready for deployment
    Program {
        authority: Pubkey,
        data: Vec<u8>,
        is_deployed: bool,
    },
    /// Program data account - deployed and executable
    ProgramData {
        slot: u64,
        upgrade_authority: Option<Pubkey>,
        data: Vec<u8>,
    },
}

impl ProgramAccountState {
    /// Serialize state to bytes
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            Self::Uninitialized => vec![0],
            Self::Buffer { authority, data } => {
                let mut bytes = vec![1];
                bytes.extend_from_slice(authority.as_bytes());
                bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
                bytes.extend_from_slice(data);
                bytes
            }
            Self::Program {
                authority,
                data,
                is_deployed,
            } => {
                let mut bytes = vec![2];
                bytes.extend_from_slice(authority.as_bytes());
                bytes.push(*is_deployed as u8);
                bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
                bytes.extend_from_slice(data);
                bytes
            }
            Self::ProgramData {
                slot,
                upgrade_authority,
                data,
            } => {
                let mut bytes = vec![3];
                bytes.extend_from_slice(&slot.to_le_bytes());
                match upgrade_authority {
                    Some(auth) => {
                        bytes.push(1);
                        bytes.extend_from_slice(auth.as_bytes());
                    }
                    None => {
                        bytes.push(0);
                        bytes.extend_from_slice(&[0u8; 32]);
                    }
                }
                bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
                bytes.extend_from_slice(data);
                bytes
            }
        }
    }

    /// Deserialize state from bytes
    pub fn deserialize(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() {
            return Ok(Self::Uninitialized);
        }

        match bytes[0] {
            0 => Ok(Self::Uninitialized),
            1 => {
                if bytes.len() < 37 {
                    return Err("Invalid buffer state".to_string());
                }
                let authority = Pubkey::new_from_array(
                    bytes[1..33]
                        .try_into()
                        .map_err(|_| "Failed to parse authority")?,
                );
                let data_len = u32::from_le_bytes(
                    bytes[33..37]
                        .try_into()
                        .map_err(|_| "Failed to parse data length")?,
                ) as usize;
                if bytes.len() < 37 + data_len {
                    return Err("Invalid buffer data length".to_string());
                }
                let data = bytes[37..37 + data_len].to_vec();
                Ok(Self::Buffer { authority, data })
            }
            2 => {
                if bytes.len() < 38 {
                    return Err("Invalid program state".to_string());
                }
                let authority = Pubkey::new_from_array(
                    bytes[1..33]
                        .try_into()
                        .map_err(|_| "Failed to parse authority")?,
                );
                let is_deployed = bytes[33] != 0;
                let data_len = u32::from_le_bytes(
                    bytes[34..38]
                        .try_into()
                        .map_err(|_| "Failed to parse data length")?,
                ) as usize;
                if bytes.len() < 38 + data_len {
                    return Err("Invalid program data length".to_string());
                }
                let data = bytes[38..38 + data_len].to_vec();
                Ok(Self::Program {
                    authority,
                    data,
                    is_deployed,
                })
            }
            3 => {
                if bytes.len() < 46 {
                    return Err("Invalid program data state".to_string());
                }
                let slot = u64::from_le_bytes(
                    bytes[1..9]
                        .try_into()
                        .map_err(|_| "Failed to parse slot")?,
                );
                let has_authority = bytes[9] != 0;
                let upgrade_authority = if has_authority {
                    Some(Pubkey::new_from_array(
                        bytes[10..42]
                            .try_into()
                            .map_err(|_| "Failed to parse upgrade authority")?,
                    ))
                } else {
                    None
                };
                let data_len = u32::from_le_bytes(
                    bytes[42..46]
                        .try_into()
                        .map_err(|_| "Failed to parse data length")?,
                ) as usize;
                if bytes.len() < 46 + data_len {
                    return Err("Invalid program data length".to_string());
                }
                let data = bytes[46..46 + data_len].to_vec();
                Ok(Self::ProgramData {
                    slot,
                    upgrade_authority,
                    data,
                })
            }
            _ => Err("Unknown account state".to_string()),
        }
    }
}

/// BPF Loader program executor
#[derive(Debug, Clone)]
pub struct BpfLoaderExecutor {
    base_cost: u64,
}

impl BpfLoaderExecutor {
    pub fn new(base_cost: u64) -> Self {
        Self { base_cost }
    }

    pub fn execute(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if context.instruction_data.is_empty() {
            return Ok(ExecutionOutcome::success(self.base_cost));
        }

        if context.instruction_data.len() < 4 {
            return Err("Instruction data too short".to_string());
        }

        let instruction_type = u32::from_le_bytes(
            context.instruction_data[0..4]
                .try_into()
                .map_err(|_| "Failed to parse instruction type")?,
        );

        let mut compute_used = 1000u64; // Base cost for BPF operations
        let mut modified_accounts = HashMap::new();
        let mut logs = Vec::new();

        let result = match instruction_type {
            BPF_LOADER_WRITE => {
                compute_used = compute_used.saturating_add(5000);
                self.execute_write(context, &mut modified_accounts, &mut logs)
            }
            BPF_LOADER_FINALIZE => {
                compute_used = compute_used.saturating_add(10000);
                self.execute_finalize(context, &mut modified_accounts, &mut logs)
            }
            BPF_LOADER_DEPLOY => {
                compute_used = compute_used.saturating_add(20000);
                self.execute_deploy(context, &mut modified_accounts, &mut logs)
            }
            BPF_LOADER_UPGRADE => {
                compute_used = compute_used.saturating_add(15000);
                self.execute_upgrade(context, &mut modified_accounts, &mut logs)
            }
            BPF_LOADER_SET_AUTHORITY => {
                compute_used = compute_used.saturating_add(2000);
                self.execute_set_authority(context, &mut modified_accounts, &mut logs)
            }
            BPF_LOADER_CLOSE => {
                compute_used = compute_used.saturating_add(3000);
                self.execute_close(context, &mut modified_accounts, &mut logs)
            }
            _ => {
                logs.push(format!(
                    "BPFLoader: Unknown instruction type {}",
                    instruction_type
                ));
                Err("Unknown instruction type".to_string())
            }
        };

        result?;

        Ok(ExecutionOutcome {
            success: true,
            compute_units_consumed: compute_used,
            modified_accounts,
            logs,
            return_data: None,
        })
    }

    fn execute_write(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("BPFLoader: Write".to_string());

        if context.accounts.is_empty() {
            return Err("Write requires at least 1 account".to_string());
        }

        if context.instruction_data.len() < 16 {
            return Err("Write instruction data too short".to_string());
        }

        // Parse offset and data
        let offset = u32::from_le_bytes(
            context.instruction_data[4..8]
                .try_into()
                .map_err(|_| "Failed to parse offset")?,
        ) as usize;

        let data_len = u32::from_le_bytes(
            context.instruction_data[8..12]
                .try_into()
                .map_err(|_| "Failed to parse data length")?,
        ) as usize;

        if context.instruction_data.len() < 12 + data_len {
            return Err("Write instruction data too short for payload".to_string());
        }

        let data = &context.instruction_data[12..12 + data_len];

        let (buffer_pubkey, mut buffer_account, writable) = context.accounts[0].clone();

        if !writable {
            return Err(BpfLoaderError::AccountNotWritable.to_string());
        }

        if buffer_account.meta.owner != BPF_LOADER_PROGRAM_ID {
            return Err("Buffer account must be owned by BPF Loader".to_string());
        }

        // Deserialize current state
        let mut state = ProgramAccountState::deserialize(buffer_account.data.as_ref())?;

        // Ensure it's a buffer or initialize as buffer
        let mut buffer_data = match state {
            ProgramAccountState::Uninitialized => {
                // Initialize as buffer with authority from instruction or first account
                let authority = if context.accounts.len() > 1 {
                    context.accounts[1].0
                } else {
                    buffer_pubkey
                };
                Vec::new()
            }
            ProgramAccountState::Buffer { ref data, .. } => data.clone(),
            _ => return Err("Account is not a buffer".to_string()),
        };

        // Ensure buffer is large enough
        let required_len = offset + data_len;
        if buffer_data.len() < required_len {
            buffer_data.resize(required_len, 0);
        }

        // Write data at offset
        buffer_data[offset..offset + data_len].copy_from_slice(data);

        // Get authority
        let authority = if context.accounts.len() > 1 {
            context.accounts[1].0
        } else {
            buffer_pubkey
        };

        // Update state
        state = ProgramAccountState::Buffer {
            authority,
            data: buffer_data,
        };

        // Serialize and update account
        let serialized = state.serialize();
        buffer_account.data = AccountData::from(serialized);

        modified_accounts.insert(buffer_pubkey, buffer_account);
        logs.push(format!(
            "Wrote {} bytes at offset {} to buffer {}",
            data_len, offset, buffer_pubkey
        ));

        Ok(())
    }

    fn execute_finalize(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("BPFLoader: Finalize".to_string());

        if context.accounts.is_empty() {
            return Err("Finalize requires at least 1 account".to_string());
        }

        let (buffer_pubkey, mut buffer_account, writable) = context.accounts[0].clone();

        if !writable {
            return Err(BpfLoaderError::AccountNotWritable.to_string());
        }

        // Deserialize current state
        let state = ProgramAccountState::deserialize(buffer_account.data.as_ref())?;

        // Must be a buffer
        let (authority, data) = match state {
            ProgramAccountState::Buffer { authority, data } => (authority, data),
            _ => return Err("Account is not a buffer".to_string()),
        };

        // Validate program data (basic check for ELF header)
        if data.len() < 4 {
            return Err(BpfLoaderError::InvalidProgramData.to_string());
        }

        // Check for ELF magic number (0x7F 'E' 'L' 'F')
        if data.len() >= 4 && &data[0..4] != &[0x7F, 0x45, 0x4C, 0x46] {
            logs.push("Warning: Program data does not start with ELF header".to_string());
        }

        // Convert to Program state
        let new_state = ProgramAccountState::Program {
            authority,
            data,
            is_deployed: false,
        };

        // Serialize and update account
        let serialized = new_state.serialize();
        buffer_account.data = AccountData::from(serialized);

        modified_accounts.insert(buffer_pubkey, buffer_account);
        logs.push(format!("Finalized program {}", buffer_pubkey));

        Ok(())
    }

    fn execute_deploy(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("BPFLoader: Deploy".to_string());

        if context.accounts.is_empty() {
            return Err("Deploy requires at least 1 account".to_string());
        }

        let (program_pubkey, mut program_account, writable) = context.accounts[0].clone();

        if !writable {
            return Err(BpfLoaderError::AccountNotWritable.to_string());
        }

        // Deserialize current state
        let state = ProgramAccountState::deserialize(program_account.data.as_ref())?;

        // Must be a finalized program
        let (authority, data, is_deployed) = match state {
            ProgramAccountState::Program {
                authority,
                data,
                is_deployed,
            } => (authority, data, is_deployed),
            _ => return Err(BpfLoaderError::ProgramNotFinalized.to_string()),
        };

        if is_deployed {
            return Err(BpfLoaderError::ProgramAlreadyDeployed.to_string());
        }

        // Convert to ProgramData state (deployed)
        let new_state = ProgramAccountState::ProgramData {
            slot: 0, // In real implementation, would use current slot
            upgrade_authority: Some(authority),
            data,
        };

        // Mark account as executable
        program_account.meta.executable = true;

        // Serialize and update account
        let serialized = new_state.serialize();
        program_account.data = AccountData::from(serialized);

        modified_accounts.insert(program_pubkey, program_account);
        logs.push(format!("Deployed program {}", program_pubkey));

        Ok(())
    }

    fn execute_upgrade(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("BPFLoader: Upgrade".to_string());

        if context.accounts.len() < 2 {
            return Err("Upgrade requires at least 2 accounts".to_string());
        }

        let (program_pubkey, mut program_account, program_writable) = context.accounts[0].clone();
        let (buffer_pubkey, buffer_account, _) = context.accounts[1].clone();

        if !program_writable {
            return Err(BpfLoaderError::AccountNotWritable.to_string());
        }

        // Deserialize program state
        let program_state = ProgramAccountState::deserialize(program_account.data.as_ref())?;

        // Must be a deployed program
        let (slot, upgrade_authority) = match program_state {
            ProgramAccountState::ProgramData {
                slot,
                upgrade_authority,
                ..
            } => (slot, upgrade_authority),
            _ => return Err("Account is not a deployed program".to_string()),
        };

        // Verify upgrade authority
        if upgrade_authority.is_none() {
            return Err("Program is not upgradeable".to_string());
        }

        // Deserialize buffer state
        let buffer_state = ProgramAccountState::deserialize(buffer_account.data.as_ref())?;

        // Get new program data from buffer
        let new_data = match buffer_state {
            ProgramAccountState::Buffer { data, .. } => data,
            _ => return Err("Source is not a buffer".to_string()),
        };

        // Validate new program data
        if new_data.len() < 4 {
            return Err(BpfLoaderError::InvalidProgramData.to_string());
        }

        // Update program with new data
        let new_state = ProgramAccountState::ProgramData {
            slot: slot + 1, // Increment slot
            upgrade_authority,
            data: new_data,
        };

        // Serialize and update account
        let serialized = new_state.serialize();
        program_account.data = AccountData::from(serialized);

        modified_accounts.insert(program_pubkey, program_account);
        logs.push(format!(
            "Upgraded program {} with data from buffer {}",
            program_pubkey, buffer_pubkey
        ));

        Ok(())
    }

    fn execute_set_authority(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("BPFLoader: SetAuthority".to_string());

        if context.accounts.is_empty() {
            return Err("SetAuthority requires at least 1 account".to_string());
        }

        if context.instruction_data.len() < 37 {
            return Err("SetAuthority instruction data too short".to_string());
        }

        // Parse new authority (or None if setting to immutable)
        let has_new_authority = context.instruction_data[4] != 0;
        let new_authority = if has_new_authority {
            Some(Pubkey::new_from_array(
                context.instruction_data[5..37]
                    .try_into()
                    .map_err(|_| "Failed to parse new authority")?,
            ))
        } else {
            None
        };

        let (account_pubkey, mut account, writable) = context.accounts[0].clone();

        if !writable {
            return Err(BpfLoaderError::AccountNotWritable.to_string());
        }

        // Deserialize current state
        let mut state = ProgramAccountState::deserialize(account.data.as_ref())?;

        // Update authority based on state type
        state = match state {
            ProgramAccountState::Buffer { data, .. } => {
                let authority = new_authority.ok_or("Buffer requires an authority")?;
                ProgramAccountState::Buffer { authority, data }
            }
            ProgramAccountState::Program {
                data, is_deployed, ..
            } => {
                let authority = new_authority.ok_or("Program requires an authority")?;
                ProgramAccountState::Program {
                    authority,
                    data,
                    is_deployed,
                }
            }
            ProgramAccountState::ProgramData { slot, data, .. } => {
                // Can set to None to make immutable
                ProgramAccountState::ProgramData {
                    slot,
                    upgrade_authority: new_authority,
                    data,
                }
            }
            ProgramAccountState::Uninitialized => {
                return Err(BpfLoaderError::AccountNotInitialized.to_string())
            }
        };

        // Serialize and update account
        let serialized = state.serialize();
        account.data = AccountData::from(serialized);

        modified_accounts.insert(account_pubkey, account);

        if let Some(auth) = new_authority {
            logs.push(format!("Set authority to {} for account {}", auth, account_pubkey));
        } else {
            logs.push(format!("Removed authority (immutable) for account {}", account_pubkey));
        }

        Ok(())
    }

    fn execute_close(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("BPFLoader: Close".to_string());

        if context.accounts.len() < 2 {
            return Err("Close requires at least 2 accounts".to_string());
        }

        let (close_pubkey, mut close_account, close_writable) = context.accounts[0].clone();
        let (recipient_pubkey, mut recipient_account, _) = context.accounts[1].clone();

        if !close_writable {
            return Err(BpfLoaderError::AccountNotWritable.to_string());
        }

        // Deserialize state to verify it can be closed
        let state = ProgramAccountState::deserialize(close_account.data.as_ref())?;

        // Only buffers and non-deployed programs can be closed
        match state {
            ProgramAccountState::Buffer { .. } | ProgramAccountState::Program { is_deployed: false, .. } => {
                // OK to close
            }
            ProgramAccountState::ProgramData { .. } => {
                return Err("Cannot close deployed program".to_string());
            }
            ProgramAccountState::Uninitialized => {
                // Already closed, but allow it
            }
            _ => {
                return Err("Cannot close this account type".to_string());
            }
        }

        // Transfer all lamports to recipient
        let lamports = close_account.meta.lamports;
        recipient_account.meta.lamports = recipient_account.meta.lamports.saturating_add(lamports);
        close_account.meta.lamports = 0;

        // Clear account data
        close_account.data = AccountData::empty();
        close_account.meta.executable = false;

        modified_accounts.insert(close_pubkey, close_account);
        modified_accounts.insert(recipient_pubkey, recipient_account);

        logs.push(format!(
            "Closed account {} and transferred {} lamports to {}",
            close_pubkey, lamports, recipient_pubkey
        ));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paradencer_types::AccountMeta;

    fn create_buffer_account() -> Account {
        Account {
            meta: AccountMeta {
                lamports: 10_000,
                owner: BPF_LOADER_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        }
    }

    #[test]
    fn test_write_to_buffer() {
        let executor = BpfLoaderExecutor::new(150);

        let buffer_account = create_buffer_account();
        let authority_pubkey = Pubkey::new_unique();

        // Write instruction: offset=0, data="test"
        let mut instruction_data = vec![0, 0, 0, 0]; // Write instruction
        instruction_data.extend_from_slice(&0u32.to_le_bytes()); // offset
        instruction_data.extend_from_slice(&4u32.to_le_bytes()); // length
        instruction_data.extend_from_slice(b"test"); // data

        let context = ExecutionContext::new(
            BPF_LOADER_PROGRAM_ID,
            vec![
                (Pubkey::new_unique(), buffer_account, true),
                (authority_pubkey, Account::default(), false),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert_eq!(outcome.modified_accounts.len(), 1);
        assert!(outcome.logs.iter().any(|log| log.contains("Wrote")));
    }

    #[test]
    fn test_finalize_buffer() {
        let executor = BpfLoaderExecutor::new(150);

        // Create buffer with ELF header
        let mut buffer_data = vec![0x7F, 0x45, 0x4C, 0x46]; // ELF magic
        buffer_data.extend_from_slice(&[0u8; 100]); // padding

        let authority = Pubkey::new_unique();
        let state = ProgramAccountState::Buffer {
            authority,
            data: buffer_data,
        };

        let mut buffer_account = create_buffer_account();
        buffer_account.data = AccountData::from(state.serialize());

        let instruction_data = vec![1, 0, 0, 0]; // Finalize instruction

        let context = ExecutionContext::new(
            BPF_LOADER_PROGRAM_ID,
            vec![(Pubkey::new_unique(), buffer_account, true)],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert_eq!(outcome.modified_accounts.len(), 1);
        assert!(outcome.logs.iter().any(|log| log.contains("Finalized")));

        // Verify state transition
        let modified = outcome.modified_accounts.values().next().unwrap();
        let new_state = ProgramAccountState::deserialize(modified.data.as_ref()).unwrap();
        match new_state {
            ProgramAccountState::Program { is_deployed, .. } => {
                assert!(!is_deployed);
            }
            _ => panic!("Expected Program state"),
        }
    }

    #[test]
    fn test_deploy_program() {
        let executor = BpfLoaderExecutor::new(150);

        // Create finalized program
        let mut program_data = vec![0x7F, 0x45, 0x4C, 0x46]; // ELF magic
        program_data.extend_from_slice(&[0u8; 100]);

        let authority = Pubkey::new_unique();
        let state = ProgramAccountState::Program {
            authority,
            data: program_data,
            is_deployed: false,
        };

        let mut program_account = create_buffer_account();
        program_account.data = AccountData::from(state.serialize());

        let instruction_data = vec![2, 0, 0, 0]; // Deploy instruction

        let context = ExecutionContext::new(
            BPF_LOADER_PROGRAM_ID,
            vec![(Pubkey::new_unique(), program_account, true)],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert_eq!(outcome.modified_accounts.len(), 1);
        assert!(outcome.logs.iter().any(|log| log.contains("Deployed")));

        // Verify state transition and executable flag
        let modified = outcome.modified_accounts.values().next().unwrap();
        assert!(modified.meta.executable);
        let new_state = ProgramAccountState::deserialize(modified.data.as_ref()).unwrap();
        match new_state {
            ProgramAccountState::ProgramData { .. } => {}
            _ => panic!("Expected ProgramData state"),
        }
    }

    #[test]
    fn test_write_finalize_deploy_lifecycle() {
        let executor = BpfLoaderExecutor::new(150);
        let buffer_pubkey = Pubkey::new_unique();
        let authority_pubkey = Pubkey::new_unique();

        // Step 1: Write program data
        let mut buffer_account = create_buffer_account();

        let mut write_data = vec![0, 0, 0, 0]; // Write instruction
        write_data.extend_from_slice(&0u32.to_le_bytes()); // offset
        let program_bytes = vec![0x7F, 0x45, 0x4C, 0x46, 1, 2, 3, 4]; // ELF + data
        write_data.extend_from_slice(&(program_bytes.len() as u32).to_le_bytes());
        write_data.extend_from_slice(&program_bytes);

        let write_context = ExecutionContext::new(
            BPF_LOADER_PROGRAM_ID,
            vec![
                (buffer_pubkey, buffer_account.clone(), true),
                (authority_pubkey, Account::default(), false),
            ],
            write_data,
        );

        let write_outcome = executor.execute(&write_context).unwrap();
        assert!(write_outcome.success);
        assert!(write_outcome.logs.iter().any(|log| log.contains("Wrote")));

        // Get modified buffer account
        buffer_account = write_outcome.modified_accounts[&buffer_pubkey].clone();

        // Step 2: Finalize
        let finalize_data = vec![1, 0, 0, 0]; // Finalize instruction

        let finalize_context = ExecutionContext::new(
            BPF_LOADER_PROGRAM_ID,
            vec![(buffer_pubkey, buffer_account.clone(), true)],
            finalize_data,
        );

        let finalize_outcome = executor.execute(&finalize_context).unwrap();
        assert!(finalize_outcome.success);
        assert!(finalize_outcome.logs.iter().any(|log| log.contains("Finalized")));

        // Get finalized program account
        buffer_account = finalize_outcome.modified_accounts[&buffer_pubkey].clone();

        // Step 3: Deploy
        let deploy_data = vec![2, 0, 0, 0]; // Deploy instruction

        let deploy_context = ExecutionContext::new(
            BPF_LOADER_PROGRAM_ID,
            vec![(buffer_pubkey, buffer_account, true)],
            deploy_data,
        );

        let deploy_outcome = executor.execute(&deploy_context).unwrap();
        assert!(deploy_outcome.success);
        assert!(deploy_outcome.logs.iter().any(|log| log.contains("Deployed")));

        // Verify final state
        let final_account = &deploy_outcome.modified_accounts[&buffer_pubkey];
        assert!(final_account.meta.executable);

        let final_state = ProgramAccountState::deserialize(final_account.data.as_ref()).unwrap();
        match final_state {
            ProgramAccountState::ProgramData { data, .. } => {
                assert_eq!(data, program_bytes);
            }
            _ => panic!("Expected ProgramData state"),
        }
    }

    #[test]
    fn test_set_authority() {
        let executor = BpfLoaderExecutor::new(150);

        let authority = Pubkey::new_unique();
        let state = ProgramAccountState::Buffer {
            authority,
            data: vec![1, 2, 3],
        };

        let mut buffer_account = create_buffer_account();
        buffer_account.data = AccountData::from(state.serialize());

        let new_authority = Pubkey::new_unique();
        let mut instruction_data = vec![4, 0, 0, 0]; // SetAuthority instruction
        instruction_data.push(1); // has new authority
        instruction_data.extend_from_slice(new_authority.as_bytes());

        let context = ExecutionContext::new(
            BPF_LOADER_PROGRAM_ID,
            vec![(Pubkey::new_unique(), buffer_account, true)],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert!(outcome.logs.iter().any(|log| log.contains("Set authority")));

        // Verify authority changed
        let modified = outcome.modified_accounts.values().next().unwrap();
        let new_state = ProgramAccountState::deserialize(modified.data.as_ref()).unwrap();
        match new_state {
            ProgramAccountState::Buffer { authority: auth, .. } => {
                assert_eq!(auth, new_authority);
            }
            _ => panic!("Expected Buffer state"),
        }
    }

    #[test]
    fn test_close_buffer() {
        let executor = BpfLoaderExecutor::new(150);

        let authority = Pubkey::new_unique();
        let state = ProgramAccountState::Buffer {
            authority,
            data: vec![1, 2, 3],
        };

        let mut buffer_account = create_buffer_account();
        buffer_account.data = AccountData::from(state.serialize());
        buffer_account.meta.lamports = 5000;

        let recipient_account = Account {
            meta: AccountMeta {
                lamports: 1000,
                owner: Pubkey::new_unique(),
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };

        let instruction_data = vec![5, 0, 0, 0]; // Close instruction

        let context = ExecutionContext::new(
            BPF_LOADER_PROGRAM_ID,
            vec![
                (Pubkey::new_unique(), buffer_account, true),
                (Pubkey::new_unique(), recipient_account, false),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert_eq!(outcome.modified_accounts.len(), 2);
        assert!(outcome.logs.iter().any(|log| log.contains("Closed")));

        // Verify lamports transferred
        let accounts: Vec<_> = outcome.modified_accounts.values().collect();
        let closed = accounts.iter().find(|a| a.meta.lamports == 0).unwrap();
        let recipient = accounts.iter().find(|a| a.meta.lamports == 6000).unwrap();

        assert_eq!(closed.data.as_ref().len(), 0);
        assert!(!closed.meta.executable);
        assert_eq!(recipient.meta.lamports, 6000);
    }

    #[test]
    fn test_upgrade_program() {
        let executor = BpfLoaderExecutor::new(150);

        // Create deployed program
        let old_data = vec![0x7F, 0x45, 0x4C, 0x46, 1, 2, 3, 4];
        let authority = Pubkey::new_unique();
        let program_state = ProgramAccountState::ProgramData {
            slot: 100,
            upgrade_authority: Some(authority),
            data: old_data.clone(),
        };

        let mut program_account = create_buffer_account();
        program_account.meta.executable = true;
        program_account.data = AccountData::from(program_state.serialize());

        // Create buffer with new program data
        let new_data = vec![0x7F, 0x45, 0x4C, 0x46, 5, 6, 7, 8];
        let buffer_state = ProgramAccountState::Buffer {
            authority,
            data: new_data.clone(),
        };

        let mut buffer_account = create_buffer_account();
        buffer_account.data = AccountData::from(buffer_state.serialize());

        let instruction_data = vec![3, 0, 0, 0]; // Upgrade instruction

        let context = ExecutionContext::new(
            BPF_LOADER_PROGRAM_ID,
            vec![
                (Pubkey::new_unique(), program_account, true),
                (Pubkey::new_unique(), buffer_account, false),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert!(outcome.logs.iter().any(|log| log.contains("Upgraded")));

        // Verify program was upgraded
        let modified = outcome.modified_accounts.values().next().unwrap();
        let new_state = ProgramAccountState::deserialize(modified.data.as_ref()).unwrap();
        match new_state {
            ProgramAccountState::ProgramData { slot, data, .. } => {
                assert_eq!(slot, 101); // Incremented
                assert_eq!(data, new_data);
            }
            _ => panic!("Expected ProgramData state"),
        }
    }

    #[test]
    fn test_state_serialization_roundtrip() {
        let authority = Pubkey::new_unique();

        // Test Buffer state
        let buffer_state = ProgramAccountState::Buffer {
            authority,
            data: vec![1, 2, 3, 4, 5],
        };
        let serialized = buffer_state.serialize();
        let deserialized = ProgramAccountState::deserialize(&serialized).unwrap();
        assert_eq!(buffer_state, deserialized);

        // Test Program state
        let program_state = ProgramAccountState::Program {
            authority,
            data: vec![0x7F, 0x45, 0x4C, 0x46],
            is_deployed: false,
        };
        let serialized = program_state.serialize();
        let deserialized = ProgramAccountState::deserialize(&serialized).unwrap();
        assert_eq!(program_state, deserialized);

        // Test ProgramData state
        let program_data_state = ProgramAccountState::ProgramData {
            slot: 42,
            upgrade_authority: Some(authority),
            data: vec![1, 2, 3],
        };
        let serialized = program_data_state.serialize();
        let deserialized = ProgramAccountState::deserialize(&serialized).unwrap();
        assert_eq!(program_data_state, deserialized);

        // Test ProgramData with no authority
        let immutable_state = ProgramAccountState::ProgramData {
            slot: 42,
            upgrade_authority: None,
            data: vec![1, 2, 3],
        };
        let serialized = immutable_state.serialize();
        let deserialized = ProgramAccountState::deserialize(&serialized).unwrap();
        assert_eq!(immutable_state, deserialized);
    }
}
