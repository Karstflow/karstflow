use super::{ExecutionContext, ExecutionOutcome};
use paradencer_constants::bpf_loader_program as constants;
use paradencer_ids::BPF_LOADER_PROGRAM_ID;
use paradencer_types::{Account, AccountData, Pubkey};
use std::collections::HashMap;

// ── Protocol-compatible state types ─────────────────────────────────────

/// On-chain state for BPF Upgradeable Loader accounts.
///
/// This enum represents the metadata header stored at the beginning of
/// account data.  Buffer and ProgramData accounts have ELF binary data
/// following the fixed-size header.
///
/// The bincode-compatible on-chain layout:
///   - Uninitialized:  4 bytes (u32 discriminant only)
///   - Buffer:         37 bytes header (disc + option<authority>) + ELF data
///   - Program:        36 bytes total (disc + programdata_address)
///   - ProgramData:    45 bytes header (disc + slot + option<authority>) + ELF data
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpgradeableLoaderState {
    /// Account created but not yet initialized.
    Uninitialized,
    /// Buffer holding uploaded program data before deployment.
    Buffer { authority: Option<Pubkey> },
    /// Deployed program account pointing to its ProgramData account.
    Program { programdata_address: Pubkey },
    /// ProgramData account holding deployment slot, authority, and ELF data.
    ProgramData {
        slot: u64,
        upgrade_authority: Option<Pubkey>,
    },
}

/// Backward-compatible alias for the old name.
pub type ProgramAccountState = UpgradeableLoaderState;

impl UpgradeableLoaderState {
    /// Size of account data for a buffer with `program_len` bytes of ELF data.
    pub fn size_of_buffer(program_len: usize) -> usize {
        constants::SIZE_OF_BUFFER_METADATA + program_len
    }

    /// Size of the program account (fixed).
    pub fn size_of_program() -> usize {
        constants::SIZE_OF_PROGRAM
    }

    /// Size of account data for programdata with `program_len` bytes of ELF data.
    pub fn size_of_programdata(program_len: usize) -> usize {
        constants::SIZE_OF_PROGRAMDATA_METADATA + program_len
    }

    /// Serialize the state header into the beginning of account data.
    ///
    /// Only writes the metadata header.  For Buffer and ProgramData, the
    /// ELF binary data is written separately at the appropriate offset.
    pub fn serialize_into(&self, data: &mut [u8]) -> Result<usize, String> {
        match self {
            Self::Uninitialized => {
                if data.len() < constants::SIZE_OF_UNINITIALIZED {
                    return Err("Account data too small for uninitialized state".into());
                }
                data[0..4].copy_from_slice(&constants::STATE_UNINITIALIZED.to_le_bytes());
                Ok(constants::SIZE_OF_UNINITIALIZED)
            }
            Self::Buffer { authority } => {
                if data.len() < constants::SIZE_OF_BUFFER_METADATA {
                    return Err("Account data too small for buffer metadata".into());
                }
                data[0..4].copy_from_slice(&constants::STATE_BUFFER.to_le_bytes());
                match authority {
                    Some(pubkey) => {
                        data[4] = 1;
                        data[5..37].copy_from_slice(pubkey.as_bytes());
                    }
                    None => {
                        data[4] = 0;
                        data[5..37].fill(0);
                    }
                }
                Ok(constants::SIZE_OF_BUFFER_METADATA)
            }
            Self::Program {
                programdata_address,
            } => {
                if data.len() < constants::SIZE_OF_PROGRAM {
                    return Err("Account data too small for program state".into());
                }
                data[0..4].copy_from_slice(&constants::STATE_PROGRAM.to_le_bytes());
                data[4..36].copy_from_slice(programdata_address.as_bytes());
                Ok(constants::SIZE_OF_PROGRAM)
            }
            Self::ProgramData {
                slot,
                upgrade_authority,
            } => {
                if data.len() < constants::SIZE_OF_PROGRAMDATA_METADATA {
                    return Err("Account data too small for programdata metadata".into());
                }
                data[0..4].copy_from_slice(&constants::STATE_PROGRAM_DATA.to_le_bytes());
                data[4..12].copy_from_slice(&slot.to_le_bytes());
                match upgrade_authority {
                    Some(pubkey) => {
                        data[12] = 1;
                        data[13..45].copy_from_slice(pubkey.as_bytes());
                    }
                    None => {
                        data[12] = 0;
                        data[13..45].fill(0);
                    }
                }
                Ok(constants::SIZE_OF_PROGRAMDATA_METADATA)
            }
        }
    }

    /// Serialize to a new Vec (includes only the header, no ELF data).
    pub fn serialize(&self) -> Vec<u8> {
        let size = match self {
            Self::Uninitialized => constants::SIZE_OF_UNINITIALIZED,
            Self::Buffer { .. } => constants::SIZE_OF_BUFFER_METADATA,
            Self::Program { .. } => constants::SIZE_OF_PROGRAM,
            Self::ProgramData { .. } => constants::SIZE_OF_PROGRAMDATA_METADATA,
        };
        let mut buf = vec![0u8; size];
        self.serialize_into(&mut buf).expect("pre-sized buffer");
        buf
    }

    /// Deserialize the state header from account data.
    pub fn deserialize(data: &[u8]) -> Result<Self, String> {
        if data.len() < 4 {
            return Ok(Self::Uninitialized);
        }
        let disc = u32::from_le_bytes(
            data[0..4]
                .try_into()
                .map_err(|_| "Failed to read discriminant")?,
        );

        match disc {
            constants::STATE_UNINITIALIZED => Ok(Self::Uninitialized),
            constants::STATE_BUFFER => {
                if data.len() < 5 {
                    return Err("Buffer state data too short".into());
                }
                let authority = if data[4] != 0 {
                    if data.len() < constants::SIZE_OF_BUFFER_METADATA {
                        return Err("Buffer authority data too short".into());
                    }
                    Some(Pubkey::new_from_array(
                        data[5..37].try_into().map_err(|_| "Bad authority bytes")?,
                    ))
                } else {
                    None
                };
                Ok(Self::Buffer { authority })
            }
            constants::STATE_PROGRAM => {
                if data.len() < constants::SIZE_OF_PROGRAM {
                    return Err("Program state data too short".into());
                }
                let programdata_address = Pubkey::new_from_array(
                    data[4..36]
                        .try_into()
                        .map_err(|_| "Bad programdata address")?,
                );
                Ok(Self::Program {
                    programdata_address,
                })
            }
            constants::STATE_PROGRAM_DATA => {
                if data.len() < 13 {
                    return Err("ProgramData state data too short".into());
                }
                let slot =
                    u64::from_le_bytes(data[4..12].try_into().map_err(|_| "Bad slot bytes")?);
                let upgrade_authority = if data[12] != 0 {
                    if data.len() < constants::SIZE_OF_PROGRAMDATA_METADATA {
                        return Err("ProgramData authority data too short".into());
                    }
                    Some(Pubkey::new_from_array(
                        data[13..45]
                            .try_into()
                            .map_err(|_| "Bad upgrade authority bytes")?,
                    ))
                } else {
                    None
                };
                Ok(Self::ProgramData {
                    slot,
                    upgrade_authority,
                })
            }
            _ => Err(format!("Unknown state discriminant: {}", disc)),
        }
    }

    pub fn is_uninitialized(&self) -> bool {
        matches!(self, Self::Uninitialized)
    }

    pub fn is_buffer(&self) -> bool {
        matches!(self, Self::Buffer { .. })
    }

    pub fn is_program(&self) -> bool {
        matches!(self, Self::Program { .. })
    }

    pub fn is_program_data(&self) -> bool {
        matches!(self, Self::ProgramData { .. })
    }
}

// ── BPF Loader Executor ─────────────────────────────────────────────────

/// Executes BPF Upgradeable Loader instructions.
///
/// Handles all 9 protocol instruction types: InitializeBuffer, Write,
/// DeployWithMaxDataLen, Upgrade, SetAuthority, Close, ExtendProgram,
/// SetAuthorityChecked, and ExtendProgramChecked.
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
            return Err("Instruction data too short".into());
        }

        let disc = u32::from_le_bytes(
            context.instruction_data[0..4]
                .try_into()
                .map_err(|_| "Failed to parse instruction discriminant")?,
        );

        let mut modified_accounts = HashMap::new();
        let mut logs = Vec::new();

        let compute_used = match disc {
            constants::INSTRUCTION_INITIALIZE_BUFFER => {
                self.execute_initialize_buffer(context, &mut modified_accounts, &mut logs)?;
                constants::COMPUTE_COST_INITIALIZE_BUFFER
            }
            constants::INSTRUCTION_WRITE => {
                self.execute_write(context, &mut modified_accounts, &mut logs)?;
                constants::COMPUTE_COST_WRITE
            }
            constants::INSTRUCTION_DEPLOY_WITH_MAX_DATA_LEN => {
                self.execute_deploy(context, &mut modified_accounts, &mut logs)?;
                constants::COMPUTE_COST_DEPLOY
            }
            constants::INSTRUCTION_UPGRADE => {
                self.execute_upgrade(context, &mut modified_accounts, &mut logs)?;
                constants::COMPUTE_COST_UPGRADE
            }
            constants::INSTRUCTION_SET_AUTHORITY => {
                self.execute_set_authority(context, &mut modified_accounts, &mut logs)?;
                constants::COMPUTE_COST_SET_AUTHORITY
            }
            constants::INSTRUCTION_CLOSE => {
                self.execute_close(context, &mut modified_accounts, &mut logs)?;
                constants::COMPUTE_COST_CLOSE
            }
            constants::INSTRUCTION_EXTEND_PROGRAM => {
                self.execute_extend_program(context, &mut modified_accounts, &mut logs)?;
                constants::COMPUTE_COST_EXTEND_PROGRAM
            }
            constants::INSTRUCTION_SET_AUTHORITY_CHECKED => {
                self.execute_set_authority_checked(context, &mut modified_accounts, &mut logs)?;
                constants::COMPUTE_COST_SET_AUTHORITY_CHECKED
            }
            constants::INSTRUCTION_EXTEND_PROGRAM_CHECKED => {
                self.execute_extend_program(context, &mut modified_accounts, &mut logs)?;
                constants::COMPUTE_COST_EXTEND_PROGRAM
            }
            _ => {
                return Err(format!("Unknown BPF loader instruction: {}", disc));
            }
        };

        Ok(ExecutionOutcome {
            success: true,
            compute_units_consumed: compute_used,
            modified_accounts,
            logs,
            return_data: None,
        })
    }

    /// InitializeBuffer (discriminant 0).
    ///
    /// Accounts: [0] buffer (writable), [1] authority
    /// Sets an uninitialized account to Buffer state with the given authority.
    fn execute_initialize_buffer(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        if context.accounts.len() < 2 {
            return Err("InitializeBuffer requires at least 2 accounts".into());
        }

        let (buffer_pubkey, mut buffer_account, writable) = context.accounts[0].clone();
        if !writable {
            return Err("Buffer account not writable".into());
        }

        let state = UpgradeableLoaderState::deserialize(buffer_account.data.as_ref())?;
        if !state.is_uninitialized() {
            return Err("Buffer account already initialized".into());
        }

        let authority_pubkey = context.accounts[1].0;
        let new_state = UpgradeableLoaderState::Buffer {
            authority: Some(authority_pubkey),
        };

        // Write state header into existing account data
        let mut data = buffer_account.data.as_ref().to_vec();
        if data.len() < constants::SIZE_OF_BUFFER_METADATA {
            data.resize(constants::SIZE_OF_BUFFER_METADATA, 0);
        }
        new_state.serialize_into(&mut data)?;
        buffer_account.data = AccountData::from(data);

        modified_accounts.insert(buffer_pubkey, buffer_account);
        logs.push(format!(
            "Initialized buffer {} with authority {}",
            buffer_pubkey, authority_pubkey
        ));
        Ok(())
    }

    /// Write (discriminant 1).
    ///
    /// Accounts: [0] buffer (writable), [1] authority (signer)
    /// Instruction data: disc(4) + offset(4) + bytes_len(8) + bytes(N)
    ///
    /// Writes program data into the buffer at `BUFFER_METADATA_SIZE + offset`.
    fn execute_write(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        if context.accounts.len() < 2 {
            return Err("Write requires at least 2 accounts".into());
        }

        let (buffer_pubkey, mut buffer_account, writable) = context.accounts[0].clone();
        if !writable {
            return Err("Buffer account not writable".into());
        }

        // Parse instruction data: disc(4) + offset(4) + bytes_len(8) + bytes
        if context.instruction_data.len() < 16 {
            return Err("Write instruction data too short".into());
        }
        let offset = u32::from_le_bytes(
            context.instruction_data[4..8]
                .try_into()
                .map_err(|_| "Bad offset")?,
        ) as usize;
        let bytes_len = u64::from_le_bytes(
            context.instruction_data[8..16]
                .try_into()
                .map_err(|_| "Bad bytes length")?,
        ) as usize;
        if context.instruction_data.len() < 16 + bytes_len {
            return Err("Write instruction data too short for payload".into());
        }
        let bytes = &context.instruction_data[16..16 + bytes_len];

        // Verify buffer state and authority
        let state = UpgradeableLoaderState::deserialize(buffer_account.data.as_ref())?;
        match &state {
            UpgradeableLoaderState::Buffer { authority } => {
                let auth = authority.ok_or("Buffer is immutable")?;
                let signer = context.accounts[1].0;
                if auth != signer {
                    return Err("Incorrect buffer authority provided".into());
                }
            }
            _ => return Err("Invalid Buffer account".into()),
        }

        // Write data at BUFFER_METADATA_SIZE + offset
        let write_start = constants::SIZE_OF_BUFFER_METADATA + offset;
        let write_end = write_start + bytes_len;

        let mut data = buffer_account.data.as_ref().to_vec();
        if data.len() < write_end {
            return Err(format!(
                "Write overflow: account data {} < required {}",
                data.len(),
                write_end
            ));
        }
        data[write_start..write_end].copy_from_slice(bytes);
        buffer_account.data = AccountData::from(data);

        modified_accounts.insert(buffer_pubkey, buffer_account);
        logs.push(format!(
            "Wrote {} bytes at offset {} to buffer {}",
            bytes_len, offset, buffer_pubkey
        ));
        Ok(())
    }

    /// DeployWithMaxDataLen (discriminant 2).
    ///
    /// Accounts: [0] payer (signer/writable), [1] programdata (writable),
    ///           [2] program (writable), [3] buffer, [4] rent sysvar,
    ///           [5] clock sysvar, [6] system program, [7] authority (signer)
    ///
    /// Instruction data: disc(4) + max_data_len(8)
    fn execute_deploy(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        if context.accounts.len() < 4 {
            return Err("Deploy requires at least 4 accounts".into());
        }

        // Parse max_data_len from instruction data
        if context.instruction_data.len() < 12 {
            return Err("Deploy instruction data too short".into());
        }
        let max_data_len = u64::from_le_bytes(
            context.instruction_data[4..12]
                .try_into()
                .map_err(|_| "Bad max_data_len")?,
        ) as usize;

        let (programdata_pubkey, mut programdata_account, _) = context.accounts[1].clone();
        let (program_pubkey, mut program_account, program_writable) = context.accounts[2].clone();
        let (buffer_pubkey, buffer_account, _) = context.accounts[3].clone();

        if !program_writable {
            return Err("Program account not writable".into());
        }

        // Verify program account is uninitialized
        let program_state = UpgradeableLoaderState::deserialize(program_account.data.as_ref())?;
        if !program_state.is_uninitialized() {
            return Err("Program account already initialized".into());
        }

        // Verify program account is large enough
        if program_account.data.as_ref().len() < constants::SIZE_OF_PROGRAM {
            return Err("Program account too small".into());
        }

        // Verify buffer account state
        let buffer_state = UpgradeableLoaderState::deserialize(buffer_account.data.as_ref())?;
        let _buffer_authority = match &buffer_state {
            UpgradeableLoaderState::Buffer { authority } => {
                authority.ok_or("Buffer has no authority")?
            }
            _ => return Err("Invalid Buffer account".into()),
        };

        // Extract ELF data from buffer (after metadata header)
        if buffer_account.data.as_ref().len() < constants::SIZE_OF_BUFFER_METADATA {
            return Err("Buffer account too small".into());
        }
        let buffer_data_offset = constants::SIZE_OF_BUFFER_METADATA;
        let buffer_data_len = buffer_account.data.as_ref().len() - buffer_data_offset;
        if buffer_data_len == 0 {
            return Err("Buffer has no program data".into());
        }
        if max_data_len < buffer_data_len {
            return Err("Max data length is too small to hold buffer data".into());
        }

        let programdata_len = constants::SIZE_OF_PROGRAMDATA_METADATA + max_data_len;
        if programdata_len as u64 > constants::MAX_PERMITTED_DATA_LENGTH {
            return Err("Max data length is too large".into());
        }

        // Get authority from accounts (at index 7, or fallback to 3)
        let authority_pubkey = if context.accounts.len() > 7 {
            context.accounts[7].0
        } else {
            _buffer_authority
        };

        // Get current slot from sysvar snapshot if available
        let current_slot = context
            .sysvar_snapshot
            .as_ref()
            .map(|s| s.slot)
            .unwrap_or(0);

        // Create ProgramData account
        let programdata_state = UpgradeableLoaderState::ProgramData {
            slot: current_slot,
            upgrade_authority: Some(authority_pubkey),
        };
        let mut programdata_data = vec![0u8; programdata_len];
        programdata_state.serialize_into(&mut programdata_data)?;

        // Copy buffer data into programdata
        let src = &buffer_account.data.as_ref()[buffer_data_offset..];
        programdata_data[constants::SIZE_OF_PROGRAMDATA_METADATA
            ..constants::SIZE_OF_PROGRAMDATA_METADATA + buffer_data_len]
            .copy_from_slice(src);

        programdata_account.data = AccountData::from(programdata_data);
        programdata_account.meta.owner = BPF_LOADER_PROGRAM_ID;

        // Set up Program account state pointing to ProgramData
        let program_state = UpgradeableLoaderState::Program {
            programdata_address: programdata_pubkey,
        };
        let mut program_data = vec![0u8; constants::SIZE_OF_PROGRAM];
        program_state.serialize_into(&mut program_data)?;
        program_account.data = AccountData::from(program_data);
        program_account.meta.executable = true;

        modified_accounts.insert(programdata_pubkey, programdata_account);
        modified_accounts.insert(program_pubkey, program_account);

        logs.push(format!("Deployed program {}", program_pubkey));
        Ok(())
    }

    /// Upgrade (discriminant 3).
    ///
    /// Accounts: [0] programdata (writable), [1] program (writable),
    ///           [2] buffer, [3] spill (writable), [4] rent sysvar,
    ///           [5] clock sysvar, [6] authority (signer)
    fn execute_upgrade(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        if context.accounts.len() < 4 {
            return Err("Upgrade requires at least 4 accounts".into());
        }

        let (programdata_pubkey, mut programdata_account, pd_writable) =
            context.accounts[0].clone();
        let (program_pubkey, program_account, _) = context.accounts[1].clone();
        let (_buffer_pubkey, buffer_account, _) = context.accounts[2].clone();
        let (spill_pubkey, mut spill_account, _) = context.accounts[3].clone();

        if !pd_writable {
            return Err("ProgramData account not writable".into());
        }

        // Verify program state points to this programdata
        let program_state = UpgradeableLoaderState::deserialize(program_account.data.as_ref())?;
        match &program_state {
            UpgradeableLoaderState::Program {
                programdata_address,
            } => {
                if *programdata_address != programdata_pubkey {
                    return Err("Program and ProgramData account mismatch".into());
                }
            }
            _ => return Err("Invalid Program account".into()),
        }

        // Verify programdata state
        let pd_state = UpgradeableLoaderState::deserialize(programdata_account.data.as_ref())?;
        let (old_slot, upgrade_authority) = match &pd_state {
            UpgradeableLoaderState::ProgramData {
                slot,
                upgrade_authority,
            } => (*slot, *upgrade_authority),
            _ => return Err("Invalid ProgramData account".into()),
        };

        let upgrade_auth = upgrade_authority.ok_or("Program is not upgradeable")?;

        // Get current slot
        let current_slot = context
            .sysvar_snapshot
            .as_ref()
            .map(|s| s.slot)
            .unwrap_or(0);
        if current_slot == old_slot && current_slot != 0 {
            return Err("Program was deployed in this block already".into());
        }

        // Verify authority signer
        let authority_pubkey = if context.accounts.len() > 6 {
            context.accounts[6].0
        } else {
            context.accounts[3].0
        };
        if upgrade_auth != authority_pubkey {
            return Err("Incorrect upgrade authority provided".into());
        }

        // Verify buffer
        let buffer_state = UpgradeableLoaderState::deserialize(buffer_account.data.as_ref())?;
        match &buffer_state {
            UpgradeableLoaderState::Buffer { authority } => {
                let buf_auth = authority.ok_or("Buffer has no authority")?;
                if buf_auth != authority_pubkey {
                    return Err("Buffer and upgrade authority don't match".into());
                }
            }
            _ => return Err("Invalid Buffer account".into()),
        }

        let buffer_data_offset = constants::SIZE_OF_BUFFER_METADATA;
        if buffer_account.data.as_ref().len() < buffer_data_offset {
            return Err("Buffer account too small".into());
        }
        let buffer_data_len = buffer_account.data.as_ref().len() - buffer_data_offset;
        if buffer_data_len == 0 {
            return Err("Buffer has no program data".into());
        }

        // Verify programdata has enough space
        if programdata_account.data.as_ref().len()
            < constants::SIZE_OF_PROGRAMDATA_METADATA + buffer_data_len
        {
            return Err("ProgramData account not large enough".into());
        }

        // Update programdata: write new state header + copy buffer data + zero rest
        let new_pd_state = UpgradeableLoaderState::ProgramData {
            slot: current_slot,
            upgrade_authority: Some(authority_pubkey),
        };
        let mut pd_data = programdata_account.data.as_ref().to_vec();
        new_pd_state.serialize_into(&mut pd_data)?;

        // Copy new ELF data
        let src = &buffer_account.data.as_ref()[buffer_data_offset..];
        pd_data[constants::SIZE_OF_PROGRAMDATA_METADATA
            ..constants::SIZE_OF_PROGRAMDATA_METADATA + buffer_data_len]
            .copy_from_slice(src);

        // Zero remaining space after new data
        let zero_start = constants::SIZE_OF_PROGRAMDATA_METADATA + buffer_data_len;
        if zero_start < pd_data.len() {
            pd_data[zero_start..].fill(0);
        }

        programdata_account.data = AccountData::from(pd_data);

        // Spill: transfer excess lamports from buffer to spill
        let buffer_lamports = buffer_account.meta.lamports;
        spill_account.meta.lamports = spill_account.meta.lamports.saturating_add(buffer_lamports);

        modified_accounts.insert(programdata_pubkey, programdata_account);
        modified_accounts.insert(spill_pubkey, spill_account);

        logs.push(format!("Upgraded program {}", program_pubkey));
        Ok(())
    }

    /// SetAuthority (discriminant 4).
    ///
    /// Accounts: [0] account (writable), [1] present authority (signer),
    ///           [2] new authority (optional)
    fn execute_set_authority(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        if context.accounts.len() < 2 {
            return Err("SetAuthority requires at least 2 accounts".into());
        }

        let (account_pubkey, mut account, writable) = context.accounts[0].clone();
        if !writable {
            return Err("Account not writable".into());
        }

        let present_authority = context.accounts[1].0;
        let new_authority = if context.accounts.len() > 2 {
            Some(context.accounts[2].0)
        } else {
            None
        };

        let state = UpgradeableLoaderState::deserialize(account.data.as_ref())?;

        let new_state = match &state {
            UpgradeableLoaderState::Buffer { authority } => {
                // Buffer authority is not optional
                if new_authority.is_none() {
                    return Err("Buffer authority is not optional".into());
                }
                let auth = authority.ok_or("Buffer is immutable")?;
                if auth != present_authority {
                    return Err("Incorrect buffer authority provided".into());
                }
                UpgradeableLoaderState::Buffer {
                    authority: new_authority,
                }
            }
            UpgradeableLoaderState::ProgramData {
                slot,
                upgrade_authority,
            } => {
                let auth = upgrade_authority
                    .as_ref()
                    .ok_or("Program not upgradeable")?;
                if *auth != present_authority {
                    return Err("Incorrect upgrade authority provided".into());
                }
                // New authority can be None (makes program immutable)
                UpgradeableLoaderState::ProgramData {
                    slot: *slot,
                    upgrade_authority: new_authority,
                }
            }
            _ => return Err("Account does not support authorities".into()),
        };

        let mut data = account.data.as_ref().to_vec();
        new_state.serialize_into(&mut data)?;
        account.data = AccountData::from(data);

        modified_accounts.insert(account_pubkey, account);

        match new_authority {
            Some(auth) => logs.push(format!("New authority Some({})", auth)),
            None => logs.push("New authority None".to_string()),
        }
        Ok(())
    }

    /// Close (discriminant 5).
    ///
    /// Accounts: [0] close account (writable), [1] recipient (writable),
    ///           [2] authority (signer, for buffer/programdata),
    ///           [3] program account (writable, for programdata close)
    fn execute_close(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        if context.accounts.len() < 2 {
            return Err("Close requires at least 2 accounts".into());
        }

        let (close_pubkey, mut close_account, close_writable) = context.accounts[0].clone();
        let (recipient_pubkey, mut recipient_account, _) = context.accounts[1].clone();

        if !close_writable {
            return Err("Close account not writable".into());
        }

        if close_pubkey == recipient_pubkey {
            return Err("Recipient is the same as the account being closed".into());
        }

        let state = UpgradeableLoaderState::deserialize(close_account.data.as_ref())?;

        match &state {
            UpgradeableLoaderState::Uninitialized => {
                // Can close uninitialized accounts without authority check
            }
            UpgradeableLoaderState::Buffer { authority } => {
                if context.accounts.len() < 3 {
                    return Err("Close buffer requires authority account".into());
                }
                let auth = authority.as_ref().ok_or("Account is immutable")?;
                let signer = context.accounts[2].0;
                if *auth != signer {
                    return Err("Incorrect authority provided".into());
                }
            }
            UpgradeableLoaderState::ProgramData {
                slot,
                upgrade_authority,
            } => {
                if context.accounts.len() < 4 {
                    return Err("Close programdata requires program account".into());
                }
                let auth = upgrade_authority.as_ref().ok_or("Account is immutable")?;
                let signer = context.accounts[2].0;
                if *auth != signer {
                    return Err("Incorrect authority provided".into());
                }

                // Check current slot vs deployment slot
                let current_slot = context
                    .sysvar_snapshot
                    .as_ref()
                    .map(|s| s.slot)
                    .unwrap_or(0);
                if current_slot == *slot && current_slot != 0 {
                    return Err("Program was deployed in this block already".into());
                }

                // Verify program account points to this programdata
                let (program_pubkey, mut program_account, _) = context.accounts[3].clone();
                let program_state =
                    UpgradeableLoaderState::deserialize(program_account.data.as_ref())?;
                match &program_state {
                    UpgradeableLoaderState::Program {
                        programdata_address,
                    } => {
                        if *programdata_address != close_pubkey {
                            return Err("Program account does not match ProgramData account".into());
                        }
                    }
                    _ => return Err("Invalid Program account".into()),
                }

                // Close the associated program account too
                let uninit = UpgradeableLoaderState::Uninitialized;
                let mut prog_data = vec![0u8; constants::SIZE_OF_UNINITIALIZED];
                uninit.serialize_into(&mut prog_data)?;
                program_account.data = AccountData::from(prog_data);
                program_account.meta.executable = false;
                modified_accounts.insert(program_pubkey, program_account);
            }
            UpgradeableLoaderState::Program { .. } => {
                return Err("Cannot close Program account directly".into());
            }
        }

        // Transfer all lamports to recipient
        let lamports = close_account.meta.lamports;
        recipient_account.meta.lamports = recipient_account.meta.lamports.saturating_add(lamports);
        close_account.meta.lamports = 0;

        // Set close account to Uninitialized
        let uninit_state = UpgradeableLoaderState::Uninitialized;
        let mut close_data = vec![0u8; constants::SIZE_OF_UNINITIALIZED];
        uninit_state.serialize_into(&mut close_data)?;
        close_account.data = AccountData::from(close_data);

        modified_accounts.insert(close_pubkey, close_account);
        modified_accounts.insert(recipient_pubkey, recipient_account);

        logs.push(format!(
            "Closed account {} and transferred {} lamports to {}",
            close_pubkey, lamports, recipient_pubkey
        ));
        Ok(())
    }

    /// ExtendProgram (discriminant 6) and ExtendProgramChecked (discriminant 9).
    ///
    /// Accounts: [0] programdata (writable), [1] program (writable),
    ///           [2] authority (signer, for checked variant),
    ///           [3 or 4] payer (signer, optional)
    ///
    /// Instruction data: disc(4) + additional_bytes(4)
    fn execute_extend_program(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        if context.accounts.len() < 2 {
            return Err("ExtendProgram requires at least 2 accounts".into());
        }

        if context.instruction_data.len() < 8 {
            return Err("ExtendProgram instruction data too short".into());
        }
        let additional_bytes = u32::from_le_bytes(
            context.instruction_data[4..8]
                .try_into()
                .map_err(|_| "Bad additional_bytes")?,
        ) as usize;

        if additional_bytes == 0 {
            return Err("Additional bytes must be greater than 0".into());
        }

        let (programdata_pubkey, mut programdata_account, pd_writable) =
            context.accounts[0].clone();
        let (_program_pubkey, program_account, _) = context.accounts[1].clone();

        if !pd_writable {
            return Err("ProgramData is not writable".into());
        }

        // Verify program account points to this programdata
        let program_state = UpgradeableLoaderState::deserialize(program_account.data.as_ref())?;
        match &program_state {
            UpgradeableLoaderState::Program {
                programdata_address,
            } => {
                if *programdata_address != programdata_pubkey {
                    return Err("Program account does not match ProgramData account".into());
                }
            }
            _ => return Err("Invalid Program account".into()),
        }

        // Verify programdata state
        let pd_state = UpgradeableLoaderState::deserialize(programdata_account.data.as_ref())?;
        let (slot, upgrade_authority) = match &pd_state {
            UpgradeableLoaderState::ProgramData {
                slot,
                upgrade_authority,
            } => (*slot, *upgrade_authority),
            _ => return Err("ProgramData state is invalid".into()),
        };

        if upgrade_authority.is_none() {
            return Err("Cannot extend ProgramData accounts that are not upgradeable".into());
        }

        // Check slot
        let current_slot = context
            .sysvar_snapshot
            .as_ref()
            .map(|s| s.slot)
            .unwrap_or(0);
        if current_slot == slot && current_slot != 0 {
            return Err("Program was extended in this block already".into());
        }

        // Extend the account data
        let old_len = programdata_account.data.as_ref().len();
        let new_len = old_len + additional_bytes;
        if new_len as u64 > constants::MAX_PERMITTED_DATA_LENGTH {
            return Err(format!(
                "Extended ProgramData length of {} bytes exceeds max account data length",
                new_len
            ));
        }

        let mut data = programdata_account.data.as_ref().to_vec();
        data.resize(new_len, 0);

        // Update slot in header
        let updated_state = UpgradeableLoaderState::ProgramData {
            slot: current_slot,
            upgrade_authority,
        };
        updated_state.serialize_into(&mut data)?;

        programdata_account.data = AccountData::from(data);
        modified_accounts.insert(programdata_pubkey, programdata_account);

        logs.push(format!(
            "Extended ProgramData account by {} bytes",
            additional_bytes
        ));
        Ok(())
    }

    /// SetAuthorityChecked (discriminant 7).
    ///
    /// Like SetAuthority but requires the new authority to also be a signer.
    /// Accounts: [0] account (writable), [1] present authority (signer),
    ///           [2] new authority (signer)
    fn execute_set_authority_checked(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        if context.accounts.len() < 3 {
            return Err("SetAuthorityChecked requires at least 3 accounts".into());
        }

        let (account_pubkey, mut account, writable) = context.accounts[0].clone();
        if !writable {
            return Err("Account not writable".into());
        }

        let present_authority = context.accounts[1].0;
        let new_authority = context.accounts[2].0;

        let state = UpgradeableLoaderState::deserialize(account.data.as_ref())?;

        let new_state = match &state {
            UpgradeableLoaderState::Buffer { authority } => {
                let auth = authority.ok_or("Buffer is immutable")?;
                if auth != present_authority {
                    return Err("Incorrect buffer authority provided".into());
                }
                UpgradeableLoaderState::Buffer {
                    authority: Some(new_authority),
                }
            }
            UpgradeableLoaderState::ProgramData {
                slot,
                upgrade_authority,
            } => {
                let auth = upgrade_authority
                    .as_ref()
                    .ok_or("Program not upgradeable")?;
                if *auth != present_authority {
                    return Err("Incorrect upgrade authority provided".into());
                }
                UpgradeableLoaderState::ProgramData {
                    slot: *slot,
                    upgrade_authority: Some(new_authority),
                }
            }
            _ => return Err("Account does not support authorities".into()),
        };

        let mut data = account.data.as_ref().to_vec();
        new_state.serialize_into(&mut data)?;
        account.data = AccountData::from(data);

        modified_accounts.insert(account_pubkey, account);
        logs.push(format!("New authority {}", new_authority));
        Ok(())
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use paradencer_types::AccountMeta;

    fn make_account(lamports: u64, data_len: usize) -> Account {
        Account {
            meta: AccountMeta {
                lamports,
                owner: BPF_LOADER_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::from(vec![0u8; data_len]),
        }
    }

    fn make_buffer_account(authority: Pubkey, elf_len: usize) -> Account {
        let total = constants::SIZE_OF_BUFFER_METADATA + elf_len;
        let mut data = vec![0u8; total];
        let state = UpgradeableLoaderState::Buffer {
            authority: Some(authority),
        };
        state.serialize_into(&mut data).unwrap();
        // Fill ELF area with fake ELF header
        if elf_len >= 4 {
            data[constants::SIZE_OF_BUFFER_METADATA] = 0x7F;
            data[constants::SIZE_OF_BUFFER_METADATA + 1] = b'E';
            data[constants::SIZE_OF_BUFFER_METADATA + 2] = b'L';
            data[constants::SIZE_OF_BUFFER_METADATA + 3] = b'F';
        }
        Account {
            meta: AccountMeta {
                lamports: 10_000,
                owner: BPF_LOADER_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::from(data),
        }
    }

    fn make_programdata_account(slot: u64, authority: Option<Pubkey>, elf_len: usize) -> Account {
        let total = constants::SIZE_OF_PROGRAMDATA_METADATA + elf_len;
        let mut data = vec![0u8; total];
        let state = UpgradeableLoaderState::ProgramData {
            slot,
            upgrade_authority: authority,
        };
        state.serialize_into(&mut data).unwrap();
        Account {
            meta: AccountMeta {
                lamports: 10_000,
                owner: BPF_LOADER_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::from(data),
        }
    }

    fn make_program_account(programdata_address: Pubkey) -> Account {
        let state = UpgradeableLoaderState::Program {
            programdata_address,
        };
        let data = state.serialize();
        Account {
            meta: AccountMeta {
                lamports: 10_000,
                owner: BPF_LOADER_PROGRAM_ID,
                executable: true,
                rent_epoch: 0,
            },
            data: AccountData::from(data),
        }
    }

    // ── State serialization tests ───────────────────────────────────────

    #[test]
    fn state_uninitialized_roundtrip() {
        let state = UpgradeableLoaderState::Uninitialized;
        let data = state.serialize();
        assert_eq!(data.len(), constants::SIZE_OF_UNINITIALIZED);
        assert_eq!(UpgradeableLoaderState::deserialize(&data).unwrap(), state);
    }

    #[test]
    fn state_buffer_with_authority_roundtrip() {
        let authority = Pubkey::new_unique();
        let state = UpgradeableLoaderState::Buffer {
            authority: Some(authority),
        };
        let data = state.serialize();
        assert_eq!(data.len(), constants::SIZE_OF_BUFFER_METADATA);
        assert_eq!(UpgradeableLoaderState::deserialize(&data).unwrap(), state);
    }

    #[test]
    fn state_buffer_without_authority_roundtrip() {
        let state = UpgradeableLoaderState::Buffer { authority: None };
        let data = state.serialize();
        // With None authority, serialized size is still full metadata
        assert_eq!(data.len(), constants::SIZE_OF_BUFFER_METADATA);
        let deser = UpgradeableLoaderState::deserialize(&data).unwrap();
        assert_eq!(deser, state);
    }

    #[test]
    fn state_program_roundtrip() {
        let programdata = Pubkey::new_unique();
        let state = UpgradeableLoaderState::Program {
            programdata_address: programdata,
        };
        let data = state.serialize();
        assert_eq!(data.len(), constants::SIZE_OF_PROGRAM);
        assert_eq!(UpgradeableLoaderState::deserialize(&data).unwrap(), state);
    }

    #[test]
    fn state_programdata_with_authority_roundtrip() {
        let authority = Pubkey::new_unique();
        let state = UpgradeableLoaderState::ProgramData {
            slot: 42,
            upgrade_authority: Some(authority),
        };
        let data = state.serialize();
        assert_eq!(data.len(), constants::SIZE_OF_PROGRAMDATA_METADATA);
        assert_eq!(UpgradeableLoaderState::deserialize(&data).unwrap(), state);
    }

    #[test]
    fn state_programdata_immutable_roundtrip() {
        let state = UpgradeableLoaderState::ProgramData {
            slot: 99,
            upgrade_authority: None,
        };
        let data = state.serialize();
        assert_eq!(data.len(), constants::SIZE_OF_PROGRAMDATA_METADATA);
        let deser = UpgradeableLoaderState::deserialize(&data).unwrap();
        assert_eq!(deser, state);
    }

    #[test]
    fn state_sizes_match_protocol() {
        assert_eq!(constants::SIZE_OF_UNINITIALIZED, 4);
        assert_eq!(constants::SIZE_OF_BUFFER_METADATA, 37);
        assert_eq!(constants::SIZE_OF_PROGRAM, 36);
        assert_eq!(constants::SIZE_OF_PROGRAMDATA_METADATA, 45);
    }

    #[test]
    fn state_buffer_with_trailing_data_deserializes() {
        let authority = Pubkey::new_unique();
        let state = UpgradeableLoaderState::Buffer {
            authority: Some(authority),
        };
        let mut data = vec![0u8; 1000]; // Buffer account has trailing ELF data
        state.serialize_into(&mut data).unwrap();
        let deser = UpgradeableLoaderState::deserialize(&data).unwrap();
        assert_eq!(deser, state);
    }

    #[test]
    fn state_programdata_with_trailing_data_deserializes() {
        let authority = Pubkey::new_unique();
        let state = UpgradeableLoaderState::ProgramData {
            slot: 100,
            upgrade_authority: Some(authority),
        };
        let mut data = vec![0u8; 5000]; // ProgramData has trailing ELF data
        state.serialize_into(&mut data).unwrap();
        let deser = UpgradeableLoaderState::deserialize(&data).unwrap();
        assert_eq!(deser, state);
    }

    // ── InitializeBuffer tests ──────────────────────────────────────────

    #[test]
    fn initialize_buffer_sets_authority() {
        let executor = BpfLoaderExecutor::new(150);
        let buffer_pubkey = Pubkey::new_unique();
        let authority = Pubkey::new_unique();

        // Uninitialized account with enough space for buffer metadata
        let buffer_account = make_account(10_000, constants::SIZE_OF_BUFFER_METADATA + 1000);

        let instruction_data = constants::INSTRUCTION_INITIALIZE_BUFFER
            .to_le_bytes()
            .to_vec();

        let context = ExecutionContext::new(
            BPF_LOADER_PROGRAM_ID,
            vec![
                (buffer_pubkey, buffer_account, true),
                (authority, Account::default(), false),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert_eq!(
            outcome.compute_units_consumed,
            constants::COMPUTE_COST_INITIALIZE_BUFFER
        );

        let modified = &outcome.modified_accounts[&buffer_pubkey];
        let state = UpgradeableLoaderState::deserialize(modified.data.as_ref()).unwrap();
        assert_eq!(
            state,
            UpgradeableLoaderState::Buffer {
                authority: Some(authority)
            }
        );
    }

    #[test]
    fn initialize_buffer_rejects_already_initialized() {
        let executor = BpfLoaderExecutor::new(150);
        let authority = Pubkey::new_unique();
        let buffer_account = make_buffer_account(authority, 100);

        let instruction_data = constants::INSTRUCTION_INITIALIZE_BUFFER
            .to_le_bytes()
            .to_vec();

        let context = ExecutionContext::new(
            BPF_LOADER_PROGRAM_ID,
            vec![
                (Pubkey::new_unique(), buffer_account, true),
                (authority, Account::default(), false),
            ],
            instruction_data,
        );

        let result = executor.execute(&context);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already initialized"));
    }

    // ── Write tests ─────────────────────────────────────────────────────

    #[test]
    fn write_stores_data_at_offset() {
        let executor = BpfLoaderExecutor::new(150);
        let buffer_pubkey = Pubkey::new_unique();
        let authority = Pubkey::new_unique();
        let buffer_account = make_buffer_account(authority, 100);

        // Write instruction: disc(4) + offset(4) + bytes_len(8) + bytes
        let mut instruction_data = constants::INSTRUCTION_WRITE.to_le_bytes().to_vec();
        instruction_data.extend_from_slice(&10u32.to_le_bytes()); // offset = 10
        let payload = b"hello";
        instruction_data.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        instruction_data.extend_from_slice(payload);

        let context = ExecutionContext::new(
            BPF_LOADER_PROGRAM_ID,
            vec![
                (buffer_pubkey, buffer_account, true),
                (authority, Account::default(), false),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);

        // Verify data written at correct offset
        let modified = &outcome.modified_accounts[&buffer_pubkey];
        let write_start = constants::SIZE_OF_BUFFER_METADATA + 10;
        assert_eq!(
            &modified.data.as_ref()[write_start..write_start + 5],
            b"hello"
        );
    }

    #[test]
    fn write_rejects_wrong_authority() {
        let executor = BpfLoaderExecutor::new(150);
        let authority = Pubkey::new_unique();
        let wrong_authority = Pubkey::new_unique();
        let buffer_account = make_buffer_account(authority, 100);

        let mut instruction_data = constants::INSTRUCTION_WRITE.to_le_bytes().to_vec();
        instruction_data.extend_from_slice(&0u32.to_le_bytes());
        instruction_data.extend_from_slice(&4u64.to_le_bytes());
        instruction_data.extend_from_slice(b"test");

        let context = ExecutionContext::new(
            BPF_LOADER_PROGRAM_ID,
            vec![
                (Pubkey::new_unique(), buffer_account, true),
                (wrong_authority, Account::default(), false),
            ],
            instruction_data,
        );

        let result = executor.execute(&context);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Incorrect buffer authority"));
    }

    #[test]
    fn write_rejects_overflow() {
        let executor = BpfLoaderExecutor::new(150);
        let authority = Pubkey::new_unique();
        let buffer_account = make_buffer_account(authority, 10); // Only 10 bytes for ELF

        let mut instruction_data = constants::INSTRUCTION_WRITE.to_le_bytes().to_vec();
        instruction_data.extend_from_slice(&5u32.to_le_bytes()); // offset 5
        instruction_data.extend_from_slice(&10u64.to_le_bytes()); // 10 bytes → overflows
        instruction_data.extend_from_slice(&[0u8; 10]);

        let context = ExecutionContext::new(
            BPF_LOADER_PROGRAM_ID,
            vec![
                (Pubkey::new_unique(), buffer_account, true),
                (authority, Account::default(), false),
            ],
            instruction_data,
        );

        let result = executor.execute(&context);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("overflow"));
    }

    // ── Deploy tests ────────────────────────────────────────────────────

    #[test]
    fn deploy_creates_program_and_programdata() {
        let executor = BpfLoaderExecutor::new(150);
        let authority = Pubkey::new_unique();
        let program_pubkey = Pubkey::new_unique();
        let programdata_pubkey = Pubkey::new_unique();

        let buffer_account = make_buffer_account(authority, 100);
        let program_account = make_account(10_000, constants::SIZE_OF_PROGRAM);
        let programdata_account = make_account(10_000, 0);

        let mut instruction_data = constants::INSTRUCTION_DEPLOY_WITH_MAX_DATA_LEN
            .to_le_bytes()
            .to_vec();
        instruction_data.extend_from_slice(&200u64.to_le_bytes()); // max_data_len

        let context = ExecutionContext::new(
            BPF_LOADER_PROGRAM_ID,
            vec![
                (Pubkey::new_unique(), Account::default(), true), // payer
                (programdata_pubkey, programdata_account, true),
                (program_pubkey, program_account, true),
                (Pubkey::new_unique(), buffer_account, false), // buffer
            ],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);

        // Verify program account
        let prog = &outcome.modified_accounts[&program_pubkey];
        assert!(prog.meta.executable);
        let prog_state = UpgradeableLoaderState::deserialize(prog.data.as_ref()).unwrap();
        match prog_state {
            UpgradeableLoaderState::Program {
                programdata_address,
            } => {
                assert_eq!(programdata_address, programdata_pubkey);
            }
            _ => panic!("Expected Program state"),
        }

        // Verify programdata account
        let pd = &outcome.modified_accounts[&programdata_pubkey];
        let pd_state = UpgradeableLoaderState::deserialize(pd.data.as_ref()).unwrap();
        match pd_state {
            UpgradeableLoaderState::ProgramData {
                slot,
                upgrade_authority,
            } => {
                assert!(upgrade_authority.is_some());
                // ProgramData should have ELF data
                assert!(pd.data.as_ref().len() > constants::SIZE_OF_PROGRAMDATA_METADATA);
            }
            _ => panic!("Expected ProgramData state"),
        }
    }

    #[test]
    fn deploy_rejects_already_initialized_program() {
        let executor = BpfLoaderExecutor::new(150);
        let authority = Pubkey::new_unique();
        let programdata_pubkey = Pubkey::new_unique();

        let buffer_account = make_buffer_account(authority, 100);
        let program_account = make_program_account(programdata_pubkey);

        let mut instruction_data = constants::INSTRUCTION_DEPLOY_WITH_MAX_DATA_LEN
            .to_le_bytes()
            .to_vec();
        instruction_data.extend_from_slice(&200u64.to_le_bytes());

        let context = ExecutionContext::new(
            BPF_LOADER_PROGRAM_ID,
            vec![
                (Pubkey::new_unique(), Account::default(), true),
                (programdata_pubkey, Account::default(), true),
                (Pubkey::new_unique(), program_account, true),
                (Pubkey::new_unique(), buffer_account, false),
            ],
            instruction_data,
        );

        let result = executor.execute(&context);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already initialized"));
    }

    // ── Upgrade tests ───────────────────────────────────────────────────

    #[test]
    fn upgrade_replaces_program_data() {
        let executor = BpfLoaderExecutor::new(150);
        let authority = Pubkey::new_unique();
        let programdata_pubkey = Pubkey::new_unique();

        let old_pd = make_programdata_account(50, Some(authority), 100);
        let program_account = make_program_account(programdata_pubkey);
        let buffer_account = make_buffer_account(authority, 80);
        let spill_account = make_account(1_000, 0);

        let instruction_data = constants::INSTRUCTION_UPGRADE.to_le_bytes().to_vec();

        let context = ExecutionContext::new(
            BPF_LOADER_PROGRAM_ID,
            vec![
                (programdata_pubkey, old_pd, true),
                (Pubkey::new_unique(), program_account, true),
                (Pubkey::new_unique(), buffer_account, false),
                (Pubkey::new_unique(), spill_account, true),
                (Pubkey::new_unique(), Account::default(), false), // rent
                (Pubkey::new_unique(), Account::default(), false), // clock
                (authority, Account::default(), false),            // authority
            ],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);

        let pd = &outcome.modified_accounts[&programdata_pubkey];
        let pd_state = UpgradeableLoaderState::deserialize(pd.data.as_ref()).unwrap();
        match pd_state {
            UpgradeableLoaderState::ProgramData {
                upgrade_authority, ..
            } => {
                assert_eq!(upgrade_authority, Some(authority));
            }
            _ => panic!("Expected ProgramData state"),
        }
    }

    #[test]
    fn upgrade_rejects_immutable_program() {
        let executor = BpfLoaderExecutor::new(150);
        let authority = Pubkey::new_unique();
        let programdata_pubkey = Pubkey::new_unique();

        // ProgramData with no upgrade authority (immutable)
        let old_pd = make_programdata_account(50, None, 100);
        let program_account = make_program_account(programdata_pubkey);
        let buffer_account = make_buffer_account(authority, 80);

        let instruction_data = constants::INSTRUCTION_UPGRADE.to_le_bytes().to_vec();

        let context = ExecutionContext::new(
            BPF_LOADER_PROGRAM_ID,
            vec![
                (programdata_pubkey, old_pd, true),
                (Pubkey::new_unique(), program_account, true),
                (Pubkey::new_unique(), buffer_account, false),
                (Pubkey::new_unique(), Account::default(), true),
            ],
            instruction_data,
        );

        let result = executor.execute(&context);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not upgradeable"));
    }

    // ── SetAuthority tests ──────────────────────────────────────────────

    #[test]
    fn set_authority_on_buffer() {
        let executor = BpfLoaderExecutor::new(150);
        let old_authority = Pubkey::new_unique();
        let new_authority = Pubkey::new_unique();
        let buffer_pubkey = Pubkey::new_unique();
        let buffer_account = make_buffer_account(old_authority, 100);

        let instruction_data = constants::INSTRUCTION_SET_AUTHORITY.to_le_bytes().to_vec();

        let context = ExecutionContext::new(
            BPF_LOADER_PROGRAM_ID,
            vec![
                (buffer_pubkey, buffer_account, true),
                (old_authority, Account::default(), false),
                (new_authority, Account::default(), false),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);

        let modified = &outcome.modified_accounts[&buffer_pubkey];
        let state = UpgradeableLoaderState::deserialize(modified.data.as_ref()).unwrap();
        assert_eq!(
            state,
            UpgradeableLoaderState::Buffer {
                authority: Some(new_authority)
            }
        );
    }

    #[test]
    fn set_authority_makes_program_immutable() {
        let executor = BpfLoaderExecutor::new(150);
        let authority = Pubkey::new_unique();
        let pd_pubkey = Pubkey::new_unique();
        let pd_account = make_programdata_account(100, Some(authority), 200);

        let instruction_data = constants::INSTRUCTION_SET_AUTHORITY.to_le_bytes().to_vec();

        // Only 2 accounts = no new authority → immutable
        let context = ExecutionContext::new(
            BPF_LOADER_PROGRAM_ID,
            vec![
                (pd_pubkey, pd_account, true),
                (authority, Account::default(), false),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);

        let modified = &outcome.modified_accounts[&pd_pubkey];
        let state = UpgradeableLoaderState::deserialize(modified.data.as_ref()).unwrap();
        match state {
            UpgradeableLoaderState::ProgramData {
                upgrade_authority, ..
            } => {
                assert_eq!(upgrade_authority, None);
            }
            _ => panic!("Expected ProgramData state"),
        }
    }

    #[test]
    fn set_authority_rejects_wrong_authority() {
        let executor = BpfLoaderExecutor::new(150);
        let authority = Pubkey::new_unique();
        let wrong = Pubkey::new_unique();
        let buffer_account = make_buffer_account(authority, 100);

        let instruction_data = constants::INSTRUCTION_SET_AUTHORITY.to_le_bytes().to_vec();

        let context = ExecutionContext::new(
            BPF_LOADER_PROGRAM_ID,
            vec![
                (Pubkey::new_unique(), buffer_account, true),
                (wrong, Account::default(), false),
                (Pubkey::new_unique(), Account::default(), false),
            ],
            instruction_data,
        );

        let result = executor.execute(&context);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Incorrect"));
    }

    // ── SetAuthorityChecked tests ───────────────────────────────────────

    #[test]
    fn set_authority_checked_requires_both_signers() {
        let executor = BpfLoaderExecutor::new(150);
        let old_auth = Pubkey::new_unique();
        let new_auth = Pubkey::new_unique();
        let buffer_pubkey = Pubkey::new_unique();
        let buffer_account = make_buffer_account(old_auth, 100);

        let instruction_data = constants::INSTRUCTION_SET_AUTHORITY_CHECKED
            .to_le_bytes()
            .to_vec();

        let context = ExecutionContext::new(
            BPF_LOADER_PROGRAM_ID,
            vec![
                (buffer_pubkey, buffer_account, true),
                (old_auth, Account::default(), false),
                (new_auth, Account::default(), false),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);

        let modified = &outcome.modified_accounts[&buffer_pubkey];
        let state = UpgradeableLoaderState::deserialize(modified.data.as_ref()).unwrap();
        assert_eq!(
            state,
            UpgradeableLoaderState::Buffer {
                authority: Some(new_auth)
            }
        );
    }

    // ── Close tests ─────────────────────────────────────────────────────

    #[test]
    fn close_buffer_transfers_lamports() {
        let executor = BpfLoaderExecutor::new(150);
        let authority = Pubkey::new_unique();
        let buffer_pubkey = Pubkey::new_unique();
        let recipient_pubkey = Pubkey::new_unique();

        let mut buffer_account = make_buffer_account(authority, 100);
        buffer_account.meta.lamports = 5_000;
        let recipient_account = make_account(1_000, 0);

        let instruction_data = constants::INSTRUCTION_CLOSE.to_le_bytes().to_vec();

        let context = ExecutionContext::new(
            BPF_LOADER_PROGRAM_ID,
            vec![
                (buffer_pubkey, buffer_account, true),
                (recipient_pubkey, recipient_account, true),
                (authority, Account::default(), false),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);

        let closed = &outcome.modified_accounts[&buffer_pubkey];
        assert_eq!(closed.meta.lamports, 0);
        let state = UpgradeableLoaderState::deserialize(closed.data.as_ref()).unwrap();
        assert!(state.is_uninitialized());

        let recipient = &outcome.modified_accounts[&recipient_pubkey];
        assert_eq!(recipient.meta.lamports, 6_000);
    }

    #[test]
    fn close_rejects_immutable_buffer() {
        let executor = BpfLoaderExecutor::new(150);
        let buffer_pubkey = Pubkey::new_unique();

        // Buffer with no authority
        let mut data = vec![0u8; constants::SIZE_OF_BUFFER_METADATA + 100];
        let state = UpgradeableLoaderState::Buffer { authority: None };
        state.serialize_into(&mut data).unwrap();
        let buffer_account = Account {
            meta: AccountMeta {
                lamports: 5_000,
                owner: BPF_LOADER_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::from(data),
        };

        let instruction_data = constants::INSTRUCTION_CLOSE.to_le_bytes().to_vec();

        let context = ExecutionContext::new(
            BPF_LOADER_PROGRAM_ID,
            vec![
                (buffer_pubkey, buffer_account, true),
                (Pubkey::new_unique(), make_account(1_000, 0), true),
                (Pubkey::new_unique(), Account::default(), false),
            ],
            instruction_data,
        );

        let result = executor.execute(&context);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("immutable"));
    }

    #[test]
    fn close_rejects_same_recipient() {
        let executor = BpfLoaderExecutor::new(150);
        let authority = Pubkey::new_unique();
        let account_pubkey = Pubkey::new_unique();
        let buffer_account = make_buffer_account(authority, 100);

        let instruction_data = constants::INSTRUCTION_CLOSE.to_le_bytes().to_vec();

        let context = ExecutionContext::new(
            BPF_LOADER_PROGRAM_ID,
            vec![
                (account_pubkey, buffer_account, true),
                (account_pubkey, make_account(1_000, 0), true),
                (authority, Account::default(), false),
            ],
            instruction_data,
        );

        let result = executor.execute(&context);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("same as the account"));
    }

    // ── ExtendProgram tests ─────────────────────────────────────────────

    #[test]
    fn extend_program_increases_data_len() {
        let executor = BpfLoaderExecutor::new(150);
        let authority = Pubkey::new_unique();
        let pd_pubkey = Pubkey::new_unique();

        let pd_account = make_programdata_account(50, Some(authority), 100);
        let program_account = make_program_account(pd_pubkey);

        let mut instruction_data = constants::INSTRUCTION_EXTEND_PROGRAM.to_le_bytes().to_vec();
        instruction_data.extend_from_slice(&200u32.to_le_bytes()); // +200 bytes

        let context = ExecutionContext::new(
            BPF_LOADER_PROGRAM_ID,
            vec![
                (pd_pubkey, pd_account.clone(), true),
                (Pubkey::new_unique(), program_account, false),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);

        let modified = &outcome.modified_accounts[&pd_pubkey];
        let old_len = pd_account.data.as_ref().len();
        assert_eq!(modified.data.as_ref().len(), old_len + 200);
    }

    #[test]
    fn extend_program_rejects_zero_bytes() {
        let executor = BpfLoaderExecutor::new(150);
        let authority = Pubkey::new_unique();
        let pd_pubkey = Pubkey::new_unique();

        let pd_account = make_programdata_account(50, Some(authority), 100);
        let program_account = make_program_account(pd_pubkey);

        let mut instruction_data = constants::INSTRUCTION_EXTEND_PROGRAM.to_le_bytes().to_vec();
        instruction_data.extend_from_slice(&0u32.to_le_bytes());

        let context = ExecutionContext::new(
            BPF_LOADER_PROGRAM_ID,
            vec![
                (pd_pubkey, pd_account, true),
                (Pubkey::new_unique(), program_account, false),
            ],
            instruction_data,
        );

        let result = executor.execute(&context);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must be greater than 0"));
    }

    #[test]
    fn extend_program_rejects_immutable() {
        let executor = BpfLoaderExecutor::new(150);
        let pd_pubkey = Pubkey::new_unique();

        let pd_account = make_programdata_account(50, None, 100); // No authority
        let program_account = make_program_account(pd_pubkey);

        let mut instruction_data = constants::INSTRUCTION_EXTEND_PROGRAM.to_le_bytes().to_vec();
        instruction_data.extend_from_slice(&100u32.to_le_bytes());

        let context = ExecutionContext::new(
            BPF_LOADER_PROGRAM_ID,
            vec![
                (pd_pubkey, pd_account, true),
                (Pubkey::new_unique(), program_account, false),
            ],
            instruction_data,
        );

        let result = executor.execute(&context);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not upgradeable"));
    }

    // ── Full lifecycle test ─────────────────────────────────────────────

    #[test]
    fn full_lifecycle_initialize_write_deploy_upgrade_close() {
        let executor = BpfLoaderExecutor::new(150);
        let authority = Pubkey::new_unique();
        let buffer_pubkey = Pubkey::new_unique();
        let program_pubkey = Pubkey::new_unique();
        let programdata_pubkey = Pubkey::new_unique();

        // Step 1: Initialize buffer
        let mut buffer_account = make_account(10_000, constants::SIZE_OF_BUFFER_METADATA + 200);
        let init_data = constants::INSTRUCTION_INITIALIZE_BUFFER
            .to_le_bytes()
            .to_vec();

        let ctx = ExecutionContext::new(
            BPF_LOADER_PROGRAM_ID,
            vec![
                (buffer_pubkey, buffer_account.clone(), true),
                (authority, Account::default(), false),
            ],
            init_data,
        );
        let outcome = executor.execute(&ctx).unwrap();
        buffer_account = outcome.modified_accounts[&buffer_pubkey].clone();

        // Step 2: Write ELF data
        let elf_data = vec![0x7F, 0x45, 0x4C, 0x46, 1, 2, 3, 4, 5, 6];
        let mut write_data = constants::INSTRUCTION_WRITE.to_le_bytes().to_vec();
        write_data.extend_from_slice(&0u32.to_le_bytes());
        write_data.extend_from_slice(&(elf_data.len() as u64).to_le_bytes());
        write_data.extend_from_slice(&elf_data);

        let ctx = ExecutionContext::new(
            BPF_LOADER_PROGRAM_ID,
            vec![
                (buffer_pubkey, buffer_account.clone(), true),
                (authority, Account::default(), false),
            ],
            write_data,
        );
        let outcome = executor.execute(&ctx).unwrap();
        buffer_account = outcome.modified_accounts[&buffer_pubkey].clone();

        // Verify ELF data written
        assert_eq!(
            &buffer_account.data.as_ref()
                [constants::SIZE_OF_BUFFER_METADATA..constants::SIZE_OF_BUFFER_METADATA + 10],
            &elf_data
        );

        // Step 3: Deploy
        let program_account = make_account(10_000, constants::SIZE_OF_PROGRAM);
        let programdata_account = make_account(10_000, 0);

        let mut deploy_data = constants::INSTRUCTION_DEPLOY_WITH_MAX_DATA_LEN
            .to_le_bytes()
            .to_vec();
        deploy_data.extend_from_slice(&200u64.to_le_bytes());

        let ctx = ExecutionContext::new(
            BPF_LOADER_PROGRAM_ID,
            vec![
                (Pubkey::new_unique(), Account::default(), true), // payer
                (programdata_pubkey, programdata_account, true),
                (program_pubkey, program_account, true),
                (buffer_pubkey, buffer_account, false),
            ],
            deploy_data,
        );
        let outcome = executor.execute(&ctx).unwrap();

        let program_account = outcome.modified_accounts[&program_pubkey].clone();
        assert!(program_account.meta.executable);

        let programdata_account = outcome.modified_accounts[&programdata_pubkey].clone();

        // Verify ELF data is in programdata
        assert_eq!(
            &programdata_account.data.as_ref()[constants::SIZE_OF_PROGRAMDATA_METADATA
                ..constants::SIZE_OF_PROGRAMDATA_METADATA + 10],
            &elf_data
        );

        // Step 4: Upgrade with new data
        let new_elf = vec![0x7F, 0x45, 0x4C, 0x46, 9, 8, 7, 6];
        let mut new_buffer_data = vec![0u8; constants::SIZE_OF_BUFFER_METADATA + new_elf.len()];
        UpgradeableLoaderState::Buffer {
            authority: Some(authority),
        }
        .serialize_into(&mut new_buffer_data)
        .unwrap();
        new_buffer_data[constants::SIZE_OF_BUFFER_METADATA..].copy_from_slice(&new_elf);
        let new_buffer = Account {
            meta: AccountMeta {
                lamports: 5_000,
                owner: BPF_LOADER_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::from(new_buffer_data),
        };

        let upgrade_data = constants::INSTRUCTION_UPGRADE.to_le_bytes().to_vec();
        let spill_account = make_account(1_000, 0);

        let ctx = ExecutionContext::new(
            BPF_LOADER_PROGRAM_ID,
            vec![
                (programdata_pubkey, programdata_account, true),
                (program_pubkey, program_account, true),
                (Pubkey::new_unique(), new_buffer, false),
                (Pubkey::new_unique(), spill_account, true),
                (Pubkey::new_unique(), Account::default(), false),
                (Pubkey::new_unique(), Account::default(), false),
                (authority, Account::default(), false),
            ],
            upgrade_data,
        );
        let outcome = executor.execute(&ctx).unwrap();
        assert!(outcome.success);

        let upgraded_pd = &outcome.modified_accounts[&programdata_pubkey];
        assert_eq!(
            &upgraded_pd.data.as_ref()[constants::SIZE_OF_PROGRAMDATA_METADATA
                ..constants::SIZE_OF_PROGRAMDATA_METADATA + new_elf.len()],
            &new_elf
        );
    }

    // ── Instruction dispatch tests ──────────────────────────────────────

    #[test]
    fn unknown_instruction_rejected() {
        let executor = BpfLoaderExecutor::new(150);
        let instruction_data = 255u32.to_le_bytes().to_vec();
        let context = ExecutionContext::new(
            BPF_LOADER_PROGRAM_ID,
            vec![(Pubkey::new_unique(), Account::default(), true)],
            instruction_data,
        );
        let result = executor.execute(&context);
        assert!(result.is_err());
    }

    #[test]
    fn empty_instruction_returns_success() {
        let executor = BpfLoaderExecutor::new(150);
        let context = ExecutionContext::new(
            BPF_LOADER_PROGRAM_ID,
            vec![(Pubkey::new_unique(), Account::default(), true)],
            vec![],
        );
        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert_eq!(outcome.compute_units_consumed, 150);
    }

    #[test]
    fn instruction_data_too_short_rejected() {
        let executor = BpfLoaderExecutor::new(150);
        let context = ExecutionContext::new(
            BPF_LOADER_PROGRAM_ID,
            vec![(Pubkey::new_unique(), Account::default(), true)],
            vec![1, 2], // Only 2 bytes, need at least 4
        );
        let result = executor.execute(&context);
        assert!(result.is_err());
    }
}
