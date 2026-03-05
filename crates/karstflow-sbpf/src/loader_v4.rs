//! Loader V4 program implementation.
//!
//! Manages the lifecycle of on-chain BPF programs through the next-generation
//! loader. Programs go through several states: uninitialized → retracted →
//! deployed → (optionally) finalized. The loader supports writing ELF data,
//! copying from existing programs, deploying (with ELF verification), and
//! transferring authority.

use crate::{ExecutionContext, ExecutionOutcome};
use karstflow_constants::loader_v4 as constants;
use karstflow_ids::{
    BPF_LOADER_DEPRECATED_PROGRAM_ID, BPF_LOADER_PROGRAM_ID, BPF_LOADER_V2_PROGRAM_ID,
    LOADER_V4_PROGRAM_ID,
};
use karstflow_types::{Account, AccountData, Pubkey};
use std::collections::HashMap;

/// On-chain state stored in the first 48 bytes of a loader v4 program account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoaderV4State {
    /// Deployment slot (used for cooldown checks). Zero if never deployed.
    pub slot: u64,
    /// Program lifecycle status (retracted, deployed, or finalized).
    pub status: u64,
    /// Authority pubkey (for retracted/deployed) or next-version address (for finalized).
    pub authority_or_next_version: Pubkey,
}

impl LoaderV4State {
    /// Deserialize the state from the first 48 bytes of account data.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < constants::PROGRAM_DATA_OFFSET {
            return None;
        }
        let slot = u64::from_le_bytes(data[0..8].try_into().ok()?);
        let status = u64::from_le_bytes(data[8..16].try_into().ok()?);
        let authority_bytes: [u8; 32] = data[16..48].try_into().ok()?;
        Some(Self {
            slot,
            status,
            authority_or_next_version: Pubkey::new(authority_bytes),
        })
    }

    /// Serialize the state into the first 48 bytes of account data.
    pub fn write_to(&self, data: &mut [u8]) {
        data[0..8].copy_from_slice(&self.slot.to_le_bytes());
        data[8..16].copy_from_slice(&self.status.to_le_bytes());
        data[16..48].copy_from_slice(self.authority_or_next_version.as_bytes());
    }

    pub fn is_retracted(&self) -> bool {
        self.status == constants::STATUS_RETRACTED
    }

    pub fn is_deployed(&self) -> bool {
        self.status == constants::STATUS_DEPLOYED
    }

    pub fn is_finalized(&self) -> bool {
        self.status == constants::STATUS_FINALIZED
    }
}

/// Errors specific to loader v4 program execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoaderV4Error {
    InvalidInstruction,
    InsufficientAccounts,
    AccountDataTooSmall,
    NotOwnedByLoader,
    ProgramNotWritable,
    AuthorityDidNotSign,
    IncorrectAuthority,
    ProgramFinalized,
    ProgramNotRetracted,
    ProgramNotDeployed,
    CooldownInEffect,
    WriteOutOfBounds,
    ReadOutOfBounds,
    SourceNotAProgram,
    InsufficientLamports,
    RecipientNotWritable,
    RecipientRequired,
    NewAuthorityDidNotSign,
    NoChange,
    NextVersionNotOwnedByLoader,
    NextVersionDifferentAuthority,
    NextVersionFinalized,
    DeployVerificationFailed,
}

impl LoaderV4Error {
    fn message(&self) -> &'static str {
        match self {
            Self::InvalidInstruction => "Invalid instruction data",
            Self::InsufficientAccounts => "Not enough accounts provided",
            Self::AccountDataTooSmall => "Account data too small",
            Self::NotOwnedByLoader => "Program not owned by loader",
            Self::ProgramNotWritable => "Program is not writeable",
            Self::AuthorityDidNotSign => "Authority did not sign",
            Self::IncorrectAuthority => "Incorrect authority provided",
            Self::ProgramFinalized => "Program is finalized",
            Self::ProgramNotRetracted => "Program is not retracted",
            Self::ProgramNotDeployed => "Program is not deployed",
            Self::CooldownInEffect => "Program was deployed recently, cooldown still in effect",
            Self::WriteOutOfBounds => "Write out of bounds",
            Self::ReadOutOfBounds => "Read out of bounds",
            Self::SourceNotAProgram => "Source is not a program",
            Self::InsufficientLamports => "Insufficient lamports",
            Self::RecipientNotWritable => "Recipient is not writeable",
            Self::RecipientRequired => "Closing a program requires a recipient account",
            Self::NewAuthorityDidNotSign => "New authority did not sign",
            Self::NoChange => "No change",
            Self::NextVersionNotOwnedByLoader => "Next version is not owned by loader",
            Self::NextVersionDifferentAuthority => "Next version has a different authority",
            Self::NextVersionFinalized => "Next version is finalized",
            Self::DeployVerificationFailed => "ELF verification failed",
        }
    }
}

/// Executor for the Loader V4 program.
pub struct LoaderV4Executor {
    base_cost: u64,
}

impl LoaderV4Executor {
    pub fn new(base_cost: u64) -> Self {
        Self { base_cost }
    }

    pub fn execute(&self, ctx: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        let compute_used = self
            .base_cost
            .saturating_add(constants::DEFAULT_COMPUTE_UNITS);

        if ctx.instruction_data.len() < 4 {
            return Err(LoaderV4Error::InvalidInstruction.message().to_string());
        }

        let discriminant = u32::from_le_bytes(
            ctx.instruction_data[0..4]
                .try_into()
                .map_err(|_| LoaderV4Error::InvalidInstruction.message())?,
        );

        match discriminant {
            constants::INSTRUCTION_WRITE => self.process_write(ctx, compute_used),
            constants::INSTRUCTION_COPY => self.process_copy(ctx, compute_used),
            constants::INSTRUCTION_SET_PROGRAM_LENGTH => {
                self.process_set_program_length(ctx, compute_used)
            }
            constants::INSTRUCTION_DEPLOY => self.process_deploy(ctx, compute_used),
            constants::INSTRUCTION_RETRACT => self.process_retract(ctx, compute_used),
            constants::INSTRUCTION_TRANSFER_AUTHORITY => {
                self.process_transfer_authority(ctx, compute_used)
            }
            constants::INSTRUCTION_FINALIZE => self.process_finalize(ctx, compute_used),
            _ => Err(format!("Unknown loader v4 instruction: {}", discriminant)),
        }
    }

    /// Validate the program account state, checking ownership, writability,
    /// authority signature, and that the program is not finalized.
    /// Returns the parsed state on success.
    fn check_program_account(
        &self,
        ctx: &ExecutionContext,
    ) -> Result<(LoaderV4State, Pubkey), String> {
        if ctx.accounts.len() < 2 {
            return Err(LoaderV4Error::InsufficientAccounts.message().to_string());
        }

        let (_program_pubkey, program_account, program_writable) = &ctx.accounts[0];
        let (authority_pubkey, _authority_account, _) = &ctx.accounts[1];

        // Must be owned by loader v4
        if program_account.meta.owner != LOADER_V4_PROGRAM_ID {
            return Err(LoaderV4Error::NotOwnedByLoader.message().to_string());
        }

        // Must be writable
        if !program_writable {
            return Err(LoaderV4Error::ProgramNotWritable.message().to_string());
        }

        // Parse state
        let state = LoaderV4State::from_bytes(program_account.data.as_ref())
            .ok_or_else(|| LoaderV4Error::AccountDataTooSmall.message().to_string())?;

        // Check authority matches
        if state.authority_or_next_version != *authority_pubkey {
            return Err(LoaderV4Error::IncorrectAuthority.message().to_string());
        }

        // Cannot modify finalized programs
        if state.is_finalized() {
            return Err(LoaderV4Error::ProgramFinalized.message().to_string());
        }

        Ok((state, *authority_pubkey))
    }

    /// Write ELF data into an undeployed (retracted) program account.
    ///
    /// Accounts: [0] program (writable), [1] authority (signer)
    /// Data: [4 bytes discriminant] [4 bytes offset] [N bytes data]
    fn process_write(
        &self,
        ctx: &ExecutionContext,
        compute_used: u64,
    ) -> Result<ExecutionOutcome, String> {
        let (state, _authority) = self.check_program_account(ctx)?;

        if !state.is_retracted() {
            return Err(LoaderV4Error::ProgramNotRetracted.message().to_string());
        }

        // Parse: offset (u32) + bytes
        if ctx.instruction_data.len() < 8 {
            return Err(LoaderV4Error::InvalidInstruction.message().to_string());
        }

        let offset = u32::from_le_bytes(
            ctx.instruction_data[4..8]
                .try_into()
                .map_err(|_| LoaderV4Error::InvalidInstruction.message())?,
        ) as usize;

        let bytes = &ctx.instruction_data[8..];
        let dest_offset = offset.saturating_add(constants::PROGRAM_DATA_OFFSET);

        let (program_pubkey, program_account, _) = &ctx.accounts[0];
        let data_len = program_account.data.len();

        if dest_offset.saturating_add(bytes.len()) > data_len {
            return Err(LoaderV4Error::WriteOutOfBounds.message().to_string());
        }

        let mut new_program = program_account.clone();
        if !bytes.is_empty() {
            let data_mut = new_program.data.as_mut_slice();
            data_mut[dest_offset..dest_offset + bytes.len()].copy_from_slice(bytes);
        }

        let mut outcome = ExecutionOutcome::success(compute_used);
        outcome
            .modified_accounts
            .insert(*program_pubkey, new_program);
        outcome.logs.push(format!(
            "LoaderV4: Wrote {} bytes at offset {}",
            bytes.len(),
            offset
        ));
        Ok(outcome)
    }

    /// Copy ELF data from a source program account into the target.
    ///
    /// Accounts: [0] program (writable), [1] authority (signer), [2] source program
    /// Data: [4 bytes discriminant] [4 bytes dest_offset] [4 bytes source_offset] [4 bytes length]
    fn process_copy(
        &self,
        ctx: &ExecutionContext,
        compute_used: u64,
    ) -> Result<ExecutionOutcome, String> {
        let (state, _authority) = self.check_program_account(ctx)?;

        if !state.is_retracted() {
            return Err(LoaderV4Error::ProgramNotRetracted.message().to_string());
        }

        if ctx.accounts.len() < 3 {
            return Err(LoaderV4Error::InsufficientAccounts.message().to_string());
        }

        if ctx.instruction_data.len() < 16 {
            return Err(LoaderV4Error::InvalidInstruction.message().to_string());
        }

        let dest_offset = u32::from_le_bytes(
            ctx.instruction_data[4..8]
                .try_into()
                .map_err(|_| LoaderV4Error::InvalidInstruction.message())?,
        ) as usize;

        let mut source_offset = u32::from_le_bytes(
            ctx.instruction_data[8..12]
                .try_into()
                .map_err(|_| LoaderV4Error::InvalidInstruction.message())?,
        ) as usize;

        let length = u32::from_le_bytes(
            ctx.instruction_data[12..16]
                .try_into()
                .map_err(|_| LoaderV4Error::InvalidInstruction.message())?,
        ) as usize;

        let (_source_pubkey, source_account, _) = &ctx.accounts[2];

        // Adjust source offset based on the source program's loader type
        let source_owner = source_account.meta.owner;
        if source_owner == LOADER_V4_PROGRAM_ID {
            source_offset = source_offset.saturating_add(constants::PROGRAM_DATA_OFFSET);
        } else if source_owner == BPF_LOADER_PROGRAM_ID {
            source_offset =
                source_offset.saturating_add(constants::UPGRADEABLE_PROGRAMDATA_METADATA_SIZE);
        } else if source_owner != BPF_LOADER_DEPRECATED_PROGRAM_ID
            && source_owner != BPF_LOADER_V2_PROGRAM_ID
        {
            return Err(LoaderV4Error::SourceNotAProgram.message().to_string());
        }

        // Bounds check on source
        if source_offset.saturating_add(length) > source_account.data.len() {
            return Err(LoaderV4Error::ReadOutOfBounds.message().to_string());
        }

        // Bounds check on destination
        let actual_dest_offset = dest_offset.saturating_add(constants::PROGRAM_DATA_OFFSET);
        let (program_pubkey, program_account, _) = &ctx.accounts[0];

        if actual_dest_offset.saturating_add(length) > program_account.data.len() {
            return Err(LoaderV4Error::WriteOutOfBounds.message().to_string());
        }

        // Copy data
        let source_data = &source_account.data.as_ref()[source_offset..source_offset + length];
        let mut new_program = program_account.clone();
        let data_mut = new_program.data.as_mut_slice();
        data_mut[actual_dest_offset..actual_dest_offset + length].copy_from_slice(source_data);

        let mut outcome = ExecutionOutcome::success(compute_used);
        outcome
            .modified_accounts
            .insert(*program_pubkey, new_program);
        outcome
            .logs
            .push(format!("LoaderV4: Copied {} bytes from source", length));
        Ok(outcome)
    }

    /// Resize a program account. If the new size is zero, the account is closed.
    /// On first initialization, sets the executable flag and creates the initial state.
    ///
    /// Accounts: [0] program (writable), [1] authority (signer),
    ///           [2] recipient (writable, optional - for excess lamports)
    /// Data: [4 bytes discriminant] [4 bytes new_size]
    fn process_set_program_length(
        &self,
        ctx: &ExecutionContext,
        compute_used: u64,
    ) -> Result<ExecutionOutcome, String> {
        if ctx.accounts.len() < 2 {
            return Err(LoaderV4Error::InsufficientAccounts.message().to_string());
        }

        if ctx.instruction_data.len() < 8 {
            return Err(LoaderV4Error::InvalidInstruction.message().to_string());
        }

        let new_size = u32::from_le_bytes(
            ctx.instruction_data[4..8]
                .try_into()
                .map_err(|_| LoaderV4Error::InvalidInstruction.message())?,
        ) as usize;

        let (program_pubkey, program_account, program_writable) = &ctx.accounts[0];
        let (authority_pubkey, _authority_account, _) = &ctx.accounts[1];

        let is_initialization = program_account.data.len() < constants::PROGRAM_DATA_OFFSET;

        if is_initialization {
            // First-time setup: validate ownership & writability directly
            if program_account.meta.owner != LOADER_V4_PROGRAM_ID {
                return Err(LoaderV4Error::NotOwnedByLoader.message().to_string());
            }
            if !program_writable {
                return Err(LoaderV4Error::ProgramNotWritable.message().to_string());
            }
        } else {
            // Already initialized: full state check
            let (state, _) = self.check_program_account(ctx)?;
            if !state.is_retracted() {
                return Err(LoaderV4Error::ProgramNotRetracted.message().to_string());
            }
        }

        let new_program_dlen = if new_size == 0 {
            0
        } else {
            constants::PROGRAM_DATA_OFFSET + new_size
        };

        // Calculate required lamports (simplified rent exemption)
        let required_lamports = if new_size == 0 {
            0u64
        } else {
            let rent_per_byte = 6_960u64; // lamports per byte for rent exemption
            let base = 890_880u64;
            base.saturating_add(rent_per_byte.saturating_mul(new_program_dlen as u64))
                .max(1)
        };

        let program_lamports = program_account.meta.lamports;
        let mut modified_accounts = HashMap::new();

        if program_lamports < required_lamports {
            return Err(format!(
                "{}: {} are required",
                LoaderV4Error::InsufficientLamports.message(),
                required_lamports
            ));
        }

        let mut new_program = program_account.clone();

        // Handle excess lamports transfer
        if program_lamports > required_lamports {
            let lamports_to_transfer = program_lamports.saturating_sub(required_lamports);

            if ctx.accounts.len() >= 3 {
                let (recipient_pubkey, recipient_account, recipient_writable) = &ctx.accounts[2];
                if !recipient_writable {
                    return Err(LoaderV4Error::RecipientNotWritable.message().to_string());
                }
                new_program.meta.lamports = required_lamports;
                let mut new_recipient = recipient_account.clone();
                new_recipient.meta.lamports = new_recipient
                    .meta
                    .lamports
                    .saturating_add(lamports_to_transfer);
                modified_accounts.insert(*recipient_pubkey, new_recipient);
            } else if new_size == 0 {
                return Err(LoaderV4Error::RecipientRequired.message().to_string());
            }
        }

        // Resize the account
        if new_size == 0 {
            new_program.data = AccountData::empty();
            new_program.meta.lamports = 0;
        } else {
            new_program.data.resize(new_program_dlen, 0);

            if is_initialization {
                new_program.meta.executable = true;
                let state = LoaderV4State {
                    slot: 0,
                    status: constants::STATUS_RETRACTED,
                    authority_or_next_version: *authority_pubkey,
                };
                state.write_to(new_program.data.as_mut_slice());
            }
        }

        modified_accounts.insert(*program_pubkey, new_program);

        let mut outcome = ExecutionOutcome::success(compute_used);
        outcome.modified_accounts = modified_accounts;
        outcome.logs.push(format!(
            "LoaderV4: Set program length to {} (total account: {})",
            new_size, new_program_dlen
        ));
        Ok(outcome)
    }

    /// Deploy a retracted program by verifying its ELF and marking it as deployed.
    ///
    /// Accounts: [0] program (writable), [1] authority (signer)
    fn process_deploy(
        &self,
        ctx: &ExecutionContext,
        compute_used: u64,
    ) -> Result<ExecutionOutcome, String> {
        let (state, _authority) = self.check_program_account(ctx)?;

        // Get current slot from sysvar snapshot
        let current_slot = ctx.sysvar_snapshot.as_ref().map(|s| s.slot).unwrap_or(0);

        // Cooldown check: skip if never deployed (slot == 0)
        if state.slot != 0
            && state
                .slot
                .saturating_add(constants::DEPLOYMENT_COOLDOWN_SLOTS)
                > current_slot
        {
            return Err(LoaderV4Error::CooldownInEffect.message().to_string());
        }

        if !state.is_retracted() {
            return Err(LoaderV4Error::ProgramNotRetracted.message().to_string());
        }

        let (program_pubkey, program_account, _) = &ctx.accounts[0];

        if program_account.data.len() < constants::PROGRAM_DATA_OFFSET {
            return Err(LoaderV4Error::AccountDataTooSmall.message().to_string());
        }

        // ELF verification: check for ELF magic bytes
        let elf_data = &program_account.data.as_ref()[constants::PROGRAM_DATA_OFFSET..];
        if elf_data.len() < 4 || &elf_data[0..4] != b"\x7fELF" {
            return Err(LoaderV4Error::DeployVerificationFailed
                .message()
                .to_string());
        }

        // Update state to deployed
        let mut new_program = program_account.clone();
        let mut new_state = state;
        new_state.slot = current_slot;
        new_state.status = constants::STATUS_DEPLOYED;
        new_state.write_to(new_program.data.as_mut_slice());

        let mut outcome = ExecutionOutcome::success(compute_used);
        outcome
            .modified_accounts
            .insert(*program_pubkey, new_program);
        outcome.logs.push(format!(
            "LoaderV4: Deployed program at slot {}",
            current_slot
        ));
        Ok(outcome)
    }

    /// Retract a deployed program, making it writable again.
    ///
    /// Accounts: [0] program (writable), [1] authority (signer)
    fn process_retract(
        &self,
        ctx: &ExecutionContext,
        compute_used: u64,
    ) -> Result<ExecutionOutcome, String> {
        let (state, _authority) = self.check_program_account(ctx)?;

        let current_slot = ctx.sysvar_snapshot.as_ref().map(|s| s.slot).unwrap_or(0);

        // Cooldown check
        if state
            .slot
            .saturating_add(constants::DEPLOYMENT_COOLDOWN_SLOTS)
            > current_slot
        {
            return Err(LoaderV4Error::CooldownInEffect.message().to_string());
        }

        if !state.is_deployed() {
            return Err(LoaderV4Error::ProgramNotDeployed.message().to_string());
        }

        let (program_pubkey, program_account, _) = &ctx.accounts[0];
        let mut new_program = program_account.clone();
        let mut new_state = state;
        new_state.status = constants::STATUS_RETRACTED;
        new_state.write_to(new_program.data.as_mut_slice());

        let mut outcome = ExecutionOutcome::success(compute_used);
        outcome
            .modified_accounts
            .insert(*program_pubkey, new_program);
        outcome.logs.push("LoaderV4: Retracted program".to_string());
        Ok(outcome)
    }

    /// Transfer authority of a program to a new signer.
    ///
    /// Accounts: [0] program (writable), [1] current authority (signer), [2] new authority (signer)
    fn process_transfer_authority(
        &self,
        ctx: &ExecutionContext,
        compute_used: u64,
    ) -> Result<ExecutionOutcome, String> {
        let (_state, _authority) = self.check_program_account(ctx)?;

        if ctx.accounts.len() < 3 {
            return Err(LoaderV4Error::InsufficientAccounts.message().to_string());
        }

        let (new_authority_pubkey, _new_authority_account, _) = &ctx.accounts[2];

        // Check that new authority is different
        let (program_pubkey, program_account, _) = &ctx.accounts[0];
        let state = LoaderV4State::from_bytes(program_account.data.as_ref())
            .ok_or_else(|| LoaderV4Error::AccountDataTooSmall.message().to_string())?;

        if state.authority_or_next_version == *new_authority_pubkey {
            return Err(LoaderV4Error::NoChange.message().to_string());
        }

        let mut new_program = program_account.clone();
        let mut new_state = state;
        new_state.authority_or_next_version = *new_authority_pubkey;
        new_state.write_to(new_program.data.as_mut_slice());

        let mut outcome = ExecutionOutcome::success(compute_used);
        outcome
            .modified_accounts
            .insert(*program_pubkey, new_program);
        outcome.logs.push(format!(
            "LoaderV4: Transferred authority to {}",
            new_authority_pubkey
        ));
        Ok(outcome)
    }

    /// Finalize a deployed program, making it permanently immutable.
    /// Requires a next-version program with the same authority.
    ///
    /// Accounts: [0] program (writable), [1] authority (signer), [2] next version program
    fn process_finalize(
        &self,
        ctx: &ExecutionContext,
        compute_used: u64,
    ) -> Result<ExecutionOutcome, String> {
        let (state, _authority) = self.check_program_account(ctx)?;

        if !state.is_deployed() {
            return Err(LoaderV4Error::ProgramNotDeployed.message().to_string());
        }

        if ctx.accounts.len() < 3 {
            return Err(LoaderV4Error::InsufficientAccounts.message().to_string());
        }

        let (next_version_pubkey, next_version_account, _) = &ctx.accounts[2];
        let (_authority_pubkey, _authority_account, _) = &ctx.accounts[1];

        // Next version must be owned by loader v4
        if next_version_account.meta.owner != LOADER_V4_PROGRAM_ID {
            return Err(LoaderV4Error::NextVersionNotOwnedByLoader
                .message()
                .to_string());
        }

        // Parse next version state
        let next_state = LoaderV4State::from_bytes(next_version_account.data.as_ref())
            .ok_or_else(|| LoaderV4Error::AccountDataTooSmall.message().to_string())?;

        // Next version must have same authority
        if next_state.authority_or_next_version != state.authority_or_next_version {
            return Err(LoaderV4Error::NextVersionDifferentAuthority
                .message()
                .to_string());
        }

        // Next version must not be finalized
        if next_state.is_finalized() {
            return Err(LoaderV4Error::NextVersionFinalized.message().to_string());
        }

        let (program_pubkey, program_account, _) = &ctx.accounts[0];
        let mut new_program = program_account.clone();
        let mut new_state = state;
        new_state.authority_or_next_version = *next_version_pubkey;
        new_state.status = constants::STATUS_FINALIZED;
        new_state.write_to(new_program.data.as_mut_slice());

        let mut outcome = ExecutionOutcome::success(compute_used);
        outcome
            .modified_accounts
            .insert(*program_pubkey, new_program);
        outcome.logs.push(format!(
            "LoaderV4: Finalized program, next version: {}",
            next_version_pubkey
        ));
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use karstflow_types::AccountMeta;

    const TEST_COST: u64 = 200;

    fn make_authority_account() -> Account {
        Account {
            meta: AccountMeta {
                lamports: 1_000_000,
                owner: Pubkey::zeroed(),
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        }
    }

    /// Create a loader v4 program account with the given state and ELF data size.
    fn make_program_account(
        authority: &Pubkey,
        status: u64,
        slot: u64,
        elf_size: usize,
    ) -> Account {
        let total_size = constants::PROGRAM_DATA_OFFSET + elf_size;
        let mut data = vec![0u8; total_size];
        let state = LoaderV4State {
            slot,
            status,
            authority_or_next_version: *authority,
        };
        state.write_to(&mut data);
        Account {
            meta: AccountMeta {
                lamports: 10_000_000,
                owner: LOADER_V4_PROGRAM_ID,
                executable: true,
                rent_epoch: 0,
            },
            data: AccountData::new(data),
        }
    }

    /// Create a program account with valid ELF magic bytes.
    fn make_deployable_program(authority: &Pubkey, slot: u64) -> Account {
        let elf_data = b"\x7fELF\x02\x01\x01\x00"; // ELF magic + minimal header
        let total_size = constants::PROGRAM_DATA_OFFSET + elf_data.len();
        let mut data = vec![0u8; total_size];
        let state = LoaderV4State {
            slot,
            status: constants::STATUS_RETRACTED,
            authority_or_next_version: *authority,
        };
        state.write_to(&mut data);
        data[constants::PROGRAM_DATA_OFFSET..constants::PROGRAM_DATA_OFFSET + elf_data.len()]
            .copy_from_slice(elf_data);
        Account {
            meta: AccountMeta {
                lamports: 10_000_000,
                owner: LOADER_V4_PROGRAM_ID,
                executable: true,
                rent_epoch: 0,
            },
            data: AccountData::new(data),
        }
    }

    fn make_uninitialized_account(lamports: u64) -> Account {
        Account {
            meta: AccountMeta {
                lamports,
                owner: LOADER_V4_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        }
    }

    // ---------- Write tests ----------

    #[test]
    fn write_succeeds() {
        let executor = LoaderV4Executor::new(TEST_COST);
        let authority = Pubkey::new_unique();
        let program_pubkey = Pubkey::new_unique();

        let program = make_program_account(&authority, constants::STATUS_RETRACTED, 0, 100);

        let mut instruction_data = constants::INSTRUCTION_WRITE.to_le_bytes().to_vec();
        instruction_data.extend_from_slice(&0u32.to_le_bytes()); // offset 0
        instruction_data.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // 3 bytes

        let ctx = ExecutionContext::new(
            LOADER_V4_PROGRAM_ID,
            vec![
                (program_pubkey, program, true),
                (authority, make_authority_account(), false),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&ctx).unwrap();
        assert!(outcome.success);
        let modified = &outcome.modified_accounts[&program_pubkey];
        assert_eq!(
            modified.data.as_ref()
                [constants::PROGRAM_DATA_OFFSET..constants::PROGRAM_DATA_OFFSET + 3],
            [0xAA, 0xBB, 0xCC]
        );
    }

    #[test]
    fn write_rejects_deployed_program() {
        let executor = LoaderV4Executor::new(TEST_COST);
        let authority = Pubkey::new_unique();
        let program_pubkey = Pubkey::new_unique();

        let program = make_program_account(&authority, constants::STATUS_DEPLOYED, 10, 100);

        let mut instruction_data = constants::INSTRUCTION_WRITE.to_le_bytes().to_vec();
        instruction_data.extend_from_slice(&0u32.to_le_bytes());
        instruction_data.push(0xFF);

        let ctx = ExecutionContext::new(
            LOADER_V4_PROGRAM_ID,
            vec![
                (program_pubkey, program, true),
                (authority, make_authority_account(), false),
            ],
            instruction_data,
        );

        let result = executor.execute(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not retracted"));
    }

    #[test]
    fn write_rejects_out_of_bounds() {
        let executor = LoaderV4Executor::new(TEST_COST);
        let authority = Pubkey::new_unique();
        let program_pubkey = Pubkey::new_unique();

        let program = make_program_account(&authority, constants::STATUS_RETRACTED, 0, 10);

        let mut instruction_data = constants::INSTRUCTION_WRITE.to_le_bytes().to_vec();
        instruction_data.extend_from_slice(&5u32.to_le_bytes()); // offset 5
        instruction_data.extend_from_slice(&[0u8; 20]); // 20 bytes - exceeds 10

        let ctx = ExecutionContext::new(
            LOADER_V4_PROGRAM_ID,
            vec![
                (program_pubkey, program, true),
                (authority, make_authority_account(), false),
            ],
            instruction_data,
        );

        let result = executor.execute(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("out of bounds"));
    }

    // ---------- Copy tests ----------

    #[test]
    fn copy_from_loader_v4_source() {
        let executor = LoaderV4Executor::new(TEST_COST);
        let authority = Pubkey::new_unique();
        let program_pubkey = Pubkey::new_unique();
        let source_pubkey = Pubkey::new_unique();

        let program = make_program_account(&authority, constants::STATUS_RETRACTED, 0, 100);

        // Source is a loader v4 program with known data after the header
        let source_authority = Pubkey::new_unique();
        let mut source = make_program_account(&source_authority, constants::STATUS_DEPLOYED, 5, 50);
        // Write recognizable data at the program data offset
        let data_mut = source.data.as_mut_slice();
        data_mut[constants::PROGRAM_DATA_OFFSET..constants::PROGRAM_DATA_OFFSET + 4]
            .copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let mut instruction_data = constants::INSTRUCTION_COPY.to_le_bytes().to_vec();
        instruction_data.extend_from_slice(&0u32.to_le_bytes()); // dest offset 0
        instruction_data.extend_from_slice(&0u32.to_le_bytes()); // source offset 0 (adjusted by PROGRAM_DATA_OFFSET)
        instruction_data.extend_from_slice(&4u32.to_le_bytes()); // length 4

        let ctx = ExecutionContext::new(
            LOADER_V4_PROGRAM_ID,
            vec![
                (program_pubkey, program, true),
                (authority, make_authority_account(), false),
                (source_pubkey, source, false),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&ctx).unwrap();
        assert!(outcome.success);
        let modified = &outcome.modified_accounts[&program_pubkey];
        assert_eq!(
            modified.data.as_ref()
                [constants::PROGRAM_DATA_OFFSET..constants::PROGRAM_DATA_OFFSET + 4],
            [0xDE, 0xAD, 0xBE, 0xEF]
        );
    }

    #[test]
    fn copy_rejects_non_program_source() {
        let executor = LoaderV4Executor::new(TEST_COST);
        let authority = Pubkey::new_unique();
        let program_pubkey = Pubkey::new_unique();
        let source_pubkey = Pubkey::new_unique();

        let program = make_program_account(&authority, constants::STATUS_RETRACTED, 0, 100);

        // Source owned by a random program — not a recognized loader
        let source = Account {
            meta: AccountMeta {
                lamports: 1000,
                owner: Pubkey::new_unique(),
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(vec![0u8; 100]),
        };

        let mut instruction_data = constants::INSTRUCTION_COPY.to_le_bytes().to_vec();
        instruction_data.extend_from_slice(&0u32.to_le_bytes());
        instruction_data.extend_from_slice(&0u32.to_le_bytes());
        instruction_data.extend_from_slice(&4u32.to_le_bytes());

        let ctx = ExecutionContext::new(
            LOADER_V4_PROGRAM_ID,
            vec![
                (program_pubkey, program, true),
                (authority, make_authority_account(), false),
                (source_pubkey, source, false),
            ],
            instruction_data,
        );

        let result = executor.execute(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not a program"));
    }

    // ---------- SetProgramLength tests ----------

    #[test]
    fn set_program_length_initializes() {
        let executor = LoaderV4Executor::new(TEST_COST);
        let authority = Pubkey::new_unique();
        let program_pubkey = Pubkey::new_unique();

        let program = make_uninitialized_account(50_000_000);

        let mut instruction_data = constants::INSTRUCTION_SET_PROGRAM_LENGTH
            .to_le_bytes()
            .to_vec();
        instruction_data.extend_from_slice(&1000u32.to_le_bytes());

        let ctx = ExecutionContext::new(
            LOADER_V4_PROGRAM_ID,
            vec![
                (program_pubkey, program, true),
                (authority, make_authority_account(), false),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&ctx).unwrap();
        assert!(outcome.success);
        let modified = &outcome.modified_accounts[&program_pubkey];

        // Should be executable now
        assert!(modified.meta.executable);

        // Should have correct total size
        assert_eq!(modified.data.len(), constants::PROGRAM_DATA_OFFSET + 1000);

        // State should be retracted with correct authority
        let state = LoaderV4State::from_bytes(modified.data.as_ref()).unwrap();
        assert!(state.is_retracted());
        assert_eq!(state.authority_or_next_version, authority);
        assert_eq!(state.slot, 0);
    }

    #[test]
    fn set_program_length_closes_with_recipient() {
        let executor = LoaderV4Executor::new(TEST_COST);
        let authority = Pubkey::new_unique();
        let program_pubkey = Pubkey::new_unique();
        let recipient_pubkey = Pubkey::new_unique();

        let program = make_program_account(&authority, constants::STATUS_RETRACTED, 0, 100);

        let recipient = Account {
            meta: AccountMeta {
                lamports: 1000,
                owner: Pubkey::zeroed(),
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };

        let mut instruction_data = constants::INSTRUCTION_SET_PROGRAM_LENGTH
            .to_le_bytes()
            .to_vec();
        instruction_data.extend_from_slice(&0u32.to_le_bytes()); // size 0 = close

        let ctx = ExecutionContext::new(
            LOADER_V4_PROGRAM_ID,
            vec![
                (program_pubkey, program, true),
                (authority, make_authority_account(), false),
                (recipient_pubkey, recipient, true),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&ctx).unwrap();
        assert!(outcome.success);

        let closed = &outcome.modified_accounts[&program_pubkey];
        assert_eq!(closed.data.len(), 0);
        assert_eq!(closed.meta.lamports, 0);

        let recipient_after = &outcome.modified_accounts[&recipient_pubkey];
        assert!(recipient_after.meta.lamports > 1000);
    }

    // ---------- Deploy tests ----------

    #[test]
    fn deploy_succeeds() {
        let executor = LoaderV4Executor::new(TEST_COST);
        let authority = Pubkey::new_unique();
        let program_pubkey = Pubkey::new_unique();

        let program = make_deployable_program(&authority, 0);

        let instruction_data = constants::INSTRUCTION_DEPLOY.to_le_bytes().to_vec();

        let ctx = ExecutionContext::new(
            LOADER_V4_PROGRAM_ID,
            vec![
                (program_pubkey, program, true),
                (authority, make_authority_account(), false),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&ctx).unwrap();
        assert!(outcome.success);

        let modified = &outcome.modified_accounts[&program_pubkey];
        let state = LoaderV4State::from_bytes(modified.data.as_ref()).unwrap();
        assert!(state.is_deployed());
    }

    #[test]
    fn deploy_rejects_non_elf() {
        let executor = LoaderV4Executor::new(TEST_COST);
        let authority = Pubkey::new_unique();
        let program_pubkey = Pubkey::new_unique();

        // Program with no ELF magic
        let program = make_program_account(&authority, constants::STATUS_RETRACTED, 0, 100);

        let instruction_data = constants::INSTRUCTION_DEPLOY.to_le_bytes().to_vec();

        let ctx = ExecutionContext::new(
            LOADER_V4_PROGRAM_ID,
            vec![
                (program_pubkey, program, true),
                (authority, make_authority_account(), false),
            ],
            instruction_data,
        );

        let result = executor.execute(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("verification failed"));
    }

    #[test]
    fn deploy_rejects_cooldown() {
        let executor = LoaderV4Executor::new(TEST_COST);
        let authority = Pubkey::new_unique();
        let program_pubkey = Pubkey::new_unique();

        // Previously deployed at slot 100
        let program = make_deployable_program(&authority, 100);
        // Override state to retracted but keep slot=100
        let mut program = program;
        let mut data = program.data.as_ref().to_vec();
        data[8..16].copy_from_slice(&constants::STATUS_RETRACTED.to_le_bytes());
        program.data = AccountData::new(data);

        let instruction_data = constants::INSTRUCTION_DEPLOY.to_le_bytes().to_vec();

        // Execute at slot 100 (within cooldown of 1 slot)
        let mut ctx = ExecutionContext::new(
            LOADER_V4_PROGRAM_ID,
            vec![
                (program_pubkey, program, true),
                (authority, make_authority_account(), false),
            ],
            instruction_data,
        );
        ctx.sysvar_snapshot = Some(crate::SysvarSnapshot {
            slot: 100,
            ..Default::default()
        });

        let result = executor.execute(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cooldown"));
    }

    // ---------- Retract tests ----------

    #[test]
    fn retract_succeeds() {
        let executor = LoaderV4Executor::new(TEST_COST);
        let authority = Pubkey::new_unique();
        let program_pubkey = Pubkey::new_unique();

        let program = make_program_account(&authority, constants::STATUS_DEPLOYED, 5, 100);

        let instruction_data = constants::INSTRUCTION_RETRACT.to_le_bytes().to_vec();

        let mut ctx = ExecutionContext::new(
            LOADER_V4_PROGRAM_ID,
            vec![
                (program_pubkey, program, true),
                (authority, make_authority_account(), false),
            ],
            instruction_data,
        );
        ctx.sysvar_snapshot = Some(crate::SysvarSnapshot {
            slot: 100, // well past cooldown
            ..Default::default()
        });

        let outcome = executor.execute(&ctx).unwrap();
        assert!(outcome.success);

        let modified = &outcome.modified_accounts[&program_pubkey];
        let state = LoaderV4State::from_bytes(modified.data.as_ref()).unwrap();
        assert!(state.is_retracted());
    }

    #[test]
    fn retract_rejects_not_deployed() {
        let executor = LoaderV4Executor::new(TEST_COST);
        let authority = Pubkey::new_unique();
        let program_pubkey = Pubkey::new_unique();

        // Use a retracted program with slot=5 so cooldown passes at slot=100
        let program = make_program_account(&authority, constants::STATUS_RETRACTED, 5, 100);

        let instruction_data = constants::INSTRUCTION_RETRACT.to_le_bytes().to_vec();

        let mut ctx = ExecutionContext::new(
            LOADER_V4_PROGRAM_ID,
            vec![
                (program_pubkey, program, true),
                (authority, make_authority_account(), false),
            ],
            instruction_data,
        );
        ctx.sysvar_snapshot = Some(crate::SysvarSnapshot {
            slot: 100,
            ..Default::default()
        });

        let result = executor.execute(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not deployed"));
    }

    // ---------- TransferAuthority tests ----------

    #[test]
    fn transfer_authority_succeeds() {
        let executor = LoaderV4Executor::new(TEST_COST);
        let authority = Pubkey::new_unique();
        let new_authority = Pubkey::new_unique();
        let program_pubkey = Pubkey::new_unique();

        let program = make_program_account(&authority, constants::STATUS_RETRACTED, 0, 100);

        let instruction_data = constants::INSTRUCTION_TRANSFER_AUTHORITY
            .to_le_bytes()
            .to_vec();

        let ctx = ExecutionContext::new(
            LOADER_V4_PROGRAM_ID,
            vec![
                (program_pubkey, program, true),
                (authority, make_authority_account(), false),
                (new_authority, make_authority_account(), false),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&ctx).unwrap();
        assert!(outcome.success);

        let modified = &outcome.modified_accounts[&program_pubkey];
        let state = LoaderV4State::from_bytes(modified.data.as_ref()).unwrap();
        assert_eq!(state.authority_or_next_version, new_authority);
    }

    #[test]
    fn transfer_authority_rejects_same() {
        let executor = LoaderV4Executor::new(TEST_COST);
        let authority = Pubkey::new_unique();
        let program_pubkey = Pubkey::new_unique();

        let program = make_program_account(&authority, constants::STATUS_RETRACTED, 0, 100);

        let instruction_data = constants::INSTRUCTION_TRANSFER_AUTHORITY
            .to_le_bytes()
            .to_vec();

        let ctx = ExecutionContext::new(
            LOADER_V4_PROGRAM_ID,
            vec![
                (program_pubkey, program, true),
                (authority, make_authority_account(), false),
                (authority, make_authority_account(), false), // same authority
            ],
            instruction_data,
        );

        let result = executor.execute(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No change"));
    }

    // ---------- Finalize tests ----------

    #[test]
    fn finalize_succeeds() {
        let executor = LoaderV4Executor::new(TEST_COST);
        let authority = Pubkey::new_unique();
        let program_pubkey = Pubkey::new_unique();
        let next_version_pubkey = Pubkey::new_unique();

        let program = make_program_account(&authority, constants::STATUS_DEPLOYED, 5, 100);
        let next_version = make_program_account(&authority, constants::STATUS_RETRACTED, 0, 50);

        let instruction_data = constants::INSTRUCTION_FINALIZE.to_le_bytes().to_vec();

        let ctx = ExecutionContext::new(
            LOADER_V4_PROGRAM_ID,
            vec![
                (program_pubkey, program, true),
                (authority, make_authority_account(), false),
                (next_version_pubkey, next_version, false),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&ctx).unwrap();
        assert!(outcome.success);

        let modified = &outcome.modified_accounts[&program_pubkey];
        let state = LoaderV4State::from_bytes(modified.data.as_ref()).unwrap();
        assert!(state.is_finalized());
        assert_eq!(state.authority_or_next_version, next_version_pubkey);
    }

    #[test]
    fn finalize_rejects_not_deployed() {
        let executor = LoaderV4Executor::new(TEST_COST);
        let authority = Pubkey::new_unique();
        let program_pubkey = Pubkey::new_unique();
        let next_version_pubkey = Pubkey::new_unique();

        let program = make_program_account(&authority, constants::STATUS_RETRACTED, 0, 100);
        let next_version = make_program_account(&authority, constants::STATUS_RETRACTED, 0, 50);

        let instruction_data = constants::INSTRUCTION_FINALIZE.to_le_bytes().to_vec();

        let ctx = ExecutionContext::new(
            LOADER_V4_PROGRAM_ID,
            vec![
                (program_pubkey, program, true),
                (authority, make_authority_account(), false),
                (next_version_pubkey, next_version, false),
            ],
            instruction_data,
        );

        let result = executor.execute(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not deployed"));
    }

    #[test]
    fn finalize_rejects_finalized_next_version() {
        let executor = LoaderV4Executor::new(TEST_COST);
        let authority = Pubkey::new_unique();
        let program_pubkey = Pubkey::new_unique();
        let next_version_pubkey = Pubkey::new_unique();

        let program = make_program_account(&authority, constants::STATUS_DEPLOYED, 5, 100);
        let next_version = make_program_account(&authority, constants::STATUS_FINALIZED, 0, 50);

        let instruction_data = constants::INSTRUCTION_FINALIZE.to_le_bytes().to_vec();

        let ctx = ExecutionContext::new(
            LOADER_V4_PROGRAM_ID,
            vec![
                (program_pubkey, program, true),
                (authority, make_authority_account(), false),
                (next_version_pubkey, next_version, false),
            ],
            instruction_data,
        );

        let result = executor.execute(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("finalized"));
    }

    #[test]
    fn finalize_rejects_different_authority() {
        let executor = LoaderV4Executor::new(TEST_COST);
        let authority = Pubkey::new_unique();
        let other_authority = Pubkey::new_unique();
        let program_pubkey = Pubkey::new_unique();
        let next_version_pubkey = Pubkey::new_unique();

        let program = make_program_account(&authority, constants::STATUS_DEPLOYED, 5, 100);
        let next_version =
            make_program_account(&other_authority, constants::STATUS_RETRACTED, 0, 50);

        let instruction_data = constants::INSTRUCTION_FINALIZE.to_le_bytes().to_vec();

        let ctx = ExecutionContext::new(
            LOADER_V4_PROGRAM_ID,
            vec![
                (program_pubkey, program, true),
                (authority, make_authority_account(), false),
                (next_version_pubkey, next_version, false),
            ],
            instruction_data,
        );

        let result = executor.execute(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("different authority"));
    }

    // ---------- Authority checks ----------

    #[test]
    fn wrong_authority_rejected() {
        let executor = LoaderV4Executor::new(TEST_COST);
        let authority = Pubkey::new_unique();
        let wrong_authority = Pubkey::new_unique();
        let program_pubkey = Pubkey::new_unique();

        let program = make_program_account(&authority, constants::STATUS_RETRACTED, 0, 100);

        let mut instruction_data = constants::INSTRUCTION_WRITE.to_le_bytes().to_vec();
        instruction_data.extend_from_slice(&0u32.to_le_bytes());
        instruction_data.push(0xFF);

        let ctx = ExecutionContext::new(
            LOADER_V4_PROGRAM_ID,
            vec![
                (program_pubkey, program, true),
                (wrong_authority, make_authority_account(), false),
            ],
            instruction_data,
        );

        let result = executor.execute(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Incorrect authority"));
    }

    #[test]
    fn finalized_program_rejected() {
        let executor = LoaderV4Executor::new(TEST_COST);
        let authority = Pubkey::new_unique();
        let program_pubkey = Pubkey::new_unique();

        let program = make_program_account(&authority, constants::STATUS_FINALIZED, 5, 100);

        let mut instruction_data = constants::INSTRUCTION_WRITE.to_le_bytes().to_vec();
        instruction_data.extend_from_slice(&0u32.to_le_bytes());
        instruction_data.push(0xFF);

        let ctx = ExecutionContext::new(
            LOADER_V4_PROGRAM_ID,
            vec![
                (program_pubkey, program, true),
                (authority, make_authority_account(), false),
            ],
            instruction_data,
        );

        let result = executor.execute(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("finalized"));
    }

    // ---------- State serialization ----------

    #[test]
    fn state_round_trip() {
        let state = LoaderV4State {
            slot: 42,
            status: constants::STATUS_DEPLOYED,
            authority_or_next_version: Pubkey::new_unique(),
        };

        let mut buf = vec![0u8; constants::PROGRAM_DATA_OFFSET];
        state.write_to(&mut buf);

        let parsed = LoaderV4State::from_bytes(&buf).unwrap();
        assert_eq!(parsed, state);
    }
}
