//! Address Lookup Table (ALT) program implementation.
//!
//! Manages versioned transaction address lookup tables, allowing
//! transactions to reference more accounts than the message format
//! directly supports. Tables are created on-chain, extended with
//! new addresses, and eventually closed to reclaim rent.

use crate::{ExecutionContext, ExecutionOutcome};
use karstflow_constants::address_lookup_table as constants;
use karstflow_ids::ADDRESS_LOOKUP_TABLE_PROGRAM_ID;
use karstflow_types::{Account, AccountData, Pubkey};

/// Current lifecycle status of a lookup table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupTableStatus {
    /// Table is active and can be extended or deactivated.
    Active,
    /// Table is deactivating; waiting for the cooldown period to expire.
    Deactivating { deactivation_slot: u64 },
    /// Table has been fully deactivated and can be closed.
    Deactivated,
    /// Table is frozen and cannot be modified further.
    Frozen,
}

/// Metadata header for a lookup table account.
#[derive(Debug, Clone)]
pub struct LookupTableMeta {
    /// Authority that can extend or deactivate the table. `None` if frozen.
    pub authority: Option<Pubkey>,
    /// Slot at which deactivation was requested. `u64::MAX` if not deactivating.
    pub deactivation_slot: u64,
    /// Slot of the most recent extend operation.
    pub last_extended_slot: u64,
    /// Starting index within the address list for the last extension batch.
    pub last_extended_slot_start_index: u8,
    /// Current lifecycle status.
    pub status: LookupTableStatus,
}

/// A lookup table combining metadata with a list of stored addresses.
#[derive(Debug, Clone)]
pub struct LookupTable {
    pub meta: LookupTableMeta,
    pub addresses: Vec<Pubkey>,
}

/// Address Lookup Table program execution errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupTableError {
    InvalidInstruction,
    InsufficientAccounts,
    AccountNotWritable,
    TableAlreadyExists,
    TableFrozen,
    TableNotActive,
    AddressLimitExceeded,
    AuthorityMismatch,
    CooldownNotExpired,
    MissingAuthority,
}

impl LookupTableError {
    fn message(&self) -> &'static str {
        match self {
            Self::InvalidInstruction => "Invalid instruction data",
            Self::InsufficientAccounts => "Insufficient accounts provided",
            Self::AccountNotWritable => "Required account is not writable",
            Self::TableAlreadyExists => "Lookup table already exists",
            Self::TableFrozen => "Lookup table is frozen",
            Self::TableNotActive => "Lookup table is not active",
            Self::AddressLimitExceeded => "Address limit exceeded",
            Self::AuthorityMismatch => "Authority does not match",
            Self::CooldownNotExpired => "Deactivation cooldown has not expired",
            Self::MissingAuthority => "Table has no authority",
        }
    }
}

/// Executor for Address Lookup Table program instructions.
pub struct AddressLookupTableExecutor {
    base_cost: u64,
}

impl AddressLookupTableExecutor {
    pub fn new(base_cost: u64) -> Self {
        Self { base_cost }
    }

    pub fn execute(&self, ctx: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if ctx.instruction_data.len() < 4 {
            return Err(LookupTableError::InvalidInstruction.message().to_string());
        }

        let instruction_type = u32::from_le_bytes(
            ctx.instruction_data[0..4]
                .try_into()
                .map_err(|_| "Failed to parse instruction type")?,
        );

        match instruction_type {
            constants::INSTRUCTION_CREATE => self.create_table(ctx),
            constants::INSTRUCTION_FREEZE => self.freeze_table(ctx),
            constants::INSTRUCTION_EXTEND => self.extend_table(ctx),
            constants::INSTRUCTION_DEACTIVATE => self.deactivate_table(ctx),
            constants::INSTRUCTION_CLOSE => self.close_table(ctx),
            _ => Err(format!(
                "Unknown ALT instruction type: {}",
                instruction_type
            )),
        }
    }

    /// Create a new lookup table with an empty address list.
    ///
    /// Accounts expected:
    ///   [0] table account (writable) - the new lookup table
    ///   [1] authority account - the table authority
    ///   [2] payer account (writable) - pays for the account
    fn create_table(&self, ctx: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if ctx.accounts.len() < 3 {
            return Err(LookupTableError::InsufficientAccounts.message().to_string());
        }

        let (table_pubkey, table_account, table_writable) = &ctx.accounts[0];
        let (authority_pubkey, _authority_account, _) = &ctx.accounts[1];
        let (_payer_pubkey, _payer_account, payer_writable) = &ctx.accounts[2];

        if !table_writable {
            return Err(LookupTableError::AccountNotWritable.message().to_string());
        }
        if !payer_writable {
            return Err(LookupTableError::AccountNotWritable.message().to_string());
        }

        // Table account must be empty (not already initialized)
        if !table_account.data.as_ref().is_empty() || table_account.meta.lamports > 0 {
            return Err(LookupTableError::TableAlreadyExists.message().to_string());
        }

        // Build initial table data: meta header + zero addresses
        let mut table_data = Vec::with_capacity(constants::LOOKUP_TABLE_META_SIZE);

        // Serialize a minimal meta header:
        // [32 bytes authority] [8 bytes deactivation_slot] [8 bytes last_extended_slot]
        // [1 byte last_extended_slot_start_index] [7 bytes padding]
        table_data.extend_from_slice(authority_pubkey.as_bytes());
        table_data.extend_from_slice(&u64::MAX.to_le_bytes()); // not deactivating
        table_data.extend_from_slice(&0u64.to_le_bytes()); // last_extended_slot = 0
        table_data.push(0u8); // last_extended_slot_start_index
        table_data.extend_from_slice(&[0u8; 7]); // padding

        let mut new_table = table_account.clone();
        new_table.data = AccountData::new(table_data);
        new_table.meta.owner = ADDRESS_LOOKUP_TABLE_PROGRAM_ID;

        let compute_used = self
            .base_cost
            .saturating_add(constants::COMPUTE_COST_CREATE);

        let mut outcome = ExecutionOutcome::success(compute_used);
        outcome.modified_accounts.insert(*table_pubkey, new_table);
        outcome
            .logs
            .push(format!("Created lookup table {}", table_pubkey));
        Ok(outcome)
    }

    /// Freeze the lookup table, permanently removing its authority.
    ///
    /// Accounts expected:
    ///   [0] table account (writable) - the lookup table to freeze
    ///   [1] authority account - must match the current table authority
    fn freeze_table(&self, ctx: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if ctx.accounts.len() < 2 {
            return Err(LookupTableError::InsufficientAccounts.message().to_string());
        }

        let (table_pubkey, table_account, table_writable) = &ctx.accounts[0];
        let (authority_pubkey, _authority_account, _) = &ctx.accounts[1];

        if !table_writable {
            return Err(LookupTableError::AccountNotWritable.message().to_string());
        }

        // Validate table has data (is initialized)
        if table_account.data.as_ref().len() < constants::LOOKUP_TABLE_META_SIZE {
            return Err(LookupTableError::TableNotActive.message().to_string());
        }

        // Read authority from table data (first 32 bytes)
        let stored_authority = Pubkey::new_from_array(
            table_account.data.as_ref()[0..32]
                .try_into()
                .map_err(|_| "Failed to read authority")?,
        );

        // Zero authority means already frozen or no authority
        if stored_authority == Pubkey::zeroed() {
            return Err(LookupTableError::MissingAuthority.message().to_string());
        }

        if &stored_authority != authority_pubkey {
            return Err(LookupTableError::AuthorityMismatch.message().to_string());
        }

        // Zero out the authority to freeze the table
        let mut new_table = table_account.clone();
        let data_mut = new_table.data.as_mut_slice();
        data_mut[0..32].copy_from_slice(&[0u8; 32]);

        let compute_used = self
            .base_cost
            .saturating_add(constants::COMPUTE_COST_FREEZE);

        let mut outcome = ExecutionOutcome::success(compute_used);
        outcome.modified_accounts.insert(*table_pubkey, new_table);
        outcome
            .logs
            .push(format!("Frozen lookup table {}", table_pubkey));
        Ok(outcome)
    }

    /// Extend the lookup table with additional addresses.
    ///
    /// Instruction data: [4 bytes type] [4 bytes num_addresses] [32 * n bytes addresses...]
    ///
    /// Accounts expected:
    ///   [0] table account (writable)
    ///   [1] authority account
    fn extend_table(&self, ctx: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if ctx.accounts.len() < 2 {
            return Err(LookupTableError::InsufficientAccounts.message().to_string());
        }

        let (table_pubkey, table_account, table_writable) = &ctx.accounts[0];
        let (authority_pubkey, _authority_account, _) = &ctx.accounts[1];

        if !table_writable {
            return Err(LookupTableError::AccountNotWritable.message().to_string());
        }

        if table_account.data.as_ref().len() < constants::LOOKUP_TABLE_META_SIZE {
            return Err(LookupTableError::TableNotActive.message().to_string());
        }

        // Verify authority
        let stored_authority = Pubkey::new_from_array(
            table_account.data.as_ref()[0..32]
                .try_into()
                .map_err(|_| "Failed to read authority")?,
        );

        if stored_authority == Pubkey::zeroed() {
            return Err(LookupTableError::TableFrozen.message().to_string());
        }

        if &stored_authority != authority_pubkey {
            return Err(LookupTableError::AuthorityMismatch.message().to_string());
        }

        // Parse new addresses from instruction data
        if ctx.instruction_data.len() < 8 {
            return Err(LookupTableError::InvalidInstruction.message().to_string());
        }

        let num_new_addresses = u32::from_le_bytes(
            ctx.instruction_data[4..8]
                .try_into()
                .map_err(|_| "Failed to parse address count")?,
        ) as usize;

        let expected_data_len = 8 + num_new_addresses * 32;
        if ctx.instruction_data.len() < expected_data_len {
            return Err(LookupTableError::InvalidInstruction.message().to_string());
        }

        // Count existing addresses beyond the metadata header
        let existing_address_count =
            (table_account.data.as_ref().len() - constants::LOOKUP_TABLE_META_SIZE) / 32;

        let total_addresses = existing_address_count + num_new_addresses;
        if total_addresses > constants::MAX_ADDRESSES {
            return Err(LookupTableError::AddressLimitExceeded.message().to_string());
        }

        // Build updated table data
        let mut new_table = table_account.clone();
        for i in 0..num_new_addresses {
            let offset = 8 + i * 32;
            let addr_bytes = &ctx.instruction_data[offset..offset + 32];
            new_table.data.extend_from_slice(addr_bytes);
        }

        let compute_used = self
            .base_cost
            .saturating_add(constants::COMPUTE_COST_EXTEND)
            .saturating_add(constants::COMPUTE_COST_EXTEND_PER_ADDRESS * num_new_addresses as u64);

        let mut outcome = ExecutionOutcome::success(compute_used);
        outcome.modified_accounts.insert(*table_pubkey, new_table);
        outcome.logs.push(format!(
            "Extended lookup table {} with {} addresses (total: {})",
            table_pubkey, num_new_addresses, total_addresses
        ));
        Ok(outcome)
    }

    /// Deactivate the lookup table, starting the cooldown period.
    ///
    /// Instruction data: [4 bytes type] [8 bytes current_slot]
    ///
    /// Accounts expected:
    ///   [0] table account (writable)
    ///   [1] authority account
    fn deactivate_table(&self, ctx: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if ctx.accounts.len() < 2 {
            return Err(LookupTableError::InsufficientAccounts.message().to_string());
        }

        let (table_pubkey, table_account, table_writable) = &ctx.accounts[0];
        let (authority_pubkey, _authority_account, _) = &ctx.accounts[1];

        if !table_writable {
            return Err(LookupTableError::AccountNotWritable.message().to_string());
        }

        if table_account.data.as_ref().len() < constants::LOOKUP_TABLE_META_SIZE {
            return Err(LookupTableError::TableNotActive.message().to_string());
        }

        // Verify authority
        let stored_authority = Pubkey::new_from_array(
            table_account.data.as_ref()[0..32]
                .try_into()
                .map_err(|_| "Failed to read authority")?,
        );

        if stored_authority == Pubkey::zeroed() {
            return Err(LookupTableError::TableFrozen.message().to_string());
        }

        if &stored_authority != authority_pubkey {
            return Err(LookupTableError::AuthorityMismatch.message().to_string());
        }

        // Check not already deactivating
        let current_deactivation_slot = u64::from_le_bytes(
            table_account.data.as_ref()[32..40]
                .try_into()
                .map_err(|_| "Failed to read deactivation slot")?,
        );

        if current_deactivation_slot != u64::MAX {
            return Err(LookupTableError::TableNotActive.message().to_string());
        }

        // Parse current slot from instruction data
        let current_slot = if ctx.instruction_data.len() >= 12 {
            u64::from_le_bytes(
                ctx.instruction_data[4..12]
                    .try_into()
                    .map_err(|_| "Failed to parse current slot")?,
            )
        } else {
            0 // Fallback for testing
        };

        // Write deactivation slot into the table meta
        let mut new_table = table_account.clone();
        let data_mut = new_table.data.as_mut_slice();
        data_mut[32..40].copy_from_slice(&current_slot.to_le_bytes());

        let compute_used = self
            .base_cost
            .saturating_add(constants::COMPUTE_COST_DEACTIVATE);

        let mut outcome = ExecutionOutcome::success(compute_used);
        outcome.modified_accounts.insert(*table_pubkey, new_table);
        outcome.logs.push(format!(
            "Deactivated lookup table {} at slot {}",
            table_pubkey, current_slot
        ));
        Ok(outcome)
    }

    /// Close the lookup table and reclaim lamports after cooldown.
    ///
    /// Instruction data: [4 bytes type] [8 bytes current_slot]
    ///
    /// Accounts expected:
    ///   [0] table account (writable) - the table to close
    ///   [1] recipient account (writable) - receives reclaimed lamports
    ///   [2] authority account
    fn close_table(&self, ctx: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if ctx.accounts.len() < 3 {
            return Err(LookupTableError::InsufficientAccounts.message().to_string());
        }

        let (table_pubkey, table_account, table_writable) = &ctx.accounts[0];
        let (recipient_pubkey, recipient_account, recipient_writable) = &ctx.accounts[1];
        let (authority_pubkey, _authority_account, _) = &ctx.accounts[2];

        if !table_writable || !recipient_writable {
            return Err(LookupTableError::AccountNotWritable.message().to_string());
        }

        if table_account.data.as_ref().len() < constants::LOOKUP_TABLE_META_SIZE {
            return Err(LookupTableError::TableNotActive.message().to_string());
        }

        // Verify authority
        let stored_authority = Pubkey::new_from_array(
            table_account.data.as_ref()[0..32]
                .try_into()
                .map_err(|_| "Failed to read authority")?,
        );

        if stored_authority == Pubkey::zeroed() {
            return Err(LookupTableError::MissingAuthority.message().to_string());
        }

        if &stored_authority != authority_pubkey {
            return Err(LookupTableError::AuthorityMismatch.message().to_string());
        }

        // Check deactivation cooldown
        let deactivation_slot = u64::from_le_bytes(
            table_account.data.as_ref()[32..40]
                .try_into()
                .map_err(|_| "Failed to read deactivation slot")?,
        );

        if deactivation_slot == u64::MAX {
            return Err(LookupTableError::TableNotActive.message().to_string()
                + ": table must be deactivated first");
        }

        // Parse current slot from instruction data
        let current_slot = if ctx.instruction_data.len() >= 12 {
            u64::from_le_bytes(
                ctx.instruction_data[4..12]
                    .try_into()
                    .map_err(|_| "Failed to parse current slot")?,
            )
        } else {
            0
        };

        if current_slot < deactivation_slot.saturating_add(constants::TABLE_DEACTIVATION_COOLDOWN) {
            return Err(LookupTableError::CooldownNotExpired.message().to_string());
        }

        // Transfer lamports from table to recipient and zero out the table
        let table_lamports = table_account.meta.lamports;

        let mut new_table = Account::zeroed();
        new_table.meta.owner = Pubkey::zeroed();

        let mut new_recipient = recipient_account.clone();
        new_recipient.meta.lamports = new_recipient.meta.lamports.saturating_add(table_lamports);

        let compute_used = self.base_cost.saturating_add(constants::COMPUTE_COST_CLOSE);

        let mut outcome = ExecutionOutcome::success(compute_used);
        outcome.modified_accounts.insert(*table_pubkey, new_table);
        outcome
            .modified_accounts
            .insert(*recipient_pubkey, new_recipient);
        outcome.logs.push(format!(
            "Closed lookup table {} and reclaimed {} lamports",
            table_pubkey, table_lamports
        ));
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use karstflow_types::AccountMeta;

    fn make_empty_account() -> Account {
        Account::zeroed()
    }

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

    fn make_table_account(authority: &Pubkey) -> Account {
        let mut data = Vec::with_capacity(constants::LOOKUP_TABLE_META_SIZE);
        data.extend_from_slice(authority.as_bytes());
        data.extend_from_slice(&u64::MAX.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes());
        data.push(0u8);
        data.extend_from_slice(&[0u8; 7]);

        Account {
            meta: AccountMeta {
                lamports: 1_000_000,
                owner: ADDRESS_LOOKUP_TABLE_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(data),
        }
    }

    fn make_deactivated_table_account(authority: &Pubkey, deactivation_slot: u64) -> Account {
        let mut data = Vec::with_capacity(constants::LOOKUP_TABLE_META_SIZE);
        data.extend_from_slice(authority.as_bytes());
        data.extend_from_slice(&deactivation_slot.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes());
        data.push(0u8);
        data.extend_from_slice(&[0u8; 7]);

        Account {
            meta: AccountMeta {
                lamports: 1_000_000,
                owner: ADDRESS_LOOKUP_TABLE_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(data),
        }
    }

    #[test]
    fn create_table_succeeds() {
        let executor = AddressLookupTableExecutor::new(150);

        let table_pubkey = Pubkey::new_unique();
        let authority_pubkey = Pubkey::new_unique();
        let payer_pubkey = Pubkey::new_unique();

        let instruction_data = constants::INSTRUCTION_CREATE.to_le_bytes().to_vec();
        let ctx = ExecutionContext::new(
            ADDRESS_LOOKUP_TABLE_PROGRAM_ID,
            vec![
                (table_pubkey, make_empty_account(), true),
                (authority_pubkey, make_authority_account(), false),
                (payer_pubkey, make_authority_account(), true),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&ctx).unwrap();
        assert!(outcome.success);
        assert!(outcome.modified_accounts.contains_key(&table_pubkey));
        let table = &outcome.modified_accounts[&table_pubkey];
        assert_eq!(table.data.len(), constants::LOOKUP_TABLE_META_SIZE);
    }

    #[test]
    fn freeze_table_removes_authority() {
        let executor = AddressLookupTableExecutor::new(150);

        let authority = Pubkey::new_unique();
        let table_pubkey = Pubkey::new_unique();

        let instruction_data = constants::INSTRUCTION_FREEZE.to_le_bytes().to_vec();
        let ctx = ExecutionContext::new(
            ADDRESS_LOOKUP_TABLE_PROGRAM_ID,
            vec![
                (table_pubkey, make_table_account(&authority), true),
                (authority, make_authority_account(), false),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&ctx).unwrap();
        assert!(outcome.success);
        let frozen_table = &outcome.modified_accounts[&table_pubkey];
        // Authority should be zeroed out
        let stored_auth = &frozen_table.data.as_ref()[0..32];
        assert_eq!(stored_auth, &[0u8; 32]);
    }

    #[test]
    fn extend_table_adds_addresses() {
        let executor = AddressLookupTableExecutor::new(150);

        let authority = Pubkey::new_unique();
        let table_pubkey = Pubkey::new_unique();

        let addr1 = Pubkey::new_unique();
        let addr2 = Pubkey::new_unique();

        let mut instruction_data = constants::INSTRUCTION_EXTEND.to_le_bytes().to_vec();
        instruction_data.extend_from_slice(&2u32.to_le_bytes()); // 2 addresses
        instruction_data.extend_from_slice(addr1.as_bytes());
        instruction_data.extend_from_slice(addr2.as_bytes());

        let ctx = ExecutionContext::new(
            ADDRESS_LOOKUP_TABLE_PROGRAM_ID,
            vec![
                (table_pubkey, make_table_account(&authority), true),
                (authority, make_authority_account(), false),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&ctx).unwrap();
        assert!(outcome.success);
        let extended_table = &outcome.modified_accounts[&table_pubkey];
        // Meta (56 bytes) + 2 addresses (64 bytes) = 120 bytes
        assert_eq!(
            extended_table.data.len(),
            constants::LOOKUP_TABLE_META_SIZE + 64
        );
    }

    #[test]
    fn extend_rejects_over_max_addresses() {
        let executor = AddressLookupTableExecutor::new(150);

        let authority = Pubkey::new_unique();
        let table_pubkey = Pubkey::new_unique();

        // Pre-fill table with MAX_ADDRESSES addresses
        let mut table = make_table_account(&authority);
        for _ in 0..constants::MAX_ADDRESSES {
            table
                .data
                .extend_from_slice(&Pubkey::new_unique().to_bytes());
        }

        // Try to add one more
        let mut instruction_data = constants::INSTRUCTION_EXTEND.to_le_bytes().to_vec();
        instruction_data.extend_from_slice(&1u32.to_le_bytes());
        instruction_data.extend_from_slice(Pubkey::new_unique().as_bytes());

        let ctx = ExecutionContext::new(
            ADDRESS_LOOKUP_TABLE_PROGRAM_ID,
            vec![
                (table_pubkey, table, true),
                (authority, make_authority_account(), false),
            ],
            instruction_data,
        );

        let result = executor.execute(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("limit exceeded"));
    }

    #[test]
    fn deactivate_starts_cooldown() {
        let executor = AddressLookupTableExecutor::new(150);

        let authority = Pubkey::new_unique();
        let table_pubkey = Pubkey::new_unique();
        let current_slot = 1000u64;

        let mut instruction_data = constants::INSTRUCTION_DEACTIVATE.to_le_bytes().to_vec();
        instruction_data.extend_from_slice(&current_slot.to_le_bytes());

        let ctx = ExecutionContext::new(
            ADDRESS_LOOKUP_TABLE_PROGRAM_ID,
            vec![
                (table_pubkey, make_table_account(&authority), true),
                (authority, make_authority_account(), false),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&ctx).unwrap();
        assert!(outcome.success);
        let deactivated = &outcome.modified_accounts[&table_pubkey];
        let stored_slot = u64::from_le_bytes(deactivated.data.as_ref()[32..40].try_into().unwrap());
        assert_eq!(stored_slot, current_slot);
    }

    #[test]
    fn close_succeeds_after_cooldown() {
        let executor = AddressLookupTableExecutor::new(150);

        let authority = Pubkey::new_unique();
        let table_pubkey = Pubkey::new_unique();
        let recipient_pubkey = Pubkey::new_unique();
        let deactivation_slot = 100u64;
        let current_slot = deactivation_slot + constants::TABLE_DEACTIVATION_COOLDOWN + 1;

        let mut instruction_data = constants::INSTRUCTION_CLOSE.to_le_bytes().to_vec();
        instruction_data.extend_from_slice(&current_slot.to_le_bytes());

        let ctx = ExecutionContext::new(
            ADDRESS_LOOKUP_TABLE_PROGRAM_ID,
            vec![
                (
                    table_pubkey,
                    make_deactivated_table_account(&authority, deactivation_slot),
                    true,
                ),
                (recipient_pubkey, make_empty_account(), true),
                (authority, make_authority_account(), false),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&ctx).unwrap();
        assert!(outcome.success);
        assert!(outcome.modified_accounts.contains_key(&table_pubkey));
        assert!(outcome.modified_accounts.contains_key(&recipient_pubkey));
        let recipient = &outcome.modified_accounts[&recipient_pubkey];
        assert_eq!(recipient.meta.lamports, 1_000_000); // Reclaimed lamports
    }

    #[test]
    fn close_rejects_before_cooldown() {
        let executor = AddressLookupTableExecutor::new(150);

        let authority = Pubkey::new_unique();
        let table_pubkey = Pubkey::new_unique();
        let recipient_pubkey = Pubkey::new_unique();
        let deactivation_slot = 100u64;
        let current_slot = deactivation_slot + 10; // Too early

        let mut instruction_data = constants::INSTRUCTION_CLOSE.to_le_bytes().to_vec();
        instruction_data.extend_from_slice(&current_slot.to_le_bytes());

        let ctx = ExecutionContext::new(
            ADDRESS_LOOKUP_TABLE_PROGRAM_ID,
            vec![
                (
                    table_pubkey,
                    make_deactivated_table_account(&authority, deactivation_slot),
                    true,
                ),
                (recipient_pubkey, make_empty_account(), true),
                (authority, make_authority_account(), false),
            ],
            instruction_data,
        );

        let result = executor.execute(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cooldown"));
    }
}
