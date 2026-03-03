//! Genesis configuration parsing and initial state creation.
//!
//! Parses genesis.bin files to bootstrap the validator with initial accounts,
//! economic parameters, and builtin program registrations.

mod accounts;
mod parser;

#[cfg(test)]
mod tests;

pub use parser::{parse_genesis, parse_genesis_bytes, parse_genesis_json, serialize_genesis};

use paradencer_types::{Account, Pubkey};
use serde::{Deserialize, Serialize};

/// Cluster type identifying the network.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClusterType {
    Mainnet,
    Devnet,
    Testnet,
    #[default]
    Development,
}

/// Fee rate governor configuration.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct FeeRateGovernor {
    pub lamports_per_signature: u64,
    pub target_lamports_per_signature: u64,
    pub target_signatures_per_slot: u64,
    pub min_lamports_per_signature: u64,
    pub max_lamports_per_signature: u64,
    pub burn_percent: u8,
}

impl Default for FeeRateGovernor {
    fn default() -> Self {
        use paradencer_constants::economics;
        Self {
            lamports_per_signature: economics::LAMPORTS_PER_SIGNATURE,
            target_lamports_per_signature: economics::LAMPORTS_PER_SIGNATURE,
            target_signatures_per_slot: economics::DEFAULT_TARGET_SIGNATURES_PER_SLOT,
            min_lamports_per_signature: economics::MIN_LAMPORTS_PER_SIGNATURE,
            max_lamports_per_signature: economics::MAX_LAMPORTS_PER_SIGNATURE,
            burn_percent: economics::DEFAULT_FEE_BURN_PERCENT,
        }
    }
}

/// Rent configuration from genesis.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct GenesisRent {
    pub lamports_per_byte_year: u64,
    pub exemption_threshold: f64,
    pub burn_percent: u8,
}

impl Default for GenesisRent {
    fn default() -> Self {
        Self {
            lamports_per_byte_year: 3480,
            exemption_threshold: 2.0,
            burn_percent: 50,
        }
    }
}

/// Inflation configuration from genesis.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct GenesisInflation {
    pub initial_rate: f64,
    pub terminal_rate: f64,
    pub tapering_rate: f64,
    pub foundation_portion: f64,
    pub foundation_duration_years: f64,
}

impl Default for GenesisInflation {
    fn default() -> Self {
        use paradencer_constants::economics;
        Self {
            initial_rate: economics::INFLATION_INITIAL_RATE,
            terminal_rate: economics::INFLATION_TERMINAL_RATE,
            tapering_rate: economics::INFLATION_TAPER_RATE,
            foundation_portion: economics::INFLATION_FOUNDATION_RATE,
            foundation_duration_years: economics::INFLATION_FOUNDATION_TERM,
        }
    }
}

/// Epoch schedule from genesis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisEpochSchedule {
    pub slots_per_epoch: u64,
    pub leader_schedule_slot_offset: u64,
    pub warmup: bool,
    pub first_normal_epoch: u64,
    pub first_normal_slot: u64,
}

impl Default for GenesisEpochSchedule {
    fn default() -> Self {
        use paradencer_constants::{consensus, ledger};
        Self {
            slots_per_epoch: ledger::SLOTS_PER_EPOCH,
            leader_schedule_slot_offset: consensus::LEADER_SCHEDULE_SLOT_OFFSET,
            warmup: true,
            first_normal_epoch: 0,
            first_normal_slot: 0,
        }
    }
}

/// Account data as stored in genesis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisAccount {
    pub lamports: u64,
    pub data: Vec<u8>,
    pub owner: Pubkey,
    pub executable: bool,
    pub rent_epoch: u64,
}

impl GenesisAccount {
    /// Convert this genesis account to a runtime Account.
    pub fn to_runtime_account(&self) -> Account {
        accounts::genesis_account_to_runtime(self)
    }
}

/// Complete genesis configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisConfig {
    /// Timestamp of genesis creation (Unix seconds).
    pub creation_time: i64,
    /// Initial accounts with their data.
    pub accounts: Vec<(Pubkey, GenesisAccount)>,
    /// Builtin programs to register (name, program_id).
    pub native_instruction_processors: Vec<(String, Pubkey)>,
    /// Rewards pool accounts.
    pub rewards_pool_accounts: Vec<(Pubkey, GenesisAccount)>,
    /// Epoch schedule parameters.
    pub epoch_schedule: GenesisEpochSchedule,
    /// Inflation parameters.
    pub inflation: GenesisInflation,
    /// Rent parameters.
    pub rent: GenesisRent,
    /// Fee rate governor.
    pub fee_rate_governor: FeeRateGovernor,
    /// Cluster type.
    pub cluster_type: ClusterType,
    /// Ticks per slot.
    pub ticks_per_slot: u64,
    /// PoH hashes per tick.
    pub poh_config_hashes_per_tick: Option<u64>,
    /// Target tick duration (nanoseconds).
    pub poh_config_target_tick_duration_ns: u64,
    /// Initial validator set for multi-validator clusters.
    ///
    /// Each entry is `(node_identity_pubkey, stake_lamports)`. When this list
    /// is non-empty the node bootstraps the leader schedule from it rather than
    /// from a single hardcoded identity, enabling multi-validator local clusters.
    ///
    /// Used only when no Solana-compatible stake/vote accounts are present in
    /// `accounts` (i.e. in development clusters created by `genesis cluster N`).
    #[serde(default)]
    pub initial_validators: Vec<(Pubkey, u64)>,
}

impl GenesisConfig {
    /// Create a development cluster genesis with default parameters.
    pub fn default_development() -> Self {
        Self {
            creation_time: 0,
            accounts: Vec::new(),
            native_instruction_processors: Vec::new(),
            rewards_pool_accounts: Vec::new(),
            epoch_schedule: GenesisEpochSchedule::default(),
            inflation: GenesisInflation::default(),
            rent: GenesisRent::default(),
            fee_rate_governor: FeeRateGovernor::default(),
            cluster_type: ClusterType::Development,
            ticks_per_slot: paradencer_constants::ledger::TICKS_PER_SLOT,
            poh_config_hashes_per_tick: None,
            poh_config_target_tick_duration_ns: 6_250_000, // 6.25ms
            initial_validators: Vec::new(),
        }
    }

    /// Sum of all account lamports (genesis + rewards pool).
    pub fn total_supply(&self) -> u64 {
        let genesis_sum: u64 = self.accounts.iter().map(|(_, a)| a.lamports).sum();
        let rewards_sum: u64 = self
            .rewards_pool_accounts
            .iter()
            .map(|(_, a)| a.lamports)
            .sum();
        genesis_sum.saturating_add(rewards_sum)
    }

    /// Check if a native program is registered in this genesis.
    pub fn has_native_program(&self, program_id: &Pubkey) -> bool {
        self.native_instruction_processors
            .iter()
            .any(|(_, id)| id == program_id)
    }

    /// Convert all genesis accounts to runtime Account types.
    pub fn to_accounts(&self) -> Vec<(Pubkey, Account)> {
        accounts::create_initial_accounts(self)
    }
}

impl Default for GenesisConfig {
    fn default() -> Self {
        Self::default_development()
    }
}

/// Errors that can occur during genesis parsing.
#[derive(Debug)]
pub enum GenesisError {
    /// I/O error reading the genesis file.
    IoError(std::io::Error),
    /// Failed to deserialize genesis data.
    DeserializationError(String),
    /// Failed to serialize genesis data.
    SerializationError(String),
    /// Too many accounts in genesis.
    TooManyAccounts(usize),
    /// Genesis file exceeds maximum size.
    FileTooLarge(usize),
}

impl std::fmt::Display for GenesisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError(e) => write!(f, "IO error: {}", e),
            Self::DeserializationError(e) => write!(f, "Deserialization error: {}", e),
            Self::SerializationError(e) => write!(f, "Serialization error: {}", e),
            Self::TooManyAccounts(n) => write!(f, "Too many accounts: {}", n),
            Self::FileTooLarge(n) => write!(f, "File too large: {} bytes", n),
        }
    }
}

impl std::error::Error for GenesisError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IoError(e) => Some(e),
            _ => None,
        }
    }
}
