//! Genesis file parsing.
//!
//! Supports both bincode binary format and JSON format for genesis files.

use super::{GenesisConfig, GenesisError};
use paradencer_constants::genesis::{MAX_GENESIS_ACCOUNTS, MAX_GENESIS_FILE_SIZE};
use std::path::Path;

/// Parse a genesis.bin file from disk.
pub fn parse_genesis(path: &Path) -> Result<GenesisConfig, GenesisError> {
    let data = std::fs::read(path).map_err(GenesisError::IoError)?;
    if data.len() > MAX_GENESIS_FILE_SIZE {
        return Err(GenesisError::FileTooLarge(data.len()));
    }
    parse_genesis_bytes(&data)
}

/// Parse genesis from raw bytes (bincode format).
pub fn parse_genesis_bytes(data: &[u8]) -> Result<GenesisConfig, GenesisError> {
    if data.len() > MAX_GENESIS_FILE_SIZE {
        return Err(GenesisError::FileTooLarge(data.len()));
    }
    let config: GenesisConfig = bincode::deserialize(data)
        .map_err(|e| GenesisError::DeserializationError(e.to_string()))?;
    validate_config(&config)?;
    Ok(config)
}

/// Parse genesis from JSON string.
pub fn parse_genesis_json(json: &str) -> Result<GenesisConfig, GenesisError> {
    let config: GenesisConfig = serde_json::from_str(json)
        .map_err(|e| GenesisError::DeserializationError(e.to_string()))?;
    validate_config(&config)?;
    Ok(config)
}

/// Serialize genesis config to bincode bytes.
pub fn serialize_genesis(config: &GenesisConfig) -> Result<Vec<u8>, GenesisError> {
    bincode::serialize(config).map_err(|e| GenesisError::SerializationError(e.to_string()))
}

/// Validate a parsed genesis config.
fn validate_config(config: &GenesisConfig) -> Result<(), GenesisError> {
    let total_accounts = config.accounts.len() + config.rewards_pool_accounts.len();
    if total_accounts > MAX_GENESIS_ACCOUNTS {
        return Err(GenesisError::TooManyAccounts(total_accounts));
    }
    Ok(())
}
