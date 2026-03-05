use std::io;
use thiserror::Error;

/// Errors that can occur during plugin operations.
#[derive(Debug, Error)]
pub enum PluginError {
    #[error("config file I/O error: {0}")]
    ConfigIo(#[from] io::Error),

    #[error("config parse error: {0}")]
    ConfigParse(String),

    #[error("library path not specified in plugin config")]
    LibraryPathMissing,

    #[error("plugin load failed: {0}")]
    LoadFailed(String),

    #[error("plugin already loaded: {0}")]
    AlreadyLoaded(String),

    #[error("plugin not found: {0}")]
    NotFound(String),

    #[error("account update notification failed: {0}")]
    AccountUpdate(String),

    #[error("transaction notification failed: {0}")]
    TransactionNotification(String),

    #[error("slot status notification failed: {0}")]
    SlotStatus(String),

    #[error("block metadata notification failed: {0}")]
    BlockMetadata(String),

    #[error("{0}")]
    Custom(Box<dyn std::error::Error + Send + Sync>),
}

pub type PluginResult<T> = Result<T, PluginError>;
