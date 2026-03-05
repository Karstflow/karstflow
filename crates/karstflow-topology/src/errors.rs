#[cfg(test)]
use std::path::PathBuf;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, TopologyError>;

#[derive(Debug, Error)]
pub enum TopologyError {
    #[cfg(test)]
    #[error("failed to read topology file '{path}': {source}")]
    TopologyRead {
        path: PathBuf,
        source: std::io::Error,
    },
    #[cfg(test)]
    #[error("failed to parse topology TOML '{path}': {source}")]
    TopologyParse {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("invalid topology: {message}")]
    InvalidTopology { message: String },
    #[error("missing required link kind in topology: {kind}")]
    MissingRequiredLinkKind { kind: &'static str },
    #[error("required stage kind is missing from topology: {kind}")]
    MissingRequiredStageKind { kind: &'static str },
    #[error("stage initialization failed: {0}")]
    Stage(#[from] karstflow_stages::StageError),
}
