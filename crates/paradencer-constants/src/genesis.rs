/// Constants for genesis configuration parsing and validation.

/// Maximum number of accounts in genesis.
pub const MAX_GENESIS_ACCOUNTS: usize = 1_000_000;

/// Maximum genesis file size (bytes).
pub const MAX_GENESIS_FILE_SIZE: usize = 256 * 1024 * 1024; // 256MB

/// Cluster type: Mainnet-Beta.
pub const CLUSTER_MAINNET: u32 = 0;

/// Cluster type: Devnet.
pub const CLUSTER_DEVNET: u32 = 1;

/// Cluster type: Testnet.
pub const CLUSTER_TESTNET: u32 = 2;

/// Cluster type: Development (local).
pub const CLUSTER_DEVELOPMENT: u32 = 3;
