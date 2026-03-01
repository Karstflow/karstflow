//! Constants for genesis configuration parsing and validation.

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

// ---------------------------------------------------------------------------
// Cluster genesis hashes (base58-encoded 32-byte SHA256 of genesis.bin)
// ---------------------------------------------------------------------------

/// Devnet genesis hash.
pub const DEVNET_GENESIS_HASH: &str = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";

/// Testnet genesis hash.
pub const TESTNET_GENESIS_HASH: &str = "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY";

/// Mainnet-Beta genesis hash.
pub const MAINNET_GENESIS_HASH: &str = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";

// ---------------------------------------------------------------------------
// Cluster gossip entrypoints
// ---------------------------------------------------------------------------

pub const DEVNET_ENTRYPOINTS: &[&str] = &[
    "entrypoint.devnet.solana.com:8001",
    "entrypoint2.devnet.solana.com:8001",
    "entrypoint3.devnet.solana.com:8001",
];

pub const TESTNET_ENTRYPOINTS: &[&str] = &[
    "entrypoint.testnet.solana.com:8001",
    "entrypoint2.testnet.solana.com:8001",
    "entrypoint3.testnet.solana.com:8001",
];

pub const MAINNET_ENTRYPOINTS: &[&str] = &[
    "entrypoint.mainnet-beta.solana.com:8001",
    "entrypoint2.mainnet-beta.solana.com:8001",
    "entrypoint3.mainnet-beta.solana.com:8001",
    "entrypoint4.mainnet-beta.solana.com:8001",
    "entrypoint5.mainnet-beta.solana.com:8001",
];

// ---------------------------------------------------------------------------
// Default Solana port assignments
// ---------------------------------------------------------------------------

/// Gossip protocol port.
pub const DEFAULT_GOSSIP_PORT: u16 = 8001;

/// RPC API port.
pub const DEFAULT_RPC_PORT: u16 = 8899;

/// RPC WebSocket port.
pub const DEFAULT_RPC_PUBSUB_PORT: u16 = 8900;

/// TPU (transaction processing) port.
pub const DEFAULT_TPU_PORT: u16 = 8003;

/// TVU (turbine / shred reception) port.
pub const DEFAULT_TVU_PORT: u16 = 8000;

/// Repair protocol port.
pub const DEFAULT_REPAIR_PORT: u16 = 8007;

// ---------------------------------------------------------------------------
// Known shred versions per cluster
// ---------------------------------------------------------------------------

/// Devnet shred version (changes on cluster restarts).
pub const DEVNET_EXPECTED_SHRED_VERSION: u16 = 64557;

/// Testnet shred version (changes on cluster restarts).
pub const TESTNET_EXPECTED_SHRED_VERSION: u16 = 64316;

/// Mainnet-Beta shred version (changes on cluster restarts).
pub const MAINNET_EXPECTED_SHRED_VERSION: u16 = 50093;

// ---------------------------------------------------------------------------
// Development mode defaults
// ---------------------------------------------------------------------------

/// Default faucet balance for development mode genesis (500M SOL in lamports).
pub const DEV_FAUCET_LAMPORTS: u64 = 500_000_000 * crate::economics::LAMPORTS_PER_SOL;

/// Default identity balance for development mode genesis (500 SOL in lamports).
pub const DEV_IDENTITY_LAMPORTS: u64 = 500 * crate::economics::LAMPORTS_PER_SOL;

/// Maximum airdrop amount per request (10,000 SOL in lamports).
pub const MAX_AIRDROP_LAMPORTS: u64 = 10_000 * crate::economics::LAMPORTS_PER_SOL;
