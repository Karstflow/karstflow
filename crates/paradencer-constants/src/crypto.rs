/// Constants for cryptographic operations across the validator.
///
/// Defines key/hash/signature sizes for all supported algorithms and
/// compute unit costs for on-chain cryptographic syscalls.

// --- Hash output sizes ---

/// SHA-256 digest size in bytes.
pub const SHA256_DIGEST_SIZE: usize = 32;

/// Keccak-256 digest size in bytes.
pub const KECCAK256_DIGEST_SIZE: usize = 32;

/// Blake3 digest size in bytes.
pub const BLAKE3_DIGEST_SIZE: usize = 32;

// --- Ed25519 ---

/// Ed25519 public key size in bytes.
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;

/// Ed25519 signature size in bytes.
pub const ED25519_SIGNATURE_SIZE: usize = 64;

/// Ed25519 secret key (seed) size in bytes.
pub const ED25519_SECRET_KEY_SIZE: usize = 32;

// --- Secp256k1 (ECDSA) ---

/// Secp256k1 compressed public key size in bytes.
pub const SECP256K1_PUBLIC_KEY_COMPRESSED_SIZE: usize = 33;

/// Secp256k1 uncompressed public key size in bytes (without 0x04 prefix).
pub const SECP256K1_PUBLIC_KEY_UNCOMPRESSED_SIZE: usize = 64;

/// Secp256k1 full uncompressed public key with 0x04 prefix.
pub const SECP256K1_PUBLIC_KEY_FULL_SIZE: usize = 65;

/// Secp256k1 ECDSA signature (r + s) size in bytes.
pub const SECP256K1_SIGNATURE_SIZE: usize = 64;

/// Secp256k1 recoverable signature (r + s + recovery_id) size in bytes.
pub const SECP256K1_RECOVERABLE_SIGNATURE_SIZE: usize = 65;

/// Ethereum address size in bytes (last 20 bytes of keccak256(pubkey)).
pub const ETH_ADDRESS_SIZE: usize = 20;

// --- Secp256r1 (P-256 / NIST P-256) ---

/// Secp256r1 compressed public key size in bytes.
pub const SECP256R1_PUBLIC_KEY_COMPRESSED_SIZE: usize = 33;

/// Secp256r1 uncompressed public key size in bytes (without 0x04 prefix).
pub const SECP256R1_PUBLIC_KEY_UNCOMPRESSED_SIZE: usize = 64;

/// Secp256r1 ECDSA signature (r + s) size in bytes.
pub const SECP256R1_SIGNATURE_SIZE: usize = 64;

// --- BN254 (alt_bn128) ---

/// BN254 G1 point size (x, y coordinates, 32 bytes each).
pub const BN254_G1_POINT_SIZE: usize = 64;

/// BN254 G2 point size (x, y coordinates as Fp2 elements, 64 bytes each).
pub const BN254_G2_POINT_SIZE: usize = 128;

/// BN254 scalar field element size in bytes.
pub const BN254_SCALAR_SIZE: usize = 32;

/// BN254 point addition input size (two G1 points).
pub const BN254_ADD_INPUT_SIZE: usize = 128;

/// BN254 scalar multiplication input size (G1 point + scalar).
pub const BN254_MUL_INPUT_SIZE: usize = 96;

/// BN254 pairing input pair size (G1 point + G2 point).
pub const BN254_PAIRING_PAIR_SIZE: usize = 192;

// --- Compute unit costs for syscalls ---

/// Base cost for a SHA-256 hash syscall invocation.
pub const SHA256_SYSCALL_BASE_COST: u64 = 100;

/// Per-byte cost for SHA-256 hashing.
pub const SHA256_SYSCALL_PER_BYTE_COST: u64 = 2;

/// Base cost for a Keccak-256 hash syscall invocation.
pub const KECCAK256_SYSCALL_BASE_COST: u64 = 100;

/// Per-byte cost for Keccak-256 hashing.
pub const KECCAK256_SYSCALL_PER_BYTE_COST: u64 = 2;

/// Base cost for a Blake3 hash syscall invocation.
pub const BLAKE3_SYSCALL_BASE_COST: u64 = 100;

/// Per-byte cost for Blake3 hashing.
pub const BLAKE3_SYSCALL_PER_BYTE_COST: u64 = 2;

/// Compute cost for secp256k1 public key recovery.
pub const SECP256K1_RECOVER_SYSCALL_COST: u64 = 25_000;

// --- Compute unit costs for curve operations ---

/// Compute cost for BN254 G1 point addition.
pub const BN254_ADD_SYSCALL_COST: u64 = 334;

/// Compute cost for BN254 G1 scalar multiplication.
pub const BN254_MUL_SYSCALL_COST: u64 = 3_840;

/// Base compute cost for BN254 pairing check (before per-pair cost).
pub const BN254_PAIRING_SYSCALL_BASE_COST: u64 = 36_364;

/// Per-pair compute cost for BN254 pairing check.
pub const BN254_PAIRING_SYSCALL_PER_PAIR_COST: u64 = 12_121;
