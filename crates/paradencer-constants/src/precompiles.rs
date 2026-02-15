/// Constants for precompile programs (native signature verification).
///
/// Precompiles run outside the sBPF VM and provide efficient
/// cryptographic operations such as signature verification.

// Ed25519 signature verification costs
pub const ED25519_VERIFY_COST: u64 = 3500;
pub const ED25519_VERIFY_PER_SIGNATURE: u64 = 1000;

// Secp256k1 ECDSA recovery costs
pub const SECP256K1_VERIFY_COST: u64 = 3500;
pub const SECP256K1_VERIFY_PER_SIGNATURE: u64 = 1500;
