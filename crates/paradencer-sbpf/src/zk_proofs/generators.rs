//! Pedersen commitment generator points.
//!
//! G is the standard Ristretto basepoint.
//! H is derived by hashing the compressed basepoint with SHA3-512 and mapping
//! the result to a Ristretto point. This matches the solana-zk-sdk definition.

use curve25519_dalek::{
    constants::{RISTRETTO_BASEPOINT_COMPRESSED, RISTRETTO_BASEPOINT_POINT},
    ristretto::RistrettoPoint,
};
use sha3::{Digest, Sha3_512};

/// Pedersen base point for encoding messages (standard Ristretto basepoint).
pub const G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;

/// Pedersen base point for encoding commitment openings.
///
/// Computed as `RistrettoPoint::from_uniform_bytes(SHA3-512(basepoint_compressed))`.
pub fn h_generator() -> RistrettoPoint {
    let hash = Sha3_512::digest(RISTRETTO_BASEPOINT_COMPRESSED.as_bytes());
    let mut wide_bytes = [0u8; 64];
    wide_bytes.copy_from_slice(&hash);
    RistrettoPoint::from_uniform_bytes(&wide_bytes)
}

/// Lazily computed H generator.
static H_POINT: std::sync::OnceLock<RistrettoPoint> = std::sync::OnceLock::new();

/// Returns the H generator point (cached after first computation).
pub fn h() -> &'static RistrettoPoint {
    H_POINT.get_or_init(h_generator)
}
