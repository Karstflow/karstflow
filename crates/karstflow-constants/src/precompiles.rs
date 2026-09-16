//! Constants for precompile programs (native signature verification).
//!
//! Precompiles run outside the sBPF VM and provide efficient
//! cryptographic operations such as signature verification.

/// Compute units a precompile instruction charges: none.
///
/// Signature verification for a precompile happens during transaction
/// verification, and is paid for by the per-signature transaction fee rather
/// than by the compute meter. Processing the instruction itself therefore
/// consumes nothing, on both the success and the failure path.
pub const PRECOMPILE_COMPUTE_UNITS: u64 = 0;
