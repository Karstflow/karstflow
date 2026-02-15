//! Precompile programs that run outside the sBPF VM.
//!
//! These are native programs for computationally expensive operations
//! like cryptographic signature verification. They execute directly
//! in the validator runtime for maximum performance.

mod ed25519;
mod secp256k1;

pub use ed25519::Ed25519PrecompileExecutor;
pub use secp256k1::Secp256k1PrecompileExecutor;
