//! Program Derived Address (PDA) creation and lookup.
//!
//! PDAs are addresses that are guaranteed to not lie on the ed25519
//! curve, making them safe for use as program-controlled accounts
//! (no private key can sign for them). They are derived by hashing
//! seeds together with a program ID and the "ProgramDerivedAddress"
//! domain separator.

use super::{SyscallContext, SyscallError};
use paradencer_constants::syscalls::*;
use paradencer_types::Pubkey;
use sha2::{Digest, Sha256};

/// Create a program address from seeds and a program ID.
///
/// Computes `SHA256(seeds || program_id || "ProgramDerivedAddress")`.
/// In a full implementation, this would also verify the result is
/// NOT on the ed25519 curve. Currently uses a simplified check.
pub fn create_program_address(
    ctx: &mut SyscallContext,
    seeds: &[&[u8]],
    program_id: &Pubkey,
) -> Result<Pubkey, SyscallError> {
    ctx.consume_compute(CREATE_PROGRAM_ADDRESS_COST)?;

    // Validate seed count
    if seeds.len() > MAX_SIGNER_SEEDS {
        return Err(SyscallError::InvalidSeeds);
    }

    // Validate individual seed lengths
    for seed in seeds {
        if seed.len() > MAX_SEED_BYTES {
            return Err(SyscallError::InvalidSeeds);
        }
    }

    // Hash: seeds || program_id || "ProgramDerivedAddress"
    let mut hasher = Sha256::new();
    for seed in seeds {
        hasher.update(seed);
    }
    hasher.update(program_id.as_bytes());
    hasher.update(b"ProgramDerivedAddress");
    let hash = hasher.finalize();

    let bytes: [u8; 32] = hash.into();

    // In production, we would check that the resulting point is NOT
    // on the ed25519 curve. If it is, the address is invalid.
    // For now, accept all results (simplified).
    Ok(Pubkey::new(bytes))
}

/// Find a valid PDA by iterating bump seeds from 255 down to 0.
///
/// Appends a single-byte bump seed to the provided seeds and attempts
/// to derive a PDA. Returns the first valid PDA along with its bump.
/// Charges additional compute for each iteration.
pub fn try_find_program_address(
    ctx: &mut SyscallContext,
    seeds: &[&[u8]],
    program_id: &Pubkey,
) -> Result<(Pubkey, u8), SyscallError> {
    ctx.consume_compute(FIND_PROGRAM_ADDRESS_COST)?;

    // Validate seed count (the bump will add one more seed)
    if seeds.len() >= MAX_SIGNER_SEEDS {
        return Err(SyscallError::InvalidSeeds);
    }

    for seed in seeds {
        if seed.len() > MAX_SEED_BYTES {
            return Err(SyscallError::InvalidSeeds);
        }
    }

    for bump in (0..=255u8).rev() {
        ctx.consume_compute(FIND_PROGRAM_ADDRESS_PER_ITERATION)?;

        let bump_bytes = [bump];

        let mut hasher = Sha256::new();
        for seed in seeds {
            hasher.update(seed);
        }
        hasher.update(&bump_bytes);
        hasher.update(program_id.as_bytes());
        hasher.update(b"ProgramDerivedAddress");
        let hash = hasher.finalize();
        let bytes: [u8; 32] = hash.into();

        // In production, we would check that the result is NOT on the
        // ed25519 curve. If it is not on the curve, it is a valid PDA.
        // Simplified: accept on the first iteration (bump=255).
        return Ok((Pubkey::new(bytes), bump));
    }

    Err(SyscallError::InvalidProgramAddress)
}
