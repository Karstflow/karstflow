//! Program Derived Address (PDA) creation and lookup.
//!
//! PDAs are addresses that are guaranteed to not lie on the ed25519
//! curve, making them safe for use as program-controlled accounts
//! (no private key can sign for them). They are derived by hashing
//! seeds together with a program ID and the "ProgramDerivedAddress"
//! domain separator.

use super::{SyscallContext, SyscallError};
use curve25519_dalek::edwards::CompressedEdwardsY;
use karstflow_constants::syscalls::*;
use karstflow_types::Pubkey;
use sha2::{Digest, Sha256};

/// Check if 32 bytes represent a valid ed25519 curve point.
/// PDAs must NOT be on the curve — if this returns true, the address is invalid as a PDA.
fn is_on_ed25519_curve(bytes: &[u8; 32]) -> bool {
    CompressedEdwardsY(*bytes).decompress().is_some()
}

/// Derive a program address from seeds, without metering.
///
/// Delegates to the canonical implementation beside `Pubkey`, which is where
/// every caller outside the VM reaches it. Returns `None` when the result lands
/// on the curve — the caller's signal to try another bump.
fn derive(seeds: &[&[u8]], program_id: &Pubkey) -> Option<Pubkey> {
    Pubkey::create_program_address(seeds, program_id)
}

/// Find the canonical program address for these seeds, outside a VM.
///
/// The metering is what makes the syscall different, and metering only makes
/// sense during execution. Genesis and the runtime need the address itself.
pub fn find_program_address(seeds: &[&[u8]], program_id: &Pubkey) -> Option<(Pubkey, u8)> {
    Pubkey::find_program_address(seeds, program_id)
}

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

    derive(seeds, program_id).ok_or(SyscallError::InvalidProgramAddress)
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

    // The loop stays here rather than calling `find_program_address`: each
    // rejected bump costs compute, and a helper that skipped ahead to the
    // answer would undercharge a program for the search it actually caused.
    for bump in (0..=255u8).rev() {
        ctx.consume_compute(FIND_PROGRAM_ADDRESS_PER_ITERATION)?;

        if let Some(key) = derive(&[seeds, &[&[bump]]].concat(), program_id) {
            return Ok((key, bump));
        }
    }

    Err(SyscallError::InvalidProgramAddress)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(budget: u64) -> SyscallContext {
        SyscallContext::new(Pubkey::new([0u8; 32]), budget)
    }

    fn program_id() -> Pubkey {
        Pubkey::new([1u8; 32])
    }

    #[test]
    fn create_program_address_with_known_bump() {
        // Use try_find to get a valid seed+bump, then verify create_program_address works
        let mut c = ctx(10_000_000);
        let pid = program_id();
        let (pda, bump) = try_find_program_address(&mut c, &[b"test"], &pid).unwrap();
        let mut c2 = ctx(1_000_000);
        let pda2 = create_program_address(&mut c2, &[b"test", &[bump]], &pid).unwrap();
        assert_eq!(pda, pda2);
    }

    #[test]
    fn create_program_address_deterministic() {
        let mut c1 = ctx(10_000_000);
        let pid = program_id();
        let (_, bump) = try_find_program_address(&mut c1, &[b"det"], &pid).unwrap();
        let mut c2 = ctx(1_000_000);
        let mut c3 = ctx(1_000_000);
        let pda1 = create_program_address(&mut c2, &[b"det", &[bump]], &pid).unwrap();
        let pda2 = create_program_address(&mut c3, &[b"det", &[bump]], &pid).unwrap();
        assert_eq!(pda1, pda2);
    }

    #[test]
    fn create_program_address_different_seeds_differ() {
        let mut c = ctx(20_000_000);
        let pid = program_id();
        let (_, bump_a) = try_find_program_address(&mut c, &[b"diff_a"], &pid).unwrap();
        let (_, bump_b) = try_find_program_address(&mut c, &[b"diff_b"], &pid).unwrap();
        let mut c1 = ctx(1_000_000);
        let mut c2 = ctx(1_000_000);
        let pda1 = create_program_address(&mut c1, &[b"diff_a", &[bump_a]], &pid).unwrap();
        let pda2 = create_program_address(&mut c2, &[b"diff_b", &[bump_b]], &pid).unwrap();
        assert_ne!(pda1, pda2);
    }

    #[test]
    fn create_program_address_rejects_too_many_seeds() {
        let mut c = ctx(1_000_000);
        let pid = program_id();
        let seeds: Vec<&[u8]> = (0..MAX_SIGNER_SEEDS + 1).map(|_| b"x" as &[u8]).collect();
        assert!(matches!(
            create_program_address(&mut c, &seeds, &pid),
            Err(SyscallError::InvalidSeeds)
        ));
    }

    #[test]
    fn create_program_address_rejects_oversized_seed() {
        let mut c = ctx(1_000_000);
        let pid = program_id();
        let big_seed = vec![0u8; MAX_SEED_BYTES + 1];
        assert!(matches!(
            create_program_address(&mut c, &[&big_seed], &pid),
            Err(SyscallError::InvalidSeeds)
        ));
    }

    #[test]
    fn try_find_program_address_returns_pda_and_bump() {
        let mut c = ctx(10_000_000);
        let pid = program_id();
        let (pda, bump) = try_find_program_address(&mut c, &[b"find_me"], &pid).unwrap();
        assert!(!pda.as_bytes().iter().all(|&b| b == 0));
        // The bump should produce the same PDA via create_program_address
        let mut c2 = ctx(1_000_000);
        let pda2 = create_program_address(&mut c2, &[b"find_me", &[bump]], &pid).unwrap();
        assert_eq!(pda, pda2);
    }

    #[test]
    fn try_find_rejects_too_many_seeds() {
        let mut c = ctx(1_000_000);
        let pid = program_id();
        // MAX_SIGNER_SEEDS seeds → adding bump would exceed limit
        let seeds: Vec<&[u8]> = (0..MAX_SIGNER_SEEDS).map(|_| b"x" as &[u8]).collect();
        assert!(matches!(
            try_find_program_address(&mut c, &seeds, &pid),
            Err(SyscallError::InvalidSeeds)
        ));
    }

    #[test]
    fn is_on_curve_accepts_identity() {
        // The identity point of ed25519 (compressed form: [1, 0, ..., 0])
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        assert!(is_on_ed25519_curve(&bytes));
    }

    #[test]
    fn is_on_curve_rejects_invalid_point() {
        // y=2 yields a non-quadratic-residue for x² on the ed25519 curve,
        // so no valid point exists with this compressed encoding.
        let mut bytes = [0u8; 32];
        bytes[0] = 2;
        assert!(!is_on_ed25519_curve(&bytes));
    }

    #[test]
    fn context_free_derivation_agrees_with_the_syscall() {
        // The two exist so that genesis and a running program can derive the
        // same address. If they ever disagreed, a program's data would sit
        // where no client would look for it, and nothing in either path alone
        // would show it.
        let program = program_id();
        let seeds: &[&[u8]] = &[b"programdata", &[7u8; 32]];

        let (expected, expected_bump) =
            try_find_program_address(&mut ctx(1_000_000), seeds, &program)
                .expect("syscall derives");
        let (actual, actual_bump) = find_program_address(seeds, &program).expect("helper derives");

        assert_eq!(actual, expected);
        assert_eq!(actual_bump, expected_bump);
    }

    #[test]
    fn context_free_derivation_rejects_oversized_input() {
        let program = program_id();
        let too_long = vec![0u8; MAX_SEED_BYTES + 1];
        assert!(find_program_address(&[&too_long], &program).is_none());

        let too_many: Vec<&[u8]> = vec![b"x"; MAX_SIGNER_SEEDS];
        assert!(find_program_address(&too_many, &program).is_none());
    }
}
