//! Pre-execution estimate of the account data a transaction requests to allocate.
//!
//! The block-level cost tracker caps the total amount of new account data a
//! single block may allocate. That cap is enforced from a transaction's
//! system-program instructions *before* execution, so every validator derives
//! an identical value for a given transaction — the estimate is
//! consensus-critical.
//!
//! Mirrors the reference cost model's allocated-accounts-data-size calculation:
//! each system-program instruction is decoded for its requested `space`; any
//! decode failure (unknown discriminant, truncated fields, or the prefund
//! instruction while its feature is inactive) zeroes the *entire* transaction's
//! allocation; an oversized `space` likewise zeroes it; and the per-transaction
//! total is capped at twice the maximum account size.

use karstflow_constants::bpf_loader_program::MAX_PERMITTED_DATA_LENGTH;
use karstflow_ids::SYSTEM_PROGRAM_ID;
use karstflow_storage::Pubkey;

// System-program instruction discriminants (bincode: 4-byte little-endian u32).
const CREATE_ACCOUNT: u32 = 0;
const ASSIGN: u32 = 1;
const TRANSFER: u32 = 2;
const CREATE_ACCOUNT_WITH_SEED: u32 = 3;
const ADVANCE_NONCE_ACCOUNT: u32 = 4;
const WITHDRAW_NONCE_ACCOUNT: u32 = 5;
const INITIALIZE_NONCE_ACCOUNT: u32 = 6;
const AUTHORIZE_NONCE_ACCOUNT: u32 = 7;
const ALLOCATE: u32 = 8;
const ALLOCATE_WITH_SEED: u32 = 9;
const ASSIGN_WITH_SEED: u32 = 10;
const TRANSFER_WITH_SEED: u32 = 11;
const UPGRADE_NONCE_ACCOUNT: u32 = 12;
const CREATE_ACCOUNT_ALLOW_PREFUND: u32 = 13;

const DISCRIMINANT_LEN: usize = 4;
const U64_LEN: usize = 8;
const PUBKEY_LEN: usize = 32;

/// Per-transaction allocation cap (2 × maximum account size), matching the
/// reference's `min( 2*FD_RUNTIME_ACC_SZ_MAX, .. )`.
const MAX_ALLOCATED_PER_TX: u64 = 2 * MAX_PERMITTED_DATA_LENGTH;

/// Compute the total account data size a transaction requests to allocate.
///
/// `instructions` yields `(program_id, instruction_data)` pairs in transaction
/// order. `prefund_active` reflects whether the `create_account_allow_prefund`
/// feature is active for the current bank.
pub fn calculate_allocated_accounts_data_size<'a>(
    instructions: impl IntoIterator<Item = (&'a Pubkey, &'a [u8])>,
    prefund_active: bool,
) -> u64 {
    let mut total: u64 = 0;
    for (program_id, data) in instructions {
        if *program_id != SYSTEM_PROGRAM_ID {
            continue;
        }
        let space = match decode_space(data, prefund_active) {
            Some(space) => space,
            // A decode failure zeroes the whole transaction's allocation.
            None => return 0,
        };
        if space > MAX_PERMITTED_DATA_LENGTH {
            return 0;
        }
        total = total.saturating_add(space);
    }
    total.min(MAX_ALLOCATED_PER_TX)
}

/// Decode a single system-program instruction's requested `space`.
///
/// Returns `Some(space)` (with `space == 0` for non-allocating instructions) on
/// a successful decode, or `None` when the instruction cannot be decoded.
fn decode_space(data: &[u8], prefund_active: bool) -> Option<u64> {
    let discriminant = read_discriminant(data)?;
    match discriminant {
        // disc(4) + lamports(8) + space(8) + owner(32) = 52
        CREATE_ACCOUNT => fixed_space(data, 52, 12),
        // disc(4) + owner(32) = 36
        ASSIGN => fixed_none(data, 36),
        // disc(4) + lamports(8) = 12
        TRANSFER => fixed_none(data, 12),
        // disc(4) + base(32) + seed(8+len) + lamports(8) + space(8) + owner(32)
        CREATE_ACCOUNT_WITH_SEED => seed_space(
            data,
            DISCRIMINANT_LEN + PUBKEY_LEN,
            U64_LEN,
            true,
            PUBKEY_LEN,
        ),
        // disc(4) = 4
        ADVANCE_NONCE_ACCOUNT => fixed_none(data, 4),
        // disc(4) + lamports(8) = 12
        WITHDRAW_NONCE_ACCOUNT => fixed_none(data, 12),
        // disc(4) + authority(32) = 36
        INITIALIZE_NONCE_ACCOUNT => fixed_none(data, 36),
        // disc(4) + new_authority(32) = 36
        AUTHORIZE_NONCE_ACCOUNT => fixed_none(data, 36),
        // disc(4) + space(8) = 12
        ALLOCATE => fixed_space(data, 12, 4),
        // disc(4) + base(32) + seed(8+len) + space(8) + owner(32)
        ALLOCATE_WITH_SEED => seed_space(data, DISCRIMINANT_LEN + PUBKEY_LEN, 0, true, PUBKEY_LEN),
        // disc(4) + base(32) + seed(8+len) + owner(32)
        ASSIGN_WITH_SEED => seed_space(data, DISCRIMINANT_LEN + PUBKEY_LEN, 0, false, PUBKEY_LEN),
        // disc(4) + lamports(8) + from_seed(8+len) + from_owner(32)
        TRANSFER_WITH_SEED => seed_space(data, DISCRIMINANT_LEN + U64_LEN, 0, false, PUBKEY_LEN),
        // disc(4) = 4
        UPGRADE_NONCE_ACCOUNT => fixed_none(data, 4),
        // disc(4) + lamports(8) + space(8) + owner(32) = 52; gated on the feature
        CREATE_ACCOUNT_ALLOW_PREFUND => {
            if !prefund_active {
                return None;
            }
            fixed_space(data, 52, 12)
        }
        // Unknown discriminant — cannot decode.
        _ => None,
    }
}

/// Read the 4-byte little-endian discriminant, or `None` if absent.
fn read_discriminant(data: &[u8]) -> Option<u32> {
    let bytes = data.get(0..DISCRIMINANT_LEN)?;
    Some(u32::from_le_bytes(bytes.try_into().unwrap()))
}

/// Read a `u64` at `offset`, or `None` if it would read past the end.
fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(U64_LEN)?;
    let bytes = data.get(offset..end)?;
    Some(u64::from_le_bytes(bytes.try_into().unwrap()))
}

/// Fixed-layout non-allocating instruction: succeed (contributing 0) only when
/// the full footprint is present.
fn fixed_none(data: &[u8], footprint: usize) -> Option<u64> {
    (data.len() >= footprint).then_some(0)
}

/// Fixed-layout allocating instruction: validate the footprint and read the
/// `space` field at `space_offset`.
fn fixed_space(data: &[u8], footprint: usize, space_offset: usize) -> Option<u64> {
    if data.len() < footprint {
        return None;
    }
    read_u64(data, space_offset)
}

/// Seed-bearing instruction: validate the footprint and, when present, read the
/// `space` field that follows the seed.
///
/// - `pre_seed` = bytes before the 8-byte seed length (discriminant + any
///   fixed-size fields, e.g. `base` or `lamports`).
/// - `post_seed_before_space` = bytes between the seed and the `space` field
///   (e.g. `lamports` for CreateAccountWithSeed; 0 otherwise).
/// - `has_space` = whether a `space: u64` field follows the seed.
/// - `trailing` = bytes after `space` (or after the seed when `!has_space`),
///   e.g. the `owner` pubkey.
fn seed_space(
    data: &[u8],
    pre_seed: usize,
    post_seed_before_space: usize,
    has_space: bool,
    trailing: usize,
) -> Option<u64> {
    let seed_len = read_u64(data, pre_seed)? as usize;
    let after_seed = pre_seed.checked_add(U64_LEN)?.checked_add(seed_len)?;

    if has_space {
        let space_offset = after_seed.checked_add(post_seed_before_space)?;
        let space = read_u64(data, space_offset)?;
        let footprint = space_offset.checked_add(U64_LEN)?.checked_add(trailing)?;
        (data.len() >= footprint).then_some(space)
    } else {
        let footprint = after_seed
            .checked_add(post_seed_before_space)?
            .checked_add(trailing)?;
        (data.len() >= footprint).then_some(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYSTEM: Pubkey = SYSTEM_PROGRAM_ID;
    const TEN_MB: u64 = MAX_PERMITTED_DATA_LENGTH;

    fn other_program() -> Pubkey {
        Pubkey::new([7u8; 32])
    }

    /// CreateAccount(space): disc(0) + lamports + space + owner.
    fn create_account(space: u64) -> Vec<u8> {
        let mut d = CREATE_ACCOUNT.to_le_bytes().to_vec();
        d.extend_from_slice(&0u64.to_le_bytes()); // lamports
        d.extend_from_slice(&space.to_le_bytes()); // space
        d.extend_from_slice(&[0u8; PUBKEY_LEN]); // owner
        d
    }

    /// Allocate(space): disc(8) + space.
    fn allocate(space: u64) -> Vec<u8> {
        let mut d = ALLOCATE.to_le_bytes().to_vec();
        d.extend_from_slice(&space.to_le_bytes());
        d
    }

    /// AllocateWithSeed: disc(9) + base + seed(len+bytes) + space + owner.
    fn allocate_with_seed(seed: &[u8], space: u64) -> Vec<u8> {
        let mut d = ALLOCATE_WITH_SEED.to_le_bytes().to_vec();
        d.extend_from_slice(&[1u8; PUBKEY_LEN]); // base
        d.extend_from_slice(&(seed.len() as u64).to_le_bytes());
        d.extend_from_slice(seed);
        d.extend_from_slice(&space.to_le_bytes());
        d.extend_from_slice(&[2u8; PUBKEY_LEN]); // owner
        d
    }

    /// CreateAccountWithSeed: disc(3) + base + seed(len+bytes) + lamports + space + owner.
    fn create_account_with_seed(seed: &[u8], space: u64) -> Vec<u8> {
        let mut d = CREATE_ACCOUNT_WITH_SEED.to_le_bytes().to_vec();
        d.extend_from_slice(&[1u8; PUBKEY_LEN]); // base
        d.extend_from_slice(&(seed.len() as u64).to_le_bytes());
        d.extend_from_slice(seed);
        d.extend_from_slice(&0u64.to_le_bytes()); // lamports
        d.extend_from_slice(&space.to_le_bytes());
        d.extend_from_slice(&[2u8; PUBKEY_LEN]); // owner
        d
    }

    /// CreateAccountAllowPrefund: same layout as CreateAccount, disc(13).
    fn create_account_allow_prefund(space: u64) -> Vec<u8> {
        let mut d = CREATE_ACCOUNT_ALLOW_PREFUND.to_le_bytes().to_vec();
        d.extend_from_slice(&0u64.to_le_bytes()); // lamports
        d.extend_from_slice(&space.to_le_bytes());
        d.extend_from_slice(&[0u8; PUBKEY_LEN]); // owner
        d
    }

    /// Transfer: disc(2) + lamports.
    fn transfer() -> Vec<u8> {
        let mut d = TRANSFER.to_le_bytes().to_vec();
        d.extend_from_slice(&100u64.to_le_bytes());
        d
    }

    fn calc<'a>(ixs: impl IntoIterator<Item = (&'a Pubkey, &'a [u8])>, prefund: bool) -> u64 {
        calculate_allocated_accounts_data_size(ixs, prefund)
    }

    #[test]
    fn non_system_program_ignored() {
        let other = other_program();
        let data = create_account(1_000);
        // A create-account-looking payload under a non-system program contributes 0.
        assert_eq!(calc([(&other, data.as_slice())], false), 0);
    }

    #[test]
    fn create_account_counts_space() {
        let data = create_account(5_000);
        assert_eq!(calc([(&SYSTEM, data.as_slice())], false), 5_000);
    }

    #[test]
    fn allocate_counts_space() {
        let data = allocate(4_096);
        assert_eq!(calc([(&SYSTEM, data.as_slice())], false), 4_096);
    }

    #[test]
    fn allocate_with_seed_counts_space() {
        let data = allocate_with_seed(b"my-seed", 8_192);
        assert_eq!(calc([(&SYSTEM, data.as_slice())], false), 8_192);
    }

    #[test]
    fn create_account_with_seed_counts_space() {
        let data = create_account_with_seed(b"abc", 1_234);
        assert_eq!(calc([(&SYSTEM, data.as_slice())], false), 1_234);
    }

    #[test]
    fn non_allocating_instruction_contributes_zero() {
        let data = transfer();
        assert_eq!(calc([(&SYSTEM, data.as_slice())], false), 0);
    }

    #[test]
    fn multiple_allocations_sum() {
        let a = create_account(1_000);
        let b = allocate(2_000);
        assert_eq!(
            calc([(&SYSTEM, a.as_slice()), (&SYSTEM, b.as_slice())], false),
            3_000
        );
    }

    #[test]
    fn space_over_max_zeroes_whole_tx() {
        let big = create_account(TEN_MB + 1);
        let small = create_account(100);
        // The oversized instruction zeroes the whole transaction's allocation.
        assert_eq!(
            calc(
                [(&SYSTEM, big.as_slice()), (&SYSTEM, small.as_slice())],
                false
            ),
            0
        );
    }

    #[test]
    fn space_at_max_is_allowed() {
        let data = create_account(TEN_MB);
        assert_eq!(calc([(&SYSTEM, data.as_slice())], false), TEN_MB);
    }

    #[test]
    fn per_tx_total_capped_at_twice_max() {
        // Two instructions each at the max → sum 20 MB, capped at 2 × 10 MB.
        let a = create_account(TEN_MB);
        let b = allocate(TEN_MB);
        assert_eq!(
            calc([(&SYSTEM, a.as_slice()), (&SYSTEM, b.as_slice())], false),
            2 * TEN_MB
        );
    }

    #[test]
    fn empty_data_zeroes_whole_tx() {
        let empty: &[u8] = &[];
        let good = create_account(500);
        // A zero-length system instruction fails to decode → whole tx is 0.
        assert_eq!(
            calc([(&SYSTEM, empty), (&SYSTEM, good.as_slice())], false),
            0
        );
    }

    #[test]
    fn truncated_create_account_zeroes_whole_tx() {
        let mut data = create_account(500);
        data.truncate(40); // drop part of the owner field
        assert_eq!(calc([(&SYSTEM, data.as_slice())], false), 0);
    }

    #[test]
    fn unknown_discriminant_zeroes_whole_tx() {
        let mut data = 99u32.to_le_bytes().to_vec();
        data.extend_from_slice(&[0u8; 48]);
        assert_eq!(calc([(&SYSTEM, data.as_slice())], false), 0);
    }

    #[test]
    fn prefund_inactive_zeroes_whole_tx() {
        let data = create_account_allow_prefund(1_000);
        assert_eq!(calc([(&SYSTEM, data.as_slice())], false), 0);
    }

    #[test]
    fn prefund_active_counts_space() {
        let data = create_account_allow_prefund(1_000);
        assert_eq!(calc([(&SYSTEM, data.as_slice())], true), 1_000);
    }

    #[test]
    fn truncated_seed_instruction_zeroes_whole_tx() {
        let mut data = allocate_with_seed(b"seed", 1_000);
        data.truncate(DISCRIMINANT_LEN + PUBKEY_LEN + 4); // cut inside the seed length
        assert_eq!(calc([(&SYSTEM, data.as_slice())], false), 0);
    }

    #[test]
    fn huge_seed_len_does_not_overflow() {
        // A seed length of u64::MAX must not panic; it simply fails to decode.
        let mut data = ALLOCATE_WITH_SEED.to_le_bytes().to_vec();
        data.extend_from_slice(&[1u8; PUBKEY_LEN]); // base
        data.extend_from_slice(&u64::MAX.to_le_bytes()); // seed_len
        data.extend_from_slice(&[0u8; 8]); // partial body
        assert_eq!(calc([(&SYSTEM, data.as_slice())], false), 0);
    }

    #[test]
    fn no_instructions_is_zero() {
        let none: [(&Pubkey, &[u8]); 0] = [];
        assert_eq!(calc(none, false), 0);
    }
}
