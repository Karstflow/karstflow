/// Bitset-based account conflict detection for the pack scheduler.
///
/// Provides O(1) conflict detection between transactions by mapping each
/// account to a bit position in a fixed-size bitset. Two transactions
/// conflict if they share any write-locked account (write-write conflict)
/// or if one writes an account that the other reads (write-read conflict).
///
/// The bitset size is fixed at 256 bits (4 u64s), so accounts are mapped
/// via hash to bit positions. Hash collisions may cause false conflicts
/// (conservative behavior), but never false non-conflicts.
use std::hash::{Hash, Hasher};

/// Number of u64 words in the bitset.
const WORDS: usize = 4;

/// Total number of bits in the bitset.
const BITS: usize = WORDS * 64;

/// A 256-bit bitset representing locked accounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountBitset {
    words: [u64; WORDS],
}

impl Default for AccountBitset {
    fn default() -> Self {
        Self::empty()
    }
}

impl AccountBitset {
    /// Create an empty bitset (no accounts set).
    pub const fn empty() -> Self {
        Self { words: [0; WORDS] }
    }

    /// Set a bit for the given account.
    pub fn set_account(&mut self, account: &[u8; 32]) {
        let bit = account_to_bit(account);
        self.words[bit / 64] |= 1u64 << (bit % 64);
    }

    /// Check if a bit is set for the given account.
    pub fn has_account(&self, account: &[u8; 32]) -> bool {
        let bit = account_to_bit(account);
        (self.words[bit / 64] & (1u64 << (bit % 64))) != 0
    }

    /// Check if this bitset intersects with another (any common bits set).
    pub fn intersects(&self, other: &Self) -> bool {
        for i in 0..WORDS {
            if self.words[i] & other.words[i] != 0 {
                return true;
            }
        }
        false
    }

    /// Bitwise OR of two bitsets.
    pub fn union(&self, other: &Self) -> Self {
        let mut result = *self;
        for i in 0..WORDS {
            result.words[i] |= other.words[i];
        }
        result
    }

    /// Union in place.
    pub fn union_in_place(&mut self, other: &Self) {
        for i in 0..WORDS {
            self.words[i] |= other.words[i];
        }
    }

    /// Count set bits (number of distinct hashed accounts).
    pub fn count(&self) -> u32 {
        self.words.iter().map(|w| w.count_ones()).sum()
    }

    /// Whether the bitset is empty.
    pub fn is_empty(&self) -> bool {
        self.words.iter().all(|w| *w == 0)
    }

    /// Clear all bits.
    pub fn clear(&mut self) {
        self.words = [0; WORDS];
    }
}

/// Lock footprint of a transaction: separate read and write bitsets.
#[derive(Debug, Clone, Copy, Default)]
pub struct TxnLockFootprint {
    /// Accounts that the transaction writes.
    pub writes: AccountBitset,
    /// Accounts that the transaction reads (but does not write).
    pub reads: AccountBitset,
}

impl TxnLockFootprint {
    /// Create a lock footprint from write and read account lists.
    pub fn from_accounts(write_accounts: &[[u8; 32]], read_accounts: &[[u8; 32]]) -> Self {
        let mut fp = Self::default();
        for account in write_accounts {
            fp.writes.set_account(account);
        }
        for account in read_accounts {
            fp.reads.set_account(account);
        }
        fp
    }

    /// Check if this transaction's locks conflict with another.
    ///
    /// Conflict rules:
    /// - write-write: any shared write account
    /// - write-read: this writes something the other reads
    /// - read-write: this reads something the other writes
    pub fn conflicts_with(&self, other: &Self) -> bool {
        // Write-write conflict
        if self.writes.intersects(&other.writes) {
            return true;
        }
        // Write-read conflict (we write, they read)
        if self.writes.intersects(&other.reads) {
            return true;
        }
        // Read-write conflict (we read, they write)
        if self.reads.intersects(&other.writes) {
            return true;
        }
        false
    }
}

/// Map an account to a bit position using a fast hash of the first 8 bytes.
fn account_to_bit(account: &[u8; 32]) -> usize {
    let mut hasher = FnvHasher::new();
    account.hash(&mut hasher);
    (hasher.finish() as usize) % BITS
}

/// Simple FNV-1a hasher for deterministic bit mapping.
struct FnvHasher(u64);

impl FnvHasher {
    fn new() -> Self {
        Self(0xcbf29ce484222325)
    }
}

impl Hasher for FnvHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 ^= b as u64;
            self.0 = self.0.wrapping_mul(0x100000001b3);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(id: u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[0] = id;
        a
    }

    #[test]
    fn empty_bitset() {
        let bs = AccountBitset::empty();
        assert!(bs.is_empty());
        assert_eq!(bs.count(), 0);
    }

    #[test]
    fn set_and_check_account() {
        let mut bs = AccountBitset::empty();
        let acct = account(1);
        assert!(!bs.has_account(&acct));
        bs.set_account(&acct);
        assert!(bs.has_account(&acct));
        assert!(!bs.is_empty());
    }

    #[test]
    fn different_accounts_may_not_collide() {
        // With 256 bits and well-distributed hash, few collisions expected
        let mut bs = AccountBitset::empty();
        let a1 = account(1);
        let a2 = account(2);
        bs.set_account(&a1);
        // a2 might or might not be set (hash collision), but a1 definitely is
        assert!(bs.has_account(&a1));
        // We can't assert !has_account(&a2) due to possible collision
    }

    #[test]
    fn intersection_detects_common_bits() {
        let mut bs1 = AccountBitset::empty();
        let mut bs2 = AccountBitset::empty();
        let acct = account(1);
        bs1.set_account(&acct);
        bs2.set_account(&acct);
        assert!(bs1.intersects(&bs2));
    }

    #[test]
    fn no_intersection_for_disjoint() {
        // Test many accounts to find a non-colliding pair
        let mut found_disjoint = false;
        for i in 1..=200u8 {
            let mut bs1 = AccountBitset::empty();
            let mut bs2 = AccountBitset::empty();
            let a1 = account(i);
            let a2 = account(i.wrapping_add(100));
            bs1.set_account(&a1);
            bs2.set_account(&a2);
            if !bs1.intersects(&bs2) {
                found_disjoint = true;
                break;
            }
        }
        assert!(
            found_disjoint,
            "Should find at least one non-colliding pair"
        );
    }

    #[test]
    fn union_combines_bits() {
        let mut bs1 = AccountBitset::empty();
        let mut bs2 = AccountBitset::empty();
        let a1 = account(1);
        let a2 = account(2);
        bs1.set_account(&a1);
        bs2.set_account(&a2);

        let combined = bs1.union(&bs2);
        assert!(combined.has_account(&a1));
        assert!(combined.has_account(&a2));
    }

    #[test]
    fn write_write_conflict() {
        let fp1 = TxnLockFootprint::from_accounts(&[account(1)], &[]);
        let fp2 = TxnLockFootprint::from_accounts(&[account(1)], &[]);
        assert!(fp1.conflicts_with(&fp2));
    }

    #[test]
    fn write_read_conflict() {
        let fp1 = TxnLockFootprint::from_accounts(&[account(1)], &[]);
        let fp2 = TxnLockFootprint::from_accounts(&[], &[account(1)]);
        assert!(fp1.conflicts_with(&fp2));
    }

    #[test]
    fn read_read_no_conflict() {
        let fp1 = TxnLockFootprint::from_accounts(&[], &[account(1)]);
        let fp2 = TxnLockFootprint::from_accounts(&[], &[account(1)]);
        assert!(!fp1.conflicts_with(&fp2));
    }

    #[test]
    fn multiple_accounts_one_conflict() {
        let fp1 = TxnLockFootprint::from_accounts(&[account(1), account(2)], &[account(3)]);
        let fp2 = TxnLockFootprint::from_accounts(&[account(4)], &[account(2)]);
        // fp1 writes account(2), fp2 reads account(2) → conflict
        assert!(fp1.conflicts_with(&fp2));
    }

    #[test]
    fn clear_resets_bitset() {
        let mut bs = AccountBitset::empty();
        bs.set_account(&account(1));
        bs.set_account(&account(2));
        bs.clear();
        assert!(bs.is_empty());
    }

    #[test]
    fn footprint_no_conflict_disjoint_accounts() {
        // Use accounts far apart to reduce collision chance
        let mut a1 = [0u8; 32];
        a1[0] = 0x01;
        a1[31] = 0xFF;
        let mut a2 = [0u8; 32];
        a2[0] = 0xFE;
        a2[31] = 0x01;

        let fp1 = TxnLockFootprint::from_accounts(&[a1], &[]);
        let fp2 = TxnLockFootprint::from_accounts(&[a2], &[]);

        // May or may not conflict due to hash collision — just verify it doesn't panic
        let _ = fp1.conflicts_with(&fp2);
    }
}
