/// Account write-lock conflict detection.
///
/// Tracks which accounts are currently locked by in-flight microblocks
/// and detects conflicts when scheduling new transactions. A transaction
/// conflicts if it writes to an account that is already write-locked by
/// another in-flight microblock.
use std::collections::{HashMap, HashSet};

/// Type of lock on an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockKind {
    /// Read-only access (multiple readers allowed).
    Read,
    /// Write access (exclusive).
    Write,
}

/// An account lock held by a microblock.
#[derive(Debug, Clone)]
pub struct AccountLock {
    /// The account pubkey (32 bytes).
    pub account: [u8; 32],
    /// Type of lock.
    pub kind: LockKind,
}

/// Tracks per-account lock state across in-flight microblocks.
pub struct ConflictDetector {
    /// account → (write_count, read_count) across all active microblocks.
    locks: HashMap<[u8; 32], (u32, u32)>,
    /// Per-microblock tracking for cleanup.
    microblock_locks: HashMap<u64, Vec<AccountLock>>,
    /// Per-account accumulated write cost units.
    write_cost_per_account: HashMap<[u8; 32], u64>,
    /// Maximum write cost allowed per account per block.
    max_write_cost_per_account: u64,
}

impl ConflictDetector {
    /// Create a new conflict detector with the given per-account write cost limit.
    pub fn new(max_write_cost_per_account: u64) -> Self {
        Self {
            locks: HashMap::new(),
            microblock_locks: HashMap::new(),
            write_cost_per_account: HashMap::new(),
            max_write_cost_per_account,
        }
    }

    /// Check if a set of account locks would conflict with current state.
    /// Returns true if the transaction CAN be scheduled (no conflicts).
    pub fn can_schedule(&self, locks: &[AccountLock]) -> bool {
        for lock in locks {
            if let Some(&(write_count, _read_count)) = self.locks.get(&lock.account) {
                match lock.kind {
                    LockKind::Write => {
                        // Any existing lock (read or write) conflicts with a new write.
                        if write_count > 0 || _read_count > 0 {
                            return false;
                        }
                    }
                    LockKind::Read => {
                        // Existing write locks conflict with a new read.
                        if write_count > 0 {
                            return false;
                        }
                    }
                }
            }
        }
        true
    }

    /// Check if a transaction's write cost would exceed per-account limits.
    pub fn would_exceed_write_cost(&self, write_accounts: &[[u8; 32]], tx_cost: u64) -> bool {
        for account in write_accounts {
            let current = self
                .write_cost_per_account
                .get(account)
                .copied()
                .unwrap_or(0);
            if current.saturating_add(tx_cost) > self.max_write_cost_per_account {
                return true;
            }
        }
        false
    }

    /// Acquire locks for a microblock. Returns the set of accounts locked.
    pub fn acquire(&mut self, microblock_id: u64, locks: Vec<AccountLock>) {
        for lock in &locks {
            let entry = self.locks.entry(lock.account).or_insert((0, 0));
            match lock.kind {
                LockKind::Write => entry.0 += 1,
                LockKind::Read => entry.1 += 1,
            }
        }
        self.microblock_locks.insert(microblock_id, locks);
    }

    /// Record write cost for a scheduled transaction.
    pub fn record_write_cost(&mut self, write_accounts: &[[u8; 32]], cost: u64) {
        for account in write_accounts {
            *self.write_cost_per_account.entry(*account).or_insert(0) += cost;
        }
    }

    /// Release locks for a completed microblock.
    pub fn release(&mut self, microblock_id: u64) {
        if let Some(locks) = self.microblock_locks.remove(&microblock_id) {
            for lock in &locks {
                if let Some(entry) = self.locks.get_mut(&lock.account) {
                    match lock.kind {
                        LockKind::Write => entry.0 = entry.0.saturating_sub(1),
                        LockKind::Read => entry.1 = entry.1.saturating_sub(1),
                    }
                    if entry.0 == 0 && entry.1 == 0 {
                        self.locks.remove(&lock.account);
                    }
                }
            }
        }
    }

    /// Reset all state for a new block.
    pub fn reset(&mut self) {
        self.locks.clear();
        self.microblock_locks.clear();
        self.write_cost_per_account.clear();
    }

    /// Number of currently locked accounts.
    pub fn locked_account_count(&self) -> usize {
        self.locks.len()
    }

    /// Number of active microblocks holding locks.
    pub fn active_microblock_count(&self) -> usize {
        self.microblock_locks.len()
    }

    /// Get the set of write-locked accounts.
    pub fn write_locked_accounts(&self) -> HashSet<[u8; 32]> {
        self.locks
            .iter()
            .filter(|(_, (w, _))| *w > 0)
            .map(|(k, _)| *k)
            .collect()
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
    fn no_conflict_with_empty_state() {
        let detector = ConflictDetector::new(u64::MAX);
        let locks = vec![AccountLock {
            account: account(1),
            kind: LockKind::Write,
        }];
        assert!(detector.can_schedule(&locks));
    }

    #[test]
    fn write_write_conflict() {
        let mut detector = ConflictDetector::new(u64::MAX);
        let locks = vec![AccountLock {
            account: account(1),
            kind: LockKind::Write,
        }];
        detector.acquire(0, locks.clone());

        assert!(!detector.can_schedule(&locks));
    }

    #[test]
    fn read_read_no_conflict() {
        let mut detector = ConflictDetector::new(u64::MAX);
        let locks = vec![AccountLock {
            account: account(1),
            kind: LockKind::Read,
        }];
        detector.acquire(0, locks.clone());

        assert!(detector.can_schedule(&locks));
    }

    #[test]
    fn write_read_conflict() {
        let mut detector = ConflictDetector::new(u64::MAX);
        let write_lock = vec![AccountLock {
            account: account(1),
            kind: LockKind::Write,
        }];
        detector.acquire(0, write_lock);

        let read_lock = vec![AccountLock {
            account: account(1),
            kind: LockKind::Read,
        }];
        assert!(!detector.can_schedule(&read_lock));
    }

    #[test]
    fn read_write_conflict() {
        let mut detector = ConflictDetector::new(u64::MAX);
        let read_lock = vec![AccountLock {
            account: account(1),
            kind: LockKind::Read,
        }];
        detector.acquire(0, read_lock);

        let write_lock = vec![AccountLock {
            account: account(1),
            kind: LockKind::Write,
        }];
        assert!(!detector.can_schedule(&write_lock));
    }

    #[test]
    fn release_allows_reuse() {
        let mut detector = ConflictDetector::new(u64::MAX);
        let locks = vec![AccountLock {
            account: account(1),
            kind: LockKind::Write,
        }];
        detector.acquire(0, locks.clone());
        assert!(!detector.can_schedule(&locks));

        detector.release(0);
        assert!(detector.can_schedule(&locks));
        assert_eq!(detector.locked_account_count(), 0);
    }

    #[test]
    fn different_accounts_no_conflict() {
        let mut detector = ConflictDetector::new(u64::MAX);
        let lock_a = vec![AccountLock {
            account: account(1),
            kind: LockKind::Write,
        }];
        detector.acquire(0, lock_a);

        let lock_b = vec![AccountLock {
            account: account(2),
            kind: LockKind::Write,
        }];
        assert!(detector.can_schedule(&lock_b));
    }

    #[test]
    fn write_cost_limit() {
        let mut detector = ConflictDetector::new(1_000_000);
        let acct = account(1);
        detector.record_write_cost(&[acct], 800_000);

        assert!(detector.would_exceed_write_cost(&[acct], 300_000));
        assert!(!detector.would_exceed_write_cost(&[acct], 100_000));
    }

    #[test]
    fn reset_clears_all() {
        let mut detector = ConflictDetector::new(u64::MAX);
        let locks = vec![AccountLock {
            account: account(1),
            kind: LockKind::Write,
        }];
        detector.acquire(0, locks.clone());
        detector.record_write_cost(&[account(1)], 500);

        detector.reset();
        assert!(detector.can_schedule(&locks));
        assert_eq!(detector.locked_account_count(), 0);
        assert_eq!(detector.active_microblock_count(), 0);
    }
}
