use super::primitives::{Account, Pubkey};
use std::sync::atomic::{AtomicU64, Ordering};

pub const XID_BYTES: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[repr(transparent)]
pub struct TransactionId([u8; XID_BYTES]);

impl TransactionId {
    pub const fn new(bytes: [u8; XID_BYTES]) -> Self {
        Self(bytes)
    }

    pub const fn root() -> Self {
        Self([0u8; XID_BYTES])
    }

    pub fn from_slot(slot: u64) -> Self {
        let mut bytes = [0u8; XID_BYTES];
        bytes[0..8].copy_from_slice(&slot.to_le_bytes());
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; XID_BYTES] {
        &self.0
    }

    pub const fn is_root(&self) -> bool {
        let bytes = &self.0;
        bytes[0] == 0
            && bytes[1] == 0
            && bytes[2] == 0
            && bytes[3] == 0
            && bytes[4] == 0
            && bytes[5] == 0
            && bytes[6] == 0
            && bytes[7] == 0
            && bytes[8] == 0
            && bytes[9] == 0
            && bytes[10] == 0
            && bytes[11] == 0
            && bytes[12] == 0
            && bytes[13] == 0
            && bytes[14] == 0
            && bytes[15] == 0
    }
}

impl Default for TransactionId {
    fn default() -> Self {
        Self::root()
    }
}

impl From<[u8; XID_BYTES]> for TransactionId {
    fn from(bytes: [u8; XID_BYTES]) -> Self {
        Self(bytes)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct RecordKey {
    pub xid: TransactionId,
    pub pubkey: Pubkey,
}

impl RecordKey {
    pub const fn new(xid: TransactionId, pubkey: Pubkey) -> Self {
        Self { xid, pubkey }
    }

    pub const fn published(pubkey: Pubkey) -> Self {
        Self {
            xid: TransactionId::root(),
            pubkey,
        }
    }
}

#[derive(Clone)]
pub struct AccountRecord {
    pub key: RecordKey,
    pub account: Account,
    pub version: u64,
}

impl AccountRecord {
    pub fn new(xid: TransactionId, pubkey: Pubkey, account: Account, version: u64) -> Self {
        Self {
            key: RecordKey::new(xid, pubkey),
            account,
            version,
        }
    }
}

pub struct VersionCounter {
    counter: AtomicU64,
}

impl VersionCounter {
    pub const fn new() -> Self {
        Self {
            counter: AtomicU64::new(1),
        }
    }

    pub fn next(&self) -> u64 {
        self.counter.fetch_add(1, Ordering::SeqCst)
    }

    pub fn current(&self) -> u64 {
        self.counter.load(Ordering::SeqCst)
    }
}

impl std::fmt::Debug for VersionCounter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VersionCounter")
            .field("current", &self.current())
            .finish()
    }
}

impl Default for VersionCounter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pubkey(n: u8) -> Pubkey {
        Pubkey::new([n; 32])
    }

    fn test_account() -> Account {
        Account::new(1000, vec![1, 2, 3], Pubkey::new([0u8; 32]))
    }

    // --- TransactionId ---

    #[test]
    fn root_is_all_zeros() {
        let root = TransactionId::root();
        assert!(root.is_root());
        assert_eq!(root.as_bytes(), &[0u8; XID_BYTES]);
    }

    #[test]
    fn from_slot_encodes_slot() {
        let xid = TransactionId::from_slot(42);
        assert!(!xid.is_root());
        let expected_slot = u64::from_le_bytes(xid.as_bytes()[0..8].try_into().unwrap());
        assert_eq!(expected_slot, 42);
    }

    #[test]
    fn from_slot_zero_is_root() {
        let xid = TransactionId::from_slot(0);
        assert!(xid.is_root());
    }

    #[test]
    fn xid_from_bytes() {
        let bytes = [7u8; XID_BYTES];
        let xid: TransactionId = bytes.into();
        assert_eq!(xid.as_bytes(), &bytes);
    }

    #[test]
    fn xid_default_is_root() {
        let xid = TransactionId::default();
        assert!(xid.is_root());
    }

    // --- RecordKey ---

    #[test]
    fn record_key_new() {
        let xid = TransactionId::from_slot(5);
        let pk = test_pubkey(1);
        let key = RecordKey::new(xid, pk);
        assert_eq!(key.xid, xid);
        assert_eq!(key.pubkey, pk);
    }

    #[test]
    fn record_key_published() {
        let pk = test_pubkey(1);
        let key = RecordKey::published(pk);
        assert!(key.xid.is_root());
        assert_eq!(key.pubkey, pk);
    }

    // --- AccountRecord ---

    #[test]
    fn account_record_new() {
        let xid = TransactionId::from_slot(10);
        let pk = test_pubkey(5);
        let acct = test_account();
        let record = AccountRecord::new(xid, pk, acct.clone(), 42);
        assert_eq!(record.key.xid, xid);
        assert_eq!(record.key.pubkey, pk);
        assert_eq!(record.version, 42);
        assert_eq!(record.account.meta.lamports, 1000);
    }

    // --- VersionCounter ---

    #[test]
    fn version_counter_starts_at_one() {
        let vc = VersionCounter::new();
        assert_eq!(vc.current(), 1);
    }

    #[test]
    fn version_counter_increments() {
        let vc = VersionCounter::new();
        assert_eq!(vc.next(), 1);
        assert_eq!(vc.next(), 2);
        assert_eq!(vc.next(), 3);
        assert_eq!(vc.current(), 4);
    }

    #[test]
    fn version_counter_default() {
        let vc = VersionCounter::default();
        assert_eq!(vc.current(), 1);
    }
}
