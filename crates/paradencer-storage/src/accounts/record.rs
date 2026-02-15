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
