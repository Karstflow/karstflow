//! Parser for the Solana AppendVec account storage format.
//!
//! Each account in an AppendVec has a 136-byte header followed by
//! variable-length data, then padding to 8-byte alignment.

use crate::accounts::primitives::{Account, AccountData, AccountMeta, Pubkey};

/// Size of the AppendVec account header in bytes.
const HEADER_SIZE: usize = 136;

/// Alignment for account records within an AppendVec.
const RECORD_ALIGNMENT: usize = 8;

/// Parsed account from an AppendVec binary stream.
#[derive(Debug, Clone)]
pub struct AppendVecAccount {
    pub pubkey: Pubkey,
    pub lamports: u64,
    pub rent_epoch: u64,
    pub owner: Pubkey,
    pub executable: bool,
    pub hash: [u8; 32],
    pub data: Vec<u8>,
}

impl AppendVecAccount {
    /// Convert to the internal Account representation.
    pub fn into_account(self) -> (Pubkey, Account) {
        let meta = AccountMeta {
            lamports: self.lamports,
            owner: self.owner,
            executable: self.executable,
            rent_epoch: self.rent_epoch,
        };
        let data = AccountData::new(self.data);
        (self.pubkey, Account { meta, data })
    }
}

/// Iterator that yields accounts from an AppendVec byte buffer.
pub struct AppendVecIter<'a> {
    buf: &'a [u8],
    offset: usize,
}

impl<'a> AppendVecIter<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, offset: 0 }
    }
}

impl<'a> Iterator for AppendVecIter<'a> {
    type Item = Result<AppendVecAccount, AppendVecError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.buf.len() {
            return None;
        }

        // Check remaining space for header.
        let remaining = self.buf.len() - self.offset;
        if remaining < HEADER_SIZE {
            // Could be trailing zeros (padding at end of AppendVec).
            if self.buf[self.offset..].iter().all(|&b| b == 0) {
                return None;
            }
            return Some(Err(AppendVecError::TruncatedHeader {
                offset: self.offset,
                available: remaining,
            }));
        }

        let header = &self.buf[self.offset..self.offset + HEADER_SIZE];

        // Parse header fields (all little-endian).
        // Bytes 0-7: reserved/unused
        let data_len = u64::from_le_bytes(header[8..16].try_into().unwrap()) as usize;

        // Bytes 16-47: pubkey (32 bytes)
        let mut pubkey_bytes = [0u8; 32];
        pubkey_bytes.copy_from_slice(&header[16..48]);
        let pubkey = Pubkey::new(pubkey_bytes);

        // Bytes 48-55: lamports
        let lamports = u64::from_le_bytes(header[48..56].try_into().unwrap());

        // Bytes 56-63: rent_epoch
        let rent_epoch = u64::from_le_bytes(header[56..64].try_into().unwrap());

        // Bytes 64-95: owner (32 bytes)
        let mut owner_bytes = [0u8; 32];
        owner_bytes.copy_from_slice(&header[64..96]);
        let owner = Pubkey::new(owner_bytes);

        // Byte 96: executable
        let executable = header[96] != 0;

        // Bytes 97-100: unused padding
        // Bytes 101-132: hash (skip byte 97-100, hash starts at 101? No...)
        // Actually from the research: bytes 97-100 are padding, then 32-byte hash at 101-132
        // But wait, 101 + 32 = 133, and header is 136 bytes. Let me recheck.
        // Research says: 96 = executable (1), 97-100 = padding (4), 101-132 = first part of hash
        // Actually total: 0(8) + 8(8=data_len) + 16(32=pubkey) + 48(8=lamports) + 56(8=rent_epoch)
        //   + 64(32=owner) + 96(1=exec) + 97(3=padding?) + 100(32=hash) + 132... that's only 132.
        // Let me recalculate: 8 + 8 + 32 + 8 + 8 + 32 + 1 + ? + 32 = 129 + padding
        // With 7 bytes padding to reach 136: 8+8+32+8+8+32+1+7+32 = 136. Yes!
        // So: byte 97-103 = padding (7 bytes), bytes 104-135 = hash (32 bytes)
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&header[104..136]);

        // Validate data_len doesn't exceed buffer.
        let data_start = self.offset + HEADER_SIZE;
        let data_end = data_start + data_len;
        if data_end > self.buf.len() {
            return Some(Err(AppendVecError::TruncatedData {
                offset: self.offset,
                data_len,
                available: self.buf.len() - data_start,
            }));
        }

        let data = self.buf[data_start..data_end].to_vec();

        // Advance past header + data + alignment padding.
        let unpadded = HEADER_SIZE + data_len;
        let padded = (unpadded + RECORD_ALIGNMENT - 1) & !(RECORD_ALIGNMENT - 1);
        self.offset += padded;

        Some(Ok(AppendVecAccount {
            pubkey,
            lamports,
            rent_epoch,
            owner,
            executable,
            hash,
            data,
        }))
    }
}

/// Parse all accounts from an AppendVec byte buffer.
#[cfg(test)]
pub fn parse_append_vec(buf: &[u8]) -> Result<Vec<AppendVecAccount>, AppendVecError> {
    AppendVecIter::new(buf).collect()
}

/// Serialize a single account into AppendVec binary format.
///
/// Produces a 136-byte header followed by account data, padded to
/// 8-byte alignment. The `hash` field is written as provided (caller
/// is responsible for computing it if needed).
pub fn serialize_append_vec_record(account: &AppendVecAccount) -> Vec<u8> {
    let data_len = account.data.len();
    let unpadded = HEADER_SIZE + data_len;
    let padded = (unpadded + RECORD_ALIGNMENT - 1) & !(RECORD_ALIGNMENT - 1);
    let mut buf = vec![0u8; padded];

    // Bytes 0-7: reserved (zeros)
    // Bytes 8-15: data_len
    buf[8..16].copy_from_slice(&(data_len as u64).to_le_bytes());
    // Bytes 16-47: pubkey
    buf[16..48].copy_from_slice(account.pubkey.as_bytes());
    // Bytes 48-55: lamports
    buf[48..56].copy_from_slice(&account.lamports.to_le_bytes());
    // Bytes 56-63: rent_epoch
    buf[56..64].copy_from_slice(&account.rent_epoch.to_le_bytes());
    // Bytes 64-95: owner
    buf[64..96].copy_from_slice(account.owner.as_bytes());
    // Byte 96: executable
    buf[96] = account.executable as u8;
    // Bytes 97-103: padding (zeros, already initialized)
    // Bytes 104-135: hash
    buf[104..136].copy_from_slice(&account.hash);
    // Data
    buf[HEADER_SIZE..HEADER_SIZE + data_len].copy_from_slice(&account.data);
    // Padding bytes are already zeros from vec initialization

    buf
}

/// Serialize multiple accounts into a single AppendVec buffer.
pub fn serialize_append_vec(accounts: &[AppendVecAccount]) -> Vec<u8> {
    let mut buf = Vec::new();
    for account in accounts {
        buf.extend(serialize_append_vec_record(account));
    }
    buf
}

/// Convert an internal Account into an AppendVecAccount for serialization.
///
/// The hash is computed as SHA-256 over the canonical account fields
/// (lamports, rent_epoch, data, executable, owner, pubkey) matching
/// the Solana protocol.
pub fn account_to_append_vec(pubkey: &Pubkey, account: &Account) -> AppendVecAccount {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(account.meta.lamports.to_le_bytes());
    hasher.update(account.meta.rent_epoch.to_le_bytes());
    hasher.update(account.data.as_ref());
    hasher.update([account.meta.executable as u8]);
    hasher.update(account.meta.owner.as_bytes());
    hasher.update(pubkey.as_bytes());
    let hash: [u8; 32] = hasher.finalize().into();

    AppendVecAccount {
        pubkey: *pubkey,
        lamports: account.meta.lamports,
        rent_epoch: account.meta.rent_epoch,
        owner: account.meta.owner,
        executable: account.meta.executable,
        hash,
        data: account.data.as_slice().to_vec(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppendVecError {
    TruncatedHeader {
        offset: usize,
        available: usize,
    },
    TruncatedData {
        offset: usize,
        data_len: usize,
        available: usize,
    },
}

impl std::fmt::Display for AppendVecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TruncatedHeader { offset, available } => {
                write!(
                    f,
                    "truncated account header at offset {offset}: need {HEADER_SIZE} bytes, have {available}"
                )
            }
            Self::TruncatedData {
                offset,
                data_len,
                available,
            } => {
                write!(
                    f,
                    "truncated account data at offset {offset}: need {data_len} bytes, have {available}"
                )
            }
        }
    }
}

impl std::error::Error for AppendVecError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a valid AppendVec record from raw parts.
    fn make_record(pubkey: [u8; 32], lamports: u64, owner: [u8; 32], data: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();

        // Bytes 0-7: reserved
        buf.extend_from_slice(&[0u8; 8]);
        // Bytes 8-15: data_len
        buf.extend_from_slice(&(data.len() as u64).to_le_bytes());
        // Bytes 16-47: pubkey
        buf.extend_from_slice(&pubkey);
        // Bytes 48-55: lamports
        buf.extend_from_slice(&lamports.to_le_bytes());
        // Bytes 56-63: rent_epoch
        buf.extend_from_slice(&0u64.to_le_bytes());
        // Bytes 64-95: owner
        buf.extend_from_slice(&owner);
        // Byte 96: executable
        buf.push(0);
        // Bytes 97-103: padding
        buf.extend_from_slice(&[0u8; 7]);
        // Bytes 104-135: hash
        buf.extend_from_slice(&[0xABu8; 32]);

        assert_eq!(buf.len(), HEADER_SIZE);

        // Account data
        buf.extend_from_slice(data);

        // Alignment padding
        let unpadded = buf.len();
        let padded = (unpadded + RECORD_ALIGNMENT - 1) & !(RECORD_ALIGNMENT - 1);
        buf.resize(padded, 0);

        buf
    }

    #[test]
    fn parse_single_account_no_data() {
        let buf = make_record([1u8; 32], 1000, [2u8; 32], &[]);
        let accounts = parse_append_vec(&buf).unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].pubkey, Pubkey::new([1u8; 32]));
        assert_eq!(accounts[0].lamports, 1000);
        assert_eq!(accounts[0].owner, Pubkey::new([2u8; 32]));
        assert!(accounts[0].data.is_empty());
        assert_eq!(accounts[0].hash, [0xABu8; 32]);
    }

    #[test]
    fn parse_single_account_with_data() {
        let data = vec![10, 20, 30, 40, 50];
        let buf = make_record([3u8; 32], 500, [4u8; 32], &data);
        let accounts = parse_append_vec(&buf).unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].data, data);
        assert_eq!(accounts[0].lamports, 500);
    }

    #[test]
    fn parse_multiple_accounts() {
        let mut buf = Vec::new();
        buf.extend(make_record([1u8; 32], 100, [10u8; 32], &[]));
        buf.extend(make_record([2u8; 32], 200, [20u8; 32], &[1, 2, 3]));
        buf.extend(make_record([3u8; 32], 300, [30u8; 32], &[4, 5]));

        let accounts = parse_append_vec(&buf).unwrap();
        assert_eq!(accounts.len(), 3);
        assert_eq!(accounts[0].lamports, 100);
        assert_eq!(accounts[1].lamports, 200);
        assert_eq!(accounts[1].data, vec![1, 2, 3]);
        assert_eq!(accounts[2].lamports, 300);
    }

    #[test]
    fn parse_account_with_alignment_padding() {
        // 5 bytes of data -> header(136) + data(5) = 141 -> padded to 144 (8-byte aligned)
        let mut buf = Vec::new();
        buf.extend(make_record([1u8; 32], 100, [10u8; 32], &[1, 2, 3, 4, 5]));
        buf.extend(make_record([2u8; 32], 200, [20u8; 32], &[]));

        let accounts = parse_append_vec(&buf).unwrap();
        assert_eq!(accounts.len(), 2);
        assert_eq!(accounts[0].data.len(), 5);
        assert_eq!(accounts[1].lamports, 200);
    }

    #[test]
    fn parse_empty_buffer() {
        let accounts = parse_append_vec(&[]).unwrap();
        assert!(accounts.is_empty());
    }

    #[test]
    fn parse_trailing_zeros_ignored() {
        let mut buf = make_record([1u8; 32], 100, [10u8; 32], &[]);
        buf.extend_from_slice(&[0u8; 64]); // trailing zeros
        let accounts = parse_append_vec(&buf).unwrap();
        assert_eq!(accounts.len(), 1);
    }

    #[test]
    fn parse_truncated_header_fails() {
        let buf = vec![1u8; 50]; // Not enough for header
        let result = parse_append_vec(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn parse_truncated_data_fails() {
        let mut buf = Vec::new();
        // Header claiming 1000 bytes of data
        buf.extend_from_slice(&[0u8; 8]); // reserved
        buf.extend_from_slice(&1000u64.to_le_bytes()); // data_len = 1000
        buf.extend_from_slice(&[0u8; HEADER_SIZE - 16]); // rest of header
        buf.extend_from_slice(&[0u8; 50]); // only 50 bytes of data (need 1000)

        let result = parse_append_vec(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn into_account_conversion() {
        let buf = make_record([5u8; 32], 777, [6u8; 32], &[9, 8, 7]);
        let accounts = parse_append_vec(&buf).unwrap();
        let (pubkey, account) = accounts[0].clone().into_account();

        assert_eq!(pubkey, Pubkey::new([5u8; 32]));
        assert_eq!(account.meta.lamports, 777);
        assert_eq!(account.meta.owner, Pubkey::new([6u8; 32]));
        assert_eq!(account.data.as_slice(), &[9, 8, 7]);
    }

    #[test]
    fn iterator_yields_correct_count() {
        let mut buf = Vec::new();
        for i in 0..10u8 {
            buf.extend(make_record([i; 32], i as u64 * 100, [0u8; 32], &[i]));
        }
        let count = AppendVecIter::new(&buf).count();
        assert_eq!(count, 10);
    }

    #[test]
    fn large_account_data() {
        let data = vec![0xFFu8; 10_000];
        let buf = make_record([1u8; 32], 42, [2u8; 32], &data);
        let accounts = parse_append_vec(&buf).unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].data.len(), 10_000);
    }

    #[test]
    fn executable_flag_parsed() {
        let mut buf = make_record([1u8; 32], 100, [2u8; 32], &[]);
        // Set executable byte (offset 96) to 1
        buf[96] = 1;
        let accounts = parse_append_vec(&buf).unwrap();
        assert!(accounts[0].executable);
    }

    // -------------------------------------------------------------------
    // Writer tests
    // -------------------------------------------------------------------

    #[test]
    fn serialize_roundtrip_no_data() {
        let account = AppendVecAccount {
            pubkey: Pubkey::new([1u8; 32]),
            lamports: 1000,
            rent_epoch: 42,
            owner: Pubkey::new([2u8; 32]),
            executable: false,
            hash: [0xAB; 32],
            data: vec![],
        };
        let buf = serialize_append_vec_record(&account);
        let parsed = parse_append_vec(&buf).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].pubkey, account.pubkey);
        assert_eq!(parsed[0].lamports, 1000);
        assert_eq!(parsed[0].owner, account.owner);
        assert_eq!(parsed[0].rent_epoch, 42);
        assert_eq!(parsed[0].hash, [0xAB; 32]);
        assert!(parsed[0].data.is_empty());
    }

    #[test]
    fn serialize_roundtrip_with_data() {
        let account = AppendVecAccount {
            pubkey: Pubkey::new([3u8; 32]),
            lamports: 5000,
            rent_epoch: 0,
            owner: Pubkey::new([4u8; 32]),
            executable: true,
            hash: [0xCD; 32],
            data: vec![10, 20, 30, 40, 50],
        };
        let buf = serialize_append_vec_record(&account);
        let parsed = parse_append_vec(&buf).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].data, vec![10, 20, 30, 40, 50]);
        assert!(parsed[0].executable);
    }

    #[test]
    fn serialize_multiple_roundtrip() {
        let accounts = vec![
            AppendVecAccount {
                pubkey: Pubkey::new([1u8; 32]),
                lamports: 100,
                rent_epoch: 0,
                owner: Pubkey::new([10u8; 32]),
                executable: false,
                hash: [0; 32],
                data: vec![],
            },
            AppendVecAccount {
                pubkey: Pubkey::new([2u8; 32]),
                lamports: 200,
                rent_epoch: 5,
                owner: Pubkey::new([20u8; 32]),
                executable: false,
                hash: [1; 32],
                data: vec![1, 2, 3],
            },
            AppendVecAccount {
                pubkey: Pubkey::new([3u8; 32]),
                lamports: 300,
                rent_epoch: 10,
                owner: Pubkey::new([30u8; 32]),
                executable: true,
                hash: [2; 32],
                data: vec![4, 5, 6, 7, 8, 9, 10],
            },
        ];
        let buf = serialize_append_vec(&accounts);
        let parsed = parse_append_vec(&buf).unwrap();
        assert_eq!(parsed.len(), 3);
        for (orig, read) in accounts.iter().zip(parsed.iter()) {
            assert_eq!(orig.pubkey, read.pubkey);
            assert_eq!(orig.lamports, read.lamports);
            assert_eq!(orig.owner, read.owner);
            assert_eq!(orig.executable, read.executable);
            assert_eq!(orig.data, read.data);
        }
    }

    #[test]
    fn serialize_alignment_correct() {
        // 5 bytes of data → 136 + 5 = 141 → padded to 144
        let account = AppendVecAccount {
            pubkey: Pubkey::new([1u8; 32]),
            lamports: 42,
            rent_epoch: 0,
            owner: Pubkey::zeroed(),
            executable: false,
            hash: [0; 32],
            data: vec![1, 2, 3, 4, 5],
        };
        let buf = serialize_append_vec_record(&account);
        assert_eq!(buf.len(), 144);
        assert_eq!(buf.len() % RECORD_ALIGNMENT, 0);
    }

    #[test]
    fn account_to_append_vec_produces_valid_hash() {
        let pubkey = Pubkey::new([5u8; 32]);
        let account = Account {
            meta: AccountMeta {
                lamports: 1000,
                owner: Pubkey::new([6u8; 32]),
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(vec![1, 2, 3]),
        };
        let av = account_to_append_vec(&pubkey, &account);
        assert_eq!(av.pubkey, pubkey);
        assert_eq!(av.lamports, 1000);
        assert_eq!(av.data, vec![1, 2, 3]);
        // Hash should be non-zero (SHA-256 of non-trivial data)
        assert_ne!(av.hash, [0; 32]);
    }

    #[test]
    fn account_to_append_vec_deterministic_hash() {
        let pubkey = Pubkey::new([7u8; 32]);
        let account = Account {
            meta: AccountMeta {
                lamports: 500,
                owner: Pubkey::new([8u8; 32]),
                executable: true,
                rent_epoch: 99,
            },
            data: AccountData::new(vec![10, 20]),
        };
        let av1 = account_to_append_vec(&pubkey, &account);
        let av2 = account_to_append_vec(&pubkey, &account);
        assert_eq!(av1.hash, av2.hash);
    }

    #[test]
    fn full_account_serialize_parse_roundtrip() {
        let pubkey = Pubkey::new([9u8; 32]);
        let account = Account {
            meta: AccountMeta {
                lamports: 42_000,
                owner: Pubkey::new([10u8; 32]),
                executable: false,
                rent_epoch: 7,
            },
            data: AccountData::new(vec![0xFF; 100]),
        };
        let av = account_to_append_vec(&pubkey, &account);
        let buf = serialize_append_vec_record(&av);
        let parsed = parse_append_vec(&buf).unwrap();
        assert_eq!(parsed.len(), 1);
        let (pk, acc) = parsed[0].clone().into_account();
        assert_eq!(pk, pubkey);
        assert_eq!(acc, account);
    }
}
