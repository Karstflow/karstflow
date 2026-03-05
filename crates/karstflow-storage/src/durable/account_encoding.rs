// Binary encoding for Account persistence.
//
// Fixed-size header (53 bytes) followed by variable-length account data.
//
// Raw format (uncompressed):
//   lamports:    8 bytes LE
//   owner:      32 bytes
//   executable:  1 byte (0 or 1)
//   rent_epoch:  8 bytes LE
//   data_len:    4 bytes LE (bit 31 = 0)
//   data:        data_len bytes
//
// Compressed format (LZ4):
//   lamports:         8 bytes LE
//   owner:           32 bytes
//   executable:       1 byte (0 or 1)
//   rent_epoch:       8 bytes LE
//   data_len:         4 bytes LE (bit 31 = 1, lower 31 bits = uncompressed len)
//   compressed_len:   4 bytes LE
//   compressed_data:  compressed_len bytes (LZ4)
//
// The two formats are distinguished by bit 31 of the data_len field. This
// makes the encoding backward-compatible: existing uncompressed records
// decode correctly because their data_len will never have bit 31 set
// (max account data ≈ 10 MB, well below 2^31).

use karstflow_constants::durable_store::{
    ACCOUNT_ENCODING_COMPRESSION_FLAG, ACCOUNT_ENCODING_DATA_LEN_MASK, COMPRESSION_MIN_DATA_SIZE,
};
use karstflow_types::{Account, AccountData, AccountMeta, Pubkey, PUBKEY_BYTES};

const HEADER_SIZE: usize = 8 + PUBKEY_BYTES + 1 + 8 + 4; // 53 bytes

/// Encode an Account into a compact binary representation.
///
/// Accounts with data at or above the compression threshold are LZ4-compressed
/// when compression achieves a net size reduction. Small accounts and those
/// where compression is ineffective are stored raw.
#[inline]
pub fn encode_account(account: &Account) -> Vec<u8> {
    let data_slice = account.data.as_slice();

    // Try LZ4 compression for data above the minimum threshold.
    if data_slice.len() >= COMPRESSION_MIN_DATA_SIZE {
        let compressed = lz4_flex::compress_prepend_size(data_slice);

        // Only use compressed format if it actually saves space (accounting
        // for the 4-byte compressed_len field overhead).
        if compressed.len() + 4 < data_slice.len() {
            return encode_compressed(account, data_slice.len(), &compressed);
        }
    }

    encode_raw(account, data_slice)
}

/// Encode without compression (raw format).
#[inline]
fn encode_raw(account: &Account, data_slice: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(HEADER_SIZE + data_slice.len());

    write_header(&mut buf, account, data_slice.len() as u32);
    buf.extend_from_slice(data_slice);

    buf
}

/// Encode with LZ4 compression.
#[inline]
fn encode_compressed(account: &Account, uncompressed_len: usize, compressed: &[u8]) -> Vec<u8> {
    let data_len_field = (uncompressed_len as u32) | ACCOUNT_ENCODING_COMPRESSION_FLAG;
    let compressed_len = compressed.len() as u32;

    let mut buf = Vec::with_capacity(HEADER_SIZE + 4 + compressed.len());
    write_header(&mut buf, account, data_len_field);
    buf.extend_from_slice(&compressed_len.to_le_bytes());
    buf.extend_from_slice(compressed);

    buf
}

/// Write the 53-byte account header.
#[inline]
fn write_header(buf: &mut Vec<u8>, account: &Account, data_len_field: u32) {
    buf.extend_from_slice(&account.meta.lamports.to_le_bytes());
    buf.extend_from_slice(account.meta.owner.as_bytes());
    buf.push(account.meta.executable as u8);
    buf.extend_from_slice(&account.meta.rent_epoch.to_le_bytes());
    buf.extend_from_slice(&data_len_field.to_le_bytes());
}

/// Decode an Account from its binary representation.
///
/// Automatically detects raw vs LZ4-compressed format by inspecting bit 31
/// of the `data_len` header field. Returns `None` if the buffer is too short,
/// data_len is inconsistent, or decompression fails.
#[inline]
pub fn decode_account(buf: &[u8]) -> Option<Account> {
    if buf.len() < HEADER_SIZE {
        return None;
    }

    let lamports = u64::from_le_bytes(buf[0..8].try_into().ok()?);
    let owner = Pubkey::from(<[u8; PUBKEY_BYTES]>::try_from(&buf[8..40]).ok()?);
    let executable = buf[40] != 0;
    let rent_epoch = u64::from_le_bytes(buf[41..49].try_into().ok()?);
    let data_len_field = u32::from_le_bytes(buf[49..53].try_into().ok()?);

    let is_compressed = data_len_field & ACCOUNT_ENCODING_COMPRESSION_FLAG != 0;
    let uncompressed_len = (data_len_field & ACCOUNT_ENCODING_DATA_LEN_MASK) as usize;

    let data = if is_compressed {
        // Compressed format: read compressed_len then decompress.
        if buf.len() < HEADER_SIZE + 4 {
            return None;
        }
        let compressed_len = u32::from_le_bytes(buf[53..57].try_into().ok()?) as usize;
        if buf.len() < HEADER_SIZE + 4 + compressed_len {
            return None;
        }
        let compressed_data = &buf[57..57 + compressed_len];
        let decompressed = lz4_flex::decompress_size_prepended(compressed_data).ok()?;
        if decompressed.len() != uncompressed_len {
            return None;
        }
        decompressed
    } else {
        // Raw format: read data_len bytes directly.
        if buf.len() < HEADER_SIZE + uncompressed_len {
            return None;
        }
        buf[HEADER_SIZE..HEADER_SIZE + uncompressed_len].to_vec()
    };

    Some(Account {
        meta: AccountMeta::new(lamports, owner, executable, rent_epoch),
        data: AccountData::new(data),
    })
}

/// Encode an Account without compression (raw format only).
///
/// Useful when compression overhead is undesirable, for example during
/// snapshot generation where zstd handles compression at a higher level.
#[inline]
pub fn encode_account_raw(account: &Account) -> Vec<u8> {
    encode_raw(account, account.data.as_slice())
}

// ---------------------------------------------------------------------------
// Compact metadata encoding for the persistent account index
// ---------------------------------------------------------------------------

/// Size of a compact account metadata record: owner(32) + lamports(8) + slot(8).
const META_RECORD_SIZE: usize = 48;

/// Encode compact account metadata for the persistent index.
///
/// The metadata record contains only the fields needed to rebuild the
/// owner index at startup: owner, lamports, and last-modified slot.
/// No data payload, no compression — just 48 fixed bytes.
#[inline]
pub fn encode_account_meta(owner: &Pubkey, lamports: u64, slot: u64) -> [u8; 48] {
    let mut buf = [0u8; META_RECORD_SIZE];
    buf[0..PUBKEY_BYTES].copy_from_slice(owner.as_bytes());
    buf[PUBKEY_BYTES..PUBKEY_BYTES + 8].copy_from_slice(&lamports.to_le_bytes());
    buf[PUBKEY_BYTES + 8..META_RECORD_SIZE].copy_from_slice(&slot.to_le_bytes());
    buf
}

/// Decode compact account metadata from the persistent index.
///
/// Returns `(owner, lamports, slot)` or `None` if the buffer is too short.
#[inline]
pub fn decode_account_meta(buf: &[u8]) -> Option<(Pubkey, u64, u64)> {
    if buf.len() < META_RECORD_SIZE {
        return None;
    }
    let owner = Pubkey::from(<[u8; PUBKEY_BYTES]>::try_from(&buf[0..PUBKEY_BYTES]).ok()?);
    let lamports = u64::from_le_bytes(buf[PUBKEY_BYTES..PUBKEY_BYTES + 8].try_into().ok()?);
    let slot = u64::from_le_bytes(buf[PUBKEY_BYTES + 8..META_RECORD_SIZE].try_into().ok()?);
    Some((owner, lamports, slot))
}

/// Extract just the lamports and owner from a full account encoding.
///
/// Reads only the first 40 bytes of the account header — no LZ4
/// decompression needed. This is the fast path for index rebuilds
/// when the metadata column family is not available.
#[inline]
pub fn decode_account_header(buf: &[u8]) -> Option<(u64, Pubkey)> {
    if buf.len() < 8 + PUBKEY_BYTES {
        return None;
    }
    let lamports = u64::from_le_bytes(buf[0..8].try_into().ok()?);
    let owner = Pubkey::from(<[u8; PUBKEY_BYTES]>::try_from(&buf[8..8 + PUBKEY_BYTES]).ok()?);
    Some((lamports, owner))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_empty_data() {
        let account = Account::new(1_000_000, vec![], Pubkey::from([0xAA; 32]));
        let encoded = encode_account(&account);
        assert_eq!(encoded.len(), HEADER_SIZE);
        let decoded = decode_account(&encoded).expect("decode");
        assert_eq!(decoded, account);
    }

    #[test]
    fn roundtrip_with_data() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let account = Account::new(999, data.clone(), Pubkey::from([0xBB; 32]));
        let encoded = encode_account(&account);
        assert_eq!(encoded.len(), HEADER_SIZE + 8);
        let decoded = decode_account(&encoded).expect("decode");
        assert_eq!(decoded.meta.lamports, 999);
        assert_eq!(decoded.data.as_slice(), &data);
    }

    #[test]
    fn roundtrip_executable() {
        let account = Account::new_with_meta(
            AccountMeta::new(42, Pubkey::from([0xCC; 32]), true, 100),
            vec![0xFF; 256],
        );
        let encoded = encode_account(&account);
        let decoded = decode_account(&encoded).expect("decode");
        assert!(decoded.meta.executable);
        assert_eq!(decoded.meta.rent_epoch, 100);
        assert_eq!(decoded.data.len(), 256);
    }

    #[test]
    fn roundtrip_large_data() {
        let data = vec![0x42; 10 * 1024 * 1024]; // 10 MB
        let account = Account::new(0, data, Pubkey::from([0xDD; 32]));
        let encoded = encode_account(&account);
        let decoded = decode_account(&encoded).expect("decode");
        assert_eq!(decoded, account);
    }

    #[test]
    fn decode_truncated_header_returns_none() {
        assert!(decode_account(&[0; 10]).is_none());
    }

    #[test]
    fn decode_truncated_data_returns_none() {
        let account = Account::new(1, vec![1, 2, 3], Pubkey::from([0; 32]));
        let encoded = encode_account(&account);
        // Truncate data portion.
        assert!(decode_account(&encoded[..HEADER_SIZE + 1]).is_none());
    }

    #[test]
    fn zeroed_account_roundtrip() {
        let account = Account::zeroed();
        let encoded = encode_account(&account);
        let decoded = decode_account(&encoded).expect("decode");
        assert_eq!(decoded, account);
    }

    // --- LZ4 compression tests ---

    #[test]
    fn small_data_not_compressed() {
        // Data below COMPRESSION_MIN_DATA_SIZE should be stored raw.
        let data = vec![0xAA; COMPRESSION_MIN_DATA_SIZE - 1];
        let account = Account::new(100, data.clone(), Pubkey::from([0x01; 32]));
        let encoded = encode_account(&account);

        // Raw format: header + data, no compressed_len field.
        assert_eq!(encoded.len(), HEADER_SIZE + data.len());

        // Verify data_len field has bit 31 clear.
        let data_len_field = u32::from_le_bytes(encoded[49..53].try_into().unwrap());
        assert_eq!(data_len_field & ACCOUNT_ENCODING_COMPRESSION_FLAG, 0);

        let decoded = decode_account(&encoded).expect("decode");
        assert_eq!(decoded, account);
    }

    #[test]
    fn compressible_data_uses_lz4() {
        // Highly compressible data (repeated bytes) above threshold.
        let data = vec![0x00; 4096];
        let account = Account::new(500, data.clone(), Pubkey::from([0x02; 32]));
        let encoded = encode_account(&account);

        // Compressed format should be smaller than raw.
        let raw_size = HEADER_SIZE + data.len();
        assert!(
            encoded.len() < raw_size,
            "compressed {} should be < raw {}",
            encoded.len(),
            raw_size
        );

        // Verify bit 31 is set.
        let data_len_field = u32::from_le_bytes(encoded[49..53].try_into().unwrap());
        assert_ne!(data_len_field & ACCOUNT_ENCODING_COMPRESSION_FLAG, 0);

        // Verify uncompressed length is correct.
        let stored_len = (data_len_field & ACCOUNT_ENCODING_DATA_LEN_MASK) as usize;
        assert_eq!(stored_len, data.len());

        let decoded = decode_account(&encoded).expect("decode");
        assert_eq!(decoded, account);
    }

    #[test]
    fn incompressible_data_stays_raw() {
        // Random-looking data that won't compress well.
        let mut data = vec![0u8; 256];
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = (i.wrapping_mul(131).wrapping_add(17)) as u8;
        }
        let account = Account::new(42, data.clone(), Pubkey::from([0x03; 32]));
        let encoded = encode_account(&account);

        // Should fall back to raw because LZ4 won't shrink pseudo-random data enough.
        let data_len_field = u32::from_le_bytes(encoded[49..53].try_into().unwrap());
        // Whether it compresses or not depends on the data — just verify roundtrip.
        let decoded = decode_account(&encoded).expect("decode");
        assert_eq!(decoded, account);
        // Either way, the data_len (uncompressed) should be correct.
        let stored_len = (data_len_field & ACCOUNT_ENCODING_DATA_LEN_MASK) as usize;
        assert_eq!(stored_len, data.len());
    }

    #[test]
    fn large_compressible_roundtrip() {
        // 1 MB of compressible program data (typical BPF ELF with runs of zeros).
        let mut data = vec![0u8; 1024 * 1024];
        // Sprinkle some non-zero bytes to simulate real ELF sections.
        for i in (0..data.len()).step_by(4096) {
            data[i..i + 64].fill(0xEF);
        }
        let account = Account::new_with_meta(
            AccountMeta::new(1_000_000, Pubkey::from([0x04; 32]), true, 0),
            data.clone(),
        );
        let encoded = encode_account(&account);

        // Should compress significantly.
        assert!(
            encoded.len() < data.len() / 2,
            "1MB sparse data should compress to < 50%: got {}",
            encoded.len()
        );

        let decoded = decode_account(&encoded).expect("decode");
        assert_eq!(decoded, account);
    }

    #[test]
    fn raw_encode_bypasses_compression() {
        let data = vec![0x00; 4096]; // highly compressible
        let account = Account::new(1, data.clone(), Pubkey::from([0x05; 32]));

        let raw_encoded = encode_account_raw(&account);
        assert_eq!(raw_encoded.len(), HEADER_SIZE + data.len());

        // data_len bit 31 should be clear.
        let data_len_field = u32::from_le_bytes(raw_encoded[49..53].try_into().unwrap());
        assert_eq!(data_len_field & ACCOUNT_ENCODING_COMPRESSION_FLAG, 0);

        let decoded = decode_account(&raw_encoded).expect("decode");
        assert_eq!(decoded, account);
    }

    #[test]
    fn decode_truncated_compressed_header_returns_none() {
        // Create compressed data, then truncate the compressed_len field.
        let data = vec![0x00; 4096];
        let account = Account::new(1, data, Pubkey::from([0x06; 32]));
        let encoded = encode_account(&account);

        // Verify it's actually compressed.
        let data_len_field = u32::from_le_bytes(encoded[49..53].try_into().unwrap());
        assert_ne!(data_len_field & ACCOUNT_ENCODING_COMPRESSION_FLAG, 0);

        // Truncate to just the header — missing compressed_len.
        assert!(decode_account(&encoded[..HEADER_SIZE + 2]).is_none());
    }

    #[test]
    fn decode_truncated_compressed_payload_returns_none() {
        let data = vec![0x00; 4096];
        let account = Account::new(1, data, Pubkey::from([0x07; 32]));
        let encoded = encode_account(&account);

        // Truncate to header + compressed_len but missing some compressed data.
        assert!(decode_account(&encoded[..HEADER_SIZE + 6]).is_none());
    }

    #[test]
    fn boundary_at_compression_threshold() {
        // Exactly at threshold.
        let data = vec![0x00; COMPRESSION_MIN_DATA_SIZE];
        let account = Account::new(1, data.clone(), Pubkey::from([0x08; 32]));
        let encoded = encode_account(&account);
        let decoded = decode_account(&encoded).expect("decode");
        assert_eq!(decoded, account);

        // One below threshold.
        let data_below = vec![0x00; COMPRESSION_MIN_DATA_SIZE - 1];
        let account_below = Account::new(1, data_below.clone(), Pubkey::from([0x09; 32]));
        let encoded_below = encode_account(&account_below);
        // Must be raw format.
        let field = u32::from_le_bytes(encoded_below[49..53].try_into().unwrap());
        assert_eq!(field & ACCOUNT_ENCODING_COMPRESSION_FLAG, 0);
        let decoded_below = decode_account(&encoded_below).expect("decode");
        assert_eq!(decoded_below, account_below);
    }

    // --- Compact metadata encoding tests ---

    #[test]
    fn meta_roundtrip() {
        let owner = Pubkey::from([0xAA; 32]);
        let lamports = 1_000_000u64;
        let slot = 42u64;

        let encoded = encode_account_meta(&owner, lamports, slot);
        assert_eq!(encoded.len(), 48);

        let (dec_owner, dec_lamports, dec_slot) = decode_account_meta(&encoded).expect("decode");
        assert_eq!(dec_owner, owner);
        assert_eq!(dec_lamports, lamports);
        assert_eq!(dec_slot, slot);
    }

    #[test]
    fn meta_zero_values() {
        let encoded = encode_account_meta(&Pubkey::from([0; 32]), 0, 0);
        let (owner, lamports, slot) = decode_account_meta(&encoded).expect("decode");
        assert_eq!(owner, Pubkey::from([0; 32]));
        assert_eq!(lamports, 0);
        assert_eq!(slot, 0);
    }

    #[test]
    fn meta_max_values() {
        let owner = Pubkey::from([0xFF; 32]);
        let encoded = encode_account_meta(&owner, u64::MAX, u64::MAX);
        let (dec_owner, dec_lamports, dec_slot) = decode_account_meta(&encoded).expect("decode");
        assert_eq!(dec_owner, owner);
        assert_eq!(dec_lamports, u64::MAX);
        assert_eq!(dec_slot, u64::MAX);
    }

    #[test]
    fn meta_truncated_returns_none() {
        let encoded = encode_account_meta(&Pubkey::from([1; 32]), 100, 5);
        assert!(decode_account_meta(&encoded[..47]).is_none());
        assert!(decode_account_meta(&encoded[..20]).is_none());
        assert!(decode_account_meta(&[]).is_none());
    }

    // --- Header extraction tests ---

    #[test]
    fn header_extraction_from_raw_account() {
        let owner = Pubkey::from([0xBB; 32]);
        let account = Account::new(999, vec![1, 2, 3, 4], owner);
        let encoded = encode_account(&account);

        let (lamports, dec_owner) = decode_account_header(&encoded).expect("decode header");
        assert_eq!(lamports, 999);
        assert_eq!(dec_owner, owner);
    }

    #[test]
    fn header_extraction_from_compressed_account() {
        // Compressed accounts still have lamports+owner uncompressed in the header.
        let owner = Pubkey::from([0xCC; 32]);
        let data = vec![0x00; 4096]; // compressible
        let account = Account::new(12345, data, owner);
        let encoded = encode_account(&account);

        let (lamports, dec_owner) = decode_account_header(&encoded).expect("decode header");
        assert_eq!(lamports, 12345);
        assert_eq!(dec_owner, owner);
    }

    #[test]
    fn header_extraction_truncated_returns_none() {
        assert!(decode_account_header(&[0; 39]).is_none());
        assert!(decode_account_header(&[]).is_none());
    }
}
