// Binary encoding for Account persistence.
//
// Fixed-size header (53 bytes) followed by variable-length account data.
// Format:
//   lamports:    8 bytes LE
//   owner:      32 bytes
//   executable:  1 byte (0 or 1)
//   rent_epoch:  8 bytes LE
//   data_len:    4 bytes LE
//   data:        data_len bytes

use paradencer_types::{Account, AccountData, AccountMeta, Pubkey, PUBKEY_BYTES};

const HEADER_SIZE: usize = 8 + PUBKEY_BYTES + 1 + 8 + 4; // 53 bytes

/// Encode an Account into a compact binary representation.
#[inline]
pub fn encode_account(account: &Account) -> Vec<u8> {
    let data_slice = account.data.as_slice();
    let mut buf = Vec::with_capacity(HEADER_SIZE + data_slice.len());

    buf.extend_from_slice(&account.meta.lamports.to_le_bytes());
    buf.extend_from_slice(account.meta.owner.as_bytes());
    buf.push(account.meta.executable as u8);
    buf.extend_from_slice(&account.meta.rent_epoch.to_le_bytes());
    buf.extend_from_slice(&(data_slice.len() as u32).to_le_bytes());
    buf.extend_from_slice(data_slice);

    buf
}

/// Decode an Account from its binary representation.
///
/// Returns `None` if the buffer is too short or data_len is inconsistent.
#[inline]
pub fn decode_account(buf: &[u8]) -> Option<Account> {
    if buf.len() < HEADER_SIZE {
        return None;
    }

    let lamports = u64::from_le_bytes(buf[0..8].try_into().ok()?);
    let owner = Pubkey::from(<[u8; PUBKEY_BYTES]>::try_from(&buf[8..40]).ok()?);
    let executable = buf[40] != 0;
    let rent_epoch = u64::from_le_bytes(buf[41..49].try_into().ok()?);
    let data_len = u32::from_le_bytes(buf[49..53].try_into().ok()?) as usize;

    if buf.len() < HEADER_SIZE + data_len {
        return None;
    }

    let data = buf[HEADER_SIZE..HEADER_SIZE + data_len].to_vec();

    Some(Account {
        meta: AccountMeta::new(lamports, owner, executable, rent_epoch),
        data: AccountData::new(data),
    })
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
}
