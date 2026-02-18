/// AES-128-GCM authenticated encryption for TLS 1.3 / QUIC packet protection.
///
/// Provides encrypt/decrypt operations with associated data (AEAD).
/// This is the only cipher suite supported: TLS_AES_128_GCM_SHA256.
use aes_gcm::{
    aead::{Aead, Payload},
    Aes128Gcm, KeyInit, Nonce,
};
use paradencer_constants::network::{AES_128_KEY_SIZE, AES_GCM_IV_SIZE, AES_GCM_TAG_SIZE};

/// AES-128-GCM key material for a single direction.
#[derive(Clone)]
pub struct AeadKey {
    /// 16-byte AES-128 key.
    pub key: [u8; AES_128_KEY_SIZE],
    /// 12-byte initialization vector (nonce base).
    pub iv: [u8; AES_GCM_IV_SIZE],
}

impl AeadKey {
    pub fn new(key: [u8; AES_128_KEY_SIZE], iv: [u8; AES_GCM_IV_SIZE]) -> Self {
        Self { key, iv }
    }

    /// Compute the nonce for a given packet number.
    ///
    /// nonce = IV XOR (packet_number as 62-bit big-endian, left-padded to 12 bytes)
    pub fn compute_nonce(&self, packet_number: u64) -> [u8; AES_GCM_IV_SIZE] {
        let mut nonce = self.iv;
        let pn_bytes = (packet_number & 0x3FFF_FFFF_FFFF_FFFF).to_be_bytes();
        // XOR the last 8 bytes of the 12-byte nonce with the packet number
        for i in 0..8 {
            nonce[4 + i] ^= pn_bytes[i];
        }
        nonce
    }
}

/// Encrypt plaintext using AES-128-GCM with associated data.
///
/// Returns ciphertext || 16-byte authentication tag appended to `out`.
/// `out` must have capacity for plaintext.len() + 16 bytes.
pub fn aead_encrypt(
    key: &AeadKey,
    packet_number: u64,
    aad: &[u8],
    plaintext: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), AeadError> {
    let nonce = key.compute_nonce(packet_number);
    let cipher = Aes128Gcm::new_from_slice(&key.key).map_err(|_| AeadError::InvalidKey)?;

    let payload = Payload {
        msg: plaintext,
        aad,
    };
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), payload)
        .map_err(|_| AeadError::EncryptFailed)?;

    out.extend_from_slice(&ciphertext);
    Ok(())
}

/// Encrypt plaintext in-place using AES-128-GCM.
///
/// `buf` must contain the plaintext starting at `payload_offset` through `payload_end`.
/// The tag is written at `payload_end..payload_end + 16`.
/// `hdr` (buf[0..payload_offset]) is used as AAD.
///
/// Returns the total size (header + ciphertext + tag).
pub fn aead_encrypt_in_place(
    key: &AeadKey,
    packet_number: u64,
    buf: &mut [u8],
    hdr_len: usize,
    payload_len: usize,
) -> Result<usize, AeadError> {
    let total = hdr_len + payload_len + AES_GCM_TAG_SIZE;
    if buf.len() < total {
        return Err(AeadError::BufferTooSmall);
    }

    let nonce = key.compute_nonce(packet_number);
    let cipher = Aes128Gcm::new_from_slice(&key.key).map_err(|_| AeadError::InvalidKey)?;

    // Split buffer: header is AAD, payload is plaintext, tag goes after
    let (hdr, rest) = buf.split_at(hdr_len);
    let aad = hdr.to_vec(); // need to copy since we mutate buf
    let payload = Payload {
        msg: &rest[..payload_len],
        aad: &aad,
    };

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), payload)
        .map_err(|_| AeadError::EncryptFailed)?;

    buf[hdr_len..hdr_len + ciphertext.len()].copy_from_slice(&ciphertext);
    Ok(hdr_len + ciphertext.len())
}

/// Decrypt ciphertext using AES-128-GCM with associated data.
///
/// `ciphertext` includes the 16-byte authentication tag at the end.
/// Returns decrypted plaintext.
pub fn aead_decrypt(
    key: &AeadKey,
    packet_number: u64,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    if ciphertext.len() < AES_GCM_TAG_SIZE {
        return Err(AeadError::BufferTooSmall);
    }

    let nonce = key.compute_nonce(packet_number);
    let cipher = Aes128Gcm::new_from_slice(&key.key).map_err(|_| AeadError::InvalidKey)?;

    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    cipher
        .decrypt(Nonce::from_slice(&nonce), payload)
        .map_err(|_| AeadError::DecryptFailed)
}

/// AEAD operation error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadError {
    InvalidKey,
    EncryptFailed,
    DecryptFailed,
    BufferTooSmall,
}

impl std::fmt::Display for AeadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKey => write!(f, "invalid AES key"),
            Self::EncryptFailed => write!(f, "AES-GCM encryption failed"),
            Self::DecryptFailed => write!(f, "AES-GCM decryption failed (authentication)"),
            Self::BufferTooSmall => write!(f, "buffer too small for AEAD operation"),
        }
    }
}

impl std::error::Error for AeadError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> AeadKey {
        AeadKey::new(
            [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10,
            ],
            [
                0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab,
            ],
        )
    }

    #[test]
    fn nonce_computation() {
        let key = test_key();
        let nonce = key.compute_nonce(0);
        assert_eq!(nonce, key.iv);

        let nonce1 = key.compute_nonce(1);
        assert_ne!(nonce, nonce1);
        // Last byte should differ by XOR with 1
        assert_eq!(nonce1[11], key.iv[11] ^ 1);
    }

    #[test]
    fn nonce_xor_large_pkt_number() {
        let key = AeadKey::new([0u8; 16], [0u8; 12]);
        let nonce = key.compute_nonce(0x1234_5678_9ABC_DEF0);
        // Only lower 62 bits are used
        let masked = 0x1234_5678_9ABC_DEF0u64 & 0x3FFF_FFFF_FFFF_FFFF;
        let expected = masked.to_be_bytes();
        assert_eq!(&nonce[4..12], &expected[..]);
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = test_key();
        let plaintext = b"hello QUIC world";
        let aad = b"packet header";
        let pkt_num = 42u64;

        let mut ciphertext = Vec::new();
        aead_encrypt(&key, pkt_num, aad, plaintext, &mut ciphertext).unwrap();

        assert_eq!(ciphertext.len(), plaintext.len() + AES_GCM_TAG_SIZE);
        assert_ne!(&ciphertext[..plaintext.len()], &plaintext[..]);

        let decrypted = aead_decrypt(&key, pkt_num, aad, &ciphertext).unwrap();
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let key1 = test_key();
        let key2 = AeadKey::new([0xffu8; 16], [0u8; 12]);

        let mut ct = Vec::new();
        aead_encrypt(&key1, 0, b"", b"data", &mut ct).unwrap();

        let result = aead_decrypt(&key2, 0, b"", &ct);
        assert_eq!(result, Err(AeadError::DecryptFailed));
    }

    #[test]
    fn decrypt_wrong_aad_fails() {
        let key = test_key();
        let mut ct = Vec::new();
        aead_encrypt(&key, 0, b"correct aad", b"data", &mut ct).unwrap();

        let result = aead_decrypt(&key, 0, b"wrong aad", &ct);
        assert_eq!(result, Err(AeadError::DecryptFailed));
    }

    #[test]
    fn decrypt_wrong_pkt_number_fails() {
        let key = test_key();
        let mut ct = Vec::new();
        aead_encrypt(&key, 1, b"aad", b"data", &mut ct).unwrap();

        let result = aead_decrypt(&key, 2, b"aad", &ct);
        assert_eq!(result, Err(AeadError::DecryptFailed));
    }

    #[test]
    fn decrypt_tampered_ciphertext_fails() {
        let key = test_key();
        let mut ct = Vec::new();
        aead_encrypt(&key, 0, b"", b"sensitive data", &mut ct).unwrap();

        ct[0] ^= 0xff; // tamper
        let result = aead_decrypt(&key, 0, b"", &ct);
        assert_eq!(result, Err(AeadError::DecryptFailed));
    }

    #[test]
    fn empty_plaintext() {
        let key = test_key();
        let mut ct = Vec::new();
        aead_encrypt(&key, 0, b"header", b"", &mut ct).unwrap();
        assert_eq!(ct.len(), AES_GCM_TAG_SIZE);

        let pt = aead_decrypt(&key, 0, b"header", &ct).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn encrypt_in_place_round_trip() {
        let key = test_key();
        let hdr = b"QUIC HDR";
        let payload = b"payload data here";

        let mut buf = vec![0u8; hdr.len() + payload.len() + AES_GCM_TAG_SIZE];
        buf[..hdr.len()].copy_from_slice(hdr);
        buf[hdr.len()..hdr.len() + payload.len()].copy_from_slice(payload);

        let total = aead_encrypt_in_place(&key, 5, &mut buf, hdr.len(), payload.len()).unwrap();

        // Decrypt using the standard function
        let ct = &buf[hdr.len()..total];
        let decrypted = aead_decrypt(&key, 5, hdr, ct).unwrap();
        assert_eq!(&decrypted[..], &payload[..]);
    }
}
