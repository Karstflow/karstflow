/// QUIC v1 cryptographic operations: key derivation and packet protection.
///
/// Implements RFC 9001 (Using TLS to Secure QUIC):
/// - Initial secret derivation from connection ID
/// - Protection key derivation from traffic secrets
/// - Packet payload encryption/decryption (AES-128-GCM AEAD)
/// - Header protection/unprotection (AES-128-ECB)
/// - Key update mechanism
use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;

use crate::tls::aead::{aead_decrypt, AeadError, AeadKey};
use crate::tls::hkdf::{hkdf_expand_label, hkdf_extract};
use karstflow_constants::network::{
    AES_128_KEY_SIZE, AES_GCM_IV_SIZE, AES_GCM_TAG_SIZE, QUIC_HP_SAMPLE_SIZE, QUIC_SECRET_SIZE,
    QUIC_V1_INITIAL_SALT, TLS_NUM_ENCRYPTION_LEVELS,
};

/// QUIC packet protection keys for a single direction.
///
/// Contains the AES-128-GCM key + IV for payload protection and
/// the AES-128-ECB key for header protection.
#[derive(Clone)]
pub struct ProtectionKeys {
    /// AES-128-GCM key for payload encryption.
    pub packet_key: [u8; AES_128_KEY_SIZE],
    /// Initialization vector for AEAD nonce derivation.
    pub iv: [u8; AES_GCM_IV_SIZE],
    /// AES-128 key for header protection (ECB mode).
    pub header_key: [u8; AES_128_KEY_SIZE],
}

impl ProtectionKeys {
    /// Derive protection keys from a traffic secret.
    ///
    /// Key schedule:
    ///   secret → packet_key = HKDF-Expand-Label(., "quic key", "", 16)
    ///   secret → iv          = HKDF-Expand-Label(., "quic iv", "", 12)
    ///   secret → header_key  = HKDF-Expand-Label(., "quic hp", "", 16)
    pub fn derive(secret: &[u8; QUIC_SECRET_SIZE]) -> Self {
        let mut packet_key = [0u8; AES_128_KEY_SIZE];
        hkdf_expand_label(&mut packet_key, secret, b"quic key", &[]);

        let mut iv = [0u8; AES_GCM_IV_SIZE];
        hkdf_expand_label(&mut iv, secret, b"quic iv", &[]);

        let mut header_key = [0u8; AES_128_KEY_SIZE];
        hkdf_expand_label(&mut header_key, secret, b"quic hp", &[]);

        Self {
            packet_key,
            iv,
            header_key,
        }
    }

    /// Get an AEAD key handle for payload encryption.
    pub fn aead_key(&self) -> AeadKey {
        AeadKey::new(self.packet_key, self.iv)
    }

    /// Compute the AEAD nonce for a given packet number.
    pub fn compute_nonce(&self, packet_number: u64) -> [u8; AES_GCM_IV_SIZE] {
        self.aead_key().compute_nonce(packet_number)
    }

    /// Apply header protection mask to a packet buffer.
    ///
    /// `buf` contains the full QUIC packet.
    /// `pkt_number_offset` is the byte offset of the packet number field.
    ///
    /// The mask is derived by encrypting a 16-byte sample from the payload
    /// using AES-128-ECB with the header protection key.
    pub fn protect_header(
        &self,
        buf: &mut [u8],
        pkt_number_offset: usize,
    ) -> Result<(), CryptoError> {
        let sample_offset = pkt_number_offset + 4;
        if sample_offset + QUIC_HP_SAMPLE_SIZE > buf.len() {
            return Err(CryptoError::BufferTooSmall);
        }

        // Generate mask by encrypting the sample with AES-ECB
        let mask = self.header_mask(&buf[sample_offset..sample_offset + QUIC_HP_SAMPLE_SIZE])?;

        // Apply mask to first byte
        let first = buf[0];
        let long_header = first & 0x80 != 0;
        buf[0] ^= mask[0] & if long_header { 0x0F } else { 0x1F };

        // Determine packet number length from the (now-masked) first byte
        let pkt_num_len = (first & 0x03) as usize + 1;

        // Apply mask to packet number bytes
        for j in 0..pkt_num_len {
            buf[pkt_number_offset + j] ^= mask[1 + j];
        }

        Ok(())
    }

    /// Remove header protection from a packet buffer.
    ///
    /// `buf` must contain the full QUIC packet with header protection applied.
    /// Returns the actual packet number length (1-4 bytes).
    pub fn unprotect_header(
        &self,
        buf: &mut [u8],
        pkt_number_offset: usize,
    ) -> Result<usize, CryptoError> {
        let sample_offset = pkt_number_offset + 4;
        if sample_offset + QUIC_HP_SAMPLE_SIZE > buf.len() {
            return Err(CryptoError::BufferTooSmall);
        }

        let mask = self.header_mask(&buf[sample_offset..sample_offset + QUIC_HP_SAMPLE_SIZE])?;

        // Unmask first byte
        let long_header = buf[0] & 0x80 != 0;
        buf[0] ^= mask[0] & if long_header { 0x0F } else { 0x1F };

        // Now we can read the actual packet number length
        let pkt_num_len = (buf[0] & 0x03) as usize + 1;
        if pkt_number_offset + pkt_num_len > buf.len() {
            return Err(CryptoError::BufferTooSmall);
        }

        // Unmask packet number
        for j in 0..pkt_num_len {
            buf[pkt_number_offset + j] ^= mask[1 + j];
        }

        Ok(pkt_num_len)
    }

    /// Generate the 5-byte header protection mask from a 16-byte sample.
    fn header_mask(&self, sample: &[u8]) -> Result<[u8; 5], CryptoError> {
        if sample.len() < QUIC_HP_SAMPLE_SIZE {
            return Err(CryptoError::BufferTooSmall);
        }

        let cipher = Aes128::new(GenericArray::from_slice(&self.header_key));
        let mut block = GenericArray::clone_from_slice(&sample[..16]);
        cipher.encrypt_block(&mut block);

        let mut mask = [0u8; 5];
        mask.copy_from_slice(&block[..5]);
        Ok(mask)
    }
}

/// QUIC connection secrets for all encryption levels and both directions.
pub struct ConnectionSecrets {
    /// Initial secret (derived from connection ID).
    pub initial_secret: [u8; QUIC_SECRET_SIZE],

    /// Traffic secrets: [encryption_level][direction]
    /// direction: 0 = read (incoming), 1 = write (outgoing)
    pub secrets: [[[u8; QUIC_SECRET_SIZE]; 2]; TLS_NUM_ENCRYPTION_LEVELS],

    /// Pending new secrets for key update.
    pub new_secrets: [[u8; QUIC_SECRET_SIZE]; 2],
}

impl ConnectionSecrets {
    /// Create empty connection secrets.
    pub fn new() -> Self {
        Self {
            initial_secret: [0u8; QUIC_SECRET_SIZE],
            secrets: [[[0u8; QUIC_SECRET_SIZE]; 2]; TLS_NUM_ENCRYPTION_LEVELS],
            new_secrets: [[0u8; QUIC_SECRET_SIZE]; 2],
        }
    }

    /// Derive initial secrets from a QUIC v1 connection ID.
    ///
    /// initial_secret = HKDF-Extract(initial_salt, conn_id)
    /// client_initial = HKDF-Expand-Label(initial_secret, "client in", "", 32)
    /// server_initial = HKDF-Expand-Label(initial_secret, "server in", "", 32)
    ///
    /// The `is_server` flag determines which direction maps to read vs write:
    /// - Server: read = client initial, write = server initial
    /// - Client: read = server initial, write = client initial
    pub fn derive_initial(conn_id: &[u8], is_server: bool) -> Self {
        let mut secrets = Self::new();

        secrets.initial_secret = hkdf_extract(&QUIC_V1_INITIAL_SALT, conn_id);

        let mut client_secret = [0u8; QUIC_SECRET_SIZE];
        hkdf_expand_label(
            &mut client_secret,
            &secrets.initial_secret,
            b"client in",
            &[],
        );

        let mut server_secret = [0u8; QUIC_SECRET_SIZE];
        hkdf_expand_label(
            &mut server_secret,
            &secrets.initial_secret,
            b"server in",
            &[],
        );

        if is_server {
            secrets.secrets[0][0] = client_secret; // read = from client
            secrets.secrets[0][1] = server_secret; // write = to client
        } else {
            secrets.secrets[0][0] = server_secret; // read = from server
            secrets.secrets[0][1] = client_secret; // write = to server
        }

        secrets
    }

    /// Set the secrets for a given encryption level.
    pub fn set_level_secrets(
        &mut self,
        level: usize,
        read_secret: [u8; QUIC_SECRET_SIZE],
        write_secret: [u8; QUIC_SECRET_SIZE],
    ) {
        self.secrets[level][0] = read_secret;
        self.secrets[level][1] = write_secret;
    }

    /// Derive protection keys for a given level and direction.
    pub fn protection_keys(&self, level: usize, is_write: bool) -> ProtectionKeys {
        let dir = if is_write { 1 } else { 0 };
        ProtectionKeys::derive(&self.secrets[level][dir])
    }

    /// Perform a key update: derive new application-level secrets.
    ///
    /// new_secret = HKDF-Expand-Label(current_secret, "quic ku", "", 32)
    pub fn key_update(&mut self) -> [ProtectionKeys; 2] {
        let app_level = 3; // Application level

        for dir in 0..2 {
            hkdf_expand_label(
                &mut self.new_secrets[dir],
                &self.secrets[app_level][dir],
                b"quic ku",
                &[],
            );
        }

        let read_keys = ProtectionKeys::derive(&self.new_secrets[0]);
        let write_keys = ProtectionKeys::derive(&self.new_secrets[1]);

        // Rotate: new secrets become current
        self.secrets[app_level] = self.new_secrets;

        [read_keys, write_keys]
    }
}

impl Default for ConnectionSecrets {
    fn default() -> Self {
        Self::new()
    }
}

/// Decrypt a QUIC packet payload in-place.
///
/// `buf[hdr_len..buf_len - TAG_SIZE]` contains the ciphertext.
/// `buf[buf_len - TAG_SIZE..buf_len]` contains the GCM tag.
/// `buf[..hdr_len]` is used as additional authenticated data.
///
/// Returns the plaintext length (excluding tag) on success.
pub fn decrypt_packet_payload(
    keys: &ProtectionKeys,
    buf: &mut [u8],
    hdr_len: usize,
    packet_number: u64,
) -> Result<usize, CryptoError> {
    if buf.len() < hdr_len + AES_GCM_TAG_SIZE {
        return Err(CryptoError::BufferTooSmall);
    }

    let aead_key = keys.aead_key();
    let hdr = buf[..hdr_len].to_vec();
    let ciphertext = &buf[hdr_len..];

    let plaintext =
        aead_decrypt(&aead_key, packet_number, &hdr, ciphertext).map_err(|e| match e {
            AeadError::DecryptFailed => CryptoError::AuthenticationFailed,
            _ => CryptoError::DecryptFailed,
        })?;

    buf[hdr_len..hdr_len + plaintext.len()].copy_from_slice(&plaintext);
    Ok(plaintext.len())
}

/// QUIC crypto operation error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    BufferTooSmall,
    EncryptFailed,
    DecryptFailed,
    AuthenticationFailed,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BufferTooSmall => write!(f, "buffer too small for crypto operation"),
            Self::EncryptFailed => write!(f, "QUIC packet encryption failed"),
            Self::DecryptFailed => write!(f, "QUIC packet decryption failed"),
            Self::AuthenticationFailed => write!(f, "QUIC packet authentication failed"),
        }
    }
}

impl std::error::Error for CryptoError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_initial_secrets_deterministic() {
        let conn_id = hex::decode("8394c8f03e515708").unwrap();
        let s1 = ConnectionSecrets::derive_initial(&conn_id, true);
        let s2 = ConnectionSecrets::derive_initial(&conn_id, true);
        assert_eq!(s1.initial_secret, s2.initial_secret);
        assert_eq!(s1.secrets[0][0], s2.secrets[0][0]);
        assert_eq!(s1.secrets[0][1], s2.secrets[0][1]);
    }

    #[test]
    fn derive_initial_client_server_mirrored() {
        let conn_id = b"test_conn_id";
        let server = ConnectionSecrets::derive_initial(conn_id, true);
        let client = ConnectionSecrets::derive_initial(conn_id, false);

        // Same initial secret
        assert_eq!(server.initial_secret, client.initial_secret);

        // Server's read = client's write, and vice versa
        assert_eq!(server.secrets[0][0], client.secrets[0][1]);
        assert_eq!(server.secrets[0][1], client.secrets[0][0]);
    }

    #[test]
    fn derive_initial_secrets_rfc9001_appendix_a() {
        // RFC 9001 Appendix A.1 test vector
        let conn_id = hex::decode("8394c8f03e515708").unwrap();
        let secrets = ConnectionSecrets::derive_initial(&conn_id, false);

        // Expected initial secret
        let expected_initial =
            hex::decode("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44")
                .unwrap();
        assert_eq!(&secrets.initial_secret[..], &expected_initial[..]);

        // Client initial secret (for client, write = client direction = index 1)
        let expected_client =
            hex::decode("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
                .unwrap();
        assert_eq!(&secrets.secrets[0][1][..], &expected_client[..]);

        // Server initial secret (for client, read = server direction = index 0)
        let expected_server =
            hex::decode("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b")
                .unwrap();
        assert_eq!(&secrets.secrets[0][0][..], &expected_server[..]);
    }

    #[test]
    fn protection_keys_derive_from_secret() {
        let secret = [0xABu8; 32];
        let keys = ProtectionKeys::derive(&secret);

        // Keys should be non-zero
        assert_ne!(keys.packet_key, [0u8; 16]);
        assert_ne!(keys.iv, [0u8; 12]);
        assert_ne!(keys.header_key, [0u8; 16]);

        // Different parts of the key should differ
        assert_ne!(keys.packet_key, keys.header_key);
    }

    #[test]
    fn protection_keys_rfc9001_client_initial() {
        // RFC 9001 Appendix A.1 - Client Initial keys
        let client_secret =
            hex::decode("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
                .unwrap();
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&client_secret);

        let keys = ProtectionKeys::derive(&secret);

        let expected_key = hex::decode("1f369613dd76d5467730efcbe3b1a22d").unwrap();
        assert_eq!(&keys.packet_key[..], &expected_key[..]);

        let expected_iv = hex::decode("fa044b2f42a3fd3b46fb255c").unwrap();
        assert_eq!(&keys.iv[..], &expected_iv[..]);

        let expected_hp = hex::decode("9f50449e04a0e810283a1e9933adedd2").unwrap();
        assert_eq!(&keys.header_key[..], &expected_hp[..]);
    }

    #[test]
    fn header_protection_round_trip() {
        let secret = [0x42u8; 32];
        let keys = ProtectionKeys::derive(&secret);

        // Simulate a packet: [header...][pkt_num][payload_with_sample...]
        let mut buf = vec![0u8; 64];
        buf[0] = 0xC3; // Long header, 4-byte pkt num
        buf[1..4].copy_from_slice(&[0x01, 0x02, 0x03]); // header bytes
        let pkt_num_off = 4;
        buf[4..8].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // packet number
                                                              // Fill payload (need at least 16 bytes for sample after pkt_num)
        for (i, byte) in buf[8..64].iter_mut().enumerate() {
            *byte = (i + 8) as u8;
        }

        let original = buf.clone();

        // Protect
        keys.protect_header(&mut buf, pkt_num_off).unwrap();
        assert_ne!(&buf[..8], &original[..8]); // Header should be different

        // Unprotect
        let pkt_num_len = keys.unprotect_header(&mut buf, pkt_num_off).unwrap();
        assert_eq!(pkt_num_len, 4);
        assert_eq!(&buf[..8], &original[..8]); // Should match original
    }

    #[test]
    fn header_protection_short_header() {
        let secret = [0x42u8; 32];
        let keys = ProtectionKeys::derive(&secret);

        let mut buf = vec![0u8; 48];
        buf[0] = 0x41; // Short header, 2-byte pkt num
        let pkt_num_off = 1;
        buf[1] = 0x10;
        buf[2] = 0x20;
        for (i, byte) in buf[3..48].iter_mut().enumerate() {
            *byte = (i + 3) as u8;
        }

        let original = buf.clone();

        keys.protect_header(&mut buf, pkt_num_off).unwrap();
        assert_ne!(buf[0], original[0]);

        let pkt_num_len = keys.unprotect_header(&mut buf, pkt_num_off).unwrap();
        assert_eq!(pkt_num_len, 2);
        assert_eq!(buf[0], original[0]);
        assert_eq!(buf[1], original[1]);
        assert_eq!(buf[2], original[2]);
    }

    #[test]
    fn key_update_produces_new_keys() {
        let conn_id = b"test";
        let mut secrets = ConnectionSecrets::derive_initial(conn_id, true);

        // Set some application-level secrets
        secrets.set_level_secrets(3, [0x11u8; 32], [0x22u8; 32]);

        let old_read = secrets.secrets[3][0];
        let [new_read, new_write] = secrets.key_update();

        // Secrets should have rotated
        assert_ne!(secrets.secrets[3][0], old_read);
        assert_ne!(new_read.packet_key, [0u8; 16]);
        assert_ne!(new_write.packet_key, [0u8; 16]);
    }

    #[test]
    fn nonce_computation() {
        let keys = ProtectionKeys {
            packet_key: [0u8; 16],
            iv: [
                0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB,
            ],
            header_key: [0u8; 16],
        };

        let nonce0 = keys.compute_nonce(0);
        assert_eq!(nonce0, keys.iv);

        let nonce1 = keys.compute_nonce(1);
        assert_ne!(nonce0, nonce1);
        assert_eq!(nonce1[11], keys.iv[11] ^ 1);
    }

    #[test]
    fn encrypt_decrypt_packet_payload() {
        let secret = [0x42u8; 32];
        let keys = ProtectionKeys::derive(&secret);

        let header = b"QUIC header";
        let plaintext = b"stream data payload";
        let pkt_num = 100u64;

        // Encrypt
        let aead_key = keys.aead_key();
        let mut ciphertext = Vec::new();
        crate::tls::aead::aead_encrypt(&aead_key, pkt_num, header, plaintext, &mut ciphertext)
            .unwrap();

        // Build full packet buffer
        let mut buf = Vec::new();
        buf.extend_from_slice(header);
        buf.extend_from_slice(&ciphertext);

        // Decrypt
        let pt_len = decrypt_packet_payload(&keys, &mut buf, header.len(), pkt_num).unwrap();
        assert_eq!(&buf[header.len()..header.len() + pt_len], &plaintext[..]);
    }

    #[test]
    fn decrypt_wrong_keys_fails() {
        let keys1 = ProtectionKeys::derive(&[0x11u8; 32]);
        let keys2 = ProtectionKeys::derive(&[0x22u8; 32]);

        let header = b"HDR";
        let aead_key = keys1.aead_key();
        let mut ct = Vec::new();
        crate::tls::aead::aead_encrypt(&aead_key, 0, header, b"data", &mut ct).unwrap();

        let mut buf = Vec::new();
        buf.extend_from_slice(header);
        buf.extend_from_slice(&ct);

        let result = decrypt_packet_payload(&keys2, &mut buf, header.len(), 0);
        assert_eq!(result, Err(CryptoError::AuthenticationFailed));
    }

    #[test]
    fn set_level_secrets() {
        let mut secrets = ConnectionSecrets::new();
        let read = [0x11u8; 32];
        let write = [0x22u8; 32];
        secrets.set_level_secrets(2, read, write);

        let read_keys = secrets.protection_keys(2, false);
        let write_keys = secrets.protection_keys(2, true);

        // Keys derived from different secrets should differ
        assert_ne!(read_keys.packet_key, write_keys.packet_key);
    }
}
