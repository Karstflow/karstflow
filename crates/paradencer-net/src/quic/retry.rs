/// Stateless QUIC retry token generation and validation (RFC 9000).
///
/// Retry tokens allow the server to verify a client's source address
/// without storing per-connection state. The token is encrypted with
/// AES-128-GCM using a server secret, and contains the original
/// destination connection ID, client address, and expiration time.
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use paradencer_constants::network::{
    QUIC_RETRY_INTEGRITY_TAG_SIZE, QUIC_RETRY_IV_SIZE, QUIC_RETRY_MAX_TOKEN_SIZE,
    QUIC_RETRY_SECRET_SIZE,
};

use super::conn_id::ConnectionId;

/// Magic bytes at the start of retry token plaintext.
const RETRY_TOKEN_MAGIC: u16 = 0xdaa5;

/// Retry token plaintext structure.
///
/// Serialized into a fixed-layout buffer for encryption.
#[derive(Debug, Clone)]
pub struct RetryTokenData {
    /// Original destination connection ID from the client's first Initial.
    pub original_dst_conn_id: ConnectionId,
    /// Client's source IPv4 address (network byte order).
    pub client_ip: u32,
    /// Client's source UDP port (host byte order).
    pub client_port: u16,
    /// Token expiration time (nanoseconds, monotonic clock).
    pub expire_at: u64,
}

/// Encoded retry token (encrypted + authenticated).
///
/// Layout: [nonce(12)] [ciphertext(variable)] [gcm_tag(16)]
/// Plaintext: [magic(2)] [odcid_len(1)] [odcid(0-20)] [ip(4)] [port(2)] [expire(8)]
pub struct RetryToken;

impl RetryToken {
    /// Maximum plaintext size: 2 + 1 + 20 + 4 + 2 + 8 = 37 bytes.
    const MAX_PLAINTEXT: usize = 37;

    /// Generate a retry token from the given data.
    ///
    /// Returns the encrypted token bytes, or `None` on failure.
    /// The `nonce` must be a unique 12-byte value per token.
    pub fn generate(
        secret: &[u8; QUIC_RETRY_SECRET_SIZE],
        iv: &[u8; QUIC_RETRY_IV_SIZE],
        nonce_seed: &[u8; 12],
        data: &RetryTokenData,
    ) -> Option<Vec<u8>> {
        let plaintext = Self::serialize_plaintext(data);

        // XOR nonce_seed with IV to get the actual nonce
        let mut nonce_bytes = [0u8; 12];
        for i in 0..12 {
            nonce_bytes[i] = iv[i] ^ nonce_seed[i];
        }

        let cipher = Aes128Gcm::new_from_slice(secret).ok()?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext.as_slice()).ok()?;

        // Token = nonce_seed || ciphertext (includes GCM tag)
        let mut token = Vec::with_capacity(12 + ciphertext.len());
        token.extend_from_slice(nonce_seed);
        token.extend_from_slice(&ciphertext);

        if token.len() > QUIC_RETRY_MAX_TOKEN_SIZE {
            return None;
        }

        Some(token)
    }

    /// Validate and decrypt a retry token.
    ///
    /// Returns the decoded token data on success, or `None` if the
    /// token is invalid, expired, or from a different client.
    pub fn validate(
        secret: &[u8; QUIC_RETRY_SECRET_SIZE],
        iv: &[u8; QUIC_RETRY_IV_SIZE],
        token: &[u8],
        client_ip: u32,
        client_port: u16,
        now: u64,
    ) -> Option<RetryTokenData> {
        // Minimum token: 12 (nonce) + 2 (magic) + 1 (odcid_len) + 4 (ip) + 2 (port) + 8 (expire) + 16 (tag)
        if token.len() < 12 + 17 + 16 {
            return None;
        }

        let nonce_seed = &token[..12];
        let ciphertext = &token[12..];

        // Reconstruct nonce
        let mut nonce_bytes = [0u8; 12];
        for i in 0..12 {
            nonce_bytes[i] = iv[i] ^ nonce_seed[i];
        }

        let cipher = Aes128Gcm::new_from_slice(secret).ok()?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = cipher.decrypt(nonce, ciphertext).ok()?;

        let data = Self::deserialize_plaintext(&plaintext)?;

        // Verify client address
        if data.client_ip != client_ip || data.client_port != client_port {
            return None;
        }

        // Verify expiration
        if now > data.expire_at {
            return None;
        }

        Some(data)
    }

    fn serialize_plaintext(data: &RetryTokenData) -> Vec<u8> {
        let odcid = data.original_dst_conn_id.as_bytes();
        let mut buf = Vec::with_capacity(Self::MAX_PLAINTEXT);

        buf.extend_from_slice(&RETRY_TOKEN_MAGIC.to_be_bytes());
        buf.push(odcid.len() as u8);
        buf.extend_from_slice(odcid);
        buf.extend_from_slice(&data.client_ip.to_be_bytes());
        buf.extend_from_slice(&data.client_port.to_be_bytes());
        buf.extend_from_slice(&data.expire_at.to_be_bytes());

        buf
    }

    fn deserialize_plaintext(buf: &[u8]) -> Option<RetryTokenData> {
        if buf.len() < 17 {
            // Minimum: 2 (magic) + 1 (odcid_len) + 0 (odcid) + 4 (ip) + 2 (port) + 8 (expire)
            return None;
        }

        let magic = u16::from_be_bytes([buf[0], buf[1]]);
        if magic != RETRY_TOKEN_MAGIC {
            return None;
        }

        let odcid_len = buf[2] as usize;
        if odcid_len > 20 || buf.len() < 3 + odcid_len + 14 {
            return None;
        }

        let original_dst_conn_id = ConnectionId::from_bytes(&buf[3..3 + odcid_len])?;
        let offset = 3 + odcid_len;

        let client_ip = u32::from_be_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]);
        let client_port = u16::from_be_bytes([buf[offset + 4], buf[offset + 5]]);
        let expire_at = u64::from_be_bytes([
            buf[offset + 6],
            buf[offset + 7],
            buf[offset + 8],
            buf[offset + 9],
            buf[offset + 10],
            buf[offset + 11],
            buf[offset + 12],
            buf[offset + 13],
        ]);

        Some(RetryTokenData {
            original_dst_conn_id,
            client_ip,
            client_port,
            expire_at,
        })
    }
}

/// RFC 9001 Section 5.8: Retry Integrity Tag computation.
///
/// The Retry Integrity Tag is an AEAD authentication tag over the
/// Retry Pseudo-Packet, using the retry integrity key and nonce
/// from RFC 9001 Section 5.8.
pub struct RetryIntegrity;

/// Retry integrity key (RFC 9001 Section 5.8).
const RETRY_INTEGRITY_KEY: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];

/// Retry integrity nonce (RFC 9001 Section 5.8).
const RETRY_INTEGRITY_NONCE: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

impl RetryIntegrity {
    /// Compute the retry integrity tag over a Retry pseudo-packet.
    ///
    /// The pseudo-packet is: [odcid_len(1)] [odcid] [retry_packet_without_tag]
    pub fn compute_tag(
        original_dst_conn_id: &ConnectionId,
        retry_packet_without_tag: &[u8],
    ) -> Option<[u8; QUIC_RETRY_INTEGRITY_TAG_SIZE]> {
        // Build the pseudo-packet (AAD for AEAD)
        let odcid = original_dst_conn_id.as_bytes();
        let mut pseudo = Vec::with_capacity(1 + odcid.len() + retry_packet_without_tag.len());
        pseudo.push(odcid.len() as u8);
        pseudo.extend_from_slice(odcid);
        pseudo.extend_from_slice(retry_packet_without_tag);

        let cipher = Aes128Gcm::new_from_slice(&RETRY_INTEGRITY_KEY).ok()?;
        let nonce = Nonce::from_slice(&RETRY_INTEGRITY_NONCE);

        // Encrypt empty plaintext with the pseudo-packet as AAD
        // The "ciphertext" is just the 16-byte GCM tag
        let result = cipher
            .encrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: &[],
                    aad: &pseudo,
                },
            )
            .ok()?;

        if result.len() != 16 {
            return None;
        }

        let mut tag = [0u8; 16];
        tag.copy_from_slice(&result);
        Some(tag)
    }

    /// Verify a retry integrity tag.
    pub fn verify_tag(
        original_dst_conn_id: &ConnectionId,
        retry_packet_without_tag: &[u8],
        expected_tag: &[u8; QUIC_RETRY_INTEGRITY_TAG_SIZE],
    ) -> bool {
        match Self::compute_tag(original_dst_conn_id, retry_packet_without_tag) {
            Some(tag) => tag == *expected_tag,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret() -> [u8; QUIC_RETRY_SECRET_SIZE] {
        [0x42; QUIC_RETRY_SECRET_SIZE]
    }

    fn test_iv() -> [u8; QUIC_RETRY_IV_SIZE] {
        [0x13; QUIC_RETRY_IV_SIZE]
    }

    fn test_nonce() -> [u8; 12] {
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ]
    }

    fn test_data() -> RetryTokenData {
        RetryTokenData {
            original_dst_conn_id: ConnectionId::from_bytes(&[0xAA; 8]).unwrap(),
            client_ip: 0x0A000001, // 10.0.0.1
            client_port: 12345,
            expire_at: 1_000_000_000_000, // 1000 seconds
        }
    }

    #[test]
    fn generate_and_validate_roundtrip() {
        let secret = test_secret();
        let iv = test_iv();
        let nonce = test_nonce();
        let data = test_data();

        let token = RetryToken::generate(&secret, &iv, &nonce, &data).unwrap();
        assert!(!token.is_empty());
        assert!(token.len() <= QUIC_RETRY_MAX_TOKEN_SIZE);

        let validated = RetryToken::validate(
            &secret,
            &iv,
            &token,
            data.client_ip,
            data.client_port,
            data.expire_at - 1, // before expiry
        )
        .unwrap();

        assert_eq!(
            validated.original_dst_conn_id.as_bytes(),
            data.original_dst_conn_id.as_bytes()
        );
        assert_eq!(validated.client_ip, data.client_ip);
        assert_eq!(validated.client_port, data.client_port);
        assert_eq!(validated.expire_at, data.expire_at);
    }

    #[test]
    fn validate_wrong_secret_fails() {
        let secret = test_secret();
        let iv = test_iv();
        let nonce = test_nonce();
        let data = test_data();

        let token = RetryToken::generate(&secret, &iv, &nonce, &data).unwrap();

        let wrong_secret = [0xFF; QUIC_RETRY_SECRET_SIZE];
        assert!(RetryToken::validate(
            &wrong_secret,
            &iv,
            &token,
            data.client_ip,
            data.client_port,
            data.expire_at - 1,
        )
        .is_none());
    }

    #[test]
    fn validate_wrong_ip_fails() {
        let secret = test_secret();
        let iv = test_iv();
        let nonce = test_nonce();
        let data = test_data();

        let token = RetryToken::generate(&secret, &iv, &nonce, &data).unwrap();

        assert!(RetryToken::validate(
            &secret,
            &iv,
            &token,
            0x0A000002, // different IP
            data.client_port,
            data.expire_at - 1,
        )
        .is_none());
    }

    #[test]
    fn validate_wrong_port_fails() {
        let secret = test_secret();
        let iv = test_iv();
        let nonce = test_nonce();
        let data = test_data();

        let token = RetryToken::generate(&secret, &iv, &nonce, &data).unwrap();

        assert!(RetryToken::validate(
            &secret,
            &iv,
            &token,
            data.client_ip,
            54321, // different port
            data.expire_at - 1,
        )
        .is_none());
    }

    #[test]
    fn validate_expired_token_fails() {
        let secret = test_secret();
        let iv = test_iv();
        let nonce = test_nonce();
        let data = test_data();

        let token = RetryToken::generate(&secret, &iv, &nonce, &data).unwrap();

        assert!(RetryToken::validate(
            &secret,
            &iv,
            &token,
            data.client_ip,
            data.client_port,
            data.expire_at + 1, // after expiry
        )
        .is_none());
    }

    #[test]
    fn validate_tampered_token_fails() {
        let secret = test_secret();
        let iv = test_iv();
        let nonce = test_nonce();
        let data = test_data();

        let mut token = RetryToken::generate(&secret, &iv, &nonce, &data).unwrap();

        // Tamper with a ciphertext byte
        let last = token.len() - 1;
        token[last] ^= 0x01;

        assert!(RetryToken::validate(
            &secret,
            &iv,
            &token,
            data.client_ip,
            data.client_port,
            data.expire_at - 1,
        )
        .is_none());
    }

    #[test]
    fn validate_truncated_token_fails() {
        assert!(RetryToken::validate(
            &test_secret(),
            &test_iv(),
            &[0u8; 10], // too short
            0x0A000001,
            12345,
            0,
        )
        .is_none());
    }

    #[test]
    fn empty_odcid_roundtrip() {
        let secret = test_secret();
        let iv = test_iv();
        let nonce = test_nonce();
        let data = RetryTokenData {
            original_dst_conn_id: ConnectionId::EMPTY,
            client_ip: 0x0A000001,
            client_port: 443,
            expire_at: 2_000_000_000_000,
        };

        let token = RetryToken::generate(&secret, &iv, &nonce, &data).unwrap();
        let validated = RetryToken::validate(
            &secret,
            &iv,
            &token,
            data.client_ip,
            data.client_port,
            data.expire_at - 1,
        )
        .unwrap();

        assert!(validated.original_dst_conn_id.is_empty());
    }

    #[test]
    fn retry_integrity_tag_deterministic() {
        let odcid = ConnectionId::from_bytes(&[0x83, 0x94, 0xc8, 0xf0]).unwrap();
        let retry_packet = [0xc0, 0x00, 0x00, 0x00, 0x01]; // minimal fake

        let tag1 = RetryIntegrity::compute_tag(&odcid, &retry_packet).unwrap();
        let tag2 = RetryIntegrity::compute_tag(&odcid, &retry_packet).unwrap();
        assert_eq!(tag1, tag2);
    }

    #[test]
    fn retry_integrity_verify_roundtrip() {
        let odcid = ConnectionId::from_bytes(&[0x01, 0x02, 0x03]).unwrap();
        let retry_packet = [0xf0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xAA];

        let tag = RetryIntegrity::compute_tag(&odcid, &retry_packet).unwrap();
        assert!(RetryIntegrity::verify_tag(&odcid, &retry_packet, &tag));
    }

    #[test]
    fn retry_integrity_wrong_odcid_fails() {
        let odcid = ConnectionId::from_bytes(&[0x01]).unwrap();
        let retry_packet = [0xc0, 0x00, 0x00, 0x00, 0x01];

        let tag = RetryIntegrity::compute_tag(&odcid, &retry_packet).unwrap();

        let wrong_odcid = ConnectionId::from_bytes(&[0x02]).unwrap();
        assert!(!RetryIntegrity::verify_tag(
            &wrong_odcid,
            &retry_packet,
            &tag
        ));
    }

    #[test]
    fn retry_integrity_tampered_packet_fails() {
        let odcid = ConnectionId::from_bytes(&[0x01]).unwrap();
        let retry_packet = [0xc0, 0x00, 0x00, 0x00, 0x01];

        let tag = RetryIntegrity::compute_tag(&odcid, &retry_packet).unwrap();

        let tampered = [0xc0, 0x00, 0x00, 0x00, 0x02];
        assert!(!RetryIntegrity::verify_tag(&odcid, &tampered, &tag));
    }
}
