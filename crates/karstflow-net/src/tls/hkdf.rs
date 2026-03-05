/// HKDF key derivation functions for TLS 1.3.
///
/// Implements HKDF-Extract (RFC 5869) and HKDF-Expand-Label (RFC 8446 Section 7.1)
/// using HMAC-SHA256 as the underlying PRF.
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// HKDF-Extract: derives a pseudorandom key from input key material.
///
/// Returns HMAC-SHA256(salt, ikm). When salt is empty, a zero-filled
/// key of hash length is used per RFC 5869.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut mac = if salt.is_empty() {
        HmacSha256::new_from_slice(&[0u8; 32]).unwrap()
    } else {
        HmacSha256::new_from_slice(salt).unwrap()
    };
    mac.update(ikm);
    let result = mac.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result.into_bytes());
    out
}

/// HKDF-Expand-Label as specified in RFC 8446 Section 7.1.
///
/// Derives `out.len()` bytes using the TLS 1.3 label format:
///   HKDF-Expand(secret, HkdfLabel, Length)
///
/// where HkdfLabel = length || "tls13 " || label || context_hash || 0x01.
///
/// Constraints: out_len <= 32, label_len <= 64, context_len <= 64.
pub fn hkdf_expand_label(out: &mut [u8], secret: &[u8; 32], label: &[u8], context: &[u8]) {
    debug_assert!(out.len() <= 32);
    debug_assert!(label.len() <= 64);
    debug_assert!(context.len() <= 64);

    // Build the info structure for HKDF-Expand with T(1) only
    // (sufficient since output <= 32 = hash length)
    //
    // Format:
    //   uint16 length (output length)
    //   opaque label<7..255> = "tls13 " + label
    //   opaque context<0..255> = context
    //   uint8 0x01 (counter for T(1))
    let out_len = out.len();
    let label_with_prefix_len = 6 + label.len(); // "tls13 " prefix

    let mut info = [0u8; 2 + 1 + 6 + 64 + 1 + 64 + 1];
    let mut pos = 0;

    // Output length (2 bytes, big-endian)
    info[pos] = 0;
    info[pos + 1] = out_len as u8;
    pos += 2;

    // Label length prefix
    info[pos] = label_with_prefix_len as u8;
    pos += 1;

    // "tls13 " prefix
    info[pos..pos + 6].copy_from_slice(b"tls13 ");
    pos += 6;

    // Label
    info[pos..pos + label.len()].copy_from_slice(label);
    pos += label.len();

    // Context length prefix
    info[pos] = context.len() as u8;
    pos += 1;

    // Context
    info[pos..pos + context.len()].copy_from_slice(context);
    pos += context.len();

    // HKDF-Expand counter (T(1))
    info[pos] = 0x01;
    pos += 1;

    // T(1) = HMAC-SHA256(secret, info)
    let mut mac = HmacSha256::new_from_slice(secret).unwrap();
    mac.update(&info[..pos]);
    let result = mac.finalize();
    out.copy_from_slice(&result.into_bytes()[..out_len]);
}

/// Pre-computed "derived" key from the TLS 1.3 key schedule.
///
/// This is HKDF-Expand-Label(early_secret, "derived", SHA256(""), 32)
/// where early_secret = HKDF-Extract(zeros, zeros).
///
/// Used as the salt for deriving the handshake secret.
pub const HANDSHAKE_DERIVED: [u8; 32] = [
    0x6f, 0x26, 0x15, 0xa1, 0x08, 0xc7, 0x02, 0xc5, 0x67, 0x8f, 0x54, 0xfc, 0x9d, 0xba, 0xb6, 0x97,
    0x16, 0xc0, 0x76, 0x18, 0x9c, 0x48, 0x25, 0x0c, 0xeb, 0xea, 0xc3, 0x57, 0x6c, 0x36, 0x11, 0xba,
];

/// SHA-256 hash of empty input.
pub const EMPTY_HASH: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

/// Derive the TLS 1.3 handshake secret from ECDH shared secret.
///
/// handshake_secret = HKDF-Extract(handshake_derived, ecdh_ikm)
pub fn derive_handshake_secret(ecdh_ikm: &[u8; 32]) -> [u8; 32] {
    hkdf_extract(&HANDSHAKE_DERIVED, ecdh_ikm)
}

/// Derive client and server handshake traffic secrets.
pub fn derive_handshake_traffic_secrets(
    handshake_secret: &[u8; 32],
    transcript_hash: &[u8; 32],
) -> ([u8; 32], [u8; 32]) {
    let mut client_secret = [0u8; 32];
    hkdf_expand_label(
        &mut client_secret,
        handshake_secret,
        b"c hs traffic",
        transcript_hash,
    );

    let mut server_secret = [0u8; 32];
    hkdf_expand_label(
        &mut server_secret,
        handshake_secret,
        b"s hs traffic",
        transcript_hash,
    );

    (client_secret, server_secret)
}

/// Derive the master secret from the handshake secret.
///
/// master_derive = HKDF-Expand-Label(handshake_secret, "derived", empty_hash)
/// master_secret = HKDF-Extract(master_derive, zeros)
pub fn derive_master_secret(handshake_secret: &[u8; 32]) -> [u8; 32] {
    let mut master_derive = [0u8; 32];
    hkdf_expand_label(
        &mut master_derive,
        handshake_secret,
        b"derived",
        &EMPTY_HASH,
    );
    hkdf_extract(&master_derive, &[0u8; 32])
}

/// Derive client and server application traffic secrets.
pub fn derive_application_traffic_secrets(
    master_secret: &[u8; 32],
    transcript_hash: &[u8; 32],
) -> ([u8; 32], [u8; 32]) {
    let mut client_secret = [0u8; 32];
    hkdf_expand_label(
        &mut client_secret,
        master_secret,
        b"c ap traffic",
        transcript_hash,
    );

    let mut server_secret = [0u8; 32];
    hkdf_expand_label(
        &mut server_secret,
        master_secret,
        b"s ap traffic",
        transcript_hash,
    );

    (client_secret, server_secret)
}

/// Derive the "Finished" verify data for handshake completion.
///
/// finished_key = HKDF-Expand-Label(hs_secret, "finished", "", 32)
/// verify_data = HMAC-SHA256(transcript_hash, finished_key)
pub fn derive_finished_verify(hs_secret: &[u8; 32], transcript_hash: &[u8; 32]) -> [u8; 32] {
    let mut finished_key = [0u8; 32];
    hkdf_expand_label(&mut finished_key, hs_secret, b"finished", &[]);

    let mut mac = HmacSha256::new_from_slice(&finished_key).unwrap();
    mac.update(transcript_hash);
    let result = mac.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result.into_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_hash_correct() {
        use sha2::{Digest, Sha256};
        let result = Sha256::digest([]);
        assert_eq!(&EMPTY_HASH[..], result.as_slice());
    }

    #[test]
    fn handshake_derived_correct() {
        // Verify that HANDSHAKE_DERIVED matches the expected derivation:
        // early_secret = HKDF-Extract(salt=empty, ikm=zeros)
        // handshake_derived = HKDF-Expand-Label(early_secret, "derived", empty_hash, 32)
        let early_secret = hkdf_extract(&[], &[0u8; 32]);
        let mut derived = [0u8; 32];
        hkdf_expand_label(&mut derived, &early_secret, b"derived", &EMPTY_HASH);
        assert_eq!(derived, HANDSHAKE_DERIVED);
    }

    #[test]
    fn hkdf_extract_basic() {
        // RFC 5869 Test Case 1 (adapted for SHA-256)
        let ikm = [0x0bu8; 22];
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let prk = hkdf_extract(&salt, &ikm);
        let expected =
            hex::decode("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
                .unwrap();
        assert_eq!(&prk[..], &expected[..]);
    }

    #[test]
    fn hkdf_expand_label_smoke() {
        // Simple round-trip: derive a key and verify it's deterministic
        let secret = [0xabu8; 32];
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        hkdf_expand_label(&mut out1, &secret, b"test label", b"context");
        hkdf_expand_label(&mut out2, &secret, b"test label", b"context");
        assert_eq!(out1, out2);
    }

    #[test]
    fn hkdf_expand_label_different_labels_differ() {
        let secret = [0xabu8; 32];
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        hkdf_expand_label(&mut out1, &secret, b"label_a", &[]);
        hkdf_expand_label(&mut out2, &secret, b"label_b", &[]);
        assert_ne!(out1, out2);
    }

    #[test]
    fn hkdf_expand_label_variable_output_length() {
        let secret = [0x42u8; 32];
        let mut out16 = [0u8; 16];
        let mut out32 = [0u8; 32];
        hkdf_expand_label(&mut out16, &secret, b"test", &[]);
        hkdf_expand_label(&mut out32, &secret, b"test", &[]);
        // First 16 bytes should match since we only do T(1)
        // Actually they will differ because the length field in info differs
        // (16 vs 32 in the first two bytes)
        assert_ne!(&out16[..], &out32[..16]);
    }

    #[test]
    fn key_schedule_round_trip() {
        // Test the full key schedule with a known ECDH secret
        let ecdh = [0x01u8; 32];
        let hs_secret = derive_handshake_secret(&ecdh);
        let transcript = [0x02u8; 32];

        let (client_hs, server_hs) = derive_handshake_traffic_secrets(&hs_secret, &transcript);
        assert_ne!(client_hs, server_hs);
        assert_ne!(client_hs, [0u8; 32]);

        let master = derive_master_secret(&hs_secret);
        assert_ne!(master, [0u8; 32]);

        let (client_app, server_app) = derive_application_traffic_secrets(&master, &transcript);
        assert_ne!(client_app, server_app);
        assert_ne!(client_app, client_hs);
    }

    #[test]
    fn finished_verify_deterministic() {
        let secret = [0x55u8; 32];
        let transcript = [0xaau8; 32];
        let v1 = derive_finished_verify(&secret, &transcript);
        let v2 = derive_finished_verify(&secret, &transcript);
        assert_eq!(v1, v2);
        assert_ne!(v1, [0u8; 32]);
    }

    #[test]
    fn finished_verify_differs_with_different_transcripts() {
        let secret = [0x55u8; 32];
        let t1 = [0xaau8; 32];
        let t2 = [0xbbu8; 32];
        let v1 = derive_finished_verify(&secret, &t1);
        let v2 = derive_finished_verify(&secret, &t2);
        assert_ne!(v1, v2);
    }
}
