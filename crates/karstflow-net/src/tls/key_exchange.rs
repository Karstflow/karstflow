use rand::rngs::OsRng;
/// X25519 Elliptic Curve Diffie-Hellman key exchange for TLS 1.3.
///
/// Implements ephemeral key generation and shared secret computation
/// using Curve25519 (RFC 7748).
use x25519_dalek::{EphemeralSecret as X25519Secret, PublicKey as X25519Public, SharedSecret};

/// An ephemeral X25519 private key.
///
/// Generated from secure randomness and used exactly once per handshake.
pub struct EphemeralSecret {
    inner: X25519Secret,
}

/// An X25519 public key (32 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey {
    bytes: [u8; 32],
}

impl EphemeralSecret {
    /// Generate a new random ephemeral secret.
    pub fn random() -> Self {
        Self {
            inner: X25519Secret::random_from_rng(OsRng),
        }
    }

    /// Derive the corresponding public key.
    pub fn public_key(&self) -> PublicKey {
        let pk = X25519Public::from(&self.inner);
        PublicKey {
            bytes: pk.to_bytes(),
        }
    }
}

impl PublicKey {
    /// Create from raw 32-byte representation.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Get the raw 32-byte representation.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

/// Perform X25519 key exchange: compute the shared secret from our
/// private key and the peer's public key.
///
/// Returns the 32-byte shared secret, or None if the result is all-zeros
/// (indicating a low-order point attack).
pub fn compute_shared_secret(
    our_secret: EphemeralSecret,
    peer_public: &PublicKey,
) -> Option<[u8; 32]> {
    let peer_pk = X25519Public::from(peer_public.bytes);
    let shared: SharedSecret = our_secret.inner.diffie_hellman(&peer_pk);
    let bytes = shared.to_bytes();

    // Reject all-zero shared secret (low-order point)
    if bytes == [0u8; 32] {
        return None;
    }
    Some(bytes)
}

/// Compute shared secret from raw key bytes (for static key pairs).
///
/// Used when the private key is loaded from configuration rather than
/// generated ephemerally.
pub fn compute_shared_secret_from_raw(
    private_key: &[u8; 32],
    peer_public: &[u8; 32],
) -> Option<[u8; 32]> {
    use x25519_dalek::StaticSecret;
    let secret = StaticSecret::from(*private_key);
    let peer = X25519Public::from(*peer_public);
    let shared = secret.diffie_hellman(&peer);
    let bytes = shared.to_bytes();

    if bytes == [0u8; 32] {
        return None;
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_exchange_round_trip() {
        let alice_secret = EphemeralSecret::random();
        let alice_public = alice_secret.public_key();

        let bob_secret = EphemeralSecret::random();
        let bob_public = bob_secret.public_key();

        let alice_shared = compute_shared_secret(alice_secret, &bob_public).unwrap();
        let bob_shared = compute_shared_secret(bob_secret, &alice_public).unwrap();

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn public_key_from_bytes() {
        let secret = EphemeralSecret::random();
        let pk = secret.public_key();
        let bytes = *pk.as_bytes();
        let pk2 = PublicKey::from_bytes(bytes);
        assert_eq!(pk, pk2);
    }

    #[test]
    fn different_keys_different_shared_secrets() {
        let server = EphemeralSecret::random();
        let server_pk = server.public_key();

        let client1 = EphemeralSecret::random();
        let client2 = EphemeralSecret::random();

        let shared1 = compute_shared_secret_from_raw(
            &[1u8; 32], // deterministic for test
            server_pk.as_bytes(),
        );
        let shared2 = compute_shared_secret_from_raw(&[2u8; 32], server_pk.as_bytes());

        // Different private keys should give different shared secrets
        assert_ne!(shared1, shared2);

        // Both should succeed (non-zero)
        let _ = compute_shared_secret(client1, &server_pk).unwrap();
        let _ = compute_shared_secret(client2, &server_pk).unwrap();
    }

    #[test]
    fn raw_key_exchange() {
        let priv_a = [0x77u8; 32];
        let priv_b = [0x88u8; 32];

        use x25519_dalek::StaticSecret;
        let pub_a = X25519Public::from(&StaticSecret::from(priv_a)).to_bytes();
        let pub_b = X25519Public::from(&StaticSecret::from(priv_b)).to_bytes();

        let shared_a = compute_shared_secret_from_raw(&priv_a, &pub_b).unwrap();
        let shared_b = compute_shared_secret_from_raw(&priv_b, &pub_a).unwrap();

        assert_eq!(shared_a, shared_b);
    }

    #[test]
    fn rejects_low_order_point() {
        // All-zeros public key is a low-order point
        let result = compute_shared_secret_from_raw(&[1u8; 32], &[0u8; 32]);
        assert!(result.is_none());
    }
}
