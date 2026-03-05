//! Wire-compatible Ping/Pong types for the gossip protocol.
//!
//! The ping/pong mechanism is used for liveness probing between validators.
//! A Ping contains a random 32-byte token signed by the sender. The Pong
//! responds with `SHA256("SOLANA_PING_PONG" || token)`, also signed.

use karstflow_constants::gossip;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use sha2::{Digest, Sha256};

/// Wire-format Ping message.
///
/// Sent to verify that a peer is reachable and holds the claimed keypair.
/// The recipient must respond with a Pong containing the hash of this token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WirePing {
    pub from: [u8; 32],
    pub token: [u8; 32],
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

/// Wire-format Pong message.
///
/// Response to a Ping. The hash field is `SHA256("SOLANA_PING_PONG" || ping.token)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WirePong {
    pub from: [u8; 32],
    pub hash: [u8; 32],
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

impl WirePing {
    /// Create a new Ping with the given token, signed by the sender.
    pub fn new(from: [u8; 32], token: [u8; 32], secret_key: &[u8; 32]) -> Self {
        let mut ping = Self {
            from,
            token,
            signature: [0u8; 64],
        };
        ping.sign(secret_key);
        ping
    }

    /// Sign the ping token.
    fn sign(&mut self, secret_key: &[u8; 32]) {
        self.signature = karstflow_crypto::sign_message(secret_key, &self.token)
            .expect("Ed25519 signing should never fail with a valid key");
    }

    /// Verify the signature over the token.
    pub fn verify(&self) -> bool {
        matches!(
            karstflow_crypto::verify_signature(&self.from, &self.token, &self.signature),
            Ok(karstflow_crypto::VerificationResult::Success)
        )
    }
}

impl WirePong {
    /// Create a Pong in response to a Ping, signed by the responder.
    pub fn from_ping(ping: &WirePing, from: [u8; 32], secret_key: &[u8; 32]) -> Self {
        let hash = Self::compute_hash(&ping.token);
        let mut pong = Self {
            from,
            hash,
            signature: [0u8; 64],
        };
        pong.sign(secret_key);
        pong
    }

    /// Compute the pong hash: `SHA256("SOLANA_PING_PONG" || token)`.
    pub fn compute_hash(token: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(gossip::PING_PONG_HASH_PREFIX);
        hasher.update(token);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Sign the pong hash.
    fn sign(&mut self, secret_key: &[u8; 32]) {
        self.signature = karstflow_crypto::sign_message(secret_key, &self.hash)
            .expect("Ed25519 signing should never fail with a valid key");
    }

    /// Verify the signature over the hash.
    pub fn verify(&self) -> bool {
        matches!(
            karstflow_crypto::verify_signature(&self.from, &self.hash, &self.signature),
            Ok(karstflow_crypto::VerificationResult::Success)
        )
    }

    /// Verify that this pong's hash matches the expected ping token.
    pub fn matches_ping(&self, ping_token: &[u8; 32]) -> bool {
        let expected = Self::compute_hash(ping_token);
        self.hash == expected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_sign_verify() {
        let (secret, pubkey) = karstflow_crypto::generate_keypair();
        let token = [42u8; 32];
        let ping = WirePing::new(pubkey, token, &secret);
        assert!(ping.verify());
    }

    #[test]
    fn ping_verify_fails_with_wrong_key() {
        let (secret, pubkey) = karstflow_crypto::generate_keypair();
        let token = [42u8; 32];
        let mut ping = WirePing::new(pubkey, token, &secret);
        ping.from = [0xFFu8; 32]; // tamper origin
        assert!(!ping.verify());
    }

    #[test]
    fn pong_from_ping() {
        let (alice_secret, alice_pubkey) = karstflow_crypto::generate_keypair();
        let (bob_secret, bob_pubkey) = karstflow_crypto::generate_keypair();

        let token = [7u8; 32];
        let ping = WirePing::new(alice_pubkey, token, &alice_secret);
        let pong = WirePong::from_ping(&ping, bob_pubkey, &bob_secret);

        assert!(ping.verify());
        assert!(pong.verify());
        assert!(pong.matches_ping(&ping.token));
    }

    #[test]
    fn pong_does_not_match_wrong_token() {
        let (alice_secret, alice_pubkey) = karstflow_crypto::generate_keypair();
        let (bob_secret, bob_pubkey) = karstflow_crypto::generate_keypair();

        let token = [7u8; 32];
        let ping = WirePing::new(alice_pubkey, token, &alice_secret);
        let pong = WirePong::from_ping(&ping, bob_pubkey, &bob_secret);

        let wrong_token = [99u8; 32];
        assert!(!pong.matches_ping(&wrong_token));
    }

    #[test]
    fn ping_bincode_round_trip() {
        let (secret, pubkey) = karstflow_crypto::generate_keypair();
        let ping = WirePing::new(pubkey, [1u8; 32], &secret);

        let bytes = bincode::serialize(&ping).unwrap();
        let decoded: WirePing = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded, ping);
        assert!(decoded.verify());
    }

    #[test]
    fn pong_bincode_round_trip() {
        let (alice_secret, alice_pubkey) = karstflow_crypto::generate_keypair();
        let (bob_secret, bob_pubkey) = karstflow_crypto::generate_keypair();

        let ping = WirePing::new(alice_pubkey, [2u8; 32], &alice_secret);
        let pong = WirePong::from_ping(&ping, bob_pubkey, &bob_secret);

        let bytes = bincode::serialize(&pong).unwrap();
        let decoded: WirePong = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded, pong);
        assert!(decoded.verify());
        assert!(decoded.matches_ping(&ping.token));
    }

    #[test]
    fn pong_hash_is_deterministic() {
        let token = [42u8; 32];
        let h1 = WirePong::compute_hash(&token);
        let h2 = WirePong::compute_hash(&token);
        assert_eq!(h1, h2);
    }

    #[test]
    fn pong_hash_differs_for_different_tokens() {
        let h1 = WirePong::compute_hash(&[1u8; 32]);
        let h2 = WirePong::compute_hash(&[2u8; 32]);
        assert_ne!(h1, h2);
    }
}
