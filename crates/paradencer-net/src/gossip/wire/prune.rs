//! Wire-compatible PruneData type for the gossip protocol.
//!
//! When a node receives push messages from a peer on behalf of an origin
//! that it already receives directly (or via a shorter path), it sends a
//! PruneMessage telling that peer to stop forwarding values from those origins.

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

/// Wire-format prune message payload.
///
/// The signature covers the bincode serialization of
/// `(pubkey, prunes, destination, wallclock)` — i.e. all fields except
/// the signature itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WirePruneData {
    /// Pubkey of the node sending the prune request.
    pub pubkey: [u8; 32],
    /// Origin pubkeys to stop forwarding.
    pub prunes: Vec<[u8; 32]>,
    /// Ed25519 signature over the signable data.
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
    /// Intended recipient of this prune message.
    pub destination: [u8; 32],
    /// Wallclock timestamp in milliseconds.
    pub wallclock: u64,
}

impl WirePruneData {
    /// Create a new signed prune message.
    pub fn new(
        pubkey: [u8; 32],
        prunes: Vec<[u8; 32]>,
        destination: [u8; 32],
        wallclock: u64,
        secret_key: &[u8; 32],
    ) -> Self {
        let mut data = Self {
            pubkey,
            prunes,
            signature: [0u8; 64],
            destination,
            wallclock,
        };
        data.sign(secret_key);
        data
    }

    /// Compute the signable bytes: bincode serialization of all fields
    /// except the signature.
    pub fn signable_bytes(&self) -> Vec<u8> {
        #[derive(Serialize)]
        struct SignData<'a> {
            pubkey: &'a [u8; 32],
            prunes: &'a Vec<[u8; 32]>,
            destination: &'a [u8; 32],
            wallclock: u64,
        }
        let sign_data = SignData {
            pubkey: &self.pubkey,
            prunes: &self.prunes,
            destination: &self.destination,
            wallclock: self.wallclock,
        };
        bincode::serialize(&sign_data).expect("PruneData signable serialization should not fail")
    }

    /// Sign the prune data using an Ed25519 secret key.
    fn sign(&mut self, secret_key: &[u8; 32]) {
        let msg = self.signable_bytes();
        self.signature = paradencer_crypto::sign_message(secret_key, &msg)
            .expect("Ed25519 signing should never fail with a valid key");
    }

    /// Verify the Ed25519 signature against the pubkey.
    pub fn verify(&self) -> bool {
        let msg = self.signable_bytes();
        matches!(
            paradencer_crypto::verify_signature(&self.pubkey, &msg, &self.signature),
            Ok(paradencer_crypto::VerificationResult::Success)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prune_sign_verify() {
        let (secret, pubkey) = paradencer_crypto::generate_keypair();
        let (_, dest) = paradencer_crypto::generate_keypair();
        let prunes = vec![[1u8; 32], [2u8; 32], [3u8; 32]];

        let prune = WirePruneData::new(pubkey, prunes, dest, 1_700_000_000_000, &secret);
        assert!(prune.verify());
    }

    #[test]
    fn prune_verify_fails_after_tamper() {
        let (secret, pubkey) = paradencer_crypto::generate_keypair();
        let (_, dest) = paradencer_crypto::generate_keypair();
        let prunes = vec![[1u8; 32], [2u8; 32]];

        let mut prune = WirePruneData::new(pubkey, prunes, dest, 1_700_000_000_000, &secret);
        prune.wallclock = 999; // tamper
        assert!(!prune.verify());
    }

    #[test]
    fn prune_verify_fails_with_wrong_key() {
        let (secret, pubkey) = paradencer_crypto::generate_keypair();
        let (_, dest) = paradencer_crypto::generate_keypair();

        let mut prune =
            WirePruneData::new(pubkey, vec![[5u8; 32]], dest, 1_700_000_000_000, &secret);
        prune.pubkey = [0xFFu8; 32]; // wrong key
        assert!(!prune.verify());
    }

    #[test]
    fn prune_bincode_round_trip() {
        let (secret, pubkey) = paradencer_crypto::generate_keypair();
        let (_, dest) = paradencer_crypto::generate_keypair();
        let prunes = vec![[10u8; 32], [20u8; 32]];

        let prune = WirePruneData::new(pubkey, prunes, dest, 42_000, &secret);

        let bytes = bincode::serialize(&prune).unwrap();
        let decoded: WirePruneData = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded, prune);
        assert!(decoded.verify());
    }

    #[test]
    fn prune_empty_prunes_list() {
        let (secret, pubkey) = paradencer_crypto::generate_keypair();
        let (_, dest) = paradencer_crypto::generate_keypair();

        let prune = WirePruneData::new(pubkey, vec![], dest, 1_000, &secret);
        assert!(prune.verify());

        let bytes = bincode::serialize(&prune).unwrap();
        let decoded: WirePruneData = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded, prune);
    }
}
