//! Wire-compatible CrdsValue type for the gossip protocol.
//!
//! Solana's CrdsValue has the layout `{ signature: [u8;64], data: CrdsData }`,
//! where the origin pubkey and wallclock are embedded inside each CrdsData
//! variant. This module provides bidirectional conversion between this wire
//! format and the internal representation where origin/wallclock are in a
//! shared envelope.

use super::crds_data::WireCrdsData;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

/// Wire-format CRDS value: signature followed by typed data.
///
/// The signature covers `bincode::serialize(&self.data)`, which is the
/// standard signing convention used by Solana validators.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireCrdsValue {
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
    pub data: WireCrdsData,
}

impl WireCrdsValue {
    /// Extract the origin pubkey from the inner data.
    pub fn origin(&self) -> &[u8; 32] {
        self.data.origin()
    }

    /// Extract the wallclock in milliseconds from the inner data.
    pub fn wallclock_ms(&self) -> u64 {
        self.data.wallclock_ms()
    }

    /// Compute the signable bytes: `bincode::serialize(&self.data)`.
    ///
    /// This is the byte sequence covered by the Ed25519 signature,
    /// matching the Solana convention.
    pub fn signable_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self.data).expect("CrdsData serialization should not fail")
    }

    /// Sign this value using an Ed25519 secret key (32-byte seed).
    pub fn sign(&mut self, secret_key: &[u8; 32]) {
        let msg = self.signable_bytes();
        self.signature = karstflow_crypto::sign_message(secret_key, &msg)
            .expect("Ed25519 signing should never fail with a valid key");
    }

    /// Verify the Ed25519 signature against the origin pubkey.
    pub fn verify(&self) -> bool {
        let msg = self.signable_bytes();
        let origin = self.data.origin();
        matches!(
            karstflow_crypto::verify_signature(origin, &msg, &self.signature),
            Ok(karstflow_crypto::VerificationResult::Success)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::crds_data::*;
    use super::*;

    fn make_wire_node_instance(secret: &[u8; 32], pubkey: &[u8; 32]) -> WireCrdsValue {
        let data = WireCrdsData::NodeInstance(WireNodeInstance {
            from: *pubkey,
            wallclock: 1_700_000_000_000,
            timestamp: 1_700_000_000,
            token: 42,
        });
        let mut value = WireCrdsValue {
            signature: [0u8; 64],
            data,
        };
        value.sign(secret);
        value
    }

    #[test]
    fn sign_and_verify() {
        let (secret, pubkey) = karstflow_crypto::generate_keypair();
        let value = make_wire_node_instance(&secret, &pubkey);
        assert!(value.verify());
    }

    #[test]
    fn verify_fails_with_wrong_key() {
        let (secret, pubkey) = karstflow_crypto::generate_keypair();
        let mut value = make_wire_node_instance(&secret, &pubkey);

        // Tamper with the origin
        if let WireCrdsData::NodeInstance(ref mut ni) = value.data {
            ni.from = [0xFFu8; 32];
        }
        assert!(!value.verify());
    }

    #[test]
    fn verify_fails_after_data_tamper() {
        let (secret, pubkey) = karstflow_crypto::generate_keypair();
        let mut value = make_wire_node_instance(&secret, &pubkey);

        // Tamper with the token
        if let WireCrdsData::NodeInstance(ref mut ni) = value.data {
            ni.token = 999;
        }
        assert!(!value.verify());
    }

    #[test]
    fn bincode_round_trip() {
        let (secret, pubkey) = karstflow_crypto::generate_keypair();
        let value = make_wire_node_instance(&secret, &pubkey);

        let bytes = bincode::serialize(&value).unwrap();
        let decoded: WireCrdsValue = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded, value);
        assert!(decoded.verify());
    }

    #[test]
    fn origin_and_wallclock() {
        let pubkey = [42u8; 32];
        let value = WireCrdsValue {
            signature: [0u8; 64],
            data: WireCrdsData::NodeInstance(WireNodeInstance {
                from: pubkey,
                wallclock: 12345,
                timestamp: 0,
                token: 0,
            }),
        };
        assert_eq!(value.origin(), &pubkey);
        assert_eq!(value.wallclock_ms(), 12345);
    }
}
