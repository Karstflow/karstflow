//! Wire-compatible gossip protocol envelope.
//!
//! The top-level message type exchanged between validators over UDP.
//! Each variant maps to a Solana gossip protocol message with standard
//! bincode serialization (u32 enum discriminant, no custom framing).

use super::bloom::WireCrdsFilter;
use super::crds_value::WireCrdsValue;
use super::ping_pong::{WirePing, WirePong};
use super::prune::WirePruneData;
use serde::{Deserialize, Serialize};

/// Wire-format gossip protocol message.
///
/// Variant discriminants (0..5) match the Solana gossip protocol exactly.
/// All messages are serialized with standard bincode (u32 discriminant prefix).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum WireProtocol {
    /// Pull request: bloom filter + caller's own CRDS value for contact exchange.
    PullRequest(WireCrdsFilter, WireCrdsValue),

    /// Pull response: responder pubkey + matching CRDS values.
    PullResponse([u8; 32], Vec<WireCrdsValue>),

    /// Push message: sender pubkey + new CRDS values to propagate.
    PushMessage([u8; 32], Vec<WireCrdsValue>),

    /// Prune message: sender pubkey + prune data telling peer to stop
    /// forwarding values from specific origins.
    PruneMessage([u8; 32], WirePruneData),

    /// Ping: liveness probe with random token.
    PingMessage(WirePing),

    /// Pong: response to ping with hashed token.
    PongMessage(WirePong),
}

impl WireProtocol {
    /// Encode this message to bytes using standard bincode serialization.
    pub fn encode(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Decode a message from bytes using standard bincode deserialization.
    pub fn decode(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }

    /// Return the protocol message type discriminant (0..5).
    pub fn discriminant(&self) -> u32 {
        match self {
            Self::PullRequest(..) => 0,
            Self::PullResponse(..) => 1,
            Self::PushMessage(..) => 2,
            Self::PruneMessage(..) => 3,
            Self::PingMessage(..) => 4,
            Self::PongMessage(..) => 5,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::bloom::{WireBloom, WireCrdsFilter};
    use super::super::crds_data::{WireCrdsData, WireNodeInstance};
    use super::*;
    use bv::BitVec;

    fn make_signed_node_instance() -> WireCrdsValue {
        let (secret, pubkey) = paradencer_crypto::generate_keypair();
        let data = WireCrdsData::NodeInstance(WireNodeInstance {
            from: pubkey,
            wallclock: 1_700_000_000_000,
            timestamp: 1_700_000_000,
            token: 42,
        });
        let mut value = WireCrdsValue {
            signature: [0u8; 64],
            data,
        };
        value.sign(&secret);
        value
    }

    fn make_crds_filter() -> WireCrdsFilter {
        WireCrdsFilter {
            filter: WireBloom {
                keys: vec![111, 222],
                bits: BitVec::new_fill(false, 64),
                num_bits_set: 0,
                _phantom: std::marker::PhantomData,
            },
            mask: 0xFF,
            mask_bits: 8,
        }
    }

    #[test]
    fn pull_request_round_trip() {
        let filter = make_crds_filter();
        let value = make_signed_node_instance();
        let msg = WireProtocol::PullRequest(filter, value);

        assert_eq!(msg.discriminant(), 0);
        let bytes = msg.encode().unwrap();
        let decoded = WireProtocol::decode(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn pull_response_round_trip() {
        let (_, pubkey) = paradencer_crypto::generate_keypair();
        let values = vec![make_signed_node_instance(), make_signed_node_instance()];
        let msg = WireProtocol::PullResponse(pubkey, values);

        assert_eq!(msg.discriminant(), 1);
        let bytes = msg.encode().unwrap();
        let decoded = WireProtocol::decode(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn push_message_round_trip() {
        let (_, pubkey) = paradencer_crypto::generate_keypair();
        let values = vec![make_signed_node_instance()];
        let msg = WireProtocol::PushMessage(pubkey, values);

        assert_eq!(msg.discriminant(), 2);
        let bytes = msg.encode().unwrap();
        let decoded = WireProtocol::decode(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn prune_message_round_trip() {
        let (secret, pubkey) = paradencer_crypto::generate_keypair();
        let (_, dest) = paradencer_crypto::generate_keypair();
        let prune = WirePruneData::new(pubkey, vec![[1u8; 32], [2u8; 32]], dest, 42_000, &secret);
        let msg = WireProtocol::PruneMessage(pubkey, prune);

        assert_eq!(msg.discriminant(), 3);
        let bytes = msg.encode().unwrap();
        let decoded = WireProtocol::decode(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn ping_message_round_trip() {
        let (secret, pubkey) = paradencer_crypto::generate_keypair();
        let ping = WirePing::new(pubkey, [7u8; 32], &secret);
        let msg = WireProtocol::PingMessage(ping);

        assert_eq!(msg.discriminant(), 4);
        let bytes = msg.encode().unwrap();
        let decoded = WireProtocol::decode(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn pong_message_round_trip() {
        let (alice_secret, alice_pubkey) = paradencer_crypto::generate_keypair();
        let (bob_secret, bob_pubkey) = paradencer_crypto::generate_keypair();

        let ping = WirePing::new(alice_pubkey, [8u8; 32], &alice_secret);
        let pong = WirePong::from_ping(&ping, bob_pubkey, &bob_secret);
        let msg = WireProtocol::PongMessage(pong);

        assert_eq!(msg.discriminant(), 5);
        let bytes = msg.encode().unwrap();
        let decoded = WireProtocol::decode(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn empty_pull_response() {
        let (_, pubkey) = paradencer_crypto::generate_keypair();
        let msg = WireProtocol::PullResponse(pubkey, vec![]);

        let bytes = msg.encode().unwrap();
        let decoded = WireProtocol::decode(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn push_with_multiple_value_types() {
        let (secret, pubkey) = paradencer_crypto::generate_keypair();

        // NodeInstance
        let mut v1 = WireCrdsValue {
            signature: [0u8; 64],
            data: WireCrdsData::NodeInstance(WireNodeInstance {
                from: pubkey,
                wallclock: 1_000,
                timestamp: 100,
                token: 1,
            }),
        };
        v1.sign(&secret);

        // SnapshotHashes
        let mut v2 = WireCrdsValue {
            signature: [0u8; 64],
            data: WireCrdsData::SnapshotHashes(super::super::crds_data::WireSnapshotHashes {
                from: pubkey,
                full: (100, [0xABu8; 32]),
                incremental: vec![(200, [0xCDu8; 32])],
                wallclock: 2_000,
            }),
        };
        v2.sign(&secret);

        let msg = WireProtocol::PushMessage(pubkey, vec![v1, v2]);
        let bytes = msg.encode().unwrap();
        let decoded = WireProtocol::decode(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn discriminants_are_correct() {
        let filter = make_crds_filter();
        let value = make_signed_node_instance();
        let (secret, pubkey) = paradencer_crypto::generate_keypair();
        let (_, dest) = paradencer_crypto::generate_keypair();

        assert_eq!(
            WireProtocol::PullRequest(filter, value.clone()).discriminant(),
            0
        );
        assert_eq!(WireProtocol::PullResponse(pubkey, vec![]).discriminant(), 1);
        assert_eq!(
            WireProtocol::PushMessage(pubkey, vec![value]).discriminant(),
            2
        );
        assert_eq!(
            WireProtocol::PruneMessage(
                pubkey,
                WirePruneData::new(pubkey, vec![], dest, 0, &secret)
            )
            .discriminant(),
            3
        );
        assert_eq!(
            WireProtocol::PingMessage(WirePing::new(pubkey, [0u8; 32], &secret)).discriminant(),
            4
        );
        let ping = WirePing::new(pubkey, [0u8; 32], &secret);
        assert_eq!(
            WireProtocol::PongMessage(WirePong::from_ping(&ping, dest, &secret)).discriminant(),
            5
        );
    }

    #[test]
    fn ping_message_fits_in_mtu() {
        let (secret, pubkey) = paradencer_crypto::generate_keypair();
        let ping = WirePing::new(pubkey, [42u8; 32], &secret);
        let msg = WireProtocol::PingMessage(ping);
        let bytes = msg.encode().unwrap();
        assert!(
            bytes.len() <= paradencer_constants::gossip::GOSSIP_MTU,
            "ping message {} bytes exceeds MTU {}",
            bytes.len(),
            paradencer_constants::gossip::GOSSIP_MTU,
        );
    }

    #[test]
    fn pong_message_fits_in_mtu() {
        let (alice_secret, alice_pubkey) = paradencer_crypto::generate_keypair();
        let (bob_secret, bob_pubkey) = paradencer_crypto::generate_keypair();

        let ping = WirePing::new(alice_pubkey, [42u8; 32], &alice_secret);
        let pong = WirePong::from_ping(&ping, bob_pubkey, &bob_secret);
        let msg = WireProtocol::PongMessage(pong);
        let bytes = msg.encode().unwrap();
        assert!(
            bytes.len() <= paradencer_constants::gossip::GOSSIP_MTU,
            "pong message {} bytes exceeds MTU {}",
            bytes.len(),
            paradencer_constants::gossip::GOSSIP_MTU,
        );
    }

    #[test]
    fn invalid_bytes_return_error() {
        let result = WireProtocol::decode(&[0xFF, 0xFF, 0xFF, 0xFF]);
        assert!(result.is_err());
    }
}
