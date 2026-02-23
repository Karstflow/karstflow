//! Wire-compatible repair protocol envelope.
//!
//! The top-level message type exchanged between validators over UDP for
//! block repair. Discriminants 0–6 are legacy (deprecated), 7–11 are
//! modern signed variants. All messages use standard bincode serialization
//! with u32 enum discriminant.

use crate::gossip::wire::WirePong;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

/// Common header for all signed repair requests.
///
/// Contains the Ed25519 signature, sender/recipient pubkeys, a
/// millisecond-precision timestamp, and a u32 nonce that the responder
/// echoes back so the requester can match responses to requests.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireRepairRequestHeader {
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
    pub sender: [u8; 32],
    pub recipient: [u8; 32],
    pub timestamp: u64,
    pub nonce: u32,
}

/// Wire-format repair protocol message.
///
/// Variant discriminants (0..11) match the Solana repair protocol exactly.
/// Legacy variants (0–6) are deprecated and never generated, but can be
/// received from older peers. Modern variants (7–11) carry signed headers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum WireRepairProtocol {
    // Legacy variants — deprecated, receive-only
    LegacyWindowIndex([u8; 32], u64, u64),
    LegacyHighestWindowIndex([u8; 32], u64, u64),
    LegacyOrphan([u8; 32], u64),
    LegacyWindowIndexWithNonce([u8; 32], u64, u64, u32),
    LegacyHighestWindowIndexWithNonce([u8; 32], u64, u64, u32),
    LegacyOrphanWithNonce([u8; 32], u64, u32),
    LegacyAncestorHashes([u8; 32], u64, u32),

    // Modern (signed) variants
    /// Pong response for address verification (reuses gossip Pong format).
    Pong(WirePong),

    /// Request a specific shred by slot and index.
    WindowIndex {
        header: WireRepairRequestHeader,
        slot: u64,
        shred_index: u64,
    },

    /// Request the highest shred index for a slot.
    HighestWindowIndex {
        header: WireRepairRequestHeader,
        slot: u64,
        shred_index: u64,
    },

    /// Request parent slot information for an orphan slot.
    Orphan {
        header: WireRepairRequestHeader,
        slot: u64,
    },

    /// Request ancestor hash chain for a slot.
    AncestorHashes {
        header: WireRepairRequestHeader,
        slot: u64,
    },
}

impl WireRepairProtocol {
    /// Encode this message to bytes using standard bincode serialization.
    pub fn encode(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Decode a message from bytes using standard bincode deserialization.
    pub fn decode(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }

    /// Return the protocol message type discriminant (0..11).
    pub fn discriminant(&self) -> u32 {
        match self {
            Self::LegacyWindowIndex(..) => 0,
            Self::LegacyHighestWindowIndex(..) => 1,
            Self::LegacyOrphan(..) => 2,
            Self::LegacyWindowIndexWithNonce(..) => 3,
            Self::LegacyHighestWindowIndexWithNonce(..) => 4,
            Self::LegacyOrphanWithNonce(..) => 5,
            Self::LegacyAncestorHashes(..) => 6,
            Self::Pong(..) => 7,
            Self::WindowIndex { .. } => 8,
            Self::HighestWindowIndex { .. } => 9,
            Self::Orphan { .. } => 10,
            Self::AncestorHashes { .. } => 11,
        }
    }

    /// Extract the sender pubkey from a modern (signed) variant.
    /// Returns `None` for Pong and legacy variants.
    pub fn sender(&self) -> Option<[u8; 32]> {
        match self {
            Self::WindowIndex { header, .. }
            | Self::HighestWindowIndex { header, .. }
            | Self::Orphan { header, .. }
            | Self::AncestorHashes { header, .. } => Some(header.sender),
            _ => None,
        }
    }

    /// Extract the nonce from a modern (signed) variant.
    /// Returns `None` for Pong and legacy unsigned variants.
    pub fn nonce(&self) -> Option<u32> {
        match self {
            Self::WindowIndex { header, .. }
            | Self::HighestWindowIndex { header, .. }
            | Self::Orphan { header, .. }
            | Self::AncestorHashes { header, .. } => Some(header.nonce),
            Self::LegacyWindowIndexWithNonce(_, _, _, nonce)
            | Self::LegacyHighestWindowIndexWithNonce(_, _, _, nonce)
            | Self::LegacyOrphanWithNonce(_, _, nonce)
            | Self::LegacyAncestorHashes(_, _, nonce) => Some(*nonce),
            _ => None,
        }
    }

    /// Sign this repair request using the provided secret key.
    ///
    /// The signature covers `[discriminant (4 bytes)] || [all bytes after the signature field]`.
    /// Only works on modern signed variants (WindowIndex, HighestWindowIndex, Orphan, AncestorHashes).
    pub fn sign(&mut self, secret_key: &[u8; 32]) {
        // Serialize to get the full byte representation
        let bytes = match bincode::serialize(&self) {
            Ok(b) => b,
            Err(_) => return,
        };

        // bytes layout: [4 discriminant] [64 signature] [remaining...]
        if bytes.len() < 68 {
            return;
        }

        // Signed data = discriminant + everything after the signature
        let mut signed_data = Vec::with_capacity(4 + bytes.len() - 68);
        signed_data.extend_from_slice(&bytes[..4]); // discriminant
        signed_data.extend_from_slice(&bytes[68..]); // fields after signature

        let signature = match paradencer_crypto::sign_message(secret_key, &signed_data) {
            Ok(sig) => sig,
            Err(_) => return,
        };

        // Set the signature in the appropriate header
        match self {
            Self::WindowIndex { header, .. }
            | Self::HighestWindowIndex { header, .. }
            | Self::Orphan { header, .. }
            | Self::AncestorHashes { header, .. } => {
                header.signature = signature;
            }
            _ => {}
        }
    }

    /// Verify the Ed25519 signature on a modern signed repair request.
    ///
    /// Returns `true` for valid signatures, `false` for invalid or unsigned messages.
    pub fn verify(&self) -> bool {
        let (header, _) = match self {
            Self::WindowIndex { header, .. }
            | Self::HighestWindowIndex { header, .. }
            | Self::Orphan { header, .. }
            | Self::AncestorHashes { header, .. } => (header, ()),
            _ => return false,
        };

        // Serialize to reconstruct byte layout
        let bytes = match bincode::serialize(&self) {
            Ok(b) => b,
            Err(_) => return false,
        };

        if bytes.len() < 68 {
            return false;
        }

        // Signed data = discriminant + everything after the signature
        let mut signed_data = Vec::with_capacity(4 + bytes.len() - 68);
        signed_data.extend_from_slice(&bytes[..4]);
        signed_data.extend_from_slice(&bytes[68..]);

        matches!(
            paradencer_crypto::verify_signature(&header.sender, &signed_data, &header.signature),
            Ok(paradencer_crypto::VerificationResult::Success)
        )
    }

    /// Check whether the timestamp is within the allowed skew window.
    pub fn is_timestamp_valid(&self, current_time_ms: u64) -> bool {
        let header = match self {
            Self::WindowIndex { header, .. }
            | Self::HighestWindowIndex { header, .. }
            | Self::Orphan { header, .. }
            | Self::AncestorHashes { header, .. } => header,
            _ => return true, // Legacy/Pong don't have timestamps
        };

        let skew_ms = paradencer_constants::repair::REPAIR_TIMESTAMP_SKEW_SECS * 1000;
        let lower = current_time_ms.saturating_sub(skew_ms);
        let upper = current_time_ms.saturating_add(skew_ms);
        header.timestamp >= lower && header.timestamp <= upper
    }
}

impl WireRepairRequestHeader {
    /// Create a new header with zeroed signature (to be signed later).
    pub fn new(sender: [u8; 32], recipient: [u8; 32], timestamp: u64, nonce: u32) -> Self {
        Self {
            signature: [0u8; 64],
            sender,
            recipient,
            timestamp,
            nonce,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gossip::wire::WirePing;

    #[test]
    fn discriminants_are_correct() {
        let pubkey = [1u8; 32];
        let header = WireRepairRequestHeader::new(pubkey, [2u8; 32], 1000, 42);

        assert_eq!(
            WireRepairProtocol::LegacyWindowIndex(pubkey, 100, 5).discriminant(),
            0
        );
        assert_eq!(
            WireRepairProtocol::LegacyHighestWindowIndex(pubkey, 100, 5).discriminant(),
            1
        );
        assert_eq!(
            WireRepairProtocol::LegacyOrphan(pubkey, 100).discriminant(),
            2
        );
        assert_eq!(
            WireRepairProtocol::LegacyWindowIndexWithNonce(pubkey, 100, 5, 1).discriminant(),
            3
        );
        assert_eq!(
            WireRepairProtocol::LegacyHighestWindowIndexWithNonce(pubkey, 100, 5, 1).discriminant(),
            4
        );
        assert_eq!(
            WireRepairProtocol::LegacyOrphanWithNonce(pubkey, 100, 1).discriminant(),
            5
        );
        assert_eq!(
            WireRepairProtocol::LegacyAncestorHashes(pubkey, 100, 1).discriminant(),
            6
        );

        let (secret, pk) = paradencer_crypto::generate_keypair();
        let ping = WirePing::new(pk, [7u8; 32], &secret);
        let pong = WirePong::from_ping(&ping, pk, &secret);
        assert_eq!(WireRepairProtocol::Pong(pong).discriminant(), 7);

        assert_eq!(
            WireRepairProtocol::WindowIndex {
                header: header.clone(),
                slot: 100,
                shred_index: 5,
            }
            .discriminant(),
            8
        );
        assert_eq!(
            WireRepairProtocol::HighestWindowIndex {
                header: header.clone(),
                slot: 100,
                shred_index: 0,
            }
            .discriminant(),
            9
        );
        assert_eq!(
            WireRepairProtocol::Orphan {
                header: header.clone(),
                slot: 100,
            }
            .discriminant(),
            10
        );
        assert_eq!(
            WireRepairProtocol::AncestorHashes { header, slot: 100 }.discriminant(),
            11
        );
    }

    #[test]
    fn window_index_round_trip() {
        let header = WireRepairRequestHeader::new([1u8; 32], [2u8; 32], 1000, 42);
        let msg = WireRepairProtocol::WindowIndex {
            header,
            slot: 12345,
            shred_index: 67,
        };

        let bytes = msg.encode().unwrap();
        let decoded = WireRepairProtocol::decode(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn highest_window_index_round_trip() {
        let header = WireRepairRequestHeader::new([3u8; 32], [4u8; 32], 2000, 99);
        let msg = WireRepairProtocol::HighestWindowIndex {
            header,
            slot: 999,
            shred_index: 0,
        };

        let bytes = msg.encode().unwrap();
        let decoded = WireRepairProtocol::decode(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn orphan_round_trip() {
        let header = WireRepairRequestHeader::new([5u8; 32], [6u8; 32], 3000, 7);
        let msg = WireRepairProtocol::Orphan {
            header,
            slot: 50000,
        };

        let bytes = msg.encode().unwrap();
        let decoded = WireRepairProtocol::decode(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn ancestor_hashes_round_trip() {
        let header = WireRepairRequestHeader::new([7u8; 32], [8u8; 32], 4000, 13);
        let msg = WireRepairProtocol::AncestorHashes {
            header,
            slot: 77777,
        };

        let bytes = msg.encode().unwrap();
        let decoded = WireRepairProtocol::decode(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn pong_round_trip() {
        let (alice_secret, alice_pubkey) = paradencer_crypto::generate_keypair();
        let (bob_secret, bob_pubkey) = paradencer_crypto::generate_keypair();

        let ping = WirePing::new(alice_pubkey, [42u8; 32], &alice_secret);
        let pong = WirePong::from_ping(&ping, bob_pubkey, &bob_secret);
        let msg = WireRepairProtocol::Pong(pong);

        assert_eq!(msg.discriminant(), 7);
        let bytes = msg.encode().unwrap();
        let decoded = WireRepairProtocol::decode(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn legacy_variants_round_trip() {
        let pubkey = [0xABu8; 32];

        let variants = [
            WireRepairProtocol::LegacyWindowIndex(pubkey, 100, 5),
            WireRepairProtocol::LegacyHighestWindowIndex(pubkey, 200, 10),
            WireRepairProtocol::LegacyOrphan(pubkey, 300),
            WireRepairProtocol::LegacyWindowIndexWithNonce(pubkey, 400, 15, 1),
            WireRepairProtocol::LegacyHighestWindowIndexWithNonce(pubkey, 500, 20, 2),
            WireRepairProtocol::LegacyOrphanWithNonce(pubkey, 600, 3),
            WireRepairProtocol::LegacyAncestorHashes(pubkey, 700, 4),
        ];

        for (i, variant) in variants.iter().enumerate() {
            let bytes = variant.encode().unwrap();
            let decoded = WireRepairProtocol::decode(&bytes).unwrap();
            assert_eq!(&decoded, variant, "legacy variant {} failed round-trip", i);
        }
    }

    #[test]
    fn sign_and_verify_window_index() {
        let (secret, pubkey) = paradencer_crypto::generate_keypair();
        let (_, recipient) = paradencer_crypto::generate_keypair();

        let header = WireRepairRequestHeader::new(pubkey, recipient, 1_700_000_000_000, 42);
        let mut msg = WireRepairProtocol::WindowIndex {
            header,
            slot: 12345,
            shred_index: 67,
        };

        msg.sign(&secret);
        assert!(msg.verify(), "valid signature should verify");
    }

    #[test]
    fn sign_and_verify_orphan() {
        let (secret, pubkey) = paradencer_crypto::generate_keypair();
        let (_, recipient) = paradencer_crypto::generate_keypair();

        let header = WireRepairRequestHeader::new(pubkey, recipient, 1_700_000_000_000, 99);
        let mut msg = WireRepairProtocol::Orphan {
            header,
            slot: 50000,
        };

        msg.sign(&secret);
        assert!(msg.verify());
    }

    #[test]
    fn sign_and_verify_ancestor_hashes() {
        let (secret, pubkey) = paradencer_crypto::generate_keypair();
        let (_, recipient) = paradencer_crypto::generate_keypair();

        let header = WireRepairRequestHeader::new(pubkey, recipient, 1_700_000_000_000, 7);
        let mut msg = WireRepairProtocol::AncestorHashes {
            header,
            slot: 99999,
        };

        msg.sign(&secret);
        assert!(msg.verify());
    }

    #[test]
    fn tampered_slot_fails_verification() {
        let (secret, pubkey) = paradencer_crypto::generate_keypair();
        let (_, recipient) = paradencer_crypto::generate_keypair();

        let header = WireRepairRequestHeader::new(pubkey, recipient, 1_700_000_000_000, 42);
        let mut msg = WireRepairProtocol::WindowIndex {
            header,
            slot: 12345,
            shred_index: 67,
        };

        msg.sign(&secret);

        // Tamper with the slot
        if let WireRepairProtocol::WindowIndex { ref mut slot, .. } = msg {
            *slot = 99999;
        }

        assert!(!msg.verify(), "tampered message should fail verification");
    }

    #[test]
    fn tampered_sender_fails_verification() {
        let (secret, pubkey) = paradencer_crypto::generate_keypair();
        let (_, recipient) = paradencer_crypto::generate_keypair();

        let header = WireRepairRequestHeader::new(pubkey, recipient, 1_700_000_000_000, 42);
        let mut msg = WireRepairProtocol::Orphan {
            header,
            slot: 50000,
        };

        msg.sign(&secret);

        // Tamper with the sender
        if let WireRepairProtocol::Orphan { ref mut header, .. } = msg {
            header.sender = [0xFFu8; 32];
        }

        assert!(!msg.verify());
    }

    #[test]
    fn unsigned_message_fails_verification() {
        let header = WireRepairRequestHeader::new([1u8; 32], [2u8; 32], 1000, 42);
        let msg = WireRepairProtocol::WindowIndex {
            header,
            slot: 100,
            shred_index: 5,
        };

        assert!(!msg.verify(), "unsigned message should not verify");
    }

    #[test]
    fn legacy_and_pong_verification_returns_false() {
        let pubkey = [1u8; 32];
        assert!(!WireRepairProtocol::LegacyOrphan(pubkey, 100).verify());
        assert!(!WireRepairProtocol::LegacyWindowIndexWithNonce(pubkey, 100, 5, 1).verify());
    }

    #[test]
    fn sender_extraction() {
        let sender = [0xABu8; 32];
        let header = WireRepairRequestHeader::new(sender, [2u8; 32], 1000, 42);

        assert_eq!(
            WireRepairProtocol::WindowIndex {
                header: header.clone(),
                slot: 100,
                shred_index: 5,
            }
            .sender(),
            Some(sender)
        );

        assert_eq!(
            WireRepairProtocol::LegacyOrphan([3u8; 32], 100).sender(),
            None
        );
    }

    #[test]
    fn nonce_extraction() {
        let header = WireRepairRequestHeader::new([1u8; 32], [2u8; 32], 1000, 42);

        assert_eq!(
            WireRepairProtocol::WindowIndex {
                header,
                slot: 100,
                shred_index: 5,
            }
            .nonce(),
            Some(42)
        );

        assert_eq!(
            WireRepairProtocol::LegacyWindowIndexWithNonce([1u8; 32], 100, 5, 99).nonce(),
            Some(99)
        );

        assert_eq!(
            WireRepairProtocol::LegacyOrphan([1u8; 32], 100).nonce(),
            None
        );
    }

    #[test]
    fn timestamp_validation() {
        let (secret, pubkey) = paradencer_crypto::generate_keypair();
        let (_, recipient) = paradencer_crypto::generate_keypair();
        let now_ms = 1_700_000_000_000u64;

        // Timestamp within window
        let header = WireRepairRequestHeader::new(pubkey, recipient, now_ms, 1);
        let mut msg = WireRepairProtocol::WindowIndex {
            header,
            slot: 100,
            shred_index: 5,
        };
        msg.sign(&secret);
        assert!(msg.is_timestamp_valid(now_ms));

        // Timestamp 5 minutes in the past — still valid
        let header = WireRepairRequestHeader::new(pubkey, recipient, now_ms - 300_000, 2);
        let mut msg = WireRepairProtocol::WindowIndex {
            header,
            slot: 100,
            shred_index: 5,
        };
        msg.sign(&secret);
        assert!(msg.is_timestamp_valid(now_ms));

        // Timestamp 11 minutes in the past — invalid
        let header = WireRepairRequestHeader::new(pubkey, recipient, now_ms - 660_000, 3);
        let mut msg = WireRepairProtocol::WindowIndex {
            header,
            slot: 100,
            shred_index: 5,
        };
        msg.sign(&secret);
        assert!(!msg.is_timestamp_valid(now_ms));
    }

    #[test]
    fn window_index_fits_in_mtu() {
        let (secret, pubkey) = paradencer_crypto::generate_keypair();
        let (_, recipient) = paradencer_crypto::generate_keypair();
        let header = WireRepairRequestHeader::new(pubkey, recipient, 1_700_000_000_000, 42);
        let mut msg = WireRepairProtocol::WindowIndex {
            header,
            slot: u64::MAX,
            shred_index: u64::MAX,
        };
        msg.sign(&secret);

        let bytes = msg.encode().unwrap();
        assert!(
            bytes.len() <= paradencer_constants::gossip::GOSSIP_MTU,
            "WindowIndex {} bytes exceeds MTU {}",
            bytes.len(),
            paradencer_constants::gossip::GOSSIP_MTU,
        );
    }

    #[test]
    fn invalid_bytes_return_error() {
        let result = WireRepairProtocol::decode(&[0xFF, 0xFF, 0xFF, 0xFF]);
        assert!(result.is_err());
    }
}
