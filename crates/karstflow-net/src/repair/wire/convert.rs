//! Bidirectional conversion between internal repair types and wire format.
//!
//! This module bridges the gap between the internal `RepairRequest`/`RepairResponse`
//! types used by the coordinator/forest/policy layers and the Solana-compatible
//! `WireRepairProtocol` types used on the network.

use super::protocol::{WireRepairProtocol, WireRepairRequestHeader};
use super::response::{decode_shred_response, encode_shred_response};
use crate::gossip::NodeId;
use crate::repair::protocol::{RepairRequest, RepairRequestType};
use crate::repair::{ShredIndex, Slot};

/// Convert an internal repair request to wire format.
///
/// Maps internal request types to Solana-compatible wire variants:
/// - `Shred` → `WindowIndex`
/// - `HighestShred` → `HighestWindowIndex`
/// - `Orphan` → `Orphan`
/// - `Ancestor` → `AncestorHashes`
/// - `SlotRange` → `None` (no Solana equivalent)
///
/// The resulting message is unsigned — call `sign()` on the result.
pub fn request_to_wire(request: &RepairRequest, recipient: [u8; 32]) -> Option<WireRepairProtocol> {
    let nonce = request.nonce() as u32;
    let sender = request.requester().0;
    let timestamp_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let header = WireRepairRequestHeader::new(sender, recipient, timestamp_ms, nonce);

    match request {
        RepairRequest::Shred { slot, index, .. } => Some(WireRepairProtocol::WindowIndex {
            header,
            slot: *slot,
            shred_index: *index as u64,
        }),
        RepairRequest::HighestShred { slot, .. } => Some(WireRepairProtocol::HighestWindowIndex {
            header,
            slot: *slot,
            shred_index: 0,
        }),
        RepairRequest::Orphan { slot, .. } => Some(WireRepairProtocol::Orphan {
            header,
            slot: *slot,
        }),
        RepairRequest::Ancestor { slot, .. } => Some(WireRepairProtocol::AncestorHashes {
            header,
            slot: *slot,
        }),
        RepairRequest::SlotRange { .. } => None, // No Solana equivalent
    }
}

/// Convert a wire repair request to internal format.
///
/// Maps wire variants to internal request types:
/// - `WindowIndex` → `Shred`
/// - `HighestWindowIndex` → `HighestShred`
/// - `Orphan` → `Orphan`
/// - `AncestorHashes` → `Ancestor`
/// - Legacy variants with nonce → corresponding internal type
/// - Legacy variants without nonce, Pong → `None`
pub fn wire_to_request(wire: &WireRepairProtocol) -> Option<RepairRequest> {
    match wire {
        WireRepairProtocol::WindowIndex {
            header,
            slot,
            shred_index,
        } => Some(RepairRequest::Shred {
            requester: NodeId::new(header.sender),
            slot: *slot,
            index: *shred_index as ShredIndex,
            nonce: header.nonce as u64,
        }),

        WireRepairProtocol::HighestWindowIndex { header, slot, .. } => {
            Some(RepairRequest::HighestShred {
                requester: NodeId::new(header.sender),
                slot: *slot,
                nonce: header.nonce as u64,
            })
        }

        WireRepairProtocol::Orphan { header, slot } => Some(RepairRequest::Orphan {
            requester: NodeId::new(header.sender),
            slot: *slot,
            nonce: header.nonce as u64,
        }),

        WireRepairProtocol::AncestorHashes { header, slot } => Some(RepairRequest::Ancestor {
            requester: NodeId::new(header.sender),
            slot: *slot,
            ancestors: 0, // AncestorHashes doesn't carry count; coordinator decides
            nonce: header.nonce as u64,
        }),

        // Legacy variants with nonce
        WireRepairProtocol::LegacyWindowIndexWithNonce(pubkey, slot, shred_index, nonce) => {
            Some(RepairRequest::Shred {
                requester: NodeId::new(*pubkey),
                slot: *slot,
                index: *shred_index as ShredIndex,
                nonce: *nonce as u64,
            })
        }

        WireRepairProtocol::LegacyHighestWindowIndexWithNonce(pubkey, slot, _, nonce) => {
            Some(RepairRequest::HighestShred {
                requester: NodeId::new(*pubkey),
                slot: *slot,
                nonce: *nonce as u64,
            })
        }

        WireRepairProtocol::LegacyOrphanWithNonce(pubkey, slot, nonce) => {
            Some(RepairRequest::Orphan {
                requester: NodeId::new(*pubkey),
                slot: *slot,
                nonce: *nonce as u64,
            })
        }

        WireRepairProtocol::LegacyAncestorHashes(pubkey, slot, nonce) => {
            Some(RepairRequest::Ancestor {
                requester: NodeId::new(*pubkey),
                slot: *slot,
                ancestors: 0,
                nonce: *nonce as u64,
            })
        }

        // Legacy without nonce and Pong are not convertible to internal requests
        _ => None,
    }
}

/// Extract the request type from a wire protocol message.
pub fn wire_request_type(wire: &WireRepairProtocol) -> Option<RepairRequestType> {
    match wire {
        WireRepairProtocol::WindowIndex { .. }
        | WireRepairProtocol::LegacyWindowIndex(..)
        | WireRepairProtocol::LegacyWindowIndexWithNonce(..) => Some(RepairRequestType::Shred),

        WireRepairProtocol::HighestWindowIndex { .. }
        | WireRepairProtocol::LegacyHighestWindowIndex(..)
        | WireRepairProtocol::LegacyHighestWindowIndexWithNonce(..) => {
            Some(RepairRequestType::HighestShred)
        }

        WireRepairProtocol::Orphan { .. }
        | WireRepairProtocol::LegacyOrphan(..)
        | WireRepairProtocol::LegacyOrphanWithNonce(..) => Some(RepairRequestType::Orphan),

        WireRepairProtocol::AncestorHashes { .. }
        | WireRepairProtocol::LegacyAncestorHashes(..) => Some(RepairRequestType::Ancestor),

        _ => None,
    }
}

/// Encode a shred as a wire-format response: raw bytes + u32 nonce.
pub fn shred_to_wire_response(shred_data: &[u8], nonce: u32) -> Vec<u8> {
    encode_shred_response(shred_data, nonce)
}

/// Decode a wire shred response into (payload bytes, nonce).
pub fn wire_response_to_shred(bytes: &[u8]) -> Option<(Vec<u8>, u32)> {
    decode_shred_response(bytes).map(|(payload, nonce)| (payload.to_vec(), nonce))
}

/// Extract slot from a wire repair request.
pub fn wire_request_slot(wire: &WireRepairProtocol) -> Option<Slot> {
    match wire {
        WireRepairProtocol::WindowIndex { slot, .. }
        | WireRepairProtocol::HighestWindowIndex { slot, .. }
        | WireRepairProtocol::Orphan { slot, .. }
        | WireRepairProtocol::AncestorHashes { slot, .. } => Some(*slot),

        WireRepairProtocol::LegacyWindowIndex(_, slot, _)
        | WireRepairProtocol::LegacyHighestWindowIndex(_, slot, _)
        | WireRepairProtocol::LegacyOrphan(_, slot)
        | WireRepairProtocol::LegacyWindowIndexWithNonce(_, slot, _, _)
        | WireRepairProtocol::LegacyHighestWindowIndexWithNonce(_, slot, _, _)
        | WireRepairProtocol::LegacyOrphanWithNonce(_, slot, _)
        | WireRepairProtocol::LegacyAncestorHashes(_, slot, _) => Some(*slot),

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shred_to_window_index_and_back() {
        let requester = NodeId::new([1u8; 32]);
        let recipient = [2u8; 32];
        let request = RepairRequest::Shred {
            requester,
            slot: 12345,
            index: 67,
            nonce: 42,
        };

        let wire = request_to_wire(&request, recipient).unwrap();
        assert_eq!(wire.discriminant(), 8); // WindowIndex

        if let WireRepairProtocol::WindowIndex {
            header,
            slot,
            shred_index,
        } = &wire
        {
            assert_eq!(header.sender, requester.0);
            assert_eq!(header.recipient, recipient);
            assert_eq!(header.nonce, 42);
            assert_eq!(*slot, 12345);
            assert_eq!(*shred_index, 67);
        } else {
            panic!("expected WindowIndex");
        }

        // Convert back
        let internal = wire_to_request(&wire).unwrap();
        if let RepairRequest::Shred {
            requester: req,
            slot,
            index,
            nonce,
        } = internal
        {
            assert_eq!(req, requester);
            assert_eq!(slot, 12345);
            assert_eq!(index, 67);
            assert_eq!(nonce, 42);
        } else {
            panic!("expected Shred");
        }
    }

    #[test]
    fn highest_shred_to_highest_window_index_and_back() {
        let requester = NodeId::new([3u8; 32]);
        let recipient = [4u8; 32];
        let request = RepairRequest::HighestShred {
            requester,
            slot: 999,
            nonce: 7,
        };

        let wire = request_to_wire(&request, recipient).unwrap();
        assert_eq!(wire.discriminant(), 9); // HighestWindowIndex

        let internal = wire_to_request(&wire).unwrap();
        if let RepairRequest::HighestShred {
            requester: req,
            slot,
            nonce,
        } = internal
        {
            assert_eq!(req, requester);
            assert_eq!(slot, 999);
            assert_eq!(nonce, 7);
        } else {
            panic!("expected HighestShred");
        }
    }

    #[test]
    fn orphan_round_trip() {
        let requester = NodeId::new([5u8; 32]);
        let recipient = [6u8; 32];
        let request = RepairRequest::Orphan {
            requester,
            slot: 50000,
            nonce: 99,
        };

        let wire = request_to_wire(&request, recipient).unwrap();
        assert_eq!(wire.discriminant(), 10); // Orphan

        let internal = wire_to_request(&wire).unwrap();
        if let RepairRequest::Orphan {
            requester: req,
            slot,
            nonce,
        } = internal
        {
            assert_eq!(req, requester);
            assert_eq!(slot, 50000);
            assert_eq!(nonce, 99);
        } else {
            panic!("expected Orphan");
        }
    }

    #[test]
    fn ancestor_to_ancestor_hashes_and_back() {
        let requester = NodeId::new([7u8; 32]);
        let recipient = [8u8; 32];
        let request = RepairRequest::Ancestor {
            requester,
            slot: 77777,
            ancestors: 10,
            nonce: 13,
        };

        let wire = request_to_wire(&request, recipient).unwrap();
        assert_eq!(wire.discriminant(), 11); // AncestorHashes

        let internal = wire_to_request(&wire).unwrap();
        if let RepairRequest::Ancestor {
            requester: req,
            slot,
            nonce,
            ..
        } = internal
        {
            assert_eq!(req, requester);
            assert_eq!(slot, 77777);
            assert_eq!(nonce, 13);
        } else {
            panic!("expected Ancestor");
        }
    }

    #[test]
    fn slot_range_returns_none() {
        let requester = NodeId::new([9u8; 32]);
        let request = RepairRequest::SlotRange {
            requester,
            start_slot: 100,
            end_slot: 200,
            nonce: 1,
        };

        assert!(request_to_wire(&request, [10u8; 32]).is_none());
    }

    #[test]
    fn nonce_truncation_preserves_low_32_bits() {
        let requester = NodeId::new([11u8; 32]);
        let recipient = [12u8; 32];
        // Nonce > u32::MAX — high bits are truncated
        let request = RepairRequest::Shred {
            requester,
            slot: 100,
            index: 5,
            nonce: 0x1_FFFF_FFFF, // 33-bit value
        };

        let wire = request_to_wire(&request, recipient).unwrap();
        if let WireRepairProtocol::WindowIndex { header, .. } = &wire {
            assert_eq!(header.nonce, 0xFFFF_FFFF); // truncated to u32
        } else {
            panic!("expected WindowIndex");
        }

        // Converting back gives the truncated value
        let internal = wire_to_request(&wire).unwrap();
        assert_eq!(internal.nonce(), 0xFFFF_FFFF);
    }

    #[test]
    fn legacy_with_nonce_converts_to_internal() {
        let pubkey = [0xABu8; 32];

        let wire = WireRepairProtocol::LegacyWindowIndexWithNonce(pubkey, 100, 5, 42);
        let internal = wire_to_request(&wire).unwrap();
        if let RepairRequest::Shred {
            requester,
            slot,
            index,
            nonce,
        } = internal
        {
            assert_eq!(requester.0, pubkey);
            assert_eq!(slot, 100);
            assert_eq!(index, 5);
            assert_eq!(nonce, 42);
        } else {
            panic!("expected Shred from legacy");
        }

        let wire = WireRepairProtocol::LegacyOrphanWithNonce(pubkey, 300, 7);
        let internal = wire_to_request(&wire).unwrap();
        if let RepairRequest::Orphan { slot, nonce, .. } = internal {
            assert_eq!(slot, 300);
            assert_eq!(nonce, 7);
        } else {
            panic!("expected Orphan from legacy");
        }
    }

    #[test]
    fn legacy_without_nonce_returns_none() {
        let pubkey = [0xCDu8; 32];
        assert!(wire_to_request(&WireRepairProtocol::LegacyWindowIndex(pubkey, 100, 5)).is_none());
        assert!(wire_to_request(&WireRepairProtocol::LegacyOrphan(pubkey, 200)).is_none());
    }

    #[test]
    fn pong_returns_none() {
        let (alice_secret, alice_pubkey) = karstflow_crypto::generate_keypair();
        let (bob_secret, bob_pubkey) = karstflow_crypto::generate_keypair();

        let ping = crate::gossip::wire::WirePing::new(alice_pubkey, [1u8; 32], &alice_secret);
        let pong = crate::gossip::wire::WirePong::from_ping(&ping, bob_pubkey, &bob_secret);

        assert!(wire_to_request(&WireRepairProtocol::Pong(pong)).is_none());
    }

    #[test]
    fn shred_response_wire_round_trip() {
        let payload = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let nonce = 42u32;

        let encoded = shred_to_wire_response(&payload, nonce);
        let (decoded_payload, decoded_nonce) = wire_response_to_shred(&encoded).unwrap();

        assert_eq!(decoded_payload, payload);
        assert_eq!(decoded_nonce, nonce);
    }

    #[test]
    fn wire_request_type_extraction() {
        let header = WireRepairRequestHeader::new([1u8; 32], [2u8; 32], 1000, 42);

        assert_eq!(
            wire_request_type(&WireRepairProtocol::WindowIndex {
                header: header.clone(),
                slot: 100,
                shred_index: 5,
            }),
            Some(RepairRequestType::Shred)
        );

        assert_eq!(
            wire_request_type(&WireRepairProtocol::HighestWindowIndex {
                header: header.clone(),
                slot: 100,
                shred_index: 0,
            }),
            Some(RepairRequestType::HighestShred)
        );

        assert_eq!(
            wire_request_type(&WireRepairProtocol::Orphan {
                header: header.clone(),
                slot: 100,
            }),
            Some(RepairRequestType::Orphan)
        );

        assert_eq!(
            wire_request_type(&WireRepairProtocol::AncestorHashes { header, slot: 100 }),
            Some(RepairRequestType::Ancestor)
        );
    }

    #[test]
    fn wire_request_slot_extraction() {
        let header = WireRepairRequestHeader::new([1u8; 32], [2u8; 32], 1000, 42);

        assert_eq!(
            wire_request_slot(&WireRepairProtocol::WindowIndex {
                header: header.clone(),
                slot: 12345,
                shred_index: 5,
            }),
            Some(12345)
        );

        assert_eq!(
            wire_request_slot(&WireRepairProtocol::LegacyOrphanWithNonce(
                [1u8; 32], 999, 1
            )),
            Some(999)
        );
    }
}
