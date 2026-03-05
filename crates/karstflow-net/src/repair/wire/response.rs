//! Wire-format encoding/decoding for repair responses.
//!
//! Repair responses use a different format from requests:
//! - Shred responses are raw shred bytes with a u32 nonce appended at the end
//! - AncestorHashes responses are a bincode-serialized enum + u32 nonce
//!
//! This asymmetry exists because shred payloads are opaque byte blobs
//! and wrapping them in another layer of serialization would waste space
//! in the already-tight UDP packet.

use crate::gossip::wire::WirePing;
use serde::{Deserialize, Serialize};

/// Wire format for ancestor hashes response.
///
/// The server responds with either a list of (slot, hash) pairs or a Ping
/// message requesting address verification before serving the data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireAncestorHashesResponse {
    /// Ancestor hash chain: Vec<(Slot, Hash)>, up to 30 pairs.
    Hashes(Vec<(u64, [u8; 32])>),
    /// Ping challenge — respond with Pong before the server will answer.
    Ping(WirePing),
}

/// Encode a shred response: raw shred bytes + u32 nonce appended at end.
///
/// Wire layout: `[shred_payload ...] [nonce: 4 bytes LE]`
pub fn encode_shred_response(shred_payload: &[u8], nonce: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(shred_payload.len() + 4);
    buf.extend_from_slice(shred_payload);
    buf.extend_from_slice(&nonce.to_le_bytes());
    buf
}

/// Decode a shred response: split last 4 bytes as nonce, rest as shred payload.
///
/// Returns `None` if the data is too short (< 4 bytes for the nonce).
pub fn decode_shred_response(bytes: &[u8]) -> Option<(&[u8], u32)> {
    if bytes.len() < 4 {
        return None;
    }
    let (payload, nonce_bytes) = bytes.split_at(bytes.len() - 4);
    let nonce = u32::from_le_bytes([
        nonce_bytes[0],
        nonce_bytes[1],
        nonce_bytes[2],
        nonce_bytes[3],
    ]);
    Some((payload, nonce))
}

/// Encode an ancestor hashes response + u32 nonce appended at end.
///
/// Wire layout: `[bincode(WireAncestorHashesResponse)] [nonce: 4 bytes LE]`
pub fn encode_ancestor_response(response: &WireAncestorHashesResponse, nonce: u32) -> Vec<u8> {
    let serialized = bincode::serialize(response).expect("ancestor response should serialize");
    let mut buf = Vec::with_capacity(serialized.len() + 4);
    buf.extend_from_slice(&serialized);
    buf.extend_from_slice(&nonce.to_le_bytes());
    buf
}

/// Decode an ancestor hashes response + nonce from wire bytes.
///
/// Returns `None` if the data is too short or deserialization fails.
pub fn decode_ancestor_response(bytes: &[u8]) -> Option<(WireAncestorHashesResponse, u32)> {
    if bytes.len() < 4 {
        return None;
    }
    let (payload, nonce_bytes) = bytes.split_at(bytes.len() - 4);
    let nonce = u32::from_le_bytes([
        nonce_bytes[0],
        nonce_bytes[1],
        nonce_bytes[2],
        nonce_bytes[3],
    ]);
    let response: WireAncestorHashesResponse = bincode::deserialize(payload).ok()?;
    Some((response, nonce))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shred_response_round_trip() {
        let payload = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let nonce = 42u32;

        let encoded = encode_shred_response(&payload, nonce);
        assert_eq!(encoded.len(), payload.len() + 4);

        let (decoded_payload, decoded_nonce) = decode_shred_response(&encoded).unwrap();
        assert_eq!(decoded_payload, &payload[..]);
        assert_eq!(decoded_nonce, nonce);
    }

    #[test]
    fn shred_response_empty_payload() {
        let encoded = encode_shred_response(&[], 99);
        assert_eq!(encoded.len(), 4);

        let (decoded_payload, decoded_nonce) = decode_shred_response(&encoded).unwrap();
        assert!(decoded_payload.is_empty());
        assert_eq!(decoded_nonce, 99);
    }

    #[test]
    fn shred_response_too_short() {
        assert!(decode_shred_response(&[1, 2, 3]).is_none());
        assert!(decode_shred_response(&[]).is_none());
    }

    #[test]
    fn shred_response_max_nonce() {
        let payload = vec![0xAB; 1024];
        let nonce = u32::MAX;

        let encoded = encode_shred_response(&payload, nonce);
        let (decoded_payload, decoded_nonce) = decode_shred_response(&encoded).unwrap();
        assert_eq!(decoded_payload, &payload[..]);
        assert_eq!(decoded_nonce, nonce);
    }

    #[test]
    fn ancestor_response_round_trip() {
        let hashes = vec![
            (100u64, [0xAAu8; 32]),
            (101u64, [0xBBu8; 32]),
            (102u64, [0xCCu8; 32]),
        ];
        let response = WireAncestorHashesResponse::Hashes(hashes.clone());
        let nonce = 7u32;

        let encoded = encode_ancestor_response(&response, nonce);
        let (decoded_response, decoded_nonce) = decode_ancestor_response(&encoded).unwrap();

        assert_eq!(decoded_nonce, nonce);
        if let WireAncestorHashesResponse::Hashes(decoded_hashes) = decoded_response {
            assert_eq!(decoded_hashes, hashes);
        } else {
            panic!("expected Hashes variant");
        }
    }

    #[test]
    fn ancestor_response_empty_hashes() {
        let response = WireAncestorHashesResponse::Hashes(vec![]);
        let nonce = 0u32;

        let encoded = encode_ancestor_response(&response, nonce);
        let (decoded_response, decoded_nonce) = decode_ancestor_response(&encoded).unwrap();

        assert_eq!(decoded_nonce, nonce);
        if let WireAncestorHashesResponse::Hashes(hashes) = decoded_response {
            assert!(hashes.is_empty());
        } else {
            panic!("expected Hashes variant");
        }
    }

    #[test]
    fn ancestor_response_ping_variant() {
        let (secret, pubkey) = karstflow_crypto::generate_keypair();
        let ping = WirePing::new(pubkey, [42u8; 32], &secret);
        let response = WireAncestorHashesResponse::Ping(ping.clone());
        let nonce = 55u32;

        let encoded = encode_ancestor_response(&response, nonce);
        let (decoded_response, decoded_nonce) = decode_ancestor_response(&encoded).unwrap();

        assert_eq!(decoded_nonce, nonce);
        if let WireAncestorHashesResponse::Ping(decoded_ping) = decoded_response {
            assert_eq!(decoded_ping, ping);
            assert!(decoded_ping.verify());
        } else {
            panic!("expected Ping variant");
        }
    }

    #[test]
    fn ancestor_response_too_short() {
        assert!(decode_ancestor_response(&[1, 2, 3]).is_none());
        assert!(decode_ancestor_response(&[]).is_none());
    }

    #[test]
    fn ancestor_response_max_pairs() {
        let hashes: Vec<(u64, [u8; 32])> = (0..30).map(|i| (i as u64, [i as u8; 32])).collect();
        let response = WireAncestorHashesResponse::Hashes(hashes.clone());
        let nonce = 123u32;

        let encoded = encode_ancestor_response(&response, nonce);
        let (decoded_response, decoded_nonce) = decode_ancestor_response(&encoded).unwrap();

        assert_eq!(decoded_nonce, nonce);
        if let WireAncestorHashesResponse::Hashes(decoded_hashes) = decoded_response {
            assert_eq!(decoded_hashes.len(), 30);
            assert_eq!(decoded_hashes, hashes);
        } else {
            panic!("expected Hashes variant");
        }
    }
}
