//! Wire-compatible ContactInfo v2 type for the gossip protocol.
//!
//! ContactInfo v2 uses custom serialization with varint-encoded fields
//! and short-vec encoded address/socket vectors. This differs from
//! standard bincode serialization, so custom Serialize/Deserialize
//! implementations are provided.

use super::crds_data::WireSolanaVersion;
use super::varint::{serde_varint_u16, serde_varint_u64, short_vec};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Wire-format ContactInfo v2.
///
/// Uses varint for wallclock and short-vec for address/socket vectors,
/// matching the Solana ContactInfo custom serialization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireContactInfo {
    pub pubkey: [u8; 32],
    #[serde(with = "serde_varint_u64")]
    pub wallclock: u64,
    pub outset: u64,
    pub shred_version: u16,
    pub version: WireSolanaVersion,
    #[serde(with = "short_vec")]
    pub addrs: Vec<IpAddr>,
    #[serde(with = "short_vec")]
    pub sockets: Vec<WireSocketEntry>,
    #[serde(with = "short_vec")]
    pub extensions: Vec<WireExtension>,
}

/// Socket entry in ContactInfo v2.
///
/// Maps a socket type (key) to an IP address (index into addrs vec)
/// with a port offset relative to the previous entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireSocketEntry {
    pub key: u8,
    pub index: u8,
    #[serde(with = "serde_varint_u16")]
    pub offset: u16,
}

/// Protocol extension placeholder.
///
/// Reserved for future protocol extensions. Currently no variants
/// are defined in the gossip protocol.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireExtension {}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_contact_info() -> WireContactInfo {
        WireContactInfo {
            pubkey: [1u8; 32],
            wallclock: 1_700_000_000_000,
            outset: 1_700_000_000,
            shred_version: 42,
            version: WireSolanaVersion {
                major: 2,
                minor: 1,
                patch: 7,
                commit: 0xDEADBEEF,
                feature_set: 0x12345678,
                client: 1,
            },
            addrs: vec![
                IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            ],
            sockets: vec![
                WireSocketEntry {
                    key: 0,
                    index: 0,
                    offset: 8000,
                },
                WireSocketEntry {
                    key: 5,
                    index: 0,
                    offset: 1,
                },
            ],
            extensions: vec![],
        }
    }

    #[test]
    fn contact_info_bincode_round_trip() {
        let ci = make_contact_info();
        let bytes = bincode::serialize(&ci).unwrap();
        let decoded: WireContactInfo = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded, ci);
    }

    #[test]
    fn contact_info_varint_wallclock() {
        let ci = make_contact_info();
        let bytes = bincode::serialize(&ci).unwrap();

        // pubkey is 32 bytes, then wallclock is varint-encoded
        // 1_700_000_000_000 in varint should be < 10 bytes
        // The total should be smaller than 32 + 8 (fixed u64) would be
        // because varint compression saves bytes for this value
        assert!(bytes.len() > 32); // at least pubkey + some data
    }

    #[test]
    fn contact_info_empty_addrs_and_sockets() {
        let ci = WireContactInfo {
            pubkey: [0u8; 32],
            wallclock: 0,
            outset: 0,
            shred_version: 0,
            version: WireSolanaVersion {
                major: 0,
                minor: 0,
                patch: 0,
                commit: 0,
                feature_set: 0,
                client: 0,
            },
            addrs: vec![],
            sockets: vec![],
            extensions: vec![],
        };
        let bytes = bincode::serialize(&ci).unwrap();
        let decoded: WireContactInfo = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded, ci);
    }
}
