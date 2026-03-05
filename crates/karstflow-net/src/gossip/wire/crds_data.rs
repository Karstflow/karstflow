//! Wire-compatible CRDS data types for the gossip protocol.
//!
//! These types match the exact bincode serialization layout used by
//! Solana validators for the 14 CRDS value variants. Each variant struct
//! carries `from` (origin pubkey) and `wallclock` (milliseconds) inline,
//! matching the Solana convention where these fields are part of each
//! variant rather than in a shared envelope.

use super::contact_info::WireContactInfo;
use super::varint::{serde_varint_u16, short_vec};
use bv::BitVec;
use serde::de::{self, SeqAccess, Visitor};
use serde::ser::SerializeTuple;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::SocketAddr;

// ===========================================================================
// Main CrdsData enum — 14 variants matching Solana's discriminant order
// ===========================================================================

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum WireCrdsData {
    LegacyContactInfo(WireLegacyContactInfo),
    Vote(u8, WireVote),
    LowestSlot(u8, WireLowestSlot),
    LegacySnapshotHashes(WireAccountsHashes),
    AccountsHashes(WireAccountsHashes),
    EpochSlots(u8, WireEpochSlots),
    LegacyVersion(WireLegacyVersionEntry),
    Version(WireVersionEntry),
    NodeInstance(WireNodeInstance),
    DuplicateShred(u16, WireDuplicateShred),
    SnapshotHashes(WireSnapshotHashes),
    ContactInfo(WireContactInfo),
    RestartLastVotedForkSlots(WireRestartLastVotedForkSlots),
    RestartHeaviestFork(WireRestartHeaviestFork),
}

impl WireCrdsData {
    /// Extract the origin pubkey from any variant.
    pub fn origin(&self) -> &[u8; 32] {
        match self {
            Self::LegacyContactInfo(v) => &v.id,
            Self::Vote(_, v) => &v.from,
            Self::LowestSlot(_, v) => &v.from,
            Self::LegacySnapshotHashes(v) | Self::AccountsHashes(v) => &v.from,
            Self::EpochSlots(_, v) => &v.from,
            Self::LegacyVersion(v) => &v.from,
            Self::Version(v) => &v.from,
            Self::NodeInstance(v) => &v.from,
            Self::DuplicateShred(_, v) => &v.from,
            Self::SnapshotHashes(v) => &v.from,
            Self::ContactInfo(v) => &v.pubkey,
            Self::RestartLastVotedForkSlots(v) => &v.from,
            Self::RestartHeaviestFork(v) => &v.from,
        }
    }

    /// Extract the wallclock (milliseconds) from any variant.
    pub fn wallclock_ms(&self) -> u64 {
        match self {
            Self::LegacyContactInfo(v) => v.wallclock,
            Self::Vote(_, v) => v.wallclock,
            Self::LowestSlot(_, v) => v.wallclock,
            Self::LegacySnapshotHashes(v) | Self::AccountsHashes(v) => v.wallclock,
            Self::EpochSlots(_, v) => v.wallclock,
            Self::LegacyVersion(v) => v.wallclock,
            Self::Version(v) => v.wallclock,
            Self::NodeInstance(v) => v.wallclock,
            Self::DuplicateShred(_, v) => v.wallclock,
            Self::SnapshotHashes(v) => v.wallclock,
            Self::ContactInfo(v) => v.wallclock,
            Self::RestartLastVotedForkSlots(v) => v.wallclock,
            Self::RestartHeaviestFork(v) => v.wallclock,
        }
    }
}

// ===========================================================================
// Variant 0: LegacyContactInfo
// ===========================================================================

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireLegacyContactInfo {
    pub id: [u8; 32],
    pub gossip: SocketAddr,
    pub tvu: SocketAddr,
    pub tvu_quic: SocketAddr,
    pub serve_repair_quic: SocketAddr,
    pub tpu: SocketAddr,
    pub tpu_forwards: SocketAddr,
    pub tpu_vote: SocketAddr,
    pub rpc: SocketAddr,
    pub rpc_pubsub: SocketAddr,
    pub serve_repair: SocketAddr,
    pub wallclock: u64,
    pub shred_version: u16,
}

// ===========================================================================
// Variant 1: Vote
// ===========================================================================

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireVote {
    pub from: [u8; 32],
    pub transaction: WireTransaction,
    pub wallclock: u64,
}

/// 64-byte Ed25519 signature with custom serde for arrays > 32.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireSignature(pub [u8; 64]);

impl Serialize for WireSignature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_tuple(64)?;
        for &byte in &self.0 {
            seq.serialize_element(&byte)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for WireSignature {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SigVisitor;
        impl<'de> Visitor<'de> for SigVisitor {
            type Value = WireSignature;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("64 bytes")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<WireSignature, A::Error> {
                let mut arr = [0u8; 64];
                for byte in &mut arr {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::custom("expected 64 bytes"))?;
                }
                Ok(WireSignature(arr))
            }
        }
        deserializer.deserialize_tuple(64, SigVisitor)
    }
}

/// Wire-compatible transaction matching Solana's bincode layout.
/// Uses short-vec encoding for signature and instruction vectors.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireTransaction {
    #[serde(with = "short_vec")]
    pub signatures: Vec<WireSignature>,
    pub message: WireMessage,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireMessage {
    pub header: WireMessageHeader,
    #[serde(with = "short_vec")]
    pub account_keys: Vec<[u8; 32]>,
    pub recent_blockhash: [u8; 32],
    #[serde(with = "short_vec")]
    pub instructions: Vec<WireCompiledInstruction>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireMessageHeader {
    pub num_required_signatures: u8,
    pub num_readonly_signed_accounts: u8,
    pub num_readonly_unsigned_accounts: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireCompiledInstruction {
    pub program_id_index: u8,
    #[serde(with = "short_vec")]
    pub accounts: Vec<u8>,
    #[serde(with = "short_vec")]
    pub data: Vec<u8>,
}

// ===========================================================================
// Variant 2: LowestSlot
// ===========================================================================

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireLowestSlot {
    pub from: [u8; 32],
    pub root: u64,
    pub lowest: u64,
    pub slots: BTreeSet<u64>,
    pub stash: Vec<DeprecatedEpochIncompleteSlots>,
    pub wallclock: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeprecatedCompressionType {
    Uncompressed,
    GZip,
    BZip2,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeprecatedEpochIncompleteSlots {
    pub first: u64,
    pub compression: DeprecatedCompressionType,
    pub compressed_list: Vec<u8>,
}

// ===========================================================================
// Variants 3 & 4: LegacySnapshotHashes / AccountsHashes (same struct)
// ===========================================================================

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireAccountsHashes {
    pub from: [u8; 32],
    pub hashes: Vec<(u64, [u8; 32])>,
    pub wallclock: u64,
}

// ===========================================================================
// Variant 5: EpochSlots
// ===========================================================================

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireEpochSlots {
    pub from: [u8; 32],
    pub slots: Vec<WireCompressedSlots>,
    pub wallclock: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireCompressedSlots {
    Flate2(WireFlate2),
    Uncompressed(WireUncompressed),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireFlate2 {
    pub first_slot: u64,
    pub num: usize,
    pub compressed: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireUncompressed {
    pub first_slot: u64,
    pub num: usize,
    pub slots: BitVec<u8>,
}

// ===========================================================================
// Variant 6: LegacyVersion
// ===========================================================================

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireLegacyVersionEntry {
    pub from: [u8; 32],
    pub wallclock: u64,
    pub version: WireLegacyVersion1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireLegacyVersion1 {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
    pub commit: Option<u32>,
}

// ===========================================================================
// Variant 7: Version
// ===========================================================================

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireVersionEntry {
    pub from: [u8; 32],
    pub wallclock: u64,
    pub version: WireLegacyVersion2,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireLegacyVersion2 {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
    pub commit: Option<u32>,
    pub feature_set: u32,
}

// ===========================================================================
// Variant 8: NodeInstance
// ===========================================================================

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireNodeInstance {
    pub from: [u8; 32],
    pub wallclock: u64,
    pub timestamp: u64,
    pub token: u64,
}

// ===========================================================================
// Variant 9: DuplicateShred
// ===========================================================================

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireDuplicateShred {
    pub from: [u8; 32],
    pub wallclock: u64,
    pub slot: u64,
    pub _unused: u32,
    pub _unused_shred_type: u8,
    pub num_chunks: u8,
    pub chunk_index: u8,
    pub chunk: Vec<u8>,
}

// ===========================================================================
// Variant 10: SnapshotHashes (new format with full + incremental)
// ===========================================================================

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireSnapshotHashes {
    pub from: [u8; 32],
    pub full: (u64, [u8; 32]),
    pub incremental: Vec<(u64, [u8; 32])>,
    pub wallclock: u64,
}

// ===========================================================================
// Variant 11: ContactInfo — see contact_info.rs
// ===========================================================================

// WireContactInfo is imported from super::contact_info

// ===========================================================================
// Variant 12: RestartLastVotedForkSlots
// ===========================================================================

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireRestartLastVotedForkSlots {
    pub from: [u8; 32],
    pub wallclock: u64,
    pub offsets: WireSlotsOffsets,
    pub last_voted_slot: u64,
    pub last_voted_hash: [u8; 32],
    pub shred_version: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireSlotsOffsets {
    RunLengthEncoding(Vec<WireVarintU16>),
    RawOffsets(BitVec<u8>),
}

/// Newtype wrapper for a u16 encoded with LEB128 varint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireVarintU16(#[serde(with = "serde_varint_u16")] pub u16);

// ===========================================================================
// Variant 13: RestartHeaviestFork
// ===========================================================================

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireRestartHeaviestFork {
    pub from: [u8; 32],
    pub wallclock: u64,
    pub last_slot: u64,
    pub last_slot_hash: [u8; 32],
    pub observed_stake: u64,
    pub shred_version: u16,
}

// ===========================================================================
// Version type used in ContactInfo v2 (varint-encoded fields)
// ===========================================================================

/// Solana version with varint-encoded numeric fields.
/// Used inside ContactInfo v2 for compact wire representation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireSolanaVersion {
    #[serde(with = "serde_varint_u16")]
    pub major: u16,
    #[serde(with = "serde_varint_u16")]
    pub minor: u16,
    #[serde(with = "serde_varint_u16")]
    pub patch: u16,
    pub commit: u32,
    pub feature_set: u32,
    #[serde(with = "serde_varint_u16")]
    pub client: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_instance_bincode_round_trip() {
        let ni = WireNodeInstance {
            from: [1u8; 32],
            wallclock: 1_700_000_000_000,
            timestamp: 1_700_000_000,
            token: 42,
        };
        let data = WireCrdsData::NodeInstance(ni.clone());
        let bytes = bincode::serialize(&data).unwrap();
        let decoded: WireCrdsData = bincode::deserialize(&bytes).unwrap();
        if let WireCrdsData::NodeInstance(decoded_ni) = decoded {
            assert_eq!(decoded_ni, ni);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn accounts_hashes_bincode_round_trip() {
        let ah = WireAccountsHashes {
            from: [2u8; 32],
            hashes: vec![(100, [3u8; 32]), (200, [4u8; 32])],
            wallclock: 1_700_000_000_000,
        };
        let data = WireCrdsData::LegacySnapshotHashes(ah.clone());
        let bytes = bincode::serialize(&data).unwrap();
        let decoded: WireCrdsData = bincode::deserialize(&bytes).unwrap();
        if let WireCrdsData::LegacySnapshotHashes(decoded_ah) = decoded {
            assert_eq!(decoded_ah, ah);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn snapshot_hashes_bincode_round_trip() {
        let sh = WireSnapshotHashes {
            from: [5u8; 32],
            full: (1000, [6u8; 32]),
            incremental: vec![(1100, [7u8; 32]), (1200, [8u8; 32])],
            wallclock: 1_700_000_000_000,
        };
        let data = WireCrdsData::SnapshotHashes(sh.clone());
        let bytes = bincode::serialize(&data).unwrap();
        let decoded: WireCrdsData = bincode::deserialize(&bytes).unwrap();
        if let WireCrdsData::SnapshotHashes(decoded_sh) = decoded {
            assert_eq!(decoded_sh, sh);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn duplicate_shred_bincode_round_trip() {
        let ds = WireDuplicateShred {
            from: [9u8; 32],
            wallclock: 1_700_000_000_000,
            slot: 42,
            _unused: 0,
            _unused_shred_type: 0,
            num_chunks: 3,
            chunk_index: 1,
            chunk: vec![1, 2, 3, 4, 5],
        };
        let data = WireCrdsData::DuplicateShred(0, ds.clone());
        let bytes = bincode::serialize(&data).unwrap();
        let decoded: WireCrdsData = bincode::deserialize(&bytes).unwrap();
        if let WireCrdsData::DuplicateShred(idx, decoded_ds) = decoded {
            assert_eq!(idx, 0);
            assert_eq!(decoded_ds, ds);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn restart_heaviest_fork_bincode_round_trip() {
        let rhf = WireRestartHeaviestFork {
            from: [10u8; 32],
            wallclock: 1_700_000_000_000,
            last_slot: 500,
            last_slot_hash: [11u8; 32],
            observed_stake: 1_000_000,
            shred_version: 42,
        };
        let data = WireCrdsData::RestartHeaviestFork(rhf.clone());
        let bytes = bincode::serialize(&data).unwrap();
        let decoded: WireCrdsData = bincode::deserialize(&bytes).unwrap();
        if let WireCrdsData::RestartHeaviestFork(decoded_rhf) = decoded {
            assert_eq!(decoded_rhf, rhf);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn vote_bincode_round_trip() {
        let vote = WireVote {
            from: [12u8; 32],
            transaction: WireTransaction {
                signatures: vec![WireSignature([0xAA; 64])],
                message: WireMessage {
                    header: WireMessageHeader {
                        num_required_signatures: 1,
                        num_readonly_signed_accounts: 0,
                        num_readonly_unsigned_accounts: 1,
                    },
                    account_keys: vec![[0xBB; 32], [0xCC; 32]],
                    recent_blockhash: [0xDD; 32],
                    instructions: vec![WireCompiledInstruction {
                        program_id_index: 1,
                        accounts: vec![0],
                        data: vec![2, 0, 0, 0, 1, 0, 0, 0, 100, 0, 0, 0, 0, 0, 0, 0],
                    }],
                },
            },
            wallclock: 1_700_000_000_000,
        };
        let data = WireCrdsData::Vote(0, vote.clone());
        let bytes = bincode::serialize(&data).unwrap();
        let decoded: WireCrdsData = bincode::deserialize(&bytes).unwrap();
        if let WireCrdsData::Vote(idx, decoded_vote) = decoded {
            assert_eq!(idx, 0);
            assert_eq!(decoded_vote, vote);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn lowest_slot_bincode_round_trip() {
        let ls = WireLowestSlot {
            from: [13u8; 32],
            root: 0,
            lowest: 42,
            slots: BTreeSet::new(),
            stash: Vec::new(),
            wallclock: 1_700_000_000_000,
        };
        let data = WireCrdsData::LowestSlot(0, ls.clone());
        let bytes = bincode::serialize(&data).unwrap();
        let decoded: WireCrdsData = bincode::deserialize(&bytes).unwrap();
        if let WireCrdsData::LowestSlot(idx, decoded_ls) = decoded {
            assert_eq!(idx, 0);
            assert_eq!(decoded_ls, ls);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn crds_data_origin_extraction() {
        let from = [42u8; 32];
        let data = WireCrdsData::NodeInstance(WireNodeInstance {
            from,
            wallclock: 100,
            timestamp: 200,
            token: 300,
        });
        assert_eq!(data.origin(), &from);
        assert_eq!(data.wallclock_ms(), 100);
    }

    #[test]
    fn version_entry_bincode_round_trip() {
        let ve = WireVersionEntry {
            from: [14u8; 32],
            wallclock: 1_700_000_000_000,
            version: WireLegacyVersion2 {
                major: 2,
                minor: 1,
                patch: 17,
                commit: Some(0xDEADBEEF),
                feature_set: 0x12345678,
            },
        };
        let data = WireCrdsData::Version(ve.clone());
        let bytes = bincode::serialize(&data).unwrap();
        let decoded: WireCrdsData = bincode::deserialize(&bytes).unwrap();
        if let WireCrdsData::Version(decoded_ve) = decoded {
            assert_eq!(decoded_ve, ve);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn legacy_version_entry_bincode_round_trip() {
        let lve = WireLegacyVersionEntry {
            from: [15u8; 32],
            wallclock: 1_700_000_000_000,
            version: WireLegacyVersion1 {
                major: 1,
                minor: 14,
                patch: 3,
                commit: Some(0xCAFEBABE),
            },
        };
        let data = WireCrdsData::LegacyVersion(lve.clone());
        let bytes = bincode::serialize(&data).unwrap();
        let decoded: WireCrdsData = bincode::deserialize(&bytes).unwrap();
        if let WireCrdsData::LegacyVersion(decoded_lve) = decoded {
            assert_eq!(decoded_lve, lve);
        } else {
            panic!("wrong variant");
        }
    }
}
