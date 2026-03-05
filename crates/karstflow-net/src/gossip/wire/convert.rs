//! Bidirectional conversion between internal CRDS types and wire format.
//!
//! Internal types use a shared envelope with origin/wallclock extracted,
//! while wire types embed origin/wallclock inside each variant. These
//! functions handle the structural reshaping and unit conversion
//! (nanoseconds internally, milliseconds on the wire).

use super::bloom::{WireBloom, WireCrdsFilter};
use super::crds_data::{
    WireAccountsHashes, WireCrdsData, WireDuplicateShred, WireEpochSlots, WireLegacyContactInfo,
    WireLegacyVersion1, WireLegacyVersion2, WireLegacyVersionEntry, WireLowestSlot,
    WireNodeInstance, WireRestartHeaviestFork, WireRestartLastVotedForkSlots, WireSnapshotHashes,
    WireVersionEntry, WireVote,
};
use super::crds_value::WireCrdsValue;
use crate::gossip::cluster_info::ContactInfo;
use crate::gossip::crds::{
    CrdsContactInfo, CrdsValue, CrdsValueData, DuplicateShredProof, EpochSlots, GossipBloomFilter,
    IncrementalSnapshotHashes, LowestSlot, NodeInstanceToken, PullRequestMask, SnapshotHashes,
    VersionInfo, VoteGossip,
};
use karstflow_constants::gossip;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Default placeholder socket address for unused fields in LegacyContactInfo.
const UNSPECIFIED_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

// ---------------------------------------------------------------------------
// ContactInfo ↔ WireCrdsValue
// ---------------------------------------------------------------------------

/// Convert an internal ContactInfo to a wire-format LegacyContactInfo CrdsValue.
///
/// Uses variant 0 (LegacyContactInfo) for maximum compatibility.
/// The returned value has a zero signature — call `.sign()` before sending.
pub fn contact_info_to_wire_value(ci: &ContactInfo) -> WireCrdsValue {
    let legacy = WireLegacyContactInfo {
        id: ci.node_id.0,
        gossip: ci.gossip_addr,
        tvu: UNSPECIFIED_ADDR,
        tvu_quic: UNSPECIFIED_ADDR,
        serve_repair_quic: UNSPECIFIED_ADDR,
        tpu: ci.tpu_addr,
        tpu_forwards: UNSPECIFIED_ADDR,
        tpu_vote: UNSPECIFIED_ADDR,
        rpc: ci.rpc_addr.unwrap_or(UNSPECIFIED_ADDR),
        rpc_pubsub: UNSPECIFIED_ADDR,
        serve_repair: ci.repair_addr,
        wallclock: ci.wallclock,
        shred_version: ci.shred_version,
    };
    WireCrdsValue {
        signature: [0u8; 64],
        data: WireCrdsData::LegacyContactInfo(legacy),
    }
}

/// Try to extract a ContactInfo from a WireCrdsValue.
///
/// Returns None if the value is not a contact info variant, or if the
/// gossip address is unspecified.
pub fn wire_value_to_contact_info(wv: &WireCrdsValue) -> Option<ContactInfo> {
    match &wv.data {
        WireCrdsData::LegacyContactInfo(lci) => {
            if lci.gossip.ip().is_unspecified() && lci.gossip.port() == 0 {
                return None;
            }
            Some(ContactInfo {
                node_id: crate::gossip::cluster_info::NodeId(lci.id),
                gossip_addr: lci.gossip,
                tpu_addr: if lci.tpu.ip().is_unspecified() {
                    lci.gossip
                } else {
                    lci.tpu
                },
                tpu_quic_addr: if lci.tpu.ip().is_unspecified() {
                    lci.gossip
                } else {
                    // TPU QUIC is typically TPU port + 6
                    lci.tpu
                },
                repair_addr: if lci.serve_repair.ip().is_unspecified() {
                    lci.gossip
                } else {
                    lci.serve_repair
                },
                rpc_addr: if lci.rpc.ip().is_unspecified() {
                    None
                } else {
                    Some(lci.rpc)
                },
                version: 0,
                wallclock: lci.wallclock,
                shred_version: lci.shred_version,
            })
        }
        WireCrdsData::ContactInfo(ci) => {
            // Resolve sockets from the v2 address/port encoding.
            // Port is accumulated: each entry's offset is relative to the
            // previous entry's resolved port (starting from 0).
            let mut resolved_sockets = vec![None; gossip::CONTACT_INFO_SOCKET_COUNT];
            let mut port_accumulator: u16 = 0;
            for entry in &ci.sockets {
                let ip = ci.addrs.get(entry.index as usize)?;
                port_accumulator = port_accumulator.wrapping_add(entry.offset);
                let addr = std::net::SocketAddr::new(*ip, port_accumulator);
                let key = entry.key as usize;
                if key < resolved_sockets.len() {
                    resolved_sockets[key] = Some(addr);
                }
            }

            let gossip_addr = resolved_sockets[gossip::SOCKET_GOSSIP]?;
            if gossip_addr.ip().is_unspecified() && gossip_addr.port() == 0 {
                return None;
            }

            Some(ContactInfo {
                node_id: crate::gossip::cluster_info::NodeId(ci.pubkey),
                gossip_addr,
                tpu_addr: resolved_sockets[gossip::SOCKET_TPU].unwrap_or(gossip_addr),
                tpu_quic_addr: resolved_sockets[gossip::SOCKET_TPU_QUIC].unwrap_or(gossip_addr),
                repair_addr: resolved_sockets[gossip::SOCKET_SERVE_REPAIR].unwrap_or(gossip_addr),
                rpc_addr: resolved_sockets[gossip::SOCKET_RPC],
                version: ci.version.major as u64,
                wallclock: ci.wallclock,
                shred_version: ci.shred_version,
            })
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// CrdsValue ↔ WireCrdsValue
// ---------------------------------------------------------------------------

/// Convert an internal CrdsValue to a wire-format WireCrdsValue.
///
/// Moves origin/wallclock into the variant struct, converts nanos → millis.
/// Returns `None` only for the deprecated `AccountHashes` variant.
/// The returned value has a zero signature — call `.sign()` before sending.
pub fn internal_to_wire_value(value: &CrdsValue) -> Option<WireCrdsValue> {
    let wallclock_ms = (value.wallclock_nanos / 1_000_000) as u64;
    let origin = value.origin;

    let data = match &value.data {
        CrdsValueData::ContactInfo(ci) => {
            let legacy = WireLegacyContactInfo {
                id: ci.pubkey,
                gossip: ci.sockets[gossip::SOCKET_GOSSIP].unwrap_or(UNSPECIFIED_ADDR),
                tvu: ci.sockets[gossip::SOCKET_TVU].unwrap_or(UNSPECIFIED_ADDR),
                tvu_quic: ci.sockets[gossip::SOCKET_TVU_QUIC].unwrap_or(UNSPECIFIED_ADDR),
                serve_repair_quic: ci.sockets[gossip::SOCKET_SERVE_REPAIR_QUIC]
                    .unwrap_or(UNSPECIFIED_ADDR),
                tpu: ci.sockets[gossip::SOCKET_TPU].unwrap_or(UNSPECIFIED_ADDR),
                tpu_forwards: ci.sockets[gossip::SOCKET_TPU_FORWARDS].unwrap_or(UNSPECIFIED_ADDR),
                tpu_vote: ci.sockets[gossip::SOCKET_TPU_VOTE].unwrap_or(UNSPECIFIED_ADDR),
                rpc: ci.sockets[gossip::SOCKET_RPC].unwrap_or(UNSPECIFIED_ADDR),
                rpc_pubsub: ci.sockets[gossip::SOCKET_RPC_PUBSUB].unwrap_or(UNSPECIFIED_ADDR),
                serve_repair: ci.sockets[gossip::SOCKET_SERVE_REPAIR].unwrap_or(UNSPECIFIED_ADDR),
                wallclock: wallclock_ms,
                shred_version: ci.shred_version,
            };
            WireCrdsData::LegacyContactInfo(legacy)
        }
        CrdsValueData::LegacyContactInfo(ci) => {
            let legacy = WireLegacyContactInfo {
                id: ci.pubkey,
                gossip: ci.sockets[gossip::SOCKET_GOSSIP].unwrap_or(UNSPECIFIED_ADDR),
                tvu: ci.sockets[gossip::SOCKET_TVU].unwrap_or(UNSPECIFIED_ADDR),
                tvu_quic: ci.sockets[gossip::SOCKET_TVU_QUIC].unwrap_or(UNSPECIFIED_ADDR),
                serve_repair_quic: ci.sockets[gossip::SOCKET_SERVE_REPAIR_QUIC]
                    .unwrap_or(UNSPECIFIED_ADDR),
                tpu: ci.sockets[gossip::SOCKET_TPU].unwrap_or(UNSPECIFIED_ADDR),
                tpu_forwards: ci.sockets[gossip::SOCKET_TPU_FORWARDS].unwrap_or(UNSPECIFIED_ADDR),
                tpu_vote: ci.sockets[gossip::SOCKET_TPU_VOTE].unwrap_or(UNSPECIFIED_ADDR),
                rpc: ci.sockets[gossip::SOCKET_RPC].unwrap_or(UNSPECIFIED_ADDR),
                rpc_pubsub: ci.sockets[gossip::SOCKET_RPC_PUBSUB].unwrap_or(UNSPECIFIED_ADDR),
                serve_repair: ci.sockets[gossip::SOCKET_SERVE_REPAIR].unwrap_or(UNSPECIFIED_ADDR),
                wallclock: wallclock_ms,
                shred_version: ci.shred_version,
            };
            WireCrdsData::LegacyContactInfo(legacy)
        }
        CrdsValueData::NodeInstance(ni) => {
            WireCrdsData::NodeInstance(WireNodeInstance {
                from: origin,
                wallclock: wallclock_ms,
                timestamp: wallclock_ms / 1000, // seconds
                token: ni.token,
            })
        }
        CrdsValueData::Vote(vote) => {
            // Deserialize the transaction bytes back to wire transaction.
            let transaction: super::crds_data::WireTransaction =
                match bincode::deserialize(&vote.transaction_bytes) {
                    Ok(tx) => tx,
                    Err(_) => return None,
                };
            WireCrdsData::Vote(
                vote.index,
                WireVote {
                    from: origin,
                    transaction,
                    wallclock: wallclock_ms,
                },
            )
        }
        CrdsValueData::DuplicateShred(ds) => WireCrdsData::DuplicateShred(
            ds.index,
            WireDuplicateShred {
                from: origin,
                wallclock: wallclock_ms,
                slot: 0,
                _unused: 0,
                _unused_shred_type: 0,
                num_chunks: 0,
                chunk_index: 0,
                chunk: ds.proof_bytes.clone(),
            },
        ),
        CrdsValueData::IncrementalSnapshotHashes(ish) => {
            WireCrdsData::SnapshotHashes(WireSnapshotHashes {
                from: origin,
                full: ish.base,
                incremental: ish.hashes.clone(),
                wallclock: wallclock_ms,
            })
        }
        CrdsValueData::LegacySnapshotHashes(sh) => {
            WireCrdsData::LegacySnapshotHashes(WireAccountsHashes {
                from: origin,
                hashes: sh.hashes.clone(),
                wallclock: wallclock_ms,
            })
        }
        CrdsValueData::Version(v) => WireCrdsData::Version(WireVersionEntry {
            from: origin,
            wallclock: wallclock_ms,
            version: WireLegacyVersion2 {
                major: v.major,
                minor: v.minor,
                patch: v.patch,
                commit: Some(v.commit),
                feature_set: v.feature_set,
            },
        }),
        CrdsValueData::LowestSlot(ls) => WireCrdsData::LowestSlot(
            0,
            WireLowestSlot {
                from: origin,
                root: 0,
                lowest: ls.slot,
                slots: std::collections::BTreeSet::new(),
                stash: Vec::new(),
                wallclock: wallclock_ms,
            },
        ),
        CrdsValueData::EpochSlots(es) => {
            // Internal stores compressed slots as bincode-serialized bytes.
            let slots = match bincode::deserialize(&es.slots) {
                Ok(s) => s,
                Err(_) => return None,
            };
            WireCrdsData::EpochSlots(
                es.index,
                WireEpochSlots {
                    from: origin,
                    slots,
                    wallclock: wallclock_ms,
                },
            )
        }
        CrdsValueData::LegacyVersion(v) => WireCrdsData::LegacyVersion(WireLegacyVersionEntry {
            from: origin,
            wallclock: wallclock_ms,
            version: WireLegacyVersion1 {
                major: v.major,
                minor: v.minor,
                patch: v.patch,
                commit: Some(v.commit),
            },
        }),
        CrdsValueData::RestartLastVotedForkSlots(rlv) => {
            // Internal stores offsets as bincode-serialized bytes.
            let offsets = match bincode::deserialize(&rlv.slots) {
                Ok(o) => o,
                Err(_) => return None,
            };
            WireCrdsData::RestartLastVotedForkSlots(WireRestartLastVotedForkSlots {
                from: origin,
                wallclock: wallclock_ms,
                offsets,
                last_voted_slot: rlv.last_voted_slot,
                last_voted_hash: rlv.last_voted_hash,
                shred_version: rlv.shred_version,
            })
        }
        CrdsValueData::RestartHeaviestFork(rhf) => {
            WireCrdsData::RestartHeaviestFork(WireRestartHeaviestFork {
                from: origin,
                wallclock: wallclock_ms,
                last_slot: rhf.slot,
                last_slot_hash: rhf.hash,
                observed_stake: rhf.observed_stake,
                shred_version: 0,
            })
        }
        CrdsValueData::AccountHashes => return None,
    };

    Some(WireCrdsValue {
        signature: [0u8; 64],
        data,
    })
}

/// Convert a wire-format WireCrdsValue to an internal CrdsValue.
///
/// Extracts origin/wallclock from the variant struct, converts millis → nanos.
/// The internal signature is set to zero since wire signature conventions differ.
pub fn wire_to_internal_value(wv: &WireCrdsValue) -> Option<CrdsValue> {
    let origin = *wv.data.origin();
    let wallclock_ms = wv.data.wallclock_ms();
    let wallclock_nanos = (wallclock_ms as i64) * 1_000_000;

    let data = match &wv.data {
        WireCrdsData::LegacyContactInfo(lci) => {
            let mut sockets: [Option<SocketAddr>; gossip::CONTACT_INFO_SOCKET_COUNT] =
                Default::default();
            sockets[gossip::SOCKET_GOSSIP] = non_unspecified(lci.gossip);
            sockets[gossip::SOCKET_TVU] = non_unspecified(lci.tvu);
            sockets[gossip::SOCKET_TVU_QUIC] = non_unspecified(lci.tvu_quic);
            sockets[gossip::SOCKET_SERVE_REPAIR_QUIC] = non_unspecified(lci.serve_repair_quic);
            sockets[gossip::SOCKET_TPU] = non_unspecified(lci.tpu);
            sockets[gossip::SOCKET_TPU_FORWARDS] = non_unspecified(lci.tpu_forwards);
            sockets[gossip::SOCKET_TPU_VOTE] = non_unspecified(lci.tpu_vote);
            sockets[gossip::SOCKET_RPC] = non_unspecified(lci.rpc);
            sockets[gossip::SOCKET_RPC_PUBSUB] = non_unspecified(lci.rpc_pubsub);
            sockets[gossip::SOCKET_SERVE_REPAIR] = non_unspecified(lci.serve_repair);

            CrdsValueData::LegacyContactInfo(CrdsContactInfo {
                pubkey: lci.id,
                shred_version: lci.shred_version,
                instance_creation_nanos: wallclock_nanos,
                wallclock_nanos,
                sockets,
                version: VersionInfo::default(),
            })
        }
        WireCrdsData::ContactInfo(ci) => {
            // Resolve v2 socket entries into the internal array format.
            // Port offsets accumulate: each entry's offset is added to the
            // previous resolved port (starting from zero).
            let mut sockets: [Option<SocketAddr>; gossip::CONTACT_INFO_SOCKET_COUNT] =
                Default::default();
            let mut port_accumulator: u16 = 0;
            for entry in &ci.sockets {
                let ip = ci.addrs.get(entry.index as usize)?;
                port_accumulator = port_accumulator.wrapping_add(entry.offset);
                let addr = SocketAddr::new(*ip, port_accumulator);
                let key = entry.key as usize;
                if key < sockets.len() {
                    sockets[key] = Some(addr);
                }
            }

            CrdsValueData::ContactInfo(CrdsContactInfo {
                pubkey: ci.pubkey,
                shred_version: ci.shred_version,
                instance_creation_nanos: (ci.outset as i64) * 1_000_000,
                wallclock_nanos,
                sockets,
                version: VersionInfo {
                    client: ci.version.client,
                    major: ci.version.major,
                    minor: ci.version.minor,
                    patch: ci.version.patch,
                    commit: ci.version.commit,
                    feature_set: ci.version.feature_set,
                },
            })
        }
        WireCrdsData::NodeInstance(ni) => {
            CrdsValueData::NodeInstance(NodeInstanceToken { token: ni.token })
        }
        WireCrdsData::Vote(index, vote) => {
            // Serialize the wire transaction to bytes for internal storage.
            let transaction_bytes = match bincode::serialize(&vote.transaction) {
                Ok(bytes) => bytes,
                Err(_) => return None,
            };
            CrdsValueData::Vote(VoteGossip {
                index: *index,
                slot: 0, // Extracted by callers if needed from the transaction data
                hash: [0u8; 32],
                transaction_bytes,
            })
        }
        WireCrdsData::DuplicateShred(index, ds) => {
            CrdsValueData::DuplicateShred(DuplicateShredProof {
                index: *index,
                proof_bytes: ds.chunk.clone(),
            })
        }
        WireCrdsData::SnapshotHashes(sh) => {
            CrdsValueData::IncrementalSnapshotHashes(IncrementalSnapshotHashes {
                base: sh.full,
                hashes: sh.incremental.clone(),
            })
        }
        WireCrdsData::LegacySnapshotHashes(ah) | WireCrdsData::AccountsHashes(ah) => {
            CrdsValueData::LegacySnapshotHashes(SnapshotHashes {
                hashes: ah.hashes.clone(),
            })
        }
        WireCrdsData::LowestSlot(_index, ls) => {
            CrdsValueData::LowestSlot(LowestSlot { slot: ls.lowest })
        }
        WireCrdsData::EpochSlots(index, es) => {
            // Store compressed slots as raw bytes for relay purposes.
            let slot_bytes: Vec<u8> = bincode::serialize(&es.slots).unwrap_or_default();
            CrdsValueData::EpochSlots(EpochSlots {
                index: *index,
                slots: slot_bytes,
            })
        }
        WireCrdsData::Version(ve) => CrdsValueData::Version(VersionInfo {
            client: 0,
            major: ve.version.major,
            minor: ve.version.minor,
            patch: ve.version.patch,
            commit: ve.version.commit.unwrap_or(0),
            feature_set: ve.version.feature_set,
        }),
        WireCrdsData::LegacyVersion(lve) => CrdsValueData::LegacyVersion(VersionInfo {
            client: 0,
            major: lve.version.major,
            minor: lve.version.minor,
            patch: lve.version.patch,
            commit: lve.version.commit.unwrap_or(0),
            feature_set: 0,
        }),
        WireCrdsData::RestartHeaviestFork(rhf) => {
            CrdsValueData::RestartHeaviestFork(super::super::crds::RestartHeaviestFork {
                slot: rhf.last_slot,
                hash: rhf.last_slot_hash,
                observed_stake: rhf.observed_stake,
            })
        }
        WireCrdsData::RestartLastVotedForkSlots(rlv) => CrdsValueData::RestartLastVotedForkSlots(
            super::super::crds::RestartLastVotedForkSlots {
                slots: bincode::serialize(&rlv.offsets).unwrap_or_default(),
                last_voted_slot: rlv.last_voted_slot,
                last_voted_hash: rlv.last_voted_hash,
                shred_version: rlv.shred_version,
            },
        ),
    };

    Some(CrdsValue {
        origin,
        wallclock_nanos,
        signature: wv.signature,
        data,
    })
}

/// Filter unspecified addresses (0.0.0.0:0) to None.
fn non_unspecified(addr: SocketAddr) -> Option<SocketAddr> {
    if addr.ip().is_unspecified() && addr.port() == 0 {
        None
    } else {
        Some(addr)
    }
}

// ---------------------------------------------------------------------------
// Bloom filter conversion
// ---------------------------------------------------------------------------

/// Convert internal bloom filter + mask to wire format.
pub fn build_wire_crds_filter(bloom: &GossipBloomFilter, mask: &PullRequestMask) -> WireCrdsFilter {
    WireCrdsFilter {
        filter: WireBloom::from_internal(bloom),
        mask: mask.mask,
        mask_bits: mask.mask_bits,
    }
}

/// Convert a wire CRDS filter back to internal bloom filter + mask.
pub fn wire_filter_to_internal(filter: &WireCrdsFilter) -> (GossipBloomFilter, PullRequestMask) {
    let bloom = filter.filter.to_internal();
    let mask = PullRequestMask {
        mask: filter.mask,
        mask_bits: filter.mask_bits,
    };
    (bloom, mask)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gossip::cluster_info::NodeId;

    fn test_contact_info(pubkey: [u8; 32], port: u16) -> ContactInfo {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
        ContactInfo {
            node_id: NodeId(pubkey),
            gossip_addr: addr,
            tpu_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port + 1),
            tpu_quic_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port + 2),
            repair_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port + 3),
            rpc_addr: Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                port + 4,
            )),
            version: 0,
            wallclock: 1_700_000_000_000,
            shred_version: 42,
        }
    }

    #[test]
    fn contact_info_round_trip() {
        let pubkey = [1u8; 32];
        let ci = test_contact_info(pubkey, 8000);
        let wire = contact_info_to_wire_value(&ci);

        assert_eq!(wire.origin(), &pubkey);
        assert_eq!(wire.wallclock_ms(), ci.wallclock);

        let back = wire_value_to_contact_info(&wire).unwrap();
        assert_eq!(back.node_id.0, pubkey);
        assert_eq!(back.gossip_addr, ci.gossip_addr);
        assert_eq!(back.tpu_addr, ci.tpu_addr);
        assert_eq!(back.repair_addr, ci.repair_addr);
        assert_eq!(back.rpc_addr, ci.rpc_addr);
        assert_eq!(back.wallclock, ci.wallclock);
        assert_eq!(back.shred_version, ci.shred_version);
    }

    #[test]
    fn contact_info_wire_value_sign_verify() {
        let (secret, pubkey) = karstflow_crypto::generate_keypair();
        let ci = test_contact_info(pubkey, 9000);
        let mut wire = contact_info_to_wire_value(&ci);
        wire.sign(&secret);
        assert!(wire.verify());
    }

    #[test]
    fn internal_crds_value_to_wire_round_trip() {
        let pubkey = [2u8; 32];
        let now_ms: u64 = 1_700_000_000_000;
        let now_nanos = (now_ms as i64) * 1_000_000;

        let mut sockets: [Option<SocketAddr>; gossip::CONTACT_INFO_SOCKET_COUNT] =
            Default::default();
        let gossip_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8001);
        sockets[gossip::SOCKET_GOSSIP] = Some(gossip_addr);

        let internal = CrdsValue {
            origin: pubkey,
            wallclock_nanos: now_nanos,
            signature: [0u8; 64],
            data: CrdsValueData::ContactInfo(CrdsContactInfo {
                pubkey,
                shred_version: 10,
                instance_creation_nanos: now_nanos,
                wallclock_nanos: now_nanos,
                sockets,
                version: VersionInfo::default(),
            }),
        };

        let wire = internal_to_wire_value(&internal).unwrap();
        assert_eq!(wire.origin(), &pubkey);
        assert_eq!(wire.wallclock_ms(), now_ms);

        let back = wire_to_internal_value(&wire).unwrap();
        assert_eq!(back.origin, pubkey);
        assert_eq!(back.wallclock_nanos, now_nanos);

        if let CrdsValueData::LegacyContactInfo(ci) = &back.data {
            assert_eq!(ci.sockets[gossip::SOCKET_GOSSIP], Some(gossip_addr));
            assert_eq!(ci.shred_version, 10);
        } else {
            panic!("expected LegacyContactInfo");
        }
    }

    #[test]
    fn node_instance_round_trip() {
        let pubkey = [3u8; 32];
        let now_nanos: i64 = 1_700_000_000_000_000_000;

        let internal = CrdsValue {
            origin: pubkey,
            wallclock_nanos: now_nanos,
            signature: [0u8; 64],
            data: CrdsValueData::NodeInstance(NodeInstanceToken { token: 12345 }),
        };

        let wire = internal_to_wire_value(&internal).unwrap();
        assert_eq!(wire.origin(), &pubkey);

        let back = wire_to_internal_value(&wire).unwrap();
        assert_eq!(back.origin, pubkey);
        if let CrdsValueData::NodeInstance(ni) = &back.data {
            assert_eq!(ni.token, 12345);
        } else {
            panic!("expected NodeInstance");
        }
    }

    #[test]
    fn wire_value_with_unspecified_gossip_returns_none() {
        let wire = WireCrdsValue {
            signature: [0u8; 64],
            data: WireCrdsData::LegacyContactInfo(WireLegacyContactInfo {
                id: [1u8; 32],
                gossip: UNSPECIFIED_ADDR,
                tvu: UNSPECIFIED_ADDR,
                tvu_quic: UNSPECIFIED_ADDR,
                serve_repair_quic: UNSPECIFIED_ADDR,
                tpu: UNSPECIFIED_ADDR,
                tpu_forwards: UNSPECIFIED_ADDR,
                tpu_vote: UNSPECIFIED_ADDR,
                rpc: UNSPECIFIED_ADDR,
                rpc_pubsub: UNSPECIFIED_ADDR,
                serve_repair: UNSPECIFIED_ADDR,
                wallclock: 0,
                shred_version: 0,
            }),
        };
        assert!(wire_value_to_contact_info(&wire).is_none());
    }

    #[test]
    fn contact_info_v2_to_internal_round_trip() {
        use super::super::contact_info::{WireContactInfo, WireSocketEntry};
        use super::super::crds_data::WireSolanaVersion;

        let pubkey = [7u8; 32];
        let wallclock_ms: u64 = 1_700_000_000_000;
        let outset_ms: u64 = 1_699_000_000_000;
        let ip = std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        // Socket entries: gossip=8000, tpu=8001, serve_repair=8003
        let wire_ci = WireContactInfo {
            pubkey,
            wallclock: wallclock_ms,
            outset: outset_ms,
            shred_version: 55,
            version: WireSolanaVersion {
                major: 2,
                minor: 1,
                patch: 7,
                commit: 0xDEAD,
                feature_set: 0xBEEF,
                client: 1,
            },
            addrs: vec![ip],
            sockets: vec![
                WireSocketEntry {
                    key: gossip::SOCKET_GOSSIP as u8,
                    index: 0,
                    offset: 8000,
                },
                WireSocketEntry {
                    key: gossip::SOCKET_TPU as u8,
                    index: 0,
                    offset: 1, // 8000 + 1 = 8001
                },
                WireSocketEntry {
                    key: gossip::SOCKET_SERVE_REPAIR as u8,
                    index: 0,
                    offset: 2, // 8001 + 2 = 8003
                },
            ],
            extensions: vec![],
        };

        let wire_value = WireCrdsValue {
            signature: [0u8; 64],
            data: WireCrdsData::ContactInfo(wire_ci),
        };

        // Test wire_value_to_contact_info (high-level)
        let ci = wire_value_to_contact_info(&wire_value).unwrap();
        assert_eq!(ci.node_id.0, pubkey);
        assert_eq!(ci.gossip_addr, SocketAddr::new(ip, 8000));
        assert_eq!(ci.tpu_addr, SocketAddr::new(ip, 8001));
        assert_eq!(ci.repair_addr, SocketAddr::new(ip, 8003));
        assert_eq!(ci.shred_version, 55);
        assert_eq!(ci.version, 2); // major version

        // Test wire_to_internal_value (CRDS-level)
        let internal = wire_to_internal_value(&wire_value).unwrap();
        assert_eq!(internal.origin, pubkey);
        let expected_wallclock_nanos = (wallclock_ms as i64) * 1_000_000;
        assert_eq!(internal.wallclock_nanos, expected_wallclock_nanos);

        if let CrdsValueData::ContactInfo(ref crds_ci) = internal.data {
            assert_eq!(crds_ci.pubkey, pubkey);
            assert_eq!(crds_ci.shred_version, 55);
            assert_eq!(
                crds_ci.sockets[gossip::SOCKET_GOSSIP],
                Some(SocketAddr::new(ip, 8000))
            );
            assert_eq!(
                crds_ci.sockets[gossip::SOCKET_TPU],
                Some(SocketAddr::new(ip, 8001))
            );
            assert_eq!(
                crds_ci.sockets[gossip::SOCKET_SERVE_REPAIR],
                Some(SocketAddr::new(ip, 8003))
            );
            assert_eq!(crds_ci.version.major, 2);
            assert_eq!(crds_ci.version.minor, 1);
            assert_eq!(crds_ci.version.patch, 7);
            assert_eq!(crds_ci.version.client, 1);
            // outset is milliseconds → nanos
            assert_eq!(
                crds_ci.instance_creation_nanos,
                (outset_ms as i64) * 1_000_000
            );
        } else {
            panic!("expected ContactInfo variant");
        }
    }

    #[test]
    fn contact_info_v2_unspecified_gossip_returns_none() {
        use super::super::contact_info::{WireContactInfo, WireSocketEntry};
        use super::super::crds_data::WireSolanaVersion;

        // No gossip socket entry → None
        let wire_ci = WireContactInfo {
            pubkey: [8u8; 32],
            wallclock: 1_700_000_000_000,
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
            addrs: vec![std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
            sockets: vec![
                // Only TPU, no gossip
                WireSocketEntry {
                    key: gossip::SOCKET_TPU as u8,
                    index: 0,
                    offset: 9000,
                },
            ],
            extensions: vec![],
        };
        let wire_value = WireCrdsValue {
            signature: [0u8; 64],
            data: WireCrdsData::ContactInfo(wire_ci),
        };
        assert!(wire_value_to_contact_info(&wire_value).is_none());
    }

    #[test]
    fn bloom_filter_round_trip() {
        let bloom = GossipBloomFilter::new(100);
        let mask = PullRequestMask::full();

        let wire_filter = build_wire_crds_filter(&bloom, &mask);
        let (back_bloom, back_mask) = wire_filter_to_internal(&wire_filter);

        assert_eq!(back_mask.mask, mask.mask);
        assert_eq!(back_mask.mask_bits, mask.mask_bits);
        assert_eq!(back_bloom.total_bits(), bloom.total_bits());
    }

    #[test]
    fn vote_wire_round_trip() {
        use super::super::crds_data::{
            WireCompiledInstruction, WireMessage, WireMessageHeader, WireSignature, WireTransaction,
        };

        let pubkey = [10u8; 32];
        let now_ms: u64 = 1_700_000_000_000;
        let now_nanos = (now_ms as i64) * 1_000_000;

        // Build a wire transaction and serialize to bytes.
        let wire_tx = WireTransaction {
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
                    data: vec![2, 0, 0, 0],
                }],
            },
        };
        let tx_bytes = bincode::serialize(&wire_tx).unwrap();

        let internal = CrdsValue {
            origin: pubkey,
            wallclock_nanos: now_nanos,
            signature: [0u8; 64],
            data: CrdsValueData::Vote(VoteGossip {
                index: 3,
                slot: 100,
                hash: [0u8; 32],
                transaction_bytes: tx_bytes.clone(),
            }),
        };

        let wire = internal_to_wire_value(&internal).unwrap();
        assert_eq!(wire.origin(), &pubkey);
        assert_eq!(wire.wallclock_ms(), now_ms);

        if let WireCrdsData::Vote(idx, ref vote) = wire.data {
            assert_eq!(idx, 3);
            assert_eq!(vote.from, pubkey);
            assert_eq!(vote.transaction, wire_tx);
        } else {
            panic!("expected Vote variant");
        }

        // Convert back to internal.
        let back = wire_to_internal_value(&wire).unwrap();
        assert_eq!(back.origin, pubkey);
        if let CrdsValueData::Vote(ref v) = back.data {
            assert_eq!(v.index, 3);
            assert_eq!(v.transaction_bytes, tx_bytes);
        } else {
            panic!("expected Vote variant");
        }
    }

    #[test]
    fn duplicate_shred_wire_round_trip() {
        let pubkey = [11u8; 32];
        let now_nanos: i64 = 1_700_000_000_000_000_000;

        let internal = CrdsValue {
            origin: pubkey,
            wallclock_nanos: now_nanos,
            signature: [0u8; 64],
            data: CrdsValueData::DuplicateShred(DuplicateShredProof {
                index: 7,
                proof_bytes: vec![1, 2, 3, 4, 5, 6, 7, 8],
            }),
        };

        let wire = internal_to_wire_value(&internal).unwrap();
        if let WireCrdsData::DuplicateShred(idx, ref ds) = wire.data {
            assert_eq!(idx, 7);
            assert_eq!(ds.chunk, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        } else {
            panic!("expected DuplicateShred variant");
        }

        let back = wire_to_internal_value(&wire).unwrap();
        if let CrdsValueData::DuplicateShred(ref dp) = back.data {
            assert_eq!(dp.index, 7);
            assert_eq!(dp.proof_bytes, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        } else {
            panic!("expected DuplicateShred variant");
        }
    }

    #[test]
    fn snapshot_hashes_wire_round_trip() {
        let pubkey = [12u8; 32];
        let now_nanos: i64 = 1_700_000_000_000_000_000;

        let internal = CrdsValue {
            origin: pubkey,
            wallclock_nanos: now_nanos,
            signature: [0u8; 64],
            data: CrdsValueData::IncrementalSnapshotHashes(IncrementalSnapshotHashes {
                base: (1000, [0xAA; 32]),
                hashes: vec![(1100, [0xBB; 32]), (1200, [0xCC; 32])],
            }),
        };

        let wire = internal_to_wire_value(&internal).unwrap();
        if let WireCrdsData::SnapshotHashes(ref sh) = wire.data {
            assert_eq!(sh.full, (1000, [0xAA; 32]));
            assert_eq!(sh.incremental.len(), 2);
        } else {
            panic!("expected SnapshotHashes variant");
        }

        let back = wire_to_internal_value(&wire).unwrap();
        if let CrdsValueData::IncrementalSnapshotHashes(ref ish) = back.data {
            assert_eq!(ish.base, (1000, [0xAA; 32]));
            assert_eq!(ish.hashes.len(), 2);
            assert_eq!(ish.hashes[0], (1100, [0xBB; 32]));
        } else {
            panic!("expected IncrementalSnapshotHashes variant");
        }
    }

    #[test]
    fn version_wire_round_trip() {
        let pubkey = [13u8; 32];
        let now_nanos: i64 = 1_700_000_000_000_000_000;

        let internal = CrdsValue {
            origin: pubkey,
            wallclock_nanos: now_nanos,
            signature: [0u8; 64],
            data: CrdsValueData::Version(VersionInfo {
                client: 5,
                major: 2,
                minor: 1,
                patch: 17,
                commit: 0xDEAD,
                feature_set: 0xBEEF,
            }),
        };

        let wire = internal_to_wire_value(&internal).unwrap();
        if let WireCrdsData::Version(ref ve) = wire.data {
            assert_eq!(ve.version.major, 2);
            assert_eq!(ve.version.minor, 1);
            assert_eq!(ve.version.patch, 17);
            assert_eq!(ve.version.feature_set, 0xBEEF);
        } else {
            panic!("expected Version variant");
        }

        let back = wire_to_internal_value(&wire).unwrap();
        if let CrdsValueData::Version(ref vi) = back.data {
            assert_eq!(vi.major, 2);
            assert_eq!(vi.minor, 1);
            assert_eq!(vi.patch, 17);
            assert_eq!(vi.commit, 0xDEAD);
            assert_eq!(vi.feature_set, 0xBEEF);
        } else {
            panic!("expected Version variant");
        }
    }

    #[test]
    fn lowest_slot_wire_round_trip() {
        let pubkey = [14u8; 32];
        let now_nanos: i64 = 1_700_000_000_000_000_000;

        let internal = CrdsValue {
            origin: pubkey,
            wallclock_nanos: now_nanos,
            signature: [0u8; 64],
            data: CrdsValueData::LowestSlot(LowestSlot { slot: 42 }),
        };

        let wire = internal_to_wire_value(&internal).unwrap();
        if let WireCrdsData::LowestSlot(_, ref ls) = wire.data {
            assert_eq!(ls.lowest, 42);
        } else {
            panic!("expected LowestSlot variant");
        }

        let back = wire_to_internal_value(&wire).unwrap();
        if let CrdsValueData::LowestSlot(ref ls) = back.data {
            assert_eq!(ls.slot, 42);
        } else {
            panic!("expected LowestSlot variant");
        }
    }

    #[test]
    fn wire_to_internal_all_types_return_some() {
        use super::super::crds_data::*;

        let pubkey = [20u8; 32];
        let wc = 1_700_000_000_000u64;

        // Vote
        let vote_wire = WireCrdsValue {
            signature: [0u8; 64],
            data: WireCrdsData::Vote(
                0,
                WireVote {
                    from: pubkey,
                    transaction: WireTransaction {
                        signatures: vec![WireSignature([0; 64])],
                        message: WireMessage {
                            header: WireMessageHeader {
                                num_required_signatures: 1,
                                num_readonly_signed_accounts: 0,
                                num_readonly_unsigned_accounts: 0,
                            },
                            account_keys: vec![[0; 32]],
                            recent_blockhash: [0; 32],
                            instructions: vec![],
                        },
                    },
                    wallclock: wc,
                },
            ),
        };
        assert!(wire_to_internal_value(&vote_wire).is_some());

        // SnapshotHashes
        let sh_wire = WireCrdsValue {
            signature: [0u8; 64],
            data: WireCrdsData::SnapshotHashes(WireSnapshotHashes {
                from: pubkey,
                full: (100, [1; 32]),
                incremental: vec![],
                wallclock: wc,
            }),
        };
        assert!(wire_to_internal_value(&sh_wire).is_some());

        // LegacySnapshotHashes
        let lsh_wire = WireCrdsValue {
            signature: [0u8; 64],
            data: WireCrdsData::LegacySnapshotHashes(WireAccountsHashes {
                from: pubkey,
                hashes: vec![(100, [1; 32])],
                wallclock: wc,
            }),
        };
        assert!(wire_to_internal_value(&lsh_wire).is_some());

        // LowestSlot
        let ls_wire = WireCrdsValue {
            signature: [0u8; 64],
            data: WireCrdsData::LowestSlot(
                0,
                WireLowestSlot {
                    from: pubkey,
                    root: 0,
                    lowest: 50,
                    slots: std::collections::BTreeSet::new(),
                    stash: vec![],
                    wallclock: wc,
                },
            ),
        };
        assert!(wire_to_internal_value(&ls_wire).is_some());

        // Version
        let ver_wire = WireCrdsValue {
            signature: [0u8; 64],
            data: WireCrdsData::Version(WireVersionEntry {
                from: pubkey,
                wallclock: wc,
                version: WireLegacyVersion2 {
                    major: 2,
                    minor: 0,
                    patch: 0,
                    commit: None,
                    feature_set: 0,
                },
            }),
        };
        assert!(wire_to_internal_value(&ver_wire).is_some());

        // LegacyVersion
        let lver_wire = WireCrdsValue {
            signature: [0u8; 64],
            data: WireCrdsData::LegacyVersion(WireLegacyVersionEntry {
                from: pubkey,
                wallclock: wc,
                version: WireLegacyVersion1 {
                    major: 1,
                    minor: 14,
                    patch: 3,
                    commit: None,
                },
            }),
        };
        assert!(wire_to_internal_value(&lver_wire).is_some());

        // DuplicateShred
        let ds_wire = WireCrdsValue {
            signature: [0u8; 64],
            data: WireCrdsData::DuplicateShred(
                5,
                WireDuplicateShred {
                    from: pubkey,
                    wallclock: wc,
                    slot: 42,
                    _unused: 0,
                    _unused_shred_type: 0,
                    num_chunks: 3,
                    chunk_index: 1,
                    chunk: vec![1, 2, 3],
                },
            ),
        };
        assert!(wire_to_internal_value(&ds_wire).is_some());

        // RestartHeaviestFork
        let rhf_wire = WireCrdsValue {
            signature: [0u8; 64],
            data: WireCrdsData::RestartHeaviestFork(WireRestartHeaviestFork {
                from: pubkey,
                wallclock: wc,
                last_slot: 500,
                last_slot_hash: [0xAA; 32],
                observed_stake: 1_000_000,
                shred_version: 42,
            }),
        };
        assert!(wire_to_internal_value(&rhf_wire).is_some());
    }

    #[test]
    fn epoch_slots_wire_round_trip() {
        use super::super::crds_data::{WireCompressedSlots, WireFlate2};

        let pubkey = [15u8; 32];
        let now_nanos: i64 = 1_700_000_000_000_000_000;

        // Build wire compressed slots and serialize to internal byte format.
        let wire_slots = vec![WireCompressedSlots::Flate2(WireFlate2 {
            first_slot: 100,
            num: 64,
            compressed: vec![0xFF; 8],
        })];
        let slot_bytes = bincode::serialize(&wire_slots).unwrap();

        let internal = CrdsValue {
            origin: pubkey,
            wallclock_nanos: now_nanos,
            signature: [0u8; 64],
            data: CrdsValueData::EpochSlots(EpochSlots {
                index: 3,
                slots: slot_bytes,
            }),
        };

        let wire = internal_to_wire_value(&internal).unwrap();
        if let WireCrdsData::EpochSlots(idx, ref es) = wire.data {
            assert_eq!(idx, 3);
            assert_eq!(es.from, pubkey);
            assert_eq!(es.slots.len(), 1);
            if let WireCompressedSlots::Flate2(ref f) = es.slots[0] {
                assert_eq!(f.first_slot, 100);
                assert_eq!(f.num, 64);
            } else {
                panic!("expected Flate2 variant");
            }
        } else {
            panic!("expected EpochSlots variant");
        }

        // Round-trip back.
        let back = wire_to_internal_value(&wire).unwrap();
        if let CrdsValueData::EpochSlots(ref ep) = back.data {
            assert_eq!(ep.index, 3);
            // Bytes should match the original serialized form.
            let rt_slots: Vec<WireCompressedSlots> = bincode::deserialize(&ep.slots).unwrap();
            assert_eq!(rt_slots, wire_slots);
        } else {
            panic!("expected EpochSlots variant");
        }
    }

    #[test]
    fn legacy_version_wire_round_trip() {
        let pubkey = [16u8; 32];
        let now_nanos: i64 = 1_700_000_000_000_000_000;

        let internal = CrdsValue {
            origin: pubkey,
            wallclock_nanos: now_nanos,
            signature: [0u8; 64],
            data: CrdsValueData::LegacyVersion(VersionInfo {
                client: 0,
                major: 1,
                minor: 14,
                patch: 3,
                commit: 0xCAFE,
                feature_set: 0, // not in legacy format
            }),
        };

        let wire = internal_to_wire_value(&internal).unwrap();
        if let WireCrdsData::LegacyVersion(ref lve) = wire.data {
            assert_eq!(lve.from, pubkey);
            assert_eq!(lve.version.major, 1);
            assert_eq!(lve.version.minor, 14);
            assert_eq!(lve.version.patch, 3);
            assert_eq!(lve.version.commit, Some(0xCAFE));
        } else {
            panic!("expected LegacyVersion variant");
        }

        let back = wire_to_internal_value(&wire).unwrap();
        if let CrdsValueData::LegacyVersion(ref vi) = back.data {
            assert_eq!(vi.major, 1);
            assert_eq!(vi.minor, 14);
            assert_eq!(vi.patch, 3);
            assert_eq!(vi.commit, 0xCAFE);
            assert_eq!(vi.feature_set, 0);
        } else {
            panic!("expected LegacyVersion variant");
        }
    }

    #[test]
    fn restart_last_voted_fork_slots_wire_round_trip() {
        use super::super::crds_data::WireSlotsOffsets;
        use bv::BitVec;

        let pubkey = [17u8; 32];
        let now_nanos: i64 = 1_700_000_000_000_000_000;

        // Build slot offsets and serialize to internal byte format.
        let mut bv = BitVec::new_fill(false, 256);
        bv.set(0, true);
        bv.set(42, true);
        bv.set(255, true);
        let offsets = WireSlotsOffsets::RawOffsets(bv);
        let offset_bytes = bincode::serialize(&offsets).unwrap();

        let internal = CrdsValue {
            origin: pubkey,
            wallclock_nanos: now_nanos,
            signature: [0u8; 64],
            data: CrdsValueData::RestartLastVotedForkSlots(
                crate::gossip::crds::RestartLastVotedForkSlots {
                    slots: offset_bytes,
                    last_voted_slot: 500,
                    last_voted_hash: [0xBB; 32],
                    shred_version: 77,
                },
            ),
        };

        let wire = internal_to_wire_value(&internal).unwrap();
        if let WireCrdsData::RestartLastVotedForkSlots(ref rlv) = wire.data {
            assert_eq!(rlv.from, pubkey);
            assert_eq!(rlv.last_voted_slot, 500);
            assert_eq!(rlv.last_voted_hash, [0xBB; 32]);
            assert_eq!(rlv.shred_version, 77);
        } else {
            panic!("expected RestartLastVotedForkSlots variant");
        }

        let back = wire_to_internal_value(&wire).unwrap();
        if let CrdsValueData::RestartLastVotedForkSlots(ref rlvfs) = back.data {
            assert_eq!(rlvfs.last_voted_slot, 500);
            assert_eq!(rlvfs.last_voted_hash, [0xBB; 32]);
            assert_eq!(rlvfs.shred_version, 77);
            // Deserialize offsets and verify bitmap.
            let rt_offsets: WireSlotsOffsets = bincode::deserialize(&rlvfs.slots).unwrap();
            assert_eq!(rt_offsets, offsets);
        } else {
            panic!("expected RestartLastVotedForkSlots variant");
        }
    }

    #[test]
    fn restart_heaviest_fork_wire_round_trip() {
        let pubkey = [18u8; 32];
        let now_nanos: i64 = 1_700_000_000_000_000_000;

        let internal = CrdsValue {
            origin: pubkey,
            wallclock_nanos: now_nanos,
            signature: [0u8; 64],
            data: CrdsValueData::RestartHeaviestFork(crate::gossip::crds::RestartHeaviestFork {
                slot: 1000,
                hash: [0xCC; 32],
                observed_stake: 5_000_000,
            }),
        };

        let wire = internal_to_wire_value(&internal).unwrap();
        if let WireCrdsData::RestartHeaviestFork(ref rhf) = wire.data {
            assert_eq!(rhf.from, pubkey);
            assert_eq!(rhf.last_slot, 1000);
            assert_eq!(rhf.last_slot_hash, [0xCC; 32]);
            assert_eq!(rhf.observed_stake, 5_000_000);
        } else {
            panic!("expected RestartHeaviestFork variant");
        }

        let back = wire_to_internal_value(&wire).unwrap();
        if let CrdsValueData::RestartHeaviestFork(ref rhf) = back.data {
            assert_eq!(rhf.slot, 1000);
            assert_eq!(rhf.hash, [0xCC; 32]);
            assert_eq!(rhf.observed_stake, 5_000_000);
        } else {
            panic!("expected RestartHeaviestFork variant");
        }
    }
}
