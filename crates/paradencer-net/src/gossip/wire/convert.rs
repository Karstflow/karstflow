//! Bidirectional conversion between internal CRDS types and wire format.
//!
//! Internal types use a shared envelope with origin/wallclock extracted,
//! while wire types embed origin/wallclock inside each variant. These
//! functions handle the structural reshaping and unit conversion
//! (nanoseconds internally, milliseconds on the wire).

use super::bloom::{WireBloom, WireCrdsFilter};
use super::crds_data::{WireCrdsData, WireLegacyContactInfo, WireNodeInstance};
use super::crds_value::WireCrdsValue;
use crate::gossip::cluster_info::ContactInfo;
use crate::gossip::crds::{
    CrdsContactInfo, CrdsValue, CrdsValueData, GossipBloomFilter, NodeInstanceToken,
    PullRequestMask, VersionInfo,
};
use paradencer_constants::gossip;
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
        // TODO: Handle WireCrdsData::ContactInfo (v2 format) when varint
        // deserialization for ContactInfo v2 is fully implemented.
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// CrdsValue ↔ WireCrdsValue
// ---------------------------------------------------------------------------

/// Convert an internal CrdsValue to a wire-format WireCrdsValue.
///
/// Moves origin/wallclock into the variant struct, converts nanos → millis.
/// Only supports ContactInfo and NodeInstance types currently.
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
        // TODO: Add conversion for other CrdsValueData variants as needed.
        _ => return None,
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
        WireCrdsData::NodeInstance(ni) => {
            CrdsValueData::NodeInstance(NodeInstanceToken { token: ni.token })
        }
        // TODO: Add conversion for other WireCrdsData variants as needed.
        _ => return None,
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
        let (secret, pubkey) = paradencer_crypto::generate_keypair();
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
    fn bloom_filter_round_trip() {
        let bloom = GossipBloomFilter::new(100);
        let mask = PullRequestMask::full();

        let wire_filter = build_wire_crds_filter(&bloom, &mask);
        let (back_bloom, back_mask) = wire_filter_to_internal(&wire_filter);

        assert_eq!(back_mask.mask, mask.mask);
        assert_eq!(back_mask.mask_bits, mask.mask_bits);
        assert_eq!(back_bloom.total_bits(), bloom.total_bits());
    }
}
