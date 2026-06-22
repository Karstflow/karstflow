//! Snapshot peer discovery and selection from gossip CRDS.
//!
//! Scans the CRDS table for SnapshotHashes entries, cross-references with
//! ContactInfo for RPC addresses, and scores peers by snapshot slot recency.

use crate::gossip::crds::{CrdsTable, CrdsValueData, SnapshotHashes};
use karstflow_constants::gossip;
use std::collections::HashMap;
use std::net::SocketAddr;

/// Information about a peer that serves snapshots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotPeerInfo {
    /// Peer's public key (32 bytes).
    pub identity: [u8; 32],
    /// Peer's RPC socket address (for HTTP snapshot download).
    pub rpc_addr: SocketAddr,
    /// Full snapshot: (slot, hash).
    pub full_snapshot: (u64, [u8; 32]),
    /// Best incremental snapshot: (base_slot, slot, hash).
    /// Only present if the peer advertises incremental snapshots
    /// based on the same full snapshot.
    pub incremental_snapshot: Option<(u64, u64, [u8; 32])>,
}

/// Discovers and scores snapshot-serving peers from gossip CRDS.
pub struct SnapshotPeerSelector;

impl SnapshotPeerSelector {
    /// Scan the CRDS table and return snapshot peers sorted by best slot (descending).
    ///
    /// Peers must have:
    /// 1. A SnapshotHashes or LegacySnapshotHashes CRDS entry with at least one hash
    /// 2. A ContactInfo entry with a valid RPC socket address
    ///
    /// Optionally filters by `min_slot` (only return peers with full snapshot >= min_slot).
    pub fn scan_crds(table: &CrdsTable, min_slot: Option<u64>) -> Vec<SnapshotPeerInfo> {
        // Collect RPC addresses from ContactInfo entries.
        let rpc_addrs = Self::collect_rpc_addresses(table);
        if rpc_addrs.is_empty() {
            return Vec::new();
        }

        // Collect snapshot hashes from both legacy and new types.
        let mut peers: HashMap<[u8; 32], SnapshotPeerInfo> = HashMap::new();

        // Legacy SnapshotHashes (type 3).
        Self::process_snapshot_entries(
            table,
            gossip::VALUE_TYPE_LEGACY_SNAPSHOT_HASHES,
            &rpc_addrs,
            min_slot,
            &mut peers,
        );

        // New SnapshotHashes (type 10 — IncrementalSnapshotHashes).
        // Type 10 entries carry both full and incremental snapshot info.
        Self::process_incremental_entries(table, &rpc_addrs, min_slot, &mut peers);

        // Sort by full snapshot slot descending (highest = best).
        let mut result: Vec<SnapshotPeerInfo> = peers.into_values().collect();
        result.sort_by_key(|b| std::cmp::Reverse(b.full_snapshot.0));
        result
    }

    /// Collect RPC socket addresses from ContactInfo entries, keyed by identity pubkey.
    fn collect_rpc_addresses(table: &CrdsTable) -> HashMap<[u8; 32], SocketAddr> {
        let mut addrs = HashMap::new();

        // Check ContactInfo (type 11).
        for entry in table.entries_by_type(gossip::VALUE_TYPE_CONTACT_INFO) {
            if let CrdsValueData::ContactInfo(ci) = &entry.value.data {
                if let Some(rpc_addr) = ci.sockets[gossip::SOCKET_RPC] {
                    addrs.insert(ci.pubkey, rpc_addr);
                }
            }
        }

        // Also check LegacyContactInfo (type 0).
        for entry in table.entries_by_type(gossip::VALUE_TYPE_LEGACY_CONTACT_INFO) {
            if let CrdsValueData::LegacyContactInfo(ci) = &entry.value.data {
                if let Some(rpc_addr) = ci.sockets[gossip::SOCKET_RPC] {
                    // Only insert if not already present from newer ContactInfo.
                    addrs.entry(ci.pubkey).or_insert(rpc_addr);
                }
            }
        }

        addrs
    }

    /// Process LegacySnapshotHashes entries (type 3).
    fn process_snapshot_entries(
        table: &CrdsTable,
        value_type: u8,
        rpc_addrs: &HashMap<[u8; 32], SocketAddr>,
        min_slot: Option<u64>,
        peers: &mut HashMap<[u8; 32], SnapshotPeerInfo>,
    ) {
        for entry in table.entries_by_type(value_type) {
            let origin = entry.key.origin;
            let rpc_addr = match rpc_addrs.get(&origin) {
                Some(addr) => *addr,
                None => continue,
            };

            let hashes = match &entry.value.data {
                CrdsValueData::LegacySnapshotHashes(sh) => sh,
                _ => continue,
            };

            let best = Self::best_snapshot_hash(hashes, min_slot);
            let (slot, hash) = match best {
                Some(v) => v,
                None => continue,
            };

            peers.entry(origin).or_insert(SnapshotPeerInfo {
                identity: origin,
                rpc_addr,
                full_snapshot: (slot, hash),
                incremental_snapshot: None,
            });
        }
    }

    /// Process IncrementalSnapshotHashes entries (type 10).
    fn process_incremental_entries(
        table: &CrdsTable,
        rpc_addrs: &HashMap<[u8; 32], SocketAddr>,
        min_slot: Option<u64>,
        peers: &mut HashMap<[u8; 32], SnapshotPeerInfo>,
    ) {
        for entry in table.entries_by_type(gossip::VALUE_TYPE_INCREMENTAL_SNAPSHOT_HASHES) {
            let origin = entry.key.origin;
            let rpc_addr = match rpc_addrs.get(&origin) {
                Some(addr) => *addr,
                None => continue,
            };

            let incr = match &entry.value.data {
                CrdsValueData::IncrementalSnapshotHashes(ih) => ih,
                _ => continue,
            };

            let (base_slot, base_hash) = incr.base;

            // Filter by min_slot on the base (full) snapshot.
            if let Some(min) = min_slot {
                if base_slot < min {
                    continue;
                }
            }

            // Find the best (highest slot) incremental hash.
            let best_incr = incr.hashes.iter().max_by_key(|(s, _)| *s).copied();

            let peer = peers.entry(origin).or_insert(SnapshotPeerInfo {
                identity: origin,
                rpc_addr,
                full_snapshot: (base_slot, base_hash),
                incremental_snapshot: None,
            });

            // Update full snapshot if this entry has a newer base.
            if base_slot > peer.full_snapshot.0 {
                peer.full_snapshot = (base_slot, base_hash);
                peer.incremental_snapshot = None;
            }

            // Set incremental if on the same base.
            if base_slot == peer.full_snapshot.0 {
                if let Some((incr_slot, incr_hash)) = best_incr {
                    match &peer.incremental_snapshot {
                        Some((_, existing_slot, _)) if *existing_slot >= incr_slot => {}
                        _ => {
                            peer.incremental_snapshot = Some((base_slot, incr_slot, incr_hash));
                        }
                    }
                }
            }
        }
    }

    /// Find the best (highest slot) hash from a SnapshotHashes entry.
    fn best_snapshot_hash(
        hashes: &SnapshotHashes,
        min_slot: Option<u64>,
    ) -> Option<(u64, [u8; 32])> {
        hashes
            .hashes
            .iter()
            .filter(|(s, _)| min_slot.is_none_or(|min| *s >= min))
            .max_by_key(|(s, _)| *s)
            .copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gossip::crds::{CrdsContactInfo, CrdsValue, EntryOrigin, IncrementalSnapshotHashes};

    fn make_contact_info_value(pubkey: [u8; 32], rpc_port: u16) -> CrdsValue {
        let mut ci = CrdsContactInfo {
            pubkey,
            ..Default::default()
        };
        ci.sockets[gossip::SOCKET_RPC] = Some(format!("127.0.0.1:{rpc_port}").parse().unwrap());

        CrdsValue {
            origin: pubkey,
            wallclock_nanos: 1_000_000_000,
            signature: [0u8; 64],
            data: CrdsValueData::ContactInfo(ci),
        }
    }

    fn make_snapshot_hashes_value(pubkey: [u8; 32], slot: u64, hash: [u8; 32]) -> CrdsValue {
        CrdsValue {
            origin: pubkey,
            wallclock_nanos: 1_000_000_000,
            signature: [0u8; 64],
            data: CrdsValueData::LegacySnapshotHashes(SnapshotHashes {
                hashes: vec![(slot, hash)],
            }),
        }
    }

    fn make_incremental_hashes_value(
        pubkey: [u8; 32],
        base_slot: u64,
        base_hash: [u8; 32],
        incr_slot: u64,
        incr_hash: [u8; 32],
    ) -> CrdsValue {
        CrdsValue {
            origin: pubkey,
            wallclock_nanos: 1_000_000_000,
            signature: [0u8; 64],
            data: CrdsValueData::IncrementalSnapshotHashes(IncrementalSnapshotHashes {
                base: (base_slot, base_hash),
                hashes: vec![(incr_slot, incr_hash)],
            }),
        }
    }

    fn insert(table: &mut CrdsTable, value: CrdsValue) {
        table.insert(value, 1000, 0, EntryOrigin::Push);
    }

    #[test]
    fn empty_table_returns_no_peers() {
        let table = CrdsTable::new();
        let peers = SnapshotPeerSelector::scan_crds(&table, None);
        assert!(peers.is_empty());
    }

    #[test]
    fn peer_without_rpc_addr_excluded() {
        let mut table = CrdsTable::new();
        let pk = [1u8; 32];
        insert(&mut table, make_snapshot_hashes_value(pk, 100, [0xAA; 32]));

        let peers = SnapshotPeerSelector::scan_crds(&table, None);
        assert!(peers.is_empty());
    }

    #[test]
    fn peer_with_rpc_and_snapshot_hashes_discovered() {
        let mut table = CrdsTable::new();
        let pk = [1u8; 32];

        insert(&mut table, make_contact_info_value(pk, 8899));
        insert(&mut table, make_snapshot_hashes_value(pk, 500, [0xBB; 32]));

        let peers = SnapshotPeerSelector::scan_crds(&table, None);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].identity, pk);
        assert_eq!(peers[0].full_snapshot.0, 500);
        assert_eq!(peers[0].full_snapshot.1, [0xBB; 32]);
        assert_eq!(
            peers[0].rpc_addr,
            "127.0.0.1:8899".parse::<SocketAddr>().unwrap()
        );
        assert!(peers[0].incremental_snapshot.is_none());
    }

    #[test]
    fn peers_sorted_by_slot_descending() {
        let mut table = CrdsTable::new();

        let pk_a = [1u8; 32];
        insert(&mut table, make_contact_info_value(pk_a, 8001));
        insert(
            &mut table,
            make_snapshot_hashes_value(pk_a, 100, [0xAA; 32]),
        );

        let pk_b = [2u8; 32];
        insert(&mut table, make_contact_info_value(pk_b, 8002));
        insert(
            &mut table,
            make_snapshot_hashes_value(pk_b, 300, [0xBB; 32]),
        );

        let pk_c = [3u8; 32];
        insert(&mut table, make_contact_info_value(pk_c, 8003));
        insert(
            &mut table,
            make_snapshot_hashes_value(pk_c, 200, [0xCC; 32]),
        );

        let peers = SnapshotPeerSelector::scan_crds(&table, None);
        assert_eq!(peers.len(), 3);
        assert_eq!(peers[0].full_snapshot.0, 300);
        assert_eq!(peers[1].full_snapshot.0, 200);
        assert_eq!(peers[2].full_snapshot.0, 100);
    }

    #[test]
    fn min_slot_filter() {
        let mut table = CrdsTable::new();

        let pk_a = [1u8; 32];
        insert(&mut table, make_contact_info_value(pk_a, 8001));
        insert(&mut table, make_snapshot_hashes_value(pk_a, 50, [0xAA; 32]));

        let pk_b = [2u8; 32];
        insert(&mut table, make_contact_info_value(pk_b, 8002));
        insert(
            &mut table,
            make_snapshot_hashes_value(pk_b, 200, [0xBB; 32]),
        );

        let peers = SnapshotPeerSelector::scan_crds(&table, Some(100));
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].identity, pk_b);
    }

    #[test]
    fn incremental_snapshot_discovered() {
        let mut table = CrdsTable::new();
        let pk = [5u8; 32];

        insert(&mut table, make_contact_info_value(pk, 9000));
        insert(
            &mut table,
            make_incremental_hashes_value(pk, 1000, [0xAA; 32], 1500, [0xBB; 32]),
        );

        let peers = SnapshotPeerSelector::scan_crds(&table, None);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].full_snapshot.0, 1000);
        assert_eq!(peers[0].full_snapshot.1, [0xAA; 32]);
        assert_eq!(
            peers[0].incremental_snapshot,
            Some((1000, 1500, [0xBB; 32]))
        );
    }

    #[test]
    fn best_snapshot_hash_picks_highest_slot() {
        let hashes = SnapshotHashes {
            hashes: vec![(100, [1u8; 32]), (300, [3u8; 32]), (200, [2u8; 32])],
        };
        let best = SnapshotPeerSelector::best_snapshot_hash(&hashes, None).unwrap();
        assert_eq!(best.0, 300);
        assert_eq!(best.1, [3u8; 32]);
    }

    #[test]
    fn best_snapshot_hash_respects_min_slot() {
        let hashes = SnapshotHashes {
            hashes: vec![(100, [1u8; 32]), (300, [3u8; 32]), (200, [2u8; 32])],
        };
        let best = SnapshotPeerSelector::best_snapshot_hash(&hashes, Some(250)).unwrap();
        assert_eq!(best.0, 300);

        let none = SnapshotPeerSelector::best_snapshot_hash(&hashes, Some(500));
        assert!(none.is_none());
    }

    #[test]
    fn multiple_snapshot_hash_entries_per_peer() {
        let hashes = SnapshotHashes {
            hashes: vec![(50, [0xAA; 32]), (150, [0xBB; 32])],
        };
        let best = SnapshotPeerSelector::best_snapshot_hash(&hashes, None).unwrap();
        assert_eq!(best.0, 150);
    }
}
