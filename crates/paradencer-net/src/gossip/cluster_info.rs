use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use super::crds::{
    CrdsContactInfo, CrdsTable, CrdsValue, CrdsValueData, EntryOrigin, GossipBloomFilter,
    InsertOutcome, PullRequestMask, VersionInfo,
};
use paradencer_constants::gossip;

pub const MAX_CLUSTER_SIZE: usize = 5000;
pub const CRDT_UPDATE_INTERVAL_MS: u64 = 100;
pub const GOSSIP_PRUNE_TIMEOUT_MS: u64 = 30_000;

/// Unique identifier for a node in the cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn random() -> Self {
        use sha2::{Digest, Sha256};
        use std::sync::atomic::{AtomicU64, Ordering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let count = COUNTER.fetch_add(1, Ordering::Relaxed);

        let mut hasher = Sha256::new();
        hasher.update(count.to_le_bytes());
        hasher.update(std::process::id().to_le_bytes());
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_base58(&self) -> String {
        bs58::encode(&self.0).into_string()
    }

    pub fn from_base58(s: &str) -> Result<Self, bs58::decode::Error> {
        let bytes = bs58::decode(s).into_vec()?;
        if bytes.len() != 32 {
            return Err(bs58::decode::Error::BufferTooSmall);
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(Self(array))
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.to_base58()[..8])
    }
}

/// Contact information for a validator node.
///
/// This is the high-level type used by the gossip service for peer
/// communication. Internally converted to/from CrdsValue for storage
/// in the CrdsTable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContactInfo {
    pub node_id: NodeId,
    pub gossip_addr: SocketAddr,
    pub tpu_addr: SocketAddr,
    pub tpu_quic_addr: SocketAddr,
    pub repair_addr: SocketAddr,
    pub rpc_addr: Option<SocketAddr>,
    pub version: u64,
    pub wallclock: u64,
    pub shred_version: u16,
}

impl ContactInfo {
    pub fn new(
        node_id: NodeId,
        gossip_addr: SocketAddr,
        tpu_addr: SocketAddr,
        tpu_quic_addr: SocketAddr,
        repair_addr: SocketAddr,
        shred_version: u16,
    ) -> Self {
        Self {
            node_id,
            gossip_addr,
            tpu_addr,
            tpu_quic_addr,
            repair_addr,
            rpc_addr: None,
            version: 0,
            wallclock: current_timestamp_ms(),
            shred_version,
        }
    }

    pub fn with_rpc_addr(mut self, rpc_addr: SocketAddr) -> Self {
        self.rpc_addr = Some(rpc_addr);
        self
    }

    pub fn is_valid(&self) -> bool {
        self.wallclock > 0 && self.version > 0
    }

    pub fn increment_version(&mut self) {
        self.version += 1;
        self.wallclock = current_timestamp_ms();
    }

    /// Convert to a CRDS value for storage in the CrdsTable.
    pub fn to_crds_value(&self) -> CrdsValue {
        let wallclock_nanos = (self.wallclock as i64) * 1_000_000; // ms → ns
        let mut sockets: [Option<SocketAddr>; gossip::CONTACT_INFO_SOCKET_COUNT] =
            Default::default();
        sockets[gossip::SOCKET_GOSSIP] = Some(self.gossip_addr);
        sockets[gossip::SOCKET_TPU] = Some(self.tpu_addr);
        sockets[gossip::SOCKET_TPU_QUIC] = Some(self.tpu_quic_addr);
        sockets[gossip::SOCKET_SERVE_REPAIR] = Some(self.repair_addr);
        if let Some(rpc) = self.rpc_addr {
            sockets[gossip::SOCKET_RPC] = Some(rpc);
        }

        CrdsValue {
            origin: self.node_id.0,
            wallclock_nanos,
            signature: [0u8; 64], // signed by ClusterInfo::sign_value() or signed_self_value()
            data: CrdsValueData::ContactInfo(CrdsContactInfo {
                pubkey: self.node_id.0,
                shred_version: self.shred_version,
                instance_creation_nanos: wallclock_nanos,
                wallclock_nanos,
                sockets,
                version: VersionInfo::default(),
            }),
        }
    }

    /// Convert from a CRDS entry's contact info data.
    pub fn from_crds_contact_info(ci: &CrdsContactInfo) -> Option<Self> {
        let gossip_addr = ci.sockets[gossip::SOCKET_GOSSIP]?;
        let tpu_addr = ci.sockets[gossip::SOCKET_TPU].unwrap_or(gossip_addr);
        let tpu_quic_addr = ci.sockets[gossip::SOCKET_TPU_QUIC].unwrap_or(gossip_addr);
        let repair_addr = ci.sockets[gossip::SOCKET_SERVE_REPAIR].unwrap_or(gossip_addr);
        let rpc_addr = ci.sockets[gossip::SOCKET_RPC];

        let wallclock_ms = (ci.wallclock_nanos / 1_000_000) as u64;

        let mut info = ContactInfo {
            node_id: NodeId(ci.pubkey),
            gossip_addr,
            tpu_addr,
            tpu_quic_addr,
            repair_addr,
            rpc_addr,
            version: 0,
            wallclock: wallclock_ms,
            shred_version: ci.shred_version,
        };
        info.version = ci.version.major as u64;
        Some(info)
    }
}

/// Validator information with stake and performance metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub contact_info: ContactInfo,
    pub stake: u64,
}

impl ValidatorInfo {
    pub fn new(contact_info: ContactInfo, stake: u64) -> Self {
        Self {
            contact_info,
            stake,
        }
    }
}

/// Gossip node with routing information.
#[derive(Debug, Clone)]
pub struct GossipNode {
    pub info: ValidatorInfo,
    pub failed_pushes: u64,
}

impl GossipNode {
    pub fn new(info: ValidatorInfo) -> Self {
        Self {
            info,
            failed_pushes: 0,
        }
    }
}

/// Tracks which CRDS value origins should be excluded when pushing to
/// specific destination nodes. Populated from received prune messages.
///
/// Key: destination node pubkey (the peer we push to).
/// Value: map of origin pubkey → expiration timestamp (millis).
///
/// When a peer sends us a prune message saying "stop forwarding origin X
/// to me", we store (peer, X) → expiration. On each push cycle, values
/// whose origin is in the prune set for a given target are excluded.
struct PruneMap {
    /// destination → (origin → expiration_ms)
    entries: HashMap<[u8; 32], HashMap<[u8; 32], u64>>,
}

impl PruneMap {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Record prune origins for a destination. The prune message tells us
    /// that `destination` no longer wants values from these `origins`.
    fn record(&mut self, destination: [u8; 32], origins: &[[u8; 32]], expiration_ms: u64) {
        let dest_map = self.entries.entry(destination).or_default();
        for &origin in origins {
            dest_map.insert(origin, expiration_ms);
        }
        // Enforce per-destination limit.
        if dest_map.len() > gossip::MAX_PRUNE_ENTRIES_PER_DEST {
            // Evict oldest entries.
            let mut pairs: Vec<_> = dest_map.iter().map(|(&k, &v)| (k, v)).collect();
            pairs.sort_by_key(|(_, exp)| *exp);
            let to_remove = pairs.len() - gossip::MAX_PRUNE_ENTRIES_PER_DEST;
            for (key, _) in pairs.into_iter().take(to_remove) {
                dest_map.remove(&key);
            }
        }
    }

    /// Check if an origin should be excluded when pushing to a destination.
    fn is_pruned(&self, destination: &[u8; 32], origin: &[u8; 32], now_ms: u64) -> bool {
        if let Some(dest_map) = self.entries.get(destination) {
            if let Some(&expiration) = dest_map.get(origin) {
                return now_ms < expiration;
            }
        }
        false
    }

    /// Remove expired prune entries. Returns total number of entries removed.
    fn expire(&mut self, now_ms: u64) -> usize {
        let mut removed = 0;
        self.entries.retain(|_, dest_map| {
            let before = dest_map.len();
            dest_map.retain(|_, expiration| *expiration > now_ms);
            removed += before - dest_map.len();
            !dest_map.is_empty()
        });
        removed
    }

    /// Total active prune entries across all destinations.
    fn total_entries(&self) -> usize {
        self.entries.values().map(|m| m.len()).sum()
    }
}

/// Cluster information storage backed by CrdsTable.
///
/// Provides a higher-level API for the gossip service while using the
/// multi-index CrdsTable for efficient storage, expiration, eviction,
/// and bloom filter operations.
pub struct ClusterInfo {
    node_id: NodeId,
    self_contact_info: Arc<RwLock<ContactInfo>>,
    table: Arc<RwLock<CrdsTable>>,
    max_nodes: usize,
    /// Ed25519 secret key (32-byte seed) for signing our own CRDS values.
    /// None when running without signing (e.g. tests that don't need it).
    signing_key: Option<[u8; 32]>,
    /// Tracks prune origins per destination for push filtering.
    prune_map: RwLock<PruneMap>,
    /// Prune entry duration (milliseconds from wallclock).
    prune_timeout_ms: u64,
}

impl ClusterInfo {
    pub fn new(
        node_id: NodeId,
        contact_info: ContactInfo,
        prune_timeout: Duration,
        max_nodes: usize,
    ) -> Self {
        let table = CrdsTable::with_limits(max_nodes, gossip::MAX_PURGED_ENTRIES);
        Self {
            node_id,
            self_contact_info: Arc::new(RwLock::new(contact_info)),
            table: Arc::new(RwLock::new(table)),
            max_nodes,
            signing_key: None,
            prune_map: RwLock::new(PruneMap::new()),
            prune_timeout_ms: prune_timeout.as_millis() as u64,
        }
    }

    /// Create a ClusterInfo with an Ed25519 signing key for CRDS value signatures.
    pub fn with_signing_key(
        node_id: NodeId,
        contact_info: ContactInfo,
        prune_timeout: Duration,
        max_nodes: usize,
        signing_key: [u8; 32],
    ) -> Self {
        let table = CrdsTable::with_limits(max_nodes, gossip::MAX_PURGED_ENTRIES);
        Self {
            node_id,
            self_contact_info: Arc::new(RwLock::new(contact_info)),
            table: Arc::new(RwLock::new(table)),
            max_nodes,
            signing_key: Some(signing_key),
            prune_map: RwLock::new(PruneMap::new()),
            prune_timeout_ms: prune_timeout.as_millis() as u64,
        }
    }

    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Access the Ed25519 signing key (if configured).
    pub fn signing_key(&self) -> Option<&[u8; 32]> {
        self.signing_key.as_ref()
    }

    pub fn self_contact_info(&self) -> ContactInfo {
        self.self_contact_info.read().clone()
    }

    pub fn update_self_contact_info<F>(&self, update_fn: F)
    where
        F: FnOnce(&mut ContactInfo),
    {
        let mut info = self.self_contact_info.write();
        update_fn(&mut info);
        info.increment_version();
    }

    /// Sign a CRDS value with our keypair (if available).
    fn sign_value(&self, value: &mut CrdsValue) {
        if let Some(ref key) = self.signing_key {
            value.sign(key);
        }
    }

    /// Create a signed CRDS value from our own contact info.
    pub fn signed_self_value(&self) -> CrdsValue {
        let info = self.self_contact_info.read();
        let mut value = info.to_crds_value();
        self.sign_value(&mut value);
        value
    }

    /// Insert or update contact info using the CrdsTable.
    pub fn insert(&self, contact_info: ContactInfo) -> bool {
        if contact_info.node_id == self.node_id {
            return false;
        }

        let crds_value = contact_info.to_crds_value();
        let now_nanos = current_timestamp_nanos();
        let mut table = self.table.write();

        matches!(
            table.insert(crds_value, 0, now_nanos, EntryOrigin::Push),
            InsertOutcome::Inserted | InsertOutcome::Updated
        )
    }

    /// Insert a CRDS value directly into the table.
    pub fn insert_crds_value(&self, value: CrdsValue, stake: u64) -> InsertOutcome {
        let now_nanos = current_timestamp_nanos();
        let mut table = self.table.write();
        table.insert(value, stake, now_nanos, EntryOrigin::Push)
    }

    /// Insert multiple contact infos (batch operation).
    pub fn insert_batch(&self, infos: Vec<ContactInfo>) -> usize {
        let now_nanos = current_timestamp_nanos();
        let mut table = self.table.write();
        let mut count = 0;
        for info in infos {
            if info.node_id == self.node_id {
                continue;
            }
            let crds_value = info.to_crds_value();
            match table.insert(crds_value, 0, now_nanos, EntryOrigin::Push) {
                InsertOutcome::Inserted | InsertOutcome::Updated => count += 1,
                _ => {}
            }
        }
        count
    }

    /// Get a contact info by node ID.
    pub fn get(&self, node_id: &NodeId) -> Option<ContactInfo> {
        let table = self.table.read();
        let key = super::crds::CrdsKey::new(gossip::VALUE_TYPE_CONTACT_INFO, node_id.0);
        table
            .get_value(&key)
            .and_then(|v| v.data.as_contact_info())
            .and_then(ContactInfo::from_crds_contact_info)
    }

    /// Get all contact infos from the CRDS table.
    pub fn get_all(&self) -> Vec<ContactInfo> {
        let table = self.table.read();
        table
            .contact_info_entries()
            .into_iter()
            .filter_map(|entry| {
                entry
                    .value
                    .data
                    .as_contact_info()
                    .and_then(ContactInfo::from_crds_contact_info)
            })
            .collect()
    }

    /// Get random subset of nodes for push/pull gossip using weighted sampling.
    pub fn get_random_nodes(&self, count: usize, exclude: &HashSet<NodeId>) -> Vec<ContactInfo> {
        let table = self.table.read();
        let all_contacts: Vec<_> = table
            .contact_info_entries()
            .into_iter()
            .filter_map(|entry| {
                entry
                    .value
                    .data
                    .as_contact_info()
                    .and_then(ContactInfo::from_crds_contact_info)
            })
            .filter(|info| !exclude.contains(&info.node_id))
            .collect();

        if all_contacts.len() <= count {
            return all_contacts;
        }

        // Use pull sampler for weighted random selection
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut selected = Vec::with_capacity(count);
        let mut seen = HashSet::new();

        for _ in 0..count * 4 {
            if selected.len() >= count {
                break;
            }
            let random_value: u64 = rng.gen();
            if let Some(peer_idx) = table.sample_pull_peer(random_value) {
                if seen.insert(peer_idx) {
                    // Get the value at this index
                    if let Some(entry) = table.entries_at(peer_idx) {
                        if let Some(ci) = entry
                            .value
                            .data
                            .as_contact_info()
                            .and_then(ContactInfo::from_crds_contact_info)
                        {
                            if !exclude.contains(&ci.node_id) {
                                selected.push(ci);
                            }
                        }
                    }
                }
            }
        }

        // Fallback to simple random if sampler didn't provide enough
        if selected.len() < count {
            use rand::seq::SliceRandom;
            let mut remaining: Vec<_> = all_contacts
                .into_iter()
                .filter(|ci| !selected.iter().any(|s| s.node_id == ci.node_id))
                .collect();
            remaining.shuffle(&mut rng);
            for ci in remaining {
                if selected.len() >= count {
                    break;
                }
                selected.push(ci);
            }
        }

        selected
    }

    /// Get all active nodes.
    pub fn get_active_nodes(&self) -> Vec<ContactInfo> {
        self.get_all()
    }

    /// Run expiration on the CRDS table (replaces time-based prune).
    pub fn prune_stale_nodes(&self) -> usize {
        let now_nanos = current_timestamp_nanos();
        let mut table = self.table.write();
        table.advance(now_nanos)
    }

    /// Update node last seen time by re-inserting its contact info.
    pub fn update_last_seen(&self, _node_id: &NodeId) {
        // In CrdsTable, freshness is tracked by received_at_nanos.
        // A push/pull response re-insert already updates this.
        // No separate action needed.
    }

    /// Record push success for a node.
    pub fn record_push_success(&self, _node_id: &NodeId) {
        // Push health is tracked externally by the service stats.
    }

    /// Record push failure for a node.
    pub fn record_push_failure(&self, _node_id: &NodeId) {
        // Push health is tracked externally by the service stats.
    }

    /// Add an entrypoint peer to bootstrap gossip discovery.
    ///
    /// Creates a minimal ContactInfo for the peer using a placeholder
    /// NodeId (all-zeros) and the given gossip socket address. Once the
    /// peer responds to a pull request, its real ContactInfo (with actual
    /// NodeId, TPU, repair addresses, etc.) will replace this stub entry.
    ///
    /// This must be called before starting the gossip service so that the
    /// push/pull loops have at least one target to talk to.
    pub fn add_entrypoint(&self, gossip_addr: SocketAddr) {
        // Use a synthetic NodeId derived from the address so that each
        // entrypoint gets its own CRDS slot and doesn't clobber others.
        let mut node_bytes = [0u8; 32];
        let addr_str = gossip_addr.to_string();
        let addr_hash = paradencer_crypto::sha256::Sha256Hasher::hash(addr_str.as_bytes());
        node_bytes.copy_from_slice(&addr_hash);
        let entrypoint_id = NodeId::new(node_bytes);

        let info = ContactInfo::new(
            entrypoint_id,
            gossip_addr,
            gossip_addr, // placeholder TPU
            gossip_addr, // placeholder QUIC
            gossip_addr, // placeholder repair
            0,           // shred_version unknown until handshake
        );
        self.insert(info);
    }

    /// Add multiple entrypoint peers for bootstrap gossip discovery.
    pub fn add_entrypoints(&self, addrs: &[SocketAddr]) {
        for addr in addrs {
            self.add_entrypoint(*addr);
        }
    }

    /// Return the current CRDS table cursor.
    ///
    /// Use with `values_since_cursor()` to efficiently retrieve only
    /// new or updated values for the push gossip loop.
    pub fn cursor(&self) -> u64 {
        self.table.read().cursor()
    }

    /// Return CRDS values inserted/updated since the given cursor.
    ///
    /// Returns cloned values and the new cursor position. Callers should
    /// store the returned cursor for subsequent calls.
    pub fn values_since_cursor(&self, since: u64) -> (Vec<CrdsValue>, u64) {
        let table = self.table.read();
        let (refs, new_cursor) = table.values_since(since);
        let values = refs.into_iter().cloned().collect();
        (values, new_cursor)
    }

    /// Get cluster size.
    pub fn size(&self) -> usize {
        let table = self.table.read();
        table.contact_info_entries().len()
    }

    /// Get total CRDS table entry count (all types).
    pub fn total_entries(&self) -> usize {
        self.table.read().len()
    }

    /// Clear all entries.
    pub fn clear(&self) {
        // Create a fresh table
        let new_table = CrdsTable::with_limits(self.max_nodes, gossip::MAX_PURGED_ENTRIES);
        *self.table.write() = new_table;
    }

    /// Record prune origins from a validated prune message.
    ///
    /// After this call, values from `origins` will be excluded when
    /// pushing to `destination` until the prune entry expires.
    pub fn record_prune(&self, destination: [u8; 32], origins: &[[u8; 32]], wallclock_ms: u64) {
        let expiration = wallclock_ms + self.prune_timeout_ms;
        self.prune_map
            .write()
            .record(destination, origins, expiration);
    }

    /// Check if a value origin should be excluded when pushing to a target.
    pub fn is_origin_pruned(&self, destination: &[u8; 32], origin: &[u8; 32]) -> bool {
        let now_ms = current_timestamp_ms();
        self.prune_map.read().is_pruned(destination, origin, now_ms)
    }

    /// Remove expired prune entries. Returns the number removed.
    pub fn expire_prune_entries(&self) -> usize {
        let now_ms = current_timestamp_ms();
        self.prune_map.write().expire(now_ms)
    }

    /// Total number of active prune entries.
    pub fn prune_entry_count(&self) -> usize {
        self.prune_map.read().total_entries()
    }

    /// Build a bloom filter for a pull request.
    pub fn build_pull_filter(&self) -> (GossipBloomFilter, PullRequestMask) {
        let table = self.table.read();
        let mask = PullRequestMask::full();
        let filter = table.build_pull_filter(&mask);
        (filter, mask)
    }

    /// Find CRDS values not present in the requester's bloom filter.
    pub fn filter_for_pull_response(
        &self,
        filter: &GossipBloomFilter,
        mask: &PullRequestMask,
        max_count: usize,
    ) -> Vec<ContactInfo> {
        let table = self.table.read();
        table
            .filter_for_pull_response(filter, mask, max_count)
            .into_iter()
            .filter_map(|v| {
                v.data
                    .as_contact_info()
                    .and_then(ContactInfo::from_crds_contact_info)
            })
            .collect()
    }

    /// Publish a vote transaction to the gossip network.
    ///
    /// Creates a signed Vote CRDS value and inserts it into the table.
    /// The value will be picked up by the push loop and broadcast to peers.
    /// `vote_index` selects which slot (0..31) this vote occupies per node.
    pub fn publish_vote(&self, vote_index: u8, transaction_bytes: Vec<u8>) {
        let now_nanos = current_timestamp_nanos();
        let mut value = CrdsValue {
            origin: self.node_id.0,
            wallclock_nanos: now_nanos,
            signature: [0u8; 64],
            data: CrdsValueData::Vote(super::crds::VoteGossip {
                index: vote_index,
                slot: 0,
                hash: [0u8; 32],
                transaction_bytes,
            }),
        };
        self.sign_value(&mut value);
        let mut table = self.table.write();
        table.insert(value, 0, now_nanos, EntryOrigin::Push);
    }

    /// Publish a duplicate shred proof to the gossip network.
    ///
    /// Creates a signed DuplicateShred CRDS value and inserts it into the
    /// table. Broadcast is handled by the push loop.
    pub fn publish_duplicate_shred(&self, index: u16, proof_bytes: Vec<u8>) {
        let now_nanos = current_timestamp_nanos();
        let mut value = CrdsValue {
            origin: self.node_id.0,
            wallclock_nanos: now_nanos,
            signature: [0u8; 64],
            data: CrdsValueData::DuplicateShred(super::crds::DuplicateShredProof {
                index,
                proof_bytes,
            }),
        };
        self.sign_value(&mut value);
        let mut table = self.table.write();
        table.insert(value, 0, now_nanos, EntryOrigin::Push);
    }

    /// Publish epoch slots to the gossip network.
    ///
    /// Advertises which slots this node has available in the current epoch.
    /// `epoch_index` selects which epoch slots entry (0..255) to use,
    /// allowing multiple entries per node for large slot ranges.
    /// `compressed_slots` is the bincode-serialized compressed slot bitmap.
    pub fn publish_epoch_slots(&self, epoch_index: u8, compressed_slots: Vec<u8>) {
        let now_nanos = current_timestamp_nanos();
        let mut value = CrdsValue {
            origin: self.node_id.0,
            wallclock_nanos: now_nanos,
            signature: [0u8; 64],
            data: CrdsValueData::EpochSlots(super::crds::EpochSlots {
                index: epoch_index,
                slots: compressed_slots,
            }),
        };
        self.sign_value(&mut value);
        let mut table = self.table.write();
        table.insert(value, 0, now_nanos, EntryOrigin::Push);
    }

    /// Publish this node's version information to the gossip network.
    ///
    /// Creates a signed Version CRDS value so peers know our software
    /// version and feature set. Broadcast is handled by the push loop.
    pub fn publish_version(&self, version: VersionInfo) {
        let now_nanos = current_timestamp_nanos();
        let mut value = CrdsValue {
            origin: self.node_id.0,
            wallclock_nanos: now_nanos,
            signature: [0u8; 64],
            data: CrdsValueData::Version(version),
        };
        self.sign_value(&mut value);
        let mut table = self.table.write();
        table.insert(value, 0, now_nanos, EntryOrigin::Push);
    }

    /// Publish snapshot hashes to the gossip network.
    ///
    /// Advertises the base full snapshot and any incremental snapshots
    /// available from this node. Used by other validators discovering
    /// snapshot sources for bootstrap.
    pub fn publish_snapshot_hashes(
        &self,
        base: (u64, [u8; 32]),
        incremental: Vec<(u64, [u8; 32])>,
    ) {
        let now_nanos = current_timestamp_nanos();
        let mut value = CrdsValue {
            origin: self.node_id.0,
            wallclock_nanos: now_nanos,
            signature: [0u8; 64],
            data: CrdsValueData::IncrementalSnapshotHashes(
                super::crds::IncrementalSnapshotHashes {
                    base,
                    hashes: incremental,
                },
            ),
        };
        self.sign_value(&mut value);
        let mut table = self.table.write();
        table.insert(value, 0, now_nanos, EntryOrigin::Push);
    }

    /// Refresh the self ContactInfo entry with an updated wallclock.
    ///
    /// Called periodically (every ~7.5s) to maintain freshness. Updates
    /// the wallclock timestamp and re-inserts into the CRDS table as a
    /// new value that will be picked up by the push loop.
    pub fn refresh_self_contact_info(&self) {
        let mut info = self.self_contact_info.write();
        info.wallclock = current_timestamp_ms();
    }

    /// Look up a node's identity by their repair socket address.
    ///
    /// Scans all contact info entries for a matching repair address.
    /// Returns `None` if no node has a matching repair address.
    pub fn lookup_by_repair_addr(&self, addr: &SocketAddr) -> Option<NodeId> {
        let table = self.table.read();
        table
            .contact_info_entries()
            .into_iter()
            .filter_map(|entry| {
                entry
                    .value
                    .data
                    .as_contact_info()
                    .and_then(ContactInfo::from_crds_contact_info)
            })
            .find(|info| info.repair_addr == *addr)
            .map(|info| info.node_id)
    }

    /// Access the underlying CRDS table (for advanced operations).
    pub fn crds_table(&self) -> &Arc<RwLock<CrdsTable>> {
        &self.table
    }

    /// Return all CRDS values matching a pull filter (all types, not just ContactInfo).
    ///
    /// This is used for pull responses where we need to return any value type
    /// that the requester doesn't already have.
    pub fn filter_all_values_for_pull(
        &self,
        filter: &GossipBloomFilter,
        mask: &PullRequestMask,
        max_count: usize,
    ) -> Vec<CrdsValue> {
        let table = self.table.read();
        table
            .filter_for_pull_response(filter, mask, max_count)
            .into_iter()
            .cloned()
            .collect()
    }
}

fn current_timestamp_ms() -> u64 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn current_timestamp_nanos() -> i64 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn create_test_contact_info(node_id: NodeId, port: u16) -> ContactInfo {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
        ContactInfo::new(node_id, addr, addr, addr, addr, 1)
    }

    #[test]
    fn test_node_id_creation() {
        let bytes = [1u8; 32];
        let node_id = NodeId::new(bytes);
        assert_eq!(node_id.as_bytes(), &bytes);
    }

    #[test]
    fn test_node_id_base58() {
        let node_id = NodeId::new([0u8; 32]);
        let base58 = node_id.to_base58();
        let decoded = NodeId::from_base58(&base58).unwrap();
        assert_eq!(node_id, decoded);
    }

    #[test]
    fn test_contact_info_creation() {
        let node_id = NodeId::new([1u8; 32]);
        let info = create_test_contact_info(node_id, 8000);
        assert_eq!(info.node_id, node_id);
        assert_eq!(info.version, 0);
        assert!(info.wallclock > 0);
    }

    #[test]
    fn test_cluster_info_insert() {
        let self_node_id = NodeId::new([0u8; 32]);
        let self_info = create_test_contact_info(self_node_id, 8000);
        let cluster = ClusterInfo::new(
            self_node_id,
            self_info,
            Duration::from_secs(30),
            MAX_CLUSTER_SIZE,
        );

        let peer_node_id = NodeId::new([1u8; 32]);
        let peer_info = create_test_contact_info(peer_node_id, 8001);
        assert!(cluster.insert(peer_info));
        assert_eq!(cluster.size(), 1);

        let retrieved = cluster.get(&peer_node_id).unwrap();
        assert_eq!(retrieved.node_id, peer_node_id);
    }

    #[test]
    fn test_cluster_info_crdt_merge() {
        let self_node_id = NodeId::new([0u8; 32]);
        let self_info = create_test_contact_info(self_node_id, 8000);
        let cluster = ClusterInfo::new(
            self_node_id,
            self_info,
            Duration::from_secs(30),
            MAX_CLUSTER_SIZE,
        );

        let peer_node_id = NodeId::new([1u8; 32]);
        let mut peer_info_v1 = create_test_contact_info(peer_node_id, 8001);
        peer_info_v1.version = 1;
        assert!(cluster.insert(peer_info_v1));

        // Insert with newer wallclock (different port to verify update)
        let mut peer_info_v2 = create_test_contact_info(peer_node_id, 8002);
        peer_info_v2.version = 2;
        // Make wallclock strictly newer
        peer_info_v2.wallclock += 1;
        assert!(cluster.insert(peer_info_v2));

        let retrieved = cluster.get(&peer_node_id).unwrap();
        assert_eq!(retrieved.gossip_addr.port(), 8002);
    }

    #[test]
    fn test_cluster_info_no_self_insert() {
        let self_node_id = NodeId::new([0u8; 32]);
        let self_info = create_test_contact_info(self_node_id, 8000);
        let cluster = ClusterInfo::new(
            self_node_id,
            self_info.clone(),
            Duration::from_secs(30),
            MAX_CLUSTER_SIZE,
        );

        assert!(!cluster.insert(self_info));
        assert_eq!(cluster.size(), 0);
    }

    #[test]
    fn test_cluster_info_batch_insert() {
        let self_node_id = NodeId::new([0u8; 32]);
        let self_info = create_test_contact_info(self_node_id, 8000);
        let cluster = ClusterInfo::new(
            self_node_id,
            self_info,
            Duration::from_secs(30),
            MAX_CLUSTER_SIZE,
        );

        let infos: Vec<_> = (1..=10)
            .map(|i| {
                let node_id = NodeId::new([i as u8; 32]);
                create_test_contact_info(node_id, 8000 + i)
            })
            .collect();

        let count = cluster.insert_batch(infos);
        assert_eq!(count, 10);
        assert_eq!(cluster.size(), 10);
    }

    #[test]
    fn test_contact_info_crds_roundtrip() {
        let node_id = NodeId::new([42u8; 32]);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9000);
        let tpu = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9001);
        let quic = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9002);
        let repair = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9003);
        let info = ContactInfo::new(node_id, addr, tpu, quic, repair, 42);

        let crds_value = info.to_crds_value();
        let crds_ci = crds_value.data.as_contact_info().unwrap();
        let roundtrip = ContactInfo::from_crds_contact_info(crds_ci).unwrap();

        assert_eq!(roundtrip.node_id, node_id);
        assert_eq!(roundtrip.gossip_addr, addr);
        assert_eq!(roundtrip.tpu_addr, tpu);
        assert_eq!(roundtrip.tpu_quic_addr, quic);
        assert_eq!(roundtrip.repair_addr, repair);
        assert_eq!(roundtrip.shred_version, 42);
    }

    #[test]
    fn test_signed_self_value() {
        let (secret, pubkey) = paradencer_crypto::generate_keypair();
        let node_id = NodeId(pubkey);
        let info = create_test_contact_info(node_id, 8000);
        let cluster = ClusterInfo::with_signing_key(
            node_id,
            info,
            Duration::from_secs(30),
            MAX_CLUSTER_SIZE,
            secret,
        );

        let signed = cluster.signed_self_value();
        assert_eq!(signed.origin, pubkey);
        assert!(signed.verify_signature());
    }

    #[test]
    fn test_signed_self_value_no_key() {
        let node_id = NodeId::new([0u8; 32]);
        let info = create_test_contact_info(node_id, 8000);
        let cluster = ClusterInfo::new(node_id, info, Duration::from_secs(30), MAX_CLUSTER_SIZE);

        let value = cluster.signed_self_value();
        // Without a signing key, signature should be zeros (unverifiable)
        assert_eq!(value.signature, [0u8; 64]);
    }

    #[test]
    fn test_add_entrypoint() {
        let self_node_id = NodeId::new([0u8; 32]);
        let self_info = create_test_contact_info(self_node_id, 8000);
        let cluster = ClusterInfo::new(
            self_node_id,
            self_info,
            Duration::from_secs(30),
            MAX_CLUSTER_SIZE,
        );

        let ep_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8001);
        cluster.add_entrypoint(ep_addr);

        // The entrypoint should appear as a peer
        assert_eq!(cluster.size(), 1);

        // The peer's gossip address should match the entrypoint
        let peers = cluster.get_all();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].gossip_addr, ep_addr);
    }

    #[test]
    fn test_add_multiple_entrypoints() {
        let self_node_id = NodeId::new([0u8; 32]);
        let self_info = create_test_contact_info(self_node_id, 8000);
        let cluster = ClusterInfo::new(
            self_node_id,
            self_info,
            Duration::from_secs(30),
            MAX_CLUSTER_SIZE,
        );

        let addrs = vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8001),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 8002),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), 8003),
        ];
        cluster.add_entrypoints(&addrs);

        // Each entrypoint gets a unique synthetic NodeId so all 3 appear
        assert_eq!(cluster.size(), 3);
    }

    #[test]
    fn test_add_entrypoint_idempotent() {
        let self_node_id = NodeId::new([0u8; 32]);
        let self_info = create_test_contact_info(self_node_id, 8000);
        let cluster = ClusterInfo::new(
            self_node_id,
            self_info,
            Duration::from_secs(30),
            MAX_CLUSTER_SIZE,
        );

        let ep_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8001);
        cluster.add_entrypoint(ep_addr);
        cluster.add_entrypoint(ep_addr);

        // Same address produces the same synthetic NodeId, so it's an update
        assert_eq!(cluster.size(), 1);
    }

    #[test]
    fn test_cluster_info_bloom_filter() {
        let self_node_id = NodeId::new([0u8; 32]);
        let self_info = create_test_contact_info(self_node_id, 8000);
        let cluster = ClusterInfo::new(
            self_node_id,
            self_info,
            Duration::from_secs(30),
            MAX_CLUSTER_SIZE,
        );

        for i in 1u8..=5 {
            let info = create_test_contact_info(NodeId::new([i; 32]), 8000 + i as u16);
            cluster.insert(info);
        }

        let (filter, _mask) = cluster.build_pull_filter();
        assert!(filter.bits_set() > 0);
    }

    // -- Prune map tests --

    #[test]
    fn prune_map_records_and_checks() {
        let mut pm = PruneMap::new();
        let dest = [1u8; 32];
        let origin_a = [2u8; 32];
        let origin_b = [3u8; 32];
        let origin_c = [4u8; 32];

        pm.record(dest, &[origin_a, origin_b], 1000 + 30_000); // expires at 31000

        assert!(pm.is_pruned(&dest, &origin_a, 1000));
        assert!(pm.is_pruned(&dest, &origin_b, 1000));
        assert!(!pm.is_pruned(&dest, &origin_c, 1000));

        // Different destination is not pruned.
        let other_dest = [99u8; 32];
        assert!(!pm.is_pruned(&other_dest, &origin_a, 1000));
    }

    #[test]
    fn prune_map_expires_entries() {
        let mut pm = PruneMap::new();
        let dest = [1u8; 32];
        let origin = [2u8; 32];

        // Expires at 31000.
        pm.record(dest, &[origin], 31_000);

        assert!(pm.is_pruned(&dest, &origin, 30_000));
        assert!(!pm.is_pruned(&dest, &origin, 31_001)); // expired

        let removed = pm.expire(31_001);
        assert_eq!(removed, 1);
        assert_eq!(pm.total_entries(), 0);
    }

    #[test]
    fn prune_map_enforces_per_dest_limit() {
        let mut pm = PruneMap::new();
        let dest = [1u8; 32];

        // Add more than MAX_PRUNE_ENTRIES_PER_DEST entries.
        let limit = gossip::MAX_PRUNE_ENTRIES_PER_DEST;
        let origins: Vec<[u8; 32]> = (0..limit + 50)
            .map(|i| {
                let mut o = [0u8; 32];
                o[0] = (i >> 8) as u8;
                o[1] = (i & 0xFF) as u8;
                o
            })
            .collect();

        pm.record(dest, &origins, 50_000);

        // Should be capped at the limit.
        assert_eq!(pm.total_entries(), limit);
    }

    #[test]
    fn publish_vote_inserts_into_table() {
        let (secret, pubkey) = paradencer_crypto::generate_keypair();
        let node_id = NodeId(pubkey);
        let info = create_test_contact_info(node_id, 8000);
        let cluster = ClusterInfo::with_signing_key(
            node_id,
            info,
            Duration::from_secs(30),
            MAX_CLUSTER_SIZE,
            secret,
        );

        let tx_bytes = vec![1, 2, 3, 4, 5]; // mock transaction
        cluster.publish_vote(0, tx_bytes.clone());

        // Check the vote was inserted into the CRDS table.
        assert!(cluster.total_entries() >= 1);

        // Verify we can retrieve it via cursor-based pull.
        let (values, _cursor) = cluster.values_since_cursor(0);
        let vote_count = values
            .iter()
            .filter(|v| matches!(v.data, CrdsValueData::Vote(_)))
            .count();
        assert_eq!(vote_count, 1);
    }

    #[test]
    fn publish_duplicate_shred_inserts_into_table() {
        let (secret, pubkey) = paradencer_crypto::generate_keypair();
        let node_id = NodeId(pubkey);
        let info = create_test_contact_info(node_id, 8000);
        let cluster = ClusterInfo::with_signing_key(
            node_id,
            info,
            Duration::from_secs(30),
            MAX_CLUSTER_SIZE,
            secret,
        );

        let proof = vec![0xDE, 0xAD, 0xBE, 0xEF];
        cluster.publish_duplicate_shred(0, proof);

        let (values, _cursor) = cluster.values_since_cursor(0);
        let ds_count = values
            .iter()
            .filter(|v| matches!(v.data, CrdsValueData::DuplicateShred(_)))
            .count();
        assert_eq!(ds_count, 1);
    }

    #[test]
    fn refresh_self_contact_info_updates_wallclock() {
        let node_id = NodeId::new([0u8; 32]);
        let info = create_test_contact_info(node_id, 8000);
        let original_wallclock = info.wallclock;
        let cluster = ClusterInfo::new(node_id, info, Duration::from_secs(30), MAX_CLUSTER_SIZE);

        // Wait a tiny bit to ensure wallclock changes.
        std::thread::sleep(Duration::from_millis(2));

        cluster.refresh_self_contact_info();
        let refreshed = cluster.self_contact_info();
        assert!(refreshed.wallclock >= original_wallclock);
    }

    #[test]
    fn lookup_by_repair_addr_finds_peer() {
        let self_node_id = NodeId::new([0u8; 32]);
        let self_info = create_test_contact_info(self_node_id, 8000);
        let cluster = ClusterInfo::new(
            self_node_id,
            self_info,
            Duration::from_secs(30),
            MAX_CLUSTER_SIZE,
        );

        let peer_id = NodeId::new([1u8; 32]);
        let repair_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9003);
        let peer_info = ContactInfo::new(
            peer_id,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9000),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9001),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9002),
            repair_addr,
            1,
        );
        cluster.insert(peer_info);

        let found = cluster.lookup_by_repair_addr(&repair_addr);
        assert_eq!(found, Some(peer_id));

        // Unknown address returns None.
        let unknown = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)), 5555);
        assert_eq!(cluster.lookup_by_repair_addr(&unknown), None);
    }

    #[test]
    fn publish_epoch_slots_inserts_into_table() {
        let (secret, pubkey) = paradencer_crypto::generate_keypair();
        let node_id = NodeId(pubkey);
        let info = create_test_contact_info(node_id, 8000);
        let cluster = ClusterInfo::with_signing_key(
            node_id,
            info,
            Duration::from_secs(30),
            MAX_CLUSTER_SIZE,
            secret,
        );

        let compressed = vec![0xFF; 16]; // mock compressed slot bitmap
        cluster.publish_epoch_slots(0, compressed);

        let (values, _cursor) = cluster.values_since_cursor(0);
        let epoch_count = values
            .iter()
            .filter(|v| matches!(v.data, CrdsValueData::EpochSlots(_)))
            .count();
        assert_eq!(epoch_count, 1);
    }

    #[test]
    fn publish_version_inserts_into_table() {
        let (secret, pubkey) = paradencer_crypto::generate_keypair();
        let node_id = NodeId(pubkey);
        let info = create_test_contact_info(node_id, 8000);
        let cluster = ClusterInfo::with_signing_key(
            node_id,
            info,
            Duration::from_secs(30),
            MAX_CLUSTER_SIZE,
            secret,
        );

        let version = VersionInfo {
            client: 0,
            major: 2,
            minor: 1,
            patch: 0,
            commit: 0xDEAD,
            feature_set: 0xBEEF,
        };
        cluster.publish_version(version);

        let (values, _cursor) = cluster.values_since_cursor(0);
        let version_count = values
            .iter()
            .filter(|v| matches!(v.data, CrdsValueData::Version(_)))
            .count();
        assert_eq!(version_count, 1);
    }

    #[test]
    fn publish_snapshot_hashes_inserts_into_table() {
        let (secret, pubkey) = paradencer_crypto::generate_keypair();
        let node_id = NodeId(pubkey);
        let info = create_test_contact_info(node_id, 8000);
        let cluster = ClusterInfo::with_signing_key(
            node_id,
            info,
            Duration::from_secs(30),
            MAX_CLUSTER_SIZE,
            secret,
        );

        let base = (1000u64, [0xAA; 32]);
        let incremental = vec![(1100u64, [0xBB; 32])];
        cluster.publish_snapshot_hashes(base, incremental);

        let (values, _cursor) = cluster.values_since_cursor(0);
        let snap_count = values
            .iter()
            .filter(|v| matches!(v.data, CrdsValueData::IncrementalSnapshotHashes(_)))
            .count();
        assert_eq!(snap_count, 1);
    }

    #[test]
    fn cluster_info_prune_integration() {
        let self_node_id = NodeId::new([0u8; 32]);
        let self_info = create_test_contact_info(self_node_id, 8000);
        let cluster = ClusterInfo::new(
            self_node_id,
            self_info,
            Duration::from_millis(30_000),
            MAX_CLUSTER_SIZE,
        );

        let dest = [1u8; 32];
        let origin = [2u8; 32];
        let now_ms = current_timestamp_ms();

        cluster.record_prune(dest, &[origin], now_ms);

        // Should be pruned since it was just recorded.
        assert!(cluster.is_origin_pruned(&dest, &origin));
        assert_eq!(cluster.prune_entry_count(), 1);

        // A different origin is not pruned.
        let other_origin = [3u8; 32];
        assert!(!cluster.is_origin_pruned(&dest, &other_origin));
    }
}
