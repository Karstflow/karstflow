//! CRDS value types exchanged via gossip.
//!
//! The gossip protocol supports 14 value types, each carrying different
//! information about validators in the cluster. Values are signed by
//! their originating node and include a wallclock timestamp for
//! conflict resolution.

use super::key::CrdsKey;
use karstflow_constants::gossip;
use std::net::SocketAddr;

/// Socket addresses for a validator node (14 types).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CrdsContactInfo {
    /// Originating node's public key.
    pub pubkey: [u8; 32],
    /// Shred version for cluster partitioning.
    pub shred_version: u16,
    /// Instance creation wallclock (nanoseconds since epoch).
    pub instance_creation_nanos: i64,
    /// Publication wallclock (nanoseconds since epoch).
    pub wallclock_nanos: i64,
    /// Socket addresses indexed by socket type.
    /// See `gossip::SOCKET_*` constants for indices.
    pub sockets: [Option<SocketAddr>; gossip::CONTACT_INFO_SOCKET_COUNT],
    /// Client version information.
    pub version: VersionInfo,
}

/// Client software version.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VersionInfo {
    /// Client identifier (0..7 for known clients).
    pub client: u16,
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
    /// First 4 bytes of the commit hash.
    pub commit: u32,
    /// Feature set bitmask.
    pub feature_set: u32,
}

/// A vote transaction propagated via gossip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteGossip {
    /// Vote index within the node's vote set (0..255).
    pub index: u8,
    /// Slot being voted on.
    pub slot: u64,
    /// Vote hash.
    pub hash: [u8; 32],
    /// Serialized vote transaction (up to max CRDS value size).
    pub transaction_bytes: Vec<u8>,
}

/// Lowest available slot for a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LowestSlot {
    pub slot: u64,
}

/// Slots available in the current epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochSlots {
    /// Epoch slots index (0..255).
    pub index: u8,
    /// Compressed bitmap of available slots.
    pub slots: Vec<u8>,
}

/// Node instance token for duplicate detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeInstanceToken {
    /// Unique random token generated at node startup.
    pub token: u64,
}

/// Proof that a node produced duplicate shreds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicateShredProof {
    /// Sub-index for duplicate shred entries (0..65535).
    pub index: u16,
    /// Serialized proof data.
    pub proof_bytes: Vec<u8>,
}

/// Snapshot hash information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotHashes {
    /// Full snapshot slot and hash pairs.
    pub hashes: Vec<(u64, [u8; 32])>,
}

/// Incremental snapshot hashes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncrementalSnapshotHashes {
    /// Base full snapshot slot and hash.
    pub base: (u64, [u8; 32]),
    /// Incremental snapshot slot and hash pairs.
    pub hashes: Vec<(u64, [u8; 32])>,
}

/// Restart protocol: last voted fork slots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestartLastVotedForkSlots {
    /// Compressed bitmap of last voted fork slots.
    pub slots: Vec<u8>,
    /// Last voted slot.
    pub last_voted_slot: u64,
    /// Last voted hash.
    pub last_voted_hash: [u8; 32],
    /// Shred version.
    pub shred_version: u16,
}

/// Restart protocol: heaviest fork information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartHeaviestFork {
    /// Observed heaviest slot.
    pub slot: u64,
    /// Observed heaviest hash.
    pub hash: [u8; 32],
    /// Total observed stake.
    pub observed_stake: u64,
}

/// The payload of a CRDS value, discriminated by type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrdsValueData {
    /// Deprecated legacy contact info (type 0).
    LegacyContactInfo(CrdsContactInfo),
    /// Vote transaction (type 1).
    Vote(VoteGossip),
    /// Lowest slot (type 2).
    LowestSlot(LowestSlot),
    /// Deprecated legacy snapshot hashes (type 3).
    LegacySnapshotHashes(SnapshotHashes),
    /// Deprecated account hashes (type 4).
    AccountHashes,
    /// Epoch slots (type 5).
    EpochSlots(EpochSlots),
    /// Deprecated legacy version (type 6).
    LegacyVersion(VersionInfo),
    /// Client version (type 7).
    Version(VersionInfo),
    /// Node instance token (type 8).
    NodeInstance(NodeInstanceToken),
    /// Duplicate shred proof (type 9).
    DuplicateShred(DuplicateShredProof),
    /// Incremental snapshot hashes (type 10).
    IncrementalSnapshotHashes(IncrementalSnapshotHashes),
    /// Contact info (type 11).
    ContactInfo(CrdsContactInfo),
    /// Restart: last voted fork slots (type 12).
    RestartLastVotedForkSlots(RestartLastVotedForkSlots),
    /// Restart: heaviest fork (type 13).
    RestartHeaviestFork(RestartHeaviestFork),
}

impl CrdsValueData {
    /// Return the type discriminant for this value.
    pub fn value_type(&self) -> u8 {
        match self {
            Self::LegacyContactInfo(_) => gossip::VALUE_TYPE_LEGACY_CONTACT_INFO,
            Self::Vote(_) => gossip::VALUE_TYPE_VOTE,
            Self::LowestSlot(_) => gossip::VALUE_TYPE_LOWEST_SLOT,
            Self::LegacySnapshotHashes(_) => gossip::VALUE_TYPE_LEGACY_SNAPSHOT_HASHES,
            Self::AccountHashes => gossip::VALUE_TYPE_ACCOUNT_HASHES,
            Self::EpochSlots(_) => gossip::VALUE_TYPE_EPOCH_SLOTS,
            Self::LegacyVersion(_) => gossip::VALUE_TYPE_LEGACY_VERSION,
            Self::Version(_) => gossip::VALUE_TYPE_VERSION,
            Self::NodeInstance(_) => gossip::VALUE_TYPE_NODE_INSTANCE,
            Self::DuplicateShred(_) => gossip::VALUE_TYPE_DUPLICATE_SHRED,
            Self::IncrementalSnapshotHashes(_) => gossip::VALUE_TYPE_INCREMENTAL_SNAPSHOT_HASHES,
            Self::ContactInfo(_) => gossip::VALUE_TYPE_CONTACT_INFO,
            Self::RestartLastVotedForkSlots(_) => gossip::VALUE_TYPE_RESTART_LAST_VOTED_FORK_SLOTS,
            Self::RestartHeaviestFork(_) => gossip::VALUE_TYPE_RESTART_HEAVIEST_FORK,
        }
    }

    /// Extract the sub-index for multi-entry types.
    pub fn sub_index(&self) -> u16 {
        match self {
            Self::Vote(v) => v.index as u16,
            Self::EpochSlots(e) => e.index as u16,
            Self::DuplicateShred(d) => d.index,
            _ => 0,
        }
    }

    /// True if this is a contact info value type (current or legacy).
    pub fn is_contact_info(&self) -> bool {
        matches!(self, Self::ContactInfo(_) | Self::LegacyContactInfo(_))
    }

    /// True if this is a node instance token.
    pub fn is_node_instance(&self) -> bool {
        matches!(self, Self::NodeInstance(_))
    }

    /// Extract contact info if this is a ContactInfo or LegacyContactInfo.
    pub fn as_contact_info(&self) -> Option<&CrdsContactInfo> {
        match self {
            Self::ContactInfo(ci) | Self::LegacyContactInfo(ci) => Some(ci),
            _ => None,
        }
    }
}

/// A signed CRDS value with metadata.
///
/// Contains the value payload, originator's public key, signature,
/// and wallclock timestamp used for conflict resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrdsValue {
    /// The originating node's public key.
    pub origin: [u8; 32],
    /// Wallclock timestamp (nanoseconds since epoch).
    pub wallclock_nanos: i64,
    /// Ed25519 signature over the serialized value.
    pub signature: [u8; 64],
    /// The value payload.
    pub data: CrdsValueData,
}

impl CrdsValue {
    /// Derive the CRDS key for this value.
    pub fn key(&self) -> CrdsKey {
        CrdsKey::with_index(self.data.value_type(), self.origin, self.data.sub_index())
    }

    /// Compute the SHA-256 hash of the value.
    ///
    /// This is used for the hash-prefix index and purged entry tracking.
    /// Includes all value-specific data to distinguish entries that share
    /// the same key but differ in content.
    pub fn compute_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update([self.data.value_type()]);
        hasher.update(self.origin);
        hasher.update(self.wallclock_nanos.to_le_bytes());
        hasher.update(self.data.sub_index().to_le_bytes());
        hasher.update(self.signature);

        // Include type-specific distinguishing data
        match &self.data {
            CrdsValueData::ContactInfo(ci) | CrdsValueData::LegacyContactInfo(ci) => {
                hasher.update(ci.instance_creation_nanos.to_le_bytes());
                hasher.update(ci.shred_version.to_le_bytes());
            }
            CrdsValueData::NodeInstance(ni) => {
                hasher.update(ni.token.to_le_bytes());
            }
            CrdsValueData::Vote(v) => {
                hasher.update(v.slot.to_le_bytes());
                hasher.update(v.hash);
                hasher.update(&v.transaction_bytes);
            }
            CrdsValueData::LowestSlot(ls) => {
                hasher.update(ls.slot.to_le_bytes());
            }
            _ => {
                // Other types: wallclock + signature is sufficient
            }
        }

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Produce the bytes covered by the signature.
    ///
    /// This is the canonical serialization: `value_type | origin | wallclock | sub_index | data-specific fields`.
    /// The signature field itself is excluded.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        buf.push(self.data.value_type());
        buf.extend_from_slice(&self.origin);
        buf.extend_from_slice(&self.wallclock_nanos.to_le_bytes());
        buf.extend_from_slice(&self.data.sub_index().to_le_bytes());

        match &self.data {
            CrdsValueData::ContactInfo(ci) | CrdsValueData::LegacyContactInfo(ci) => {
                buf.extend_from_slice(&ci.instance_creation_nanos.to_le_bytes());
                buf.extend_from_slice(&ci.shred_version.to_le_bytes());
                for socket in &ci.sockets {
                    match socket {
                        Some(addr) => {
                            buf.push(1);
                            match addr {
                                std::net::SocketAddr::V4(v4) => {
                                    buf.extend_from_slice(&v4.ip().octets());
                                    buf.extend_from_slice(&v4.port().to_le_bytes());
                                }
                                std::net::SocketAddr::V6(v6) => {
                                    buf.extend_from_slice(&v6.ip().octets());
                                    buf.extend_from_slice(&v6.port().to_le_bytes());
                                }
                            }
                        }
                        None => buf.push(0),
                    }
                }
            }
            CrdsValueData::NodeInstance(ni) => {
                buf.extend_from_slice(&ni.token.to_le_bytes());
            }
            CrdsValueData::Vote(v) => {
                buf.push(v.index);
                buf.extend_from_slice(&v.slot.to_le_bytes());
                buf.extend_from_slice(&v.hash);
                buf.extend_from_slice(&v.transaction_bytes);
            }
            CrdsValueData::LowestSlot(ls) => {
                buf.extend_from_slice(&ls.slot.to_le_bytes());
            }
            CrdsValueData::EpochSlots(es) => {
                buf.push(es.index);
                buf.extend_from_slice(&es.slots);
            }
            CrdsValueData::LegacySnapshotHashes(sh) => {
                for (slot, hash) in &sh.hashes {
                    buf.extend_from_slice(&slot.to_le_bytes());
                    buf.extend_from_slice(hash);
                }
            }
            CrdsValueData::IncrementalSnapshotHashes(ish) => {
                buf.extend_from_slice(&ish.base.0.to_le_bytes());
                buf.extend_from_slice(&ish.base.1);
                for (slot, hash) in &ish.hashes {
                    buf.extend_from_slice(&slot.to_le_bytes());
                    buf.extend_from_slice(hash);
                }
            }
            CrdsValueData::DuplicateShred(ds) => {
                buf.extend_from_slice(&ds.index.to_le_bytes());
                buf.extend_from_slice(&ds.proof_bytes);
            }
            CrdsValueData::RestartLastVotedForkSlots(r) => {
                buf.extend_from_slice(&r.last_voted_slot.to_le_bytes());
                buf.extend_from_slice(&r.last_voted_hash);
                buf.extend_from_slice(&r.shred_version.to_le_bytes());
                buf.extend_from_slice(&r.slots);
            }
            CrdsValueData::RestartHeaviestFork(r) => {
                buf.extend_from_slice(&r.slot.to_le_bytes());
                buf.extend_from_slice(&r.hash);
                buf.extend_from_slice(&r.observed_stake.to_le_bytes());
            }
            CrdsValueData::Version(v) | CrdsValueData::LegacyVersion(v) => {
                buf.extend_from_slice(&v.client.to_le_bytes());
                buf.extend_from_slice(&v.major.to_le_bytes());
                buf.extend_from_slice(&v.minor.to_le_bytes());
                buf.extend_from_slice(&v.patch.to_le_bytes());
                buf.extend_from_slice(&v.commit.to_le_bytes());
                buf.extend_from_slice(&v.feature_set.to_le_bytes());
            }
            CrdsValueData::AccountHashes => {}
        }

        buf
    }

    /// Sign this value using an Ed25519 secret key (32-byte seed).
    pub fn sign(&mut self, secret_key: &[u8; 32]) {
        let msg = self.signable_bytes();
        // sign_message only fails on invalid key, which can't happen with a 32-byte seed
        self.signature = karstflow_crypto::sign_message(secret_key, &msg)
            .expect("Ed25519 signing should never fail with a valid key");
    }

    /// Verify this value's Ed25519 signature against its origin public key.
    pub fn verify_signature(&self) -> bool {
        let msg = self.signable_bytes();
        matches!(
            karstflow_crypto::verify_signature(&self.origin, &msg, &self.signature),
            Ok(karstflow_crypto::VerificationResult::Success)
        )
    }

    /// Compare wallclock with another value for the same key.
    /// Returns true if this value should override the other.
    pub fn overrides(&self, other: &Self) -> bool {
        if self.wallclock_nanos != other.wallclock_nanos {
            return self.wallclock_nanos > other.wallclock_nanos;
        }
        // Tiebreak by hash (deterministic)
        self.compute_hash() > other.compute_hash()
    }

    /// Perform fast override check specific to value type.
    ///
    /// For ContactInfo: compare instance_creation_wallclock first.
    /// For NodeInstance: compare tokens first.
    /// For all others: compare wallclock.
    pub fn fast_overrides(&self, incumbent: &Self) -> FastCheckResult {
        match (&self.data, &incumbent.data) {
            (CrdsValueData::ContactInfo(new_ci), CrdsValueData::ContactInfo(old_ci))
            | (
                CrdsValueData::LegacyContactInfo(new_ci),
                CrdsValueData::LegacyContactInfo(old_ci),
            ) => {
                if new_ci.instance_creation_nanos != old_ci.instance_creation_nanos {
                    if new_ci.instance_creation_nanos > old_ci.instance_creation_nanos {
                        return FastCheckResult::Overrides;
                    }
                    return FastCheckResult::Fails;
                }
                wallclock_compare(self.wallclock_nanos, incumbent.wallclock_nanos)
            }
            (CrdsValueData::NodeInstance(new_ni), CrdsValueData::NodeInstance(old_ni)) => {
                if new_ni.token != old_ni.token {
                    if new_ni.token > old_ni.token {
                        return FastCheckResult::Overrides;
                    }
                    return FastCheckResult::Fails;
                }
                wallclock_compare(self.wallclock_nanos, incumbent.wallclock_nanos)
            }
            _ => wallclock_compare(self.wallclock_nanos, incumbent.wallclock_nanos),
        }
    }
}

/// Result of the fast check algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastCheckResult {
    /// Value should override the incumbent.
    Overrides,
    /// Value fails the check (older or duplicate).
    Fails,
    /// Need full hash comparison to determine.
    Undetermined,
}

fn wallclock_compare(new_wallclock: i64, old_wallclock: i64) -> FastCheckResult {
    match new_wallclock.cmp(&old_wallclock) {
        std::cmp::Ordering::Greater => FastCheckResult::Overrides,
        std::cmp::Ordering::Less => FastCheckResult::Fails,
        std::cmp::Ordering::Equal => FastCheckResult::Undetermined,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_contact_info_value(origin: [u8; 32], wallclock: i64) -> CrdsValue {
        CrdsValue {
            origin,
            wallclock_nanos: wallclock,
            signature: [0u8; 64],
            data: CrdsValueData::ContactInfo(CrdsContactInfo {
                pubkey: origin,
                shred_version: 1,
                instance_creation_nanos: 1000,
                wallclock_nanos: wallclock,
                sockets: Default::default(),
                version: VersionInfo::default(),
            }),
        }
    }

    fn make_vote_value(origin: [u8; 32], index: u8, wallclock: i64) -> CrdsValue {
        CrdsValue {
            origin,
            wallclock_nanos: wallclock,
            signature: [0u8; 64],
            data: CrdsValueData::Vote(VoteGossip {
                index,
                slot: 100,
                hash: [0u8; 32],
                transaction_bytes: vec![1, 2, 3],
            }),
        }
    }

    #[test]
    fn test_value_type_discriminant() {
        let origin = [1u8; 32];
        let ci = make_contact_info_value(origin, 1000);
        assert_eq!(ci.data.value_type(), gossip::VALUE_TYPE_CONTACT_INFO);

        let vote = make_vote_value(origin, 0, 1000);
        assert_eq!(vote.data.value_type(), gossip::VALUE_TYPE_VOTE);
    }

    #[test]
    fn test_key_derivation() {
        let origin = [1u8; 32];
        let ci = make_contact_info_value(origin, 1000);
        let key = ci.key();
        assert_eq!(key.value_type, gossip::VALUE_TYPE_CONTACT_INFO);
        assert_eq!(key.origin, origin);
        assert_eq!(key.sub_index, 0);
    }

    #[test]
    fn test_vote_key_with_index() {
        let origin = [1u8; 32];
        let vote = make_vote_value(origin, 5, 1000);
        let key = vote.key();
        assert_eq!(key.value_type, gossip::VALUE_TYPE_VOTE);
        assert_eq!(key.sub_index, 5);
    }

    #[test]
    fn test_overrides_newer_wallclock() {
        let origin = [1u8; 32];
        let v1 = make_contact_info_value(origin, 1000);
        let v2 = make_contact_info_value(origin, 2000);
        assert!(v2.overrides(&v1));
        assert!(!v1.overrides(&v2));
    }

    #[test]
    fn test_fast_check_contact_info_instance_creation() {
        let origin = [1u8; 32];
        let v1 = make_contact_info_value(origin, 1000);
        let mut v2 = make_contact_info_value(origin, 1000);

        // Same wallclock but different instance creation
        if let CrdsValueData::ContactInfo(ref mut ci) = v2.data {
            ci.instance_creation_nanos = 2000;
        }
        assert_eq!(v2.fast_overrides(&v1), FastCheckResult::Overrides);
        assert_eq!(v1.fast_overrides(&v2), FastCheckResult::Fails);
    }

    #[test]
    fn test_fast_check_node_instance_token() {
        let origin = [1u8; 32];
        let v1 = CrdsValue {
            origin,
            wallclock_nanos: 1000,
            signature: [0u8; 64],
            data: CrdsValueData::NodeInstance(NodeInstanceToken { token: 100 }),
        };
        let v2 = CrdsValue {
            origin,
            wallclock_nanos: 1000,
            signature: [0u8; 64],
            data: CrdsValueData::NodeInstance(NodeInstanceToken { token: 200 }),
        };
        assert_eq!(v2.fast_overrides(&v1), FastCheckResult::Overrides);
        assert_eq!(v1.fast_overrides(&v2), FastCheckResult::Fails);
    }

    #[test]
    fn test_fast_check_equal_wallclock() {
        let origin = [1u8; 32];
        let v1 = make_vote_value(origin, 0, 1000);
        let v2 = make_vote_value(origin, 0, 1000);
        assert_eq!(v2.fast_overrides(&v1), FastCheckResult::Undetermined);
    }

    #[test]
    fn test_is_contact_info() {
        let ci = CrdsValueData::ContactInfo(CrdsContactInfo::default());
        assert!(ci.is_contact_info());

        let legacy = CrdsValueData::LegacyContactInfo(CrdsContactInfo::default());
        assert!(legacy.is_contact_info());

        let vote = CrdsValueData::Vote(VoteGossip {
            index: 0,
            slot: 0,
            hash: [0u8; 32],
            transaction_bytes: vec![],
        });
        assert!(!vote.is_contact_info());
    }

    #[test]
    fn test_compute_hash_deterministic() {
        let origin = [1u8; 32];
        let v = make_contact_info_value(origin, 1000);
        let h1 = v.compute_hash();
        let h2 = v.compute_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_compute_hash_different_wallclock() {
        let origin = [1u8; 32];
        let v1 = make_contact_info_value(origin, 1000);
        let v2 = make_contact_info_value(origin, 2000);
        assert_ne!(v1.compute_hash(), v2.compute_hash());
    }

    #[test]
    fn test_sign_and_verify() {
        let (secret, pubkey) = karstflow_crypto::generate_keypair();
        let mut value = make_contact_info_value(pubkey, 1000);

        // Unsigned value should not verify (zero signature)
        assert!(!value.verify_signature());

        // Sign and verify
        value.sign(&secret);
        assert!(value.verify_signature());
    }

    #[test]
    fn test_sign_verify_wrong_key() {
        let (secret, pubkey) = karstflow_crypto::generate_keypair();
        let (_other_secret, other_pubkey) = karstflow_crypto::generate_keypair();

        let mut value = make_contact_info_value(pubkey, 1000);
        value.sign(&secret);
        assert!(value.verify_signature());

        // Change origin to different key — verification should fail
        value.origin = other_pubkey;
        assert!(!value.verify_signature());
    }

    #[test]
    fn test_sign_verify_vote() {
        let (secret, pubkey) = karstflow_crypto::generate_keypair();
        let mut value = make_vote_value(pubkey, 3, 5000);

        value.sign(&secret);
        assert!(value.verify_signature());

        // Tamper with data — verification should fail
        if let CrdsValueData::Vote(ref mut v) = value.data {
            v.slot = 999;
        }
        assert!(!value.verify_signature());
    }

    #[test]
    fn test_signable_bytes_deterministic() {
        let origin = [1u8; 32];
        let value = make_contact_info_value(origin, 1000);
        let b1 = value.signable_bytes();
        let b2 = value.signable_bytes();
        assert_eq!(b1, b2);
    }

    #[test]
    fn test_signable_bytes_different_for_different_values() {
        let origin = [1u8; 32];
        let v1 = make_contact_info_value(origin, 1000);
        let v2 = make_contact_info_value(origin, 2000);
        assert_ne!(v1.signable_bytes(), v2.signable_bytes());
    }
}
