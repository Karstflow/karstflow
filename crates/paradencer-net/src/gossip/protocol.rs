use super::*;
use crate::gossip::cluster_info::{ContactInfo, NodeId};
use crate::gossip::crds::{GossipBloomFilter, PullRequestMask};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};

pub const GOSSIP_PROTOCOL_VERSION: u16 = 1;

/// Gossip protocol version for compatibility checking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipVersion(pub u16);

impl GossipVersion {
    pub fn current() -> Self {
        Self(GOSSIP_PROTOCOL_VERSION)
    }

    pub fn is_compatible(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

/// Type of gossip message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GossipMessageType {
    Push = 1,
    Pull = 2,
    PullResponse = 3,
    Ping = 4,
    Pong = 5,
}

impl GossipMessageType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Push),
            2 => Some(Self::Pull),
            3 => Some(Self::PullResponse),
            4 => Some(Self::Ping),
            5 => Some(Self::Pong),
            _ => None,
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// Push gossip message for broadcasting updates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipPushMessage {
    pub sender: NodeId,
    pub contact_infos: Vec<ContactInfo>,
    pub wallclock: u64,
}

impl GossipPushMessage {
    pub fn new(sender: NodeId, contact_infos: Vec<ContactInfo>) -> Self {
        Self {
            sender,
            contact_infos,
            wallclock: current_timestamp_ms(),
        }
    }

    pub fn is_valid(&self) -> bool {
        !self.contact_infos.is_empty() && self.wallclock > 0
    }
}

/// Pull request for requesting updates from peers.
///
/// Uses the CRDS bloom filter with mask-based partitioning for efficient
/// deduplication across large tables.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipPullRequest {
    pub sender: NodeId,
    pub filter: PullRequestFilter,
    pub wallclock: u64,
}

impl GossipPullRequest {
    pub fn new(sender: NodeId, filter: PullRequestFilter) -> Self {
        Self {
            sender,
            filter,
            wallclock: current_timestamp_ms(),
        }
    }
}

/// Combined bloom filter + mask for pull requests.
///
/// The bloom filter contains hashes of all CRDS entries the sender
/// already has. The mask partitions the hash space so that each pull
/// request only covers a portion of the table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullRequestFilter {
    /// Serialized bloom filter bits.
    pub bloom_bits: Vec<u64>,
    /// Number of bits in the bloom filter.
    pub bloom_num_bits: u64,
    /// Hash function seeds.
    pub bloom_keys: Vec<u64>,
    /// Partition mask value.
    pub mask: u64,
    /// Number of significant mask bits.
    pub mask_bits: u32,
}

impl PullRequestFilter {
    /// Create from a GossipBloomFilter and PullRequestMask.
    pub fn from_bloom_and_mask(filter: &GossipBloomFilter, mask: &PullRequestMask) -> Self {
        Self {
            bloom_bits: filter.bits().to_vec(),
            bloom_num_bits: filter.total_bits(),
            bloom_keys: filter.keys().to_vec(),
            mask: mask.mask,
            mask_bits: mask.mask_bits,
        }
    }

    /// Reconstruct the PullRequestMask.
    pub fn to_mask(&self) -> PullRequestMask {
        PullRequestMask {
            mask: self.mask,
            mask_bits: self.mask_bits,
        }
    }

    /// Reconstruct the GossipBloomFilter.
    pub fn to_bloom_filter(&self) -> GossipBloomFilter {
        GossipBloomFilter::from_parts(
            self.bloom_bits.clone(),
            self.bloom_num_bits,
            self.bloom_keys.clone(),
        )
    }

    /// Check if a node's hash is likely contained in this filter.
    pub fn contains_hash(&self, hash: &[u8; 32]) -> bool {
        let filter = self.to_bloom_filter();
        filter.contains(hash)
    }
}

/// Pull response containing requested updates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipPullResponse {
    pub sender: NodeId,
    pub contact_infos: Vec<ContactInfo>,
    pub wallclock: u64,
}

impl GossipPullResponse {
    pub fn new(sender: NodeId, contact_infos: Vec<ContactInfo>) -> Self {
        Self {
            sender,
            contact_infos,
            wallclock: current_timestamp_ms(),
        }
    }
}

/// Main gossip message envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipMessage {
    Push(GossipPushMessage),
    Pull(GossipPullRequest),
    PullResponse(GossipPullResponse),
    Ping { sender: NodeId, nonce: u64 },
    Pong { sender: NodeId, nonce: u64 },
}

impl GossipMessage {
    pub fn sender(&self) -> NodeId {
        match self {
            Self::Push(msg) => msg.sender,
            Self::Pull(msg) => msg.sender,
            Self::PullResponse(msg) => msg.sender,
            Self::Ping { sender, .. } => *sender,
            Self::Pong { sender, .. } => *sender,
        }
    }

    pub fn message_type(&self) -> GossipMessageType {
        match self {
            Self::Push(_) => GossipMessageType::Push,
            Self::Pull(_) => GossipMessageType::Pull,
            Self::PullResponse(_) => GossipMessageType::PullResponse,
            Self::Ping { .. } => GossipMessageType::Ping,
            Self::Pong { .. } => GossipMessageType::Pong,
        }
    }

    /// Encode message to bytes with version prefix.
    pub fn encode(&self) -> Result<Bytes, IngressError> {
        let serialized = bincode::serialize(self).map_err(|e| IngressError::Serialization {
            detail: format!("failed to serialize gossip message: {}", e),
        })?;

        let mut buf = BytesMut::with_capacity(4 + serialized.len());
        buf.put_u16(GOSSIP_PROTOCOL_VERSION);
        buf.put_u16(serialized.len() as u16);
        buf.put_slice(&serialized);

        Ok(buf.freeze())
    }

    /// Decode message from bytes with version check.
    pub fn decode(mut bytes: Bytes) -> Result<Self, IngressError> {
        if bytes.remaining() < 4 {
            return Err(IngressError::Deserialization {
                detail: "gossip message too short".to_string(),
            });
        }

        let version = bytes.get_u16();
        if version != GOSSIP_PROTOCOL_VERSION {
            return Err(IngressError::Deserialization {
                detail: format!(
                    "incompatible gossip protocol version: expected {}, got {}",
                    GOSSIP_PROTOCOL_VERSION, version
                ),
            });
        }

        let len = bytes.get_u16() as usize;
        if bytes.remaining() < len {
            return Err(IngressError::Deserialization {
                detail: "incomplete gossip message".to_string(),
            });
        }

        let message_bytes = bytes.copy_to_bytes(len);
        bincode::deserialize(&message_bytes).map_err(|e| IngressError::Deserialization {
            detail: format!("failed to deserialize gossip message: {}", e),
        })
    }
}

fn current_timestamp_ms() -> u64 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn create_test_contact_info(node_id: NodeId) -> ContactInfo {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8000);
        ContactInfo::new(node_id, addr, addr, addr, addr, 1)
    }

    #[test]
    fn test_gossip_version() {
        let v1 = GossipVersion::current();
        let v2 = GossipVersion(GOSSIP_PROTOCOL_VERSION);
        assert!(v1.is_compatible(&v2));

        let v3 = GossipVersion(GOSSIP_PROTOCOL_VERSION + 1);
        assert!(!v1.is_compatible(&v3));
    }

    #[test]
    fn test_message_type_conversion() {
        assert_eq!(GossipMessageType::from_u8(1), Some(GossipMessageType::Push));
        assert_eq!(GossipMessageType::from_u8(2), Some(GossipMessageType::Pull));
        assert_eq!(GossipMessageType::from_u8(99), None);
    }

    #[test]
    fn test_push_message_creation() {
        let sender = NodeId::new([1u8; 32]);
        let contact_info = create_test_contact_info(sender);
        let msg = GossipPushMessage::new(sender, vec![contact_info]);

        assert!(msg.is_valid());
        assert_eq!(msg.sender, sender);
        assert_eq!(msg.contact_infos.len(), 1);
    }

    #[test]
    fn test_gossip_message_encode_decode() {
        let sender = NodeId::new([1u8; 32]);
        let msg = GossipMessage::Ping {
            sender,
            nonce: 12345,
        };

        let encoded = msg.encode().unwrap();
        let decoded = GossipMessage::decode(encoded).unwrap();

        match decoded {
            GossipMessage::Ping {
                sender: decoded_sender,
                nonce,
            } => {
                assert_eq!(decoded_sender, sender);
                assert_eq!(nonce, 12345);
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn test_pull_request_filter_roundtrip() {
        let bloom = GossipBloomFilter::new(100);
        let mask = PullRequestMask::full();

        let filter = PullRequestFilter::from_bloom_and_mask(&bloom, &mask);
        let restored_mask = filter.to_mask();
        let restored_bloom = filter.to_bloom_filter();

        assert_eq!(restored_mask.mask, mask.mask);
        assert_eq!(restored_mask.mask_bits, mask.mask_bits);
        assert_eq!(restored_bloom.total_bits(), bloom.total_bits());
    }
}
