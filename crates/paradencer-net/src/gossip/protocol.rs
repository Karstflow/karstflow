use super::*;
use crate::gossip::cluster_info::{ContactInfo, NodeId};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};

pub const GOSSIP_PROTOCOL_VERSION: u16 = 1;

/// Gossip protocol version for compatibility checking
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

/// Type of gossip message
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

/// Push gossip message for broadcasting updates
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

/// Pull request for requesting updates from peers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipPullRequest {
    pub sender: NodeId,
    pub filter: BloomFilter,
    pub wallclock: u64,
}

impl GossipPullRequest {
    pub fn new(sender: NodeId, filter: BloomFilter) -> Self {
        Self {
            sender,
            filter,
            wallclock: current_timestamp_ms(),
        }
    }
}

/// Pull response containing requested updates
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

/// Main gossip message envelope
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

    /// Encode message to bytes with version prefix
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

    /// Decode message from bytes with version check
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

/// Simple bloom filter for pull requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BloomFilter {
    bits: Vec<u64>,
    num_hashes: u32,
    num_bits: u64,
}

impl BloomFilter {
    pub fn new(expected_items: usize, false_positive_rate: f64) -> Self {
        let num_bits = Self::optimal_num_bits(expected_items, false_positive_rate);
        let num_hashes = Self::optimal_num_hashes(num_bits, expected_items);

        Self {
            bits: vec![0u64; (num_bits / 64 + 1) as usize],
            num_hashes,
            num_bits,
        }
    }

    fn optimal_num_bits(items: usize, fp_rate: f64) -> u64 {
        let m = -(items as f64 * fp_rate.ln()) / (2.0_f64.ln().powi(2));
        m.ceil() as u64
    }

    fn optimal_num_hashes(num_bits: u64, items: usize) -> u32 {
        let k = (num_bits as f64 / items as f64) * 2.0_f64.ln();
        k.ceil() as u32
    }

    pub fn insert(&mut self, item: &NodeId) {
        for i in 0..self.num_hashes {
            let hash = self.hash(item, i);
            let bit_index = (hash % self.num_bits) as usize;
            let word_index = bit_index / 64;
            let bit_offset = bit_index % 64;
            self.bits[word_index] |= 1u64 << bit_offset;
        }
    }

    pub fn contains(&self, item: &NodeId) -> bool {
        for i in 0..self.num_hashes {
            let hash = self.hash(item, i);
            let bit_index = (hash % self.num_bits) as usize;
            let word_index = bit_index / 64;
            let bit_offset = bit_index % 64;
            if (self.bits[word_index] & (1u64 << bit_offset)) == 0 {
                return false;
            }
        }
        true
    }

    fn hash(&self, item: &NodeId, seed: u32) -> u64 {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(item.as_bytes());
        hasher.update(seed.to_le_bytes());
        let result = hasher.finalize();
        u64::from_le_bytes(result[..8].try_into().unwrap())
    }
}

fn current_timestamp_ms() -> u64 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
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
    fn test_bloom_filter_basic() {
        let mut filter = BloomFilter::new(100, 0.01);
        let node_id = NodeId::new([1u8; 32]);

        assert!(!filter.contains(&node_id));
        filter.insert(&node_id);
        assert!(filter.contains(&node_id));
    }

    #[test]
    fn test_bloom_filter_multiple_items() {
        let mut filter = BloomFilter::new(1000, 0.01);

        let items: Vec<_> = (0..100).map(|i| NodeId::new([i as u8; 32])).collect();

        for item in &items {
            filter.insert(item);
        }

        for item in &items {
            assert!(filter.contains(item));
        }

        let non_inserted = NodeId::new([200u8; 32]);
        assert!(!filter.contains(&non_inserted));
    }
}
