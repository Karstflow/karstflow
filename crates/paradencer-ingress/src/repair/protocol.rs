use super::*;
use crate::gossip::NodeId;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};

pub const REPAIR_PROTOCOL_VERSION: u16 = 1;
pub const MAX_REPAIR_RESPONSE_SIZE: usize = 10 * 1024 * 1024; // 10 MB

/// Repair protocol version
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairProtocol(pub u16);

impl RepairProtocol {
    pub fn current() -> Self {
        Self(REPAIR_PROTOCOL_VERSION)
    }

    pub fn is_compatible(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

/// Type of repair request
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RepairRequestType {
    /// Request a specific shred by slot and index
    Shred = 1,
    /// Request the highest shred index for a slot
    HighestShred = 2,
    /// Request all shreds for a slot range
    SlotRange = 3,
    /// Request orphan shreds (parent unknown)
    Orphan = 4,
    /// Request ancestor chain
    Ancestor = 5,
}

impl RepairRequestType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Shred),
            2 => Some(Self::HighestShred),
            3 => Some(Self::SlotRange),
            4 => Some(Self::Orphan),
            5 => Some(Self::Ancestor),
            _ => None,
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// Repair request message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RepairRequest {
    /// Request specific shred
    Shred {
        requester: NodeId,
        slot: Slot,
        index: ShredIndex,
        nonce: u64,
    },
    /// Request highest shred for slot
    HighestShred {
        requester: NodeId,
        slot: Slot,
        nonce: u64,
    },
    /// Request shreds in slot range
    SlotRange {
        requester: NodeId,
        start_slot: Slot,
        end_slot: Slot,
        nonce: u64,
    },
    /// Request orphan shreds
    Orphan {
        requester: NodeId,
        slot: Slot,
        nonce: u64,
    },
    /// Request ancestor chain
    Ancestor {
        requester: NodeId,
        slot: Slot,
        ancestors: u64,
        nonce: u64,
    },
}

impl RepairRequest {
    pub fn requester(&self) -> NodeId {
        match self {
            Self::Shred { requester, .. } => *requester,
            Self::HighestShred { requester, .. } => *requester,
            Self::SlotRange { requester, .. } => *requester,
            Self::Orphan { requester, .. } => *requester,
            Self::Ancestor { requester, .. } => *requester,
        }
    }

    pub fn nonce(&self) -> u64 {
        match self {
            Self::Shred { nonce, .. } => *nonce,
            Self::HighestShred { nonce, .. } => *nonce,
            Self::SlotRange { nonce, .. } => *nonce,
            Self::Orphan { nonce, .. } => *nonce,
            Self::Ancestor { nonce, .. } => *nonce,
        }
    }

    pub fn request_type(&self) -> RepairRequestType {
        match self {
            Self::Shred { .. } => RepairRequestType::Shred,
            Self::HighestShred { .. } => RepairRequestType::HighestShred,
            Self::SlotRange { .. } => RepairRequestType::SlotRange,
            Self::Orphan { .. } => RepairRequestType::Orphan,
            Self::Ancestor { .. } => RepairRequestType::Ancestor,
        }
    }
}

/// Shred data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShredData {
    pub slot: Slot,
    pub index: ShredIndex,
    pub data: Vec<u8>,
    pub is_last_in_slot: bool,
}

impl ShredData {
    pub fn new(slot: Slot, index: ShredIndex, data: Vec<u8>, is_last_in_slot: bool) -> Self {
        Self {
            slot,
            index,
            data,
            is_last_in_slot,
        }
    }

    pub fn size(&self) -> usize {
        self.data.len()
    }
}

/// Repair response message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RepairResponse {
    /// Single shred response
    Shred {
        responder: NodeId,
        shred: Option<ShredData>,
        nonce: u64,
    },
    /// Highest shred response
    HighestShred {
        responder: NodeId,
        slot: Slot,
        index: Option<ShredIndex>,
        nonce: u64,
    },
    /// Multiple shreds response
    Shreds {
        responder: NodeId,
        shreds: Vec<ShredData>,
        nonce: u64,
    },
    /// Error response
    Error {
        responder: NodeId,
        error_code: u32,
        message: String,
        nonce: u64,
    },
}

impl RepairResponse {
    pub fn responder(&self) -> NodeId {
        match self {
            Self::Shred { responder, .. } => *responder,
            Self::HighestShred { responder, .. } => *responder,
            Self::Shreds { responder, .. } => *responder,
            Self::Error { responder, .. } => *responder,
        }
    }

    pub fn nonce(&self) -> u64 {
        match self {
            Self::Shred { nonce, .. } => *nonce,
            Self::HighestShred { nonce, .. } => *nonce,
            Self::Shreds { nonce, .. } => *nonce,
            Self::Error { nonce, .. } => *nonce,
        }
    }

    pub fn is_error(&self) -> bool {
        matches!(self, Self::Error { .. })
    }
}

/// Repair message envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RepairMessage {
    Request(RepairRequest),
    Response(RepairResponse),
}

impl RepairMessage {
    /// Encode message to bytes with version prefix
    pub fn encode(&self) -> Result<Bytes, IngressError> {
        let serialized = bincode::serialize(self).map_err(|e| IngressError::Serialization {
            detail: format!("failed to serialize repair message: {}", e),
        })?;

        let mut buf = BytesMut::with_capacity(4 + serialized.len());
        buf.put_u16(REPAIR_PROTOCOL_VERSION);
        buf.put_u16(serialized.len() as u16);
        buf.put_slice(&serialized);

        Ok(buf.freeze())
    }

    /// Decode message from bytes with version check
    pub fn decode(mut bytes: Bytes) -> Result<Self, IngressError> {
        if bytes.remaining() < 4 {
            return Err(IngressError::Deserialization {
                detail: "repair message too short".to_string(),
            });
        }

        let version = bytes.get_u16();
        if version != REPAIR_PROTOCOL_VERSION {
            return Err(IngressError::Deserialization {
                detail: format!(
                    "incompatible repair protocol version: expected {}, got {}",
                    REPAIR_PROTOCOL_VERSION, version
                ),
            });
        }

        let len = bytes.get_u16() as usize;
        if bytes.remaining() < len {
            return Err(IngressError::Deserialization {
                detail: "incomplete repair message".to_string(),
            });
        }

        let message_bytes = bytes.copy_to_bytes(len);
        bincode::deserialize(&message_bytes).map_err(|e| IngressError::Deserialization {
            detail: format!("failed to deserialize repair message: {}", e),
        })
    }

    pub fn is_request(&self) -> bool {
        matches!(self, Self::Request(_))
    }

    pub fn is_response(&self) -> bool {
        matches!(self, Self::Response(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_repair_protocol_version() {
        let v1 = RepairProtocol::current();
        let v2 = RepairProtocol(REPAIR_PROTOCOL_VERSION);
        assert!(v1.is_compatible(&v2));

        let v3 = RepairProtocol(REPAIR_PROTOCOL_VERSION + 1);
        assert!(!v1.is_compatible(&v3));
    }

    #[test]
    fn test_request_type_conversion() {
        assert_eq!(
            RepairRequestType::from_u8(1),
            Some(RepairRequestType::Shred)
        );
        assert_eq!(
            RepairRequestType::from_u8(2),
            Some(RepairRequestType::HighestShred)
        );
        assert_eq!(RepairRequestType::from_u8(99), None);
    }

    #[test]
    fn test_repair_request_creation() {
        let requester = NodeId::new([1u8; 32]);
        let request = RepairRequest::Shred {
            requester,
            slot: 100,
            index: 5,
            nonce: 12345,
        };

        assert_eq!(request.requester(), requester);
        assert_eq!(request.nonce(), 12345);
        assert_eq!(request.request_type(), RepairRequestType::Shred);
    }

    #[test]
    fn test_shred_data_creation() {
        let data = vec![1, 2, 3, 4, 5];
        let shred = ShredData::new(100, 5, data.clone(), false);

        assert_eq!(shred.slot, 100);
        assert_eq!(shred.index, 5);
        assert_eq!(shred.data, data);
        assert_eq!(shred.size(), 5);
    }

    #[test]
    fn test_repair_message_encode_decode() {
        let requester = NodeId::new([1u8; 32]);
        let request = RepairRequest::HighestShred {
            requester,
            slot: 100,
            nonce: 12345,
        };
        let message = RepairMessage::Request(request);

        let encoded = message.encode().unwrap();
        let decoded = RepairMessage::decode(encoded).unwrap();

        assert!(decoded.is_request());
        if let RepairMessage::Request(RepairRequest::HighestShred { slot, nonce, .. }) = decoded {
            assert_eq!(slot, 100);
            assert_eq!(nonce, 12345);
        } else {
            panic!("wrong message type");
        }
    }

    #[test]
    fn test_repair_response_error() {
        let responder = NodeId::new([1u8; 32]);
        let response = RepairResponse::Error {
            responder,
            error_code: 404,
            message: "not found".to_string(),
            nonce: 12345,
        };

        assert!(response.is_error());
        assert_eq!(response.nonce(), 12345);
    }
}
