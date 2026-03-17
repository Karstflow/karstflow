/// `FragmentCodec` implementations for `InboundFrame` and `PreparedTransaction`.
///
/// Encoding uses fixed LE headers followed by variable-length payload.
use karstflow_mesh::FragmentCodec;

use super::domain::{InboundFrame, IngressSource, PreparedTransaction};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn encode_ingress_source(source: IngressSource) -> u8 {
    match source {
        IngressSource::Quic => 0,
        IngressSource::Gossip => 1,
        IngressSource::Bundle => 2,
        IngressSource::Rpc => 3,
        IngressSource::Tvu => 4,
    }
}

fn decode_ingress_source(byte: u8) -> IngressSource {
    match byte {
        0 => IngressSource::Quic,
        1 => IngressSource::Gossip,
        2 => IngressSource::Bundle,
        3 => IngressSource::Rpc,
        _ => IngressSource::Tvu,
    }
}

// ---------------------------------------------------------------------------
// InboundFrame
// ---------------------------------------------------------------------------
// Layout: [packet_id:8][payload_bytes:4][source:1][data_len:4][data:...]

const INBOUND_FRAME_HEADER: usize = 8 + 4 + 1 + 4;
const INBOUND_FRAME_MAX_DATA: usize = 1536;

impl FragmentCodec for InboundFrame {
    fn encode(&self, buf: &mut [u8]) -> usize {
        buf[..8].copy_from_slice(&self.packet_id.to_le_bytes());
        buf[8..12].copy_from_slice(&(self.payload_bytes as u32).to_le_bytes());
        buf[12] = encode_ingress_source(self.source);
        let data_len = self.data.len().min(INBOUND_FRAME_MAX_DATA);
        buf[13..17].copy_from_slice(&(data_len as u32).to_le_bytes());
        buf[17..17 + data_len].copy_from_slice(&self.data[..data_len]);
        INBOUND_FRAME_HEADER + data_len
    }

    fn decode(bytes: &[u8]) -> Self {
        let packet_id = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let payload_bytes = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
        let source = decode_ingress_source(bytes[12]);
        let data_len = u32::from_le_bytes(bytes[13..17].try_into().unwrap()) as usize;
        let data = bytes[17..17 + data_len].to_vec();
        Self {
            packet_id,
            payload_bytes,
            source,
            data,
        }
    }

    fn max_encoded_size() -> usize {
        INBOUND_FRAME_HEADER + INBOUND_FRAME_MAX_DATA
    }

    fn signature(&self) -> u64 {
        self.packet_id
    }
}

// ---------------------------------------------------------------------------
// PreparedTransaction
// ---------------------------------------------------------------------------
// Layout: [tx_id:8][cost_units:8][dedup_fp:8][source:1][payload_len:4][payload:...]

const PREPARED_TX_HEADER: usize = 8 + 8 + 8 + 1 + 4;
const PREPARED_TX_MAX_PAYLOAD: usize = 1280;

impl FragmentCodec for PreparedTransaction {
    fn encode(&self, buf: &mut [u8]) -> usize {
        buf[..8].copy_from_slice(&self.transaction_id.to_le_bytes());
        buf[8..16].copy_from_slice(&self.estimated_cost_units.to_le_bytes());
        buf[16..24].copy_from_slice(&self.dedup_fingerprint.to_le_bytes());
        buf[24] = encode_ingress_source(self.source);
        let payload_len = self.raw_payload.len().min(PREPARED_TX_MAX_PAYLOAD);
        buf[25..29].copy_from_slice(&(payload_len as u32).to_le_bytes());
        buf[29..29 + payload_len].copy_from_slice(&self.raw_payload[..payload_len]);
        PREPARED_TX_HEADER + payload_len
    }

    fn decode(bytes: &[u8]) -> Self {
        let transaction_id = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let estimated_cost_units = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let dedup_fingerprint = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
        let source = decode_ingress_source(bytes[24]);
        let payload_len = u32::from_le_bytes(bytes[25..29].try_into().unwrap()) as usize;
        let raw_payload = bytes[29..29 + payload_len].to_vec();
        Self {
            transaction_id,
            estimated_cost_units,
            dedup_fingerprint,
            source,
            raw_payload,
        }
    }

    fn max_encoded_size() -> usize {
        PREPARED_TX_HEADER + PREPARED_TX_MAX_PAYLOAD
    }

    fn signature(&self) -> u64 {
        self.dedup_fingerprint
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inbound_frame_codec_roundtrip() {
        let frame = InboundFrame {
            packet_id: 12345,
            payload_bytes: 100,
            source: IngressSource::Gossip,
            data: vec![0xAA; 100],
        };
        let mut buf = vec![0u8; InboundFrame::max_encoded_size()];
        let len = frame.encode(&mut buf);
        let decoded = InboundFrame::decode(&buf[..len]);
        assert_eq!(decoded.packet_id, 12345);
        assert_eq!(decoded.payload_bytes, 100);
        assert_eq!(decoded.source, IngressSource::Gossip);
        assert_eq!(decoded.data, vec![0xAA; 100]);
    }

    #[test]
    fn inbound_frame_empty_data() {
        let frame = InboundFrame {
            packet_id: 0,
            payload_bytes: 0,
            source: IngressSource::Quic,
            data: vec![],
        };
        let mut buf = vec![0u8; InboundFrame::max_encoded_size()];
        let len = frame.encode(&mut buf);
        let decoded = InboundFrame::decode(&buf[..len]);
        assert_eq!(decoded.data.len(), 0);
        assert_eq!(decoded.source, IngressSource::Quic);
    }

    #[test]
    fn prepared_transaction_codec_roundtrip() {
        let tx = PreparedTransaction {
            transaction_id: 9999,
            estimated_cost_units: 200_000,
            dedup_fingerprint: 0xDEAD_BEEF,
            source: IngressSource::Bundle,
            raw_payload: vec![0xBB; 256],
        };
        let mut buf = vec![0u8; PreparedTransaction::max_encoded_size()];
        let len = tx.encode(&mut buf);
        let decoded = PreparedTransaction::decode(&buf[..len]);
        assert_eq!(decoded.transaction_id, 9999);
        assert_eq!(decoded.estimated_cost_units, 200_000);
        assert_eq!(decoded.dedup_fingerprint, 0xDEAD_BEEF);
        assert_eq!(decoded.source, IngressSource::Bundle);
        assert_eq!(decoded.raw_payload, vec![0xBB; 256]);
    }

    #[test]
    fn all_ingress_sources_roundtrip() {
        for source in [
            IngressSource::Quic,
            IngressSource::Gossip,
            IngressSource::Bundle,
            IngressSource::Rpc,
            IngressSource::Tvu,
        ] {
            let frame = InboundFrame {
                packet_id: 0,
                payload_bytes: 0,
                source,
                data: vec![],
            };
            let mut buf = vec![0u8; InboundFrame::max_encoded_size()];
            let len = frame.encode(&mut buf);
            let decoded = InboundFrame::decode(&buf[..len]);
            assert_eq!(decoded.source, source);
        }
    }
}
