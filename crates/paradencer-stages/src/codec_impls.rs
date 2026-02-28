/// `FragmentCodec` implementation for `RawTransaction`.
///
/// Encoding format: [source:1][payload_len:4][payload:...]
/// All multi-byte integers are little-endian.
use paradencer_mesh::FragmentCodec;

use crate::pipeline_service::RawTransaction;
use crate::verify_stage::TransactionSource;

const RAW_TX_HEADER: usize = 1 + 4;
const RAW_TX_MAX_PAYLOAD: usize = 1280;

fn encode_tx_source(source: &TransactionSource) -> u8 {
    match source {
        TransactionSource::Quic => 0,
        TransactionSource::Gossip => 1,
        TransactionSource::Bundle => 2,
        TransactionSource::Forwarded => 3,
    }
}

fn decode_tx_source(byte: u8) -> TransactionSource {
    match byte {
        0 => TransactionSource::Quic,
        1 => TransactionSource::Gossip,
        2 => TransactionSource::Bundle,
        _ => TransactionSource::Forwarded,
    }
}

impl FragmentCodec for RawTransaction {
    fn encode(&self, buf: &mut [u8]) -> usize {
        buf[0] = encode_tx_source(&self.source);
        let payload_len = self.payload.len().min(RAW_TX_MAX_PAYLOAD);
        buf[1..5].copy_from_slice(&(payload_len as u32).to_le_bytes());
        buf[5..5 + payload_len].copy_from_slice(&self.payload[..payload_len]);
        RAW_TX_HEADER + payload_len
    }

    fn decode(bytes: &[u8]) -> Self {
        let source = decode_tx_source(bytes[0]);
        let payload_len = u32::from_le_bytes(bytes[1..5].try_into().unwrap()) as usize;
        let payload = bytes[5..5 + payload_len].to_vec();
        Self { payload, source }
    }

    fn max_encoded_size() -> usize {
        RAW_TX_HEADER + RAW_TX_MAX_PAYLOAD
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_transaction_codec_roundtrip() {
        let tx = RawTransaction {
            payload: vec![1, 2, 3, 4, 5],
            source: TransactionSource::Gossip,
        };
        let mut buf = vec![0u8; RawTransaction::max_encoded_size()];
        let len = tx.encode(&mut buf);
        let decoded = RawTransaction::decode(&buf[..len]);
        assert_eq!(decoded.payload, vec![1, 2, 3, 4, 5]);
        assert!(matches!(decoded.source, TransactionSource::Gossip));
    }

    #[test]
    fn all_transaction_sources_roundtrip() {
        for (tag, expected_source) in [
            (TransactionSource::Quic, TransactionSource::Quic),
            (TransactionSource::Gossip, TransactionSource::Gossip),
            (TransactionSource::Bundle, TransactionSource::Bundle),
            (TransactionSource::Forwarded, TransactionSource::Forwarded),
        ] {
            let tx = RawTransaction {
                payload: vec![],
                source: tag,
            };
            let mut buf = vec![0u8; RawTransaction::max_encoded_size()];
            let len = tx.encode(&mut buf);
            let decoded = RawTransaction::decode(&buf[..len]);
            assert_eq!(
                std::mem::discriminant(&decoded.source),
                std::mem::discriminant(&expected_source)
            );
        }
    }
}
