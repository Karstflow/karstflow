/// `FragmentCodec` implementations for pipeline message types.
///
/// All multi-byte integers are little-endian.
use paradencer_mesh::FragmentCodec;
use paradencer_types::shred::Shred;

use crate::fec_resolver::EquivocationProof;
use crate::pipeline_service::RawTransaction;
use crate::shred_assembler::{AssembledBlock, Entry};
use crate::shred_network::{CompletedFecSet, RetransmitDecision};
use crate::verify_stage::{TransactionSource, UnverifiedTransaction, VerifiedTransaction};

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

// ---------------------------------------------------------------------------
// UnverifiedTransaction codec
// ---------------------------------------------------------------------------
// Encoding: [source:1][num_signatures:2][signature_offset:4][message_offset:4]
//           [signer_count:2][signer_offsets:4*N][payload_len:4][payload:M]

const UNVERIFIED_HEADER: usize = 1 + 2 + 4 + 4 + 2;
const UNVERIFIED_MAX_SIGNERS: usize = 64;
const UNVERIFIED_MAX_ENCODED: usize =
    UNVERIFIED_HEADER + 4 * UNVERIFIED_MAX_SIGNERS + 4 + RAW_TX_MAX_PAYLOAD;

impl FragmentCodec for UnverifiedTransaction {
    fn encode(&self, buf: &mut [u8]) -> usize {
        let mut pos = 0;
        buf[pos] = encode_tx_source(&self.source);
        pos += 1;
        buf[pos..pos + 2].copy_from_slice(&self.num_signatures.to_le_bytes());
        pos += 2;
        buf[pos..pos + 4].copy_from_slice(&(self.signature_offset as u32).to_le_bytes());
        pos += 4;
        buf[pos..pos + 4].copy_from_slice(&(self.message_offset as u32).to_le_bytes());
        pos += 4;
        let signer_count = self.signer_offsets.len().min(UNVERIFIED_MAX_SIGNERS);
        buf[pos..pos + 2].copy_from_slice(&(signer_count as u16).to_le_bytes());
        pos += 2;
        for &offset in &self.signer_offsets[..signer_count] {
            buf[pos..pos + 4].copy_from_slice(&(offset as u32).to_le_bytes());
            pos += 4;
        }
        let payload_len = self.payload.len().min(RAW_TX_MAX_PAYLOAD);
        buf[pos..pos + 4].copy_from_slice(&(payload_len as u32).to_le_bytes());
        pos += 4;
        buf[pos..pos + payload_len].copy_from_slice(&self.payload[..payload_len]);
        pos + payload_len
    }

    fn decode(bytes: &[u8]) -> Self {
        let mut pos = 0;
        let source = decode_tx_source(bytes[pos]);
        pos += 1;
        let num_signatures = u16::from_le_bytes(bytes[pos..pos + 2].try_into().unwrap());
        pos += 2;
        let signature_offset = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let message_offset = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let signer_count = u16::from_le_bytes(bytes[pos..pos + 2].try_into().unwrap()) as usize;
        pos += 2;
        let mut signer_offsets = Vec::with_capacity(signer_count);
        for _ in 0..signer_count {
            signer_offsets
                .push(u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize);
            pos += 4;
        }
        let payload_len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let payload = bytes[pos..pos + payload_len].to_vec();
        Self {
            payload,
            source,
            num_signatures,
            signature_offset,
            message_offset,
            signer_offsets,
        }
    }

    fn max_encoded_size() -> usize {
        UNVERIFIED_MAX_ENCODED
    }
}

// ---------------------------------------------------------------------------
// VerifiedTransaction codec
// ---------------------------------------------------------------------------
// Encoding: [source:1][num_signatures:2][payload_len:4][payload:N]

const VERIFIED_HEADER: usize = 1 + 2 + 4;
const VERIFIED_MAX_ENCODED: usize = VERIFIED_HEADER + RAW_TX_MAX_PAYLOAD;

impl FragmentCodec for VerifiedTransaction {
    fn encode(&self, buf: &mut [u8]) -> usize {
        let mut pos = 0;
        buf[pos] = encode_tx_source(&self.source);
        pos += 1;
        buf[pos..pos + 2].copy_from_slice(&self.num_signatures.to_le_bytes());
        pos += 2;
        let payload_len = self.payload.len().min(RAW_TX_MAX_PAYLOAD);
        buf[pos..pos + 4].copy_from_slice(&(payload_len as u32).to_le_bytes());
        pos += 4;
        buf[pos..pos + payload_len].copy_from_slice(&self.payload[..payload_len]);
        pos + payload_len
    }

    fn decode(bytes: &[u8]) -> Self {
        let mut pos = 0;
        let source = decode_tx_source(bytes[pos]);
        pos += 1;
        let num_signatures = u16::from_le_bytes(bytes[pos..pos + 2].try_into().unwrap());
        pos += 2;
        let payload_len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let payload = bytes[pos..pos + payload_len].to_vec();
        Self {
            payload,
            source,
            num_signatures,
        }
    }

    fn max_encoded_size() -> usize {
        VERIFIED_MAX_ENCODED
    }
}

// ---------------------------------------------------------------------------
// RetransmitDecision codec
// ---------------------------------------------------------------------------
// Encoding: [slot:8][shred_len:4][shred_data:N][dest_count:2][dest_indices:2*M]

const RETRANSMIT_HEADER: usize = 8 + 4;
const RETRANSMIT_MAX_SHRED: usize = 1280;
const RETRANSMIT_MAX_DESTS: usize = 512;
const RETRANSMIT_MAX_ENCODED: usize =
    RETRANSMIT_HEADER + RETRANSMIT_MAX_SHRED + 2 + 2 * RETRANSMIT_MAX_DESTS;

impl FragmentCodec for RetransmitDecision {
    fn encode(&self, buf: &mut [u8]) -> usize {
        let mut pos = 0;
        buf[pos..pos + 8].copy_from_slice(&self.slot.to_le_bytes());
        pos += 8;
        let shred_len = self.shred_data.len().min(RETRANSMIT_MAX_SHRED);
        buf[pos..pos + 4].copy_from_slice(&(shred_len as u32).to_le_bytes());
        pos += 4;
        buf[pos..pos + shred_len].copy_from_slice(&self.shred_data[..shred_len]);
        pos += shred_len;
        let dest_count = self.destination_indices.len().min(RETRANSMIT_MAX_DESTS);
        buf[pos..pos + 2].copy_from_slice(&(dest_count as u16).to_le_bytes());
        pos += 2;
        for &idx in &self.destination_indices[..dest_count] {
            buf[pos..pos + 2].copy_from_slice(&idx.to_le_bytes());
            pos += 2;
        }
        pos
    }

    fn decode(bytes: &[u8]) -> Self {
        let mut pos = 0;
        let slot = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap());
        pos += 8;
        let shred_len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let shred_data = bytes[pos..pos + shred_len].to_vec();
        pos += shred_len;
        let dest_count = u16::from_le_bytes(bytes[pos..pos + 2].try_into().unwrap()) as usize;
        pos += 2;
        let mut destination_indices = Vec::with_capacity(dest_count);
        for _ in 0..dest_count {
            destination_indices.push(u16::from_le_bytes(bytes[pos..pos + 2].try_into().unwrap()));
            pos += 2;
        }
        Self {
            shred_data,
            destination_indices,
            slot,
        }
    }

    fn max_encoded_size() -> usize {
        RETRANSMIT_MAX_ENCODED
    }

    fn signature(&self) -> u64 {
        self.slot
    }
}

// ---------------------------------------------------------------------------
// CompletedFecSet codec
// ---------------------------------------------------------------------------
// Encoding: [slot:8][fec_set_index:4][was_recovered:1][shred_count:2]
//           [shred_0_len:4][shred_0_encoded:N]...

const FEC_SET_HEADER: usize = 8 + 4 + 1 + 2;
const FEC_SET_MAX_SHREDS: usize = 67;
// Shred max encoded = 83 (common header) + 308 (variant) + 4 (payload len) + 1280 (payload) = 1675
const SHRED_CODEC_MAX: usize = 1675;
const FEC_SET_MAX_ENCODED: usize = FEC_SET_HEADER + FEC_SET_MAX_SHREDS * (4 + SHRED_CODEC_MAX);

impl FragmentCodec for CompletedFecSet {
    fn encode(&self, buf: &mut [u8]) -> usize {
        let mut pos = 0;
        buf[pos..pos + 8].copy_from_slice(&self.slot.to_le_bytes());
        pos += 8;
        buf[pos..pos + 4].copy_from_slice(&self.fec_set_index.to_le_bytes());
        pos += 4;
        buf[pos] = self.was_recovered as u8;
        pos += 1;
        let count = self.data_shreds.len().min(FEC_SET_MAX_SHREDS);
        buf[pos..pos + 2].copy_from_slice(&(count as u16).to_le_bytes());
        pos += 2;
        for shred in &self.data_shreds[..count] {
            let shred_len = shred.encode(&mut buf[pos + 4..]);
            buf[pos..pos + 4].copy_from_slice(&(shred_len as u32).to_le_bytes());
            pos += 4 + shred_len;
        }
        pos
    }

    fn decode(bytes: &[u8]) -> Self {
        let mut pos = 0;
        let slot = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap());
        pos += 8;
        let fec_set_index = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let was_recovered = bytes[pos] != 0;
        pos += 1;
        let count = u16::from_le_bytes(bytes[pos..pos + 2].try_into().unwrap()) as usize;
        pos += 2;
        let mut data_shreds = Vec::with_capacity(count);
        for _ in 0..count {
            let shred_len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            let shred = Shred::decode(&bytes[pos..pos + shred_len]);
            pos += shred_len;
            data_shreds.push(shred);
        }
        Self {
            slot,
            fec_set_index,
            data_shreds,
            was_recovered,
        }
    }

    fn max_encoded_size() -> usize {
        FEC_SET_MAX_ENCODED
    }

    fn signature(&self) -> u64 {
        self.slot
    }
}

// ---------------------------------------------------------------------------
// AssembledBlock codec
// ---------------------------------------------------------------------------
// Encoding: [slot:8][parent_slot:8][tx_count:4][total_bytes:4][shred_count:4]
//           [entry_count:4][entry_0...entry_N]
// Entry:    [num_hashes:8][hash:32][tx_count:4][tx_0_len:4][tx_0_data:N]...

const BLOCK_HEADER: usize = 8 + 8 + 4 + 4 + 4 + 4;
// Conservative max: 256 entries, each with up to 64 txs of 1232 bytes.
const BLOCK_MAX_ENCODED: usize = 4 * 1024 * 1024;

fn encode_entry(entry: &Entry, buf: &mut [u8]) -> usize {
    let mut pos = 0;
    buf[pos..pos + 8].copy_from_slice(&entry.num_hashes.to_le_bytes());
    pos += 8;
    buf[pos..pos + 32].copy_from_slice(&entry.hash);
    pos += 32;
    let tx_count = entry.transactions.len();
    buf[pos..pos + 4].copy_from_slice(&(tx_count as u32).to_le_bytes());
    pos += 4;
    for tx in &entry.transactions {
        let tx_len = tx.len();
        buf[pos..pos + 4].copy_from_slice(&(tx_len as u32).to_le_bytes());
        pos += 4;
        buf[pos..pos + tx_len].copy_from_slice(tx);
        pos += tx_len;
    }
    pos
}

fn decode_entry(bytes: &[u8]) -> (Entry, usize) {
    let mut pos = 0;
    let num_hashes = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap());
    pos += 8;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes[pos..pos + 32]);
    pos += 32;
    let tx_count = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    let mut transactions = Vec::with_capacity(tx_count);
    for _ in 0..tx_count {
        let tx_len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        transactions.push(bytes[pos..pos + tx_len].to_vec());
        pos += tx_len;
    }
    (
        Entry {
            num_hashes,
            hash,
            transactions,
        },
        pos,
    )
}

impl FragmentCodec for AssembledBlock {
    fn encode(&self, buf: &mut [u8]) -> usize {
        let mut pos = 0;
        buf[pos..pos + 8].copy_from_slice(&self.slot.to_le_bytes());
        pos += 8;
        buf[pos..pos + 8].copy_from_slice(&self.parent_slot.to_le_bytes());
        pos += 8;
        buf[pos..pos + 4].copy_from_slice(&(self.transaction_count as u32).to_le_bytes());
        pos += 4;
        buf[pos..pos + 4].copy_from_slice(&(self.total_bytes as u32).to_le_bytes());
        pos += 4;
        buf[pos..pos + 4].copy_from_slice(&(self.shred_count as u32).to_le_bytes());
        pos += 4;
        let entry_count = self.entries.len();
        buf[pos..pos + 4].copy_from_slice(&(entry_count as u32).to_le_bytes());
        pos += 4;
        for entry in &self.entries {
            let entry_len = encode_entry(entry, &mut buf[pos..]);
            pos += entry_len;
        }
        pos
    }

    fn decode(bytes: &[u8]) -> Self {
        let mut pos = 0;
        let slot = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap());
        pos += 8;
        let parent_slot = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap());
        pos += 8;
        let transaction_count =
            u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let total_bytes = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let shred_count = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let entry_count = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            let (entry, consumed) = decode_entry(&bytes[pos..]);
            pos += consumed;
            entries.push(entry);
        }
        Self {
            slot,
            parent_slot,
            entries,
            transaction_count,
            total_bytes,
            shred_count,
        }
    }

    fn max_encoded_size() -> usize {
        BLOCK_MAX_ENCODED
    }

    fn signature(&self) -> u64 {
        self.slot
    }
}

// ---------------------------------------------------------------------------
// EquivocationProof codec
// ---------------------------------------------------------------------------
// Fixed layout: [slot:8][fec_set_index:4][position:4]
//               [existing_signature:64][conflicting_signature:64]

const EQUIVOCATION_PROOF_SIZE: usize = 8 + 4 + 4 + 64 + 64;

impl FragmentCodec for EquivocationProof {
    fn encode(&self, buf: &mut [u8]) -> usize {
        buf[0..8].copy_from_slice(&self.slot.to_le_bytes());
        buf[8..12].copy_from_slice(&self.fec_set_index.to_le_bytes());
        buf[12..16].copy_from_slice(&self.position.to_le_bytes());
        buf[16..80].copy_from_slice(&self.existing_signature);
        buf[80..144].copy_from_slice(&self.conflicting_signature);
        EQUIVOCATION_PROOF_SIZE
    }

    fn decode(bytes: &[u8]) -> Self {
        let slot = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let fec_set_index = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        let position = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        let mut existing_signature = [0u8; 64];
        existing_signature.copy_from_slice(&bytes[16..80]);
        let mut conflicting_signature = [0u8; 64];
        conflicting_signature.copy_from_slice(&bytes[80..144]);
        Self {
            slot,
            fec_set_index,
            position,
            existing_signature,
            conflicting_signature,
        }
    }

    fn max_encoded_size() -> usize {
        EQUIVOCATION_PROOF_SIZE
    }

    fn signature(&self) -> u64 {
        self.slot
    }
}

// ---------------------------------------------------------------------------
// ShredBatch codec — newtype for shred batch transfer to replay service
// ---------------------------------------------------------------------------
// Encoding: [count:4][shred_0_len:4][shred_0_encoded:N]...

/// Newtype wrapper for a batch of shreds, enabling FragmentCodec implementation.
pub struct ShredBatch(pub Vec<Shred>);

const SHRED_BATCH_MAX_COUNT: usize = 128;
const SHRED_BATCH_MAX_ENCODED: usize = 4 + SHRED_BATCH_MAX_COUNT * (4 + SHRED_CODEC_MAX);

impl FragmentCodec for ShredBatch {
    fn encode(&self, buf: &mut [u8]) -> usize {
        let mut pos = 0;
        let count = self.0.len().min(SHRED_BATCH_MAX_COUNT);
        buf[pos..pos + 4].copy_from_slice(&(count as u32).to_le_bytes());
        pos += 4;
        for shred in &self.0[..count] {
            let shred_len = shred.encode(&mut buf[pos + 4..]);
            buf[pos..pos + 4].copy_from_slice(&(shred_len as u32).to_le_bytes());
            pos += 4 + shred_len;
        }
        pos
    }

    fn decode(bytes: &[u8]) -> Self {
        let mut pos = 0;
        let count = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let mut shreds = Vec::with_capacity(count);
        for _ in 0..count {
            let shred_len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            let shred = Shred::decode(&bytes[pos..pos + shred_len]);
            pos += shred_len;
            shreds.push(shred);
        }
        ShredBatch(shreds)
    }

    fn max_encoded_size() -> usize {
        SHRED_BATCH_MAX_ENCODED
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paradencer_types::shred::{
        DataShredHeader, ShredCommonHeader, ShredVariant, SIGNATURE_SIZE,
    };

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

    fn make_test_shred(slot: u64, index: u32) -> Shred {
        Shred::new(
            ShredCommonHeader {
                signature: [0x42; SIGNATURE_SIZE],
                variant: 0x55,
                slot,
                index,
                version: 1,
                fec_set_index: 0,
            },
            ShredVariant::LegacyData(DataShredHeader {
                parent_offset: 1,
                flags: 0,
                size: 32,
            }),
            vec![0xAB; 32],
        )
    }

    #[test]
    fn retransmit_decision_codec_roundtrip() {
        let decision = RetransmitDecision {
            shred_data: vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02],
            destination_indices: vec![3, 7, 15, 42],
            slot: 12345,
        };
        let mut buf = vec![0u8; RetransmitDecision::max_encoded_size()];
        let len = decision.encode(&mut buf);
        let decoded = RetransmitDecision::decode(&buf[..len]);
        assert_eq!(decoded.slot, 12345);
        assert_eq!(decoded.shred_data, vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02]);
        assert_eq!(decoded.destination_indices, vec![3, 7, 15, 42]);
    }

    #[test]
    fn retransmit_decision_empty_destinations() {
        let decision = RetransmitDecision {
            shred_data: vec![1, 2, 3],
            destination_indices: vec![],
            slot: 0,
        };
        let mut buf = vec![0u8; RetransmitDecision::max_encoded_size()];
        let len = decision.encode(&mut buf);
        let decoded = RetransmitDecision::decode(&buf[..len]);
        assert_eq!(decoded.destination_indices.len(), 0);
        assert_eq!(decoded.shred_data, vec![1, 2, 3]);
    }

    #[test]
    fn completed_fec_set_codec_roundtrip() {
        let fec = CompletedFecSet {
            slot: 999,
            fec_set_index: 7,
            data_shreds: vec![make_test_shred(999, 0), make_test_shred(999, 1)],
            was_recovered: true,
        };
        let mut buf = vec![0u8; CompletedFecSet::max_encoded_size()];
        let len = fec.encode(&mut buf);
        let decoded = CompletedFecSet::decode(&buf[..len]);
        assert_eq!(decoded.slot, 999);
        assert_eq!(decoded.fec_set_index, 7);
        assert!(decoded.was_recovered);
        assert_eq!(decoded.data_shreds.len(), 2);
        assert_eq!(decoded.data_shreds[0].common_header.index, 0);
        assert_eq!(decoded.data_shreds[1].common_header.index, 1);
        assert_eq!(decoded.data_shreds[0].payload, vec![0xAB; 32]);
    }

    #[test]
    fn completed_fec_set_empty_shreds() {
        let fec = CompletedFecSet {
            slot: 0,
            fec_set_index: 0,
            data_shreds: vec![],
            was_recovered: false,
        };
        let mut buf = vec![0u8; CompletedFecSet::max_encoded_size()];
        let len = fec.encode(&mut buf);
        let decoded = CompletedFecSet::decode(&buf[..len]);
        assert_eq!(decoded.data_shreds.len(), 0);
        assert!(!decoded.was_recovered);
    }

    #[test]
    fn assembled_block_codec_roundtrip() {
        let block = AssembledBlock {
            slot: 500,
            parent_slot: 499,
            entries: vec![
                Entry {
                    num_hashes: 12345,
                    hash: [0xCC; 32],
                    transactions: vec![vec![1, 2, 3], vec![4, 5, 6, 7]],
                },
                Entry {
                    num_hashes: 0,
                    hash: [0xDD; 32],
                    transactions: vec![],
                },
            ],
            transaction_count: 2,
            total_bytes: 100,
            shred_count: 5,
        };
        let mut buf = vec![0u8; AssembledBlock::max_encoded_size()];
        let len = block.encode(&mut buf);
        let decoded = AssembledBlock::decode(&buf[..len]);
        assert_eq!(decoded.slot, 500);
        assert_eq!(decoded.parent_slot, 499);
        assert_eq!(decoded.transaction_count, 2);
        assert_eq!(decoded.total_bytes, 100);
        assert_eq!(decoded.shred_count, 5);
        assert_eq!(decoded.entries.len(), 2);
        assert_eq!(decoded.entries[0].num_hashes, 12345);
        assert_eq!(decoded.entries[0].hash, [0xCC; 32]);
        assert_eq!(decoded.entries[0].transactions.len(), 2);
        assert_eq!(decoded.entries[0].transactions[0], vec![1, 2, 3]);
        assert_eq!(decoded.entries[0].transactions[1], vec![4, 5, 6, 7]);
        assert_eq!(decoded.entries[1].transactions.len(), 0);
    }

    #[test]
    fn assembled_block_empty() {
        let block = AssembledBlock {
            slot: 0,
            parent_slot: 0,
            entries: vec![],
            transaction_count: 0,
            total_bytes: 0,
            shred_count: 0,
        };
        let mut buf = vec![0u8; AssembledBlock::max_encoded_size()];
        let len = block.encode(&mut buf);
        assert_eq!(len, BLOCK_HEADER);
        let decoded = AssembledBlock::decode(&buf[..len]);
        assert_eq!(decoded.entries.len(), 0);
    }

    #[test]
    fn equivocation_proof_codec_roundtrip() {
        let proof = EquivocationProof {
            slot: 42_000,
            fec_set_index: 7,
            position: 3,
            existing_signature: [0xAA; 64],
            conflicting_signature: [0xBB; 64],
        };
        let mut buf = vec![0u8; EquivocationProof::max_encoded_size()];
        let len = proof.encode(&mut buf);
        assert_eq!(len, EQUIVOCATION_PROOF_SIZE);
        let decoded = EquivocationProof::decode(&buf[..len]);
        assert_eq!(decoded.slot, 42_000);
        assert_eq!(decoded.fec_set_index, 7);
        assert_eq!(decoded.position, 3);
        assert_eq!(decoded.existing_signature, [0xAA; 64]);
        assert_eq!(decoded.conflicting_signature, [0xBB; 64]);
    }

    #[test]
    fn shred_batch_codec_roundtrip() {
        let batch = ShredBatch(vec![
            make_test_shred(100, 0),
            make_test_shred(100, 1),
            make_test_shred(101, 0),
        ]);
        let mut buf = vec![0u8; ShredBatch::max_encoded_size()];
        let len = batch.encode(&mut buf);
        let decoded = ShredBatch::decode(&buf[..len]);
        assert_eq!(decoded.0.len(), 3);
        assert_eq!(decoded.0[0].common_header.slot, 100);
        assert_eq!(decoded.0[0].common_header.index, 0);
        assert_eq!(decoded.0[1].common_header.index, 1);
        assert_eq!(decoded.0[2].common_header.slot, 101);
    }

    #[test]
    fn shred_batch_empty_roundtrip() {
        let batch = ShredBatch(vec![]);
        let mut buf = vec![0u8; ShredBatch::max_encoded_size()];
        let len = batch.encode(&mut buf);
        assert_eq!(len, 4); // just the count
        let decoded = ShredBatch::decode(&buf[..len]);
        assert!(decoded.0.is_empty());
    }
}
