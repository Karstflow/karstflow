/// `FragmentCodec` implementation for `Shred`.
///
/// Encoding format: common_header fields LE, variant tag + header, payload.
/// All multi-byte integers are little-endian.
use karstflow_mesh::FragmentCodec;

use super::types::{
    CodingShredHeader, DataShredHeader, MerkleProof, Shred, ShredCommonHeader, ShredVariant,
    MERKLE_PROOF_NODE_BYTES, SIGNATURE_SIZE,
};

const SHRED_COMMON_HEADER_SIZE: usize = SIGNATURE_SIZE + 1 + 8 + 4 + 2 + 4;
const SHRED_MAX_PAYLOAD: usize = 1280;
// Variant header worst case: tag(1) + coding(6) + proof_count(1) + proof_data(15*20=300)
const SHRED_MAX_VARIANT: usize = 1 + 6 + 1 + 15 * MERKLE_PROOF_NODE_BYTES;
const SHRED_MAX_ENCODED: usize =
    SHRED_COMMON_HEADER_SIZE + SHRED_MAX_VARIANT + 4 + SHRED_MAX_PAYLOAD;

fn encode_data_header(buf: &mut [u8], pos: usize, dh: &DataShredHeader) -> usize {
    let mut p = pos;
    buf[p..p + 2].copy_from_slice(&dh.parent_offset.to_le_bytes());
    p += 2;
    buf[p] = dh.flags;
    p += 1;
    buf[p..p + 2].copy_from_slice(&dh.size.to_le_bytes());
    p += 2;
    p
}

fn decode_data_header(bytes: &[u8], pos: usize) -> (DataShredHeader, usize) {
    let mut p = pos;
    let parent_offset = u16::from_le_bytes(bytes[p..p + 2].try_into().unwrap());
    p += 2;
    let flags = bytes[p];
    p += 1;
    let size = u16::from_le_bytes(bytes[p..p + 2].try_into().unwrap());
    p += 2;
    (
        DataShredHeader {
            parent_offset,
            flags,
            size,
        },
        p,
    )
}

fn encode_coding_header(buf: &mut [u8], pos: usize, ch: &CodingShredHeader) -> usize {
    let mut p = pos;
    buf[p..p + 2].copy_from_slice(&ch.num_data_shreds.to_le_bytes());
    p += 2;
    buf[p..p + 2].copy_from_slice(&ch.num_coding_shreds.to_le_bytes());
    p += 2;
    buf[p..p + 2].copy_from_slice(&ch.position.to_le_bytes());
    p += 2;
    p
}

fn decode_coding_header(bytes: &[u8], pos: usize) -> (CodingShredHeader, usize) {
    let mut p = pos;
    let num_data_shreds = u16::from_le_bytes(bytes[p..p + 2].try_into().unwrap());
    p += 2;
    let num_coding_shreds = u16::from_le_bytes(bytes[p..p + 2].try_into().unwrap());
    p += 2;
    let position = u16::from_le_bytes(bytes[p..p + 2].try_into().unwrap());
    p += 2;
    (
        CodingShredHeader {
            num_data_shreds,
            num_coding_shreds,
            position,
        },
        p,
    )
}

fn encode_merkle_proof(buf: &mut [u8], pos: usize, proof: &MerkleProof) -> usize {
    let mut p = pos;
    let count = proof.proof.len() as u8;
    buf[p] = count;
    p += 1;
    for node in &proof.proof {
        buf[p..p + MERKLE_PROOF_NODE_BYTES].copy_from_slice(node);
        p += MERKLE_PROOF_NODE_BYTES;
    }
    p
}

fn decode_merkle_proof(bytes: &[u8], pos: usize) -> (MerkleProof, usize) {
    let mut p = pos;
    let count = bytes[p] as usize;
    p += 1;
    let mut proof = Vec::with_capacity(count);
    for _ in 0..count {
        let mut node = [0u8; MERKLE_PROOF_NODE_BYTES];
        node.copy_from_slice(&bytes[p..p + MERKLE_PROOF_NODE_BYTES]);
        p += MERKLE_PROOF_NODE_BYTES;
        proof.push(node);
    }
    (MerkleProof { proof }, p)
}

impl FragmentCodec for Shred {
    fn encode(&self, buf: &mut [u8]) -> usize {
        let mut pos = 0;

        // Common header
        buf[pos..pos + SIGNATURE_SIZE].copy_from_slice(&self.common_header.signature);
        pos += SIGNATURE_SIZE;
        buf[pos] = self.common_header.variant;
        pos += 1;
        buf[pos..pos + 8].copy_from_slice(&self.common_header.slot.to_le_bytes());
        pos += 8;
        buf[pos..pos + 4].copy_from_slice(&self.common_header.index.to_le_bytes());
        pos += 4;
        buf[pos..pos + 2].copy_from_slice(&self.common_header.version.to_le_bytes());
        pos += 2;
        buf[pos..pos + 4].copy_from_slice(&self.common_header.fec_set_index.to_le_bytes());
        pos += 4;

        // Variant tag + data
        match &self.variant {
            ShredVariant::LegacyData(dh) => {
                buf[pos] = 0;
                pos += 1;
                pos = encode_data_header(buf, pos, dh);
            }
            ShredVariant::LegacyCoding(ch) => {
                buf[pos] = 1;
                pos += 1;
                pos = encode_coding_header(buf, pos, ch);
            }
            ShredVariant::MerkleData(dh, proof) => {
                buf[pos] = 2;
                pos += 1;
                pos = encode_data_header(buf, pos, dh);
                pos = encode_merkle_proof(buf, pos, proof);
            }
            ShredVariant::MerkleCoding(ch, proof) => {
                buf[pos] = 3;
                pos += 1;
                pos = encode_coding_header(buf, pos, ch);
                pos = encode_merkle_proof(buf, pos, proof);
            }
        }

        // Payload
        let payload_len = self.payload.len().min(SHRED_MAX_PAYLOAD);
        buf[pos..pos + 4].copy_from_slice(&(payload_len as u32).to_le_bytes());
        pos += 4;
        buf[pos..pos + payload_len].copy_from_slice(&self.payload[..payload_len]);
        pos += payload_len;

        pos
    }

    fn decode(bytes: &[u8]) -> Self {
        let mut pos = 0;

        // Common header
        let mut signature = [0u8; SIGNATURE_SIZE];
        signature.copy_from_slice(&bytes[pos..pos + SIGNATURE_SIZE]);
        pos += SIGNATURE_SIZE;
        let variant_byte = bytes[pos];
        pos += 1;
        let slot = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap());
        pos += 8;
        let index = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let version = u16::from_le_bytes(bytes[pos..pos + 2].try_into().unwrap());
        pos += 2;
        let fec_set_index = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap());
        pos += 4;

        let common_header = ShredCommonHeader {
            signature,
            variant: variant_byte,
            slot,
            index,
            version,
            fec_set_index,
        };

        // Variant
        let variant_tag = bytes[pos];
        pos += 1;
        let variant = match variant_tag {
            0 => {
                let (dh, new_pos) = decode_data_header(bytes, pos);
                pos = new_pos;
                ShredVariant::LegacyData(dh)
            }
            1 => {
                let (ch, new_pos) = decode_coding_header(bytes, pos);
                pos = new_pos;
                ShredVariant::LegacyCoding(ch)
            }
            2 => {
                let (dh, new_pos) = decode_data_header(bytes, pos);
                pos = new_pos;
                let (proof, new_pos) = decode_merkle_proof(bytes, pos);
                pos = new_pos;
                ShredVariant::MerkleData(dh, proof)
            }
            3 => {
                let (ch, new_pos) = decode_coding_header(bytes, pos);
                pos = new_pos;
                let (proof, new_pos) = decode_merkle_proof(bytes, pos);
                pos = new_pos;
                ShredVariant::MerkleCoding(ch, proof)
            }
            _ => ShredVariant::LegacyData(DataShredHeader {
                parent_offset: 0,
                flags: 0,
                size: 0,
            }),
        };

        // Payload
        let payload_len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let payload = bytes[pos..pos + payload_len].to_vec();

        Shred {
            common_header,
            variant,
            payload,
            raw: None,
        }
    }

    fn max_encoded_size() -> usize {
        SHRED_MAX_ENCODED
    }

    fn signature(&self) -> u64 {
        u64::from_le_bytes(self.common_header.signature[..8].try_into().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shred_data_codec_roundtrip() {
        let shred = Shred::new(
            ShredCommonHeader {
                signature: [0x42; SIGNATURE_SIZE],
                variant: 0x55,
                slot: 100,
                index: 5,
                version: 1,
                fec_set_index: 3,
            },
            ShredVariant::LegacyData(DataShredHeader {
                parent_offset: 1,
                flags: 0,
                size: 64,
            }),
            vec![0xCC; 64],
        );

        let mut buf = vec![0u8; Shred::max_encoded_size()];
        let len = shred.encode(&mut buf);
        let decoded = Shred::decode(&buf[..len]);

        assert_eq!(decoded.common_header.slot, 100);
        assert_eq!(decoded.common_header.index, 5);
        assert_eq!(decoded.common_header.fec_set_index, 3);
        assert_eq!(decoded.payload, vec![0xCC; 64]);
        assert!(matches!(decoded.variant, ShredVariant::LegacyData(_)));
    }

    #[test]
    fn shred_coding_codec_roundtrip() {
        let proof = MerkleProof {
            proof: vec![[0xEE; MERKLE_PROOF_NODE_BYTES]; 4],
        };
        let shred = Shred::new(
            ShredCommonHeader {
                signature: [0x11; SIGNATURE_SIZE],
                variant: 0xAA,
                slot: 200,
                index: 10,
                version: 2,
                fec_set_index: 7,
            },
            ShredVariant::MerkleCoding(
                CodingShredHeader {
                    num_data_shreds: 32,
                    num_coding_shreds: 32,
                    position: 5,
                },
                proof,
            ),
            vec![0xDD; 128],
        );

        let mut buf = vec![0u8; Shred::max_encoded_size()];
        let len = shred.encode(&mut buf);
        let decoded = Shred::decode(&buf[..len]);

        assert_eq!(decoded.common_header.slot, 200);
        assert!(
            matches!(&decoded.variant, ShredVariant::MerkleCoding(ch, p) if ch.num_data_shreds == 32 && p.proof.len() == 4)
        );
        assert_eq!(decoded.payload, vec![0xDD; 128]);
    }

    #[test]
    fn shred_signature_uses_first_8_bytes() {
        let shred = Shred::new(
            ShredCommonHeader {
                signature: {
                    let mut sig = [0u8; SIGNATURE_SIZE];
                    sig[..8].copy_from_slice(&0xDEADBEEF_u64.to_le_bytes());
                    sig
                },
                variant: 0x55,
                slot: 1,
                index: 0,
                version: 1,
                fec_set_index: 0,
            },
            ShredVariant::LegacyData(DataShredHeader {
                parent_offset: 1,
                flags: 0,
                size: 0,
            }),
            vec![],
        );
        assert_eq!(shred.signature(), 0xDEADBEEF);
    }
}
