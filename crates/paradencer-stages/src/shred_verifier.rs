/// Shred signature verification.
///
/// Validates Ed25519 signatures on shreds before accepting them into
/// FEC sets. Legacy shreds sign the wire-format bytes after the 64-byte
/// signature prefix. Merkle shreds sign the Merkle root computed from the
/// binary tree: each shred carries an inclusion proof that lets us derive
/// the root from its leaf hash, and the root is Ed25519-verified against
/// the leader key stored in the signature field.
use paradencer_constants::shred::{
    CODE_MERKLE_PROTECTED_BASE, DATA_MERKLE_PROTECTED_BASE, MERKLE_LEAF_PREFIX, MERKLE_NODE_PREFIX,
    MERKLE_PROOF_NODE_BYTES, SHRED_SIGNATURE_BYTES, SHRED_TYPEMASK_DATA, SHRED_TYPE_LEGACY_CODE,
    SHRED_TYPE_LEGACY_DATA, SHRED_TYPE_MASK, SHRED_TYPE_MERKLE_CODE_CHAINED_RESIGNED,
    SHRED_TYPE_MERKLE_DATA_CHAINED_RESIGNED,
};
use paradencer_crypto::ed25519_batch::{verify_signature, VerificationResult};
use paradencer_crypto::sha256::Sha256Hasher;
use paradencer_types::shred::{Shred, ShredVariant, SIGNATURE_SIZE};

/// Trait for looking up the leader public key for a given slot.
///
/// The shred network stage uses this to determine which key to verify
/// shred signatures against. Implementations typically delegate to the
/// leader schedule derived from the current epoch's stake distribution.
pub trait LeaderLookup: Send + Sync {
    /// Return the 32-byte Ed25519 public key of the leader for `slot`,
    /// or `None` if the leader is unknown (e.g. slot too far ahead).
    fn leader_for_slot(&self, slot: u64) -> Option<[u8; 32]>;
}

/// Outcome of shred signature verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShredVerifyResult {
    /// Signature is valid.
    Valid,
    /// Signature is invalid (wrong key or corrupted data).
    Invalid,
    /// Signature is all zeros (shred must be rejected).
    ZeroSignature,
    /// Verification skipped — raw wire bytes not available for Merkle shreds.
    Deferred,
    /// Leader pubkey unknown for this slot — cannot verify.
    UnknownLeader,
}

/// Check whether the signature bytes are all zeros.
pub fn is_zero_signature(signature: &[u8; SIGNATURE_SIZE]) -> bool {
    signature.iter().all(|&b| b == 0)
}

/// Build the signed message for a legacy (non-Merkle) shred.
///
/// The Ed25519 signature covers everything after the 64-byte signature
/// prefix in the wire format: variant byte, slot, index, version,
/// fec_set_index, variant-specific header fields, and the payload.
fn legacy_signed_message(shred: &Shred) -> Vec<u8> {
    // Common header fields after signature: variant(1) + slot(8) + index(4) + version(2) + fec_set_index(4) = 19
    // Variant header: data = 5, coding = 6
    let header_size = 19
        + match &shred.variant {
            ShredVariant::LegacyData(_) => 5,
            ShredVariant::LegacyCoding(_) => 6,
            _ => 0,
        };
    let mut msg = Vec::with_capacity(header_size + shred.payload.len());

    // Common header (excluding signature)
    msg.push(shred.common_header.variant);
    msg.extend_from_slice(&shred.common_header.slot.to_le_bytes());
    msg.extend_from_slice(&shred.common_header.index.to_le_bytes());
    msg.extend_from_slice(&shred.common_header.version.to_le_bytes());
    msg.extend_from_slice(&shred.common_header.fec_set_index.to_le_bytes());

    // Variant-specific header
    match &shred.variant {
        ShredVariant::LegacyData(h) => {
            msg.extend_from_slice(&h.parent_offset.to_le_bytes());
            msg.push(h.flags);
            msg.extend_from_slice(&h.size.to_le_bytes());
        }
        ShredVariant::LegacyCoding(h) => {
            msg.extend_from_slice(&h.num_data_shreds.to_le_bytes());
            msg.extend_from_slice(&h.num_coding_shreds.to_le_bytes());
            msg.extend_from_slice(&h.position.to_le_bytes());
        }
        _ => {}
    }

    // Payload
    msg.extend_from_slice(&shred.payload);
    msg
}

// ---------------------------------------------------------------------------
// Merkle shred verification
// ---------------------------------------------------------------------------

/// Compute the Merkle-protected byte count for a shred.
///
/// The leaf hash covers bytes `[64, 64 + merkle_protected_sz)` of the raw
/// wire-format shred. This includes header fields, payload, and zero-padding
/// but excludes the signature, proof nodes, chained root, and retransmitter
/// signature.
fn merkle_protected_sz(variant_byte: u8) -> usize {
    let shred_type = variant_byte & SHRED_TYPE_MASK;
    let is_data = shred_type & SHRED_TYPEMASK_DATA != 0;
    let is_resigned = shred_type == SHRED_TYPE_MERKLE_DATA_CHAINED_RESIGNED
        || shred_type == SHRED_TYPE_MERKLE_CODE_CHAINED_RESIGNED;
    let proof_depth = (variant_byte & 0x0F) as usize;
    let resign_penalty = if is_resigned {
        SHRED_SIGNATURE_BYTES
    } else {
        0
    };

    let base = if is_data {
        DATA_MERKLE_PROTECTED_BASE
    } else {
        CODE_MERKLE_PROTECTED_BASE
    };

    base.saturating_sub(MERKLE_PROOF_NODE_BYTES * proof_depth + resign_penalty)
}

/// Compute the leaf hash for a Merkle shred from raw wire bytes.
///
/// `leaf = SHA-256(LEAF_PREFIX || raw[64 .. 64 + protected_sz])`
///
/// Returns truncated 20-byte hash for intermediate tree operations and
/// the full 32-byte hash (the last 12 bytes are used only if this leaf
/// ends up being the root).
fn merkle_leaf_hash(raw: &[u8], protected_sz: usize) -> [u8; 32] {
    let start = SHRED_SIGNATURE_BYTES;
    let end = (start + protected_sz).min(raw.len());
    Sha256Hasher::hash_chunks(&[&MERKLE_LEAF_PREFIX, &raw[start..end]])
}

/// Merge two child nodes (20-byte truncated hashes) into their parent.
///
/// `parent = SHA-256(NODE_PREFIX || left[0..20] || right[0..20])`
fn merkle_merge(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    Sha256Hasher::hash_chunks(&[
        &MERKLE_NODE_PREFIX,
        &left[..MERKLE_PROOF_NODE_BYTES],
        &right[..MERKLE_PROOF_NODE_BYTES],
    ])
}

/// Walk the Merkle inclusion proof to reconstruct the root.
///
/// Starting from the leaf hash, at each layer we combine the current node
/// with the sibling from the proof. The position in the tree is determined
/// by the `leaf_idx`: if the bit for the current layer is 0, the current
/// node is the left child; otherwise it's the right child.
///
/// Returns the 32-byte root hash on success.
fn merkle_root_from_proof(
    leaf: &[u8; 32],
    proof_nodes: &[[u8; MERKLE_PROOF_NODE_BYTES]],
    leaf_idx: usize,
) -> [u8; 32] {
    let mut current = *leaf;
    let mut inc_idx = leaf_idx * 2;

    for (layer, sibling_bytes) in proof_nodes.iter().enumerate() {
        let mut sibling = [0u8; 32];
        sibling[..MERKLE_PROOF_NODE_BYTES].copy_from_slice(sibling_bytes);

        let is_left = (inc_idx & (1 << (layer + 1))) == 0;
        current = if is_left {
            merkle_merge(&current, &sibling)
        } else {
            merkle_merge(&sibling, &current)
        };

        // Advance tree index (match the reference binary tree walk).
        let mask = (2usize << layer) - 1;
        inc_idx = (inc_idx & !((2 << (layer + 1)) - 1)) | mask;
    }

    current
}

/// Compute the leaf index for a shred within its Merkle tree.
///
/// Data shreds are leaves `[0, num_data)`.
/// Coding shreds are leaves `[num_data, num_data + num_coding)`.
fn merkle_leaf_index(shred: &Shred) -> Option<usize> {
    if shred.is_data() {
        Some((shred.index() as usize).saturating_sub(shred.fec_set_index() as usize))
    } else {
        let coding = shred.coding_header()?;
        Some(coding.num_data_shreds as usize + coding.position as usize)
    }
}

/// Verify a Merkle shred using its raw wire bytes.
///
/// Computes the leaf hash over the Merkle-protected region, walks the
/// inclusion proof to derive the root, and checks the Ed25519 signature
/// on the 32-byte root against the leader public key.
fn verify_merkle_shred(shred: &Shred, raw: &[u8], leader_pubkey: &[u8; 32]) -> ShredVerifyResult {
    let variant_byte = raw.get(SHRED_SIGNATURE_BYTES).copied().unwrap_or(0);
    let protected_sz = merkle_protected_sz(variant_byte);

    // Ensure we have enough bytes.
    if raw.len() < SHRED_SIGNATURE_BYTES + protected_sz {
        return ShredVerifyResult::Invalid;
    }

    // Compute leaf hash.
    let leaf = merkle_leaf_hash(raw, protected_sz);

    // Get proof nodes.
    let proof = match &shred.variant {
        ShredVariant::MerkleData(_, p) | ShredVariant::MerkleCoding(_, p) => &p.proof,
        _ => return ShredVerifyResult::Invalid,
    };

    // Compute leaf index.
    let leaf_idx = match merkle_leaf_index(shred) {
        Some(idx) => idx,
        None => return ShredVerifyResult::Invalid,
    };

    // Walk the proof tree to compute the root.
    let root = merkle_root_from_proof(&leaf, proof, leaf_idx);

    // The signature in the shred covers the 32-byte Merkle root.
    let signature = &shred.common_header.signature;
    match verify_signature(leader_pubkey, &root, signature) {
        Ok(VerificationResult::Success) => ShredVerifyResult::Valid,
        Ok(VerificationResult::Failed) => ShredVerifyResult::Invalid,
        Err(_) => ShredVerifyResult::Invalid,
    }
}

/// Verify the Ed25519 signature on a shred.
///
/// - **Legacy shreds**: Verified immediately by reconstructing the signed
///   message from the parsed fields and checking against the leader key.
/// - **Merkle shreds with raw bytes**: The leaf hash is computed from the
///   wire-format bytes, walked up the inclusion proof to derive the root,
///   and the root is Ed25519-verified against the leader key.
/// - **Merkle shreds without raw bytes**: Returns `Deferred` since we
///   cannot compute the leaf hash without the original wire data.
/// - **Zero signatures**: Always rejected.
pub fn verify_shred(shred: &Shred, leader_pubkey: &[u8; 32]) -> ShredVerifyResult {
    let signature = &shred.common_header.signature;

    // Reject zero signatures unconditionally.
    if is_zero_signature(signature) {
        return ShredVerifyResult::ZeroSignature;
    }

    match &shred.variant {
        ShredVariant::LegacyData(_) | ShredVariant::LegacyCoding(_) => {
            let message = legacy_signed_message(shred);
            match verify_signature(leader_pubkey, &message, signature) {
                Ok(VerificationResult::Success) => ShredVerifyResult::Valid,
                Ok(VerificationResult::Failed) => ShredVerifyResult::Invalid,
                Err(_) => ShredVerifyResult::Invalid,
            }
        }
        ShredVariant::MerkleData(_, _) | ShredVariant::MerkleCoding(_, _) => match &shred.raw {
            Some(raw) => verify_merkle_shred(shred, raw, leader_pubkey),
            None => ShredVerifyResult::Deferred,
        },
    }
}

/// Build a legacy data shred signed by the given secret key.
///
/// Available only in test builds for integration testing across modules.
#[cfg(test)]
pub fn make_signed_data_shred(
    secret_key: &[u8; 32],
    slot: u64,
    index: u32,
    fec_set_index: u32,
    payload: &[u8],
) -> Shred {
    use paradencer_crypto::ed25519_batch::sign_message;
    use paradencer_types::shred::{
        DataShredHeader, ShredCommonHeader, SHRED_LEGACY_DATA_NIBBLE, SHRED_TYPE_LEGACY_DATA,
    };

    let variant_byte = SHRED_TYPE_LEGACY_DATA | SHRED_LEGACY_DATA_NIBBLE;
    let data_header = DataShredHeader {
        parent_offset: 1,
        flags: 0,
        size: payload.len() as u16,
    };
    let variant = ShredVariant::LegacyData(data_header);

    let mut shred = Shred::new(
        ShredCommonHeader {
            signature: [0u8; 64],
            variant: variant_byte,
            slot,
            index,
            version: 1,
            fec_set_index,
        },
        variant,
        payload.to_vec(),
    );

    let message = legacy_signed_message(&shred);
    let signature = sign_message(secret_key, &message).unwrap();
    shred.common_header.signature = signature;
    shred
}

#[cfg(test)]
mod tests {
    use super::*;
    use paradencer_crypto::ed25519_batch::{generate_keypair, sign_message};
    use paradencer_types::shred::{
        CodingShredHeader, DataShredHeader, MerkleProof, ShredCommonHeader,
        MERKLE_PROOF_NODE_BYTES, SHRED_LEGACY_CODE_NIBBLE, SHRED_LEGACY_DATA_NIBBLE,
        SHRED_MIN_SIZE, SHRED_TYPE_LEGACY_CODE, SHRED_TYPE_LEGACY_DATA, SHRED_TYPE_MERKLE_DATA,
    };

    /// Build a legacy coding shred signed by the given secret key.
    fn make_signed_coding_shred(
        secret_key: &[u8; 32],
        slot: u64,
        index: u32,
        fec_set_index: u32,
        num_data: u16,
        num_coding: u16,
        position: u16,
        payload: &[u8],
    ) -> Shred {
        let variant_byte = SHRED_TYPE_LEGACY_CODE | SHRED_LEGACY_CODE_NIBBLE;
        let coding_header = CodingShredHeader {
            num_data_shreds: num_data,
            num_coding_shreds: num_coding,
            position,
        };
        let variant = ShredVariant::LegacyCoding(coding_header);

        let mut shred = Shred::new(
            ShredCommonHeader {
                signature: [0u8; 64],
                variant: variant_byte,
                slot,
                index,
                version: 1,
                fec_set_index,
            },
            variant,
            payload.to_vec(),
        );

        let message = legacy_signed_message(&shred);
        let signature = sign_message(secret_key, &message).unwrap();
        shred.common_header.signature = signature;
        shred
    }

    #[test]
    fn valid_legacy_data_shred_passes() {
        let (secret, pubkey) = generate_keypair();
        let payload = vec![0xABu8; 512];
        let shred = make_signed_data_shred(&secret, 100, 0, 0, &payload);

        assert_eq!(verify_shred(&shred, &pubkey), ShredVerifyResult::Valid);
    }

    #[test]
    fn valid_legacy_coding_shred_passes() {
        let (secret, pubkey) = generate_keypair();
        let payload = vec![0xCDu8; 1024];
        let shred = make_signed_coding_shred(&secret, 200, 4, 0, 4, 4, 0, &payload);

        assert_eq!(verify_shred(&shred, &pubkey), ShredVerifyResult::Valid);
    }

    #[test]
    fn wrong_leader_key_fails() {
        let (secret, _pubkey) = generate_keypair();
        let (_, wrong_pubkey) = generate_keypair();
        let payload = vec![0xABu8; 512];
        let shred = make_signed_data_shred(&secret, 100, 0, 0, &payload);

        assert_eq!(
            verify_shred(&shred, &wrong_pubkey),
            ShredVerifyResult::Invalid
        );
    }

    #[test]
    fn corrupted_payload_fails() {
        let (secret, pubkey) = generate_keypair();
        let payload = vec![0xABu8; 512];
        let mut shred = make_signed_data_shred(&secret, 100, 0, 0, &payload);

        // Corrupt the payload after signing.
        shred.payload[0] ^= 0xFF;

        assert_eq!(verify_shred(&shred, &pubkey), ShredVerifyResult::Invalid);
    }

    #[test]
    fn corrupted_slot_fails() {
        let (secret, pubkey) = generate_keypair();
        let payload = vec![0xABu8; 512];
        let mut shred = make_signed_data_shred(&secret, 100, 0, 0, &payload);

        // Tamper with the slot after signing.
        shred.common_header.slot = 999;

        assert_eq!(verify_shred(&shred, &pubkey), ShredVerifyResult::Invalid);
    }

    #[test]
    fn zero_signature_rejected() {
        let (_, pubkey) = generate_keypair();
        let variant_byte = SHRED_TYPE_LEGACY_DATA | SHRED_LEGACY_DATA_NIBBLE;
        let shred = Shred::new(
            ShredCommonHeader {
                signature: [0u8; 64],
                variant: variant_byte,
                slot: 100,
                index: 0,
                version: 1,
                fec_set_index: 0,
            },
            ShredVariant::LegacyData(DataShredHeader {
                parent_offset: 1,
                flags: 0,
                size: 64,
            }),
            vec![0u8; 64],
        );

        assert_eq!(
            verify_shred(&shred, &pubkey),
            ShredVerifyResult::ZeroSignature
        );
    }

    #[test]
    fn merkle_shred_without_raw_deferred() {
        let (_, pubkey) = generate_keypair();
        let proof_depth = 3u8;
        let variant_byte = SHRED_TYPE_MERKLE_DATA | proof_depth;
        let shred = Shred::new(
            ShredCommonHeader {
                signature: [1u8; 64], // non-zero
                variant: variant_byte,
                slot: 100,
                index: 0,
                version: 1,
                fec_set_index: 0,
            },
            ShredVariant::MerkleData(
                DataShredHeader {
                    parent_offset: 1,
                    flags: 0,
                    size: 64,
                },
                MerkleProof {
                    proof: vec![[0xFFu8; MERKLE_PROOF_NODE_BYTES]; proof_depth as usize],
                },
            ),
            vec![0u8; 64],
        );

        // Without raw bytes, should defer.
        assert_eq!(verify_shred(&shred, &pubkey), ShredVerifyResult::Deferred);
    }

    #[test]
    fn different_fec_set_index_fails() {
        let (secret, pubkey) = generate_keypair();
        let payload = vec![0xABu8; 256];
        let mut shred = make_signed_data_shred(&secret, 100, 5, 0, &payload);

        // Change fec_set_index after signing.
        shred.common_header.fec_set_index = 4;

        assert_eq!(verify_shred(&shred, &pubkey), ShredVerifyResult::Invalid);
    }

    #[test]
    fn multiple_shreds_from_same_leader_all_valid() {
        let (secret, pubkey) = generate_keypair();

        for idx in 0..10 {
            let payload = vec![(idx as u8).wrapping_mul(17); 512];
            let shred = make_signed_data_shred(&secret, 300, idx, 0, &payload);
            assert_eq!(
                verify_shred(&shred, &pubkey),
                ShredVerifyResult::Valid,
                "Shred index {} should verify",
                idx
            );
        }
    }

    #[test]
    fn is_zero_signature_detects_all_zeros() {
        assert!(is_zero_signature(&[0u8; 64]));
        let mut sig = [0u8; 64];
        sig[63] = 1;
        assert!(!is_zero_signature(&sig));
    }

    // -----------------------------------------------------------------------
    // Merkle verification unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn merkle_protected_sz_data_no_resign() {
        // Merkle data, depth=10, not chained, not resigned: 1139 - 20*10 = 939
        let variant_byte = SHRED_TYPE_MERKLE_DATA | 10;
        assert_eq!(merkle_protected_sz(variant_byte), 939);
    }

    #[test]
    fn merkle_protected_sz_data_depth_zero() {
        // Merkle data, depth=0: 1139
        let variant_byte = SHRED_TYPE_MERKLE_DATA;
        assert_eq!(merkle_protected_sz(variant_byte), 1139);
    }

    #[test]
    fn merkle_leaf_hash_deterministic() {
        let mut raw = vec![0u8; 200];
        raw[64] = 0x85; // variant byte at offset 64
        raw[65..73].copy_from_slice(&42u64.to_le_bytes()); // slot

        let hash1 = merkle_leaf_hash(&raw, 100);
        let hash2 = merkle_leaf_hash(&raw, 100);
        assert_eq!(hash1, hash2);

        // Different protected_sz → different hash.
        let hash3 = merkle_leaf_hash(&raw, 50);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn merkle_merge_deterministic() {
        let left = Sha256Hasher::hash(b"left");
        let right = Sha256Hasher::hash(b"right");

        let m1 = merkle_merge(&left, &right);
        let m2 = merkle_merge(&left, &right);
        assert_eq!(m1, m2);

        // Order matters.
        let m3 = merkle_merge(&right, &left);
        assert_ne!(m1, m3);
    }

    #[test]
    fn merkle_root_single_leaf_no_proof() {
        // With no proof nodes, the leaf itself is the root.
        let leaf = Sha256Hasher::hash(b"single leaf");
        let root = merkle_root_from_proof(&leaf, &[], 0);
        assert_eq!(root, leaf);
    }

    #[test]
    fn merkle_root_two_leaves() {
        // Tree with 2 leaves: root = merge(leaf0, leaf1)
        let leaf0 = Sha256Hasher::hash(b"leaf0");
        let leaf1 = Sha256Hasher::hash(b"leaf1");
        let expected_root = merkle_merge(&leaf0, &leaf1);

        // From leaf0 perspective: sibling is leaf1 (truncated to 20 bytes).
        let mut sibling = [0u8; MERKLE_PROOF_NODE_BYTES];
        sibling.copy_from_slice(&leaf1[..MERKLE_PROOF_NODE_BYTES]);
        let root0 = merkle_root_from_proof(&leaf0, &[sibling], 0);
        assert_eq!(root0, expected_root);

        // From leaf1 perspective: sibling is leaf0.
        let mut sibling = [0u8; MERKLE_PROOF_NODE_BYTES];
        sibling.copy_from_slice(&leaf0[..MERKLE_PROOF_NODE_BYTES]);
        let root1 = merkle_root_from_proof(&leaf1, &[sibling], 1);
        assert_eq!(root1, expected_root);
    }

    #[test]
    fn merkle_root_four_leaves() {
        // Tree with 4 leaves:
        //       root
        //      /    \
        //    n01     n23
        //   /   \   /   \
        //  L0   L1 L2   L3

        let leaves: Vec<[u8; 32]> = (0..4).map(|i| Sha256Hasher::hash(&[i as u8])).collect();

        let n01 = merkle_merge(&leaves[0], &leaves[1]);
        let n23 = merkle_merge(&leaves[2], &leaves[3]);
        let expected_root = merkle_merge(&n01, &n23);

        // From leaf 0: proof = [L1, n23], leaf_idx=0
        let proof_for_0 = [truncate_node(&leaves[1]), truncate_node(&n23)];
        let root0 = merkle_root_from_proof(&leaves[0], &proof_for_0, 0);
        assert_eq!(root0, expected_root);

        // From leaf 2: proof = [L3, n01], leaf_idx=2
        let proof_for_2 = [truncate_node(&leaves[3]), truncate_node(&n01)];
        let root2 = merkle_root_from_proof(&leaves[2], &proof_for_2, 2);
        assert_eq!(root2, expected_root);

        // From leaf 3: proof = [L2, n01], leaf_idx=3
        let proof_for_3 = [truncate_node(&leaves[2]), truncate_node(&n01)];
        let root3 = merkle_root_from_proof(&leaves[3], &proof_for_3, 3);
        assert_eq!(root3, expected_root);
    }

    /// Build a complete Merkle data shred with valid signature and raw bytes.
    ///
    /// Creates a properly laid-out wire-format shred, computes the Merkle
    /// leaf hash and root, signs it, then parses back.
    fn make_signed_merkle_data_shred(
        secret_key: &[u8; 32],
        slot: u64,
        shred_index: u32,
        fec_set_index: u32,
        proof_depth: u8,
    ) -> Shred {
        let variant_byte = SHRED_TYPE_MERKLE_DATA | proof_depth;
        let merkle_sz = proof_depth as usize * MERKLE_PROOF_NODE_BYTES;

        // Build wire bytes: must be exactly SHRED_MIN_SIZE (1203) bytes.
        let mut raw = vec![0u8; SHRED_MIN_SIZE];

        // Leave signature blank for now (offset 0..64).
        // Variant byte.
        raw[64] = variant_byte;
        // Slot.
        raw[0x41..0x49].copy_from_slice(&slot.to_le_bytes());
        // Index.
        raw[0x49..0x4d].copy_from_slice(&shred_index.to_le_bytes());
        // Version.
        raw[0x4d..0x4f].copy_from_slice(&1u16.to_le_bytes());
        // FEC set index.
        raw[0x4f..0x53].copy_from_slice(&fec_set_index.to_le_bytes());
        // Data header: parent_offset=1, flags=0, size=256.
        raw[0x53..0x55].copy_from_slice(&1u16.to_le_bytes());
        raw[0x55] = 0;
        raw[0x56..0x58].copy_from_slice(&256u16.to_le_bytes());
        // Payload: fill with pattern.
        for i in 0x58..0x58usize.saturating_add(256) {
            if i < raw.len() {
                raw[i] = (i & 0xFF) as u8;
            }
        }
        // Rest is zero-padding until proof area.

        // Compute leaf hash.
        let protected_sz = merkle_protected_sz(variant_byte);
        let leaf = merkle_leaf_hash(&raw, protected_sz);

        // For a single shred at leaf_idx=0 with no siblings, the root = leaf.
        // For a real FEC set we'd need all shreds. Here we test with a single
        // shred and its proof path set to make the root deterministic.
        //
        // We build a synthetic tree where our shred is leaf 0 and all
        // sibling nodes are known values.
        let leaf_idx = (shred_index as usize).saturating_sub(fec_set_index as usize);
        let mut current = leaf;
        let mut proof_nodes: Vec<[u8; MERKLE_PROOF_NODE_BYTES]> = Vec::new();

        for layer in 0..proof_depth as usize {
            // Synthetic sibling: hash of layer index.
            let sibling_full = Sha256Hasher::hash(&[layer as u8, 0xBB]);
            let sibling = truncate_node(&sibling_full);
            proof_nodes.push(sibling);

            let mut sibling_32 = [0u8; 32];
            sibling_32[..MERKLE_PROOF_NODE_BYTES].copy_from_slice(&sibling);

            let is_left = ((leaf_idx * 2) & (1 << (layer + 1))) == 0;
            current = if is_left {
                merkle_merge(&current, &sibling_32)
            } else {
                merkle_merge(&sibling_32, &current)
            };
        }

        let root = current;

        // Write proof nodes at the tail.
        let proof_start = SHRED_MIN_SIZE - merkle_sz;
        for (i, node) in proof_nodes.iter().enumerate() {
            let off = proof_start + i * MERKLE_PROOF_NODE_BYTES;
            raw[off..off + MERKLE_PROOF_NODE_BYTES].copy_from_slice(node);
        }

        // Sign the Merkle root.
        let signature = sign_message(secret_key, &root).unwrap();
        raw[..64].copy_from_slice(&signature);

        // Parse back into a Shred (which extracts raw, proof, etc.).
        let mut shred = paradencer_types::shred::ShredParser::parse(&raw).unwrap();
        // Sanity: parsed proof should match what we wrote.
        match &shred.variant {
            ShredVariant::MerkleData(_, p) => {
                assert_eq!(p.proof.len(), proof_depth as usize);
            }
            _ => panic!("Expected MerkleData"),
        }
        shred
    }

    #[test]
    fn merkle_data_shred_valid_signature() {
        let (secret, pubkey) = generate_keypair();
        let shred = make_signed_merkle_data_shred(&secret, 100, 0, 0, 5);

        assert!(shred.is_merkle());
        assert!(shred.raw.is_some());
        assert_eq!(verify_shred(&shred, &pubkey), ShredVerifyResult::Valid);
    }

    #[test]
    fn merkle_data_shred_wrong_leader_fails() {
        let (secret, _) = generate_keypair();
        let (_, wrong_pubkey) = generate_keypair();
        let shred = make_signed_merkle_data_shred(&secret, 100, 0, 0, 5);

        assert_eq!(
            verify_shred(&shred, &wrong_pubkey),
            ShredVerifyResult::Invalid
        );
    }

    #[test]
    fn merkle_data_shred_corrupted_raw_fails() {
        let (secret, pubkey) = generate_keypair();
        let mut shred = make_signed_merkle_data_shred(&secret, 100, 0, 0, 5);

        // Corrupt a byte in the Merkle-protected region.
        if let Some(ref mut raw) = shred.raw {
            raw[100] ^= 0xFF;
        }

        assert_eq!(verify_shred(&shred, &pubkey), ShredVerifyResult::Invalid);
    }

    #[test]
    fn merkle_data_shred_corrupted_proof_fails() {
        let (secret, pubkey) = generate_keypair();
        let mut shred = make_signed_merkle_data_shred(&secret, 100, 0, 0, 5);

        // Corrupt the first proof node.
        match &mut shred.variant {
            ShredVariant::MerkleData(_, ref mut p) => {
                p.proof[0][0] ^= 0xFF;
            }
            _ => panic!("Expected MerkleData"),
        }

        assert_eq!(verify_shred(&shred, &pubkey), ShredVerifyResult::Invalid);
    }

    #[test]
    fn merkle_data_shred_depth_zero() {
        let (secret, pubkey) = generate_keypair();
        let shred = make_signed_merkle_data_shred(&secret, 100, 0, 0, 0);

        assert!(shred.is_merkle());
        assert_eq!(verify_shred(&shred, &pubkey), ShredVerifyResult::Valid);
    }

    #[test]
    fn merkle_data_shred_depth_ten() {
        let (secret, pubkey) = generate_keypair();
        let shred = make_signed_merkle_data_shred(&secret, 500, 3, 0, 10);

        assert!(shred.is_merkle());
        assert_eq!(shred.merkle_proof_count(), 10);
        assert_eq!(verify_shred(&shred, &pubkey), ShredVerifyResult::Valid);
    }

    /// Truncate a 32-byte hash to 20 bytes for use as a proof entry.
    fn truncate_node(hash: &[u8; 32]) -> [u8; MERKLE_PROOF_NODE_BYTES] {
        let mut node = [0u8; MERKLE_PROOF_NODE_BYTES];
        node.copy_from_slice(&hash[..MERKLE_PROOF_NODE_BYTES]);
        node
    }
}
