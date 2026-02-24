/// Shred signature verification.
///
/// Validates Ed25519 signatures on shreds before accepting them into
/// FEC sets. Legacy shreds sign the wire-format bytes after the 64-byte
/// signature prefix. Merkle shreds sign the Merkle root of their FEC set.
use paradencer_crypto::ed25519_batch::{verify_signature, VerificationResult};
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
    /// Verification skipped (Merkle shreds require FEC set completion).
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

/// Verify the Ed25519 signature on a shred.
///
/// - **Legacy shreds**: Verified immediately by reconstructing the signed
///   message from the parsed fields and checking against the leader key.
/// - **Merkle shreds**: Deferred — individual verification requires the
///   Merkle root which is computed at FEC set completion. Returns
///   `ShredVerifyResult::Deferred`.
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
        ShredVariant::MerkleData(_, _) | ShredVariant::MerkleCoding(_, _) => {
            // TODO: Implement Merkle root computation and verification.
            // Each Merkle shred carries a proof; the leaf hash is computed
            // from the shred data, walked up the tree via the proof, and
            // the resulting root is verified against the signature.
            // For now, defer verification to FEC set completion.
            ShredVerifyResult::Deferred
        }
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
    use paradencer_types::shred::{DataShredHeader, ShredCommonHeader, SHRED_DATA_FLAG};

    let data_header = DataShredHeader {
        parent_offset: 1,
        flags: 0,
        size: payload.len() as u16,
    };
    let variant = ShredVariant::LegacyData(data_header);

    let mut shred = Shred::new(
        ShredCommonHeader {
            signature: [0u8; 64],
            variant: SHRED_DATA_FLAG,
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
        CodingShredHeader, DataShredHeader, ShredCommonHeader, SHRED_CODE_FLAG, SHRED_DATA_FLAG,
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
        let coding_header = CodingShredHeader {
            num_data_shreds: num_data,
            num_coding_shreds: num_coding,
            position,
        };
        let variant = ShredVariant::LegacyCoding(coding_header);

        let mut shred = Shred::new(
            ShredCommonHeader {
                signature: [0u8; 64],
                variant: SHRED_CODE_FLAG,
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
        let shred = Shred::new(
            ShredCommonHeader {
                signature: [0u8; 64],
                variant: SHRED_DATA_FLAG,
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
    fn merkle_shred_deferred() {
        let (_, pubkey) = generate_keypair();
        let shred = Shred::new(
            ShredCommonHeader {
                signature: [1u8; 64], // non-zero
                variant: 0x45,        // data + merkle
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
                paradencer_types::shred::MerkleProof {
                    proof: vec![[0xFFu8; 32]; 3],
                },
            ),
            vec![0u8; 64],
        );

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
}
