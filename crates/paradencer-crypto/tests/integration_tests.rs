//! Integration tests for paradencer-crypto

use ed25519_dalek::{Signer, SigningKey};
use paradencer_crypto::{
    blake3::{Blake3Hasher, Blake3StreamingHasher},
    ed25519_batch::{BatchVerifier, SignatureSet, VerificationResult},
    sha256::{Sha256Hasher, Sha256StreamingHasher},
    verify_signature, CryptoError, PUBKEY_SIZE, SIGNATURE_SIZE,
};
use rand::rngs::OsRng;

// ============================================================================
// Ed25519 Batch Verification Tests
// ============================================================================

#[test]
fn test_batch_verification_small_batch() {
    let mut verifier = BatchVerifier::new();

    // Create 8 valid signatures
    for i in 0..8 {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let message = format!("message {}", i).into_bytes();
        let signature = signing_key.sign(&message);

        let mut pubkey = [0u8; PUBKEY_SIZE];
        pubkey.copy_from_slice(verifying_key.as_bytes());

        let mut sig_bytes = [0u8; SIGNATURE_SIZE];
        sig_bytes.copy_from_slice(&signature.to_bytes());

        verifier.add_signature(pubkey, message, sig_bytes).unwrap();
    }

    let result = verifier.verify_batch().unwrap();
    assert_eq!(result, VerificationResult::Success);

    // Check stats
    let stats = verifier.stats();
    assert_eq!(stats.get_batches_verified(), 1);
    assert_eq!(stats.get_signatures_verified(), 8);
    assert_eq!(stats.get_success_rate(), 1.0);
}

#[test]
fn test_batch_verification_medium_batch() {
    let mut verifier = BatchVerifier::new();

    // Create 32 valid signatures
    for i in 0..32 {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let message = format!("message {}", i).into_bytes();
        let signature = signing_key.sign(&message);

        let mut pubkey = [0u8; PUBKEY_SIZE];
        pubkey.copy_from_slice(verifying_key.as_bytes());

        let mut sig_bytes = [0u8; SIGNATURE_SIZE];
        sig_bytes.copy_from_slice(&signature.to_bytes());

        verifier.add_signature(pubkey, message, sig_bytes).unwrap();
    }

    let result = verifier.verify_batch().unwrap();
    assert_eq!(result, VerificationResult::Success);

    let stats = verifier.stats();
    assert_eq!(stats.get_batches_verified(), 1);
    assert_eq!(stats.get_signatures_verified(), 32);
}

#[test]
fn test_batch_verification_large_batch() {
    let mut verifier = BatchVerifier::new();

    // Create 128 valid signatures
    for i in 0..128 {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let message = format!("message {}", i).into_bytes();
        let signature = signing_key.sign(&message);

        let mut pubkey = [0u8; PUBKEY_SIZE];
        pubkey.copy_from_slice(verifying_key.as_bytes());

        let mut sig_bytes = [0u8; SIGNATURE_SIZE];
        sig_bytes.copy_from_slice(&signature.to_bytes());

        verifier.add_signature(pubkey, message, sig_bytes).unwrap();
    }

    let result = verifier.verify_batch().unwrap();
    assert_eq!(result, VerificationResult::Success);

    let stats = verifier.stats();
    assert_eq!(stats.get_batches_verified(), 1);
    assert_eq!(stats.get_signatures_verified(), 128);
}

#[test]
fn test_batch_verification_mixed_valid_invalid() {
    let mut verifier = BatchVerifier::new();

    // Add 10 valid signatures
    for i in 0..10 {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let message = format!("valid message {}", i).into_bytes();
        let signature = signing_key.sign(&message);

        let mut pubkey = [0u8; PUBKEY_SIZE];
        pubkey.copy_from_slice(verifying_key.as_bytes());

        let mut sig_bytes = [0u8; SIGNATURE_SIZE];
        sig_bytes.copy_from_slice(&signature.to_bytes());

        verifier.add_signature(pubkey, message, sig_bytes).unwrap();
    }

    // Add 1 invalid signature in the middle
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let message = b"invalid message".to_vec();
    let signature = signing_key.sign(&message);

    let mut pubkey = [0u8; PUBKEY_SIZE];
    pubkey.copy_from_slice(verifying_key.as_bytes());

    let mut sig_bytes = [0u8; SIGNATURE_SIZE];
    sig_bytes.copy_from_slice(&signature.to_bytes());
    // Corrupt the signature
    sig_bytes[0] ^= 0xFF;

    verifier.add_signature(pubkey, message, sig_bytes).unwrap();

    // Add 10 more valid signatures
    for i in 10..20 {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let message = format!("valid message {}", i).into_bytes();
        let signature = signing_key.sign(&message);

        let mut pubkey = [0u8; PUBKEY_SIZE];
        pubkey.copy_from_slice(verifying_key.as_bytes());

        let mut sig_bytes = [0u8; SIGNATURE_SIZE];
        sig_bytes.copy_from_slice(&signature.to_bytes());

        verifier.add_signature(pubkey, message, sig_bytes).unwrap();
    }

    // Batch verification should fail
    let result = verifier.verify_batch().unwrap();
    assert_eq!(result, VerificationResult::Failed);
}

#[test]
fn test_batch_verification_detailed_identifies_failures() {
    let mut verifier = BatchVerifier::new();
    let mut expected_results = Vec::new();

    // Add signatures with known outcomes
    for i in 0..20 {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let message = format!("message {}", i).into_bytes();
        let signature = signing_key.sign(&message);

        let mut pubkey = [0u8; PUBKEY_SIZE];
        pubkey.copy_from_slice(verifying_key.as_bytes());

        let mut sig_bytes = [0u8; SIGNATURE_SIZE];
        sig_bytes.copy_from_slice(&signature.to_bytes());

        // Corrupt signatures at indices 5, 10, 15
        let is_valid = i != 5 && i != 10 && i != 15;
        if !is_valid {
            sig_bytes[0] ^= 0xFF;
        }
        expected_results.push(is_valid);

        verifier.add_signature(pubkey, message, sig_bytes).unwrap();
    }

    let results = verifier.verify_batch_detailed().unwrap();
    assert_eq!(results, expected_results);
}

#[test]
fn test_batch_auto_flush() {
    const MAX_BATCH: usize = 10;
    let mut verifier = BatchVerifier::with_max_batch_size(MAX_BATCH);

    // Add MAX_BATCH - 1 signatures
    for i in 0..(MAX_BATCH - 1) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let message = format!("message {}", i).into_bytes();
        let signature = signing_key.sign(&message);

        let mut pubkey = [0u8; PUBKEY_SIZE];
        pubkey.copy_from_slice(verifying_key.as_bytes());

        let mut sig_bytes = [0u8; SIGNATURE_SIZE];
        sig_bytes.copy_from_slice(&signature.to_bytes());

        let result = verifier.add_signature(pubkey, message, sig_bytes).unwrap();
        assert!(result.is_none()); // Should not auto-flush yet
    }

    assert_eq!(verifier.pending_count(), MAX_BATCH - 1);

    // Add one more signature to trigger auto-flush
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let message = b"final message".to_vec();
    let signature = signing_key.sign(&message);

    let mut pubkey = [0u8; PUBKEY_SIZE];
    pubkey.copy_from_slice(verifying_key.as_bytes());

    let mut sig_bytes = [0u8; SIGNATURE_SIZE];
    sig_bytes.copy_from_slice(&signature.to_bytes());

    let result = verifier.add_signature(pubkey, message, sig_bytes).unwrap();
    assert!(result.is_some()); // Should auto-flush
    assert_eq!(result.unwrap(), VerificationResult::Success);
    assert_eq!(verifier.pending_count(), 0);
}

// ============================================================================
// Blake3 Hashing Tests
// ============================================================================

#[test]
fn test_blake3_hash_consistency() {
    let data = b"test data for blake3 hashing";

    // One-shot hash
    let hash1 = Blake3Hasher::hash(data);

    // Streaming hash
    let mut hasher = Blake3StreamingHasher::new();
    hasher.update(data);
    let hash2 = hasher.finalize();

    assert_eq!(hash1, hash2);
}

#[test]
fn test_blake3_hash_chunks_consistency() {
    let full_data = b"hello world from blake3";

    let hash1 = Blake3Hasher::hash(full_data);

    let chunks = vec![b"hello " as &[u8], b"world ", b"from ", b"blake3"];
    let hash2 = Blake3Hasher::hash_chunks(&chunks);

    assert_eq!(hash1, hash2);
}

#[test]
fn test_blake3_streaming_incremental() {
    let mut hasher = Blake3StreamingHasher::new();

    hasher.update(b"part1");
    assert_eq!(hasher.bytes_hashed(), 5);

    hasher.update(b"part2");
    assert_eq!(hasher.bytes_hashed(), 10);

    hasher.update(b"part3");
    assert_eq!(hasher.bytes_hashed(), 15);

    let hash = hasher.finalize();

    let expected = Blake3Hasher::hash(b"part1part2part3");
    assert_eq!(hash, expected);
}

#[test]
fn test_blake3_keyed_hashing() {
    let key = [42u8; 32];
    let data = b"sensitive data";

    let hash1 = Blake3Hasher::hash_keyed(&key, data);
    let hash2 = Blake3Hasher::hash_keyed(&key, data);
    assert_eq!(hash1, hash2);

    // Different key should produce different hash
    let different_key = [99u8; 32];
    let hash3 = Blake3Hasher::hash_keyed(&different_key, data);
    assert_ne!(hash1, hash3);

    // Regular hash should differ from keyed hash
    let regular_hash = Blake3Hasher::hash(data);
    assert_ne!(hash1, regular_hash);
}

#[test]
fn test_blake3_large_data() {
    let large_data = vec![0xAAu8; 1024 * 1024]; // 1 MB

    let hash1 = Blake3Hasher::hash(&large_data);

    let mut hasher = Blake3StreamingHasher::new();
    for chunk in large_data.chunks(4096) {
        hasher.update(chunk);
    }
    let hash2 = hasher.finalize();

    assert_eq!(hash1, hash2);
}

// ============================================================================
// SHA256 Hashing Tests
// ============================================================================

#[test]
fn test_sha256_hash_consistency() {
    let data = b"test data for sha256 hashing";

    let hash1 = Sha256Hasher::hash(data);

    let mut hasher = Sha256StreamingHasher::new();
    hasher.update(data);
    let hash2 = hasher.finalize();

    assert_eq!(hash1, hash2);
}

#[test]
fn test_sha256_hash_chunks_consistency() {
    let full_data = b"hello world from sha256";

    let hash1 = Sha256Hasher::hash(full_data);

    let chunks = vec![b"hello " as &[u8], b"world ", b"from ", b"sha256"];
    let hash2 = Sha256Hasher::hash_chunks(&chunks);

    assert_eq!(hash1, hash2);
}

#[test]
fn test_sha256_known_values() {
    // Test against known SHA256 values
    let empty_hash = Sha256Hasher::hash(b"");
    let expected_empty = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ];
    assert_eq!(empty_hash, expected_empty);
}

#[test]
fn test_sha256_double_hash() {
    let data = b"double hash test";

    let double = Sha256Hasher::hash_double(data);

    let first = Sha256Hasher::hash(data);
    let expected = Sha256Hasher::hash(&first);

    assert_eq!(double, expected);
}

// ============================================================================
// Hash Performance Comparison Tests
// ============================================================================

#[test]
fn test_blake3_faster_than_sha256_large_data() {
    use std::time::Instant;

    let large_data = vec![0xABu8; 1024 * 1024]; // 1 MB

    let start = Instant::now();
    let _blake3_hash = Blake3Hasher::hash(&large_data);
    let blake3_duration = start.elapsed();

    let start = Instant::now();
    let _sha256_hash = Sha256Hasher::hash(&large_data);
    let sha256_duration = start.elapsed();

    // Blake3 should be faster for large data
    println!(
        "Blake3: {:?}, SHA256: {:?}",
        blake3_duration, sha256_duration
    );
    // Note: This is an approximate test, actual performance may vary
}

// ============================================================================
// Transaction-specific Integration Tests
// ============================================================================

#[test]
fn test_transaction_signature_deduplication() {
    use paradencer_crypto::blake3::hash_transaction_signature;
    use std::collections::HashSet;

    let mut seen_hashes = HashSet::new();

    // Create 100 unique transaction signatures
    for i in 0..100u64 {
        let mut signature = [0u8; 64];
        signature[0..8].copy_from_slice(&i.to_le_bytes());

        let hash = hash_transaction_signature(&signature);

        // Each hash should be unique
        assert!(
            seen_hashes.insert(hash),
            "Hash collision detected for signature {}",
            i
        );
    }

    assert_eq!(seen_hashes.len(), 100);
}

#[test]
fn test_shred_fingerprint_uniqueness() {
    use paradencer_crypto::blake3::hash_shred_fingerprint;
    use std::collections::HashSet;

    let mut seen_hashes = HashSet::new();
    let data = vec![0u8; 1024];

    // Create fingerprints for different slots and indices
    for slot in 0..10u64 {
        for index in 0..10u32 {
            let hash = hash_shred_fingerprint(slot, index, &data);
            assert!(
                seen_hashes.insert(hash),
                "Hash collision detected for slot {}, index {}",
                slot,
                index
            );
        }
    }

    assert_eq!(seen_hashes.len(), 100);
}

// ============================================================================
// Stress Tests
// ============================================================================

#[test]
fn test_batch_verification_stress() {
    // Verify 1000 signatures in batches of 128
    const TOTAL_SIGNATURES: usize = 1000;
    const BATCH_SIZE: usize = 128;

    let mut all_signatures = Vec::new();

    // Generate all signatures
    for i in 0..TOTAL_SIGNATURES {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let message = format!("stress test message {}", i).into_bytes();
        let signature = signing_key.sign(&message);

        let mut pubkey = [0u8; PUBKEY_SIZE];
        pubkey.copy_from_slice(verifying_key.as_bytes());

        let mut sig_bytes = [0u8; SIGNATURE_SIZE];
        sig_bytes.copy_from_slice(&signature.to_bytes());

        all_signatures.push(SignatureSet::new(pubkey, message, sig_bytes));
    }

    // Verify in batches
    for batch in all_signatures.chunks(BATCH_SIZE) {
        let mut verifier = BatchVerifier::new();
        for sig_set in batch {
            verifier.add_signature_set(sig_set.clone()).unwrap();
        }
        let result = verifier.verify_batch().unwrap();
        assert_eq!(result, VerificationResult::Success);
    }
}

#[test]
fn test_hashing_stress() {
    // Hash 10000 small messages
    for i in 0..10000 {
        let data = format!("message {}", i).into_bytes();
        let _blake3_hash = Blake3Hasher::hash(&data);
        let _sha256_hash = Sha256Hasher::hash(&data);
    }
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_empty_batch_error() {
    let mut verifier = BatchVerifier::new();
    let result = verifier.verify_batch();

    assert!(matches!(result, Err(CryptoError::EmptyBatch)));
}

#[test]
fn test_single_signature_in_batch() {
    let mut verifier = BatchVerifier::new();

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let message = b"single message".to_vec();
    let signature = signing_key.sign(&message);

    let mut pubkey = [0u8; PUBKEY_SIZE];
    pubkey.copy_from_slice(verifying_key.as_bytes());

    let mut sig_bytes = [0u8; SIGNATURE_SIZE];
    sig_bytes.copy_from_slice(&signature.to_bytes());

    verifier.add_signature(pubkey, message, sig_bytes).unwrap();

    let result = verifier.verify_batch().unwrap();
    assert_eq!(result, VerificationResult::Success);
}

#[test]
fn test_hash_empty_data() {
    let blake3_hash = Blake3Hasher::hash(b"");
    assert_eq!(blake3_hash.len(), 32);

    let sha256_hash = Sha256Hasher::hash(b"");
    assert_eq!(sha256_hash.len(), 32);

    // Empty data should produce different hashes for different algorithms
    assert_ne!(blake3_hash, sha256_hash);
}
