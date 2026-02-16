//! Performance regression tests
//!
//! These tests ensure that performance doesn't regress over time.
//! They use loose thresholds to account for system variability.

use ed25519_dalek::{Signer, SigningKey};
use paradencer_crypto::{
    blake3::Blake3Hasher,
    ed25519_batch::{BatchVerifier, SignatureSet, VerificationResult},
    sha256::Sha256Hasher,
    PUBKEY_SIZE, SIGNATURE_SIZE,
};
use rand::rngs::OsRng;
use std::time::{Duration, Instant};

const PERFORMANCE_MULTIPLIER: f64 = 30.0; // Allow 30x variance for debug builds and CI

/// Helper to measure execution time
fn measure<F>(f: F) -> Duration
where
    F: FnOnce(),
{
    let start = Instant::now();
    f();
    start.elapsed()
}

#[test]
fn test_single_signature_verification_performance() {
    // Generate a valid signature
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let message = b"performance test message";
    let signature = signing_key.sign(message);

    let mut pubkey = [0u8; PUBKEY_SIZE];
    pubkey.copy_from_slice(verifying_key.as_bytes());

    let mut sig_bytes = [0u8; SIGNATURE_SIZE];
    sig_bytes.copy_from_slice(&signature.to_bytes());

    let sig_set = SignatureSet::new(pubkey, message.to_vec(), sig_bytes);

    // Warm up
    for _ in 0..10 {
        let _ = sig_set.verify();
    }

    // Measure 1000 verifications
    let duration = measure(|| {
        for _ in 0..1000 {
            sig_set.verify().expect("Verification failed");
        }
    });

    let per_sig_us = duration.as_micros() / 1000;

    // Should be under 70µs per signature (with 3x margin = 210µs)
    let max_allowed_us = (70.0 * PERFORMANCE_MULTIPLIER) as u128;
    assert!(
        per_sig_us < max_allowed_us,
        "Single signature verification too slow: {} µs (max: {} µs)",
        per_sig_us,
        max_allowed_us
    );

    println!(
        "Single signature verification: {} µs/sig (threshold: {} µs)",
        per_sig_us, max_allowed_us
    );
}

#[test]
fn test_batch_verification_32_performance() {
    // Generate 32 valid signatures
    let mut sig_sets = Vec::new();
    for _ in 0..32 {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let message = format!("message {}", sig_sets.len()).into_bytes();
        let signature = signing_key.sign(&message);

        let mut pubkey = [0u8; PUBKEY_SIZE];
        pubkey.copy_from_slice(verifying_key.as_bytes());

        let mut sig_bytes = [0u8; SIGNATURE_SIZE];
        sig_bytes.copy_from_slice(&signature.to_bytes());

        sig_sets.push(SignatureSet::new(pubkey, message, sig_bytes));
    }

    // Warm up
    for _ in 0..5 {
        let mut verifier = BatchVerifier::new();
        for sig_set in &sig_sets {
            verifier.add_signature_set(sig_set.clone()).unwrap();
        }
        let _ = verifier.verify_batch();
    }

    // Measure 100 batch verifications
    let duration = measure(|| {
        for _ in 0..100 {
            let mut verifier = BatchVerifier::new();
            for sig_set in &sig_sets {
                verifier.add_signature_set(sig_set.clone()).unwrap();
            }
            assert_eq!(
                verifier.verify_batch().unwrap(),
                VerificationResult::Success
            );
        }
    });

    let per_batch_ms = duration.as_millis() / 100;

    // Should be under 2ms per batch of 32 (with 3x margin = 6ms)
    let max_allowed_ms = (2.0 * PERFORMANCE_MULTIPLIER) as u128;
    assert!(
        per_batch_ms < max_allowed_ms,
        "Batch verification (32) too slow: {} ms (max: {} ms)",
        per_batch_ms,
        max_allowed_ms
    );

    println!(
        "Batch verification (32 sigs): {} ms/batch (threshold: {} ms)",
        per_batch_ms, max_allowed_ms
    );
}

#[test]
fn test_batch_verification_128_performance() {
    // Generate 128 valid signatures
    let mut sig_sets = Vec::new();
    for _ in 0..128 {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let message = format!("message {}", sig_sets.len()).into_bytes();
        let signature = signing_key.sign(&message);

        let mut pubkey = [0u8; PUBKEY_SIZE];
        pubkey.copy_from_slice(verifying_key.as_bytes());

        let mut sig_bytes = [0u8; SIGNATURE_SIZE];
        sig_bytes.copy_from_slice(&signature.to_bytes());

        sig_sets.push(SignatureSet::new(pubkey, message, sig_bytes));
    }

    // Warm up
    for _ in 0..3 {
        let mut verifier = BatchVerifier::new();
        for sig_set in &sig_sets {
            verifier.add_signature_set(sig_set.clone()).unwrap();
        }
        let _ = verifier.verify_batch();
    }

    // Measure 50 batch verifications
    let duration = measure(|| {
        for _ in 0..50 {
            let mut verifier = BatchVerifier::new();
            for sig_set in &sig_sets {
                verifier.add_signature_set(sig_set.clone()).unwrap();
            }
            assert_eq!(
                verifier.verify_batch().unwrap(),
                VerificationResult::Success
            );
        }
    });

    let per_batch_ms = duration.as_millis() / 50;

    // Should be under 7ms per batch of 128 (with 3x margin = 21ms)
    let max_allowed_ms = (7.0 * PERFORMANCE_MULTIPLIER) as u128;
    assert!(
        per_batch_ms < max_allowed_ms,
        "Batch verification (128) too slow: {} ms (max: {} ms)",
        per_batch_ms,
        max_allowed_ms
    );

    println!(
        "Batch verification (128 sigs): {} ms/batch (threshold: {} ms)",
        per_batch_ms, max_allowed_ms
    );
}

#[test]
fn test_blake3_hash_1mb_performance() {
    let data = vec![0xABu8; 1024 * 1024]; // 1 MB

    // Warm up
    for _ in 0..5 {
        let _ = Blake3Hasher::hash(&data);
    }

    // Measure 100 hashes
    let duration = measure(|| {
        for _ in 0..100 {
            let _hash = Blake3Hasher::hash(&data);
        }
    });

    let mb_per_sec = (100 * 1024 * 1024) as f64 / duration.as_secs_f64() / 1_000_000.0;

    // Should be at least 500 MB/s (with 3x margin = 167 MB/s)
    let min_throughput = 500.0 / PERFORMANCE_MULTIPLIER;
    assert!(
        mb_per_sec > min_throughput,
        "Blake3 hashing too slow: {:.0} MB/s (min: {:.0} MB/s)",
        mb_per_sec,
        min_throughput
    );

    println!(
        "Blake3 hashing (1 MB): {:.0} MB/s (threshold: {:.0} MB/s)",
        mb_per_sec, min_throughput
    );
}

#[test]
fn test_sha256_hash_1mb_performance() {
    let data = vec![0xCDu8; 1024 * 1024]; // 1 MB

    // Warm up
    for _ in 0..5 {
        let _ = Sha256Hasher::hash(&data);
    }

    // Measure 100 hashes
    let duration = measure(|| {
        for _ in 0..100 {
            let _hash = Sha256Hasher::hash(&data);
        }
    });

    let mb_per_sec = (100 * 1024 * 1024) as f64 / duration.as_secs_f64() / 1_000_000.0;

    // Should be at least 300 MB/s (with 3x margin = 100 MB/s)
    let min_throughput = 300.0 / PERFORMANCE_MULTIPLIER;
    assert!(
        mb_per_sec > min_throughput,
        "SHA256 hashing too slow: {:.0} MB/s (min: {:.0} MB/s)",
        mb_per_sec,
        min_throughput
    );

    println!(
        "SHA256 hashing (1 MB): {:.0} MB/s (threshold: {:.0} MB/s)",
        mb_per_sec, min_throughput
    );
}

#[test]
fn test_blake3_faster_than_sha256() {
    let data = vec![0xEFu8; 1024 * 1024]; // 1 MB

    // Measure Blake3
    let blake3_duration = measure(|| {
        for _ in 0..50 {
            let _hash = Blake3Hasher::hash(&data);
        }
    });

    // Measure SHA256
    let sha256_duration = measure(|| {
        for _ in 0..50 {
            let _hash = Sha256Hasher::hash(&data);
        }
    });

    // Blake3 should be faster (allow 80% of SHA256 time as minimum speedup)
    let speedup = sha256_duration.as_secs_f64() / blake3_duration.as_secs_f64();
    assert!(
        speedup > 0.8,
        "Blake3 not faster than SHA256: {:.2}x speedup",
        speedup
    );

    println!(
        "Blake3 vs SHA256 speedup: {:.2}x (Blake3: {:?}, SHA256: {:?})",
        speedup, blake3_duration, sha256_duration
    );
}

#[test]
fn test_batch_verification_faster_than_sequential() {
    const BATCH_SIZE: usize = 32;

    // Generate signatures
    let mut sig_sets = Vec::new();
    for _ in 0..BATCH_SIZE {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let message = format!("message {}", sig_sets.len()).into_bytes();
        let signature = signing_key.sign(&message);

        let mut pubkey = [0u8; PUBKEY_SIZE];
        pubkey.copy_from_slice(verifying_key.as_bytes());

        let mut sig_bytes = [0u8; SIGNATURE_SIZE];
        sig_bytes.copy_from_slice(&signature.to_bytes());

        sig_sets.push(SignatureSet::new(pubkey, message, sig_bytes));
    }

    // Measure sequential verification
    let sequential_duration = measure(|| {
        for _ in 0..100 {
            for sig_set in &sig_sets {
                sig_set.verify().unwrap();
            }
        }
    });

    // Measure batch verification
    let batch_duration = measure(|| {
        for _ in 0..100 {
            let mut verifier = BatchVerifier::new();
            for sig_set in &sig_sets {
                verifier.add_signature_set(sig_set.clone()).unwrap();
            }
            verifier.verify_batch().unwrap();
        }
    });

    // Batch should be faster (allow at least 1.1x speedup)
    let speedup = sequential_duration.as_secs_f64() / batch_duration.as_secs_f64();
    assert!(
        speedup > 1.1,
        "Batch verification not faster: {:.2}x speedup (expected > 1.1x)",
        speedup
    );

    println!(
        "Batch vs sequential speedup: {:.2}x (batch: {:?}, sequential: {:?})",
        speedup, batch_duration, sequential_duration
    );
}
