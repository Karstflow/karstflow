//! Comprehensive cryptography benchmarks
//!
//! Run with: cargo bench --package paradencer-crypto

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ed25519_dalek::{Signer, SigningKey};
use paradencer_crypto::{
    blake3::{Blake3Hasher, Blake3ParallelHasher, Blake3StreamingHasher},
    ed25519_batch::{BatchVerifier, SignatureSet, VerificationResult},
    sha256::{Sha256Hasher, Sha256StreamingHasher},
    verify_signature, PUBKEY_SIZE, SIGNATURE_SIZE,
};
use rand::rngs::OsRng;

// ============================================================================
// Ed25519 Signature Verification Benchmarks
// ============================================================================

fn bench_ed25519_single_signature(c: &mut Criterion) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let message = b"benchmark message for signature verification";
    let signature = signing_key.sign(message);

    let mut pubkey = [0u8; PUBKEY_SIZE];
    pubkey.copy_from_slice(verifying_key.as_bytes());

    let mut sig_bytes = [0u8; SIGNATURE_SIZE];
    sig_bytes.copy_from_slice(&signature.to_bytes());

    c.bench_function("ed25519_verify_single", |b| {
        b.iter(|| {
            let result = verify_signature(
                black_box(&pubkey),
                black_box(message),
                black_box(&sig_bytes),
            )
            .unwrap();
            assert_eq!(result, VerificationResult::Success);
        })
    });
}

fn bench_ed25519_batch_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed25519_batch_verify");

    for batch_size in [8, 16, 32, 64, 128, 256].iter() {
        // Generate test signatures
        let mut sig_sets = Vec::new();
        for _ in 0..*batch_size {
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

        group.throughput(Throughput::Elements(*batch_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(batch_size),
            batch_size,
            |b, _| {
                b.iter(|| {
                    let mut verifier = BatchVerifier::new();
                    for sig_set in &sig_sets {
                        verifier
                            .add_signature_set(sig_set.clone())
                            .expect("failed to add signature");
                    }
                    let result = verifier.verify_batch().unwrap();
                    assert_eq!(result, VerificationResult::Success);
                })
            },
        );
    }

    group.finish();
}

fn bench_ed25519_batch_vs_sequential(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed25519_batch_vs_sequential");

    const BATCH_SIZE: usize = 32;

    // Generate test signatures
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

    group.throughput(Throughput::Elements(BATCH_SIZE as u64));

    group.bench_function("batch", |b| {
        b.iter(|| {
            let mut verifier = BatchVerifier::new();
            for sig_set in &sig_sets {
                verifier
                    .add_signature_set(sig_set.clone())
                    .expect("failed to add signature");
            }
            let result = verifier.verify_batch().unwrap();
            assert_eq!(result, VerificationResult::Success);
        })
    });

    group.bench_function("sequential", |b| {
        b.iter(|| {
            for sig_set in &sig_sets {
                let result = sig_set.verify().unwrap();
                assert_eq!(result, VerificationResult::Success);
            }
        })
    });

    group.finish();
}

// ============================================================================
// Blake3 Hashing Benchmarks
// ============================================================================

fn bench_blake3_hash_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake3_hash_sizes");

    for size in [64, 256, 1024, 4096, 16384, 65536, 1024 * 1024].iter() {
        let data = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                let hash = Blake3Hasher::hash(black_box(&data));
                black_box(hash);
            })
        });
    }

    group.finish();
}

fn bench_blake3_streaming(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake3_streaming");

    for size in [1024, 4096, 16384, 65536].iter() {
        let data = vec![0u8; *size];
        const CHUNK_SIZE: usize = 256;

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                let mut hasher = Blake3StreamingHasher::new();
                for chunk in data.chunks(CHUNK_SIZE) {
                    hasher.update(black_box(chunk));
                }
                let hash = hasher.finalize();
                black_box(hash);
            })
        });
    }

    group.finish();
}

fn bench_blake3_parallel(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake3_parallel");

    for size in [65536, 256 * 1024, 1024 * 1024, 4 * 1024 * 1024].iter() {
        let data = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                let hash = Blake3ParallelHasher::hash_large(black_box(&data));
                black_box(hash);
            })
        });
    }

    group.finish();
}

// ============================================================================
// SHA256 Hashing Benchmarks
// ============================================================================

fn bench_sha256_hash_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256_hash_sizes");

    for size in [64, 256, 1024, 4096, 16384, 65536, 1024 * 1024].iter() {
        let data = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                let hash = Sha256Hasher::hash(black_box(&data));
                black_box(hash);
            })
        });
    }

    group.finish();
}

fn bench_sha256_streaming(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256_streaming");

    for size in [1024, 4096, 16384, 65536].iter() {
        let data = vec![0u8; *size];
        const CHUNK_SIZE: usize = 256;

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                let mut hasher = Sha256StreamingHasher::new();
                for chunk in data.chunks(CHUNK_SIZE) {
                    hasher.update(black_box(chunk));
                }
                let hash = hasher.finalize();
                black_box(hash);
            })
        });
    }

    group.finish();
}

// ============================================================================
// Blake3 vs SHA256 Comparison
// ============================================================================

fn bench_blake3_vs_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake3_vs_sha256");

    for size in [1024, 16384, 1024 * 1024].iter() {
        let data = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::new("blake3", size), size, |b, _| {
            b.iter(|| {
                let hash = Blake3Hasher::hash(black_box(&data));
                black_box(hash);
            })
        });

        group.bench_with_input(BenchmarkId::new("sha256", size), size, |b, _| {
            b.iter(|| {
                let hash = Sha256Hasher::hash(black_box(&data));
                black_box(hash);
            })
        });
    }

    group.finish();
}

// ============================================================================
// Transaction-specific Benchmarks
// ============================================================================

fn bench_transaction_signature_hashing(c: &mut Criterion) {
    let signature = [42u8; 64];

    c.bench_function("hash_transaction_signature", |b| {
        b.iter(|| {
            let hash = paradencer_crypto::blake3::hash_transaction_signature(black_box(&signature));
            black_box(hash);
        })
    });
}

fn bench_shred_fingerprint_hashing(c: &mut Criterion) {
    let slot = 12345u64;
    let index = 67u32;
    let data = vec![0u8; 1024]; // Typical shred data size

    c.bench_function("hash_shred_fingerprint", |b| {
        b.iter(|| {
            let hash = paradencer_crypto::blake3::hash_shred_fingerprint(
                black_box(slot),
                black_box(index),
                black_box(&data),
            );
            black_box(hash);
        })
    });
}

// ============================================================================
// Realistic Workload Benchmarks
// ============================================================================

fn bench_realistic_transaction_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("realistic_transaction_verification");

    // Simulate verifying a batch of transactions from a slot
    // Typical slot: 32 transactions, avg 2 signatures each = 64 signatures
    const NUM_TRANSACTIONS: usize = 32;
    const AVG_SIGS_PER_TX: usize = 2;

    let mut all_sig_sets = Vec::new();
    for _ in 0..NUM_TRANSACTIONS * AVG_SIGS_PER_TX {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let message = format!("transaction data {}", all_sig_sets.len()).into_bytes();
        let signature = signing_key.sign(&message);

        let mut pubkey = [0u8; PUBKEY_SIZE];
        pubkey.copy_from_slice(verifying_key.as_bytes());

        let mut sig_bytes = [0u8; SIGNATURE_SIZE];
        sig_bytes.copy_from_slice(&signature.to_bytes());

        all_sig_sets.push(SignatureSet::new(pubkey, message, sig_bytes));
    }

    group.throughput(Throughput::Elements(
        (NUM_TRANSACTIONS * AVG_SIGS_PER_TX) as u64,
    ));

    group.bench_function("batch_verify_slot", |b| {
        b.iter(|| {
            let mut verifier = BatchVerifier::new();
            for sig_set in &all_sig_sets {
                verifier
                    .add_signature_set(sig_set.clone())
                    .expect("failed to add signature");
            }
            let result = verifier.verify_batch().unwrap();
            assert_eq!(result, VerificationResult::Success);
        })
    });

    group.finish();
}

fn bench_realistic_deduplication_hashing(c: &mut Criterion) {
    // Simulate hashing signatures for deduplication cache
    // Typical: 1000 transactions/second
    let mut signatures = Vec::new();
    for i in 0..1000 {
        let mut sig = [0u8; 64];
        sig[0..8].copy_from_slice(&i.to_le_bytes());
        signatures.push(sig);
    }

    c.bench_function("dedup_hash_1000_signatures", |b| {
        b.iter(|| {
            for signature in &signatures {
                let hash =
                    paradencer_crypto::blake3::hash_transaction_signature(black_box(signature));
                black_box(hash);
            }
        })
    });
}

// ============================================================================
// Benchmark Groups
// ============================================================================

criterion_group!(
    ed25519_benches,
    bench_ed25519_single_signature,
    bench_ed25519_batch_verification,
    bench_ed25519_batch_vs_sequential,
);

criterion_group!(
    blake3_benches,
    bench_blake3_hash_sizes,
    bench_blake3_streaming,
    bench_blake3_parallel,
);

criterion_group!(
    sha256_benches,
    bench_sha256_hash_sizes,
    bench_sha256_streaming,
);

criterion_group!(comparison_benches, bench_blake3_vs_sha256,);

criterion_group!(
    transaction_benches,
    bench_transaction_signature_hashing,
    bench_shred_fingerprint_hashing,
);

criterion_group!(
    realistic_benches,
    bench_realistic_transaction_verification,
    bench_realistic_deduplication_hashing,
);

criterion_main!(
    ed25519_benches,
    blake3_benches,
    sha256_benches,
    comparison_benches,
    transaction_benches,
    realistic_benches,
);
