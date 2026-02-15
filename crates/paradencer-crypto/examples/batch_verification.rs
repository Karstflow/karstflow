//! Example: Batch signature verification
//!
//! This example demonstrates how to use the batch verification API
//! to efficiently verify multiple Ed25519 signatures.
//!
//! Run with: cargo run --example batch_verification

use ed25519_dalek::{Signer, SigningKey};
use paradencer_crypto::ed25519_batch::{BatchVerifier, SignatureSet, VerificationResult};
use rand::rngs::OsRng;
use std::time::Instant;

fn main() {
    println!("=== Batch Ed25519 Signature Verification Example ===\n");

    // Generate test signatures
    println!("Generating 100 valid signatures...");
    let mut signature_sets = Vec::new();

    for i in 0..100 {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let message = format!("Transaction message {}", i).into_bytes();
        let signature = signing_key.sign(&message);

        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(verifying_key.as_bytes());

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&signature.to_bytes());

        signature_sets.push(SignatureSet::new(pubkey, message, sig_bytes));
    }

    println!("Generated {} signatures\n", signature_sets.len());

    // Benchmark: Sequential verification
    println!("--- Sequential Verification ---");
    let start = Instant::now();
    let mut success_count = 0;

    for sig_set in &signature_sets {
        match sig_set.verify() {
            Ok(VerificationResult::Success) => success_count += 1,
            Ok(VerificationResult::Failed) => {}
            Err(e) => eprintln!("Error: {}", e),
        }
    }

    let sequential_duration = start.elapsed();
    println!("Verified {} signatures sequentially", success_count);
    println!("Time: {:?}", sequential_duration);
    println!(
        "Throughput: {:.0} sigs/sec\n",
        signature_sets.len() as f64 / sequential_duration.as_secs_f64()
    );

    // Benchmark: Batch verification (batch size 32)
    println!("--- Batch Verification (batch size 32) ---");
    let start = Instant::now();
    let mut total_verified = 0;
    let mut batch_count = 0;

    for batch in signature_sets.chunks(32) {
        let mut verifier = BatchVerifier::new();

        for sig_set in batch {
            verifier
                .add_signature_set(sig_set.clone())
                .expect("Failed to add signature");
        }

        match verifier.verify_batch() {
            Ok(VerificationResult::Success) => {
                total_verified += batch.len();
                batch_count += 1;
            }
            Ok(VerificationResult::Failed) => {
                eprintln!("Batch verification failed!");
            }
            Err(e) => eprintln!("Error: {}", e),
        }
    }

    let batch_duration = start.elapsed();
    println!(
        "Verified {} signatures in {} batches",
        total_verified, batch_count
    );
    println!("Time: {:?}", batch_duration);
    println!(
        "Throughput: {:.0} sigs/sec",
        total_verified as f64 / batch_duration.as_secs_f64()
    );

    let speedup = sequential_duration.as_secs_f64() / batch_duration.as_secs_f64();
    println!("Speedup: {:.2}x faster than sequential\n", speedup);

    // Benchmark: Batch verification (batch size 128)
    println!("--- Batch Verification (batch size 128) ---");
    let start = Instant::now();
    let mut total_verified = 0;
    let mut batch_count = 0;

    for batch in signature_sets.chunks(128) {
        let mut verifier = BatchVerifier::new();

        for sig_set in batch {
            verifier
                .add_signature_set(sig_set.clone())
                .expect("Failed to add signature");
        }

        match verifier.verify_batch() {
            Ok(VerificationResult::Success) => {
                total_verified += batch.len();
                batch_count += 1;
            }
            Ok(VerificationResult::Failed) => {
                eprintln!("Batch verification failed!");
            }
            Err(e) => eprintln!("Error: {}", e),
        }
    }

    let batch_duration = start.elapsed();
    println!(
        "Verified {} signatures in {} batches",
        total_verified, batch_count
    );
    println!("Time: {:?}", batch_duration);
    println!(
        "Throughput: {:.0} sigs/sec",
        total_verified as f64 / batch_duration.as_secs_f64()
    );

    let speedup = sequential_duration.as_secs_f64() / batch_duration.as_secs_f64();
    println!("Speedup: {:.2}x faster than sequential\n", speedup);

    // Demonstrate statistics tracking
    println!("--- Statistics Tracking ---");
    let mut verifier = BatchVerifier::new();

    // Add and verify multiple batches
    for (i, sig_set) in signature_sets.iter().enumerate() {
        verifier
            .add_signature_set(sig_set.clone())
            .expect("Failed to add signature");

        // Verify every 10 signatures
        if (i + 1) % 10 == 0 {
            verifier.verify_batch().expect("Batch verification failed");
        }
    }

    let stats = verifier.stats();
    println!("Total batches verified: {}", stats.get_batches_verified());
    println!(
        "Total signatures verified: {}",
        stats.get_signatures_verified()
    );
    println!("Average batch size: {:.1}", stats.get_average_batch_size());
    println!("Success rate: {:.1}%", stats.get_success_rate() * 100.0);
    println!(
        "Average time per signature: {:.1} µs",
        stats.get_average_time_per_signature_us()
    );
}
