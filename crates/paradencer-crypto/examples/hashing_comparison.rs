//! Example: Blake3 vs SHA256 hashing comparison
//!
//! This example demonstrates the performance difference between
//! Blake3 and SHA256 hashing algorithms.
//!
//! Run with: cargo run --example hashing_comparison

use paradencer_crypto::{
    blake3::{Blake3Hasher, Blake3ParallelHasher, Blake3StreamingHasher},
    sha256::{Sha256Hasher, Sha256StreamingHasher},
};
use std::time::Instant;

fn format_throughput(bytes: usize, duration: std::time::Duration) -> String {
    let bytes_per_sec = bytes as f64 / duration.as_secs_f64();
    if bytes_per_sec > 1_000_000_000.0 {
        format!("{:.2} GB/s", bytes_per_sec / 1_000_000_000.0)
    } else if bytes_per_sec > 1_000_000.0 {
        format!("{:.2} MB/s", bytes_per_sec / 1_000_000.0)
    } else if bytes_per_sec > 1_000.0 {
        format!("{:.2} KB/s", bytes_per_sec / 1_000.0)
    } else {
        format!("{:.2} B/s", bytes_per_sec)
    }
}

fn benchmark_hash_algorithm<F>(name: &str, data: &[u8], iterations: usize, hash_fn: F)
where
    F: Fn(&[u8]) -> [u8; 32],
{
    let start = Instant::now();

    for _ in 0..iterations {
        let _hash = hash_fn(data);
    }

    let duration = start.elapsed();
    let total_bytes = data.len() * iterations;
    let throughput = format_throughput(total_bytes, duration);

    println!(
        "{:20} | {:>12} | {:>10}",
        name,
        format!("{:?}", duration),
        throughput
    );
}

fn main() {
    println!("=== Blake3 vs SHA256 Hashing Comparison ===\n");

    // Test different data sizes
    let sizes = vec![
        (64, "64 B"),
        (256, "256 B"),
        (1024, "1 KB"),
        (4096, "4 KB"),
        (16384, "16 KB"),
        (65536, "64 KB"),
        (1024 * 1024, "1 MB"),
    ];

    for (size, label) in sizes {
        println!("\n--- Data Size: {} ---", label);
        println!("{:20} | {:>12} | {:>10}", "Algorithm", "Time", "Throughput");
        println!("{}", "-".repeat(48));

        let data = vec![0xABu8; size];
        let iterations = if size < 1024 {
            10000
        } else if size < 65536 {
            1000
        } else {
            100
        };

        benchmark_hash_algorithm("Blake3", &data, iterations, |d| Blake3Hasher::hash(d));
        benchmark_hash_algorithm("SHA256", &data, iterations, |d| Sha256Hasher::hash(d));
    }

    // Streaming hashing comparison
    println!("\n--- Streaming Hashing (1 MB in 4 KB chunks) ---");
    println!("{:20} | {:>12} | {:>10}", "Algorithm", "Time", "Throughput");
    println!("{}", "-".repeat(48));

    let data = vec![0xCDu8; 1024 * 1024]; // 1 MB
    let chunk_size = 4096; // 4 KB chunks
    let iterations = 100;

    // Blake3 streaming
    let start = Instant::now();
    for _ in 0..iterations {
        let mut hasher = Blake3StreamingHasher::new();
        for chunk in data.chunks(chunk_size) {
            hasher.update(chunk);
        }
        let _hash = hasher.finalize();
    }
    let blake3_duration = start.elapsed();
    let total_bytes = data.len() * iterations;
    println!(
        "{:20} | {:>12} | {:>10}",
        "Blake3 Streaming",
        format!("{:?}", blake3_duration),
        format_throughput(total_bytes, blake3_duration)
    );

    // SHA256 streaming
    let start = Instant::now();
    for _ in 0..iterations {
        let mut hasher = Sha256StreamingHasher::new();
        for chunk in data.chunks(chunk_size) {
            hasher.update(chunk);
        }
        let _hash = hasher.finalize();
    }
    let sha256_duration = start.elapsed();
    println!(
        "{:20} | {:>12} | {:>10}",
        "SHA256 Streaming",
        format!("{:?}", sha256_duration),
        format_throughput(total_bytes, sha256_duration)
    );

    // Parallel hashing (Blake3 only)
    println!("\n--- Parallel Hashing (4 MB) ---");
    println!("{:20} | {:>12} | {:>10}", "Algorithm", "Time", "Throughput");
    println!("{}", "-".repeat(48));

    let large_data = vec![0xEFu8; 4 * 1024 * 1024]; // 4 MB
    let iterations = 50;

    let start = Instant::now();
    for _ in 0..iterations {
        let _hash = Blake3ParallelHasher::hash_large(&large_data);
    }
    let duration = start.elapsed();
    let total_bytes = large_data.len() * iterations;
    println!(
        "{:20} | {:>12} | {:>10}",
        "Blake3 Parallel",
        format!("{:?}", duration),
        format_throughput(total_bytes, duration)
    );

    // Transaction signature hashing
    println!("\n--- Transaction Signature Hashing (64 bytes) ---");
    println!("Simulating deduplication cache lookups for 10,000 transactions\n");

    let signatures: Vec<[u8; 64]> = (0..10000u64)
        .map(|i| {
            let mut sig = [0u8; 64];
            sig[0..8].copy_from_slice(&i.to_le_bytes());
            sig
        })
        .collect();

    let start = Instant::now();
    for signature in &signatures {
        let _hash = paradencer_crypto::blake3::hash_transaction_signature(signature);
    }
    let duration = start.elapsed();
    let total_bytes = signatures.len() * 64;

    println!("Hashed {} signatures in {:?}", signatures.len(), duration);
    println!("Throughput: {}", format_throughput(total_bytes, duration));
    println!(
        "Average time per signature: {:.2} µs",
        duration.as_micros() as f64 / signatures.len() as f64
    );

    // Shred fingerprint hashing
    println!("\n--- Shred Fingerprint Hashing ---");
    println!("Simulating deduplication for 1,000 shreds (1 KB each)\n");

    let shred_data = vec![0u8; 1024]; // 1 KB shred
    let iterations: usize = 1000;

    let start = Instant::now();
    for i in 0..iterations {
        let slot = (i / 100) as u64;
        let index = (i % 100) as u32;
        let _hash = paradencer_crypto::blake3::hash_shred_fingerprint(slot, index, &shred_data);
    }
    let duration = start.elapsed();
    let total_bytes = shred_data.len() * iterations;

    println!("Hashed {} shreds in {:?}", iterations, duration);
    println!("Throughput: {}", format_throughput(total_bytes, duration));
    println!(
        "Average time per shred: {:.2} µs",
        duration.as_micros() as f64 / iterations as f64
    );

    // Summary
    println!("\n=== Summary ===");
    println!("Blake3 is significantly faster than SHA256, especially for larger data.");
    println!("Use Blake3 for new code and SHA256 only when required for compatibility.");
    println!("\nKey takeaways:");
    println!("- Blake3 is 2-3x faster than SHA256 for most data sizes");
    println!("- Blake3 parallel hashing scales well with CPU cores");
    println!("- For small messages (<1KB), both are fast enough for real-time processing");
}
