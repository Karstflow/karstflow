use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompressionType {
    None,
    Zstd,
}

impl CompressionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            CompressionType::None => "none",
            CompressionType::Zstd => "zstd",
        }
    }
}

impl Default for CompressionType {
    fn default() -> Self {
        CompressionType::Zstd
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotMetadata {
    pub slot: u64,
    pub hash: [u8; 32],
    pub total_accounts: u64,
    pub total_lamports: u64,
    pub incremental_base: Option<u64>,
    pub compression: CompressionType,
    pub version: u32,
    pub created_at: u64,
    pub account_data_size: u64,
}

impl SnapshotMetadata {
    pub fn new(
        slot: u64,
        total_accounts: u64,
        total_lamports: u64,
        incremental_base: Option<u64>,
        compression: CompressionType,
        account_data_size: u64,
    ) -> Self {
        let hash = [0u8; 32];
        let version = 1;
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            slot,
            hash,
            total_accounts,
            total_lamports,
            incremental_base,
            compression,
            version,
            created_at,
            account_data_size,
        }
    }

    pub fn is_incremental(&self) -> bool {
        self.incremental_base.is_some()
    }

    pub fn is_full(&self) -> bool {
        self.incremental_base.is_none()
    }

    pub fn update_hash(&mut self, hash: [u8; 32]) {
        self.hash = hash;
    }

    pub fn compute_content_hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    pub fn verify_hash(&self, data: &[u8]) -> bool {
        let computed_hash = Self::compute_content_hash(data);
        computed_hash == self.hash
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotManifest {
    pub metadata: SnapshotMetadata,
    pub chunk_count: usize,
    pub chunk_hashes: Vec<[u8; 32]>,
}

impl SnapshotManifest {
    pub fn new(metadata: SnapshotMetadata) -> Self {
        Self {
            metadata,
            chunk_count: 0,
            chunk_hashes: Vec::new(),
        }
    }

    pub fn add_chunk(&mut self, chunk_hash: [u8; 32]) {
        self.chunk_hashes.push(chunk_hash);
        self.chunk_count = self.chunk_hashes.len();
    }

    pub fn verify_chunk(&self, index: usize, data: &[u8]) -> bool {
        if index >= self.chunk_hashes.len() {
            return false;
        }
        let computed_hash = SnapshotMetadata::compute_content_hash(data);
        computed_hash == self.chunk_hashes[index]
    }
}

#[derive(Debug, Clone)]
pub struct SnapshotConfig {
    pub full_snapshot_interval: u64,
    pub incremental_snapshot_interval: u64,
    pub max_full_snapshots: usize,
    pub max_incremental_snapshots: usize,
    pub compression_level: i32,
    pub parallel_workers: usize,
    pub chunk_size: usize,
}

impl SnapshotConfig {
    pub fn new() -> Self {
        Self {
            full_snapshot_interval: 10000,
            incremental_snapshot_interval: 1000,
            max_full_snapshots: 3,
            max_incremental_snapshots: 10,
            compression_level: 3,
            parallel_workers: num_cpus::get(),
            chunk_size: 1024 * 1024,
        }
    }

    pub fn with_full_interval(mut self, interval: u64) -> Self {
        self.full_snapshot_interval = interval;
        self
    }

    pub fn with_incremental_interval(mut self, interval: u64) -> Self {
        self.incremental_snapshot_interval = interval;
        self
    }

    pub fn with_max_full_snapshots(mut self, max: usize) -> Self {
        self.max_full_snapshots = max;
        self
    }

    pub fn with_max_incremental_snapshots(mut self, max: usize) -> Self {
        self.max_incremental_snapshots = max;
        self
    }

    pub fn with_compression_level(mut self, level: i32) -> Self {
        self.compression_level = level;
        self
    }

    pub fn with_parallel_workers(mut self, workers: usize) -> Self {
        self.parallel_workers = workers;
        self
    }

    pub fn with_chunk_size(mut self, size: usize) -> Self {
        self.chunk_size = size;
        self
    }
}

impl Default for SnapshotConfig {
    fn default() -> Self {
        Self::new()
    }
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_creation() {
        let metadata = SnapshotMetadata::new(
            100,
            1000,
            5000000,
            None,
            CompressionType::Zstd,
            10000,
        );
        assert_eq!(metadata.slot, 100);
        assert_eq!(metadata.total_accounts, 1000);
        assert_eq!(metadata.total_lamports, 5000000);
        assert!(metadata.is_full());
        assert!(!metadata.is_incremental());
    }

    #[test]
    fn test_incremental_metadata() {
        let metadata = SnapshotMetadata::new(
            200,
            500,
            2500000,
            Some(100),
            CompressionType::Zstd,
            5000,
        );
        assert_eq!(metadata.slot, 200);
        assert_eq!(metadata.incremental_base, Some(100));
        assert!(metadata.is_incremental());
        assert!(!metadata.is_full());
    }

    #[test]
    fn test_hash_computation() {
        let data = b"test data";
        let hash1 = SnapshotMetadata::compute_content_hash(data);
        let hash2 = SnapshotMetadata::compute_content_hash(data);
        assert_eq!(hash1, hash2);

        let different_data = b"different data";
        let hash3 = SnapshotMetadata::compute_content_hash(different_data);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_hash_verification() {
        let data = b"test data";
        let hash = SnapshotMetadata::compute_content_hash(data);
        let mut metadata = SnapshotMetadata::new(
            100,
            1000,
            5000000,
            None,
            CompressionType::Zstd,
            10000,
        );
        metadata.update_hash(hash);
        assert!(metadata.verify_hash(data));
        assert!(!metadata.verify_hash(b"wrong data"));
    }

    #[test]
    fn test_manifest_creation() {
        let metadata = SnapshotMetadata::new(
            100,
            1000,
            5000000,
            None,
            CompressionType::Zstd,
            10000,
        );
        let mut manifest = SnapshotManifest::new(metadata);
        assert_eq!(manifest.chunk_count, 0);
        assert!(manifest.chunk_hashes.is_empty());

        let chunk_data = b"chunk data";
        let chunk_hash = SnapshotMetadata::compute_content_hash(chunk_data);
        manifest.add_chunk(chunk_hash);
        assert_eq!(manifest.chunk_count, 1);
        assert!(manifest.verify_chunk(0, chunk_data));
        assert!(!manifest.verify_chunk(0, b"wrong data"));
    }

    #[test]
    fn test_config_builder() {
        let config = SnapshotConfig::new()
            .with_full_interval(5000)
            .with_incremental_interval(500)
            .with_max_full_snapshots(5)
            .with_compression_level(5);
        assert_eq!(config.full_snapshot_interval, 5000);
        assert_eq!(config.incremental_snapshot_interval, 500);
        assert_eq!(config.max_full_snapshots, 5);
        assert_eq!(config.compression_level, 5);
    }
}
