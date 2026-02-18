//! Parser for Solana snapshot archive format (tar.zst).
//!
//! A Solana snapshot is a zstd-compressed tar archive containing:
//! - `version` — "1.2.0" version string
//! - `snapshots/<slot>/manifest` — bincode-encoded bank state
//! - `snapshots/status_cache` — transaction status cache
//! - `accounts/<slot>.<id>` — AppendVec account storage files

use std::io::{self, Read};

/// TAR block size.
const TAR_BLOCK_SIZE: usize = 512;

/// Expected snapshot format version.
#[allow(dead_code)]
const EXPECTED_VERSION: &str = "1.2.0";

/// Entry from a Solana snapshot archive.
#[derive(Debug, Clone)]
pub enum SnapshotArchiveEntry {
    /// Version string (should be "1.2.0").
    Version(String),
    /// Manifest data (raw bincode bytes).
    Manifest(Vec<u8>),
    /// Status cache data (raw bincode bytes).
    StatusCache(Vec<u8>),
    /// Account vector with slot and vector ID.
    AccountVec {
        slot: u64,
        vec_id: u64,
        data: Vec<u8>,
    },
    /// Unknown file in the archive.
    Unknown { path: String, data: Vec<u8> },
}

/// Streaming Solana snapshot archive parser.
///
/// Accepts either compressed (.tar.zst) or uncompressed (.tar) data
/// and yields archive entries.
pub struct SnapshotArchive;

impl SnapshotArchive {
    /// Parse a zstd-compressed snapshot archive from a reader.
    ///
    /// Decompresses and yields all entries in order.
    pub fn parse_compressed<R: Read>(reader: R) -> Result<Vec<SnapshotArchiveEntry>, ArchiveError> {
        let decoder = zstd::stream::Decoder::new(reader)?;
        Self::parse_tar(decoder)
    }

    /// Parse an uncompressed tar archive from a reader.
    pub fn parse_tar<R: Read>(mut reader: R) -> Result<Vec<SnapshotArchiveEntry>, ArchiveError> {
        let mut entries = Vec::new();
        let mut block = [0u8; TAR_BLOCK_SIZE];
        let mut consecutive_zero_blocks = 0;

        loop {
            // Read a TAR header block.
            match reader.read_exact(&mut block) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(ArchiveError::Io(e.to_string())),
            }

            // Two consecutive zero blocks signal end of archive.
            if block.iter().all(|&b| b == 0) {
                consecutive_zero_blocks += 1;
                if consecutive_zero_blocks >= 2 {
                    break;
                }
                continue;
            }
            consecutive_zero_blocks = 0;

            // Parse the header.
            let header = TarHeader::parse(&block)?;

            // Read file content.
            let data = Self::read_file_data(&mut reader, header.size)?;

            // Classify entry by path.
            let entry = Self::classify_entry(&header.name, data)?;
            entries.push(entry);
        }

        Ok(entries)
    }

    /// Parse from a byte buffer (zstd-compressed).
    pub fn parse_bytes(data: &[u8]) -> Result<Vec<SnapshotArchiveEntry>, ArchiveError> {
        Self::parse_compressed(std::io::Cursor::new(data))
    }

    /// Parse from an uncompressed byte buffer.
    pub fn parse_tar_bytes(data: &[u8]) -> Result<Vec<SnapshotArchiveEntry>, ArchiveError> {
        Self::parse_tar(std::io::Cursor::new(data))
    }

    fn read_file_data<R: Read>(reader: &mut R, size: u64) -> Result<Vec<u8>, ArchiveError> {
        let size = size as usize;
        let mut data = vec![0u8; size];
        reader
            .read_exact(&mut data)
            .map_err(|e| ArchiveError::Io(e.to_string()))?;

        // TAR pads files to 512-byte boundaries.
        let pad = (TAR_BLOCK_SIZE - (size % TAR_BLOCK_SIZE)) % TAR_BLOCK_SIZE;
        if pad > 0 {
            let mut skip = vec![0u8; pad];
            reader
                .read_exact(&mut skip)
                .map_err(|e| ArchiveError::Io(e.to_string()))?;
        }

        Ok(data)
    }

    fn classify_entry(name: &str, data: Vec<u8>) -> Result<SnapshotArchiveEntry, ArchiveError> {
        let name = name.trim_start_matches("./");

        if name == "version" {
            let version = String::from_utf8(data)
                .map_err(|_| ArchiveError::InvalidVersion)?
                .trim()
                .to_string();
            if !version.starts_with("1.") {
                return Err(ArchiveError::UnsupportedVersion(version));
            }
            return Ok(SnapshotArchiveEntry::Version(version));
        }

        if name.contains("status_cache") {
            return Ok(SnapshotArchiveEntry::StatusCache(data));
        }

        if name.starts_with("snapshots/") && !name.contains("status_cache") {
            return Ok(SnapshotArchiveEntry::Manifest(data));
        }

        if name.starts_with("accounts/") {
            // Parse "accounts/<slot>.<id>" path.
            let filename = name.trim_start_matches("accounts/");
            if let Some((slot_str, id_str)) = filename.split_once('.') {
                let slot = slot_str
                    .parse::<u64>()
                    .map_err(|_| ArchiveError::InvalidAccountPath(name.to_string()))?;
                let vec_id = id_str
                    .parse::<u64>()
                    .map_err(|_| ArchiveError::InvalidAccountPath(name.to_string()))?;
                return Ok(SnapshotArchiveEntry::AccountVec { slot, vec_id, data });
            }
        }

        Ok(SnapshotArchiveEntry::Unknown {
            path: name.to_string(),
            data,
        })
    }
}

/// Build a Solana-compatible snapshot archive as an uncompressed tar.
///
/// The archive contains:
/// - `version` — version string (default "1.18.26")
/// - `snapshots/<slot>/<slot>` — manifest data (bincode-encoded bank state)
/// - `snapshots/status_cache` — status cache data
/// - `accounts/<slot>.<id>` — AppendVec account files
///
/// Returns the uncompressed tar bytes. Caller can compress with zstd.
#[allow(dead_code)]
pub struct SnapshotArchiveBuilder {
    entries: Vec<(String, Vec<u8>)>,
}

#[allow(dead_code)]
impl SnapshotArchiveBuilder {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Set the version string (e.g., "1.18.26").
    pub fn set_version(&mut self, version: &str) -> &mut Self {
        self.entries
            .push(("version".to_string(), version.as_bytes().to_vec()));
        self
    }

    /// Add the bank state manifest for a given slot.
    pub fn set_manifest(&mut self, slot: u64, data: Vec<u8>) -> &mut Self {
        let path = format!("snapshots/{slot}/{slot}");
        self.entries.push((path, data));
        self
    }

    /// Add the status cache.
    pub fn set_status_cache(&mut self, data: Vec<u8>) -> &mut Self {
        self.entries
            .push(("snapshots/status_cache".to_string(), data));
        self
    }

    /// Add an AppendVec account file.
    pub fn add_account_vec(&mut self, slot: u64, vec_id: u64, data: Vec<u8>) -> &mut Self {
        let path = format!("accounts/{slot}.{vec_id}");
        self.entries.push((path, data));
        self
    }

    /// Build the tar archive (uncompressed).
    pub fn build_tar(&self) -> Vec<u8> {
        let mut archive = Vec::new();

        for (name, content) in &self.entries {
            Self::write_tar_entry(&mut archive, name, content);
        }

        // End-of-archive marker: two 512-byte zero blocks.
        archive.extend(std::iter::repeat_n(0u8, TAR_BLOCK_SIZE * 2));
        archive
    }

    /// Build the archive and compress with zstd.
    pub fn build_compressed(&self, compression_level: i32) -> Result<Vec<u8>, ArchiveError> {
        let tar = self.build_tar();
        zstd::bulk::compress(&tar, compression_level)
            .map_err(|e| ArchiveError::Io(format!("zstd compression failed: {e}")))
    }

    fn write_tar_entry(archive: &mut Vec<u8>, name: &str, content: &[u8]) {
        let mut header = [0u8; TAR_BLOCK_SIZE];

        // Name (bytes 0-99).
        let name_bytes = name.as_bytes();
        let copy_len = name_bytes.len().min(100);
        header[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        // Size (bytes 124-135, octal 11 chars).
        let size_str = format!("{:011o}", content.len());
        header[124..124 + size_str.len()].copy_from_slice(size_str.as_bytes());

        // Typeflag '0' for regular file.
        header[156] = b'0';

        // Magic "ustar\0".
        header[257..263].copy_from_slice(b"ustar\0");

        // Compute checksum: treat checksum field (148-155) as spaces.
        header[148..156].copy_from_slice(b"        ");
        let checksum: u32 = header.iter().map(|&b| b as u32).sum();
        let cksum_str = format!("{checksum:06o}\0 ");
        header[148..156].copy_from_slice(&cksum_str.as_bytes()[..8]);

        archive.extend_from_slice(&header);
        archive.extend_from_slice(content);

        // Pad to 512-byte boundary.
        let pad = (TAR_BLOCK_SIZE - (content.len() % TAR_BLOCK_SIZE)) % TAR_BLOCK_SIZE;
        archive.extend(std::iter::repeat_n(0u8, pad));
    }
}

impl Default for SnapshotArchiveBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Minimal TAR header parser.
struct TarHeader {
    name: String,
    size: u64,
}

impl TarHeader {
    fn parse(block: &[u8; TAR_BLOCK_SIZE]) -> Result<Self, ArchiveError> {
        // Name: bytes 0-99 (null-terminated).
        // Prefix (for long names): bytes 345-499.
        let prefix = Self::parse_str(&block[345..500]);
        let name_part = Self::parse_str(&block[0..100]);
        let name = if prefix.is_empty() {
            name_part
        } else {
            format!("{prefix}/{name_part}")
        };

        // Size: bytes 124-135 (octal string or binary).
        let size = Self::parse_size(&block[124..136])?;

        Ok(TarHeader { name, size })
    }

    fn parse_str(bytes: &[u8]) -> String {
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        String::from_utf8_lossy(&bytes[..end]).trim().to_string()
    }

    fn parse_size(bytes: &[u8]) -> Result<u64, ArchiveError> {
        // Check for OLDGNU binary encoding (first byte = 0x80).
        if !bytes.is_empty() && bytes[0] == 0x80 {
            // Big-endian u64 in last 8 bytes.
            if bytes.len() >= 12 {
                let size_bytes: [u8; 8] = bytes[4..12].try_into().unwrap();
                return Ok(u64::from_be_bytes(size_bytes));
            }
        }

        // Standard octal encoding.
        let s = Self::parse_str(bytes);
        if s.is_empty() {
            return Ok(0);
        }
        u64::from_str_radix(&s, 8).map_err(|_| ArchiveError::InvalidSize(s))
    }
}

#[derive(Debug, Clone)]
pub enum ArchiveError {
    Io(String),
    InvalidVersion,
    UnsupportedVersion(String),
    InvalidSize(String),
    InvalidAccountPath(String),
}

impl std::fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(msg) => write!(f, "I/O error: {msg}"),
            Self::InvalidVersion => write!(f, "invalid version string"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported snapshot version: {v}"),
            Self::InvalidSize(s) => write!(f, "invalid tar size field: {s}"),
            Self::InvalidAccountPath(p) => write!(f, "invalid account path: {p}"),
        }
    }
}

impl std::error::Error for ArchiveError {}

impl From<io::Error> for ArchiveError {
    fn from(e: io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal tar archive in memory.
    fn make_tar(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut archive = Vec::new();

        for (name, content) in files {
            // Build header.
            let mut header = [0u8; TAR_BLOCK_SIZE];

            // Name.
            let name_bytes = name.as_bytes();
            let copy_len = name_bytes.len().min(100);
            header[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

            // Size (octal, 11 chars max).
            let size_str = format!("{:011o}", content.len());
            header[124..124 + size_str.len()].copy_from_slice(size_str.as_bytes());

            // Typeflag '0' for regular file.
            header[156] = b'0';

            // Magic "ustar\0".
            header[257..263].copy_from_slice(b"ustar\0");

            // Checksum (sum of all bytes with checksum field as spaces).
            header[148..156].copy_from_slice(b"        ");
            let checksum: u32 = header.iter().map(|&b| b as u32).sum();
            let cksum_str = format!("{checksum:06o}\0 ");
            header[148..156].copy_from_slice(&cksum_str.as_bytes()[..8]);

            archive.extend_from_slice(&header);

            // File content.
            archive.extend_from_slice(content);

            // Pad to 512-byte boundary.
            let pad = (TAR_BLOCK_SIZE - (content.len() % TAR_BLOCK_SIZE)) % TAR_BLOCK_SIZE;
            archive.extend(std::iter::repeat_n(0u8, pad));
        }

        // Two zero blocks to end archive.
        archive.extend(std::iter::repeat_n(0u8, TAR_BLOCK_SIZE * 2));

        archive
    }

    #[test]
    fn parse_version_entry() {
        let tar = make_tar(&[("version", b"1.2.0")]);
        let entries = SnapshotArchive::parse_tar_bytes(&tar).unwrap();
        assert_eq!(entries.len(), 1);
        match &entries[0] {
            SnapshotArchiveEntry::Version(v) => assert_eq!(v, "1.2.0"),
            other => panic!("expected Version, got {other:?}"),
        }
    }

    #[test]
    fn parse_manifest_entry() {
        let manifest_data = vec![1, 2, 3, 4, 5];
        let tar = make_tar(&[("snapshots/100/100", &manifest_data)]);
        let entries = SnapshotArchive::parse_tar_bytes(&tar).unwrap();
        assert_eq!(entries.len(), 1);
        match &entries[0] {
            SnapshotArchiveEntry::Manifest(data) => assert_eq!(data, &manifest_data),
            other => panic!("expected Manifest, got {other:?}"),
        }
    }

    #[test]
    fn parse_status_cache_entry() {
        let tar = make_tar(&[("snapshots/status_cache", &[10, 20, 30])]);
        let entries = SnapshotArchive::parse_tar_bytes(&tar).unwrap();
        assert_eq!(entries.len(), 1);
        matches!(&entries[0], SnapshotArchiveEntry::StatusCache(_));
    }

    #[test]
    fn parse_account_vec_entry() {
        let account_data = vec![0u8; 200];
        let tar = make_tar(&[("accounts/42.7", &account_data)]);
        let entries = SnapshotArchive::parse_tar_bytes(&tar).unwrap();
        assert_eq!(entries.len(), 1);
        match &entries[0] {
            SnapshotArchiveEntry::AccountVec { slot, vec_id, data } => {
                assert_eq!(*slot, 42);
                assert_eq!(*vec_id, 7);
                assert_eq!(data.len(), 200);
            }
            other => panic!("expected AccountVec, got {other:?}"),
        }
    }

    #[test]
    fn parse_full_snapshot_structure() {
        let tar = make_tar(&[
            ("version", b"1.2.0"),
            ("snapshots/100/100", &[1, 2, 3]),
            ("snapshots/status_cache", &[4, 5, 6]),
            ("accounts/100.0", &[7, 8, 9]),
            ("accounts/100.1", &[10, 11, 12]),
        ]);
        let entries = SnapshotArchive::parse_tar_bytes(&tar).unwrap();
        assert_eq!(entries.len(), 5);
        assert!(matches!(&entries[0], SnapshotArchiveEntry::Version(_)));
        assert!(matches!(&entries[1], SnapshotArchiveEntry::Manifest(_)));
        assert!(matches!(&entries[2], SnapshotArchiveEntry::StatusCache(_)));
        assert!(matches!(
            &entries[3],
            SnapshotArchiveEntry::AccountVec { .. }
        ));
        assert!(matches!(
            &entries[4],
            SnapshotArchiveEntry::AccountVec { .. }
        ));
    }

    #[test]
    fn parse_compressed_archive() {
        let tar = make_tar(&[("version", b"1.2.0"), ("accounts/1.0", &[42])]);

        // Compress with zstd.
        let compressed = zstd::bulk::compress(&tar, 3).unwrap();

        let entries = SnapshotArchive::parse_bytes(&compressed).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn unsupported_version_rejected() {
        let tar = make_tar(&[("version", b"0.5.0")]);
        let result = SnapshotArchive::parse_tar_bytes(&tar);
        assert!(result.is_err());
    }

    #[test]
    fn empty_archive_ok() {
        let archive = vec![0u8; TAR_BLOCK_SIZE * 2]; // Two zero blocks
        let entries = SnapshotArchive::parse_tar_bytes(&archive).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn unknown_file_preserved() {
        let tar = make_tar(&[("some/random/file.txt", b"hello")]);
        let entries = SnapshotArchive::parse_tar_bytes(&tar).unwrap();
        assert_eq!(entries.len(), 1);
        match &entries[0] {
            SnapshotArchiveEntry::Unknown { path, data } => {
                assert_eq!(path, "some/random/file.txt");
                assert_eq!(data, b"hello");
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // Archive builder tests
    // -------------------------------------------------------------------

    #[test]
    fn builder_version_roundtrip() {
        let mut builder = SnapshotArchiveBuilder::new();
        builder.set_version("1.18.26");
        let tar = builder.build_tar();
        let entries = SnapshotArchive::parse_tar_bytes(&tar).unwrap();
        assert_eq!(entries.len(), 1);
        match &entries[0] {
            SnapshotArchiveEntry::Version(v) => assert_eq!(v, "1.18.26"),
            other => panic!("expected Version, got {other:?}"),
        }
    }

    #[test]
    fn builder_manifest_roundtrip() {
        let mut builder = SnapshotArchiveBuilder::new();
        builder.set_manifest(100, vec![1, 2, 3, 4, 5]);
        let tar = builder.build_tar();
        let entries = SnapshotArchive::parse_tar_bytes(&tar).unwrap();
        assert_eq!(entries.len(), 1);
        match &entries[0] {
            SnapshotArchiveEntry::Manifest(data) => assert_eq!(data, &[1, 2, 3, 4, 5]),
            other => panic!("expected Manifest, got {other:?}"),
        }
    }

    #[test]
    fn builder_account_vec_roundtrip() {
        let mut builder = SnapshotArchiveBuilder::new();
        builder.add_account_vec(42, 7, vec![10, 20, 30]);
        let tar = builder.build_tar();
        let entries = SnapshotArchive::parse_tar_bytes(&tar).unwrap();
        assert_eq!(entries.len(), 1);
        match &entries[0] {
            SnapshotArchiveEntry::AccountVec { slot, vec_id, data } => {
                assert_eq!(*slot, 42);
                assert_eq!(*vec_id, 7);
                assert_eq!(data, &[10, 20, 30]);
            }
            other => panic!("expected AccountVec, got {other:?}"),
        }
    }

    #[test]
    fn builder_full_snapshot_structure() {
        let mut builder = SnapshotArchiveBuilder::new();
        builder.set_version("1.18.26");
        builder.set_manifest(100, vec![1, 2, 3]);
        builder.set_status_cache(vec![4, 5]);
        builder.add_account_vec(100, 0, vec![6, 7]);
        builder.add_account_vec(100, 1, vec![8, 9, 10]);

        let tar = builder.build_tar();
        let entries = SnapshotArchive::parse_tar_bytes(&tar).unwrap();
        assert_eq!(entries.len(), 5);
        assert!(matches!(&entries[0], SnapshotArchiveEntry::Version(_)));
        assert!(matches!(&entries[1], SnapshotArchiveEntry::Manifest(_)));
        assert!(matches!(&entries[2], SnapshotArchiveEntry::StatusCache(_)));
        assert!(matches!(
            &entries[3],
            SnapshotArchiveEntry::AccountVec { .. }
        ));
        assert!(matches!(
            &entries[4],
            SnapshotArchiveEntry::AccountVec { .. }
        ));
    }

    #[test]
    fn builder_compressed_roundtrip() {
        let mut builder = SnapshotArchiveBuilder::new();
        builder.set_version("1.18.26");
        builder.add_account_vec(50, 0, vec![42; 100]);

        let compressed = builder.build_compressed(3).unwrap();
        let entries = SnapshotArchive::parse_bytes(&compressed).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn builder_empty_archive() {
        let builder = SnapshotArchiveBuilder::new();
        let tar = builder.build_tar();
        let entries = SnapshotArchive::parse_tar_bytes(&tar).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn builder_large_account_data() {
        let mut builder = SnapshotArchiveBuilder::new();
        let big_data = vec![0xAB; 100_000];
        builder.add_account_vec(1, 0, big_data.clone());

        let tar = builder.build_tar();
        let entries = SnapshotArchive::parse_tar_bytes(&tar).unwrap();
        assert_eq!(entries.len(), 1);
        match &entries[0] {
            SnapshotArchiveEntry::AccountVec { data, .. } => {
                assert_eq!(data.len(), 100_000);
                assert_eq!(data, &big_data);
            }
            _ => panic!("expected AccountVec"),
        }
    }
}
