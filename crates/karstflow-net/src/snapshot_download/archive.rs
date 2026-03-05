//! Snapshot archive filename utilities.
//!
//! Solana validators serve snapshots as tar.zst archives with a canonical
//! naming convention: `snapshot-{slot}-{hash_base58}.tar.zst` for full
//! snapshots and `incremental-snapshot-{base_slot}-{slot}-{hash_base58}.tar.zst`
//! for incremental snapshots.

/// Parsed snapshot archive filename.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveInfo {
    /// Snapshot slot.
    pub slot: u64,
    /// Snapshot bank hash (32 bytes).
    pub hash: [u8; 32],
    /// Base slot for incremental snapshots (None for full).
    pub base_slot: Option<u64>,
}

/// Build the canonical filename for a full snapshot archive.
///
/// Format: `snapshot-{slot}-{hash_base58}.tar.zst`
pub fn archive_filename(slot: u64, hash: &[u8; 32]) -> String {
    let hash_b58 = bs58::encode(hash).into_string();
    format!("snapshot-{slot}-{hash_b58}.tar.zst")
}

/// Build the canonical filename for an incremental snapshot archive.
///
/// Format: `incremental-snapshot-{base_slot}-{slot}-{hash_base58}.tar.zst`
pub fn incremental_archive_filename(base_slot: u64, slot: u64, hash: &[u8; 32]) -> String {
    let hash_b58 = bs58::encode(hash).into_string();
    format!("incremental-snapshot-{base_slot}-{slot}-{hash_b58}.tar.zst")
}

/// Build the URL path for downloading a full snapshot from a peer's RPC endpoint.
///
/// Returns the path component: `/snapshot-{slot}-{hash_base58}.tar.zst`
pub fn snapshot_download_path(slot: u64, hash: &[u8; 32]) -> String {
    let hash_b58 = bs58::encode(hash).into_string();
    format!("/snapshot-{slot}-{hash_b58}.tar.zst")
}

/// Build the URL path for downloading an incremental snapshot.
pub fn incremental_download_path(base_slot: u64, slot: u64, hash: &[u8; 32]) -> String {
    let hash_b58 = bs58::encode(hash).into_string();
    format!("/incremental-snapshot-{base_slot}-{slot}-{hash_b58}.tar.zst")
}

/// Parse a snapshot archive filename into its components.
///
/// Supports both full and incremental snapshot filenames:
/// - `snapshot-{slot}-{hash}.tar.zst`
/// - `incremental-snapshot-{base}-{slot}-{hash}.tar.zst`
///
/// Returns `None` if the filename doesn't match the expected format.
pub fn parse_archive_filename(filename: &str) -> Option<ArchiveInfo> {
    let name = filename.strip_suffix(".tar.zst")?;

    if let Some(rest) = name.strip_prefix("snapshot-") {
        // Full snapshot: snapshot-{slot}-{hash}
        let (slot_str, hash_str) = rest.split_once('-')?;
        let slot = slot_str.parse::<u64>().ok()?;
        let hash = decode_hash_base58(hash_str)?;
        Some(ArchiveInfo {
            slot,
            hash,
            base_slot: None,
        })
    } else if let Some(rest) = name.strip_prefix("incremental-snapshot-") {
        // Incremental: incremental-snapshot-{base}-{slot}-{hash}
        let (base_str, remainder) = rest.split_once('-')?;
        let base_slot = base_str.parse::<u64>().ok()?;
        let (slot_str, hash_str) = remainder.split_once('-')?;
        let slot = slot_str.parse::<u64>().ok()?;
        let hash = decode_hash_base58(hash_str)?;
        Some(ArchiveInfo {
            slot,
            hash,
            base_slot: Some(base_slot),
        })
    } else {
        None
    }
}

fn decode_hash_base58(s: &str) -> Option<[u8; 32]> {
    let bytes = bs58::decode(s).into_vec().ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Some(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_snapshot_filename_roundtrip() {
        let slot = 123456789;
        let hash = [42u8; 32];
        let filename = archive_filename(slot, &hash);

        assert!(filename.starts_with("snapshot-123456789-"));
        assert!(filename.ends_with(".tar.zst"));

        let parsed = parse_archive_filename(&filename).unwrap();
        assert_eq!(parsed.slot, slot);
        assert_eq!(parsed.hash, hash);
        assert_eq!(parsed.base_slot, None);
    }

    #[test]
    fn incremental_snapshot_filename_roundtrip() {
        let base = 100000;
        let slot = 200000;
        let hash = [7u8; 32];
        let filename = incremental_archive_filename(base, slot, &hash);

        assert!(filename.starts_with("incremental-snapshot-100000-200000-"));
        assert!(filename.ends_with(".tar.zst"));

        let parsed = parse_archive_filename(&filename).unwrap();
        assert_eq!(parsed.slot, slot);
        assert_eq!(parsed.hash, hash);
        assert_eq!(parsed.base_slot, Some(base));
    }

    #[test]
    fn download_path_format() {
        let hash = [1u8; 32];
        let path = snapshot_download_path(42, &hash);
        assert!(path.starts_with("/snapshot-42-"));
        assert!(path.ends_with(".tar.zst"));
    }

    #[test]
    fn incremental_download_path_format() {
        let hash = [2u8; 32];
        let path = incremental_download_path(100, 200, &hash);
        assert!(path.starts_with("/incremental-snapshot-100-200-"));
        assert!(path.ends_with(".tar.zst"));
    }

    #[test]
    fn parse_invalid_filename() {
        assert!(parse_archive_filename("random-file.tar.zst").is_none());
        assert!(parse_archive_filename("snapshot-.tar.zst").is_none());
        assert!(parse_archive_filename("snapshot-abc-def.tar.zst").is_none());
        assert!(parse_archive_filename("not-a-snapshot").is_none());
    }

    #[test]
    fn parse_full_snapshot_known_hash() {
        let hash = [0u8; 32];
        let hash_b58 = bs58::encode(hash).into_string();
        let filename = format!("snapshot-999-{hash_b58}.tar.zst");
        let info = parse_archive_filename(&filename).unwrap();
        assert_eq!(info.slot, 999);
        assert_eq!(info.hash, hash);
        assert!(info.base_slot.is_none());
    }

    #[test]
    fn parse_incremental_snapshot_known_hash() {
        let hash = [0xFFu8; 32];
        let hash_b58 = bs58::encode(hash).into_string();
        let filename = format!("incremental-snapshot-500-1000-{hash_b58}.tar.zst");
        let info = parse_archive_filename(&filename).unwrap();
        assert_eq!(info.slot, 1000);
        assert_eq!(info.hash, hash);
        assert_eq!(info.base_slot, Some(500));
    }
}
