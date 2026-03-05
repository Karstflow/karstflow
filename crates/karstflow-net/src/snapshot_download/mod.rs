//! Snapshot network download infrastructure.
//!
//! Discovers snapshot-serving peers via gossip CRDS entries (SnapshotHashes +
//! ContactInfo), scores them by slot recency, and downloads snapshot archives
//! over HTTP from the peer's RPC endpoint.

mod archive;
mod downloader;
mod peer_selector;

pub use archive::{
    archive_filename, incremental_archive_filename, incremental_download_path,
    parse_archive_filename, snapshot_download_path, ArchiveInfo,
};
pub use downloader::{DownloadConfig, DownloadError, SnapshotDownloader};
pub use peer_selector::{SnapshotPeerInfo, SnapshotPeerSelector};
