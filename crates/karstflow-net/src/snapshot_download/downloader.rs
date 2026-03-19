//! HTTP snapshot downloader.
//!
//! Downloads snapshot archives from validator RPC endpoints over HTTP.
//! Uses `ureq` for a lightweight sync HTTP client. Intended to run
//! in a dedicated thread (not async) since snapshot download is a
//! startup-only operation.

use super::archive::{incremental_download_path, snapshot_download_path};
use super::peer_selector::SnapshotPeerInfo;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::{debug, info, warn};

/// Errors during snapshot download.
#[derive(Debug, Error)]
pub enum DownloadError {
    #[error("HTTP request failed: {0}")]
    Http(Box<ureq::Error>),

    #[error("HTTP status {status} from {addr}")]
    HttpStatus { status: u16, addr: SocketAddr },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("download too slow: {bytes_per_sec} B/s (min: {min_bytes_per_sec} B/s)")]
    TooSlow {
        bytes_per_sec: u64,
        min_bytes_per_sec: u64,
    },

    #[error("no peers available")]
    NoPeers,
}

impl From<ureq::Error> for DownloadError {
    fn from(e: ureq::Error) -> Self {
        Self::Http(Box::new(e))
    }
}

/// Configuration for snapshot downloads.
#[derive(Debug, Clone)]
pub struct DownloadConfig {
    /// Minimum download speed in bytes/sec before aborting.
    /// Default: 10 MB/s.
    pub min_speed_bytes_per_sec: u64,

    /// Connect timeout in seconds.
    pub connect_timeout_secs: u64,

    /// Read buffer size in bytes.
    pub read_buffer_size: usize,
}

impl Default for DownloadConfig {
    fn default() -> Self {
        Self {
            min_speed_bytes_per_sec: 10 * 1024 * 1024,
            connect_timeout_secs: 30,
            read_buffer_size: 256 * 1024, // 256 KB
        }
    }
}

/// Downloads snapshot archives from peers.
pub struct SnapshotDownloader {
    agent: ureq::Agent,
    config: DownloadConfig,
}

impl SnapshotDownloader {
    /// Create a new downloader with the given configuration.
    pub fn new(config: DownloadConfig) -> Self {
        let agent = ureq::config::Config::builder()
            .timeout_connect(Some(std::time::Duration::from_secs(
                config.connect_timeout_secs,
            )))
            .build()
            .new_agent();
        Self { agent, config }
    }

    /// Download a full snapshot from a fallback HTTP server.
    ///
    /// Uses the generic `/snapshot.tar.bz2` URL which typically redirects
    /// to the actual snapshot file with slot/hash in the filename.
    /// Returns the path to the downloaded archive.
    pub fn download_full_from_server(
        &self,
        addr: std::net::SocketAddr,
        output_dir: &Path,
    ) -> Result<PathBuf, DownloadError> {
        let url = format!("http://{}/snapshot.tar.bz2", addr);
        info!(%url, "downloading snapshot from fallback server");

        let output_path = output_dir.join("snapshot-fallback.tar.zst");
        let temp_path = output_dir.join("snapshot-fallback.tar.zst.partial");

        self.download_to_file(&url, addr, &temp_path)?;

        std::fs::rename(&temp_path, &output_path)?;
        info!(path = %output_path.display(), "fallback snapshot download complete");

        Ok(output_path)
    }

    /// Download a full snapshot from a peer to the output directory.
    ///
    /// Returns the path to the downloaded archive file.
    /// This is a blocking operation — call from a dedicated thread.
    pub fn download_full(
        &self,
        peer: &SnapshotPeerInfo,
        output_dir: &Path,
    ) -> Result<PathBuf, DownloadError> {
        let (slot, hash) = &peer.full_snapshot;
        let url = Self::build_full_url(peer);

        let filename = super::archive::archive_filename(*slot, hash);
        let output_path = output_dir.join(&filename);
        let temp_path = output_dir.join(format!("{filename}.partial"));

        info!(
            slot = slot,
            peer = %peer.rpc_addr,
            "downloading full snapshot"
        );

        self.download_to_file(&url, peer.rpc_addr, &temp_path)?;

        std::fs::rename(&temp_path, &output_path)?;
        info!(
            slot = slot,
            path = %output_path.display(),
            "full snapshot download complete"
        );

        Ok(output_path)
    }

    /// Download an incremental snapshot from a peer to the output directory.
    ///
    /// Returns the path to the downloaded archive file, or `None` if the
    /// peer does not advertise an incremental snapshot.
    pub fn download_incremental(
        &self,
        peer: &SnapshotPeerInfo,
        output_dir: &Path,
    ) -> Result<Option<PathBuf>, DownloadError> {
        let (base_slot, incr_slot, incr_hash) = match &peer.incremental_snapshot {
            Some(v) => *v,
            None => return Ok(None),
        };

        let url_path = incremental_download_path(base_slot, incr_slot, &incr_hash);
        let url = format!("http://{}{}", peer.rpc_addr, url_path);

        let filename =
            super::archive::incremental_archive_filename(base_slot, incr_slot, &incr_hash);
        let output_path = output_dir.join(&filename);
        let temp_path = output_dir.join(format!("{filename}.partial"));

        info!(
            base_slot = base_slot,
            slot = incr_slot,
            peer = %peer.rpc_addr,
            "downloading incremental snapshot"
        );

        self.download_to_file(&url, peer.rpc_addr, &temp_path)?;

        std::fs::rename(&temp_path, &output_path)?;
        info!(
            slot = incr_slot,
            path = %output_path.display(),
            "incremental snapshot download complete"
        );

        Ok(Some(output_path))
    }

    /// Stream an HTTP response body to a file with speed monitoring.
    fn download_to_file(
        &self,
        url: &str,
        addr: SocketAddr,
        output_path: &Path,
    ) -> Result<(), DownloadError> {
        debug!(url = url, "starting HTTP download");

        let response = self.agent.get(url).call()?;

        let status = response.status().as_u16();
        if status != 200 {
            return Err(DownloadError::HttpStatus { status, addr });
        }

        let content_length: Option<u64> = response
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok());

        if let Some(len) = content_length {
            info!(content_length = len, "snapshot size");
        }

        let mut reader = response.into_body().into_reader();
        let mut file = std::fs::File::create(output_path)?;
        let mut buf = vec![0u8; self.config.read_buffer_size];
        let mut downloaded: u64 = 0;
        let start = std::time::Instant::now();
        let mut last_speed_check = start;
        let mut bytes_since_check: u64 = 0;

        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            file.write_all(&buf[..n])?;
            downloaded += n as u64;
            bytes_since_check += n as u64;

            // Speed check every 10 seconds.
            let now = std::time::Instant::now();
            let check_elapsed = now.duration_since(last_speed_check);
            if check_elapsed.as_secs() >= 10 {
                let speed = bytes_since_check / check_elapsed.as_secs().max(1);
                if speed < self.config.min_speed_bytes_per_sec {
                    warn!(
                        speed_bps = speed,
                        min_bps = self.config.min_speed_bytes_per_sec,
                        downloaded = downloaded,
                        "download too slow, aborting"
                    );
                    drop(file);
                    let _ = std::fs::remove_file(output_path);
                    return Err(DownloadError::TooSlow {
                        bytes_per_sec: speed,
                        min_bytes_per_sec: self.config.min_speed_bytes_per_sec,
                    });
                }
                last_speed_check = now;
                bytes_since_check = 0;
            }
        }

        file.flush()?;

        let elapsed = start.elapsed();
        let speed_mbs = if elapsed.as_secs() > 0 {
            downloaded / 1024 / 1024 / elapsed.as_secs().max(1)
        } else {
            0
        };
        info!(
            bytes = downloaded,
            elapsed_secs = elapsed.as_secs(),
            speed_mbs = speed_mbs,
            "download complete"
        );

        Ok(())
    }

    /// Build the download URL for a peer's full snapshot.
    pub fn build_full_url(peer: &SnapshotPeerInfo) -> String {
        let (slot, hash) = &peer.full_snapshot;
        let path = snapshot_download_path(*slot, hash);
        format!("http://{}{}", peer.rpc_addr, path)
    }

    /// Build the download URL for a peer's incremental snapshot.
    pub fn build_incremental_url(peer: &SnapshotPeerInfo) -> Option<String> {
        let (base_slot, incr_slot, incr_hash) = peer.incremental_snapshot.as_ref()?;
        let path = incremental_download_path(*base_slot, *incr_slot, incr_hash);
        Some(format!("http://{}{}", peer.rpc_addr, path))
    }
}

/// Download genesis.tar.bz2 from a peer RPC endpoint and extract genesis.bin.
///
/// Tries each provided RPC address in order until one succeeds.
/// The genesis archive is a bzip2-compressed tar containing genesis.bin.
pub fn download_genesis(
    rpc_addrs: &[std::net::SocketAddr],
    output_dir: &Path,
    connect_timeout_secs: u64,
) -> Result<PathBuf, DownloadError> {
    let genesis_path = output_dir.join("genesis.bin");
    if genesis_path.exists() {
        info!(path = %genesis_path.display(), "genesis.bin already exists, skipping download");
        return Ok(genesis_path);
    }

    let archive_path = output_dir.join("genesis.tar.bz2");

    for addr in rpc_addrs {
        let url = format!("http://{}/genesis.tar.bz2", addr);
        info!(%url, "downloading genesis.tar.bz2");

        let agent = ureq::config::Config::builder()
            .timeout_connect(Some(std::time::Duration::from_secs(connect_timeout_secs)))
            .timeout_recv_body(Some(std::time::Duration::from_secs(60)))
            .build()
            .new_agent();

        match agent.get(&url).call() {
            Ok(response) => {
                let mut reader = response.into_body().into_reader();
                let mut file = match std::fs::File::create(&archive_path) {
                    Ok(f) => f,
                    Err(e) => {
                        warn!(error = %e, "failed to create genesis archive file");
                        continue;
                    }
                };
                let mut total = 0u64;
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            file.write_all(&buf[..n]).map_err(DownloadError::Io)?;
                            total += n as u64;
                        }
                        Err(e) => {
                            warn!(error = %e, "genesis download read error");
                            break;
                        }
                    }
                }
                drop(file);
                info!(bytes = total, "genesis.tar.bz2 downloaded");

                match extract_genesis_archive(&archive_path, output_dir) {
                    Ok(path) => {
                        info!(path = %path.display(), "genesis.bin extracted");
                        return Ok(path);
                    }
                    Err(e) => {
                        warn!(error = %e, "genesis archive extraction failed");
                        continue;
                    }
                }
            }
            Err(e) => {
                warn!(%url, error = %e, "genesis download failed, trying next peer");
            }
        }
    }

    Err(DownloadError::NoPeers)
}

/// Extract genesis.bin from a genesis.tar.bz2 archive using the system `tar` command.
fn extract_genesis_archive(
    archive_path: &Path,
    output_dir: &Path,
) -> Result<PathBuf, DownloadError> {
    let status = std::process::Command::new("tar")
        .args(["-xjf", &archive_path.to_string_lossy()])
        .current_dir(output_dir)
        .status()
        .map_err(DownloadError::Io)?;

    if !status.success() {
        return Err(DownloadError::Io(std::io::Error::other(format!(
            "tar extraction failed with status {status}"
        ))));
    }

    let genesis_path = output_dir.join("genesis.bin");
    if genesis_path.exists() {
        Ok(genesis_path)
    } else {
        Err(DownloadError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "genesis.bin not found after extraction",
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_peer() -> SnapshotPeerInfo {
        SnapshotPeerInfo {
            identity: [1u8; 32],
            rpc_addr: "127.0.0.1:8899".parse().unwrap(),
            full_snapshot: (1000, [0xAA; 32]),
            incremental_snapshot: Some((1000, 1500, [0xBB; 32])),
        }
    }

    #[test]
    fn build_full_url_format() {
        let peer = test_peer();
        let url = SnapshotDownloader::build_full_url(&peer);
        assert!(url.starts_with("http://127.0.0.1:8899/snapshot-1000-"));
        assert!(url.ends_with(".tar.zst"));
    }

    #[test]
    fn build_incremental_url_format() {
        let peer = test_peer();
        let url = SnapshotDownloader::build_incremental_url(&peer).unwrap();
        assert!(url.starts_with("http://127.0.0.1:8899/incremental-snapshot-1000-1500-"));
        assert!(url.ends_with(".tar.zst"));
    }

    #[test]
    fn build_incremental_url_none_when_no_incremental() {
        let peer = SnapshotPeerInfo {
            identity: [1u8; 32],
            rpc_addr: "127.0.0.1:8899".parse().unwrap(),
            full_snapshot: (1000, [0xAA; 32]),
            incremental_snapshot: None,
        };
        assert!(SnapshotDownloader::build_incremental_url(&peer).is_none());
    }

    #[test]
    fn download_config_defaults() {
        let config = DownloadConfig::default();
        assert_eq!(config.min_speed_bytes_per_sec, 10 * 1024 * 1024);
        assert_eq!(config.connect_timeout_secs, 30);
        assert_eq!(config.read_buffer_size, 256 * 1024);
    }

    #[test]
    fn error_display() {
        let err = DownloadError::NoPeers;
        assert_eq!(format!("{err}"), "no peers available");

        let err = DownloadError::TooSlow {
            bytes_per_sec: 1000,
            min_bytes_per_sec: 10_000_000,
        };
        let msg = format!("{err}");
        assert!(msg.contains("too slow"));
    }

    #[test]
    fn downloader_creation() {
        let config = DownloadConfig::default();
        let _downloader = SnapshotDownloader::new(config);
    }
}
