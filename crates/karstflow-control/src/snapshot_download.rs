//! Snapshot download orchestrator.
//!
//! Coordinates the full snapshot bootstrap flow:
//! 1. Wait for gossip to accumulate SnapshotHashes peers
//! 2. Select best peer by slot recency
//! 3. Download snapshot archive over HTTP
//! 4. Fall back to next peer on failure
//!
//! Designed to run as a blocking operation in a dedicated thread
//! during node startup.

use crate::{ControlPlaneError, Result};
use karstflow_net::gossip::crds::CrdsTable;
use karstflow_net::snapshot_download::{
    DownloadConfig, DownloadError, SnapshotDownloader, SnapshotPeerInfo, SnapshotPeerSelector,
};
use parking_lot::RwLock;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// Configuration for snapshot network download.
#[derive(Debug, Clone)]
pub struct SnapshotDownloadConfig {
    /// How long to wait for gossip to accumulate snapshot peers.
    /// Default: 60 seconds.
    pub gossip_timeout: Duration,

    /// How often to poll gossip for new peers during the wait period.
    /// Default: 2 seconds.
    pub gossip_poll_interval: Duration,

    /// Minimum number of peers before starting download.
    /// Default: 1 (download as soon as any peer is found).
    pub min_peers: usize,

    /// Maximum number of download retries before giving up.
    /// Default: 5.
    pub max_retries: usize,

    /// Minimum full snapshot slot to accept.
    /// Default: None (accept any slot).
    pub min_slot: Option<u64>,

    /// HTTP download configuration.
    pub download: DownloadConfig,
}

impl Default for SnapshotDownloadConfig {
    fn default() -> Self {
        Self {
            gossip_timeout: Duration::from_secs(60),
            gossip_poll_interval: Duration::from_secs(2),
            min_peers: 1,
            max_retries: 5,
            min_slot: None,
            download: DownloadConfig::default(),
        }
    }
}

/// Result of a successful snapshot download.
#[derive(Debug)]
pub struct SnapshotDownloadResult {
    /// Path to the downloaded full snapshot archive.
    pub full_snapshot_path: PathBuf,
    /// Path to the downloaded incremental snapshot archive (if available).
    pub incremental_snapshot_path: Option<PathBuf>,
    /// Peer that served the snapshot.
    pub peer: SnapshotPeerInfo,
}

/// Download a snapshot from the network via gossip peer discovery.
///
/// This is a blocking function that should be called from a dedicated
/// thread during node startup. It:
/// 1. Polls the CRDS table for peers with SnapshotHashes
/// 2. Waits until enough peers are found or timeout
/// 3. Downloads from the best peer (highest slot)
/// 4. Retries with next peer on failure
///
/// Returns the path to the downloaded snapshot archive.
pub fn download_snapshot_from_network(
    crds: &Arc<RwLock<CrdsTable>>,
    output_dir: &Path,
    config: &SnapshotDownloadConfig,
) -> Result<SnapshotDownloadResult> {
    // Phase 1: Wait for gossip peers.
    info!(
        timeout_secs = config.gossip_timeout.as_secs(),
        min_peers = config.min_peers,
        "waiting for snapshot peers from gossip"
    );

    let start = Instant::now();
    let mut peers;

    loop {
        {
            let table = crds.read();
            peers = SnapshotPeerSelector::scan_crds(&table, config.min_slot);
        }

        if peers.len() >= config.min_peers {
            info!(
                peer_count = peers.len(),
                best_slot = peers.first().map(|p| p.full_snapshot.0).unwrap_or(0),
                "found snapshot peers"
            );
            break;
        }

        if start.elapsed() >= config.gossip_timeout {
            if peers.is_empty() {
                return Err(ControlPlaneError::Bootstrap {
                    message: format!(
                        "no snapshot peers found after {}s gossip timeout",
                        config.gossip_timeout.as_secs()
                    ),
                });
            }
            info!(
                peer_count = peers.len(),
                "gossip timeout reached, proceeding with available peers"
            );
            break;
        }

        std::thread::sleep(config.gossip_poll_interval);
    }

    // Phase 2: Download from best peer with retry.
    let downloader = SnapshotDownloader::new(config.download.clone());

    std::fs::create_dir_all(output_dir).map_err(|e| ControlPlaneError::Bootstrap {
        message: format!(
            "failed to create snapshot output dir {}: {e}",
            output_dir.display()
        ),
    })?;

    let mut tried: Vec<[u8; 32]> = Vec::new();
    let mut last_error: Option<DownloadError> = None;

    for attempt in 0..config.max_retries {
        // Pick the best peer we haven't tried yet.
        let peer = match peers.iter().find(|p| !tried.contains(&p.identity)) {
            Some(p) => p.clone(),
            None => {
                // Re-scan CRDS for new peers.
                let table = crds.read();
                peers = SnapshotPeerSelector::scan_crds(&table, config.min_slot);
                drop(table);

                match peers.iter().find(|p| !tried.contains(&p.identity)) {
                    Some(p) => p.clone(),
                    None => break,
                }
            }
        };

        info!(
            attempt = attempt + 1,
            max_retries = config.max_retries,
            peer = %peer.rpc_addr,
            slot = peer.full_snapshot.0,
            "attempting snapshot download"
        );

        tried.push(peer.identity);

        // Download full snapshot.
        match downloader.download_full(&peer, output_dir) {
            Ok(full_path) => {
                // Try incremental if available.
                let incr_path = match downloader.download_incremental(&peer, output_dir) {
                    Ok(path) => path,
                    Err(e) => {
                        warn!(error = %e, "incremental snapshot download failed, continuing with full only");
                        None
                    }
                };

                return Ok(SnapshotDownloadResult {
                    full_snapshot_path: full_path,
                    incremental_snapshot_path: incr_path,
                    peer,
                });
            }
            Err(e) => {
                warn!(
                    error = %e,
                    peer = %peer.rpc_addr,
                    "snapshot download failed, trying next peer"
                );
                last_error = Some(e);
            }
        }
    }

    Err(ControlPlaneError::Bootstrap {
        message: format!(
            "snapshot download failed after {} attempts: {}",
            config.max_retries,
            last_error.map_or("no peers available".to_string(), |e| e.to_string())
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use karstflow_constants::gossip;
    use karstflow_net::gossip::crds::{
        CrdsContactInfo, CrdsValue, CrdsValueData, EntryOrigin, SnapshotHashes,
    };

    fn make_test_crds() -> Arc<RwLock<CrdsTable>> {
        let mut table = CrdsTable::new();

        let pk = [1u8; 32];
        let ci = CrdsValue {
            origin: pk,
            wallclock_nanos: 1_000_000_000,
            signature: [0u8; 64],
            data: CrdsValueData::ContactInfo(CrdsContactInfo {
                pubkey: pk,
                sockets: {
                    let mut s: [Option<std::net::SocketAddr>; gossip::CONTACT_INFO_SOCKET_COUNT] =
                        Default::default();
                    s[gossip::SOCKET_RPC] = Some("127.0.0.1:8899".parse().unwrap());
                    s
                },
                ..Default::default()
            }),
        };
        table.insert(ci, 1000, 0, EntryOrigin::Push);

        let sh = CrdsValue {
            origin: pk,
            wallclock_nanos: 1_000_000_000,
            signature: [0u8; 64],
            data: CrdsValueData::LegacySnapshotHashes(SnapshotHashes {
                hashes: vec![(500, [0xBB; 32])],
            }),
        };
        table.insert(sh, 1000, 0, EntryOrigin::Push);

        Arc::new(RwLock::new(table))
    }

    #[test]
    fn peer_discovery_from_crds() {
        let crds = make_test_crds();
        let table = crds.read();
        let peers = SnapshotPeerSelector::scan_crds(&table, None);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].full_snapshot.0, 500);
    }

    #[test]
    fn download_config_defaults() {
        let config = SnapshotDownloadConfig::default();
        assert_eq!(config.gossip_timeout.as_secs(), 60);
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.min_peers, 1);
    }

    #[test]
    fn download_fails_with_no_peers() {
        let crds = Arc::new(RwLock::new(CrdsTable::new()));
        let dir = tempfile::tempdir().unwrap();
        let config = SnapshotDownloadConfig {
            gossip_timeout: Duration::from_millis(100),
            gossip_poll_interval: Duration::from_millis(50),
            ..Default::default()
        };

        let result = download_snapshot_from_network(&crds, dir.path(), &config);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("no snapshot peers"));
    }

    #[test]
    fn download_fails_with_unreachable_peer() {
        let crds = make_test_crds();
        let dir = tempfile::tempdir().unwrap();
        let config = SnapshotDownloadConfig {
            gossip_timeout: Duration::from_millis(100),
            gossip_poll_interval: Duration::from_millis(50),
            max_retries: 1,
            download: DownloadConfig {
                connect_timeout_secs: 1,
                ..Default::default()
            },
            ..Default::default()
        };

        let result = download_snapshot_from_network(&crds, dir.path(), &config);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("failed"));
    }
}
