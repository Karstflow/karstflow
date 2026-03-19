//! Wait-for-supermajority Phase 2: gossip-based online stake tracking.
//!
//! After loading a snapshot and validating the bank hash (Phase 1), this
//! module blocks the bootstrap thread until 80% of activated stake is
//! observed online via gossip ContactInfo entries.
//!
//! The algorithm matches Agave's `get_stake_percent_in_gossip()`:
//! 1. Iterate all vote accounts from the snapshot bank
//! 2. For each, check if the validator's node identity appears in gossip
//! 3. Count our own identity as online
//! 4. Exclude peers with wrong shred version
//! 5. Wait until online_stake / total_stake >= 80%

use crate::{ControlPlaneError, Result};
use karstflow_consensus::VoteAccountCache;
use karstflow_net::{ClusterInfo, ContactInfo};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// Threshold: 80% of activated stake must be online.
const SUPERMAJORITY_THRESHOLD_PERCENT: u64 = 80;

/// Configuration for wait-for-supermajority Phase 2.
#[derive(Debug, Clone)]
pub struct WaitForSupermajorityConfig {
    /// How long to wait before giving up. Default: no timeout (wait forever).
    pub timeout: Option<Duration>,

    /// How often to poll gossip for peer updates.
    /// Default: 1 second.
    pub poll_interval: Duration,

    /// Log progress every N poll iterations.
    /// Default: 10.
    pub log_interval: usize,
}

impl Default for WaitForSupermajorityConfig {
    fn default() -> Self {
        Self {
            timeout: None,
            poll_interval: Duration::from_secs(1),
            log_interval: 10,
        }
    }
}

/// Result of the online stake calculation.
#[derive(Debug, Clone)]
pub struct StakeStatus {
    /// Total activated stake across all vote accounts.
    pub total_stake: u64,
    /// Stake from validators visible in gossip (matching shred version).
    pub online_stake: u64,
    /// Stake from validators in gossip with wrong shred version.
    pub wrong_shred_stake: u64,
    /// Stake from validators not seen in gossip.
    pub offline_stake: u64,
    /// Percentage of online stake (0-100).
    pub online_percent: u64,
}

/// Calculate online stake from gossip peers and vote accounts.
///
/// For each vote account, checks if the validator's node identity
/// appears in the gossip peer list. Counts our own identity as online.
pub fn compute_stake_status(
    vote_cache: &VoteAccountCache,
    gossip_peers: &[ContactInfo],
    my_identity: &[u8; 32],
    my_shred_version: u16,
) -> StakeStatus {
    let total_stake = vote_cache.total_epoch_stake();
    if total_stake == 0 {
        return StakeStatus {
            total_stake: 0,
            online_stake: 0,
            wrong_shred_stake: 0,
            offline_stake: 0,
            online_percent: 0,
        };
    }

    // Build set of online node identities with their shred versions.
    let peer_set: HashSet<[u8; 32]> = gossip_peers.iter().map(|p| p.node_id.0).collect();
    let peer_shred_versions: std::collections::HashMap<[u8; 32], u16> = gossip_peers
        .iter()
        .map(|p| (p.node_id.0, p.shred_version))
        .collect();

    let mut online_stake: u64 = 0;
    let mut wrong_shred_stake: u64 = 0;
    let mut offline_stake: u64 = 0;

    for (_vote_key, entry) in vote_cache.iter() {
        let stake = entry.stake;
        if stake == 0 {
            continue;
        }

        let node_bytes = entry.node_pubkey.as_bytes();

        if node_bytes == my_identity {
            // We're online by definition.
            online_stake += stake;
        } else if peer_set.contains(node_bytes) {
            // Check shred version.
            let peer_shred = peer_shred_versions.get(node_bytes).copied().unwrap_or(0);
            if peer_shred == my_shred_version || my_shred_version == 0 {
                online_stake += stake;
            } else {
                wrong_shred_stake += stake;
            }
        } else {
            offline_stake += stake;
        }
    }

    let online_percent = (online_stake * 100) / total_stake;

    StakeStatus {
        total_stake,
        online_stake,
        wrong_shred_stake,
        offline_stake,
        online_percent,
    }
}

/// Block until 80% of activated stake is observed online via gossip.
///
/// This is Phase 2 of wait-for-supermajority. Call after Phase 1 (hash
/// validation) and after gossip service is started.
///
/// Returns the final stake status when the threshold is reached.
pub fn wait_for_supermajority_phase2(
    vote_cache: &VoteAccountCache,
    cluster_info: &Arc<ClusterInfo>,
    my_identity: &[u8; 32],
    my_shred_version: u16,
    config: &WaitForSupermajorityConfig,
) -> Result<StakeStatus> {
    info!(
        threshold_percent = SUPERMAJORITY_THRESHOLD_PERCENT,
        total_stake = vote_cache.total_epoch_stake(),
        "waiting for supermajority online stake"
    );

    let start = Instant::now();
    let mut iteration = 0usize;

    loop {
        let peers = cluster_info.get_all();
        let status = compute_stake_status(vote_cache, &peers, my_identity, my_shred_version);

        if status.online_percent >= SUPERMAJORITY_THRESHOLD_PERCENT {
            info!(
                online_percent = status.online_percent,
                online_stake = status.online_stake,
                total_stake = status.total_stake,
                peers = peers.len(),
                elapsed_secs = start.elapsed().as_secs(),
                "supermajority reached"
            );
            return Ok(status);
        }

        if iteration.is_multiple_of(config.log_interval) {
            info!(
                online_percent = status.online_percent,
                online_stake = status.online_stake,
                wrong_shred = status.wrong_shred_stake,
                offline = status.offline_stake,
                total_stake = status.total_stake,
                peers = peers.len(),
                "waiting for supermajority..."
            );
        }

        if let Some(timeout) = config.timeout {
            if start.elapsed() >= timeout {
                warn!(
                    online_percent = status.online_percent,
                    total_stake = status.total_stake,
                    elapsed_secs = start.elapsed().as_secs(),
                    "wait-for-supermajority timeout"
                );
                return Err(ControlPlaneError::Bootstrap {
                    message: format!(
                        "wait-for-supermajority timed out after {}s: only {}% online (need {}%)",
                        timeout.as_secs(),
                        status.online_percent,
                        SUPERMAJORITY_THRESHOLD_PERCENT,
                    ),
                });
            }
        }

        std::thread::sleep(config.poll_interval);
        iteration += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use karstflow_consensus::VoteAccountCache;
    use karstflow_types::Pubkey;

    fn make_cache(entries: &[([u8; 32], u64)]) -> VoteAccountCache {
        let mut cache = VoteAccountCache::new();
        for (i, (node_pk, stake)) in entries.iter().enumerate() {
            let vote_key = Pubkey::new([(i + 100) as u8; 32]);
            let node_pubkey = Pubkey::new(*node_pk);
            cache.update_from_vote_state(vote_key, node_pubkey, 10, 0, 0);
            cache.set_stake(&vote_key, *stake);
        }
        cache
    }

    fn make_contact(node_id: [u8; 32], shred_version: u16) -> ContactInfo {
        let addr = "127.0.0.1:8000".parse().unwrap();
        ContactInfo {
            node_id: karstflow_net::NodeId(node_id),
            gossip_addr: addr,
            tpu_addr: addr,
            tpu_quic_addr: addr,
            tvu_addr: addr,
            tvu_quic_addr: addr,
            repair_addr: addr,
            rpc_addr: None,
            version: 0,
            wallclock: 0,
            shred_version,
        }
    }

    #[test]
    fn empty_cache_returns_zero() {
        let cache = VoteAccountCache::new();
        let status = compute_stake_status(&cache, &[], &[0u8; 32], 0);
        assert_eq!(status.total_stake, 0);
        assert_eq!(status.online_percent, 0);
    }

    #[test]
    fn self_counted_as_online() {
        let my_id = [1u8; 32];
        let cache = make_cache(&[(my_id, 100)]);
        let status = compute_stake_status(&cache, &[], &my_id, 0);
        assert_eq!(status.online_stake, 100);
        assert_eq!(status.online_percent, 100);
    }

    #[test]
    fn peer_with_matching_shred_version_counted() {
        let my_id = [1u8; 32];
        let peer_id = [2u8; 32];
        let cache = make_cache(&[(my_id, 100), (peer_id, 100)]);
        let peers = vec![make_contact(peer_id, 42)];
        let status = compute_stake_status(&cache, &peers, &my_id, 42);
        assert_eq!(status.online_stake, 200);
        assert_eq!(status.online_percent, 100);
    }

    #[test]
    fn peer_with_wrong_shred_version_excluded() {
        let my_id = [1u8; 32];
        let peer_id = [2u8; 32];
        let cache = make_cache(&[(my_id, 100), (peer_id, 100)]);
        let peers = vec![make_contact(peer_id, 99)]; // wrong shred version
        let status = compute_stake_status(&cache, &peers, &my_id, 42);
        assert_eq!(status.online_stake, 100); // only self
        assert_eq!(status.wrong_shred_stake, 100);
        assert_eq!(status.online_percent, 50);
    }

    #[test]
    fn threshold_calculation() {
        let my_id = [1u8; 32];
        let peer_a = [2u8; 32];
        let peer_b = [3u8; 32];
        let peer_c = [4u8; 32];
        let peer_d = [5u8; 32];

        // 100 stake each, 5 validators total = 500
        let cache = make_cache(&[
            (my_id, 100),
            (peer_a, 100),
            (peer_b, 100),
            (peer_c, 100),
            (peer_d, 100),
        ]);

        // Only 3 peers online (self + 2) = 300/500 = 60%
        let peers = vec![make_contact(peer_a, 0), make_contact(peer_b, 0)];
        let status = compute_stake_status(&cache, &peers, &my_id, 0);
        assert_eq!(status.online_percent, 60);
        assert!(status.online_percent < SUPERMAJORITY_THRESHOLD_PERCENT);

        // 4 peers online (self + 3) = 400/500 = 80% — meets threshold
        let peers = vec![
            make_contact(peer_a, 0),
            make_contact(peer_b, 0),
            make_contact(peer_c, 0),
        ];
        let status = compute_stake_status(&cache, &peers, &my_id, 0);
        assert_eq!(status.online_percent, 80);
        assert!(status.online_percent >= SUPERMAJORITY_THRESHOLD_PERCENT);
    }

    #[test]
    fn offline_stake_tracked() {
        let my_id = [1u8; 32];
        let peer_id = [2u8; 32];
        let offline_id = [3u8; 32];
        let cache = make_cache(&[(my_id, 100), (peer_id, 200), (offline_id, 300)]);
        let peers = vec![make_contact(peer_id, 0)];
        let status = compute_stake_status(&cache, &peers, &my_id, 0);
        assert_eq!(status.online_stake, 300); // self + peer
        assert_eq!(status.offline_stake, 300); // offline
        assert_eq!(status.online_percent, 50);
    }

    #[test]
    fn wfs_timeout() {
        let cache = make_cache(&[([1u8; 32], 100), ([2u8; 32], 100)]);
        let addr: std::net::SocketAddr = "127.0.0.1:8000".parse().unwrap();
        let ci = ContactInfo {
            node_id: karstflow_net::NodeId([1u8; 32]),
            gossip_addr: addr,
            tpu_addr: addr,
            tpu_quic_addr: addr,
            tvu_addr: addr,
            tvu_quic_addr: addr,
            repair_addr: addr,
            rpc_addr: None,
            version: 0,
            wallclock: 0,
            shred_version: 0,
        };
        let cluster_info = Arc::new(ClusterInfo::new(
            karstflow_net::NodeId([1u8; 32]),
            ci,
            Duration::from_secs(30),
            100,
        ));
        let config = WaitForSupermajorityConfig {
            timeout: Some(Duration::from_millis(100)),
            poll_interval: Duration::from_millis(50),
            ..Default::default()
        };

        let result = wait_for_supermajority_phase2(&cache, &cluster_info, &[1u8; 32], 0, &config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("timed out"));
    }
}
