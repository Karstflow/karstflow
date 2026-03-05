//! Direct vote delivery to leaders via UDP.
//!
//! Complements the gossip-based VoteBroadcastAdapter with low-latency
//! direct delivery of vote transactions to the current and upcoming
//! leaders' TPU_VOTE sockets. This mirrors Firedancer's txsend tile
//! behavior where votes are sent directly for fast consensus participation.

use karstflow_config::ValidatorIdentity;
use karstflow_consensus::{BankForks, Tower};
use karstflow_constants::gossip::SOCKET_TPU_VOTE;
use karstflow_constants::vote_sender::{POLL_INTERVAL_MS, TARGET_LEADER_COUNT};
use karstflow_net::ClusterInfo;
use karstflow_types::Pubkey;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, RwLock};
use tracing::{debug, trace};

/// Result of building the vote sender service.
pub struct VoteSenderBundle {
    pub service: Box<dyn karstflow_runtime::Service>,
}

/// Direct vote sender service.
///
/// Polls the Tower for new votes and sends them as serialized
/// transactions via UDP to the TPU_VOTE sockets of upcoming leaders.
struct VoteSenderService {
    tower: Arc<RwLock<Tower>>,
    bank_forks: Arc<RwLock<BankForks>>,
    cluster_info: Arc<ClusterInfo>,
    identity: ValidatorIdentity,
    vote_account: [u8; 32],
    udp_socket: UdpSocket,
    last_sent_slot: Option<u64>,
}

impl VoteSenderService {
    /// Resolve the TPU_VOTE socket address for a given validator pubkey
    /// by looking up the CRDS contact info in gossip.
    fn resolve_tpu_vote_addr(&self, leader: &Pubkey) -> Option<SocketAddr> {
        self.cluster_info
            .lookup_socket(leader.as_bytes(), SOCKET_TPU_VOTE)
    }

    /// Resolve the next N unique leaders starting from the given slot.
    fn resolve_upcoming_leaders(&self, slot: u64) -> Vec<(Pubkey, SocketAddr)> {
        let forks = match self.bank_forks.read() {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };
        let bank = forks.working_bank();
        let schedule = bank.leader_schedule();
        let epoch_schedule = bank.epoch_schedule();

        let mut result = Vec::with_capacity(TARGET_LEADER_COUNT);
        let mut seen = std::collections::HashSet::new();

        // Scan forward from current slot to find unique leaders
        for offset in 0..256u64 {
            if result.len() >= TARGET_LEADER_COUNT {
                break;
            }
            let check_slot = slot.saturating_add(offset);
            if let Some(leader) = schedule.leader_for_absolute_slot(check_slot, epoch_schedule) {
                // Skip ourselves — no need to send to self
                if leader.as_bytes() == self.identity.pubkey() {
                    continue;
                }
                if seen.insert(leader) {
                    if let Some(addr) = self.resolve_tpu_vote_addr(&leader) {
                        result.push((leader, addr));
                    }
                }
            }
        }
        result
    }

    /// Send the vote transaction bytes to the given addresses via UDP.
    fn send_vote_to_leaders(&self, tx_bytes: &[u8], targets: &[(Pubkey, SocketAddr)]) {
        for (leader, addr) in targets {
            match self.udp_socket.send_to(tx_bytes, addr) {
                Ok(_) => {
                    trace!(leader = %leader, addr = %addr, "sent vote to leader TPU_VOTE");
                }
                Err(e) => {
                    debug!(leader = %leader, addr = %addr, error = %e, "failed to send vote");
                }
            }
        }
    }
}

impl karstflow_runtime::Service for VoteSenderService {
    fn name(&self) -> &'static str {
        "vote-sender"
    }

    fn tick_interval(&self) -> std::time::Duration {
        std::time::Duration::from_millis(POLL_INTERVAL_MS)
    }

    fn on_start(
        &mut self,
        _context: &karstflow_runtime::ServiceContext,
    ) -> karstflow_runtime::RuntimeResult<()> {
        Ok(())
    }

    fn tick(
        &mut self,
        _context: &karstflow_runtime::ServiceContext,
    ) -> karstflow_runtime::RuntimeResult<()> {
        let tower = self.tower.read().map_err(|_| {
            karstflow_runtime::RuntimeError::service_failure("vote-sender", "tower lock poisoned")
        })?;

        let current_vote_slot = tower.last_vote_slot();

        // Only send if there's a new vote we haven't sent yet.
        if current_vote_slot.is_none() || current_vote_slot == self.last_sent_slot {
            return Ok(());
        }

        let vote_slot = current_vote_slot.expect("checked is_none above");

        // Get bank hash for the voted slot.
        let bank_hash = {
            let forks = self.bank_forks.read().map_err(|_| {
                karstflow_runtime::RuntimeError::service_failure(
                    "vote-sender",
                    "bank_forks lock poisoned",
                )
            })?;
            forks.get(vote_slot).map(|b| b.hash())
        };
        let bank_hash = bank_hash.unwrap_or([0u8; 32]);

        // Build vote transaction
        let votes = tower.votes();
        let root = tower.root();
        let tx_bytes = super::bootstrap::build_vote_transaction(
            self.identity.secret_key(),
            self.identity.pubkey(),
            &self.vote_account,
            votes,
            root,
            &bank_hash,
        );

        // Must drop tower lock before resolving leaders (which acquires bank_forks + cluster_info)
        drop(tower);

        // Resolve upcoming leaders and send
        let targets = self.resolve_upcoming_leaders(vote_slot);
        if !targets.is_empty() {
            self.send_vote_to_leaders(&tx_bytes, &targets);
            debug!(
                vote_slot = vote_slot,
                target_count = targets.len(),
                "direct vote sent to leaders"
            );
        }

        self.last_sent_slot = Some(vote_slot);
        Ok(())
    }

    fn on_stop(
        &mut self,
        _context: &karstflow_runtime::ServiceContext,
    ) -> karstflow_runtime::RuntimeResult<()> {
        Ok(())
    }
}

/// Build the vote sender service for direct leader delivery.
///
/// Creates a UDP socket and a poll-driven service that monitors the Tower
/// for new vote decisions. When a new vote is detected, the service builds
/// a TowerSync vote transaction, resolves the TPU_VOTE addresses of the
/// next N leaders from gossip contact info, and sends the transaction
/// directly via UDP.
pub fn build_vote_sender_service(
    identity: &ValidatorIdentity,
    tower: Arc<RwLock<Tower>>,
    bank_forks: Arc<RwLock<BankForks>>,
    cluster_info: Arc<ClusterInfo>,
) -> std::io::Result<VoteSenderBundle> {
    let vote_account = *identity.pubkey();

    // Bind to an ephemeral UDP port for sending votes
    let udp_socket = UdpSocket::bind("0.0.0.0:0")?;
    udp_socket.set_nonblocking(true)?;

    let service = VoteSenderService {
        tower,
        bank_forks,
        cluster_info,
        identity: identity.clone(),
        vote_account,
        udp_socket,
        last_sent_slot: None,
    };

    Ok(VoteSenderBundle {
        service: Box::new(service),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use karstflow_consensus::TowerVote;
    use karstflow_runtime::Service;
    use std::net::SocketAddr;

    fn test_bank_forks() -> Arc<RwLock<BankForks>> {
        let db = Arc::new(karstflow_storage::AccountDatabase::new());
        let epoch_schedule = Arc::new(karstflow_consensus::EpochSchedule::default());
        let validator = Pubkey::new([0u8; 32]);
        let ls =
            Arc::new(karstflow_consensus::LeaderSchedule::new(0, &[(validator, 1000)]).unwrap());
        let bank = karstflow_consensus::Bank::new_genesis(db, epoch_schedule, ls);
        Arc::new(RwLock::new(BankForks::new(bank)))
    }

    fn test_cluster_info(pubkey: [u8; 32]) -> Arc<ClusterInfo> {
        let node_id = karstflow_net::NodeId::new(pubkey);
        let addr: SocketAddr = "127.0.0.1:8000".parse().unwrap();
        let contact_info = karstflow_net::ContactInfo::new(node_id, addr, addr, addr, addr, 0);
        Arc::new(ClusterInfo::new(
            node_id,
            contact_info,
            std::time::Duration::from_secs(30),
            100,
        ))
    }

    #[test]
    fn vote_sender_bundle_builds_successfully() {
        let (secret_key, pubkey) = karstflow_crypto::generate_keypair();
        let identity = ValidatorIdentity::new(secret_key, pubkey);
        let tower = Arc::new(RwLock::new(Tower::new()));
        let bundle = build_vote_sender_service(
            &identity,
            tower,
            test_bank_forks(),
            test_cluster_info(pubkey),
        );
        assert!(bundle.is_ok());
        assert_eq!(bundle.unwrap().service.name(), "vote-sender");
    }

    #[test]
    fn vote_transaction_format_roundtrip() {
        let (secret_key, pubkey) = karstflow_crypto::generate_keypair();
        let votes = vec![
            TowerVote {
                slot: 100,
                confirmation_count: 1,
            },
            TowerVote {
                slot: 101,
                confirmation_count: 2,
            },
        ];
        let tx_bytes = super::super::bootstrap::build_vote_transaction(
            &secret_key,
            &pubkey,
            &pubkey,
            &votes,
            Some(50),
            &[0xBB; 32],
        );
        assert!(tx_bytes.len() > 64 + 32);
        assert_eq!(tx_bytes[0], 1); // 1 signature
        let msg = &tx_bytes[65..];
        assert_eq!(msg[0], 1); // num_required_signatures
        assert_eq!(msg[1], 0); // num_readonly_signed
        assert_eq!(msg[2], 1); // num_readonly_unsigned
        assert_eq!(msg[3], 3); // 3 account keys
    }

    #[test]
    fn vote_sender_skips_when_no_new_vote() {
        let (secret_key, pubkey) = karstflow_crypto::generate_keypair();
        let identity = ValidatorIdentity::new(secret_key, pubkey);
        let tower = Arc::new(RwLock::new(Tower::new()));
        let udp = UdpSocket::bind("0.0.0.0:0").unwrap();
        udp.set_nonblocking(true).unwrap();
        let mut service = VoteSenderService {
            tower: tower.clone(),
            bank_forks: test_bank_forks(),
            cluster_info: test_cluster_info(pubkey),
            identity,
            vote_account: pubkey,
            udp_socket: udp,
            last_sent_slot: None,
        };
        let ctx = karstflow_runtime::ServiceContext::new(karstflow_runtime::ShutdownSwitch::new());
        assert!(service.tick(&ctx).is_ok());
        assert!(service.last_sent_slot.is_none());
    }

    #[test]
    fn vote_sender_detects_new_vote() {
        let (secret_key, pubkey) = karstflow_crypto::generate_keypair();
        let identity = ValidatorIdentity::new(secret_key, pubkey);
        let tower = Arc::new(RwLock::new(Tower::new()));
        let udp = UdpSocket::bind("0.0.0.0:0").unwrap();
        udp.set_nonblocking(true).unwrap();
        let mut service = VoteSenderService {
            tower: tower.clone(),
            bank_forks: test_bank_forks(),
            cluster_info: test_cluster_info(pubkey),
            identity,
            vote_account: pubkey,
            udp_socket: udp,
            last_sent_slot: None,
        };
        tower.write().unwrap().push_vote(100);
        let ctx = karstflow_runtime::ServiceContext::new(karstflow_runtime::ShutdownSwitch::new());
        assert!(service.tick(&ctx).is_ok());
        assert_eq!(service.last_sent_slot, Some(100));
    }

    #[test]
    fn vote_sender_skips_duplicate_vote() {
        let (secret_key, pubkey) = karstflow_crypto::generate_keypair();
        let identity = ValidatorIdentity::new(secret_key, pubkey);
        let tower = Arc::new(RwLock::new(Tower::new()));
        let udp = UdpSocket::bind("0.0.0.0:0").unwrap();
        udp.set_nonblocking(true).unwrap();
        let mut service = VoteSenderService {
            tower: tower.clone(),
            bank_forks: test_bank_forks(),
            cluster_info: test_cluster_info(pubkey),
            identity,
            vote_account: pubkey,
            udp_socket: udp,
            last_sent_slot: None,
        };
        tower.write().unwrap().push_vote(100);
        let ctx = karstflow_runtime::ServiceContext::new(karstflow_runtime::ShutdownSwitch::new());
        service.tick(&ctx).unwrap();
        assert_eq!(service.last_sent_slot, Some(100));
        // Second tick with same vote — should be skipped
        service.tick(&ctx).unwrap();
        assert_eq!(service.last_sent_slot, Some(100));
    }
}
