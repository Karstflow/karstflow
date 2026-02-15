use super::*;
use crate::gossip::cluster_info::{ClusterInfo, ContactInfo, NodeId, CRDT_UPDATE_INTERVAL_MS};
use crate::gossip::protocol::{
    BloomFilter, GossipMessage, GossipPullRequest, GossipPullResponse, GossipPushMessage,
};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, mpsc};
use tokio::time::{interval, sleep};

const GOSSIP_PUSH_FANOUT: usize = 6;
const GOSSIP_PULL_FANOUT: usize = 3;
const GOSSIP_PUSH_INTERVAL_MS: u64 = 100;
const GOSSIP_PULL_INTERVAL_MS: u64 = 5000;
const GOSSIP_PRUNE_INTERVAL_MS: u64 = 10000;
const GOSSIP_MAX_PACKET_SIZE: usize = 1232;

/// Configuration for gossip service
#[derive(Debug, Clone)]
pub struct GossipConfig {
    pub bind_addr: SocketAddr,
    pub push_fanout: usize,
    pub pull_fanout: usize,
    pub push_interval: Duration,
    pub pull_interval: Duration,
    pub prune_interval: Duration,
    pub prune_timeout: Duration,
    pub max_cluster_size: usize,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:8001".parse().unwrap(),
            push_fanout: GOSSIP_PUSH_FANOUT,
            pull_fanout: GOSSIP_PULL_FANOUT,
            push_interval: Duration::from_millis(GOSSIP_PUSH_INTERVAL_MS),
            pull_interval: Duration::from_millis(GOSSIP_PULL_INTERVAL_MS),
            prune_interval: Duration::from_millis(GOSSIP_PRUNE_INTERVAL_MS),
            prune_timeout: Duration::from_secs(30),
            max_cluster_size: 5000,
        }
    }
}

/// Statistics for gossip service
#[derive(Debug, Clone)]
pub struct GossipServiceStats {
    pub push_messages_sent: Arc<AtomicU64>,
    pub push_messages_received: Arc<AtomicU64>,
    pub pull_requests_sent: Arc<AtomicU64>,
    pub pull_requests_received: Arc<AtomicU64>,
    pub pull_responses_sent: Arc<AtomicU64>,
    pub pull_responses_received: Arc<AtomicU64>,
    pub pings_sent: Arc<AtomicU64>,
    pub pongs_received: Arc<AtomicU64>,
    pub nodes_discovered: Arc<AtomicU64>,
    pub nodes_pruned: Arc<AtomicU64>,
    pub bytes_sent: Arc<AtomicU64>,
    pub bytes_received: Arc<AtomicU64>,
    pub send_errors: Arc<AtomicU64>,
    pub receive_errors: Arc<AtomicU64>,
}

impl GossipServiceStats {
    pub fn new() -> Self {
        Self {
            push_messages_sent: Arc::new(AtomicU64::new(0)),
            push_messages_received: Arc::new(AtomicU64::new(0)),
            pull_requests_sent: Arc::new(AtomicU64::new(0)),
            pull_requests_received: Arc::new(AtomicU64::new(0)),
            pull_responses_sent: Arc::new(AtomicU64::new(0)),
            pull_responses_received: Arc::new(AtomicU64::new(0)),
            pings_sent: Arc::new(AtomicU64::new(0)),
            pongs_received: Arc::new(AtomicU64::new(0)),
            nodes_discovered: Arc::new(AtomicU64::new(0)),
            nodes_pruned: Arc::new(AtomicU64::new(0)),
            bytes_sent: Arc::new(AtomicU64::new(0)),
            bytes_received: Arc::new(AtomicU64::new(0)),
            send_errors: Arc::new(AtomicU64::new(0)),
            receive_errors: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl Default for GossipServiceStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Gossip service for cluster communication
pub struct GossipService {
    cluster_info: Arc<ClusterInfo>,
    config: GossipConfig,
    stats: GossipServiceStats,
    socket: Arc<UdpSocket>,
    shutdown_tx: Option<broadcast::Sender<()>>,
}

impl GossipService {
    pub async fn new(
        node_id: NodeId,
        contact_info: ContactInfo,
        config: GossipConfig,
    ) -> GossipResult<Self> {
        let socket = UdpSocket::bind(config.bind_addr).await.map_err(|e| {
            IngressError::QuicEndpointBind {
                detail: format!("failed to bind gossip socket: {}", e),
            }
        })?;

        let cluster_info = Arc::new(ClusterInfo::new(
            node_id,
            contact_info,
            config.prune_timeout,
            config.max_cluster_size,
        ));

        Ok(Self {
            cluster_info,
            config,
            stats: GossipServiceStats::new(),
            socket: Arc::new(socket),
            shutdown_tx: None,
        })
    }

    pub fn cluster_info(&self) -> Arc<ClusterInfo> {
        Arc::clone(&self.cluster_info)
    }

    pub fn stats(&self) -> &GossipServiceStats {
        &self.stats
    }

    pub fn local_addr(&self) -> GossipResult<SocketAddr> {
        self.socket.local_addr().map_err(|e| IngressError::QuicIo {
            detail: format!("failed to get local addr: {}", e),
        })
    }

    /// Start the gossip service
    pub async fn start(&mut self) -> GossipResult<()> {
        let (shutdown_tx, _shutdown_rx) = broadcast::channel(1);
        self.shutdown_tx = Some(shutdown_tx);

        // Spawn receive task
        let recv_cluster_info = Arc::clone(&self.cluster_info);
        let recv_stats = self.stats.clone();
        let recv_socket = Arc::clone(&self.socket);
        tokio::spawn(async move {
            Self::receive_loop(recv_socket, recv_cluster_info, recv_stats).await;
        });

        // Spawn push gossip task
        let push_cluster_info = Arc::clone(&self.cluster_info);
        let push_stats = self.stats.clone();
        let push_socket = Arc::clone(&self.socket);
        let push_config = self.config.clone();
        let mut push_shutdown_rx = self.shutdown_tx.as_ref().unwrap().subscribe();
        tokio::spawn(async move {
            Self::push_loop(
                push_socket,
                push_cluster_info,
                push_stats,
                push_config,
                &mut push_shutdown_rx,
            )
            .await;
        });

        // Spawn pull gossip task
        let pull_cluster_info = Arc::clone(&self.cluster_info);
        let pull_stats = self.stats.clone();
        let pull_socket = Arc::clone(&self.socket);
        let pull_config = self.config.clone();
        let mut pull_shutdown_rx = self.shutdown_tx.as_ref().unwrap().subscribe();
        tokio::spawn(async move {
            Self::pull_loop(
                pull_socket,
                pull_cluster_info,
                pull_stats,
                pull_config,
                &mut pull_shutdown_rx,
            )
            .await;
        });

        // Spawn prune task
        let prune_cluster_info = Arc::clone(&self.cluster_info);
        let prune_stats = self.stats.clone();
        let prune_config = self.config.clone();
        let mut prune_shutdown_rx = self.shutdown_tx.as_ref().unwrap().subscribe();
        tokio::spawn(async move {
            Self::prune_loop(
                prune_cluster_info,
                prune_stats,
                prune_config,
                &mut prune_shutdown_rx,
            )
            .await;
        });

        Ok(())
    }

    /// Stop the gossip service
    pub async fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }

    /// Receive loop for incoming gossip messages
    async fn receive_loop(
        socket: Arc<UdpSocket>,
        cluster_info: Arc<ClusterInfo>,
        stats: GossipServiceStats,
    ) {
        let mut buf = vec![0u8; GOSSIP_MAX_PACKET_SIZE];

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, src_addr)) => {
                    stats
                        .bytes_received
                        .fetch_add(len as u64, Ordering::Relaxed);

                    let data = bytes::Bytes::copy_from_slice(&buf[..len]);
                    if let Ok(message) = GossipMessage::decode(data) {
                        Self::handle_message(message, src_addr, &cluster_info, &stats, &socket)
                            .await;
                    } else {
                        stats.receive_errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(_) => {
                    stats.receive_errors.fetch_add(1, Ordering::Relaxed);
                    sleep(Duration::from_millis(10)).await;
                }
            }
        }
    }

    /// Handle incoming gossip message
    async fn handle_message(
        message: GossipMessage,
        src_addr: SocketAddr,
        cluster_info: &Arc<ClusterInfo>,
        stats: &GossipServiceStats,
        socket: &Arc<UdpSocket>,
    ) {
        match message {
            GossipMessage::Push(push_msg) => {
                stats.push_messages_received.fetch_add(1, Ordering::Relaxed);
                let count = cluster_info.insert_batch(push_msg.contact_infos);
                stats
                    .nodes_discovered
                    .fetch_add(count as u64, Ordering::Relaxed);
                cluster_info.update_last_seen(&push_msg.sender);
            }
            GossipMessage::Pull(pull_req) => {
                stats.pull_requests_received.fetch_add(1, Ordering::Relaxed);

                let contact_infos: Vec<_> = cluster_info
                    .get_all()
                    .into_iter()
                    .filter(|info| !pull_req.filter.contains(&info.node_id))
                    .collect();

                let response = GossipMessage::PullResponse(GossipPullResponse::new(
                    cluster_info.node_id(),
                    contact_infos,
                ));

                if let Ok(encoded) = response.encode() {
                    let _ = socket.send_to(&encoded, src_addr).await;
                    stats.pull_responses_sent.fetch_add(1, Ordering::Relaxed);
                    stats
                        .bytes_sent
                        .fetch_add(encoded.len() as u64, Ordering::Relaxed);
                }
            }
            GossipMessage::PullResponse(pull_resp) => {
                stats
                    .pull_responses_received
                    .fetch_add(1, Ordering::Relaxed);
                let count = cluster_info.insert_batch(pull_resp.contact_infos);
                stats
                    .nodes_discovered
                    .fetch_add(count as u64, Ordering::Relaxed);
                cluster_info.update_last_seen(&pull_resp.sender);
            }
            GossipMessage::Ping { sender, nonce } => {
                let pong = GossipMessage::Pong {
                    sender: cluster_info.node_id(),
                    nonce,
                };
                if let Ok(encoded) = pong.encode() {
                    let _ = socket.send_to(&encoded, src_addr).await;
                    stats
                        .bytes_sent
                        .fetch_add(encoded.len() as u64, Ordering::Relaxed);
                }
                cluster_info.update_last_seen(&sender);
            }
            GossipMessage::Pong { sender, .. } => {
                stats.pongs_received.fetch_add(1, Ordering::Relaxed);
                cluster_info.update_last_seen(&sender);
            }
        }
    }

    /// Push gossip loop
    async fn push_loop(
        socket: Arc<UdpSocket>,
        cluster_info: Arc<ClusterInfo>,
        stats: GossipServiceStats,
        config: GossipConfig,
        shutdown_rx: &mut broadcast::Receiver<()>,
    ) {
        let mut ticker = interval(config.push_interval);

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    Self::do_push_gossip(&socket, &cluster_info, &stats, &config).await;
                }
                _ = shutdown_rx.recv() => {
                    break;
                }
            }
        }
    }

    async fn do_push_gossip(
        socket: &Arc<UdpSocket>,
        cluster_info: &Arc<ClusterInfo>,
        stats: &GossipServiceStats,
        config: &GossipConfig,
    ) {
        let self_info = cluster_info.self_contact_info();
        let all_infos = cluster_info.get_all();

        let mut contact_infos = Vec::with_capacity(all_infos.len() + 1);
        contact_infos.push(self_info.clone());
        contact_infos.extend(all_infos);

        let mut exclude = HashSet::new();
        exclude.insert(cluster_info.node_id());

        let targets = cluster_info.get_random_nodes(config.push_fanout, &exclude);

        if targets.is_empty() {
            return;
        }

        let message = GossipMessage::Push(GossipPushMessage::new(
            cluster_info.node_id(),
            contact_infos,
        ));

        if let Ok(encoded) = message.encode() {
            for target in targets {
                match socket.send_to(&encoded, target.gossip_addr).await {
                    Ok(_) => {
                        stats.push_messages_sent.fetch_add(1, Ordering::Relaxed);
                        stats
                            .bytes_sent
                            .fetch_add(encoded.len() as u64, Ordering::Relaxed);
                        cluster_info.record_push_success(&target.node_id);
                    }
                    Err(_) => {
                        stats.send_errors.fetch_add(1, Ordering::Relaxed);
                        cluster_info.record_push_failure(&target.node_id);
                    }
                }
            }
        }
    }

    /// Pull gossip loop
    async fn pull_loop(
        socket: Arc<UdpSocket>,
        cluster_info: Arc<ClusterInfo>,
        stats: GossipServiceStats,
        config: GossipConfig,
        shutdown_rx: &mut broadcast::Receiver<()>,
    ) {
        let mut ticker = interval(config.pull_interval);

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    Self::do_pull_gossip(&socket, &cluster_info, &stats, &config).await;
                }
                _ = shutdown_rx.recv() => {
                    break;
                }
            }
        }
    }

    async fn do_pull_gossip(
        socket: &Arc<UdpSocket>,
        cluster_info: &Arc<ClusterInfo>,
        stats: &GossipServiceStats,
        config: &GossipConfig,
    ) {
        let mut exclude = HashSet::new();
        exclude.insert(cluster_info.node_id());

        let targets = cluster_info.get_random_nodes(config.pull_fanout, &exclude);

        if targets.is_empty() {
            return;
        }

        let mut filter = BloomFilter::new(config.max_cluster_size, 0.01);
        for info in cluster_info.get_all() {
            filter.insert(&info.node_id);
        }

        let message = GossipMessage::Pull(GossipPullRequest::new(cluster_info.node_id(), filter));

        if let Ok(encoded) = message.encode() {
            for target in targets {
                match socket.send_to(&encoded, target.gossip_addr).await {
                    Ok(_) => {
                        stats.pull_requests_sent.fetch_add(1, Ordering::Relaxed);
                        stats
                            .bytes_sent
                            .fetch_add(encoded.len() as u64, Ordering::Relaxed);
                    }
                    Err(_) => {
                        stats.send_errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
    }

    /// Prune loop for removing stale nodes
    async fn prune_loop(
        cluster_info: Arc<ClusterInfo>,
        stats: GossipServiceStats,
        config: GossipConfig,
        shutdown_rx: &mut broadcast::Receiver<()>,
    ) {
        let mut ticker = interval(config.prune_interval);

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let pruned = cluster_info.prune_stale_nodes();
                    stats.nodes_pruned.fetch_add(pruned as u64, Ordering::Relaxed);
                }
                _ = shutdown_rx.recv() => {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn create_test_contact_info(node_id: NodeId, port: u16) -> ContactInfo {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
        ContactInfo::new(node_id, addr, addr, addr, addr, 1)
    }

    #[tokio::test]
    async fn test_gossip_service_creation() {
        let node_id = NodeId::random();
        let contact_info = create_test_contact_info(node_id, 8001);

        let mut config = GossipConfig::default();
        config.bind_addr = "127.0.0.1:0".parse().unwrap();

        let service = GossipService::new(node_id, contact_info, config).await;
        assert!(service.is_ok());
    }

    #[tokio::test]
    async fn test_gossip_service_stats() {
        let stats = GossipServiceStats::new();
        stats.push_messages_sent.fetch_add(5, Ordering::Relaxed);
        stats.push_messages_received.fetch_add(3, Ordering::Relaxed);

        assert_eq!(stats.push_messages_sent.load(Ordering::Relaxed), 5);
        assert_eq!(stats.push_messages_received.load(Ordering::Relaxed), 3);
    }
}
