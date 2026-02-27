use super::*;
use crate::gossip::cluster_info::{ClusterInfo, ContactInfo, NodeId};
use crate::gossip::wire::convert;
use crate::gossip::wire::{WireCrdsValue, WirePong, WireProtocol};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::broadcast;
use tokio::time::{interval, sleep};

use paradencer_constants::gossip as gossip_const;

/// Configuration for gossip service.
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
            push_fanout: gossip_const::PUSH_FANOUT,
            pull_fanout: gossip_const::PULL_FANOUT,
            push_interval: Duration::from_millis(gossip_const::PUSH_INTERVAL_MS),
            pull_interval: Duration::from_millis(gossip_const::PULL_INTERVAL_MS),
            prune_interval: Duration::from_millis(gossip_const::PRUNE_INTERVAL_MS),
            prune_timeout: Duration::from_secs(30),
            max_cluster_size: 5000,
        }
    }
}

/// Statistics for gossip service.
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
    pub prune_messages_received: Arc<AtomicU64>,
    pub nodes_discovered: Arc<AtomicU64>,
    pub nodes_pruned: Arc<AtomicU64>,
    pub bytes_sent: Arc<AtomicU64>,
    pub bytes_received: Arc<AtomicU64>,
    pub send_errors: Arc<AtomicU64>,
    pub receive_errors: Arc<AtomicU64>,
    pub pull_responses_budget_exhausted: Arc<AtomicU64>,
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
            prune_messages_received: Arc::new(AtomicU64::new(0)),
            nodes_discovered: Arc::new(AtomicU64::new(0)),
            nodes_pruned: Arc::new(AtomicU64::new(0)),
            bytes_sent: Arc::new(AtomicU64::new(0)),
            bytes_received: Arc::new(AtomicU64::new(0)),
            send_errors: Arc::new(AtomicU64::new(0)),
            receive_errors: Arc::new(AtomicU64::new(0)),
            pull_responses_budget_exhausted: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl Default for GossipServiceStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Maximum packet size for gossip messages.
const GOSSIP_MAX_PACKET_SIZE: usize = gossip_const::GOSSIP_MTU;

/// Token-bucket rate limiter for outbound pull response data.
///
/// Replenished every 100ms with `num_staked * 1024` bytes, capped at
/// 5x that amount. Only pull responses are rate-limited; push messages
/// are not.
#[derive(Debug)]
pub struct DataBudget {
    remaining: u64,
    last_replenish: Instant,
}

impl Default for DataBudget {
    fn default() -> Self {
        Self::new()
    }
}

impl DataBudget {
    pub fn new() -> Self {
        Self {
            remaining: 0,
            last_replenish: Instant::now(),
        }
    }

    /// Replenish the budget based on elapsed time and staked validator count.
    /// Returns the current remaining budget after replenishment.
    pub fn replenish(&mut self, num_staked: u64) -> u64 {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_replenish);

        if elapsed.as_nanos() >= gossip_const::BUDGET_REPLENISH_INTERVAL_NS as u128 {
            let staked = num_staked.max(gossip_const::BUDGET_MIN_STAKED);
            let increment = staked.saturating_mul(gossip_const::BUDGET_BYTES_PER_INTERVAL);
            let cap = gossip_const::BUDGET_MAX_MULTIPLE.saturating_mul(increment);
            self.remaining = self.remaining.saturating_add(increment).min(cap);
            self.last_replenish = now;
        }

        self.remaining
    }

    /// Debit bytes from the budget. Returns true if the full amount was
    /// available, false if the budget was exhausted (partial debit).
    pub fn debit(&mut self, bytes: u64) -> bool {
        if self.remaining >= bytes {
            self.remaining -= bytes;
            true
        } else {
            self.remaining = 0;
            false
        }
    }

    /// Current remaining budget in bytes.
    pub fn remaining(&self) -> u64 {
        self.remaining
    }
}

/// Thread-safe handle to the outbound pull response budget.
type SharedBudget = Arc<parking_lot::Mutex<DataBudget>>;

/// Gossip service for cluster communication.
///
/// Uses wire-compatible protocol encoding that matches the standard
/// gossip binary format for interoperability with all validators.
pub struct GossipService {
    cluster_info: Arc<ClusterInfo>,
    config: GossipConfig,
    stats: GossipServiceStats,
    socket: Arc<UdpSocket>,
    pull_budget: SharedBudget,
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
            pull_budget: Arc::new(parking_lot::Mutex::new(DataBudget::new())),
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

    /// Start the gossip service.
    pub async fn start(&mut self) -> GossipResult<()> {
        let (shutdown_tx, _shutdown_rx) = broadcast::channel(1);
        self.shutdown_tx = Some(shutdown_tx);

        // Spawn receive task
        let recv_cluster_info = Arc::clone(&self.cluster_info);
        let recv_stats = self.stats.clone();
        let recv_socket = Arc::clone(&self.socket);
        let recv_budget = Arc::clone(&self.pull_budget);
        tokio::spawn(async move {
            Self::receive_loop(recv_socket, recv_cluster_info, recv_stats, recv_budget).await;
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

        // Spawn prune/expire task
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

    /// Stop the gossip service.
    pub async fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }

    /// Receive loop for incoming gossip messages.
    async fn receive_loop(
        socket: Arc<UdpSocket>,
        cluster_info: Arc<ClusterInfo>,
        stats: GossipServiceStats,
        pull_budget: SharedBudget,
    ) {
        let mut buf = vec![0u8; GOSSIP_MAX_PACKET_SIZE];

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, src_addr)) => {
                    stats
                        .bytes_received
                        .fetch_add(len as u64, Ordering::Relaxed);

                    match WireProtocol::decode(&buf[..len]) {
                        Ok(message) => {
                            Self::handle_message(
                                message,
                                src_addr,
                                &cluster_info,
                                &stats,
                                &socket,
                                &pull_budget,
                            )
                            .await;
                        }
                        Err(_) => {
                            stats.receive_errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                Err(_) => {
                    stats.receive_errors.fetch_add(1, Ordering::Relaxed);
                    sleep(Duration::from_millis(10)).await;
                }
            }
        }
    }

    /// Handle incoming wire protocol message.
    async fn handle_message(
        message: WireProtocol,
        src_addr: SocketAddr,
        cluster_info: &Arc<ClusterInfo>,
        stats: &GossipServiceStats,
        socket: &Arc<UdpSocket>,
        pull_budget: &SharedBudget,
    ) {
        match message {
            WireProtocol::PushMessage(_sender, values) => {
                stats.push_messages_received.fetch_add(1, Ordering::Relaxed);
                let count = Self::insert_wire_values(cluster_info, &values);
                stats
                    .nodes_discovered
                    .fetch_add(count as u64, Ordering::Relaxed);
            }

            WireProtocol::PullRequest(wire_filter, caller_value) => {
                stats.pull_requests_received.fetch_add(1, Ordering::Relaxed);

                // Replenish and check pull response budget.
                // Use cluster size as proxy for staked count until stake
                // tracking is integrated.
                let num_staked = cluster_info.size() as u64;
                {
                    let mut budget = pull_budget.lock();
                    if budget.replenish(num_staked) == 0 {
                        stats
                            .pull_responses_budget_exhausted
                            .fetch_add(1, Ordering::Relaxed);
                        // Still insert the caller's contact info even when budget-limited.
                        Self::insert_wire_values(cluster_info, &[caller_value]);
                        return;
                    }
                }

                // Also insert the caller's self-value (contains their contact info)
                Self::insert_wire_values(cluster_info, &[caller_value]);

                // Convert wire filter to internal bloom filter
                let (bloom, mask) = convert::wire_filter_to_internal(&wire_filter);

                // Return all CRDS value types matching the filter, not just ContactInfo.
                let matching_values = cluster_info.filter_all_values_for_pull(
                    &bloom,
                    &mask,
                    gossip_const::MAX_VALUES_PER_MESSAGE,
                );

                // Convert internal values to wire format and sign them.
                let wire_values: Vec<WireCrdsValue> = matching_values
                    .iter()
                    .filter_map(|v| {
                        let mut wv = convert::internal_to_wire_value(v)?;
                        if let Some(key) = cluster_info.signing_key() {
                            wv.sign(key);
                        }
                        Some(wv)
                    })
                    .collect();

                let response = WireProtocol::PullResponse(cluster_info.node_id().0, wire_values);

                if let Ok(encoded) = response.encode() {
                    // Debit the pull response budget.
                    {
                        let mut budget = pull_budget.lock();
                        budget.debit(encoded.len() as u64);
                    }
                    let _ = socket.send_to(&encoded, src_addr).await;
                    stats.pull_responses_sent.fetch_add(1, Ordering::Relaxed);
                    stats
                        .bytes_sent
                        .fetch_add(encoded.len() as u64, Ordering::Relaxed);
                }
            }

            WireProtocol::PullResponse(_sender, values) => {
                stats
                    .pull_responses_received
                    .fetch_add(1, Ordering::Relaxed);
                let count = Self::insert_wire_values(cluster_info, &values);
                stats
                    .nodes_discovered
                    .fetch_add(count as u64, Ordering::Relaxed);
            }

            WireProtocol::PruneMessage(_sender, prune_data) => {
                stats
                    .prune_messages_received
                    .fetch_add(1, Ordering::Relaxed);
                // Verify prune data signature before processing.
                if prune_data.verify() {
                    // The prune message says: "I (pubkey) already receive
                    // values from these origins via another path, so stop
                    // forwarding them to me." We record this so that our
                    // push loop can filter accordingly.
                    cluster_info.record_prune(
                        prune_data.pubkey,
                        &prune_data.prunes,
                        prune_data.wallclock,
                    );
                    tracing::debug!(
                        sender = %bs58::encode(&prune_data.pubkey).into_string()[..8],
                        prune_count = prune_data.prunes.len(),
                        "processed prune message"
                    );
                }
            }

            WireProtocol::PingMessage(ping) => {
                if ping.verify() {
                    // Respond with a signed pong
                    if let Some(key) = cluster_info.signing_key() {
                        let pong = WirePong::from_ping(&ping, cluster_info.node_id().0, key);
                        let response = WireProtocol::PongMessage(pong);
                        if let Ok(encoded) = response.encode() {
                            let _ = socket.send_to(&encoded, src_addr).await;
                            stats
                                .bytes_sent
                                .fetch_add(encoded.len() as u64, Ordering::Relaxed);
                        }
                    }
                    // Update last seen for the sender
                    let sender_id = NodeId(ping.from);
                    cluster_info.update_last_seen(&sender_id);
                }
            }

            WireProtocol::PongMessage(pong) => {
                if pong.verify() {
                    stats.pongs_received.fetch_add(1, Ordering::Relaxed);
                    let sender_id = NodeId(pong.from);
                    cluster_info.update_last_seen(&sender_id);
                }
            }
        }
    }

    /// Insert wire CRDS values into the cluster info table.
    ///
    /// Verifies signatures and converts to internal types. Returns the
    /// count of newly inserted/updated entries.
    fn insert_wire_values(cluster_info: &Arc<ClusterInfo>, values: &[WireCrdsValue]) -> usize {
        let mut count = 0;
        for wv in values {
            // Verify the wire signature before accepting
            if !wv.verify() {
                // Accept unsigned values (zero signature) for backwards compatibility
                // with peers that don't yet sign their values.
                if wv.signature != [0u8; 64] {
                    continue;
                }
            }

            // Try to convert to ContactInfo (handles LegacyContactInfo variant)
            if let Some(ci) = convert::wire_value_to_contact_info(wv) {
                if cluster_info.insert(ci) {
                    count += 1;
                }
            } else if let Some(internal) = convert::wire_to_internal_value(wv) {
                // For non-ContactInfo types (NodeInstance, etc.), insert directly
                let outcome = cluster_info.insert_crds_value(internal, 0);
                if matches!(
                    outcome,
                    crate::gossip::crds::InsertOutcome::Inserted
                        | crate::gossip::crds::InsertOutcome::Updated
                ) {
                    count += 1;
                }
            }
        }
        count
    }

    /// Push gossip loop.
    ///
    /// Tracks a cursor into the CRDS table so each push cycle only sends
    /// values that were inserted or updated since the previous cycle,
    /// plus our own self-value (always included for freshness).
    ///
    /// Also runs a ContactInfo refresh timer that re-signs our own
    /// ContactInfo periodically (every ~7.5s) to maintain freshness
    /// across the cluster.
    async fn push_loop(
        socket: Arc<UdpSocket>,
        cluster_info: Arc<ClusterInfo>,
        stats: GossipServiceStats,
        config: GossipConfig,
        shutdown_rx: &mut broadcast::Receiver<()>,
    ) {
        let mut push_ticker = interval(config.push_interval);
        let mut refresh_ticker = interval(Duration::from_millis(
            gossip_const::CONTACT_INFO_REFRESH_INTERVAL_MS,
        ));
        let mut push_cursor: u64 = cluster_info.cursor();

        loop {
            tokio::select! {
                _ = push_ticker.tick() => {
                    push_cursor = Self::do_push_gossip(
                        &socket, &cluster_info, &stats, &config, push_cursor
                    ).await;
                }
                _ = refresh_ticker.tick() => {
                    // Refresh self ContactInfo wallclock to maintain freshness.
                    cluster_info.refresh_self_contact_info();
                }
                _ = shutdown_rx.recv() => {
                    break;
                }
            }
        }
    }

    /// Execute one push gossip cycle. Returns the new cursor position.
    async fn do_push_gossip(
        socket: &Arc<UdpSocket>,
        cluster_info: &Arc<ClusterInfo>,
        stats: &GossipServiceStats,
        config: &GossipConfig,
        push_cursor: u64,
    ) -> u64 {
        // Collect only new/updated values since our last push.
        let (new_values, new_cursor) = cluster_info.values_since_cursor(push_cursor);

        let signing_key = cluster_info.signing_key().copied();

        // Always include our own self-value for freshness.
        let mut wire_values = Vec::with_capacity(new_values.len() + 1);
        let mut self_wire = convert::contact_info_to_wire_value(&cluster_info.self_contact_info());
        if let Some(ref key) = signing_key {
            self_wire.sign(key);
        }
        wire_values.push(self_wire);

        // Convert new/updated CRDS values to wire format.
        for value in &new_values {
            if let Some(mut wv) = convert::internal_to_wire_value(value) {
                if let Some(ref key) = signing_key {
                    wv.sign(key);
                }
                wire_values.push(wv);
            }
        }

        let mut exclude = HashSet::new();
        exclude.insert(cluster_info.node_id());

        let targets = cluster_info.get_random_nodes(config.push_fanout, &exclude);

        if targets.is_empty() {
            return new_cursor;
        }

        let self_pubkey = cluster_info.node_id().0;
        let has_prune_entries = cluster_info.prune_entry_count() > 0;

        for target in &targets {
            // Apply per-target prune filtering: exclude values whose origin
            // is in the prune set for this destination.
            let filtered: Vec<&WireCrdsValue> = if has_prune_entries {
                wire_values
                    .iter()
                    .filter(|wv| {
                        let origin = wv.origin();
                        // Never prune our own self-value.
                        if *origin == self_pubkey {
                            return true;
                        }
                        !cluster_info.is_origin_pruned(&target.node_id.0, origin)
                    })
                    .collect()
            } else {
                wire_values.iter().collect()
            };

            if filtered.is_empty() {
                continue;
            }

            // Build a per-target push message with only non-pruned values.
            let values_for_target: Vec<WireCrdsValue> = filtered.into_iter().cloned().collect();
            let message = WireProtocol::PushMessage(self_pubkey, values_for_target);

            if let Ok(encoded) = message.encode() {
                match socket.send_to(&encoded, target.gossip_addr).await {
                    Ok(_) => {
                        stats.push_messages_sent.fetch_add(1, Ordering::Relaxed);
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

        new_cursor
    }

    /// Pull gossip loop.
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

        // Build wire CRDS filter from our bloom filter
        let (bloom, mask) = cluster_info.build_pull_filter();
        let wire_filter = convert::build_wire_crds_filter(&bloom, &mask);

        // Our own signed contact info as the self-value
        let self_info = cluster_info.self_contact_info();
        let mut self_wire = convert::contact_info_to_wire_value(&self_info);
        if let Some(key) = cluster_info.signing_key() {
            self_wire.sign(key);
        }

        let message = WireProtocol::PullRequest(wire_filter, self_wire);

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

    /// Prune/expire loop for removing stale entries from the CRDS table.
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
                    let expired = cluster_info.prune_stale_nodes();
                    stats.nodes_pruned.fetch_add(expired as u64, Ordering::Relaxed);

                    // Expire stale prune map entries.
                    let _prune_expired = cluster_info.expire_prune_entries();
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

        let config = GossipConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            ..GossipConfig::default()
        };

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

    // --- DataBudget tests ---

    #[test]
    fn budget_starts_at_zero() {
        let budget = DataBudget::new();
        assert_eq!(budget.remaining(), 0);
    }

    #[test]
    fn budget_replenish_adds_bytes() {
        let mut budget = DataBudget::new();
        // Force last_replenish far enough in the past to trigger replenishment.
        budget.last_replenish = Instant::now() - Duration::from_millis(200);

        let remaining = budget.replenish(10);
        // 10 staked * 1024 = 10240
        assert_eq!(remaining, 10_240);
        assert_eq!(budget.remaining(), 10_240);
    }

    #[test]
    fn budget_replenish_uses_minimum_staked() {
        let mut budget = DataBudget::new();
        budget.last_replenish = Instant::now() - Duration::from_millis(200);

        // 0 staked should use BUDGET_MIN_STAKED (2)
        let remaining = budget.replenish(0);
        assert_eq!(remaining, 2 * 1024);
    }

    #[test]
    fn budget_caps_at_max_multiple() {
        let mut budget = DataBudget::new();

        // Replenish many times to accumulate
        for _ in 0..20 {
            budget.last_replenish = Instant::now() - Duration::from_millis(200);
            budget.replenish(10);
        }

        // Cap: 5 * 10 * 1024 = 51200
        assert_eq!(budget.remaining(), 51_200);
    }

    #[test]
    fn budget_debit_subtracts() {
        let mut budget = DataBudget::new();
        budget.last_replenish = Instant::now() - Duration::from_millis(200);
        budget.replenish(10); // 10240

        assert!(budget.debit(5000));
        assert_eq!(budget.remaining(), 5240);
    }

    #[test]
    fn budget_debit_exhaustion() {
        let mut budget = DataBudget::new();
        budget.last_replenish = Instant::now() - Duration::from_millis(200);
        budget.replenish(2); // 2048

        assert!(!budget.debit(5000));
        assert_eq!(budget.remaining(), 0);
    }

    #[test]
    fn budget_no_replenish_before_interval() {
        let mut budget = DataBudget::new();
        // last_replenish is now, so no time has passed
        let remaining = budget.replenish(100);
        assert_eq!(remaining, 0);
    }
}
