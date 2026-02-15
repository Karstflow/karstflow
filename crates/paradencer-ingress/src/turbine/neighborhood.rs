use crate::gossip::NodeId;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Network proximity score (lower is better)
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct ProximityScore(f64);

impl ProximityScore {
    pub fn new(score: f64) -> Self {
        Self(score)
    }

    pub fn score(&self) -> f64 {
        self.0
    }

    /// Infinite distance (unreachable)
    pub fn infinite() -> Self {
        Self(f64::INFINITY)
    }

    /// Zero distance (same node)
    pub fn zero() -> Self {
        Self(0.0)
    }
}

/// Network proximity information for a peer
#[derive(Debug, Clone)]
pub struct NetworkProximity {
    /// Node identifier
    pub node_id: NodeId,

    /// Network address
    pub addr: SocketAddr,

    /// Proximity score to this node
    pub proximity: ProximityScore,

    /// Last time proximity was measured
    pub last_measured: Instant,

    /// Average RTT in milliseconds
    pub avg_rtt_ms: Option<f64>,

    /// Packet loss rate (0.0 to 1.0)
    pub loss_rate: Option<f64>,
}

impl NetworkProximity {
    pub fn new(node_id: NodeId, addr: SocketAddr) -> Self {
        Self {
            node_id,
            addr,
            proximity: ProximityScore::infinite(),
            last_measured: Instant::now(),
            avg_rtt_ms: None,
            loss_rate: None,
        }
    }

    /// Update proximity based on RTT measurement
    pub fn update_rtt(&mut self, rtt_ms: f64) {
        self.avg_rtt_ms = Some(match self.avg_rtt_ms {
            Some(current) => current * 0.8 + rtt_ms * 0.2, // EWMA
            None => rtt_ms,
        });
        self.last_measured = Instant::now();
        self.recalculate_proximity();
    }

    /// Update packet loss rate
    pub fn update_loss_rate(&mut self, loss_rate: f64) {
        self.loss_rate = Some(loss_rate.clamp(0.0, 1.0));
        self.recalculate_proximity();
    }

    /// Recalculate proximity score from RTT and loss rate
    fn recalculate_proximity(&mut self) {
        let rtt_score = self.avg_rtt_ms.unwrap_or(1000.0);
        let loss_penalty = self.loss_rate.unwrap_or(0.0) * 10000.0;
        self.proximity = ProximityScore::new(rtt_score + loss_penalty);
    }

    /// Check if proximity measurement is stale
    pub fn is_stale(&self, max_age: Duration) -> bool {
        self.last_measured.elapsed() > max_age
    }
}

/// Neighborhood of peers sorted by network proximity
#[derive(Debug, Clone)]
pub struct Neighborhood {
    /// Peers in the neighborhood, sorted by proximity
    peers: Vec<NetworkProximity>,

    /// Maximum neighborhood size
    max_size: usize,

    /// Proximity measurement timeout
    measurement_timeout: Duration,
}

impl Neighborhood {
    pub fn new(max_size: usize, measurement_timeout: Duration) -> Self {
        Self {
            peers: Vec::with_capacity(max_size),
            max_size,
            measurement_timeout,
        }
    }

    /// Add or update a peer in the neighborhood
    pub fn upsert_peer(&mut self, mut proximity: NetworkProximity) {
        // Remove existing entry if present
        self.peers.retain(|p| p.node_id != proximity.node_id);

        // If stale, don't add
        if proximity.is_stale(self.measurement_timeout) {
            return;
        }

        // Add the peer
        self.peers.push(proximity);

        // Sort by proximity (best first)
        self.peers.sort_by(|a, b| {
            a.proximity
                .partial_cmp(&b.proximity)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Trim to max size
        self.peers.truncate(self.max_size);
    }

    /// Get the closest N peers
    pub fn get_closest(&self, count: usize) -> Vec<NodeId> {
        self.peers
            .iter()
            .filter(|p| !p.is_stale(self.measurement_timeout))
            .take(count)
            .map(|p| p.node_id)
            .collect()
    }

    /// Get all peers in the neighborhood
    pub fn get_all(&self) -> Vec<NodeId> {
        self.peers
            .iter()
            .filter(|p| !p.is_stale(self.measurement_timeout))
            .map(|p| p.node_id)
            .collect()
    }

    /// Get proximity information for a specific peer
    pub fn get_proximity(&self, node_id: &NodeId) -> Option<&NetworkProximity> {
        self.peers.iter().find(|p| &p.node_id == node_id)
    }

    /// Remove a peer from the neighborhood
    pub fn remove_peer(&mut self, node_id: &NodeId) {
        self.peers.retain(|p| &p.node_id != node_id);
    }

    /// Prune stale entries
    pub fn prune_stale(&mut self) -> usize {
        let before = self.peers.len();
        self.peers.retain(|p| !p.is_stale(self.measurement_timeout));
        before - self.peers.len()
    }

    /// Get the number of peers in the neighborhood
    pub fn size(&self) -> usize {
        self.peers
            .iter()
            .filter(|p| !p.is_stale(self.measurement_timeout))
            .count()
    }

    /// Clear all peers
    pub fn clear(&mut self) {
        self.peers.clear();
    }
}

/// Simple network proximity estimator based on IP address prefix matching
pub struct ProximityEstimator;

impl ProximityEstimator {
    /// Estimate proximity between two IP addresses
    /// Returns a score where lower is better (0 = same network, higher = more distant)
    pub fn estimate(addr1: &SocketAddr, addr2: &SocketAddr) -> ProximityScore {
        use std::net::IpAddr;

        match (addr1.ip(), addr2.ip()) {
            (IpAddr::V4(ip1), IpAddr::V4(ip2)) => {
                let bytes1 = ip1.octets();
                let bytes2 = ip2.octets();

                // Count matching prefix octets
                let matching = bytes1
                    .iter()
                    .zip(bytes2.iter())
                    .take_while(|(a, b)| a == b)
                    .count();

                // Score: fewer matching octets = higher score (worse proximity)
                ProximityScore::new((4 - matching) as f64 * 100.0)
            }
            (IpAddr::V6(ip1), IpAddr::V6(ip2)) => {
                let segments1 = ip1.segments();
                let segments2 = ip2.segments();

                // Count matching prefix segments
                let matching = segments1
                    .iter()
                    .zip(segments2.iter())
                    .take_while(|(a, b)| a == b)
                    .count();

                // Score: fewer matching segments = higher score
                ProximityScore::new((8 - matching) as f64 * 50.0)
            }
            _ => ProximityScore::infinite(), // Different IP versions
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn create_node_id(byte: u8) -> NodeId {
        NodeId::new([byte; 32])
    }

    fn create_addr(a: u8, b: u8, c: u8, d: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), 8000)
    }

    #[test]
    fn test_proximity_score() {
        let score1 = ProximityScore::new(10.0);
        let score2 = ProximityScore::new(20.0);
        assert!(score1 < score2);
        assert_eq!(score1.score(), 10.0);
    }

    #[test]
    fn test_network_proximity_update() {
        let node_id = create_node_id(1);
        let addr = create_addr(192, 168, 1, 1);
        let mut proximity = NetworkProximity::new(node_id, addr);

        assert!(proximity.avg_rtt_ms.is_none());

        proximity.update_rtt(10.0);
        assert_eq!(proximity.avg_rtt_ms, Some(10.0));

        proximity.update_rtt(20.0);
        // EWMA: 10.0 * 0.8 + 20.0 * 0.2 = 12.0
        assert_eq!(proximity.avg_rtt_ms, Some(12.0));
    }

    #[test]
    fn test_network_proximity_loss_rate() {
        let node_id = create_node_id(1);
        let addr = create_addr(192, 168, 1, 1);
        let mut proximity = NetworkProximity::new(node_id, addr);

        proximity.update_rtt(10.0);
        proximity.update_loss_rate(0.1);

        // Proximity should increase due to loss
        assert!(proximity.proximity.score() > 10.0);
    }

    #[test]
    fn test_neighborhood_insert() {
        let mut neighborhood = Neighborhood::new(3, Duration::from_secs(60));

        for i in 0..5 {
            let node_id = create_node_id(i);
            let addr = create_addr(192, 168, 1, i);
            let mut proximity = NetworkProximity::new(node_id, addr);
            proximity.update_rtt((i as f64 + 1.0) * 10.0);
            neighborhood.upsert_peer(proximity);
        }

        // Should only keep 3 best (lowest RTT)
        assert_eq!(neighborhood.size(), 3);

        let closest = neighborhood.get_closest(3);
        assert_eq!(closest.len(), 3);
        assert_eq!(closest[0], create_node_id(0)); // Lowest RTT
    }

    #[test]
    fn test_neighborhood_remove() {
        let mut neighborhood = Neighborhood::new(10, Duration::from_secs(60));

        let node_id = create_node_id(1);
        let addr = create_addr(192, 168, 1, 1);
        let mut proximity = NetworkProximity::new(node_id, addr);
        proximity.update_rtt(10.0);

        neighborhood.upsert_peer(proximity);
        assert_eq!(neighborhood.size(), 1);

        neighborhood.remove_peer(&node_id);
        assert_eq!(neighborhood.size(), 0);
    }

    #[test]
    fn test_proximity_estimator_ipv4() {
        let addr1 = create_addr(192, 168, 1, 10);
        let addr2 = create_addr(192, 168, 1, 20); // Same /24
        let addr3 = create_addr(192, 168, 2, 10); // Same /16
        let addr4 = create_addr(10, 0, 0, 1); // Different network

        let score12 = ProximityEstimator::estimate(&addr1, &addr2);
        let score13 = ProximityEstimator::estimate(&addr1, &addr3);
        let score14 = ProximityEstimator::estimate(&addr1, &addr4);

        // Closer networks should have lower scores
        assert!(score12 < score13);
        assert!(score13 < score14);
    }

    #[test]
    fn test_proximity_estimator_same_address() {
        let addr = create_addr(192, 168, 1, 10);
        let score = ProximityEstimator::estimate(&addr, &addr);
        assert_eq!(score.score(), 0.0);
    }
}
