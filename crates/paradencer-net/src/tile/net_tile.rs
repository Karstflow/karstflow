/// Network tile: packet demux, routing, and transport management.
///
/// The network tile owns the transport backend (UDP or XDP) and
/// dispatches incoming packets to protocol handlers. It handles:
/// - Packet receive from the transport layer
/// - ARP/neighbor resolution
/// - IPv4 routing decisions
/// - Forwarding to the QUIC tile for QUIC packets
///
/// Runs as a single-threaded polling loop, pinned to one CPU core.
use crate::backend::{Transport, TransportConfig, TransportStats};
use crate::neighbor::NeighborTable;
use crate::routing::RoutingTable;

/// Network tile configuration.
#[derive(Debug, Clone)]
pub struct NetworkTileConfig {
    /// Transport configuration.
    pub transport: TransportConfig,
    /// Maximum neighbor table entries.
    pub max_neighbors: usize,
    /// Tile CPU affinity (core index, or `None` for no pinning).
    pub cpu_affinity: Option<usize>,
}

impl Default for NetworkTileConfig {
    fn default() -> Self {
        Self {
            transport: TransportConfig::default(),
            max_neighbors: 256,
            cpu_affinity: None,
        }
    }
}

/// Network tile state.
pub struct NetworkTile {
    /// Transport backend.
    transport: Transport,
    /// IPv4 routing table.
    routing: RoutingTable,
    /// Neighbor (ARP) table.
    neighbors: NeighborTable,
    /// Configuration.
    _config: NetworkTileConfig,
    /// Whether the tile is running.
    running: bool,
    /// Service loop iteration counter.
    iterations: u64,
}

impl NetworkTile {
    /// Create a new network tile.
    pub fn new(config: NetworkTileConfig) -> Self {
        let transport = Transport::new(config.transport.clone());
        let neighbors = NeighborTable::new(config.max_neighbors);

        Self {
            transport,
            routing: RoutingTable::new(),
            neighbors,
            _config: config,
            running: false,
            iterations: 0,
        }
    }

    /// Get a mutable reference to the routing table (for configuration).
    pub fn routing_mut(&mut self) -> &mut RoutingTable {
        &mut self.routing
    }

    /// Get a reference to the routing table.
    pub fn routing(&self) -> &RoutingTable {
        &self.routing
    }

    /// Get a mutable reference to the neighbor table.
    pub fn neighbors_mut(&mut self) -> &mut NeighborTable {
        &mut self.neighbors
    }

    /// Get a reference to the neighbor table.
    pub fn neighbors(&self) -> &NeighborTable {
        &self.neighbors
    }

    /// Get a reference to the transport.
    pub fn transport(&self) -> &Transport {
        &self.transport
    }

    /// Get a mutable reference to the transport.
    pub fn transport_mut(&mut self) -> &mut Transport {
        &mut self.transport
    }

    /// Get the transport statistics.
    pub fn stats(&self) -> &TransportStats {
        self.transport.stats()
    }

    /// Whether the tile is currently running.
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Number of service loop iterations.
    pub fn iterations(&self) -> u64 {
        self.iterations
    }

    /// Start the tile (marks as running).
    pub fn start(&mut self) {
        self.running = true;
    }

    /// Stop the tile (marks as stopped).
    pub fn stop(&mut self) {
        self.running = false;
    }

    /// Execute one service iteration.
    ///
    /// This is the main polling function called in a tight loop.
    /// It receives packets, processes them, and dispatches to handlers.
    ///
    /// Returns the number of packets processed.
    pub fn service(&mut self) -> usize {
        if !self.running {
            return 0;
        }
        self.iterations += 1;

        // In a full implementation, this would:
        // 1. Poll the transport for received packets
        // 2. Parse Ethernet/IP headers
        // 3. Look up routes
        // 4. Resolve neighbor MACs
        // 5. Forward QUIC packets to QuicTile
        // 6. Handle ARP requests/replies
        // 7. Send any pending outbound packets

        0 // Placeholder: actual packet processing in future integration
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creation() {
        let tile = NetworkTile::new(NetworkTileConfig::default());
        assert!(!tile.is_running());
        assert_eq!(tile.iterations(), 0);
    }

    #[test]
    fn start_stop() {
        let mut tile = NetworkTile::new(NetworkTileConfig::default());
        tile.start();
        assert!(tile.is_running());

        tile.service();
        assert_eq!(tile.iterations(), 1);

        tile.stop();
        assert!(!tile.is_running());
        assert_eq!(tile.service(), 0); // no-op when stopped
    }

    #[test]
    fn routing_access() {
        let mut tile = NetworkTile::new(NetworkTileConfig::default());
        use crate::routing::{ipv4, NextHop};
        use paradencer_constants::network::ROUTE_TYPE_UNICAST;

        tile.routing_mut().add_host_route(
            ipv4(10, 0, 0, 1),
            NextHop {
                gateway: 0,
                interface_idx: 1,
                source_addr: 0,
                route_type: ROUTE_TYPE_UNICAST,
            },
        );

        assert!(tile.routing().lookup(ipv4(10, 0, 0, 1)).is_some());
    }

    #[test]
    fn neighbor_access() {
        let mut tile = NetworkTile::new(NetworkTileConfig::default());
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        tile.neighbors_mut().update(0x0A000001, mac, 1000);
        assert!(tile.neighbors().lookup(0x0A000001).is_some());
    }
}
