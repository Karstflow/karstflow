/// Network tile: packet demux, routing, and transport management.
///
/// The network tile owns the transport backend (UDP or XDP) and
/// dispatches incoming packets to protocol handlers. It handles:
/// - Packet receive from the transport layer
/// - Outbound packet transmission
/// - Forwarding to the QUIC tile for QUIC packets
///
/// Runs as a single-threaded polling loop, pinned to one CPU core.
use std::io;
use std::net::SocketAddrV4;

use crate::backend::{Transport, TransportConfig, TransportStats};
use crate::io::IoHandle;
use crate::neighbor::NeighborTable;
use crate::packet::{PacketBatch, PacketBuffer};
use crate::routing::RoutingTable;
use paradencer_constants::network::PACKET_BATCH_DEFAULT;

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
    /// Receive scratch buffer (pre-allocated, reused each service call).
    rx_batch: PacketBatch<PACKET_BATCH_DEFAULT>,
    /// Outbound packet queue (accumulated between service calls).
    tx_batch: PacketBatch<PACKET_BATCH_DEFAULT>,
    /// Callback for delivering received packets to the QUIC tile.
    quic_callback: Option<IoHandle>,
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
            rx_batch: PacketBatch::new(),
            tx_batch: PacketBatch::new(),
            quic_callback: None,
        }
    }

    /// Open the transport (bind socket). Must be called before `start()`.
    pub fn open(&mut self) -> io::Result<()> {
        self.transport.open()
    }

    /// Set the callback for forwarding received UDP packets to the QUIC tile.
    pub fn set_quic_callback(&mut self, callback: IoHandle) {
        self.quic_callback = Some(callback);
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

    /// Queue a packet for outbound transmission.
    ///
    /// Returns `true` if the packet was queued, `false` if the TX batch
    /// is full. Queued packets are sent on the next `service()` call.
    pub fn queue_tx(&mut self, pkt: PacketBuffer) -> bool {
        self.tx_batch.push(pkt)
    }

    /// Send a single packet immediately via the transport.
    pub fn send_to(&mut self, data: &[u8], addr: &SocketAddrV4) -> io::Result<usize> {
        self.transport.send_to(data, addr)
    }

    /// Execute one service iteration.
    ///
    /// This is the main polling function called in a tight loop:
    /// 1. Flush any pending TX packets
    /// 2. Receive incoming packets from the transport
    /// 3. Forward received packets to the QUIC callback
    ///
    /// Returns the number of packets received.
    pub fn service(&mut self) -> usize {
        if !self.running {
            return 0;
        }
        self.iterations += 1;

        // Step 1: Flush pending TX packets.
        if !self.tx_batch.is_empty() {
            self.transport.send_batch(&self.tx_batch);
            self.tx_batch.clear();
        }

        // Step 2: Receive incoming packets.
        self.rx_batch.clear();
        let received = self.transport.receive_batch(&mut self.rx_batch);
        if received == 0 {
            return 0;
        }

        // Step 3: Forward to QUIC callback (if set).
        if let Some(ref callback) = self.quic_callback {
            callback.send(self.rx_batch.as_slice(), false);
        }

        received
    }

    /// Access the last received packet batch.
    ///
    /// Valid after `service()` returns > 0. Used by the bridge to feed
    /// packets directly to the co-located QUIC tile without copying.
    pub fn rx_batch_ref(&self) -> &[PacketBuffer] {
        self.rx_batch.as_slice()
    }

    /// Get the local bind address of the transport.
    pub fn local_addr(&self) -> Option<SocketAddrV4> {
        self.transport.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::{ipv4, NextHop};
    use paradencer_constants::network::ROUTE_TYPE_UNICAST;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn localhost_config() -> NetworkTileConfig {
        NetworkTileConfig {
            transport: TransportConfig {
                bind_addr: Ipv4Addr::LOCALHOST,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn creation() {
        let tile = NetworkTile::new(NetworkTileConfig::default());
        assert!(!tile.is_running());
        assert_eq!(tile.iterations(), 0);
        assert!(!tile.transport().is_open());
    }

    #[test]
    fn open_and_start() {
        let mut tile = NetworkTile::new(localhost_config());
        tile.open().expect("open failed");
        assert!(tile.transport().is_open());
        assert!(tile.local_addr().is_some());

        tile.start();
        assert!(tile.is_running());
    }

    #[test]
    fn service_when_stopped_returns_zero() {
        let mut tile = NetworkTile::new(localhost_config());
        tile.open().expect("open");
        assert_eq!(tile.service(), 0); // not started
    }

    #[test]
    fn service_with_no_packets() {
        let mut tile = NetworkTile::new(localhost_config());
        tile.open().expect("open");
        tile.start();
        let received = tile.service();
        assert_eq!(received, 0);
        assert_eq!(tile.iterations(), 1);
    }

    #[test]
    fn service_receives_and_forwards() {
        static FORWARDED: AtomicUsize = AtomicUsize::new(0);

        unsafe fn counting_callback(
            _ctx: *mut (),
            packets: &[PacketBuffer],
            _flush: bool,
        ) -> crate::io::SendResult {
            FORWARDED.fetch_add(packets.len(), Ordering::Relaxed);
            crate::io::SendResult::Success
        }

        FORWARDED.store(0, Ordering::Relaxed);

        // Create the network tile.
        let mut tile = NetworkTile::new(localhost_config());
        tile.open().expect("open");
        let callback = unsafe { IoHandle::new(std::ptr::null_mut(), counting_callback) };
        tile.set_quic_callback(callback);
        tile.start();

        // Send a packet to the tile's transport from an external socket.
        let tile_addr = tile.local_addr().unwrap();
        let sender_config = TransportConfig {
            bind_addr: Ipv4Addr::LOCALHOST,
            ..Default::default()
        };
        let mut sender = Transport::new(sender_config);
        sender.open().expect("sender open");
        sender.send_to(b"test packet", &tile_addr).expect("send");

        // Poll until we receive.
        let mut total_received = 0;
        for _ in 0..50 {
            std::thread::sleep(std::time::Duration::from_millis(5));
            total_received += tile.service();
            if total_received > 0 {
                break;
            }
        }

        assert_eq!(total_received, 1);
        assert_eq!(FORWARDED.load(Ordering::Relaxed), 1);
        assert!(tile.stats().rx_packets >= 1);
    }

    #[test]
    fn queue_and_send_tx() {
        let mut tile = NetworkTile::new(localhost_config());
        tile.open().expect("open");
        tile.start();

        // Create a receiver.
        let mut receiver = Transport::new(TransportConfig {
            bind_addr: Ipv4Addr::LOCALHOST,
            ..Default::default()
        });
        receiver.open().expect("rx open");
        let rx_addr = receiver.local_addr().unwrap();

        // Queue a packet for TX.
        let pkt = PacketBuffer::from_slice(b"queued packet", Some(rx_addr));
        assert!(tile.queue_tx(pkt));

        // Service call flushes the TX queue.
        tile.service();

        // Check receiver got it.
        let mut batch = PacketBatch::<4>::new();
        let mut received = 0;
        for _ in 0..50 {
            std::thread::sleep(std::time::Duration::from_millis(5));
            received = receiver.receive_batch(&mut batch);
            if received > 0 {
                break;
            }
        }
        assert_eq!(received, 1);
        assert_eq!(batch.get(0).payload(), b"queued packet");
    }

    #[test]
    fn start_stop() {
        let mut tile = NetworkTile::new(NetworkTileConfig::default());
        tile.start();
        assert!(tile.is_running());

        tile.stop();
        assert!(!tile.is_running());
        assert_eq!(tile.service(), 0); // no-op when stopped
    }

    #[test]
    fn routing_access() {
        let mut tile = NetworkTile::new(NetworkTileConfig::default());

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
