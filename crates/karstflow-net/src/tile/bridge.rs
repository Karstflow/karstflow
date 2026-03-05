/// Network-QUIC tile bridge: co-locates NetworkTile and QuicTile on a
/// single dedicated thread with the QUIC transaction output flowing to
/// a crossbeam channel for downstream pipeline integration.
///
/// Both tiles run in the same polling loop:
/// 1. NetworkTile receives UDP packets
/// 2. Received packets are immediately fed to QuicTile (no cross-thread copy)
/// 3. QuicTile processes QUIC protocol and reassembles transactions
/// 4. Completed transactions are sent to the outbound channel
///
/// This matches Firedancer's architecture where net and quic tiles
/// share a tight processing loop without inter-tile packet channels.
use crate::tile::net_tile::{NetworkTile, NetworkTileConfig};
use crate::tile::quic_tile::{QuicTile, QuicTileConfig, QuicTransaction};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

/// Configuration for the network-QUIC bridge.
#[derive(Debug, Clone)]
pub struct BridgeConfig {
    /// Network tile configuration.
    pub net: NetworkTileConfig,
    /// QUIC tile configuration.
    pub quic: QuicTileConfig,
    /// Capacity of the outbound transaction channel.
    pub transaction_channel_capacity: usize,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            net: NetworkTileConfig::default(),
            quic: QuicTileConfig::default(),
            transaction_channel_capacity: 2048,
        }
    }
}

/// Handle to a running network-QUIC bridge.
///
/// Dropping this handle signals the tile thread to stop and joins it.
pub struct BridgeHandle {
    /// Receiver for completed QUIC transactions.
    pub transaction_rx: crossbeam_channel::Receiver<QuicTransaction>,
    /// Shutdown signal shared with the tile thread.
    shutdown: Arc<AtomicBool>,
    /// Combined tile thread handle.
    thread: Option<thread::JoinHandle<()>>,
}

impl BridgeHandle {
    /// Signal the bridge to shut down.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
    }

    /// Whether the bridge has been signaled to shut down.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }
}

impl Drop for BridgeHandle {
    fn drop(&mut self) {
        self.shutdown();
        if let Some(h) = self.thread.take() {
            let _ = h.join();
        }
    }
}

/// Spawn the network-QUIC bridge on a dedicated thread.
///
/// Returns a handle with the transaction receiver and shutdown control.
/// Both tiles are created and bound inside the spawned thread to avoid
/// Send requirements on tile internals (IoHandle contains raw pointers).
pub fn spawn_bridge(config: BridgeConfig) -> io::Result<BridgeHandle> {
    let shutdown = Arc::new(AtomicBool::new(false));

    // Transaction output channel: bridge thread → downstream pipeline.
    let (tx_tx, tx_rx) =
        crossbeam_channel::bounded::<QuicTransaction>(config.transaction_channel_capacity);

    // Use a oneshot channel to propagate initialization errors.
    let (init_tx, init_rx) = crossbeam_channel::bounded::<io::Result<()>>(1);

    let bridge_shutdown = Arc::clone(&shutdown);
    let thread = thread::Builder::new()
        .name("net-quic-tile".into())
        .spawn(move || {
            // Create and bind both tiles inside the thread.
            let mut net_tile = NetworkTile::new(config.net);
            if let Err(e) = net_tile.open() {
                let _ = init_tx.send(Err(e));
                return;
            }

            let quic_tile = QuicTile::new(config.quic);
            let mut quic_tile = match quic_tile {
                Some(t) => t,
                None => {
                    let _ = init_tx.send(Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "invalid QUIC engine limits",
                    )));
                    return;
                }
            };
            quic_tile.set_outbound(tx_tx);

            // Signal successful initialization.
            let _ = init_tx.send(Ok(()));

            run_bridge_loop(&mut net_tile, &mut quic_tile, &bridge_shutdown);
        })?;

    // Wait for initialization result.
    match init_rx.recv() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(io::Error::other(
                "bridge thread panicked during initialization",
            ))
        }
    }

    Ok(BridgeHandle {
        transaction_rx: tx_rx,
        shutdown,
        thread: Some(thread),
    })
}

/// Combined poll loop for both tiles.
///
/// Runs on a single thread to avoid cross-thread packet copies.
/// NetworkTile receives packets, then they are immediately processed
/// by QuicTile in the same iteration.
fn run_bridge_loop(net: &mut NetworkTile, quic: &mut QuicTile, shutdown: &AtomicBool) {
    net.start();
    quic.start();
    let start = Instant::now();

    while !shutdown.load(Ordering::Acquire) {
        let now_ns = start.elapsed().as_nanos() as u64;

        // Step 1: Receive packets from the network.
        // NetworkTile::service() receives into its internal rx_batch.
        // In bridge mode, we skip the IoHandle callback and instead
        // feed packets directly to the co-located QUIC tile.
        let received = net.service();

        // Step 2: Feed received packets to the QUIC tile.
        if received > 0 {
            quic.receive_packets(net.rx_batch_ref(), now_ns);
        }

        // Step 3: Service QUIC engine (timers, retransmissions) and
        // extract completed transactions to the outbound channel.
        quic.service(now_ns);
    }

    quic.stop();
    net.stop();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::TransportConfig;
    use std::net::Ipv4Addr;

    fn localhost_bridge_config() -> BridgeConfig {
        BridgeConfig {
            net: NetworkTileConfig {
                transport: TransportConfig {
                    bind_addr: Ipv4Addr::LOCALHOST,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn bridge_starts_and_stops() {
        let handle = spawn_bridge(localhost_bridge_config()).unwrap();
        assert!(!handle.is_shutdown());

        std::thread::sleep(std::time::Duration::from_millis(20));

        handle.shutdown();
        assert!(handle.is_shutdown());

        drop(handle);
    }

    #[test]
    fn bridge_transaction_rx_is_empty_initially() {
        let handle = spawn_bridge(localhost_bridge_config()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));

        assert!(handle.transaction_rx.try_recv().is_err());
        handle.shutdown();
    }
}
