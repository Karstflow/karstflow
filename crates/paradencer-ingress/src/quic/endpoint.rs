use super::*;
use quinn::Endpoint;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub struct QuicEndpointStats {
    pub connections_accepted: Arc<AtomicU64>,
    pub connections_rejected: Arc<AtomicU64>,
    pub connections_closed: Arc<AtomicU64>,
    pub uni_streams_accepted: Arc<AtomicU64>,
    pub bi_streams_rejected: Arc<AtomicU64>,
    pub packets_received: Arc<AtomicU64>,
    pub bytes_received: Arc<AtomicU64>,
}

impl QuicEndpointStats {
    pub fn new() -> Self {
        Self {
            connections_accepted: Arc::new(AtomicU64::new(0)),
            connections_rejected: Arc::new(AtomicU64::new(0)),
            connections_closed: Arc::new(AtomicU64::new(0)),
            uni_streams_accepted: Arc::new(AtomicU64::new(0)),
            bi_streams_rejected: Arc::new(AtomicU64::new(0)),
            packets_received: Arc::new(AtomicU64::new(0)),
            bytes_received: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn record_connection_accepted(&self) {
        self.connections_accepted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_connection_rejected(&self) {
        self.connections_rejected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_connection_closed(&self) {
        self.connections_closed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_uni_stream_accepted(&self) {
        self.uni_streams_accepted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_bi_stream_rejected(&self) {
        self.bi_streams_rejected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_packet_received(&self, bytes: u64) {
        self.packets_received.fetch_add(1, Ordering::Relaxed);
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> QuicEndpointStatsSnapshot {
        QuicEndpointStatsSnapshot {
            connections_accepted: self.connections_accepted.load(Ordering::Relaxed),
            connections_rejected: self.connections_rejected.load(Ordering::Relaxed),
            connections_closed: self.connections_closed.load(Ordering::Relaxed),
            uni_streams_accepted: self.uni_streams_accepted.load(Ordering::Relaxed),
            bi_streams_rejected: self.bi_streams_rejected.load(Ordering::Relaxed),
            packets_received: self.packets_received.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
        }
    }
}

impl Default for QuicEndpointStats {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicEndpointStatsSnapshot {
    pub connections_accepted: u64,
    pub connections_rejected: u64,
    pub connections_closed: u64,
    pub uni_streams_accepted: u64,
    pub bi_streams_rejected: u64,
    pub packets_received: u64,
    pub bytes_received: u64,
}

pub struct QuicEndpoint {
    endpoint: Endpoint,
    stats: QuicEndpointStats,
    stream_stats: StreamStats,
    packet_tx: mpsc::Sender<QuicPacket>,
    packet_rx: mpsc::Receiver<QuicPacket>,
}

impl QuicEndpoint {
    /// Create a QuicEndpoint synchronously using a temporary tokio runtime.
    pub fn new(config: QuicConfig, _stats: Arc<QuicEndpointStats>) -> QuicResult<Self> {
        // Try current runtime first, fall back to creating temporary one
        let rt = tokio::runtime::Handle::try_current();
        match rt {
            Ok(handle) => {
                let _guard = handle.enter();
                Self::bind_sync(config)
            }
            Err(_) => {
                let rt =
                    tokio::runtime::Runtime::new().map_err(|e| IngressError::QuicEndpointBind {
                        detail: format!("failed to create runtime: {}", e),
                    })?;
                let _guard = rt.enter();
                Self::bind_sync(config)
            }
        }
    }

    fn bind_sync(config: QuicConfig) -> QuicResult<Self> {
        let endpoint = Endpoint::server((*config.server_config).clone(), config.bind_addr)
            .map_err(|e| IngressError::QuicEndpointBind {
                detail: format!("failed to bind endpoint: {}", e),
            })?;

        let (packet_tx, packet_rx) = mpsc::channel(PACKET_CHANNEL_CAPACITY);

        Ok(Self {
            endpoint,
            stats: QuicEndpointStats::new(),
            stream_stats: StreamStats::new(),
            packet_tx,
            packet_rx,
        })
    }

    pub async fn bind(config: QuicConfig) -> QuicResult<Self> {
        let endpoint = Endpoint::server((*config.server_config).clone(), config.bind_addr)
            .map_err(|e| IngressError::QuicEndpointBind {
                detail: format!("failed to bind endpoint: {}", e),
            })?;

        let (packet_tx, packet_rx) = mpsc::channel(PACKET_CHANNEL_CAPACITY);

        Ok(Self {
            endpoint,
            stats: QuicEndpointStats::new(),
            stream_stats: StreamStats::new(),
            packet_tx,
            packet_rx,
        })
    }

    pub fn local_addr(&self) -> QuicResult<std::net::SocketAddr> {
        self.endpoint
            .local_addr()
            .map_err(|e| IngressError::QuicIo {
                detail: format!("failed to get local addr: {}", e),
            })
    }

    pub fn stats(&self) -> &QuicEndpointStats {
        &self.stats
    }

    pub fn stream_stats(&self) -> &StreamStats {
        &self.stream_stats
    }

    pub async fn accept_connection(&mut self) -> QuicResult<()> {
        let Some(connecting) = self.endpoint.accept().await else {
            return Ok(());
        };

        let connection = match connecting.await {
            Ok(conn) => {
                self.stats.record_connection_accepted();
                conn
            }
            Err(e) => {
                self.stats.record_connection_rejected();
                return Err(IngressError::QuicConnection {
                    detail: format!("connection failed: {}", e),
                });
            }
        };

        let remote_addr = connection.remote_address();
        let stats = self.stats.clone();
        let stream_stats = self.stream_stats.clone();
        let packet_tx = self.packet_tx.clone();

        tokio::spawn(async move {
            Self::handle_connection(connection, remote_addr, stats, stream_stats, packet_tx).await;
        });

        Ok(())
    }

    async fn handle_connection(
        connection: quinn::Connection,
        remote_addr: std::net::SocketAddr,
        stats: QuicEndpointStats,
        stream_stats: StreamStats,
        packet_tx: mpsc::Sender<QuicPacket>,
    ) {
        loop {
            match connection.accept_uni().await {
                Ok(recv_stream) => {
                    stats.record_uni_stream_accepted();
                    let stream_id = recv_stream.id().index();
                    let stream_handler = QuicStream::new(stream_stats.clone());
                    let packet_tx = packet_tx.clone();
                    let endpoint_stats = stats.clone();

                    tokio::spawn(async move {
                        if let Ok(packets) = stream_handler
                            .read_packets(
                                recv_stream,
                                remote_addr,
                                stream_id,
                                MAX_PACKETS_PER_STREAM,
                            )
                            .await
                        {
                            for packet in packets {
                                endpoint_stats.record_packet_received(packet.len() as u64);
                                let _ = packet_tx.send(packet).await;
                            }
                        }
                    });
                }
                Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                    stats.record_connection_closed();
                    break;
                }
                Err(_) => {
                    stats.record_connection_closed();
                    break;
                }
            }

            if let Ok(bi_stream) = connection.accept_bi().await {
                stats.record_bi_stream_rejected();
                drop(bi_stream);
            }
        }
    }

    pub async fn recv_packet(&mut self) -> Option<QuicPacket> {
        self.packet_rx.recv().await
    }

    pub async fn recv_packet_batch(&mut self, max_packets: usize) -> QuicPacketBatch {
        let mut batch = QuicPacketBatch::with_capacity(0, max_packets);

        if let Some(first_packet) = self.packet_rx.recv().await {
            batch.push(first_packet);

            while batch.len() < max_packets {
                match self.packet_rx.try_recv() {
                    Ok(packet) => batch.push(packet),
                    Err(_) => break,
                }
            }
        }

        batch
    }

    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"shutdown");
    }
}
