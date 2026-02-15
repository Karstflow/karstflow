use super::*;
use quinn::RecvStream;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct StreamStats {
    pub bytes_received: Arc<AtomicU64>,
    pub packets_received: Arc<AtomicU64>,
    pub streams_opened: Arc<AtomicU64>,
    pub streams_closed: Arc<AtomicU64>,
    pub read_errors: Arc<AtomicU64>,
}

impl StreamStats {
    pub fn new() -> Self {
        Self {
            bytes_received: Arc::new(AtomicU64::new(0)),
            packets_received: Arc::new(AtomicU64::new(0)),
            streams_opened: Arc::new(AtomicU64::new(0)),
            streams_closed: Arc::new(AtomicU64::new(0)),
            read_errors: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn record_stream_opened(&self) {
        self.streams_opened.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_stream_closed(&self) {
        self.streams_closed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_bytes_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_packet_received(&self) {
        self.packets_received.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_read_error(&self) {
        self.read_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> StreamStatsSnapshot {
        StreamStatsSnapshot {
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            packets_received: self.packets_received.load(Ordering::Relaxed),
            streams_opened: self.streams_opened.load(Ordering::Relaxed),
            streams_closed: self.streams_closed.load(Ordering::Relaxed),
            read_errors: self.read_errors.load(Ordering::Relaxed),
        }
    }
}

impl Default for StreamStats {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamStatsSnapshot {
    pub bytes_received: u64,
    pub packets_received: u64,
    pub streams_opened: u64,
    pub streams_closed: u64,
    pub read_errors: u64,
}

pub struct QuicStream {
    stats: StreamStats,
}

impl QuicStream {
    pub fn new(stats: StreamStats) -> Self {
        Self { stats }
    }

    pub async fn read_packets(
        &self,
        mut stream: RecvStream,
        remote_addr: SocketAddr,
        stream_id: u64,
        max_packets: usize,
    ) -> QuicResult<Vec<QuicPacket>> {
        self.stats.record_stream_opened();

        let mut packets = Vec::new();
        let mut total_bytes_read = 0usize;

        while packets.len() < max_packets {
            match self
                .read_single_packet(&mut stream, remote_addr, stream_id, total_bytes_read)
                .await
            {
                Ok(Some(packet)) => {
                    total_bytes_read = total_bytes_read.saturating_add(packet.len());
                    self.stats.record_bytes_received(packet.len() as u64);
                    self.stats.record_packet_received();
                    packets.push(packet);
                }
                Ok(None) => {
                    break;
                }
                Err(e) => {
                    self.stats.record_read_error();
                    if !packets.is_empty() {
                        break;
                    }
                    return Err(e);
                }
            }

            if total_bytes_read >= MAX_STREAM_READ_SIZE {
                break;
            }
        }

        self.stats.record_stream_closed();
        Ok(packets)
    }

    async fn read_single_packet(
        &self,
        stream: &mut RecvStream,
        remote_addr: SocketAddr,
        stream_id: u64,
        total_bytes_read: usize,
    ) -> QuicResult<Option<QuicPacket>> {
        let remaining_budget = MAX_STREAM_READ_SIZE.saturating_sub(total_bytes_read);
        if remaining_budget == 0 {
            return Ok(None);
        }

        let chunk_size = STREAM_READ_CHUNK_SIZE.min(remaining_budget);

        match stream.read_chunk(chunk_size, true).await {
            Ok(Some(chunk)) => {
                if chunk.bytes.is_empty() {
                    return Ok(None);
                }
                Ok(Some(QuicPacket::new(chunk.bytes, remote_addr, stream_id)))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(IngressError::QuicStream {
                detail: format!("stream read error: {}", e),
            }),
        }
    }
}
