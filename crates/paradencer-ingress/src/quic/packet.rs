use bytes::Bytes;
use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct QuicPacket {
    pub data: Bytes,
    pub remote_addr: SocketAddr,
    pub stream_id: u64,
    pub received_at_ns: u64,
}

impl QuicPacket {
    pub fn new(data: Bytes, remote_addr: SocketAddr, stream_id: u64) -> Self {
        let received_at_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        Self {
            data,
            remote_addr,
            stream_id,
            received_at_ns,
        }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct QuicPacketBatch {
    pub packets: Vec<QuicPacket>,
    pub batch_id: u64,
}

impl QuicPacketBatch {
    pub fn new(batch_id: u64) -> Self {
        Self {
            packets: Vec::new(),
            batch_id,
        }
    }

    pub fn with_capacity(batch_id: u64, capacity: usize) -> Self {
        Self {
            packets: Vec::with_capacity(capacity),
            batch_id,
        }
    }

    pub fn push(&mut self, packet: QuicPacket) {
        self.packets.push(packet);
    }

    pub fn len(&self) -> usize {
        self.packets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    pub fn total_bytes(&self) -> usize {
        self.packets.iter().map(|p| p.len()).sum()
    }
}
