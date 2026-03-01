use crate::InboundPacket;
use paradencer_mesh::{DualSendError, DualSender};
use paradencer_net::{IngressMode, IngressPolicy, IngressSource};
use paradencer_runtime::{RuntimeError, RuntimeResult, Service, ServiceContext};
use std::net::UdpSocket;
use std::time::Duration;

pub struct EdgeIntake {
    next_packet_id: u64,
    outgoing_tx_packets: Vec<DualSender<InboundPacket>>,
    outgoing_shred_packets: Vec<DualSender<InboundPacket>>,
    ingress_policy: IngressPolicy,
    synthetic_source_cursor: u64,
    packets_sent_in_batch: u32,
    idle_ticks_remaining: u32,
    udp_socket: Option<UdpSocket>,
    next_tx_route_index: usize,
    next_shred_route_index: usize,
}

impl EdgeIntake {
    pub fn new(outgoing_tx_packets: DualSender<InboundPacket>) -> Self {
        Self::with_policy(outgoing_tx_packets, IngressPolicy::default())
    }

    pub fn with_policy(
        outgoing_tx_packets: DualSender<InboundPacket>,
        ingress_policy: IngressPolicy,
    ) -> Self {
        Self::with_policy_and_links(vec![outgoing_tx_packets], Vec::new(), ingress_policy)
    }

    pub fn with_policy_and_shred(
        outgoing_tx_packets: DualSender<InboundPacket>,
        outgoing_shred_packets: DualSender<InboundPacket>,
        ingress_policy: IngressPolicy,
    ) -> Self {
        Self::with_policy_and_links(
            vec![outgoing_tx_packets],
            vec![outgoing_shred_packets],
            ingress_policy,
        )
    }

    pub fn with_policy_and_links(
        outgoing_tx_packets: Vec<DualSender<InboundPacket>>,
        outgoing_shred_packets: Vec<DualSender<InboundPacket>>,
        ingress_policy: IngressPolicy,
    ) -> Self {
        Self {
            next_packet_id: 1,
            outgoing_tx_packets: if outgoing_tx_packets.is_empty() {
                Vec::new()
            } else {
                outgoing_tx_packets
            },
            outgoing_shred_packets,
            packets_sent_in_batch: 0,
            ingress_policy,
            synthetic_source_cursor: 0,
            idle_ticks_remaining: 0,
            udp_socket: None,
            next_tx_route_index: 0,
            next_shred_route_index: 0,
        }
    }

    fn should_route_to_shred_path(&self, source: paradencer_net::IngressSource) -> bool {
        !self.outgoing_shred_packets.is_empty() && source == paradencer_net::IngressSource::Gossip
    }

    fn try_send_to_routes(
        context: &ServiceContext,
        name: &'static str,
        packet: InboundPacket,
        routes: &mut [DualSender<InboundPacket>],
        start_index: usize,
    ) -> RuntimeResult<bool> {
        if routes.is_empty() {
            return Err(RuntimeError::service_failure(
                name,
                "no outgoing links configured",
            ));
        }
        let mut closed_routes = 0_usize;
        for route_offset in 0..routes.len() {
            let route_index = (start_index + route_offset) % routes.len();
            match routes[route_index].try_send(packet.clone()) {
                Ok(()) => return Ok(true),
                Err(DualSendError::Full(_) | DualSendError::NoCredits(_)) => continue,
                Err(DualSendError::Closed(_)) => {
                    closed_routes = closed_routes.saturating_add(1);
                }
            }
        }
        if closed_routes == routes.len() {
            context.shutdown.request_stop();
            return Err(RuntimeError::service_failure(
                name,
                "all outgoing links are closed",
            ));
        }
        Ok(false)
    }

    fn try_send_packet(
        &mut self,
        context: &ServiceContext,
        packet: InboundPacket,
    ) -> RuntimeResult<bool> {
        if self.should_route_to_shred_path(packet.source) {
            let start_index = self.next_shred_route_index;
            self.next_shred_route_index =
                (self.next_shred_route_index.saturating_add(1)) % self.outgoing_shred_packets.len();
            Self::try_send_to_routes(
                context,
                "edge-intake",
                packet,
                &mut self.outgoing_shred_packets,
                start_index,
            )
        } else {
            if self.outgoing_tx_packets.is_empty() {
                return Err(RuntimeError::service_failure(
                    self.name(),
                    "no outgoing transaction links configured",
                ));
            }
            let start_index = self.next_tx_route_index;
            self.next_tx_route_index =
                (self.next_tx_route_index.saturating_add(1)) % self.outgoing_tx_packets.len();
            Self::try_send_to_routes(
                context,
                "edge-intake",
                packet,
                &mut self.outgoing_tx_packets,
                start_index,
            )
        }
    }

    #[cfg(test)]
    pub(crate) fn udp_local_addr(&self) -> Option<std::net::SocketAddr> {
        self.udp_socket
            .as_ref()
            .and_then(|socket| socket.local_addr().ok())
    }

    /// Build synthetic shred bytes for gossip-sourced packets.
    ///
    /// Creates a minimal valid legacy data shred. The first shred in each slot
    /// (index=0) carries a bincode-serialized entry batch (1 entry, 0 txs).
    /// Subsequent shreds carry empty payloads (size=0).
    /// The slot is derived from the packet ID so that shreds from consecutive
    /// IDs share the same slot (32 shreds per slot).
    fn build_synthetic_shred_data(packet_id: u64) -> Vec<u8> {
        // Derive slot from packet_id: every 32 packets share a slot.
        let slot = packet_id / 32;
        let index = (packet_id % 32) as u32;
        let is_last = index == 31;

        // Entry payload: only the first shred carries data.
        // Bincode format: Vec<PohEntry> with 1 entry (num_hashes=1, zero hash, 0 txs).
        // Layout: u64 vec_len=1 + u64 num_hashes=1 + [u8;32] hash + u64 tx_count=0 = 56 bytes.
        let (payload, payload_size) = if index == 0 {
            let mut p = Vec::with_capacity(56);
            p.extend_from_slice(&1u64.to_le_bytes()); // vec length: 1 entry
            p.extend_from_slice(&1u64.to_le_bytes()); // num_hashes: 1
            p.extend_from_slice(&[0u8; 32]); // hash: zeros
            p.extend_from_slice(&0u64.to_le_bytes()); // transactions: 0
            (p, 56u16)
        } else {
            (Vec::new(), 0u16)
        };

        let mut buf = Vec::with_capacity(88 + payload.len());
        // Signature (64 bytes) — unique per packet to avoid deduplication.
        let mut sig = [0u8; 64];
        sig[..8].copy_from_slice(&packet_id.to_le_bytes());
        buf.extend_from_slice(&sig);
        // Variant: legacy data (0xA5)
        buf.push(0xA5);
        // Slot (8 bytes LE)
        buf.extend_from_slice(&slot.to_le_bytes());
        // Index (4 bytes LE)
        buf.extend_from_slice(&index.to_le_bytes());
        // Version (2 bytes LE)
        buf.extend_from_slice(&1u16.to_le_bytes());
        // FEC set index (4 bytes LE)
        buf.extend_from_slice(&0u32.to_le_bytes());
        // Data header: parent_offset=1, flags, size
        buf.extend_from_slice(&1u16.to_le_bytes());
        let flags = if is_last { 0x80u8 } else { 0u8 };
        buf.push(flags);
        buf.extend_from_slice(&payload_size.to_le_bytes());
        // Entry payload
        buf.extend_from_slice(&payload);
        buf
    }

    fn tick_synthetic(&mut self, context: &ServiceContext) -> RuntimeResult<()> {
        if self.idle_ticks_remaining > 0 {
            self.idle_ticks_remaining = self.idle_ticks_remaining.saturating_sub(1);
            return Ok(());
        }

        if self.packets_sent_in_batch >= self.ingress_policy.synthetic_batch_size_per_tick {
            self.packets_sent_in_batch = 0;
            if self.ingress_policy.synthetic_idle_ticks_between_batches > 0 {
                self.idle_ticks_remaining = self
                    .ingress_policy
                    .synthetic_idle_ticks_between_batches
                    .saturating_sub(1);
                return Ok(());
            }
        }

        let source = self
            .ingress_policy
            .synthetic_source_for_cursor(self.synthetic_source_cursor);
        self.synthetic_source_cursor = self.synthetic_source_cursor.saturating_add(1);

        let data = if source == IngressSource::Gossip {
            Self::build_synthetic_shred_data(self.next_packet_id)
        } else {
            vec![]
        };
        let payload_bytes = if data.is_empty() {
            self.ingress_policy.synthetic_payload_bytes
        } else {
            data.len()
        };

        let packet = InboundPacket {
            packet_id: self.next_packet_id,
            payload_bytes,
            source,
            data,
        };
        self.next_packet_id += 1;
        self.packets_sent_in_batch = self.packets_sent_in_batch.saturating_add(1);

        self.try_send_packet(context, packet).map(|_| ())
    }

    fn tick_udp(&mut self, context: &ServiceContext) -> RuntimeResult<()> {
        let mut buffer = [0_u8; 65_536];

        for _ in 0..self.ingress_policy.udp_max_packets_per_tick {
            let recv_result = {
                let socket = self.udp_socket.as_ref().ok_or_else(|| {
                    RuntimeError::service_failure(self.name(), "udp socket is not initialized")
                })?;
                socket.recv_from(&mut buffer)
            };
            match recv_result {
                Ok((packet_len, source_addr)) => {
                    let packet = InboundPacket {
                        packet_id: self.next_packet_id,
                        payload_bytes: packet_len,
                        source: self
                            .ingress_policy
                            .classify_udp_source_port(source_addr.port()),
                        data: buffer[..packet_len].to_vec(),
                    };
                    self.next_packet_id = self.next_packet_id.saturating_add(1);

                    if !self.try_send_packet(context, packet)? {
                        break;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => {
                    return Err(RuntimeError::service_failure(
                        self.name(),
                        &format!("udp recv failed: {error}"),
                    ))
                }
            }
        }

        Ok(())
    }
}

impl Service for EdgeIntake {
    fn name(&self) -> &'static str {
        "edge-intake"
    }

    fn tick_interval(&self) -> Duration {
        Duration::from_millis(2)
    }

    fn on_start(&mut self, _context: &ServiceContext) -> RuntimeResult<()> {
        if self.ingress_policy.ingress_mode == IngressMode::Udp {
            let bind_address = self.ingress_policy.udp_bind_address.ok_or_else(|| {
                RuntimeError::service_failure(
                    self.name(),
                    "udp mode requires ingress_policy.udp_bind_address",
                )
            })?;
            let socket = UdpSocket::bind(bind_address).map_err(|error| {
                RuntimeError::service_failure(
                    self.name(),
                    &format!("failed to bind udp socket {bind_address}: {error}"),
                )
            })?;
            socket.set_nonblocking(true).map_err(|error| {
                RuntimeError::service_failure(
                    self.name(),
                    &format!("failed to set udp socket nonblocking mode: {error}"),
                )
            })?;
            self.udp_socket = Some(socket);
        }
        Ok(())
    }

    fn tick(&mut self, context: &ServiceContext) -> RuntimeResult<()> {
        match self.ingress_policy.ingress_mode {
            IngressMode::Synthetic => self.tick_synthetic(context),
            IngressMode::Udp => self.tick_udp(context),
        }
    }
}
