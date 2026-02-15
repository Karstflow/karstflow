use crate::InboundPacket;
use paradencer_ingress::{IngressMode, IngressPolicy};
use paradencer_mesh::{OutPort, SendError};
use paradencer_runtime::{RuntimeError, RuntimeResult, Service, ServiceContext};
use std::net::UdpSocket;
use std::time::Duration;

pub struct EdgeIntake {
    next_packet_id: u64,
    outgoing_tx_packets: Vec<OutPort<InboundPacket>>,
    outgoing_shred_packets: Vec<OutPort<InboundPacket>>,
    ingress_policy: IngressPolicy,
    synthetic_source_cursor: u64,
    packets_sent_in_batch: u32,
    idle_ticks_remaining: u32,
    udp_socket: Option<UdpSocket>,
    next_tx_route_index: usize,
    next_shred_route_index: usize,
}

impl EdgeIntake {
    pub fn new(outgoing_tx_packets: OutPort<InboundPacket>) -> Self {
        Self::with_policy(outgoing_tx_packets, IngressPolicy::default())
    }

    pub fn with_policy(
        outgoing_tx_packets: OutPort<InboundPacket>,
        ingress_policy: IngressPolicy,
    ) -> Self {
        Self::with_policy_and_links(vec![outgoing_tx_packets], Vec::new(), ingress_policy)
    }

    pub fn with_policy_and_shred(
        outgoing_tx_packets: OutPort<InboundPacket>,
        outgoing_shred_packets: OutPort<InboundPacket>,
        ingress_policy: IngressPolicy,
    ) -> Self {
        Self::with_policy_and_links(
            vec![outgoing_tx_packets],
            vec![outgoing_shred_packets],
            ingress_policy,
        )
    }

    pub fn with_policy_and_links(
        outgoing_tx_packets: Vec<OutPort<InboundPacket>>,
        outgoing_shred_packets: Vec<OutPort<InboundPacket>>,
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

    fn should_route_to_shred_path(&self, source: paradencer_ingress::IngressSource) -> bool {
        !self.outgoing_shred_packets.is_empty()
            && source == paradencer_ingress::IngressSource::Gossip
    }

    fn try_send_to_route_set(
        &mut self,
        context: &ServiceContext,
        packet: InboundPacket,
        routes: &[OutPort<InboundPacket>],
        start_index: usize,
    ) -> RuntimeResult<bool> {
        if routes.is_empty() {
            return Err(RuntimeError::service_failure(
                self.name(),
                "no outgoing links configured",
            ));
        }
        let mut closed_routes = 0_usize;
        for route_offset in 0..routes.len() {
            let route_index = (start_index + route_offset) % routes.len();
            match routes[route_index].try_send(packet.clone()) {
                Ok(()) => return Ok(true),
                Err(SendError::QueueFull(_)) => continue,
                Err(SendError::QueueClosed(_)) => {
                    closed_routes = closed_routes.saturating_add(1);
                }
            }
        }
        if closed_routes == routes.len() {
            context.shutdown.request_stop();
            return Err(RuntimeError::service_failure(
                self.name(),
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
            let routes = self.outgoing_shred_packets.clone();
            self.try_send_to_route_set(context, packet, &routes, start_index)
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
            let routes = self.outgoing_tx_packets.clone();
            self.try_send_to_route_set(context, packet, &routes, start_index)
        }
    }

    #[cfg(test)]
    pub(crate) fn udp_local_addr(&self) -> Option<std::net::SocketAddr> {
        self.udp_socket
            .as_ref()
            .and_then(|socket| socket.local_addr().ok())
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
        let packet = InboundPacket {
            packet_id: self.next_packet_id,
            payload_bytes: self.ingress_policy.synthetic_payload_bytes,
            source,
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
