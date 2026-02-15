use super::*;
use crate::gossip::{ClusterInfo, NodeId};
use crate::repair::protocol::{RepairMessage, RepairRequest, RepairResponse, ShredData};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;

const DEFAULT_REPAIR_TIMEOUT_MS: u64 = 5000;
const MAX_PENDING_REQUESTS: usize = 1000;
const REPAIR_REQUEST_CHANNEL_SIZE: usize = 256;

/// Statistics for repair requester
#[derive(Debug, Clone)]
pub struct RepairRequesterStats {
    pub requests_sent: Arc<AtomicU64>,
    pub responses_received: Arc<AtomicU64>,
    pub errors_received: Arc<AtomicU64>,
    pub timeouts: Arc<AtomicU64>,
    pub shreds_received: Arc<AtomicU64>,
    pub bytes_sent: Arc<AtomicU64>,
    pub bytes_received: Arc<AtomicU64>,
}

impl RepairRequesterStats {
    pub fn new() -> Self {
        Self {
            requests_sent: Arc::new(AtomicU64::new(0)),
            responses_received: Arc::new(AtomicU64::new(0)),
            errors_received: Arc::new(AtomicU64::new(0)),
            timeouts: Arc::new(AtomicU64::new(0)),
            shreds_received: Arc::new(AtomicU64::new(0)),
            bytes_sent: Arc::new(AtomicU64::new(0)),
            bytes_received: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl Default for RepairRequesterStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Pending repair request
struct PendingRequest {
    created_at: Instant,
    response_tx: oneshot::Sender<RepairResponse>,
}

/// Repair requester for sending repair requests to peers
pub struct RepairRequester {
    node_id: NodeId,
    cluster_info: Arc<ClusterInfo>,
    socket: Arc<UdpSocket>,
    stats: RepairRequesterStats,
    nonce_counter: Arc<AtomicU64>,
    pending_requests: Arc<parking_lot::RwLock<HashMap<u64, PendingRequest>>>,
    request_timeout: Duration,
    request_tx: mpsc::Sender<(RepairRequest, SocketAddr, oneshot::Sender<RepairResponse>)>,
    request_rx:
        Option<mpsc::Receiver<(RepairRequest, SocketAddr, oneshot::Sender<RepairResponse>)>>,
}

impl RepairRequester {
    pub fn new(node_id: NodeId, cluster_info: Arc<ClusterInfo>, socket: Arc<UdpSocket>) -> Self {
        let (request_tx, request_rx) = mpsc::channel(REPAIR_REQUEST_CHANNEL_SIZE);

        Self {
            node_id,
            cluster_info,
            socket,
            stats: RepairRequesterStats::new(),
            nonce_counter: Arc::new(AtomicU64::new(0)),
            pending_requests: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            request_timeout: Duration::from_millis(DEFAULT_REPAIR_TIMEOUT_MS),
            request_tx,
            request_rx: Some(request_rx),
        }
    }

    pub fn stats(&self) -> &RepairRequesterStats {
        &self.stats
    }

    pub fn get_request_sender(
        &self,
    ) -> mpsc::Sender<(RepairRequest, SocketAddr, oneshot::Sender<RepairResponse>)> {
        self.request_tx.clone()
    }

    /// Start the repair requester
    pub async fn start(&mut self) -> RepairResult<()> {
        let request_rx = self
            .request_rx
            .take()
            .ok_or_else(|| IngressError::Configuration {
                detail: "repair requester already started".to_string(),
            })?;

        let send_socket = Arc::clone(&self.socket);
        let send_stats = self.stats.clone();
        let send_pending = Arc::clone(&self.pending_requests);

        tokio::spawn(async move {
            Self::send_loop(send_socket, send_stats, send_pending, request_rx).await;
        });

        let recv_socket = Arc::clone(&self.socket);
        let recv_stats = self.stats.clone();
        let recv_pending = Arc::clone(&self.pending_requests);

        tokio::spawn(async move {
            Self::receive_loop(recv_socket, recv_stats, recv_pending).await;
        });

        let cleanup_pending = Arc::clone(&self.pending_requests);
        let cleanup_stats = self.stats.clone();
        let request_timeout = self.request_timeout;

        tokio::spawn(async move {
            Self::cleanup_loop(cleanup_pending, cleanup_stats, request_timeout).await;
        });

        Ok(())
    }

    /// Request a specific shred
    pub async fn request_shred(
        &self,
        target: SocketAddr,
        slot: Slot,
        index: ShredIndex,
    ) -> RepairResult<Option<ShredData>> {
        let nonce = self.next_nonce();
        let request = RepairRequest::Shred {
            requester: self.node_id,
            slot,
            index,
            nonce,
        };

        let response = self.send_request(request, target).await?;

        match response {
            RepairResponse::Shred { shred, .. } => Ok(shred),
            RepairResponse::Error { message, .. } => {
                Err(IngressError::RepairRequest { detail: message })
            }
            _ => Err(IngressError::RepairRequest {
                detail: "unexpected response type".to_string(),
            }),
        }
    }

    /// Request highest shred index for a slot
    pub async fn request_highest_shred(
        &self,
        target: SocketAddr,
        slot: Slot,
    ) -> RepairResult<Option<ShredIndex>> {
        let nonce = self.next_nonce();
        let request = RepairRequest::HighestShred {
            requester: self.node_id,
            slot,
            nonce,
        };

        let response = self.send_request(request, target).await?;

        match response {
            RepairResponse::HighestShred { index, .. } => Ok(index),
            RepairResponse::Error { message, .. } => {
                Err(IngressError::RepairRequest { detail: message })
            }
            _ => Err(IngressError::RepairRequest {
                detail: "unexpected response type".to_string(),
            }),
        }
    }

    /// Request shreds in a slot range
    pub async fn request_slot_range(
        &self,
        target: SocketAddr,
        start_slot: Slot,
        end_slot: Slot,
    ) -> RepairResult<Vec<ShredData>> {
        let nonce = self.next_nonce();
        let request = RepairRequest::SlotRange {
            requester: self.node_id,
            start_slot,
            end_slot,
            nonce,
        };

        let response = self.send_request(request, target).await?;

        match response {
            RepairResponse::Shreds { shreds, .. } => Ok(shreds),
            RepairResponse::Error { message, .. } => {
                Err(IngressError::RepairRequest { detail: message })
            }
            _ => Err(IngressError::RepairRequest {
                detail: "unexpected response type".to_string(),
            }),
        }
    }

    /// Request ancestor chain
    pub async fn request_ancestor(
        &self,
        target: SocketAddr,
        slot: Slot,
        ancestors: u64,
    ) -> RepairResult<Vec<ShredData>> {
        let nonce = self.next_nonce();
        let request = RepairRequest::Ancestor {
            requester: self.node_id,
            slot,
            ancestors,
            nonce,
        };

        let response = self.send_request(request, target).await?;

        match response {
            RepairResponse::Shreds { shreds, .. } => Ok(shreds),
            RepairResponse::Error { message, .. } => {
                Err(IngressError::RepairRequest { detail: message })
            }
            _ => Err(IngressError::RepairRequest {
                detail: "unexpected response type".to_string(),
            }),
        }
    }

    async fn send_request(
        &self,
        request: RepairRequest,
        target: SocketAddr,
    ) -> RepairResult<RepairResponse> {
        let (response_tx, response_rx) = oneshot::channel();

        self.request_tx
            .send((request, target, response_tx))
            .await
            .map_err(|_| IngressError::RepairRequest {
                detail: "failed to queue request".to_string(),
            })?;

        match timeout(self.request_timeout, response_rx).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => Err(IngressError::RepairRequest {
                detail: "response channel closed".to_string(),
            }),
            Err(_) => {
                self.stats.timeouts.fetch_add(1, Ordering::Relaxed);
                Err(IngressError::RepairRequest {
                    detail: "request timeout".to_string(),
                })
            }
        }
    }

    async fn send_loop(
        socket: Arc<UdpSocket>,
        stats: RepairRequesterStats,
        pending: Arc<parking_lot::RwLock<HashMap<u64, PendingRequest>>>,
        mut request_rx: mpsc::Receiver<(
            RepairRequest,
            SocketAddr,
            oneshot::Sender<RepairResponse>,
        )>,
    ) {
        while let Some((request, target, response_tx)) = request_rx.recv().await {
            let nonce = request.nonce();

            let message = RepairMessage::Request(request);
            match message.encode() {
                Ok(encoded) => {
                    if let Ok(_) = socket.send_to(&encoded, target).await {
                        stats.requests_sent.fetch_add(1, Ordering::Relaxed);
                        stats
                            .bytes_sent
                            .fetch_add(encoded.len() as u64, Ordering::Relaxed);

                        let mut pending_map = pending.write();
                        if pending_map.len() < MAX_PENDING_REQUESTS {
                            pending_map.insert(
                                nonce,
                                PendingRequest {
                                    created_at: Instant::now(),
                                    response_tx,
                                },
                            );
                        }
                    }
                }
                Err(_) => {}
            }
        }
    }

    async fn receive_loop(
        socket: Arc<UdpSocket>,
        stats: RepairRequesterStats,
        pending: Arc<parking_lot::RwLock<HashMap<u64, PendingRequest>>>,
    ) {
        let mut buf = vec![0u8; 65536];

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, _src_addr)) => {
                    stats
                        .bytes_received
                        .fetch_add(len as u64, Ordering::Relaxed);

                    let data = bytes::Bytes::copy_from_slice(&buf[..len]);
                    if let Ok(RepairMessage::Response(response)) = RepairMessage::decode(data) {
                        let nonce = response.nonce();

                        if let Some(pending_req) = pending.write().remove(&nonce) {
                            if response.is_error() {
                                stats.errors_received.fetch_add(1, Ordering::Relaxed);
                            } else {
                                stats.responses_received.fetch_add(1, Ordering::Relaxed);

                                if let RepairResponse::Shred { ref shred, .. } = response {
                                    if shred.is_some() {
                                        stats.shreds_received.fetch_add(1, Ordering::Relaxed);
                                    }
                                } else if let RepairResponse::Shreds { ref shreds, .. } = response {
                                    stats
                                        .shreds_received
                                        .fetch_add(shreds.len() as u64, Ordering::Relaxed);
                                }
                            }

                            let _ = pending_req.response_tx.send(response);
                        }
                    }
                }
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    }

    async fn cleanup_loop(
        pending: Arc<parking_lot::RwLock<HashMap<u64, PendingRequest>>>,
        stats: RepairRequesterStats,
        timeout_duration: Duration,
    ) {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;

            let now = Instant::now();
            let mut pending_map = pending.write();

            pending_map.retain(|_, req| {
                let is_expired = now.duration_since(req.created_at) > timeout_duration;
                if is_expired {
                    stats.timeouts.fetch_add(1, Ordering::Relaxed);
                }
                !is_expired
            });
        }
    }

    fn next_nonce(&self) -> u64 {
        self.nonce_counter.fetch_add(1, Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_requester_stats() {
        let stats = RepairRequesterStats::new();
        stats.requests_sent.fetch_add(5, Ordering::Relaxed);
        stats.responses_received.fetch_add(3, Ordering::Relaxed);

        assert_eq!(stats.requests_sent.load(Ordering::Relaxed), 5);
        assert_eq!(stats.responses_received.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn test_requester_nonce() {
        let node_id = NodeId::new([1u8; 32]);
        let cluster_info = Arc::new(ClusterInfo::new(
            node_id,
            create_test_contact_info(node_id),
            Duration::from_secs(30),
            1000,
        ));
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

        let requester = RepairRequester::new(node_id, cluster_info, socket);

        let nonce1 = requester.next_nonce();
        let nonce2 = requester.next_nonce();

        assert_eq!(nonce2, nonce1 + 1);
    }

    fn create_test_contact_info(node_id: NodeId) -> crate::gossip::ContactInfo {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8000);
        crate::gossip::ContactInfo::new(node_id, addr, addr, addr, addr, 1)
    }
}
