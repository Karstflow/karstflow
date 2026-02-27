use super::*;
use crate::gossip::{ClusterInfo, NodeId};
use crate::repair::nonce::{current_time_ns, RepairNonceGenerator};
use crate::repair::protocol::{RepairRequest, RepairRequestType, RepairResponse, ShredData};
use crate::repair::wire::convert;
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

/// Pending repair request with metadata for response reconstruction.
///
/// Wire responses are raw shred bytes + nonce — the requester must remember
/// what was asked for (slot, index, type) to reconstruct an internal response.
struct PendingRequest {
    created_at: Instant,
    request_type: RepairRequestType,
    slot: Slot,
    index: ShredIndex,
    response_tx: oneshot::Sender<RepairResponse>,
}

/// Repair requester for sending repair requests to peers.
///
/// Sends wire-compatible repair requests signed with the node's Ed25519 key.
/// Responses are raw shred payloads with a u32 nonce appended.
///
/// Nonces are computed from a keyed SHA-256 hash of (slot, shred_index, time),
/// tying each nonce to its request parameters for response validation.
pub struct RepairRequester {
    node_id: NodeId,
    cluster_info: Arc<ClusterInfo>,
    socket: Arc<UdpSocket>,
    stats: RepairRequesterStats,
    nonce_gen: RepairNonceGenerator,
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
            nonce_gen: RepairNonceGenerator::new(),
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
        let send_cluster_info = Arc::clone(&self.cluster_info);

        tokio::spawn(async move {
            Self::send_loop(
                send_socket,
                send_stats,
                send_pending,
                send_cluster_info,
                request_rx,
            )
            .await;
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
        let nonce = self
            .nonce_gen
            .compute_shred_nonce(slot, index, current_time_ns()) as u64;
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
        let nonce = self
            .nonce_gen
            .compute_shred_nonce(slot, 0, current_time_ns()) as u64;
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
        let nonce = self
            .nonce_gen
            .compute_shred_nonce(start_slot, 0, current_time_ns()) as u64;
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
        let nonce = self.nonce_gen.compute_orphan_nonce(slot, current_time_ns()) as u64;
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
        cluster_info: Arc<ClusterInfo>,
        mut request_rx: mpsc::Receiver<(
            RepairRequest,
            SocketAddr,
            oneshot::Sender<RepairResponse>,
        )>,
    ) {
        while let Some((request, target, response_tx)) = request_rx.recv().await {
            let nonce = request.nonce();
            let request_type = request.request_type();
            let (slot, index) = extract_slot_index(&request);

            // Convert to wire format and sign.
            // Look up recipient pubkey from ClusterInfo by repair SocketAddr.
            let recipient = cluster_info
                .lookup_by_repair_addr(&target)
                .map(|id| id.0)
                .unwrap_or([0u8; 32]);
            let mut wire_msg = match convert::request_to_wire(&request, recipient) {
                Some(msg) => msg,
                None => continue, // SlotRange not representable
            };

            if let Some(key) = cluster_info.signing_key() {
                wire_msg.sign(key);
            }

            if let Ok(encoded) = wire_msg.encode() {
                if (socket.send_to(&encoded, target).await).is_ok() {
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
                                request_type,
                                slot,
                                index,
                                response_tx,
                            },
                        );
                    }
                }
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

                    let data = &buf[..len];

                    // Wire responses are raw shred bytes + u32 nonce appended at end.
                    // Extract nonce, match to pending request, reconstruct response.
                    if let Some((payload, nonce_u32)) = convert::wire_response_to_shred(data) {
                        let nonce = nonce_u32 as u64;

                        if let Some(pending_req) = pending.write().remove(&nonce) {
                            stats.responses_received.fetch_add(1, Ordering::Relaxed);

                            let response = reconstruct_response(&pending_req, payload, nonce);

                            if let RepairResponse::Shred { shred: Some(_), .. } = &response {
                                stats.shreds_received.fetch_add(1, Ordering::Relaxed);
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

    /// Access the nonce generator (for tests).
    #[cfg(test)]
    fn nonce_gen(&self) -> &RepairNonceGenerator {
        &self.nonce_gen
    }
}

/// Extract slot and shred index from a repair request.
fn extract_slot_index(request: &RepairRequest) -> (Slot, ShredIndex) {
    match request {
        RepairRequest::Shred { slot, index, .. } => (*slot, *index),
        RepairRequest::HighestShred { slot, .. } => (*slot, 0),
        RepairRequest::SlotRange { start_slot, .. } => (*start_slot, 0),
        RepairRequest::Orphan { slot, .. } => (*slot, 0),
        RepairRequest::Ancestor { slot, .. } => (*slot, 0),
    }
}

/// Reconstruct an internal RepairResponse from wire response payload.
///
/// Parses the raw shred bytes to extract slot, index, and is_last_in_slot
/// from the shred header. Falls back to pending request metadata if the
/// payload can't be parsed (too short, coding shred, etc.).
fn reconstruct_response(pending: &PendingRequest, payload: Vec<u8>, nonce: u64) -> RepairResponse {
    let responder = NodeId::new([0u8; 32]); // Wire responses don't carry responder ID

    match pending.request_type {
        RepairRequestType::Shred => {
            if payload.is_empty() {
                RepairResponse::Shred {
                    responder,
                    shred: None,
                    nonce,
                }
            } else {
                let (slot, index, is_last) =
                    parse_shred_header(&payload).unwrap_or((pending.slot, pending.index, false));
                RepairResponse::Shred {
                    responder,
                    shred: Some(ShredData::new(slot, index, payload, is_last)),
                    nonce,
                }
            }
        }
        RepairRequestType::HighestShred => {
            // HighestWindowIndex returns the highest shred for the slot.
            if payload.is_empty() {
                RepairResponse::HighestShred {
                    responder,
                    slot: pending.slot,
                    index: None,
                    nonce,
                }
            } else {
                let (slot, index, is_last) =
                    parse_shred_header(&payload).unwrap_or((pending.slot, 0, false));
                RepairResponse::Shred {
                    responder,
                    shred: Some(ShredData::new(slot, index, payload, is_last)),
                    nonce,
                }
            }
        }
        RepairRequestType::Orphan => {
            // Orphan returns ancestor shreds.
            if payload.is_empty() {
                RepairResponse::Shreds {
                    responder,
                    shreds: vec![],
                    nonce,
                }
            } else {
                let (slot, index, is_last) =
                    parse_shred_header(&payload).unwrap_or((pending.slot, 0, false));
                RepairResponse::Shreds {
                    responder,
                    shreds: vec![ShredData::new(slot, index, payload, is_last)],
                    nonce,
                }
            }
        }
        RepairRequestType::Ancestor => {
            // AncestorHashes returns bincode-serialized Vec<(Slot, Hash)> + nonce.
            // Wrap as raw data — the caller decodes the ancestor hash response.
            RepairResponse::Shreds {
                responder,
                shreds: vec![ShredData::new(pending.slot, 0, payload, false)],
                nonce,
            }
        }
        RepairRequestType::SlotRange => {
            // SlotRange has no wire equivalent, should not reach here.
            RepairResponse::Error {
                responder,
                error_code: 400,
                message: "SlotRange not supported in wire protocol".to_string(),
                nonce,
            }
        }
    }
}

/// Parse raw shred bytes to extract slot, index, and is_last_in_slot.
///
/// Returns `None` if the payload is too short or not a valid shred
/// (e.g., corrupted data). The caller should fall back to request metadata.
fn parse_shred_header(payload: &[u8]) -> Option<(Slot, ShredIndex, bool)> {
    use paradencer_types::shred::ShredParser;
    let shred = ShredParser::parse(payload).ok()?;
    Some((shred.slot(), shred.index(), shred.is_last_in_slot()))
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
    async fn test_requester_nonce_keyed() {
        let node_id = NodeId::new([1u8; 32]);
        let cluster_info = Arc::new(ClusterInfo::new(
            node_id,
            create_test_contact_info(node_id),
            Duration::from_secs(30),
            1000,
        ));
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

        let requester = RepairRequester::new(node_id, cluster_info, socket);

        let t = super::super::nonce::current_time_ns();
        let n1 = requester.nonce_gen().compute_shred_nonce(100, 0, t);
        let n2 = requester.nonce_gen().compute_shred_nonce(101, 0, t);

        assert!(n1 > 0, "nonce should be nonzero");
        assert_ne!(n1, n2, "different params should produce different nonces");
    }

    #[test]
    fn test_extract_slot_index() {
        let node = NodeId::new([1u8; 32]);
        assert_eq!(
            extract_slot_index(&RepairRequest::Shred {
                requester: node,
                slot: 100,
                index: 5,
                nonce: 0,
            }),
            (100, 5)
        );
        assert_eq!(
            extract_slot_index(&RepairRequest::HighestShred {
                requester: node,
                slot: 200,
                nonce: 0,
            }),
            (200, 0)
        );
        assert_eq!(
            extract_slot_index(&RepairRequest::Orphan {
                requester: node,
                slot: 300,
                nonce: 0,
            }),
            (300, 0)
        );
    }

    #[test]
    fn test_reconstruct_shred_response() {
        let pending = PendingRequest {
            created_at: Instant::now(),
            request_type: RepairRequestType::Shred,
            slot: 100,
            index: 5,
            response_tx: oneshot::channel().0,
        };

        let response = reconstruct_response(&pending, vec![1, 2, 3], 42);
        if let RepairResponse::Shred {
            shred: Some(shred),
            nonce,
            ..
        } = response
        {
            assert_eq!(shred.slot, 100);
            assert_eq!(shred.index, 5);
            assert_eq!(shred.data, vec![1, 2, 3]);
            assert_eq!(nonce, 42);
        } else {
            panic!("expected Shred response");
        }
    }

    #[test]
    fn test_reconstruct_empty_response() {
        let pending = PendingRequest {
            created_at: Instant::now(),
            request_type: RepairRequestType::Shred,
            slot: 100,
            index: 5,
            response_tx: oneshot::channel().0,
        };

        let response = reconstruct_response(&pending, vec![], 42);
        if let RepairResponse::Shred {
            shred: None, nonce, ..
        } = response
        {
            assert_eq!(nonce, 42);
        } else {
            panic!("expected Shred None response");
        }
    }

    /// Build a minimal legacy data shred for testing.
    fn build_test_shred(slot: u64, index: u32, is_last: bool) -> Vec<u8> {
        use paradencer_types::shred::{
            SHRED_LAST_IN_SLOT, SHRED_LEGACY_DATA_NIBBLE, SHRED_TYPE_LEGACY_DATA, SIGNATURE_SIZE,
        };
        let variant_byte = SHRED_TYPE_LEGACY_DATA | SHRED_LEGACY_DATA_NIBBLE;
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; SIGNATURE_SIZE]); // signature
        buf.push(variant_byte);
        buf.extend_from_slice(&slot.to_le_bytes());
        buf.extend_from_slice(&index.to_le_bytes());
        buf.extend_from_slice(&1u16.to_le_bytes()); // version
        buf.extend_from_slice(&0u32.to_le_bytes()); // fec_set_index
                                                    // Data header
        buf.extend_from_slice(&1u16.to_le_bytes()); // parent_offset
        let flags = if is_last { SHRED_LAST_IN_SLOT } else { 0 };
        buf.push(flags);
        buf.extend_from_slice(&64u16.to_le_bytes()); // size
                                                     // Payload
        buf.extend_from_slice(&[0xAB; 64]);
        buf
    }

    #[test]
    fn test_parse_shred_header_extracts_fields() {
        let payload = build_test_shred(500, 42, false);
        let (slot, index, is_last) = parse_shred_header(&payload).unwrap();
        assert_eq!(slot, 500);
        assert_eq!(index, 42);
        assert!(!is_last);
    }

    #[test]
    fn test_parse_shred_header_last_in_slot() {
        let payload = build_test_shred(999, 10, true);
        let (slot, index, is_last) = parse_shred_header(&payload).unwrap();
        assert_eq!(slot, 999);
        assert_eq!(index, 10);
        assert!(is_last);
    }

    #[test]
    fn test_parse_shred_header_too_short_falls_back() {
        // A payload too short to parse should return None.
        assert!(parse_shred_header(&[1, 2, 3]).is_none());
        assert!(parse_shred_header(&[]).is_none());
    }

    #[test]
    fn test_reconstruct_parses_shred_header() {
        let payload = build_test_shred(777, 33, true);
        let pending = PendingRequest {
            created_at: Instant::now(),
            request_type: RepairRequestType::Shred,
            slot: 0,  // wrong — should be overridden by parsed value
            index: 0, // wrong — should be overridden by parsed value
            response_tx: oneshot::channel().0,
        };

        let response = reconstruct_response(&pending, payload, 99);
        if let RepairResponse::Shred {
            shred: Some(shred),
            nonce,
            ..
        } = response
        {
            assert_eq!(shred.slot, 777);
            assert_eq!(shred.index, 33);
            assert!(shred.is_last_in_slot);
            assert_eq!(nonce, 99);
        } else {
            panic!("expected Shred response");
        }
    }

    #[test]
    fn test_reconstruct_highest_parses_header() {
        let payload = build_test_shred(555, 100, false);
        let pending = PendingRequest {
            created_at: Instant::now(),
            request_type: RepairRequestType::HighestShred,
            slot: 0,
            index: 0,
            response_tx: oneshot::channel().0,
        };

        let response = reconstruct_response(&pending, payload, 88);
        if let RepairResponse::Shred {
            shred: Some(shred), ..
        } = response
        {
            assert_eq!(shred.slot, 555);
            assert_eq!(shred.index, 100);
            assert!(!shred.is_last_in_slot);
        } else {
            panic!("expected Shred response with parsed header");
        }
    }

    #[test]
    fn test_reconstruct_orphan_parses_header() {
        let payload = build_test_shred(300, 7, true);
        let pending = PendingRequest {
            created_at: Instant::now(),
            request_type: RepairRequestType::Orphan,
            slot: 0,
            index: 0,
            response_tx: oneshot::channel().0,
        };

        let response = reconstruct_response(&pending, payload, 77);
        if let RepairResponse::Shreds { shreds, nonce, .. } = response {
            assert_eq!(shreds.len(), 1);
            assert_eq!(shreds[0].slot, 300);
            assert_eq!(shreds[0].index, 7);
            assert!(shreds[0].is_last_in_slot);
            assert_eq!(nonce, 77);
        } else {
            panic!("expected Shreds response");
        }
    }

    #[test]
    fn test_reconstruct_falls_back_on_invalid_payload() {
        // Non-parseable payload falls back to pending request metadata.
        let pending = PendingRequest {
            created_at: Instant::now(),
            request_type: RepairRequestType::Shred,
            slot: 200,
            index: 15,
            response_tx: oneshot::channel().0,
        };

        // 10 bytes is too short for a shred header.
        let response = reconstruct_response(&pending, vec![0xFF; 10], 55);
        if let RepairResponse::Shred {
            shred: Some(shred), ..
        } = response
        {
            assert_eq!(shred.slot, 200);
            assert_eq!(shred.index, 15);
            assert!(!shred.is_last_in_slot);
        } else {
            panic!("expected Shred response with fallback metadata");
        }
    }

    fn create_test_contact_info(node_id: NodeId) -> crate::gossip::ContactInfo {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8000);
        crate::gossip::ContactInfo::new(node_id, addr, addr, addr, addr, 1)
    }
}
