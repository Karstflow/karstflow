use super::*;
use crate::gossip::{ClusterInfo, NodeId};
use crate::repair::request::RepairRequester;
use crate::repair::server::{RepairServer, RepairServerConfig, ShredProvider};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

/// Configuration for repair service
#[derive(Debug, Clone)]
pub struct RepairServiceConfig {
    pub requester_bind_addr: SocketAddr,
    pub server_config: RepairServerConfig,
}

impl Default for RepairServiceConfig {
    fn default() -> Self {
        Self {
            requester_bind_addr: "0.0.0.0:0".parse().unwrap(),
            server_config: RepairServerConfig::default(),
        }
    }
}

/// Combined repair service with requester and server
pub struct RepairService {
    node_id: NodeId,
    requester: RepairRequester,
    server: RepairServer,
}

impl RepairService {
    pub async fn new(
        node_id: NodeId,
        cluster_info: Arc<ClusterInfo>,
        config: RepairServiceConfig,
        shred_provider: Arc<dyn ShredProvider>,
    ) -> RepairResult<Self> {
        let requester_socket = UdpSocket::bind(config.requester_bind_addr)
            .await
            .map_err(|e| IngressError::QuicEndpointBind {
                detail: format!("failed to bind repair requester socket: {}", e),
            })?;

        let requester = RepairRequester::new(node_id, cluster_info, Arc::new(requester_socket));

        let server = RepairServer::new(node_id, config.server_config, shred_provider).await?;

        Ok(Self {
            node_id,
            requester,
            server,
        })
    }

    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    pub fn requester(&self) -> &RepairRequester {
        &self.requester
    }

    pub fn server(&self) -> &RepairServer {
        &self.server
    }

    /// Start both requester and server
    pub async fn start(&mut self) -> RepairResult<()> {
        self.requester.start().await?;
        self.server.start().await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gossip::ContactInfo;
    use crate::repair::server::InMemoryShredStore;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    fn create_test_contact_info(node_id: NodeId) -> ContactInfo {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8000);
        ContactInfo::new(node_id, addr, addr, addr, addr, 1)
    }

    #[tokio::test]
    async fn test_repair_service_creation() {
        let node_id = NodeId::random();
        let contact_info = create_test_contact_info(node_id);
        let cluster_info = Arc::new(ClusterInfo::new(
            node_id,
            contact_info,
            Duration::from_secs(30),
            1000,
        ));

        let config = RepairServiceConfig {
            requester_bind_addr: "127.0.0.1:0".parse().unwrap(),
            server_config: RepairServerConfig {
                bind_addr: "127.0.0.1:0".parse().unwrap(),
                ..RepairServerConfig::default()
            },
        };

        let shred_provider = Arc::new(InMemoryShredStore::new());

        let service = RepairService::new(node_id, cluster_info, config, shred_provider).await;
        assert!(service.is_ok());
    }
}
