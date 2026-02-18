use serde::Deserialize;

/// Network configuration from TOML profile.
#[derive(Debug, Default, Deserialize)]
pub struct NetworkProfileToml {
    /// Transport backend: "udp" or "xdp".
    pub transport: Option<String>,
    /// Bind address for QUIC listener (e.g., "0.0.0.0").
    pub bind_address: Option<String>,
    /// QUIC listen port (TPU).
    pub quic_port: Option<u16>,
    /// Maximum concurrent QUIC connections.
    pub max_connections: Option<usize>,
    /// Maximum streams per connection.
    pub max_streams_per_connection: Option<usize>,
    /// Connection idle timeout in milliseconds.
    pub idle_timeout_ms: Option<u64>,
    /// Enable stateless retry tokens.
    pub enable_retry: Option<bool>,
    /// Network interface name (for XDP backend).
    pub interface: Option<String>,
    /// NIC queue index (for XDP backend).
    pub queue_id: Option<u32>,
    /// CPU affinity for network tile.
    pub net_tile_cpu: Option<usize>,
    /// CPU affinity for QUIC tile.
    pub quic_tile_cpu: Option<usize>,
}

/// Parsed network configuration.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Transport backend type.
    pub transport: NetworkTransport,
    /// Bind address (IPv4 string).
    pub bind_address: String,
    /// QUIC listen port.
    pub quic_port: u16,
    /// Maximum concurrent QUIC connections.
    pub max_connections: usize,
    /// Maximum streams per connection.
    pub max_streams_per_connection: usize,
    /// Connection idle timeout in milliseconds.
    pub idle_timeout_ms: u64,
    /// Enable stateless retry tokens.
    pub enable_retry: bool,
    /// Network interface name (for XDP).
    pub interface: String,
    /// NIC queue index (for XDP).
    pub queue_id: u32,
    /// CPU affinity for network tile.
    pub net_tile_cpu: Option<usize>,
    /// CPU affinity for QUIC tile.
    pub quic_tile_cpu: Option<usize>,
}

/// Network transport backend selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkTransport {
    Udp,
    Xdp,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            transport: NetworkTransport::Udp,
            bind_address: "0.0.0.0".to_string(),
            quic_port: 8003,
            max_connections: 1024,
            max_streams_per_connection: 128,
            idle_timeout_ms: 10_000,
            enable_retry: true,
            interface: String::new(),
            queue_id: 0,
            net_tile_cpu: None,
            quic_tile_cpu: None,
        }
    }
}

pub fn build_network_config(profile: Option<&NetworkProfileToml>) -> NetworkConfig {
    let mut config = NetworkConfig::default();

    if let Some(p) = profile {
        if let Some(ref t) = p.transport {
            config.transport = match t.as_str() {
                "xdp" => NetworkTransport::Xdp,
                _ => NetworkTransport::Udp,
            };
        }
        if let Some(ref addr) = p.bind_address {
            config.bind_address = addr.clone();
        }
        if let Some(port) = p.quic_port {
            config.quic_port = port;
        }
        if let Some(mc) = p.max_connections {
            config.max_connections = mc;
        }
        if let Some(ms) = p.max_streams_per_connection {
            config.max_streams_per_connection = ms;
        }
        if let Some(timeout) = p.idle_timeout_ms {
            config.idle_timeout_ms = timeout;
        }
        if let Some(retry) = p.enable_retry {
            config.enable_retry = retry;
        }
        if let Some(ref iface) = p.interface {
            config.interface = iface.clone();
        }
        if let Some(qid) = p.queue_id {
            config.queue_id = qid;
        }
        config.net_tile_cpu = p.net_tile_cpu;
        config.quic_tile_cpu = p.quic_tile_cpu;
    }

    config
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let config = NetworkConfig::default();
        assert_eq!(config.transport, NetworkTransport::Udp);
        assert_eq!(config.quic_port, 8003);
        assert_eq!(config.max_connections, 1024);
        assert!(config.enable_retry);
    }

    #[test]
    fn build_from_none() {
        let config = build_network_config(None);
        assert_eq!(config.transport, NetworkTransport::Udp);
    }

    #[test]
    fn build_from_profile() {
        let profile = NetworkProfileToml {
            transport: Some("xdp".to_string()),
            quic_port: Some(9000),
            max_connections: Some(2048),
            enable_retry: Some(false),
            interface: Some("eth0".to_string()),
            ..Default::default()
        };
        let config = build_network_config(Some(&profile));
        assert_eq!(config.transport, NetworkTransport::Xdp);
        assert_eq!(config.quic_port, 9000);
        assert_eq!(config.max_connections, 2048);
        assert!(!config.enable_retry);
        assert_eq!(config.interface, "eth0");
    }

    #[test]
    fn build_with_cpu_affinity() {
        let profile = NetworkProfileToml {
            net_tile_cpu: Some(2),
            quic_tile_cpu: Some(3),
            ..Default::default()
        };
        let config = build_network_config(Some(&profile));
        assert_eq!(config.net_tile_cpu, Some(2));
        assert_eq!(config.quic_tile_cpu, Some(3));
    }
}
