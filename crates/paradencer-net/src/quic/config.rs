/// QUIC engine configuration and resource limits.
///
/// Separates static resource limits (determined at allocation time) from
/// mutable runtime configuration. All resources are pre-allocated based
/// on limits — no dynamic allocation after engine initialization.
use paradencer_constants::network::{
    QUIC_DEFAULT_ACK_DELAY_NS, QUIC_DEFAULT_ACK_THRESHOLD, QUIC_DEFAULT_IDLE_TIMEOUT_NS,
    QUIC_DEFAULT_RETRY_TTL_NS, QUIC_DEFAULT_TLS_HS_TTL_NS,
};

/// Resource limits determining the engine's memory footprint.
///
/// These are immutable after engine creation — changing them requires
/// creating a new engine.
#[derive(Debug, Clone)]
pub struct EngineLimits {
    /// Maximum concurrent connections.
    pub max_connections: usize,
    /// Maximum concurrent TLS handshakes (usually ≤ max_connections).
    pub max_handshakes: usize,
    /// Maximum connection IDs per connection (min 4).
    pub conn_ids_per_conn: usize,
    /// Maximum concurrent streams per connection.
    pub streams_per_conn: usize,
    /// TX buffer size per stream (bytes).
    pub tx_buf_size: usize,
    /// Total pre-allocated stream pool size.
    pub stream_pool_size: usize,
}

impl Default for EngineLimits {
    fn default() -> Self {
        Self {
            max_connections: 1024,
            max_handshakes: 256,
            conn_ids_per_conn: 4,
            streams_per_conn: 128,
            tx_buf_size: 4096,
            stream_pool_size: 4096,
        }
    }
}

impl EngineLimits {
    /// Validate limits for consistency.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.max_connections == 0 {
            return Err("max_connections must be > 0");
        }
        if self.conn_ids_per_conn < 4 {
            return Err("conn_ids_per_conn must be >= 4");
        }
        if self.streams_per_conn == 0 {
            return Err("streams_per_conn must be > 0");
        }
        if self.tx_buf_size == 0 {
            return Err("tx_buf_size must be > 0");
        }
        Ok(())
    }
}

/// Role of this QUIC endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineRole {
    Client,
    Server,
}

/// Mutable runtime configuration.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Endpoint role (client or server).
    pub role: EngineRole,
    /// Whether to use stateless retry for new connections (server only).
    pub enable_retry: bool,
    /// Connection idle timeout in nanoseconds (0 = disabled).
    pub idle_timeout_ns: u64,
    /// Median ACK delay in nanoseconds.
    pub ack_delay_ns: u64,
    /// Immediate ACK threshold in bytes.
    pub ack_threshold: u64,
    /// Retry token time-to-live in nanoseconds.
    pub retry_ttl_ns: u64,
    /// TLS handshake cache time-to-live in nanoseconds.
    pub tls_handshake_ttl_ns: u64,
    /// Initial per-stream RX buffer size for flow control.
    pub initial_rx_max_stream_data: u64,
    /// Initial connection-level RX flow control limit.
    pub initial_rx_max_data: u64,
    /// Initial max bidirectional streams the peer can open.
    pub initial_max_streams_bidi: u64,
    /// Initial max unidirectional streams the peer can open.
    pub initial_max_streams_uni: u64,
    /// Ed25519 identity public key (32 bytes).
    pub identity_public_key: [u8; 32],
    /// ALPN protocol name (e.g., "solana-tpu").
    pub alpn: Vec<u8>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            role: EngineRole::Server,
            enable_retry: true,
            idle_timeout_ns: QUIC_DEFAULT_IDLE_TIMEOUT_NS,
            ack_delay_ns: QUIC_DEFAULT_ACK_DELAY_NS,
            ack_threshold: QUIC_DEFAULT_ACK_THRESHOLD,
            retry_ttl_ns: QUIC_DEFAULT_RETRY_TTL_NS,
            tls_handshake_ttl_ns: QUIC_DEFAULT_TLS_HS_TTL_NS,
            initial_rx_max_stream_data: 65536,
            initial_rx_max_data: 1_048_576,
            initial_max_streams_bidi: 128,
            initial_max_streams_uni: 128,
            identity_public_key: [0; 32],
            alpn: b"solana-tpu".to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_limits_valid() {
        let limits = EngineLimits::default();
        assert!(limits.validate().is_ok());
    }

    #[test]
    fn zero_connections_rejected() {
        let limits = EngineLimits {
            max_connections: 0,
            ..Default::default()
        };
        assert!(limits.validate().is_err());
    }

    #[test]
    fn too_few_conn_ids_rejected() {
        let limits = EngineLimits {
            conn_ids_per_conn: 3,
            ..Default::default()
        };
        assert!(limits.validate().is_err());
    }

    #[test]
    fn default_config_values() {
        let config = EngineConfig::default();
        assert_eq!(config.role, EngineRole::Server);
        assert!(config.enable_retry);
        assert_eq!(config.idle_timeout_ns, QUIC_DEFAULT_IDLE_TIMEOUT_NS);
        assert_eq!(config.ack_delay_ns, QUIC_DEFAULT_ACK_DELAY_NS);
        assert_eq!(config.alpn, b"solana-tpu");
    }
}
