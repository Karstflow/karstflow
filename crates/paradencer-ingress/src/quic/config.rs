use super::*;
use quinn::crypto::rustls::QuicServerConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct QuicLimits {
    pub max_concurrent_connections: u32,
    pub max_concurrent_uni_streams: u64,
    pub max_concurrent_bi_streams: u64,
    pub max_idle_timeout: Duration,
    pub keep_alive_interval: Duration,
    pub max_packet_size: usize,
    pub initial_mtu: u16,
}

impl Default for QuicLimits {
    fn default() -> Self {
        Self {
            max_concurrent_connections: DEFAULT_MAX_CONCURRENT_CONNECTIONS,
            max_concurrent_uni_streams: DEFAULT_MAX_CONCURRENT_UNI_STREAMS,
            max_concurrent_bi_streams: DEFAULT_MAX_CONCURRENT_BI_STREAMS,
            max_idle_timeout: Duration::from_millis(DEFAULT_MAX_IDLE_TIMEOUT_MS),
            keep_alive_interval: Duration::from_millis(DEFAULT_KEEP_ALIVE_INTERVAL_MS),
            max_packet_size: DEFAULT_MAX_PACKET_SIZE,
            initial_mtu: DEFAULT_INITIAL_MTU,
        }
    }
}

#[derive(Clone)]
pub struct QuicConfig {
    pub bind_addr: SocketAddr,
    pub limits: QuicLimits,
    pub server_config: Arc<quinn::ServerConfig>,
}

impl QuicConfig {
    pub fn new(bind_addr: SocketAddr) -> QuicResult<Self> {
        let limits = QuicLimits::default();
        let server_config = Self::build_server_config(&limits)?;

        Ok(Self {
            bind_addr,
            limits,
            server_config: Arc::new(server_config),
        })
    }

    pub fn with_limits(bind_addr: SocketAddr, limits: QuicLimits) -> QuicResult<Self> {
        let server_config = Self::build_server_config(&limits)?;

        Ok(Self {
            bind_addr,
            limits,
            server_config: Arc::new(server_config),
        })
    }

    fn build_server_config(limits: &QuicLimits) -> QuicResult<quinn::ServerConfig> {
        let crypto = Self::build_self_signed_crypto()?;

        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_uni_streams(
            quinn::VarInt::from_u64(limits.max_concurrent_uni_streams).map_err(|_| {
                IngressError::QuicConfiguration {
                    detail: "invalid max_concurrent_uni_streams".to_string(),
                }
            })?,
        );
        transport.max_concurrent_bidi_streams(
            quinn::VarInt::from_u64(limits.max_concurrent_bi_streams).map_err(|_| {
                IngressError::QuicConfiguration {
                    detail: "invalid max_concurrent_bi_streams".to_string(),
                }
            })?,
        );
        transport.max_idle_timeout(Some(limits.max_idle_timeout.try_into().map_err(|_| {
            IngressError::QuicConfiguration {
                detail: "invalid idle timeout".to_string(),
            }
        })?));
        transport.keep_alive_interval(Some(limits.keep_alive_interval));
        transport.initial_mtu(limits.initial_mtu);

        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        server_config.transport_config(Arc::new(transport));

        Ok(server_config)
    }

    /// Create a config bound to localhost with an ephemeral port.
    pub fn for_testing() -> Self {
        // Ensure a crypto provider is installed for rustls
        let _ = rustls::crypto::ring::default_provider().install_default();
        Self::new("127.0.0.1:0".parse().unwrap()).expect("test QuicConfig creation failed")
    }

    fn build_self_signed_crypto() -> QuicResult<QuicServerConfig> {
        let cert = rcgen::generate_simple_self_signed(vec!["paradencer.local".to_string()])
            .map_err(|e| IngressError::QuicConfiguration {
                detail: format!("failed to generate self-signed cert: {}", e),
            })?;

        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.key_pair.serialize_der();

        let cert_chain = vec![rustls::pki_types::CertificateDer::from(cert_der)];
        let private_key = rustls::pki_types::PrivateKeyDer::try_from(key_der).map_err(|_| {
            IngressError::QuicConfiguration {
                detail: "failed to parse private key".to_string(),
            }
        })?;

        let rustls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .map_err(|e| IngressError::QuicConfiguration {
                detail: format!("failed to build rustls config: {}", e),
            })?;

        QuicServerConfig::try_from(rustls_config).map_err(|e| IngressError::QuicConfiguration {
            detail: format!("failed to build QUIC server config: {}", e),
        })
    }
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self::for_testing()
    }
}
