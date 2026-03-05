/// TLS configuration shared across multiple handshakes.
///
/// Contains the local identity (keys, certificates), cryptographic parameters,
/// and callback functions. A single config is typically shared by all connections
/// on a tile.
use crate::tls::handshake::EncryptionLevel;

/// Maximum ALPN protocol identifier length.
const MAX_ALPN_SIZE: usize = 32;

/// TLS configuration for the local endpoint.
///
/// Shared across all handshakes. Contains identity keys and callbacks.
pub struct TlsConfig {
    /// X25519 private key for key exchange.
    pub kex_private_key: [u8; 32],
    /// X25519 public key (derived from private key).
    pub kex_public_key: [u8; 32],
    /// Ed25519 public key for peer authentication.
    pub cert_public_key: [u8; 32],
    /// ALPN protocol identifier (length-prefixed).
    pub alpn: [u8; MAX_ALPN_SIZE],
    /// Actual length of ALPN data.
    pub alpn_len: usize,
    /// Whether QUIC mode is enabled (mandates transport params exchange).
    pub quic_mode: bool,
    /// Callback interface for handshake events.
    pub callbacks: Box<dyn TlsCallbacks>,
}

impl TlsConfig {
    /// Create a new TLS config with the given keys and callbacks.
    pub fn new(
        kex_private: [u8; 32],
        kex_public: [u8; 32],
        cert_public: [u8; 32],
        callbacks: Box<dyn TlsCallbacks>,
    ) -> Self {
        Self {
            kex_private_key: kex_private,
            kex_public_key: kex_public,
            cert_public_key: cert_public,
            alpn: [0; MAX_ALPN_SIZE],
            alpn_len: 0,
            quic_mode: true,
            callbacks,
        }
    }

    /// Set the ALPN protocol identifier.
    ///
    /// `alpn` should be in the TLS ALPN wire format: length-prefixed ASCII.
    pub fn set_alpn(&mut self, alpn: &[u8]) {
        let len = alpn.len().min(MAX_ALPN_SIZE);
        self.alpn[..len].copy_from_slice(&alpn[..len]);
        self.alpn_len = len;
    }

    /// Get the ALPN bytes.
    pub fn alpn_bytes(&self) -> &[u8] {
        &self.alpn[..self.alpn_len]
    }
}

/// Callbacks invoked during TLS handshake.
///
/// These decouple the TLS state machine from transport and application logic.
pub trait TlsCallbacks: Send {
    /// New encryption secrets are available.
    ///
    /// Called for each encryption level (Handshake, Application).
    /// `recv_secret` is for decrypting incoming data,
    /// `send_secret` is for encrypting outgoing data.
    fn on_secrets(
        &self,
        handshake: *const (),
        recv_secret: &[u8; 32],
        send_secret: &[u8; 32],
        level: EncryptionLevel,
    );

    /// Send a TLS message to the peer.
    ///
    /// `msg` contains the complete TLS message (header + body).
    /// `level` indicates the encryption level for this message.
    /// `flush` hints that no more messages will follow immediately.
    /// Returns `true` on success, `false` on failure.
    fn on_send_message(
        &self,
        handshake: *const (),
        msg: &[u8],
        level: EncryptionLevel,
        flush: bool,
    ) -> bool;

    /// Get our QUIC transport parameters to send to the peer.
    ///
    /// Writes encoded transport parameters into `buf`.
    /// Returns the number of bytes written, or `None` on error.
    fn quic_transport_params(&self, handshake: *const (), buf: &mut [u8]) -> Option<usize>;

    /// Receive the peer's QUIC transport parameters.
    fn on_peer_transport_params(&self, handshake: *const (), params: &[u8]);

    /// Sign a TLS 1.3 CertificateVerify payload.
    ///
    /// `payload` is the 130-byte message to sign (64 spaces + context string + 0x00 + transcript hash).
    /// Returns the 64-byte Ed25519 signature.
    fn sign(&self, payload: &[u8; 130]) -> [u8; 64];

    /// Generate cryptographically secure random bytes.
    ///
    /// Fills `buf` with random data. Returns `true` on success.
    fn random(&self, buf: &mut [u8]) -> bool;
}

/// No-op TLS callbacks for testing.
pub struct NoopCallbacks;

impl TlsCallbacks for NoopCallbacks {
    fn on_secrets(
        &self,
        _handshake: *const (),
        _recv_secret: &[u8; 32],
        _send_secret: &[u8; 32],
        _level: EncryptionLevel,
    ) {
    }

    fn on_send_message(
        &self,
        _handshake: *const (),
        _msg: &[u8],
        _level: EncryptionLevel,
        _flush: bool,
    ) -> bool {
        true
    }

    fn quic_transport_params(&self, _handshake: *const (), _buf: &mut [u8]) -> Option<usize> {
        Some(0)
    }

    fn on_peer_transport_params(&self, _handshake: *const (), _params: &[u8]) {}

    fn sign(&self, _payload: &[u8; 130]) -> [u8; 64] {
        [0; 64]
    }

    fn random(&self, buf: &mut [u8]) -> bool {
        use rand::RngCore;
        rand::thread_rng().fill_bytes(buf);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_creation() {
        let config = TlsConfig::new([0x01; 32], [0x02; 32], [0x03; 32], Box::new(NoopCallbacks));
        assert!(config.quic_mode);
        assert_eq!(config.alpn_len, 0);
    }

    #[test]
    fn config_set_alpn() {
        let mut config =
            TlsConfig::new([0x01; 32], [0x02; 32], [0x03; 32], Box::new(NoopCallbacks));
        config.set_alpn(b"\x0asolana-tpu");
        assert_eq!(config.alpn_len, 11);
        assert_eq!(config.alpn_bytes(), b"\x0asolana-tpu");
    }

    #[test]
    fn noop_callbacks_work() {
        let cb = NoopCallbacks;
        assert!(cb.on_send_message(std::ptr::null(), b"test", EncryptionLevel::Initial, true,));
        assert!(cb.random(&mut [0u8; 32]));
    }
}
