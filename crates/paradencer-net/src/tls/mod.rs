pub mod aead;
pub mod config;
pub mod handshake;
/// TLS 1.3 implementation for QUIC transport security.
///
/// Only supports the minimal cipher suite required by Solana:
/// - TLS_AES_128_GCM_SHA256
/// - X25519 key exchange
/// - Ed25519 authentication
/// - Raw public keys (RFC 7250)
pub mod hkdf;
pub mod key_exchange;
pub mod transcript;

pub use config::TlsConfig;
pub use handshake::{EncryptionLevel, HandshakeState};
