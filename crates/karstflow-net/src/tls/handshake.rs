/// TLS 1.3 handshake state machine types and transitions.
///
/// Models the TLS handshake as a state machine with 9 states matching the
/// protocol specification. Server and client handshakes have different
/// state subsets and transition paths.
use crate::tls::transcript::Transcript;

/// TLS handshake state identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeState {
    /// Handshake failed with an alert.
    Failed = 0,
    /// Handshake completed successfully, connection is secured.
    Connected = 1,
    /// Initial state, ready to begin handshake.
    Start = 2,
    /// Waiting for peer's Certificate message.
    WaitCertificate = 3,
    /// Waiting for peer's CertificateVerify message.
    WaitCertificateVerify = 4,
    /// Waiting for peer's Finished message.
    WaitFinished = 5,
    /// Client only: waiting for ServerHello.
    WaitServerHello = 6,
    /// Client only: waiting for EncryptedExtensions.
    WaitEncryptedExtensions = 7,
    /// Client only: waiting for Certificate or CertificateRequest.
    WaitCertificateOrRequest = 8,
}

impl HandshakeState {
    /// Whether this is a terminal state (no more transitions possible).
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Failed | Self::Connected)
    }
}

/// TLS encryption level (determines which keys to use).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EncryptionLevel {
    /// Initial (plaintext or initial keys).
    Initial = 0,
    /// Early data (0-RTT) — not used in this implementation.
    EarlyData = 1,
    /// Handshake encryption.
    Handshake = 2,
    /// Application data encryption.
    Application = 3,
}

impl EncryptionLevel {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Initial),
            1 => Some(Self::EarlyData),
            2 => Some(Self::Handshake),
            3 => Some(Self::Application),
            _ => None,
        }
    }
}

/// TLS alert with extended reason code for debugging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsAlert {
    /// TLS alert code (RFC 8446 Section 6.2).
    pub alert: u8,
    /// Extended reason code for debugging.
    pub reason: AlertReason,
}

impl TlsAlert {
    pub fn new(alert: u8, reason: AlertReason) -> Self {
        Self { alert, reason }
    }
}

/// Extended alert reason codes for detailed error diagnosis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertReason {
    None,
    IllegalState,
    SendFailed,
    WrongEncryptionLevel,
    RandomGenerationFailed,
    X25519Failed,
    Ed25519Failed,
    WrongPublicKey,

    // ClientHello errors
    ClientHelloExpected,
    ClientHelloParseFailed,
    ClientHelloEncodeFailed,
    ClientHelloMissingQuicParams,
    ClientHelloRetryKeyShare,
    UnsupportedTlsVersion,
    UnsupportedKeyExchange,
    UnsupportedSignatureAlg,
    UnsupportedCipherSuite,

    // ServerHello errors
    ServerHelloExpected,
    ServerHelloParseFailed,
    ServerHelloEncodeFailed,

    // EncryptedExtensions errors
    EncryptedExtExpected,
    EncryptedExtParseFailed,
    EncryptedExtMissingQuic,

    // Certificate errors
    CertificateExpected,
    CertificateParseFailed,
    UnsupportedCertType,

    // CertificateVerify errors
    CertVerifyExpected,
    CertVerifyParseFailed,
    CertVerifyWrongSigAlg,

    // Finished errors
    FinishedExpected,
    FinishedParseFailed,
    FinishedVerifyFailed,

    // ALPN errors
    AlpnParseFailed,
    AlpnNegotiationFailed,
    AlpnMissing,

    // QUIC transport params
    QuicParamsOverflow,
}

/// Base handshake state shared by server and client.
#[derive(Clone)]
pub struct HandshakeBase {
    pub state: HandshakeState,
    pub is_server: bool,
    pub reason: AlertReason,
    /// Client random (32 bytes) for SSLKEYLOGFILE compatibility.
    pub client_random: [u8; 32],
}

impl HandshakeBase {
    fn new(is_server: bool) -> Self {
        Self {
            state: HandshakeState::Start,
            is_server,
            reason: AlertReason::None,
            client_random: [0; 32],
        }
    }
}

/// Server-side handshake state.
///
/// Designed for compact memory (similar to Firedancer's ~128 byte estate).
/// Only stores the minimum state needed between handshake message exchanges.
pub struct ServerHandshake {
    pub base: HandshakeBase,
    /// Whether server uses raw public key (vs X.509).
    pub server_cert_rpk: bool,
    /// Whether client authentication is requested.
    pub client_cert: bool,
    /// Whether client uses raw public key.
    pub client_cert_rpk: bool,
    /// Whether this is a HelloRetryRequest flow.
    pub hello_retry: bool,
    /// Transcript hash (compact form for server).
    pub transcript: Transcript,
    /// Client handshake traffic secret (for verifying client Finished).
    pub client_hs_secret: [u8; 32],
    /// Client's Ed25519 public key (from certificate).
    pub client_pubkey: [u8; 32],
}

impl ServerHandshake {
    /// Create a new server handshake in the Start state.
    pub fn new() -> Self {
        Self {
            base: HandshakeBase::new(true),
            server_cert_rpk: false,
            client_cert: false,
            client_cert_rpk: false,
            hello_retry: false,
            transcript: Transcript::new(),
            client_hs_secret: [0; 32],
            client_pubkey: [0; 32],
        }
    }

    /// Current handshake state.
    pub fn state(&self) -> HandshakeState {
        self.base.state
    }
}

impl Default for ServerHandshake {
    fn default() -> Self {
        Self::new()
    }
}

/// Client-side handshake state.
///
/// Larger than server state because clients aren't vulnerable to handshake
/// floods (peers can't initiate connections to clients). Stores all secrets
/// needed during the full handshake flow.
pub struct ClientHandshake {
    pub base: HandshakeBase,
    /// Server's Ed25519 public key (from certificate or pre-configured).
    pub server_pubkey: [u8; 32],
    /// Server handshake traffic secret.
    pub server_hs_secret: [u8; 32],
    /// Client handshake traffic secret.
    pub client_hs_secret: [u8; 32],
    /// Master secret for deriving application keys.
    pub master_secret: [u8; 32],
    /// Whether client cert authentication is required.
    pub client_cert: bool,
    /// Whether server uses raw public key.
    pub server_cert_rpk: bool,
    /// Whether client uses raw public key.
    pub client_cert_rpk: bool,
    /// Whether to pin the server public key (reject if cert doesn't match).
    pub server_pubkey_pin: bool,
    /// Full transcript hasher (clients can afford the memory).
    pub transcript: Transcript,
}

impl ClientHandshake {
    /// Create a new client handshake in the Start state.
    pub fn new() -> Self {
        Self {
            base: HandshakeBase::new(false),
            server_pubkey: [0; 32],
            server_hs_secret: [0; 32],
            client_hs_secret: [0; 32],
            master_secret: [0; 32],
            client_cert: false,
            server_cert_rpk: false,
            client_cert_rpk: false,
            server_pubkey_pin: false,
            transcript: Transcript::new(),
        }
    }

    /// Create a client handshake with a pinned server public key.
    pub fn with_pinned_server(server_pubkey: [u8; 32]) -> Self {
        let mut hs = Self::new();
        hs.server_pubkey = server_pubkey;
        hs.server_pubkey_pin = true;
        hs
    }

    /// Current handshake state.
    pub fn state(&self) -> HandshakeState {
        self.base.state
    }
}

impl Default for ClientHandshake {
    fn default() -> Self {
        Self::new()
    }
}

/// Union-like enum for either server or client handshake.
pub enum Handshake {
    Server(ServerHandshake),
    Client(ClientHandshake),
}

impl Handshake {
    pub fn state(&self) -> HandshakeState {
        match self {
            Self::Server(hs) => hs.state(),
            Self::Client(hs) => hs.state(),
        }
    }

    pub fn is_server(&self) -> bool {
        matches!(self, Self::Server(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_handshake_starts_correctly() {
        let hs = ServerHandshake::new();
        assert_eq!(hs.state(), HandshakeState::Start);
        assert!(hs.base.is_server);
        assert!(!hs.hello_retry);
    }

    #[test]
    fn client_handshake_starts_correctly() {
        let hs = ClientHandshake::new();
        assert_eq!(hs.state(), HandshakeState::Start);
        assert!(!hs.base.is_server);
    }

    #[test]
    fn client_with_pinned_server() {
        let pubkey = [0xAA; 32];
        let hs = ClientHandshake::with_pinned_server(pubkey);
        assert!(hs.server_pubkey_pin);
        assert_eq!(hs.server_pubkey, pubkey);
    }

    #[test]
    fn handshake_enum_dispatch() {
        let server = Handshake::Server(ServerHandshake::new());
        assert!(server.is_server());
        assert_eq!(server.state(), HandshakeState::Start);

        let client = Handshake::Client(ClientHandshake::new());
        assert!(!client.is_server());
        assert_eq!(client.state(), HandshakeState::Start);
    }

    #[test]
    fn handshake_state_is_terminal() {
        assert!(HandshakeState::Failed.is_terminal());
        assert!(HandshakeState::Connected.is_terminal());
        assert!(!HandshakeState::Start.is_terminal());
        assert!(!HandshakeState::WaitFinished.is_terminal());
    }

    #[test]
    fn encryption_level_from_u8() {
        assert_eq!(EncryptionLevel::from_u8(0), Some(EncryptionLevel::Initial));
        assert_eq!(
            EncryptionLevel::from_u8(2),
            Some(EncryptionLevel::Handshake)
        );
        assert_eq!(
            EncryptionLevel::from_u8(3),
            Some(EncryptionLevel::Application)
        );
        assert_eq!(EncryptionLevel::from_u8(4), None);
    }

    #[test]
    fn alert_creation() {
        let alert = TlsAlert::new(40, AlertReason::UnsupportedCipherSuite);
        assert_eq!(alert.alert, 40);
        assert_eq!(alert.reason, AlertReason::UnsupportedCipherSuite);
    }
}
