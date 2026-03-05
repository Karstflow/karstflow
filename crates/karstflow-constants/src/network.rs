// Network constants for the custom networking stack.

// ---------------------------------------------------------------------------
// Link layer
// ---------------------------------------------------------------------------

/// Ethernet frame header size (dst MAC + src MAC + EtherType).
pub const ETHERNET_HEADER_SIZE: usize = 14;
/// EtherType for IPv4 (0x0800).
pub const ETHERTYPE_IPV4: u16 = 0x0800;
/// EtherType for ARP (0x0806).
pub const ETHERTYPE_ARP: u16 = 0x0806;
/// MAC address size in bytes.
pub const MAC_ADDR_SIZE: usize = 6;

// ---------------------------------------------------------------------------
// IPv4
// ---------------------------------------------------------------------------

/// Minimum IPv4 header size (no options).
pub const IPV4_HEADER_SIZE: usize = 20;
/// IPv4 protocol number for UDP.
pub const IPV4_PROTO_UDP: u8 = 17;
/// IPv4 version field value.
pub const IPV4_VERSION: u8 = 4;
/// Default IPv4 IHL (header length in 32-bit words, no options).
pub const IPV4_DEFAULT_IHL: u8 = 5;
/// Default IPv4 TTL.
pub const IPV4_DEFAULT_TTL: u8 = 64;
/// IPv4 "Don't Fragment" flag.
pub const IPV4_FLAG_DF: u16 = 0x4000;

// ---------------------------------------------------------------------------
// UDP
// ---------------------------------------------------------------------------

/// UDP header size.
pub const UDP_HEADER_SIZE: usize = 8;

// ---------------------------------------------------------------------------
// MTU and payload
// ---------------------------------------------------------------------------

/// Standard Ethernet MTU.
pub const MTU: usize = 1500;
/// Maximum UDP payload after subtracting IPv4 + UDP headers from MTU.
pub const MAX_UDP_PAYLOAD: usize = MTU - IPV4_HEADER_SIZE - UDP_HEADER_SIZE;

// ---------------------------------------------------------------------------
// QUIC protocol (RFC 9000)
// ---------------------------------------------------------------------------

/// QUIC version 1 (RFC 9000).
pub const QUIC_VERSION_1: u32 = 0x0000_0001;
/// Minimum Initial packet payload size (RFC 9000 Section 14.1).
pub const QUIC_INITIAL_PAYLOAD_MIN: usize = 1200;
/// Maximum QUIC payload derived from MTU.
pub const QUIC_MAX_PAYLOAD: usize = MAX_UDP_PAYLOAD;
/// Smallest possible QUIC v1 packet in bytes.
pub const QUIC_SHORTEST_PACKET: usize = 16;
/// Maximum coalesced long packets per datagram.
pub const QUIC_COALESCE_LIMIT: usize = 4;
/// Maximum QUIC connection ID length in bytes.
pub const QUIC_MAX_CONN_ID_LEN: usize = 20;
/// Minimum connection IDs per connection.
pub const QUIC_MIN_CONN_IDS: usize = 4;
/// Maximum versions in a Version Negotiation packet.
pub const QUIC_MAX_VERSIONS: usize = 8;
/// Unused stream ID sentinel.
pub const QUIC_STREAM_ID_UNUSED: u64 = u64::MAX;
/// Unused packet number sentinel.
pub const QUIC_PKT_NUM_UNUSED: u64 = u64::MAX;

// ---------------------------------------------------------------------------
// QUIC packet types
// ---------------------------------------------------------------------------

pub const QUIC_PKT_INITIAL: u8 = 0;
pub const QUIC_PKT_ZERO_RTT: u8 = 1;
pub const QUIC_PKT_HANDSHAKE: u8 = 2;
pub const QUIC_PKT_RETRY: u8 = 3;
pub const QUIC_PKT_ONE_RTT: u8 = 4;

// ---------------------------------------------------------------------------
// QUIC frame types (RFC 9000 Section 19)
// ---------------------------------------------------------------------------

pub const FRAME_PADDING: u8 = 0x00;
pub const FRAME_PING: u8 = 0x01;
pub const FRAME_ACK: u8 = 0x02;
pub const FRAME_ACK_ECN: u8 = 0x03;
pub const FRAME_RESET_STREAM: u8 = 0x04;
pub const FRAME_STOP_SENDING: u8 = 0x05;
pub const FRAME_CRYPTO: u8 = 0x06;
pub const FRAME_NEW_TOKEN: u8 = 0x07;
pub const FRAME_STREAM_BASE: u8 = 0x08;
pub const FRAME_STREAM_END: u8 = 0x0f;
pub const FRAME_MAX_DATA: u8 = 0x10;
pub const FRAME_MAX_STREAM_DATA: u8 = 0x11;
pub const FRAME_MAX_STREAMS_BIDI: u8 = 0x12;
pub const FRAME_MAX_STREAMS_UNI: u8 = 0x13;
pub const FRAME_DATA_BLOCKED: u8 = 0x14;
pub const FRAME_STREAM_DATA_BLOCKED: u8 = 0x15;
pub const FRAME_STREAMS_BLOCKED_BIDI: u8 = 0x16;
pub const FRAME_STREAMS_BLOCKED_UNI: u8 = 0x17;
pub const FRAME_NEW_CONNECTION_ID: u8 = 0x18;
pub const FRAME_RETIRE_CONNECTION_ID: u8 = 0x19;
pub const FRAME_PATH_CHALLENGE: u8 = 0x1a;
pub const FRAME_PATH_RESPONSE: u8 = 0x1b;
pub const FRAME_CONNECTION_CLOSE: u8 = 0x1c;
pub const FRAME_CONNECTION_CLOSE_APP: u8 = 0x1d;
pub const FRAME_HANDSHAKE_DONE: u8 = 0x1e;
/// Total number of frame type IDs for lookup tables.
pub const FRAME_TYPE_COUNT: usize = 0x1f;

// ---------------------------------------------------------------------------
// QUIC stream types
// ---------------------------------------------------------------------------

pub const STREAM_BIDI_CLIENT: u8 = 0;
pub const STREAM_BIDI_SERVER: u8 = 1;
pub const STREAM_UNI_CLIENT: u8 = 2;
pub const STREAM_UNI_SERVER: u8 = 3;

// ---------------------------------------------------------------------------
// QUIC stream notification types
// ---------------------------------------------------------------------------

pub const STREAM_NOTIFY_END: u8 = 0;
pub const STREAM_NOTIFY_PEER_RESET: u8 = 1;
pub const STREAM_NOTIFY_PEER_STOP: u8 = 2;
pub const STREAM_NOTIFY_DROP: u8 = 3;
pub const STREAM_NOTIFY_CONN_CLOSE: u8 = 4;

// ---------------------------------------------------------------------------
// QUIC roles
// ---------------------------------------------------------------------------

pub const ROLE_CLIENT: u8 = 1;
pub const ROLE_SERVER: u8 = 2;

// ---------------------------------------------------------------------------
// QUIC connection states
// ---------------------------------------------------------------------------

pub const CONN_STATE_INVALID: u8 = 0;
pub const CONN_STATE_HANDSHAKING: u8 = 1;
pub const CONN_STATE_HANDSHAKE_COMPLETE: u8 = 2;
pub const CONN_STATE_ACTIVE: u8 = 3;
pub const CONN_STATE_PEER_CLOSE: u8 = 4;
pub const CONN_STATE_ABORT: u8 = 5;
pub const CONN_STATE_CLOSE_PENDING: u8 = 6;
pub const CONN_STATE_DEAD: u8 = 7;
pub const CONN_STATE_COUNT: usize = 8;

// ---------------------------------------------------------------------------
// TLS 1.3 encryption levels
// ---------------------------------------------------------------------------

pub const TLS_LEVEL_INITIAL: u8 = 0;
pub const TLS_LEVEL_EARLY: u8 = 1;
pub const TLS_LEVEL_HANDSHAKE: u8 = 2;
pub const TLS_LEVEL_APPLICATION: u8 = 3;

// ---------------------------------------------------------------------------
// Cryptographic sizes (AES-128-GCM / QUIC packet protection)
// ---------------------------------------------------------------------------

pub const AES_128_KEY_SIZE: usize = 16;
pub const AES_GCM_IV_SIZE: usize = 12;
pub const AES_GCM_TAG_SIZE: usize = 16;
pub const QUIC_INITIAL_SECRET_SIZE: usize = 32;
pub const QUIC_SECRET_SIZE: usize = 32;
pub const QUIC_HP_SAMPLE_SIZE: usize = 16;
pub const QUIC_NONCE_SIZE: usize = 12;

// ---------------------------------------------------------------------------
// QUIC retry token
// ---------------------------------------------------------------------------

pub const QUIC_RETRY_MAX_TOKEN_SIZE: usize = 256;
pub const QUIC_RETRY_SECRET_SIZE: usize = 16;
pub const QUIC_RETRY_IV_SIZE: usize = 12;
pub const QUIC_RETRY_INTEGRITY_TAG_SIZE: usize = 16;

// ---------------------------------------------------------------------------
// QUIC timing defaults
// ---------------------------------------------------------------------------

/// Default idle timeout in nanoseconds (1 second).
pub const QUIC_DEFAULT_IDLE_TIMEOUT_NS: u64 = 1_000_000_000;
/// Default ACK delay in nanoseconds (50 ms).
pub const QUIC_DEFAULT_ACK_DELAY_NS: u64 = 50_000_000;
/// Default ACK threshold in bytes (64 KiB).
pub const QUIC_DEFAULT_ACK_THRESHOLD: u64 = 65_536;
/// Default retry token TTL in nanoseconds (1 second).
pub const QUIC_DEFAULT_RETRY_TTL_NS: u64 = 1_000_000_000;
/// Default TLS handshake TTL in nanoseconds (3 seconds).
pub const QUIC_DEFAULT_TLS_HS_TTL_NS: u64 = 3_000_000_000;
/// Initial RTT estimate in microseconds (200 ms).
pub const QUIC_INITIAL_RTT_US: u64 = 200_000;

// ---------------------------------------------------------------------------
// QUIC ACK generator
// ---------------------------------------------------------------------------

/// Capacity of the ACK range ring buffer per connection (power of 2).
pub const QUIC_ACK_QUEUE_CAPACITY: usize = 64;

/// ACK coalescing result: no action taken (duplicate or invalid).
pub const QUIC_ACK_NOOP: u8 = 0;
/// ACK coalescing result: new ACK range created.
pub const QUIC_ACK_NEW: u8 = 1;
/// ACK coalescing result: merged into existing ACK range.
pub const QUIC_ACK_MERGED: u8 = 2;
/// ACK coalescing result: ring buffer full (excessive reordering).
pub const QUIC_ACK_OVERFLOW: u8 = 3;

// ---------------------------------------------------------------------------
// QUIC service scheduler
// ---------------------------------------------------------------------------

/// Service type: process ASAP (doubly-linked list).
pub const SVC_TYPE_INSTANT: u8 = 0;
/// Service type: process at scheduled time (priority queue).
pub const SVC_TYPE_DYNAMIC: u8 = 1;
/// Number of service types.
pub const SVC_TYPE_COUNT: usize = 2;
/// Sentinel index for empty doubly-linked list slot.
pub const SVC_DLIST_SENTINEL: u32 = u32::MAX;

// ---------------------------------------------------------------------------
// QUIC stream pool
// ---------------------------------------------------------------------------

/// Default per-stream TX buffer size (4 KiB).
pub const STREAM_TX_BUF_DEFAULT: usize = 4096;

// ---------------------------------------------------------------------------
// QUIC send errors
// ---------------------------------------------------------------------------

pub const QUIC_SEND_ERR_INVALID_STREAM: i32 = -1;
pub const QUIC_SEND_ERR_INVALID_CONN: i32 = -2;
pub const QUIC_SEND_ERR_FIN: i32 = -3;
pub const QUIC_SEND_ERR_STREAM_STATE: i32 = -4;
pub const QUIC_SEND_ERR_FLOW: i32 = -5;

// ---------------------------------------------------------------------------
// AIO (packet I/O abstraction)
// ---------------------------------------------------------------------------

pub const AIO_SUCCESS: i32 = 0;
pub const AIO_ERR_INVALID: i32 = -1;
pub const AIO_ERR_AGAIN: i32 = -2;
/// Maximum buffer size for a single packet info entry.
pub const AIO_PKT_BUF_MAX: usize = 4096;
/// Alignment for packet info structs.
pub const AIO_PKT_INFO_ALIGN: usize = 16;

// ---------------------------------------------------------------------------
// TLS 1.3 handshake states
// ---------------------------------------------------------------------------

pub const TLS_HS_FAIL: u8 = 0;
pub const TLS_HS_CONNECTED: u8 = 1;
pub const TLS_HS_START: u8 = 2;
pub const TLS_HS_WAIT_CERT: u8 = 3;
pub const TLS_HS_WAIT_CERT_VERIFY: u8 = 4;
pub const TLS_HS_WAIT_FINISHED: u8 = 5;
pub const TLS_HS_WAIT_SERVER_HELLO: u8 = 6;
pub const TLS_HS_WAIT_ENCRYPTED_EXT: u8 = 7;
pub const TLS_HS_WAIT_CERT_OR_REQ: u8 = 8;

/// Number of encryption levels (Initial, Early, Handshake, Application).
pub const TLS_NUM_ENCRYPTION_LEVELS: usize = 4;

// ---------------------------------------------------------------------------
// TLS 1.3 message types
// ---------------------------------------------------------------------------

pub const TLS_MSG_CLIENT_HELLO: u8 = 1;
pub const TLS_MSG_SERVER_HELLO: u8 = 2;
pub const TLS_MSG_ENCRYPTED_EXTENSIONS: u8 = 8;
pub const TLS_MSG_CERTIFICATE: u8 = 11;
pub const TLS_MSG_CERTIFICATE_REQUEST: u8 = 13;
pub const TLS_MSG_CERTIFICATE_VERIFY: u8 = 15;
pub const TLS_MSG_FINISHED: u8 = 20;

// ---------------------------------------------------------------------------
// TLS 1.3 cipher suite and algorithms
// ---------------------------------------------------------------------------

/// TLS_AES_128_GCM_SHA256 cipher suite identifier.
pub const TLS_CIPHER_AES_128_GCM_SHA256: u16 = 0x1301;
/// Ed25519 signature algorithm identifier in TLS.
pub const TLS_SIGNATURE_ED25519: u16 = 0x0807;
/// X25519 named group identifier.
pub const TLS_GROUP_X25519: u16 = 0x001d;
/// TLS 1.3 version number.
pub const TLS_VERSION_1_3: u16 = 0x0304;
/// Raw public key certificate type (RFC 7250).
pub const TLS_CERTTYPE_RAW_PUBKEY: u8 = 2;
/// X.509 certificate type.
pub const TLS_CERTTYPE_X509: u8 = 0;

// ---------------------------------------------------------------------------
// TLS 1.3 alerts (RFC 8446 Section 6.2)
// ---------------------------------------------------------------------------

pub const TLS_ALERT_UNEXPECTED_MESSAGE: u8 = 10;
pub const TLS_ALERT_BAD_RECORD_MAC: u8 = 20;
pub const TLS_ALERT_HANDSHAKE_FAILURE: u8 = 40;
pub const TLS_ALERT_BAD_CERTIFICATE: u8 = 42;
pub const TLS_ALERT_UNSUPPORTED_CERTIFICATE: u8 = 43;
pub const TLS_ALERT_CERTIFICATE_REVOKED: u8 = 44;
pub const TLS_ALERT_CERTIFICATE_EXPIRED: u8 = 45;
pub const TLS_ALERT_CERTIFICATE_UNKNOWN: u8 = 46;
pub const TLS_ALERT_ILLEGAL_PARAMETER: u8 = 47;
pub const TLS_ALERT_UNKNOWN_CA: u8 = 48;
pub const TLS_ALERT_DECODE_ERROR: u8 = 50;
pub const TLS_ALERT_DECRYPT_ERROR: u8 = 51;
pub const TLS_ALERT_PROTOCOL_VERSION: u8 = 70;
pub const TLS_ALERT_INTERNAL_ERROR: u8 = 80;
pub const TLS_ALERT_MISSING_EXTENSION: u8 = 109;
pub const TLS_ALERT_NO_APPLICATION_PROTOCOL: u8 = 120;

// ---------------------------------------------------------------------------
// QUIC v1 initial salt (RFC 9001 Section 5.2)
// ---------------------------------------------------------------------------

/// Salt used for deriving initial secrets in QUIC v1.
pub const QUIC_V1_INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// Header protection sample offset from packet number start.
pub const QUIC_HP_SAMPLE_OFFSET: usize = 4;

/// Number of QUIC encryption levels (alias for TLS_NUM_ENCRYPTION_LEVELS).
pub const QUIC_NUM_ENC_LEVELS: usize = TLS_NUM_ENCRYPTION_LEVELS;

/// Size of the AEAD authentication tag appended to encrypted payloads.
pub const QUIC_CRYPTO_TAG_SIZE: usize = 16;

/// Maximum byte size of encoded QUIC transport parameters.
pub const TLS_QUIC_PARAMS_MAX_SIZE: usize = 510;
/// Maximum DER-encoded X.509 server certificate size.
pub const TLS_SERVER_CERT_MAX_SIZE: usize = 1011;

// ---------------------------------------------------------------------------
// Packet buffer sizing
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// QUIC transport error codes (RFC 9000 Section 20)
// ---------------------------------------------------------------------------

pub const QUIC_ERR_NO_ERROR: u64 = 0x00;
pub const QUIC_ERR_INTERNAL: u64 = 0x01;
pub const QUIC_ERR_CONNECTION_REFUSED: u64 = 0x02;
pub const QUIC_ERR_FLOW_CONTROL: u64 = 0x03;
pub const QUIC_ERR_STREAM_LIMIT: u64 = 0x04;
pub const QUIC_ERR_STREAM_STATE: u64 = 0x05;
pub const QUIC_ERR_FINAL_SIZE: u64 = 0x06;
pub const QUIC_ERR_FRAME_ENCODING: u64 = 0x07;
pub const QUIC_ERR_TRANSPORT_PARAMETER: u64 = 0x08;
pub const QUIC_ERR_CONN_ID_LIMIT: u64 = 0x09;
pub const QUIC_ERR_PROTOCOL_VIOLATION: u64 = 0x0a;
pub const QUIC_ERR_INVALID_TOKEN: u64 = 0x0b;
pub const QUIC_ERR_APPLICATION: u64 = 0x0c;
pub const QUIC_ERR_CRYPTO_BUFFER_EXCEEDED: u64 = 0x0d;
pub const QUIC_ERR_KEY_UPDATE: u64 = 0x0e;
pub const QUIC_ERR_AEAD_LIMIT_REACHED: u64 = 0x0f;
pub const QUIC_ERR_NO_VIABLE_PATH: u64 = 0x10;
/// Base error code for TLS alerts mapped to QUIC (+ alert code).
pub const QUIC_ERR_CRYPTO_BASE: u64 = 0x100;

// ---------------------------------------------------------------------------
// QUIC transport parameter IDs (RFC 9000 Section 18.2)
// ---------------------------------------------------------------------------

pub const TP_ORIGINAL_DST_CONN_ID: u64 = 0x00;
pub const TP_MAX_IDLE_TIMEOUT: u64 = 0x01;
pub const TP_STATELESS_RESET_TOKEN: u64 = 0x02;
pub const TP_MAX_UDP_PAYLOAD_SIZE: u64 = 0x03;
pub const TP_INITIAL_MAX_DATA: u64 = 0x04;
pub const TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x05;
pub const TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
pub const TP_INITIAL_MAX_STREAM_DATA_UNI: u64 = 0x07;
pub const TP_INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;
pub const TP_INITIAL_MAX_STREAMS_UNI: u64 = 0x09;
pub const TP_ACK_DELAY_EXPONENT: u64 = 0x0a;
pub const TP_MAX_ACK_DELAY: u64 = 0x0b;
pub const TP_DISABLE_ACTIVE_MIGRATION: u64 = 0x0c;
pub const TP_PREFERRED_ADDRESS: u64 = 0x0d;
pub const TP_ACTIVE_CONN_ID_LIMIT: u64 = 0x0e;
pub const TP_INITIAL_SOURCE_CONN_ID: u64 = 0x0f;
pub const TP_RETRY_SOURCE_CONN_ID: u64 = 0x10;

// ---------------------------------------------------------------------------
// QUIC varint limits (RFC 9000 Section 16)
// ---------------------------------------------------------------------------

/// Maximum value representable in a QUIC variable-length integer (2^62 - 1).
pub const QUIC_VARINT_MAX: u64 = 0x3fff_ffff_ffff_ffff;

// ---------------------------------------------------------------------------
// QUIC connection ID sizing
// ---------------------------------------------------------------------------

/// Default connection ID size in bytes (matching Firedancer's default).
pub const QUIC_DEFAULT_CONN_ID_SIZE: usize = 8;

// ---------------------------------------------------------------------------
// Packet buffer sizing
// ---------------------------------------------------------------------------

/// Default packet buffer size (aligned to power of 2, fits MTU + headroom).
pub const PACKET_BUFFER_SIZE: usize = 2048;
/// Default batch size for packet I/O operations.
pub const PACKET_BATCH_DEFAULT: usize = 64;

// ---------------------------------------------------------------------------
// AF_XDP / XDP (Linux kernel bypass)
// ---------------------------------------------------------------------------

/// Default XDP UMEM frame size (power of 2, fits one packet).
pub const XDP_FRAME_SIZE: usize = 4096;
/// Required UMEM alignment (page-aligned).
pub const XDP_UMEM_ALIGN: usize = 4096;
/// Default number of UMEM frames.
pub const XDP_DEFAULT_FRAME_COUNT: u32 = 4096;
/// Default depth for each XDP ring (power of 2).
pub const XDP_DEFAULT_RING_DEPTH: u32 = 2048;
/// Minimum ring depth.
pub const XDP_MIN_RING_DEPTH: u32 = 64;
/// Sentinel for empty ring slot or invalid frame.
pub const XDP_FRAME_INVALID: u64 = u64::MAX;
/// XDP headroom reserved before packet data in each frame.
pub const XDP_HEADROOM: usize = 256;

// ---------------------------------------------------------------------------
// IPv4 routing (FIB4)
// ---------------------------------------------------------------------------

/// Route type: unspecified / invalid.
pub const ROUTE_TYPE_UNSPEC: u8 = 0;
/// Route type: normal unicast forwarding.
pub const ROUTE_TYPE_UNICAST: u8 = 1;
/// Route type: destination is a local address.
pub const ROUTE_TYPE_LOCAL: u8 = 2;
/// Route type: broadcast address.
pub const ROUTE_TYPE_BROADCAST: u8 = 3;
/// Route type: silently drop the packet.
pub const ROUTE_TYPE_BLACKHOLE: u8 = 6;

/// Maximum number of routes in the routing table.
pub const FIB4_MAX_ROUTES: usize = 256;

// ---------------------------------------------------------------------------
// Neighbor (ARP) table
// ---------------------------------------------------------------------------

/// Neighbor entry state: ARP resolution in progress.
pub const NEIGH_STATE_INCOMPLETE: u8 = 0;
/// Neighbor entry state: MAC address resolved and active.
pub const NEIGH_STATE_ACTIVE: u8 = 1;
/// Maximum entries in the neighbor table.
pub const NEIGH_TABLE_MAX: usize = 256;

// ---------------------------------------------------------------------------
// eBPF / XDP program constants
// ---------------------------------------------------------------------------

/// Maximum eBPF instructions in a generated XDP program.
pub const BPF_MAX_INSNS: usize = 512;
/// XDP action: pass packet to kernel networking stack.
pub const XDP_PASS: u32 = 2;
/// XDP action: redirect packet to AF_XDP socket via XSKMAP.
pub const XDP_REDIRECT: u32 = 4;
/// eBPF helper function ID: bpf_redirect_map.
pub const BPF_FUNC_REDIRECT_MAP: u32 = 0x33;
/// Maximum UDP ports in the XDP filter program.
pub const XDP_MAX_FILTER_PORTS: usize = 32;
