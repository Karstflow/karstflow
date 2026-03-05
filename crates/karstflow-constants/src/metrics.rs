/// Default TCP port for the Prometheus metrics HTTP server.
pub const DEFAULT_METRICS_HTTP_PORT: u16 = 7999;

/// Maximum number of concurrent HTTP connections to the metrics server.
pub const MAX_METRICS_HTTP_CONNECTIONS: usize = 8;

/// Pre-allocated buffer size for building the HTTP response body.
pub const METRICS_RESPONSE_BUFFER_SIZE: usize = 32_768;

/// Maximum acceptable HTTP request size in bytes.
/// Anything larger is rejected to prevent memory exhaustion.
pub const MAX_METRICS_REQUEST_SIZE: usize = 4_096;

/// Read timeout for metrics HTTP connections in milliseconds.
pub const METRICS_HTTP_READ_TIMEOUT_MS: u64 = 2_000;

/// Write timeout for metrics HTTP connections in milliseconds.
pub const METRICS_HTTP_WRITE_TIMEOUT_MS: u64 = 2_000;

/// Maximum slot lag before the `/ready` probe reports not-ready.
/// Validators within this many slots of the network tip are considered synced.
pub const READY_SLOT_LAG_THRESHOLD: u64 = 128;
