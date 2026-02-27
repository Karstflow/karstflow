/// Lightweight HTTP server for Prometheus metrics scraping.
///
/// Runs a simple TCP listener that responds to `GET /metrics` with the
/// latest Prometheus-format metrics text. The metrics content is updated
/// periodically by the `MetricsReporter` service via a shared buffer.
///
/// Design: Single-threaded accept loop with non-blocking per-connection
/// handling. Connections that exceed the read timeout or send malformed
/// requests are dropped immediately. No external HTTP framework is used
/// to keep the dependency footprint zero.
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use paradencer_constants::metrics::{
    MAX_METRICS_HTTP_CONNECTIONS, MAX_METRICS_REQUEST_SIZE, METRICS_HTTP_READ_TIMEOUT_MS,
    METRICS_HTTP_WRITE_TIMEOUT_MS,
};

/// Shared metrics content buffer updated by the reporter and read by
/// the HTTP server. The inner `String` contains the full Prometheus
/// text exposition format body.
pub type MetricsContent = Arc<Mutex<String>>;

/// Create a new shared metrics content buffer.
pub fn shared_metrics_content() -> MetricsContent {
    Arc::new(Mutex::new(String::new()))
}

/// Statistics for the metrics HTTP server.
#[derive(Debug, Clone, Default)]
pub struct MetricsHttpStats {
    /// Total HTTP requests received.
    pub requests_total: u64,
    /// Successful /metrics responses served.
    pub requests_ok: u64,
    /// Requests to unknown paths (404 responses).
    pub requests_not_found: u64,
    /// Requests with unsupported methods (405 responses).
    pub requests_method_not_allowed: u64,
    /// Requests that failed due to I/O or timeout.
    pub requests_failed: u64,
    /// Connections rejected because the server is at capacity.
    pub connections_rejected: u64,
}

/// A simple TCP-based HTTP server serving Prometheus metrics.
///
/// The server reads metrics content from a shared buffer that is
/// updated externally (typically by `MetricsReporter`). It handles
/// only `GET /metrics` — all other paths return 404, and non-GET
/// methods return 405.
pub struct MetricsHttpServer {
    listener: TcpListener,
    content: MetricsContent,
    stats: MetricsHttpStats,
    active_connections: usize,
}

impl MetricsHttpServer {
    /// Bind to the given address and create a new metrics server.
    ///
    /// The listener is set to non-blocking mode so `accept()` can be
    /// polled without stalling the caller's service loop.
    pub fn bind(addr: SocketAddr, content: MetricsContent) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            content,
            stats: MetricsHttpStats::default(),
            active_connections: 0,
        })
    }

    /// The local address the server is listening on.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Poll for incoming connections and handle them.
    ///
    /// This is designed to be called from a service tick loop. It
    /// accepts up to `MAX_METRICS_HTTP_CONNECTIONS` connections per
    /// call, handles each synchronously, and returns.
    pub fn poll(&mut self) {
        self.active_connections = 0;

        for _ in 0..MAX_METRICS_HTTP_CONNECTIONS {
            match self.listener.accept() {
                Ok((stream, _peer)) => {
                    self.active_connections += 1;
                    self.handle_connection(stream);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    break;
                }
                Err(_) => {
                    self.stats.connections_rejected += 1;
                    break;
                }
            }
        }
    }

    /// Handle a single HTTP connection.
    fn handle_connection(&mut self, mut stream: TcpStream) {
        // Set timeouts for the connection.
        let _ = stream.set_read_timeout(Some(Duration::from_millis(METRICS_HTTP_READ_TIMEOUT_MS)));
        let _ =
            stream.set_write_timeout(Some(Duration::from_millis(METRICS_HTTP_WRITE_TIMEOUT_MS)));

        // Read the request (we only need the first line).
        let mut buf = [0u8; MAX_METRICS_REQUEST_SIZE];
        let n = match stream.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => n,
            Err(_) => {
                self.stats.requests_failed += 1;
                return;
            }
        };

        self.stats.requests_total += 1;

        let request = match std::str::from_utf8(&buf[..n]) {
            Ok(s) => s,
            Err(_) => {
                self.stats.requests_failed += 1;
                let _ = write_response(&mut stream, 400, "text/plain", "Bad Request");
                return;
            }
        };

        // Parse the request line: "METHOD /path HTTP/1.x\r\n..."
        let request_line = request.lines().next().unwrap_or("");
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("");
        let path = parts.next().unwrap_or("");

        if method != "GET" {
            self.stats.requests_method_not_allowed += 1;
            let _ = write_response(&mut stream, 405, "text/plain", "Method Not Allowed");
            return;
        }

        match path {
            "/metrics" => {
                let body = self
                    .content
                    .lock()
                    .map(|guard| guard.clone())
                    .unwrap_or_default();
                if write_response(
                    &mut stream,
                    200,
                    "text/plain; version=0.0.4; charset=utf-8",
                    &body,
                )
                .is_ok()
                {
                    self.stats.requests_ok += 1;
                } else {
                    self.stats.requests_failed += 1;
                }
            }
            "/" | "/health" => {
                let _ = write_response(&mut stream, 200, "text/plain", "ok\n");
                self.stats.requests_ok += 1;
            }
            _ => {
                self.stats.requests_not_found += 1;
                let _ = write_response(&mut stream, 404, "text/plain", "Not Found");
            }
        }
    }

    /// Get current server statistics.
    pub fn stats(&self) -> &MetricsHttpStats {
        &self.stats
    }

    /// Reset statistics counters.
    pub fn reset_stats(&mut self) {
        self.stats = MetricsHttpStats::default();
    }
}

/// Write an HTTP response with the given status, content-type, and body.
fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &str,
) -> std::io::Result<()> {
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Unknown",
    };

    let header = format!(
        "HTTP/1.1 {status} {status_text}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );

    stream.write_all(header.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    stream.flush()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::TcpStream;

    fn bind_server(content: &str) -> MetricsHttpServer {
        let shared = shared_metrics_content();
        {
            let mut guard = shared.lock().unwrap();
            *guard = content.to_string();
        }
        MetricsHttpServer::bind("127.0.0.1:0".parse().unwrap(), shared).unwrap()
    }

    fn http_get(addr: SocketAddr, path: &str) -> (u16, String) {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let request =
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).unwrap();

        let mut reader = BufReader::new(stream);

        // Read status line.
        let mut status_line = String::new();
        reader.read_line(&mut status_line).unwrap();
        let status_code: u16 = status_line
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();

        // Skip headers until empty line.
        let mut content_length: usize = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line.trim().is_empty() {
                break;
            }
            if line.to_lowercase().starts_with("content-length:") {
                content_length = line.split(':').nth(1).unwrap().trim().parse().unwrap_or(0);
            }
        }

        // Read body.
        let mut body = vec![0u8; content_length];
        if content_length > 0 {
            reader.read_exact(&mut body).unwrap();
        }

        (status_code, String::from_utf8(body).unwrap_or_default())
    }

    #[test]
    fn serves_metrics_on_get_metrics() {
        let metrics_text = "paradencer_uptime_millis 42000\n";
        let mut server = bind_server(metrics_text);
        let addr = server.local_addr().unwrap();

        // Poll in a separate thread since we need to connect concurrently.
        let handle = std::thread::spawn(move || {
            // Give the client time to connect.
            std::thread::sleep(Duration::from_millis(50));
            server.poll();
            server
        });

        // Small delay to let server thread start.
        std::thread::sleep(Duration::from_millis(10));

        let (status, body) = http_get(addr, "/metrics");
        let server = handle.join().unwrap();

        assert_eq!(status, 200);
        assert!(body.contains("paradencer_uptime_millis 42000"));
        assert_eq!(server.stats().requests_ok, 1);
        assert_eq!(server.stats().requests_total, 1);
    }

    #[test]
    fn returns_404_for_unknown_path() {
        let mut server = bind_server("");
        let addr = server.local_addr().unwrap();

        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            server.poll();
            server
        });

        std::thread::sleep(Duration::from_millis(10));

        let (status, _body) = http_get(addr, "/unknown");
        let server = handle.join().unwrap();

        assert_eq!(status, 404);
        assert_eq!(server.stats().requests_not_found, 1);
    }

    #[test]
    fn returns_200_for_health_check() {
        let mut server = bind_server("");
        let addr = server.local_addr().unwrap();

        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            server.poll();
            server
        });

        std::thread::sleep(Duration::from_millis(10));

        let (status, body) = http_get(addr, "/health");
        let _ = handle.join().unwrap();

        assert_eq!(status, 200);
        assert!(body.contains("ok"));
    }

    #[test]
    fn returns_405_for_post_request() {
        let mut server = bind_server("");
        let addr = server.local_addr().unwrap();

        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            server.poll();
            server
        });

        std::thread::sleep(Duration::from_millis(10));

        // Send POST instead of GET.
        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let request = "POST /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        stream.write_all(request.as_bytes()).unwrap();

        let mut response = String::new();
        let mut reader = BufReader::new(stream);
        reader.read_line(&mut response).unwrap();

        let server = handle.join().unwrap();
        assert!(response.contains("405"));
        assert_eq!(server.stats().requests_method_not_allowed, 1);
    }

    #[test]
    fn shared_content_updates_propagate() {
        let content = shared_metrics_content();
        let mut server =
            MetricsHttpServer::bind("127.0.0.1:0".parse().unwrap(), content.clone()).unwrap();
        let addr = server.local_addr().unwrap();

        // Set initial content.
        {
            let mut guard = content.lock().unwrap();
            *guard = "version_1\n".to_string();
        }

        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            server.poll();
            server
        });

        std::thread::sleep(Duration::from_millis(10));

        let (status, body) = http_get(addr, "/metrics");
        let _ = handle.join().unwrap();

        assert_eq!(status, 200);
        assert!(body.contains("version_1"));
    }

    #[test]
    fn stats_reset_clears_counters() {
        let mut server = bind_server("");
        assert_eq!(server.stats().requests_total, 0);

        // Simulate a request count.
        server.stats.requests_total = 5;
        server.stats.requests_ok = 3;
        server.reset_stats();

        assert_eq!(server.stats().requests_total, 0);
        assert_eq!(server.stats().requests_ok, 0);
    }

    #[test]
    fn poll_without_connections_is_noop() {
        let mut server = bind_server("");
        // Should return immediately without error.
        server.poll();
        assert_eq!(server.stats().requests_total, 0);
    }
}
