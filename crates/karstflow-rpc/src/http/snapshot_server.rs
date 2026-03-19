//! Lightweight HTTP server for snapshot and genesis file serving.
//!
//! Serves snapshot archives and genesis.tar.bz2 at well-known paths so
//! other validators can download them during bootstrap. Runs on the same
//! port as the RPC server by intercepting non-JSON-RPC requests.
//!
//! Paths served:
//! - `/snapshot.tar.bz2` → redirects to latest full snapshot archive
//! - `/genesis.tar.bz2` → serves the genesis archive
//! - `/health` → returns "ok" (for load balancers)

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{info, warn};

/// Configuration for the snapshot file server.
#[derive(Debug, Clone)]
pub struct SnapshotServerConfig {
    /// Directory containing snapshot archives.
    pub snapshot_dir: PathBuf,
    /// Path to genesis.tar.bz2 (or directory containing it).
    pub genesis_path: Option<PathBuf>,
}

/// Spawn a background thread serving snapshot files via HTTP.
///
/// Binds on `bind_addr` and serves:
/// - GET /genesis.tar.bz2 → genesis archive file
/// - GET /snapshot.tar.bz2 → latest full snapshot (redirect to actual file)
pub fn spawn_snapshot_file_server(
    bind_addr: SocketAddr,
    config: SnapshotServerConfig,
) -> Option<std::thread::JoinHandle<()>> {
    let config = Arc::new(config);

    std::thread::Builder::new()
        .name("snapshot-http".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    warn!(error = %e, "snapshot-http: failed to create runtime");
                    return;
                }
            };

            rt.block_on(async move {
                let listener = match tokio::net::TcpListener::bind(bind_addr).await {
                    Ok(l) => l,
                    Err(e) => {
                        warn!(error = %e, %bind_addr, "snapshot-http: failed to bind");
                        return;
                    }
                };
                info!(%bind_addr, "snapshot-http: serving snapshot files");

                loop {
                    let (stream, _) = match listener.accept().await {
                        Ok(conn) => conn,
                        Err(_) => continue,
                    };
                    let cfg = config.clone();
                    tokio::spawn(async move {
                        handle_connection(stream, &cfg).await;
                    });
                }
            });
        })
        .ok()
}

async fn handle_connection(mut stream: tokio::net::TcpStream, config: &SnapshotServerConfig) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf = vec![0u8; 4096];
    let n = match stream.read(&mut buf).await {
        Ok(n) if n > 0 => n,
        _ => return,
    };

    let request = String::from_utf8_lossy(&buf[..n]);
    let first_line = request.lines().next().unwrap_or("");

    if first_line.starts_with("GET /genesis.tar.bz2") {
        serve_file(&mut stream, config, "genesis.tar.bz2").await;
    } else if first_line.starts_with("GET /snapshot.tar.bz2")
        || first_line.starts_with("HEAD /snapshot.tar.bz2")
    {
        serve_latest_snapshot(&mut stream, config, first_line.starts_with("HEAD")).await;
    } else {
        let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found";
        let _ = stream.write_all(response.as_bytes()).await;
    }
}

async fn serve_file(
    stream: &mut tokio::net::TcpStream,
    config: &SnapshotServerConfig,
    filename: &str,
) {
    use tokio::io::AsyncWriteExt;

    let path = if let Some(ref genesis) = config.genesis_path {
        if genesis.is_file() {
            genesis.clone()
        } else {
            genesis.join(filename)
        }
    } else {
        config.snapshot_dir.join(filename)
    };

    match std::fs::read(&path) {
        Ok(data) => {
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\n\r\n",
                data.len()
            );
            let _ = stream.write_all(header.as_bytes()).await;
            let _ = stream.write_all(&data).await;
        }
        Err(_) => {
            let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found";
            let _ = stream.write_all(response.as_bytes()).await;
        }
    }
}

async fn serve_latest_snapshot(
    stream: &mut tokio::net::TcpStream,
    config: &SnapshotServerConfig,
    _is_head: bool,
) {
    use tokio::io::AsyncWriteExt;

    // Find latest snapshot file in snapshot_dir
    let snapshot_file = find_latest_snapshot(&config.snapshot_dir);

    match snapshot_file {
        Some(path) => {
            let filename = path.file_name().unwrap_or_default().to_string_lossy();
            // Redirect to the actual snapshot file
            let redirect = format!(
                "HTTP/1.1 303 See Other\r\nLocation: /{}\r\nContent-Length: 0\r\n\r\n",
                filename
            );
            let _ = stream.write_all(redirect.as_bytes()).await;
        }
        None => {
            let response =
                "HTTP/1.1 404 Not Found\r\nContent-Length: 21\r\n\r\nNo snapshot available";
            let _ = stream.write_all(response.as_bytes()).await;
        }
    }
}

fn find_latest_snapshot(dir: &Path) -> Option<PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    let mut snapshots: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .map(|ext| ext == "zst" || ext == "bz2")
                .unwrap_or(false)
                && p.file_name()
                    .map(|n| n.to_string_lossy().starts_with("snapshot-"))
                    .unwrap_or(false)
        })
        .collect();
    snapshots.sort();
    snapshots.last().cloned()
}
