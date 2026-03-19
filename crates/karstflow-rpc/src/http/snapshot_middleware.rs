//! Tower middleware that intercepts GET requests for snapshot and genesis files.
//!
//! Installed on the jsonrpsee HTTP server via `set_http_middleware()` so that
//! snapshot/genesis serving happens on the same RPC port. Non-matching requests
//! pass through to the JSON-RPC handler.

use http::{Method, Request, Response, StatusCode};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::{Layer, Service};
use tracing::info;

/// Paths intercepted by the snapshot middleware.
const GENESIS_PATH: &str = "/genesis.tar.bz2";
const SNAPSHOT_PATH: &str = "/snapshot.tar.bz2";

/// Configuration for which files to serve.
#[derive(Debug, Clone)]
pub struct SnapshotMiddlewareConfig {
    /// Directory containing snapshot archives.
    pub snapshot_dir: PathBuf,
    /// Path to genesis.tar.bz2 file (or directory containing it).
    pub genesis_path: Option<PathBuf>,
}

/// Tower layer that wraps an inner service with snapshot file interception.
#[derive(Clone)]
pub struct SnapshotLayer {
    config: Arc<SnapshotMiddlewareConfig>,
}

impl SnapshotLayer {
    pub fn new(config: SnapshotMiddlewareConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
}

impl<S> Layer<S> for SnapshotLayer {
    type Service = SnapshotService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SnapshotService {
            inner,
            config: self.config.clone(),
        }
    }
}

/// The middleware service that checks incoming requests.
#[derive(Clone)]
pub struct SnapshotService<S> {
    inner: S,
    config: Arc<SnapshotMiddlewareConfig>,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for SnapshotService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: From<Vec<u8>> + From<&'static str> + Default + Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let path = req.uri().path().to_owned();
        let method = req.method().clone();

        // Only intercept GET/HEAD for our known paths.
        if matches!(method, Method::GET | Method::HEAD)
            && (path == GENESIS_PATH || path == SNAPSHOT_PATH)
        {
            let config = self.config.clone();
            let is_head = method == Method::HEAD;
            Box::pin(async move {
                let response = serve_snapshot_request::<ResBody>(&path, &config, is_head);
                Ok(response)
            })
        } else {
            // Pass through to jsonrpsee.
            let future = self.inner.call(req);
            Box::pin(future)
        }
    }
}

/// Build an HTTP response for a snapshot/genesis request.
fn serve_snapshot_request<B: From<Vec<u8>> + From<&'static str> + Default>(
    path: &str,
    config: &SnapshotMiddlewareConfig,
    is_head: bool,
) -> Response<B> {
    if path == GENESIS_PATH {
        serve_genesis_file(config, is_head)
    } else {
        serve_latest_snapshot(config, is_head)
    }
}

fn serve_genesis_file<B: From<Vec<u8>> + From<&'static str> + Default>(
    config: &SnapshotMiddlewareConfig,
    is_head: bool,
) -> Response<B> {
    let file_path = if let Some(ref genesis) = config.genesis_path {
        if genesis.is_file() {
            genesis.clone()
        } else {
            genesis.join("genesis.tar.bz2")
        }
    } else {
        config.snapshot_dir.join("genesis.tar.bz2")
    };

    serve_file_response(&file_path, is_head)
}

fn serve_latest_snapshot<B: From<Vec<u8>> + From<&'static str> + Default>(
    config: &SnapshotMiddlewareConfig,
    is_head: bool,
) -> Response<B> {
    match find_latest_snapshot(&config.snapshot_dir) {
        Some(path) => {
            info!(path = %path.display(), "serving snapshot file via RPC port");
            serve_file_response(&path, is_head)
        }
        None => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(B::from("No snapshot available"))
            .expect("valid response"),
    }
}

fn serve_file_response<B: From<Vec<u8>> + From<&'static str> + Default>(
    path: &Path,
    is_head: bool,
) -> Response<B> {
    match std::fs::read(path) {
        Ok(data) => {
            let len = data.len();
            let body = if is_head { B::default() } else { B::from(data) };
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/octet-stream")
                .header("content-length", len)
                .body(body)
                .expect("valid response")
        }
        Err(_) => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(B::from("Not Found"))
            .expect("valid response"),
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
