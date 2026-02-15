use crate::errors::{ObservabilityError, Result};
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::thread;

pub fn spawn_metrics_http_bridge(bind_addr: SocketAddr, metrics_file_path: PathBuf) -> Result<()> {
    let listener = TcpListener::bind(bind_addr)
        .map_err(|source| ObservabilityError::MetricsHttpBind { bind_addr, source })?;
    println!(
        "[metrics-http] serving /metrics on http://{} from file '{}'",
        bind_addr,
        metrics_file_path.display()
    );

    thread::Builder::new()
        .name("metrics-http-bridge".to_string())
        .spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let mut request_buffer = [0_u8; 1024];
                let _ = stream.read(&mut request_buffer);

                let metrics_payload =
                    fs::read_to_string(&metrics_file_path).unwrap_or_else(|_| String::new());

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    metrics_payload.len(),
                    metrics_payload
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        })
        .map_err(ObservabilityError::MetricsHttpThreadSpawn)?;

    Ok(())
}
