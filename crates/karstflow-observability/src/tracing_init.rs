//! Tracing subscriber initialization for the Karstflow validator.
//!
//! Configures structured logging with separate levels for stderr (ephemeral)
//! and optional file output (persistent). Supports both human-readable and
//! JSON formats, with optional ANSI color for terminal output.

use crate::errors::Result;
use std::path::PathBuf;
use tracing_subscriber::fmt::time::SystemTime;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

/// Logging configuration for the validator process.
#[derive(Debug, Clone)]
pub struct TracingConfig {
    /// Minimum log level for stderr output. Defaults to "info".
    pub stderr_level: String,
    /// Minimum log level for the log file. Defaults to "info".
    /// Only used when `log_file_path` is set.
    pub file_level: String,
    /// Path to the persistent log file. When `None`, only stderr is used.
    pub log_file_path: Option<PathBuf>,
    /// Whether to use ANSI color codes for stderr. Defaults to true.
    pub colorize_stderr: bool,
    /// Whether to use JSON format for the log file. Defaults to false.
    /// Stderr always uses human-readable format.
    pub json_file_format: bool,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            stderr_level: "info".to_string(),
            file_level: "info".to_string(),
            log_file_path: None,
            colorize_stderr: true,
            json_file_format: false,
        }
    }
}

/// Guard that keeps the non-blocking file writer alive.
/// Must be held for the lifetime of the process — dropping it flushes
/// and closes the log file.
pub struct TracingGuard {
    _guard: Option<tracing_appender::non_blocking::WorkerGuard>,
}

/// Initialize the global tracing subscriber.
///
/// Sets up a stderr layer (always present) and an optional file layer.
/// The `RUST_LOG` environment variable can override the configured levels
/// for fine-grained per-module control.
///
/// Returns a guard that must be kept alive for the process lifetime.
/// Dropping the guard flushes any buffered log file output.
pub fn init_tracing(config: &TracingConfig) -> Result<TracingGuard> {
    let env_filter_stderr = build_env_filter(&config.stderr_level)?;

    let stderr_layer = fmt::layer()
        .with_ansi(config.colorize_stderr)
        .with_target(true)
        .with_thread_ids(false)
        .with_thread_names(true)
        .with_timer(SystemTime)
        .with_filter(env_filter_stderr);

    match &config.log_file_path {
        Some(path) => {
            let parent = path.parent().unwrap_or(path);
            let file_name = path
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_else(|| "karstflow.log".to_string());

            let file_appender = tracing_appender::rolling::never(parent, file_name);
            let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

            let env_filter_file = build_env_filter(&config.file_level)?;

            if config.json_file_format {
                let file_layer = fmt::layer()
                    .json()
                    .with_ansi(false)
                    .with_target(true)
                    .with_thread_names(true)
                    .with_timer(SystemTime)
                    .with_writer(non_blocking)
                    .with_filter(env_filter_file);

                tracing_subscriber::registry()
                    .with(stderr_layer)
                    .with(file_layer)
                    .init();
            } else {
                let file_layer = fmt::layer()
                    .with_ansi(false)
                    .with_target(true)
                    .with_thread_names(true)
                    .with_timer(SystemTime)
                    .with_writer(non_blocking)
                    .with_filter(env_filter_file);

                tracing_subscriber::registry()
                    .with(stderr_layer)
                    .with(file_layer)
                    .init();
            }

            Ok(TracingGuard {
                _guard: Some(guard),
            })
        }
        None => {
            tracing_subscriber::registry().with(stderr_layer).init();

            Ok(TracingGuard { _guard: None })
        }
    }
}

/// Build an `EnvFilter` from a level string, respecting `RUST_LOG` overrides.
///
/// If `RUST_LOG` is set, it takes full precedence (matching standard Rust
/// convention). Otherwise, the provided level string is used as default.
fn build_env_filter(default_level: &str) -> Result<EnvFilter> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));
    Ok(filter)
}
