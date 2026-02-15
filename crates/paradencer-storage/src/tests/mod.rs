mod accounts;
mod catalog;
mod hot_state;
mod processor;
mod runtime_state;
mod snapshot;

use std::time::{SystemTime, UNIX_EPOCH};

pub(super) fn unique_temp_file(prefix: &str, extension: &str) -> std::path::PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{suffix}.{extension}"))
}
