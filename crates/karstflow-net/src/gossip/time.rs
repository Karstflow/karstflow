/// Shared timestamp helpers for gossip subsystem.
use std::time::SystemTime;

/// Current UNIX timestamp in milliseconds.
#[inline]
pub(super) fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_millis() as u64
}

/// Current UNIX timestamp in nanoseconds.
#[inline]
pub(super) fn current_timestamp_nanos() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos() as i64
}
