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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_ms_is_positive() {
        let ts = current_timestamp_ms();
        assert!(ts > 0);
    }

    #[test]
    fn timestamp_ms_is_reasonable() {
        // Should be after 2024-01-01 (1704067200000 ms)
        let ts = current_timestamp_ms();
        assert!(ts > 1_704_067_200_000);
    }

    #[test]
    fn timestamp_nanos_is_positive() {
        let ts = current_timestamp_nanos();
        assert!(ts > 0);
    }

    #[test]
    fn timestamp_nanos_greater_than_millis() {
        let ms = current_timestamp_ms();
        let ns = current_timestamp_nanos();
        // Nanos should be roughly ms * 1_000_000
        assert!(ns as u64 > ms);
    }

    #[test]
    fn timestamp_ms_monotonic_within_call() {
        let t1 = current_timestamp_ms();
        let t2 = current_timestamp_ms();
        assert!(t2 >= t1);
    }
}
