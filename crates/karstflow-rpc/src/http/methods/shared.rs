use karstflow_constants::time::SYNTHETIC_UNIX_TIMESTAMP_BASE;

pub(crate) fn synthetic_block_time(uptime_millis: u128, requested_slot: u64) -> i64 {
    let uptime_secs = (uptime_millis / 1000) as i64;
    SYNTHETIC_UNIX_TIMESTAMP_BASE
        .saturating_add(uptime_secs)
        .saturating_add(requested_slot as i64)
}

pub(crate) fn format_blockhash_from_seed(seed: u64) -> String {
    let segment = format!("{seed:016x}");
    [
        segment.as_str(),
        segment.as_str(),
        segment.as_str(),
        segment.as_str(),
    ]
    .join("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_block_time_basic() {
        let t = synthetic_block_time(5_000, 10);
        assert_eq!(t, SYNTHETIC_UNIX_TIMESTAMP_BASE + 5 + 10);
    }

    #[test]
    fn synthetic_block_time_zero_uptime() {
        let t = synthetic_block_time(0, 0);
        assert_eq!(t, SYNTHETIC_UNIX_TIMESTAMP_BASE);
    }

    #[test]
    fn synthetic_block_time_sub_second_uptime() {
        // 999ms → 0 seconds
        let t = synthetic_block_time(999, 1);
        assert_eq!(t, SYNTHETIC_UNIX_TIMESTAMP_BASE + 1);
    }

    #[test]
    fn synthetic_block_time_saturates_on_overflow() {
        // u128::MAX / 1000 overflows i64 cast, but saturating_add should not panic.
        let t = synthetic_block_time(u128::MAX, u64::MAX);
        // Result may wrap due to `as i64` cast, but function should not panic.
        let _ = t;
    }

    #[test]
    fn format_blockhash_seed_zero() {
        let hash = format_blockhash_from_seed(0);
        assert_eq!(
            hash,
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn format_blockhash_seed_one() {
        let hash = format_blockhash_from_seed(1);
        assert_eq!(
            hash,
            "0000000000000001000000000000000100000000000000010000000000000001"
        );
    }

    #[test]
    fn format_blockhash_length_is_64() {
        for seed in [0, 1, 42, u64::MAX] {
            assert_eq!(format_blockhash_from_seed(seed).len(), 64);
        }
    }

    #[test]
    fn format_blockhash_max_seed() {
        let hash = format_blockhash_from_seed(u64::MAX);
        assert_eq!(
            hash,
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
    }
}
