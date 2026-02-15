use paradencer_constants::time::SYNTHETIC_UNIX_TIMESTAMP_BASE;

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
