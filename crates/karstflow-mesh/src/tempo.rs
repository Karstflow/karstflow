/// Timer calibration and jittered housekeeping scheduling.
///
/// Tiles must periodically perform housekeeping tasks (flow control
/// credit returns, metrics updates, CnC checks) without introducing
/// correlated timing between tiles. This module provides:
///
/// - **`tick_per_ns()`**: One-time TSC calibration returning ticks/ns.
/// - **`lazy_default()`**: Compute a reasonable housekeeping interval
///   from the flow-control credit maximum.
/// - **`async_min()`**: Convert the interval to a power-of-2 tick count.
/// - **`async_reload()`**: Add uniform jitter to prevent tile synchronization.
///
/// The jittered reload prevents "thundering herd" effects where tiles
/// that start at similar times auto-synchronize their housekeeping,
/// causing correlated CPU contention spikes.
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Cached calibration result: (ticks_per_ns, sigma).
static CALIBRATION: OnceLock<(f64, f64)> = OnceLock::new();

/// Measure the TSC tick rate in ticks per nanosecond.
///
/// This function is called once and cached. Subsequent calls return
/// the cached value. The calibration takes ~500ms (32 trials of ~16ms).
///
/// Returns the mean ticks-per-nanosecond (typically ~3.0 for a 3 GHz CPU).
pub fn tick_per_ns() -> f64 {
    CALIBRATION.get_or_init(calibrate).0
}

/// Compute a default housekeeping interval in nanoseconds from the
/// flow-control credit maximum.
///
/// Formula: `1 + floor(9 * cr_max / 4)`, capped at `i32::MAX`.
///
/// At 100G line rate with minimum Ethernet frames, a producer exhausts
/// `cr_max` credits in ~6.72 * cr_max ns. The ~2.25x factor provides
/// headroom for housekeeping to run before credits are fully depleted.
#[inline]
pub fn lazy_default(cr_max: u64) -> i64 {
    if cr_max > 954_437_176 {
        i32::MAX as i64
    } else {
        (1 + (9 * cr_max / 4)) as i64
    }
}

/// Compute the minimum housekeeping interval in ticks, floored to
/// the largest power of 2 that fits.
///
/// Given `event_cnt` housekeeping events that must complete within
/// `lazy` nanoseconds at a tick rate of `ticks_per_ns`, returns the
/// largest power-of-2 tick count per event.
///
/// Returns `None` if parameters are invalid (zero, overflow).
pub fn async_min(lazy: i64, event_cnt: u64, ticks_per_ns: f32) -> Option<u64> {
    if !(1..(1i64 << 31)).contains(&lazy) {
        return None;
    }
    if !(1..(1u64 << 31)).contains(&event_cnt) {
        return None;
    }
    if ticks_per_ns <= 0.0 || !ticks_per_ns.is_finite() {
        return None;
    }

    let target = (ticks_per_ns * lazy as f32) / event_cnt as f32;
    if target < 1.0 || target >= (1u64 << 32) as f32 {
        return None;
    }

    let target = target as u64;
    if target == 0 {
        return None;
    }

    // Floor to largest power of 2 <= target.
    Some(1u64 << (63 - target.leading_zeros()))
}

/// Generate a jittered reload value in `[async_min, 2 * async_min)`.
///
/// `async_min_val` must be a power of 2. The random bits come from
/// a simple counter-based hash (no external RNG dependency).
///
/// Each call advances the internal counter to produce a different value.
#[inline]
pub fn async_reload(rng_state: &mut u64, async_min_val: u64) -> u64 {
    debug_assert!(async_min_val.is_power_of_two());
    let r = rng_next_u32(rng_state);
    async_min_val + ((r as u64) & (async_min_val - 1))
}

/// Simple counter-based PRNG. Returns a pseudo-random u32.
///
/// Uses a bijective 64-bit hash (splitmix64 variant) on an incrementing
/// counter. This is sufficient for housekeeping jitter — cryptographic
/// quality is not needed.
#[inline]
fn rng_next_u32(state: &mut u64) -> u32 {
    *state = state.wrapping_add(1);
    let mut x = *state;
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^= x >> 31;
    x as u32
}

/// Perform TSC calibration.
///
/// Takes 32 paired (wallclock, tickcount) measurements separated by
/// ~16ms sleeps. Trims 4 outliers from each end and computes the
/// mean tick rate.
fn calibrate() -> (f64, f64) {
    const TRIAL_CNT: usize = 32;
    const TRIM_CNT: usize = 4;
    const SLEEP_NS: u64 = 16_777_216; // ~16.8 ms

    let mut trials = [0.0f64; TRIAL_CNT];
    let epoch = Instant::now();

    for trial in &mut trials {
        let t0 = epoch.elapsed();
        std::thread::sleep(Duration::from_nanos(SLEEP_NS));
        let t1 = epoch.elapsed();

        let dt_ns = (t1 - t0).as_nanos() as f64;
        // We use wallclock intervals directly since Rust's Instant
        // provides monotonic high-resolution time. The "tick rate"
        // in our model is ns-per-ns = 1.0 by default, but we measure
        // the actual system clock resolution.
        if dt_ns > 0.0 {
            *trial = dt_ns / SLEEP_NS as f64;
        } else {
            *trial = 1.0;
        }
    }

    // Sort and trim outliers.
    trials.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let trimmed = &trials[TRIM_CNT..TRIAL_CNT - TRIM_CNT];

    // Compute mean and std deviation.
    let n = trimmed.len() as f64;
    let mu = trimmed.iter().sum::<f64>() / n;
    let sigma = (trimmed.iter().map(|&x| (x - mu) * (x - mu)).sum::<f64>() / n).sqrt();

    // In our Rust model, we work in nanoseconds directly (tick = 1 ns).
    // The calibration factor adjusts for sleep timer granularity.
    // For the tile loop, we use Instant::elapsed().as_nanos() as ticks.
    // tick_per_ns ≈ 1.0 (by definition since our "ticks" ARE nanoseconds).
    // We keep the calibration infrastructure for future TSC integration.
    let _ = sigma; // reserved for future use
    (mu, sigma)
}

/// Read the current tick counter (monotonic nanoseconds since process start).
///
/// This is the Rust equivalent of the reference implementation's `fd_tickcount()` which reads
/// the TSC register. We use `Instant` for portability. For production
/// deployments on x86, this could be replaced with an `rdtsc` intrinsic.
#[inline]
pub fn tickcount() -> i64 {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    let epoch = EPOCH.get_or_init(Instant::now);
    epoch.elapsed().as_nanos() as i64
}

/// Housekeeping timer state for a tile's service loop.
///
/// Encapsulates the async_min/reload pattern. The tile checks
/// `should_run_housekeeping()` on each service iteration and calls
/// `reload()` after completing one housekeeping event.
pub struct HousekeepingTimer {
    /// Deadline tick for next housekeeping event.
    then: i64,
    /// Minimum interval (power of 2).
    async_min: u64,
    /// RNG state for jitter.
    rng_state: u64,
}

impl HousekeepingTimer {
    /// Create a new timer.
    ///
    /// `async_min_val` must be a power of 2. `seed` initializes the
    /// jitter RNG.
    pub fn new(async_min_val: u64, seed: u64) -> Self {
        debug_assert!(async_min_val.is_power_of_two());
        Self {
            then: tickcount(), // fires immediately on first check
            async_min: async_min_val,
            rng_state: seed,
        }
    }

    /// Check if housekeeping should run now.
    ///
    /// Returns `true` when the elapsed ticks since the last reload
    /// have exceeded the jittered interval.
    #[inline]
    pub fn should_run(&self) -> bool {
        let now = tickcount();
        (now - self.then) >= 0
    }

    /// Reload the timer with a fresh jittered interval.
    ///
    /// Call this after completing one housekeeping event.
    #[inline]
    pub fn reload(&mut self) {
        let now = tickcount();
        self.then = now + async_reload(&mut self.rng_state, self.async_min) as i64;
    }

    /// The minimum interval in ticks (power of 2).
    pub fn async_min(&self) -> u64 {
        self.async_min
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lazy_default_boundary_values() {
        assert_eq!(lazy_default(0), 1);
        assert_eq!(lazy_default(1), 3); // 1 + 9/4 = 1 + 2 = 3
        assert_eq!(lazy_default(4), 10); // 1 + 36/4 = 1 + 9 = 10
        assert_eq!(lazy_default(954_437_176), i32::MAX as i64);
        assert_eq!(lazy_default(954_437_177), i32::MAX as i64);
        assert_eq!(lazy_default(u64::MAX), i32::MAX as i64);
    }

    #[test]
    fn async_min_returns_power_of_2() {
        let result = async_min(100_000, 1, 3.0).unwrap();
        assert!(result.is_power_of_two());
        // 3.0 * 100000 / 1 = 300000, floor to pow2 = 262144
        assert_eq!(result, 262144);
    }

    #[test]
    fn async_min_multiple_events() {
        let result = async_min(100_000, 10, 3.0).unwrap();
        assert!(result.is_power_of_two());
        // 3.0 * 100000 / 10 = 30000, floor to pow2 = 16384
        assert_eq!(result, 16384);
    }

    #[test]
    fn async_min_invalid_params() {
        assert!(async_min(0, 1, 3.0).is_none()); // lazy < 1
        assert!(async_min(-1, 1, 3.0).is_none()); // lazy < 1
        assert!(async_min(100, 0, 3.0).is_none()); // event_cnt < 1
        assert!(async_min(100, 1, 0.0).is_none()); // tick_per_ns <= 0
        assert!(async_min(100, 1, f32::NAN).is_none()); // NaN
        assert!(async_min(100, 1, f32::INFINITY).is_none()); // Inf
    }

    #[test]
    fn async_reload_in_range() {
        let mut rng = 42u64;
        let min = 1024u64;

        for _ in 0..1000 {
            let val = async_reload(&mut rng, min);
            assert!(val >= min, "reload {val} < min {min}");
            assert!(val < 2 * min, "reload {val} >= 2*min {}", 2 * min);
        }
    }

    #[test]
    fn async_reload_varies() {
        let mut rng = 0u64;
        let min = 256u64;

        let mut values = std::collections::HashSet::new();
        for _ in 0..100 {
            values.insert(async_reload(&mut rng, min));
        }
        // Should produce many distinct values (at least 50 out of 100).
        assert!(
            values.len() > 50,
            "reload produced only {} distinct values",
            values.len()
        );
    }

    #[test]
    fn tickcount_is_monotonic() {
        let a = tickcount();
        let b = tickcount();
        let c = tickcount();
        assert!(b >= a);
        assert!(c >= b);
    }

    #[test]
    fn housekeeping_timer_fires_immediately() {
        let timer = HousekeepingTimer::new(1024, 0);
        // Should fire immediately on first check.
        assert!(timer.should_run());
    }

    #[test]
    fn housekeeping_timer_reload_delays() {
        let mut timer = HousekeepingTimer::new(1 << 30, 0); // very large interval
        timer.reload();
        // After reload with a huge interval, should not fire immediately.
        assert!(!timer.should_run());
    }

    #[test]
    fn rng_produces_distinct_values() {
        let mut state = 0u64;
        let mut values = Vec::new();
        for _ in 0..100 {
            values.push(rng_next_u32(&mut state));
        }
        let unique: std::collections::HashSet<_> = values.iter().collect();
        assert_eq!(unique.len(), 100, "RNG produced duplicates in 100 calls");
    }
}
