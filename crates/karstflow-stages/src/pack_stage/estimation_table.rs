/// Per-program cost estimation table for the pack scheduler.
///
/// Uses exponential moving average (EMA) to estimate the mean and variance
/// of compute unit usage per program. Tags (program IDs) are hashed into
/// a fixed number of bins. Aliasing between programs that hash to the same
/// bin is intentional — it provides a reasonable default for unseen programs.
///
/// When a program has no history, the table returns a configurable default
/// value (typically the max CU limit).

/// A single bin in the estimation table.
#[derive(Debug, Clone, Copy)]
struct Bin {
    /// EMA numerator of values.
    x: f64,
    /// EMA numerator of squared values.
    x2: f64,
    /// EMA denominator (weight sum).
    d: f64,
    /// EMA denominator for variance correction.
    d2: f64,
}

impl Default for Bin {
    fn default() -> Self {
        Self {
            x: 0.0,
            x2: 0.0,
            d: 0.0,
            d2: 0.0,
        }
    }
}

/// EMA-based estimation table with configurable bin count and window.
pub struct EstimationTable {
    bins: Vec<Bin>,
    bin_mask: usize,
    ema_coeff: f64,
    default_val: f64,
}

impl EstimationTable {
    /// Create a new estimation table.
    ///
    /// - `bin_cnt`: number of bins (must be a power of 2, > 0)
    /// - `history`: EMA window size (larger = slower adaptation)
    /// - `default_val`: value returned when no data exists for a tag
    ///
    /// # Panics
    /// Panics if `bin_cnt` is 0 or not a power of 2, or `history` is 0.
    pub fn new(bin_cnt: usize, history: usize, default_val: u32) -> Self {
        assert!(
            bin_cnt > 0 && bin_cnt.is_power_of_two(),
            "bin_cnt must be a power of 2"
        );
        assert!(history > 0, "history must be positive");

        Self {
            bins: vec![Bin::default(); bin_cnt],
            bin_mask: bin_cnt - 1,
            ema_coeff: 1.0 - 1.0 / (history as f64),
            default_val: default_val as f64,
        }
    }

    /// Estimate the mean and variance for the given tag.
    ///
    /// Returns `(mean, variance)`. If no data has been recorded for this
    /// tag (or an aliased tag), returns `(default_val, 0.0)`.
    pub fn estimate(&self, tag: u64) -> (f64, f64) {
        let bin = &self.bins[tag as usize & self.bin_mask];

        if !(bin.d > 0.0) {
            return (self.default_val, 0.0);
        }

        let mean = bin.x / bin.d;
        let denom = bin.d * bin.d - bin.d2;
        let var = if denom > 0.0 {
            let v = (bin.d * bin.x2 - bin.x * bin.x) / denom;
            if v > 0.0 {
                v
            } else {
                0.0
            }
        } else {
            0.0
        };

        (mean, var)
    }

    /// Return the estimated mean for the given tag.
    pub fn estimate_mean(&self, tag: u64) -> f64 {
        self.estimate(tag).0
    }

    /// Insert a new observation for the given tag.
    pub fn update(&mut self, tag: u64, value: u32) {
        let c = self.ema_coeff;
        let bin = &mut self.bins[tag as usize & self.bin_mask];
        let v = value as f64;

        bin.x = v + if c * bin.x > f64::MIN_POSITIVE {
            c * bin.x
        } else {
            0.0
        };
        bin.x2 = v * v
            + if c * bin.x2 > f64::MIN_POSITIVE {
                c * bin.x2
            } else {
                0.0
            };
        bin.d = 1.0 + c * bin.d;
        bin.d2 = 1.0 + c * c * bin.d2;
    }

    /// Reset all bins to empty state.
    pub fn reset(&mut self) {
        for bin in &mut self.bins {
            *bin = Bin::default();
        }
    }

    /// Number of bins in the table.
    pub fn bin_count(&self) -> usize {
        self.bin_mask + 1
    }

    /// The default value used when no data exists.
    pub fn default_val(&self) -> f64 {
        self.default_val
    }
}

/// Hash a program ID (32 bytes) to a u64 tag for the estimation table.
///
/// Uses the first 8 bytes as a quick hash, matching the reference approach.
pub fn program_id_to_tag(program_id: &[u8; 32]) -> u64 {
    u64::from_le_bytes(program_id[..8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_table_returns_default() {
        let tbl = EstimationTable::new(64, 100, 200_000);
        let (mean, var) = tbl.estimate(42);
        assert_eq!(mean, 200_000.0);
        assert_eq!(var, 0.0);
    }

    #[test]
    fn single_update_changes_mean() {
        let mut tbl = EstimationTable::new(64, 100, 200_000);
        tbl.update(42, 150_000);
        let (mean, _) = tbl.estimate(42);
        assert_eq!(mean, 150_000.0);
    }

    #[test]
    fn multiple_updates_converge() {
        let mut tbl = EstimationTable::new(64, 10, 200_000);
        for _ in 0..100 {
            tbl.update(7, 50_000);
        }
        let (mean, _) = tbl.estimate(7);
        assert!((mean - 50_000.0).abs() < 1.0);
    }

    #[test]
    fn ema_decay_toward_new_values() {
        let mut tbl = EstimationTable::new(64, 5, 200_000);
        // Insert many 100k values
        for _ in 0..50 {
            tbl.update(1, 100_000);
        }
        let (mean1, _) = tbl.estimate(1);
        assert!((mean1 - 100_000.0).abs() < 1.0);

        // Now insert 200k values — mean should shift
        for _ in 0..50 {
            tbl.update(1, 200_000);
        }
        let (mean2, _) = tbl.estimate(1);
        assert!(
            (mean2 - 200_000.0).abs() < 100.0,
            "mean should converge near 200k: {mean2}"
        );
    }

    #[test]
    fn variance_is_non_negative() {
        let mut tbl = EstimationTable::new(64, 10, 200_000);
        tbl.update(0, 100_000);
        tbl.update(0, 200_000);
        tbl.update(0, 50_000);
        let (_, var) = tbl.estimate(0);
        assert!(var >= 0.0);
    }

    #[test]
    fn constant_values_zero_variance() {
        let mut tbl = EstimationTable::new(64, 10, 200_000);
        for _ in 0..100 {
            tbl.update(5, 100_000);
        }
        let (_, var) = tbl.estimate(5);
        assert!(
            var < 1.0,
            "variance should be near zero for constant input: {var}"
        );
    }

    #[test]
    fn different_tags_independent() {
        let mut tbl = EstimationTable::new(256, 10, 200_000);
        for _ in 0..50 {
            tbl.update(1, 100_000);
            tbl.update(2, 50_000);
        }
        let (m1, _) = tbl.estimate(1);
        let (m2, _) = tbl.estimate(2);
        assert!((m1 - 100_000.0).abs() < 1.0);
        assert!((m2 - 50_000.0).abs() < 1.0);
    }

    #[test]
    fn aliased_tags_blend() {
        // With 4 bins, tags 0 and 4 alias to the same bin
        let mut tbl = EstimationTable::new(4, 10, 200_000);
        for _ in 0..50 {
            tbl.update(0, 100_000);
        }
        for _ in 0..50 {
            tbl.update(4, 200_000);
        }
        // Both share the bin, so estimates will blend
        let (m0, _) = tbl.estimate(0);
        let (m4, _) = tbl.estimate(4);
        assert_eq!(m0, m4); // same bin
    }

    #[test]
    fn reset_clears_all_bins() {
        let mut tbl = EstimationTable::new(64, 10, 200_000);
        tbl.update(1, 100_000);
        tbl.reset();
        let (mean, _) = tbl.estimate(1);
        assert_eq!(mean, 200_000.0);
    }

    #[test]
    fn program_id_hash() {
        let mut id = [0u8; 32];
        id[0] = 0xAB;
        id[1] = 0xCD;
        let tag = program_id_to_tag(&id);
        assert_eq!(tag & 0xFFFF, 0xCDAB);
    }

    #[test]
    #[should_panic]
    fn zero_bin_count_panics() {
        EstimationTable::new(0, 10, 200_000);
    }

    #[test]
    #[should_panic]
    fn non_power_of_two_panics() {
        EstimationTable::new(3, 10, 200_000);
    }

    #[test]
    #[should_panic]
    fn zero_history_panics() {
        EstimationTable::new(64, 0, 200_000);
    }
}
