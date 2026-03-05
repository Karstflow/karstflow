//! Tile trait for poll-driven processing units.
//!
//! A tile is a self-contained processing stage that runs in a tight
//! service loop: poll inputs, process fragments, publish results.
//! Tiles communicate exclusively through zero-copy IPC links
//! (TileStem for outputs, StemInput for inputs).
//!
//! Each tile runs on a dedicated thread (or core) and never blocks.
//! The `service()` method is called in a spin loop and returns the
//! number of fragments processed in this iteration.

/// A tile is a poll-driven processing unit in the validator pipeline.
///
/// Tiles run in tight service loops without blocking. Each call to
/// `service()` performs one iteration of work: polling inputs,
/// processing available fragments, and publishing results.
pub trait Tile: Send {
    /// Human-readable tile name for logging and metrics.
    fn name(&self) -> &str;

    /// Initialize the tile. Called once before the service loop begins.
    fn initialize(&mut self) {}

    /// Run one iteration of the service loop.
    ///
    /// Returns the number of fragments processed in this iteration.
    /// A return value of 0 means no work was available (idle iteration).
    fn service(&mut self) -> usize;

    /// Graceful shutdown. Called once after the service loop ends.
    fn shutdown(&mut self) {}
}

/// Runs a tile in a spin loop until the shutdown signal is set.
///
/// This is the standard tile execution pattern:
/// 1. Call `tile.initialize()`
/// 2. Spin-loop calling `tile.service()` until `should_stop()` returns true
/// 3. Call `tile.shutdown()`
///
/// The `should_stop` closure is checked every iteration. For production
/// use, this would check an atomic flag or channel.
pub fn run_tile<F>(tile: &mut dyn Tile, mut should_stop: F)
where
    F: FnMut() -> bool,
{
    tile.initialize();

    loop {
        if should_stop() {
            break;
        }
        tile.service();
    }

    tile.shutdown();
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CounterTile {
        count: usize,
        max: usize,
    }

    impl Tile for CounterTile {
        fn name(&self) -> &str {
            "counter"
        }

        fn service(&mut self) -> usize {
            if self.count < self.max {
                self.count += 1;
                1
            } else {
                0
            }
        }
    }

    #[test]
    fn tile_trait_basic() {
        let mut tile = CounterTile { count: 0, max: 5 };
        assert_eq!(tile.name(), "counter");

        for _ in 0..5 {
            assert_eq!(tile.service(), 1);
        }
        assert_eq!(tile.service(), 0); // idle
        assert_eq!(tile.count, 5);
    }

    #[test]
    fn run_tile_stops() {
        let mut tile = CounterTile { count: 0, max: 10 };
        let mut iterations = 0usize;

        run_tile(&mut tile, || {
            iterations += 1;
            iterations > 10
        });

        assert!(tile.count <= 10);
    }
}
