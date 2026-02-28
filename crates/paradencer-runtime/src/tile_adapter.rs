//! Adapter that wraps a [`Service`] as a [`Tile`].
//!
//! This bridges the two execution models: tick-based services become
//! poll-driven tiles without code changes. The adapter calls `tick()`
//! on each `service()` invocation and manages the lifecycle mapping
//! (`on_start` → `initialize`, `on_stop` → `shutdown`).

use crate::service::{Service, ServiceContext, ShutdownSwitch};
use paradencer_mesh::Tile;

/// Wraps a [`Service`] into a [`Tile`] for poll-driven execution.
///
/// Each `service()` call invokes the underlying `tick()`. The tile
/// spins calling `service()` in a tight loop — unlike the Service
/// executor which sleeps between ticks. This gives maximum throughput
/// at the cost of 100% CPU per core.
pub struct TileAdapter {
    inner: Box<dyn Service>,
    context: ServiceContext,
    name: String,
    started: bool,
    errored: bool,
}

impl TileAdapter {
    /// Create a new tile adapter wrapping the given service.
    pub fn new(service: Box<dyn Service>, shutdown: ShutdownSwitch) -> Self {
        let name = service.name().to_string();
        Self {
            inner: service,
            context: ServiceContext::new(shutdown),
            name,
            started: false,
            errored: false,
        }
    }
}

impl Tile for TileAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn initialize(&mut self) {
        if let Err(e) = self.inner.on_start(&self.context) {
            tracing::error!(service = %self.name, error = %e, "service on_start failed");
            self.errored = true;
        }
        self.started = true;
    }

    fn service(&mut self) -> usize {
        if self.errored || self.context.shutdown.is_stop_requested() {
            return 0;
        }
        match self.inner.tick(&self.context) {
            Ok(()) => 1,
            Err(e) => {
                tracing::error!(service = %self.name, error = %e, "service tick failed");
                self.errored = true;
                self.context.shutdown.request_stop();
                0
            }
        }
    }

    fn shutdown(&mut self) {
        if self.started {
            if let Err(e) = self.inner.on_stop(&self.context) {
                tracing::error!(service = %self.name, error = %e, "service on_stop failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RuntimeResult;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct CountingService {
        tick_count: Arc<AtomicUsize>,
        started: Arc<AtomicUsize>,
        stopped: Arc<AtomicUsize>,
    }

    impl Service for CountingService {
        fn name(&self) -> &'static str {
            "counting"
        }
        fn on_start(&mut self, _ctx: &ServiceContext) -> RuntimeResult<()> {
            self.started.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        fn tick(&mut self, _ctx: &ServiceContext) -> RuntimeResult<()> {
            self.tick_count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        fn on_stop(&mut self, _ctx: &ServiceContext) -> RuntimeResult<()> {
            self.stopped.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[test]
    fn adapter_lifecycle() {
        let ticks = Arc::new(AtomicUsize::new(0));
        let starts = Arc::new(AtomicUsize::new(0));
        let stops = Arc::new(AtomicUsize::new(0));

        let svc = CountingService {
            tick_count: ticks.clone(),
            started: starts.clone(),
            stopped: stops.clone(),
        };

        let shutdown = ShutdownSwitch::new();
        let mut adapter = TileAdapter::new(Box::new(svc), shutdown);

        adapter.initialize();
        assert_eq!(starts.load(Ordering::Relaxed), 1);

        for _ in 0..5 {
            let processed = adapter.service();
            assert_eq!(processed, 1);
        }
        assert_eq!(ticks.load(Ordering::Relaxed), 5);

        adapter.shutdown();
        assert_eq!(stops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn adapter_stops_on_shutdown_signal() {
        let ticks = Arc::new(AtomicUsize::new(0));
        let svc = CountingService {
            tick_count: ticks.clone(),
            started: Arc::new(AtomicUsize::new(0)),
            stopped: Arc::new(AtomicUsize::new(0)),
        };

        let shutdown = ShutdownSwitch::new();
        let mut adapter = TileAdapter::new(Box::new(svc), shutdown.clone());

        adapter.initialize();
        assert_eq!(adapter.service(), 1);

        shutdown.request_stop();
        assert_eq!(adapter.service(), 0); // returns 0 after shutdown
        adapter.shutdown();
    }

    struct FailingService;

    impl Service for FailingService {
        fn name(&self) -> &'static str {
            "failing"
        }
        fn tick(&mut self, _ctx: &ServiceContext) -> RuntimeResult<()> {
            Err(crate::RuntimeError::service_failure("failing", "boom"))
        }
    }

    #[test]
    fn adapter_handles_tick_error() {
        let shutdown = ShutdownSwitch::new();
        let mut adapter = TileAdapter::new(Box::new(FailingService), shutdown.clone());

        adapter.initialize();
        assert_eq!(adapter.service(), 0); // error returns 0
        assert!(shutdown.is_stop_requested()); // triggers shutdown
        assert_eq!(adapter.service(), 0); // stays at 0
    }
}
