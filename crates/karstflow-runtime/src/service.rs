use crate::RuntimeResult;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct ShutdownSwitch {
    requested: Arc<AtomicBool>,
}

impl ShutdownSwitch {
    pub fn new() -> Self {
        Self {
            requested: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn request_stop(&self) {
        self.requested.store(true, Ordering::SeqCst);
    }

    pub fn is_stop_requested(&self) -> bool {
        self.requested.load(Ordering::SeqCst)
    }
}

impl Default for ShutdownSwitch {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ServiceContext {
    pub shutdown: ShutdownSwitch,
    pub launch_time: Instant,
}

impl ServiceContext {
    pub fn new(shutdown: ShutdownSwitch) -> Self {
        Self {
            shutdown,
            launch_time: Instant::now(),
        }
    }
}

pub trait Service: Send + 'static {
    fn name(&self) -> &'static str;

    fn tick_interval(&self) -> Duration {
        Duration::from_millis(50)
    }

    fn on_start(&mut self, _context: &ServiceContext) -> RuntimeResult<()> {
        Ok(())
    }

    fn tick(&mut self, _context: &ServiceContext) -> RuntimeResult<()>;

    fn on_stop(&mut self, _context: &ServiceContext) -> RuntimeResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_switch_initially_not_requested() {
        let switch = ShutdownSwitch::new();
        assert!(!switch.is_stop_requested());
    }

    #[test]
    fn shutdown_switch_request_stop_transitions() {
        let switch = ShutdownSwitch::new();
        switch.request_stop();
        assert!(switch.is_stop_requested());
    }

    #[test]
    fn shutdown_switch_clones_share_state() {
        let switch = ShutdownSwitch::new();
        let clone = switch.clone();
        switch.request_stop();
        assert!(clone.is_stop_requested());
    }

    #[test]
    fn shutdown_switch_default_equals_new() {
        let switch = ShutdownSwitch::default();
        assert!(!switch.is_stop_requested());
    }

    #[test]
    fn shutdown_switch_double_stop_is_idempotent() {
        let switch = ShutdownSwitch::new();
        switch.request_stop();
        switch.request_stop();
        assert!(switch.is_stop_requested());
    }

    #[test]
    fn service_context_captures_shutdown() {
        let switch = ShutdownSwitch::new();
        let ctx = ServiceContext::new(switch.clone());
        switch.request_stop();
        assert!(ctx.shutdown.is_stop_requested());
    }

    #[test]
    fn service_context_launch_time_is_recent() {
        let before = Instant::now();
        let ctx = ServiceContext::new(ShutdownSwitch::new());
        let after = Instant::now();
        assert!(ctx.launch_time >= before);
        assert!(ctx.launch_time <= after);
    }
}
