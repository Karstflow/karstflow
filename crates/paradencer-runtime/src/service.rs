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
