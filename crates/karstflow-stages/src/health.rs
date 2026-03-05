//! Validator health status for monitoring and orchestration.
//!
//! Provides a shared health status that is updated by the metrics reporter
//! and consumed by the HTTP server for `/health`, `/ready`, and `/alive`
//! probe endpoints.

use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Shared health status updated by the metrics reporter.
pub type SharedHealthStatus = Arc<HealthState>;

/// Create a new shared health status.
pub fn shared_health_status() -> SharedHealthStatus {
    Arc::new(HealthState::new())
}

/// Atomic health state for lock-free reads from HTTP server.
///
/// The heartbeat counter proves the process is alive and making progress.
/// Slot and block height are updated from the working bank on each
/// metrics reporter tick.
pub struct HealthState {
    /// Current slot from working bank.
    slot: AtomicU64,
    /// Current block height from working bank.
    block_height: AtomicU64,
    /// Transaction count from working bank.
    transaction_count: AtomicU64,
    /// Number of active tiles/services.
    active_tiles: AtomicU64,
    /// Monotonically increasing heartbeat counter.
    heartbeat: AtomicU64,
    /// Uptime in milliseconds.
    uptime_millis: AtomicU64,
    /// Known network slot (from gossip, for sync lag calculation).
    network_slot: AtomicU64,
    /// Optional status message (e.g. "syncing", "running", "error").
    status_message: Mutex<String>,
}

impl HealthState {
    fn new() -> Self {
        Self {
            slot: AtomicU64::new(0),
            block_height: AtomicU64::new(0),
            transaction_count: AtomicU64::new(0),
            active_tiles: AtomicU64::new(0),
            heartbeat: AtomicU64::new(0),
            uptime_millis: AtomicU64::new(0),
            network_slot: AtomicU64::new(0),
            status_message: Mutex::new("booting".to_string()),
        }
    }

    /// Update health status from the metrics reporter tick.
    pub fn update(
        &self,
        slot: u64,
        block_height: u64,
        transaction_count: u64,
        active_tiles: u64,
        uptime_millis: u64,
    ) {
        self.slot.store(slot, Ordering::Relaxed);
        self.block_height.store(block_height, Ordering::Relaxed);
        self.transaction_count
            .store(transaction_count, Ordering::Relaxed);
        self.active_tiles.store(active_tiles, Ordering::Relaxed);
        self.uptime_millis.store(uptime_millis, Ordering::Relaxed);
        self.heartbeat.fetch_add(1, Ordering::Relaxed);
    }

    /// Set the known network slot (from gossip or external source).
    pub fn set_network_slot(&self, slot: u64) {
        self.network_slot.store(slot, Ordering::Relaxed);
    }

    /// Set the status message.
    pub fn set_status(&self, status: &str) {
        if let Ok(mut guard) = self.status_message.lock() {
            guard.clear();
            guard.push_str(status);
        }
    }

    /// Current slot.
    pub fn slot(&self) -> u64 {
        self.slot.load(Ordering::Relaxed)
    }

    /// Current heartbeat counter.
    pub fn heartbeat(&self) -> u64 {
        self.heartbeat.load(Ordering::Relaxed)
    }

    /// Compute the slot lag behind the network.
    pub fn slot_lag(&self) -> u64 {
        let net = self.network_slot.load(Ordering::Relaxed);
        let local = self.slot.load(Ordering::Relaxed);
        net.saturating_sub(local)
    }

    /// Whether the validator is considered synced (slot lag below threshold).
    pub fn is_ready(&self, max_lag: u64) -> bool {
        let net = self.network_slot.load(Ordering::Relaxed);
        // If network slot is 0 (not yet known), consider ready
        // once we have any slot data (optimistic for single-node devnet).
        if net == 0 {
            return self.slot.load(Ordering::Relaxed) > 0;
        }
        self.slot_lag() <= max_lag
    }

    /// Build a JSON health response string.
    pub fn to_json(&self) -> String {
        let status = self
            .status_message
            .lock()
            .map(|g| g.clone())
            .unwrap_or_else(|_| "unknown".to_string());

        let report = HealthReport {
            status,
            slot: self.slot.load(Ordering::Relaxed),
            block_height: self.block_height.load(Ordering::Relaxed),
            transaction_count: self.transaction_count.load(Ordering::Relaxed),
            active_tiles: self.active_tiles.load(Ordering::Relaxed),
            heartbeat: self.heartbeat.load(Ordering::Relaxed),
            uptime_millis: self.uptime_millis.load(Ordering::Relaxed),
            network_slot: self.network_slot.load(Ordering::Relaxed),
            slot_lag: self.slot_lag(),
        };

        serde_json::to_string(&report).unwrap_or_else(|_| r#"{"status":"error"}"#.to_string())
    }
}

/// Serializable health report for the `/health` JSON endpoint.
#[derive(Serialize)]
struct HealthReport {
    status: String,
    slot: u64,
    block_height: u64,
    transaction_count: u64,
    active_tiles: u64,
    heartbeat: u64,
    uptime_millis: u64,
    network_slot: u64,
    slot_lag: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_state_defaults() {
        let state = HealthState::new();
        assert_eq!(state.slot(), 0);
        assert_eq!(state.heartbeat(), 0);
        assert_eq!(state.slot_lag(), 0);
    }

    #[test]
    fn update_increments_heartbeat() {
        let state = HealthState::new();
        state.update(100, 50, 1000, 5, 60_000);
        assert_eq!(state.slot(), 100);
        assert_eq!(state.heartbeat(), 1);
        state.update(101, 51, 1010, 5, 61_000);
        assert_eq!(state.heartbeat(), 2);
    }

    #[test]
    fn slot_lag_computed_correctly() {
        let state = HealthState::new();
        state.update(100, 50, 1000, 5, 60_000);
        state.set_network_slot(200);
        assert_eq!(state.slot_lag(), 100);
    }

    #[test]
    fn is_ready_when_synced() {
        let state = HealthState::new();
        state.update(195, 50, 1000, 5, 60_000);
        state.set_network_slot(200);
        assert!(state.is_ready(128)); // lag=5, threshold=128
    }

    #[test]
    fn is_not_ready_when_behind() {
        let state = HealthState::new();
        state.update(50, 25, 500, 5, 30_000);
        state.set_network_slot(200);
        assert!(!state.is_ready(128)); // lag=150, threshold=128
    }

    #[test]
    fn is_ready_single_node_devnet() {
        let state = HealthState::new();
        // Network slot unknown (0), but we have local slot data.
        state.update(10, 5, 100, 3, 5_000);
        assert!(state.is_ready(128));
    }

    #[test]
    fn is_not_ready_before_any_slot() {
        let state = HealthState::new();
        // No data at all.
        assert!(!state.is_ready(128));
    }

    #[test]
    fn to_json_produces_valid_json() {
        let state = HealthState::new();
        state.update(42, 20, 500, 4, 10_000);
        state.set_status("running");

        let json = state.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["status"], "running");
        assert_eq!(parsed["slot"], 42);
        assert_eq!(parsed["block_height"], 20);
        assert_eq!(parsed["active_tiles"], 4);
        assert_eq!(parsed["heartbeat"], 1);
    }

    #[test]
    fn set_status_updates_message() {
        let state = HealthState::new();
        let json = state.to_json();
        assert!(json.contains("booting"));
        state.set_status("running");
        let json = state.to_json();
        assert!(json.contains("running"));
    }
}
