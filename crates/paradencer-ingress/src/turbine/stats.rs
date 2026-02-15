use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Statistics for turbine propagation
#[derive(Debug, Default)]
pub struct TurbineStats {
    /// Number of shreds broadcast
    pub shreds_broadcast: AtomicU64,

    /// Number of shreds retransmitted
    pub shreds_retransmitted: AtomicU64,

    /// Number of shreds received
    pub shreds_received: AtomicU64,

    /// Number of shreds dropped
    pub shreds_dropped: AtomicU64,

    /// Number of successful broadcasts
    pub broadcast_success: AtomicU64,

    /// Number of failed broadcasts
    pub broadcast_failures: AtomicU64,

    /// Number of retransmit attempts
    pub retransmit_attempts: AtomicU64,

    /// Number of retransmit timeouts
    pub retransmit_timeouts: AtomicU64,

    /// Total bytes transmitted
    pub bytes_transmitted: AtomicU64,

    /// Total bytes received
    pub bytes_received: AtomicU64,

    /// Number of tree rebuilds
    pub tree_rebuilds: AtomicU64,

    /// Number of active layer1 peers
    pub active_layer1_peers: AtomicUsize,

    /// Number of active layer2 peers
    pub active_layer2_peers: AtomicUsize,
}

impl TurbineStats {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful broadcast
    pub fn record_broadcast(&self, num_shreds: u64, num_bytes: u64) {
        self.shreds_broadcast
            .fetch_add(num_shreds, Ordering::Relaxed);
        self.bytes_transmitted
            .fetch_add(num_bytes, Ordering::Relaxed);
        self.broadcast_success.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a failed broadcast
    pub fn record_broadcast_failure(&self) {
        self.broadcast_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a retransmit
    pub fn record_retransmit(&self, num_shreds: u64, num_bytes: u64) {
        self.shreds_retransmitted
            .fetch_add(num_shreds, Ordering::Relaxed);
        self.bytes_transmitted
            .fetch_add(num_bytes, Ordering::Relaxed);
        self.retransmit_attempts.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a retransmit timeout
    pub fn record_retransmit_timeout(&self) {
        self.retransmit_timeouts.fetch_add(1, Ordering::Relaxed);
    }

    /// Record received shred
    pub fn record_received(&self, num_bytes: u64) {
        self.shreds_received.fetch_add(1, Ordering::Relaxed);
        self.bytes_received.fetch_add(num_bytes, Ordering::Relaxed);
    }

    /// Record dropped shred
    pub fn record_dropped(&self) {
        self.shreds_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Record tree rebuild
    pub fn record_tree_rebuild(&self) {
        self.tree_rebuilds.fetch_add(1, Ordering::Relaxed);
    }

    /// Update active peer counts
    pub fn update_peer_counts(&self, layer1: usize, layer2: usize) {
        self.active_layer1_peers.store(layer1, Ordering::Relaxed);
        self.active_layer2_peers.store(layer2, Ordering::Relaxed);
    }

    /// Get broadcast success count
    pub fn broadcast_success_count(&self) -> u64 {
        self.broadcast_success.load(Ordering::Relaxed)
    }

    /// Get broadcast failure count
    pub fn broadcast_failure_count(&self) -> u64 {
        self.broadcast_failures.load(Ordering::Relaxed)
    }

    /// Get total shreds broadcast
    pub fn total_shreds_broadcast(&self) -> u64 {
        self.shreds_broadcast.load(Ordering::Relaxed)
    }

    /// Get total shreds retransmitted
    pub fn total_shreds_retransmitted(&self) -> u64 {
        self.shreds_retransmitted.load(Ordering::Relaxed)
    }

    /// Get total shreds received
    pub fn total_shreds_received(&self) -> u64 {
        self.shreds_received.load(Ordering::Relaxed)
    }

    /// Get total bytes transmitted
    pub fn total_bytes_transmitted(&self) -> u64 {
        self.bytes_transmitted.load(Ordering::Relaxed)
    }

    /// Get layer1 peer count
    pub fn layer1_peer_count(&self) -> usize {
        self.active_layer1_peers.load(Ordering::Relaxed)
    }

    /// Get layer2 peer count
    pub fn layer2_peer_count(&self) -> usize {
        self.active_layer2_peers.load(Ordering::Relaxed)
    }

    /// Reset all statistics
    pub fn reset(&self) {
        self.shreds_broadcast.store(0, Ordering::Relaxed);
        self.shreds_retransmitted.store(0, Ordering::Relaxed);
        self.shreds_received.store(0, Ordering::Relaxed);
        self.shreds_dropped.store(0, Ordering::Relaxed);
        self.broadcast_success.store(0, Ordering::Relaxed);
        self.broadcast_failures.store(0, Ordering::Relaxed);
        self.retransmit_attempts.store(0, Ordering::Relaxed);
        self.retransmit_timeouts.store(0, Ordering::Relaxed);
        self.bytes_transmitted.store(0, Ordering::Relaxed);
        self.bytes_received.store(0, Ordering::Relaxed);
        self.tree_rebuilds.store(0, Ordering::Relaxed);
    }
}

/// Propagation metrics for a specific slot
#[derive(Debug, Clone)]
pub struct PropagationMetrics {
    /// Slot number
    pub slot: u64,

    /// Time when first shred was sent
    pub start_time: Instant,

    /// Time when last shred was confirmed received by all layer1 peers
    pub layer1_completion_time: Option<Instant>,

    /// Time when last shred was confirmed received by all peers
    pub full_completion_time: Option<Instant>,

    /// Number of shreds in the slot
    pub total_shreds: usize,

    /// Number of shreds confirmed received by layer1 peers
    pub layer1_confirmed_shreds: usize,

    /// Number of shreds confirmed received by all peers
    pub fully_confirmed_shreds: usize,

    /// Number of retransmits required
    pub retransmits_required: usize,
}

impl PropagationMetrics {
    pub fn new(slot: u64, total_shreds: usize) -> Self {
        Self {
            slot,
            start_time: Instant::now(),
            layer1_completion_time: None,
            full_completion_time: None,
            total_shreds,
            layer1_confirmed_shreds: 0,
            fully_confirmed_shreds: 0,
            retransmits_required: 0,
        }
    }

    /// Record layer1 shred confirmation
    pub fn record_layer1_confirmation(&mut self) {
        self.layer1_confirmed_shreds += 1;
        if self.layer1_confirmed_shreds == self.total_shreds
            && self.layer1_completion_time.is_none()
        {
            self.layer1_completion_time = Some(Instant::now());
        }
    }

    /// Record full shred confirmation
    pub fn record_full_confirmation(&mut self) {
        self.fully_confirmed_shreds += 1;
        if self.fully_confirmed_shreds == self.total_shreds && self.full_completion_time.is_none() {
            self.full_completion_time = Some(Instant::now());
        }
    }

    /// Record a retransmit
    pub fn record_retransmit(&mut self) {
        self.retransmits_required += 1;
    }

    /// Get layer1 propagation time in milliseconds
    pub fn layer1_propagation_time_ms(&self) -> Option<u64> {
        self.layer1_completion_time
            .map(|end| end.duration_since(self.start_time).as_millis() as u64)
    }

    /// Get full propagation time in milliseconds
    pub fn full_propagation_time_ms(&self) -> Option<u64> {
        self.full_completion_time
            .map(|end| end.duration_since(self.start_time).as_millis() as u64)
    }

    /// Get layer1 completion percentage
    pub fn layer1_completion_percentage(&self) -> f64 {
        if self.total_shreds == 0 {
            0.0
        } else {
            (self.layer1_confirmed_shreds as f64 / self.total_shreds as f64) * 100.0
        }
    }

    /// Get full completion percentage
    pub fn full_completion_percentage(&self) -> f64 {
        if self.total_shreds == 0 {
            0.0
        } else {
            (self.fully_confirmed_shreds as f64 / self.total_shreds as f64) * 100.0
        }
    }

    /// Check if layer1 propagation is complete
    pub fn is_layer1_complete(&self) -> bool {
        self.layer1_confirmed_shreds >= self.total_shreds
    }

    /// Check if full propagation is complete
    pub fn is_fully_complete(&self) -> bool {
        self.fully_confirmed_shreds >= self.total_shreds
    }
}

/// Broadcast statistics tracker
#[derive(Debug)]
pub struct BroadcastStats {
    inner: Arc<TurbineStats>,
}

impl BroadcastStats {
    pub fn new(stats: Arc<TurbineStats>) -> Self {
        Self { inner: stats }
    }

    /// Record a successful broadcast
    pub fn record_success(&self, num_shreds: u64, num_bytes: u64) {
        self.inner.record_broadcast(num_shreds, num_bytes);
    }

    /// Record a failed broadcast
    pub fn record_failure(&self) {
        self.inner.record_broadcast_failure();
    }

    /// Get the underlying stats
    pub fn stats(&self) -> &Arc<TurbineStats> {
        &self.inner
    }
}

impl Clone for BroadcastStats {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

/// Retransmit statistics tracker
#[derive(Debug)]
pub struct RetransmitStats {
    inner: Arc<TurbineStats>,
}

impl RetransmitStats {
    pub fn new(stats: Arc<TurbineStats>) -> Self {
        Self { inner: stats }
    }

    /// Record a retransmit
    pub fn record_retransmit(&self, num_shreds: u64, num_bytes: u64) {
        self.inner.record_retransmit(num_shreds, num_bytes);
    }

    /// Record a timeout
    pub fn record_timeout(&self) {
        self.inner.record_retransmit_timeout();
    }

    /// Get the underlying stats
    pub fn stats(&self) -> &Arc<TurbineStats> {
        &self.inner
    }
}

impl Clone for RetransmitStats {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_turbine_stats() {
        let stats = TurbineStats::new();

        stats.record_broadcast(10, 12280);
        assert_eq!(stats.total_shreds_broadcast(), 10);
        assert_eq!(stats.total_bytes_transmitted(), 12280);
        assert_eq!(stats.broadcast_success_count(), 1);

        stats.record_retransmit(5, 6140);
        assert_eq!(stats.total_shreds_retransmitted(), 5);
        assert_eq!(stats.total_bytes_transmitted(), 18420);

        stats.record_received(1228);
        assert_eq!(stats.total_shreds_received(), 1);
    }

    #[test]
    fn test_propagation_metrics() {
        let mut metrics = PropagationMetrics::new(100, 10);

        assert_eq!(metrics.slot, 100);
        assert_eq!(metrics.total_shreds, 10);
        assert!(!metrics.is_layer1_complete());

        for _ in 0..10 {
            metrics.record_layer1_confirmation();
        }

        assert!(metrics.is_layer1_complete());
        assert!(metrics.layer1_completion_time.is_some());
        assert_eq!(metrics.layer1_completion_percentage(), 100.0);
    }

    #[test]
    fn test_broadcast_stats() {
        let stats = Arc::new(TurbineStats::new());
        let broadcast_stats = BroadcastStats::new(Arc::clone(&stats));

        broadcast_stats.record_success(5, 6140);
        assert_eq!(stats.broadcast_success_count(), 1);
        assert_eq!(stats.total_shreds_broadcast(), 5);
    }

    #[test]
    fn test_retransmit_stats() {
        let stats = Arc::new(TurbineStats::new());
        let retransmit_stats = RetransmitStats::new(Arc::clone(&stats));

        retransmit_stats.record_retransmit(3, 3684);
        assert_eq!(stats.total_shreds_retransmitted(), 3);

        retransmit_stats.record_timeout();
        assert_eq!(stats.retransmit_timeouts.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_stats_reset() {
        let stats = TurbineStats::new();

        stats.record_broadcast(10, 12280);
        stats.record_retransmit(5, 6140);

        stats.reset();

        assert_eq!(stats.total_shreds_broadcast(), 0);
        assert_eq!(stats.total_shreds_retransmitted(), 0);
        assert_eq!(stats.total_bytes_transmitted(), 0);
    }
}
