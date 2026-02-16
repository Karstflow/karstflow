/// Slot timing and metrics tracking for replay performance analysis
///
/// Provides comprehensive metrics about replay performance including:
/// - Per-slot timing measurements
/// - Transaction throughput tracking
/// - Resource utilization monitoring
/// - Performance degradation detection
use paradencer_constants::execution::MAX_COMPUTE_UNITS;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Metrics for a single slot replay
#[derive(Debug, Clone)]
pub struct SlotMetrics {
    /// Slot number
    pub slot: u64,
    /// Time when replay started
    pub start_time: Instant,
    /// Time when replay completed
    pub end_time: Option<Instant>,
    /// Number of transactions processed
    pub transaction_count: usize,
    /// Number of successful transactions
    pub successful_transactions: usize,
    /// Number of failed transactions
    pub failed_transactions: usize,
    /// Total compute units consumed
    pub compute_units: u64,
    /// Number of entries processed
    pub entry_count: usize,
    /// Number of ticks registered
    pub tick_count: usize,
    /// Whether bank was frozen
    pub bank_frozen: bool,
    /// Whether votes were processed
    pub votes_processed: usize,
}

impl SlotMetrics {
    pub fn new(slot: u64) -> Self {
        Self {
            slot,
            start_time: Instant::now(),
            end_time: None,
            transaction_count: 0,
            successful_transactions: 0,
            failed_transactions: 0,
            compute_units: 0,
            entry_count: 0,
            tick_count: 0,
            bank_frozen: false,
            votes_processed: 0,
        }
    }

    /// Mark replay as complete
    pub fn complete(&mut self) {
        self.end_time = Some(Instant::now());
    }

    /// Get elapsed time in microseconds
    pub fn elapsed_micros(&self) -> Option<u64> {
        self.end_time
            .map(|end| end.duration_since(self.start_time).as_micros() as u64)
    }

    /// Get elapsed time in milliseconds
    pub fn elapsed_millis(&self) -> Option<u64> {
        self.end_time
            .map(|end| end.duration_since(self.start_time).as_millis() as u64)
    }

    /// Get transaction success rate
    pub fn success_rate(&self) -> f64 {
        if self.transaction_count == 0 {
            return 1.0;
        }
        self.successful_transactions as f64 / self.transaction_count as f64
    }

    /// Get transactions per second
    pub fn tps(&self) -> Option<f64> {
        self.elapsed_micros().map(|micros| {
            if micros == 0 {
                return 0.0;
            }
            let seconds = micros as f64 / 1_000_000.0;
            self.transaction_count as f64 / seconds
        })
    }

    /// Get compute units per transaction
    pub fn compute_per_tx(&self) -> u64 {
        if self.transaction_count == 0 {
            return 0;
        }
        self.compute_units / self.transaction_count as u64
    }
}

/// Aggregate metrics across multiple slots
#[derive(Debug, Clone)]
pub struct AggregateMetrics {
    /// Total slots processed
    pub total_slots: usize,
    /// Total transactions processed
    pub total_transactions: usize,
    /// Total successful transactions
    pub total_successful: usize,
    /// Total failed transactions
    pub total_failed: usize,
    /// Total compute units
    pub total_compute_units: u64,
    /// Total elapsed time in microseconds
    pub total_elapsed_micros: u64,
    /// Average slot processing time in microseconds
    pub avg_slot_time_micros: u64,
    /// Average transaction processing time in microseconds
    pub avg_tx_time_micros: u64,
    /// Average transactions per slot
    pub avg_txs_per_slot: f64,
    /// Overall success rate
    pub overall_success_rate: f64,
    /// Overall TPS
    pub overall_tps: f64,
}

impl AggregateMetrics {
    pub fn from_slot_metrics(metrics: &[SlotMetrics]) -> Self {
        let total_slots = metrics.len();
        let total_transactions: usize = metrics.iter().map(|m| m.transaction_count).sum();
        let total_successful: usize = metrics.iter().map(|m| m.successful_transactions).sum();
        let total_failed: usize = metrics.iter().map(|m| m.failed_transactions).sum();
        let total_compute_units: u64 = metrics.iter().map(|m| m.compute_units).sum();
        let total_elapsed_micros: u64 = metrics.iter().filter_map(|m| m.elapsed_micros()).sum();

        let avg_slot_time_micros = if total_slots > 0 {
            total_elapsed_micros / total_slots as u64
        } else {
            0
        };

        let avg_tx_time_micros = if total_transactions > 0 {
            total_elapsed_micros / total_transactions as u64
        } else {
            0
        };

        let avg_txs_per_slot = if total_slots > 0 {
            total_transactions as f64 / total_slots as f64
        } else {
            0.0
        };

        let overall_success_rate = if total_transactions > 0 {
            total_successful as f64 / total_transactions as f64
        } else {
            1.0
        };

        let overall_tps = if total_elapsed_micros > 0 {
            let seconds = total_elapsed_micros as f64 / 1_000_000.0;
            total_transactions as f64 / seconds
        } else {
            0.0
        };

        Self {
            total_slots,
            total_transactions,
            total_successful,
            total_failed,
            total_compute_units,
            total_elapsed_micros,
            avg_slot_time_micros,
            avg_tx_time_micros,
            avg_txs_per_slot,
            overall_success_rate,
            overall_tps,
        }
    }
}

/// Tracker for replay metrics with rolling window
pub struct MetricsTracker {
    /// Recent slot metrics (ring buffer)
    recent_metrics: VecDeque<SlotMetrics>,
    /// Maximum metrics to keep
    max_metrics: usize,
    /// Metrics by slot number
    metrics_by_slot: HashMap<u64, SlotMetrics>,
    /// Current slot being tracked
    current_slot: Option<u64>,
    /// Enable detailed tracking
    detailed_tracking: bool,
}

impl MetricsTracker {
    pub fn new(max_metrics: usize) -> Self {
        Self {
            recent_metrics: VecDeque::new(),
            max_metrics,
            metrics_by_slot: HashMap::new(),
            current_slot: None,
            detailed_tracking: true,
        }
    }

    pub fn with_detailed_tracking(mut self, enabled: bool) -> Self {
        self.detailed_tracking = enabled;
        self
    }

    /// Start tracking a new slot
    pub fn start_slot(&mut self, slot: u64) {
        let metrics = SlotMetrics::new(slot);
        self.current_slot = Some(slot);
        if self.detailed_tracking {
            self.metrics_by_slot.insert(slot, metrics.clone());
        }
        self.add_to_recent(metrics);
    }

    /// Complete the current slot
    pub fn complete_slot(&mut self) {
        if let Some(slot) = self.current_slot {
            if let Some(metrics) = self.metrics_by_slot.get_mut(&slot) {
                metrics.complete();
            }

            // Update recent metrics
            if let Some(recent) = self.recent_metrics.iter_mut().find(|m| m.slot == slot) {
                recent.complete();
            }

            self.current_slot = None;
        }
    }

    /// Record transaction processing
    pub fn record_transaction(&mut self, success: bool, compute_units: u64) {
        if let Some(slot) = self.current_slot {
            if let Some(metrics) = self.metrics_by_slot.get_mut(&slot) {
                metrics.transaction_count += 1;
                if success {
                    metrics.successful_transactions += 1;
                } else {
                    metrics.failed_transactions += 1;
                }
                metrics.compute_units += compute_units;
            }

            // Update recent metrics
            if let Some(recent) = self.recent_metrics.iter_mut().find(|m| m.slot == slot) {
                recent.transaction_count += 1;
                if success {
                    recent.successful_transactions += 1;
                } else {
                    recent.failed_transactions += 1;
                }
                recent.compute_units += compute_units;
            }
        }
    }

    /// Record entry processing
    pub fn record_entry(&mut self) {
        if let Some(slot) = self.current_slot {
            if let Some(metrics) = self.metrics_by_slot.get_mut(&slot) {
                metrics.entry_count += 1;
            }
        }
    }

    /// Record tick registration
    pub fn record_tick(&mut self) {
        if let Some(slot) = self.current_slot {
            if let Some(metrics) = self.metrics_by_slot.get_mut(&slot) {
                metrics.tick_count += 1;
            }
        }
    }

    /// Record bank freeze
    pub fn record_bank_freeze(&mut self) {
        if let Some(slot) = self.current_slot {
            if let Some(metrics) = self.metrics_by_slot.get_mut(&slot) {
                metrics.bank_frozen = true;
            }
        }
    }

    /// Record vote processing
    pub fn record_vote(&mut self, count: usize) {
        if let Some(slot) = self.current_slot {
            if let Some(metrics) = self.metrics_by_slot.get_mut(&slot) {
                metrics.votes_processed += count;
            }
        }
    }

    /// Add metrics to recent window
    fn add_to_recent(&mut self, metrics: SlotMetrics) {
        if self.recent_metrics.len() >= self.max_metrics {
            self.recent_metrics.pop_front();
        }
        self.recent_metrics.push_back(metrics);
    }

    /// Get metrics for a specific slot
    pub fn get_slot_metrics(&self, slot: u64) -> Option<&SlotMetrics> {
        self.metrics_by_slot.get(&slot)
    }

    /// Get recent metrics
    pub fn recent_metrics(&self) -> &VecDeque<SlotMetrics> {
        &self.recent_metrics
    }

    /// Get aggregate metrics for recent slots
    pub fn aggregate_recent(&self) -> AggregateMetrics {
        let metrics: Vec<_> = self.recent_metrics.iter().cloned().collect();
        AggregateMetrics::from_slot_metrics(&metrics)
    }

    /// Get aggregate metrics for all tracked slots
    pub fn aggregate_all(&self) -> AggregateMetrics {
        let metrics: Vec<_> = self.metrics_by_slot.values().cloned().collect();
        AggregateMetrics::from_slot_metrics(&metrics)
    }

    /// Clear old metrics below a slot
    pub fn prune_below_slot(&mut self, slot: u64) {
        self.metrics_by_slot.retain(|&s, _| s >= slot);
    }

    /// Get slowest slots
    pub fn slowest_slots(&self, count: usize) -> Vec<(u64, u64)> {
        let mut slots_with_time: Vec<_> = self
            .recent_metrics
            .iter()
            .filter_map(|m| m.elapsed_micros().map(|t| (m.slot, t)))
            .collect();

        slots_with_time.sort_by_key(|(_, time)| std::cmp::Reverse(*time));
        slots_with_time.truncate(count);
        slots_with_time
    }

    /// Get fastest slots
    pub fn fastest_slots(&self, count: usize) -> Vec<(u64, u64)> {
        let mut slots_with_time: Vec<_> = self
            .recent_metrics
            .iter()
            .filter_map(|m| m.elapsed_micros().map(|t| (m.slot, t)))
            .collect();

        slots_with_time.sort_by_key(|(_, time)| *time);
        slots_with_time.truncate(count);
        slots_with_time
    }

    /// Detect performance anomalies
    pub fn detect_anomalies(&self, threshold_percent: f64) -> Vec<PerformanceAnomaly> {
        let mut anomalies = Vec::new();

        let aggregate = self.aggregate_recent();
        let avg_time = aggregate.avg_slot_time_micros;

        for metrics in &self.recent_metrics {
            if let Some(elapsed) = metrics.elapsed_micros() {
                let percent_diff = (elapsed as f64 - avg_time as f64) / avg_time as f64 * 100.0;

                if percent_diff.abs() > threshold_percent {
                    anomalies.push(PerformanceAnomaly {
                        slot: metrics.slot,
                        expected_micros: avg_time,
                        actual_micros: elapsed,
                        percent_deviation: percent_diff,
                        anomaly_type: if percent_diff > 0.0 {
                            AnomalyType::SlowSlot
                        } else {
                            AnomalyType::FastSlot
                        },
                    });
                }
            }
        }

        anomalies
    }
}

/// Performance anomaly detection
#[derive(Debug, Clone)]
pub struct PerformanceAnomaly {
    pub slot: u64,
    pub expected_micros: u64,
    pub actual_micros: u64,
    pub percent_deviation: f64,
    pub anomaly_type: AnomalyType,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AnomalyType {
    SlowSlot,
    FastSlot,
    HighFailureRate,
    LowThroughput,
}

/// Performance monitor with alerting
pub struct PerformanceMonitor {
    /// Metrics tracker
    tracker: MetricsTracker,
    /// Alert thresholds
    thresholds: PerformanceThresholds,
    /// Recent alerts
    recent_alerts: VecDeque<PerformanceAlert>,
    /// Maximum alerts to keep
    max_alerts: usize,
}

impl PerformanceMonitor {
    pub fn new(max_metrics: usize, thresholds: PerformanceThresholds) -> Self {
        Self {
            tracker: MetricsTracker::new(max_metrics),
            thresholds,
            recent_alerts: VecDeque::new(),
            max_alerts: 100,
        }
    }

    /// Start monitoring a slot
    pub fn start_slot(&mut self, slot: u64) {
        self.tracker.start_slot(slot);
    }

    /// Complete monitoring a slot and check thresholds
    pub fn complete_slot(&mut self) -> Vec<PerformanceAlert> {
        // Save current slot before complete clears it
        let slot = self.tracker.current_slot;
        self.tracker.complete_slot();

        let mut alerts = Vec::new();

        // Check thresholds against the just-completed slot
        if let Some(slot) = slot {
            if let Some(metrics) = self.tracker.get_slot_metrics(slot) {
                if let Some(alert) = self.check_thresholds(metrics) {
                    self.add_alert(alert.clone());
                    alerts.push(alert);
                }
            }
        }

        alerts
    }

    /// Record transaction
    pub fn record_transaction(&mut self, success: bool, compute_units: u64) {
        self.tracker.record_transaction(success, compute_units);
    }

    /// Check if metrics violate thresholds
    fn check_thresholds(&self, metrics: &SlotMetrics) -> Option<PerformanceAlert> {
        // Check elapsed time
        if let Some(elapsed) = metrics.elapsed_micros() {
            if elapsed > self.thresholds.max_slot_time_micros {
                return Some(PerformanceAlert {
                    slot: metrics.slot,
                    alert_type: AlertType::SlowSlot,
                    message: format!(
                        "Slot took {}μs (threshold: {}μs)",
                        elapsed, self.thresholds.max_slot_time_micros
                    ),
                    severity: AlertSeverity::Warning,
                });
            }
        }

        // Check success rate
        if metrics.success_rate() < self.thresholds.min_success_rate {
            return Some(PerformanceAlert {
                slot: metrics.slot,
                alert_type: AlertType::HighFailureRate,
                message: format!(
                    "Success rate {:.2}% (threshold: {:.2}%)",
                    metrics.success_rate() * 100.0,
                    self.thresholds.min_success_rate * 100.0
                ),
                severity: AlertSeverity::Error,
            });
        }

        // Check TPS
        if let Some(tps) = metrics.tps() {
            if tps < self.thresholds.min_tps {
                return Some(PerformanceAlert {
                    slot: metrics.slot,
                    alert_type: AlertType::LowThroughput,
                    message: format!(
                        "TPS {} (threshold: {})",
                        tps as u64, self.thresholds.min_tps as u64
                    ),
                    severity: AlertSeverity::Warning,
                });
            }
        }

        None
    }

    /// Add alert to history
    fn add_alert(&mut self, alert: PerformanceAlert) {
        if self.recent_alerts.len() >= self.max_alerts {
            self.recent_alerts.pop_front();
        }
        self.recent_alerts.push_back(alert);
    }

    /// Get recent alerts
    pub fn recent_alerts(&self) -> &VecDeque<PerformanceAlert> {
        &self.recent_alerts
    }

    /// Get metrics tracker
    pub fn tracker(&self) -> &MetricsTracker {
        &self.tracker
    }

    /// Get aggregate metrics
    pub fn aggregate_metrics(&self) -> AggregateMetrics {
        self.tracker.aggregate_recent()
    }
}

/// Performance thresholds for alerting
#[derive(Debug, Clone)]
pub struct PerformanceThresholds {
    pub max_slot_time_micros: u64,
    pub min_success_rate: f64,
    pub min_tps: f64,
    pub max_compute_per_tx: u64,
}

impl Default for PerformanceThresholds {
    fn default() -> Self {
        Self {
            max_slot_time_micros: 500_000, // 500ms
            min_success_rate: 0.95,        // 95%
            min_tps: 1000.0,
            max_compute_per_tx: MAX_COMPUTE_UNITS,
        }
    }
}

/// Performance alert
#[derive(Debug, Clone)]
pub struct PerformanceAlert {
    pub slot: u64,
    pub alert_type: AlertType,
    pub message: String,
    pub severity: AlertSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AlertType {
    SlowSlot,
    HighFailureRate,
    LowThroughput,
    HighComputeUsage,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AlertSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn slot_metrics_tracks_basics() {
        let mut metrics = SlotMetrics::new(100);
        assert_eq!(metrics.slot, 100);
        assert_eq!(metrics.transaction_count, 0);

        metrics.transaction_count = 10;
        metrics.successful_transactions = 8;
        metrics.failed_transactions = 2;
        metrics.compute_units = 50000;

        assert_eq!(metrics.success_rate(), 0.8);
        assert_eq!(metrics.compute_per_tx(), 5000);
    }

    #[test]
    fn slot_metrics_measures_time() {
        let mut metrics = SlotMetrics::new(100);

        // Sleep for a bit
        thread::sleep(Duration::from_millis(10));

        metrics.complete();

        let elapsed = metrics.elapsed_millis().unwrap();
        assert!(elapsed >= 10);
    }

    #[test]
    fn slot_metrics_calculates_tps() {
        let mut metrics = SlotMetrics::new(100);
        metrics.transaction_count = 1000;

        thread::sleep(Duration::from_millis(100));
        metrics.complete();

        let tps = metrics.tps().unwrap();
        assert!(tps > 0.0);
    }

    #[test]
    fn aggregate_metrics_calculates_totals() {
        let metrics1 = {
            let mut m = SlotMetrics::new(100);
            m.transaction_count = 10;
            m.successful_transactions = 8;
            m.compute_units = 10000;
            m.complete();
            m
        };

        let metrics2 = {
            let mut m = SlotMetrics::new(101);
            m.transaction_count = 20;
            m.successful_transactions = 18;
            m.compute_units = 20000;
            m.complete();
            m
        };

        let aggregate = AggregateMetrics::from_slot_metrics(&[metrics1, metrics2]);

        assert_eq!(aggregate.total_slots, 2);
        assert_eq!(aggregate.total_transactions, 30);
        assert_eq!(aggregate.total_successful, 26);
        assert_eq!(aggregate.total_compute_units, 30000);
        assert!((aggregate.overall_success_rate - 0.866).abs() < 0.01);
    }

    #[test]
    fn metrics_tracker_tracks_slots() {
        let mut tracker = MetricsTracker::new(10);

        tracker.start_slot(100);
        tracker.record_transaction(true, 1000);
        tracker.record_transaction(true, 2000);
        tracker.complete_slot();

        let metrics = tracker.get_slot_metrics(100).unwrap();
        assert_eq!(metrics.transaction_count, 2);
        assert_eq!(metrics.successful_transactions, 2);
        assert_eq!(metrics.compute_units, 3000);
    }

    #[test]
    fn metrics_tracker_maintains_recent_window() {
        let mut tracker = MetricsTracker::new(5);

        for slot in 0..10 {
            tracker.start_slot(slot);
            tracker.complete_slot();
        }

        // Should only keep last 5
        assert_eq!(tracker.recent_metrics().len(), 5);
    }

    #[test]
    fn metrics_tracker_aggregates() {
        let mut tracker = MetricsTracker::new(10);

        for slot in 0..5 {
            tracker.start_slot(slot);
            tracker.record_transaction(true, 1000);
            tracker.complete_slot();
        }

        let aggregate = tracker.aggregate_recent();
        assert_eq!(aggregate.total_slots, 5);
        assert_eq!(aggregate.total_transactions, 5);
    }

    #[test]
    fn metrics_tracker_finds_slow_slots() {
        let mut tracker = MetricsTracker::new(10);

        for slot in 0..3 {
            tracker.start_slot(slot);
            if slot == 1 {
                thread::sleep(Duration::from_millis(50));
            }
            tracker.complete_slot();
        }

        let slowest = tracker.slowest_slots(1);
        assert_eq!(slowest.len(), 1);
        assert_eq!(slowest[0].0, 1); // Slot 1 was slowest
    }

    #[test]
    fn metrics_tracker_detects_anomalies() {
        let mut tracker = MetricsTracker::new(10);

        // Add normal slots
        for slot in 0..5 {
            tracker.start_slot(slot);
            thread::sleep(Duration::from_millis(10));
            tracker.complete_slot();
        }

        // Add slow slot
        tracker.start_slot(10);
        thread::sleep(Duration::from_millis(100)); // 10x slower
        tracker.complete_slot();

        let anomalies = tracker.detect_anomalies(50.0);
        assert!(!anomalies.is_empty());
    }

    #[test]
    fn performance_monitor_generates_alerts() {
        let thresholds = PerformanceThresholds {
            max_slot_time_micros: 10_000, // 10ms
            min_success_rate: 0.9,
            min_tps: 100.0,
            max_compute_per_tx: 10_000,
        };

        let mut monitor = PerformanceMonitor::new(10, thresholds);

        monitor.start_slot(100);
        thread::sleep(Duration::from_millis(20)); // Slow!
        let alerts = monitor.complete_slot();

        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].alert_type, AlertType::SlowSlot);
    }

    #[test]
    fn performance_monitor_tracks_alerts() {
        let mut monitor = PerformanceMonitor::new(10, PerformanceThresholds::default());

        monitor.start_slot(100);
        monitor.complete_slot();

        assert!(monitor.recent_alerts().len() <= 1);
    }

    #[test]
    fn performance_thresholds_have_defaults() {
        let thresholds = PerformanceThresholds::default();
        assert!(thresholds.max_slot_time_micros > 0);
        assert!(thresholds.min_success_rate > 0.0);
        assert!(thresholds.min_tps > 0.0);
    }
}
