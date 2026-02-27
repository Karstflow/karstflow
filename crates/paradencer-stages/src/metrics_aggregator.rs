/// Unified metrics aggregator that collects snapshots from all pipeline stages.
///
/// Provides a single point for gathering metrics across the full transaction
/// and block processing pipeline: verify, dedup, resolv, pack, exec, shred
/// network, FEC resolver, and FEC cache.
///
/// For stages with atomic stats (verify, resolv, pack, exec, shred network),
/// the aggregator holds `Arc` references and calls `.snapshot()` on demand.
///
/// For stages with plain counters (dedup, FEC resolver, FEC cache), the
/// aggregator stores snapshot copies that are updated externally via
/// `update_*` methods before each aggregation cycle.
use std::sync::Arc;

use crate::exec_stage::{ExecStats, ExecStatsSnapshot};
use crate::pack_stage::{PackStats, PackStatsSnapshot};
use crate::resolv_stage::{ResolvStats, ResolvStatsSnapshot};
use crate::shred_network::{ShredNetworkStats, ShredNetworkStatsSnapshot};
use crate::verify_stage::{VerifyStats, VerifyStatsSnapshot};

/// Holds references to all stage stats for aggregation.
pub struct MetricsAggregator {
    // Atomic stats — snapshot on demand via Arc.
    verify: Option<Arc<VerifyStats>>,
    resolv: Option<Arc<ResolvStats>>,
    pack: Option<Arc<PackStats>>,
    exec: Option<Arc<ExecStats>>,
    shred_network: Option<Arc<ShredNetworkStats>>,

    // Plain stats — stored as snapshot copies, updated externally.
    dedup: Option<DedupSnapshot>,
    fec_resolver: Option<FecResolverSnapshot>,
    fec_cache: Option<FecCacheSnapshot>,
}

/// Builder and snapshot methods for MetricsAggregator.
impl MetricsAggregator {
    /// Create an empty aggregator with no stats sources.
    pub fn new() -> Self {
        Self {
            verify: None,
            resolv: None,
            pack: None,
            exec: None,
            shred_network: None,
            dedup: None,
            fec_resolver: None,
            fec_cache: None,
        }
    }

    /// Register verify stage stats (atomic — snapshotted on demand).
    pub fn with_verify(mut self, stats: Arc<VerifyStats>) -> Self {
        self.verify = Some(stats);
        self
    }

    /// Register resolv stage stats (atomic — snapshotted on demand).
    pub fn with_resolv(mut self, stats: Arc<ResolvStats>) -> Self {
        self.resolv = Some(stats);
        self
    }

    /// Register pack stage stats (atomic — snapshotted on demand).
    pub fn with_pack(mut self, stats: Arc<PackStats>) -> Self {
        self.pack = Some(stats);
        self
    }

    /// Register exec stage stats (atomic — snapshotted on demand).
    pub fn with_exec(mut self, stats: Arc<ExecStats>) -> Self {
        self.exec = Some(stats);
        self
    }

    /// Register shred network stats (atomic — snapshotted on demand).
    pub fn with_shred_network(mut self, stats: Arc<ShredNetworkStats>) -> Self {
        self.shred_network = Some(stats);
        self
    }

    /// Set initial dedup snapshot.
    pub fn with_dedup(mut self, snapshot: DedupSnapshot) -> Self {
        self.dedup = Some(snapshot);
        self
    }

    /// Set initial FEC resolver snapshot.
    pub fn with_fec_resolver(mut self, snapshot: FecResolverSnapshot) -> Self {
        self.fec_resolver = Some(snapshot);
        self
    }

    /// Set initial FEC cache snapshot.
    pub fn with_fec_cache(mut self, snapshot: FecCacheSnapshot) -> Self {
        self.fec_cache = Some(snapshot);
        self
    }

    /// Update dedup stats snapshot (call before `snapshot()` for fresh data).
    pub fn update_dedup(&mut self, snapshot: DedupSnapshot) {
        self.dedup = Some(snapshot);
    }

    /// Update FEC resolver stats snapshot (call before `snapshot()` for fresh data).
    pub fn update_fec_resolver(&mut self, snapshot: FecResolverSnapshot) {
        self.fec_resolver = Some(snapshot);
    }

    /// Update FEC cache stats snapshot (call before `snapshot()` for fresh data).
    pub fn update_fec_cache(&mut self, snapshot: FecCacheSnapshot) {
        self.fec_cache = Some(snapshot);
    }

    /// Collect a point-in-time snapshot from all registered stats sources.
    ///
    /// Atomic stats are read via `.snapshot()` (always current).
    /// Plain stats reflect the last `update_*` call.
    pub fn snapshot(&self) -> AggregatedSnapshot {
        AggregatedSnapshot {
            verify: self.verify.as_ref().map(|s| s.snapshot()),
            dedup: self.dedup.clone(),
            resolv: self.resolv.as_ref().map(|s| s.snapshot()),
            pack: self.pack.as_ref().map(|s| s.snapshot()),
            exec: self.exec.as_ref().map(|s| s.snapshot()),
            shred_network: self.shred_network.as_ref().map(|s| s.snapshot()),
            fec_resolver: self.fec_resolver.clone(),
            fec_cache: self.fec_cache.clone(),
        }
    }
}

/// Snapshot of dedup stage counters.
#[derive(Debug, Clone, Default)]
pub struct DedupSnapshot {
    pub total_checked: u64,
    pub duplicates_found: u64,
    pub unique_passed: u64,
}

/// Snapshot of FEC resolver pool counters.
#[derive(Debug, Clone, Default)]
pub struct FecResolverSnapshot {
    pub shreds_inserted: u64,
    pub sets_completed: u64,
    pub sets_recoverable: u64,
    pub sets_spilled: u64,
    pub duplicates_rejected: u64,
    pub duplicate_shreds_rejected: u64,
}

/// Snapshot of FEC cache counters.
#[derive(Debug, Clone, Default)]
pub struct FecCacheSnapshot {
    pub inserts: u64,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub cached_count: u64,
    pub slot_count: u64,
}

/// Combined point-in-time snapshot of all pipeline stage metrics.
#[derive(Debug, Clone, Default)]
pub struct AggregatedSnapshot {
    pub verify: Option<VerifyStatsSnapshot>,
    pub dedup: Option<DedupSnapshot>,
    pub resolv: Option<ResolvStatsSnapshot>,
    pub pack: Option<PackStatsSnapshot>,
    pub exec: Option<ExecStatsSnapshot>,
    pub shred_network: Option<ShredNetworkStatsSnapshot>,
    pub fec_resolver: Option<FecResolverSnapshot>,
    pub fec_cache: Option<FecCacheSnapshot>,
}

impl AggregatedSnapshot {
    /// Render the snapshot as Prometheus text exposition format lines.
    pub fn to_prometheus_lines(&self) -> Vec<String> {
        let mut lines = Vec::with_capacity(64);

        if let Some(ref v) = self.verify {
            lines.push(format!(
                "paradencer_verify_transactions_received {}",
                v.transactions_received
            ));
            lines.push(format!(
                "paradencer_verify_transactions_verified {}",
                v.transactions_verified
            ));
            lines.push(format!(
                "paradencer_verify_transactions_failed {}",
                v.transactions_failed
            ));
            lines.push(format!(
                "paradencer_verify_transactions_malformed {}",
                v.transactions_malformed
            ));
            lines.push(format!(
                "paradencer_verify_transactions_filtered {}",
                v.transactions_filtered
            ));
            lines.push(format!(
                "paradencer_verify_batches_processed {}",
                v.batches_processed
            ));
            lines.push(format!(
                "paradencer_verify_gossip_votes_received {}",
                v.gossip_votes_received
            ));
        }

        if let Some(ref d) = self.dedup {
            lines.push(format!(
                "paradencer_dedup_total_checked {}",
                d.total_checked
            ));
            lines.push(format!(
                "paradencer_dedup_duplicates_found {}",
                d.duplicates_found
            ));
            lines.push(format!(
                "paradencer_dedup_unique_passed {}",
                d.unique_passed
            ));
        }

        if let Some(ref r) = self.resolv {
            lines.push(format!(
                "paradencer_resolv_transactions_received {}",
                r.transactions_received
            ));
            lines.push(format!(
                "paradencer_resolv_transactions_resolved {}",
                r.transactions_resolved
            ));
            lines.push(format!(
                "paradencer_resolv_transactions_expired {}",
                r.transactions_expired
            ));
            lines.push(format!(
                "paradencer_resolv_transactions_stashed {}",
                r.transactions_stashed
            ));
            lines.push(format!(
                "paradencer_resolv_transactions_dropped {}",
                r.transactions_dropped
            ));
            lines.push(format!(
                "paradencer_resolv_blockhashes_registered {}",
                r.blockhashes_registered
            ));
        }

        if let Some(ref p) = self.pack {
            lines.push(format!(
                "paradencer_pack_transactions_scheduled {}",
                p.transactions_scheduled
            ));
            lines.push(format!(
                "paradencer_pack_transactions_conflicted {}",
                p.transactions_conflicted
            ));
            lines.push(format!(
                "paradencer_pack_transactions_expired {}",
                p.transactions_expired
            ));
            lines.push(format!(
                "paradencer_pack_microblocks_produced {}",
                p.microblocks_produced
            ));
            lines.push(format!(
                "paradencer_pack_blocks_completed {}",
                p.blocks_completed
            ));
            lines.push(format!(
                "paradencer_pack_block_cost_units_used {}",
                p.block_cost_units_used
            ));
            lines.push(format!("paradencer_pack_rebated_cus {}", p.rebated_cus));
            lines.push(format!(
                "paradencer_pack_microblocks_paced {}",
                p.microblocks_paced
            ));
        }

        if let Some(ref e) = self.exec {
            lines.push(format!(
                "paradencer_exec_microblocks_executed {}",
                e.microblocks_executed
            ));
            lines.push(format!(
                "paradencer_exec_transactions_executed {}",
                e.transactions_executed
            ));
            lines.push(format!(
                "paradencer_exec_transactions_succeeded {}",
                e.transactions_succeeded
            ));
            lines.push(format!(
                "paradencer_exec_transactions_failed {}",
                e.transactions_failed
            ));
            lines.push(format!(
                "paradencer_exec_compute_units_consumed {}",
                e.compute_units_consumed
            ));
            lines.push(format!(
                "paradencer_exec_fees_collected {}",
                e.fees_collected
            ));
        }

        if let Some(ref s) = self.shred_network {
            lines.push(format!(
                "paradencer_shred_network_shreds_received {}",
                s.shreds_received
            ));
            lines.push(format!(
                "paradencer_shred_network_shreds_from_turbine {}",
                s.shreds_from_turbine
            ));
            lines.push(format!(
                "paradencer_shred_network_shreds_from_repair {}",
                s.shreds_from_repair
            ));
            lines.push(format!(
                "paradencer_shred_network_shreds_duplicate {}",
                s.shreds_duplicate
            ));
            lines.push(format!(
                "paradencer_shred_network_shreds_signature_invalid {}",
                s.shreds_signature_invalid
            ));
            lines.push(format!(
                "paradencer_shred_network_fec_sets_completed {}",
                s.fec_sets_completed
            ));
            lines.push(format!(
                "paradencer_shred_network_fec_sets_recovered {}",
                s.fec_sets_recovered
            ));
            lines.push(format!(
                "paradencer_shred_network_retransmits_sent {}",
                s.retransmits_sent
            ));
            lines.push(format!(
                "paradencer_shred_network_slots_completed {}",
                s.slots_completed
            ));
        }

        if let Some(ref f) = self.fec_resolver {
            lines.push(format!(
                "paradencer_fec_resolver_shreds_inserted {}",
                f.shreds_inserted
            ));
            lines.push(format!(
                "paradencer_fec_resolver_sets_completed {}",
                f.sets_completed
            ));
            lines.push(format!(
                "paradencer_fec_resolver_sets_recoverable {}",
                f.sets_recoverable
            ));
            lines.push(format!(
                "paradencer_fec_resolver_sets_spilled {}",
                f.sets_spilled
            ));
            lines.push(format!(
                "paradencer_fec_resolver_duplicates_rejected {}",
                f.duplicates_rejected
            ));
            lines.push(format!(
                "paradencer_fec_resolver_duplicate_shreds_rejected {}",
                f.duplicate_shreds_rejected
            ));
        }

        if let Some(ref c) = self.fec_cache {
            lines.push(format!("paradencer_fec_cache_inserts {}", c.inserts));
            lines.push(format!("paradencer_fec_cache_hits {}", c.hits));
            lines.push(format!("paradencer_fec_cache_misses {}", c.misses));
            lines.push(format!("paradencer_fec_cache_evictions {}", c.evictions));
            lines.push(format!(
                "paradencer_fec_cache_cached_count {}",
                c.cached_count
            ));
            lines.push(format!("paradencer_fec_cache_slot_count {}", c.slot_count));
        }

        lines
    }
}

// ---------------------------------------------------------------------------
// Conversions from stats types to snapshot types.
// ---------------------------------------------------------------------------

impl From<&crate::dedup_stage::DedupStats> for DedupSnapshot {
    fn from(s: &crate::dedup_stage::DedupStats) -> Self {
        Self {
            total_checked: s.total_checked,
            duplicates_found: s.duplicates_found,
            unique_passed: s.unique_passed,
        }
    }
}

impl From<&crate::fec_resolver::FecResolverStats> for FecResolverSnapshot {
    fn from(s: &crate::fec_resolver::FecResolverStats) -> Self {
        Self {
            shreds_inserted: s.shreds_inserted,
            sets_completed: s.sets_completed,
            sets_recoverable: s.sets_recoverable,
            sets_spilled: s.sets_spilled,
            duplicates_rejected: s.duplicates_rejected,
            duplicate_shreds_rejected: s.duplicate_shreds_rejected,
        }
    }
}

impl From<&crate::fec_cache::FecCacheStats> for FecCacheSnapshot {
    fn from(s: &crate::fec_cache::FecCacheStats) -> Self {
        Self {
            inserts: s.inserts,
            hits: s.hits,
            misses: s.misses,
            evictions: s.evictions,
            cached_count: s.cached_count as u64,
            slot_count: s.slot_count as u64,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_verify_stats() -> Arc<VerifyStats> {
        let stats = Arc::new(VerifyStats::default());
        stats
            .transactions_received
            .store(100, std::sync::atomic::Ordering::Relaxed);
        stats
            .transactions_verified
            .store(95, std::sync::atomic::Ordering::Relaxed);
        stats
            .transactions_failed
            .store(5, std::sync::atomic::Ordering::Relaxed);
        stats
    }

    fn make_pack_stats() -> Arc<PackStats> {
        let stats = Arc::new(PackStats::default());
        stats
            .transactions_scheduled
            .store(80, std::sync::atomic::Ordering::Relaxed);
        stats
            .microblocks_produced
            .store(10, std::sync::atomic::Ordering::Relaxed);
        stats
    }

    fn make_exec_stats() -> Arc<ExecStats> {
        let stats = Arc::new(ExecStats::default());
        stats
            .transactions_executed
            .store(75, std::sync::atomic::Ordering::Relaxed);
        stats
            .transactions_succeeded
            .store(70, std::sync::atomic::Ordering::Relaxed);
        stats
            .transactions_failed
            .store(5, std::sync::atomic::Ordering::Relaxed);
        stats
            .compute_units_consumed
            .store(500_000, std::sync::atomic::Ordering::Relaxed);
        stats
    }

    fn make_shred_network_stats() -> Arc<ShredNetworkStats> {
        let stats = Arc::new(ShredNetworkStats::default());
        stats
            .shreds_received
            .store(1000, std::sync::atomic::Ordering::Relaxed);
        stats
            .fec_sets_completed
            .store(50, std::sync::atomic::Ordering::Relaxed);
        stats
    }

    #[test]
    fn empty_aggregator_produces_empty_snapshot() {
        let agg = MetricsAggregator::new();
        let snap = agg.snapshot();
        assert!(snap.verify.is_none());
        assert!(snap.dedup.is_none());
        assert!(snap.resolv.is_none());
        assert!(snap.pack.is_none());
        assert!(snap.exec.is_none());
        assert!(snap.shred_network.is_none());
        assert!(snap.fec_resolver.is_none());
        assert!(snap.fec_cache.is_none());
    }

    #[test]
    fn aggregator_collects_registered_stats() {
        let agg = MetricsAggregator::new()
            .with_verify(make_verify_stats())
            .with_pack(make_pack_stats())
            .with_exec(make_exec_stats())
            .with_shred_network(make_shred_network_stats());

        let snap = agg.snapshot();

        let verify = snap.verify.unwrap();
        assert_eq!(verify.transactions_received, 100);
        assert_eq!(verify.transactions_verified, 95);
        assert_eq!(verify.transactions_failed, 5);

        let pack = snap.pack.unwrap();
        assert_eq!(pack.transactions_scheduled, 80);
        assert_eq!(pack.microblocks_produced, 10);

        let exec = snap.exec.unwrap();
        assert_eq!(exec.transactions_executed, 75);
        assert_eq!(exec.compute_units_consumed, 500_000);

        let shred = snap.shred_network.unwrap();
        assert_eq!(shred.shreds_received, 1000);
        assert_eq!(shred.fec_sets_completed, 50);

        // Unregistered sources are None.
        assert!(snap.dedup.is_none());
        assert!(snap.resolv.is_none());
    }

    #[test]
    fn prometheus_lines_include_all_registered_stages() {
        let agg = MetricsAggregator::new()
            .with_verify(make_verify_stats())
            .with_pack(make_pack_stats())
            .with_exec(make_exec_stats())
            .with_shred_network(make_shred_network_stats());

        let snap = agg.snapshot();
        let lines = snap.to_prometheus_lines();
        let text = lines.join("\n");

        assert!(text.contains("paradencer_verify_transactions_received 100"));
        assert!(text.contains("paradencer_verify_transactions_verified 95"));
        assert!(text.contains("paradencer_pack_transactions_scheduled 80"));
        assert!(text.contains("paradencer_pack_microblocks_produced 10"));
        assert!(text.contains("paradencer_exec_transactions_executed 75"));
        assert!(text.contains("paradencer_exec_compute_units_consumed 500000"));
        assert!(text.contains("paradencer_shred_network_shreds_received 1000"));
        assert!(text.contains("paradencer_shred_network_fec_sets_completed 50"));

        // Unregistered stages should NOT appear.
        assert!(!text.contains("paradencer_dedup_"));
        assert!(!text.contains("paradencer_resolv_"));
    }

    #[test]
    fn empty_snapshot_produces_no_lines() {
        let agg = MetricsAggregator::new();
        let snap = agg.snapshot();
        let lines = snap.to_prometheus_lines();
        assert!(lines.is_empty());
    }

    #[test]
    fn fec_resolver_and_cache_snapshots() {
        let resolver = FecResolverSnapshot {
            shreds_inserted: 200,
            sets_completed: 18,
            sets_recoverable: 2,
            sets_spilled: 5,
            duplicates_rejected: 3,
            duplicate_shreds_rejected: 10,
        };

        let cache = FecCacheSnapshot {
            inserts: 100,
            hits: 500,
            misses: 50,
            evictions: 10,
            cached_count: 90,
            slot_count: 45,
        };

        let agg = MetricsAggregator::new()
            .with_fec_resolver(resolver)
            .with_fec_cache(cache);

        let snap = agg.snapshot();
        let lines = snap.to_prometheus_lines();
        let text = lines.join("\n");

        assert!(text.contains("paradencer_fec_resolver_shreds_inserted 200"));
        assert!(text.contains("paradencer_fec_resolver_sets_completed 18"));
        assert!(text.contains("paradencer_fec_resolver_sets_recoverable 2"));
        assert!(text.contains("paradencer_fec_resolver_sets_spilled 5"));
        assert!(text.contains("paradencer_fec_resolver_duplicates_rejected 3"));
        assert!(text.contains("paradencer_fec_resolver_duplicate_shreds_rejected 10"));
        assert!(text.contains("paradencer_fec_cache_hits 500"));
        assert!(text.contains("paradencer_fec_cache_misses 50"));
        assert!(text.contains("paradencer_fec_cache_inserts 100"));
        assert!(text.contains("paradencer_fec_cache_cached_count 90"));
        assert!(text.contains("paradencer_fec_cache_slot_count 45"));
    }

    #[test]
    fn dedup_snapshot_rendering() {
        let dedup = DedupSnapshot {
            total_checked: 200,
            duplicates_found: 30,
            unique_passed: 170,
        };

        let agg = MetricsAggregator::new().with_dedup(dedup);
        let snap = agg.snapshot();
        let lines = snap.to_prometheus_lines();
        let text = lines.join("\n");

        assert!(text.contains("paradencer_dedup_total_checked 200"));
        assert!(text.contains("paradencer_dedup_duplicates_found 30"));
        assert!(text.contains("paradencer_dedup_unique_passed 170"));
    }

    #[test]
    fn update_methods_refresh_plain_stats() {
        let mut agg = MetricsAggregator::new();

        // Initially no dedup stats.
        assert!(agg.snapshot().dedup.is_none());

        // Push initial snapshot.
        agg.update_dedup(DedupSnapshot {
            total_checked: 10,
            duplicates_found: 1,
            unique_passed: 9,
        });

        let snap = agg.snapshot();
        assert_eq!(snap.dedup.as_ref().unwrap().total_checked, 10);

        // Push updated snapshot.
        agg.update_dedup(DedupSnapshot {
            total_checked: 50,
            duplicates_found: 5,
            unique_passed: 45,
        });

        let snap = agg.snapshot();
        assert_eq!(snap.dedup.as_ref().unwrap().total_checked, 50);
        assert_eq!(snap.dedup.as_ref().unwrap().unique_passed, 45);
    }

    #[test]
    fn from_fec_resolver_stats() {
        use crate::fec_resolver::FecResolverStats;

        let stats = FecResolverStats {
            shreds_inserted: 100,
            sets_completed: 20,
            sets_recoverable: 3,
            sets_spilled: 5,
            duplicates_rejected: 2,
            duplicate_shreds_rejected: 7,
        };

        let snapshot = FecResolverSnapshot::from(&stats);
        assert_eq!(snapshot.shreds_inserted, 100);
        assert_eq!(snapshot.sets_completed, 20);
        assert_eq!(snapshot.sets_recoverable, 3);
        assert_eq!(snapshot.sets_spilled, 5);
        assert_eq!(snapshot.duplicates_rejected, 2);
        assert_eq!(snapshot.duplicate_shreds_rejected, 7);
    }

    #[test]
    fn from_fec_cache_stats() {
        use crate::fec_cache::FecCacheStats;

        let stats = FecCacheStats {
            inserts: 50,
            hits: 300,
            misses: 20,
            evictions: 5,
            cached_count: 45,
            slot_count: 10,
        };

        let snapshot = FecCacheSnapshot::from(&stats);
        assert_eq!(snapshot.inserts, 50);
        assert_eq!(snapshot.hits, 300);
        assert_eq!(snapshot.misses, 20);
        assert_eq!(snapshot.evictions, 5);
        assert_eq!(snapshot.cached_count, 45);
        assert_eq!(snapshot.slot_count, 10);
    }

    #[test]
    fn from_dedup_stats() {
        use crate::dedup_stage::DedupStats;

        let stats = DedupStats {
            total_checked: 1000,
            duplicates_found: 100,
            unique_passed: 900,
        };

        let snapshot = DedupSnapshot::from(&stats);
        assert_eq!(snapshot.total_checked, 1000);
        assert_eq!(snapshot.duplicates_found, 100);
        assert_eq!(snapshot.unique_passed, 900);
    }
}
