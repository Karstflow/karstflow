use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RpcCommitment {
    Processed,
    Confirmed,
    Finalized,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RpcRuntimeSnapshot {
    pub slot: u64,
    pub block_height: u64,
    pub transaction_count: u64,
    pub uptime_millis: u128,
    pub latest_blockhash_seed: u64,
}

impl RpcRuntimeSnapshot {
    pub fn slot_for_commitment(self, commitment: RpcCommitment) -> u64 {
        match commitment {
            RpcCommitment::Processed => self.slot,
            RpcCommitment::Confirmed => self.slot.saturating_sub(1),
            RpcCommitment::Finalized => self.slot.saturating_sub(32),
        }
    }

    pub fn block_height_for_commitment(self, commitment: RpcCommitment) -> u64 {
        self.slot_for_commitment(commitment)
    }

    pub fn blockhash_seed_for_commitment(self, commitment: RpcCommitment) -> u64 {
        self.latest_blockhash_seed
            .wrapping_add(self.slot_for_commitment(commitment).rotate_left(7))
    }
}

pub trait RuntimeSnapshotProvider: Send + Sync {
    fn latest_snapshot(&self) -> Option<RpcRuntimeSnapshot>;
}

pub struct MetricsFileRuntimeSnapshotProvider {
    metrics_file_path: PathBuf,
}

impl MetricsFileRuntimeSnapshotProvider {
    pub fn from_path(metrics_file_path: PathBuf) -> Self {
        Self { metrics_file_path }
    }
}

impl RuntimeSnapshotProvider for MetricsFileRuntimeSnapshotProvider {
    fn latest_snapshot(&self) -> Option<RpcRuntimeSnapshot> {
        read_runtime_snapshot_from_metrics_file(&self.metrics_file_path)
    }
}

pub fn metrics_file_provider(metrics_file_path: PathBuf) -> Arc<dyn RuntimeSnapshotProvider> {
    Arc::new(MetricsFileRuntimeSnapshotProvider::from_path(
        metrics_file_path,
    ))
}

fn read_runtime_snapshot_from_metrics_file(metrics_file_path: &Path) -> Option<RpcRuntimeSnapshot> {
    let content = fs::read_to_string(metrics_file_path).ok()?;
    let latest_json_line = content
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty() && line.trim_start().starts_with('{'))?;
    let value = serde_json::from_str::<serde_json::Value>(latest_json_line).ok()?;

    let block_assembly = value.get("block_assembly");
    let committed_fragments = block_assembly
        .and_then(|scope| scope.get("committed_fragments"))
        .and_then(|raw| raw.as_u64())
        .unwrap_or(0);
    let replay_window_rewinds = block_assembly
        .and_then(|scope| scope.get("replay_window_rewinds"))
        .and_then(|raw| raw.as_u64())
        .unwrap_or(0);
    let transaction_count = value
        .get("ingress_filter")
        .and_then(|scope| scope.get("accepted_transactions"))
        .and_then(|raw| raw.as_u64())
        .unwrap_or(0);
    let uptime_millis = value
        .get("uptime_millis")
        .and_then(|raw| raw.as_u64())
        .map(u128::from)
        .unwrap_or(0);

    Some(RpcRuntimeSnapshot {
        slot: committed_fragments,
        block_height: committed_fragments,
        transaction_count,
        uptime_millis,
        latest_blockhash_seed: committed_fragments ^ replay_window_rewinds.rotate_left(13),
    })
}

#[cfg(test)]
pub fn read_metrics_snapshot_for_test(path: &Path) -> Option<RpcRuntimeSnapshot> {
    read_runtime_snapshot_from_metrics_file(path)
}
