use crate::errors::StageError;
use crate::{BlockAssemblyMetrics, IngressFilterMetrics, ShredFilterMetrics};
use paradencer_mesh::ChannelSnapshot;
use serde::Serialize;

#[derive(Serialize)]
struct MetricsEnvelope {
    event: &'static str,
    uptime_millis: u128,
    packet_link: LinkMetrics,
    shred_link: LinkMetrics,
    transaction_link: LinkMetrics,
    ingress_filter: IngressFilterMetrics,
    shred_filter: ShredFilterMetrics,
    block_assembly: BlockAssemblyMetrics,
}

#[derive(Serialize)]
struct LinkMetrics {
    enqueued_messages: u64,
    dequeued_messages: u64,
    blocked_sends: u64,
    closed_sends: u64,
    empty_receives: u64,
    closed_receives: u64,
}

pub(crate) fn build_json_line(
    uptime_millis: u128,
    packet_snapshot: &ChannelSnapshot,
    shred_snapshot: &ChannelSnapshot,
    transaction_snapshot: &ChannelSnapshot,
    ingress_filter_snapshot: IngressFilterMetrics,
    shred_filter_snapshot: ShredFilterMetrics,
    block_assembly_snapshot: BlockAssemblyMetrics,
) -> Result<String, StageError> {
    let metrics = MetricsEnvelope {
        event: "mesh_metrics",
        uptime_millis,
        packet_link: to_link_metrics(packet_snapshot),
        shred_link: to_link_metrics(shred_snapshot),
        transaction_link: to_link_metrics(transaction_snapshot),
        ingress_filter: ingress_filter_snapshot,
        shred_filter: shred_filter_snapshot,
        block_assembly: block_assembly_snapshot,
    };

    serde_json::to_string(&metrics).map_err(StageError::Serialize)
}

pub(crate) fn build_prometheus_lines(
    uptime_millis: u128,
    packet_snapshot: &ChannelSnapshot,
    shred_snapshot: &ChannelSnapshot,
    transaction_snapshot: &ChannelSnapshot,
    ingress_filter_snapshot: IngressFilterMetrics,
    shred_filter_snapshot: ShredFilterMetrics,
    block_assembly_snapshot: BlockAssemblyMetrics,
) -> Vec<String> {
    vec![
        format!(
            "paradencer_mesh_packet_enqueued_messages {}",
            packet_snapshot.enqueued_messages
        ),
        format!(
            "paradencer_mesh_packet_dequeued_messages {}",
            packet_snapshot.dequeued_messages
        ),
        format!(
            "paradencer_mesh_packet_blocked_sends {}",
            packet_snapshot.blocked_sends
        ),
        format!(
            "paradencer_mesh_shred_enqueued_messages {}",
            shred_snapshot.enqueued_messages
        ),
        format!(
            "paradencer_mesh_shred_dequeued_messages {}",
            shred_snapshot.dequeued_messages
        ),
        format!(
            "paradencer_mesh_shred_blocked_sends {}",
            shred_snapshot.blocked_sends
        ),
        format!(
            "paradencer_mesh_transaction_enqueued_messages {}",
            transaction_snapshot.enqueued_messages
        ),
        format!(
            "paradencer_mesh_transaction_dequeued_messages {}",
            transaction_snapshot.dequeued_messages
        ),
        format!(
            "paradencer_mesh_transaction_blocked_sends {}",
            transaction_snapshot.blocked_sends
        ),
        format!("paradencer_uptime_millis {uptime_millis}"),
        format!(
            "paradencer_ingress_accepted_transactions {}",
            ingress_filter_snapshot.accepted_transactions
        ),
        format!(
            "paradencer_ingress_accepted_transactions_quic {}",
            ingress_filter_snapshot.accepted_quic_source
        ),
        format!(
            "paradencer_ingress_accepted_transactions_gossip {}",
            ingress_filter_snapshot.accepted_gossip_source
        ),
        format!(
            "paradencer_ingress_accepted_transactions_bundle {}",
            ingress_filter_snapshot.accepted_bundle_source
        ),
        format!(
            "paradencer_ingress_accepted_transactions_rpc {}",
            ingress_filter_snapshot.accepted_rpc_source
        ),
        format!(
            "paradencer_ingress_duplicate_transactions {}",
            ingress_filter_snapshot.duplicate_transactions
        ),
        format!(
            "paradencer_ingress_duplicate_transactions_quic {}",
            ingress_filter_snapshot.duplicate_quic_source
        ),
        format!(
            "paradencer_ingress_duplicate_transactions_gossip {}",
            ingress_filter_snapshot.duplicate_gossip_source
        ),
        format!(
            "paradencer_ingress_duplicate_transactions_bundle {}",
            ingress_filter_snapshot.duplicate_bundle_source
        ),
        format!(
            "paradencer_ingress_duplicate_transactions_rpc {}",
            ingress_filter_snapshot.duplicate_rpc_source
        ),
        format!(
            "paradencer_ingress_dropped_empty_payload {}",
            ingress_filter_snapshot.dropped_empty_payload
        ),
        format!(
            "paradencer_ingress_dropped_oversized_payload {}",
            ingress_filter_snapshot.dropped_oversized_payload
        ),
        format!(
            "paradencer_ingress_dropped_disallowed_source {}",
            ingress_filter_snapshot.dropped_disallowed_source
        ),
        format!(
            "paradencer_ingress_dropped_rate_limited_source {}",
            ingress_filter_snapshot.dropped_rate_limited_source
        ),
        format!(
            "paradencer_ingress_dropped_cost_budget_source {}",
            ingress_filter_snapshot.dropped_cost_budget_source
        ),
        format!(
            "paradencer_ingress_dropped_downstream_backpressure {}",
            ingress_filter_snapshot.dropped_downstream_backpressure
        ),
        format!(
            "paradencer_shred_accepted {}",
            shred_filter_snapshot.accepted_shreds
        ),
        format!(
            "paradencer_shred_duplicates {}",
            shred_filter_snapshot.duplicate_shreds
        ),
        format!(
            "paradencer_shred_dropped_empty_payload {}",
            shred_filter_snapshot.dropped_empty_payload
        ),
        format!(
            "paradencer_shred_dropped_oversized_payload {}",
            shred_filter_snapshot.dropped_oversized_payload
        ),
        format!(
            "paradencer_shred_dropped_disallowed_source {}",
            shred_filter_snapshot.dropped_disallowed_source
        ),
        format!(
            "paradencer_block_assembly_deferred_retries_total {}",
            block_assembly_snapshot.deferred_retries
        ),
        format!(
            "paradencer_block_assembly_dropped_fragments_total {}",
            block_assembly_snapshot.dropped_fragments
        ),
        format!(
            "paradencer_block_assembly_committed_fragments_total {}",
            block_assembly_snapshot.committed_fragments
        ),
        format!(
            "paradencer_block_assembly_pending_retries {}",
            block_assembly_snapshot.pending_retries
        ),
        format!(
            "paradencer_block_assembly_execution_error_total {}",
            block_assembly_snapshot.execution_error_total
        ),
        format!(
            "paradencer_block_assembly_execution_error_empty_batch_total {}",
            block_assembly_snapshot.execution_error_empty_batch
        ),
        format!(
            "paradencer_block_assembly_execution_error_cost_overflow_total {}",
            block_assembly_snapshot.execution_error_cost_overflow
        ),
        format!(
            "paradencer_block_assembly_execution_error_adapter_apply_total {}",
            block_assembly_snapshot.execution_error_adapter_apply
        ),
        format!(
            "paradencer_block_assembly_execution_error_adapter_rollback_total {}",
            block_assembly_snapshot.execution_error_adapter_rollback
        ),
        format!(
            "paradencer_block_assembly_execution_error_adapter_state_conflict_total {}",
            block_assembly_snapshot.execution_error_adapter_state_conflict
        ),
        format!(
            "paradencer_block_assembly_execution_error_adapter_contract_violation_total {}",
            block_assembly_snapshot.execution_error_adapter_contract_violation
        ),
        format!(
            "paradencer_block_assembly_execution_error_adapter_receipt_missing_total {}",
            block_assembly_snapshot.execution_error_adapter_receipt_missing
        ),
        format!(
            "paradencer_block_assembly_execution_error_adapter_mutex_poisoned_total {}",
            block_assembly_snapshot.execution_error_adapter_mutex_poisoned
        ),
        format!(
            "paradencer_block_assembly_execution_error_fail_open_continue_total {}",
            block_assembly_snapshot.execution_error_fail_open_continue
        ),
        format!(
            "paradencer_block_assembly_execution_error_fail_fast_halt_total {}",
            block_assembly_snapshot.execution_error_fail_fast_halt
        ),
        format!(
            "paradencer_block_assembly_execution_error_fail_open_circuit_breaker_halt_total {}",
            block_assembly_snapshot.execution_error_fail_open_circuit_breaker_halt
        ),
        format!(
            "paradencer_block_assembly_execution_error_consecutive_current {}",
            block_assembly_snapshot.execution_error_consecutive_current
        ),
        format!(
            "paradencer_block_assembly_retry_scheduled_replay_conflict_total {}",
            block_assembly_snapshot.retry_scheduled_replay_conflict
        ),
        format!(
            "paradencer_block_assembly_retry_scheduled_transient_pressure_total {}",
            block_assembly_snapshot.retry_scheduled_transient_pressure
        ),
        format!(
            "paradencer_block_assembly_retry_scheduled_resource_exhaustion_total {}",
            block_assembly_snapshot.retry_scheduled_resource_exhaustion
        ),
        format!(
            "paradencer_block_assembly_retry_scheduled_fallback_total {}",
            block_assembly_snapshot.retry_scheduled_fallback
        ),
        format!(
            "paradencer_block_assembly_dropped_replay_conflict_total {}",
            block_assembly_snapshot.dropped_replay_conflict
        ),
        format!(
            "paradencer_block_assembly_dropped_deterministic_total {}",
            block_assembly_snapshot.dropped_deterministic
        ),
        format!(
            "paradencer_block_assembly_dropped_transient_pressure_total {}",
            block_assembly_snapshot.dropped_transient_pressure
        ),
        format!(
            "paradencer_block_assembly_dropped_resource_exhaustion_total {}",
            block_assembly_snapshot.dropped_resource_exhaustion
        ),
        format!(
            "paradencer_block_assembly_dropped_fallback_total {}",
            block_assembly_snapshot.dropped_fallback
        ),
        format!(
            "paradencer_block_assembly_dropped_reorg_retry_exhausted_total {}",
            block_assembly_snapshot.dropped_reorg_retry_exhausted
        ),
        format!(
            "paradencer_block_assembly_leader_gate_permit_total {}",
            block_assembly_snapshot.leader_gate_permit
        ),
        format!(
            "paradencer_block_assembly_leader_gate_hold_total {}",
            block_assembly_snapshot.leader_gate_hold
        ),
        format!(
            "paradencer_block_assembly_fork_choice_keep_total {}",
            block_assembly_snapshot.fork_choice_keep
        ),
        format!(
            "paradencer_block_assembly_fork_choice_reorg_total {}",
            block_assembly_snapshot.fork_choice_reorg
        ),
        format!(
            "paradencer_block_assembly_execution_health_cooldown_entries_total {}",
            block_assembly_snapshot.execution_health_cooldown_entries
        ),
        format!(
            "paradencer_block_assembly_execution_health_cooldown_skipped_ticks_total {}",
            block_assembly_snapshot.execution_health_cooldown_skipped_ticks
        ),
        format!(
            "paradencer_block_assembly_replay_safety_hold_entries_total {}",
            block_assembly_snapshot.replay_safety_hold_entries
        ),
        format!(
            "paradencer_block_assembly_replay_safety_hold_skipped_ticks_total {}",
            block_assembly_snapshot.replay_safety_hold_skipped_ticks
        ),
        format!(
            "paradencer_block_assembly_fork_choice_quarantine_entries_total {}",
            block_assembly_snapshot.fork_choice_quarantine_entries
        ),
        format!(
            "paradencer_block_assembly_fork_choice_quarantine_skipped_ticks_total {}",
            block_assembly_snapshot.fork_choice_quarantine_skipped_ticks
        ),
        format!(
            "paradencer_block_assembly_slot_transition_committed_total {}",
            block_assembly_snapshot.slot_transition_committed
        ),
        format!(
            "paradencer_block_assembly_slot_transition_dropped_total {}",
            block_assembly_snapshot.slot_transition_dropped
        ),
        format!(
            "paradencer_block_assembly_slot_transition_reorg_pending_total {}",
            block_assembly_snapshot.slot_transition_reorg_pending
        ),
        format!(
            "paradencer_block_assembly_replay_controller_holds_total {}",
            block_assembly_snapshot.replay_controller_holds
        ),
        format!(
            "paradencer_block_assembly_replay_controller_confirmed_candidates_total {}",
            block_assembly_snapshot.replay_controller_confirmed_candidates
        ),
        format!(
            "paradencer_block_assembly_replay_controller_candidate_switches_total {}",
            block_assembly_snapshot.replay_controller_candidate_switches
        ),
        format!(
            "paradencer_block_assembly_replay_controller_stale_candidates_pruned_total {}",
            block_assembly_snapshot.replay_controller_stale_candidates_pruned
        ),
        format!(
            "paradencer_block_assembly_replay_controller_switch_suppressed_total {}",
            block_assembly_snapshot.replay_controller_switch_suppressed
        ),
        format!(
            "paradencer_block_assembly_replay_controller_active_candidate_failed_ratio_bps {}",
            block_assembly_snapshot.replay_controller_active_candidate_failed_ratio_bps
        ),
        format!(
            "paradencer_block_assembly_replay_controller_tracked_candidates {}",
            block_assembly_snapshot.replay_controller_tracked_candidates
        ),
        format!(
            "paradencer_block_assembly_replay_window_checkpoint_depth {}",
            block_assembly_snapshot.replay_window_checkpoint_depth
        ),
        format!(
            "paradencer_block_assembly_replay_window_rewinds_total {}",
            block_assembly_snapshot.replay_window_rewinds
        ),
        format!(
            "paradencer_block_assembly_replay_window_catalog_snapshots_pruned_total {}",
            block_assembly_snapshot.replay_window_catalog_snapshots_pruned
        ),
        format!(
            "paradencer_block_assembly_execution_state_rewind_failures_total {}",
            block_assembly_snapshot.execution_state_rewind_failures
        ),
    ]
}

fn to_link_metrics(snapshot: &ChannelSnapshot) -> LinkMetrics {
    LinkMetrics {
        enqueued_messages: snapshot.enqueued_messages,
        dequeued_messages: snapshot.dequeued_messages,
        blocked_sends: snapshot.blocked_sends,
        closed_sends: snapshot.closed_sends,
        empty_receives: snapshot.empty_receives,
        closed_receives: snapshot.closed_receives,
    }
}
