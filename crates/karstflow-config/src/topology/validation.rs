use crate::{ConfigError, Result};
use karstflow_core::{LinkKind, StageKind, TopologySpec};

pub(super) fn finalize_topology(topology_spec: TopologySpec) -> Result<TopologySpec> {
    topology_spec
        .validate()
        .map_err(|error| ConfigError::InvalidScope {
            scope: "topology",
            message: error.to_string(),
        })?;
    ensure_required_stage_kinds(&topology_spec)?;
    ensure_lane_connectivity(&topology_spec)?;
    Ok(topology_spec)
}

fn ensure_required_stage_kinds(topology_spec: &TopologySpec) -> Result<()> {
    let stage_kinds: Vec<StageKind> = topology_spec
        .stages
        .iter()
        .map(|stage| stage.stage_kind)
        .collect();
    for required_kind in [
        StageKind::IngressGateway,
        StageKind::TransactionSanitizer,
        StageKind::ShredSanitizer,
        StageKind::BlockBuilder,
        StageKind::Telemetry,
    ] {
        if !stage_kinds.contains(&required_kind) {
            return Err(ConfigError::MissingRequiredStageKind {
                stage_kind: required_kind,
            });
        }
    }
    Ok(())
}

fn ensure_lane_connectivity(topology_spec: &TopologySpec) -> Result<()> {
    let transaction_stage_ids: Vec<&str> = topology_spec
        .stages
        .iter()
        .filter(|stage| stage.stage_kind == StageKind::TransactionSanitizer)
        .map(|stage| stage.stage_id.as_str())
        .collect();
    for stage_id in &transaction_stage_ids {
        let packet_input_links = topology_spec.links.iter().filter(|link| {
            link.link_kind == LinkKind::PacketStream && link.destination_stage_id == *stage_id
        });
        if packet_input_links.count() != 1 {
            return Err(ConfigError::InvalidScope {
                scope: "topology",
                message: format!(
                    "transaction_sanitizer stage '{stage_id}' must have exactly one inbound packet_stream link"
                ),
            });
        }
    }
    for stage_id in &transaction_stage_ids {
        let transaction_output_links = topology_spec.links.iter().filter(|link| {
            link.link_kind == LinkKind::TransactionStream && link.source_stage_id == *stage_id
        });
        if transaction_output_links.count() != 1 {
            return Err(ConfigError::InvalidScope {
                scope: "topology",
                message: format!(
                    "transaction_sanitizer stage '{stage_id}' must have exactly one outbound transaction_stream link"
                ),
            });
        }
    }

    let shred_stage_ids: Vec<&str> = topology_spec
        .stages
        .iter()
        .filter(|stage| stage.stage_kind == StageKind::ShredSanitizer)
        .map(|stage| stage.stage_id.as_str())
        .collect();
    for stage_id in &shred_stage_ids {
        let shred_input_links = topology_spec.links.iter().filter(|link| {
            link.link_kind == LinkKind::ShredStream && link.destination_stage_id == *stage_id
        });
        if shred_input_links.count() != 1 {
            return Err(ConfigError::InvalidScope {
                scope: "topology",
                message: format!(
                    "shred_sanitizer stage '{stage_id}' must have exactly one inbound shred_stream link"
                ),
            });
        }
    }
    Ok(())
}
