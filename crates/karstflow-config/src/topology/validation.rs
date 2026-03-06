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

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_topology() -> TopologySpec {
        TopologySpec {
            topology_name: "test".to_string(),
            stages: vec![
                karstflow_core::StageSpec {
                    stage_id: "ingress".to_string(),
                    stage_kind: StageKind::IngressGateway,
                },
                karstflow_core::StageSpec {
                    stage_id: "tx_san".to_string(),
                    stage_kind: StageKind::TransactionSanitizer,
                },
                karstflow_core::StageSpec {
                    stage_id: "shred_san".to_string(),
                    stage_kind: StageKind::ShredSanitizer,
                },
                karstflow_core::StageSpec {
                    stage_id: "builder".to_string(),
                    stage_kind: StageKind::BlockBuilder,
                },
                karstflow_core::StageSpec {
                    stage_id: "telem".to_string(),
                    stage_kind: StageKind::Telemetry,
                },
            ],
            links: vec![
                karstflow_core::LinkSpec {
                    link_id: "pkt".to_string(),
                    link_kind: LinkKind::PacketStream,
                    source_stage_id: "ingress".to_string(),
                    destination_stage_id: "tx_san".to_string(),
                    capacity: 64,
                },
                karstflow_core::LinkSpec {
                    link_id: "tx".to_string(),
                    link_kind: LinkKind::TransactionStream,
                    source_stage_id: "tx_san".to_string(),
                    destination_stage_id: "builder".to_string(),
                    capacity: 64,
                },
                karstflow_core::LinkSpec {
                    link_id: "shred".to_string(),
                    link_kind: LinkKind::ShredStream,
                    source_stage_id: "ingress".to_string(),
                    destination_stage_id: "shred_san".to_string(),
                    capacity: 64,
                },
            ],
        }
    }

    #[test]
    fn finalize_valid_topology_succeeds() {
        let spec = minimal_topology();
        assert!(finalize_topology(spec).is_ok());
    }

    #[test]
    fn missing_ingress_gateway_fails() {
        let mut spec = minimal_topology();
        spec.stages
            .retain(|s| s.stage_kind != StageKind::IngressGateway);
        assert!(finalize_topology(spec).is_err());
    }

    #[test]
    fn missing_transaction_sanitizer_fails() {
        let mut spec = minimal_topology();
        spec.stages
            .retain(|s| s.stage_kind != StageKind::TransactionSanitizer);
        spec.links.retain(|l| {
            l.link_kind != LinkKind::PacketStream && l.link_kind != LinkKind::TransactionStream
        });
        assert!(finalize_topology(spec).is_err());
    }

    #[test]
    fn missing_shred_sanitizer_fails() {
        let mut spec = minimal_topology();
        spec.stages
            .retain(|s| s.stage_kind != StageKind::ShredSanitizer);
        spec.links.retain(|l| l.link_kind != LinkKind::ShredStream);
        assert!(finalize_topology(spec).is_err());
    }

    #[test]
    fn missing_block_builder_fails() {
        let mut spec = minimal_topology();
        spec.stages
            .retain(|s| s.stage_kind != StageKind::BlockBuilder);
        assert!(finalize_topology(spec).is_err());
    }

    #[test]
    fn missing_telemetry_fails() {
        let mut spec = minimal_topology();
        spec.stages.retain(|s| s.stage_kind != StageKind::Telemetry);
        assert!(finalize_topology(spec).is_err());
    }

    #[test]
    fn tx_sanitizer_without_packet_input_fails() {
        let mut spec = minimal_topology();
        spec.links.retain(|l| l.link_kind != LinkKind::PacketStream);
        assert!(finalize_topology(spec).is_err());
    }

    #[test]
    fn tx_sanitizer_without_transaction_output_fails() {
        let mut spec = minimal_topology();
        spec.links
            .retain(|l| l.link_kind != LinkKind::TransactionStream);
        assert!(finalize_topology(spec).is_err());
    }

    #[test]
    fn shred_sanitizer_without_shred_input_fails() {
        let mut spec = minimal_topology();
        spec.links.retain(|l| l.link_kind != LinkKind::ShredStream);
        assert!(finalize_topology(spec).is_err());
    }
}
