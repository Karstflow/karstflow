use crate::errors::{Result, TopologyError};
use paradencer_core::{LinkKind, StageKind, TopologySpec};

pub(crate) fn validate_topology_requirements(topology_spec: &TopologySpec) -> Result<()> {
    topology_spec
        .validate()
        .map_err(|error| TopologyError::InvalidTopology {
            message: error.to_string(),
        })?;

    ensure_required_stage_kinds(topology_spec)?;
    ensure_lane_connectivity(topology_spec)
}

pub(crate) fn find_link_capacity(
    topology_spec: &TopologySpec,
    target_kind: LinkKind,
) -> Result<usize> {
    let capacity: usize = topology_spec
        .links
        .iter()
        .filter(|link| link.link_kind == target_kind)
        .map(|link| link.capacity)
        .sum();
    if capacity == 0 {
        return Err(TopologyError::MissingRequiredLinkKind {
            kind: match target_kind {
                LinkKind::PacketStream => "packet_stream",
                LinkKind::ShredStream => "shred_stream",
                LinkKind::TransactionStream => "transaction_stream",
                LinkKind::VerifiedStream => "verified_stream",
                LinkKind::BlockStream => "block_stream",
                LinkKind::QuicStream => "quic_stream",
            },
        });
    }
    Ok(capacity)
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
            return Err(TopologyError::MissingRequiredStageKind {
                kind: match required_kind {
                    StageKind::IngressGateway => "ingress_gateway",
                    StageKind::TransactionSanitizer => "transaction_sanitizer",
                    StageKind::ShredSanitizer => "shred_sanitizer",
                    StageKind::BlockBuilder => "block_builder",
                    StageKind::Telemetry => "telemetry",
                    StageKind::SignatureVerifier
                    | StageKind::BlockhashResolver
                    | StageKind::ReplayEngine
                    | StageKind::NetworkTile
                    | StageKind::QuicTile => unreachable!(),
                },
            });
        }
    }

    Ok(())
}

fn ensure_lane_connectivity(topology_spec: &TopologySpec) -> Result<()> {
    let stage_kind_by_id: std::collections::HashMap<&str, StageKind> = topology_spec
        .stages
        .iter()
        .map(|stage| (stage.stage_id.as_str(), stage.stage_kind))
        .collect();
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
            return Err(TopologyError::InvalidTopology {
                message: format!(
                    "transaction_sanitizer stage '{stage_id}' must have exactly one inbound packet_stream link"
                ),
            });
        }
    }
    for stage_id in &transaction_stage_ids {
        let transaction_output_links: Vec<_> = topology_spec
            .links
            .iter()
            .filter(|link| {
                link.link_kind == LinkKind::TransactionStream && link.source_stage_id == *stage_id
            })
            .collect();
        if transaction_output_links.len() != 1 {
            return Err(TopologyError::InvalidTopology {
                message: format!(
                    "transaction_sanitizer stage '{stage_id}' must have exactly one outbound transaction_stream link"
                ),
            });
        }
        let destination_stage_id = transaction_output_links[0].destination_stage_id.as_str();
        if stage_kind_by_id.get(destination_stage_id) != Some(&StageKind::BlockBuilder) {
            return Err(TopologyError::InvalidTopology {
                message: format!(
                    "transaction_stream from stage '{stage_id}' must route to block_builder stage"
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
            return Err(TopologyError::InvalidTopology {
                message: format!(
                    "shred_sanitizer stage '{stage_id}' must have exactly one inbound shred_stream link"
                ),
            });
        }
    }
    let block_builder_stage_ids: Vec<&str> = topology_spec
        .stages
        .iter()
        .filter(|stage| stage.stage_kind == StageKind::BlockBuilder)
        .map(|stage| stage.stage_id.as_str())
        .collect();
    for stage_id in &block_builder_stage_ids {
        let transaction_input_links = topology_spec.links.iter().filter(|link| {
            link.link_kind == LinkKind::TransactionStream && link.destination_stage_id == *stage_id
        });
        if transaction_input_links.count() == 0 {
            return Err(TopologyError::InvalidTopology {
                message: format!(
                    "block_builder stage '{stage_id}' must have at least one inbound transaction_stream link"
                ),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::find_link_capacity;
    use paradencer_core::{LinkKind, LinkSpec, StageKind, StageSpec, TopologySpec};

    #[test]
    fn find_link_capacity_sums_capacities_for_same_link_kind() {
        let topology = TopologySpec {
            topology_name: "capacity-sum".to_string(),
            stages: vec![
                StageSpec {
                    stage_id: "ingress_gateway".to_string(),
                    stage_kind: StageKind::IngressGateway,
                },
                StageSpec {
                    stage_id: "transaction_sanitizer".to_string(),
                    stage_kind: StageKind::TransactionSanitizer,
                },
                StageSpec {
                    stage_id: "transaction_sanitizer_1".to_string(),
                    stage_kind: StageKind::TransactionSanitizer,
                },
            ],
            links: vec![
                LinkSpec {
                    link_id: "packet_stream".to_string(),
                    link_kind: LinkKind::PacketStream,
                    source_stage_id: "ingress_gateway".to_string(),
                    destination_stage_id: "transaction_sanitizer".to_string(),
                    capacity: 64,
                },
                LinkSpec {
                    link_id: "packet_stream_1".to_string(),
                    link_kind: LinkKind::PacketStream,
                    source_stage_id: "ingress_gateway".to_string(),
                    destination_stage_id: "transaction_sanitizer_1".to_string(),
                    capacity: 96,
                },
            ],
        };

        let packet_capacity = find_link_capacity(&topology, LinkKind::PacketStream).unwrap();
        assert_eq!(packet_capacity, 160);
    }
}
