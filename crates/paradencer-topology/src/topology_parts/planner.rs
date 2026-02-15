use crate::errors::Result;
use crate::topology_parts::validation::validate_topology_requirements;
use paradencer_core::{LinkKind, StageKind, TopologySpec};

pub fn plan_default_topology(
    packet_link_capacity: usize,
    shred_link_capacity: usize,
    transaction_link_capacity: usize,
    transaction_sanitizer_workers: usize,
    shred_sanitizer_workers: usize,
) -> Result<TopologySpec> {
    let transaction_sanitizer_workers = transaction_sanitizer_workers.max(1);
    let shred_sanitizer_workers = shred_sanitizer_workers.max(1);
    let mut stages = vec![paradencer_core::StageSpec {
        stage_id: "ingress_gateway".to_string(),
        stage_kind: StageKind::IngressGateway,
    }];
    for worker_index in 0..transaction_sanitizer_workers {
        let stage_id = if worker_index == 0 {
            "transaction_sanitizer".to_string()
        } else {
            format!("transaction_sanitizer_{worker_index}")
        };
        stages.push(paradencer_core::StageSpec {
            stage_id,
            stage_kind: StageKind::TransactionSanitizer,
        });
    }
    for worker_index in 0..shred_sanitizer_workers {
        let stage_id = if worker_index == 0 {
            "shred_sanitizer".to_string()
        } else {
            format!("shred_sanitizer_{worker_index}")
        };
        stages.push(paradencer_core::StageSpec {
            stage_id,
            stage_kind: StageKind::ShredSanitizer,
        });
    }
    stages.extend([
        paradencer_core::StageSpec {
            stage_id: "block_builder".to_string(),
            stage_kind: StageKind::BlockBuilder,
        },
        paradencer_core::StageSpec {
            stage_id: "telemetry".to_string(),
            stage_kind: StageKind::Telemetry,
        },
    ]);

    let mut links =
        Vec::with_capacity((2 * transaction_sanitizer_workers) + shred_sanitizer_workers);
    for worker_index in 0..transaction_sanitizer_workers {
        let destination_stage_id = if worker_index == 0 {
            "transaction_sanitizer".to_string()
        } else {
            format!("transaction_sanitizer_{worker_index}")
        };
        let link_id = if worker_index == 0 {
            "packet_stream".to_string()
        } else {
            format!("packet_stream_{worker_index}")
        };
        links.push(paradencer_core::LinkSpec {
            link_id,
            link_kind: LinkKind::PacketStream,
            source_stage_id: "ingress_gateway".to_string(),
            destination_stage_id,
            capacity: packet_link_capacity.max(1),
        });
    }
    for worker_index in 0..transaction_sanitizer_workers {
        let source_stage_id = if worker_index == 0 {
            "transaction_sanitizer".to_string()
        } else {
            format!("transaction_sanitizer_{worker_index}")
        };
        let link_id = if worker_index == 0 {
            "transaction_stream".to_string()
        } else {
            format!("transaction_stream_{worker_index}")
        };
        links.push(paradencer_core::LinkSpec {
            link_id,
            link_kind: LinkKind::TransactionStream,
            source_stage_id,
            destination_stage_id: "block_builder".to_string(),
            capacity: transaction_link_capacity.max(1),
        });
    }
    for worker_index in 0..shred_sanitizer_workers {
        let destination_stage_id = if worker_index == 0 {
            "shred_sanitizer".to_string()
        } else {
            format!("shred_sanitizer_{worker_index}")
        };
        let link_id = if worker_index == 0 {
            "shred_stream".to_string()
        } else {
            format!("shred_stream_{worker_index}")
        };
        links.push(paradencer_core::LinkSpec {
            link_id,
            link_kind: LinkKind::ShredStream,
            source_stage_id: "ingress_gateway".to_string(),
            destination_stage_id,
            capacity: shred_link_capacity.max(1),
        });
    }

    let topology_spec = TopologySpec {
        topology_name: "default-pipeline".to_string(),
        stages,
        links,
    };

    validate_topology_requirements(&topology_spec)?;
    Ok(topology_spec)
}
