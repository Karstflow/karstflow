use crate::errors::Result;
use crate::topology_parts::validation::validate_topology_requirements;
use karstflow_core::{LinkKind, StageKind, TopologySpec};

pub fn plan_default_topology(
    packet_link_capacity: usize,
    shred_link_capacity: usize,
    transaction_link_capacity: usize,
    transaction_sanitizer_workers: usize,
    shred_sanitizer_workers: usize,
) -> Result<TopologySpec> {
    let transaction_sanitizer_workers = transaction_sanitizer_workers.max(1);
    let shred_sanitizer_workers = shred_sanitizer_workers.max(1);
    let mut stages = vec![karstflow_core::StageSpec {
        stage_id: "ingress_gateway".to_string(),
        stage_kind: StageKind::IngressGateway,
    }];
    for worker_index in 0..transaction_sanitizer_workers {
        let stage_id = if worker_index == 0 {
            "transaction_sanitizer".to_string()
        } else {
            format!("transaction_sanitizer_{worker_index}")
        };
        stages.push(karstflow_core::StageSpec {
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
        stages.push(karstflow_core::StageSpec {
            stage_id,
            stage_kind: StageKind::ShredSanitizer,
        });
    }
    stages.extend([
        karstflow_core::StageSpec {
            stage_id: "block_builder".to_string(),
            stage_kind: StageKind::BlockBuilder,
        },
        karstflow_core::StageSpec {
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
        links.push(karstflow_core::LinkSpec {
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
        links.push(karstflow_core::LinkSpec {
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
        links.push(karstflow_core::LinkSpec {
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

#[cfg(test)]
mod tests {
    use super::*;
    use karstflow_core::StageKind;

    #[test]
    fn plan_default_topology_single_workers() {
        let spec = plan_default_topology(64, 64, 64, 1, 1).unwrap();
        assert_eq!(spec.topology_name, "default-pipeline");
        // 1 ingress + 1 tx_sanitizer + 1 shred_sanitizer + 1 block_builder + 1 telemetry = 5
        assert_eq!(spec.stages.len(), 5);
        // 1 packet_stream + 1 transaction_stream + 1 shred_stream = 3
        assert_eq!(spec.links.len(), 3);
    }

    #[test]
    fn plan_default_topology_multi_workers() {
        let spec = plan_default_topology(64, 64, 64, 3, 2).unwrap();
        // 1 ingress + 3 tx_sanitizer + 2 shred_sanitizer + 1 block_builder + 1 telemetry = 8
        assert_eq!(spec.stages.len(), 8);
        // 3 packet + 3 transaction + 2 shred = 8
        assert_eq!(spec.links.len(), 8);
    }

    #[test]
    fn plan_default_topology_zero_workers_clamped_to_one() {
        let spec = plan_default_topology(64, 64, 64, 0, 0).unwrap();
        // 0 gets clamped to 1
        assert_eq!(spec.stages.len(), 5);
        assert_eq!(spec.links.len(), 3);
    }

    #[test]
    fn plan_default_topology_has_required_stage_kinds() {
        let spec = plan_default_topology(128, 128, 128, 2, 2).unwrap();
        let kinds: Vec<StageKind> = spec.stages.iter().map(|s| s.stage_kind).collect();
        assert!(kinds.contains(&StageKind::IngressGateway));
        assert!(kinds.contains(&StageKind::TransactionSanitizer));
        assert!(kinds.contains(&StageKind::ShredSanitizer));
        assert!(kinds.contains(&StageKind::BlockBuilder));
        assert!(kinds.contains(&StageKind::Telemetry));
    }

    #[test]
    fn plan_default_topology_naming_convention() {
        let spec = plan_default_topology(64, 64, 64, 3, 2).unwrap();
        let stage_ids: Vec<&str> = spec.stages.iter().map(|s| s.stage_id.as_str()).collect();
        assert!(stage_ids.contains(&"transaction_sanitizer"));
        assert!(stage_ids.contains(&"transaction_sanitizer_1"));
        assert!(stage_ids.contains(&"transaction_sanitizer_2"));
        assert!(stage_ids.contains(&"shred_sanitizer"));
        assert!(stage_ids.contains(&"shred_sanitizer_1"));
    }

    #[test]
    fn plan_default_topology_zero_capacity_clamped() {
        let spec = plan_default_topology(0, 0, 0, 1, 1).unwrap();
        for link in &spec.links {
            assert!(link.capacity >= 1, "capacity must be at least 1");
        }
    }

    #[test]
    fn plan_default_topology_passes_validation() {
        // This implicitly tests that validate_topology_requirements() passes
        assert!(plan_default_topology(64, 64, 64, 4, 4).is_ok());
    }
}
