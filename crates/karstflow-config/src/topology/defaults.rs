use super::validation::finalize_topology;
use crate::Result;
use karstflow_core::{LinkKind, StageKind, TopologySpec};

pub(super) fn plan_default_topology(
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
    finalize_topology(topology_spec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_topology_single_worker() {
        let spec = plan_default_topology(128, 128, 128, 1, 1).unwrap();
        assert_eq!(spec.topology_name, "default-pipeline");
        // 1 ingress + 1 tx_sanitizer + 1 shred_sanitizer + 1 block_builder + 1 telemetry = 5
        assert_eq!(spec.stages.len(), 5);
        // 1 packet_stream + 1 transaction_stream + 1 shred_stream = 3
        assert_eq!(spec.links.len(), 3);
    }

    #[test]
    fn default_topology_multiple_tx_workers() {
        let spec = plan_default_topology(128, 128, 128, 3, 1).unwrap();
        // 1 ingress + 3 tx_sanitizer + 1 shred_sanitizer + 1 block_builder + 1 telemetry = 7
        assert_eq!(spec.stages.len(), 7);
        // 3 packet_stream + 3 transaction_stream + 1 shred_stream = 7
        assert_eq!(spec.links.len(), 7);
    }

    #[test]
    fn default_topology_multiple_shred_workers() {
        let spec = plan_default_topology(128, 128, 128, 1, 4).unwrap();
        // 1 ingress + 1 tx_sanitizer + 4 shred_sanitizer + 1 block_builder + 1 telemetry = 8
        assert_eq!(spec.stages.len(), 8);
        // 1 packet_stream + 1 transaction_stream + 4 shred_stream = 6
        assert_eq!(spec.links.len(), 6);
    }

    #[test]
    fn zero_workers_clamped_to_one() {
        let spec = plan_default_topology(128, 128, 128, 0, 0).unwrap();
        // Clamped to 1 each → same as single worker
        assert_eq!(spec.stages.len(), 5);
        assert_eq!(spec.links.len(), 3);
    }

    #[test]
    fn link_capacities_clamped_to_one() {
        let spec = plan_default_topology(0, 0, 0, 1, 1).unwrap();
        for link in &spec.links {
            assert!(link.capacity >= 1);
        }
    }

    #[test]
    fn stage_ids_are_unique() {
        let spec = plan_default_topology(128, 128, 128, 3, 2).unwrap();
        let ids: Vec<&str> = spec.stages.iter().map(|s| s.stage_id.as_str()).collect();
        let mut unique = ids.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(ids.len(), unique.len());
    }

    #[test]
    fn link_ids_are_unique() {
        let spec = plan_default_topology(128, 128, 128, 3, 2).unwrap();
        let ids: Vec<&str> = spec.links.iter().map(|l| l.link_id.as_str()).collect();
        let mut unique = ids.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(ids.len(), unique.len());
    }

    #[test]
    fn required_stage_kinds_present() {
        let spec = plan_default_topology(128, 128, 128, 1, 1).unwrap();
        let kinds: Vec<StageKind> = spec.stages.iter().map(|s| s.stage_kind).collect();
        assert!(kinds.contains(&StageKind::IngressGateway));
        assert!(kinds.contains(&StageKind::TransactionSanitizer));
        assert!(kinds.contains(&StageKind::ShredSanitizer));
        assert!(kinds.contains(&StageKind::BlockBuilder));
        assert!(kinds.contains(&StageKind::Telemetry));
    }
}
