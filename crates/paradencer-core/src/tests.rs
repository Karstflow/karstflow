use crate::{LinkKind, LinkSpec, StageKind, StageSpec, TopologySpec};

#[test]
fn topology_validation_rejects_duplicate_stage_ids() {
    let topology = TopologySpec {
        topology_name: "dup-stage".to_string(),
        stages: vec![
            StageSpec {
                stage_id: "a".to_string(),
                stage_kind: StageKind::IngressGateway,
            },
            StageSpec {
                stage_id: "a".to_string(),
                stage_kind: StageKind::Telemetry,
            },
        ],
        links: vec![],
    };

    assert!(topology.validate().is_err());
}

#[test]
fn topology_validation_rejects_links_to_unknown_stages() {
    let topology = TopologySpec {
        topology_name: "bad-link".to_string(),
        stages: vec![StageSpec {
            stage_id: "ingress".to_string(),
            stage_kind: StageKind::IngressGateway,
        }],
        links: vec![LinkSpec {
            link_id: "packet".to_string(),
            link_kind: LinkKind::PacketStream,
            source_stage_id: "ingress".to_string(),
            destination_stage_id: "missing".to_string(),
            capacity: 64,
        }],
    };

    assert!(topology.validate().is_err());
}
