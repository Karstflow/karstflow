use crate::{
    ExecutionMode, IpcMode, LinkKind, LinkSpec, PinnedCorePolicy, StageKind, StageSpec,
    TopologySpec,
};

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

#[test]
fn execution_mode_from_env_tokio() {
    assert_eq!(ExecutionMode::from_env("tokio"), Some(ExecutionMode::Tokio));
}

#[test]
fn execution_mode_from_env_pinned() {
    assert_eq!(
        ExecutionMode::from_env("pinned"),
        Some(ExecutionMode::Pinned)
    );
}

#[test]
fn execution_mode_from_env_case_insensitive() {
    assert_eq!(ExecutionMode::from_env("TOKIO"), Some(ExecutionMode::Tokio));
    assert_eq!(
        ExecutionMode::from_env("Pinned"),
        Some(ExecutionMode::Pinned)
    );
}

#[test]
fn execution_mode_from_env_invalid() {
    assert_eq!(ExecutionMode::from_env("async"), None);
    assert_eq!(ExecutionMode::from_env(""), None);
}

#[test]
fn execution_mode_display() {
    assert_eq!(format!("{}", ExecutionMode::Tokio), "tokio");
    assert_eq!(format!("{}", ExecutionMode::Pinned), "pinned");
}

#[test]
fn pinned_core_policy_from_env_all_variants() {
    assert_eq!(
        PinnedCorePolicy::from_env("strict"),
        Some(PinnedCorePolicy::Strict)
    );
    assert_eq!(
        PinnedCorePolicy::from_env("shared"),
        Some(PinnedCorePolicy::Shared)
    );
    assert_eq!(
        PinnedCorePolicy::from_env("adaptive"),
        Some(PinnedCorePolicy::Adaptive)
    );
}

#[test]
fn pinned_core_policy_from_env_case_insensitive() {
    assert_eq!(
        PinnedCorePolicy::from_env("STRICT"),
        Some(PinnedCorePolicy::Strict)
    );
    assert_eq!(
        PinnedCorePolicy::from_env("Adaptive"),
        Some(PinnedCorePolicy::Adaptive)
    );
}

#[test]
fn pinned_core_policy_from_env_invalid() {
    assert_eq!(PinnedCorePolicy::from_env("exclusive"), None);
    assert_eq!(PinnedCorePolicy::from_env(""), None);
}

#[test]
fn pinned_core_policy_display() {
    assert_eq!(format!("{}", PinnedCorePolicy::Strict), "strict");
    assert_eq!(format!("{}", PinnedCorePolicy::Shared), "shared");
    assert_eq!(format!("{}", PinnedCorePolicy::Adaptive), "adaptive");
}

#[test]
fn topology_validation_accepts_valid_spec() {
    let topology = TopologySpec {
        topology_name: "valid".to_string(),
        stages: vec![
            StageSpec {
                stage_id: "a".to_string(),
                stage_kind: StageKind::IngressGateway,
            },
            StageSpec {
                stage_id: "b".to_string(),
                stage_kind: StageKind::Telemetry,
            },
        ],
        links: vec![LinkSpec {
            link_id: "link1".to_string(),
            link_kind: LinkKind::PacketStream,
            source_stage_id: "a".to_string(),
            destination_stage_id: "b".to_string(),
            capacity: 128,
        }],
    };
    assert!(topology.validate().is_ok());
}

#[test]
fn topology_validation_rejects_duplicate_link_ids() {
    let topology = TopologySpec {
        topology_name: "dup-link".to_string(),
        stages: vec![
            StageSpec {
                stage_id: "a".to_string(),
                stage_kind: StageKind::IngressGateway,
            },
            StageSpec {
                stage_id: "b".to_string(),
                stage_kind: StageKind::Telemetry,
            },
        ],
        links: vec![
            LinkSpec {
                link_id: "same".to_string(),
                link_kind: LinkKind::PacketStream,
                source_stage_id: "a".to_string(),
                destination_stage_id: "b".to_string(),
                capacity: 64,
            },
            LinkSpec {
                link_id: "same".to_string(),
                link_kind: LinkKind::ShredStream,
                source_stage_id: "b".to_string(),
                destination_stage_id: "a".to_string(),
                capacity: 64,
            },
        ],
    };
    assert!(topology.validate().is_err());
}

#[test]
fn topology_validation_rejects_empty_stages() {
    let topology = TopologySpec {
        topology_name: "empty".to_string(),
        stages: vec![],
        links: vec![],
    };
    assert!(topology.validate().is_err());
}

#[test]
fn topology_validation_rejects_empty_stage_id() {
    let topology = TopologySpec {
        topology_name: "empty-id".to_string(),
        stages: vec![StageSpec {
            stage_id: "  ".to_string(),
            stage_kind: StageKind::IngressGateway,
        }],
        links: vec![],
    };
    let err = topology.validate().unwrap_err();
    assert!(err.contains("stage_id must not be empty"));
}

#[test]
fn topology_validation_rejects_empty_link_id() {
    let topology = TopologySpec {
        topology_name: "empty-link-id".to_string(),
        stages: vec![
            StageSpec {
                stage_id: "a".to_string(),
                stage_kind: StageKind::IngressGateway,
            },
            StageSpec {
                stage_id: "b".to_string(),
                stage_kind: StageKind::Telemetry,
            },
        ],
        links: vec![LinkSpec {
            link_id: "".to_string(),
            link_kind: LinkKind::PacketStream,
            source_stage_id: "a".to_string(),
            destination_stage_id: "b".to_string(),
            capacity: 64,
        }],
    };
    let err = topology.validate().unwrap_err();
    assert!(err.contains("link_id must not be empty"));
}

#[test]
fn topology_validation_rejects_zero_capacity() {
    let topology = TopologySpec {
        topology_name: "zero-cap".to_string(),
        stages: vec![
            StageSpec {
                stage_id: "a".to_string(),
                stage_kind: StageKind::IngressGateway,
            },
            StageSpec {
                stage_id: "b".to_string(),
                stage_kind: StageKind::Telemetry,
            },
        ],
        links: vec![LinkSpec {
            link_id: "link1".to_string(),
            link_kind: LinkKind::PacketStream,
            source_stage_id: "a".to_string(),
            destination_stage_id: "b".to_string(),
            capacity: 0,
        }],
    };
    let err = topology.validate().unwrap_err();
    assert!(err.contains("zero capacity"));
}

#[test]
fn topology_validation_rejects_unknown_source_stage() {
    let topology = TopologySpec {
        topology_name: "bad-src".to_string(),
        stages: vec![StageSpec {
            stage_id: "a".to_string(),
            stage_kind: StageKind::IngressGateway,
        }],
        links: vec![LinkSpec {
            link_id: "link1".to_string(),
            link_kind: LinkKind::PacketStream,
            source_stage_id: "nonexistent".to_string(),
            destination_stage_id: "a".to_string(),
            capacity: 64,
        }],
    };
    let err = topology.validate().unwrap_err();
    assert!(err.contains("unknown source stage"));
}

#[test]
fn ipc_mode_from_env_channel() {
    assert_eq!(IpcMode::from_env("channel"), Some(IpcMode::Channel));
    assert_eq!(IpcMode::from_env("channels"), Some(IpcMode::Channel));
}

#[test]
fn ipc_mode_from_env_shared_memory() {
    assert_eq!(
        IpcMode::from_env("shared_memory"),
        Some(IpcMode::SharedMemory)
    );
    assert_eq!(IpcMode::from_env("shm"), Some(IpcMode::SharedMemory));
}

#[test]
fn ipc_mode_from_env_case_insensitive() {
    assert_eq!(IpcMode::from_env("CHANNEL"), Some(IpcMode::Channel));
    assert_eq!(IpcMode::from_env("SHM"), Some(IpcMode::SharedMemory));
}

#[test]
fn ipc_mode_from_env_invalid() {
    assert_eq!(IpcMode::from_env("pipe"), None);
    assert_eq!(IpcMode::from_env(""), None);
}

#[test]
fn ipc_mode_display() {
    assert_eq!(format!("{}", IpcMode::Channel), "channel");
    assert_eq!(format!("{}", IpcMode::SharedMemory), "shared_memory");
}

#[test]
fn execution_mode_tile_variant() {
    assert_eq!(ExecutionMode::from_env("tile"), Some(ExecutionMode::Tile));
    assert_eq!(ExecutionMode::from_env("TILE"), Some(ExecutionMode::Tile));
    assert_eq!(format!("{}", ExecutionMode::Tile), "tile");
}
