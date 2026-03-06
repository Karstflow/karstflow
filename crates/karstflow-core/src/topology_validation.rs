use crate::TopologySpec;
use std::collections::HashSet;

impl TopologySpec {
    pub fn validate(&self) -> Result<(), String> {
        if self.stages.is_empty() {
            return Err("topology must contain at least one stage".to_string());
        }

        let mut stage_ids = HashSet::new();
        for stage in &self.stages {
            if stage.stage_id.trim().is_empty() {
                return Err("stage_id must not be empty".to_string());
            }
            if !stage_ids.insert(stage.stage_id.clone()) {
                return Err(format!("duplicate stage_id '{}'", stage.stage_id));
            }
        }

        let mut link_ids = HashSet::new();
        for link in &self.links {
            if link.link_id.trim().is_empty() {
                return Err("link_id must not be empty".to_string());
            }
            if !link_ids.insert(link.link_id.clone()) {
                return Err(format!("duplicate link_id '{}'", link.link_id));
            }
            if link.capacity == 0 {
                return Err(format!("link '{}' has zero capacity", link.link_id));
            }
            if !stage_ids.contains(&link.source_stage_id) {
                return Err(format!(
                    "link '{}' references unknown source stage '{}'",
                    link.link_id, link.source_stage_id
                ));
            }
            if !stage_ids.contains(&link.destination_stage_id) {
                return Err(format!(
                    "link '{}' references unknown destination stage '{}'",
                    link.link_id, link.destination_stage_id
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LinkKind, LinkSpec, StageKind, StageSpec};

    fn one_stage_topology() -> TopologySpec {
        TopologySpec {
            topology_name: "test".to_string(),
            stages: vec![StageSpec {
                stage_id: "s1".to_string(),
                stage_kind: StageKind::IngressGateway,
            }],
            links: vec![],
        }
    }

    #[test]
    fn valid_topology_passes() {
        assert!(one_stage_topology().validate().is_ok());
    }

    #[test]
    fn empty_stages_fails() {
        let spec = TopologySpec {
            topology_name: "test".to_string(),
            stages: vec![],
            links: vec![],
        };
        let err = spec.validate().unwrap_err();
        assert!(err.contains("at least one stage"));
    }

    #[test]
    fn empty_stage_id_fails() {
        let spec = TopologySpec {
            topology_name: "test".to_string(),
            stages: vec![StageSpec {
                stage_id: "  ".to_string(),
                stage_kind: StageKind::Telemetry,
            }],
            links: vec![],
        };
        let err = spec.validate().unwrap_err();
        assert!(err.contains("stage_id must not be empty"));
    }

    #[test]
    fn duplicate_stage_id_fails() {
        let spec = TopologySpec {
            topology_name: "test".to_string(),
            stages: vec![
                StageSpec {
                    stage_id: "dup".to_string(),
                    stage_kind: StageKind::Telemetry,
                },
                StageSpec {
                    stage_id: "dup".to_string(),
                    stage_kind: StageKind::BlockBuilder,
                },
            ],
            links: vec![],
        };
        let err = spec.validate().unwrap_err();
        assert!(err.contains("duplicate stage_id 'dup'"));
    }

    #[test]
    fn empty_link_id_fails() {
        let mut spec = one_stage_topology();
        spec.links.push(LinkSpec {
            link_id: "".to_string(),
            link_kind: LinkKind::PacketStream,
            source_stage_id: "s1".to_string(),
            destination_stage_id: "s1".to_string(),
            capacity: 64,
        });
        let err = spec.validate().unwrap_err();
        assert!(err.contains("link_id must not be empty"));
    }

    #[test]
    fn duplicate_link_id_fails() {
        let mut spec = TopologySpec {
            topology_name: "test".to_string(),
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
            links: vec![],
        };
        spec.links.push(LinkSpec {
            link_id: "l1".to_string(),
            link_kind: LinkKind::PacketStream,
            source_stage_id: "a".to_string(),
            destination_stage_id: "b".to_string(),
            capacity: 64,
        });
        spec.links.push(LinkSpec {
            link_id: "l1".to_string(),
            link_kind: LinkKind::ShredStream,
            source_stage_id: "a".to_string(),
            destination_stage_id: "b".to_string(),
            capacity: 32,
        });
        let err = spec.validate().unwrap_err();
        assert!(err.contains("duplicate link_id 'l1'"));
    }

    #[test]
    fn zero_capacity_link_fails() {
        let mut spec = one_stage_topology();
        spec.links.push(LinkSpec {
            link_id: "l1".to_string(),
            link_kind: LinkKind::PacketStream,
            source_stage_id: "s1".to_string(),
            destination_stage_id: "s1".to_string(),
            capacity: 0,
        });
        let err = spec.validate().unwrap_err();
        assert!(err.contains("zero capacity"));
    }

    #[test]
    fn unknown_source_stage_fails() {
        let mut spec = one_stage_topology();
        spec.links.push(LinkSpec {
            link_id: "l1".to_string(),
            link_kind: LinkKind::PacketStream,
            source_stage_id: "missing".to_string(),
            destination_stage_id: "s1".to_string(),
            capacity: 64,
        });
        let err = spec.validate().unwrap_err();
        assert!(err.contains("unknown source stage"));
    }

    #[test]
    fn unknown_destination_stage_fails() {
        let mut spec = one_stage_topology();
        spec.links.push(LinkSpec {
            link_id: "l1".to_string(),
            link_kind: LinkKind::PacketStream,
            source_stage_id: "s1".to_string(),
            destination_stage_id: "missing".to_string(),
            capacity: 64,
        });
        let err = spec.validate().unwrap_err();
        assert!(err.contains("unknown destination stage"));
    }
}
