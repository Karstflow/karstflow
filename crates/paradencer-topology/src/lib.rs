mod errors;
mod topology_parts;

pub use errors::{Result, TopologyError};
#[cfg(test)]
pub use topology_parts::{load_topology_from_file, plan_default_topology};
pub use topology_parts::{materialize_services, MaterializedTopology};

#[cfg(test)]
mod tests {
    use super::{load_topology_from_file, materialize_services, plan_default_topology};
    use paradencer_net::IngressPolicy;
    use paradencer_stages::{MetricsOutputFormat, MetricsOutputTarget, StorageRuntimePolicy};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn planner_builds_valid_default_topology() {
        let topology = plan_default_topology(256, 256, 512, 1, 1).unwrap();
        assert_eq!(topology.stages.len(), 5);
        assert_eq!(topology.links.len(), 3);
    }

    #[test]
    fn planner_expands_transaction_sanitizer_workers() {
        let topology = plan_default_topology(256, 256, 512, 3, 2).unwrap();
        assert_eq!(topology.stages.len(), 8);
        assert_eq!(topology.links.len(), 8);
    }

    #[test]
    fn planner_expands_shred_sanitizer_workers() {
        let topology = plan_default_topology(256, 256, 512, 1, 3).unwrap();
        assert_eq!(topology.stages.len(), 7);
        assert_eq!(topology.links.len(), 5);
    }

    #[test]
    fn materializer_builds_service_set_from_topology() {
        let topology = plan_default_topology(16, 16, 16, 1, 1).unwrap();
        let materialized = materialize_services(
            topology,
            IngressPolicy::default(),
            MetricsOutputFormat::JsonLines,
            MetricsOutputTarget::Stdout,
            StorageRuntimePolicy::default(),
        )
        .unwrap();
        assert_eq!(materialized.services.len(), 5);
    }

    #[test]
    fn materializer_builds_service_set_from_multi_worker_topology() {
        let topology = plan_default_topology(16, 16, 16, 3, 2).unwrap();
        let materialized = materialize_services(
            topology,
            IngressPolicy::default(),
            MetricsOutputFormat::JsonLines,
            MetricsOutputTarget::Stdout,
            StorageRuntimePolicy::default(),
        )
        .unwrap();
        assert_eq!(materialized.services.len(), 8);
    }

    #[test]
    fn loader_parses_external_topology_file() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_path = std::env::temp_dir().join(format!("paradencer-topology-{suffix}.toml"));

        let file_content = r#"
topology_name = "test-topology"

[[stages]]
stage_id = "ingress_gateway"
stage_kind = "ingress_gateway"

[[stages]]
stage_id = "transaction_sanitizer"
stage_kind = "transaction_sanitizer"

[[stages]]
stage_id = "block_builder"
stage_kind = "block_builder"

[[stages]]
stage_id = "shred_sanitizer"
stage_kind = "shred_sanitizer"

[[stages]]
stage_id = "telemetry"
stage_kind = "telemetry"

[[links]]
link_id = "packet_stream"
link_kind = "packet_stream"
source_stage_id = "ingress_gateway"
destination_stage_id = "transaction_sanitizer"
capacity = 64

[[links]]
link_id = "transaction_stream"
link_kind = "transaction_stream"
source_stage_id = "transaction_sanitizer"
destination_stage_id = "block_builder"
capacity = 64

[[links]]
link_id = "shred_stream"
link_kind = "shred_stream"
source_stage_id = "ingress_gateway"
destination_stage_id = "shred_sanitizer"
capacity = 64
"#;

        fs::write(&temp_path, file_content).unwrap();
        let loaded_topology = load_topology_from_file(&temp_path).unwrap();
        fs::remove_file(&temp_path).unwrap();

        assert_eq!(loaded_topology.topology_name, "test-topology");
        assert_eq!(loaded_topology.stages.len(), 5);
        assert_eq!(loaded_topology.links.len(), 3);
    }

    #[test]
    fn loader_rejects_external_topology_with_unwired_transaction_worker() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_path =
            std::env::temp_dir().join(format!("paradencer-topology-invalid-{suffix}.toml"));

        let file_content = r#"
topology_name = "invalid-topology"

[[stages]]
stage_id = "ingress_gateway"
stage_kind = "ingress_gateway"

[[stages]]
stage_id = "transaction_sanitizer"
stage_kind = "transaction_sanitizer"

[[stages]]
stage_id = "transaction_sanitizer_1"
stage_kind = "transaction_sanitizer"

[[stages]]
stage_id = "block_builder"
stage_kind = "block_builder"

[[stages]]
stage_id = "shred_sanitizer"
stage_kind = "shred_sanitizer"

[[stages]]
stage_id = "telemetry"
stage_kind = "telemetry"

[[links]]
link_id = "packet_stream"
link_kind = "packet_stream"
source_stage_id = "ingress_gateway"
destination_stage_id = "transaction_sanitizer"
capacity = 64

[[links]]
link_id = "transaction_stream"
link_kind = "transaction_stream"
source_stage_id = "transaction_sanitizer"
destination_stage_id = "block_builder"
capacity = 64

[[links]]
link_id = "shred_stream"
link_kind = "shred_stream"
source_stage_id = "ingress_gateway"
destination_stage_id = "shred_sanitizer"
capacity = 64
"#;

        fs::write(&temp_path, file_content).unwrap();
        let load_result = load_topology_from_file(&temp_path);
        fs::remove_file(&temp_path).unwrap();

        assert!(load_result.is_err());
    }

    #[test]
    fn loader_rejects_transaction_stream_not_pointing_to_block_builder() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_path =
            std::env::temp_dir().join(format!("paradencer-topology-invalid-dst-{suffix}.toml"));

        let file_content = r#"
topology_name = "invalid-topology"

[[stages]]
stage_id = "ingress_gateway"
stage_kind = "ingress_gateway"

[[stages]]
stage_id = "transaction_sanitizer"
stage_kind = "transaction_sanitizer"

[[stages]]
stage_id = "block_builder"
stage_kind = "block_builder"

[[stages]]
stage_id = "shred_sanitizer"
stage_kind = "shred_sanitizer"

[[stages]]
stage_id = "telemetry"
stage_kind = "telemetry"

[[links]]
link_id = "packet_stream"
link_kind = "packet_stream"
source_stage_id = "ingress_gateway"
destination_stage_id = "transaction_sanitizer"
capacity = 64

[[links]]
link_id = "transaction_stream"
link_kind = "transaction_stream"
source_stage_id = "transaction_sanitizer"
destination_stage_id = "telemetry"
capacity = 64

[[links]]
link_id = "shred_stream"
link_kind = "shred_stream"
source_stage_id = "ingress_gateway"
destination_stage_id = "shred_sanitizer"
capacity = 64
"#;

        fs::write(&temp_path, file_content).unwrap();
        let load_result = load_topology_from_file(&temp_path);
        fs::remove_file(&temp_path).unwrap();

        assert!(load_result.is_err());
    }
}
