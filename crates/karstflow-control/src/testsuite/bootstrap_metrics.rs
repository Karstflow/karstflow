use crate::bootstrap::{
    materialize_services_from_config, maybe_start_metrics_http_bridge, maybe_start_rpc_http_server,
};
use karstflow_config::NodeConfig;

#[test]
fn maybe_start_metrics_http_bridge_rejects_non_file_metrics_target() {
    let mut node_config = NodeConfig::from_profile(None).unwrap();
    node_config.metrics_http_bind = Some("127.0.0.1:0".parse().unwrap());
    node_config.metrics_output_target = karstflow_stages::MetricsOutputTarget::Stdout;

    let result = maybe_start_metrics_http_bridge(&node_config, None, None);
    assert!(result.is_err());
}

#[test]
fn metrics_http_bridge_starts_with_http_target_and_content() {
    let mut node_config = NodeConfig::from_profile(None).unwrap();
    node_config.metrics_http_bind = Some("127.0.0.1:0".parse().unwrap());
    node_config.metrics_output_target = karstflow_stages::MetricsOutputTarget::Http;

    let content = karstflow_stages::shared_metrics_content();
    let result = maybe_start_metrics_http_bridge(&node_config, Some(content), None);
    assert!(result.is_ok());
}

#[test]
fn metrics_http_bridge_fails_http_target_without_content() {
    let mut node_config = NodeConfig::from_profile(None).unwrap();
    node_config.metrics_http_bind = Some("127.0.0.1:0".parse().unwrap());
    node_config.metrics_output_target = karstflow_stages::MetricsOutputTarget::Http;

    let result = maybe_start_metrics_http_bridge(&node_config, None, None);
    assert!(result.is_err());
}

#[test]
fn materialize_with_http_target_returns_shared_content() {
    let mut node_config = NodeConfig::from_profile(None).unwrap();
    node_config.metrics_output_format = karstflow_stages::MetricsOutputFormat::PrometheusText;
    node_config.metrics_output_target = karstflow_stages::MetricsOutputTarget::Http;

    let materialized = materialize_services_from_config(&node_config).unwrap();
    assert!(
        materialized.metrics_http_content.is_some(),
        "Http target must produce shared metrics content buffer"
    );
}

#[test]
fn materialize_with_file_target_returns_no_content() {
    let mut node_config = NodeConfig::from_profile(None).unwrap();
    node_config.metrics_output_target =
        karstflow_stages::MetricsOutputTarget::File("/tmp/test-metrics.log".into());

    let materialized = materialize_services_from_config(&node_config).unwrap();
    assert!(
        materialized.metrics_http_content.is_none(),
        "File target must not produce shared metrics content buffer"
    );
}

#[test]
fn maybe_start_rpc_http_server_rejects_enabled_without_bind() {
    let mut node_config = NodeConfig::from_profile(None).unwrap();
    node_config.rpc_enabled = true;
    node_config.rpc_bind = None;

    let result = maybe_start_rpc_http_server(&node_config);
    assert!(result.is_err());
}
