use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
pub struct MetricsProfileToml {
    pub output_format: Option<String>,
    pub output_target: Option<String>,
    pub file_path: Option<String>,
    pub udp_addr: Option<String>,
    pub http_bind: Option<String>,
}
