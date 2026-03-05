use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
pub struct TopologyProfileToml {
    pub topology_path: Option<String>,
    pub packet_link_capacity: Option<usize>,
    pub shred_link_capacity: Option<usize>,
    pub transaction_link_capacity: Option<usize>,
    pub transaction_sanitizer_workers: Option<usize>,
    pub shred_sanitizer_workers: Option<usize>,
}
