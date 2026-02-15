use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
pub struct RuntimeProfileToml {
    pub mode: Option<String>,
    pub workers: Option<usize>,
    pub run_for_seconds: Option<u64>,
    pub pinned_core_policy: Option<String>,
    pub pinned_allow_core_sharing: Option<bool>,
    pub pinned_service_core_ids: Option<Vec<usize>>,
}
