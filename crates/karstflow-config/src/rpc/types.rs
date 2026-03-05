use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
pub struct RpcProfileToml {
    pub enabled: Option<bool>,
    pub bind: Option<String>,
    pub private: Option<bool>,
    pub full_api: Option<bool>,
}
