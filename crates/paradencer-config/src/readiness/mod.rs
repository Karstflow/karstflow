mod env;
mod profile;
mod types;

use crate::profile_types::NodeProfileToml;
use crate::{MainnetReadinessPolicy, Result};
use env::apply_env_overrides;
pub use types::MainnetReadinessProfileToml;

pub fn build_mainnet_readiness_policy(
    profile: Option<&NodeProfileToml>,
) -> Result<MainnetReadinessPolicy> {
    let mut policy = MainnetReadinessPolicy::default();

    if let Some(readiness_profile) =
        profile.and_then(|node_profile| node_profile.readiness.as_ref())
    {
        profile::apply_profile(&mut policy, readiness_profile)?;
    }

    apply_env_overrides(&mut policy)?;
    Ok(policy)
}
