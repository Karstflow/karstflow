mod defaults;
mod env;
mod file;
mod types;
mod validation;

pub use types::TopologyProfileToml;

use crate::profile_types::NodeProfileToml;
use crate::Result;
use defaults::plan_default_topology;
use env::{ensure_nonzero_usize, parse_optional_usize_env, resolve_topology_path};
use file::load_topology_from_file;
use paradencer_core::TopologySpec;

pub fn build_topology_spec(profile: Option<&NodeProfileToml>) -> Result<TopologySpec> {
    let profile_topology = profile.and_then(|node_profile| node_profile.topology.as_ref());
    let topology_path = resolve_topology_path(
        profile_topology.and_then(|topology_profile| topology_profile.topology_path.as_deref()),
    );

    if let Some(path) = topology_path {
        println!(
            "[topology] loading external topology from '{}'",
            path.display()
        );
        return load_topology_from_file(&path);
    }

    let mut packet_link_capacity = profile_topology
        .and_then(|topology_profile| topology_profile.packet_link_capacity)
        .unwrap_or(4096);
    let mut shred_link_capacity = profile_topology
        .and_then(|topology_profile| topology_profile.shred_link_capacity)
        .unwrap_or(4096);
    let mut transaction_link_capacity = profile_topology
        .and_then(|topology_profile| topology_profile.transaction_link_capacity)
        .unwrap_or(4096);
    let mut transaction_sanitizer_workers = profile_topology
        .and_then(|topology_profile| topology_profile.transaction_sanitizer_workers)
        .unwrap_or(1);
    let mut shred_sanitizer_workers = profile_topology
        .and_then(|topology_profile| topology_profile.shred_sanitizer_workers)
        .unwrap_or(1);

    packet_link_capacity = ensure_nonzero_usize("packet_link_capacity", packet_link_capacity)?;
    shred_link_capacity = ensure_nonzero_usize("shred_link_capacity", shred_link_capacity)?;
    transaction_link_capacity =
        ensure_nonzero_usize("transaction_link_capacity", transaction_link_capacity)?;
    transaction_sanitizer_workers = ensure_nonzero_usize(
        "transaction_sanitizer_workers",
        transaction_sanitizer_workers,
    )?;
    shred_sanitizer_workers =
        ensure_nonzero_usize("shred_sanitizer_workers", shred_sanitizer_workers)?;

    if let Some(value) = parse_optional_usize_env("PARADENCER_PACKET_LINK_CAPACITY")? {
        packet_link_capacity = value;
    }
    if let Some(value) = parse_optional_usize_env("PARADENCER_SHRED_LINK_CAPACITY")? {
        shred_link_capacity = value;
    }
    if let Some(value) = parse_optional_usize_env("PARADENCER_TRANSACTION_LINK_CAPACITY")? {
        transaction_link_capacity = value;
    }
    if let Some(value) = parse_optional_usize_env("PARADENCER_TRANSACTION_SANITIZER_WORKERS")? {
        transaction_sanitizer_workers = value;
    }
    if let Some(value) = parse_optional_usize_env("PARADENCER_SHRED_SANITIZER_WORKERS")? {
        shred_sanitizer_workers = value;
    }

    plan_default_topology(
        packet_link_capacity,
        shred_link_capacity,
        transaction_link_capacity,
        transaction_sanitizer_workers,
        shred_sanitizer_workers,
    )
}
