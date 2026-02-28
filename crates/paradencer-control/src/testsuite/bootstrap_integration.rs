use crate::bootstrap::{
    build_blockstore, build_pipeline_service, build_replay_service, build_shred_pipeline,
    build_storage_maintenance_service, materialize_service_pair_from_config,
    materialize_services_from_config, BlockstoreShredProvider,
};
use paradencer_config::NodeConfig;
use std::sync::Arc;

#[test]
fn materialize_services_from_config_builds_default_services() {
    let node_config = NodeConfig::from_profile(None).unwrap();
    let materialized = materialize_services_from_config(&node_config).unwrap();
    // 5 topology stages + ShredNetworkService + ShredCollector = 7 services.
    assert_eq!(materialized.services.len(), 7);
}

#[test]
fn materialize_service_pair_from_config_builds_startup_and_runtime_services() {
    let node_config = NodeConfig::from_profile(None).unwrap();
    let pair = materialize_service_pair_from_config(&node_config).unwrap();
    assert_eq!(pair.startup.services.len(), pair.runtime.services.len());
    assert_eq!(pair.runtime.services.len(), 7);
}

#[test]
fn build_pipeline_service_creates_service_and_handle() {
    use paradencer_runtime::{ServiceContext, ShutdownSwitch};
    use paradencer_stages::PipelineServiceConfig;

    let bundle = build_pipeline_service(PipelineServiceConfig::default(), Vec::new());
    assert_eq!(bundle.service.name(), "validator-pipeline");
    assert!(!bundle.handle.is_leading());

    let ctx = ServiceContext::new(ShutdownSwitch::new());
    let mut service = bundle.service;
    service.tick(&ctx).unwrap();
}

#[test]
fn pipeline_service_integrates_with_topology_services() {
    use paradencer_stages::PipelineServiceConfig;

    let node_config = NodeConfig::from_profile(None).unwrap();
    let materialized = materialize_services_from_config(&node_config).unwrap();
    let bundle = build_pipeline_service(
        PipelineServiceConfig::default(),
        materialized.pipeline_inputs,
    );

    let mut services = materialized.services;
    services.push(bundle.service);

    // Topology (7) + pipeline (1) = 8 total services.
    assert_eq!(services.len(), 8);
    assert_eq!(services.last().unwrap().name(), "validator-pipeline");
}

#[test]
fn build_replay_service_creates_service_and_consensus() {
    use paradencer_runtime::{ServiceContext, ShutdownSwitch};
    use paradencer_stages::ReplayServiceConfig;

    let bundle = build_replay_service(ReplayServiceConfig::default(), 1_000_000);
    assert_eq!(bundle.service.name(), "replay-service");

    let forks = bundle.consensus.bank_forks.read().unwrap();
    assert_eq!(forks.root_slot(), 0);
    drop(forks);

    let ctx = ServiceContext::new(ShutdownSwitch::new());
    let mut service = bundle.service;
    service.tick(&ctx).unwrap();
}

#[test]
fn replay_and_pipeline_integrate_with_topology() {
    use paradencer_stages::{PipelineServiceConfig, ReplayServiceConfig};

    let node_config = NodeConfig::from_profile(None).unwrap();
    let materialized = materialize_services_from_config(&node_config).unwrap();
    let replay_bundle = build_replay_service(ReplayServiceConfig::default(), 1_000_000);
    let pipeline_bundle = build_pipeline_service(
        PipelineServiceConfig::default(),
        materialized.pipeline_inputs,
    );

    let mut services = materialized.services;
    services.push(replay_bundle.service);
    services.push(pipeline_bundle.service);

    // Topology (7) + replay (1) + pipeline (1) = 9 total services.
    assert_eq!(services.len(), 9);

    let names: Vec<&str> = services.iter().map(|s| s.name()).collect();
    assert!(names.contains(&"replay-service"));
    assert!(names.contains(&"validator-pipeline"));
}

#[test]
fn build_shred_pipeline_creates_service_and_channels() {
    use paradencer_runtime::{ServiceContext, ShutdownSwitch};
    use paradencer_stages::ShredCollectorConfig;

    let bundle = build_shred_pipeline(ShredCollectorConfig::default(), None, None);
    assert_eq!(bundle.service.name(), "shred-collector");

    let ctx = ServiceContext::new(ShutdownSwitch::new());
    let mut service = bundle.service;
    service.tick(&ctx).unwrap();
}

#[test]
fn build_shred_pipeline_with_blockstore_persists_shreds() {
    use paradencer_runtime::{ServiceContext, ShutdownSwitch};
    use paradencer_stages::ShredCollectorConfig;
    use paradencer_storage::Blockstore;
    use paradencer_types::shred::{
        DataShredHeader, Shred, ShredCommonHeader, ShredVariant, SIGNATURE_SIZE,
    };

    let blockstore = Arc::new(Blockstore::in_memory());
    let bundle = build_shred_pipeline(
        ShredCollectorConfig::default(),
        Some(Arc::clone(&blockstore)),
        None,
    );

    let common = ShredCommonHeader {
        signature: [0u8; SIGNATURE_SIZE],
        variant: 0x55,
        slot: 42,
        index: 0,
        version: 1,
        fec_set_index: 0,
    };
    let data_header = DataShredHeader {
        parent_offset: 1,
        flags: 0,
        size: 64,
    };
    let shred = Shred::new(
        common,
        ShredVariant::LegacyData(data_header),
        vec![0xBE; 64],
    );

    bundle.shred_input.try_send(shred).unwrap();

    let ctx = ServiceContext::new(ShutdownSwitch::new());
    let mut service = bundle.service;
    service.tick(&ctx).unwrap();

    let stored = blockstore.get_data_shred(42, 0).unwrap();
    assert!(stored.is_some());
    assert_eq!(stored.unwrap(), vec![0xBE; 64]);
}

#[test]
fn build_blockstore_creates_persistent_store() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let bs = build_blockstore(Some(dir.path())).unwrap();
    assert!(bs.is_some());

    let bs = bs.unwrap();
    bs.insert_data_shred(1, 0, &[0xFF; 32]).unwrap();
    assert!(bs.get_data_shred(1, 0).unwrap().is_some());
}

#[test]
fn build_blockstore_returns_none_without_data_dir() {
    let bs = build_blockstore(None).unwrap();
    assert!(bs.is_none());
}

#[test]
fn topology_includes_shred_collector_and_integrates_with_bootstrap_services() {
    use paradencer_stages::{PipelineServiceConfig, ReplayServiceConfig};

    let node_config = NodeConfig::from_profile(None).unwrap();
    let materialized = materialize_services_from_config(&node_config).unwrap();

    assert!(materialized.shred_block_receiver.is_some());

    let replay_bundle = build_replay_service(ReplayServiceConfig::default(), 1_000_000);
    let pipeline_bundle = build_pipeline_service(
        PipelineServiceConfig::default(),
        materialized.pipeline_inputs,
    );

    let mut services = materialized.services;
    services.push(replay_bundle.service);
    services.push(pipeline_bundle.service);

    // Topology (7, including shred-network + shred-collector) + replay (1) + pipeline (1) = 9.
    assert_eq!(services.len(), 9);

    let names: Vec<&str> = services.iter().map(|s| s.name()).collect();
    assert!(names.contains(&"replay-service"));
    assert!(names.contains(&"validator-pipeline"));
    assert!(names.contains(&"shred-network"));
    assert!(names.contains(&"shred-collector"));
}

#[test]
fn blockstore_shred_provider_serves_stored_shreds() {
    use paradencer_net::ShredProvider;
    use paradencer_storage::Blockstore;

    let bs = Arc::new(Blockstore::in_memory());

    bs.insert_data_shred(10, 0, &[0xAA; 64]).unwrap();
    bs.insert_data_shred(10, 1, &[0xBB; 64]).unwrap();
    bs.insert_data_shred(11, 0, &[0xCC; 64]).unwrap();

    let provider = BlockstoreShredProvider::new(Arc::clone(&bs));

    let shred = provider.get_shred(10, 0).unwrap();
    assert_eq!(shred.slot, 10);
    assert_eq!(shred.index, 0);
    assert_eq!(shred.data, vec![0xAA; 64]);

    assert!(provider.get_shred(10, 99).is_none());
    assert!(provider.get_shred(999, 0).is_none());

    assert_eq!(provider.get_highest_shred_index(10), Some(1));
    assert_eq!(provider.get_highest_shred_index(11), Some(0));
    assert!(provider.get_highest_shred_index(999).is_none());

    let range_shreds = provider.get_shreds_in_range(10, 11);
    assert_eq!(range_shreds.len(), 3);

    let ancestors = provider.get_ancestors(11, 2);
    assert_eq!(ancestors.len(), 2);
    assert!(ancestors.iter().all(|s| s.slot == 10));
}

#[test]
fn build_storage_maintenance_creates_service() {
    use paradencer_runtime::{ServiceContext, ShutdownSwitch};
    use paradencer_storage::{MaintenanceConfig, StorageEngine};

    let dir = tempfile::tempdir().expect("tmpdir");
    let engine = Arc::new(StorageEngine::open(dir.path()).expect("open"));
    let bundle = build_storage_maintenance_service(engine, MaintenanceConfig::default());
    assert_eq!(bundle.service.name(), "storage-maintenance");

    let ctx = ServiceContext::new(ShutdownSwitch::new());
    let mut service = bundle.service;
    service.tick(&ctx).unwrap();
}

#[test]
fn convert_repair_target_to_request_all_variants() {
    use crate::bootstrap::convert_repair_target_to_request;
    use paradencer_net::{repair::RepairRequest, repair::RepairTarget, NodeId};

    let requester = NodeId([42u8; 32]);

    let target = RepairTarget::Shred {
        slot: 100,
        index: 5,
    };
    let req = convert_repair_target_to_request(requester, &target, 999);
    match req {
        RepairRequest::Shred {
            requester: r,
            slot,
            index,
            nonce,
        } => {
            assert_eq!(r.0, [42u8; 32]);
            assert_eq!(slot, 100);
            assert_eq!(index, 5);
            assert_eq!(nonce, 999);
        }
        _ => panic!("expected Shred variant"),
    }

    let target = RepairTarget::HighestShred { slot: 200 };
    let req = convert_repair_target_to_request(requester, &target, 1000);
    match req {
        RepairRequest::HighestShred {
            requester: r,
            slot,
            nonce,
        } => {
            assert_eq!(r.0, [42u8; 32]);
            assert_eq!(slot, 200);
            assert_eq!(nonce, 1000);
        }
        _ => panic!("expected HighestShred variant"),
    }

    let target = RepairTarget::Orphan { slot: 300 };
    let req = convert_repair_target_to_request(requester, &target, 1001);
    match req {
        RepairRequest::Orphan {
            requester: r,
            slot,
            nonce,
        } => {
            assert_eq!(r.0, [42u8; 32]);
            assert_eq!(slot, 300);
            assert_eq!(nonce, 1001);
        }
        _ => panic!("expected Orphan variant"),
    }
}
