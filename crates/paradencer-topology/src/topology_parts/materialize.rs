use crate::errors::Result;
use crate::topology_parts::types::MaterializedTopology;
use crate::topology_parts::validation::{find_link_capacity, validate_topology_requirements};
use paradencer_constants::ipc::PIPELINE_CHANNEL_DEPTH_PER_WORKER;
use paradencer_core::{LinkKind, StageKind, TopologySpec};
use paradencer_mesh::bounded_link;
use paradencer_net::IngressPolicy;
use paradencer_runtime::Service;
use paradencer_stages::{
    shared_metrics_content, AssembledBlock, BlockAssembler, BlockAssemblyStats, CompletedFecSet,
    EdgeIntake, InboundPacket, IngressFilterStats, LinkTelemetryStats, MetricsContent,
    MetricsOutputFormat, MetricsOutputTarget, MetricsReporter, RawTransaction,
    SanitizedTransaction, ShredArrival, ShredCollector, ShredFilter, ShredFilterStats,
    ShredNetworkConfig, ShredNetworkService, StageTelemetryStats, StorageRuntimePolicy, TxFilter,
};
use paradencer_storage::Blockstore;
use paradencer_types::shred::Shred;
use std::collections::HashMap;
use std::sync::Arc;

pub fn materialize_services(
    topology_spec: TopologySpec,
    ingress_policy: IngressPolicy,
    metrics_output_format: MetricsOutputFormat,
    metrics_output_target: MetricsOutputTarget,
    storage_runtime_policy: StorageRuntimePolicy,
) -> Result<MaterializedTopology> {
    materialize_services_with_blockstore(
        topology_spec,
        ingress_policy,
        metrics_output_format,
        metrics_output_target,
        storage_runtime_policy,
        None,
    )
}

pub fn materialize_services_with_blockstore(
    topology_spec: TopologySpec,
    ingress_policy: IngressPolicy,
    metrics_output_format: MetricsOutputFormat,
    metrics_output_target: MetricsOutputTarget,
    storage_runtime_policy: StorageRuntimePolicy,
    blockstore: Option<Arc<Blockstore>>,
) -> Result<MaterializedTopology> {
    validate_topology_requirements(&topology_spec)?;

    let _packet_capacity = find_link_capacity(&topology_spec, LinkKind::PacketStream)?;
    let _shred_capacity = find_link_capacity(&topology_spec, LinkKind::ShredStream)?;
    let _transaction_capacity = find_link_capacity(&topology_spec, LinkKind::TransactionStream)?;

    let mut packet_outbound_links = Vec::new();
    let mut packet_stats = Vec::new();
    let mut packet_inbound_by_stage: HashMap<String, paradencer_mesh::InPort<InboundPacket>> =
        HashMap::new();
    for link in topology_spec
        .links
        .iter()
        .filter(|link| link.link_kind == LinkKind::PacketStream)
    {
        let (outbound, inbound) = bounded_link::<InboundPacket>(link.capacity);
        packet_stats.push(outbound.stats());
        packet_outbound_links.push(outbound);
        packet_inbound_by_stage.insert(link.destination_stage_id.clone(), inbound);
    }

    let mut shred_outbound_links = Vec::new();
    let mut shred_stats = Vec::new();
    let mut shred_inbound_by_stage: HashMap<String, paradencer_mesh::InPort<InboundPacket>> =
        HashMap::new();
    for link in topology_spec
        .links
        .iter()
        .filter(|link| link.link_kind == LinkKind::ShredStream)
    {
        let (outbound, inbound) = bounded_link::<InboundPacket>(link.capacity);
        shred_stats.push(outbound.stats());
        shred_outbound_links.push(outbound);
        shred_inbound_by_stage.insert(link.destination_stage_id.clone(), inbound);
    }

    let mut transaction_outbound_by_stage: HashMap<
        String,
        paradencer_mesh::OutPort<SanitizedTransaction>,
    > = HashMap::new();
    let mut transaction_inbound_by_stage: HashMap<
        String,
        Vec<paradencer_mesh::InPort<SanitizedTransaction>>,
    > = HashMap::new();
    let mut transaction_stats = Vec::new();
    for link in topology_spec
        .links
        .iter()
        .filter(|link| link.link_kind == LinkKind::TransactionStream)
    {
        let (outbound, inbound) = bounded_link::<SanitizedTransaction>(link.capacity);
        transaction_stats.push(outbound.stats());
        transaction_outbound_by_stage.insert(link.source_stage_id.clone(), outbound);
        transaction_inbound_by_stage
            .entry(link.destination_stage_id.clone())
            .or_default()
            .push(inbound);
    }

    assert!(
        !packet_stats.is_empty(),
        "packet links must exist after topology validation"
    );
    assert!(
        !shred_stats.is_empty(),
        "shred links must exist after topology validation"
    );
    assert!(
        !transaction_stats.is_empty(),
        "transaction links must exist after topology validation"
    );
    // Internal shred pipeline:
    //   ShredFilter → ShredNetworkService (FEC resolution) → ShredCollector → block output.
    // The filtered shred link connects ShredFilter to ShredNetworkService.
    // Completed FEC sets flow from ShredNetworkService to ShredCollector.
    // A direct shred link to ShredCollector is kept for future repair/catch-up paths.
    // The block link carries assembled blocks out of the topology for replay.
    let shred_pipeline_capacity = 2048;
    let fec_completed_capacity = 256;
    let block_pipeline_capacity = 64;
    let (filtered_shred_tx, filtered_shred_rx) = bounded_link::<Shred>(shred_pipeline_capacity);
    let (fec_completed_tx, fec_completed_rx) =
        bounded_link::<CompletedFecSet>(fec_completed_capacity);
    let (direct_shred_tx, direct_shred_rx) = bounded_link::<Shred>(shred_pipeline_capacity);
    let (assembled_block_tx, assembled_block_rx) =
        bounded_link::<AssembledBlock>(block_pipeline_capacity);

    // Channel for shred arrival notifications from the collector to the
    // repair coordinator. The collector sends a ShredArrival for each
    // received data shred so the repair forest can track turbine progress.
    let (shred_arrival_tx, shred_arrival_rx) = crossbeam_channel::bounded::<ShredArrival>(4096);

    let ingress_filter_stats = Arc::new(IngressFilterStats::default());
    let shred_filter_stats = Arc::new(ShredFilterStats::default());
    let block_assembly_stats = Arc::new(BlockAssemblyStats::default());

    let mut services: Vec<Box<dyn Service>> = Vec::new();
    let mut shred_collector_added = false;
    let mut pipeline_inputs: Vec<paradencer_mesh::InPort<RawTransaction>> = Vec::new();
    let mut metrics_http_content: Option<MetricsContent> = None;

    for stage in &topology_spec.stages {
        match stage.stage_kind {
            StageKind::IngressGateway => {
                services.push(Box::new(EdgeIntake::with_policy_and_links(
                    packet_outbound_links.clone(),
                    shred_outbound_links.clone(),
                    ingress_policy.clone(),
                )))
            }
            StageKind::TransactionSanitizer => {
                let packet_inbound = packet_inbound_by_stage
                    .get(&stage.stage_id)
                    .cloned()
                    .expect("packet stream link must exist for transaction sanitizer stage");
                let transaction_outbound = transaction_outbound_by_stage
                    .get(&stage.stage_id)
                    .cloned()
                    .expect("transaction stream outbound link must exist for transaction sanitizer stage");
                let (pipeline_tx, pipeline_rx) =
                    bounded_link::<RawTransaction>(PIPELINE_CHANNEL_DEPTH_PER_WORKER);
                pipeline_inputs.push(pipeline_rx);
                services.push(Box::new(TxFilter::with_policy_pipeline_and_stats(
                    packet_inbound,
                    transaction_outbound,
                    pipeline_tx,
                    ingress_policy.clone(),
                    ingress_filter_stats.clone(),
                )))
            }
            StageKind::ShredSanitizer => {
                let shred_inbound = shred_inbound_by_stage
                    .get(&stage.stage_id)
                    .cloned()
                    .expect("shred stream link must exist for shred sanitizer stage");
                services.push(Box::new(ShredFilter::with_output(
                    shred_inbound,
                    ingress_policy.clone(),
                    shred_filter_stats.clone(),
                    filtered_shred_tx.clone(),
                )));
                // Add network service and collector once (after the first ShredSanitizer).
                if !shred_collector_added {
                    // ShredNetworkService: FEC set tracking + Reed-Solomon recovery.
                    services.push(Box::new(ShredNetworkService::new(
                        ShredNetworkConfig::default(),
                        filtered_shred_rx.clone(),
                        fec_completed_tx.clone(),
                    )));
                    // ShredCollector: accumulates shreds by slot, emits assembled blocks.
                    // Receives completed FEC sets from the network service, plus a
                    // direct shred channel for future repair/catch-up paths.
                    let mut collector = ShredCollector::with_fec_input(
                        direct_shred_rx.clone(),
                        fec_completed_rx.clone(),
                        assembled_block_tx.clone(),
                    );
                    if let Some(ref bs) = blockstore {
                        collector.set_blockstore(Arc::clone(bs));
                    }
                    collector.set_repair_notifier(shred_arrival_tx.clone());
                    services.push(Box::new(collector));
                    shred_collector_added = true;
                }
            }
            StageKind::BlockBuilder => {
                let transaction_inbound = transaction_inbound_by_stage
                    .get(&stage.stage_id)
                    .cloned()
                    .expect("transaction stream inbound links must exist for block builder stage");
                services.push(Box::new(
                    BlockAssembler::with_storage_policy_and_stats_and_inputs(
                        transaction_inbound,
                        storage_runtime_policy.clone(),
                        block_assembly_stats.clone(),
                    )?,
                ))
            }
            StageKind::Telemetry => {
                let mut reporter = MetricsReporter::with_output_format_and_stats(
                    LinkTelemetryStats {
                        packet_link_stats: packet_stats.clone(),
                        shred_link_stats: shred_stats.clone(),
                        transaction_link_stats: transaction_stats.clone(),
                    },
                    metrics_output_format,
                    metrics_output_target.clone(),
                    StageTelemetryStats {
                        ingress_filter_stats: ingress_filter_stats.clone(),
                        shred_filter_stats: shred_filter_stats.clone(),
                        block_assembly_stats: block_assembly_stats.clone(),
                    },
                );
                // When Http target is selected, create a shared buffer so
                // MetricsReporter writes Prometheus text into it on each tick
                // and MetricsHttpServer can serve it to scrapers.
                if matches!(metrics_output_target, MetricsOutputTarget::Http) {
                    let content = shared_metrics_content();
                    reporter = reporter.with_http_content(content.clone());
                    metrics_http_content = Some(content);
                }
                services.push(Box::new(reporter))
            }
            // Signature verification and blockhash resolution stages
            // process transactions before they reach the pack scheduler.
            // They are configured during node bootstrap with the
            // appropriate channel endpoints.
            StageKind::SignatureVerifier | StageKind::BlockhashResolver => {}
            // Replay engine processes assembled blocks through consensus.
            // Requires consensus infrastructure (BankForks, Tower, etc.)
            // which is configured separately during node bootstrap.
            StageKind::ReplayEngine => {}
            // Network and QUIC tiles run dedicated poll loops outside
            // the Service-based runtime. They are launched separately.
            StageKind::NetworkTile | StageKind::QuicTile => {}
        }
    }

    Ok(MaterializedTopology {
        topology_spec,
        services,
        shred_block_receiver: if shred_collector_added {
            Some(assembled_block_rx)
        } else {
            None
        },
        pipeline_inputs,
        direct_shred_sender: if shred_collector_added {
            Some(direct_shred_tx)
        } else {
            None
        },
        shred_arrival_receiver: if shred_collector_added {
            Some(shred_arrival_rx)
        } else {
            None
        },
        metrics_http_content,
    })
}
