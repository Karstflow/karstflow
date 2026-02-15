use crate::errors::Result;
use crate::topology_parts::types::MaterializedTopology;
use crate::topology_parts::validation::{find_link_capacity, validate_topology_requirements};
use paradencer_core::{LinkKind, StageKind, TopologySpec};
use paradencer_ingress::IngressPolicy;
use paradencer_mesh::bounded_link;
use paradencer_runtime::Service;
use paradencer_stages::{
    BlockAssembler, BlockAssemblyStats, EdgeIntake, InboundPacket, IngressFilterStats,
    LinkTelemetryStats, MetricsOutputFormat, MetricsOutputTarget, MetricsReporter,
    SanitizedTransaction, ShredFilter, ShredFilterStats, StageTelemetryStats, StorageRuntimePolicy,
    TxFilter,
};
use std::collections::HashMap;
use std::sync::Arc;

pub fn materialize_services(
    topology_spec: TopologySpec,
    ingress_policy: IngressPolicy,
    metrics_output_format: MetricsOutputFormat,
    metrics_output_target: MetricsOutputTarget,
    storage_runtime_policy: StorageRuntimePolicy,
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
    let ingress_filter_stats = Arc::new(IngressFilterStats::default());
    let shred_filter_stats = Arc::new(ShredFilterStats::default());
    let block_assembly_stats = Arc::new(BlockAssemblyStats::default());

    let mut services: Vec<Box<dyn Service>> = Vec::new();

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
                services.push(Box::new(TxFilter::with_policy_and_stats(
                    packet_inbound,
                    transaction_outbound,
                    ingress_policy.clone(),
                    ingress_filter_stats.clone(),
                )))
            }
            StageKind::ShredSanitizer => {
                let shred_inbound = shred_inbound_by_stage
                    .get(&stage.stage_id)
                    .cloned()
                    .expect("shred stream link must exist for shred sanitizer stage");
                services.push(Box::new(ShredFilter::with_policy_and_stats(
                    shred_inbound,
                    ingress_policy.clone(),
                    shred_filter_stats.clone(),
                )))
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
                services.push(Box::new(MetricsReporter::with_output_format_and_stats(
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
                )))
            }
        }
    }

    Ok(MaterializedTopology {
        topology_spec,
        services,
    })
}
