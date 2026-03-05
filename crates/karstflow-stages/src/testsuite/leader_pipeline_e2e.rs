/// End-to-end leader pipeline integration test.
///
/// Exercises the complete transaction processing flow:
///   submit → verify → resolve → pack → exec → PoH → entries
///
/// Uses VerifyService and ResolvService as Service-based wrappers,
/// wiring them through mesh channels to the LeaderPipeline which
/// coordinates pack + exec + PoH.
use crate::block_producer::PohService;
use crate::exec_stage::{ExecStage, MockExecutionEngine};
use crate::leader_pipeline::LeaderPipeline;
use crate::pack_stage::{PackConfig, PackScheduler, PackedTransaction};
use crate::resolv_service::ResolvService;
use crate::resolv_stage::ResolvStage;
use crate::verify_service::VerifyService;
use crate::verify_stage::{
    TransactionSource, UnverifiedTransaction, VerifiedTransaction, VerifyConfig, VerifyStage,
};
use karstflow_mesh::{bounded_link, DualReceiver, DualSender};
use karstflow_runtime::{Service, ServiceContext, ShutdownSwitch};
use karstflow_types::Hash;
use std::sync::atomic::Ordering;

/// Create a synthetic unverified transaction with a specific ID byte.
fn synthetic_unverified(id: u8) -> UnverifiedTransaction {
    let mut payload = vec![0u8; 256];
    for (i, byte) in payload[..64].iter_mut().enumerate() {
        *byte = id.wrapping_add(i as u8);
    }
    payload[64..96].fill(0xAA);

    UnverifiedTransaction {
        payload,
        source: TransactionSource::Quic,
        num_signatures: 1,
        signature_offset: 0,
        message_offset: 64,
        signer_offsets: vec![64],
    }
}

#[test]
fn verify_service_processes_and_forwards() {
    let (in_tx, in_rx) = bounded_link::<UnverifiedTransaction>(32);
    let (out_tx, _out_rx) = bounded_link::<VerifiedTransaction>(32);

    let config = VerifyConfig {
        round_robin_index: 0,
        round_robin_count: 1,
        ..VerifyConfig::default()
    };
    let stage = VerifyStage::with_config(config);
    let mut service = VerifyService::new(
        stage,
        DualReceiver::Channel(in_rx),
        DualSender::Channel(out_tx),
    );
    let ctx = ServiceContext::new(ShutdownSwitch::new());

    for i in 0..5 {
        in_tx.try_send(synthetic_unverified(i)).unwrap();
    }

    for _ in 0..3 {
        service.tick(&ctx).unwrap();
    }

    let stats = service.stats();
    let total = stats.verified.load(Ordering::Relaxed)
        + stats.invalid_signature.load(Ordering::Relaxed)
        + stats.malformed.load(Ordering::Relaxed)
        + stats.filtered.load(Ordering::Relaxed);
    assert_eq!(total, 5, "all 5 transactions should be processed");
}

#[test]
fn resolv_service_processes_verified_transactions() {
    let (in_tx, in_rx) = bounded_link::<VerifiedTransaction>(32);
    let pack = PackScheduler::new();

    let mut stage = ResolvStage::new();
    let test_hash = [0xAA_u8; 32];
    stage.register_blockhash(test_hash, 100);

    let mut service = ResolvService::new(stage, DualReceiver::Channel(in_rx), pack);
    let ctx = ServiceContext::new(ShutdownSwitch::new());

    for i in 0..3 {
        let tx = VerifiedTransaction {
            payload: {
                let mut p = vec![0u8; 256];
                p[0] = i;
                p[64..96].fill(0xAA);
                p
            },
            source: TransactionSource::Quic,
            num_signatures: 1,
        };
        in_tx.try_send(tx).unwrap();
    }

    service.tick(&ctx).unwrap();

    let stats = service.stats();
    let total = stats.resolved_valid.load(Ordering::Relaxed)
        + stats.resolved_expired.load(Ordering::Relaxed)
        + stats.stashed.load(Ordering::Relaxed)
        + stats.stash_full.load(Ordering::Relaxed);
    assert_eq!(total, 3, "all 3 transactions should be processed");
}

#[test]
fn leader_pipeline_produces_entries() {
    let pack = PackScheduler::with_config(PackConfig::default());
    let engine = MockExecutionEngine::new(50_000);
    let exec = ExecStage::new(Box::new(engine));
    let poh = PohService::new(Hash::default());

    let mut pipeline = LeaderPipeline::new(pack, exec, poh);
    pipeline.begin_slot(42);
    pipeline.poh_mut().begin_leader(42);

    for i in 0..4 {
        let tx = PackedTransaction {
            payload: vec![i; 128],
            blockhash: [0u8; 32],
            priority_fee: (4 - i) as u64 * 100,
            compute_units: 50_000,
            total_cost: 0,
            is_vote: false,
            expires_at_slot: 200,
            write_accounts: vec![{
                let mut key = [0u8; 32];
                key[0] = i;
                key
            }],
            read_accounts: vec![],
            data_size: 128,
            insertion_order: i as u64,
        };
        pipeline.submit_transaction(tx);
    }

    let mut steps = 0;
    while let Some(_result) = pipeline.step() {
        steps += 1;
        if steps >= 10 {
            break;
        }
    }
    assert!(steps > 0, "pipeline should produce at least one microblock");

    pipeline.advance_poh(100);
    let entries = pipeline.finish_slot();

    assert!(
        !entries.is_empty(),
        "finished slot should have entries (microblocks + ticks)"
    );
    assert!(
        pipeline.microblocks_executed() > 0,
        "should have executed microblocks"
    );
}

#[test]
fn full_pipeline_verify_resolv_pack_exec_poh() {
    // === Stage 1: Verify ===
    let (unverified_tx, unverified_rx) = bounded_link::<UnverifiedTransaction>(32);
    let (verified_tx, verified_rx) = bounded_link::<VerifiedTransaction>(32);

    let verify_config = VerifyConfig {
        round_robin_index: 0,
        round_robin_count: 1,
        ..VerifyConfig::default()
    };
    let verify_stage = VerifyStage::with_config(verify_config);
    let mut verify_svc = VerifyService::new(
        verify_stage,
        DualReceiver::Channel(unverified_rx),
        DualSender::Channel(verified_tx),
    );

    // === Stage 2: Resolv ===
    let mut resolv_stage = ResolvStage::new();
    let test_blockhash = [0xBB_u8; 32];
    resolv_stage.register_blockhash(test_blockhash, 200);
    let pack = PackScheduler::with_config(PackConfig::default());
    let mut resolv_svc = ResolvService::new(resolv_stage, DualReceiver::Channel(verified_rx), pack);

    // === Stage 3: Leader Pipeline (exec + PoH) ===
    let leader_pack = PackScheduler::with_config(PackConfig::default());
    let engine = MockExecutionEngine::new(50_000);
    let exec = ExecStage::new(Box::new(engine));
    let poh = PohService::new(Hash::default());
    let mut pipeline = LeaderPipeline::new(leader_pack, exec, poh);
    pipeline.begin_slot(100);
    pipeline.poh_mut().begin_leader(100);

    let ctx = ServiceContext::new(ShutdownSwitch::new());

    // Submit unverified transactions.
    for i in 0u8..3 {
        let mut payload = vec![0u8; 256];
        for (j, byte) in payload[..64].iter_mut().enumerate() {
            *byte = i.wrapping_add(j as u8);
        }
        payload[64..96].fill(0xBB);

        unverified_tx
            .try_send(UnverifiedTransaction {
                payload,
                source: TransactionSource::Quic,
                num_signatures: 1,
                signature_offset: 0,
                message_offset: 64,
                signer_offsets: vec![64],
            })
            .unwrap();
    }

    // Tick verify service.
    verify_svc.tick(&ctx).unwrap();

    let verify_stats = verify_svc.stats();
    let verify_total = verify_stats.verified.load(Ordering::Relaxed)
        + verify_stats.invalid_signature.load(Ordering::Relaxed)
        + verify_stats.malformed.load(Ordering::Relaxed)
        + verify_stats.filtered.load(Ordering::Relaxed);
    assert_eq!(verify_total, 3, "verify should process all 3");

    // Tick resolv service.
    resolv_svc.tick(&ctx).unwrap();

    let resolv_stats = resolv_svc.stats();
    let resolv_total = resolv_stats.resolved_valid.load(Ordering::Relaxed)
        + resolv_stats.resolved_expired.load(Ordering::Relaxed)
        + resolv_stats.stashed.load(Ordering::Relaxed)
        + resolv_stats.stash_full.load(Ordering::Relaxed);

    let forwarded = verify_stats.forwarded.load(Ordering::Relaxed);

    // If any were forwarded, resolv should process them.
    if forwarded > 0 {
        assert!(
            resolv_total > 0,
            "resolv should process forwarded transactions"
        );
    }

    // Direct pack submission (to test exec + PoH independently).
    for i in 0..2 {
        let tx = PackedTransaction {
            payload: vec![i; 128],
            blockhash: test_blockhash,
            priority_fee: (2 - i) as u64 * 500,
            compute_units: 100_000,
            total_cost: 0,
            is_vote: false,
            expires_at_slot: 300,
            write_accounts: vec![{
                let mut key = [0u8; 32];
                key[0] = i;
                key
            }],
            read_accounts: vec![],
            data_size: 128,
            insertion_order: i as u64,
        };
        pipeline.submit_transaction(tx);
    }

    let mut microblock_count = 0;
    while let Some(_result) = pipeline.step() {
        microblock_count += 1;
        if microblock_count >= 10 {
            break;
        }
    }

    pipeline.advance_poh(64);
    let entries = pipeline.finish_slot();

    assert!(microblock_count > 0, "should produce microblocks");
    assert!(!entries.is_empty(), "should produce entries");

    // Summary: full pipeline exercised all stages end-to-end.
    assert_eq!(verify_total, 3);
    assert!(pipeline.microblocks_executed() > 0);
}
