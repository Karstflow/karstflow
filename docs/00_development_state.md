# Paradencer Development State

Last update: 2026-02-19

Primary residual tracker:
- `docs/04_module_residual_matrix.md` (module-by-module remaining work and priorities)
- `docs/04_module_residual_matrix.md` -> `Firedancer Logic Weight And Migration Table` (weight-based parity tracking table)

## Rough Migration Progress
- Paradencer total lines: **160,000** (20 crates, 3,088 tests)
- Firedancer total lines (native only, no Frankendancer): **~623,600** (C+H across 13 subsystems)
- Paradencer framework completion: **~100%**
- Firedancer logic parity (estimated): **~63%** (weighted by functional importance)
- Confidence level:
  - framework completion: high
  - firedancer parity: medium-high (measured via deep line-by-line subsystem comparison 2026-02-17)
- Firedancer parity estimation basis:
  - Sysvars: ~90% (all 14 sysvars, SysvarCache, per-slot/per-epoch updates)
  - Builtin Programs: ~82% (all 12+ programs, 96+ instructions, 32+ tests per program)
  - Rewards & Stakes: ~80% (inflation, partitioned distribution, 18 stake handlers)
  - Runtime Core: ~75% (bank, executor, epoch processing, cost tracker, tx cache)
  - Consensus: ~70% (tower BFT, GHOST fork choice, equivocation detection, commitment)
  - VM + Syscalls: ~85% (interpreter, CPI/crypto/PDA/curve/hash syscalls, SBPF versions, memory model, abort/panic, BLS12-381 stubs)
  - Types: ~55% (core types done, many inline, not all generated types)
  - Crypto: ~50% (ed25519 batch, blake3, sha256, keccak, secp, bn254, reed-solomon, lthash; missing BLS)
  - Network Stack: ~35% (custom paradencer-net: packet types, I/O traits, UDP socket, TLS crypto, QUIC key derivation; plus quinn ingress, gossip/repair basic)
  - Tile Pipeline: ~32% (replay stage, block production, shred assembly, PoH 6-state machine with dynamic hashing; pack/net/metrics gaps)
  - Storage: ~67% (MVCC accounts, blockstore, snapshots, DurableStore persistent backend, StorageEngine facade, snapshot manifest parser + serializer, status cache parser, disk persistence + recovery, blockstore persistence, compaction, full snapshot bootstrap: lthash/stakes/history/sysvars/features/txcache, genesis bootstrap, bank hash verification, SHA-256 accounts hash, incremental dirty-set tracking, incremental snapshot creation, snapshot loader DB integration, AppendVec writer, Solana-compatible archive builder + creator with full roundtrip, bank state manifest serializer, AccountsDbFields serializer, incremental Solana-compatible archives, snapshot scheduler)
  - App/Config/IPC: ~25% (config done, control plane basic, no tango/shared-memory IPC)
- Update policy:
  - revise both percentages after each substantial subsystem move
  - keep firedancer parity estimate intentionally conservative
  - deep re-analysis performed 2026-02-17 comparing all Firedancer C modules against Paradencer crates
  - updated 2026-02-18: storage 50%→60% (cycles 15-19), overall 60%→62%
  - updated 2026-02-18: storage 64%→67% (cycles 25-27: manifest serializer, incremental Solana archives, AccountsDbFields), overall 63%→64%
  - updated 2026-02-18: network 30%→35% (net cycles 0-5: paradencer-net crate, packets, I/O, UDP socket, TLS crypto, QUIC key derivation, 91 tests)
  - updated 2026-02-19: VM+Syscalls 80%→85% (4 missing syscalls: abort, panic, BLS12-381 decompress/pairing), storage metrics + auto-compaction
  - updated 2026-02-19: Tile Pipeline 30%→32% (PoH 6-state machine, dynamic hashes_per_tick, low-power mode, bank/slot coordination)

## Firedancer Module Comparison (deep analysis 2026-02-17, updated 2026-02-18)

| Area | FD lines (C+H) | PD lines | Transfer | Status |
|---|---|---|---|---|
| **Sysvars** (14 types, cache, lifecycle) | ~1,900 | ~3,000 | **90%** | Done |
| **Builtin Programs** (12+, 96+ instructions) | ~16,100 | ~20,000 | **82%** | High |
| **Rewards & Stakes** (inflation, distribution) | ~2,500 | ~5,000 | **80%** | High |
| **Runtime Core** (bank, executor, epoch) | ~8,400 | ~15,000 | **75%** | Critical |
| **VM + Syscalls** (interp, CPI, crypto) | ~7,900 | ~10,300 | **85%** | High |
| **Consensus** (tower, fork, equivocation) | ~7,900 | ~8,000 | **70%** | High |
| **Types** (bincode serialization) | ~10,100 | ~3,000 | **55%** | High |
| **Crypto** (ed25519, blake3, bn254...) | ~30,000 | ~5,000 | **50%** | Medium |
| **Storage** (accdb, funk, vinyl, snapshots) | ~25,500 | ~16,300 | **60%** | Critical |
| **Tile Pipeline** (replay, pack, shred) | ~125,600 | ~44,300 | **40%** | Critical |
| **Network Stack** (QUIC, TLS, HTTP) | ~56,300 | ~14,000 | **35%** | High |
| **App/Config/IPC** (config, tango, util) | ~145,000 | ~9,500 | **25%** | Medium |

**Weighted overall estimate: ~62%** (by importance for working validator)

### Firedancer Module Breakdown (native only, excluding discoh)

| FD Module | Lines C+H | % of total | Purpose | PD Mapping | Transfer |
|---|---|---|---|---|---|
| **ballet** | 150,419 | 24.1% | Crypto, serialization, parsing | crypto + Rust crates | **~50%** |
| **flamenco** | 114,117 | 18.3% | Runtime, VM, types, accounts, programs | consensus + sbpf + types | **~70%** |
| **util** | 105,836 | 17.0% | Utilities, data structures, allocators | Rust stdlib + crates | **~25%** |
| **disco** | 69,950 | 11.2% | Shared tile infrastructure (pack, shred, net) | stages + ingress | **~30%** |
| **waltz** | 56,301 | 9.0% | Network stack (QUIC, TLS, HTTP, gRPC) | paradencer-net + quinn/hyper | **~35%** |
| **discof** | 55,608 | 8.9% | Native tiles (replay, restore, repair, PoH) | stages + storage | **~25%** |
| **app** | 30,457 | 4.9% | CLI, config, orchestration | config + control + node | **~35%** |
| **vinyl** | 17,301 | 2.8% | Persistent storage | DurableStore + FileDurableStore | **~40%** |
| **tango** | 8,650 | 1.4% | IPC / lock-free queues | mesh (218 lines) | **~10%** |
| **choreo** | 7,860 | 1.3% | Tower BFT, fork choice, equivocation | consensus | **~70%** |
| **funk** | 3,762 | 0.6% | KV account store | storage/accounts | **~60%** |
| **groove** | 3,340 | 0.5% | Slab allocator | Rust alloc/jemalloc | **~20%** |
| **Total** | **~623,600** | **100%** | | | |

Key observations:
1. **ballet** (150K) — 70K is tables/codegen (reedsol, fiat-crypto). Rust uses ready crates.
2. **util** (106K) — largely replaced by Rust stdlib and ecosystem.
3. **waltz** (56K) — custom QUIC/TLS/HTTP. In Rust — quinn/rustls/hyper.
4. **discof/restore** (21K) — largest single gap. Snapshot restore critical for startup.
5. **disco/pack** (12K) — transaction scheduler. Partially in paradencer-consensus/pack.
6. All **flamenco** — pure native Firedancer, zero Agave dependencies.

## Project Goal
- Rewrite Firedancer full-client logic in Rust.
- Preserve behavior/invariants, not source naming.
- Exclude Frankendancer/Agave bridge path.
- Support two execution modes with same stage logic:
  - `tokio`
  - `pinned`

## Engineering Priorities (Locked)
1. Logic parity first:
- В каждом крупном шаге приоритет №1 — перенос и сохранение поведенческой логики Firedancer (инварианты/семантика), а не косметический рефакторинг.
2. Performance by default:
- Любая новая подсистема проектируется с упором на throughput/latency, предсказуемое использование памяти и отсутствие лишних копий/аллокаций.
3. Senior-grade maintainability:
- Код должен оставаться поддерживаемым командой senior-разработчиков: явные границы модулей, typed errors, тестируемые контракты, минимум "скрытой магии" и временных костылей.

## Current Snapshot
- Workspace and crate layout established.
- Runtime substrate implemented with lifecycle hooks:
  - `on_start`
  - `tick`
  - `on_stop`
- Message mesh implemented with bounded channels and counters.
- Initial 3-stage pipeline wired:
  - intake -> filter -> assembler
- Ingress logic split into dedicated crate with decode + dedup window.
- Ingress policy layer added: source classification, payload limits, drop rules.
- Node config now wires ingress policy from env into stage materialization.
- Ingress policy now supports TOML profile + env override merge.
- Added unified node root config (`runtime/topology/ingress_policy`) with env override precedence.
- Added pinned-core policy profiles (`strict/shared/adaptive`) in runtime scheduler checks.
- Added metrics output format abstraction (`json_lines` / `prometheus_text`) with config/env wiring.
- Added ingress filter counters by decision reason and exported them in metrics output.
- Added config schema-version checks for node/ingress TOML profiles.
- Added metrics sink targets (`stdout` / `file`) configurable from node config and env.
- Added execution bridge crate and wired block fragments through deterministic execution outcomes.
- Added replay/fork-choice boundary directives in execution bridge.
- Expanded ingress counters with source-specific metrics labels.
- Added schema migration hooks for legacy config version `0 -> 1`.
- Added UDP socket metrics sink target for exporter bridge integration.
- Added execution scheduler/leader-gating directives.
- Replaced `anyhow` in library crates with typed `thiserror` errors and dedicated `errors.rs` modules.
- Added storage/snapshot skeleton crate and wired commit/snapshot hooks in block assembler.
- Added HTTP metrics bridge in node (`/metrics`) backed by file sink snapshots.
- Added ingress config migration tests for legacy and unknown schema versions.
- Added execution retry directive placeholder and integrated it into stage execution flow.
- Added snapshot ingest/restore interfaces in storage and wired restore/write hooks in stage path.
- Added storage startup policy wiring (`node config -> topology -> block assembler`) with TOML/env controls.
- Added metrics sink tests for `file` and `udp` targets, including file-open failure path.
- Added typed execution errors and fallible execution path (`try_execute_batch`) in execution/stage integration.
- Added snapshot catalog file persistence (`persist/load`) with schema-version validation and restart tests.
- Wired snapshot catalog persistence into stage runtime policy (`storage.catalog_path`) with startup load support.
- Startup restore now initializes block assembly/replay counters from restored snapshot state.
- Execution bridge now models deterministic failure classes with class-aware retry and scheduler priority.
- Block assembler now applies retry directives with deferred retries, bounded retry budget, and drop semantics.
- Refactored execution crate into submodules (`types`, `bridge`, `errors`) to keep `lib.rs` as a facade.
- Started modularization of stages crate by extracting shared stage domain/policy types into `stages::types`.
- Split stage service implementations into dedicated modules (`edge_intake`, `tx_filter`, `block_assembler`) to keep `stages/lib.rs` focused as a facade/composition layer.
- Completed stage service modularization by extracting `metrics_reporter` into its own module.
- Added block-assembly retry telemetry counters and exported them via metrics output.
- Added snapshot catalog schema migration support/tests for legacy v0 persisted formats.
- Split node config implementation into dedicated internal module (`config_parts`) and kept `config.rs` as facade + tests.
- Split storage crate internals into dedicated modules (`types`, `hot_state`, `catalog`) and kept `storage/lib.rs` as facade + tests.
- Moved stages unit/integration-like tests from `stages/lib.rs` into dedicated module file (`stages/testsuite.rs`) to keep core library file focused.
- Split node topology implementation into dedicated internal module (`topology_parts`) and kept `topology.rs` as facade + tests.
- Added block-assembly leader-gate and fork-choice telemetry counters and exported them through metrics formats.
- Added configurable retry runtime policy knobs (`max_retry_attempts`, `retry_backoff_cap_millis`) with TOML/env wiring and validation.
- Added configurable scheduler runtime policy knobs and applied scheduler directive to retry backoff timing in block assembler.
- Refined replay boundary semantics: only replay-conflict/deterministic failures trigger `ConsiderReorg`.
- Added configurable fork-choice runtime policy and applied reorg hold/drop handling in block assembler.
- Expanded ingress dataplane with per-source throttling (`min_gap_ticks`) and rate-limit drop classification.
- Expanded ingress dataplane with per-source token-bucket burst controls (capacity + refill ticks).
- Expanded ingress dataplane with per-source cost-budget windows (cost units per time window).
- Added block assembly policy controls (tx-count cap, cost-unit cap, wait-ticks cap) to trigger fragment sealing.
- Added tx-filter downstream backpressure retry buffer with bounded wait/drop behavior and metrics.
- Added policy-driven synthetic ingress generation in edge intake (weighted source mix + batch/idle cadence + payload size).
- Added execution-health runtime policy (transient failure threshold + cooldown ticks) with stage enforcement and config/env wiring.
- Added execution-health metrics export (cooldown entries + cooldown skipped ticks) in block-assembly telemetry.
- Added replay-safety runtime policy (replay-conflict threshold + hold ticks) with stage enforcement and config/env wiring.
- Added replay-safety metrics export (hold entries + hold skipped ticks) in block-assembly telemetry.
- Added fork-choice quarantine runtime policy (consecutive reorg threshold + quarantine ticks) with stage enforcement and config/env wiring.
- Added fork-choice quarantine metrics export (quarantine entries + quarantine skipped ticks) in block-assembly telemetry.
- Added ingress intake mode switch (`synthetic`/`udp`) with nonblocking UDP socket ingestion path in `EdgeIntake`.
- Added ingress UDP config wiring (`ingress_mode`, `udp_bind_address`, source-port mapping) via TOML and env overrides.
- Added live/dev cluster preflight guardrails in node config (`PARADENCER_CLUSTER_MODE`) with live-mode checks for UDP ingress mode, identity path presence, expected genesis hash/shred version, non-stdout metrics target, and non-default topology name.
- Added live-network safety preflight checks for routability/cluster consistency: validated `PARADENCER_LIVE_ENTRYPOINTS` parsing + non-loopback/non-unspecified entrypoints, validated live UDP bind routability, and enforced strict genesis-hash format + positive shred version in live mode.
- Added node runtime startup network-socket preflight in live mode: early ingress UDP bind probe and UDP probe connect/send checks for configured live entrypoints before service startup.
- Added explicit node command surface (`run`, `preflight`, `version`) with dedicated preflight-only execution path and command parser tests.
- Hardened JSON-RPC request conformance in `paradencer-rpc`: non-array `params` are now rejected with `-32602` (Invalid params) both in legacy renderer path and jsonrpsee HTTP dispatch path (instead of silent fallback to empty params).
- Hardened JSON-RPC envelope conformance in `paradencer-rpc`: non-object requests, non-`2.0` protocol version, and non-string `method` are now rejected with `-32600` (Invalid request).
- Moved synthetic transaction-RPC tuning numbers from `paradencer-rpc` method code into centralized `paradencer-constants::rpc` constants (send/simulate cost and signature-shaping knobs).
- Hardened runtime-like execution/storage invariant for empty fragments: empty batches now use `RuntimeStateWriteIntent::None` and skip runtime-effects apply/rollback path, preventing unintended runtime-state advancement on zero-transaction ticks.
- Hardened runtime-like failure-signal invariant: `failed_transactions` is now clamped to batch size before forming `ExecutionOutcome`, preventing adapter overreporting from producing invalid outcome semantics.
- Hardened execution-bridge boundary invariants for pluggable engines: bridge now normalizes returned outcomes (forces batch fragment id, clamps `failed_transactions` to batch size, and recomputes `executed_transactions`) before stage consumption.
- Added explicit runtime-adapter contract error (`AdapterContractViolation`) and runtime-like preflight intent validation (`RuntimeStateWriteIntent` must be batch-consistent), preventing silent execution of inconsistent adapter contracts.
- Classified `AdapterContractViolation` at bridge boundary as deterministic failure and exported dedicated stage telemetry counter (`execution_error_adapter_contract_violation`).
- Hardened runtime-like apply-report contract validation: engine now validates adapter `RuntimeApplyReport` consistency (aggregate/channel coherence, target overrun protection, strict policy exactness) and rejects violations via `AdapterContractViolation`.
- Hardened rollback safety on post-apply validation failures: when `RuntimeApplyReport` contract validation fails after successful apply, runtime-like engine now triggers rollback (when rollback is required) before surfacing the contract violation.
- Expanded stage-runtime coverage for adapter contract violations: block-assembler fail-open path now asserts dedicated runtime telemetry counter (`execution_error_adapter_contract_violation`) in addition to deterministic-drop behavior.
- Hardened storage counter integrity: replaced saturating counter updates with checked overflow validation in `HotStateStore` and `RuntimeStateStore` (`StorageError::StateCounterOverflow`) with dedicated overflow tests, preventing silent state corruption under counter wrap conditions.
- Hardened storage apply atomicity on overflow paths: `HotStateStore::apply_committed_fragment` and `RuntimeStateStore::apply_effects` now compute next counters first and only commit state after all checked-add validations pass, preventing partial state mutation on overflow errors.
- Fixed runtime-like/storage rollback handshake for post-apply validation failures: `StorageBackedRuntimeAdapter` now retains pending apply receipts long enough for rollback-on-validation-failure and prunes stale receipts when newer fragments begin apply, preserving rollback correctness without unbounded receipt growth.
- Hardened runtime-like observation contract validation: engine now rejects adapter observations where `consumed_compute_units` exceeds preflight compute budget, surfacing deterministic contract violations before effects application.
- Added runtime-like contention-range contract validation: adapter-reported `write_lock_contention_ratio_bps` is now strictly bounded to `[0, 10_000]`, rejecting out-of-range observations as contract violations.
- Added runtime-like failed-count contract validation: adapter observations now must satisfy `failed_transactions <= batch.transaction_count`; overreporting is rejected as `AdapterContractViolation` (instead of silent clamping).
- Added runtime-like failure attribution invariants: observations with `failed_transactions > 0` now require a non-empty `failure_class`, and transactional failure classes (`deterministic/transient/resource`) are rejected when `failed_transactions == 0`.
- Hardened bridge-level engine outcome normalization: `ExecutionBridge` now repairs impossible failure-class combinations from custom engines (`failed > 0 && class == None` -> deterministic class, `failed == 0 && transactional class` -> `None`) before retry/fork-choice evaluation.
- Added runtime-like effects-summary contract validation before apply phase: account/program-cache effect summaries are now rejected on internal contradictions (`rent_epoch_updates > written_accounts`, data/rent updates with zero writes, or program-cache invalidations without preflight refresh intent).
- Added runtime-like effects-plan contract validation before apply phase: prepared plan targets must stay within summarized effects, strict apply policies require full target coverage, and commit-candidate plans must enforce rollback-on-error.
- Added runtime-like preflight/effects identity contracts: non-empty batches now require non-zero preflight cost budget (empty batches require zero), and `RuntimeEffectsPlan.effects` must exactly match the adapter-provided effects summary.
- Hardened storage-backed adapter boundary: `StorageBackedRuntimeAdapter::apply_effects` now validates strict plan/effects coverage and target bounds before touching runtime-state store, rejecting malformed plans as `AdapterContractViolation`.
- Hardened execution-bridge cost-budget invariant for pluggable engines: non-empty batches now normalize zero `total_cost_units` from custom engines to batch-estimated cost budget before downstream retry/fork-choice handling.
- Hardened execution/runtime arithmetic safety for program-cache aggregates: runtime adapter, storage-backed adapter, and runtime-like apply-report validation now use checked aggregation for `applied_program_cache_ops` and surface overflow as `AdapterContractViolation` (no silent wrap).
- Hardened storage-backed apply ordering: adapter now rejects out-of-order `apply_effects` attempts when a newer fragment receipt is already pending, enforcing monotonic apply progression before rollback/pruning.
- Unified bridge cost-budget normalization across success/error paths: `execute_batch_with_error` now applies the same non-empty budget floor (`max(estimated, 1)`) as successful outcome normalization, while keeping empty-batch budget at `0`.
- Hardened storage-backed preflight contract at adapter boundary: `apply_effects` now requires commit-candidate preflight intent with matching fragment id and requires rollback-on-error plan semantics before runtime-state store writes.
- Hardened storage-backed rollback contract at adapter boundary: `rollback_effects` now enforces matching commit-candidate preflight intent and rollback-required plan semantics, preventing out-of-contract rollback calls from consuming pending receipts.
- Enforced empty-batch no-write/no-rollback invariants at storage adapter boundary: direct `apply_effects`/`rollback_effects` calls with `transaction_count == 0` are now rejected as contract violations.
- Enforced non-empty preflight budget guard at storage adapter boundary: direct `apply_effects`/`rollback_effects` calls for non-empty batches now require `preflight.total_cost_units > 0`, otherwise fail with `AdapterContractViolation`.
- Added explicit fragment-mismatch contract coverage for storage adapter boundaries: direct `apply`/`rollback` now have regression tests for mismatched commit-candidate fragment id, including rollback receipt-retention guarantee after reject.
- Added storage-adapter effects-consistency guardrails at direct boundary calls: apply/rollback now reject effects with account-write inconsistencies and program invalidations without refresh intent, with rollback receipt-retention coverage after contract rejection.
- Hardened runtime-like batch-context construction: replaced silent saturating context sizing with checked arithmetic and explicit contract rejection on overflow (`transaction_count` too large), preventing hidden context distortion.
- Hardened runtime-like failure-scaling arithmetic: replaced direct `transaction_count * 3` ratio path with overflow-safe scaled helper for large `usize` inputs and added regression coverage for large-value scaling behavior.
- Hardened storage-backed policy-boundary contract: direct `apply_effects` now rejects plan apply-policy mismatches against adapter-configured channel policies, preventing out-of-band lenient/strict policy bypass.
- Extended storage-backed policy-boundary contract to rollback path: direct `rollback_effects` now also enforces plan policy match with adapter configuration, with receipt-retention regression coverage after contract rejection.
- Hardened transaction-count cost arithmetic for cross-platform correctness: replaced `as u64` transaction-count conversions in heuristic/runtime-like cost paths with checked conversion (`u64::try_from`) and moved average-cost division to `u128` arithmetic to avoid silent truncation semantics.
- Hardened replay-boundary accounting conversion: replaced direct `executed_transactions as u64` cast with safe conversion + saturating accumulation and added regression coverage for near-`u64::MAX` totals.
- Added shared execution numeric conversion module (`paradencer-execution::numeric`) and rewired `heuristic`/`runtime_adapter`/`runtime_like`/`bridge` to use one saturating conversion surface instead of duplicated local helpers.
- Added numeric conversion regression tests (`usize/u128` saturating boundaries) and removed remaining direct `as u128` scaling cast from runtime-like ratio path.
- Extended storage runtime-state model with receipt-history-backed rewind API (`RuntimeStateStore::rewind_to_fragment`) for controlled multi-step rollback to target fragment ids.
- Hardened runtime-state rollback contract with strict receipt payload matching against the latest applied receipt (`RuntimeStateReceiptMismatch`) before rollback mutation.
- Added runtime-state rewind/error-path coverage (multi-step rewind, rewind-to-zero, target-ahead rejection, mismatched rollback receipt payload rejection).
- Added execution-state control surface in execution bridge (`ExecutionStateController`) with optional bridge wiring (`with_engine_retry_policy_and_state_controller`) and rewind API (`rewind_execution_state_to_fragment`).
- Implemented execution-state rewind control for storage-backed runtime adapter and hooked it into block-assembler confirmed-reorg rewind path, so replay-window checkpoint rewind now rewinds runtime execution state together with hot-state/replay counters.
- Added execution-bridge rewind tests (no-controller no-op, successful controller call, error propagation) and re-verified affected suites.
- Added storage-backed adapter rewind tests for state/pruned-receipt behavior and ahead-target error mapping (`ExecutionStateController::rewind_to_fragment` contract coverage).
- Added stage-level confirmed-reorg rewind failure coverage: block assembler now has regression test proving execution-state rewind failure is surfaced as runtime error (no silent continue).
- Added dedicated block-assembly telemetry for confirmed-reorg execution-state rewind failures (`execution_state_rewind_failures_total`) and exported it via metrics reporter.
- Hardened confirmed-reorg rewind failure path: block assembler now records typed execution error telemetry (`AdapterRollbackFailure`) before returning runtime error.
- Hardened replay-window checkpoint consistency on confirmed reorg: `BankTimeline::maybe_rewind_on_confirmed_reorg` now prunes future checkpoints above the selected checkpoint (no stale post-rewind tail).
- Synced replay-window depth gauge after confirmed reorg rewind by updating `replay_window_checkpoint_depth` from pruned bank timeline state.
- Added `SnapshotCatalog::rewind_to_fragment` in storage with coverage for partial prune and full clear rewind paths (while preserving `snapshots_written` as cumulative counter).
- Integrated snapshot-catalog rewind into block-assembler confirmed reorg rewind path and persisted catalog immediately after rewind, preventing stale future snapshots from surviving across restarts.
- Added stage-level regression coverage for persisted-catalog consistency after confirmed reorg rewind: test now validates that on-disk snapshot catalog is pruned to rewind checkpoint (no future snapshot residue).
- Synced fragment-id progression after confirmed reorg rewind by resetting block-assembler `fragment_counter` to rewind checkpoint, preventing post-rewind fragment-id drift from pre-reorg state.
- Added replay-controller rewind reset hook (`on_rewind_to_fragment`) and integrated it into confirmed reorg rewind path to clear stale candidates and reset canonical fragment tracking at checkpoint.
- Added runtime-state baseline seeding for startup restore: runtime-like execution bridge now seeds `RuntimeStateStore` with restored fragment checkpoint (`seed_checkpoint`) before first apply.
- Added runtime-state rewind floor invariant (`RuntimeStateRewindTargetBelowFloor`) to prevent rewinds below seeded restore baseline, with dedicated storage tests.
- Added execution-boundary coverage for seeded-floor rewind guard: storage-backed adapter rewind below baseline now surfaces typed rollback failure (`AdapterRollbackFailure`) with floor-context error text.
- Added replay-window catalog-prune telemetry (`replay_window_catalog_snapshots_pruned_total`) and wired it to actual `SnapshotCatalog::rewind_to_fragment` prune count in confirmed reorg rewind path.
- Expanded stage/metrics regression coverage for catalog-prune telemetry in both no-catalog (0 pruned) and persisted-catalog reorg scenarios (>0 pruned).
- Added startup-restore/runtime-like execution consistency guard: runtime-state baseline is now seeded from restored fragment checkpoint and protected by floor-bound rewind invariant.
- Added execution/storage/stage coverage that confirms rewind-below-floor is rejected and surfaced as typed rollback failure on adapter boundary.
- Extended preflight command with deep startup validation: materializes topology and executes service `on_start`/`on_stop` hooks without entering runtime loop, surfacing startup failures early.
- Hardened live identity preflight: keypair file is now validated as JSON byte-array with strict 64-byte length checks (not only file existence).
- Expanded node control-plane commands with `config` (resolved configuration summary dump) and `keys` (explicit identity keypair validation), alongside existing `run`/`preflight`/`version`.
- Added explicit live-mode rejection of dev-only runtime bounded-run knob (`runtime.run_for_seconds`) with dedicated validation helper/tests.
- `run` path now performs deep service startup preflight (`on_start`/`on_stop`) before entering runtime loop, ensuring fail-fast startup behavior consistent with preflight command.
- Added early storage startup preflight checks: validate snapshot catalog parent directory presence and enforce strict-restore catalog-file existence before stage startup.
- Added strict startup-restore policy (require snapshot presence for `restore_latest`/`restore_specific`) with config/env wiring and startup failure paths.
- Added strict startup-restore preflight for missing `storage.catalog_path` (config-time and stage startup-time guardrails).
- Replaced `anyhow` in `paradencer-node` with typed `thiserror`-based node errors and dedicated `errors.rs`.
- Added production topology validation at service materialization boundary (schema/link/stage requirements are now enforced at runtime startup, not only in tests).
- Removed stale `anyhow` workspace dependency after full typed-error migration.
- Split oversized storage config module into focused submodules (`storage/mod.rs`, `storage/types.rs`, `storage/env.rs`, `storage/policies.rs`) while preserving behavior.
- Added stage tests for storage catalog startup/persist edge cases (malformed catalog and missing parent path).
- Added stage test coverage for retry-policy tuning behavior (custom retry budget + capped backoff).
- Added explicit precedence coverage for storage retry controls (`default <- TOML <- env overrides`) without global env mutation in tests.
- Split node storage config parsing/building into dedicated module (`storage_config.rs`) to reduce density in `config_parts.rs`.
- Split node runtime config parsing/building into dedicated module (`runtime_config.rs`) to reduce density in `config_parts.rs`.
- Split stages metrics reporter into dedicated submodules (`metrics_reporter/mod.rs`, `metrics_reporter/format.rs`, `metrics_reporter/sink.rs`).
- Split node ingress/metrics config parsing/building into dedicated modules (`ingress_config.rs`, `metrics_config.rs`) to reduce density in `config_parts.rs`.
- Split node topology config parsing/building into dedicated module (`topology_config.rs`) and schema-version handling into `profile_schema.rs`.
- Split node root profile loading/parsing into dedicated module (`profile_loader.rs`) and kept `config_parts.rs` as facade for profile composition.
- Added dedicated node profile type module (`profile_types.rs`) and reduced `config_parts.rs` to functional reexports/facade wiring.
- Extracted node configuration into a dedicated reusable crate `paradencer-config` and switched `paradencer-node` to consume it as a dependency.
- Added execution retry-policy tuning knobs in config -> storage runtime policy -> execution bridge wiring.
- Replaced `anyhow` with typed `thiserror` errors in `paradencer-config` via dedicated `errors.rs`.
- Added stage-level tests that confirm `execution_retry_policy` delay knobs affect retry/drop timing behavior.
- Added config tests for zero-value rejection in execution retry policy and env retry-attempt overrides.
- Applied leader-gate directive in block assembler before execution (real hold/defer behavior, no-op placeholder removed).
- Added configurable leader-slot schedule policy (`TOML + ENV`) and stage-level rotation tests.
- Added storage fault-path test for non-writable catalog parent directory (unix).
- Added storage startup fault-path test for truncated (partially written) snapshot catalog file.
- Added restart-recovery test: startup failure on corrupted catalog, then successful restore after rewriting valid catalog.
- Added startup fault-path test for catalog file with unsupported schema version.
- Added startup fault-path test for structurally invalid catalog JSON shape (`snapshots` wrong type).
- Split `paradencer-config` crate tests into dedicated module file (`src/tests.rs`) to keep `lib.rs` focused as facade.
- Hardened UDP metrics reporter test for sandboxed CI environments (skip on socket permission denial).
- Split execution bridge internals into focused submodules (`bridge/mod.rs`, `bridge/classify.rs`, `bridge/directives.rs`, `bridge/retry.rs`, `bridge/tests.rs`) while preserving execution semantics and tests.
- Split metrics config module into focused submodules (`metrics/mod.rs`, `metrics/types.rs`, `metrics/profile.rs`, `metrics/env.rs`) while preserving `TOML <- env` precedence and validation behavior.
- Split runtime config module into focused submodules (`runtime/mod.rs`, `runtime/types.rs`, `runtime/profile.rs`, `runtime/env.rs`, `runtime/parsers.rs`) while preserving defaults and override semantics.
- Split ingress crate internals into focused modules (`ingress/mod.rs`, `ingress/domain.rs`, `ingress/policy.rs`, `ingress/decoder.rs`, `ingress/dedup.rs`, `ingress/limiters.rs`, `ingress/tests.rs`) while preserving public API and dataplane semantics.
- Split stages shared telemetry/stat counters into dedicated module (`stages/stats.rs`) and kept `stages/lib.rs` as thin facade.
- Split topology config module into focused submodules (`topology/mod.rs`, `topology/types.rs`, `topology/defaults.rs`, `topology/env.rs`, `topology/file.rs`, `topology/validation.rs`) while preserving external topology loading and required-stage validation.
- Split storage crate tests out of `storage/lib.rs` into dedicated `storage/tests.rs` to keep crate root as facade.
- Split block assembler implementation into focused submodules (`block_assembler/mod.rs`, `block_assembler/retry.rs`, `block_assembler/service.rs`) while preserving startup restore and retry/fork-choice behavior.
- Split tx-filter implementation into focused submodules (`tx_filter/mod.rs`, `tx_filter/egress.rs`, `tx_filter/service.rs`) while preserving rate-limit/cost-budget/dedup and egress backpressure semantics.
- Split storage policy application module into focused submodules (`storage/policies/mod.rs`, `storage/policies/common.rs`, `storage/policies/assembly.rs`, `storage/policies/startup.rs`, `storage/policies/execution_retry.rs`, `storage/policies/leader_scheduler.rs`, `storage/policies/fork_choice.rs`, `storage/policies/health_replay.rs`) while preserving policy precedence and validation semantics.
- Split config crate tests into focused modules (`tests/mod.rs`, `tests/runtime_ingress_schema.rs`, `tests/storage_profile.rs`, `tests/storage_env_overrides.rs`) and removed monolithic `tests.rs`.
- Split runtime crate core into focused modules (`runtime/lib.rs`, `runtime/service.rs`, `runtime/executors.rs`, `runtime/validation.rs`) while preserving tokio/pinned execution behavior and pinned-core policy checks.
- Split stages test suite into focused modules (`testsuite/mod.rs`, `testsuite/pipeline.rs`, `testsuite/tx_filter.rs`, `testsuite/metrics_reporter.rs`, `testsuite/block_assembler_startup.rs`, `testsuite/block_assembler_runtime.rs`) and removed monolithic `testsuite.rs`.
- Split core crate internals into focused modules (`core/lib.rs`, `core/types.rs`, `core/topology_validation.rs`, `core/tests.rs`) while preserving public API and topology validation semantics.
- Split mesh crate internals into focused modules (`mesh/lib.rs`, `mesh/ports.rs`, `mesh/stats.rs`, `mesh/types.rs`, `mesh/tests.rs`) while preserving bounded-channel behavior and counters API.
- Split node topology internals into focused submodules (`topology_parts/mod.rs`, `topology_parts/types.rs`, `topology_parts/materialize.rs`, `topology_parts/validation.rs`, `topology_parts/planner.rs`, `topology_parts/loader.rs`) while preserving topology load/plan/materialization behavior.
- Split stages stats internals into focused submodules (`stats/mod.rs`, `stats/ingress.rs`, `stats/block_assembly.rs`, `stats/metrics.rs`) while preserving telemetry counters and snapshot export behavior.
- Added dedicated shred ingress lane in topology (`shred_stream`) and stage graph (`shred_sanitizer`) while preserving existing tx path behavior.
- Extended edge intake routing to split gossip-classified packets into a dedicated shred channel when shred lane is materialized.
- Added `ShredFilter` stage with shred decode + dedup behavior and dedicated shred filter telemetry counters.
- Extended metrics reporter envelope/export with shred link and shred filter metrics.
- Added topology capacity knob for shred lane (`shred_link_capacity`) with TOML/env wiring.
- Added explicit slot pipeline state machine inside block assembly (collecting/executing/retry/reorg/commit/drop transitions) to model replay/bank-like state progression without changing external behavior.
- Added block-assembly telemetry for slot-state transitions (`committed`, `dropped`, `reorg_pending`) and exporter coverage in metrics tests.
- Added dedicated `replay_controller` module in block assembly to track canonical chain progress and reorg candidates, decoupling replay publication decisions from execution bridge glue.
- Added replay-controller telemetry counters (`replay_controller_holds`, `replay_controller_confirmed_candidates`) and metrics-export test coverage.
- Extended replay controller to track multiple competing reorg candidates with deterministic active-candidate selection and confirmation thresholding.
- Added replay-controller candidate-switch telemetry (`replay_controller_candidate_switches`) and expanded controller/runtime tests for competing-branch behavior.
- Added replay-controller runtime policy knobs in config (`candidate_confirmation_threshold`, `max_candidates`) with TOML/env wiring and validation.
- Split fork-choice ranking into dedicated `fork_choice_engine` module used by replay controller, with explicit candidate scoring and deterministic tie-break behavior.
- Added startup regression coverage for `runtime_like + restore_latest`: first post-restore fragment commit now explicitly validated to advance from restored checkpoint without fragment-id drift.
- Hardened ingress source cost-budget limiter arithmetic: replaced saturating spent-cost accumulation with checked addition so overflow cannot bypass budget enforcement.
- Hardened startup restore slot/leader alignment: block assembler now seeds `slot_pipeline.current_slot` and `leader_gate_state.next_leader_slot` from `max(leader.initial_slot, restored_fragment_id)` to prevent post-restore scheduler/slot drift.
- Hardened block-assembly fragment-id progression against wraparound: fragment counter increment is now checked (`checked_add`) and surfaces explicit runtime failure on overflow instead of silent/wrapping behavior.
- Fixed startup replay-window telemetry consistency: `replay_window_checkpoint_depth` is now seeded immediately from restored bank timeline state instead of remaining zero until first post-startup commit.
- Fixed confirmed-reorg rewind slot-state consistency: block assembler now rewinds `slot_pipeline.current_slot` to the selected checkpoint together with hot-state/replay/catalog state, preventing post-reorg slot drift.
- Fixed confirmed-reorg rewind scheduler-state consistency: block assembler now also rewinds `leader_gate_state.next_leader_slot` to the selected checkpoint to avoid post-reorg leader/scheduler drift against rewound fragment state.
- Hardened confirmed-reorg rewind with leader-slot floor semantics: rewound slot/scheduler positions now clamp to `max(checkpoint.fragment_id, leader.initial_slot)` so rewind cannot violate configured startup slot floor after restore.
- Hardened execution-state rewind contract at storage adapter boundary: `StorageBackedRuntimeAdapter::rewind_to_fragment` now treats rewind as a strict state barrier and clears all pending apply receipts, preventing post-rewind stale rollback eligibility on both target and newer fragments.
- Added regression coverage that rewind-barrier semantics remain forward-progress compatible: after `rewind_to_fragment`, the adapter can re-apply the next fragment id and rollback it normally (pending receipt lifecycle remains valid after barrier clear).
- Hardened runtime-state checkpoint seeding semantics: `RuntimeStateStore::seed_checkpoint` now resets all accumulated totals and clears receipt history while setting floor/fragment baseline, preventing stale aggregate carryover when re-seeding store baseline.
- Hardened JSON-RPC transaction-submission config conformance in `paradencer-rpc`: `sendTransaction`/`simulateTransaction` (including nested `accounts` config) now reject unknown config keys with `-32602` instead of silently ignoring extra fields.
- Hardened JSON-RPC block/transaction history config conformance in `paradencer-rpc`: `getBlock` and `getTransaction` config objects now reject unknown keys with `-32602` (strict allowlist), removing silent acceptance of unsupported fields.
- Hardened JSON-RPC query-shape conformance for history range/time methods: `getBlocks`, `getBlocksWithLimit`, `getBlockCommitment`, and `getBlockTime` now enforce strict params layout (typed positional args, optional config object in the expected slot, no extra params, config unknown-key rejection as `-32602`).
- Refined history-method error precedence for strict JSON-RPC conformance: query-shape/config validation now runs before `minContextSlot` gating on range/time methods, so malformed params consistently return `-32602` instead of leaking into `-32016` in mispositioned-config cases.
- Hardened positional-params conformance for full-API methods: `getBlock`, `getTransaction`, `sendTransaction`, and `simulateTransaction` now reject extra trailing positional params (`params.len() > 2`) with `-32602` instead of silently ignoring tail arguments.
- Added config-driven fork-choice scoring weights (`reorg_signal_weight`, `fragment_recency_weight`) and wired them from storage policy into replay controller/engine.
- Added dedicated `publication_gate` module to isolate publish/hold decisions for leader-gate and reorg paths from execution/retry flow plumbing.
- Added replay-window checkpoint timeline in block assembly (`bank_timeline`) with config-driven checkpoint depth and optional rewind-on-confirmed-reorg behavior.
- Added replay-window telemetry export (`replay_window_checkpoint_depth`, `replay_window_rewinds_total`) and test coverage.
- Added snapshot-catalog retention policy (max retained snapshots) with automatic pruning of oldest snapshots during commit flow.
- Hardened WS subscription param conformance in `paradencer-rpc` with strict unknown-key rejection for subscription config objects (`slot`, `vote`, `account`, `signature`, `block`, `logs`, `program`) and nested objects (`dataSlice`, `block` filter, `logs` filter, `program` filters including `memcmp`).
- Expanded WS negative-test coverage for strict unknown-key rejection across subscription methods and nested filter/data-slice payloads.
- Verified `paradencer-rpc` test suite after WS conformance hardening: `219 passed; 0 failed`.
- Refactored `paradencer-execution` to a pluggable engine boundary (`ExecutionEngine`) with default `HeuristicExecutionEngine`, preserving existing execution semantics while opening a clean path for a real SVM-like runtime adapter.
- Added execution-bridge support for injected engines (`with_engine`, `with_engine_and_retry_policy`) and test coverage for custom engine integration (`14 passed; 0 failed` for `paradencer-execution`).
- Added storage-config wiring for execution engine policy selection (`storage.execution_engine_policy` / `PARADENCER_STORAGE_EXECUTION_ENGINE_POLICY`) with strict parsing (`heuristic`) and validation tests.
- Wired block assembly to instantiate execution bridge through explicit `execution_engine_policy` selection (currently `heuristic`, future-ready for runtime adapters).
- Verified policy wiring with green suites: `paradencer-config` (`70 passed; 0 failed`) and `paradencer-stages` (`75 passed; 0 failed`).
- Added `RuntimeLikeExecutionEngine` scaffold in `paradencer-execution` and exposed it via pluggable engine boundary without changing default execution behavior.
- Extended execution engine policy surface with `runtime_like` aliases (`runtime_like` / `runtime-like` / `runtime`) and wired selection through storage profile/env into block assembly engine instantiation.
- Added policy coverage tests (`profile + env + block-assembler startup`) and re-verified suites: `paradencer-config` (`72 passed; 0 failed`), `paradencer-stages` (`76 passed; 0 failed`), `paradencer-execution` (`14 passed; 0 failed`).
- Extended control-plane config summary output to include active `execution_engine_policy` for operator diagnostics (`paradencer-control` tests: `35 passed; 0 failed`).
- Refactored `RuntimeLikeExecutionEngine` around an explicit runtime-adapter contract (`RuntimeExecutionAdapter`) with preflight/outcome hooks, plus default synthetic adapter (`SyntheticRuntimeAdapter`) and injectable adapter constructor (`with_adapter`).
- Added execution-level adapter-injection test coverage for runtime-like path and re-verified full affected suites (`paradencer-execution` `15 passed`, `paradencer-config` `72 passed`, `paradencer-stages` `76 passed`, `paradencer-rpc` `219 passed`, `paradencer-control` `35 passed`; all green).
- Split runtime-like adapter contract into dedicated execution module with explicit state/accounts/program-cache hook types (`RuntimeBatchContext`, `RuntimePreflightOutcome`, `RuntimeExecutionObservation`, `RuntimeStateWriteIntent`, `AccountAccessPattern`, `ProgramCacheHint`) and kept default synthetic adapter behavior stable.
- Added runtime-like engine test for default adapter path and updated execution suite (`paradencer-execution` `16 passed; 0 failed`).
- Added explicit execution-effects hook surface in runtime adapter contract (`RuntimeExecutionEffects`, `AccountStateDeltaSummary`, `ProgramCacheDeltaSummary`) and integrated effects summarization into runtime-like engine flow.
- Added effects-aware failure normalization guard in runtime-like engine (promote transient pressure to resource exhaustion under heavy account-write effects) with dedicated test coverage; updated execution suite (`paradencer-execution` `17 passed; 0 failed`).
- Added phased execution-effects lifecycle hooks to runtime adapter contract (`prepare_effects`, `apply_effects`, `rollback_effects`) with typed plan/apply artifacts (`RuntimeEffectsPlan`, `RuntimeApplyReport`).
- Integrated lifecycle hooks into runtime-like execution flow with rollback-on-apply-failure behavior and explicit typed adapter errors (`AdapterApplyFailure`, `AdapterRollbackFailure`) plus dedicated rollback-path tests; updated execution suite (`paradencer-execution` `19 passed; 0 failed`).
- Split execution-effects lifecycle into explicit channel-level plans/reports for `account_state` and `program_cache` (`AccountStateEffectsPlan`, `ProgramCacheEffectsPlan`, `RuntimeEffectsChannelsPlan`, `RuntimeEffectsChannelsApplyReport`) inside `RuntimeEffectsPlan`/`RuntimeApplyReport`.
- Kept runtime behavior stable while making channel-level application explicit in default adapter path; suites remain green (`paradencer-execution` `19 passed`, `paradencer-config` `72 passed`, `paradencer-stages` `76 passed`).
- Added channel-level runtime-effects apply policies (`strict`/`lenient` for account-state and program-cache subflows) with adapter override hook (`select_effects_apply_policies`) and runtime-like coverage for custom policy selection; suites remain green (`paradencer-execution` `20 passed`, `paradencer-config` `72 passed`, `paradencer-stages` `76 passed`).
- Added storage runtime-state model in `paradencer-storage` (`RuntimeStateStore` + apply/rollback receipts + state snapshots + underflow/fragment-regression guards) and test coverage.
- Added `StorageBackedRuntimeAdapter` in `paradencer-execution` and integrated runtime-like effects apply/rollback with persistent runtime-state store semantics.
- Runtime-like engine now preserves adapter-typed apply/rollback failures without double-wrapping and includes storage-backed rollback-path coverage; suites remain green (`paradencer-storage` `22 passed`, `paradencer-execution` `22 passed`, `paradencer-config` `72 passed`, `paradencer-stages` `76 passed`).
- Integrated storage-backed runtime adapter into the real block-assembler execution path: `execution_engine_policy=runtime_like` now materializes `RuntimeLikeExecutionEngine` with `StorageBackedRuntimeAdapter` by default.
- Added configurable runtime-like effects apply policies in storage runtime policy (`runtime_like_account_state_apply_policy`, `runtime_like_program_cache_apply_policy`) with `strict/lenient` parsing via TOML + ENV (`PARADENCER_STORAGE_RUNTIME_LIKE_ACCOUNT_STATE_APPLY_POLICY`, `PARADENCER_STORAGE_RUNTIME_LIKE_PROGRAM_CACHE_APPLY_POLICY`).
- Wired configured apply policies end-to-end into block-assembler runtime-like engine materialization (`StorageBackedRuntimeAdapter::with_state_store_and_policies`) and added coverage for lenient policy behavior in execution tests.
- Updated suites remain green after policy wiring (`paradencer-config` `76 passed`, `paradencer-execution` `23 passed`, `paradencer-stages` `76 passed`).
- Hardened runtime-like storage-backed execution invariants:
  - runtime state apply is now strictly monotonic by `fragment_id` (duplicate fragment apply rejected),
  - rollback is now LIFO-only (`receipt.fragment_id` must match current `last_fragment_id`),
  - storage adapter now clears pending rollback receipts on successful apply and returns typed `AdapterReceiptMissing` for invalid rollback calls.
- Expanded execution/storage typed errors for adapter state conflicts and mutex-poison paths; preserved these typed failures through runtime-like error wrapping.
- Re-verified broad suites after invariant hardening (`paradencer-storage` `24 passed`, `paradencer-execution` `24 passed`, `paradencer-stages` `76 passed`, `paradencer-config` `76 passed`, `paradencer-runtime` `14 passed`, `paradencer-control` `35 passed`, `paradencer-node` `0 failed`).
- Extended control-plane config summary to include runtime-like channel apply policies for operator diagnostics (`runtime_like_account_state_apply_policy`, `runtime_like_program_cache_apply_policy`).
- Improved execution error semantics at bridge boundary: `ExecutionBridge::execute_batch` now maps typed engine errors to meaningful failure classes (`replay_conflict` / `transient_scheduler_pressure` / `deterministic`) instead of forcing all errors into deterministic failures.
- Refined execution fallback outcome semantics for error path: `replay_conflict` now preserves `failed_transactions=0` (non-transactional conflict signal), while deterministic/transient classes keep batch-level failed count for retry/backpressure accounting.
- Fixed retry-directive invariant for replay conflicts: `ReplayConflict` now triggers retry/backoff by failure class even when `failed_transactions=0` (prevents accidental `NoRetry` on conflict-only fallback outcomes).
- Unified execution-error streak tracking across handling modes: `execution_error_consecutive_current` now increments on all execution errors (including `fail_fast`) and resets on successful execution.
- Hardened storage-backed rollback contract with receipt/plan consistency: rollback now requires computed channel-apply totals from the supplied plan to exactly match the stored runtime-state apply receipt for the fragment.
- Preserved rollback safety on contract rejects: when rollback plan/receipt mismatch is detected, pending receipt is retained (not consumed), so a subsequent valid rollback can still complete.
- Added deterministic test helper path for rollback artifacts in storage-adapter tests to generate runtime-like matching `context/preflight/plan` and validate strict receipt-match behavior across rollback-reject scenarios.
- Added explicit rollback mismatch regression (`plan != stored receipt`) with receipt-retention recovery path coverage.
- Hardened storage counter conversion safety: removed direct `usize -> u64` casts in `RuntimeStateStore` and `HotStateStore`, replacing them with checked conversions before counter add/subtract paths.
- Hardened runtime-like rollback error diagnostics: rollback failures on apply/report error paths now retain prior-error context in typed rollback failure messages (no root-cause loss during rollback-failure escalation).
- Added regression coverage for rollback-failure error chaining both after direct apply failure and after apply-report contract validation failure.
- Standardized saturating numeric conversion helpers in execution engines (`heuristic`, `runtime-like`, runtime adapter defaults) to remove remaining `unwrap_or(MAX)` conversion idioms and keep overflow intent explicit.
- Hardened JSON-RPC protocol conformance in renderer for batch/notification flows: added batch-array request handling, empty-batch invalid-request behavior, notification no-response behavior, and mixed batch filtering (responses only for non-notification items).
- Added strict JSON-RPC `id` validation in renderer (`string|number|null` only); invalid id shapes now return `-32600` invalid-request with `id:null`, including inside batch payloads.
- Added strict JSON-RPC method-name envelope guards in renderer: empty method names and reserved `rpc.*` method namespace are now rejected as `-32600` invalid-request.
- Tightened JSON-RPC `id` numeric conformance: fractional numeric ids are now rejected as invalid-request (`-32600`, `id:null`), while preserving valid integer/string/null id forms.
- Hardened runtime-like preflight contract with context/access-pattern consistency: adapters now cannot report `ReadMostly` when runtime batch-context requires mixed write access (`estimated_accounts_touched > transaction_count`), enforced as `AdapterContractViolation`.
- Hardened runtime-like preflight program-cache contract: `ColdPath` batch-context now requires `requires_program_cache_refresh=true` from adapters; missing refresh intent is rejected as `AdapterContractViolation`.
- Hardened runtime-like empty-batch contract at observation boundary: empty batches must report zero contention and no failure-class attribution; synthetic default adapter updated accordingly (`contention=0` for empty path).
- Refined JSON-RPC invalid-request semantics for id-less malformed envelopes: invalid requests without `id` now return `-32600` with `id:null` (not treated as notifications), while valid notifications still produce no response payload.
- Hardened storage-backed adapter boundary with context/preflight coherence checks on direct `apply/rollback`: access-pattern mismatch (`estimated_accounts_touched > tx_count` with `ReadMostly`) and `ColdPath` refresh-intent mismatch are now explicit contract violations.
- Added rollback receipt-retention coverage for new context/preflight contract rejects (subsequent valid rollback still succeeds).
- Added strict empty-batch preflight contract in runtime-like path: empty batches must use `ReadMostly`, must not request program-cache refresh, and must produce neutral observation signals (zero contention, no failure class).
- Extended storage-backed context/preflight contract coverage to full symmetry: added direct-apply ColdPath refresh mismatch reject and direct-rollback access-pattern mismatch reject with receipt-retention recovery tests.
- Improved storage-backed pending-receipt path for larger pending sets: switched receipt index from hash map to ordered map and replaced linear newer-fragment scan with ordered-tail check while preserving rollback/prune semantics.
- Hardened storage-backed rollback failure safety: pending receipt is now removed only after successful runtime-state rollback, preventing receipt loss on rollback-store failures and allowing deterministic retry/diagnostics paths.
- Hardened storage-backed rollback concurrency window: pending-receipt lock is now held through store-rollback + receipt removal, closing a race where concurrent apply-prune could invalidate rollback receipt lifecycle mid-rollback.
- Added bridge-level tests for typed error-to-failure mapping and preserved fallback `total_cost_units` from batch estimate on execution errors.
- Added block-assembly telemetry for execution error-path classification (`execution_error_total`, `empty_batch`, `cost_overflow`, `adapter_apply`, `adapter_rollback`, `adapter_state_conflict`, `adapter_receipt_missing`, `adapter_mutex_poisoned`).
- Added block-assembly telemetry for execution-error policy actions (`execution_error_fail_open_continue`, `execution_error_fail_fast_halt`) to distinguish fail-open continuation vs fail-fast halt behavior.
- Added block-assembly telemetry for fail-open circuit-breaker halts (`execution_error_fail_open_circuit_breaker_halt`).
- Added block-assembly gauge for current execution-error streak length (`execution_error_consecutive_current`) and wired reset-on-success semantics for recovery visibility.
- Added block-assembly retry-cause telemetry counters for scheduled retries (`retry_scheduled_replay_conflict`, `retry_scheduled_transient_pressure`, `retry_scheduled_resource_exhaustion`, `retry_scheduled_fallback`) to distinguish retry source classes from generic deferred-retry totals.
- Added block-assembly drop-cause telemetry counters (`dropped_replay_conflict`, `dropped_deterministic`, `dropped_transient_pressure`, `dropped_resource_exhaustion`, `dropped_fallback`) for execution-driven drop paths (`DropCurrentFragment` and retry-budget exhaustion) plus a dedicated reorg-path drop counter (`dropped_reorg_retry_exhausted`) for fork-choice retry exhaustion.
- Wired execution error accounting at stage boundary (`attempt_fragment` now records typed execution errors before surfacing runtime failure).
- Exported execution error counters through metrics reporter (Prometheus/JSON envelope fields) and extended metrics tests to validate new counters.
- Switched block-assembler execution path to fail-open behavior on execution-engine errors: stage now consumes `ExecutionBridge::execute_batch_with_error(...)`, records typed errors in telemetry, and continues through retry/replay policy flow via fallback `ExecutionOutcome` instead of hard-stopping the service loop.
- Added stage-level integration test coverage for fail-open execution error path with injected failing execution engine (`block_assembler_fail_open_on_execution_error_records_telemetry_and_continues`).
- Added test-only block-assembler constructor with explicit `ExecutionBridge` injection to support deterministic execution-failure scenario testing without mutating production policy wiring.
- Added explicit execution error handling policy surface in storage runtime policy (`execution_error_handling_policy`):
  - `FailOpen` (default): record telemetry and continue via fallback execution outcome,
  - `FailFast`: record telemetry and fail service tick on execution error.
- Wired execution error handling policy through config profile/env:
  - `storage.execution_error_handling_policy`,
  - `PARADENCER_STORAGE_EXECUTION_ERROR_HANDLING_POLICY`.
- Extended control-plane config summary with `execution_error_handling_policy` and added config/stage tests for both policy modes (`fail_open`, `fail_fast`).
- Added readiness-level guard for execution error mode (`readiness.require_fail_fast_execution_errors` / `PARADENCER_READINESS_REQUIRE_FAIL_FAST_EXECUTION_ERRORS`) so diagnostics/preflight can explicitly require `execution_error_handling_policy=fail_fast`.
- Added readiness-level guard for fail-open safety (`readiness.require_fail_open_execution_error_circuit_breaker` / `PARADENCER_READINESS_REQUIRE_FAIL_OPEN_EXECUTION_ERROR_CIRCUIT_BREAKER`) so diagnostics/preflight can require non-zero `execution_error_fail_open_max_consecutive` whenever `fail_open` mode is active.
- Added fail-open circuit-breaker threshold in storage runtime policy (`execution_error_fail_open_max_consecutive`) so prolonged execution-error streaks can escalate from fail-open to service halt.
- Added snapshot-retention controls to storage config (`TOML + ENV`) with validation and stage/storage test coverage.
- Added strict snapshot-catalog invariant validation on load (monotonic fragment and state counters) to reject corrupted catalog sequences.
- Added configurable multi-worker expansion for transaction sanitizer stages in default topology planning (`TOML + ENV`) to increase ingest-side parallelism.
- Added configurable multi-worker expansion for shred sanitizer stages in default topology planning (`TOML + ENV`) for symmetric lane scaling.
- Updated topology capacity resolution in node materialization to aggregate per-link-kind capacity across multiple links.
- Added strict topology lane-connectivity validation (each sanitizer worker must be wired to its lane input; transaction lane must have at least one output to block builder path).
- Updated node topology link-capacity resolution to sum capacities across same-kind links, so multi-worker lane fanout increases effective queue budget.
- Updated default topology planner so each `transaction_sanitizer` worker emits its own `transaction_stream` link; topology validation now requires outbound transaction wiring per tx worker.
- Node materialization now binds sanitizer stages to per-destination ingress links (instead of a single shared packet/shred queue), and `EdgeIntake` dispatches across multiple lane outports.
- Lane wiring validation tightened to `exactly one` inbound lane link per sanitizer worker (packet for tx workers, shred for shred workers) and `exactly one` outbound transaction-stream per tx worker.
- Node materialization now wires `transaction_stream` as real per-link channels (per source/destination stage) instead of a single shared queue.
- Block assembler now supports multiple inbound transaction links with round-robin receive and graceful shutdown only after all transaction inputs are closed.
- Topology validation now enforces transaction-lane destination semantics (`transaction_sanitizer -> block_builder`) and requires at least one inbound `transaction_stream` for each `block_builder`.
- Metrics reporter now aggregates link counters across all per-link channels per lane kind (`packet`/`shred`/`transaction`) for multi-worker topologies.
- Control-plane surface extracted into dedicated crate `paradencer-control` (command parsing, live network socket preflight, service startup preflight, metrics HTTP bridge) and integrated back into `paradencer-node` as orchestration-only entrypoint.
- Config facade expanded with explicit reusable entry points `NodeConfig::from_file(...)` and `NodeConfig::from_profile(...)`, while keeping `from_env()` behavior unchanged and validating through one shared build path.
- Control-plane command parser now supports explicit profile path injection via `--config <path>` for `run`/`preflight`/`config`, wiring directly to `NodeConfig::from_file(...)` instead of requiring only `PARADENCER_NODE_CONFIG_PATH`.
- Control-plane crate now owns config/keys command surface helpers (`render_config_summary`, `validate_identity_keypair_from_env`), reducing `paradencer-node` entrypoint to orchestration and routing.
- Control-plane crate now also owns common startup bootstrap helpers (`load_node_config`, `run_startup_checks`, `maybe_start_metrics_http_bridge`, `print_preflight_ok`), further reducing `paradencer-node` to topology materialization + runtime launch wiring.
- Control-plane crate now includes phase-level orchestration helpers (`ServiceBundle`, `run_runtime_phase`, `run_preflight_phase`) so `paradencer-node` delegates startup/preflight flow and keeps only topology materialization wiring.
- Topology planning/loading/materialization extracted from `paradencer-node` into dedicated crate `paradencer-topology` with its own typed error surface and tests; node now consumes topology as a library.
- Control-plane crate now provides command dispatch runner (`dispatch_command`) for `run/preflight/config/keys/version`; `paradencer-node` binary reduced to thin callbacks over topology materialization and phase execution.
- Observability transport surface extracted into dedicated crate `paradencer-observability`; metrics HTTP bridge implementation moved out of `paradencer-control` and integrated via typed `ObservabilityError`.
- Added dedicated control output surface module (`output.rs`) for consistent CLI line rendering (phase/topology/preflight/version/keys) and switched control bootstrap/runner to use it.
- Stabilized UDP intake pipeline test by replacing single-tick receive assumption with bounded retry loop (`edge_intake_udp_mode_receives_datagrams_and_classifies_source_port`).
- Added control-plane diagnostics command path (`diagnostics` / `doctor`) with config-path support and callback dispatch, enabling topology materialization diagnostics without entering runtime loop.
- Moved node topology materialization wiring into control bootstrap helpers (`materialize_services_from_config`, `materialize_service_pair_from_config`) so `paradencer-node` no longer duplicates materializer argument plumbing across run/preflight/diagnostics flows.
- Added dedicated UDP ingress budget knob (`udp_max_packets_per_tick`) with TOML/env wiring and stage usage, decoupling live UDP receive throughput tuning from synthetic traffic generator controls.
- Added runtime-level lifecycle probe API (`probe_service_lifecycle`) with structured reports and integrated it into control preflight/diagnostics, including diagnostics startup-probe summary and fail-on-probe-errors behavior.
- Added deep lifecycle probe mode for control-plane checks with configurable tick count (`--with-tick` and `--probe-ticks N` on `preflight`/`diagnostics`) to validate `on_start + N*tick + on_stop` without entering runtime loop.
- Added centralized diagnostics phase helper in control bootstrap (`run_diagnostics_phase`) that executes live-network socket preflight + lifecycle probe checks and returns typed diagnostics summary; node diagnostics path now delegates to control orchestration.
- Expanded diagnostics summary with topology/service readiness details: stage-kind mix, per-lane aggregate capacities (`packet/shred/transaction`), and runtime service-name list for fast operator sanity checks in pre-mainnet validation.
- Added explicit diagnostics readiness gate (`--mainnet-readiness`) with fail-fast checks and issue reporting for production-like expectations (worker mix, lane capacities, pinned runtime mode, UDP ingress mode, and non-stdout metrics sink).
- Added configurable mainnet-readiness policy surface in node config (`[readiness]` section + env overrides), replacing hardcoded diagnostics thresholds with profile-driven constraints.
- Extended mainnet-readiness gate to `preflight` path and refactored control bootstrap so preflight/readiness share one startup probe report (no duplicate probe pass), with dedicated preflight readiness output lines.
- Expanded readiness policy/checks with additional production constraints (`min_runtime_workers`, `min_live_entrypoints`, optional `require_metrics_http_bind`) wired through config/env and enforced by both diagnostics/preflight readiness gates.
- Added explicit pinned-core affinity mapping (`runtime.pinned_service_core_ids` + `PARADENCER_PINNED_SERVICE_CORES`) with runtime validation (length, available core IDs, strict-mode uniqueness) and deterministic `service -> core` assignments.
- Added reusable runtime affinity-planning API (`build_pinned_affinity_plan`) and wired early pinned-affinity preflight checks into startup/diagnostics phases with explicit operator output lines.
- Upgraded snapshot catalog schema to v2 with snapshot integrity checksum (`state_checksum`) validation, added strict checksum verification on catalog load, and migration support from legacy v0/v1 catalogs without checksum fields.
- Config preflight now performs deep validation of existing snapshot catalog files (including schema migration/invariant/checksum checks) and fails early on corrupted catalogs before runtime startup.
- Execution bridge now evaluates failure classes using batch load signals (`transaction_count` + `estimated_total_cost_units`) in addition to deterministic fragment patterns; block assembler now carries batch cost through retry/reorg paths so repeated attempts preserve execution-load classification semantics.
- Replay controller/fork-choice scoring now optionally penalizes reorg candidates with high failed-transaction ratios (`failed_transaction_ratio_penalty_weight` via TOML/env), and block assembler now reports per-fragment failed ratio into replay-candidate tracking.
- Added replay-candidate quality telemetry export: metrics now include active-candidate failed-ratio (`bps`) and tracked replay-candidate count, enabling runtime visibility of fork-choice candidate health.
- Strengthened snapshot-catalog startup validation with strict header invariants (`last_snapshot_fragment_id`/`snapshots_written` consistency with catalog entries) and added corruption-path tests.
- Extended config-level storage startup preflight tests to reject snapshot catalogs with header-consistency corruption before runtime launch.
- Added initial client RPC bootstrap path: dedicated `paradencer-rpc` crate with minimal JSON-RPC HTTP methods (`getHealth`, `getVersion`), plus config/env wiring (`[rpc]` / `PARADENCER_RPC_*`) and runtime startup integration.
- Expanded RPC bootstrap method set with runtime-linked methods (`getSlot`, `getBlockHeight`, `getLatestBlockhash`) sourced from latest metrics JSON snapshot when file-target metrics are enabled.
- Extended RPC read methods (`getBlockCount`, `getTransactionCount`, `getRecentPerformanceSamples`) with explicit method allowlist and `full_api` gating for performance samples.
- Switched RPC transport to a proven server stack (`jsonrpsee`) and split RPC implementation into dedicated modules (`http/server.rs`, `http/registry.rs`, `http/renderer.rs`) to separate transport from method logic.
- Added typed JSON-RPC method error model and explicit method-dispatch layer split by domains (`http/methods/{basic,ledger,accounts,cluster,history,inflation}.rs`) with centralized routing in `http/methods/mod.rs`.
- Replaced stringly-typed method routing with explicit `RpcMethod` registry enum + resolver (`resolve_method`) and `requires_full_api` policy, so registration, allowlist checks, and dispatch mapping are now centralized and strongly typed.
- Migrated `history` and `ledger` RPC method logic (builders/parsers) out of monolithic `renderer` into domain modules, reducing renderer responsibility to JSON-RPC envelope parsing + dispatch + error shaping.
- Added dedicated `paradencer-constants` crate and migrated key RPC/economics/timing literals (including `lamportsPerSignature=5000`, epoch slot constants, blockhash window, and RPC limits) out of inline handlers.
- Reduced `renderer` to a thin JSON-RPC envelope/dispatch layer; domain logic now lives in `methods/*` (`basic`, `ledger`, `history`, `cluster`, `accounts`, `inflation`) plus shared helpers (`methods/shared.rs`).
- Added shared RPC parameter parsing helpers (`methods/params.rs`) and started converging module parsers (`ledger`/`history`/`inflation`/parts of `accounts` and `cluster`) onto one validation path to reduce duplication and drift.
- Completed cleanup/rewrite of `accounts` and `cluster` method modules to use shared parsing helpers consistently and removed local parsing duplication artifacts.
- Extended account-family RPC guards with `minContextSlot` enforcement (`getBalance`, `getAccountInfo`, `getMultipleAccounts`, `getProgramAccounts`, `getTokenAccountsByOwner`, `getTokenAccountsByDelegate`, `getSignatureStatuses`) and added dedicated regression tests for `-32016` behavior.
- Strengthened history RPC semantics: added `minContextSlot` guard + config validation for `getBlock`/`getTransaction` (`encoding`, `transactionDetails`, `rewards`, `maxSupportedTransactionVersion`, commitment shape) and added regression tests for invalid-config and guardrail paths.
- Hardened history RPC request/response shaping with typed per-method config parsing (`getBlock`/`getTransaction`), config-driven response toggles (`transactionDetails`, `rewards`, `encoding`, `maxSupportedTransactionVersion`), and extra invalid-param regression tests.
- Added global JSON-RPC commitment validation in envelope parsing (`commitment` must be `processed|confirmed|finalized` string), returning `-32602` for invalid commitment values/types across methods.
- Expanded history method surface with `getBlocksWithLimit` (typed registry + dispatch wiring, full_api gate, limit validation, commitment-aware range clamping, and regression tests).
- Expanded history method surface with `getBlockCommitment` (typed registry + dispatch wiring, full_api gate, slot validation, future-slot null behavior, and deterministic synthetic commitment payload).
- Hardened `getBlocksWithLimit` semantics with strict limit validation (`1..=MAX_BLOCKS_RANGE_LEN`) and extended regression coverage for `minContextSlot` guardrails on both `getBlocksWithLimit` and `getBlockCommitment`.
- Expanded cluster/leader RPC surface with non-`full_api` methods `getSlotLeader` and `getSlotLeaders` (typed registry/dispatch integration, max-limit validation, future-range empty behavior, and regression tests).
- Hardened ledger RPC `minContextSlot` semantics across blockhash/fee reads (`getLatestBlockhash`, `getRecentBlockhash`, `isBlockhashValid`, `getFeeForMessage`) with shared guardrails and dedicated `-32016` regression coverage.
- Added baseline non-`full_api` compatibility method `getEpochSchedule` (typed registry/dispatch integration + regression tests) for closer client-RPC surface parity.
- Added baseline non-`full_api` compatibility method `getMinimumBalanceForRentExemption` with typed param validation (`-32602` on missing/invalid `dataLen`) and constants-driven rent formula.
- Added baseline non-`full_api` compatibility method `getStakeMinimumDelegation` with context payload and `minContextSlot` guard behavior (`-32016` when context slot is not reached).
- Added legacy compatibility method `getFees` in ledger RPC with context/value payload (`blockhash`, `feeCalculator`, `lastValidSlot`, `lastValidBlockHeight`) and `minContextSlot` guard semantics.
- Added legacy compatibility method `getFeeCalculatorForBlockhash` with typed blockhash validation, context payload semantics (`value` object or `null`), and `minContextSlot` guard behavior.
- Expanded token account/supply RPC surface with `getTokenSupply` and `getTokenAccountBalance` (full_api-gated), including typed param validation and `minContextSlot` guardrails for token-supply reads.
- Added non-`full_api` node-operator compatibility methods `getHighestSnapshotSlot` and `getMaxRetransmitSlot`, with commitment-aware synthetic slot projection and regression test coverage.
- Strengthened `getSignaturesForAddress` history semantics: added `minContextSlot` guard handling and deterministic `before`/`until`-aware slot anchoring in synthetic signature pagination path.
- Added legacy alias compatibility `getConfirmedSignaturesForAddress2` (wired to shared signatures-history semantics with full_api gating and regression coverage).
- Expanded cluster guardrails: added `minContextSlot` enforcement for `getLeaderSchedule`, `getBlockProduction`, and `getRecentPrioritizationFees`, with dedicated `-32016` regression tests.
- Strengthened supply/token-account semantics in `accounts`: added `minContextSlot` guardrails for `getSupply` and `getTokenLargestAccounts`, plus typed config support for `getSupply.excludeNonCirculatingAccountsList`.
- Expanded `getVoteAccounts` semantics with typed config parsing (`votePubkey`, `keepUnstakedDelinquents`, `delinquentSlotDistance`, `minContextSlot`), filter-aware current-set shaping, and delinquent-set emission controls.
- Strengthened ledger core read semantics: `getSlot`/`getBlockHeight`/`getBlockCount` now enforce `minContextSlot`; `getRecentPerformanceSamples` now rejects invalid limits (non-numeric/zero) with `-32602`.
- Strengthened `getSignatureStatuses` semantics with typed config parsing (`searchTransactionHistory`, `minContextSlot`) and search-aware result shaping (nullable entries when history scan is disabled).
- Added RPC account/block read scaffolding (`getAccountInfo`, `getBlock`) with parameter validation (`-32602` on invalid params), future-slot null-block handling, and `full_api` gating.
- Added initial RPC commitment semantics (`processed` / `confirmed` / `finalized`) for slot/block/account/blockhash read paths, with commitment-aware visibility windows.
- Extracted RPC runtime state boundary into dedicated provider layer (`state.rs`) and switched HTTP serving path to consume `RuntimeSnapshotProvider` instead of direct metrics-file parsing.
- Expanded RPC method surface with `getBalance`, `getEpochInfo`, and `getBlockTime` (including `full_api` gating for block-time path and commitment-aware visibility checks).
- Expanded RPC read scaffolding with `getMultipleAccounts`, `getFirstAvailableBlock`, and `getBlocks` (range clamping, invalid-params handling, and `full_api` gating for richer history/account-batch reads).
- Expanded RPC read scaffolding with `getTransaction` and `getSignatureStatuses` (typed signature param validation, `full_api` gating, and commitment-aware synthetic status/slot projection).
- Expanded RPC read scaffolding with `getBlockProduction` and `getRecentPrioritizationFees` (range/config validation, `full_api` gating, and commitment-aware synthetic history windows).
- Expanded RPC surface with `getLeaderSchedule`, `minimumLedgerSlot`, and `getMaxShredInsertSlot` (leader-identity filter validation, `full_api` gating for leader schedule, and commitment-aware shred slot projection).
- Expanded RPC supply/account-distribution scaffolding with `getSupply`, `getLargestAccounts`, and `getTokenLargestAccounts` (typed filter/mint validation and `full_api` gating).
- Expanded RPC operator/read scaffolding with `getIdentity`, `getClusterNodes`, and `getVoteAccounts` (cluster/vote payload stubs, `full_api` gating where appropriate, and typed validation invariants).
- Expanded RPC chain-history/read scaffolding with `getGenesisHash` and `getSignaturesForAddress`, and added `minContextSlot` guardrail handling for `getTransactionCount` (`-32016` when context is ahead of visible commitment slot).
- Expanded RPC token/program account query scaffolding with `getProgramAccounts`, `getTokenAccountsByOwner`, and `getTokenAccountsByDelegate` (filter/selector validation and `full_api` gating).
- Expanded RPC legacy-compat/read surface with `isBlockhashValid`, `getFeeForMessage`, and `getRecentBlockhash` (commitment-aware contexts) while keeping `getGenesisHash` subset-readable.
- Expanded RPC inflation/read scaffolding with `getInflationGovernor`, `getInflationRate`, and `getInflationReward` (`full_api` gating, typed params, and deterministic reward payloads).
- Expanded RPC submission + legacy compatibility surface with dedicated `transactions` method module: added `sendTransaction` and `simulateTransaction` with typed config validation (`encoding`, preflight/simulation flags, account payload config), `minContextSlot` guardrails, and `full_api` gating; added explicit alias regression coverage for `getConfirmedBlock`/`getConfirmedBlocks`/`getConfirmedTransaction`.
- Strengthened execution/runtime retry behavior with class-aware retry budgets: `RetryPolicy` now carries per-failure-class retry caps (`replay/transient/resource/fallback`), `BlockAssembler` applies effective retry budget as `min(storage.max_retry_attempts, class_budget)`, and config layer now supports TOML/env wiring for those limits with strict non-zero validation.
- Strengthened replay-controller lifecycle semantics with stale-candidate pruning: reorg candidates are now evicted by configurable fragment lag window (`candidate_stale_fragment_lag`) before active-candidate selection, reducing long-lived stale branch holds; policy is wired through storage TOML/env config with validation and regression coverage.
- Added replay-controller stale-pruning observability: block-assembly metrics now export total pruned stale candidates (`replay_controller_stale_candidates_pruned_total`) via metrics reporter output for runtime tuning/diagnostics.
- Added fork-choice hysteresis for replay candidate switching: replay controller now supports configurable minimum score delta for active-candidate switch (`candidate_switch_min_score_delta`) to suppress low-signal flap, with TOML/env policy wiring and observability counter for suppressed switches (`replay_controller_switch_suppressed_total`).
- Added fork-choice publication gating mode for reorg safety: runtime policy can now require a confirmed replay candidate before holding publication on reorg (`hold_requires_confirmed_candidate`), with TOML/env wiring and unit/runtime coverage.
- Strengthened replay candidate confirmation semantics with quality gate: candidate confirmation now depends on both confirmation signal count and configurable max failed-transaction ratio (`candidate_confirmation_max_failed_ratio_bps`), with TOML/env policy wiring and regression coverage.
- Added initial RPC WebSocket subscription path on top of the existing jsonrpsee server: `slotSubscribe/slotUnsubscribe` and `accountSubscribe/accountUnsubscribe` with typed param validation, commitment-aware synthetic notifications, `full_api` gating, and async module-level subscription tests.
- Expanded RPC WebSocket subscription set with `rootSubscribe/rootUnsubscribe`, `signatureSubscribe/signatureUnsubscribe`, `voteSubscribe/voteUnsubscribe`, `blockSubscribe/blockUnsubscribe`, `logsSubscribe/logsUnsubscribe`, `programSubscribe/programUnsubscribe`, and `slotsUpdatesSubscribe/slotsUpdatesUnsubscribe`; refactored WS publish path to a shared `tokio::broadcast` snapshot feed (single producer loop, channel fanout to all subscribers) to avoid per-subscription timers and reduce overhead.
- Moved RPC WS runtime knobs into shared constants crate (`WS_SNAPSHOT_FEED_INTERVAL_MILLIS`, `WS_SNAPSHOT_FEED_CHANNEL_CAPACITY`) to remove magic numbers from subscription transport and keep tuning centralized.
- Hardened WS subscription parameter conformance for `blockSubscribe`/`logsSubscribe`/`programSubscribe`: strict filter/program-id validation with dedicated negative tests and explicit invalid-params rejection paths.
- Split RPC WS subscription implementation into focused submodules (`http/subscriptions.rs` facade + `http/subscriptions/loops.rs` + `http/subscriptions/params.rs`) to keep transport wiring, payload loops, and parameter validation isolated and maintainable.
- Extended `accountSubscribe` WS config semantics with strict `encoding` and `dataSlice` parsing/validation, plus response payload shaping based on selected encoding (`base58`/`base64`/`base64+zstd`/`jsonParsed`) and slice window.
- Extended `logsSubscribe` WS semantics to Solana-style filter model (`all` / `allWithVotes` / `mentions`), with strict validation (`mentions` requires exactly one key) and explicit filter reflection in notification payload.
- Extended `signatureSubscribe` WS config semantics with strict `enableReceivedNotification` parsing and compatibility behavior for `processed` commitment (`"receivedSignature"` notifications when flag is enabled).
- Extended `blockSubscribe` WS config semantics with strict parsing/validation for `encoding`, `transactionDetails`, `showRewards`, and `maxSupportedTransactionVersion`, plus config-aware block payload shaping.
- Extended `programSubscribe` WS config semantics with strict parsing/validation for `encoding`, `dataSlice`, and `filters` (`dataSize` / `memcmp`), plus config-aware account payload shaping and emitted filter-summary reflection.
- Added per-subscription duplicate-suppression in WS loops (slot/status dedup) to avoid repeated notifications on unchanged runtime snapshots and reduce unnecessary transport load.
- Added strict no-params subscription guards for `rootSubscribe` and `slotsUpdatesSubscribe` (unexpected arguments now explicitly rejected with invalid-params semantics).
- Added strict optional-config parsing guards for `slotSubscribe` and `voteSubscribe` (only 0 or 1 object-arg allowed; non-object and extra args are rejected).
- **Wave 9: Stake Program & Sysvar Lifecycle** (2026-02-16):
  - `paradencer-sbpf`: added self-contained stake state types (`StakeState`, `Authorized`, `Lockup`, `Meta`, `Delegation`, `StakeAccount`, `StakeFlags`, `StakeError`) with binary serialization matching consensus format exactly — same circular-dependency pattern as vote program.
  - `paradencer-sbpf`: implemented all 18 real stake program instruction handlers (Initialize, Authorize, DelegateStake, Split, Withdraw, Deactivate, SetLockup, Merge, AuthorizeWithSeed, InitializeChecked, AuthorizeChecked, AuthorizeCheckedWithSeed, SetLockupChecked, GetMinimumDelegation, DeactivateDelinquent, Redelegate, MoveStake, MoveLamports) — authority validation, lockup enforcement, delegation management, rent-exempt checks.
  - `paradencer-consensus`: wired `SysvarCache` into Bank — `Option<Arc<SysvarCache>>` field inherited by child banks.
  - `paradencer-consensus`: `finish_slot()` now updates Clock, SlotHashes, SlotHistory, RecentBlockhashes sysvars per-slot.
  - `paradencer-consensus`: `load_transaction_accounts()` now resolves sysvar accounts from cache before falling back to account database.
  - Added 98 new tests: stake state serde roundtrips, all 18 handler unit tests, stake lifecycle integration (init→delegate→deactivate→withdraw), split/merge cycle, sysvar lifecycle integration (7 Bank+sysvar tests).
  - Total: **117,122 LOC**, **2,199 tests**, 0 failures.
  - Parity estimate: **~25% → ~28%**.
- **Wave 10: Consensus Integration & Epoch Processing** (2026-02-17):
  - `paradencer-sbpf`: fixed VoteState serialize/deserialize to include epoch_credits (was missing entirely, broke reward calculation).
  - `paradencer-consensus`: added `VoteAccountReader` trait and binary parser for extracting real vote credits/commission from vote accounts, replacing hardcoded defaults.
  - `paradencer-consensus`: created `RewardApplicator` — credits computed epoch rewards to accounts via `apply_rewards` (batch) and `apply_partition` (per-slot partitioned distribution).
  - `paradencer-storage`: added `store_published_account` to `AccountDatabase` for protocol-level writes outside transaction flow.
  - `paradencer-consensus`: wired real epoch boundary processing into `Bank.finish_slot()` — feature activation, rewards calculation + immediate vote reward application, leader schedule regeneration.
  - `paradencer-consensus`: added `StakeTracker`, `StakeHistory`, `FeatureSet` (RwLock) fields to Bank with inheritance in `new_from_parent`.
  - `paradencer-consensus`: implemented consensus decision engine (`decide_vote_and_reset`, `execute_decision`, `advance_root`) on `ConsensusCoordinator` — matches Firedancer's tower vote-and-reset pattern with cases for empty tower, same fork, locked out, switch approved/denied.
  - `paradencer-consensus`: connected vote pipeline — `Bank.route_vote_updates()` forwards transaction-extracted vote updates to `ConsensusCoordinator`/`ForkChoice`.
  - Added 35 new tests: binary parser, vote reader, reward application, epoch boundary in Bank, consensus decisions, vote flow integration, end-to-end epoch boundary.
  - Total: **118,706 LOC**, **2,234 tests**, 0 failures.
  - Parity estimate: **~28% → ~33%**.
- **Wave 11: Bank Hash & Lattice Hash — Deterministic State Verification** (2026-02-17):
  - `paradencer-constants`: added lattice hash constants (`LTHASH_VALUE_BYTES`, `LTHASH_ELEMENT_COUNT`) to crypto module.
  - `paradencer-crypto`: added Blake3 XOF (eXtendable Output Function) support for 2048-byte output via `finalize_xof()` and standalone `hash_xof()`.
  - `paradencer-crypto`: created `lthash` module — `LatticeHashValue` type (1024 u16 elements, element-wise wrapping arithmetic) with `add`/`subtract`/`as_bytes`/`from_bytes` operations and compact Debug repr.
  - `paradencer-crypto`: added `hash_account()` — per-account lattice hash via `Blake3_XOF_2048(lamports || data || executable || owner || pubkey)`, zero-lamport accounts excluded.
  - `paradencer-consensus`: added bank-level lattice hash accumulator (`lthash`, `signature_count`, `last_blockhash` fields) with inheritance in `new_from_parent`.
  - `paradencer-consensus`: hooked `update_account_hash()` into `write_accounts()` — subtracts old, adds new account hash on every account modification.
  - `paradencer-consensus`: replaced placeholder `Bank.hash()` (non-deterministic SipHash) with `SHA256(SHA256(prev_bank_hash || sig_count || last_blockhash) || lthash)` — deterministic, Firedancer-compatible bank hash formula.
  - `paradencer-consensus`: wired signature counting into transaction processing and blockhash derivation into `register_tick()`.
  - Added 37 new tests: lthash value operations, account hashing, bank accumulator, deterministic hash, integration (replay determinism, incremental vs recompute, parent-child chain).
  - Total: **119,612 LOC**, **2,271 tests**, 0 failures.
  - Parity estimate: **~33% → ~37%**.
- Topology planner added with declarative stage/link spec and validation.
- External topology loading from TOML is implemented.
- Node config is centralized in a dedicated config module with env parsing + validation.
- Pinned mode now prints explicit service-to-core assignment report.
- Local command runner switched to `justfile`.
- CI for fmt/clippy/test/build exists.

## Implemented Components

### Core
- `ExecutionMode`
- `PinnedCorePolicy`
- `RuntimeSpec`
- `TopologySpec`, `StageSpec`, `LinkSpec`
- topology validation rules
File: `crates/paradencer-core/src/lib.rs`

### Runtime
- `Service` trait
- `ShutdownSwitch`
- `ServiceContext`
- executors: `run_tokio`, `run_pinned`
- pinned-core assignment reporting
- pinned oversubscription policy gate
- pinned-core policy profiles:
  - `strict` (no oversubscription)
  - `shared` (always allow with warning)
  - `adaptive` (allow up to 2.0x oversubscription, then reject)
- typed runtime errors in dedicated file:
  - `crates/paradencer-runtime/src/errors.rs`
File: `crates/paradencer-runtime/src/lib.rs`

### Mesh
- bounded link constructor
- in/out ports
- backpressure and queue counters
- snapshot API for metrics
File: `crates/paradencer-mesh/src/lib.rs`

### Ingress
- ingress frame and prepared transaction domain types
- packet decoder with explicit `DecodeOutcome` and drop reasons
- bounded-window signature deduplicator
- `IngressPolicy` with validation:
  - source allowlist (`quic/gossip/bundle/rpc`)
  - max payload bytes
  - dedup window capacity
- typed ingress errors in dedicated file:
  - `crates/paradencer-ingress/src/errors.rs`
File: `crates/paradencer-ingress/src/lib.rs`

### Execution
- execution batch domain model
- deterministic execution bridge placeholder
- typed execution errors (`ExecutionError`)
- fallible execution API (`try_execute_batch`)
- execution outcome model (executed/failed/cost)
- execution failure classes (`transient pressure`, `replay conflict`, `deterministic`, `resource exhaustion`)
- class-aware retry directives (including drop-fragment path)
- scheduler priority escalation on resource exhaustion
- replay boundary state + fork-choice directive
- leader-gate and scheduler directives
File: `crates/paradencer-execution/src/lib.rs`
Files:
- `crates/paradencer-execution/src/lib.rs`
- `crates/paradencer-execution/src/types.rs`
- `crates/paradencer-execution/src/bridge.rs`
- `crates/paradencer-execution/src/errors.rs`

### Storage
- committed fragment record model
- hot state store with monotonic fragment guard
- snapshot catalog interval trigger
- snapshot image model
- named snapshot restore API + latest snapshot restore API
- restore hot-state from snapshot API
- snapshot catalog JSON persistence API (`persist_to_file`, `load_from_file`, `load_from_file_if_exists`)
- snapshot catalog schema-version validation for persisted format
- snapshot catalog migration path from legacy v0 format (`schema_version=0` or missing)
- typed storage errors in dedicated file:
  - `crates/paradencer-storage/src/errors.rs`
File: `crates/paradencer-storage/src/lib.rs`
Files:
- `crates/paradencer-storage/src/lib.rs`
- `crates/paradencer-storage/src/types.rs`
- `crates/paradencer-storage/src/hot_state.rs`
- `crates/paradencer-storage/src/catalog.rs`
- `crates/paradencer-storage/src/errors.rs`

### Stages
- `EdgeIntake`
- `TxFilter`
- `BlockAssembler`
- `MetricsReporter`
- `TxFilter` now delegates parse+dedup to `paradencer-ingress`
- `TxFilter::with_policy` allows policy-driven filtering behavior
- `MetricsReporter::with_output_format` supports json-lines or prometheus-text output
- shared ingress filter counters:
  - accepted
  - duplicate
  - dropped_empty_payload
  - dropped_oversized_payload
- dropped_disallowed_source
- source-specific accepted/duplicate counters (`quic/gossip/bundle/rpc`)
- block assembler now calls execution bridge for each assembled fragment
- block assembler now commits execution outcome into storage hooks and snapshot trigger
- block assembler restore path now checks latest snapshot during initialization
- block assembler now persists snapshot catalog to file when configured
- block assembler startup now restores fragment/replay counters from snapshot state
- block assembler retry path now executes `defer/retry/drop` behavior (not placeholder ignore)
- block assembler now updates shared telemetry counters for retries/drops/commits
- block assembler now updates telemetry counters for leader-gate and fork-choice directives
- block assembler now applies leader-gate holds with deferred retries based on configurable leader-slot schedule
- block assembler now applies scheduler directive to retry delay computation via configurable scheduler runtime policy
- typed stage errors in dedicated file:
  - `crates/paradencer-stages/src/errors.rs`
File: `crates/paradencer-stages/src/lib.rs`
Files:
- `crates/paradencer-stages/src/lib.rs`
- `crates/paradencer-stages/src/types.rs`
- `crates/paradencer-stages/src/edge_intake.rs`
- `crates/paradencer-stages/src/tx_filter.rs`
- `crates/paradencer-stages/src/block_assembler.rs`
- `crates/paradencer-stages/src/metrics_reporter/mod.rs`
- `crates/paradencer-stages/src/metrics_reporter/format.rs`
- `crates/paradencer-stages/src/metrics_reporter/sink.rs`
- `crates/paradencer-stages/src/testsuite.rs`

### Node
- centralized env-driven runtime config parsing moved into `paradencer-config::NodeConfig`
- topology planning + service materialization
- topology TOML file loading via `PARADENCER_TOPOLOGY_PATH`
- ingress policy env parsing + validation
- ingress policy profile loading (`default <- TOML <- env`)
- node root config profile loading (`default <- node.toml <- env`)
- schema-version validation for node + ingress policy files
- schema migration hooks for node + ingress policy profile versions
- storage catalog path config wiring (`storage.catalog_path` and env override)
- storage retry controls wiring (`storage.max_retry_attempts`, `storage.retry_backoff_cap_millis`)
- leader schedule controls wiring (`storage.leader_*`) with env overrides
- scheduler controls wiring (`storage.scheduler_*`) with env overrides
- fork-choice controls wiring (`storage.fork_choice_*`) with env overrides
- ingress rate-limit controls wiring (`ingress_policy.*_min_gap_ticks`) with env overrides
- ingress burst controls wiring (`ingress_policy.*_burst_*`) with env overrides
- ingress cost-budget controls wiring (`ingress_policy.*_cost_budget_*`) with env overrides
- block-assembly controls wiring (`storage.assembly_*`) with env overrides
- tx-filter egress retry controls wiring (`ingress_policy.egress_retry_*`) with env overrides
- synthetic ingress generator controls wiring (`ingress_policy.synthetic_*`) with env overrides
- stage wiring and launch
Files:
- `crates/paradencer-config/src/lib.rs`
- `crates/paradencer-config/src/errors.rs`
- `crates/paradencer-config/src/parts.rs`
- `crates/paradencer-config/src/profile_loader.rs`
- `crates/paradencer-config/src/profile_schema.rs`
- `crates/paradencer-config/src/profile_types.rs`
- `crates/paradencer-config/src/runtime.rs`
- `crates/paradencer-config/src/topology.rs`
- `crates/paradencer-config/src/ingress.rs`
- `crates/paradencer-config/src/metrics.rs`
- `crates/paradencer-config/src/storage.rs`
- `crates/paradencer-execution/src/types.rs`
- `crates/paradencer-execution/src/bridge.rs`
- `crates/paradencer-stages/src/block_assembler.rs`
- `crates/paradencer-stages/src/types.rs`
- `crates/paradencer-node/src/main.rs`
- `crates/paradencer-node/src/topology.rs`
- `crates/paradencer-node/src/topology_parts.rs`

## Verification Status
- `cargo fmt --all -- --check`: pass
- `cargo clippy --workspace --all-targets -- -D warnings`: pass
- `cargo test --workspace --all-targets`: pass

## Existing Tests
- core topology validation tests
- mesh backpressure and empty receive counters
- ingress decoder/dedup tests
- ingress policy drop-rule tests
- execution bridge determinism test
- execution bridge invalid-empty-batch error test
- execution failure-class/retry/scheduler policy tests
- storage monotonic-commit and snapshot interval tests
- storage snapshot restore and regression tests
- storage snapshot catalog persist/load restart tests
- 3-stage pipeline smoke test
- intake backpressure test
- tx filter duplicate-drop test
- tx filter source-policy test
- metrics reporter file/udp sink tests (success + file-open failure)
- block assembler startup restore tests (`restore_latest` / `restore_specific`)
- block assembler retry behavior tests (`defer`, retry-budget exhaust/drop, deterministic drop)
- block assembler retry runtime-policy tuning test (`max_retry_attempts`, `retry_backoff_cap_millis`)
- block assembler execution-health cooldown tests (enabled/disabled behavior)
- block assembler replay-safety hold tests (enabled/disabled behavior)
- block assembler fork-choice quarantine tests (enabled/disabled behavior)
- block assembler strict startup-restore tests for missing snapshot conditions
- block assembler catalog edge-case tests (malformed startup file, missing persist parent)
- block assembler catalog permission test (non-writable persist parent, unix)
- block assembler truncated-catalog startup test (partial-write corruption shape)
- block assembler restart-recovery test after corrupted catalog is repaired
- block assembler unknown-schema catalog startup test
- block assembler invalid-shape catalog startup test
- storage catalog migration tests (`v0` legacy + unknown version reject)
- metrics reporter test for block-assembly leader/fork telemetry export
- node topology planner/materializer tests
- storage runtime-policy precedence tests for retry knobs (`default`, profile TOML, env override layer)
- storage runtime-policy tests for execution-health profile/env precedence and zero-value validation
- storage runtime-policy tests for replay-safety profile/env precedence and zero-value validation
- storage runtime-policy tests for fork-choice quarantine profile/env precedence and zero-value validation
- storage runtime-policy tests for strict startup-restore profile/env precedence

## Runtime Controls
- `PARADENCER_EXEC_MODE=tokio|pinned`
- `PARADENCER_WORKERS=<N>`
- `PARADENCER_RUN_SECONDS=<N>`
- `PARADENCER_PACKET_LINK_CAPACITY=<N>`
- `PARADENCER_SHRED_LINK_CAPACITY=<N>`
- `PARADENCER_TRANSACTION_LINK_CAPACITY=<N>`
- `PARADENCER_TRANSACTION_SANITIZER_WORKERS=<N>`
- `PARADENCER_SHRED_SANITIZER_WORKERS=<N>`
- `PARADENCER_PINNED_ALLOW_CORE_SHARING=true|false`
- `PARADENCER_PINNED_CORE_POLICY=strict|shared|adaptive`
- `PARADENCER_TOPOLOGY_PATH=<path-to-topology.toml>`
- `PARADENCER_NODE_CONFIG_PATH=<path-to-node-config.toml>`
- `PARADENCER_INGRESS_MAX_PAYLOAD_BYTES=<N>`
- `PARADENCER_INGRESS_ALLOW_QUIC=true|false`
- `PARADENCER_INGRESS_ALLOW_GOSSIP=true|false`
- `PARADENCER_INGRESS_ALLOW_BUNDLE=true|false`
- `PARADENCER_INGRESS_ALLOW_RPC=true|false`
- `PARADENCER_INGRESS_DEDUP_WINDOW=<N>`
- `PARADENCER_INGRESS_POLICY_PATH=<path-to-ingress-policy.toml>`
- `PARADENCER_METRICS_FORMAT=json|json_lines|prometheus|prometheus_text`
- `PARADENCER_METRICS_TARGET=stdout|file|udp`
- `PARADENCER_METRICS_FILE_PATH=<path>` (required when target is `file`)
- `PARADENCER_METRICS_UDP_ADDR=<host:port>` (required when target is `udp`)
- `PARADENCER_METRICS_HTTP_BIND=<host:port>` (requires metrics target `file`)
- `PARADENCER_RPC_ENABLED=true|false`
- `PARADENCER_RPC_BIND=<host:port>` (required when `PARADENCER_RPC_ENABLED=true`)
- `PARADENCER_RPC_PRIVATE=true|false`
- `PARADENCER_RPC_FULL_API=true|false`
- `PARADENCER_STORAGE_STARTUP_POLICY=skip_restore|restore_latest|restore_specific`
- `PARADENCER_STORAGE_RESTORE_FRAGMENT_ID=<u64>` (required for `restore_specific`)
- `PARADENCER_STORAGE_SNAPSHOT_INTERVAL=<u64>` (must be > 0)
- `PARADENCER_STORAGE_SNAPSHOT_MAX_CATALOG_ENTRIES=<usize>` (must be > 0)
- `PARADENCER_STORAGE_CATALOG_PATH=<path-to-snapshot-catalog.json>`
- `PARADENCER_STORAGE_MAX_RETRY_ATTEMPTS=<u8>` (must be > 0)
- `PARADENCER_STORAGE_RETRY_BACKOFF_CAP_MILLIS=<u64>` (must be > 0)
- `PARADENCER_STORAGE_EXECUTION_ENGINE_POLICY=heuristic|runtime_like`
- `PARADENCER_STORAGE_EXECUTION_ERROR_HANDLING_POLICY=fail_open|fail_fast`
- `PARADENCER_STORAGE_EXECUTION_ERROR_FAIL_OPEN_MAX_CONSECUTIVE=<u32>` (`0` disables circuit breaker)
- `PARADENCER_READINESS_REQUIRE_FAIL_FAST_EXECUTION_ERRORS=true|false`
- `PARADENCER_READINESS_REQUIRE_FAIL_OPEN_EXECUTION_ERROR_CIRCUIT_BREAKER=true|false`
- `PARADENCER_EXEC_RETRY_REPLAY_CONFLICT_DELAY_MILLIS=<u64>` (must be > 0)
- `PARADENCER_EXEC_RETRY_TRANSIENT_BASE_DELAY_MILLIS=<u64>` (must be > 0)
- `PARADENCER_EXEC_RETRY_TRANSIENT_PER_FAILED_TX_DELAY_MILLIS=<u64>` (must be > 0)
- `PARADENCER_EXEC_RETRY_TRANSIENT_CAP_MILLIS=<u64>` (must be > 0)
- `PARADENCER_EXEC_RETRY_RESOURCE_BASE_DELAY_MILLIS=<u64>` (must be > 0)
- `PARADENCER_EXEC_RETRY_RESOURCE_PER_FAILED_TX_DELAY_MILLIS=<u64>` (must be > 0)
- `PARADENCER_EXEC_RETRY_RESOURCE_CAP_MILLIS=<u64>` (must be > 0)
- `PARADENCER_EXEC_RETRY_FALLBACK_MIN_DELAY_MILLIS=<u64>` (must be > 0)
- `PARADENCER_EXEC_RETRY_FALLBACK_PER_FAILED_TX_DELAY_MILLIS=<u64>` (must be > 0)
- `PARADENCER_STORAGE_EXECUTION_HEALTH_ENABLED=true|false`
- `PARADENCER_STORAGE_EXECUTION_HEALTH_TRANSIENT_FAILURE_THRESHOLD=<u32>` (must be > 0)
- `PARADENCER_STORAGE_EXECUTION_HEALTH_COOLDOWN_TICKS=<u32>` (must be > 0)
- `PARADENCER_STORAGE_REPLAY_SAFETY_ENABLED=true|false`
- `PARADENCER_STORAGE_REPLAY_SAFETY_CONFLICT_THRESHOLD=<u32>` (must be > 0)
- `PARADENCER_STORAGE_REPLAY_SAFETY_HOLD_TICKS=<u32>` (must be > 0)
- `PARADENCER_STORAGE_REPLAY_CONTROLLER_CANDIDATE_CONFIRMATION_THRESHOLD=<u32>` (must be > 0)
- `PARADENCER_STORAGE_REPLAY_CONTROLLER_MAX_CANDIDATES=<usize>` (must be > 0)
- `PARADENCER_STORAGE_REPLAY_CONTROLLER_REORG_SIGNAL_WEIGHT=<u64>` (must be > 0)
- `PARADENCER_STORAGE_REPLAY_CONTROLLER_FRAGMENT_RECENCY_WEIGHT=<u64>` (must be > 0)
- `PARADENCER_STORAGE_REPLAY_WINDOW_MAX_CHECKPOINTS=<usize>` (must be > 0)
- `PARADENCER_STORAGE_REPLAY_WINDOW_REWIND_ON_CONFIRMED_REORG=true|false`
- `PARADENCER_STORAGE_FORK_CHOICE_QUARANTINE_ENABLED=true|false`
- `PARADENCER_STORAGE_FORK_CHOICE_QUARANTINE_CONSECUTIVE_REORG_THRESHOLD=<u32>` (must be > 0)
- `PARADENCER_STORAGE_FORK_CHOICE_QUARANTINE_TICKS=<u32>` (must be > 0)
- `PARADENCER_STORAGE_STARTUP_STRICT_RESTORE_LATEST_REQUIRES_SNAPSHOT=true|false`
- `PARADENCER_STORAGE_STARTUP_STRICT_RESTORE_SPECIFIC_REQUIRES_SNAPSHOT=true|false`

## Decisions Log
1. Channels are used only on stage boundaries where ownership transfer/backpressure are needed.
2. Compute-heavy internals should avoid extra channels unless correctness requires them.
3. Naming policy: descriptive Rust-native naming, no source-name mirroring.
4. Topology is declared first, then materialized into concrete services.

## Next Steps (Priority)
1. Continue targeted split/cleanup for remaining shared config surface (facade organization/tests grouping).
2. Expand persistence fault-path coverage with additional corruption variants and mixed-recovery sequences.
3. Continue moving large Firedancer subsystems (network/replay/bank/funk-equivalent) crate-by-crate while preserving behavior contracts.
4. Keep `docs/04_module_residual_matrix.md` synchronized after each substantial subsystem move.

## Tracking Files
- Plan: `docs/03_paradencer_implementation_plan.md`
- Module mapping: `docs/90_module_mapping_working.md`
- Rewrite rules: `docs/91_naming_and_rewrite_rules.md`
