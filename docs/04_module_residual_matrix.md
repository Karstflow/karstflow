# Paradencer Module Residual Matrix

Last update: 2026-02-16

Purpose:
- фиксировать остатки по каждому модулю/крейту;
- отделять "каркас готов" от "логика Firedancer перенесена";
- держать приоритетный backlog в одном месте.

Status legend:
- `done` - блок закрыт для текущей итерации (может потребовать future hardening)
- `partial` - есть рабочая версия, но без полной parity
- `not_started` - существенная часть не начата

## Module-by-Module Residuals

| Module / Area | Current status | Done now | Residual (what is missing) | Priority |
|---|---|---|---|---|
| `paradencer-core` | `partial` | Базовые domain-типы, topology validation | Более строгие протокольные контракты, расширенные domain invariants | High |
| `paradencer-consensus` | `partial` | Bank state machine (slot progression, tick counting, freeze/root lifecycle), BankForks (fork tree management, ancestry tracking, root progression), EpochSchedule (epoch boundaries, slot→epoch mapping, warmup support), LeaderSchedule (deterministic stake-weighted leader rotation), SlotInfo metadata, **Bank execution pipeline** (`ExecutionBackend` trait, `process_transaction`/`process_transactions`, account load/writeback, fee validation/collection), **Bank lifecycle** (rent collection, slot finish with fee distribution + epoch boundary hooks), **Transaction pack/scheduler** (priority queue with eviction, write-lock conflict detection, microblock scheduling with vote preference, block resource tracking), **Sysvar lifecycle** (SysvarCache wired into Bank, per-slot updates for Clock/SlotHashes/SlotHistory/RecentBlockhashes in finish_slot(), sysvar account resolution in load_transaction_accounts(), epoch boundary stake history updates, child bank sysvar inheritance), **Epoch boundary processing** (real rewards calculation via VoteAccountReader + binary parser, immediate vote reward application via RewardApplicator, partitioned stake distribution via RewardsDistributor, feature activation via FeatureSet, leader schedule regeneration, StakeTracker/StakeHistory/FeatureSet state in Bank with RwLock + parent inheritance), **Consensus decision engine** (decide_vote_and_reset: empty tower/same fork/lockout/switch approved/denied, execute_decision + advance_root coordination across tower+fork_choice+votes), **Vote flow wiring** (Bank.route_vote_updates forwards transaction-extracted VoteUpdates to ConsensusCoordinator) | Full optimistic confirmation pipeline, partitioned rent collection, gossip-based vote propagation, PoH integration | Critical |
| `paradencer-runtime` | `partial` | `tokio/pinned`, lifecycle, affinity policy | Более близкая tile/core scheduling semantics, OS-level tuning surface, production perf guards | High |
| `paradencer-mesh` | `partial` | Bounded channels, counters, snapshots | Более точная модель очередей/flows под high-throughput и long-run soak behavior | Medium |
| `paradencer-ingress` | `partial` | Decode/dedup/policy/limiters, UDP mode, QUIC networking stack (QuicConfig/QuicEndpoint/QuicStream/QuicPacket with TLS self-signed certs), QuicProcessor integration with decoder/dedup/rate-limiter/cost-limiter | Deeper packet pipeline parity, repair/retransmit-adjacent semantics | High |
| `paradencer-execution` | `partial` | Execution bridge + failure classes + retry directives + class-aware retry budgets (`RetryPolicy` per failure class) + pluggable execution engine boundary (`ExecutionEngine`) with default heuristic engine and bridge-level engine injection hooks + config/runtime policy selection path for execution engine (`storage.execution_engine_policy` / `PARADENCER_STORAGE_EXECUTION_ENGINE_POLICY`) + runtime-like execution scaffold (`RuntimeLikeExecutionEngine`) with dedicated adapter module and explicit hook contracts for state/accounts/program-cache (`RuntimeBatchContext`, `RuntimePreflightOutcome`, `RuntimeExecutionObservation`, `RuntimeStateWriteIntent`, `AccountAccessPattern`, `ProgramCacheHint`) + checked-overflow runtime batch-context construction (no saturating fallback for context sizing) + overflow-safe runtime failure-scaling helper for large batch-size ratios (`usize` scale-floor path without direct multiply overflow) + execution-effects summaries (`RuntimeExecutionEffects`, account/program-cache delta summaries) + strict effects-summary contract validation before apply (account/program-cache consistency and refresh-intent conformance) + strict effects-plan contract validation before apply (plan-target bounds, strict full-coverage requirement, rollback-on-error requirement for commit-candidate plans, embedded-effects identity check) + phased effects lifecycle (`prepare/apply/rollback` hooks with `RuntimeEffectsPlan`/`RuntimeApplyReport`) + channel-level effects plans/reports for account/program-cache subflows (`RuntimeEffectsChannelsPlan`, `RuntimeEffectsChannelsApplyReport`) + channel apply policy hooks (`strict`/`lenient`) with adapter-level policy selection override + storage-backed runtime adapter path with runtime-state apply/rollback receipts (`StorageBackedRuntimeAdapter`) + adapter-local pre-store plan-contract validation in storage-backed apply path (strict full-coverage and target-bound checks even if runtime-like layer is bypassed) + adapter-local apply-policy match validation in storage-backed apply path (plan policies must match adapter-configured channel policies) + adapter-local rollback-policy match validation in storage-backed rollback path (plan policies must match adapter-configured channel policies, with rollback receipt-retention regression coverage after policy reject) + adapter-local context/preflight coherence checks in storage-backed apply/rollback paths (access-pattern consistency and non-empty ColdPath refresh-intent consistency, including rollback receipt-retention regression coverage after reject and symmetric apply/rollback mismatch tests) + adapter-local preflight-intent validation in storage-backed apply path (commit-candidate + fragment match + rollback-required, with explicit mismatch regression coverage) + adapter-local rollback-contract validation in storage-backed rollback path (commit-candidate + fragment match + rollback-required, with rollback receipt-retention regression coverage after contract reject) + adapter-local effects-consistency validation in storage-backed apply/rollback paths (account-write/rent consistency and refresh-gated invalidation checks, with rollback receipt-retention regression coverage after contract reject) + adapter-local empty-batch guards in storage-backed apply/rollback paths (direct zero-tx calls are rejected) + adapter-local non-empty preflight-budget guard in storage-backed apply/rollback paths (`preflight.total_cost_units > 0` required for non-empty batches) + checked-overflow safety for program-cache aggregate counters (`applied_program_cache_ops`) across adapter apply and runtime-like apply-report validation paths + stricter adapter/state invariants (pending-receipt lifecycle, typed adapter state/mutex errors, monotonic apply + LIFO rollback contract coverage, retained-receipt rollback correctness for post-apply validation failures, stale-receipt pruning on newer apply, explicit reject of out-of-order apply when newer pending receipt exists, pending receipt removal only after successful store rollback, pending-lock held through rollback+remove to prevent mid-rollback prune races) + strict rollback receipt/plan coherence checks in storage-backed adapter (rollback apply-totals derived from plan must exactly match stored runtime-state receipt; mismatch rejects without consuming rollback receipt) + runtime-like rollback error chaining (rollback-failure paths now retain prior apply/apply-report root-cause context in typed rollback errors) + explicit saturating conversion helpers for execution-side numeric casts (`usize/u128` to bounded targets) replacing implicit `unwrap_or(MAX)` paths + runtime-like preflight context/access-pattern coherence checks (`ReadMostly` rejected when context implies mixed-write access) + runtime-like preflight ColdPath refresh-intent checks (`requires_program_cache_refresh` required when context hint is `ColdPath` for non-empty batches) + runtime-like empty-batch strict preflight/observation invariants (ReadMostly, no refresh intent, zero contention, no failure class) + empty-batch no-write invariant (`RuntimeStateWriteIntent::None` skips effects apply/rollback and prevents runtime-state fragment advancement on zero-transaction ticks) + strict runtime preflight/observation contract bounds (non-empty preflight budget must be non-zero; empty preflight budget must be zero; `failed_transactions <= batch.transaction_count`; `consumed_compute_units <= preflight.total_cost_units`; contention ratio bps in `[0, 10_000]`; consistent failure-class attribution for zero/non-zero failed-tx cases) + execution-bridge outcome normalization invariant (batch fragment-id authority + clamped failed-count + recomputed executed-count + invalid failure-class combo normalization for custom engines + non-zero cost-budget normalization for non-empty batches in both success and error-fallback paths) + explicit adapter contract-violation surface (`AdapterContractViolation`) with runtime-like preflight intent consistency checks, apply-report contract validation (aggregate/channel coherence + target/policy conformance), rollback-on-post-apply-validation-failure behavior, and deterministic bridge classification + bridge-level typed error-to-failure-class mapping for retry/fork-choice paths + class-aware fallback failed-tx semantics (`replay_conflict` as non-transactional conflict) + retry-invariant fix for class-driven replay-conflict backoff when fallback failed-tx count is zero | Реальный SVM/sBPF execution path, deterministic execution parity, full accounts/program cache integration depth | Critical |
| `paradencer-storage` | `partial` | Hot-state, snapshot catalog, checksum/invariant checks, retention + runtime-state apply/rollback store for execution effects (`RuntimeStateStore`) with typed receipts/snapshots and strict monotonic + rollback-order guards + checked counter-overflow detection (`StateCounterOverflow`) for hot-state/runtime-state accumulators (no silent saturating wrap) + atomic apply semantics on overflow paths (no partial state mutation before overflow rejection) + checked `usize -> u64` counter conversions in hot-state/runtime-state paths (no direct cast-based truncation risk on wider-pointer targets) + **account database with funk-inspired transaction/fork model** (`AccountDatabase` with versioned records, copy-on-write semantics, publish/cancel transaction lifecycle, concurrent access via DashMap) + **account primitives** (custom `Pubkey`, `Account`, `AccountMeta`, `AccountData` without solana-sdk dependencies) + **transaction types** (`Transaction`, `Instruction`, `Signature`, `AccountRef` with read/write mode tracking) + **transaction processor** (`TransactionProcessor` with account loading, simulated execution, writeback to database, batch processing support) | Real SVM/sBPF execution integration, full accounts state lifecycle with rent/compute budget enforcement, catch-up/restore pipeline depth, snapshot network download/verification | Critical |
| `paradencer-stages` | `partial` | Intake/filter/assembler/metrics + replay/fork-choice scaffolding + class-aware retry budget enforcement in block assembly + replay candidate stale-pruning policy + fork-choice switch hysteresis + confirmed-only reorg hold option + failed-ratio-gated candidate confirmation + runtime-like execution policy path wired to storage-backed adapter by default + runtime-like channel apply policies (`strict/lenient`) plumbed from storage policy to adapter + execution error-path telemetry + configurable execution error handling mode (`fail_open` / `fail_fast`) with stage-level integration coverage via injected execution bridge + configurable fail-open circuit-breaker (`execution_error_fail_open_max_consecutive`) | Полный набор full-client stage logic (bank/vote/repair/snapshot services), deeper replay semantics | Critical |
| `paradencer-topology` | `partial` | Planner + loader + strict lane validations + materialization helpers | Расширение topology map под недостающие full-client сервисы и их constraints | High |
| `paradencer-config` | `partial` | Typed config, env/profile precedence, readiness/preflight checks + execution retry-class policy wiring (`TOML`/`ENV`) + replay controller stale-lag/hysteresis/quality-gate policy wiring + fork-choice confirmed-hold policy wiring + runtime-like channel apply policy wiring (`strict/lenient`) + execution error handling policy wiring (`fail_open` / `fail_fast`) + readiness guard wiring for fail-fast execution errors (`readiness.require_fail_fast_execution_errors`) + fail-open circuit-breaker policy wiring (`execution_error_fail_open_max_consecutive`) + readiness guard wiring for fail-open circuit breaker presence (`readiness.require_fail_open_execution_error_circuit_breaker`) | Конфиги для недостающих больших подсистем (execution real runtime, rpc, snapshot networking) | High |
| `paradencer-control` | `partial` | CLI dispatch, diagnostics/preflight/readiness output + config summary includes runtime-like apply-policy diagnostics and execution error handling policy for storage execution path + readiness check for fail-fast execution-error mode | Production-grade operator workflows/runbooks, richer failure triage/reporting | Medium |
| `paradencer-rpc` | `partial` | JSON-RPC HTTP bootstrap (`getHealth`, `getVersion`, `getSlot`, `getBlockHeight`, `getBlockCount`, `getTransactionCount`, `getLatestBlockhash`, `getRecentBlockhash`, `getFees`, `getFeeCalculatorForBlockhash`, `isBlockhashValid`, `getFeeForMessage`, `getGenesisHash`, `getBalance`, `getIdentity`, `getEpochSchedule`, `getMinimumBalanceForRentExemption`, `getStakeMinimumDelegation`, `getSlotLeader`, `getSlotLeaders`, `getEpochInfo`, `getFirstAvailableBlock`, `minimumLedgerSlot`, `getMaxShredInsertSlot`, `getHighestSnapshotSlot`, `getMaxRetransmitSlot`, `getRecentPerformanceSamples`, `getSignaturesForAddress`, `getConfirmedSignaturesForAddress2`, `getClusterNodes`, `getVoteAccounts`, `getSupply`, `getTokenSupply`, `getTokenAccountBalance`, `getLargestAccounts`, `getTokenLargestAccounts`, `getProgramAccounts`, `getTokenAccountsByOwner`, `getTokenAccountsByDelegate`, `getInflationGovernor`, `getInflationRate`, `getInflationReward`, `getAccountInfo`, `getMultipleAccounts`, `getSignatureStatuses`, `getLeaderSchedule`, `getBlockProduction`, `getRecentPrioritizationFees`, `getBlocks`, `getBlocksWithLimit`, `getBlockCommitment`, `getBlock`, `getConfirmedBlock`, `getConfirmedBlocks`, `getBlockTime`, `getTransaction`, `getConfirmedTransaction`, `sendTransaction`, `simulateTransaction`) + WebSocket subscriptions (`slot`, `account`, `root`, `signature`, `vote`, `block`, `logs`, `program`, `slotsUpdates` + unsubs) + WS internals split into focused modules (`subscriptions.rs` facade + `subscriptions/loops.rs` + `subscriptions/params.rs`) + shared broadcast snapshot feed for WS fanout + per-subscription duplicate-notification suppression + centralized WS tuning constants (`WS_SNAPSHOT_FEED_INTERVAL_MILLIS`, `WS_SNAPSHOT_FEED_CHANNEL_CAPACITY`) + strict WS param conformance checks (`root/slotsUpdates` strict no-params, `slot/vote` strict optional single-object config parsing, `block` filter + `encoding`/`transactionDetails`/`showRewards`/`maxSupportedTransactionVersion`, `logs` filter model: `all`/`allWithVotes`/single `mentions`, `program` config: `encoding`/`dataSlice`/`filters(dataSize|memcmp)`, non-empty `program` id, `account` encoding + strict `dataSlice` validation, `signature` received-notification flag validation, strict unknown-key rejection for subscription config and nested WS filter objects) + HTTP/renderer strict params-shape conformance (non-array `params` rejected with `-32602`, no silent fallback to empty params) + strict JSON-RPC envelope conformance (`-32600` for non-object request, non-`2.0` version, non-string method) + strict JSON-RPC id-shape conformance (`id` must be `string|integer-number|null`, invalid/drobnye ids return `-32600` with `id:null`) + strict JSON-RPC method-name envelope conformance (reject empty method and reserved `rpc.*` namespace as `-32600`) + stricter id-less invalid-envelope handling (`invalid request` returns with `id:null`, valid notifications remain no-response) + renderer-level JSON-RPC batch/notification conformance (empty-batch invalid-request, mixed batch response shaping, notification no-response semantics) + centralized transaction-RPC numeric policy constants in `paradencer-constants::rpc` (send/simulate shaping and limits) + config/env wiring + runtime snapshot provider boundary (`RuntimeSnapshotProvider`) + typed method registry/resolver (`RpcMethod`, `resolve_method`, `requires_full_api`) + typed method errors (`RpcMethodError`) + domain method modules (`methods/*`, including dedicated `transactions.rs`) + centralized dispatch mapping + params validation + strict global commitment validation + strengthened ledger/history/basic/accounts/cluster `minContextSlot` guardrails (including slot/height/count/vote-accounts/supply/token-largest/schedule/production/fees/signature-status paths) + stricter signatures-history pagination semantics (`before`/`until`) + stricter signature-status config/nullable semantics + stricter performance-sample limit validation + strict `getBlocksWithLimit` range validation | Расширить до целевого метода-сета и history semantics; добавить production-grade error/data model для full response payloads; расширить websocket/subscription method set и deep RPC conformance tests | High |
| `paradencer-observability` | `partial` | Metrics HTTP bridge transport + replay stale-pruning telemetry export (`replay_controller_stale_candidates_pruned_total`) + hysteresis suppression metric (`replay_controller_switch_suppressed_total`) + execution error-path telemetry export (`execution_error_*` counters) + execution-error policy action counters (`execution_error_fail_open_continue_total`, `execution_error_fail_fast_halt_total`) + fail-open circuit-breaker halt counter (`execution_error_fail_open_circuit_breaker_halt_total`) + current execution-error streak gauge (`execution_error_consecutive_current`) + adapter-contract telemetry counter (`execution_error_adapter_contract_violation_total`) + retry-cause counters for scheduled retries (`retry_scheduled_replay_conflict_total`, `retry_scheduled_transient_pressure_total`, `retry_scheduled_resource_exhaustion_total`, `retry_scheduled_fallback_total`) + execution-driven drop-cause counters (`dropped_replay_conflict_total`, `dropped_deterministic_total`, `dropped_transient_pressure_total`, `dropped_resource_exhaustion_total`, `dropped_fallback_total`) | Расширенные метрики/alerts для execution/storage/replay parity-paths | Medium |
| `paradencer-node` | `partial` | Thin orchestration wrapper | Интеграция новых крупных подсистем по мере переноса логики | High |

## Incremental Hardening — Wave 5 (2026-02-16)

- **Test stabilization**: Fixed 20 test failures and ~45 compilation errors across 6 crates (consensus, rpc, types, crypto, ingress, stages). Full suite: 1991 tests, 0 failures.
- `paradencer-consensus`: added `ExecutionBackend` trait for pluggable instruction execution — keeps consensus independent of `paradencer-sbpf`. Added `SanitizedTransaction`, `CompiledInstruction`, `TransactionExecutionResult`, `BatchExecutionSummary` types.
- `paradencer-consensus`: added `Bank::process_transaction()` — full pipeline: bank state check → load accounts → validate fee → debit payer → execute instructions → write accounts → collect fees → update count.
- `paradencer-consensus`: added `Bank::process_transactions()` — batch sequential execution with per-transaction results.
- `paradencer-consensus`: added `Bank::collect_rent()` — iterates published accounts, calculates rent, deducts from non-exempt, burns configured percentage.
- `paradencer-consensus`: added `Bank::finish_slot()` — combines fee distribution, rent collection, and epoch boundary processing into single end-of-slot hook.
- `paradencer-consensus`: added `pack` module — transaction packing and block scheduling engine:
  - `PriorityQueue`: fixed-capacity max-heap with vote/non-vote separation, lowest-priority eviction, expiration support, FIFO tiebreaking.
  - `BlockScheduler`: write-lock conflict detection (write-write and read-write), vote-first scheduling with configurable vote fraction, per-account write cost tracking, block CU/data-bytes limit enforcement, lock release on completion.
  - `TransactionPack`: top-level API combining queue + scheduler for microblock production.
- `paradencer-storage`: added `AccountDatabase::get()` and `AccountDatabase::store()` convenience methods for direct published-state access (bypasses MVCC).
- `paradencer-constants`: added pack/scheduler constants in `block_limits` module (`MAX_DATA_BYTES_PER_BLOCK`, `PACK_FEE_PER_SIGNATURE`, `DEFAULT_PENDING_POOL_CAPACITY`, `MAX_PENDING_TRANSACTION_AGE_SLOTS`).
- `paradencer-ingress`: fixed `NodeId::random()` collision (atomic counter + thread ID instead of `Instant::now().elapsed()`).
- `paradencer-ingress`: fixed turbine layer distribution (fair-share round-robin instead of greedy sequential).
- `paradencer-stages`: fixed block_producer `try_recv` infinite loop, ancestry_verifier genesis cycle detection, fork detector sibling false positives, vote switch threshold tests, PerformanceMonitor complete_slot timing.
- Total parity estimate: **~22% → ~25%**.

## Incremental Hardening (2026-02-15)

- `paradencer-storage`: added funk-inspired account database (`AccountDatabase`) with versioned records, copy-on-write semantics, transaction/fork model (publish/cancel), concurrent access via DashMap.
- `paradencer-storage`: added custom account primitives (`Pubkey`, `Account`, `AccountMeta`, `AccountData`) without solana-sdk dependencies for maximum performance and control.
- `paradencer-storage`: added transaction types (`Transaction`, `Instruction`, `Signature`, `AccountRef`) with read/write mode tracking for account access patterns.
- `paradencer-storage`: added sBPF execution boundary (`SbpfVm` trait, `ExecutionContext`, `ExecutionOutcome`) with stub implementation (`StubSbpfVm`) for System program and generic program execution with compute budget tracking.
- `paradencer-storage`: full System Program executor implementation (`SystemProgramExecutor`) with instructions: CreateAccount (with validation: lamports check, empty target, space allocation), Assign (with owner validation), Transfer (with balance checks), Allocate (with data allocation), stubs for CreateAccountWithSeed/Nonce/Seeded instructions.
- `paradencer-storage`: sBPF VM integration with `TransactionProcessor` — real instruction execution through VM instead of simulation, execution outcome handling, modified accounts writeback, early exit on failed instructions.
- `paradencer-storage`: extended `Pubkey` primitives (`system_program()`, `new_unique()` for tests).
- `paradencer-constants`: added `execution` module with compute unit constants (`MAX_COMPUTE_UNITS`, `DEFAULT_INSTRUCTION_BASE_COST`, cost per account/data/writeback).
- `paradencer-constants`: added `quic` module with all QUIC-related constants (connection limits, stream limits, MTU, packet sizes, buffer capacities, batch sizes) following constants centralization policy.
- `paradencer-execution`: integrated `AccountBackedExecutionEngine` with execution bridge through `ExecutionStateController` and `RuntimeExecutionAdapter` traits.
- `paradencer-ingress`: added full QUIC networking stack implementation (`QuicConfig`, `QuicEndpoint`, `QuicStream`, `QuicPacket`, `QuicPacketBatch`) with quinn/rustls TLS, self-signed certificate generation via rcgen, connection/stream lifecycle management, stats tracking.
- `paradencer-ingress`: added `QuicProcessor` — integrates QUIC packets with existing ingress pipeline (PacketDecoder, SignatureDeduplicator, SourceRateLimiter, SourceCostBudgetLimiter) with content-based packet ID hashing for deduplication, tick-based rate/cost limiting, comprehensive stats tracking (received, accepted, dropped by reason), batch processing support.
- `paradencer-ingress`: QUIC data flow: `QuicEndpoint` → `QuicStream` reads packets → `QuicPacket` sent via channel → `QuicProcessor.process_packet()` → content-hash packet_id → decoder → rate limiter → cost limiter → deduplicator → `PreparedTransaction` ready for execution pipeline.
- **`paradencer-consensus`** (NEW CRATE): architectural separation of consensus protocol logic from storage layer, following Firedancer's clean module boundaries.
- `paradencer-consensus`: added `Bank` state machine — slot progression with tick counting (64 ticks per slot), parent hash linking for fork tree, Processing → Frozen → Rooted lifecycle, transaction/tick registration, leader lookup for current slot.
- `paradencer-consensus`: added `EpochSchedule` — epoch→slot arithmetic with warmup support (exponential growth for early epochs), slot→epoch mapping, leader schedule epoch calculation with slot offset.
- `paradencer-consensus`: added `LeaderSchedule` — deterministic stake-weighted leader rotation, proportional slot distribution based on validator stake, consistent schedule generation per epoch via seed hashing.
- `paradencer-consensus`: added `SlotInfo` metadata structure for slot/epoch/slot_index/ticks_per_slot tracking.
- `paradencer-consensus`: added `BankForks` — fork tree management with ancestry tracking, root progression, working bank selection, orphan rejection, automatic pruning on root advancement, descendant enumeration for fork choice integration.
- `paradencer-constants`: added `ledger` module constants (`TICKS_PER_SLOT`, `DEFAULT_TICKS_PER_SECOND`, `DEFAULT_MS_PER_SLOT`, `GENESIS_EPOCH`, `GENESIS_SLOT`).
- `paradencer-constants`: added `consensus` module constants (`MAX_VALIDATORS_IN_SCHEDULE`, `LEADER_SCHEDULE_SLOT_OFFSET`, `VOTE_THRESHOLD_SIZE`, `SWITCH_FORK_THRESHOLD`, `MAX_LOCKOUT_HISTORY`, `VOTE_THRESHOLD_DEPTH`).
- `paradencer-storage`: all new components covered by unit + integration tests (56 passing tests total: +3 system_program unit tests, +3 integration end-to-end tests, +4 VM tests).
- `paradencer-ingress`: all QUIC components covered by tests (17 tests passing: QuicProcessor 5 tests including dedup verification, QuicEndpoint/QuicStream tested via integration).
- `paradencer-consensus`: all consensus components covered by unit tests (29 tests passing: Bank 9 tests, EpochSchedule 6 tests, LeaderSchedule 6 tests, BankForks 8 tests including ancestry/pruning/root advancement).
- Storage/accounts migrated percentage increased from 8% to 25% (contribution: 1.0% → 3.0%).
- Execution runtime migrated percentage increased from 6% to 10% (contribution: 1.4% → 2.4%).
- **Ingress/networking migrated percentage increased from ~5% to ~15%** (QUIC stack implementation covers significant portion of Firedancer's QUIC ingress logic, which represents ~18% of Firedancer total logic weight; contribution: 0.6% → 1.8%).
- **Consensus/Bank migrated percentage increased from 0% to ~20%** (Bank state machine, epoch/leader schedules cover foundational consensus protocol logic, which represents ~15% of Firedancer total logic weight; contribution: 0% → 3.0%).
- Total Firedancer parity estimate updated: **~21%** (was ~18%).

## Incremental Hardening (2026-02-14)

- `paradencer-execution`: введён общий internal-модуль `numeric` для saturating/checked conversion helper-функций (`usize/u128 -> u64/usize`) вместо дублирования helper-логики в `engine/*` и `bridge/*`.
- `paradencer-execution`: runtime-like scaling path очищен от прямого `as u128` в пользу общего saturating helper-а; добавлены unit-тесты на boundary-поведение numeric-конверсий.
- `paradencer-stages`: добавлен startup regression-тест для `runtime_like + restore_latest`, фиксирующий инвариант post-restore fragment progression (следующий коммит после restore идёт с `restored_fragment_id + 1` без drift).
- `paradencer-ingress`: усилен source cost-budget limiter — overflow в окне затрат теперь явно отклоняется (`checked_add` reject), добавлен regression-тест overflow-path.
- `paradencer-stages`: устранён startup restore drift по slot/leader state — `slot_pipeline.current_slot` и `leader_gate_state.next_leader_slot` теперь seed'ятся от `max(initial_slot, restored_fragment_id)`; добавлены regression-тесты на restore-checkpoint и initial-slot floor.
- `paradencer-stages`: добавлен checked overflow guard для `fragment_counter` при сборке фрагмента (`checked_add` + runtime error), чтобы исключить wraparound в long-run сценариях; покрыто regression-тестом.
- `paradencer-stages`: исправлена startup-consistency метрика replay-window depth — gauge теперь инициализируется от seed'нутого `bank_timeline` сразу после restore (`restore_latest`/`restore_specific`), добавлены regression-assertions.
- `paradencer-stages`: устранён confirmed-reorg rewind drift по slot pipeline — вместе с `fragment_counter/hot_state/replay_boundary/snapshot_catalog` теперь откатывается и `slot_pipeline.current_slot` до checkpoint; добавлен regression-assert на runtime path.
- `paradencer-stages`: устранён confirmed-reorg rewind drift по leader scheduler state — `leader_gate_state.next_leader_slot` теперь также откатывается до checkpoint, чтобы scheduler directives не опережали rewound chain state; добавлен regression-assert.
- `paradencer-stages`: добавлена floor-semantics на confirmed-reorg rewind для slot/scheduler state — rewind now uses `max(checkpoint.fragment_id, leader.initial_slot)`; добавлен regression-тест на policy с высоким `initial_slot`.
- `paradencer-execution`: усилен rewind barrier-контракт storage-backed adapter — `rewind_to_fragment` теперь очищает весь pending receipt set (вместо частичного retain), исключая stale rollback eligibility после reorg rewind; тест расширен проверками `AdapterReceiptMissing` для target и newer fragment rollback после rewind.
- `paradencer-execution`: добавлен regression на post-rewind forward progress — после barrier rewind адаптер повторно применяет следующий fragment id и успешно выполняет rollback, подтверждая корректный re-seeding pending receipt lifecycle.
- `paradencer-storage`: усилен checkpoint-seed контракт runtime-state store — `seed_checkpoint` теперь полностью сбрасывает accumulated counters + receipt history при установке baseline/floor; добавлен regression-тест на zeroed totals после re-seed.
- `paradencer-rpc`: усилен strict JSON-RPC config conformance для transaction-submit paths — `sendTransaction`/`simulateTransaction` и nested `simulate.accounts` теперь отклоняют неизвестные ключи (`-32602`) вместо silent-ignore; добавлены renderer regression-тесты.
- `paradencer-rpc`: усилен strict JSON-RPC config conformance для history paths — `getBlock`/`getTransaction` теперь также отклоняют неизвестные поля конфига (`-32602`) по явному allowlist-контракту; добавлены renderer regression-тесты.
- `paradencer-rpc`: усилен strict JSON-RPC params-shape conformance для history query methods (`getBlocks`/`getBlocksWithLimit`/`getBlockCommitment`/`getBlockTime`) — добавлена строгая проверка позиции/типа optional config object, лимит длины params и unknown-key reject (`-32602`); добавлены renderer regression-тесты.
- `paradencer-rpc`: уточнён error-precedence для history query methods — shape/config validation выполняется до `minContextSlot` gate, чтобы malformed/mispositioned params стабильно давали `-32602`, а не `-32016`; добавлен regression-кейс для misplaced `minContextSlot` object.
- `paradencer-rpc`: усилен positional params conformance на full-API method paths (`getBlock`/`getTransaction`/`sendTransaction`/`simulateTransaction`) — trailing positional args теперь строго запрещены (`-32602`), без silent-ignore хвоста; добавлены renderer regression-тесты.
- `paradencer-storage`: добавлен receipt-history-backed runtime-state rewind API (`rewind_to_fragment`) для контролируемого многошагового отката runtime effects к целевому `fragment_id`.
- `paradencer-storage`: усилен rollback-контракт runtime-state (`RuntimeStateReceiptMismatch`) с проверкой полного совпадения rollback receipt и последнего apply receipt до мутации состояния.
- `paradencer-execution` + `paradencer-stages`: добавлен bridge-level execution-state rewind control (`ExecutionStateController`) и подключён в confirmed-reorg path block-assembler, чтобы checkpoint rewind откатывал не только hot-state/replay boundary, но и runtime execution state.
- `paradencer-execution` + `paradencer-stages`: добавлены интеграционные regression-тесты для execution-state rewind path (adapter rewind semantics + stage error surfacing on confirmed-reorg rewind failure).
- `paradencer-stages`: добавлена выделенная телеметрия execution-state rewind fail-path (`execution_state_rewind_failures_total`) и учёт typed execution-error telemetry (`AdapterRollbackFailure`) при fail-fast возврате на confirmed reorg rewind.
- `paradencer-stages`: усилена replay-window consistency семантика: confirmed-reorg rewind теперь пруняет будущие bank checkpoints и синхронизирует depth-метрику с пост-rewind timeline.
- `paradencer-storage` + `paradencer-stages`: добавлен snapshot-catalog rewind path (`SnapshotCatalog::rewind_to_fragment`) и подключён к confirmed-reorg rewind с немедленной persist-синхронизацией каталога.
- `paradencer-stages`: добавлен интеграционный тест restart-consistency, подтверждающий, что persisted snapshot catalog после confirmed-reorg rewind не содержит future snapshots выше rewind checkpoint.
- `paradencer-stages`: confirmed-reorg rewind теперь синхронизирует `fragment_counter` и сбрасывает `replay_controller` state (canonical/candidates), чтобы избежать post-rewind drift и stale reorg candidates.
- `paradencer-storage` + `paradencer-stages`: runtime-like path теперь seed'ит runtime-state baseline от restored checkpoint и вводит floor-guard для rewind (`RuntimeStateRewindTargetBelowFloor`) против отката ниже startup restore точки.
- `paradencer-execution`: добавлен regression-тест на adapter boundary, подтверждающий что rewind ниже seeded floor корректно мапится в typed `AdapterRollbackFailure` (без silent success paths).
- `paradencer-stages` + `paradencer-observability`: добавлена метрика количества prune-операций snapshot catalog при confirmed-reorg rewind (`replay_window_catalog_snapshots_pruned_total`) с runtime + metrics regression coverage.
- Firedancer parity estimate remains conservative at **~15%** (текущий шаг повышает reliability/maintainability базы переноса, но не закрывает крупный parity-блок сам по себе).

## Cross-Cutting Large Gaps

1. Execution/Bank/Replay parity:
- ✓ Bank state machine foundation (slot progression, tick counting, freeze/root lifecycle).
- ✓ Epoch/Leader schedules (deterministic leader rotation, epoch boundaries).
- ✓ Bank execution pipeline (ExecutionBackend trait, process_transaction, account load/writeback).
- ✓ Bank lifecycle (rent collection, slot finish, fee distribution, epoch boundary hooks).
- ✓ Transaction pack/scheduler (priority queue, conflict detection, microblock scheduling).
- ✓ All 13 builtin programs with real handlers (system, vote, stake, ALT, compute budget, config, ed25519, secp256k1, secp256r1, loader-v1/v2/v3/v4).
- ✓ Sysvar lifecycle wired into Bank (per-slot Clock/SlotHashes/SlotHistory/RecentBlockhashes updates).
- Real SVM/sBPF VM interpreter for user programs.
- Partitioned rent collection (per-slot partitioning within epoch).
- Epoch processing with real vote account data (currently hardcoded credits/commission).

2. Networking dataplane parity:
- ✓ QUIC ingress stack complete (endpoint, streams, processor integration).
- Repair/retransmit behavior.
- Deeper peer/session management and network fault handling.

3. Consensus and voting path:
- ✓ Bank/epoch/leader schedule primitives established.
- ✓ Vote program with real state management (vote/authorize/withdraw/update).
- ✓ Stake program with real delegation/authority/lockup logic (18 handlers).
- Tower BFT consensus with lockouts and optimistic confirmation.
- Full fork choice with weighted voting.

4. Storage/accounts parity:
- Funk/groove-equivalent layers, account index/state lifecycle, large-state operations.

5. Snapshot lifecycle parity:
- Network snapshot download/verification/insert orchestration production-level.

6. Client RPC parity:
- Выделенный RPC сервисный путь с поддержкой целевого набора методов и history semantics.

## Approximate Remaining Work Split (conservative, from current ~28% parity)

- Execution/Bank/Replay deep parity: ~35% (VM interpreter, partitioned rent, epoch processing with real data)
- Networking dataplane parity: ~22%
- Consensus/voting path: ~15% (tower BFT, fork choice with weighted voting)
- Storage/accounts/funk-equivalent: ~12%
- Snapshot lifecycle production parity: ~6%
- Client RPC parity: ~2%
- Final parity matrix, perf, rollout hardening: ~3%

## Firedancer Logic Weight And Migration Table

Method:
- `logic weight` = approximate share of total full-client application logic in Firedancer.
- `migrated in Paradencer` = approximate completeness for that specific block.
- `contribution to total` = `logic weight * migrated`.

| Firedancer major block | Logic weight in app | Migrated in Paradencer (block) | Contribution to total migrated logic |
|---|---:|---:|---:|
| Runtime / scheduler / core loops | 8% | 40% | 3.2% |
| Ingress dataplane (UDP/QUIC, decode/dedup/filter) | 18% | 20% | 3.6% |
| Shred path (sanitize/dedup/flow), repair-adjacent | 7% | 12% | 0.8% |
| Execution runtime (SVM/sBPF) | 24% | 35% | 8.4% |
| Replay / bank / fork-choice | 14% | 43% | 6.0% |
| Storage/accounts state model (funk/groove-equivalent) | 12% | 33% | 4.0% |
| Consensus / voting / leader pipeline | 9% | 28% | 2.5% |
| Snapshot lifecycle (download/verify/restore orchestration) | 4% | 18% | 0.7% |
| Client RPC/WS surface | 3% | 30% | 0.9% |
| Observability / control-plane / ops guardrails | 1% | 50% | 0.5% |

Summary:
- Total migrated logic estimate: **~33.4%** (rounded tracking value: **~33%**).
- This table is intentionally conservative and should be revised after each substantial subsystem move.

Wave 10 changes (2026-02-17):
- Execution runtime: 33% → 35% (vote state epoch_credits serialization fix enables real reward calculation)
- Replay / bank / fork-choice: 36% → 43% (epoch boundary processing wired into Bank.finish_slot() — real rewards calculation, immediate vote reward application, partitioned stake distribution, feature activation, leader schedule regeneration, StakeTracker/StakeHistory/FeatureSet in Bank state)
- Storage/accounts: 32% → 33% (store_published_account for protocol-level writes)
- Consensus / voting: 18% → 28% (consensus decision engine: decide_vote_and_reset with empty tower/same fork/lockout/switch cases, execute_decision + advance_root coordination, vote flow wiring from Bank to ConsensusCoordinator)

Wave 9 changes (2026-02-16):
- Execution runtime: 28% → 33% (real stake program with all 18 instruction handlers, self-contained state types with binary serde, authority/lockup/delegation logic)
- Replay / bank / fork-choice: 32% → 36% (sysvar lifecycle wired into Bank.finish_slot() — Clock/SlotHashes/SlotHistory/RecentBlockhashes updated per-slot, sysvar account resolution in load_transaction_accounts())
- Consensus / voting: 15% → 18% (all 13 builtin programs now have real handlers; vote+stake programs complete)

Wave 5 changes (2026-02-16):
- Execution runtime: 20% → 28% (Bank execution pipeline with ExecutionBackend trait, transaction processing, account load/writeback)
- Replay / bank / fork-choice: 25% → 32% (Bank lifecycle: rent collection, slot finish, fee distribution, epoch boundary hooks)
- Consensus / voting: 10% → 15% (Transaction pack/scheduler: priority queue, write-lock conflict detection, microblock scheduling, block resource tracking)
- Runtime: 38% → 40% (constants organization: pack/scheduler constants in block_limits)

Wave 3 changes (2026-02-16):
- Execution runtime: 10% → 20% (sysvars cache 11 types, tx cache, cost tracker, CPI syscalls, programs: ALT/CB/Config/precompiles, features 29)
- Replay / bank / fork-choice: 17% → 25% (genesis parsing, blockstore in-memory, program cache LRU)
- Storage: 25% → 32% (genesis config, blockstore backend, program cache)
- Consensus: 4% → 10% (feature activation, sysvar-bank integration)
- Runtime: 35% → 38% (constants organization expansion)
- Shred: 10% → 12% (blockstore shred storage)
- Snapshot: 12% → 18% (blockstore cleanup, slot metadata)

Note:
- цифры грубые и intentionally conservative;
- при закрытии крупных блоков обновлять этот файл и `docs/00_development_state.md` синхронно.

## Next Implementation Order (recommended)

1. Execution real-runtime slice:
- начать с минимально рабочего sBPF/SVM-compatible execution boundary + deterministic tests.

2. Bank/replay deepening:
- расширить slot/reorg semantics и state invariants.

3. Storage/accounts expansion:
- добавить account-state model и интеграцию с execution path.

4. Networking expansion:
- добавить QUIC path и fault-oriented ingress tests.

5. RPC service hardening:
- расширить `paradencer-rpc` до production-grade layout (method modules, subscriptions/ws where needed, richer history semantics).
