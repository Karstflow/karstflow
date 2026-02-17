# Paradencer Working Module Mapping

Purpose: working map from Firedancer areas to Paradencer areas while we rewrite.
This file is intentionally implementation-facing and will evolve during development.

Rules for rewrite:
- Preserve logic and invariants, not names.
- Prefer explicit, descriptive identifiers over short abbreviations.
- Keep mapping at subsystem level and update when responsibilities move.

## Current Mapping (v1)

| Firedancer area | Paradencer area | Notes |
|---|---|---|
| `src/app/firedancer` | `crates/paradencer-node` + `crates/paradencer-runtime` | Full-client entrypoint and launch flow |
| `src/app/shared/*config*` | `crates/paradencer-config` + `crates/paradencer-core` | Typed schema, strict validation, live/dev gating, reusable node-config loading API (`env`/`file`/`inline-profile`), configurable readiness policy surface (`[readiness]` + env overrides) including worker/entrypoint/metrics-http requirements, and deep storage catalog preflight validation (schema/invariant/checksum via storage loader) |
| `src/disco/*` (common pipeline) | `crates/paradencer-stages` + `crates/paradencer-mesh` + `crates/paradencer-config/src/topology` + `crates/paradencer-topology` | Stage graph and transport abstraction, including configurable multi-worker stage fanout for transaction and shred sanitizer lanes, strict lane validation, real per-link materialization for packet/shred/transaction streams with block-builder fan-in, and per-lane telemetry aggregation across all links |
| `src/disco/dedup/*` | `crates/paradencer-ingress` | Windowed dedup state and acceptance decisions |
| `src/disco/verify/*` (early parse role) | `crates/paradencer-ingress` | Early decode/parsing surface with policy-driven drops before forwarding |
| shred ingress/verification lane in full-client pipeline | `crates/paradencer-stages` (`edge_intake` + `shred_filter`) + `crates/paradencer-ingress` (`ShredDecoder`) | Dedicated shred lane split from tx lane with independent dedup/telemetry |
| `src/discof/*` (full-client stages) | `crates/paradencer-stages` | Rewrite each stage with new names |
| `src/discof/execrp/*` + execution edge in replay | `crates/paradencer-execution` + `crates/paradencer-stages` | Execution bridge entry from assembled block fragments with load-aware failure classification (batch size + estimated cost units) and retry/reorg attempts preserving original batch-cost context |
| `src/flamenco/runtime/*` (transaction execution) | `crates/paradencer-sbpf` | Transaction processor routing instructions to program executors (System/Vote/Stake), compute budget management, account state transformation; integrated via `paradencer-storage::TransactionProcessor` which delegates execution to sbpf layer |
| `src/ballet/lthash/*` (lattice hash) | `crates/paradencer-crypto/src/lthash.rs` | `LatticeHashValue` (1024 u16 elements, wrapping arithmetic), `hash_account()` via Blake3 XOF |
| `src/flamenco/runtime/fd_hashes.*` (bank hash) | `crates/paradencer-consensus/src/bank.rs` (`hash()`, `update_account_hash()`) | Deterministic `SHA256(SHA256(prev_bank_hash \|\| sig_count \|\| last_blockhash) \|\| lthash)`, incremental lthash accumulator |
| `src/funk/*` (account database) | `crates/paradencer-storage` | Account database (multi-version concurrency control with transaction IDs), snapshot catalog, hot state store, runtime state management; storage layer provides account loading/writeback but delegates transaction execution to sbpf |
| replay/bank slot progression control in full-client path | `crates/paradencer-stages/src/block_assembler/slot_pipeline.rs` + `crates/paradencer-stages/src/block_assembler/replay_controller.rs` + `crates/paradencer-stages/src/block_assembler/fork_choice_engine.rs` + `crates/paradencer-stages/src/block_assembler/publication_gate.rs` + `crates/paradencer-stages/src/block_assembler/bank_timeline.rs` + `crates/paradencer-config/src/storage/policies/replay_controller.rs` + `crates/paradencer-config/src/storage/policies/replay_window.rs` | Explicit slot state machine and canonical/reorg-candidate controller (including competing-branch candidate selection) with dedicated fork-choice scoring engine (reorg signal, recency, and optional failed-ratio penalty), isolated publication gating, and replay-window checkpoints for optional rewind on confirmed reorg |
| storage/snapshot boundary in full-client flow | `crates/paradencer-storage` + `crates/paradencer-stages` + `crates/paradencer-config/src/storage/policies/snapshot_retention.rs` | Hot-state commit hook + snapshot trigger interval + catalog retention/pruning policy + strict catalog invariants on startup load, including header-consistency checks (`last_snapshot_fragment_id`/`snapshots_written`) + snapshot integrity checksum verification (`state_checksum`) with legacy schema migration (`v0/v1 -> v2`) |
| `src/discoh/*` (hybrid/Agave bridge) | out of scope | No Frankendancer path in Paradencer |
| topology + affinity planning | `crates/paradencer-runtime` (planner/executor) + `crates/paradencer-config/src/runtime` | Two execution modes: tokio and pinned, with optional explicit pinned service-core affinity map (`runtime.pinned_service_core_ids` / `PARADENCER_PINNED_SERVICE_CORES`) |
| metrics/control surfaces | `crates/paradencer-control` + `crates/paradencer-observability` + `crates/paradencer-rpc` + `crates/paradencer-runtime` + `crates/paradencer-node` | Control-plane crate handles CLI parsing/dispatch/bootstrap, output rendering, diagnostics command path, topology materialization helpers from node config, deep probe flags (`--with-tick`, `--probe-ticks N`), centralized diagnostics orchestration (`run_diagnostics_phase` with network preflight + probe summary + stage-mix/lane-capacity/runtime-service diagnostics), early pinned-affinity preflight validation/output via runtime affinity planner, optional mainnet-readiness gating (`--mainnet-readiness`) for both diagnostics and preflight with issue list + fail-fast backed by configurable readiness policy values from config/env (including runtime workers, live entrypoints, and optional metrics-http binding), and RPC bootstrap (`[rpc]`/`PARADENCER_RPC_*`) via dedicated `paradencer-rpc` JSON-RPC HTTP server (`getHealth`, `getVersion`, `getSlot`, `getBlockHeight`, `getBlockCount`, `getTransactionCount`, `getLatestBlockhash`, `getRecentBlockhash`, `isBlockhashValid`, `getFeeForMessage`, `getGenesisHash`, `getBalance`, `getIdentity`, `getEpochInfo`, `getFirstAvailableBlock`, `minimumLedgerSlot`, `getMaxShredInsertSlot`, `getRecentPerformanceSamples`, `getSignaturesForAddress`, `getClusterNodes`, `getVoteAccounts`, `getSupply`, `getLargestAccounts`, `getTokenLargestAccounts`, `getProgramAccounts`, `getTokenAccountsByOwner`, `getTokenAccountsByDelegate`, `getInflationGovernor`, `getInflationRate`, `getInflationReward`, `getAccountInfo`, `getMultipleAccounts`, `getSignatureStatuses`, `getLeaderSchedule`, `getBlockProduction`, `getRecentPrioritizationFees`, `getBlocks`, `getBlock`, `getBlockTime`, `getTransaction`) with a dedicated runtime-state boundary (`RuntimeSnapshotProvider`) for snapshot sourcing, method allowlist (`full_api` gate), invalid-params handling (`-32602`) for malformed account/block/signature/range/identity/mint/filter requests, plus `-32016` guardrail for unsatisfied `minContextSlot` in transaction-count path and initial commitment-aware visibility mapping (`processed`/`confirmed`/`finalized`); metrics export includes replay-candidate health gauges (active failed-ratio bps + tracked candidate count); runtime crate exposes reusable lifecycle probe reporting + pinned affinity plan API; observability crate owns metrics HTTP bridge transport; node is a thin binary callback wrapper over control + topology crates |

## Execution Mapping

- Firedancer tile-per-core strategy -> Paradencer `ExecutionMode::Pinned`
- Thread/task friendly development mode -> Paradencer `ExecutionMode::Tokio`

Both modes must run the same stage logic and differ only by scheduler/executor behavior.

## Open Mapping Decisions

1. Snapshot and storage decomposition boundaries.
2. Consensus/fork-choice crate split (`core` vs `stages`).
3. RPC method/history parity depth and long-run service hardening (split into dedicated crate already completed).

## Channel Usage Policy (performance-aware)
- Use bounded channels only at stage boundaries where ownership transfer/backpressure is needed.
- Do not introduce channels inside compute-heavy stage internals unless required for correctness.
- Keep queue capacities explicitly configurable per link.
- Track blocked send counters to detect where queueing harms throughput.
