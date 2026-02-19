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

## Full Firedancer Module → Paradencer Mapping (2026-02-17)

This section maps ALL Firedancer native modules to their Paradencer equivalents.
Native Firedancer total: ~623,600 lines C+H (excluding discoh/Frankendancer).

| FD Module | FD Lines (C+H) | Paradencer Crate(s) | Approach |
|---|---|---|---|
| `ballet/ed25519` | 27,446 | `paradencer-crypto/ed25519_batch` | ed25519-dalek + batch verification wrapper |
| `ballet/reedsol` | 37,465 | `paradencer-crypto/reed_solomon` | reed-solomon-erasure crate |
| `ballet/fiat-crypto` | 19,550 | N/A (via ed25519-dalek internals) | Generated field arithmetic — not ported |
| `ballet/bn254` | 11,395 | `paradencer-crypto/bn254` | ark-bn254 crate |
| `ballet/zksdk` | 9,151 | minimal (in sbpf precompiles) | Low priority |
| `ballet/sha256` | 2,448 | `paradencer-crypto/sha256` | sha2 crate |
| `ballet/sha512` | 2,521 | N/A (via ed25519-dalek) | Implicit |
| `ballet/blake3` | 4,298 | `paradencer-crypto/blake3` | blake3 crate |
| `ballet/keccak256` | 628 | `paradencer-crypto/keccak256` | tiny-keccak |
| `ballet/secp256k1` | 275 | `paradencer-crypto/secp256k1` | k256 crate |
| `ballet/secp256r1` | 2,021 | `paradencer-crypto/secp256r1` | p256 crate |
| `ballet/bls` | 1,811 | **not implemented** | Future |
| `ballet/lthash` | 682 | `paradencer-crypto/lthash` | Custom Rust impl |
| `ballet/sbpf` | 3,083 | `paradencer-sbpf/elf_loader` | ELF parsing/loading |
| `ballet/txn` | 1,730 | `paradencer-types` + inline in stages | Transaction parsing |
| `ballet/shred` | 1,262 | `paradencer-types/shred` | Shred parsing |
| `ballet/base58` | 1,757 | bs58 crate | External |
| `ballet/json+toml` | 5,505 | serde_json + toml crates | External |
| `ballet/nanopb` | 4,504 | N/A (prost crate if needed) | Protobuf via Rust crates |
| `ballet/aes+chacha` | 3,718 | aes/chacha20 crates | When needed |
| `ballet/*` (other) | ~15,000 | various external crates | bmtree, wsample, hmac, etc. |
| `flamenco/runtime/` (top) | 8,118 | `paradencer-consensus` (bank, executor, lifecycle) | Core runtime logic |
| `flamenco/runtime/sysvar/` | 1,881 | `paradencer-consensus/sysvars/` | All 14 sysvars |
| `flamenco/runtime/program/` | 16,120 | `paradencer-sbpf` (all builtin programs) | 12+ programs, 96+ instr |
| `flamenco/vm/` (core) | 3,275 | `paradencer-sbpf/interpreter+vm` | sBPF interpreter |
| `flamenco/vm/syscall/` | 4,584 | `paradencer-sbpf/syscalls/` | CPI, crypto, PDA, hash |
| `flamenco/types/` | 10,088 | `paradencer-types` + inline | Bincode types (FD auto-gen) |
| `flamenco/gossip/` | 4,837 | `paradencer-ingress/gossip/` | CRDS, push/pull, ping |
| `flamenco/accdb/` | 4,420 | `paradencer-storage/accounts` | Account DB v0/v1/v2 |
| `flamenco/features/` | 2,428 | `paradencer-consensus/features/` | Feature gates (FD auto-gen) |
| `flamenco/progcache/` | 1,699 | `paradencer-storage/program_cache/` | Program cache |
| `flamenco/rewards/` | 1,399 | `paradencer-consensus/rewards*` | Epoch rewards |
| `flamenco/stakes/` | 1,140 | `paradencer-consensus/stake/` | Delegation tracking |
| `flamenco/leaders/` | 345 | `paradencer-consensus/leader_schedule` | Leader schedule |
| `flamenco/genesis/` | 336 | `paradencer-storage/genesis/` | Genesis creation |
| `choreo/tower` | 3,158 | `paradencer-consensus/tower` | Tower BFT |
| `choreo/ghost` | 1,825 | `paradencer-consensus/fork_choice` | GHOST algorithm |
| `choreo/eqvoc` | 1,098 | `paradencer-consensus/equivocation` | Equivocation detection |
| `choreo/hfork` | 771 | partially in fork_choice | Heavy fork tracking |
| `choreo/notar` | 555 | `paradencer-consensus/commitment` | Block commitment (4 thresholds: propagated/dup_conf/opt_conf/sup_conf) |
| `choreo/voter` | 407 | `paradencer-consensus/vote_processor` | Vote submission |
| `disco/pack` | 11,860 | `paradencer-consensus/pack` + stages | Transaction scheduling |
| `disco/shred` | 8,856 | `paradencer-stages/shred_assembler` + ingress/turbine | Shred tiles |
| `disco/gui` | 11,757 | N/A (skip for now) | Web dashboard |
| `disco/metrics` | 7,956 | `paradencer-observability` | Metrics/telemetry |
| `disco/bundle` | 5,566 | **not started** | MEV/bundle support |
| `disco/net` | 5,161 | `paradencer-net/tile/net_tile` + `paradencer-config/network` | Network tile with transport backend, config integration |
| `disco/topo` | 3,186 | `paradencer-topology` | Topology wiring |
| `disco/quic` | 2,172 | `paradencer-net/tile/quic_tile` | QUIC tile with engine service, TPU reassembly |
| `disco/verify+dedup` | 2,543 | `paradencer-ingress` | Sig verify + dedup |
| `disco/store` | 1,210 | `paradencer-storage/blockstore` | Block store tile |
| `disco/*` (other) | ~9,200 | `paradencer-stages` + config | keyguard, events, etc. |
| `discof/restore` | 21,197 | `paradencer-storage/snapshot` | **Largest gap** |
| `discof/replay` | 9,294 | `paradencer-stages/replay_stage` | Block replay |
| `discof/repair` | 3,163 | `paradencer-ingress/repair` | Repair protocol |
| `discof/forest` | 3,010 | `paradencer-consensus/bank_forks` | Fork tree |
| `discof/rpc` | 1,877 | `paradencer-rpc` | RPC server |
| `discof/gossip` | 1,841 | `paradencer-ingress/gossip` | Gossip tile |
| `discof/poh` | 1,631 | `paradencer-stages/block_producer/poh` | Proof of History |
| `discof/tower` | 1,578 | `paradencer-consensus/tower` | Tower tile |
| `discof/*` (other) | ~11,600 | various | reasm, genesis, txsend, etc. |
| `waltz/quic` | 24,957 | `paradencer-net/quic` (custom) | QUIC v1 engine: varint, headers, frames, connections, streams, ACK, service queue, retry, crypto |
| `waltz/h2+http` | 14,177 | hyper crate | HTTP |
| `waltz/tls` | 5,666 | `paradencer-net/tls` (custom) | TLS 1.3: HKDF, AES-128-GCM AEAD, X25519 key exchange, handshake state machine |
| `waltz/grpc` | 2,353 | tonic crate (planned) | gRPC |
| `waltz/aio` | ~1,200 | `paradencer-net/io` | I/O abstraction: IoHandle (fn-pointer + ctx), PacketSender/Receiver traits |
| `waltz/ip` | ~2,000 | `paradencer-net/routing` | FIB4 routing: dual-path IPv4 lookup (HashMap /32 + sorted prefix array) |
| `waltz/neigh` | ~1,500 | `paradencer-net/neighbor` | ARP neighbor table: open-addressing hashmap, probe suppression |
| `waltz/xdp+xsk` | ~3,500 | `paradencer-net/xdp` | AF_XDP: UMEM frame allocator, SPSC rings, socket abstraction, eBPF program generator |
| `waltz/*` (other) | ~1,000 | `paradencer-net` (packet, wire, socket) | Ethernet/IPv4/UDP wire types, PacketBuffer/Batch, UDP sendmmsg/recvmmsg |
| `disco/net` | ~2,500 | `paradencer-net/tile/net_tile` | Network tile: packet demux, routing, transport backend (UDP/XDP) |
| `disco/quic` | ~1,800 | `paradencer-net/tile/quic_tile` | QUIC tile: engine service, TPU transaction reassembly |
| `funk/` | 3,762 | `paradencer-storage/accounts` | KV store |
| `vinyl/` | 17,301 | **not started** | Persistent storage |
| `tango/` | 8,650 | `paradencer-mesh` (218 lines) | IPC — major gap |
| `groove/` | 3,340 | Rust allocator (jemalloc) | Memory management |
| `app/firedancer` | 2,836 | `paradencer-node` + topology | Native entry point |
| `app/shared` | 11,116 | `paradencer-config` | Configuration |
| `app/*` (other) | 16,505 | `paradencer-control` + dev tools | CLI, debug |
| `util/` | 105,836 | Rust stdlib + external crates | ~70% replaced by Rust |

## Open Mapping Decisions

1. Snapshot and storage decomposition boundaries (vinyl equivalent).
2. IPC layer (tango equivalent) — bounded channels vs shared memory.
3. Bundle/MEV support timeline.
4. BLS signature support timeline.
5. gRPC/Geyser API support.

## Channel Usage Policy (performance-aware)
- Use bounded channels only at stage boundaries where ownership transfer/backpressure is needed.
- Do not introduce channels inside compute-heavy stage internals unless required for correctness.
- Keep queue capacities explicitly configurable per link.
- Track blocked send counters to detect where queueing harms throughput.
