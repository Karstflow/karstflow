# Paradencer

> High-performance Solana validator implementation in Rust

Paradencer is a ground-up Solana validator built for maximum throughput and minimal latency. It features a custom network stack, pre-allocated data structures, zero-copy I/O patterns, and a modular tile-based architecture designed for predictable performance at scale.

**255K+ lines of Rust | 5,300+ tests | 20 crates**

## Design Principles

- **Performance first**: Pre-allocated pools, batch processing, zero-copy where possible, segment-based compute metering
- **Native implementation**: No runtime dependency on existing Solana validator codebases
- **Clean architecture**: 20-crate workspace with strict dependency hierarchy and single-responsibility modules
- **Idiomatic Rust**: Leverages Rust's type system, ownership model, traits, and ecosystem for safety and correctness
- **Tile-based execution**: Pinned-core service model for deterministic scheduling and cache locality

## Architecture

```
paradencer-types          (core types: Pubkey, Account, Hash, Shred)
  |
  +-- paradencer-sbpf     (sBPF VM + 14 builtin programs)
  |
  +-- paradencer-storage  (MVCC accounts, blockstore, snapshots, persistent backend)
  |     |
  |     +-- paradencer-consensus  (Bank, BankForks, Tower BFT, Fork Choice, Economics)
  |
  +-- paradencer-crypto   (Ed25519 batch, Blake3, SHA-256, Reed-Solomon FEC, LtHash)
  |
  +-- paradencer-net      (Custom QUIC/TLS, Gossip CRDS, Turbine, Repair, XDP)
  |
  +-- paradencer-execution (SVM adapter, batch orchestration, retry logic)
  |
  +-- paradencer-stages   (Replay, Block production, PoH, Pack, Shred assembly, Metrics)
  |
  +-- paradencer-rpc      (JSON-RPC 2.0 server, WebSocket subscriptions)
  |
  +-- paradencer-plugin   (Dynamic plugin system, RPC control, C FFI)
  |
  +-- paradencer-node     (Validator orchestration and entry point)
```

### Crate Overview

| Crate | LOC | Tests | Purpose |
|-------|-----|-------|---------|
| `paradencer-consensus` | 43,952 | 1,128 | Tower BFT, GHOST fork choice, leader schedule, epoch processing, Bank lifecycle, multi-threshold confirmation |
| `paradencer-sbpf` | 38,403 | 716 | sBPF interpreter (126 opcodes), 14 builtin programs, ELF loader, CPI, 40+ syscalls, program cache |
| `paradencer-net` | 37,913 | 818 | Custom QUIC engine, TLS 1.3, gossip with 14-type CRDS, turbine broadcast, repair, AF_XDP |
| `paradencer-stages` | 34,925 | 642 | Replay with fork tracking, block production, PoH state machine, pack scheduler, shred pipeline, metrics aggregation |
| `paradencer-storage` | 25,910 | 660 | Disk-primary account database, blockstore, full+incremental snapshots, persistent backend, LZ4 compression |
| `paradencer-rpc` | 13,857 | 312 | 60+ JSON-RPC methods, 9 WebSocket subscription types, transaction simulation |
| `paradencer-config` | 6,081 | 103 | TOML configuration with env override, live-mode preflight checks, schema migration |
| `paradencer-execution` | 5,337 | 104 | SVM backend adapter, batch execution orchestration, retry policies |
| `paradencer-control` | 4,606 | 62 | Control plane: bootstrap, preflight validation, diagnostics, service materialization |
| `paradencer-types` | 3,512 | 82 | Core types: Account, Pubkey, Hash, Transaction, Shred, compact-u16 codec |
| `paradencer-crypto` | 3,329 | 111 | Ed25519 batch verification, Blake3/SHA-256/Keccak, secp256k1/r1, BN254, Reed-Solomon FEC, LtHash |
| `paradencer-mesh` | 3,153 | 134 | Dual-mode IPC (channels + shared memory), typed SPSC tile links, bounded channels, stats tracking |
| `paradencer-constants` | 2,885 | -- | Protocol constants: fees, timing, compute limits, program parameters (23 modules) |
| `paradencer-plugin` | 1,191 | 16 | Dynamic plugin system: load/unload, RPC control, C FFI |
| `paradencer-topology` | 1,016 | 10 | Service topology planning and materialization |
| `paradencer-runtime` | 797 | 14 | Execution substrate: tokio/pinned/tile modes, CnC supervisor, CPU affinity, lifecycle |
| `paradencer-node` | 507 | -- | Validator orchestration and entry point |
| `paradencer-ids` | 452 | 4 | Well-known program and sysvar addresses |
| `paradencer-core` | 357 | 14 | Shared vocabulary types (RuntimeSpec, TopologySpec, ExecutionMode) |
| `paradencer-observability` | 192 | -- | Metrics HTTP endpoint, tracing initialization |

## Key Features

### Consensus

- **Tower BFT** with lockout-based vote tracking and switch threshold
- **GHOST fork choice** with weighted voting and ancestry verification
- **Multi-threshold confirmation** pipeline: propagated (1/3), duplicate confirmed (52%), optimistically confirmed (2/3), super confirmed (4/5)
- **Equivocation detection** with cryptographic proof generation
- **Full Bank lifecycle**: Processing -> Frozen -> Rooted with 64 ticks/slot

### Execution

- **14 builtin programs**: System, Vote, Stake, Token, Token-2022, Associated Token, Memo, Compute Budget, Config, BPF Loader, Loader v4, Address Lookup Table, Ed25519 precompile, Secp256k1 precompile
- **sBPF interpreter** with segment-based compute unit accounting (batch CU deduction at control-flow boundaries for reduced per-instruction overhead)
- **ELF loader** with program caching
- **Full CPI** support with syscall dispatch (crypto, PDA derivation, logging, memory, sysvar access)
- **Pluggable execution backend**: consensus layer stays independent of VM implementation

### Storage

- **Disk-primary account database**: Fork-aware MVCC with bounded LRU cache, copy-on-write ancestor chains, O(1) owner index
- **Custom file-backed store**: Column-family key-value store with WAL, CRC32 checksums, auto-compaction, mmap reads
- **LZ4 account compression**: Transparent compression for persisted accounts (backward-compatible, configurable threshold)
- **Parallel recovery**: Rayon-based parallel account loading with automatic serial/parallel mode selection
- **Full snapshot pipeline**: Create, load, and restore from Solana-compatible tar.zst archives
- **Incremental snapshots**: Dirty-set tracking for efficient delta snapshots
- **Blockstore**: Shred windowing with FEC reconstruction, slot metadata, persistent backend
- **Genesis bootstrap**: Full initialization from snapshot (stakes, sysvars, features, history, transaction cache)
- **Background maintenance**: Periodic auto-compaction, flush, blockstore cleanup via poll-driven service

### Network

- **Custom QUIC engine**: No tokio/quinn dependency, synchronous poll-driven service loop
- **TLS 1.3**: Minimal implementation (AES-128-GCM + X25519 + Ed25519)
- **Gossip**: CRDS data model with 14 value types, FNV-1a bloom filters, weighted peer sampling, push/pull/prune protocol
- **Turbine**: Shred broadcast tree, neighborhood assignment, retransmit service
- **Repair**: Request/response protocol for missing shreds
- **Ingress filter**: Signature deduplication, source rate limiting, cost budgets
- **AF_XDP**: Kernel-bypass socket support (Linux, feature-gated)

### Pipeline Stages

- **Verify stage**: Signature verification with batch Ed25519
- **Dedup stage**: Bloom-filter-based transaction deduplication
- **Resolv stage**: Blockhash resolution and expiry tracking
- **Pack stage**: Transaction scheduling with conflict detection, vote prioritization, CU-based pacing
- **Exec stage**: Microblock execution with compute unit tracking
- **Shred network**: FEC resolver pool, set cache, turbine retransmit, equivocation detection
- **Leader pipeline**: Integrated block production with sign service and pacing
- **Replay service**: Fork-aware slot processing with GHOST fork choice, orphan buffering, cascade replay
- **Metrics aggregation**: Cross-tile Prometheus metrics with HTTP scraping endpoint

All pipeline stages communicate through dual-mode IPC (`DualSender`/`DualReceiver`). Eight `FragmentCodec` implementations cover the full message type set: `RawTransaction`, `UnverifiedTransaction`, `VerifiedTransaction`, `RetransmitDecision`, `CompletedFecSet`, `AssembledBlock`, `EquivocationProof`, `ShredBatch`, plus `Shred` (in paradencer-types).

### RPC

- **60+ JSON-RPC methods** with strict envelope and parameter validation
- **9 WebSocket subscription types**: slot, account, root, signature, vote, block, logs, program, slotsUpdates
- **Transaction simulation** engine
- **Account caching** with LRU eviction

### Plugin System (Geyser-compatible)

Paradencer includes a streaming notification system analogous to Solana's Geyser plugin interface. External shared libraries (.so/.dylib) receive real-time account updates, transaction notifications, slot status changes, and block metadata from the validator.

- **Dynamic loading**: Load/unload shared libraries at runtime via C FFI
- **RPC control**: Register, unregister, and query plugins through RPC interface (`pluginRegister`, `pluginUnregister`, `pluginList`, `pluginReload`)
- **Lifecycle management**: Plugin start/stop/reload with graceful handling
- **Notification types**: `AccountUpdate`, `TransactionNotification`, `SlotStatus`, `BlockMetadata`

#### Writing a Plugin

Plugins implement the `PluginInterface` trait and export a C constructor:

```rust
use paradencer_plugin::{PluginInterface, PluginResult, AccountUpdate};

#[derive(Debug)]
struct MyGeyserPlugin;

impl PluginInterface for MyGeyserPlugin {
    fn name(&self) -> &'static str { "my-geyser-plugin" }

    fn notify_account_update(
        &self,
        account: &AccountUpdate<'_>,
        slot: u64,
        _is_startup: bool,
    ) -> PluginResult<()> {
        // Stream account updates to your database, indexer, etc.
        Ok(())
    }
}

#[no_mangle]
pub unsafe extern "C" fn _create_plugin() -> *mut dyn PluginInterface {
    Box::into_raw(Box::new(MyGeyserPlugin))
}
```

#### Plugin Configuration

Each plugin is configured via a JSON file:

```json
{
    "libpath": "/path/to/libmy_geyser_plugin.so",
    "name": "my-geyser-plugin",
    "accounts_selector": { "owners": ["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"] }
}
```

#### Loading Plugins

```bash
# Via environment variable at startup
PARADENCER_PLUGIN_CONFIG=/path/to/plugin-config.json cargo run -p paradencer-node

# Via RPC at runtime
curl -X POST http://localhost:8899 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"pluginRegister","params":["/path/to/plugin-config.json"]}'

# List loaded plugins
curl -X POST http://localhost:8899 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"pluginList","params":[]}'

# Reload a plugin (hot-swap)
curl -X POST http://localhost:8899 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"pluginReload","params":["my-geyser-plugin"]}'
```

**Note**: The gRPC transport layer (HTTP/2 + protobuf service definitions) for full Geyser protocol compatibility is planned as a separate .so plugin.

## Quick Start

### Prerequisites

- Rust stable toolchain (managed via `rust-toolchain.toml`)
- [Just](https://github.com/casey/just) command runner (optional)

### Build

```bash
cargo build --workspace --all-targets
```

### Test

```bash
cargo test --workspace --all-targets
```

### Development Commands

```bash
# Build & Quality
just check         # cargo check
just fmt            # Format all code
just lint           # Clippy with strict settings
just test           # Run all tests
just ci             # fmt-check + lint + test

# Run
just run            # Run node (tokio mode)
just run-pinned     # Run node (pinned cores mode)
just smoke          # Quick 2-second smoke run

# Test-Validator Mode
just dev            # Run in dev mode with auto-genesis and airdrop
just dev-tile       # Dev mode with tile executor
just run-profile p  # Run with named profile (devnet, testnet, mainnet, local)

# Genesis
just genesis-init   # Interactive genesis builder
just run-genesis p  # Run from existing genesis.bin file
```

### Runtime Modes

Paradencer supports three execution modes:

- **`tokio`** -- Cooperative async tasks (default, development)
- **`pinned`** -- One service per dedicated core/thread (production)
- **`tile`** -- Pinned cores with CnC supervisor, heartbeat monitoring, and stuck detection (production, recommended)

```bash
# Development mode
PARADENCER_EXEC_MODE=tokio PARADENCER_RUN_SECONDS=10 cargo run -p paradencer-node

# Production mode with tile executor
PARADENCER_EXEC_MODE=tile PARADENCER_RUN_SECONDS=10 cargo run -p paradencer-node
```

### IPC Modes

All inter-tile communication uses a dual-mode IPC system. Every point-to-point link in the pipeline supports both modes transparently:

- **`channel`** -- Crossbeam bounded MPMC channels (default, compatible everywhere)
- **`shared_memory`** -- Lock-free SPSC queues in shared memory regions (zero-copy, zero-syscall)

```bash
# Full zero-copy pipeline
PARADENCER_IPC_MODE=shared_memory PARADENCER_EXEC_MODE=tile cargo run -p paradencer-node
```

**Architecture**: The `DualSender<T>` / `DualReceiver<T>` enum selects at construction time between `Channel(OutPort<T>)` for crossbeam and `Link(TileSender<T>)` / `Link(LinkConsumer<'static>)` for shared memory. Messages are encoded/decoded via the `FragmentCodec` trait — each pipeline type (transactions, shreds, FEC sets, blocks, retransmit decisions, equivocation proofs) has a zero-allocation binary codec. The two paths are completely independent: no fallback, no cross-contamination.

Fan-in links (multiple producers to one consumer, e.g., shred filter fan-in) stay on channels. All point-to-point SPSC links use `dual_link()` which selects the IPC backend based on `IpcMode` config. Shared memory ownership handles are kept alive for the full pipeline lifetime via `link_ownership` in `MaterializedTopology`.

## Test-Validator Mode

Paradencer includes a built-in test-validator mode for local development — no separate binary required. When the cluster mode is set to `dev` (or its alias `test-validator`), the node automatically:

- **Generates a development genesis** with a pre-funded validator identity (500 SOL) and faucet account (500M SOL)
- **Enables `requestAirdrop` RPC** — transfers up to 10,000 SOL per request directly via bank credit
- **Starts with permissive defaults** — private addresses allowed, full RPC API enabled, no identity keypair required

### Quick Start (Dev Mode)

```bash
# Fastest way — auto-genesis, all defaults
just dev

# With tile executor (production runtime, dev config)
just dev-tile
```

### `requestAirdrop` RPC

Available only in test-validator mode. Mirrors the Solana `requestAirdrop` JSON-RPC method:

```bash
curl -X POST http://localhost:8899 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"requestAirdrop","params":["<BASE58_PUBKEY>", 1000000000]}'
```

Returns a transaction signature (base58). The airdrop is applied immediately via direct bank credit — no faucet TCP service or separate airdrop binary needed.

### Safety Guards

Test-validator mode is **blocked for production clusters**. The validator will refuse to start if dev mode is combined with:

- Known genesis hashes (devnet, testnet, mainnet-beta)
- Known cluster entrypoint hostnames (*.devnet.solana.com, *.testnet.solana.com, *.mainnet-beta.solana.com)

This prevents accidental use of dev-only features (airdrop, auto-funded genesis) against real networks.

### Genesis CLI

For custom genesis configurations, use the interactive genesis builder:

```bash
just genesis-init
# or directly:
cargo run -p paradencer-node -- genesis init
```

The CLI prompts for each parameter with sensible defaults — press Enter to accept:

- Output path (`genesis.bin`)
- Cluster type (Development / Devnet / Testnet / Mainnet)
- Ticks per slot (64)
- Identity lamports, faucet lamports
- Hashes per tick (12500)

Then boot with the generated genesis:

```bash
just run-genesis path/to/genesis.bin
```

## Cluster Profiles

Pre-built TOML profiles for different environments:

| Profile | File | Cluster | Mode |
|---------|------|---------|------|
| `local` | `config/local.toml` | Local dev | `dev` (test-validator) |
| `devnet` | `config/devnet.toml` | Solana Devnet | `live` |
| `testnet` | `config/testnet.toml` | Solana Testnet | `live` |
| `mainnet` | `config/mainnet.toml` | Solana Mainnet-Beta | `live` |

Usage:

```bash
# Run with a profile
just run-profile devnet
# or directly:
cargo run -p paradencer-node -- run --profile devnet

# Env vars override any profile setting
PARADENCER_RPC_BIND=0.0.0.0:9999 just run-profile devnet
```

Each live profile includes the cluster's genesis hash, shred version, gossip entrypoints, and tuned runtime settings. Environment variables always take priority over TOML values.

## Configuration

Configuration follows a layered model: **TOML profile → environment variable override → defaults**.

Configuration files in `config/`:

| File | Purpose |
|------|---------|
| `local.toml` | Local development / test-validator mode |
| `devnet.toml` | Solana Devnet cluster |
| `testnet.toml` | Solana Testnet cluster |
| `mainnet.toml` | Solana Mainnet-Beta cluster |
| `node.default.toml` | Node identity, cluster, paths |
| `ingress.default.toml` | Network ingress settings |
| `topology.default.toml` | Service topology |

Live mode includes preflight safety checks (identity keypair, entrypoint routability, genesis hash validation, storage catalog verification).

## Project Structure

```
paradencer/
+-- crates/                        # 20 Rust crates
|   +-- paradencer-consensus/      # Consensus (Tower BFT, Bank, Economics)
|   +-- paradencer-crypto/         # Cryptography (Ed25519, FEC, Hashing)
|   +-- paradencer-sbpf/           # sBPF VM + Builtin programs
|   +-- paradencer-storage/        # Storage (Accounts, Shreds, Snapshots)
|   +-- paradencer-net/            # Network (Custom QUIC/TLS, Gossip, Turbine, Repair)
|   +-- paradencer-rpc/            # RPC server (JSON-RPC, WebSocket)
|   +-- paradencer-stages/         # Pipeline (Replay, Block Production, PoH, Metrics)
|   +-- paradencer-execution/      # Transaction execution adapter
|   +-- paradencer-plugin/         # Dynamic plugin system
|   +-- paradencer-types/          # Core type definitions
|   +-- paradencer-ids/            # Program IDs
|   +-- paradencer-constants/      # Protocol constants
|   +-- paradencer-config/         # Configuration management
|   +-- paradencer-control/        # Control plane
|   +-- paradencer-mesh/           # Dual-mode IPC (channels + shared memory tile links)
|   +-- paradencer-node/           # Node entry point
|   +-- paradencer-observability/  # Metrics
|   +-- paradencer-topology/       # Service topology
|   +-- paradencer-runtime/        # Runtime utilities
|   +-- paradencer-core/           # Core utilities
+-- config/                        # TOML configuration files
+-- Cargo.toml                     # Workspace definition
+-- rust-toolchain.toml            # Rust toolchain
+-- justfile                       # Development commands
```

## Module Readiness

Current maturity of each subsystem (as of March 2026):

| Module | Maturity | Notes |
|--------|----------|-------|
| Consensus | 94% | Tower BFT, GHOST fork choice, bank lifecycle, epoch processing, rewards, leader schedule, vote processing, optimistic confirmation, commitment tracking, equivocation detection |
| sBPF VM | 88% | All 126 opcodes, 14 builtins, 40+ syscalls, ELF loader, program cache, CPI. Remaining: JIT not planned, segment metering edge cases |
| Network | 83% | Custom QUIC, TLS 1.3, gossip (14 CRDS types + vote integration), turbine with real stake weights, repair protocol, DNS resolution. Remaining: gRPC transport |
| Pipeline Stages | 93% | Full leader pipeline (verify → resolv → pack → exec → PoH → shred → broadcast), shred network with FEC resolver, replay with orphan buffering, dual-mode IPC, Prometheus metrics for all stages. Real execution engine enforced (no mock fallback) |
| Storage | 93% | Disk-primary MVCC accounts, file-backed store, full/incremental snapshots with gossip hash publishing, blockstore with transaction/block-height/time indexes, LZ4 compression, lattice hash, auto-scheduled snapshot creation |
| IPC / Mesh | 95% | Dual-mode SPSC (channels + shared memory), 9 FragmentCodec implementations, tile links, bounded channels with backpressure stats |
| RPC | 95% | 52 JSON-RPC methods with real bank data via BankAccessProvider, WebSocket subscriptions, getHealth wired to real health check |
| Execution | 92% | SVM adapter with real BankExecutionEngine enforced in production, batch orchestration, retry policies |
| Crypto | 88% | Ed25519 batch verify, Blake3/SHA-256/Keccak, secp256k1/r1, BN254 pairing, Reed-Solomon FEC, LtHash, ChaCha RNG, ZK ElGamal proofs |
| Config | 91% | TOML with env override, live-mode preflight, schema migration, cluster profiles (devnet/testnet/mainnet/local) |
| Control | 93% | Bootstrap, materialization, consensus wiring, shred store service, snapshot scheduling, configure/monitor CLI commands |
| Runtime | 95% | Tokio/pinned/tile modes, CnC supervisor, heartbeat, stuck detection, graceful shutdown |

### Overall Readiness: 92%

Weighted readiness score across all subsystems (consensus 15%, networking 12%, stages 15%, storage 10%, execution 10%, native programs 10%, crypto 10%, IPC 5%, RPC 5%, config 5%, runtime 3%).

### Devnet Readiness: 9/10

The validator can boot from genesis or snapshot, sync via gossip and turbine, participate in consensus (voting, fork choice, root advancement), serve real account/block data through RPC, produce blocks during leader slots (entries → shreds → broadcast → self-replay), create and restore snapshots, and publish metrics to Prometheus.

**Operational**: Gossip discovery, turbine shred reception, FEC reconstruction, block replay, vote submission, snapshot auto-scheduling with gossip hash publishing, leader pipeline with real execution, shred store persistence, repair protocol, blockstore GC with retention policies.

**Remaining for full devnet operation**: TPU forwarding resilience (fallback leader chain), expanded conformance testing against reference implementations.

### Mainnet Readiness: 6/10

Core consensus, execution, and storage logic is functionally complete. All P0 and P1 blockers resolved. Gaps are in operational hardening:

- Performance optimization: crypto ASM paths, zero-copy critical paths, shared memory IPC tuning
- Security: formal audit, fuzzing coverage
- Observability: Prometheus metrics wired for all major stages, remaining: per-account I/O tracking
- Resilience: network partition handling, disk I/O backpressure, memory budget enforcement
- Production tooling: gRPC plugin transport (HTTP/2 + protobuf), ledger-tool equivalent

## Code Quality

- **Linting**: `clippy` with `-D warnings` (zero warnings policy)
- **Formatting**: `rustfmt` with custom rules (`rustfmt.toml`)
- **CI**: `just ci` runs format check + clippy + all tests
- **Constants discipline**: All protocol constants in `paradencer-constants` crate (single source of truth)
- **Zero warnings**: Clean `cargo check --workspace` with no dead code or unused imports
- **TODO tracking**: Zero outstanding TODOs in production code

## License

Copyright (c) 2025-2026 boogvar. All rights reserved.

This software is proprietary and confidential. See `LICENSE` for full terms.
