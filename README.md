# Karstflow

> High-performance Solana validator implementation in Rust

Karstflow is a ground-up Solana validator built for maximum throughput and minimal latency. It features a custom network stack, pre-allocated data structures, zero-copy I/O patterns, and a modular tile-based architecture designed for predictable performance at scale.

**270K+ lines of Rust | 6,100+ unit tests | 597/668 E2E tests | 22 crates | 8 embedded BPF programs**

## Design Principles

- **Performance first**: Pre-allocated pools, batch processing, zero-copy where possible, segment-based compute metering
- **Native implementation**: No runtime dependency on existing Solana validator codebases
- **Clean architecture**: 22-crate workspace with strict dependency hierarchy and single-responsibility modules
- **Idiomatic Rust**: Leverages Rust's type system, ownership model, traits, and ecosystem for safety and correctness
- **Tile-based execution**: Pinned-core service model for deterministic scheduling and cache locality

## Architecture

```
karstflow-types          (core types: Pubkey, Account, Hash, Shred)
  |
  +-- karstflow-sbpf     (sBPF VM + 16 builtin programs)
  |
  +-- karstflow-storage  (MVCC accounts, blockstore, snapshots, persistent backend)
  |     |
  |     +-- karstflow-consensus  (Bank, BankForks, Tower BFT, Fork Choice, Economics)
  |
  +-- karstflow-crypto   (Ed25519 batch, Blake3, SHA-256, BLS12-381, Reed-Solomon FEC, LtHash, PoH)
  |
  +-- karstflow-net      (Custom QUIC/TLS, Gossip CRDS, Turbine, Repair, XDP)
  |
  +-- karstflow-execution (SVM adapter, batch orchestration, retry logic)
  |
  +-- karstflow-stages   (Replay, Block production, PoH, Pack, Shred assembly, Metrics)
  |
  +-- karstflow-rpc      (JSON-RPC 2.0 server, WebSocket subscriptions)
  |
  +-- karstflow-plugin   (Dynamic plugin system, RPC control, C FFI)
  |
  +-- karstflow-node     (Validator orchestration and entry point)
```

### Crate Overview

| Crate | LOC | Tests | Purpose |
|-------|-----|-------|---------|
| `karstflow-consensus` | 46,076 | 1,168 | Tower BFT, GHOST fork choice, leader schedule, epoch processing, Bank lifecycle, multi-threshold confirmation |
| `karstflow-sbpf` | 44,790 | 872 | sBPF interpreter (126 opcodes), 16 builtin programs, ELF loader, CPI, 40+ syscalls, program cache |
| `karstflow-stages` | 43,836 | 907 | Replay with fork tracking, block production, PoH state machine, pack scheduler with CU pacing, shred pipeline, metrics aggregation |
| `karstflow-net` | 40,947 | 904 | Custom QUIC engine, TLS 1.3, gossip with 14-type CRDS, turbine broadcast, repair, AF_XDP |
| `karstflow-storage` | 29,317 | 744 | Disk-primary account database, blockstore, full+incremental snapshots, persistent backend, LZ4 compression |
| `karstflow-rpc` | 16,671 | 441 | 60+ JSON-RPC methods, 9 WebSocket subscription types, transaction simulation |
| `karstflow-control` | 9,009 | 129 | Control plane: bootstrap, preflight validation, diagnostics, service materialization |
| `karstflow-config` | 7,769 | 207 | TOML configuration with env override, live-mode preflight checks, schema migration |
| `karstflow-mesh` | 6,615 | 147 | Dual-mode IPC (channels + shared memory), typed SPSC tile links, bounded channels, stats tracking |
| `karstflow-crypto` | 6,113 | 190 | Ed25519 batch verification, Blake3/SHA-256/Keccak, secp256k1/r1, BN254, BLS12-381, Reed-Solomon FEC, LtHash |
| `karstflow-execution` | 5,389 | 110 | SVM backend adapter, batch execution orchestration, retry policies |
| `karstflow-types` | 3,848 | 85 | Core types: Account, Pubkey, Hash, Transaction, Shred, compact-u16 codec |
| `karstflow-constants` | 3,023 | -- | Protocol constants: fees, timing, compute limits, program parameters (23 modules) |
| `karstflow-runtime` | 1,412 | 34 | Execution substrate: tokio/pinned/tile modes, CnC supervisor, CPU affinity, lifecycle |
| `karstflow-topology` | 1,342 | 24 | Service topology planning and materialization |
| `karstflow-plugin` | 1,253 | 26 | Dynamic plugin system: load/unload, RPC control, C FFI |
| `karstflow-node` | 1,161 | -- | Validator orchestration and entry point |
| `karstflow-core` | 770 | 40 | Shared vocabulary types (RuntimeSpec, TopologySpec, ExecutionMode) |
| `karstflow-ids` | 515 | 4 | Well-known program and sysvar addresses |
| `karstflow-conformance` | 1,200+ | 35 | Conformance testing: instruction/transaction/block harnesses, state diff engine, fixture system ([README](crates/karstflow-conformance/README.md)) |
| `karstflow-integration-tests` | 800+ | 15 | Multi-node cluster integration tests: airdrop, transfers, BPF deploy, PDA derivation |
| `karstflow-observability` | 192 | -- | Metrics HTTP endpoint, tracing initialization |

## Key Features

### Consensus

- **Tower BFT** with lockout-based vote tracking and switch threshold
- **GHOST fork choice** with weighted voting and ancestry verification
- **Multi-threshold confirmation** pipeline: propagated (1/3), duplicate confirmed (52%), optimistically confirmed (2/3), super confirmed (4/5)
- **Equivocation detection** with cryptographic proof generation
- **Full Bank lifecycle**: Processing -> Frozen -> Rooted with 64 ticks/slot

### Execution

- **16 builtin programs**: System, Vote, Stake, Token, Token-2022, Associated Token, Memo, Compute Budget, Config, BPF Loader, Loader v4, Address Lookup Table, Ed25519 precompile, Secp256k1 precompile, Secp256r1 precompile, ZK ElGamal Proof
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
- **Pack stage**: Transaction scheduling with conflict detection, vote prioritization, CU-based pacing, smallest-pending tracking, penalty/rebate system, bundle scheduling, estimation tables
- **Exec stage**: Microblock execution with compute unit tracking
- **Shred network**: FEC resolver pool, set cache, turbine retransmit, equivocation detection
- **Leader pipeline**: Integrated block production with sign service and pacing
- **Replay service**: Fork-aware slot processing with GHOST fork choice, orphan buffering, cascade replay, ALUT resolution, pre-execution tx verification
- **Metrics aggregation**: Cross-tile Prometheus metrics with HTTP scraping endpoint

All pipeline stages communicate through dual-mode IPC (`DualSender`/`DualReceiver`). Eight `FragmentCodec` implementations cover the full message type set: `RawTransaction`, `UnverifiedTransaction`, `VerifiedTransaction`, `RetransmitDecision`, `CompletedFecSet`, `AssembledBlock`, `EquivocationProof`, `ShredBatch`, plus `Shred` (in karstflow-types).

### RPC

- **61 JSON-RPC methods** with strict envelope and parameter validation
- **9 WebSocket subscription types**: slot, account, root, signature, vote, block, logs, program, slotsUpdates
- **Transaction simulation** engine
- **Account caching** with LRU eviction

### Plugin System (Geyser-compatible)

Karstflow includes a streaming notification system analogous to Solana's Geyser plugin interface. External shared libraries (.so/.dylib) receive real-time account updates, transaction notifications, slot status changes, and block metadata from the validator.

- **Dynamic loading**: Load/unload shared libraries at runtime via C FFI
- **RPC control**: Register, unregister, and query plugins through RPC interface (`pluginRegister`, `pluginUnregister`, `pluginList`, `pluginReload`)
- **Lifecycle management**: Plugin start/stop/reload with graceful handling
- **Notification types**: `AccountUpdate`, `TransactionNotification`, `SlotStatus`, `BlockMetadata`

#### Writing a Plugin

Plugins implement the `PluginInterface` trait and export a C constructor:

```rust
use karstflow_plugin::{PluginInterface, PluginResult, AccountUpdate};

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
KARSTFLOW_PLUGIN_CONFIG=/path/to/plugin-config.json cargo run -p karstflow-node

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
just test           # Run all unit tests
just integration   # Run integration tests (bank-level tx execution)
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

Karstflow supports three execution modes:

- **`tokio`** -- Cooperative async tasks (default, development)
- **`pinned`** -- One service per dedicated core/thread (production)
- **`tile`** -- Pinned cores with CnC supervisor, heartbeat monitoring, and stuck detection (production, recommended)

```bash
# Development mode
KARSTFLOW_EXEC_MODE=tokio KARSTFLOW_RUN_SECONDS=10 cargo run -p karstflow-node

# Production mode with tile executor
KARSTFLOW_EXEC_MODE=tile KARSTFLOW_RUN_SECONDS=10 cargo run -p karstflow-node
```

### IPC Modes

All inter-tile communication uses a dual-mode IPC system. Every point-to-point link in the pipeline supports both modes transparently:

- **`channel`** -- Crossbeam bounded MPMC channels (default, compatible everywhere)
- **`shared_memory`** -- Lock-free SPSC queues in shared memory regions (zero-copy, zero-syscall)

```bash
# Full zero-copy pipeline
KARSTFLOW_IPC_MODE=shared_memory KARSTFLOW_EXEC_MODE=tile cargo run -p karstflow-node
```

**Architecture**: The `DualSender<T>` / `DualReceiver<T>` enum selects at construction time between `Channel(OutPort<T>)` for crossbeam and `Link(TileSender<T>)` / `Link(LinkConsumer<'static>)` for shared memory. Messages are encoded/decoded via the `FragmentCodec` trait — each pipeline type (transactions, shreds, FEC sets, blocks, retransmit decisions, equivocation proofs) has a zero-allocation binary codec. The two paths are completely independent: no fallback, no cross-contamination.

Fan-in links (multiple producers to one consumer, e.g., shred filter fan-in) stay on channels. All point-to-point SPSC links use `dual_link()` which selects the IPC backend based on `IpcMode` config. Shared memory ownership handles are kept alive for the full pipeline lifetime via `link_ownership` in `MaterializedTopology`.

## Test-Validator Mode

Karstflow includes a built-in test-validator mode for local development — no separate binary required. When the cluster mode is set to `dev` (or its alias `test-validator`), the node automatically:

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

## Live Network Mode (Devnet / Testnet / Mainnet)

Karstflow can connect to live Solana networks as an RPC node. In live mode, the node automatically:

1. **Downloads `genesis.bin`** from entrypoint RPC endpoints (`/genesis.tar.bz2`)
2. **Discovers snapshot peers** via gossip (SnapshotHashes CRDS messages)
3. **Downloads the latest snapshot** from the best peer (scored by latency + slot freshness)
4. **Restores accounts** from snapshot and begins replay

### Quick Start (Live Mode)

```bash
# Connect to Solana Devnet
just run-profile devnet

# Or with a custom config:
KARSTFLOW_NODE_CONFIG_PATH=/path/to/devnet.toml cargo run --release -p karstflow-node
```

Minimal devnet config:

```toml
[cluster]
mode = "live"
gossip_bind_addr = "0.0.0.0:8001"
entrypoints = ["entrypoint.devnet.solana.com:8001"]
expected_genesis_hash = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG"
expected_shred_version = 29062
data_dir = "/var/karstflow/data"
identity_keypair_path = "/var/karstflow/identity.json"

[runtime]
mode = "tokio"

[rpc]
enabled = true
bind = "0.0.0.0:8899"

[metrics]
output_target = "file"
file_path = "/var/karstflow/metrics.log"
```

The node will automatically download genesis and snapshot from the network — no manual file management required.

Snapshot and genesis files are served on the **same RPC port** (e.g. `8899`) via tower middleware — other validators can download `/genesis.tar.bz2` and `/snapshot.tar.bz2` directly from the RPC endpoint.

### Embedded BPF Programs

Genesis includes real BPF program binaries from the Solana ecosystem (sourced from agave `program-binaries`):

| Program | ID | Size |
|---------|-----|------|
| SPL Token | `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` | 133 KB |
| SPL Token 2022 | `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb` | 507 KB |
| SPL Memo v1 | `Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo` | 17 KB |
| SPL Memo v3 | `MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr` | 75 KB |
| Associated Token | `ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL` | 105 KB |
| Address Lookup Table | `AddressLookupTab1e1111111111111111111111111` | 170 KB |
| Config | `Config1111111111111111111111111111111111111` | 157 KB |
| Feature Gate | `Feature111111111111111111111111111111111111` | 73 KB |

These are embedded at compile time — no external downloads needed for program execution.

### PoH Architecture

Slot management follows the reference implementation (firedancer) pattern:

- **PoH-driven slots**: The PoH service continuously hashes SHA-256 and drives slot boundaries (no timer-based slot driver)
- **Hardware-calibrated**: `hashes_per_tick` is auto-calibrated to the CPU's SHA-256 speed, targeting ~400ms/slot
- **Transaction mixin**: Executed transactions are mixed into the PoH chain and included in block entries for shredding
- **Leader rotation**: Replay stage detects leader transitions and emits BecameLeader signals

### Multi-Node Local Cluster

For testing multi-validator consensus locally:

```bash
# Generate a 2-node cluster with shared genesis
cargo run --release -p karstflow-node -- genesis cluster 2 --output-dir /tmp/cluster

# Start both nodes
bash /tmp/cluster/start.sh
```

Features verified on local cluster:
- **Cross-node transaction propagation** through PoH entries → shreds → turbine → replay
- **Leader rotation** with hardware-calibrated PoH (~400ms/slot target)
- **Consensus-driven root advancement** via Tower BFT vote chain

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
cargo run -p karstflow-node -- genesis init
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
cargo run -p karstflow-node -- run --profile devnet

# Env vars override any profile setting
KARSTFLOW_RPC_BIND=0.0.0.0:9999 just run-profile devnet
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
karstflow/
+-- crates/                        # 22 Rust crates
|   +-- karstflow-consensus/      # Consensus (Tower BFT, Bank, Economics)
|   +-- karstflow-crypto/         # Cryptography (Ed25519, FEC, Hashing)
|   +-- karstflow-sbpf/           # sBPF VM + Builtin programs
|   +-- karstflow-storage/        # Storage (Accounts, Shreds, Snapshots)
|   +-- karstflow-net/            # Network (Custom QUIC/TLS, Gossip, Turbine, Repair)
|   +-- karstflow-rpc/            # RPC server (JSON-RPC, WebSocket)
|   +-- karstflow-stages/         # Pipeline (Replay, Block Production, PoH, Metrics)
|   +-- karstflow-execution/      # Transaction execution adapter
|   +-- karstflow-plugin/         # Dynamic plugin system
|   +-- karstflow-types/          # Core type definitions
|   +-- karstflow-ids/            # Program IDs
|   +-- karstflow-constants/      # Protocol constants
|   +-- karstflow-config/         # Configuration management
|   +-- karstflow-control/        # Control plane
|   +-- karstflow-mesh/           # Dual-mode IPC (channels + shared memory tile links)
|   +-- karstflow-node/           # Node entry point
|   +-- karstflow-observability/  # Metrics
|   +-- karstflow-topology/       # Service topology
|   +-- karstflow-runtime/        # Runtime utilities
|   +-- karstflow-core/           # Core utilities
|   +-- karstflow-conformance/   # Conformance test harnesses
|   +-- karstflow-integration-tests/ # Multi-node integration tests
+-- config/                        # TOML configuration files
+-- Cargo.toml                     # Workspace definition
+-- rust-toolchain.toml            # Rust toolchain
+-- justfile                       # Development commands
```

## Module Readiness

Current maturity of each subsystem (as of March 2026):

| Module | Maturity | Notes |
|--------|----------|-------|
| Consensus | 99% | Tower BFT, GHOST fork choice, bank lifecycle, epoch processing, rewards, leader schedule (multi-epoch), vote processing with lockout sync, optimistic confirmation, commitment tracking, equivocation detection, tower persistence, sysvar cache, 260/260 features |
| sBPF VM | 98% | All 126 opcodes, 16 builtins with 100% real mutations (zero stubs), 40+ syscalls, ELF loader, program cache, CPI depth enforcement (max 4), Poseidon syscall, ALT deactivation guard, segment-based CU metering. All native programs production-ready: System (13), Vote (17 with full lockout/tower sync), Stake (full lifecycle), Token (18), Token-2022 (43), BPF Loader (9), Loader v4 (7), ALT (5), Config, Compute Budget, Memo, Associated Token, 3 precompiles, ZK ElGamal (13). Remaining: JIT (not planned) |
| Pipeline Stages | 100% | Full leader pipeline (verify → resolv → pack → exec → PoH → shred → broadcast) with real account state, FEC resolver, replay with orphan buffering + cascade + ALUT + tx verification, dual-mode IPC, CU pacing, smallest-txn tracking, schedule metrics, Prometheus metrics |
| Network | 97% | Custom QUIC with pool lifecycle hardening, TLS 1.3, gossip (14 CRDS types + vote integration), turbine with real stake weights + XDP + retransmit cache eviction, repair with signed requests, AF_XDP kernel-bypass (4K LOC), TPU forwarding. Remaining: gRPC plugin transport (auxiliary) |
| Storage | 98% | Disk-primary MVCC accounts, file-backed store, full/incremental snapshots with gossip hash publishing + merkle tree + parallel decompress, blockstore indexes, LZ4 compression, lattice hash, auto-scheduled snapshot creation |
| IPC / Mesh | 98% | Dual-mode SPSC (channels + shared memory), 9 FragmentCodec implementations, tile links, bounded channels with backpressure stats |
| RPC | 100% | 61 JSON-RPC methods (vs 52 in reference) with real bank data via BankAccessProvider, 9 WebSocket subscription types, transaction simulation, getHealth wired to real health check |
| Execution | 98% | SVM adapter with real BankExecutionEngine enforced in production, batch orchestration, retry policies, compute budget enforcement, epoch rewards sysvar wiring |
| Crypto | 99% | Ed25519 batch verify, Blake3/SHA-256/Keccak, secp256k1/r1, BN254 pairing, BLS12-381 (G1/G2 via BLST), Reed-Solomon FEC, LtHash, ChaCha20 RNG, PoH module, ZK ElGamal (13 instruction types) |
| Config | 98% | TOML with env override, live-mode preflight, schema migration, cluster profiles, UDP/XDP transport config, feature gate registry with override modes |
| Control | 98% | Bootstrap with transport branching (UDP/XDP), materialization, consensus wiring, shred store service, snapshot scheduling, configure/monitor CLI |
| Runtime | 98% | Tokio/pinned/tile modes, CnC supervisor, heartbeat, stuck detection, graceful shutdown |

### Overall Readiness: 99%

Weighted readiness score across all subsystems (consensus 15%, networking 12%, stages 15%, storage 10%, execution 10%, native programs 10%, crypto 10%, IPC 5%, RPC 5%, config 5%, runtime 3%).

### Devnet Readiness: 9/10

The validator can boot from genesis or snapshot, sync via gossip and turbine, participate in consensus (voting, fork choice, root advancement), serve real account/block data through RPC, produce blocks during leader slots (entries → shreds → broadcast → self-replay), create and restore snapshots, and publish metrics to Prometheus.

**Operational**: Gossip discovery, turbine shred reception, FEC reconstruction, block replay, vote submission, snapshot auto-scheduling with gossip hash publishing, leader pipeline with real execution, shred store persistence, repair protocol, blockstore GC with retention policies.

**Remaining for full devnet operation**: Expanded conformance testing, TPU forwarding fallback chain.

### Mainnet Readiness: 7/10

Core consensus, execution, and storage logic is functionally complete at 99% reference parity. Gaps are in operational hardening:

- Performance optimization: crypto ASM paths, zero-copy critical paths, shared memory IPC tuning
- Security: formal audit, fuzzing coverage
- Observability: per-account I/O tracking
- Resilience: network partition handling, disk I/O backpressure, memory budget enforcement
- Production tooling: gRPC plugin transport (HTTP/2 + protobuf), ledger-tool equivalent

## Hardware Requirements

### Local Development (1 node, `just dev`)

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 4 cores | 8 cores |
| RAM | 8 GB | 16 GB |
| Disk | SSD 50 GB | NVMe 100 GB |
| OS | macOS / Linux | Linux (for AF_XDP) |

Sufficient for: dev genesis, RPC transactions, program testing, integration tests.

### Local Cluster (3 nodes, single machine)

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 8 cores | 16 cores |
| RAM | 16 GB | 32 GB |
| Disk | NVMe 100 GB | NVMe 200 GB |

Each node uses ~2–4 GB RAM in tokio mode. Pinned/tile mode requires 3–4 dedicated cores per node.

```bash
just cluster-init 3    # generates 3-node cluster configs
just cluster-start     # starts all nodes
```

### Multi-Server Cluster (3 separate machines)

| Resource (each) | Minimum | Recommended |
|-----------------|---------|-------------|
| CPU | 4 cores | 8+ cores |
| RAM | 8 GB | 16 GB |
| Disk | NVMe 50 GB | NVMe 100 GB |
| Network | 1 Gbps | 10 Gbps |

### Execution Mode Impact on Resources

| Mode | CPU per Node | Use Case |
|------|-------------|----------|
| `tokio` | 2–4 cores (shared) | Development, testing |
| `pinned` | 8–12 dedicated cores | Pre-production |
| `tile` | 16+ dedicated cores | Production (CnC supervisor, heartbeat) |

AF_XDP kernel-bypass requires Linux with root or `CAP_NET_RAW`.

## Testing

### Unit Tests

```bash
just test              # 6,100+ tests across 22 crates
just ci                # fmt-check + clippy + test
```

### Integration Tests

Bank-level transaction execution tests (bootstrap, SOL transfers, signature verification). Excluded from `cargo test --workspace` via `#[ignore]`.

```bash
just integration       # run all integration tests
```

Tests cover:
- Dev genesis bootstrap and bank state verification
- SOL transfer via `process_transaction` (unsigned + Ed25519 signed)
- Multiple sequential transfers with balance accumulation
- Insufficient funds rejection
- Airdrop → transfer end-to-end flow

### Conformance Tests

Three-layer execution verification: instruction, transaction, and block. Tests compare execution outcomes against expected post-states and verify bank hash determinism. See [karstflow-conformance README](crates/karstflow-conformance/README.md) for details.

```bash
just conformance       # run conformance tests (20 ignored tests)
```

### Smoke Test

```bash
just smoke             # 2-second node startup/shutdown cycle
```

### E2E Tests (karstflow-tests)

Black-box testing via JSON-RPC and WebSocket using the official Solana Python client. See [karstflow-tests README](../karstflow-tests/README.md) for setup and usage.

```bash
cd ../karstflow-tests
just smoke             # health + genesis checks
just functional        # single-node RPC method coverage
just websocket         # WebSocket subscription tests
just integration       # multi-node cluster tests
just load              # Locust load tests + benchmarks
```

### Docker

Build and run the validator in Docker:

```bash
# Build image
docker build -t karstflow:latest .

# Run single dev node
cd ../karstflow-tests
just node-up           # start single node
just node-down         # stop

# Run 3-node cluster
just cluster-up        # start cluster
just cluster-down      # stop
```

### Local Cluster Test

```bash
just dev               # single-node test-validator with auto-genesis
just dev-tile          # same with tile executor (production runtime)
just cluster-init 3    # multi-node local cluster
```

## Code Quality

- **Linting**: `clippy` with `-D warnings` (zero warnings policy)
- **Formatting**: `rustfmt` with custom rules (`rustfmt.toml`)
- **CI**: `just ci` runs format check + clippy + all tests
- **Constants discipline**: All protocol constants in `karstflow-constants` crate (single source of truth)
- **Zero warnings**: Clean `cargo check --workspace` with no dead code or unused imports
- **TODO tracking**: Zero outstanding TODOs in production code

## License

Copyright (c) 2025–2026 boogvar. All rights reserved.

This software is proprietary and confidential. See `LICENSE` for full terms.
