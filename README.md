# Paradencer

> High-performance Solana validator implementation in Rust

Paradencer is a ground-up Solana validator built for maximum throughput and minimal latency. It features a custom network stack, pre-allocated data structures, zero-copy I/O patterns, and a modular tile-based architecture designed for predictable performance at scale.

**197K+ lines of Rust | 3,855+ tests | 19 crates**

## Design Principles

- **Performance first**: Pre-allocated pools, batch processing, zero-copy where possible, segment-based compute metering
- **Native implementation**: No runtime dependency on existing Solana validator codebases
- **Clean architecture**: 19-crate workspace with strict dependency hierarchy and single-responsibility modules
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
  +-- paradencer-stages   (Replay, Block production, PoH, Pack, Shred assembly)
  |
  +-- paradencer-rpc      (JSON-RPC 2.0 server, WebSocket subscriptions)
  |
  +-- paradencer-node     (Validator orchestration and entry point)
```

### Crate Overview

| Crate | LOC | Tests | Purpose |
|-------|-----|-------|---------|
| `paradencer-sbpf` | 35,646 | 600 | sBPF interpreter (126 opcodes), 12 builtin programs, ELF loader, CPI, 40+ syscalls, program cache |
| `paradencer-net` | 34,754 | 721 | Custom QUIC engine, TLS 1.3, gossip with 14-type CRDS, turbine broadcast, repair, AF_XDP |
| `paradencer-consensus` | 33,156 | 763 | Tower BFT, GHOST fork choice, leader schedule, epoch processing, Bank lifecycle, multi-threshold confirmation |
| `paradencer-stages` | 26,034 | 454 | Replay with fork tracking, block production, PoH state machine, pack scheduler, shred pipeline |
| `paradencer-storage` | 23,896 | 496 | Disk-primary account database, blockstore, full+incremental snapshots, persistent backend, LZ4 compression |
| `paradencer-rpc` | 13,912 | 330 | 60+ JSON-RPC methods, 9 WebSocket subscription types, transaction simulation |
| `paradencer-config` | 5,820 | 87 | TOML configuration with env override, live-mode preflight checks, schema migration |
| `paradencer-crypto` | 5,003 | 141 | Ed25519 batch verification, Blake3/SHA-256/Keccak, secp256k1/r1, BN254, Reed-Solomon FEC, LtHash |
| `paradencer-execution` | 4,849 | 72 | SVM backend adapter, batch execution orchestration, retry policies |
| `paradencer-control` | 3,111 | 48 | Control plane: bootstrap, preflight validation, diagnostics |
| `paradencer-types` | 3,082 | 60 | Core types: Account, Pubkey, Hash, Transaction, Shred, compact-u16 codec |
| `paradencer-mesh` | 2,805 | 57 | Typed bounded channels for inter-tile communication |
| `paradencer-constants` | 2,535 | -- | Protocol constants: fees, timing, compute limits, program parameters (22 modules) |
| `paradencer-topology` | 976 | 10 | Service topology planning and materialization |
| `paradencer-runtime` | 728 | 14 | Execution substrate: tokio/pinned modes, CPU affinity, lifecycle |
| `paradencer-node` | 243 | -- | Validator orchestration and entry point |
| `paradencer-core` | 211 | 2 | Shared vocabulary types |
| `paradencer-ids` | 199 | -- | Well-known program and sysvar addresses |
| `paradencer-observability` | 58 | -- | Metrics HTTP endpoint |

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

### RPC

- **60+ JSON-RPC methods** with strict envelope and parameter validation
- **9 WebSocket subscription types**: slot, account, root, signature, vote, block, logs, program, slotsUpdates
- **Transaction simulation** engine
- **Account caching** with LRU eviction

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
just check       # cargo check
just fmt          # Format all code
just lint         # Clippy with strict settings
just test         # Run all tests
just ci           # fmt-check + lint + test
just run          # Run node (tokio mode)
just run-pinned   # Run node (pinned cores mode)
just smoke        # Quick 2-second smoke run
```

### Runtime Modes

Paradencer supports two execution modes:

- **`tokio`** -- Cooperative async tasks (default, development)
- **`pinned`** -- One service per dedicated core/thread (production)

```bash
PARADENCER_EXEC_MODE=tokio PARADENCER_RUN_SECONDS=10 cargo run -p paradencer-node
```

## Configuration

Configuration files in `config/`:

| File | Purpose |
|------|---------|
| `node.default.toml` | Node identity, cluster, paths |
| `ingress.default.toml` | Network ingress settings |
| `topology.default.toml` | Service topology |

Environment variables override TOML values. Live mode includes preflight safety checks (identity keypair, entrypoint routability, storage catalog validation).

## Project Structure

```
paradencer/
+-- crates/                        # 19 Rust crates
|   +-- paradencer-consensus/      # Consensus (Tower BFT, Bank, Economics)
|   +-- paradencer-crypto/         # Cryptography (Ed25519, FEC, Hashing)
|   +-- paradencer-sbpf/           # sBPF VM + Builtin programs
|   +-- paradencer-storage/        # Storage (Accounts, Shreds, Snapshots)
|   +-- paradencer-net/            # Network (Custom QUIC/TLS, Gossip, Turbine, Repair)
|   +-- paradencer-rpc/            # RPC server (JSON-RPC, WebSocket)
|   +-- paradencer-stages/         # Pipeline (Replay, Block Production, PoH)
|   +-- paradencer-execution/      # Transaction execution adapter
|   +-- paradencer-types/          # Core type definitions
|   +-- paradencer-ids/            # Program IDs
|   +-- paradencer-constants/      # Protocol constants
|   +-- paradencer-config/         # Configuration management
|   +-- paradencer-control/        # Control plane
|   +-- paradencer-mesh/           # IPC channels
|   +-- paradencer-node/           # Node entry point
|   +-- paradencer-observability/  # Metrics
|   +-- paradencer-topology/       # Service topology
|   +-- paradencer-runtime/        # Runtime utilities
|   +-- paradencer-core/           # Core utilities
+-- config/                        # TOML configuration files
+-- docs/                          # Development documentation
+-- Cargo.toml                     # Workspace definition
+-- rust-toolchain.toml            # Rust toolchain
+-- justfile                       # Development commands
```

## Code Quality

- **Linting**: `clippy` with `-D warnings` (zero warnings policy)
- **Formatting**: `rustfmt` with custom rules (`rustfmt.toml`)
- **CI**: `just ci` runs format check + clippy + all tests
- **Constants discipline**: All protocol constants in `paradencer-constants` crate (single source of truth)

## License

Copyright (c) 2025 boogvar. All rights reserved.

This software is proprietary and confidential. See `LICENSE` for full terms.
