# Paradencer

> High-performance Solana validator implementation in Rust

Paradencer is a ground-up Rust rewrite of [Firedancer](https://github.com/firedancer-io/firedancer) — Jump Crypto's high-performance Solana validator. The goal is to preserve Firedancer's architecture, logic, and performance characteristics while leveraging Rust's safety guarantees, type system, and ecosystem.

**155K+ lines of Rust | 2,990 tests | 19 crates | ~63% Firedancer logic parity**

## Design Philosophy

- **Firedancer-native**: Rewriting Firedancer's native validator (not Frankendancer/Agave hybrid)
- **Performance first**: Atomic operations, batch processing, zero-copy where possible, parallel execution
- **Clean architecture**: 19-crate modular workspace with clear separation of concerns
- **Idiomatic Rust**: Not a line-by-line port — logic adapted to Rust's strengths (channels, iterators, Result types, traits)
- **No Agave dependency**: Full native implementation, no runtime dependency on Solana/Agave repos

## Architecture

```
paradencer-types          (core types: Pubkey, Account, Hash, Shred)
  |
  +-- paradencer-sbpf     (VM + builtin programs: System, Vote, Stake, Token...)
  |
  +-- paradencer-storage  (MVCC accounts, blockstore, snapshots, persistent backend)
  |     |
  |     +-- paradencer-consensus  (Bank, BankForks, Tower BFT, Fork Choice, Economics)
  |
  +-- paradencer-crypto   (Ed25519 batch, Blake3, SHA-256, Reed-Solomon FEC, LtHash)
  |
  +-- paradencer-ingress  (QUIC transport, Turbine, Gossip, Repair, Shred processing)
  |
  +-- paradencer-stages   (Replay stage, Block production, PoH service)
  |
  +-- paradencer-rpc      (JSON-RPC 2.0 server, WebSocket subscriptions)
  |
  +-- paradencer-node     (Main validator orchestration)
```

### Crate Overview

| Crate | Tests | Purpose |
|-------|-------|---------|
| `paradencer-consensus` | 717 | Tower BFT, fork choice, leader schedule, epoch schedule, stake tracking, Bank, economics |
| `paradencer-sbpf` | 585 | Transaction processor, SBPF VM, 7 builtin programs (System/Vote/Stake/Token/Token-2022/Memo/ATA) |
| `paradencer-storage` | 383 | MVCC account database, blockstore, snapshot pipeline, persistent storage backend |
| `paradencer-stages` | 380 | Replay stage with fork choice, block production with PoH service |
| `paradencer-rpc` | 374 | 40+ JSON-RPC methods, WebSocket subscriptions, transaction simulation |
| `paradencer-crypto` | 145 | Ed25519 batch verification, Blake3/SHA-256 hashing, Reed-Solomon FEC, LtHash |
| `paradencer-ingress` | 144 | QUIC transport, Turbine block propagation, Gossip membership, Repair protocol |
| `paradencer-types` | 52 | Core types: Account, Pubkey, Hash, Shred structures |
| `paradencer-constants` | — | Protocol constants: fees, timing, compute limits, program IDs |
| `paradencer-ids` | — | Well-known program addresses |
| `paradencer-config` | — | TOML configuration management |
| `paradencer-mesh` | — | Inter-component communication channels |
| `paradencer-topology` | — | Service topology and orchestration |
| `paradencer-execution` | — | Batch execution orchestration and retry logic |
| `paradencer-observability` | — | Metrics and monitoring |
| `paradencer-control` | — | Control plane and admin API |
| `paradencer-node` | — | Main validator node entry point |
| `paradencer-runtime` | — | Runtime utilities |
| `paradencer-core` | — | Core utilities |

## Firedancer Parity Status

Estimated at **~63%** weighted by functional importance for a working validator.

| Area | Parity | Key Capabilities |
|------|--------|-----------------|
| Sysvars | 90% | All 14 sysvars, SysvarCache, per-slot/per-epoch updates |
| Builtin Programs | 82% | 12+ programs, 96+ instructions, comprehensive test coverage |
| VM + Syscalls | 80% | Interpreter, CPI/crypto/PDA syscalls, SBPF versions, memory model |
| Rewards & Stakes | 80% | Inflation, partitioned distribution, 18 stake handlers |
| Runtime Core | 75% | Bank, executor, epoch processing, cost tracker, transaction cache |
| Consensus | 70% | Tower BFT, GHOST fork choice, equivocation detection, commitment tracking |
| Storage | 64% | MVCC accounts, blockstore, snapshots (read+write), persistent backend, compaction |
| Types | 55% | Core types done, many inline serialization types pending |
| Crypto | 50% | Ed25519 batch, Blake3, SHA-256, Keccak, Secp256k1, BN254, Reed-Solomon, LtHash |
| Tile Pipeline | 30% | Replay stage, block production, shred assembly; pack/net/metrics gaps |
| Network Stack | 30% | QUIC via quinn, gossip/repair basic, protocol behavior partial |
| App/Config/IPC | 25% | Config done, control plane basic; no tango/shared-memory IPC |

See `docs/00_development_state.md` and `docs/04_module_residual_matrix.md` for detailed tracking.

## Builtin Programs

| Program | Instructions | Status |
|---------|-------------|--------|
| System Program | 13/13 | Complete |
| Vote Program | 17/17 | Complete |
| Stake Program | 18/18 | Complete |
| Token Program | 23/23 | Complete |
| Token-2022 Program | 15/15 | Complete |
| Memo Program | 2/2 | Complete |
| Associated Token Account | 2/2 | Complete |

## Storage Pipeline

The storage subsystem includes a complete snapshot pipeline:

- **AccountDatabase**: Fork-aware MVCC store with DashMap, copy-on-write ancestor chains
- **DurableStore**: Persistent key-value backend with column families (file-based implementation)
- **Blockstore**: Shred windowing with FEC reconstruction, persistent backend
- **Snapshot creation**: Full and incremental snapshots via dirty-set tracking
- **Snapshot loading**: Parse and restore from snapshot files with DB integration
- **Solana-compatible archives**: Read AND write tar.zst snapshots with AppendVec binary format
- **Snapshot scheduling**: Slot-based full/incremental scheduling with retention management
- **Genesis bootstrap**: Full bootstrap from snapshot including stakes, sysvars, features, history
- **Bank hash verification**: SHA-256 accounts hash with hash-verified state

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

- **`tokio`** — Cooperative async tasks (default)
- **`pinned`** — One service per dedicated core/thread (Firedancer-style)

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

## Project Structure

```
paradencer/
├── crates/                        # 19 Rust crates
│   ├── paradencer-consensus/      # Consensus (Tower BFT, Bank, Economics)
│   ├── paradencer-crypto/         # Cryptography (Ed25519, FEC, Hashing)
│   ├── paradencer-sbpf/           # VM + Builtin programs
│   ├── paradencer-storage/        # Storage (Accounts, Shreds, Snapshots)
│   ├── paradencer-ingress/        # Network (QUIC, Turbine, Gossip, Repair)
│   ├── paradencer-rpc/            # RPC server (JSON-RPC, WebSocket)
│   ├── paradencer-stages/         # Pipeline (Replay, Block Production)
│   ├── paradencer-execution/      # Transaction execution
│   ├── paradencer-types/          # Core type definitions
│   ├── paradencer-ids/            # Program IDs
│   ├── paradencer-constants/      # Protocol constants
│   ├── paradencer-config/         # Configuration
│   ├── paradencer-control/        # Control plane
│   ├── paradencer-mesh/           # IPC channels
│   ├── paradencer-node/           # Node entry point
│   ├── paradencer-observability/  # Metrics
│   ├── paradencer-topology/       # Service topology
│   ├── paradencer-runtime/        # Runtime utilities
│   └── paradencer-core/           # Core utilities
├── config/                        # TOML configuration files
├── docs/                          # Development documentation
│   ├── 00_development_state.md    # Progress tracking
│   ├── 04_module_residual_matrix.md # Module-by-module residual
│   ├── 90_module_mapping_working.md # Firedancer → Paradencer mapping
│   └── plans/                     # Cycle implementation plans
├── Cargo.toml                     # Workspace definition
├── rust-toolchain.toml            # Rust toolchain
└── justfile                       # Development commands
```

## Documentation

| Document | Purpose |
|----------|---------|
| `docs/00_development_state.md` | Overall progress, Firedancer module comparison |
| `docs/04_module_residual_matrix.md` | Per-module remaining work and priorities |
| `docs/90_module_mapping_working.md` | Firedancer → Paradencer name mapping |
| `docs/91_development_conventions.md` | Coding conventions and rules |
| `docs/05_execution_architecture.md` | Transaction execution architecture |
| `docs/plans/` | Detailed cycle implementation plans |

## Code Quality

- **Linting**: `clippy` with `-D warnings` (zero warnings policy)
- **Formatting**: `rustfmt` with custom rules (`rustfmt.toml`)
- **CI**: `just ci` runs format check + clippy + all tests

## License

Copyright (c) 2025 boogvar. All rights reserved.

This software is proprietary and confidential. See `LICENSE` for full terms.
