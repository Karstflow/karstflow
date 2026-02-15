# Paradencer

> High-performance Solana validator implementation in Rust

Paradencer is a ground-up Rust implementation of a Solana validator, designed for maximum performance, modularity, and correctness.

## 🎯 Design Philosophy

- **Performance First**: Optimized for high-throughput transaction processing
- **Clean Architecture**: Multi-crate workspace with clear separation of concerns
- **Type Safety**: Leveraging Rust's type system for correctness guarantees
- **Comprehensive Testing**: 829 tests ensuring reliability

## 🏗️ Architecture

Paradencer is organized as a modular workspace:

### Core Components

- **`paradencer-consensus`** - Consensus layer (Tower BFT, Fork Choice, Stake tracking)
- **`paradencer-sbpf`** - Transaction processor and builtin program executors (System/Vote/Stake)
- **`paradencer-storage`** - Account database (MVCC), state management, integrates sbpf for execution
- **`paradencer-execution`** - Batch execution orchestration and retry logic
- **`paradencer-ingress`** - QUIC-based transaction ingress with signature verification

### Economic Systems

- **`paradencer-consensus`** - Inflation, Rewards, Fees, Rent calculations

### Infrastructure

- **`paradencer-mesh`** - Inter-component communication
- **`paradencer-topology`** - Service topology and orchestration
- **`paradencer-config`** - Configuration management
- **`paradencer-observability`** - Metrics and monitoring

## 📊 Current Status

### Builtin Programs

| Program | Instructions | Completion |
|---------|-------------|------------|
| System Program | 13/13 | ✅ 100% |
| Vote Program | 17/17 | ✅ 100% |
| Stake Program | 18/18 | ✅ 100% |
| Token Program | 18/23 | 🟨 78% |

### Core Systems

- ✅ **Consensus**: Tower BFT, Fork Choice, Leader Schedule, Epoch Schedule
- ✅ **Economics**: Inflation, Rewards, Fee burning, Rent collection
- ✅ **State Management**: Bank, BankForks, BlockhashQueue
- ✅ **Networking**: QUIC server, Ed25519 signature verification, deduplication
- ✅ **Storage**: Account database, Runtime state, Snapshot catalog

### Test Coverage

- **829 passing tests** across all components
- Comprehensive unit and integration test suites
- Three core programs at 100% instruction coverage
- Token Program at 78% instruction coverage

## 🚀 Quick Start

### Prerequisites

- Rust 1.75+ (specified in `rust-toolchain.toml`)
- Just command runner (optional, for convenience)

### Building

```bash
cargo build --release
```

### Testing

```bash
cargo test --workspace
```

### Development Commands

```bash
just check      # Run cargo check
just test       # Run all tests
just lint       # Run clippy
just fmt        # Format code
```

## ⚙️ Configuration

Paradencer supports two runtime execution modes:

- **`tokio`** - Cooperative async tasks (default)
- **`pinned`** - One service per dedicated core/thread

Set via environment:

```bash
export PARADENCER_EXEC_MODE=tokio
export PARADENCER_WORKERS=16
```

Configuration files:
- `config/node.default.toml` - Node configuration
- `config/ingress.default.toml` - Ingress settings
- `config/topology.default.toml` - Service topology

## 📁 Project Structure

```
paradencer/
├── crates/              # All Rust crates
│   ├── paradencer-consensus/
│   ├── paradencer-sbpf/
│   ├── paradencer-ingress/
│   ├── paradencer-storage/
│   └── ...
├── config/              # Configuration files
├── Cargo.toml          # Workspace definition
└── README.md
```

## 🔬 Development

### Code Quality

- **Linting**: `clippy` with strict settings (`clippy.toml`)
- **Formatting**: `rustfmt` with custom rules (`rustfmt.toml`)
- **CI/CD**: GitHub Actions workflow (`.github/workflows/ci.yml`)

### Contributing

See `CONTRIBUTING.md` for guidelines.

## 📄 License

Copyright (c) 2025 boogvar. All rights reserved.

This software is proprietary and confidential. See `LICENSE` for full terms.

## 🎯 Roadmap

- [x] Consensus layer implementation
- [x] System Program (100%)
- [x] Vote Program (100%)
- [x] Stake Program (100%)
- [x] Runtime integration (transaction processing architecture)
- [ ] SPL Token Program
- [ ] Network protocol implementation
- [ ] Full validator functionality

---

**Status**: Active Development | **Language**: Rust | **License**: Proprietary
