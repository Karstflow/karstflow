set positional-arguments

default:
  @just --list

check:
  cargo check

fmt:
  cargo fmt --all

fmt-check:
  cargo fmt --all -- --check

lint:
  cargo clippy --workspace --all-targets -- -D warnings

test:
  cargo test --workspace --all-targets

build:
  cargo build --workspace --all-targets

run:
  KARSTFLOW_EXEC_MODE=tokio KARSTFLOW_RUN_SECONDS=10 cargo run -p karstflow-node

run-pinned:
  KARSTFLOW_EXEC_MODE=pinned KARSTFLOW_RUN_SECONDS=10 cargo run -p karstflow-node

ci:
  just fmt-check
  just lint
  just test

smoke:
  KARSTFLOW_EXEC_MODE=tokio KARSTFLOW_RUN_SECONDS=2 cargo run -p karstflow-node

# Development mode: auto-genesis with funded faucet, airdrop enabled
dev:
  cargo run -p karstflow-node -- --profile local

# Development mode with tile executor
dev-tile:
  KARSTFLOW_EXEC_MODE=tile cargo run -p karstflow-node -- --profile local

# Run with a specific cluster profile (devnet, testnet, mainnet, local)
run-profile profile:
  cargo run -p karstflow-node -- --profile {{profile}}

# Generate a custom genesis.bin interactively
genesis-init:
  cargo run -p karstflow-node -- genesis init

# Run with an existing genesis file
run-genesis path:
  KARSTFLOW_GENESIS_PATH={{path}} cargo run -p karstflow-node

# Run integration tests (excluded from normal `just test`)
integration:
  cargo test -p karstflow-integration-tests -- --ignored --test-threads=1

# Run conformance tests (excluded from normal `just test`)
conformance:
  cargo test -p karstflow-conformance -- --ignored --test-threads=1

# Replay the upstream conformance-vector corpus. Needs KARSTFLOW_TEST_VECTORS
# pointing at the corpus root; without it the tests report a skip and pass.
conformance-vectors:
  cargo test -p karstflow-conformance vector_conformance -- --ignored --test-threads=1 --nocapture

# Initialize a local multi-validator cluster (default: 3 nodes, output: cluster-data/)
cluster-init n="3" dir="cluster-data":
  cargo run -p karstflow-node -- genesis cluster {{n}} --output-dir {{dir}}

# Start all nodes in a previously initialized cluster
cluster-start dir="cluster-data":
  bash {{dir}}/start.sh
