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
  PARADENCER_EXEC_MODE=tokio PARADENCER_RUN_SECONDS=10 cargo run -p paradencer-node

run-pinned:
  PARADENCER_EXEC_MODE=pinned PARADENCER_RUN_SECONDS=10 cargo run -p paradencer-node

ci:
  just fmt-check
  just lint
  just test

smoke:
  PARADENCER_EXEC_MODE=tokio PARADENCER_RUN_SECONDS=2 cargo run -p paradencer-node

# Development mode: auto-genesis with funded faucet, airdrop enabled
dev:
  cargo run -p paradencer-node -- --profile local

# Development mode with tile executor
dev-tile:
  PARADENCER_EXEC_MODE=tile cargo run -p paradencer-node -- --profile local

# Run with a specific cluster profile (devnet, testnet, mainnet, local)
run-profile profile:
  cargo run -p paradencer-node -- --profile {{profile}}

# Generate a custom genesis.bin interactively
genesis-init:
  cargo run -p paradencer-node -- genesis init

# Run with an existing genesis file
run-genesis path:
  PARADENCER_GENESIS_PATH={{path}} cargo run -p paradencer-node
