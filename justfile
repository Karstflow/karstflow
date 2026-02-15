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
