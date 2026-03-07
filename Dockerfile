FROM rust:1.84-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev build-essential cmake clang \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Cache dependencies: copy manifests first, build a dummy to cache deps layer
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/karstflow-core/Cargo.toml crates/karstflow-core/Cargo.toml
COPY crates/karstflow-runtime/Cargo.toml crates/karstflow-runtime/Cargo.toml
COPY crates/karstflow-mesh/Cargo.toml crates/karstflow-mesh/Cargo.toml
COPY crates/karstflow-execution/Cargo.toml crates/karstflow-execution/Cargo.toml
COPY crates/karstflow-storage/Cargo.toml crates/karstflow-storage/Cargo.toml
COPY crates/karstflow-constants/Cargo.toml crates/karstflow-constants/Cargo.toml
COPY crates/karstflow-stages/Cargo.toml crates/karstflow-stages/Cargo.toml
COPY crates/karstflow-config/Cargo.toml crates/karstflow-config/Cargo.toml
COPY crates/karstflow-observability/Cargo.toml crates/karstflow-observability/Cargo.toml
COPY crates/karstflow-rpc/Cargo.toml crates/karstflow-rpc/Cargo.toml
COPY crates/karstflow-control/Cargo.toml crates/karstflow-control/Cargo.toml
COPY crates/karstflow-topology/Cargo.toml crates/karstflow-topology/Cargo.toml
COPY crates/karstflow-node/Cargo.toml crates/karstflow-node/Cargo.toml
COPY crates/karstflow-consensus/Cargo.toml crates/karstflow-consensus/Cargo.toml
COPY crates/karstflow-sbpf/Cargo.toml crates/karstflow-sbpf/Cargo.toml
COPY crates/karstflow-types/Cargo.toml crates/karstflow-types/Cargo.toml
COPY crates/karstflow-ids/Cargo.toml crates/karstflow-ids/Cargo.toml
COPY crates/karstflow-crypto/Cargo.toml crates/karstflow-crypto/Cargo.toml
COPY crates/karstflow-net/Cargo.toml crates/karstflow-net/Cargo.toml
COPY crates/karstflow-plugin/Cargo.toml crates/karstflow-plugin/Cargo.toml
COPY crates/karstflow-integration-tests/Cargo.toml crates/karstflow-integration-tests/Cargo.toml
COPY crates/karstflow-conformance/Cargo.toml crates/karstflow-conformance/Cargo.toml

# Create stub lib.rs for each crate so cargo can resolve the workspace
RUN for crate_dir in crates/*/; do \
      mkdir -p "$crate_dir/src"; \
      echo "" > "$crate_dir/src/lib.rs"; \
    done && \
    mkdir -p crates/karstflow-node/src && \
    echo "fn main() {}" > crates/karstflow-node/src/main.rs

RUN cargo build --release --bin karstflow-node 2>/dev/null || true

# Now copy real source and build
COPY . .
RUN cargo build --release --bin karstflow-node

# ── Runtime stage ────────────────────────────────────────────────────

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r karstflow && useradd -r -g karstflow -m -d /home/karstflow karstflow

COPY --from=builder /build/target/release/karstflow-node /usr/local/bin/
COPY config/local.toml /etc/karstflow/config.toml
COPY config/devnet.toml /etc/karstflow/devnet.toml
COPY config/testnet.toml /etc/karstflow/testnet.toml
COPY config/mainnet.toml /etc/karstflow/mainnet.toml

RUN mkdir -p /var/lib/karstflow/ledger \
             /var/lib/karstflow/accounts \
             /var/lib/karstflow/snapshots \
             /var/log/karstflow && \
    chown -R karstflow:karstflow /var/lib/karstflow /var/log/karstflow

USER karstflow
WORKDIR /home/karstflow

# JSON-RPC, WebSocket, Gossip, TPU
EXPOSE 8899 8900 8001 8000

HEALTHCHECK --interval=5s --timeout=3s --start-period=10s --retries=10 \
    CMD curl -sf http://localhost:8899 -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' || exit 1

ENTRYPOINT ["karstflow-node"]
CMD ["--config", "/etc/karstflow/config.toml", "--dev"]
