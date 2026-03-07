FROM rust:1.84-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev build-essential cmake clang \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

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
    CMD curl -sf -H "Content-Type: application/json" http://localhost:8899 \
    -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' || exit 1

ENTRYPOINT ["karstflow-node"]
CMD ["--config", "/etc/karstflow/config.toml"]
