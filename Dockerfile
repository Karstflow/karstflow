FROM rust:1.77-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .
RUN cargo build --release --bin karstflow-node

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/karstflow-node /usr/local/bin/
COPY config/default.toml /etc/karstflow/config.toml

EXPOSE 8899 8900 8001 8000

ENTRYPOINT ["karstflow-node"]
CMD ["--config", "/etc/karstflow/config.toml"]
