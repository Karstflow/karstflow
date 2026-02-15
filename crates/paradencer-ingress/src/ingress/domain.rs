#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IngressSource {
    Quic,
    Gossip,
    Bundle,
    Rpc,
}

#[derive(Debug, Clone)]
pub struct InboundFrame {
    pub packet_id: u64,
    pub payload_bytes: usize,
    pub source: IngressSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedTransaction {
    pub transaction_id: u64,
    pub estimated_cost_units: u64,
    pub dedup_fingerprint: u64,
    pub source: IngressSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedShred {
    pub shred_id: u64,
    pub slot: u64,
    pub dedup_fingerprint: u64,
    pub source: IngressSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    EmptyPayload,
    OversizedPayload,
    SourceNotAllowed,
    SourceRateLimited,
    SourceCostBudgetExceeded,
    DownstreamBackpressure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeOutcome {
    Accepted(PreparedTransaction),
    Dropped(DropReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShredDecodeOutcome {
    Accepted(PreparedShred),
    Dropped(DropReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DedupDecision {
    Accepted,
    Duplicate,
}
