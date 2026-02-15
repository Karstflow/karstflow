mod decoder;
mod dedup;
mod domain;
mod limiters;
mod policy;
mod verify;
mod verify_batch;

pub use decoder::{PacketDecoder, ShredDecoder};
pub use dedup::SignatureDeduplicator;
pub use domain::{
    DecodeOutcome, DedupDecision, DropReason, InboundFrame, IngressSource, PreparedShred,
    PreparedTransaction, ShredDecodeOutcome,
};
pub use limiters::{SourceCostBudgetLimiter, SourceRateLimiter};
pub use policy::{IngressMode, IngressPolicy};
pub use verify::{SignatureVerifier, VerificationError, VerificationResult, VerificationStats};
pub use verify_batch::{
    BatchVerificationError, BatchVerificationStats, ParsedTransaction, TransactionBatchVerifier,
};

#[cfg(test)]
mod tests;
