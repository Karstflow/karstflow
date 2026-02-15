use super::domain::{
    DecodeOutcome, DropReason, InboundFrame, IngressSource, PreparedShred, PreparedTransaction,
    ShredDecodeOutcome,
};
use super::policy::IngressPolicy;
use crate::IngressError;
use paradencer_crypto::BatchVerifier;
use paradencer_types::shred::{Shred, ShredParseError, ShredParser};
use std::hash::{Hash, Hasher};

pub struct PacketDecoder {
    policy: IngressPolicy,
}

pub struct ShredDecoder {
    policy: IngressPolicy,
}

impl PacketDecoder {
    pub fn new(policy: IngressPolicy) -> Result<Self, IngressError> {
        policy.validate()?;
        Ok(Self { policy })
    }

    pub fn decode(&self, frame: &InboundFrame) -> DecodeOutcome {
        if frame.payload_bytes == 0 {
            return DecodeOutcome::Dropped(DropReason::EmptyPayload);
        }

        if frame.payload_bytes > self.policy.max_payload_bytes {
            return DecodeOutcome::Dropped(DropReason::OversizedPayload);
        }

        if !self.policy.source_is_allowed(frame.source) {
            return DecodeOutcome::Dropped(DropReason::SourceNotAllowed);
        }

        let cost_units = (frame.payload_bytes as u64).saturating_mul(4);
        let dedup_fingerprint = fingerprint(frame.packet_id, frame.payload_bytes, frame.source);

        DecodeOutcome::Accepted(PreparedTransaction {
            transaction_id: frame.packet_id,
            estimated_cost_units: cost_units,
            dedup_fingerprint,
            source: frame.source,
        })
    }
}

impl ShredDecoder {
    pub fn new(policy: IngressPolicy) -> Result<Self, IngressError> {
        policy.validate()?;
        Ok(Self { policy })
    }

    /// Decode a raw frame into a prepared shred
    pub fn decode(&self, frame: &InboundFrame) -> ShredDecodeOutcome {
        if frame.payload_bytes == 0 {
            return ShredDecodeOutcome::Dropped(DropReason::EmptyPayload);
        }

        if frame.payload_bytes > self.policy.max_payload_bytes {
            return ShredDecodeOutcome::Dropped(DropReason::OversizedPayload);
        }

        if !self.policy.source_is_allowed(frame.source) {
            return ShredDecodeOutcome::Dropped(DropReason::SourceNotAllowed);
        }

        let dedup_fingerprint = fingerprint(frame.packet_id, frame.payload_bytes, frame.source);

        ShredDecodeOutcome::Accepted(PreparedShred {
            shred_id: frame.packet_id,
            slot: frame.packet_id / 32,
            dedup_fingerprint,
            source: frame.source,
        })
    }

    /// Parse raw bytes into a shred structure
    pub fn parse_shred(&self, data: &[u8]) -> Result<Shred, ShredParseError> {
        ShredParser::parse(data)
    }

    /// Decode and parse in one operation
    pub fn decode_and_parse(
        &self,
        frame: &InboundFrame,
        data: &[u8],
    ) -> Result<(PreparedShred, Shred), DecodeError> {
        // First decode the frame
        match self.decode(frame) {
            ShredDecodeOutcome::Accepted(prepared) => {
                // Then parse the shred
                let shred = self.parse_shred(data).map_err(DecodeError::ParseError)?;

                Ok((prepared, shred))
            }
            ShredDecodeOutcome::Dropped(reason) => Err(DecodeError::Dropped(reason)),
        }
    }
}

/// Errors that can occur during decoding
#[derive(Debug)]
pub enum DecodeError {
    /// Frame was dropped during decode
    Dropped(DropReason),
    /// Shred parsing failed
    ParseError(ShredParseError),
}

fn fingerprint(packet_id: u64, payload_bytes: usize, source: IngressSource) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    packet_id.hash(&mut hasher);
    payload_bytes.hash(&mut hasher);
    source.hash(&mut hasher);
    hasher.finish()
}
