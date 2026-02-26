use super::domain::{
    DecodeOutcome, DropReason, InboundFrame, IngressSource, PreparedShred, PreparedTransaction,
    ShredDecodeOutcome,
};
use super::policy::IngressPolicy;
use crate::IngressError;
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
            raw_payload: frame.data.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn default_policy() -> IngressPolicy {
        IngressPolicy::default()
    }

    fn make_frame(packet_id: u64, payload_bytes: usize, source: IngressSource) -> InboundFrame {
        InboundFrame {
            packet_id,
            payload_bytes,
            source,
            data: vec![0u8; payload_bytes],
        }
    }

    // --- PacketDecoder ---

    #[test]
    fn packet_decoder_accepts_valid_frame() {
        let decoder = PacketDecoder::new(default_policy()).unwrap();
        let frame = make_frame(1, 100, IngressSource::Quic);
        match decoder.decode(&frame) {
            DecodeOutcome::Accepted(tx) => {
                assert_eq!(tx.transaction_id, 1);
                assert_eq!(tx.estimated_cost_units, 400); // 100 * 4
                assert_eq!(tx.source, IngressSource::Quic);
            }
            DecodeOutcome::Dropped(reason) => panic!("expected accepted, got {:?}", reason),
        }
    }

    #[test]
    fn packet_decoder_drops_empty_payload() {
        let decoder = PacketDecoder::new(default_policy()).unwrap();
        let frame = make_frame(1, 0, IngressSource::Quic);
        match decoder.decode(&frame) {
            DecodeOutcome::Dropped(DropReason::EmptyPayload) => {}
            other => panic!("expected EmptyPayload, got {:?}", other),
        }
    }

    #[test]
    fn packet_decoder_drops_oversized_payload() {
        let decoder = PacketDecoder::new(default_policy()).unwrap();
        let frame = make_frame(1, 2000, IngressSource::Quic); // default max is 1232
        match decoder.decode(&frame) {
            DecodeOutcome::Dropped(DropReason::OversizedPayload) => {}
            other => panic!("expected OversizedPayload, got {:?}", other),
        }
    }

    #[test]
    fn packet_decoder_drops_disallowed_source() {
        let mut policy = default_policy();
        policy.allow_gossip_source = false;
        let decoder = PacketDecoder::new(policy).unwrap();
        let frame = make_frame(1, 100, IngressSource::Gossip);
        match decoder.decode(&frame) {
            DecodeOutcome::Dropped(DropReason::SourceNotAllowed) => {}
            other => panic!("expected SourceNotAllowed, got {:?}", other),
        }
    }

    #[test]
    fn packet_decoder_dedup_fingerprint_deterministic() {
        let decoder = PacketDecoder::new(default_policy()).unwrap();
        let frame1 = make_frame(42, 100, IngressSource::Quic);
        let frame2 = make_frame(42, 100, IngressSource::Quic);
        let tx1 = match decoder.decode(&frame1) {
            DecodeOutcome::Accepted(tx) => tx,
            _ => panic!("expected accepted"),
        };
        let tx2 = match decoder.decode(&frame2) {
            DecodeOutcome::Accepted(tx) => tx,
            _ => panic!("expected accepted"),
        };
        assert_eq!(tx1.dedup_fingerprint, tx2.dedup_fingerprint);
    }

    // --- ShredDecoder ---

    #[test]
    fn shred_decoder_accepts_valid_frame() {
        let decoder = ShredDecoder::new(default_policy()).unwrap();
        let frame = make_frame(64, 200, IngressSource::Quic);
        match decoder.decode(&frame) {
            ShredDecodeOutcome::Accepted(shred) => {
                assert_eq!(shred.shred_id, 64);
                assert_eq!(shred.slot, 2); // 64 / 32
                assert_eq!(shred.source, IngressSource::Quic);
            }
            ShredDecodeOutcome::Dropped(reason) => panic!("expected accepted, got {:?}", reason),
        }
    }

    #[test]
    fn shred_decoder_drops_empty_payload() {
        let decoder = ShredDecoder::new(default_policy()).unwrap();
        let frame = make_frame(1, 0, IngressSource::Quic);
        assert!(matches!(
            decoder.decode(&frame),
            ShredDecodeOutcome::Dropped(DropReason::EmptyPayload)
        ));
    }

    #[test]
    fn shred_decoder_drops_oversized() {
        let decoder = ShredDecoder::new(default_policy()).unwrap();
        let frame = make_frame(1, 2000, IngressSource::Quic);
        assert!(matches!(
            decoder.decode(&frame),
            ShredDecodeOutcome::Dropped(DropReason::OversizedPayload)
        ));
    }

    // --- fingerprint ---

    #[test]
    fn fingerprint_changes_with_source() {
        let f1 = fingerprint(1, 100, IngressSource::Quic);
        let f2 = fingerprint(1, 100, IngressSource::Gossip);
        assert_ne!(f1, f2);
    }

    #[test]
    fn fingerprint_changes_with_packet_id() {
        let f1 = fingerprint(1, 100, IngressSource::Quic);
        let f2 = fingerprint(2, 100, IngressSource::Quic);
        assert_ne!(f1, f2);
    }
}
