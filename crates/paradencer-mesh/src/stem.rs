/// Tile stem: multi-link management for a tile.
///
/// A tile typically has multiple input and output links. The `TileStem`
/// manages all output links for a tile, providing credit-tracked
/// publishing and round-robin input polling.
///
/// Each output has its own MetaRing + DataRegion + sequence counter.
/// Credits are tracked per-output to prevent overwhelming slow consumers.
use crate::data_region::{compact_next, DataRegion};
use crate::flow::FlowSequence;
use crate::fragment::{seq_diff, seq_inc};
use crate::meta_ring::MetaRing;

// ---------------------------------------------------------------------------
// StemOutput — one output link managed by the stem
// ---------------------------------------------------------------------------

/// An output link managed by the TileStem.
pub struct StemOutput {
    /// Metadata ring for this output.
    meta_ring: MetaRing,
    /// Data region for payload storage.
    data_region: DataRegion,
    /// Next sequence number to publish.
    seq: u64,
    /// Ring depth.
    depth: usize,
    /// Current write chunk position.
    current_chunk: u32,
    /// First valid chunk.
    chunk0: u32,
    /// High water mark for compact mode.
    wmark: u32,
    /// Maximum payload size.
    mtu: usize,
    /// Available credits (how many more fragments can be published).
    credits: usize,
}

/// Configuration for a single stem output.
#[derive(Debug, Clone)]
pub struct StemOutputConfig {
    /// Maximum fragment payload size in bytes.
    pub mtu: usize,
    /// Ring depth (power of 2).
    pub depth: usize,
    /// Initial sequence number.
    pub initial_seq: u64,
}

impl Default for StemOutputConfig {
    fn default() -> Self {
        Self {
            mtu: paradencer_constants::ipc::DATA_REGION_DEFAULT_MTU,
            depth: paradencer_constants::ipc::META_RING_DEFAULT_DEPTH,
            initial_seq: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// StemInput — one input link consumed by the tile
// ---------------------------------------------------------------------------

/// An input link consumed by a tile via the TileStem.
pub struct StemInput {
    /// Reference to the producer's metadata ring.
    // TODO: Used when input polling is implemented.
    _meta_ring_ptr: *const MetaRing,
    /// Reference to the producer's data region.
    _data_region_ptr: *const DataRegion,
    /// Flow sequence for returning credits to the producer.
    _flow_seq_ptr: *const FlowSequence,
    /// Next expected sequence number.
    _seq: u64,
    /// Ring depth.
    _depth: u32,
    /// Index of this input in the stem's input list.
    _idx: u32,
}

// SAFETY: StemInput holds raw pointers to shared resources that are
// guaranteed to outlive the stem (owned by TileLink or similar).
// Access patterns follow the SPSC protocol.
unsafe impl Send for StemInput {}
unsafe impl Sync for StemInput {}

// ---------------------------------------------------------------------------
// TileStem
// ---------------------------------------------------------------------------

/// Multi-link manager for a tile.
///
/// Manages multiple output links (for publishing) and provides
/// credit tracking per output. Input links are managed separately
/// by the tile's polling loop.
pub struct TileStem {
    /// Output links.
    outputs: Vec<StemOutput>,
    /// Minimum credits across all outputs (bottleneck indicator).
    min_credits: usize,
}

impl TileStem {
    /// Create a new TileStem with the given output configurations.
    pub fn new(output_configs: &[StemOutputConfig]) -> Self {
        let outputs: Vec<StemOutput> = output_configs
            .iter()
            .map(|cfg| {
                let meta_ring = MetaRing::new(cfg.depth, cfg.initial_seq);
                let data_region = DataRegion::for_link(cfg.mtu, cfg.depth, 1, true);
                let chunk0 = data_region.chunk0();
                let wmark = data_region.watermark(cfg.mtu);

                StemOutput {
                    meta_ring,
                    data_region,
                    seq: cfg.initial_seq,
                    depth: cfg.depth,
                    current_chunk: chunk0,
                    chunk0,
                    wmark,
                    mtu: cfg.mtu,
                    credits: cfg.depth, // Start with full credits.
                }
            })
            .collect();

        let min_credits = outputs.iter().map(|o| o.credits).min().unwrap_or(0);

        Self {
            outputs,
            min_credits,
        }
    }

    /// Number of output links.
    #[inline]
    pub fn output_count(&self) -> usize {
        self.outputs.len()
    }

    /// Publish a fragment to a specific output.
    ///
    /// Writes the payload to the output's data region and publishes
    /// metadata to its MetaRing. Returns the sequence number on success,
    /// or `None` if no credits are available for this output.
    pub fn publish(
        &mut self,
        out_idx: usize,
        sig: u64,
        payload: &[u8],
        ctl: u16,
        tsorig: u32,
        tspub: u32,
    ) -> Option<u64> {
        let output = &mut self.outputs[out_idx];

        assert!(payload.len() <= output.mtu, "payload exceeds output MTU");

        if output.credits == 0 {
            return None;
        }

        // Write payload to data region.
        let chunk = output.current_chunk;
        // SAFETY: current_chunk is maintained within [chunk0, wmark].
        unsafe {
            let dest = output.data_region.write_slice(chunk, payload.len());
            dest.copy_from_slice(payload);
        }

        // Publish metadata.
        let seq = output.seq;
        output
            .meta_ring
            .publish(seq, sig, chunk, payload.len() as u16, ctl, tsorig, tspub);

        // Advance state.
        output.current_chunk = compact_next(chunk, payload.len(), output.chunk0, output.wmark);
        output.seq = seq_inc(seq, 1);
        output.credits -= 1;

        // Update minimum credits.
        self.min_credits = self.min_credits.min(output.credits);

        // Update watermark.
        output.meta_ring.update_watermark(output.seq);

        Some(seq)
    }

    /// Refresh credits for an output based on consumer flow sequence.
    ///
    /// Call this periodically to update credits from consumer progress.
    pub fn refresh_credits(&mut self, out_idx: usize, consumer_fseq: &FlowSequence) {
        let output = &mut self.outputs[out_idx];
        let consumer_seq = consumer_fseq.query();
        let ahead = seq_diff(output.seq, consumer_seq);
        if ahead >= 0 {
            output.credits = output.depth.saturating_sub(ahead as usize);
        } else {
            output.credits = output.depth;
        }
        self.min_credits = self.outputs.iter().map(|o| o.credits).min().unwrap_or(0);
    }

    /// Minimum credits across all outputs (bottleneck indicator).
    #[inline]
    pub fn min_credits(&self) -> usize {
        self.min_credits
    }

    /// Whether any output has credits available.
    #[inline]
    pub fn has_credits(&self) -> bool {
        self.min_credits > 0
    }

    /// Access a specific output's MetaRing (for wiring to consumers).
    pub fn output_meta_ring(&self, out_idx: usize) -> &MetaRing {
        &self.outputs[out_idx].meta_ring
    }

    /// Access a specific output's DataRegion (for wiring to consumers).
    pub fn output_data_region(&self, out_idx: usize) -> &DataRegion {
        &self.outputs[out_idx].data_region
    }

    /// Current sequence number for a specific output.
    pub fn output_seq(&self, out_idx: usize) -> u64 {
        self.outputs[out_idx].seq
    }

    /// Available credits for a specific output.
    pub fn output_credits(&self, out_idx: usize) -> usize {
        self.outputs[out_idx].credits
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fragment::ctl_pack;
    use crate::meta_ring::PollResult;

    fn default_stem() -> TileStem {
        TileStem::new(&[StemOutputConfig {
            mtu: 256,
            depth: 16,
            initial_seq: 0,
        }])
    }

    #[test]
    fn create_stem() {
        let stem = default_stem();
        assert_eq!(stem.output_count(), 1);
        assert!(stem.has_credits());
        assert_eq!(stem.min_credits(), 16);
    }

    #[test]
    fn publish_and_read() {
        let mut stem = default_stem();
        let ctl = ctl_pack(0, true, true, false);

        let seq = stem.publish(0, 0xCAFE, b"stem payload", ctl, 0, 0);
        assert_eq!(seq, Some(0));

        // Read from the output's meta ring.
        let ring = stem.output_meta_ring(0);
        match ring.poll(0, 1) {
            PollResult::Ready(meta) => {
                assert_eq!(meta.sig, 0xCAFE);
                assert_eq!(meta.sz, 12); // "stem payload".len()
            }
            other => panic!("expected Ready, got {:?}", other),
        }
    }

    #[test]
    fn multi_output_stem() {
        let mut stem = TileStem::new(&[
            StemOutputConfig {
                mtu: 128,
                depth: 8,
                initial_seq: 0,
            },
            StemOutputConfig {
                mtu: 256,
                depth: 16,
                initial_seq: 100,
            },
        ]);

        assert_eq!(stem.output_count(), 2);

        let ctl = ctl_pack(0, true, true, false);

        // Publish to output 0.
        let seq0 = stem.publish(0, 1, b"out0", ctl, 0, 0);
        assert_eq!(seq0, Some(0));

        // Publish to output 1.
        let seq1 = stem.publish(1, 2, b"out1", ctl, 0, 0);
        assert_eq!(seq1, Some(100));

        assert_eq!(stem.output_seq(0), 1);
        assert_eq!(stem.output_seq(1), 101);
    }

    #[test]
    fn credit_exhaustion() {
        let mut stem = TileStem::new(&[StemOutputConfig {
            mtu: 64,
            depth: 4,
            initial_seq: 0,
        }]);

        let ctl = ctl_pack(0, true, true, false);

        // Publish depth fragments (exhausts credits).
        for i in 0..4 {
            assert!(stem.publish(0, i, b"x", ctl, 0, 0).is_some());
        }

        assert_eq!(stem.output_credits(0), 0);
        assert!(!stem.has_credits());

        // Next publish should fail.
        assert!(stem.publish(0, 4, b"x", ctl, 0, 0).is_none());
    }

    #[test]
    fn credit_refresh() {
        let mut stem = TileStem::new(&[StemOutputConfig {
            mtu: 64,
            depth: 4,
            initial_seq: 0,
        }]);

        let ctl = ctl_pack(0, true, true, false);
        let consumer_fseq = FlowSequence::new(0);

        // Exhaust credits.
        for i in 0..4 {
            stem.publish(0, i, b"x", ctl, 0, 0);
        }
        assert_eq!(stem.output_credits(0), 0);

        // Simulate consumer progress.
        consumer_fseq.update(2);
        stem.refresh_credits(0, &consumer_fseq);

        // Should now have 2 credits.
        assert_eq!(stem.output_credits(0), 2);

        // Can publish 2 more.
        assert!(stem.publish(0, 10, b"y", ctl, 0, 0).is_some());
        assert!(stem.publish(0, 11, b"y", ctl, 0, 0).is_some());
        assert!(stem.publish(0, 12, b"y", ctl, 0, 0).is_none());
    }
}
