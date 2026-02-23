/// Tile stem: multi-link management for a tile.
///
/// A tile typically has multiple input and output links. The `TileStem`
/// manages all output links for a tile, providing credit-tracked
/// publishing and round-robin input polling.
///
/// Each output has its own MetaRing + DataRegion + FlowSequence + sequence
/// counter. Credits are tracked per-output to prevent overwhelming slow
/// consumers.
use crate::data_region::{compact_next, DataRegion};
use crate::flow::FlowSequence;
use crate::fragment::{seq_diff, seq_inc, FragmentMeta};
use crate::meta_ring::{MetaRing, PollResult};

// ---------------------------------------------------------------------------
// StemOutput — one output link managed by the stem
// ---------------------------------------------------------------------------

/// An output link managed by the TileStem.
pub struct StemOutput {
    /// Metadata ring for this output.
    meta_ring: MetaRing,
    /// Data region for payload storage.
    data_region: DataRegion,
    /// Flow sequence for consumer backpressure.
    flow_seq: FlowSequence,
    /// Next sequence number to publish.
    seq: u64,
    /// Initial sequence number (for consumer creation).
    initial_seq: u64,
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

/// An input link consumed by a tile via raw pointers.
///
/// Created from a `TileStem`'s output, this provides consumer-side access
/// to the producer's MetaRing, DataRegion, and FlowSequence. The producer
/// tile must outlive this input.
///
/// Uses raw pointers for `'static` lifetime, allowing tiles to own their
/// inputs independently from the pipeline's link ownership.
pub struct StemInput {
    /// Pointer to the producer's metadata ring.
    meta_ring: *const MetaRing,
    /// Pointer to the producer's data region.
    data_region: *const DataRegion,
    /// Pointer to the flow sequence (consumer writes, producer reads).
    flow_seq: *const FlowSequence,
    /// Next expected sequence number.
    next_seq: u64,
    /// Index of this input (for round-robin tracking).
    idx: u32,
}

// SAFETY: StemInput holds raw pointers to shared resources that are
// guaranteed to outlive the input (owned by TileStem). Access patterns
// follow the SPSC protocol: one consumer reads metadata + payload,
// one producer writes them.
unsafe impl Send for StemInput {}
unsafe impl Sync for StemInput {}

/// Result of polling a StemInput for a fragment.
#[derive(Debug)]
pub enum InputResult<'a> {
    /// Fragment received with metadata and zero-copy payload reference.
    Ready {
        meta: FragmentMeta,
        payload: &'a [u8],
    },
    /// Consumer was overrun (producer wrapped around the ring).
    Overrun { recover_seq: u64 },
    /// No fragment available yet.
    Empty,
}

impl StemInput {
    /// Create a StemInput wired to the given stem output.
    ///
    /// # Safety
    ///
    /// The `TileStem` that owns the output at `out_idx` must outlive this
    /// `StemInput`. The caller must ensure that only one consumer exists
    /// per output.
    pub unsafe fn from_stem(stem: &TileStem, out_idx: usize, idx: u32) -> Self {
        let output = &stem.outputs[out_idx];
        Self {
            meta_ring: &output.meta_ring as *const MetaRing,
            data_region: &output.data_region as *const DataRegion,
            flow_seq: &output.flow_seq as *const FlowSequence,
            next_seq: output.initial_seq,
            idx,
        }
    }

    /// Poll for the next fragment.
    ///
    /// Returns `InputResult::Ready` with metadata and a zero-copy payload
    /// slice, `InputResult::Overrun` if the consumer fell behind, or
    /// `InputResult::Empty` if nothing is available.
    pub fn receive(&mut self, max_polls: usize) -> InputResult<'_> {
        // SAFETY: meta_ring pointer is valid for the lifetime of the stem.
        let ring = unsafe { &*self.meta_ring };

        match ring.poll(self.next_seq, max_polls) {
            PollResult::Ready(meta) => {
                // SAFETY: data_region pointer is valid, chunk+sz within bounds.
                let payload = unsafe { (*self.data_region).read_payload(meta.chunk, meta.sz) };

                // Advance consumer state.
                self.next_seq = seq_inc(self.next_seq, 1);

                // Update flow sequence for producer backpressure.
                // SAFETY: flow_seq pointer is valid.
                unsafe { (*self.flow_seq).update(self.next_seq) };

                InputResult::Ready { meta, payload }
            }
            PollResult::Overrun { found_seq } => {
                // Recover to the found sequence.
                self.next_seq = found_seq;
                // SAFETY: flow_seq pointer is valid.
                unsafe { (*self.flow_seq).update(self.next_seq) };
                InputResult::Overrun {
                    recover_seq: found_seq,
                }
            }
            PollResult::Timeout => InputResult::Empty,
        }
    }

    /// Next expected sequence number.
    #[inline]
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Index of this input in the tile's input list.
    #[inline]
    pub fn idx(&self) -> u32 {
        self.idx
    }

    /// How far behind this consumer is from the producer watermark.
    pub fn lag(&self) -> u64 {
        // SAFETY: meta_ring pointer is valid.
        let ring = unsafe { &*self.meta_ring };
        let watermark = ring.query_watermark();
        let diff = seq_diff(watermark, self.next_seq);
        if diff > 0 {
            diff as u64
        } else {
            0
        }
    }
}

// ---------------------------------------------------------------------------
// TileStem
// ---------------------------------------------------------------------------

/// Multi-link manager for a tile.
///
/// Manages multiple output links (for publishing) and provides
/// credit tracking per output. Each output has its own MetaRing,
/// DataRegion, and FlowSequence. Consumers connect via `StemInput`
/// created with `create_input()`.
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
                let flow_seq = FlowSequence::new(cfg.initial_seq);
                let chunk0 = data_region.chunk0();
                let wmark = data_region.watermark(cfg.mtu);

                StemOutput {
                    meta_ring,
                    data_region,
                    flow_seq,
                    seq: cfg.initial_seq,
                    initial_seq: cfg.initial_seq,
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

    /// Create a consumer input wired to the given output.
    ///
    /// # Safety
    ///
    /// This TileStem must outlive the returned `StemInput`. Only one
    /// consumer should exist per output for correct SPSC semantics.
    pub unsafe fn create_input(&self, out_idx: usize, input_idx: u32) -> StemInput {
        StemInput::from_stem(self, out_idx, input_idx)
    }

    /// Publish a fragment to a specific output.
    ///
    /// Writes the payload to the output's data region and publishes
    /// metadata to its MetaRing. Returns the sequence number on success,
    /// or `None` if no credits are available for this output.
    #[allow(clippy::too_many_arguments)]
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

    /// Refresh credits for an output by reading its consumer's flow sequence.
    ///
    /// Call this periodically to update credits from consumer progress.
    pub fn refresh_credits(&mut self, out_idx: usize) {
        let output = &mut self.outputs[out_idx];
        let consumer_seq = output.flow_seq.query();
        let ahead = seq_diff(output.seq, consumer_seq);
        if ahead >= 0 {
            output.credits = output.depth.saturating_sub(ahead as usize);
        } else {
            output.credits = output.depth;
        }
        self.min_credits = self.outputs.iter().map(|o| o.credits).min().unwrap_or(0);
    }

    /// Refresh credits for all outputs.
    pub fn refresh_all_credits(&mut self) {
        for i in 0..self.outputs.len() {
            let output = &mut self.outputs[i];
            let consumer_seq = output.flow_seq.query();
            let ahead = seq_diff(output.seq, consumer_seq);
            if ahead >= 0 {
                output.credits = output.depth.saturating_sub(ahead as usize);
            } else {
                output.credits = output.depth;
            }
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

    /// Access a specific output's MetaRing (for diagnostics/wiring).
    pub fn output_meta_ring(&self, out_idx: usize) -> &MetaRing {
        &self.outputs[out_idx].meta_ring
    }

    /// Access a specific output's DataRegion (for diagnostics/wiring).
    pub fn output_data_region(&self, out_idx: usize) -> &DataRegion {
        &self.outputs[out_idx].data_region
    }

    /// Access a specific output's FlowSequence (for external credit refresh).
    pub fn output_flow_seq(&self, out_idx: usize) -> &FlowSequence {
        &self.outputs[out_idx].flow_seq
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
    fn stem_input_receive() {
        let mut stem = TileStem::new(&[StemOutputConfig {
            mtu: 256,
            depth: 16,
            initial_seq: 0,
        }]);

        let ctl = ctl_pack(0, true, true, false);

        // Publish a fragment.
        stem.publish(0, 0xBEEF, b"hello input", ctl, 0, 0);

        // Create an input consumer.
        // SAFETY: stem outlives input within this test.
        let mut input = unsafe { stem.create_input(0, 0) };

        // Receive the fragment.
        match input.receive(1) {
            InputResult::Ready { meta, payload } => {
                assert_eq!(meta.sig, 0xBEEF);
                assert_eq!(payload, b"hello input");
            }
            other => panic!("expected Ready, got {:?}", other),
        }

        // No more fragments.
        match input.receive(1) {
            InputResult::Empty => {}
            other => panic!("expected Empty, got {:?}", other),
        }
    }

    #[test]
    fn stem_input_backpressure() {
        let mut stem = TileStem::new(&[StemOutputConfig {
            mtu: 64,
            depth: 4,
            initial_seq: 0,
        }]);

        let ctl = ctl_pack(0, true, true, false);

        // Create input before publishing.
        // SAFETY: stem outlives input within this test.
        let mut input = unsafe { stem.create_input(0, 0) };

        // Exhaust credits.
        for i in 0..4u64 {
            assert!(stem.publish(0, i, b"x", ctl, 0, 0).is_some());
        }
        assert_eq!(stem.output_credits(0), 0);

        // Consumer reads 2 fragments (advancing flow sequence).
        for _ in 0..2 {
            match input.receive(1) {
                InputResult::Ready { .. } => {}
                other => panic!("expected Ready, got {:?}", other),
            }
        }

        // Refresh credits from the output's own flow sequence.
        stem.refresh_credits(0);
        assert_eq!(stem.output_credits(0), 2);

        // Can publish 2 more.
        assert!(stem.publish(0, 10, b"y", ctl, 0, 0).is_some());
        assert!(stem.publish(0, 11, b"y", ctl, 0, 0).is_some());
        assert!(stem.publish(0, 12, b"y", ctl, 0, 0).is_none());
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
    fn stem_input_lag() {
        let mut stem = TileStem::new(&[StemOutputConfig {
            mtu: 64,
            depth: 16,
            initial_seq: 0,
        }]);

        let ctl = ctl_pack(0, true, true, false);

        // SAFETY: stem outlives input within this test.
        let input = unsafe { stem.create_input(0, 0) };

        // Publish 5 fragments.
        for i in 0..5u64 {
            stem.publish(0, i, b"x", ctl, 0, 0);
        }

        // Input hasn't consumed any — lag should be 5.
        assert_eq!(input.lag(), 5);
    }
}
