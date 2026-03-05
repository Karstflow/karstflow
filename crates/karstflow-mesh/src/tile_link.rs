/// Zero-copy inter-tile communication link.
///
/// A `TileLink` combines a MetaRing (fragment metadata ring buffer),
/// DataRegion (payload storage), and FlowSequence (backpressure) into
/// a complete SPSC communication channel between two tiles.
///
/// The producer writes payloads to the DataRegion and publishes metadata
/// to the MetaRing. The consumer polls the MetaRing and reads payloads
/// directly from shared memory — zero copies on the consumer path.
use crate::data_region::{compact_next, DataRegion};
use crate::flow::FlowSequence;
use crate::fragment::{seq_diff, seq_inc, ts_compress, FragmentMeta};
use crate::meta_ring::{MetaRing, PollResult};
use std::sync::OnceLock;
use std::time::Instant;

/// Process-local epoch for monotonic nanosecond timestamps.
///
/// Initialized on first call to `now_nanos()`. All tile link timestamps
/// are relative to this epoch, giving sub-microsecond inter-tile latency
/// measurement within the ~4.3 second window of the 32-bit compressed form.
static EPOCH: OnceLock<Instant> = OnceLock::new();

/// Current nanosecond timestamp relative to process startup.
#[inline]
fn now_nanos() -> i64 {
    let epoch = EPOCH.get_or_init(Instant::now);
    epoch.elapsed().as_nanos() as i64
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for creating a TileLink.
#[derive(Debug, Clone)]
pub struct TileLinkConfig {
    /// Maximum fragment payload size in bytes.
    pub mtu: usize,
    /// Number of fragment slots in the metadata ring (power of 2).
    pub depth: usize,
    /// Number of fragments the producer can prepare concurrently.
    pub burst: usize,
    /// Initial sequence number.
    pub initial_seq: u64,
}

impl Default for TileLinkConfig {
    fn default() -> Self {
        Self {
            mtu: karstflow_constants::ipc::DATA_REGION_DEFAULT_MTU,
            depth: karstflow_constants::ipc::META_RING_DEFAULT_DEPTH,
            burst: 1,
            initial_seq: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// TileLink
// ---------------------------------------------------------------------------

/// A zero-copy SPSC link between a producer tile and a consumer tile.
///
/// Owns the shared resources (MetaRing, DataRegion, FlowSequence) and
/// provides separate producer/consumer views for type-safe access.
pub struct TileLink {
    meta_ring: MetaRing,
    data_region: DataRegion,
    flow_seq: FlowSequence,
    config: TileLinkConfig,
}

impl TileLink {
    /// Create a new link with the given configuration.
    pub fn new(config: TileLinkConfig) -> Self {
        let meta_ring = MetaRing::new(config.depth, config.initial_seq);
        let data_region = DataRegion::for_link(config.mtu, config.depth, config.burst, true);
        let flow_seq = FlowSequence::new(config.initial_seq);

        Self {
            meta_ring,
            data_region,
            flow_seq,
            config,
        }
    }

    /// Create a producer handle for this link.
    pub fn producer(&mut self) -> LinkProducer<'_> {
        self.producer_at(self.config.initial_seq)
    }

    /// Create a producer handle starting at a specific sequence number.
    ///
    /// Useful for resuming production after a producer was dropped
    /// and re-created (e.g., after recovering from a stall).
    pub fn producer_at(&mut self, start_seq: u64) -> LinkProducer<'_> {
        let chunk0 = self.data_region.chunk0();
        let wmark = self.data_region.watermark(self.config.mtu);
        LinkProducer {
            meta_ring: &self.meta_ring,
            data_region: &mut self.data_region,
            flow_seq: &self.flow_seq,
            next_seq: start_seq,
            current_chunk: chunk0,
            chunk0,
            wmark,
            mtu: self.config.mtu,
            depth: self.config.depth,
        }
    }

    /// Create a consumer handle for this link.
    pub fn consumer(&self) -> LinkConsumer<'_> {
        LinkConsumer {
            meta_ring: &self.meta_ring,
            data_region: &self.data_region,
            flow_seq: &self.flow_seq,
            next_seq: self.config.initial_seq,
            depth: self.config.depth,
        }
    }

    /// Create a consumer handle starting at a specific sequence number.
    ///
    /// Useful for resuming consumption after a consumer was dropped
    /// and re-created (e.g., after overrun recovery).
    pub fn consumer_at(&self, start_seq: u64) -> LinkConsumer<'_> {
        LinkConsumer {
            meta_ring: &self.meta_ring,
            data_region: &self.data_region,
            flow_seq: &self.flow_seq,
            next_seq: start_seq,
            depth: self.config.depth,
        }
    }

    /// Access the underlying MetaRing (for diagnostics).
    pub fn meta_ring(&self) -> &MetaRing {
        &self.meta_ring
    }

    /// Access the underlying FlowSequence (for diagnostics).
    pub fn flow_seq(&self) -> &FlowSequence {
        &self.flow_seq
    }

    /// Link configuration.
    pub fn config(&self) -> &TileLinkConfig {
        &self.config
    }
}

// ---------------------------------------------------------------------------
// LinkProducer
// ---------------------------------------------------------------------------

/// Producer-side view of a TileLink.
///
/// Provides methods to write payloads and publish fragment metadata.
/// Only one producer should exist per link at a time.
pub struct LinkProducer<'a> {
    meta_ring: &'a MetaRing,
    data_region: &'a mut DataRegion,
    flow_seq: &'a FlowSequence,
    /// Next sequence number to publish.
    next_seq: u64,
    /// Current write position in the data region.
    current_chunk: u32,
    /// First valid chunk.
    chunk0: u32,
    /// High water mark for compact mode.
    wmark: u32,
    /// Maximum payload size.
    mtu: usize,
    /// Ring depth for credit calculation.
    depth: usize,
}

impl<'a> LinkProducer<'a> {
    /// Write a payload to the data region and publish metadata.
    ///
    /// Returns the published sequence number, or `None` if the consumer
    /// hasn't consumed enough (backpressure / no credits).
    ///
    /// This is the all-in-one convenience method that:
    /// 1. Checks flow control credits
    /// 2. Copies payload into the data region
    /// 3. Publishes fragment metadata
    /// 4. Advances internal state
    pub fn send(&mut self, sig: u64, payload: &[u8], ctl: u16) -> Option<u64> {
        assert!(payload.len() <= self.mtu, "payload exceeds MTU");

        // Check backpressure: consumer must have consumed within `depth`.
        if !self.has_credits() {
            return None;
        }

        // Write payload to data region at current chunk.
        let chunk = self.current_chunk;
        // SAFETY: current_chunk is maintained within [chunk0, wmark].
        unsafe {
            let dest = self.data_region.write_slice(chunk, payload.len());
            dest.copy_from_slice(payload);
        }

        // Publish metadata with current timestamps.
        let seq = self.next_seq;
        let ts = ts_compress(now_nanos());
        self.meta_ring
            .publish(seq, sig, chunk, payload.len() as u16, ctl, ts, ts);

        // Advance state.
        self.current_chunk = compact_next(chunk, payload.len(), self.chunk0, self.wmark);
        self.next_seq = seq_inc(seq, 1);

        // Update watermark periodically.
        self.meta_ring.update_watermark(self.next_seq);

        Some(seq)
    }

    /// Check if the producer has credits to publish (consumer not too far behind).
    pub fn has_credits(&self) -> bool {
        let consumer_seq = self.flow_seq.query();
        let ahead = seq_diff(self.next_seq, consumer_seq);
        ahead < self.depth as i64
    }

    /// Next sequence number that will be published.
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Current write chunk position.
    pub fn current_chunk(&self) -> u32 {
        self.current_chunk
    }
}

// ---------------------------------------------------------------------------
// LinkConsumer
// ---------------------------------------------------------------------------

/// Consumer-side view of a TileLink.
///
/// Provides methods to poll for fragments and read payloads.
/// Multiple consumers can exist (for monitoring), but only one should
/// update the flow sequence for backpressure.
pub struct LinkConsumer<'a> {
    meta_ring: &'a MetaRing,
    data_region: &'a DataRegion,
    flow_seq: &'a FlowSequence,
    /// Next sequence number expected from the producer.
    next_seq: u64,
    /// Ring depth for overrun recovery during batch receive.
    depth: usize,
}

/// Result of receiving a fragment.
#[derive(Debug)]
pub enum ReceiveResult<'a> {
    /// Fragment received with metadata and payload slice.
    Ready {
        meta: FragmentMeta,
        payload: &'a [u8],
    },
    /// Consumer was overrun (producer wrapped around).
    /// Contains the sequence number to recover to.
    Overrun { recover_seq: u64 },
    /// No fragment available (producer hasn't published yet).
    Empty,
}

impl<'a> LinkConsumer<'a> {
    /// Poll for the next fragment.
    ///
    /// Returns `ReceiveResult::Ready` with metadata and a zero-copy
    /// reference to the payload, `ReceiveResult::Overrun` if the consumer
    /// fell behind, or `ReceiveResult::Empty` if nothing is available.
    pub fn receive(&mut self, max_polls: usize) -> ReceiveResult<'a> {
        match self.meta_ring.poll(self.next_seq, max_polls) {
            PollResult::Ready(meta) => {
                // Read payload directly from shared data region.
                // SAFETY: The producer has published this chunk+sz and the
                // metadata is consistent (verified by poll). The data region
                // is large enough to hold depth fragments, so the producer
                // hasn't overwritten this payload yet.
                let payload = unsafe { self.data_region.read_payload(meta.chunk, meta.sz) };

                // Advance consumer state.
                self.next_seq = seq_inc(self.next_seq, 1);
                self.flow_seq.update(self.next_seq);

                ReceiveResult::Ready { meta, payload }
            }
            PollResult::Overrun { found_seq } => {
                // Recover to the found sequence.
                self.next_seq = found_seq;
                self.flow_seq.update(self.next_seq);
                ReceiveResult::Overrun {
                    recover_seq: found_seq,
                }
            }
            PollResult::Timeout => ReceiveResult::Empty,
        }
    }

    /// Next expected sequence number.
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Receive up to `max_count` consecutive fragments in a batch.
    ///
    /// Returns a vector of `(FragmentMeta, payload_slice)` pairs.
    /// If an overrun is detected mid-batch, recovery is performed:
    /// the consumer skips to the producer's current position and returns
    /// whatever fragments were successfully received before the overrun.
    ///
    /// This is more efficient than calling `receive()` in a loop because
    /// it amortizes the flow sequence update across the entire batch.
    pub fn receive_batch(
        &mut self,
        max_count: usize,
        max_polls_per_frag: usize,
    ) -> Vec<(FragmentMeta, &'a [u8])> {
        let mut results = Vec::with_capacity(max_count.min(self.depth));

        for _ in 0..max_count {
            match self.meta_ring.poll(self.next_seq, max_polls_per_frag) {
                PollResult::Ready(meta) => {
                    let payload = unsafe { self.data_region.read_payload(meta.chunk, meta.sz) };
                    self.next_seq = seq_inc(self.next_seq, 1);
                    results.push((meta, payload));
                }
                PollResult::Overrun { found_seq } => {
                    // Overrun detected — skip to the producer's current position.
                    self.next_seq = found_seq;
                    self.flow_seq.update(self.next_seq);
                    break;
                }
                PollResult::Timeout => break,
            }
        }

        // Single flow sequence update for the entire batch.
        if !results.is_empty() {
            self.flow_seq.update(self.next_seq);
        }

        results
    }

    /// How far behind the consumer is from the producer watermark.
    pub fn lag(&self) -> u64 {
        let watermark = self.meta_ring.query_watermark();
        let diff = seq_diff(watermark, self.next_seq);
        if diff > 0 {
            diff as u64
        } else {
            0
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fragment::ctl_pack;

    fn default_link() -> TileLink {
        TileLink::new(TileLinkConfig {
            mtu: 256,
            depth: 16,
            burst: 1,
            initial_seq: 0,
        })
    }

    #[test]
    fn create_link() {
        let link = default_link();
        assert_eq!(link.config().depth, 16);
        assert_eq!(link.config().mtu, 256);
    }

    #[test]
    fn send_and_receive() {
        let mut link = default_link();

        // Send from producer.
        {
            let mut producer = link.producer();
            let ctl = ctl_pack(0, true, true, false);
            let seq = producer.send(0xBEEF, b"hello tile link", ctl);
            assert!(seq.is_some());
            assert_eq!(seq.unwrap(), 0);
        }

        // Receive on consumer.
        {
            let mut consumer = link.consumer();
            match consumer.receive(1) {
                ReceiveResult::Ready { meta, payload } => {
                    assert_eq!(meta.seq, 0);
                    assert_eq!(meta.sig, 0xBEEF);
                    assert_eq!(payload, b"hello tile link");
                }
                other => panic!("expected Ready, got {:?}", other),
            }
        }
    }

    #[test]
    fn multiple_send_receive() {
        let mut link = TileLink::new(TileLinkConfig {
            mtu: 128,
            depth: 8,
            burst: 1,
            initial_seq: 0,
        });

        let messages: Vec<Vec<u8>> = (0..5u8)
            .map(|i| format!("message {}", i).into_bytes())
            .collect();

        // Send all messages.
        {
            let mut producer = link.producer();
            for (i, msg) in messages.iter().enumerate() {
                let ctl = ctl_pack(0, true, true, false);
                let seq = producer.send(i as u64, msg, ctl);
                assert_eq!(seq, Some(i as u64));
            }
        }

        // Receive all messages.
        {
            let mut consumer = link.consumer();
            for (i, msg) in messages.iter().enumerate() {
                match consumer.receive(1) {
                    ReceiveResult::Ready { meta, payload } => {
                        assert_eq!(meta.seq, i as u64);
                        assert_eq!(meta.sig, i as u64);
                        assert_eq!(payload, msg.as_slice());
                    }
                    other => panic!("msg {} expected Ready, got {:?}", i, other),
                }
            }
        }
    }

    #[test]
    fn empty_receive_when_nothing_published() {
        let link = default_link();
        let mut consumer = link.consumer();
        match consumer.receive(5) {
            ReceiveResult::Empty => {} // expected
            other => panic!("expected Empty, got {:?}", other),
        }
    }

    #[test]
    fn backpressure() {
        let mut link = TileLink::new(TileLinkConfig {
            mtu: 64,
            depth: 4,
            burst: 1,
            initial_seq: 0,
        });

        let mut producer = link.producer();
        let ctl = ctl_pack(0, true, true, false);

        // Send depth fragments (fills the ring).
        for i in 0..4u64 {
            assert!(producer.send(i, b"data", ctl).is_some());
        }

        // Next send should fail (no credits — consumer hasn't advanced).
        assert!(producer.send(4, b"data", ctl).is_none());
    }

    #[test]
    fn consumer_lag() {
        let mut link = TileLink::new(TileLinkConfig {
            mtu: 64,
            depth: 16,
            burst: 1,
            initial_seq: 0,
        });

        // Publish 5 fragments.
        {
            let mut producer = link.producer();
            let ctl = ctl_pack(0, true, true, false);
            for i in 0..5u64 {
                producer.send(i, b"x", ctl);
            }
        }

        // Consumer hasn't received any — lag should be 5.
        let consumer = link.consumer();
        assert_eq!(consumer.lag(), 5);
    }

    #[test]
    fn overrun_recovery() {
        let mut link = TileLink::new(TileLinkConfig {
            mtu: 64,
            depth: 4,
            burst: 1,
            initial_seq: 0,
        });

        let ctl = ctl_pack(0, true, true, false);

        // Round 1: publish 4, consume 4.
        let mut prod_seq;
        {
            let mut producer = link.producer();
            for i in 0..4u64 {
                producer.send(i, b"x", ctl);
            }
            prod_seq = producer.next_seq();
        }
        {
            let mut consumer = link.consumer();
            for _ in 0..4 {
                match consumer.receive(1) {
                    ReceiveResult::Ready { .. } => {}
                    other => panic!("expected Ready, got {:?}", other),
                }
            }
        }

        // Round 2: publish 4 more (seqs 4-7), consume them.
        {
            let mut producer = link.producer_at(prod_seq);
            for i in 4..8u64 {
                producer.send(i, &[i as u8], ctl);
            }
            prod_seq = producer.next_seq();
        }
        {
            let mut consumer = link.consumer_at(4);
            for _ in 0..4 {
                match consumer.receive(1) {
                    ReceiveResult::Ready { .. } => {}
                    other => panic!("expected Ready, got {:?}", other),
                }
            }
        }

        // Round 3: publish 4 more (seqs 8-11). Ring now holds 8,9,10,11.
        {
            let mut producer = link.producer_at(prod_seq);
            for i in 8..12u64 {
                producer.send(i, &[i as u8], ctl);
            }
        }

        // Create a "stale" consumer at seq 4. It should detect overrun
        // because slot 4%4=0 now holds seq 8.
        let mut stale_consumer = link.consumer_at(4);
        match stale_consumer.receive(1) {
            ReceiveResult::Overrun { recover_seq } => {
                assert_eq!(recover_seq, 8);
            }
            other => panic!("expected Overrun, got {:?}", other),
        }
    }

    #[test]
    fn producer_sequence_tracking() {
        let mut link = default_link();
        let mut producer = link.producer();
        assert_eq!(producer.next_seq(), 0);

        let ctl = ctl_pack(0, true, true, false);
        producer.send(0, b"a", ctl);
        assert_eq!(producer.next_seq(), 1);

        producer.send(0, b"b", ctl);
        assert_eq!(producer.next_seq(), 2);
    }

    #[test]
    fn timestamps_are_populated() {
        let mut link = default_link();

        {
            let mut producer = link.producer();
            let ctl = ctl_pack(0, true, true, false);
            producer.send(0, b"timestamped", ctl);
        }

        let mut consumer = link.consumer();
        match consumer.receive(1) {
            ReceiveResult::Ready { meta, .. } => {
                // tsorig and tspub should be non-zero compressed timestamps.
                assert_ne!(meta.tsorig, 0, "tsorig should be set");
                assert_ne!(meta.tspub, 0, "tspub should be set");
                // For a direct send, origin and publish timestamps are equal.
                assert_eq!(meta.tsorig, meta.tspub);
            }
            other => panic!("expected Ready, got {:?}", other),
        }
    }

    #[test]
    fn timestamps_are_monotonic() {
        let mut link = TileLink::new(TileLinkConfig {
            mtu: 64,
            depth: 16,
            burst: 1,
            initial_seq: 0,
        });

        {
            let mut producer = link.producer();
            let ctl = ctl_pack(0, true, true, false);
            producer.send(0, b"first", ctl);
            // Small delay to ensure distinct timestamps.
            std::thread::sleep(std::time::Duration::from_millis(1));
            producer.send(1, b"second", ctl);
        }

        let mut consumer = link.consumer();
        let first = match consumer.receive(1) {
            ReceiveResult::Ready { meta, .. } => meta.tspub,
            other => panic!("expected Ready, got {:?}", other),
        };
        let second = match consumer.receive(1) {
            ReceiveResult::Ready { meta, .. } => meta.tspub,
            other => panic!("expected Ready, got {:?}", other),
        };

        // Second timestamp should be >= first (compressed 32-bit wrapping
        // means we compare as unsigned within a short window).
        assert!(
            second >= first,
            "timestamps should be monotonic: {} >= {}",
            second,
            first
        );
    }

    #[test]
    fn batch_receive_multiple() {
        let mut link = TileLink::new(TileLinkConfig {
            mtu: 128,
            depth: 16,
            burst: 1,
            initial_seq: 0,
        });

        let messages: Vec<Vec<u8>> = (0..5u8)
            .map(|i| format!("batch-{}", i).into_bytes())
            .collect();

        {
            let mut producer = link.producer();
            let ctl = ctl_pack(0, true, true, false);
            for (i, msg) in messages.iter().enumerate() {
                producer.send(i as u64, msg, ctl);
            }
        }

        let mut consumer = link.consumer();
        let batch = consumer.receive_batch(10, 1);

        assert_eq!(batch.len(), 5);
        for (i, (meta, payload)) in batch.iter().enumerate() {
            assert_eq!(meta.seq, i as u64);
            assert_eq!(*payload, messages[i].as_slice());
        }
    }

    #[test]
    fn batch_receive_respects_max_count() {
        let mut link = TileLink::new(TileLinkConfig {
            mtu: 64,
            depth: 16,
            burst: 1,
            initial_seq: 0,
        });

        {
            let mut producer = link.producer();
            let ctl = ctl_pack(0, true, true, false);
            for i in 0..5u64 {
                producer.send(i, b"x", ctl);
            }
        }

        let mut consumer = link.consumer();
        // Request at most 3 of 5 available.
        let batch = consumer.receive_batch(3, 1);
        assert_eq!(batch.len(), 3);
        assert_eq!(consumer.next_seq(), 3);

        // Remaining 2 should be available.
        let batch2 = consumer.receive_batch(10, 1);
        assert_eq!(batch2.len(), 2);
        assert_eq!(consumer.next_seq(), 5);
    }

    #[test]
    fn batch_receive_empty_when_nothing_available() {
        let link = default_link();
        let mut consumer = link.consumer();
        let batch = consumer.receive_batch(10, 5);
        assert!(batch.is_empty());
    }

    #[test]
    fn batch_receive_overrun_recovery() {
        let mut link = TileLink::new(TileLinkConfig {
            mtu: 64,
            depth: 4,
            burst: 1,
            initial_seq: 0,
        });

        let ctl = ctl_pack(0, true, true, false);

        // Round 1: publish 4, consume 4 to advance flow.
        let mut prod_seq;
        {
            let mut producer = link.producer();
            for i in 0..4u64 {
                producer.send(i, b"x", ctl);
            }
            prod_seq = producer.next_seq();
        }
        {
            let mut consumer = link.consumer();
            let _ = consumer.receive_batch(4, 1);
        }

        // Round 2: publish 4 more (seqs 4-7), consume them.
        {
            let mut producer = link.producer_at(prod_seq);
            for i in 4..8u64 {
                producer.send(i, &[i as u8], ctl);
            }
            prod_seq = producer.next_seq();
        }
        {
            let mut consumer = link.consumer_at(4);
            let _ = consumer.receive_batch(4, 1);
        }

        // Round 3: publish 4 more (seqs 8-11). Ring now holds 8,9,10,11.
        {
            let mut producer = link.producer_at(prod_seq);
            for i in 8..12u64 {
                producer.send(i, &[i as u8], ctl);
            }
        }

        // Stale consumer at seq 4 should detect overrun and recover.
        let mut stale = link.consumer_at(4);
        let batch = stale.receive_batch(10, 1);

        // Overrun detected — batch may be empty (recovery happened immediately).
        // Consumer should have advanced past the overrun point.
        assert!(batch.is_empty());
        assert_eq!(stale.next_seq(), 8, "consumer should recover to seq 8");
    }
}
