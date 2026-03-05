/// ACK range accumulator and generator.
///
/// Maintains a fixed-capacity ring buffer of disjoint packet number ranges.
/// Incoming packet numbers are coalesced into existing ranges when contiguous,
/// or start new ranges when not. The ring is flushed into ACK frames when
/// a connection needs to acknowledge received packets.
///
/// Mirrors the dual-phase pattern: accumulate ranges via `record()`, then
/// drain via `pending_ranges()` to encode ACK frames.
use karstflow_constants::network::{
    QUIC_ACK_MERGED, QUIC_ACK_NEW, QUIC_ACK_NOOP, QUIC_ACK_OVERFLOW, QUIC_ACK_QUEUE_CAPACITY,
};

/// A half-open range of packet numbers [lo, hi).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketRange {
    /// Inclusive lower bound.
    pub lo: u64,
    /// Exclusive upper bound.
    pub hi: u64,
}

impl PacketRange {
    /// Create a new range covering a single packet number.
    pub fn single(pn: u64) -> Self {
        Self { lo: pn, hi: pn + 1 }
    }

    /// Number of packet numbers in this range.
    pub fn count(&self) -> u64 {
        self.hi - self.lo
    }

    /// Whether `pn` can extend this range (adjacent or within).
    pub fn can_extend(&self, pn: u64) -> bool {
        pn + 1 >= self.lo && pn <= self.hi
    }

    /// Extend the range to include `pn`.
    pub fn extend(&mut self, pn: u64) {
        if pn < self.lo {
            self.lo = pn;
        }
        if pn + 1 > self.hi {
            self.hi = pn + 1;
        }
    }
}

/// Single entry in the ACK ring buffer.
#[derive(Debug, Clone, Copy)]
struct AckEntry {
    /// Packet number range [lo, hi).
    range: PacketRange,
    /// Timestamp (nanoseconds) when the highest packet in this range arrived.
    timestamp_ns: i64,
    /// Encryption level this range belongs to.
    enc_level: u8,
}

/// ACK range accumulator with a fixed-size ring buffer.
///
/// Capacity is `QUIC_ACK_QUEUE_CAPACITY` (64). Head/tail indices wrap around
/// using power-of-2 masking for efficient circular access.
pub struct AckGenerator {
    /// Ring buffer of ACK entries.
    queue: [AckEntry; QUIC_ACK_QUEUE_CAPACITY],
    /// Next insertion index (monotonically increasing).
    head: u32,
    /// Oldest unsent entry index (monotonically increasing).
    tail: u32,
    /// Whether an ACK-eliciting packet has been received since last flush.
    ack_elicited: bool,
}

const MASK: u32 = (QUIC_ACK_QUEUE_CAPACITY as u32) - 1;

impl AckGenerator {
    /// Create a new empty ACK generator.
    pub fn new() -> Self {
        Self {
            queue: [AckEntry {
                range: PacketRange { lo: 0, hi: 0 },
                timestamp_ns: 0,
                enc_level: 0,
            }; QUIC_ACK_QUEUE_CAPACITY],
            head: 0,
            tail: 0,
            ack_elicited: false,
        }
    }

    /// Record a received packet number for future ACK generation.
    ///
    /// Returns one of the `QUIC_ACK_*` result codes:
    /// - `QUIC_ACK_NOOP`: duplicate or already covered
    /// - `QUIC_ACK_NEW`: new range created
    /// - `QUIC_ACK_MERGED`: merged into existing range
    /// - `QUIC_ACK_OVERFLOW`: ring buffer full
    pub fn record(&mut self, pn: u64, enc_level: u8, now_ns: i64) -> u8 {
        // Try to merge into the most recent entry for this encryption level.
        if self.head != self.tail {
            let last_idx = ((self.head - 1) & MASK) as usize;
            let last = &mut self.queue[last_idx];
            if last.enc_level == enc_level && last.range.can_extend(pn) {
                let was_within = pn >= last.range.lo && pn < last.range.hi;
                if was_within {
                    return QUIC_ACK_NOOP;
                }
                last.range.extend(pn);
                if pn + 1 == last.range.hi {
                    last.timestamp_ns = now_ns; // update timestamp for new highest
                }
                return QUIC_ACK_MERGED;
            }
        }

        // Scan older entries for same encryption level.
        let count = self.len();
        for i in 0..count {
            let idx = ((self.tail + i as u32) & MASK) as usize;
            let entry = &mut self.queue[idx];
            if entry.enc_level == enc_level && entry.range.can_extend(pn) {
                let was_within = pn >= entry.range.lo && pn < entry.range.hi;
                if was_within {
                    return QUIC_ACK_NOOP;
                }
                entry.range.extend(pn);
                if pn + 1 == entry.range.hi {
                    entry.timestamp_ns = now_ns;
                }
                return QUIC_ACK_MERGED;
            }
        }

        // No merge possible — create new entry.
        if count >= QUIC_ACK_QUEUE_CAPACITY {
            return QUIC_ACK_OVERFLOW;
        }

        let idx = (self.head & MASK) as usize;
        self.queue[idx] = AckEntry {
            range: PacketRange::single(pn),
            timestamp_ns: now_ns,
            enc_level,
        };
        self.head += 1;
        QUIC_ACK_NEW
    }

    /// Mark that an ACK-eliciting frame was received.
    pub fn set_elicited(&mut self) {
        self.ack_elicited = true;
    }

    /// Whether an ACK should be generated (eliciting frame received).
    pub fn needs_ack(&self) -> bool {
        self.ack_elicited && !self.is_empty()
    }

    /// Number of pending ACK ranges.
    pub fn len(&self) -> usize {
        (self.head - self.tail) as usize
    }

    /// Whether the ring buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    /// Iterate pending ranges for a given encryption level.
    ///
    /// Returns ranges ordered from oldest to newest. Caller should encode
    /// these into ACK frames. Does NOT consume entries.
    pub fn pending_ranges(&self, enc_level: u8) -> PendingRanges<'_> {
        PendingRanges {
            gen: self,
            enc_level,
            pos: self.tail,
        }
    }

    /// Remove all entries for the given encryption level.
    ///
    /// Used when abandoning a packet number space (e.g., handshake complete).
    pub fn abandon_level(&mut self, enc_level: u8) {
        // Mark matching entries as empty by setting range to zero-width,
        // then compact from tail.
        let count = self.len();
        for i in 0..count {
            let idx = ((self.tail + i as u32) & MASK) as usize;
            if self.queue[idx].enc_level == enc_level {
                self.queue[idx].range.lo = 0;
                self.queue[idx].range.hi = 0;
            }
        }

        // Advance tail past any zero-width entries at the front.
        while self.tail != self.head {
            let idx = (self.tail & MASK) as usize;
            if self.queue[idx].range.lo == self.queue[idx].range.hi {
                self.tail += 1;
            } else {
                break;
            }
        }
    }

    /// Flush all pending ACK ranges for the given encryption level.
    ///
    /// Returns the ranges that were pending and removes them from the queue.
    /// Clears the `ack_elicited` flag if no ranges remain.
    pub fn flush_level(&mut self, enc_level: u8) -> Vec<(PacketRange, i64)> {
        let mut flushed = Vec::new();

        let count = self.len();
        for i in 0..count {
            let idx = ((self.tail + i as u32) & MASK) as usize;
            let entry = &self.queue[idx];
            if entry.enc_level == enc_level && entry.range.count() > 0 {
                flushed.push((entry.range, entry.timestamp_ns));
            }
        }

        // Remove flushed entries.
        self.abandon_level(enc_level);

        // Clear elicited flag if nothing remains.
        if self.is_empty() {
            self.ack_elicited = false;
        }

        flushed
    }

    /// Clear all state.
    pub fn reset(&mut self) {
        self.head = 0;
        self.tail = 0;
        self.ack_elicited = false;
    }

    /// Largest acknowledged packet number across all levels, if any.
    pub fn largest_acked(&self, enc_level: u8) -> Option<u64> {
        let mut largest = None;
        let count = self.len();
        for i in 0..count {
            let idx = ((self.tail + i as u32) & MASK) as usize;
            let entry = &self.queue[idx];
            if entry.enc_level == enc_level && entry.range.count() > 0 {
                let hi = entry.range.hi - 1;
                largest = Some(largest.map_or(hi, |prev: u64| prev.max(hi)));
            }
        }
        largest
    }
}

impl Default for AckGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Iterator over pending ACK ranges for a specific encryption level.
pub struct PendingRanges<'a> {
    gen: &'a AckGenerator,
    enc_level: u8,
    pos: u32,
}

impl<'a> Iterator for PendingRanges<'a> {
    type Item = (PacketRange, i64);

    fn next(&mut self) -> Option<Self::Item> {
        while self.pos != self.gen.head {
            let idx = (self.pos & MASK) as usize;
            self.pos += 1;
            let entry = &self.gen.queue[idx];
            if entry.enc_level == self.enc_level && entry.range.count() > 0 {
                return Some((entry.range, entry.timestamp_ns));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_generator() {
        let gen = AckGenerator::new();
        assert!(gen.is_empty());
        assert!(!gen.needs_ack());
        assert_eq!(gen.len(), 0);
        assert!(gen.largest_acked(0).is_none());
    }

    #[test]
    fn record_single_packet() {
        let mut gen = AckGenerator::new();
        let result = gen.record(42, 0, 1000);
        assert_eq!(result, QUIC_ACK_NEW);
        assert_eq!(gen.len(), 1);
        assert_eq!(gen.largest_acked(0), Some(42));
    }

    #[test]
    fn coalesce_contiguous() {
        let mut gen = AckGenerator::new();
        assert_eq!(gen.record(10, 0, 1000), QUIC_ACK_NEW);
        assert_eq!(gen.record(11, 0, 1001), QUIC_ACK_MERGED);
        assert_eq!(gen.record(12, 0, 1002), QUIC_ACK_MERGED);
        assert_eq!(gen.len(), 1); // single range [10, 13)

        let ranges: Vec<_> = gen.pending_ranges(0).collect();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].0, PacketRange { lo: 10, hi: 13 });
    }

    #[test]
    fn coalesce_adjacent_below() {
        let mut gen = AckGenerator::new();
        gen.record(10, 0, 1000);
        assert_eq!(gen.record(9, 0, 999), QUIC_ACK_MERGED);
        assert_eq!(gen.len(), 1);

        let ranges: Vec<_> = gen.pending_ranges(0).collect();
        assert_eq!(ranges[0].0, PacketRange { lo: 9, hi: 11 });
    }

    #[test]
    fn duplicate_is_noop() {
        let mut gen = AckGenerator::new();
        gen.record(10, 0, 1000);
        assert_eq!(gen.record(10, 0, 1001), QUIC_ACK_NOOP);
        assert_eq!(gen.len(), 1);
    }

    #[test]
    fn disjoint_ranges() {
        let mut gen = AckGenerator::new();
        gen.record(10, 0, 1000);
        gen.record(20, 0, 2000);
        gen.record(30, 0, 3000);
        assert_eq!(gen.len(), 3);

        let ranges: Vec<_> = gen.pending_ranges(0).collect();
        assert_eq!(ranges.len(), 3);
        assert_eq!(ranges[0].0, PacketRange { lo: 10, hi: 11 });
        assert_eq!(ranges[1].0, PacketRange { lo: 20, hi: 21 });
        assert_eq!(ranges[2].0, PacketRange { lo: 30, hi: 31 });
    }

    #[test]
    fn separate_encryption_levels() {
        let mut gen = AckGenerator::new();
        gen.record(1, 0, 100); // Initial
        gen.record(2, 0, 200);
        gen.record(1, 2, 300); // Handshake

        let initial: Vec<_> = gen.pending_ranges(0).collect();
        let handshake: Vec<_> = gen.pending_ranges(2).collect();

        assert_eq!(initial.len(), 1);
        assert_eq!(initial[0].0, PacketRange { lo: 1, hi: 3 });
        assert_eq!(handshake.len(), 1);
        assert_eq!(handshake[0].0, PacketRange { lo: 1, hi: 2 });
    }

    #[test]
    fn needs_ack_requires_elicited() {
        let mut gen = AckGenerator::new();
        gen.record(1, 0, 100);
        assert!(!gen.needs_ack()); // not elicited yet

        gen.set_elicited();
        assert!(gen.needs_ack());
    }

    #[test]
    fn abandon_level() {
        let mut gen = AckGenerator::new();
        gen.record(1, 0, 100);
        gen.record(2, 0, 200);
        gen.record(1, 2, 300);

        gen.abandon_level(0);
        assert_eq!(gen.pending_ranges(0).count(), 0);
        assert_eq!(gen.pending_ranges(2).count(), 1);
    }

    #[test]
    fn flush_level() {
        let mut gen = AckGenerator::new();
        gen.set_elicited();
        gen.record(1, 0, 100);
        gen.record(2, 0, 200);
        gen.record(10, 2, 300);

        let flushed = gen.flush_level(0);
        assert_eq!(flushed.len(), 1);
        assert_eq!(flushed[0].0, PacketRange { lo: 1, hi: 3 });

        // Level 0 gone, level 2 remains
        assert_eq!(gen.pending_ranges(0).count(), 0);
        assert_eq!(gen.pending_ranges(2).count(), 1);
        assert!(gen.needs_ack()); // still has level 2 data
    }

    #[test]
    fn flush_clears_elicited_when_empty() {
        let mut gen = AckGenerator::new();
        gen.set_elicited();
        gen.record(1, 0, 100);

        gen.flush_level(0);
        assert!(!gen.needs_ack());
    }

    #[test]
    fn overflow_when_full() {
        let mut gen = AckGenerator::new();
        // Fill with disjoint ranges
        for i in 0..QUIC_ACK_QUEUE_CAPACITY as u64 {
            assert_ne!(gen.record(i * 100, 0, i as i64), QUIC_ACK_OVERFLOW);
        }

        // Next disjoint range should overflow
        assert_eq!(gen.record(99999, 0, 99999), QUIC_ACK_OVERFLOW);
    }

    #[test]
    fn largest_acked_per_level() {
        let mut gen = AckGenerator::new();
        gen.record(5, 0, 100);
        gen.record(10, 0, 200);
        gen.record(3, 2, 300);
        gen.record(7, 2, 400);

        assert_eq!(gen.largest_acked(0), Some(10));
        assert_eq!(gen.largest_acked(2), Some(7));
        assert_eq!(gen.largest_acked(3), None); // no data for application level
    }

    #[test]
    fn reset_clears_all() {
        let mut gen = AckGenerator::new();
        gen.set_elicited();
        gen.record(1, 0, 100);
        gen.record(2, 2, 200);

        gen.reset();
        assert!(gen.is_empty());
        assert!(!gen.needs_ack());
        assert!(gen.largest_acked(0).is_none());
    }

    #[test]
    fn merge_into_older_range() {
        let mut gen = AckGenerator::new();
        gen.record(10, 0, 1000); // range [10, 11)
        gen.record(20, 0, 2000); // range [20, 21)
                                 // Packet 11 should merge into the first range, not create new
        assert_eq!(gen.record(11, 0, 1100), QUIC_ACK_MERGED);
        assert_eq!(gen.len(), 2); // still 2 ranges

        let ranges: Vec<_> = gen.pending_ranges(0).collect();
        assert_eq!(ranges[0].0, PacketRange { lo: 10, hi: 12 });
        assert_eq!(ranges[1].0, PacketRange { lo: 20, hi: 21 });
    }
}
