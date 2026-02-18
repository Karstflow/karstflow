/// QUIC packet number spaces and tracking (RFC 9000 Section 12.3).
///
/// QUIC uses three independent packet number spaces:
/// - Initial: for Initial packets
/// - Handshake: for Handshake packets
/// - Application: for 0-RTT and 1-RTT packets
///
/// Each space has its own monotonically increasing packet number counter
/// and independent ACK state.
use paradencer_constants::network::{
    QUIC_PKT_HANDSHAKE, QUIC_PKT_INITIAL, QUIC_PKT_ONE_RTT, QUIC_PKT_ZERO_RTT,
};

/// The three QUIC packet number spaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PacketNumberSpace {
    Initial = 0,
    Handshake = 1,
    Application = 2,
}

impl PacketNumberSpace {
    /// Number of packet number spaces.
    pub const COUNT: usize = 3;

    /// Map a packet type to its number space.
    pub fn from_packet_type(pkt_type: u8) -> Option<Self> {
        match pkt_type {
            QUIC_PKT_INITIAL => Some(Self::Initial),
            QUIC_PKT_HANDSHAKE => Some(Self::Handshake),
            QUIC_PKT_ZERO_RTT | QUIC_PKT_ONE_RTT => Some(Self::Application),
            _ => None,
        }
    }

    /// Index for array lookups (0, 1, or 2).
    #[inline]
    pub fn index(self) -> usize {
        self as usize
    }
}

/// Per-space packet number state for sending.
#[derive(Debug, Clone)]
pub struct PacketNumberGenerator {
    /// Next packet number to assign.
    next: u64,
}

impl PacketNumberGenerator {
    pub fn new() -> Self {
        Self { next: 0 }
    }

    /// Allocate the next packet number.
    pub fn allocate(&mut self) -> u64 {
        let pn = self.next;
        self.next += 1;
        pn
    }

    /// Current next value (peek without allocating).
    pub fn peek(&self) -> u64 {
        self.next
    }
}

impl Default for PacketNumberGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-space packet number state for receiving.
#[derive(Debug, Clone)]
pub struct PacketNumberTracker {
    /// Largest packet number received in this space.
    largest_received: Option<u64>,
    /// Number of packets received.
    received_count: u64,
}

impl PacketNumberTracker {
    pub fn new() -> Self {
        Self {
            largest_received: None,
            received_count: 0,
        }
    }

    /// Record a received packet number. Returns `true` if this is a new largest.
    pub fn record(&mut self, pn: u64) -> bool {
        self.received_count += 1;
        match self.largest_received {
            None => {
                self.largest_received = Some(pn);
                true
            }
            Some(prev) if pn > prev => {
                self.largest_received = Some(pn);
                true
            }
            _ => false,
        }
    }

    /// Largest received packet number, if any.
    pub fn largest_received(&self) -> Option<u64> {
        self.largest_received
    }

    /// Total packets received in this space.
    pub fn received_count(&self) -> u64 {
        self.received_count
    }
}

impl Default for PacketNumberTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Determine the encoding length for a packet number.
///
/// Uses the smallest encoding that keeps the truncated representation
/// unambiguous relative to `largest_acked`.
pub fn encoding_length(pn: u64, largest_acked: u64) -> usize {
    let num_unacked = pn.saturating_sub(largest_acked);
    if num_unacked < (1 << 7) {
        1
    } else if num_unacked < (1 << 15) {
        2
    } else if num_unacked < (1 << 23) {
        3
    } else {
        4
    }
}

/// Truncate a full packet number to `len` bytes for wire encoding.
pub fn truncate(pn: u64, len: usize) -> u32 {
    (pn & ((1u64 << (len * 8)) - 1)) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_number_space_from_type() {
        assert_eq!(
            PacketNumberSpace::from_packet_type(QUIC_PKT_INITIAL),
            Some(PacketNumberSpace::Initial)
        );
        assert_eq!(
            PacketNumberSpace::from_packet_type(QUIC_PKT_HANDSHAKE),
            Some(PacketNumberSpace::Handshake)
        );
        assert_eq!(
            PacketNumberSpace::from_packet_type(QUIC_PKT_ZERO_RTT),
            Some(PacketNumberSpace::Application)
        );
        assert_eq!(
            PacketNumberSpace::from_packet_type(QUIC_PKT_ONE_RTT),
            Some(PacketNumberSpace::Application)
        );
        assert_eq!(PacketNumberSpace::from_packet_type(3), None); // Retry
    }

    #[test]
    fn generator_allocates_sequentially() {
        let mut gen = PacketNumberGenerator::new();
        assert_eq!(gen.allocate(), 0);
        assert_eq!(gen.allocate(), 1);
        assert_eq!(gen.allocate(), 2);
        assert_eq!(gen.peek(), 3);
    }

    #[test]
    fn tracker_records_largest() {
        let mut tracker = PacketNumberTracker::new();
        assert!(tracker.largest_received().is_none());

        assert!(tracker.record(5));
        assert_eq!(tracker.largest_received(), Some(5));

        assert!(!tracker.record(3)); // Not a new largest
        assert_eq!(tracker.largest_received(), Some(5));

        assert!(tracker.record(10));
        assert_eq!(tracker.largest_received(), Some(10));
        assert_eq!(tracker.received_count(), 3);
    }

    #[test]
    fn encoding_length_selection() {
        assert_eq!(encoding_length(0, 0), 1);
        assert_eq!(encoding_length(127, 0), 1);
        assert_eq!(encoding_length(128, 0), 2);
        assert_eq!(encoding_length(32767, 0), 2);
        assert_eq!(encoding_length(32768, 0), 3);

        // Relative to largest_acked
        assert_eq!(encoding_length(1000, 999), 1);
        assert_eq!(encoding_length(1200, 999), 2);
    }

    #[test]
    fn truncate_values() {
        assert_eq!(truncate(0x12345678, 1), 0x78);
        assert_eq!(truncate(0x12345678, 2), 0x5678);
        assert_eq!(truncate(0x12345678, 3), 0x345678);
        assert_eq!(truncate(0x12345678, 4), 0x12345678);
    }

    #[test]
    fn space_index() {
        assert_eq!(PacketNumberSpace::Initial.index(), 0);
        assert_eq!(PacketNumberSpace::Handshake.index(), 1);
        assert_eq!(PacketNumberSpace::Application.index(), 2);
    }
}
