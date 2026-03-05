/// Core packet I/O traits.
use crate::packet::PacketBuffer;

/// Result of a batch send operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendResult {
    /// All packets were accepted for transmission.
    Success,
    /// Partial send: packets [0..sent_count) were accepted.
    Partial { sent_count: usize },
    /// No packets could be sent; try again later.
    WouldBlock,
    /// Unrecoverable error.
    Error,
}

/// Generic packet sender — the core I/O output abstraction.
///
/// Works with packet slices to avoid const generic issues with trait objects.
pub trait PacketSender: Send {
    fn send_packets(&self, packets: &[PacketBuffer], flush: bool) -> SendResult;
}

/// Generic packet receiver callback.
pub trait PacketReceiver: Send {
    fn on_receive(&mut self, packets: &[PacketBuffer]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::PacketBuffer;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct CountingSender {
        sent: Arc<AtomicUsize>,
    }

    impl PacketSender for CountingSender {
        fn send_packets(&self, packets: &[PacketBuffer], _flush: bool) -> SendResult {
            self.sent.fetch_add(packets.len(), Ordering::Relaxed);
            SendResult::Success
        }
    }

    struct CollectingReceiver {
        received: Vec<Vec<u8>>,
    }

    impl PacketReceiver for CollectingReceiver {
        fn on_receive(&mut self, packets: &[PacketBuffer]) {
            for pkt in packets {
                self.received.push(pkt.payload().to_vec());
            }
        }
    }

    #[test]
    fn sender_counts_packets() {
        let sent = Arc::new(AtomicUsize::new(0));
        let sender = CountingSender { sent: sent.clone() };

        let pkts = [
            PacketBuffer::from_slice(b"a", None),
            PacketBuffer::from_slice(b"b", None),
        ];

        assert_eq!(sender.send_packets(&pkts, true), SendResult::Success);
        assert_eq!(sent.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn receiver_collects_data() {
        let mut rx = CollectingReceiver { received: vec![] };
        let pkts = [
            PacketBuffer::from_slice(b"hello", None),
            PacketBuffer::from_slice(b"world", None),
        ];

        rx.on_receive(&pkts);
        assert_eq!(rx.received.len(), 2);
        assert_eq!(rx.received[0], b"hello");
        assert_eq!(rx.received[1], b"world");
    }

    #[test]
    fn send_result_partial() {
        let r = SendResult::Partial { sent_count: 5 };
        assert_ne!(r, SendResult::Success);
        if let SendResult::Partial { sent_count } = r {
            assert_eq!(sent_count, 5);
        }
    }
}
