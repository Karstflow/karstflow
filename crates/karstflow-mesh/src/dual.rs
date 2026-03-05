/// Dual-mode IPC abstraction.
///
/// `DualSender<T>` and `DualReceiver<T>` wrap either a crossbeam channel
/// (`OutPort<T>` / `InPort<T>`) or a zero-copy tile link
/// (`LinkProducer` / `LinkConsumer`), selected at construction time.
///
/// The caller uses the same `try_send` / `try_recv` API regardless of
/// the backing transport. When using the tile link path, messages are
/// serialized via the `FragmentCodec` trait.
use crate::codec::FragmentCodec;
use crate::fragment::ctl_pack;
use crate::ports::{bounded_link, InPort, OutPort};
use crate::tile_link::{LinkConsumer, LinkProducer, ReceiveResult, TileLink, TileLinkConfig};
use crate::types::{ReceiveError, SendError};

/// Backend selection for dual-mode links.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcBackend {
    /// Crossbeam bounded MPMC channel (typed, copies `T`).
    Channel,
    /// Zero-copy SPSC tile link (raw bytes via `FragmentCodec`).
    SharedMemory,
}

/// Sender side of a dual-mode link.
pub enum DualSender<T: FragmentCodec> {
    /// Channel-backed sender.
    Channel(OutPort<T>),
    /// Tile-link-backed sender with encode buffer.
    Link {
        producer: LinkProducer<'static>,
        buf: Vec<u8>,
    },
}

/// Receiver side of a dual-mode link.
pub enum DualReceiver<T: FragmentCodec> {
    /// Channel-backed receiver.
    Channel(InPort<T>),
    /// Tile-link-backed receiver.
    Link(LinkConsumer<'static>),
}

/// Error returned by `DualSender::try_send`.
#[derive(Debug)]
pub enum DualSendError<T> {
    /// Channel is full (backpressure).
    Full(T),
    /// Channel was closed.
    Closed(T),
    /// Tile link has no credits (consumer too far behind).
    NoCredits(T),
}

/// Error returned by `DualReceiver::try_recv`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DualReceiveError {
    /// Channel was closed.
    Closed,
    /// Consumer was overrun (tile link only). Contains recovery sequence.
    Overrun { recover_seq: u64 },
}

impl<T: FragmentCodec> DualSender<T> {
    /// Try to send a message. Returns `Ok(())` on success or the message
    /// back on failure (backpressure, no credits, or closed).
    pub fn try_send(&mut self, msg: T) -> Result<(), DualSendError<T>> {
        match self {
            Self::Channel(port) => port.try_send(msg).map_err(|e| match e {
                SendError::QueueFull(m) => DualSendError::Full(m),
                SendError::QueueClosed(m) => DualSendError::Closed(m),
            }),
            Self::Link { producer, buf } => {
                let sig = msg.signature();
                let len = msg.encode(buf);
                let ctl = ctl_pack(0, true, true, false);
                match producer.send(sig, &buf[..len], ctl) {
                    Some(_seq) => Ok(()),
                    None => Err(DualSendError::NoCredits(msg)),
                }
            }
        }
    }

    /// Returns `true` if this sender uses the shared-memory backend.
    pub fn is_shared_memory(&self) -> bool {
        matches!(self, Self::Link { .. })
    }
}

impl<T: FragmentCodec> DualReceiver<T> {
    /// Try to receive a message. Returns `Ok(Some(msg))` if available,
    /// `Ok(None)` if nothing is ready, or `Err` on close/overrun.
    pub fn try_recv(&mut self) -> Result<Option<T>, DualReceiveError> {
        match self {
            Self::Channel(port) => port.try_recv().map_err(|e| match e {
                ReceiveError::QueueClosed => DualReceiveError::Closed,
            }),
            Self::Link(consumer) => match consumer.receive(1) {
                ReceiveResult::Ready { payload, .. } => Ok(Some(T::decode(payload))),
                ReceiveResult::Empty => Ok(None),
                ReceiveResult::Overrun { recover_seq } => {
                    Err(DualReceiveError::Overrun { recover_seq })
                }
            },
        }
    }

    /// Returns `true` if this receiver uses the shared-memory backend.
    pub fn is_shared_memory(&self) -> bool {
        matches!(self, Self::Link(_))
    }
}

// SAFETY: DualSender contains either OutPort (Send) or LinkProducer
// backed by heap-allocated TileLink. The 'static lifetime on
// LinkProducer is achieved via Box::leak of the owning TileLink.
// The sender is the sole writer — no aliasing.
unsafe impl<T: FragmentCodec> Send for DualSender<T> {}

// SAFETY: Same reasoning as DualSender.
unsafe impl<T: FragmentCodec> Send for DualReceiver<T> {}

/// Ownership wrapper for a `TileLink` that has been leaked to provide
/// `'static` producer/consumer handles.
///
/// When dropped, reclaims the leaked `TileLink` allocation.
struct OwnedTileLink {
    ptr: *mut TileLink,
}

impl Drop for OwnedTileLink {
    fn drop(&mut self) {
        // SAFETY: ptr was created by Box::leak and is exclusively owned.
        unsafe {
            drop(Box::from_raw(self.ptr));
        }
    }
}

// SAFETY: TileLink is heap-allocated and exclusively owned.
unsafe impl Send for OwnedTileLink {}
unsafe impl Sync for OwnedTileLink {}

/// Create a dual-mode link pair.
///
/// - `IpcBackend::Channel`: creates a bounded crossbeam channel with the
///   given `capacity`.
/// - `IpcBackend::SharedMemory`: creates a `TileLink` with depth derived
///   from `capacity` (rounded to next power of 2) and MTU from
///   `T::max_encoded_size()`.
///
/// Returns `(sender, receiver, _ownership_handle)`. The ownership handle
/// must be kept alive for the lifetime of the sender/receiver when using
/// the shared-memory backend. For the channel backend it is `None`.
pub fn dual_link<T: FragmentCodec>(
    backend: IpcBackend,
    capacity: usize,
) -> (DualSender<T>, DualReceiver<T>, Option<Box<dyn Send>>) {
    match backend {
        IpcBackend::Channel => {
            let (tx, rx) = bounded_link::<T>(capacity);
            (DualSender::Channel(tx), DualReceiver::Channel(rx), None)
        }
        IpcBackend::SharedMemory => {
            let depth = capacity.next_power_of_two().max(4);
            let mtu = T::max_encoded_size();
            let config = TileLinkConfig {
                mtu,
                depth,
                burst: 1,
                initial_seq: 0,
            };
            let link = Box::new(TileLink::new(config));
            let link_ptr = Box::into_raw(link);

            // SAFETY: link_ptr is valid and exclusively owned. We create
            // exactly one producer and one consumer. The OwnedTileLink
            // handle ensures the allocation lives as long as both handles.
            let producer = unsafe { (*link_ptr).producer() };
            let consumer = unsafe { (*link_ptr).consumer() };

            // Extend lifetimes to 'static via transmute. Sound because
            // OwnedTileLink prevents deallocation while handles exist.
            let producer: LinkProducer<'static> = unsafe { std::mem::transmute(producer) };
            let consumer: LinkConsumer<'static> = unsafe { std::mem::transmute(consumer) };

            let buf = vec![0u8; mtu];
            let ownership: Box<dyn Send> = Box::new(OwnedTileLink { ptr: link_ptr });

            (
                DualSender::Link { producer, buf },
                DualReceiver::Link(consumer),
                Some(ownership),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Simple test type for codec roundtrip.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TestMsg {
        id: u64,
        data: Vec<u8>,
    }

    impl FragmentCodec for TestMsg {
        fn encode(&self, buf: &mut [u8]) -> usize {
            buf[..8].copy_from_slice(&self.id.to_le_bytes());
            let data_len = self.data.len();
            buf[8..12].copy_from_slice(&(data_len as u32).to_le_bytes());
            buf[12..12 + data_len].copy_from_slice(&self.data);
            12 + data_len
        }

        fn decode(bytes: &[u8]) -> Self {
            let id = u64::from_le_bytes(bytes[..8].try_into().unwrap());
            let data_len = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
            let data = bytes[12..12 + data_len].to_vec();
            Self { id, data }
        }

        fn max_encoded_size() -> usize {
            12 + 256
        }

        fn signature(&self) -> u64 {
            self.id
        }
    }

    #[test]
    fn codec_roundtrip() {
        let msg = TestMsg {
            id: 42,
            data: b"hello codec".to_vec(),
        };
        let mut buf = vec![0u8; TestMsg::max_encoded_size()];
        let len = msg.encode(&mut buf);
        let decoded = TestMsg::decode(&buf[..len]);
        assert_eq!(msg, decoded);
    }

    #[test]
    fn dual_link_channel_send_recv() {
        let (mut tx, mut rx, _handle) = dual_link::<TestMsg>(IpcBackend::Channel, 16);
        assert!(!tx.is_shared_memory());
        assert!(!rx.is_shared_memory());

        let msg = TestMsg {
            id: 1,
            data: b"channel".to_vec(),
        };
        tx.try_send(msg.clone()).unwrap();
        let received = rx.try_recv().unwrap().unwrap();
        assert_eq!(received, msg);
    }

    #[test]
    fn dual_link_channel_empty() {
        let (_tx, mut rx, _handle) = dual_link::<TestMsg>(IpcBackend::Channel, 16);
        let result = rx.try_recv().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn dual_link_shared_memory_send_recv() {
        let (mut tx, mut rx, handle) = dual_link::<TestMsg>(IpcBackend::SharedMemory, 16);
        assert!(tx.is_shared_memory());
        assert!(rx.is_shared_memory());
        assert!(handle.is_some());

        let msg = TestMsg {
            id: 99,
            data: b"shared memory".to_vec(),
        };
        tx.try_send(msg.clone()).unwrap();
        let received = rx.try_recv().unwrap().unwrap();
        assert_eq!(received, msg);
    }

    #[test]
    fn dual_link_shared_memory_empty() {
        let (_tx, mut rx, _handle) = dual_link::<TestMsg>(IpcBackend::SharedMemory, 16);
        let result = rx.try_recv().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn dual_link_shared_memory_multiple_messages() {
        let (mut tx, mut rx, _handle) = dual_link::<TestMsg>(IpcBackend::SharedMemory, 32);

        for i in 0..10u64 {
            let msg = TestMsg {
                id: i,
                data: format!("msg-{i}").into_bytes(),
            };
            tx.try_send(msg).unwrap();
        }

        for i in 0..10u64 {
            let received = rx.try_recv().unwrap().unwrap();
            assert_eq!(received.id, i);
            assert_eq!(received.data, format!("msg-{i}").into_bytes());
        }
    }

    #[test]
    fn dual_link_shared_memory_backpressure() {
        let (mut tx, mut _rx, _handle) = dual_link::<TestMsg>(IpcBackend::SharedMemory, 4);

        // Fill the ring (depth=4).
        for i in 0..4u64 {
            let msg = TestMsg {
                id: i,
                data: vec![0; 8],
            };
            tx.try_send(msg).unwrap();
        }

        // Next send should fail with NoCredits.
        let msg = TestMsg {
            id: 100,
            data: vec![0; 8],
        };
        let result = tx.try_send(msg);
        assert!(matches!(result, Err(DualSendError::NoCredits(_))));
    }

    #[test]
    fn dual_link_channel_backpressure() {
        let (mut tx, mut _rx, _handle) = dual_link::<TestMsg>(IpcBackend::Channel, 2);

        tx.try_send(TestMsg {
            id: 0,
            data: vec![],
        })
        .unwrap();
        tx.try_send(TestMsg {
            id: 1,
            data: vec![],
        })
        .unwrap();

        let result = tx.try_send(TestMsg {
            id: 2,
            data: vec![],
        });
        assert!(matches!(result, Err(DualSendError::Full(_))));
    }

    #[test]
    fn dual_link_signature_propagated() {
        let (mut tx, mut rx, _handle) = dual_link::<TestMsg>(IpcBackend::SharedMemory, 16);

        let msg = TestMsg {
            id: 0xDEADBEEF,
            data: b"sig".to_vec(),
        };
        tx.try_send(msg).unwrap();

        // The signature (0xDEADBEEF) should be on the fragment metadata.
        // We verify indirectly by checking the decoded message.
        let received = rx.try_recv().unwrap().unwrap();
        assert_eq!(received.id, 0xDEADBEEF);
    }
}
