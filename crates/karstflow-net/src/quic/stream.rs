//! QUIC stream state and TX buffer.
//!
//! Each stream has an independent state machine, byte-level flow control,
//! and an inline transmit buffer for outgoing data. Streams are identified
//! by a 62-bit stream ID where the two LSBs encode the type:
//!   00 = client-initiated bidirectional
//!   01 = server-initiated bidirectional
//!   10 = client-initiated unidirectional
//!   11 = server-initiated unidirectional

/// Default inline TX buffer size per stream (4 KiB).
const DEFAULT_TX_BUF_SIZE: usize = 4096;

/// Stream lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StreamState {
    /// Slot is unused.
    Idle = 0,
    /// Stream is open and data can be sent/received.
    Open = 1,
    /// Local side has sent FIN (no more data from us).
    HalfClosedLocal = 2,
    /// Remote side has sent FIN (no more data from peer).
    HalfClosedRemote = 3,
    /// Both sides have sent FIN, waiting for final ACK.
    Closed = 4,
    /// Stream was reset by either side.
    Reset = 5,
}

impl StreamState {
    /// Whether data can still be sent on this stream.
    pub fn can_send(self) -> bool {
        matches!(self, Self::Open | Self::HalfClosedRemote)
    }

    /// Whether data can still be received on this stream.
    pub fn can_receive(self) -> bool {
        matches!(self, Self::Open | Self::HalfClosedLocal)
    }

    /// Whether the stream is in a terminal state.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Idle | Self::Closed | Self::Reset)
    }
}

/// Stream type extracted from stream ID bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamType {
    BidiClient,
    BidiServer,
    UniClient,
    UniServer,
}

impl StreamType {
    /// Extract stream type from a stream ID.
    pub fn from_id(stream_id: u64) -> Self {
        match stream_id & 0x03 {
            0 => Self::BidiClient,
            1 => Self::BidiServer,
            2 => Self::UniClient,
            3 => Self::UniServer,
            _ => unreachable!(),
        }
    }

    /// Whether this is a bidirectional stream.
    pub fn is_bidi(self) -> bool {
        matches!(self, Self::BidiClient | Self::BidiServer)
    }

    /// Whether this stream was initiated by the client.
    pub fn is_client_initiated(self) -> bool {
        matches!(self, Self::BidiClient | Self::UniClient)
    }
}

/// Flat byte buffer for stream transmit data.
pub struct StreamBuffer {
    /// Pre-allocated data storage.
    data: Vec<u8>,
    /// Write position (next byte to write into).
    write_pos: usize,
    /// Read position (next byte to transmit).
    read_pos: usize,
}

impl StreamBuffer {
    /// Create a new buffer with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            data: vec![0; capacity],
            write_pos: 0,
            read_pos: 0,
        }
    }

    /// Available bytes to read (buffered data ready to send).
    pub fn available(&self) -> usize {
        self.write_pos - self.read_pos
    }

    /// Remaining capacity for writes.
    pub fn remaining(&self) -> usize {
        self.data.len() - self.write_pos
    }

    /// Write data into the buffer. Returns bytes actually written.
    pub fn write(&mut self, data: &[u8]) -> usize {
        let can_write = data.len().min(self.remaining());
        if can_write > 0 {
            self.data[self.write_pos..self.write_pos + can_write]
                .copy_from_slice(&data[..can_write]);
            self.write_pos += can_write;
        }
        can_write
    }

    /// Read data from the buffer without consuming. Returns a slice of
    /// up to `max_len` bytes available for transmission.
    pub fn peek(&self, max_len: usize) -> &[u8] {
        let available = self.available().min(max_len);
        &self.data[self.read_pos..self.read_pos + available]
    }

    /// Consume `count` bytes from the read side (they've been acknowledged).
    pub fn consume(&mut self, count: usize) {
        let count = count.min(self.available());
        self.read_pos += count;

        // Compact if we've consumed more than half the buffer
        if self.read_pos > self.data.len() / 2 {
            let remaining = self.available();
            self.data.copy_within(self.read_pos..self.write_pos, 0);
            self.read_pos = 0;
            self.write_pos = remaining;
        }
    }

    /// Whether the buffer is empty (nothing to send).
    pub fn is_empty(&self) -> bool {
        self.read_pos >= self.write_pos
    }

    /// Reset the buffer to empty state.
    pub fn reset(&mut self) {
        self.write_pos = 0;
        self.read_pos = 0;
    }
}

/// A single QUIC stream.
pub struct Stream {
    /// Stream ID (62-bit).
    pub id: u64,
    /// Current stream state.
    pub state: StreamState,
    /// Transmit buffer for outgoing data.
    pub tx_buf: StreamBuffer,
    /// Byte offset of the next byte to send.
    pub tx_offset: u64,
    /// Byte offset of the next byte to send that hasn't been ACKed.
    pub tx_acked_offset: u64,
    /// Maximum bytes the peer allows us to send (peer's flow control).
    pub tx_max_data: u64,
    /// Byte offset of the next byte to receive.
    pub rx_offset: u64,
    /// Maximum bytes we allow the peer to send (our flow control).
    pub rx_max_data: u64,
    /// Whether we've sent FIN.
    pub fin_sent: bool,
    /// Whether we've received FIN from peer.
    pub fin_received: bool,
    /// Final size (set when FIN is sent or received).
    pub final_size: Option<u64>,
    /// Index in the stream pool (for reverse lookups).
    pub pool_index: u32,
    /// Connection index this stream belongs to.
    pub conn_index: u32,
}

impl Stream {
    /// Create a new idle stream.
    pub fn new() -> Self {
        Self {
            id: u64::MAX,
            state: StreamState::Idle,
            tx_buf: StreamBuffer::new(DEFAULT_TX_BUF_SIZE),
            tx_offset: 0,
            tx_acked_offset: 0,
            tx_max_data: 0,
            rx_offset: 0,
            rx_max_data: 0,
            fin_sent: false,
            fin_received: false,
            final_size: None,
            pool_index: 0,
            conn_index: 0,
        }
    }

    /// Initialize the stream for use.
    pub fn init(&mut self, id: u64, conn_index: u32, tx_max_data: u64, rx_max_data: u64) {
        self.id = id;
        self.state = StreamState::Open;
        self.tx_buf.reset();
        self.tx_offset = 0;
        self.tx_acked_offset = 0;
        self.tx_max_data = tx_max_data;
        self.rx_offset = 0;
        self.rx_max_data = rx_max_data;
        self.fin_sent = false;
        self.fin_received = false;
        self.final_size = None;
        self.conn_index = conn_index;
    }

    /// Write data for transmission. Returns bytes actually buffered.
    pub fn send(&mut self, data: &[u8]) -> usize {
        if !self.state.can_send() {
            return 0;
        }
        let flow_limit = self.tx_max_data.saturating_sub(self.tx_offset) as usize;
        let max_write = data.len().min(flow_limit);
        let written = self.tx_buf.write(&data[..max_write]);
        self.tx_offset += written as u64;
        written
    }

    /// Mark the stream as finished (no more data to send).
    pub fn send_fin(&mut self) {
        if self.state.can_send() {
            self.fin_sent = true;
            self.final_size = Some(self.tx_offset);
            self.state = match self.state {
                StreamState::Open => StreamState::HalfClosedLocal,
                StreamState::HalfClosedRemote => StreamState::Closed,
                _ => self.state,
            };
        }
    }

    /// Record that peer has sent FIN.
    pub fn receive_fin(&mut self, final_size: u64) {
        self.fin_received = true;
        self.final_size = Some(final_size);
        self.state = match self.state {
            StreamState::Open => StreamState::HalfClosedRemote,
            StreamState::HalfClosedLocal => StreamState::Closed,
            _ => self.state,
        };
    }

    /// Reset the stream for pool reuse.
    pub fn reset_for_reuse(&mut self) {
        self.id = u64::MAX;
        self.state = StreamState::Idle;
        self.tx_buf.reset();
        self.tx_offset = 0;
        self.tx_acked_offset = 0;
        self.tx_max_data = 0;
        self.rx_offset = 0;
        self.rx_max_data = 0;
        self.fin_sent = false;
        self.fin_received = false;
        self.final_size = None;
        self.conn_index = 0;
    }

    /// Stream type based on ID bits.
    pub fn stream_type(&self) -> StreamType {
        StreamType::from_id(self.id)
    }

    /// Whether this stream has unsent data.
    pub fn has_pending_data(&self) -> bool {
        !self.tx_buf.is_empty()
    }
}

impl Default for Stream {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_buffer_write_read() {
        let mut buf = StreamBuffer::new(64);
        assert!(buf.is_empty());
        assert_eq!(buf.remaining(), 64);

        let written = buf.write(b"hello");
        assert_eq!(written, 5);
        assert_eq!(buf.available(), 5);

        assert_eq!(buf.peek(3), b"hel");
        assert_eq!(buf.peek(10), b"hello");

        buf.consume(3);
        assert_eq!(buf.available(), 2);
        assert_eq!(buf.peek(10), b"lo");
    }

    #[test]
    fn stream_buffer_capacity() {
        let mut buf = StreamBuffer::new(8);
        let written = buf.write(b"0123456789"); // 10 bytes, only 8 fit
        assert_eq!(written, 8);
        assert_eq!(buf.available(), 8);
        assert_eq!(buf.remaining(), 0);
    }

    #[test]
    fn stream_buffer_compaction() {
        let mut buf = StreamBuffer::new(16);
        buf.write(b"0123456789abcdef");
        assert_eq!(buf.available(), 16);

        // Consume more than half
        buf.consume(10);
        assert_eq!(buf.available(), 6);

        // After compaction, we should have space again
        let written = buf.write(b"XXXX");
        assert_eq!(written, 4);
        assert_eq!(buf.available(), 10);
    }

    #[test]
    fn stream_init_and_send() {
        let mut s = Stream::new();
        assert_eq!(s.state, StreamState::Idle);

        s.init(4, 0, 1024, 1024);
        assert_eq!(s.state, StreamState::Open);
        assert_eq!(s.id, 4);

        let written = s.send(b"hello world");
        assert_eq!(written, 11);
        assert_eq!(s.tx_offset, 11);
        assert!(s.has_pending_data());
    }

    #[test]
    fn stream_flow_control() {
        let mut s = Stream::new();
        s.init(0, 0, 5, 1024); // Only 5 bytes allowed

        let written = s.send(b"0123456789");
        assert_eq!(written, 5);
        assert_eq!(s.tx_offset, 5);

        // No more data allowed
        let written = s.send(b"more");
        assert_eq!(written, 0);
    }

    #[test]
    fn stream_fin() {
        let mut s = Stream::new();
        s.init(0, 0, 1024, 1024);

        s.send(b"data");
        s.send_fin();
        assert_eq!(s.state, StreamState::HalfClosedLocal);
        assert!(s.fin_sent);
        assert_eq!(s.final_size, Some(4));

        // Can't send after FIN
        assert_eq!(s.send(b"more"), 0);
    }

    #[test]
    fn stream_both_fin() {
        let mut s = Stream::new();
        s.init(0, 0, 1024, 1024);

        s.send_fin();
        assert_eq!(s.state, StreamState::HalfClosedLocal);

        s.receive_fin(100);
        assert_eq!(s.state, StreamState::Closed);
        assert!(s.state.is_terminal());
    }

    #[test]
    fn stream_type_from_id() {
        assert_eq!(StreamType::from_id(0), StreamType::BidiClient);
        assert_eq!(StreamType::from_id(1), StreamType::BidiServer);
        assert_eq!(StreamType::from_id(2), StreamType::UniClient);
        assert_eq!(StreamType::from_id(3), StreamType::UniServer);
        assert_eq!(StreamType::from_id(4), StreamType::BidiClient);
        assert_eq!(StreamType::from_id(7), StreamType::UniServer);

        assert!(StreamType::BidiClient.is_bidi());
        assert!(!StreamType::UniClient.is_bidi());
        assert!(StreamType::UniClient.is_client_initiated());
        assert!(!StreamType::UniServer.is_client_initiated());
    }

    #[test]
    fn stream_state_properties() {
        assert!(StreamState::Open.can_send());
        assert!(StreamState::Open.can_receive());
        assert!(StreamState::HalfClosedLocal.can_receive());
        assert!(!StreamState::HalfClosedLocal.can_send());
        assert!(StreamState::HalfClosedRemote.can_send());
        assert!(!StreamState::HalfClosedRemote.can_receive());
        assert!(StreamState::Closed.is_terminal());
        assert!(StreamState::Reset.is_terminal());
        assert!(!StreamState::Open.is_terminal());
    }

    #[test]
    fn stream_reset_for_reuse() {
        let mut s = Stream::new();
        s.init(4, 5, 1024, 512);
        s.send(b"data");
        s.reset_for_reuse();

        assert_eq!(s.state, StreamState::Idle);
        assert_eq!(s.id, u64::MAX);
        assert!(!s.has_pending_data());
        assert_eq!(s.tx_offset, 0);
    }
}
