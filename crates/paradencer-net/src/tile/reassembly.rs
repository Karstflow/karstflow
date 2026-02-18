/// TPU transaction reassembly from QUIC stream data.
///
/// QUIC streams carry serialized Solana transactions. Each stream
/// delivers a single transaction as a contiguous byte sequence.
/// The reassembler collects stream data and produces complete
/// transaction payloads when a stream's FIN is received.
use paradencer_constants::transaction::MAX_TRANSACTION_SIZE;

/// A reassembly buffer for a single transaction.
struct ReassemblyBuffer {
    /// Stream ID this buffer belongs to.
    stream_id: u64,
    /// Connection index.
    conn_idx: u32,
    /// Accumulated data bytes.
    data: Vec<u8>,
    /// Whether FIN has been received.
    fin_received: bool,
    /// Whether this slot is in use.
    active: bool,
}

impl ReassemblyBuffer {
    fn new() -> Self {
        Self {
            stream_id: 0,
            conn_idx: 0,
            data: Vec::with_capacity(MAX_TRANSACTION_SIZE),
            fin_received: false,
            active: false,
        }
    }

    fn reset(&mut self) {
        self.stream_id = 0;
        self.conn_idx = 0;
        self.data.clear();
        self.fin_received = false;
        self.active = false;
    }

    fn is_complete(&self) -> bool {
        self.active && self.fin_received && !self.data.is_empty()
    }
}

/// TPU transaction reassembler.
///
/// Manages a pool of reassembly buffers, one per in-flight stream.
/// When a stream completes (FIN received), the transaction payload
/// is ready for extraction.
pub struct TpuReassembler {
    /// Pool of reassembly buffers.
    buffers: Vec<ReassemblyBuffer>,
    /// Number of active (in-use) buffers.
    active: usize,
    /// Number of completed transactions awaiting drain.
    completed: usize,
    /// Total transactions completed over lifetime.
    total_completed: u64,
    /// Total bytes reassembled.
    total_bytes: u64,
}

impl TpuReassembler {
    /// Create a new reassembler with the given capacity.
    pub fn new(max_streams: usize) -> Self {
        let buffers = (0..max_streams).map(|_| ReassemblyBuffer::new()).collect();
        Self {
            buffers,
            active: 0,
            completed: 0,
            total_completed: 0,
            total_bytes: 0,
        }
    }

    /// Begin reassembly for a new stream.
    ///
    /// Returns a buffer index or `None` if all buffers are in use.
    pub fn begin(&mut self, stream_id: u64, conn_idx: u32) -> Option<usize> {
        let idx = self.buffers.iter().position(|b| !b.active)?;
        let buf = &mut self.buffers[idx];
        buf.stream_id = stream_id;
        buf.conn_idx = conn_idx;
        buf.active = true;
        self.active += 1;
        Some(idx)
    }

    /// Append data to a reassembly buffer.
    ///
    /// Returns `false` if the data would exceed the maximum transaction size.
    pub fn append(&mut self, idx: usize, data: &[u8]) -> bool {
        let buf = &mut self.buffers[idx];
        if !buf.active {
            return false;
        }
        if buf.data.len() + data.len() > MAX_TRANSACTION_SIZE {
            return false;
        }
        buf.data.extend_from_slice(data);
        true
    }

    /// Mark a stream as finished (FIN received).
    pub fn finish(&mut self, idx: usize) {
        let buf = &mut self.buffers[idx];
        if buf.active {
            buf.fin_received = true;
            if buf.is_complete() {
                self.completed += 1;
            }
        }
    }

    /// Cancel reassembly for a stream (e.g., stream reset).
    pub fn cancel(&mut self, idx: usize) {
        let buf = &mut self.buffers[idx];
        if buf.active {
            if buf.is_complete() && self.completed > 0 {
                self.completed -= 1;
            }
            buf.reset();
            self.active -= 1;
        }
    }

    /// Extract a completed transaction payload.
    ///
    /// Returns the transaction data for the first completed buffer found,
    /// or `None` if no transactions are ready.
    pub fn extract(&mut self) -> Option<Vec<u8>> {
        if self.completed == 0 {
            return None;
        }

        let idx = self.buffers.iter().position(|b| b.is_complete())?;
        let buf = &mut self.buffers[idx];
        let data = std::mem::take(&mut buf.data);
        self.total_bytes += data.len() as u64;
        self.total_completed += 1;
        self.completed -= 1;
        buf.reset();
        self.active -= 1;
        Some(data)
    }

    /// Drain all completed transactions, returning the count.
    ///
    /// This is a fast path for counting without extracting data.
    pub fn drain_completed(&mut self) -> usize {
        let mut count = 0;
        while self.completed > 0 {
            if let Some(idx) = self.buffers.iter().position(|b| b.is_complete()) {
                self.total_bytes += self.buffers[idx].data.len() as u64;
                self.total_completed += 1;
                self.completed -= 1;
                self.buffers[idx].reset();
                self.active -= 1;
                count += 1;
            } else {
                break;
            }
        }
        count
    }

    /// Number of active (in-progress) reassembly buffers.
    pub fn active_count(&self) -> usize {
        self.active
    }

    /// Number of completed transactions awaiting extraction.
    pub fn completed_count(&self) -> usize {
        self.completed
    }

    /// Total transactions completed.
    pub fn total_completed(&self) -> u64 {
        self.total_completed
    }

    /// Total bytes reassembled.
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Total capacity.
    pub fn capacity(&self) -> usize {
        self.buffers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_reassembler() {
        let mut r = TpuReassembler::new(16);
        assert_eq!(r.active_count(), 0);
        assert_eq!(r.completed_count(), 0);
        assert_eq!(r.capacity(), 16);
        assert!(r.extract().is_none());
    }

    #[test]
    fn basic_reassembly() {
        let mut r = TpuReassembler::new(16);

        let idx = r.begin(0, 0).unwrap();
        assert_eq!(r.active_count(), 1);

        assert!(r.append(idx, b"hello "));
        assert!(r.append(idx, b"world"));

        r.finish(idx);
        assert_eq!(r.completed_count(), 1);

        let data = r.extract().unwrap();
        assert_eq!(data, b"hello world");
        assert_eq!(r.active_count(), 0);
        assert_eq!(r.completed_count(), 0);
        assert_eq!(r.total_completed(), 1);
    }

    #[test]
    fn multiple_streams() {
        let mut r = TpuReassembler::new(16);

        let idx0 = r.begin(0, 0).unwrap();
        let idx1 = r.begin(4, 0).unwrap();

        r.append(idx0, b"tx0");
        r.append(idx1, b"tx1");

        r.finish(idx0);
        r.finish(idx1);

        assert_eq!(r.completed_count(), 2);
        assert!(r.extract().is_some());
        assert!(r.extract().is_some());
        assert!(r.extract().is_none());
    }

    #[test]
    fn cancel_stream() {
        let mut r = TpuReassembler::new(16);

        let idx = r.begin(0, 0).unwrap();
        r.append(idx, b"partial");
        r.cancel(idx);

        assert_eq!(r.active_count(), 0);
        assert_eq!(r.completed_count(), 0);
    }

    #[test]
    fn cancel_completed_stream() {
        let mut r = TpuReassembler::new(16);

        let idx = r.begin(0, 0).unwrap();
        r.append(idx, b"data");
        r.finish(idx);
        assert_eq!(r.completed_count(), 1);

        r.cancel(idx);
        assert_eq!(r.completed_count(), 0);
        assert_eq!(r.active_count(), 0);
    }

    #[test]
    fn max_size_exceeded() {
        let mut r = TpuReassembler::new(16);
        let idx = r.begin(0, 0).unwrap();

        let big_data = vec![0u8; MAX_TRANSACTION_SIZE];
        assert!(r.append(idx, &big_data));

        // One more byte exceeds limit.
        assert!(!r.append(idx, &[1]));
    }

    #[test]
    fn capacity_exhaustion() {
        let mut r = TpuReassembler::new(2);

        let _idx0 = r.begin(0, 0).unwrap();
        let _idx1 = r.begin(4, 0).unwrap();
        assert!(r.begin(8, 0).is_none());
    }

    #[test]
    fn drain_completed() {
        let mut r = TpuReassembler::new(16);

        for i in 0..5u64 {
            let idx = r.begin(i * 4, 0).unwrap();
            r.append(idx, b"data");
            r.finish(idx);
        }

        assert_eq!(r.completed_count(), 5);
        let drained = r.drain_completed();
        assert_eq!(drained, 5);
        assert_eq!(r.completed_count(), 0);
        assert_eq!(r.active_count(), 0);
        assert_eq!(r.total_completed(), 5);
    }

    #[test]
    fn fin_without_data_not_complete() {
        let mut r = TpuReassembler::new(16);
        let idx = r.begin(0, 0).unwrap();
        r.finish(idx); // FIN without any data
        assert_eq!(r.completed_count(), 0); // empty payload not counted
    }

    #[test]
    fn slot_reuse_after_extract() {
        let mut r = TpuReassembler::new(1);

        let idx0 = r.begin(0, 0).unwrap();
        r.append(idx0, b"first");
        r.finish(idx0);
        r.extract();

        // Slot should be reusable.
        let idx1 = r.begin(4, 0).unwrap();
        r.append(idx1, b"second");
        r.finish(idx1);

        let data = r.extract().unwrap();
        assert_eq!(data, b"second");
    }
}
