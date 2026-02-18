/// Pre-allocated stream pool with index-based freelist.
///
/// All stream memory is allocated upfront. Free streams form a singly-linked
/// list via `pool_index`, giving O(1) allocation and deallocation with zero
/// heap allocation on the hot path.
use super::stream::Stream;

/// Sentinel value indicating end of freelist.
const FREELIST_END: u32 = u32::MAX;

/// Pre-allocated pool of QUIC streams.
pub struct StreamPool {
    /// Flat array of streams.
    streams: Vec<Stream>,
    /// Head of the freelist (index into `streams`, or `FREELIST_END`).
    free_head: u32,
    /// Number of currently allocated (in-use) streams.
    allocated: u32,
    /// Total capacity.
    capacity: u32,
}

impl StreamPool {
    /// Create a pool with `capacity` pre-allocated streams.
    pub fn new(capacity: u32) -> Self {
        let mut streams: Vec<Stream> = (0..capacity)
            .map(|i| {
                let mut s = Stream::new();
                s.pool_index = i;
                s
            })
            .collect();

        // Build freelist: each stream's conn_index repurposed as next-free pointer.
        // (conn_index is meaningless for idle streams.)
        for i in 0..capacity {
            let next = if i + 1 < capacity {
                i + 1
            } else {
                FREELIST_END
            };
            streams[i as usize].conn_index = next;
        }

        Self {
            streams,
            free_head: if capacity > 0 { 0 } else { FREELIST_END },
            allocated: 0,
            capacity,
        }
    }

    /// Allocate a stream from the pool. Returns the pool index, or `None` if exhausted.
    pub fn allocate(&mut self) -> Option<u32> {
        if self.free_head == FREELIST_END {
            return None;
        }

        let idx = self.free_head;
        let stream = &mut self.streams[idx as usize];
        self.free_head = stream.conn_index; // next-free was stored in conn_index
        stream.conn_index = 0; // clear the repurposed field
        self.allocated += 1;
        Some(idx)
    }

    /// Return a stream to the pool by its pool index.
    ///
    /// The stream is reset to idle state and placed at the head of the freelist.
    pub fn release(&mut self, idx: u32) {
        debug_assert!((idx as usize) < self.streams.len());

        let stream = &mut self.streams[idx as usize];
        stream.reset_for_reuse();

        // Push onto freelist head.
        stream.conn_index = self.free_head;
        self.free_head = idx;
        self.allocated -= 1;
    }

    /// Get a reference to a stream by pool index.
    #[inline]
    pub fn get(&self, idx: u32) -> &Stream {
        &self.streams[idx as usize]
    }

    /// Get a mutable reference to a stream by pool index.
    #[inline]
    pub fn get_mut(&mut self, idx: u32) -> &mut Stream {
        &mut self.streams[idx as usize]
    }

    /// Number of streams currently in use.
    pub fn allocated_count(&self) -> u32 {
        self.allocated
    }

    /// Number of free streams available.
    pub fn available_count(&self) -> u32 {
        self.capacity - self.allocated
    }

    /// Total pool capacity.
    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    /// Whether the pool is exhausted.
    pub fn is_exhausted(&self) -> bool {
        self.free_head == FREELIST_END
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::stream::StreamState;

    #[test]
    fn empty_pool() {
        let pool = StreamPool::new(0);
        assert!(pool.is_exhausted());
        assert_eq!(pool.capacity(), 0);
        assert_eq!(pool.allocated_count(), 0);
    }

    #[test]
    fn allocate_single() {
        let mut pool = StreamPool::new(4);
        assert_eq!(pool.available_count(), 4);

        let idx = pool.allocate().unwrap();
        assert_eq!(pool.allocated_count(), 1);
        assert_eq!(pool.available_count(), 3);

        let stream = pool.get(idx);
        assert_eq!(stream.state, StreamState::Idle);
        assert_eq!(stream.pool_index, idx);
    }

    #[test]
    fn allocate_all() {
        let mut pool = StreamPool::new(4);
        let mut indices = Vec::new();

        for _ in 0..4 {
            indices.push(pool.allocate().unwrap());
        }

        assert!(pool.is_exhausted());
        assert!(pool.allocate().is_none());
        assert_eq!(pool.allocated_count(), 4);

        // All indices should be unique
        indices.sort();
        indices.dedup();
        assert_eq!(indices.len(), 4);
    }

    #[test]
    fn allocate_and_release() {
        let mut pool = StreamPool::new(4);

        let idx0 = pool.allocate().unwrap();
        let idx1 = pool.allocate().unwrap();

        // Use the streams
        pool.get_mut(idx0).init(0, 0, 1024, 1024);
        pool.get_mut(idx0).send(b"hello");

        pool.get_mut(idx1).init(4, 0, 1024, 1024);

        // Release first stream
        pool.release(idx0);
        assert_eq!(pool.allocated_count(), 1);
        assert_eq!(pool.available_count(), 3);

        // Released stream should be reset
        let stream = pool.get(idx0);
        assert_eq!(stream.state, StreamState::Idle);
        assert!(!stream.has_pending_data());
    }

    #[test]
    fn release_reuses_slots() {
        let mut pool = StreamPool::new(2);

        let a = pool.allocate().unwrap();
        let b = pool.allocate().unwrap();
        assert!(pool.allocate().is_none());

        pool.release(a);
        // Should get the just-released slot back (LIFO freelist)
        let c = pool.allocate().unwrap();
        assert_eq!(c, a);

        pool.release(b);
        pool.release(c);
        assert_eq!(pool.available_count(), 2);
    }

    #[test]
    fn pool_indices_are_stable() {
        let mut pool = StreamPool::new(8);

        let idx = pool.allocate().unwrap();
        pool.get_mut(idx).init(100, 5, 2048, 2048);

        assert_eq!(pool.get(idx).id, 100);
        assert_eq!(pool.get(idx).pool_index, idx);
    }

    #[test]
    fn stress_allocate_release() {
        let mut pool = StreamPool::new(16);
        let mut active = Vec::new();

        // Fill half
        for _ in 0..8 {
            active.push(pool.allocate().unwrap());
        }

        // Release and reallocate in waves
        for _ in 0..100 {
            if !active.is_empty() {
                let idx = active.remove(0);
                pool.release(idx);
            }
            if let Some(idx) = pool.allocate() {
                active.push(idx);
            }
        }

        // All indices should still be valid
        for &idx in &active {
            assert!((idx as usize) < 16);
        }
        assert_eq!(
            pool.allocated_count() as usize + pool.available_count() as usize,
            16
        );
    }
}
