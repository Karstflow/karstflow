/// Connection service scheduler with dual-queue design.
///
/// Connections that need immediate processing go into the instant queue
/// (doubly-linked list for O(1) insert/remove). Connections with future
/// timeouts go into the dynamic queue (binary min-heap ordered by timeout).
///
/// This mirrors the pattern of separating urgent work (ACK generation,
/// data ready to send) from deferred work (idle timeout, loss detection
/// retransmit timers).
use paradencer_constants::network::{SVC_DLIST_SENTINEL, SVC_TYPE_DYNAMIC, SVC_TYPE_INSTANT};

/// Per-connection service metadata.
///
/// Stored alongside each connection (indexed by connection pool index).
#[derive(Debug, Clone)]
pub struct ServiceMeta {
    /// Absolute time for next service (nanoseconds). `i64::MAX` = unscheduled.
    pub next_timeout: i64,
    /// Which queue this connection is in.
    pub svc_type: u8,
    /// Next connection index in instant dlist (or `SVC_DLIST_SENTINEL`).
    pub dlist_next: u32,
    /// Previous connection index in instant dlist (or `SVC_DLIST_SENTINEL`).
    pub dlist_prev: u32,
    /// Index in the heap array (only valid when `svc_type == SVC_TYPE_DYNAMIC`).
    pub heap_idx: u32,
}

impl ServiceMeta {
    pub fn new() -> Self {
        Self {
            next_timeout: i64::MAX,
            svc_type: u8::MAX, // not in any queue
            dlist_next: SVC_DLIST_SENTINEL,
            dlist_prev: SVC_DLIST_SENTINEL,
            heap_idx: u32::MAX,
        }
    }

    /// Whether this connection is currently scheduled in any queue.
    pub fn is_scheduled(&self) -> bool {
        self.svc_type == SVC_TYPE_INSTANT || self.svc_type == SVC_TYPE_DYNAMIC
    }
}

impl Default for ServiceMeta {
    fn default() -> Self {
        Self::new()
    }
}

/// Heap entry for the dynamic (timer-based) queue.
#[derive(Debug, Clone, Copy)]
struct HeapEntry {
    /// Timeout timestamp (nanoseconds).
    timeout: i64,
    /// Connection pool index.
    conn_idx: u32,
}

/// Dual-queue service scheduler.
pub struct ServiceQueue {
    /// Per-connection metadata (indexed by connection pool index).
    meta: Vec<ServiceMeta>,

    // -- Instant queue (doubly-linked list) --
    /// Head of instant queue (connection index, or `SVC_DLIST_SENTINEL`).
    instant_head: u32,
    /// Tail of instant queue (connection index, or `SVC_DLIST_SENTINEL`).
    instant_tail: u32,
    /// Number of connections in instant queue.
    instant_count: u32,

    // -- Dynamic queue (binary min-heap) --
    /// Min-heap of (timeout, conn_idx) ordered by timeout.
    heap: Vec<HeapEntry>,
}

impl ServiceQueue {
    /// Create a new service queue for up to `max_connections` connections.
    pub fn new(max_connections: u32) -> Self {
        let meta = (0..max_connections).map(|_| ServiceMeta::new()).collect();
        Self {
            meta,
            instant_head: SVC_DLIST_SENTINEL,
            instant_tail: SVC_DLIST_SENTINEL,
            instant_count: 0,
            heap: Vec::with_capacity(max_connections as usize),
        }
    }

    /// Schedule a connection for service at the given time.
    ///
    /// If `timeout == now`, the connection is added to the instant queue.
    /// Otherwise, it's added to the dynamic queue for future service.
    ///
    /// Re-scheduling rules:
    /// - INSTANT → INSTANT: no-op (already queued for immediate processing)
    /// - DYNAMIC → DYNAMIC with earlier timeout: reschedule (accelerate)
    /// - DYNAMIC → DYNAMIC with later timeout: no-op (never delay)
    /// - DYNAMIC → INSTANT: move from heap to instant queue
    /// - Unscheduled → either queue: insert
    pub fn schedule(&mut self, conn_idx: u32, timeout: i64, now: i64) {
        let meta = &self.meta[conn_idx as usize];
        let is_instant = timeout <= now;
        let currently_scheduled = meta.is_scheduled();

        if currently_scheduled {
            let current_type = meta.svc_type;

            if current_type == SVC_TYPE_INSTANT {
                // Already instant — no-op (can't be more urgent).
                return;
            }

            if current_type == SVC_TYPE_DYNAMIC {
                if is_instant {
                    // Upgrade DYNAMIC → INSTANT.
                    self.remove_from_heap(conn_idx);
                    self.insert_instant(conn_idx);
                    self.meta[conn_idx as usize].next_timeout = timeout;
                } else if timeout < meta.next_timeout {
                    // Accelerate DYNAMIC timer.
                    self.meta[conn_idx as usize].next_timeout = timeout;
                    let heap_idx = self.meta[conn_idx as usize].heap_idx as usize;
                    self.heap[heap_idx].timeout = timeout;
                    self.heap_sift_up(heap_idx);
                }
                // else: timeout >= current → no-op (never delay)
                return;
            }
        }

        // Not currently scheduled — insert fresh.
        self.meta[conn_idx as usize].next_timeout = timeout;
        if is_instant {
            self.insert_instant(conn_idx);
        } else {
            self.insert_dynamic(conn_idx, timeout);
        }
    }

    /// Remove a connection from whatever queue it's in.
    pub fn cancel(&mut self, conn_idx: u32) {
        let meta = &self.meta[conn_idx as usize];
        if !meta.is_scheduled() {
            return;
        }

        match meta.svc_type {
            SVC_TYPE_INSTANT => self.remove_from_instant(conn_idx),
            SVC_TYPE_DYNAMIC => self.remove_from_heap(conn_idx),
            _ => {}
        }

        self.meta[conn_idx as usize].next_timeout = i64::MAX;
        self.meta[conn_idx as usize].svc_type = u8::MAX;
    }

    /// Pop the next connection that needs service.
    ///
    /// Priority: instant queue first, then dynamic queue if timeout expired.
    /// Returns `(conn_idx, timeout)` or `None` if nothing is ready.
    pub fn pop_next(&mut self, now: i64) -> Option<(u32, i64)> {
        // Check instant queue first.
        if self.instant_head != SVC_DLIST_SENTINEL {
            let conn_idx = self.instant_head;
            let timeout = self.meta[conn_idx as usize].next_timeout;
            self.remove_from_instant(conn_idx);
            self.meta[conn_idx as usize].next_timeout = i64::MAX;
            self.meta[conn_idx as usize].svc_type = u8::MAX;
            return Some((conn_idx, timeout));
        }

        // Check dynamic queue.
        if let Some(top) = self.heap.first() {
            if top.timeout <= now {
                let conn_idx = top.conn_idx;
                let timeout = top.timeout;
                self.remove_from_heap(conn_idx);
                self.meta[conn_idx as usize].next_timeout = i64::MAX;
                self.meta[conn_idx as usize].svc_type = u8::MAX;
                return Some((conn_idx, timeout));
            }
        }

        None
    }

    /// Peek at the next service time without popping.
    ///
    /// Returns `i64::MAX` if nothing is scheduled.
    pub fn next_timeout(&self) -> i64 {
        if self.instant_head != SVC_DLIST_SENTINEL {
            return i64::MIN; // instant = now
        }
        self.heap.first().map_or(i64::MAX, |e| e.timeout)
    }

    /// Number of connections in the instant queue.
    pub fn instant_count(&self) -> u32 {
        self.instant_count
    }

    /// Number of connections in the dynamic queue.
    pub fn dynamic_count(&self) -> usize {
        self.heap.len()
    }

    /// Total scheduled connections.
    pub fn total_scheduled(&self) -> usize {
        self.instant_count as usize + self.heap.len()
    }

    /// Get a reference to a connection's service metadata.
    pub fn meta(&self, conn_idx: u32) -> &ServiceMeta {
        &self.meta[conn_idx as usize]
    }

    // -- Instant queue (doubly-linked list) operations --

    fn insert_instant(&mut self, conn_idx: u32) {
        let meta = &mut self.meta[conn_idx as usize];
        meta.svc_type = SVC_TYPE_INSTANT;
        meta.dlist_next = SVC_DLIST_SENTINEL;
        meta.dlist_prev = self.instant_tail;

        if self.instant_tail != SVC_DLIST_SENTINEL {
            self.meta[self.instant_tail as usize].dlist_next = conn_idx;
        } else {
            self.instant_head = conn_idx;
        }
        self.instant_tail = conn_idx;
        self.instant_count += 1;
    }

    fn remove_from_instant(&mut self, conn_idx: u32) {
        let prev = self.meta[conn_idx as usize].dlist_prev;
        let next = self.meta[conn_idx as usize].dlist_next;

        if prev != SVC_DLIST_SENTINEL {
            self.meta[prev as usize].dlist_next = next;
        } else {
            self.instant_head = next;
        }

        if next != SVC_DLIST_SENTINEL {
            self.meta[next as usize].dlist_prev = prev;
        } else {
            self.instant_tail = prev;
        }

        self.meta[conn_idx as usize].dlist_next = SVC_DLIST_SENTINEL;
        self.meta[conn_idx as usize].dlist_prev = SVC_DLIST_SENTINEL;
        self.instant_count -= 1;
    }

    // -- Dynamic queue (binary min-heap) operations --

    fn insert_dynamic(&mut self, conn_idx: u32, timeout: i64) {
        let heap_idx = self.heap.len();
        self.heap.push(HeapEntry { timeout, conn_idx });
        self.meta[conn_idx as usize].svc_type = SVC_TYPE_DYNAMIC;
        self.meta[conn_idx as usize].heap_idx = heap_idx as u32;
        self.heap_sift_up(heap_idx);
    }

    fn remove_from_heap(&mut self, conn_idx: u32) {
        let heap_idx = self.meta[conn_idx as usize].heap_idx as usize;
        let last = self.heap.len() - 1;

        if heap_idx != last {
            self.heap.swap(heap_idx, last);
            // Update swapped entry's metadata.
            let swapped_conn = self.heap[heap_idx].conn_idx;
            self.meta[swapped_conn as usize].heap_idx = heap_idx as u32;
        }

        self.heap.pop();

        if heap_idx < self.heap.len() {
            self.heap_sift_down(heap_idx);
            self.heap_sift_up(heap_idx);
        }
    }

    fn heap_sift_up(&mut self, mut idx: usize) {
        while idx > 0 {
            let parent = (idx - 1) / 2;
            if self.heap[idx].timeout >= self.heap[parent].timeout {
                break;
            }
            self.heap.swap(idx, parent);
            self.meta[self.heap[idx].conn_idx as usize].heap_idx = idx as u32;
            self.meta[self.heap[parent].conn_idx as usize].heap_idx = parent as u32;
            idx = parent;
        }
    }

    fn heap_sift_down(&mut self, mut idx: usize) {
        let len = self.heap.len();
        loop {
            let left = 2 * idx + 1;
            let right = 2 * idx + 2;
            let mut smallest = idx;

            if left < len && self.heap[left].timeout < self.heap[smallest].timeout {
                smallest = left;
            }
            if right < len && self.heap[right].timeout < self.heap[smallest].timeout {
                smallest = right;
            }

            if smallest == idx {
                break;
            }

            self.heap.swap(idx, smallest);
            self.meta[self.heap[idx].conn_idx as usize].heap_idx = idx as u32;
            self.meta[self.heap[smallest].conn_idx as usize].heap_idx = smallest as u32;
            idx = smallest;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_queue() {
        let q = ServiceQueue::new(16);
        assert_eq!(q.total_scheduled(), 0);
        assert_eq!(q.next_timeout(), i64::MAX);
    }

    #[test]
    fn schedule_instant() {
        let mut q = ServiceQueue::new(16);
        q.schedule(3, 100, 100); // timeout == now → instant
        assert_eq!(q.instant_count(), 1);
        assert_eq!(q.dynamic_count(), 0);
        assert!(q.meta(3).is_scheduled());
    }

    #[test]
    fn schedule_dynamic() {
        let mut q = ServiceQueue::new(16);
        q.schedule(5, 200, 100); // timeout > now → dynamic
        assert_eq!(q.instant_count(), 0);
        assert_eq!(q.dynamic_count(), 1);
        assert!(q.meta(5).is_scheduled());
    }

    #[test]
    fn pop_instant_first() {
        let mut q = ServiceQueue::new(16);
        q.schedule(1, 200, 100); // dynamic at t=200
        q.schedule(2, 100, 100); // instant

        // Instant has priority over expired dynamic.
        let (idx, _) = q.pop_next(300).unwrap();
        assert_eq!(idx, 2);

        let (idx, _) = q.pop_next(300).unwrap();
        assert_eq!(idx, 1);
    }

    #[test]
    fn pop_dynamic_when_expired() {
        let mut q = ServiceQueue::new(16);
        q.schedule(0, 200, 100);

        assert!(q.pop_next(150).is_none()); // not yet
        let (idx, timeout) = q.pop_next(200).unwrap();
        assert_eq!(idx, 0);
        assert_eq!(timeout, 200);
    }

    #[test]
    fn pop_dynamic_order() {
        let mut q = ServiceQueue::new(16);
        q.schedule(0, 300, 0);
        q.schedule(1, 100, 0);
        q.schedule(2, 200, 0);

        let (idx, _) = q.pop_next(300).unwrap();
        assert_eq!(idx, 1); // earliest timeout first
        let (idx, _) = q.pop_next(300).unwrap();
        assert_eq!(idx, 2);
        let (idx, _) = q.pop_next(300).unwrap();
        assert_eq!(idx, 0);
        assert!(q.pop_next(300).is_none());
    }

    #[test]
    fn instant_fifo_order() {
        let mut q = ServiceQueue::new(16);
        let now = 100;
        q.schedule(0, now, now);
        q.schedule(1, now, now);
        q.schedule(2, now, now);

        assert_eq!(q.pop_next(now).unwrap().0, 0);
        assert_eq!(q.pop_next(now).unwrap().0, 1);
        assert_eq!(q.pop_next(now).unwrap().0, 2);
    }

    #[test]
    fn reschedule_instant_noop() {
        let mut q = ServiceQueue::new(16);
        q.schedule(0, 100, 100);
        q.schedule(0, 100, 100); // duplicate instant → noop
        assert_eq!(q.instant_count(), 1);
    }

    #[test]
    fn reschedule_dynamic_accelerate() {
        let mut q = ServiceQueue::new(16);
        q.schedule(0, 500, 100); // dynamic at 500
        q.schedule(0, 300, 100); // accelerate to 300

        let (_, timeout) = q.pop_next(300).unwrap();
        assert_eq!(timeout, 300);
    }

    #[test]
    fn reschedule_dynamic_no_delay() {
        let mut q = ServiceQueue::new(16);
        q.schedule(0, 300, 100);
        q.schedule(0, 500, 100); // try to delay → noop

        let (_, timeout) = q.pop_next(500).unwrap();
        assert_eq!(timeout, 300); // original earlier timeout kept
    }

    #[test]
    fn upgrade_dynamic_to_instant() {
        let mut q = ServiceQueue::new(16);
        q.schedule(0, 500, 100); // dynamic
        assert_eq!(q.dynamic_count(), 1);

        q.schedule(0, 200, 200); // timeout <= now → upgrade to instant
        assert_eq!(q.instant_count(), 1);
        assert_eq!(q.dynamic_count(), 0);
    }

    #[test]
    fn cancel() {
        let mut q = ServiceQueue::new(16);
        q.schedule(0, 100, 100);
        q.schedule(1, 200, 100);

        q.cancel(0);
        assert_eq!(q.instant_count(), 0);
        assert!(!q.meta(0).is_scheduled());
        assert_eq!(q.dynamic_count(), 1);

        q.cancel(1);
        assert_eq!(q.total_scheduled(), 0);
    }

    #[test]
    fn cancel_unscheduled_noop() {
        let mut q = ServiceQueue::new(16);
        q.cancel(5); // not scheduled → no-op, no panic
        assert_eq!(q.total_scheduled(), 0);
    }

    #[test]
    fn stress_mixed_scheduling() {
        let mut q = ServiceQueue::new(64);

        // Schedule 30 dynamic, 10 instant
        for i in 0..30u32 {
            q.schedule(i, (i as i64 + 1) * 100, 0);
        }
        for i in 30..40u32 {
            q.schedule(i, 0, 0);
        }

        assert_eq!(q.instant_count(), 10);
        assert_eq!(q.dynamic_count(), 30);

        // Pop all instant first
        for _ in 0..10 {
            let (idx, _) = q.pop_next(5000).unwrap();
            assert!(idx >= 30);
        }
        assert_eq!(q.instant_count(), 0);

        // Pop all dynamic in order
        let mut prev_timeout = 0i64;
        for _ in 0..30 {
            let (_, timeout) = q.pop_next(5000).unwrap();
            assert!(timeout >= prev_timeout);
            prev_timeout = timeout;
        }

        assert!(q.pop_next(5000).is_none());
    }
}
