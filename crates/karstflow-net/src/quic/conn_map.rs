/// Pre-allocated connection ID to connection index mapping.
///
/// Uses a flat hash map with open addressing and linear probing.
/// All memory is allocated upfront — no heap allocation during lookups
/// or insertions. Designed for the QUIC engine's hot path.
use super::conn_id::ConnectionId;

/// Sentinel value indicating an empty slot.
const EMPTY_INDEX: u32 = u32::MAX;

/// Entry in the connection map.
#[derive(Clone)]
struct Entry {
    /// Connection ID key.
    conn_id: ConnectionId,
    /// Index into the connection pool.
    conn_index: u32,
}

/// Pre-allocated hash map from connection IDs to connection pool indices.
pub struct ConnectionMap {
    /// Hash table entries (open addressing with linear probing).
    entries: Vec<Entry>,
    /// Capacity (must be a power of 2).
    capacity: usize,
    /// Number of occupied entries.
    len: usize,
}

impl ConnectionMap {
    /// Create a new map with the given capacity (rounded up to power of 2).
    ///
    /// The map can hold up to ~75% of capacity before degrading.
    pub fn new(min_capacity: usize) -> Self {
        let capacity = min_capacity.next_power_of_two().max(16);
        let entries = vec![
            Entry {
                conn_id: ConnectionId::EMPTY,
                conn_index: EMPTY_INDEX,
            };
            capacity
        ];
        Self {
            entries,
            capacity,
            len: 0,
        }
    }

    /// Look up a connection index by connection ID.
    pub fn get(&self, conn_id: &ConnectionId) -> Option<u32> {
        let mask = self.capacity - 1;
        let mut idx = hash_conn_id(conn_id) & mask;

        for _ in 0..self.capacity {
            let entry = &self.entries[idx];
            if entry.conn_index == EMPTY_INDEX {
                return None;
            }
            if entry.conn_id == *conn_id {
                return Some(entry.conn_index);
            }
            idx = (idx + 1) & mask;
        }

        None
    }

    /// Insert a connection ID → index mapping.
    ///
    /// Returns `true` if inserted, `false` if the map is full or the key
    /// already exists (in which case the index is updated).
    pub fn insert(&mut self, conn_id: ConnectionId, conn_index: u32) -> bool {
        if self.len >= (self.capacity * 3) / 4 {
            return false; // Load factor too high
        }

        let mask = self.capacity - 1;
        let mut idx = hash_conn_id(&conn_id) & mask;

        for _ in 0..self.capacity {
            let entry = &mut self.entries[idx];
            if entry.conn_index == EMPTY_INDEX {
                entry.conn_id = conn_id;
                entry.conn_index = conn_index;
                self.len += 1;
                return true;
            }
            if entry.conn_id == conn_id {
                entry.conn_index = conn_index; // Update existing
                return true;
            }
            idx = (idx + 1) & mask;
        }

        false
    }

    /// Remove a connection ID mapping.
    ///
    /// Returns the connection index that was removed, or `None` if not found.
    /// Uses backward-shift deletion to maintain probe chains.
    pub fn remove(&mut self, conn_id: &ConnectionId) -> Option<u32> {
        let mask = self.capacity - 1;
        let mut idx = hash_conn_id(conn_id) & mask;

        // Find the entry
        for _ in 0..self.capacity {
            let entry = &self.entries[idx];
            if entry.conn_index == EMPTY_INDEX {
                return None;
            }
            if entry.conn_id == *conn_id {
                let removed_index = self.entries[idx].conn_index;
                self.backward_shift_delete(idx);
                self.len -= 1;
                return Some(removed_index);
            }
            idx = (idx + 1) & mask;
        }

        None
    }

    /// Number of entries in the map.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        for entry in &mut self.entries {
            entry.conn_index = EMPTY_INDEX;
        }
        self.len = 0;
    }

    /// Backward-shift deletion to avoid breaking probe chains.
    fn backward_shift_delete(&mut self, removed_idx: usize) {
        let mask = self.capacity - 1;
        let mut empty = removed_idx;
        let mut scan = (removed_idx + 1) & mask;

        loop {
            if self.entries[scan].conn_index == EMPTY_INDEX {
                break;
            }

            let home = hash_conn_id(&self.entries[scan].conn_id) & mask;

            // Should we shift `scan` into `empty`?
            // Yes if `empty` lies between `home` and `scan` on the circular table.
            let should_shift = if empty <= scan {
                // No wrap: home <= empty < scan (or home > scan, meaning wrap)
                home <= empty || home > scan
            } else {
                // Wrap: empty > scan. Both conditions must hold.
                home <= empty && home > scan
            };

            if should_shift {
                self.entries[empty] = self.entries[scan].clone();
                empty = scan;
            }

            scan = (scan + 1) & mask;
        }

        self.entries[empty].conn_index = EMPTY_INDEX;
    }
}

/// Simple hash function for connection IDs.
fn hash_conn_id(conn_id: &ConnectionId) -> usize {
    let bytes = conn_id.as_bytes();
    // FNV-1a hash for small inputs
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cid(val: u8) -> ConnectionId {
        ConnectionId::from_bytes(&[val]).unwrap()
    }

    #[test]
    fn empty_map() {
        let map = ConnectionMap::new(16);
        assert!(map.is_empty());
        assert_eq!(map.len(), 0);
        assert!(map.get(&make_cid(1)).is_none());
    }

    #[test]
    fn insert_and_get() {
        let mut map = ConnectionMap::new(16);
        assert!(map.insert(make_cid(1), 100));
        assert_eq!(map.get(&make_cid(1)), Some(100));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn insert_multiple() {
        let mut map = ConnectionMap::new(32);
        for i in 0..10 {
            assert!(map.insert(make_cid(i), i as u32));
        }
        assert_eq!(map.len(), 10);
        for i in 0..10 {
            assert_eq!(map.get(&make_cid(i)), Some(i as u32));
        }
    }

    #[test]
    fn update_existing() {
        let mut map = ConnectionMap::new(16);
        map.insert(make_cid(1), 100);
        map.insert(make_cid(1), 200); // Update
        assert_eq!(map.get(&make_cid(1)), Some(200));
        assert_eq!(map.len(), 1); // Count shouldn't increase
    }

    #[test]
    fn remove_entry() {
        let mut map = ConnectionMap::new(16);
        map.insert(make_cid(1), 100);
        map.insert(make_cid(2), 200);
        map.insert(make_cid(3), 300);

        assert_eq!(map.remove(&make_cid(2)), Some(200));
        assert_eq!(map.len(), 2);
        assert!(map.get(&make_cid(2)).is_none());
        assert_eq!(map.get(&make_cid(1)), Some(100));
        assert_eq!(map.get(&make_cid(3)), Some(300));
    }

    #[test]
    fn remove_nonexistent() {
        let mut map = ConnectionMap::new(16);
        map.insert(make_cid(1), 100);
        assert!(map.remove(&make_cid(2)).is_none());
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn clear_map() {
        let mut map = ConnectionMap::new(16);
        for i in 0..5 {
            map.insert(make_cid(i), i as u32);
        }
        assert_eq!(map.len(), 5);
        map.clear();
        assert!(map.is_empty());
        for i in 0..5 {
            assert!(map.get(&make_cid(i)).is_none());
        }
    }

    #[test]
    fn load_factor_limit() {
        let mut map = ConnectionMap::new(16); // Capacity = 16, limit = 12
        for i in 0..12 {
            assert!(map.insert(make_cid(i), i as u32));
        }
        // 13th insert should fail (75% load factor)
        assert!(!map.insert(make_cid(100), 100));
    }

    #[test]
    fn longer_connection_ids() {
        let mut map = ConnectionMap::new(32);
        let cid1 =
            ConnectionId::from_bytes(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]).unwrap();
        let cid2 =
            ConnectionId::from_bytes(&[0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]).unwrap();

        map.insert(cid1, 0);
        map.insert(cid2, 1);

        assert_eq!(map.get(&cid1), Some(0));
        assert_eq!(map.get(&cid2), Some(1));
    }

    #[test]
    fn remove_with_probe_chain() {
        // Insert entries that collide, then remove middle one
        let mut map = ConnectionMap::new(16);
        for i in 0..8 {
            map.insert(make_cid(i), i as u32);
        }

        // Remove a few and verify remaining entries are still findable
        map.remove(&make_cid(3));
        map.remove(&make_cid(5));

        for i in [0, 1, 2, 4, 6, 7] {
            assert_eq!(
                map.get(&make_cid(i)),
                Some(i as u32),
                "failed to find cid {i}"
            );
        }
        assert!(map.get(&make_cid(3)).is_none());
        assert!(map.get(&make_cid(5)).is_none());
    }
}
