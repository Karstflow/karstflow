/// IPv4 neighbor (ARP) table for MAC address resolution.
///
/// Maps IPv4 addresses to Ethernet MAC addresses. Entries have two states:
/// incomplete (ARP request sent, awaiting reply) and active (MAC resolved).
///
/// Uses a flat hashmap with open addressing. All memory pre-allocated.
/// In production, entries would be updated via netlink ARP notifications
/// or direct ARP packet processing.
use karstflow_constants::network::{
    MAC_ADDR_SIZE, NEIGH_STATE_ACTIVE, NEIGH_STATE_INCOMPLETE, NEIGH_TABLE_MAX,
};

/// A neighbor table entry.
#[derive(Debug, Clone, Copy)]
pub struct NeighborEntry {
    /// IPv4 address (host byte order).
    pub ip_addr: u32,
    /// Ethernet MAC address (6 bytes).
    pub mac_addr: [u8; MAC_ADDR_SIZE],
    /// Entry state: incomplete or active.
    pub state: u8,
    /// Timestamp (nanoseconds) when this entry was last updated.
    pub updated_ns: i64,
    /// Suppress ARP probes until this timestamp (nanoseconds).
    pub probe_suppress_until_ns: i64,
}

impl NeighborEntry {
    /// Create an empty/invalid entry.
    const EMPTY: Self = Self {
        ip_addr: 0,
        mac_addr: [0; MAC_ADDR_SIZE],
        state: NEIGH_STATE_INCOMPLETE,
        updated_ns: 0,
        probe_suppress_until_ns: 0,
    };

    /// Whether this entry has a resolved MAC address.
    pub fn is_active(&self) -> bool {
        self.state == NEIGH_STATE_ACTIVE
    }

    /// Whether this entry is still waiting for ARP resolution.
    pub fn is_incomplete(&self) -> bool {
        self.state == NEIGH_STATE_INCOMPLETE
    }
}

/// Sentinel indicating an unused slot.
const SLOT_EMPTY: u32 = 0;

/// IPv4 neighbor table using open-addressing hashmap.
pub struct NeighborTable {
    /// Entry storage.
    entries: Vec<NeighborEntry>,
    /// Slot occupancy markers (IP address or 0 = empty).
    keys: Vec<u32>,
    /// Table capacity (power of 2).
    capacity: usize,
    /// Number of active entries.
    len: usize,
    /// Hash seed for distribution.
    seed: u32,
}

impl NeighborTable {
    /// Create a new neighbor table with the given capacity.
    pub fn new(max_entries: usize) -> Self {
        // Use 3x sparsity like the reference implementation for good probe distribution.
        let capacity = (max_entries * 3).next_power_of_two().max(16);
        Self {
            entries: vec![NeighborEntry::EMPTY; capacity],
            keys: vec![SLOT_EMPTY; capacity],
            capacity,
            len: 0,
            seed: 0x9e3779b9, // golden ratio constant
        }
    }

    /// Look up a neighbor by IPv4 address.
    ///
    /// Returns the entry if found and active, `None` otherwise.
    pub fn lookup(&self, ip_addr: u32) -> Option<&NeighborEntry> {
        if ip_addr == SLOT_EMPTY {
            return None;
        }

        let mask = self.capacity - 1;
        let mut idx = self.hash(ip_addr) & mask;

        for _ in 0..self.capacity {
            if self.keys[idx] == SLOT_EMPTY {
                return None;
            }
            if self.keys[idx] == ip_addr {
                return Some(&self.entries[idx]);
            }
            idx = (idx + 1) & mask;
        }

        None
    }

    /// Resolve a MAC address for the given IP.
    ///
    /// Returns the MAC address if the entry exists and is active.
    pub fn resolve_mac(&self, ip_addr: u32) -> Option<[u8; MAC_ADDR_SIZE]> {
        self.lookup(ip_addr)
            .filter(|e| e.is_active())
            .map(|e| e.mac_addr)
    }

    /// Insert or update a neighbor entry.
    ///
    /// Returns `true` if inserted/updated, `false` if table is full.
    pub fn update(&mut self, ip_addr: u32, mac_addr: [u8; MAC_ADDR_SIZE], now_ns: i64) -> bool {
        if ip_addr == SLOT_EMPTY {
            return false;
        }

        let mask = self.capacity - 1;
        let mut idx = self.hash(ip_addr) & mask;

        for _ in 0..self.capacity {
            if self.keys[idx] == ip_addr {
                // Update existing entry.
                self.entries[idx].mac_addr = mac_addr;
                self.entries[idx].state = NEIGH_STATE_ACTIVE;
                self.entries[idx].updated_ns = now_ns;
                return true;
            }
            if self.keys[idx] == SLOT_EMPTY {
                // Insert new entry.
                if self.len >= self.capacity * 3 / 4 {
                    return false; // Load factor too high.
                }
                self.keys[idx] = ip_addr;
                self.entries[idx] = NeighborEntry {
                    ip_addr,
                    mac_addr,
                    state: NEIGH_STATE_ACTIVE,
                    updated_ns: now_ns,
                    probe_suppress_until_ns: 0,
                };
                self.len += 1;
                return true;
            }
            idx = (idx + 1) & mask;
        }

        false
    }

    /// Insert an incomplete entry (ARP request sent, awaiting reply).
    pub fn insert_incomplete(&mut self, ip_addr: u32, now_ns: i64) -> bool {
        if ip_addr == SLOT_EMPTY {
            return false;
        }

        let mask = self.capacity - 1;
        let mut idx = self.hash(ip_addr) & mask;

        for _ in 0..self.capacity {
            if self.keys[idx] == ip_addr {
                return true; // Already exists.
            }
            if self.keys[idx] == SLOT_EMPTY {
                if self.len >= self.capacity * 3 / 4 {
                    return false;
                }
                self.keys[idx] = ip_addr;
                self.entries[idx] = NeighborEntry {
                    ip_addr,
                    mac_addr: [0; MAC_ADDR_SIZE],
                    state: NEIGH_STATE_INCOMPLETE,
                    updated_ns: now_ns,
                    probe_suppress_until_ns: 0,
                };
                self.len += 1;
                return true;
            }
            idx = (idx + 1) & mask;
        }

        false
    }

    /// Remove a neighbor entry.
    ///
    /// Uses backward-shift deletion to preserve probe chains.
    pub fn remove(&mut self, ip_addr: u32) -> bool {
        if ip_addr == SLOT_EMPTY {
            return false;
        }

        let mask = self.capacity - 1;
        let mut idx = self.hash(ip_addr) & mask;

        for _ in 0..self.capacity {
            if self.keys[idx] == SLOT_EMPTY {
                return false;
            }
            if self.keys[idx] == ip_addr {
                self.backward_shift_delete(idx);
                self.len -= 1;
                return true;
            }
            idx = (idx + 1) & mask;
        }

        false
    }

    /// Number of entries in the table.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.keys.fill(SLOT_EMPTY);
        self.len = 0;
    }

    /// Check whether we should suppress ARP probes for this IP.
    pub fn is_probe_suppressed(&self, ip_addr: u32, now_ns: i64) -> bool {
        self.lookup(ip_addr)
            .is_some_and(|e| now_ns < e.probe_suppress_until_ns)
    }

    /// Set probe suppression deadline for an entry.
    pub fn suppress_probes(&mut self, ip_addr: u32, until_ns: i64) {
        if ip_addr == SLOT_EMPTY {
            return;
        }

        let mask = self.capacity - 1;
        let mut idx = self.hash(ip_addr) & mask;

        for _ in 0..self.capacity {
            if self.keys[idx] == SLOT_EMPTY {
                return;
            }
            if self.keys[idx] == ip_addr {
                self.entries[idx].probe_suppress_until_ns = until_ns;
                return;
            }
            idx = (idx + 1) & mask;
        }
    }

    fn hash(&self, ip: u32) -> usize {
        // FNV-inspired integer hash.
        let mut h = ip ^ self.seed;
        h = h.wrapping_mul(0x9e3779b9);
        h ^= h >> 16;
        h = h.wrapping_mul(0x85ebca6b);
        h ^= h >> 13;
        h as usize
    }

    fn backward_shift_delete(&mut self, removed_idx: usize) {
        let mask = self.capacity - 1;
        let mut empty = removed_idx;
        let mut scan = (removed_idx + 1) & mask;

        loop {
            if self.keys[scan] == SLOT_EMPTY {
                break;
            }

            let home = self.hash(self.keys[scan]) & mask;

            let should_shift = if empty <= scan {
                home <= empty || home > scan
            } else {
                home <= empty && home > scan
            };

            if should_shift {
                self.keys[empty] = self.keys[scan];
                self.entries[empty] = self.entries[scan];
                empty = scan;
            }

            scan = (scan + 1) & mask;
        }

        self.keys[empty] = SLOT_EMPTY;
    }
}

impl Default for NeighborTable {
    fn default() -> Self {
        Self::new(NEIGH_TABLE_MAX)
    }
}

/// Format a MAC address as a colon-separated hex string.
pub fn format_mac(mac: &[u8; MAC_ADDR_SIZE]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_mac(last: u8) -> [u8; 6] {
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, last]
    }

    fn ip(a: u8, b: u8, c: u8, d: u8) -> u32 {
        ((a as u32) << 24) | ((b as u32) << 16) | ((c as u32) << 8) | (d as u32)
    }

    #[test]
    fn empty_table() {
        let table = NeighborTable::new(16);
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
        assert!(table.lookup(ip(10, 0, 0, 1)).is_none());
        assert!(table.resolve_mac(ip(10, 0, 0, 1)).is_none());
    }

    #[test]
    fn insert_and_lookup() {
        let mut table = NeighborTable::new(16);
        assert!(table.update(ip(10, 0, 0, 1), test_mac(1), 1000));
        assert_eq!(table.len(), 1);

        let entry = table.lookup(ip(10, 0, 0, 1)).unwrap();
        assert!(entry.is_active());
        assert_eq!(entry.mac_addr, test_mac(1));
        assert_eq!(entry.updated_ns, 1000);
    }

    #[test]
    fn resolve_mac() {
        let mut table = NeighborTable::new(16);
        table.update(ip(10, 0, 0, 1), test_mac(1), 1000);

        assert_eq!(table.resolve_mac(ip(10, 0, 0, 1)), Some(test_mac(1)));
        assert!(table.resolve_mac(ip(10, 0, 0, 2)).is_none());
    }

    #[test]
    fn update_existing() {
        let mut table = NeighborTable::new(16);
        table.update(ip(10, 0, 0, 1), test_mac(1), 1000);
        table.update(ip(10, 0, 0, 1), test_mac(2), 2000);

        assert_eq!(table.len(), 1);
        assert_eq!(table.resolve_mac(ip(10, 0, 0, 1)), Some(test_mac(2)));

        let entry = table.lookup(ip(10, 0, 0, 1)).unwrap();
        assert_eq!(entry.updated_ns, 2000);
    }

    #[test]
    fn incomplete_entry() {
        let mut table = NeighborTable::new(16);
        table.insert_incomplete(ip(10, 0, 0, 1), 1000);

        let entry = table.lookup(ip(10, 0, 0, 1)).unwrap();
        assert!(entry.is_incomplete());
        assert!(!entry.is_active());

        // resolve_mac returns None for incomplete entries.
        assert!(table.resolve_mac(ip(10, 0, 0, 1)).is_none());

        // Update completes the entry.
        table.update(ip(10, 0, 0, 1), test_mac(1), 2000);
        assert!(table.lookup(ip(10, 0, 0, 1)).unwrap().is_active());
        assert_eq!(table.resolve_mac(ip(10, 0, 0, 1)), Some(test_mac(1)));
    }

    #[test]
    fn remove_entry() {
        let mut table = NeighborTable::new(16);
        table.update(ip(10, 0, 0, 1), test_mac(1), 1000);
        table.update(ip(10, 0, 0, 2), test_mac(2), 1000);

        assert!(table.remove(ip(10, 0, 0, 1)));
        assert_eq!(table.len(), 1);
        assert!(table.lookup(ip(10, 0, 0, 1)).is_none());
        assert!(table.lookup(ip(10, 0, 0, 2)).is_some());
    }

    #[test]
    fn remove_nonexistent() {
        let mut table = NeighborTable::new(16);
        assert!(!table.remove(ip(10, 0, 0, 1)));
    }

    #[test]
    fn clear_table() {
        let mut table = NeighborTable::new(16);
        for i in 1..=10u8 {
            table.update(ip(10, 0, 0, i), test_mac(i), 1000);
        }
        assert_eq!(table.len(), 10);

        table.clear();
        assert!(table.is_empty());
        for i in 1..=10u8 {
            assert!(table.lookup(ip(10, 0, 0, i)).is_none());
        }
    }

    #[test]
    fn probe_suppression() {
        let mut table = NeighborTable::new(16);
        table.insert_incomplete(ip(10, 0, 0, 1), 1000);

        assert!(!table.is_probe_suppressed(ip(10, 0, 0, 1), 1000));

        table.suppress_probes(ip(10, 0, 0, 1), 5000);
        assert!(table.is_probe_suppressed(ip(10, 0, 0, 1), 3000));
        assert!(!table.is_probe_suppressed(ip(10, 0, 0, 1), 5001));
    }

    #[test]
    fn multiple_entries() {
        let mut table = NeighborTable::new(32);
        for i in 1..=20u8 {
            table.update(ip(10, 0, 0, i), test_mac(i), 1000);
        }
        assert_eq!(table.len(), 20);

        for i in 1..=20u8 {
            assert_eq!(table.resolve_mac(ip(10, 0, 0, i)), Some(test_mac(i)));
        }
    }

    #[test]
    fn remove_preserves_probe_chains() {
        let mut table = NeighborTable::new(16);
        for i in 1..=8u8 {
            table.update(ip(10, 0, 0, i), test_mac(i), 1000);
        }

        table.remove(ip(10, 0, 0, 3));
        table.remove(ip(10, 0, 0, 5));

        for i in [1, 2, 4, 6, 7, 8] {
            assert!(
                table.lookup(ip(10, 0, 0, i)).is_some(),
                "missing entry for 10.0.0.{i}"
            );
        }
        assert!(table.lookup(ip(10, 0, 0, 3)).is_none());
        assert!(table.lookup(ip(10, 0, 0, 5)).is_none());
    }

    #[test]
    fn format_mac_address() {
        assert_eq!(
            format_mac(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            "00:11:22:33:44:55"
        );
    }

    #[test]
    fn zero_ip_rejected() {
        let mut table = NeighborTable::new(16);
        assert!(!table.update(0, test_mac(1), 1000));
        assert!(!table.remove(0));
    }
}
