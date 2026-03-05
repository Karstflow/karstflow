/// IPv4 routing table with dual-path lookup.
///
/// Combines a hashmap for /32 host routes (O(1) lookup) with a sorted
/// array for prefix routes (longest prefix match via linear scan).
/// Designed for a small number of routes (validator typically has < 20).
///
/// Thread safety: single writer, multiple readers can use generation
/// counter for torn-read detection.
use std::collections::HashMap;

use karstflow_constants::network::{FIB4_MAX_ROUTES, ROUTE_TYPE_BLACKHOLE, ROUTE_TYPE_LOCAL};

/// Routing lookup result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NextHop {
    /// Gateway IPv4 address (0 = directly connected).
    pub gateway: u32,
    /// Output interface index.
    pub interface_idx: u32,
    /// Source address override (0 = use interface default).
    pub source_addr: u32,
    /// Route type (unicast, local, blackhole, etc.).
    pub route_type: u8,
}

impl NextHop {
    /// A blackhole route (drop the packet).
    pub const BLACKHOLE: Self = Self {
        gateway: 0,
        interface_idx: 0,
        source_addr: 0,
        route_type: ROUTE_TYPE_BLACKHOLE,
    };

    /// Whether this route drops the packet.
    pub fn is_blackhole(&self) -> bool {
        self.route_type == ROUTE_TYPE_BLACKHOLE
    }

    /// Whether this is a local address.
    pub fn is_local(&self) -> bool {
        self.route_type == ROUTE_TYPE_LOCAL
    }
}

/// A prefix route entry.
#[derive(Debug, Clone, Copy)]
struct PrefixRoute {
    /// Network address (masked to prefix length).
    addr: u32,
    /// Subnet mask (e.g., 0xFFFFFF00 for /24).
    mask: u32,
    /// Prefix length (0-31, /32 routes go in hashmap).
    prefix_len: u8,
    /// Priority (lower = higher priority).
    priority: u32,
    /// Next hop for matching packets.
    next_hop: NextHop,
}

/// IPv4 routing table.
pub struct RoutingTable {
    /// /32 host routes (fast hashmap lookup).
    host_routes: HashMap<u32, NextHop>,
    /// Prefix routes sorted by (prefix_len descending, priority ascending).
    /// This ensures longest prefix match on linear scan.
    prefix_routes: Vec<PrefixRoute>,
    /// Generation counter for torn-read detection.
    generation: u64,
}

impl RoutingTable {
    /// Create a new empty routing table.
    pub fn new() -> Self {
        Self {
            host_routes: HashMap::with_capacity(64),
            prefix_routes: Vec::with_capacity(FIB4_MAX_ROUTES),
            generation: 0,
        }
    }

    /// Look up the next hop for a destination IPv4 address.
    ///
    /// First checks /32 host routes (O(1)), then prefix routes
    /// (linear scan, longest prefix match). Returns `None` if no
    /// route matches.
    pub fn lookup(&self, dst_ip: u32) -> Option<NextHop> {
        // Fast path: /32 host route.
        if let Some(hop) = self.host_routes.get(&dst_ip) {
            return Some(*hop);
        }

        // Slow path: prefix routes (sorted longest-first).
        for route in &self.prefix_routes {
            if (dst_ip & route.mask) == route.addr {
                return Some(route.next_hop);
            }
        }

        None
    }

    /// Add a /32 host route.
    pub fn add_host_route(&mut self, dst_ip: u32, next_hop: NextHop) {
        self.generation += 2;
        self.host_routes.insert(dst_ip, next_hop);
    }

    /// Add a prefix route.
    ///
    /// `prefix_len` must be 0-31. Use `add_host_route` for /32.
    pub fn add_prefix_route(
        &mut self,
        network: u32,
        prefix_len: u8,
        priority: u32,
        next_hop: NextHop,
    ) {
        debug_assert!(prefix_len < 32, "use add_host_route for /32");

        let mask = if prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - prefix_len)
        };
        let addr = network & mask;

        self.generation += 2;

        let route = PrefixRoute {
            addr,
            mask,
            prefix_len,
            priority,
            next_hop,
        };

        // Insert in sorted order: longest prefix first, then lowest priority.
        let pos = self
            .prefix_routes
            .iter()
            .position(|r| {
                r.prefix_len < prefix_len || (r.prefix_len == prefix_len && r.priority > priority)
            })
            .unwrap_or(self.prefix_routes.len());

        self.prefix_routes.insert(pos, route);
    }

    /// Add a default route (0.0.0.0/0).
    pub fn add_default_route(&mut self, next_hop: NextHop) {
        self.add_prefix_route(0, 0, u32::MAX, next_hop);
    }

    /// Remove a /32 host route. Returns `true` if removed.
    pub fn remove_host_route(&mut self, dst_ip: u32) -> bool {
        self.generation += 2;
        self.host_routes.remove(&dst_ip).is_some()
    }

    /// Remove all prefix routes matching the given network and prefix length.
    pub fn remove_prefix_route(&mut self, network: u32, prefix_len: u8) -> bool {
        let mask = if prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - prefix_len)
        };
        let addr = network & mask;

        self.generation += 2;
        let before = self.prefix_routes.len();
        self.prefix_routes
            .retain(|r| r.addr != addr || r.prefix_len != prefix_len);
        self.prefix_routes.len() < before
    }

    /// Clear all routes.
    pub fn clear(&mut self) {
        self.generation += 2;
        self.host_routes.clear();
        self.prefix_routes.clear();
    }

    /// Number of /32 host routes.
    pub fn host_route_count(&self) -> usize {
        self.host_routes.len()
    }

    /// Number of prefix routes.
    pub fn prefix_route_count(&self) -> usize {
        self.prefix_routes.len()
    }

    /// Total route count.
    pub fn total_routes(&self) -> usize {
        self.host_routes.len() + self.prefix_routes.len()
    }

    /// Current generation counter.
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

impl Default for RoutingTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper to build an IPv4 address from 4 octets.
pub fn ipv4(a: u8, b: u8, c: u8, d: u8) -> u32 {
    ((a as u32) << 24) | ((b as u32) << 16) | ((c as u32) << 8) | (d as u32)
}

/// Compute a subnet mask from prefix length (0-32).
pub fn prefix_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else if prefix_len >= 32 {
        !0u32
    } else {
        !0u32 << (32 - prefix_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use karstflow_constants::network::ROUTE_TYPE_UNICAST;

    fn unicast_hop(gw: u32, iface: u32) -> NextHop {
        NextHop {
            gateway: gw,
            interface_idx: iface,
            source_addr: 0,
            route_type: ROUTE_TYPE_UNICAST,
        }
    }

    fn local_hop(iface: u32) -> NextHop {
        NextHop {
            gateway: 0,
            interface_idx: iface,
            source_addr: 0,
            route_type: ROUTE_TYPE_LOCAL,
        }
    }

    #[test]
    fn empty_table_returns_none() {
        let table = RoutingTable::new();
        assert!(table.lookup(ipv4(10, 0, 0, 1)).is_none());
        assert_eq!(table.total_routes(), 0);
    }

    #[test]
    fn host_route_lookup() {
        let mut table = RoutingTable::new();
        let hop = unicast_hop(0, 1);
        table.add_host_route(ipv4(10, 0, 0, 1), hop);

        assert_eq!(table.lookup(ipv4(10, 0, 0, 1)), Some(hop));
        assert!(table.lookup(ipv4(10, 0, 0, 2)).is_none());
        assert_eq!(table.host_route_count(), 1);
    }

    #[test]
    fn prefix_route_lookup() {
        let mut table = RoutingTable::new();
        let hop = unicast_hop(ipv4(10, 0, 0, 1), 1);
        table.add_prefix_route(ipv4(10, 0, 0, 0), 24, 100, hop);

        // Matches 10.0.0.0/24.
        assert_eq!(table.lookup(ipv4(10, 0, 0, 50)), Some(hop));
        assert_eq!(table.lookup(ipv4(10, 0, 0, 255)), Some(hop));

        // Doesn't match 10.0.1.0.
        assert!(table.lookup(ipv4(10, 0, 1, 0)).is_none());
    }

    #[test]
    fn longest_prefix_match() {
        let mut table = RoutingTable::new();
        let hop_16 = unicast_hop(ipv4(1, 0, 0, 1), 1);
        let hop_24 = unicast_hop(ipv4(2, 0, 0, 1), 2);

        table.add_prefix_route(ipv4(10, 0, 0, 0), 16, 100, hop_16);
        table.add_prefix_route(ipv4(10, 0, 1, 0), 24, 100, hop_24);

        // 10.0.1.50 matches both /16 and /24, should get /24.
        assert_eq!(table.lookup(ipv4(10, 0, 1, 50)), Some(hop_24));

        // 10.0.2.50 only matches /16.
        assert_eq!(table.lookup(ipv4(10, 0, 2, 50)), Some(hop_16));
    }

    #[test]
    fn host_route_overrides_prefix() {
        let mut table = RoutingTable::new();
        let prefix_hop = unicast_hop(ipv4(1, 0, 0, 1), 1);
        let host_hop = local_hop(2);

        table.add_prefix_route(ipv4(10, 0, 0, 0), 24, 100, prefix_hop);
        table.add_host_route(ipv4(10, 0, 0, 5), host_hop);

        // Host route takes priority.
        assert_eq!(table.lookup(ipv4(10, 0, 0, 5)), Some(host_hop));
        // Other addresses in subnet use prefix route.
        assert_eq!(table.lookup(ipv4(10, 0, 0, 6)), Some(prefix_hop));
    }

    #[test]
    fn default_route() {
        let mut table = RoutingTable::new();
        let default = unicast_hop(ipv4(192, 168, 1, 1), 1);
        table.add_default_route(default);

        assert_eq!(table.lookup(ipv4(8, 8, 8, 8)), Some(default));
        assert_eq!(table.lookup(ipv4(1, 2, 3, 4)), Some(default));
    }

    #[test]
    fn priority_ordering() {
        let mut table = RoutingTable::new();
        let low_prio = unicast_hop(ipv4(1, 0, 0, 1), 1);
        let high_prio = unicast_hop(ipv4(2, 0, 0, 1), 2);

        table.add_prefix_route(ipv4(10, 0, 0, 0), 24, 200, low_prio);
        table.add_prefix_route(ipv4(10, 0, 0, 0), 24, 100, high_prio);

        // Higher priority (lower number) wins.
        assert_eq!(table.lookup(ipv4(10, 0, 0, 1)), Some(high_prio));
    }

    #[test]
    fn remove_host_route() {
        let mut table = RoutingTable::new();
        table.add_host_route(ipv4(10, 0, 0, 1), unicast_hop(0, 1));
        assert!(table.remove_host_route(ipv4(10, 0, 0, 1)));
        assert!(table.lookup(ipv4(10, 0, 0, 1)).is_none());
        assert!(!table.remove_host_route(ipv4(10, 0, 0, 1)));
    }

    #[test]
    fn remove_prefix_route() {
        let mut table = RoutingTable::new();
        table.add_prefix_route(ipv4(10, 0, 0, 0), 24, 100, unicast_hop(0, 1));
        assert!(table.remove_prefix_route(ipv4(10, 0, 0, 0), 24));
        assert!(table.lookup(ipv4(10, 0, 0, 1)).is_none());
    }

    #[test]
    fn clear_routes() {
        let mut table = RoutingTable::new();
        table.add_host_route(ipv4(10, 0, 0, 1), unicast_hop(0, 1));
        table.add_prefix_route(ipv4(10, 0, 0, 0), 24, 100, unicast_hop(0, 1));

        table.clear();
        assert_eq!(table.total_routes(), 0);
        assert!(table.lookup(ipv4(10, 0, 0, 1)).is_none());
    }

    #[test]
    fn blackhole_route() {
        let mut table = RoutingTable::new();
        table.add_host_route(ipv4(10, 0, 0, 1), NextHop::BLACKHOLE);

        let hop = table.lookup(ipv4(10, 0, 0, 1)).unwrap();
        assert!(hop.is_blackhole());
    }

    #[test]
    fn ipv4_helper() {
        assert_eq!(ipv4(10, 0, 0, 1), 0x0A000001);
        assert_eq!(ipv4(192, 168, 1, 0), 0xC0A80100);
        assert_eq!(ipv4(255, 255, 255, 255), 0xFFFFFFFF);
    }

    #[test]
    fn prefix_mask_values() {
        assert_eq!(prefix_mask(0), 0);
        assert_eq!(prefix_mask(8), 0xFF000000);
        assert_eq!(prefix_mask(16), 0xFFFF0000);
        assert_eq!(prefix_mask(24), 0xFFFFFF00);
        assert_eq!(prefix_mask(32), 0xFFFFFFFF);
    }

    #[test]
    fn generation_increments() {
        let mut table = RoutingTable::new();
        let g0 = table.generation();

        table.add_host_route(ipv4(10, 0, 0, 1), unicast_hop(0, 1));
        assert!(table.generation() > g0);

        let g1 = table.generation();
        table.add_prefix_route(ipv4(10, 0, 0, 0), 24, 100, unicast_hop(0, 1));
        assert!(table.generation() > g1);
    }
}
