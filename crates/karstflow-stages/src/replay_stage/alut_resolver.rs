/// Address Lookup Table (ALUT) resolver for the replay pipeline.
///
/// Resolves v0 transaction account keys by looking up addresses in
/// on-chain Address Lookup Tables before execution. This enables
/// transactions to reference more accounts than fit in the 1232-byte
/// transaction size limit.
///
/// The resolver caches recently used lookup tables to avoid repeated
/// account reads during block processing.
use karstflow_types::Pubkey;
use std::collections::HashMap;

/// Error during ALUT resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlutError {
    /// Lookup table account not found.
    TableNotFound(Pubkey),
    /// Lookup table data is too short or malformed.
    InvalidTableData(Pubkey),
    /// Address index exceeds the table's address count.
    IndexOutOfRange {
        table: Pubkey,
        index: u8,
        table_len: usize,
    },
    /// Lookup table is deactivated (deactivation_slot < current_slot).
    TableDeactivated(Pubkey),
}

impl std::fmt::Display for AlutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TableNotFound(key) => write!(f, "ALUT not found: {key:?}"),
            Self::InvalidTableData(key) => write!(f, "ALUT invalid data: {key:?}"),
            Self::IndexOutOfRange {
                table,
                index,
                table_len,
            } => write!(
                f,
                "ALUT index {index} out of range (table {table:?} has {table_len} entries)"
            ),
            Self::TableDeactivated(key) => write!(f, "ALUT deactivated: {key:?}"),
        }
    }
}

impl std::error::Error for AlutError {}

/// Metadata header size for Address Lookup Table accounts.
/// authority (32) + deactivation_slot (8) + last_extended_slot (8) +
/// last_extended_slot_start_index (1) + padding (1) + serialized_map_len (2)
/// = 56 bytes, but the actual meta size is defined by protocol constants.
pub const LOOKUP_TABLE_META_SIZE: usize = 56;

/// Parsed lookup table: just the address list.
#[derive(Debug, Clone)]
pub struct ParsedLookupTable {
    /// The addresses stored in this lookup table.
    pub addresses: Vec<Pubkey>,
}

/// Parse a lookup table account's data into an address list.
pub fn parse_lookup_table(data: &[u8]) -> Result<ParsedLookupTable, &'static str> {
    if data.len() < LOOKUP_TABLE_META_SIZE {
        return Err("data too short for lookup table");
    }

    let addresses_data = &data[LOOKUP_TABLE_META_SIZE..];
    if addresses_data.len() % 32 != 0 {
        return Err("address data not aligned to 32 bytes");
    }

    let count = addresses_data.len() / 32;
    let mut addresses = Vec::with_capacity(count);
    for i in 0..count {
        let start = i * 32;
        let mut key = [0u8; 32];
        key.copy_from_slice(&addresses_data[start..start + 32]);
        addresses.push(Pubkey::from(key));
    }

    Ok(ParsedLookupTable { addresses })
}

/// Cache for recently resolved lookup tables.
pub struct AlutCache {
    /// table_key → parsed addresses.
    cache: HashMap<Pubkey, Vec<Pubkey>>,
    /// Maximum number of cached tables.
    max_entries: usize,
}

impl AlutCache {
    /// Create a new cache with the given capacity.
    pub fn new(max_entries: usize) -> Self {
        Self {
            cache: HashMap::with_capacity(max_entries),
            max_entries,
        }
    }

    /// Get cached addresses for a table, or None if not cached.
    pub fn get(&self, table_key: &Pubkey) -> Option<&[Pubkey]> {
        self.cache.get(table_key).map(|v| v.as_slice())
    }

    /// Insert a parsed table into the cache.
    /// If at capacity, the cache is not evicted (caller should call clear at block boundaries).
    pub fn insert(&mut self, table_key: Pubkey, addresses: Vec<Pubkey>) {
        if self.cache.len() < self.max_entries {
            self.cache.insert(table_key, addresses);
        }
    }

    /// Clear the cache (e.g., at slot boundaries).
    pub fn clear(&mut self) {
        self.cache.clear();
    }

    /// Number of cached tables.
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

/// A lookup request from a v0 transaction.
#[derive(Debug, Clone)]
pub struct LookupRequest {
    /// The lookup table account key.
    pub table_key: Pubkey,
    /// Indices for writable accounts.
    pub writable_indices: Vec<u8>,
    /// Indices for read-only accounts.
    pub readonly_indices: Vec<u8>,
}

/// Resolved addresses from lookup table resolution.
#[derive(Debug, Clone, Default)]
pub struct ResolvedLookups {
    /// Writable accounts resolved from lookup tables.
    pub writable: Vec<Pubkey>,
    /// Read-only accounts resolved from lookup tables.
    pub readonly: Vec<Pubkey>,
}

/// Resolve lookup requests against a cache, falling back to `read_account`.
///
/// Returns resolved addresses or the first error encountered.
pub fn resolve_lookups<F>(
    requests: &[LookupRequest],
    cache: &mut AlutCache,
    read_account: F,
) -> Result<ResolvedLookups, AlutError>
where
    F: Fn(&Pubkey) -> Option<Vec<u8>>,
{
    let mut result = ResolvedLookups::default();

    for req in requests {
        let addresses = if let Some(cached) = cache.get(&req.table_key) {
            cached
        } else {
            let data = read_account(&req.table_key)
                .ok_or(AlutError::TableNotFound(req.table_key))?;

            let parsed = parse_lookup_table(&data)
                .map_err(|_| AlutError::InvalidTableData(req.table_key))?;

            cache.insert(req.table_key, parsed.addresses);
            cache.get(&req.table_key).unwrap()
        };

        for &idx in &req.writable_indices {
            let i = idx as usize;
            if i >= addresses.len() {
                return Err(AlutError::IndexOutOfRange {
                    table: req.table_key,
                    index: idx,
                    table_len: addresses.len(),
                });
            }
            result.writable.push(addresses[i]);
        }

        for &idx in &req.readonly_indices {
            let i = idx as usize;
            if i >= addresses.len() {
                return Err(AlutError::IndexOutOfRange {
                    table: req.table_key,
                    index: idx,
                    table_len: addresses.len(),
                });
            }
            result.readonly.push(addresses[i]);
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_table_data(addresses: &[Pubkey]) -> Vec<u8> {
        let mut data = vec![0u8; LOOKUP_TABLE_META_SIZE];
        for addr in addresses {
            data.extend_from_slice(addr.as_bytes());
        }
        data
    }

    fn table_key(id: u8) -> Pubkey {
        let mut k = [0u8; 32];
        k[0] = id;
        Pubkey::new(k)
    }

    fn addr(id: u8) -> Pubkey {
        let mut k = [0u8; 32];
        k[0] = 0xA0;
        k[1] = id;
        Pubkey::new(k)
    }

    #[test]
    fn parse_empty_table() {
        let data = vec![0u8; LOOKUP_TABLE_META_SIZE];
        let parsed = parse_lookup_table(&data).unwrap();
        assert!(parsed.addresses.is_empty());
    }

    #[test]
    fn parse_table_with_addresses() {
        let addrs = vec![addr(1), addr(2), addr(3)];
        let data = make_table_data(&addrs);
        let parsed = parse_lookup_table(&data).unwrap();
        assert_eq!(parsed.addresses.len(), 3);
        assert_eq!(parsed.addresses[0], addr(1));
        assert_eq!(parsed.addresses[2], addr(3));
    }

    #[test]
    fn parse_table_too_short() {
        let data = vec![0u8; 10];
        assert!(parse_lookup_table(&data).is_err());
    }

    #[test]
    fn resolve_writable_and_readonly() {
        let table = table_key(1);
        let addrs = vec![addr(10), addr(20), addr(30), addr(40)];
        let data = make_table_data(&addrs);

        let mut cache = AlutCache::new(16);
        let requests = vec![LookupRequest {
            table_key: table,
            writable_indices: vec![0, 2],
            readonly_indices: vec![1, 3],
        }];

        let resolved = resolve_lookups(&requests, &mut cache, |_| Some(data.clone())).unwrap();
        assert_eq!(resolved.writable.len(), 2);
        assert_eq!(resolved.writable[0], addr(10));
        assert_eq!(resolved.writable[1], addr(30));
        assert_eq!(resolved.readonly.len(), 2);
        assert_eq!(resolved.readonly[0], addr(20));
        assert_eq!(resolved.readonly[1], addr(40));
    }

    #[test]
    fn resolve_index_out_of_range() {
        let table = table_key(1);
        let addrs = vec![addr(10)];
        let data = make_table_data(&addrs);

        let mut cache = AlutCache::new(16);
        let requests = vec![LookupRequest {
            table_key: table,
            writable_indices: vec![5],
            readonly_indices: vec![],
        }];

        let err = resolve_lookups(&requests, &mut cache, |_| Some(data.clone())).unwrap_err();
        match err {
            AlutError::IndexOutOfRange { index, .. } => assert_eq!(index, 5),
            _ => panic!("expected IndexOutOfRange"),
        }
    }

    #[test]
    fn resolve_table_not_found() {
        let mut cache = AlutCache::new(16);
        let requests = vec![LookupRequest {
            table_key: table_key(99),
            writable_indices: vec![0],
            readonly_indices: vec![],
        }];

        let err = resolve_lookups(&requests, &mut cache, |_| None).unwrap_err();
        assert!(matches!(err, AlutError::TableNotFound(_)));
    }

    #[test]
    fn cache_hit_avoids_read() {
        let table = table_key(1);
        let addrs = vec![addr(10), addr(20)];

        let mut cache = AlutCache::new(16);
        cache.insert(table, addrs.clone());

        let requests = vec![LookupRequest {
            table_key: table,
            writable_indices: vec![0],
            readonly_indices: vec![1],
        }];

        // read_account should NOT be called (panics if it is)
        let resolved =
            resolve_lookups(&requests, &mut cache, |_| panic!("should not read")).unwrap();
        assert_eq!(resolved.writable[0], addr(10));
        assert_eq!(resolved.readonly[0], addr(20));
    }

    #[test]
    fn cache_operations() {
        let mut cache = AlutCache::new(2);
        assert!(cache.is_empty());

        cache.insert(table_key(1), vec![addr(1)]);
        assert_eq!(cache.len(), 1);
        assert!(cache.get(&table_key(1)).is_some());

        cache.insert(table_key(2), vec![addr(2)]);
        assert_eq!(cache.len(), 2);

        // At capacity — should not insert
        cache.insert(table_key(3), vec![addr(3)]);
        assert_eq!(cache.len(), 2);
        assert!(cache.get(&table_key(3)).is_none());

        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn multiple_tables() {
        let t1 = table_key(1);
        let t2 = table_key(2);
        let data1 = make_table_data(&[addr(10), addr(11)]);
        let data2 = make_table_data(&[addr(20), addr(21), addr(22)]);

        let mut cache = AlutCache::new(16);
        let requests = vec![
            LookupRequest {
                table_key: t1,
                writable_indices: vec![0],
                readonly_indices: vec![],
            },
            LookupRequest {
                table_key: t2,
                writable_indices: vec![],
                readonly_indices: vec![2],
            },
        ];

        let resolved = resolve_lookups(&requests, &mut cache, |key| {
            if *key == t1 {
                Some(data1.clone())
            } else if *key == t2 {
                Some(data2.clone())
            } else {
                None
            }
        })
        .unwrap();

        assert_eq!(resolved.writable.len(), 1);
        assert_eq!(resolved.writable[0], addr(10));
        assert_eq!(resolved.readonly.len(), 1);
        assert_eq!(resolved.readonly[0], addr(22));
    }
}
