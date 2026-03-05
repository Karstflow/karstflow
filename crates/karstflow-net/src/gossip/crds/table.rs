//! CRDS table: the core multi-index container for gossip data.
//!
//! Maintains five concurrent indexes over CRDS entries:
//! 1. Lookup map (HashMap) for O(1) key-value access
//! 2. Eviction ordering by stake (BTreeMap) for lowest-stake removal
//! 3. Staked expiration list (ordered by reception time)
//! 4. Unstaked expiration list (ordered by reception time)
//! 5. Hash-prefix index (BTreeMap) for bloom filter range queries
//!
//! Also maintains a purged entry set for tracking recently removed hashes.

use super::bloom::{GossipBloomFilter, PullRequestMask};
use super::entry::{CrdsEntry, EntryOrigin};
use super::key::CrdsKey;
use super::sampler::WeightedPeerSampler;
use super::value::{CrdsValue, FastCheckResult};
use karstflow_constants::gossip;
use std::collections::{BTreeMap, HashMap, VecDeque};

/// Result of inserting a value into the CRDS table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertOutcome {
    /// New entry inserted successfully.
    Inserted,
    /// Existing entry updated (newer value replaced older).
    Updated,
    /// Duplicate value (same hash already present).
    Duplicate,
    /// Value is older than the incumbent (rejected).
    Stale,
    /// Table full and value has lower stake than all entries (rejected).
    EvictionFailed,
}

/// Tracks a purged entry hash with its expiration time.
#[derive(Debug, Clone)]
struct PurgedEntry {
    /// SHA-256 hash of the removed value.
    hash: [u8; 32],
    /// Hash prefix for range queries.
    hash_prefix: u64,
    /// When this purge record expires (nanos).
    expires_at_nanos: i64,
}

/// Per-value-type entry counter for metrics.
#[derive(Debug, Clone, Default)]
pub struct CrdsMetrics {
    /// Count of entries per value type.
    pub entry_counts: [usize; gossip::VALUE_TYPE_COUNT],
    /// Number of entries expired.
    pub expired_count: u64,
    /// Number of entries evicted (table full).
    pub evicted_count: u64,
    /// Number of staked peers.
    pub staked_peer_count: usize,
    /// Number of unstaked peers.
    pub unstaked_peer_count: usize,
    /// Total purged entries tracked.
    pub purged_count: usize,
}

/// The CRDS table: multi-index container for gossip data.
///
/// Holds all CRDS entries with efficient access patterns:
/// - Key lookup: O(1)
/// - Stake-ordered eviction: O(log n)
/// - Time-ordered expiration: O(1) per entry
/// - Hash-prefix range queries: O(log n + k)
pub struct CrdsTable {
    /// Maximum number of entries.
    max_entries: usize,
    /// Maximum purged entries to track.
    max_purged: usize,

    // --- Index 1: Lookup map ---
    /// Key → entry index in the entries vec.
    lookup: HashMap<CrdsKey, usize>,

    // --- Entry storage ---
    /// All entries, indexed by position. Holes are marked with is_occupied=false.
    entries: Vec<Option<CrdsEntry>>,
    /// Free list of available positions.
    free_list: Vec<usize>,

    // --- Index 2: Eviction ordering ---
    /// (stake, entry_index) → entry_index. Sorted by stake ascending.
    /// Used to find the lowest-stake entry for eviction.
    eviction_order: BTreeMap<(u64, usize), usize>,

    // --- Index 3 & 4: Expiration lists ---
    /// Staked entries ordered by reception time (oldest first).
    staked_expire: VecDeque<usize>,
    /// Unstaked entries ordered by reception time (oldest first).
    unstaked_expire: VecDeque<usize>,

    // --- Index 5: Hash-prefix index ---
    /// hash_prefix → entry indices. For bloom filter range queries.
    hash_index: BTreeMap<u64, Vec<usize>>,

    // --- Purged entry tracking ---
    /// Recently removed entry hashes (for pull request bloom filter inclusion).
    purged: VecDeque<PurgedEntry>,
    /// Failed insert hashes (entries that failed fast check).
    failed_inserts: VecDeque<PurgedEntry>,

    // --- Peer samplers ---
    /// Pull request peer sampler (weighted by stake).
    pub pull_sampler: WeightedPeerSampler,
    /// Active set bucket samplers (25 buckets).
    pub bucket_samplers: Vec<WeightedPeerSampler>,

    // --- Metrics ---
    pub metrics: CrdsMetrics,

    // --- State tracking ---
    /// Whether any staked node has been observed (affects unstaked expiry).
    has_seen_staked_node: bool,

    // --- Cursor tracking for push ---
    /// Next ordinal to assign to inserted/updated entries.
    next_ordinal: u64,
    /// Ordinal-ordered index: ordinal → entry index. Enables efficient
    /// "values since cursor N" queries for the push gossip loop.
    ordinal_index: BTreeMap<u64, usize>,
}

impl CrdsTable {
    /// Create a new CRDS table with default limits.
    pub fn new() -> Self {
        Self::with_limits(gossip::MAX_CRDS_TABLE_ENTRIES, gossip::MAX_PURGED_ENTRIES)
    }

    /// Create a CRDS table with custom limits.
    pub fn with_limits(max_entries: usize, max_purged: usize) -> Self {
        let bucket_samplers = (0..gossip::ACTIVE_SET_BUCKET_COUNT)
            .map(|_| WeightedPeerSampler::with_capacity(64))
            .collect();

        Self {
            max_entries,
            max_purged,
            lookup: HashMap::with_capacity(max_entries),
            entries: Vec::with_capacity(max_entries),
            free_list: Vec::new(),
            eviction_order: BTreeMap::new(),
            staked_expire: VecDeque::new(),
            unstaked_expire: VecDeque::new(),
            hash_index: BTreeMap::new(),
            purged: VecDeque::new(),
            failed_inserts: VecDeque::new(),
            pull_sampler: WeightedPeerSampler::with_capacity(64),
            bucket_samplers,
            metrics: CrdsMetrics::default(),
            has_seen_staked_node: false,
            next_ordinal: 0,
            ordinal_index: BTreeMap::new(),
        }
    }

    /// Number of entries currently in the table.
    pub fn len(&self) -> usize {
        self.lookup.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.lookup.is_empty()
    }

    /// Number of purged entry hashes being tracked.
    pub fn purged_len(&self) -> usize {
        self.purged.len() + self.failed_inserts.len()
    }

    /// Insert or update a CRDS value.
    ///
    /// Performs the fast check algorithm, eviction if needed, and
    /// updates all five indexes atomically.
    pub fn insert(
        &mut self,
        value: CrdsValue,
        stake: u64,
        now_nanos: i64,
        origin: EntryOrigin,
    ) -> InsertOutcome {
        let key = value.key();

        // Check against incumbent (if exists)
        if let Some(&existing_idx) = self.lookup.get(&key) {
            if let Some(existing) = &self.entries[existing_idx] {
                // Step 1: Quick duplicate check (same hash = same value)
                let new_hash = value.compute_hash();
                if new_hash == existing.value_hash {
                    return InsertOutcome::Duplicate;
                }

                // Step 2: Fast override check (type-specific comparison)
                match value.fast_overrides(&existing.value) {
                    FastCheckResult::Overrides => {
                        // Proceed to replace
                    }
                    FastCheckResult::Fails => {
                        self.record_failed_insert(&value, now_nanos);
                        return InsertOutcome::Stale;
                    }
                    FastCheckResult::Undetermined => {
                        // Step 3: Full hash comparison as tiebreaker
                        if !value.overrides(&existing.value) {
                            self.record_failed_insert(&value, now_nanos);
                            return InsertOutcome::Stale;
                        }
                    }
                }

                // Replace: purge old entry hash, insert new one
                self.purge_entry_hash(existing_idx, now_nanos);
                let entry = CrdsEntry::new(value, stake, now_nanos, origin);
                self.replace_entry(existing_idx, entry);
                return InsertOutcome::Updated;
            }
        }

        // New entry: check capacity
        if self.len() >= self.max_entries {
            // Try to evict lowest-stake entry
            if let Some((&(victim_stake, victim_idx), _)) = self.eviction_order.iter().next() {
                if stake > victim_stake || (stake == victim_stake && !self.is_empty()) {
                    self.purge_entry_hash(victim_idx, now_nanos);
                    self.remove_entry(victim_idx);
                    self.metrics.evicted_count += 1;
                } else {
                    self.record_failed_insert(&value, now_nanos);
                    return InsertOutcome::EvictionFailed;
                }
            } else {
                self.record_failed_insert(&value, now_nanos);
                return InsertOutcome::EvictionFailed;
            }
        }

        // Insert new entry
        if stake > 0 {
            self.has_seen_staked_node = true;
        }
        let entry = CrdsEntry::new(value, stake, now_nanos, origin);
        self.insert_entry(entry);
        InsertOutcome::Inserted
    }

    /// Look up an entry by key.
    pub fn get(&self, key: &CrdsKey) -> Option<&CrdsEntry> {
        self.lookup
            .get(key)
            .and_then(|&idx| self.entries[idx].as_ref())
    }

    /// Look up a value by key.
    pub fn get_value(&self, key: &CrdsKey) -> Option<&CrdsValue> {
        self.get(key).map(|e| &e.value)
    }

    /// Get all contact info entries.
    pub fn contact_info_entries(&self) -> Vec<&CrdsEntry> {
        self.lookup
            .iter()
            .filter_map(|(_, &idx)| {
                self.entries[idx]
                    .as_ref()
                    .filter(|e| e.value.data.is_contact_info())
            })
            .collect()
    }

    /// Get an entry by its internal storage index.
    ///
    /// This is used by the peer sampler: the sampler stores entry indices,
    /// and callers can resolve them back to entries.
    pub fn entries_at(&self, index: usize) -> Option<&CrdsEntry> {
        self.entries.get(index).and_then(|e| e.as_ref())
    }

    /// Get all entries of a specific value type.
    pub fn entries_by_type(&self, value_type: u8) -> Vec<&CrdsEntry> {
        self.lookup
            .iter()
            .filter(|(k, _)| k.value_type == value_type)
            .filter_map(|(_, &idx)| self.entries[idx].as_ref())
            .collect()
    }

    /// Expire old entries and purged hashes.
    ///
    /// Should be called periodically (e.g., every tick).
    pub fn advance(&mut self, now_nanos: i64) -> usize {
        let mut expired_count = 0;

        // Expire staked entries (48h)
        expired_count += self.expire_list(now_nanos, gossip::STAKED_EXPIRE_DURATION_NANOS, true);

        // Expire unstaked entries (15s, or 48h if no staked nodes seen)
        let unstaked_duration = if self.has_seen_staked_node {
            gossip::UNSTAKED_EXPIRE_DURATION_NANOS
        } else {
            gossip::STAKED_EXPIRE_DURATION_NANOS
        };
        expired_count += self.expire_list(now_nanos, unstaked_duration, false);

        // Expire purged entries (60s)
        while let Some(front) = self.purged.front() {
            if front.expires_at_nanos <= now_nanos {
                self.purged.pop_front();
            } else {
                break;
            }
        }

        // Expire failed inserts (20s)
        while let Some(front) = self.failed_inserts.front() {
            if front.expires_at_nanos <= now_nanos {
                self.failed_inserts.pop_front();
            } else {
                break;
            }
        }

        self.metrics.expired_count += expired_count as u64;
        self.metrics.purged_count = self.purged.len() + self.failed_inserts.len();
        expired_count
    }

    /// Build a bloom filter for a pull request.
    ///
    /// Includes all CRDS entries and purged entries matching the mask.
    pub fn build_pull_filter(&self, mask: &PullRequestMask) -> GossipBloomFilter {
        let matching_count = self.count_entries_in_range(mask);
        let total_count = matching_count + self.count_purged_in_range(mask);
        let mut filter = GossipBloomFilter::new(total_count.max(1));

        // Insert matching CRDS entries
        for (&prefix, indices) in self.hash_index.range(mask.range_start()..=mask.range_end()) {
            if mask.matches(prefix) {
                for &idx in indices {
                    if let Some(entry) = &self.entries[idx] {
                        filter.insert(&entry.value_hash);
                    }
                }
            }
        }

        // Insert matching purged entries
        for purged in &self.purged {
            if mask.matches(purged.hash_prefix) {
                filter.insert(&purged.hash);
            }
        }
        for failed in &self.failed_inserts {
            if mask.matches(failed.hash_prefix) {
                filter.insert(&failed.hash);
            }
        }

        filter
    }

    /// Find entries that pass through a bloom filter (for pull responses).
    ///
    /// Returns entries whose hashes are NOT in the filter (the requester
    /// doesn't have them), limited by max_count.
    pub fn filter_for_pull_response(
        &self,
        filter: &GossipBloomFilter,
        mask: &PullRequestMask,
        max_count: usize,
    ) -> Vec<&CrdsValue> {
        let mut results = Vec::with_capacity(max_count);

        for (&prefix, indices) in self.hash_index.range(mask.range_start()..=mask.range_end()) {
            if !mask.matches(prefix) {
                continue;
            }
            for &idx in indices {
                if results.len() >= max_count {
                    return results;
                }
                if let Some(entry) = &self.entries[idx] {
                    if !filter.contains(&entry.value_hash) {
                        results.push(&entry.value);
                    }
                }
            }
        }

        results
    }

    /// Sample a random peer for pull requests.
    pub fn sample_pull_peer(&self, random_value: u64) -> Option<usize> {
        self.pull_sampler.sample(random_value)
    }

    /// Sample a random peer from an active set bucket.
    pub fn sample_active_set_peer(&self, bucket: usize, random_value: u64) -> Option<usize> {
        self.bucket_samplers
            .get(bucket)
            .and_then(|s| s.sample(random_value))
    }

    /// Return the current ordinal cursor.
    ///
    /// A caller that wants to receive all future inserts/updates should
    /// save this value and later pass it to `values_since()`.
    pub fn cursor(&self) -> u64 {
        self.next_ordinal
    }

    /// Return values inserted or updated since the given ordinal cursor.
    ///
    /// Returns a Vec of references to CrdsValues and the new cursor to
    /// use in subsequent calls. Only entries with ordinal >= `since` are
    /// included.
    pub fn values_since(&self, since: u64) -> (Vec<&CrdsValue>, u64) {
        let mut values = Vec::new();
        for (&_ordinal, &idx) in self.ordinal_index.range(since..) {
            if let Some(entry) = &self.entries[idx] {
                values.push(&entry.value);
            }
        }
        (values, self.next_ordinal)
    }

    /// Update metrics snapshot.
    pub fn update_metrics(&mut self) {
        self.metrics.entry_counts = [0; gossip::VALUE_TYPE_COUNT];
        self.metrics.staked_peer_count = 0;
        self.metrics.unstaked_peer_count = 0;

        for &idx in self.lookup.values() {
            if let Some(entry) = &self.entries[idx] {
                let vt = entry.key.value_type as usize;
                if vt < gossip::VALUE_TYPE_COUNT {
                    self.metrics.entry_counts[vt] += 1;
                }
                if entry.value.data.is_contact_info() {
                    if entry.is_staked() {
                        self.metrics.staked_peer_count += 1;
                    } else {
                        self.metrics.unstaked_peer_count += 1;
                    }
                }
            }
        }
        self.metrics.purged_count = self.purged.len() + self.failed_inserts.len();
    }

    // --- Internal helpers ---

    fn allocate_slot(&mut self) -> usize {
        if let Some(idx) = self.free_list.pop() {
            idx
        } else {
            let idx = self.entries.len();
            self.entries.push(None);
            idx
        }
    }

    fn insert_entry(&mut self, mut entry: CrdsEntry) {
        let idx = self.allocate_slot();
        let key = entry.key;
        let stake = entry.stake;
        let hash_prefix = entry.hash_prefix;
        let is_staked = entry.is_staked();
        let is_contact_info = entry.value.data.is_contact_info();

        // Assign monotonically increasing ordinal for push cursor tracking.
        let ordinal = self.next_ordinal;
        self.next_ordinal += 1;
        entry.ordinal = ordinal;

        // Update peer samplers for contact info entries
        if is_contact_info {
            let now = entry.received_at_nanos;
            let score = entry.peer_score(now, gossip::FRESH_THRESHOLD_NANOS);
            self.pull_sampler.add(idx, score);
            for sampler in &mut self.bucket_samplers {
                sampler.add(idx, score);
            }
        }

        self.entries[idx] = Some(entry);
        self.lookup.insert(key, idx);
        self.ordinal_index.insert(ordinal, idx);
        self.eviction_order.insert((stake, idx), idx);

        // Add to hash-prefix index
        self.hash_index.entry(hash_prefix).or_default().push(idx);

        // Add to expiration list
        if is_staked {
            self.staked_expire.push_back(idx);
        } else {
            self.unstaked_expire.push_back(idx);
        }
    }

    fn replace_entry(&mut self, idx: usize, mut new_entry: CrdsEntry) {
        if let Some(old_entry) = &self.entries[idx] {
            let old_stake = old_entry.stake;
            let old_hash_prefix = old_entry.hash_prefix;
            let old_ordinal = old_entry.ordinal;

            // Remove from eviction order
            self.eviction_order.remove(&(old_stake, idx));

            // Remove from hash-prefix index
            if let Some(indices) = self.hash_index.get_mut(&old_hash_prefix) {
                indices.retain(|&i| i != idx);
                if indices.is_empty() {
                    self.hash_index.remove(&old_hash_prefix);
                }
            }

            // Remove old ordinal from ordinal index
            self.ordinal_index.remove(&old_ordinal);
        }

        // Assign new ordinal for cursor tracking.
        let ordinal = self.next_ordinal;
        self.next_ordinal += 1;
        new_entry.ordinal = ordinal;

        let new_stake = new_entry.stake;
        let new_hash_prefix = new_entry.hash_prefix;
        let is_contact_info = new_entry.value.data.is_contact_info();

        // Update peer samplers for contact info entries
        if is_contact_info {
            let now = new_entry.received_at_nanos;
            let score = new_entry.peer_score(now, gossip::FRESH_THRESHOLD_NANOS);
            // Update weight in existing sampler position
            // The sampler uses peer_index = idx, so we just update weight
            self.pull_sampler.update_weight(idx, score);
            for sampler in &mut self.bucket_samplers {
                sampler.update_weight(idx, score);
            }
        }

        self.entries[idx] = Some(new_entry);
        self.eviction_order.insert((new_stake, idx), idx);
        self.hash_index
            .entry(new_hash_prefix)
            .or_default()
            .push(idx);
        self.ordinal_index.insert(ordinal, idx);
    }

    fn remove_entry(&mut self, idx: usize) {
        if let Some(entry) = self.entries[idx].take() {
            self.lookup.remove(&entry.key);
            self.eviction_order.remove(&(entry.stake, idx));

            // Remove from hash-prefix index
            if let Some(indices) = self.hash_index.get_mut(&entry.hash_prefix) {
                indices.retain(|&i| i != idx);
                if indices.is_empty() {
                    self.hash_index.remove(&entry.hash_prefix);
                }
            }

            // Remove from ordinal index
            self.ordinal_index.remove(&entry.ordinal);

            // Remove from samplers if contact info
            if entry.value.data.is_contact_info() {
                self.pull_sampler.remove(idx);
                for sampler in &mut self.bucket_samplers {
                    sampler.remove(idx);
                }
            }

            self.free_list.push(idx);

            // Note: expiration list entries become stale (idx points to None).
            // They are cleaned up lazily during expire_list().
        }
    }

    fn purge_entry_hash(&mut self, idx: usize, now_nanos: i64) {
        if let Some(entry) = &self.entries[idx] {
            if self.purged.len() >= self.max_purged {
                self.purged.pop_front();
            }
            self.purged.push_back(PurgedEntry {
                hash: entry.value_hash,
                hash_prefix: entry.hash_prefix,
                expires_at_nanos: now_nanos + gossip::PURGED_EXPIRE_DURATION_NANOS,
            });
        }
    }

    fn record_failed_insert(&mut self, value: &CrdsValue, now_nanos: i64) {
        let hash = value.compute_hash();
        let hash_prefix = u64::from_be_bytes([
            hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
        ]);

        if self.failed_inserts.len() >= gossip::MAX_FAILED_INSERT_ENTRIES {
            self.failed_inserts.pop_front();
        }
        self.failed_inserts.push_back(PurgedEntry {
            hash,
            hash_prefix,
            expires_at_nanos: now_nanos + gossip::FAILED_INSERT_EXPIRE_DURATION_NANOS,
        });
    }

    fn expire_list(&mut self, now_nanos: i64, duration_nanos: i64, is_staked: bool) -> usize {
        let cutoff = now_nanos.saturating_sub(duration_nanos);

        // Phase 1: Collect indices to expire (avoids borrow conflict).
        let mut to_expire = Vec::new();
        {
            let list = if is_staked {
                &mut self.staked_expire
            } else {
                &mut self.unstaked_expire
            };

            while let Some(&front_idx) = list.front() {
                match self.entries.get(front_idx).and_then(|e| e.as_ref()) {
                    Some(entry) => {
                        if entry.received_at_nanos <= cutoff {
                            list.pop_front();
                            to_expire.push(front_idx);
                        } else {
                            break;
                        }
                    }
                    None => {
                        // Entry was already removed, clean up the stale reference.
                        list.pop_front();
                    }
                }
            }
        }

        // Phase 2: Purge and remove collected entries.
        let expired = to_expire.len();
        for idx in to_expire {
            self.purge_entry_hash(idx, now_nanos);
            self.remove_entry(idx);
        }

        expired
    }

    fn count_entries_in_range(&self, mask: &PullRequestMask) -> usize {
        let mut count = 0;
        for (&prefix, indices) in self.hash_index.range(mask.range_start()..=mask.range_end()) {
            if mask.matches(prefix) {
                count += indices.len();
            }
        }
        count
    }

    fn count_purged_in_range(&self, mask: &PullRequestMask) -> usize {
        let mut count = 0;
        for entry in &self.purged {
            if mask.matches(entry.hash_prefix) {
                count += 1;
            }
        }
        for entry in &self.failed_inserts {
            if mask.matches(entry.hash_prefix) {
                count += 1;
            }
        }
        count
    }
}

impl Default for CrdsTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gossip::crds::value::{
        CrdsContactInfo, CrdsValueData, NodeInstanceToken, VersionInfo, VoteGossip,
    };

    fn make_contact_value(origin: [u8; 32], wallclock: i64) -> CrdsValue {
        CrdsValue {
            origin,
            wallclock_nanos: wallclock,
            signature: [0u8; 64],
            data: CrdsValueData::ContactInfo(CrdsContactInfo {
                pubkey: origin,
                shred_version: 1,
                instance_creation_nanos: 1000,
                wallclock_nanos: wallclock,
                sockets: Default::default(),
                version: VersionInfo::default(),
            }),
        }
    }

    fn make_vote_value(origin: [u8; 32], index: u8, wallclock: i64) -> CrdsValue {
        CrdsValue {
            origin,
            wallclock_nanos: wallclock,
            signature: [0u8; 64],
            data: CrdsValueData::Vote(VoteGossip {
                index,
                slot: 100,
                hash: [0u8; 32],
                transaction_bytes: vec![1, 2, 3],
            }),
        }
    }

    fn make_node_instance_value(origin: [u8; 32], token: u64, wallclock: i64) -> CrdsValue {
        CrdsValue {
            origin,
            wallclock_nanos: wallclock,
            signature: [0u8; 64],
            data: CrdsValueData::NodeInstance(NodeInstanceToken { token }),
        }
    }

    #[test]
    fn test_table_insert_new() {
        let mut table = CrdsTable::new();
        let origin = [1u8; 32];
        let value = make_contact_value(origin, 1000);

        let result = table.insert(value, 500, 2000, EntryOrigin::Push);
        assert_eq!(result, InsertOutcome::Inserted);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_table_insert_update_newer() {
        let mut table = CrdsTable::new();
        let origin = [1u8; 32];

        let v1 = make_contact_value(origin, 1000);
        table.insert(v1, 500, 2000, EntryOrigin::Push);

        let v2 = make_contact_value(origin, 2000);
        let result = table.insert(v2, 500, 3000, EntryOrigin::Push);
        assert_eq!(result, InsertOutcome::Updated);
        assert_eq!(table.len(), 1);

        // Verify the new value is stored
        let key = CrdsKey::new(gossip::VALUE_TYPE_CONTACT_INFO, origin);
        let entry = table.get(&key).unwrap();
        assert_eq!(entry.value.wallclock_nanos, 2000);
    }

    #[test]
    fn test_table_insert_stale_rejected() {
        let mut table = CrdsTable::new();
        let origin = [1u8; 32];

        let v1 = make_contact_value(origin, 2000);
        table.insert(v1, 500, 3000, EntryOrigin::Push);

        let v2 = make_contact_value(origin, 1000);
        let result = table.insert(v2, 500, 4000, EntryOrigin::Push);
        assert_eq!(result, InsertOutcome::Stale);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_table_insert_duplicate() {
        let mut table = CrdsTable::new();
        let origin = [1u8; 32];

        let v1 = make_contact_value(origin, 1000);
        table.insert(v1.clone(), 500, 2000, EntryOrigin::Push);

        let result = table.insert(v1, 500, 3000, EntryOrigin::Push);
        assert_eq!(result, InsertOutcome::Duplicate);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_table_multiple_value_types() {
        let mut table = CrdsTable::new();
        let origin = [1u8; 32];

        let ci = make_contact_value(origin, 1000);
        let vote0 = make_vote_value(origin, 0, 1000);
        let vote1 = make_vote_value(origin, 1, 1000);
        let ni = make_node_instance_value(origin, 42, 1000);

        assert_eq!(
            table.insert(ci, 500, 2000, EntryOrigin::Push),
            InsertOutcome::Inserted
        );
        assert_eq!(
            table.insert(vote0, 500, 2000, EntryOrigin::Push),
            InsertOutcome::Inserted
        );
        assert_eq!(
            table.insert(vote1, 500, 2000, EntryOrigin::Push),
            InsertOutcome::Inserted
        );
        assert_eq!(
            table.insert(ni, 500, 2000, EntryOrigin::Push),
            InsertOutcome::Inserted
        );
        assert_eq!(table.len(), 4);
    }

    #[test]
    fn test_table_entries_by_type() {
        let mut table = CrdsTable::new();

        for i in 0u8..5 {
            let origin = [i + 1; 32];
            table.insert(
                make_contact_value(origin, 1000),
                100,
                2000,
                EntryOrigin::Push,
            );
            table.insert(
                make_vote_value(origin, 0, 1000),
                100,
                2000,
                EntryOrigin::Push,
            );
        }

        let contacts = table.entries_by_type(gossip::VALUE_TYPE_CONTACT_INFO);
        assert_eq!(contacts.len(), 5);

        let votes = table.entries_by_type(gossip::VALUE_TYPE_VOTE);
        assert_eq!(votes.len(), 5);
    }

    #[test]
    fn test_table_eviction_by_stake() {
        let mut table = CrdsTable::with_limits(3, 100);

        // Insert 3 entries with different stakes
        let v1 = make_contact_value([1u8; 32], 1000);
        let v2 = make_contact_value([2u8; 32], 1000);
        let v3 = make_contact_value([3u8; 32], 1000);

        table.insert(v1, 100, 2000, EntryOrigin::Push);
        table.insert(v2, 200, 2000, EntryOrigin::Push);
        table.insert(v3, 300, 2000, EntryOrigin::Push);
        assert_eq!(table.len(), 3);

        // Insert a 4th with higher stake — should evict the lowest (stake=100)
        let v4 = make_contact_value([4u8; 32], 1000);
        let result = table.insert(v4, 400, 3000, EntryOrigin::Push);
        assert_eq!(result, InsertOutcome::Inserted);
        assert_eq!(table.len(), 3);

        // Verify [1u8; 32] (stake=100) was evicted
        let key1 = CrdsKey::new(gossip::VALUE_TYPE_CONTACT_INFO, [1u8; 32]);
        assert!(table.get(&key1).is_none());

        // Verify others still present
        let key2 = CrdsKey::new(gossip::VALUE_TYPE_CONTACT_INFO, [2u8; 32]);
        let key4 = CrdsKey::new(gossip::VALUE_TYPE_CONTACT_INFO, [4u8; 32]);
        assert!(table.get(&key2).is_some());
        assert!(table.get(&key4).is_some());
    }

    #[test]
    fn test_table_eviction_fails_for_low_stake() {
        let mut table = CrdsTable::with_limits(2, 100);

        let v1 = make_contact_value([1u8; 32], 1000);
        let v2 = make_contact_value([2u8; 32], 1000);
        table.insert(v1, 500, 2000, EntryOrigin::Push);
        table.insert(v2, 500, 2000, EntryOrigin::Push);

        // Try to insert with stake=0 — should fail eviction
        let v3 = make_contact_value([3u8; 32], 1000);
        let result = table.insert(v3, 0, 3000, EntryOrigin::Push);
        assert_eq!(result, InsertOutcome::EvictionFailed);
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn test_table_expiration_unstaked() {
        let mut table = CrdsTable::new();
        let origin = [1u8; 32];

        // Insert unstaked entry at t=1000
        let v = make_contact_value(origin, 500);
        table.insert(v, 0, 1000, EntryOrigin::Push);

        // Mark that we've seen a staked node (so unstaked expire at 15s)
        let staked_v = make_contact_value([2u8; 32], 500);
        table.insert(staked_v, 100, 1000, EntryOrigin::Push);

        assert_eq!(table.len(), 2);

        // Advance past unstaked expiry (15s = 15_000_000_000 nanos)
        let expired = table.advance(1000 + gossip::UNSTAKED_EXPIRE_DURATION_NANOS + 1);
        assert_eq!(expired, 1); // Only the unstaked entry should expire

        // Unstaked entry gone
        let key = CrdsKey::new(gossip::VALUE_TYPE_CONTACT_INFO, origin);
        assert!(table.get(&key).is_none());

        // Staked entry still present
        let key2 = CrdsKey::new(gossip::VALUE_TYPE_CONTACT_INFO, [2u8; 32]);
        assert!(table.get(&key2).is_some());
    }

    #[test]
    fn test_table_purged_tracking() {
        let mut table = CrdsTable::new();
        let origin = [1u8; 32];

        let v1 = make_contact_value(origin, 1000);
        table.insert(v1, 500, 2000, EntryOrigin::Push);

        // Update with newer value — old hash should be purged
        let v2 = make_contact_value(origin, 2000);
        table.insert(v2, 500, 3000, EntryOrigin::Push);

        assert!(table.purged_len() > 0);
    }

    #[test]
    fn test_table_purged_expiration() {
        let mut table = CrdsTable::new();
        let origin = [1u8; 32];

        let v1 = make_contact_value(origin, 1000);
        table.insert(v1, 500, 2000, EntryOrigin::Push);

        let v2 = make_contact_value(origin, 2000);
        table.insert(v2, 500, 3000, EntryOrigin::Push);

        let purged_before = table.purged_len();
        assert!(purged_before > 0);

        // Advance past purged expiry (60s)
        table.advance(3000 + gossip::PURGED_EXPIRE_DURATION_NANOS + 1);
        assert_eq!(table.purged.len(), 0);
    }

    #[test]
    fn test_table_bloom_filter_pull() {
        let mut table = CrdsTable::new();

        // Insert some entries
        for i in 0u8..10 {
            let origin = [i + 1; 32];
            table.insert(
                make_contact_value(origin, 1000),
                100,
                2000,
                EntryOrigin::Push,
            );
        }

        // Build a bloom filter with full mask (no partitioning)
        let mask = PullRequestMask::full();
        let filter = table.build_pull_filter(&mask);

        // All entries should be in the filter
        for &idx in table.lookup.values() {
            if let Some(entry) = &table.entries[idx] {
                assert!(filter.contains(&entry.value_hash));
            }
        }
    }

    #[test]
    fn test_table_pull_response_filter() {
        let mut table = CrdsTable::new();

        for i in 0u8..5 {
            let origin = [i + 1; 32];
            table.insert(
                make_contact_value(origin, 1000),
                100,
                2000,
                EntryOrigin::Push,
            );
        }

        // Build a bloom filter that contains some entries
        let mask = PullRequestMask::full();
        let mut partial_filter = GossipBloomFilter::new(10);

        // Only add first 3 entries to the filter
        let keys: Vec<CrdsKey> = table.lookup.keys().cloned().collect();
        for (i, key) in keys.iter().enumerate() {
            if i < 3 {
                if let Some(entry) = table.get(key) {
                    partial_filter.insert(&entry.value_hash);
                }
            }
        }

        // Pull response should return entries NOT in the filter
        let response = table.filter_for_pull_response(&partial_filter, &mask, 100);
        // Should be at least 2 entries (the 2 not in the filter)
        assert!(response.len() >= 2, "got {} entries", response.len());
    }

    #[test]
    fn test_table_metrics() {
        let mut table = CrdsTable::new();

        for i in 0u8..3 {
            let origin = [i + 1; 32];
            let stake = if i < 2 { 100 } else { 0 };
            table.insert(
                make_contact_value(origin, 1000),
                stake,
                2000,
                EntryOrigin::Push,
            );
        }

        table.update_metrics();
        assert_eq!(
            table.metrics.entry_counts[gossip::VALUE_TYPE_CONTACT_INFO as usize],
            3
        );
        assert_eq!(table.metrics.staked_peer_count, 2);
        assert_eq!(table.metrics.unstaked_peer_count, 1);
    }

    #[test]
    fn test_table_contact_info_fast_override() {
        let mut table = CrdsTable::new();
        let origin = [1u8; 32];

        // Insert with instance_creation=1000
        let mut v1 = make_contact_value(origin, 1000);
        if let CrdsValueData::ContactInfo(ref mut ci) = v1.data {
            ci.instance_creation_nanos = 1000;
        }
        table.insert(v1, 500, 2000, EntryOrigin::Push);

        // Update with newer instance_creation=2000 (should override even with same wallclock)
        let mut v2 = make_contact_value(origin, 1000); // same wallclock
        if let CrdsValueData::ContactInfo(ref mut ci) = v2.data {
            ci.instance_creation_nanos = 2000;
        }
        let result = table.insert(v2, 500, 3000, EntryOrigin::Push);
        assert_eq!(result, InsertOutcome::Updated);
    }

    #[test]
    fn test_table_node_instance_token_override() {
        let mut table = CrdsTable::new();
        let origin = [1u8; 32];

        let v1 = make_node_instance_value(origin, 100, 1000);
        table.insert(v1, 500, 2000, EntryOrigin::Push);

        // Newer token should override (even with same wallclock)
        let v2 = make_node_instance_value(origin, 200, 1000);
        let result = table.insert(v2, 500, 3000, EntryOrigin::Push);
        assert_eq!(result, InsertOutcome::Updated);

        // Older token should be rejected
        let v3 = make_node_instance_value(origin, 50, 1000);
        let result = table.insert(v3, 500, 4000, EntryOrigin::Push);
        assert_eq!(result, InsertOutcome::Stale);
    }

    #[test]
    fn test_table_failed_insert_tracking() {
        let mut table = CrdsTable::new();
        let origin = [1u8; 32];

        let v1 = make_contact_value(origin, 2000);
        table.insert(v1, 500, 3000, EntryOrigin::Push);

        // Insert stale value — should be tracked as failed insert
        let v2 = make_contact_value(origin, 1000);
        let result = table.insert(v2, 500, 4000, EntryOrigin::Push);
        assert_eq!(result, InsertOutcome::Stale);
        assert!(!table.failed_inserts.is_empty());

        // Expire failed inserts
        table.advance(4000 + gossip::FAILED_INSERT_EXPIRE_DURATION_NANOS + 1);
        assert_eq!(table.failed_inserts.len(), 0);
    }
}
