/// Cache for validated sBPF programs.
///
/// Stores parsed and validated programs to avoid repeated ELF loading
/// and validation on every execution. Supports LRU-based eviction
/// when the cache reaches capacity.
use crate::elf_loader::{ElfError, LoadedProgram, SbpfVersion};
use karstflow_constants::program_cache::{
    DEFAULT_MAX_CACHE_ENTRIES, DELAY_VISIBILITY_SLOT_OFFSET, EVICTION_THRESHOLD_PERCENT,
    MAX_PROGRAM_SIZE,
};
use karstflow_types::Pubkey;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Cached program entry
// ---------------------------------------------------------------------------

/// A single cached program with usage tracking metadata.
#[derive(Debug, Clone)]
pub struct CachedProgram {
    /// The parsed and validated program.
    pub program: LoadedProgram,
    /// Slot at which this program was last accessed.
    pub last_used_slot: u64,
    /// Total number of times this entry has been accessed.
    pub use_count: u64,
    /// Size of the original ELF binary (bytes).
    pub elf_size: usize,
    /// Earliest slot at which this program is visible for execution.
    ///
    /// Programs deployed at slot N have `effective_slot = N + DELAY_VISIBILITY_SLOT_OFFSET`.
    /// Programs loaded from pre-existing accounts use `effective_slot = 0` (always visible).
    pub effective_slot: u64,
}

// ---------------------------------------------------------------------------
// Cache errors
// ---------------------------------------------------------------------------

/// Errors that can occur during cache operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheError {
    /// ELF binary exceeds the maximum allowed program size.
    ProgramTooLarge { size: usize, max: usize },
    /// ELF loading failed.
    LoadError(String),
    /// Program exists but is not yet visible at the requested slot.
    NotYetVisible { effective_slot: u64 },
}

impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProgramTooLarge { size, max } => {
                write!(f, "program size {} exceeds maximum {}", size, max)
            }
            Self::LoadError(msg) => write!(f, "failed to load program: {}", msg),
            Self::NotYetVisible { effective_slot } => {
                write!(f, "program not visible until slot {}", effective_slot)
            }
        }
    }
}

impl std::error::Error for CacheError {}

impl From<ElfError> for CacheError {
    fn from(e: ElfError) -> Self {
        Self::LoadError(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Program cache
// ---------------------------------------------------------------------------

/// LRU cache for loaded sBPF programs.
///
/// Programs are keyed by their account public key. When the cache
/// exceeds the eviction threshold, the least-recently-used entries
/// are removed until the cache is back within budget.
pub struct ProgramCache {
    entries: HashMap<Pubkey, CachedProgram>,
    max_entries: usize,
}

impl ProgramCache {
    /// Create a new cache with the default capacity.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            max_entries: DEFAULT_MAX_CACHE_ENTRIES,
        }
    }

    /// Create a new cache with a custom maximum entry count.
    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries: max_entries.max(1),
        }
    }

    /// Number of programs currently in the cache.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look up a cached program, updating its usage stats.
    ///
    /// Returns `None` if the program is not cached or not yet visible
    /// at the given slot (deployment visibility delay).
    pub fn get(&mut self, program_id: &Pubkey, slot: u64) -> Option<&LoadedProgram> {
        let entry = self.entries.get_mut(program_id)?;
        if slot < entry.effective_slot {
            return None;
        }
        entry.last_used_slot = slot;
        entry.use_count += 1;
        Some(&entry.program)
    }

    /// Insert a pre-loaded program into the cache.
    ///
    /// `effective_slot` controls when the program becomes visible for execution.
    /// Use `0` for pre-existing programs (always visible) or
    /// `deployment_slot + DELAY_VISIBILITY_SLOT_OFFSET` for newly deployed programs.
    ///
    /// Evicts stale entries if the cache is at or above the eviction
    /// threshold before inserting.
    pub fn insert(
        &mut self,
        program_id: Pubkey,
        program: LoadedProgram,
        elf_size: usize,
        slot: u64,
        effective_slot: u64,
    ) {
        self.evict_if_needed();

        self.entries.insert(
            program_id,
            CachedProgram {
                program,
                last_used_slot: slot,
                use_count: 1,
                elf_size,
                effective_slot,
            },
        );
    }

    /// Load an ELF binary, cache it, and return a reference.
    ///
    /// If the program is already cached and visible at the given slot,
    /// returns the cached version (updating usage stats). Otherwise
    /// parses the ELF, caches the result, and returns it.
    ///
    /// `effective_slot` controls visibility delay for newly deployed programs.
    /// Use `0` for pre-existing programs (always visible).
    pub fn get_or_load(
        &mut self,
        program_id: &Pubkey,
        elf_bytes: &[u8],
        slot: u64,
        effective_slot: u64,
    ) -> Result<&LoadedProgram, CacheError> {
        // Fast path: already cached and visible
        if let Some(entry) = self.entries.get_mut(program_id) {
            if slot < entry.effective_slot {
                return Err(CacheError::NotYetVisible {
                    effective_slot: entry.effective_slot,
                });
            }
            entry.last_used_slot = slot;
            entry.use_count += 1;
            return Ok(&self.entries[program_id].program);
        }

        // Size guard
        if elf_bytes.len() > MAX_PROGRAM_SIZE {
            return Err(CacheError::ProgramTooLarge {
                size: elf_bytes.len(),
                max: MAX_PROGRAM_SIZE,
            });
        }

        // Load and cache
        let program = crate::elf_loader::load_elf(elf_bytes)?;
        let elf_size = elf_bytes.len();

        self.evict_if_needed();

        self.entries.insert(
            *program_id,
            CachedProgram {
                program,
                last_used_slot: slot,
                use_count: 1,
                elf_size,
                effective_slot,
            },
        );

        Ok(&self.entries[program_id].program)
    }

    /// Remove a specific program from the cache.
    ///
    /// Used when a program is upgraded or closed.
    pub fn invalidate(&mut self, program_id: &Pubkey) -> bool {
        self.entries.remove(program_id).is_some()
    }

    /// Remove all entries from the cache.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Check if a program is present in the cache.
    pub fn contains(&self, program_id: &Pubkey) -> bool {
        self.entries.contains_key(program_id)
    }

    /// Evict least-recently-used entries when above the threshold.
    fn evict_if_needed(&mut self) {
        let threshold = self.max_entries * EVICTION_THRESHOLD_PERCENT / 100;

        if self.entries.len() < threshold {
            return;
        }

        // Collect entries sorted by last_used_slot (oldest first)
        let mut by_age: Vec<(Pubkey, u64)> = self
            .entries
            .iter()
            .map(|(k, v)| (*k, v.last_used_slot))
            .collect();

        by_age.sort_unstable_by_key(|&(_, slot)| slot);

        // Remove oldest entries until we're below 75% of max
        let target = self.max_entries * 3 / 4;
        let to_remove = self.entries.len().saturating_sub(target);

        for (key, _) in by_age.iter().take(to_remove) {
            self.entries.remove(key);
        }
    }
}

impl Default for ProgramCache {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ProgramCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProgramCache")
            .field("entries", &self.entries.len())
            .field("max_entries", &self.max_entries)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_program() -> LoadedProgram {
        use crate::instruction::{Instruction, Opcode};
        LoadedProgram {
            instructions: vec![
                Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 0),
                Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
            ],
            rodata: Vec::new(),
            entry_point: 0,
            call_targets: HashMap::new(),
            sbpf_version: SbpfVersion::V0,
            text_bytes: Vec::new(),
        }
    }

    #[test]
    fn insert_and_get() {
        let mut cache = ProgramCache::new();
        let id = Pubkey::new_unique();
        let program = dummy_program();

        cache.insert(id, program.clone(), 100, 42, 0);
        assert_eq!(cache.len(), 1);
        assert!(cache.contains(&id));

        let retrieved = cache.get(&id, 50).unwrap();
        assert_eq!(retrieved.entry_point, program.entry_point);
        assert_eq!(retrieved.instructions.len(), program.instructions.len());
    }

    #[test]
    fn get_missing_returns_none() {
        let mut cache = ProgramCache::new();
        let id = Pubkey::new_unique();
        assert!(cache.get(&id, 0).is_none());
    }

    #[test]
    fn invalidate_removes_entry() {
        let mut cache = ProgramCache::new();
        let id = Pubkey::new_unique();

        cache.insert(id, dummy_program(), 100, 0, 0);
        assert!(cache.contains(&id));

        assert!(cache.invalidate(&id));
        assert!(!cache.contains(&id));
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn invalidate_missing_returns_false() {
        let mut cache = ProgramCache::new();
        assert!(!cache.invalidate(&Pubkey::new_unique()));
    }

    #[test]
    fn clear_empties_cache() {
        let mut cache = ProgramCache::new();
        for _ in 0..5 {
            cache.insert(Pubkey::new_unique(), dummy_program(), 100, 0, 0);
        }
        assert_eq!(cache.len(), 5);

        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn eviction_removes_oldest_entries() {
        // Small cache: max 10 entries, threshold at 90% = 9
        let mut cache = ProgramCache::with_capacity(10);

        // Fill to threshold (insert 9 entries at increasing slots)
        let mut keys = Vec::new();
        for i in 0..9 {
            let id = Pubkey::new_unique();
            cache.insert(id, dummy_program(), 100, i as u64, 0);
            keys.push(id);
        }
        assert_eq!(cache.len(), 9);

        // Insert one more — should trigger eviction
        // Eviction target: 75% of 10 = 7, so remove 9 - 7 = 2 oldest
        let new_id = Pubkey::new_unique();
        cache.insert(new_id, dummy_program(), 100, 100, 0);

        // Should have evicted the 2 oldest entries (slot 0 and slot 1)
        assert!(cache.len() <= 8);
        assert!(!cache.contains(&keys[0]));
        assert!(!cache.contains(&keys[1]));
        // Newer entries remain
        assert!(cache.contains(&keys[8]));
        assert!(cache.contains(&new_id));
    }

    #[test]
    fn use_count_increments_on_access() {
        let mut cache = ProgramCache::new();
        let id = Pubkey::new_unique();

        cache.insert(id, dummy_program(), 100, 0, 0);

        // Access multiple times
        cache.get(&id, 1);
        cache.get(&id, 2);
        cache.get(&id, 3);

        let entry = cache.entries.get(&id).unwrap();
        assert_eq!(entry.use_count, 4); // 1 initial + 3 gets
        assert_eq!(entry.last_used_slot, 3);
    }

    #[test]
    fn program_too_large_rejected() {
        let mut cache = ProgramCache::new();
        let id = Pubkey::new_unique();
        let oversized = vec![0u8; MAX_PROGRAM_SIZE + 1];

        let result = cache.get_or_load(&id, &oversized, 0, 0);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CacheError::ProgramTooLarge { .. }
        ));
    }

    #[test]
    fn delay_visibility_hides_program_until_effective_slot() {
        let mut cache = ProgramCache::new();
        let id = Pubkey::new_unique();

        // Program deployed at slot 10 → effective at slot 11
        let effective = 10 + DELAY_VISIBILITY_SLOT_OFFSET;
        cache.insert(id, dummy_program(), 100, 10, effective);

        // Not visible at deployment slot
        assert!(cache.get(&id, 10).is_none());

        // Visible at effective slot
        assert!(cache.get(&id, 11).is_some());

        // Visible at later slots
        assert!(cache.get(&id, 100).is_some());
    }

    #[test]
    fn zero_effective_slot_always_visible() {
        let mut cache = ProgramCache::new();
        let id = Pubkey::new_unique();

        // Pre-existing program: effective_slot = 0
        cache.insert(id, dummy_program(), 100, 0, 0);

        assert!(cache.get(&id, 0).is_some());
        assert!(cache.get(&id, 1).is_some());
    }

    #[test]
    fn get_or_load_respects_effective_slot() {
        let mut cache = ProgramCache::new();
        let id = Pubkey::new_unique();

        // Insert with delayed visibility
        cache.insert(id, dummy_program(), 100, 5, 6);

        // Query at slot 5 should fail (not yet visible)
        let result = cache.get_or_load(&id, &[], 5, 6);
        assert!(matches!(result, Err(CacheError::NotYetVisible { .. })));

        // Query at slot 6 should succeed
        assert!(cache.get(&id, 6).is_some());
    }
}
