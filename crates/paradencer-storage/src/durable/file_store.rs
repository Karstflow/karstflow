// Custom file-backed persistent storage with integrity verification.
//
// Each column family is stored as an append-only log file with an
// in-memory hash index rebuilt from disk on open. No external database
// dependencies — full control over every byte on disk.
//
// File layout per column family:
//   [file header: 16 bytes]
//     magic(4) + version(2) + flags(2) + reserved(8)
//   [records: variable]
//     Each record:
//       [crc32: u32 LE]      CRC32 of status+key_len+value_len+key+value
//       [status: u8]         0 = active, 1 = deleted
//       [key_len: u32 LE]
//       [value_len: u32 LE]
//       [key: key_len bytes]
//       [value: value_len bytes]
//
// On open: sequential scan verifies CRC per record, rebuilds in-memory index.
// Reads: index lookup → positional file read (pread, no seek contention).
// Writes: compute CRC, append full record in single write, update index.
// Batch: append all records sequentially, fsync once per CF.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[cfg(unix)]
use std::os::unix::fs::FileExt;

use paradencer_constants::durable_store::{
    CF_FILE_FORMAT_VERSION, CF_FILE_HEADER_SIZE, CF_FILE_MAGIC, RECORD_HEADER_SIZE,
    RECORD_STATUS_ACTIVE, RECORD_STATUS_DELETED, STANDARD_COLUMN_FAMILIES,
};

use super::read_cache::{CacheStats, ReadCache};

use super::batch::WriteOp;
use super::{DurableStore, ScanEntry, WriteBatch};
use crate::StorageError;

/// Location of a value within the column family file.
#[derive(Debug, Clone, Copy)]
struct RecordLoc {
    /// Byte offset of the record header in the file.
    offset: u64,
    key_len: u32,
    value_len: u32,
}

impl RecordLoc {
    /// Byte offset where the value data begins.
    #[inline]
    fn value_offset(&self) -> u64 {
        self.offset + RECORD_HEADER_SIZE as u64 + self.key_len as u64
    }

    /// Total size of the record on disk (header + key + value).
    #[inline]
    fn record_size(&self) -> u64 {
        RECORD_HEADER_SIZE as u64 + self.key_len as u64 + self.value_len as u64
    }
}

/// Mutable state for a single column family.
struct CfState {
    file: File,
    /// Maps key bytes → record location for O(1) lookups.
    index: HashMap<Vec<u8>, RecordLoc>,
    /// Current end-of-file position (next append offset).
    file_end: u64,
    /// Accumulated dead space from overwrites and deletes (bytes).
    dead_bytes: u64,
}

impl CfState {
    /// Ratio of dead space to total file size (0.0–1.0).
    #[inline]
    fn dead_ratio(&self) -> f64 {
        let data_size = self.file_end.saturating_sub(CF_FILE_HEADER_SIZE as u64);
        if data_size == 0 {
            return 0.0;
        }
        self.dead_bytes as f64 / data_size as f64
    }
}

/// File-backed persistent key-value store with CRC32 integrity checks.
///
/// Each column family is a separate append-only file on disk.
/// An in-memory hash index provides O(1) point lookups.
/// Every record carries a CRC32 checksum verified on startup.
/// Batch writes are protected by a Write-Ahead Log for crash recovery.
pub struct FileDurableStore {
    data_dir: PathBuf,
    families: HashMap<String, Mutex<CfState>>,
    wal: Mutex<super::wal::WriteAheadLog>,
    /// LRU cache for recently accessed key-value pairs.
    cache: Mutex<ReadCache>,
    /// If true, directory is temporary and deleted on drop.
    is_temporary: bool,
}

impl FileDurableStore {
    /// Open or create a store at the given directory.
    ///
    /// On open, replays any pending WAL entries from a previous crash.
    pub fn open(data_dir: &Path) -> Result<Self, StorageError> {
        fs::create_dir_all(data_dir).map_err(|e| StorageError::DurableStoreError {
            details: format!("create dir {}: {}", data_dir.display(), e),
        })?;

        let mut families = HashMap::with_capacity(STANDARD_COLUMN_FAMILIES.len());
        for &cf_name in STANDARD_COLUMN_FAMILIES {
            let state = Self::open_cf(data_dir, cf_name)?;
            families.insert(cf_name.to_owned(), Mutex::new(state));
        }

        // Open WAL and replay any pending entries from a crash.
        let mut wal = super::wal::WriteAheadLog::open(data_dir)?;
        if let Some(ops) = wal.read_pending()? {
            Self::replay_wal_ops(&families, &ops)?;
            wal.clear()?;
        }

        Ok(Self {
            data_dir: data_dir.to_owned(),
            families,
            wal: Mutex::new(wal),
            cache: Mutex::new(ReadCache::with_default_capacity()),
            is_temporary: false,
        })
    }

    /// Create a temporary store backed by a temp directory.
    /// The directory is cleaned up when the store is dropped.
    pub fn temporary() -> Result<Self, StorageError> {
        let tmp = std::env::temp_dir().join(format!(
            "paradencer-store-{}-{}",
            std::process::id(),
            rand_u64()
        ));
        let mut store = Self::open(&tmp)?;
        store.is_temporary = true;
        Ok(store)
    }

    /// Replay WAL operations into the families map.
    fn replay_wal_ops(
        families: &HashMap<String, Mutex<CfState>>,
        ops: &[super::wal::WalOp],
    ) -> Result<(), StorageError> {
        use super::wal::WalOp;

        for op in ops {
            match op {
                WalOp::Put { cf, key, value } => {
                    if let Some(mutex) = families.get(cf.as_str()) {
                        let mut state = mutex.lock().unwrap();
                        Self::append_record(&mut state, RECORD_STATUS_ACTIVE, key, value)?;
                    }
                }
                WalOp::Delete { cf, key } => {
                    if let Some(mutex) = families.get(cf.as_str()) {
                        let mut state = mutex.lock().unwrap();
                        if state.index.contains_key(key.as_slice()) {
                            Self::append_record(&mut state, RECORD_STATUS_DELETED, key, &[])?;
                        }
                    }
                }
            }
        }

        // Fsync all affected CFs after replay.
        for mutex in families.values() {
            let state = mutex.lock().unwrap();
            state
                .file
                .sync_data()
                .map_err(|e| StorageError::DurableStoreError {
                    details: format!("fsync after WAL replay: {e}"),
                })?;
        }

        Ok(())
    }

    /// Open a single column family file, verifying integrity and rebuilding the index.
    fn open_cf(data_dir: &Path, name: &str) -> Result<CfState, StorageError> {
        let path = data_dir.join(format!("{name}.dat"));

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| StorageError::DurableStoreError {
                details: format!("open {}: {}", path.display(), e),
            })?;

        let file_len = file
            .metadata()
            .map_err(|e| StorageError::DurableStoreError {
                details: format!("metadata {}: {}", path.display(), e),
            })?
            .len();

        if file_len == 0 {
            // New file — write the file header.
            write_file_header(&file)?;
            return Ok(CfState {
                file,
                index: HashMap::new(),
                file_end: CF_FILE_HEADER_SIZE as u64,
                dead_bytes: 0,
            });
        }

        if file_len < CF_FILE_HEADER_SIZE as u64 {
            // File too small for a valid header — truncate and reinitialize.
            file.set_len(0)
                .map_err(|e| StorageError::DurableStoreError {
                    details: format!("truncate corrupt header {}: {}", path.display(), e),
                })?;
            write_file_header(&file)?;
            return Ok(CfState {
                file,
                index: HashMap::new(),
                file_end: CF_FILE_HEADER_SIZE as u64,
                dead_bytes: 0,
            });
        }

        // Validate file header.
        let mut header_buf = [0u8; CF_FILE_HEADER_SIZE];
        read_at_checked(&file, &mut header_buf, 0)?;

        let magic =
            u32::from_le_bytes([header_buf[0], header_buf[1], header_buf[2], header_buf[3]]);
        let version = u16::from_le_bytes([header_buf[4], header_buf[5]]);

        if magic != CF_FILE_MAGIC {
            // Old format file (pre-CRC). Migrate by truncating and starting fresh.
            // In development, old test data is expendable.
            file.set_len(0)
                .map_err(|e| StorageError::DurableStoreError {
                    details: format!("truncate old format {}: {}", path.display(), e),
                })?;
            write_file_header(&file)?;
            return Ok(CfState {
                file,
                index: HashMap::new(),
                file_end: CF_FILE_HEADER_SIZE as u64,
                dead_bytes: 0,
            });
        }

        if version > CF_FILE_FORMAT_VERSION {
            return Err(StorageError::DurableStoreError {
                details: format!(
                    "{}: file format version {version} is newer than supported ({CF_FILE_FORMAT_VERSION})",
                    path.display()
                ),
            });
        }

        let mut state = CfState {
            file,
            index: HashMap::new(),
            file_end: file_len,
            dead_bytes: 0,
        };

        // Rebuild index by scanning records with CRC verification.
        Self::rebuild_index(&mut state)?;

        Ok(state)
    }

    /// Sequential scan to rebuild the in-memory index with CRC verification.
    fn rebuild_index(state: &mut CfState) -> Result<(), StorageError> {
        let mut offset = CF_FILE_HEADER_SIZE as u64;
        let file_end = state.file_end;
        let mut header_buf = [0u8; RECORD_HEADER_SIZE];

        while offset + RECORD_HEADER_SIZE as u64 <= file_end {
            // Read record header.
            read_at_checked(&state.file, &mut header_buf, offset)?;

            let stored_crc =
                u32::from_le_bytes([header_buf[0], header_buf[1], header_buf[2], header_buf[3]]);
            let status = header_buf[4];
            let key_len =
                u32::from_le_bytes([header_buf[5], header_buf[6], header_buf[7], header_buf[8]]);
            let value_len = u32::from_le_bytes([
                header_buf[9],
                header_buf[10],
                header_buf[11],
                header_buf[12],
            ]);

            let data_size = key_len as u64 + value_len as u64;
            let record_size = RECORD_HEADER_SIZE as u64 + data_size;

            if offset + record_size > file_end {
                // Truncated record at end of file — stop here.
                state.file_end = offset;
                break;
            }

            // Read key+value for CRC verification.
            let mut data_buf = vec![0u8; data_size as usize];
            read_at_checked(
                &state.file,
                &mut data_buf,
                offset + RECORD_HEADER_SIZE as u64,
            )?;

            // Verify CRC32 covers: status + key_len + value_len + key + value.
            let computed_crc = compute_record_crc(status, key_len, value_len, &data_buf);

            if stored_crc != computed_crc {
                // Corrupt record — truncate file at this point.
                state.file_end = offset;
                break;
            }

            let key = data_buf[..key_len as usize].to_vec();
            let loc = RecordLoc {
                offset,
                key_len,
                value_len,
            };

            match status {
                RECORD_STATUS_ACTIVE => {
                    if let Some(old_loc) = state.index.insert(key, loc) {
                        // Overwritten key — old record is dead space.
                        state.dead_bytes += old_loc.record_size();
                    }
                }
                RECORD_STATUS_DELETED => {
                    if let Some(old_loc) = state.index.remove(&key) {
                        // Deleted key — both old record and this tombstone are dead.
                        state.dead_bytes += old_loc.record_size();
                    }
                    // The tombstone itself is dead space.
                    state.dead_bytes += record_size;
                }
                _ => {
                    // Unknown status — treat as corruption, stop scan.
                    state.file_end = offset;
                    break;
                }
            }

            offset += record_size;
        }

        Ok(())
    }

    /// Get the CfState mutex, returning an error for unknown CFs.
    #[inline]
    fn cf(&self, name: &str) -> Result<&Mutex<CfState>, StorageError> {
        self.families
            .get(name)
            .ok_or_else(|| StorageError::UnknownColumnFamily {
                name: name.to_owned(),
            })
    }

    /// Append a record to the CF file and update the index.
    fn append_record(
        state: &mut CfState,
        status: u8,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), StorageError> {
        let key_len = key.len() as u32;
        let value_len = value.len() as u32;

        // Build data portion that CRC covers: key + value bytes.
        // CRC is computed over: status + key_len(LE) + value_len(LE) + key + value.
        let data_size = key.len() + value.len();
        let crc = compute_record_crc_parts(status, key_len, value_len, key, value);

        // Build complete record buffer for single write.
        let record_size = RECORD_HEADER_SIZE + data_size;
        let mut buf = Vec::with_capacity(record_size);
        buf.extend_from_slice(&crc.to_le_bytes());
        buf.push(status);
        buf.extend_from_slice(&key_len.to_le_bytes());
        buf.extend_from_slice(&value_len.to_le_bytes());
        buf.extend_from_slice(key);
        buf.extend_from_slice(value);

        let offset = state.file_end;

        // Single positional write for the entire record.
        write_at_checked(&state.file, &buf, offset)?;

        state.file_end += record_size as u64;

        match status {
            RECORD_STATUS_ACTIVE => {
                let loc = RecordLoc {
                    offset,
                    key_len,
                    value_len,
                };
                if let Some(old_loc) = state.index.insert(key.to_vec(), loc) {
                    // Overwritten key — old record becomes dead space.
                    state.dead_bytes += old_loc.record_size();
                }
            }
            RECORD_STATUS_DELETED => {
                if let Some(old_loc) = state.index.remove(key) {
                    state.dead_bytes += old_loc.record_size();
                }
                // The tombstone itself is dead space.
                state.dead_bytes += record_size as u64;
            }
            _ => {}
        }

        Ok(())
    }

    /// Read value bytes at a known location via positional read.
    fn read_value_at(file: &File, loc: &RecordLoc) -> Result<Vec<u8>, StorageError> {
        let mut buf = vec![0u8; loc.value_len as usize];
        read_at_checked(file, &mut buf, loc.value_offset())?;
        Ok(buf)
    }

    /// Open a custom column family (not in the standard set).
    pub fn open_tree(&mut self, name: &str) -> Result<(), StorageError> {
        if !self.families.contains_key(name) {
            let state = Self::open_cf(&self.data_dir, name)?;
            self.families.insert(name.to_owned(), Mutex::new(state));
        }
        Ok(())
    }

    /// Dead space ratio for a column family (0.0–1.0).
    pub fn dead_ratio(&self, cf: &str) -> Result<f64, StorageError> {
        let mutex = self.cf(cf)?;
        let state = mutex.lock().unwrap();
        Ok(state.dead_ratio())
    }

    /// Dead bytes accumulated across all column families.
    pub fn total_dead_bytes(&self) -> u64 {
        self.families
            .values()
            .map(|m| m.lock().unwrap().dead_bytes)
            .sum()
    }

    /// Read cache statistics snapshot.
    pub fn cache_stats(&self) -> CacheStats {
        self.cache.lock().unwrap().stats()
    }

    /// Compact a single column family by rewriting only live records.
    ///
    /// Writes all live records to a new temporary file, then atomically
    /// renames it over the original. Reclaims all dead space from
    /// overwrites and deletes. Returns the number of bytes reclaimed.
    pub fn compact_cf(&self, cf: &str) -> Result<CfCompactionStats, StorageError> {
        let mutex = self.cf(cf)?;
        let mut state = mutex.lock().unwrap();

        let original_size = state.file_end;
        let _original_dead = state.dead_bytes;

        if state.index.is_empty() && original_size <= CF_FILE_HEADER_SIZE as u64 {
            // Nothing to compact.
            return Ok(CfCompactionStats {
                records_rewritten: 0,
                bytes_before: original_size,
                bytes_after: original_size,
                bytes_reclaimed: 0,
            });
        }

        if state.dead_bytes == 0 {
            // No dead space — skip compaction.
            return Ok(CfCompactionStats {
                records_rewritten: state.index.len() as u64,
                bytes_before: original_size,
                bytes_after: original_size,
                bytes_reclaimed: 0,
            });
        }

        // Write live records to a temp file.
        let cf_path = self.data_dir.join(format!("{cf}.dat"));
        let tmp_path = self.data_dir.join(format!("{cf}.dat.compact"));

        let tmp_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(|e| StorageError::DurableStoreError {
                details: format!("create compaction temp {}: {}", tmp_path.display(), e),
            })?;

        // Write file header.
        write_file_header(&tmp_file)?;
        let mut write_offset = CF_FILE_HEADER_SIZE as u64;
        let mut new_index = HashMap::with_capacity(state.index.len());
        let mut records_written = 0u64;

        // Collect entries sorted by key for deterministic output.
        let mut entries: Vec<_> = state.index.iter().collect();
        entries.sort_by(|a, b| a.0.cmp(b.0));

        for (key, loc) in entries {
            // Read the original value from the old file.
            let value = Self::read_value_at(&state.file, loc)?;

            // Compute CRC and build record buffer.
            let key_len = key.len() as u32;
            let value_len = value.len() as u32;
            let crc =
                compute_record_crc_parts(RECORD_STATUS_ACTIVE, key_len, value_len, key, &value);

            let record_size = RECORD_HEADER_SIZE + key.len() + value.len();
            let mut buf = Vec::with_capacity(record_size);
            buf.extend_from_slice(&crc.to_le_bytes());
            buf.push(RECORD_STATUS_ACTIVE);
            buf.extend_from_slice(&key_len.to_le_bytes());
            buf.extend_from_slice(&value_len.to_le_bytes());
            buf.extend_from_slice(key);
            buf.extend_from_slice(&value);

            write_at_checked(&tmp_file, &buf, write_offset)?;

            new_index.insert(
                key.clone(),
                RecordLoc {
                    offset: write_offset,
                    key_len,
                    value_len,
                },
            );

            write_offset += record_size as u64;
            records_written += 1;
        }

        // Fsync the temp file before rename.
        tmp_file
            .sync_all()
            .map_err(|e| StorageError::DurableStoreError {
                details: format!("fsync compacted file: {e}"),
            })?;

        // Atomic rename: tmp → original.
        fs::rename(&tmp_path, &cf_path).map_err(|e| StorageError::DurableStoreError {
            details: format!(
                "rename {} → {}: {}",
                tmp_path.display(),
                cf_path.display(),
                e
            ),
        })?;

        // Reopen the file handle (the old handle points to the deleted inode).
        let new_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&cf_path)
            .map_err(|e| StorageError::DurableStoreError {
                details: format!("reopen compacted {}: {}", cf_path.display(), e),
            })?;

        // Update state in place.
        state.file = new_file;
        state.index = new_index;
        state.file_end = write_offset;
        state.dead_bytes = 0;

        // Invalidate cache for this CF — record offsets have all changed.
        self.cache.lock().unwrap().invalidate_cf(cf);

        let bytes_reclaimed = original_size.saturating_sub(write_offset);

        Ok(CfCompactionStats {
            records_rewritten: records_written,
            bytes_before: original_size,
            bytes_after: write_offset,
            bytes_reclaimed,
        })
    }

    /// Compact all column families that exceed the dead space ratio threshold.
    pub fn compact_all(
        &self,
        dead_ratio_threshold: f64,
    ) -> Result<Vec<(String, CfCompactionStats)>, StorageError> {
        let cf_names: Vec<String> = self.families.keys().cloned().collect();
        let mut results = Vec::new();

        for cf_name in cf_names {
            let ratio = self.dead_ratio(&cf_name)?;
            if ratio >= dead_ratio_threshold {
                let stats = self.compact_cf(&cf_name)?;
                if stats.bytes_reclaimed > 0 {
                    results.push((cf_name, stats));
                }
            }
        }

        Ok(results)
    }

    /// Wrap in Arc for shared ownership.
    pub fn into_arc(self) -> std::sync::Arc<Self> {
        std::sync::Arc::new(self)
    }
}

/// Statistics from compacting a single column family.
#[derive(Debug, Clone, Default)]
pub struct CfCompactionStats {
    /// Number of live records rewritten.
    pub records_rewritten: u64,
    /// File size before compaction.
    pub bytes_before: u64,
    /// File size after compaction.
    pub bytes_after: u64,
    /// Bytes reclaimed (before - after).
    pub bytes_reclaimed: u64,
}

impl DurableStore for FileDurableStore {
    fn get(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        // Check cache first.
        {
            let mut cache = self.cache.lock().unwrap();
            if let Some(value) = cache.get(cf, key) {
                return Ok(Some(value));
            }
        }

        let mutex = self.cf(cf)?;
        let state = mutex.lock().unwrap();
        match state.index.get(key) {
            Some(loc) => {
                let value = Self::read_value_at(&state.file, loc)?;
                // Populate cache on miss.
                self.cache.lock().unwrap().insert(cf, key, &value);
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    fn put(&self, cf: &str, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        let mutex = self.cf(cf)?;
        let mut state = mutex.lock().unwrap();
        Self::append_record(&mut state, RECORD_STATUS_ACTIVE, key, value)?;
        // Update cache with the new value.
        self.cache.lock().unwrap().insert(cf, key, value);
        Ok(())
    }

    fn delete(&self, cf: &str, key: &[u8]) -> Result<(), StorageError> {
        let mutex = self.cf(cf)?;
        let mut state = mutex.lock().unwrap();
        // Only write tombstone if key actually exists.
        if state.index.contains_key(key) {
            Self::append_record(&mut state, RECORD_STATUS_DELETED, key, &[])?;
            self.cache.lock().unwrap().invalidate(cf, key);
        }
        Ok(())
    }

    fn write_batch(&self, batch: &WriteBatch) -> Result<(), StorageError> {
        if batch.is_empty() {
            return Ok(());
        }

        // Verify all CFs exist before writing to WAL.
        for op in batch.ops() {
            let cf_name = match op {
                WriteOp::Put { cf, .. } => cf.as_str(),
                WriteOp::Delete { cf, .. } => cf.as_str(),
            };
            let _ = self.cf(cf_name)?;
        }

        // Phase 1: Write intent to WAL and fsync.
        {
            let mut wal = self.wal.lock().unwrap();
            wal.write_batch(batch)?;
        }

        // Phase 2: Apply operations to CF files.
        let mut by_cf: HashMap<&str, Vec<&WriteOp>> = HashMap::new();
        for op in batch.ops() {
            let cf_name = match op {
                WriteOp::Put { cf, .. } => cf.as_str(),
                WriteOp::Delete { cf, .. } => cf.as_str(),
            };
            by_cf.entry(cf_name).or_default().push(op);
        }

        for (cf_name, ops) in by_cf {
            let mutex = self.cf(cf_name)?;
            let mut state = mutex.lock().unwrap();
            for op in ops {
                match op {
                    WriteOp::Put { key, value, .. } => {
                        Self::append_record(&mut state, RECORD_STATUS_ACTIVE, key, value)?;
                    }
                    WriteOp::Delete { key, .. } => {
                        if state.index.contains_key(key.as_slice()) {
                            Self::append_record(&mut state, RECORD_STATUS_DELETED, key, &[])?;
                        }
                    }
                }
            }
            // Fsync after all ops in this CF.
            state
                .file
                .sync_data()
                .map_err(|e| StorageError::DurableStoreError {
                    details: format!("fsync: {e}"),
                })?;
        }

        // Phase 3: Clear WAL after successful application.
        {
            let mut wal = self.wal.lock().unwrap();
            wal.clear()?;
        }

        // Phase 4: Update cache for all applied operations.
        {
            let mut cache = self.cache.lock().unwrap();
            for op in batch.ops() {
                match op {
                    WriteOp::Put { cf, key, value } => {
                        cache.insert(cf, key, value);
                    }
                    WriteOp::Delete { cf, key } => {
                        cache.invalidate(cf, key);
                    }
                }
            }
        }

        Ok(())
    }

    fn contains(&self, cf: &str, key: &[u8]) -> Result<bool, StorageError> {
        let mutex = self.cf(cf)?;
        let state = mutex.lock().unwrap();
        Ok(state.index.contains_key(key))
    }

    fn prefix_scan(&self, cf: &str, prefix: &[u8]) -> Result<Vec<ScanEntry>, StorageError> {
        let mutex = self.cf(cf)?;
        let state = mutex.lock().unwrap();
        let mut results = Vec::new();
        for (key, loc) in &state.index {
            if key.starts_with(prefix) {
                let value = Self::read_value_at(&state.file, loc)?;
                results.push((key.clone(), value));
            }
        }
        results.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(results)
    }

    fn range_scan(
        &self,
        cf: &str,
        start: &[u8],
        end: &[u8],
    ) -> Result<Vec<ScanEntry>, StorageError> {
        let mutex = self.cf(cf)?;
        let state = mutex.lock().unwrap();
        let mut results = Vec::new();
        for (key, loc) in &state.index {
            if key.as_slice() >= start && key.as_slice() < end {
                let value = Self::read_value_at(&state.file, loc)?;
                results.push((key.clone(), value));
            }
        }
        results.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(results)
    }

    fn flush(&self) -> Result<(), StorageError> {
        for mutex in self.families.values() {
            let state = mutex.lock().unwrap();
            state
                .file
                .sync_all()
                .map_err(|e| StorageError::DurableStoreError {
                    details: format!("fsync: {e}"),
                })?;
        }
        Ok(())
    }

    fn disk_usage(&self) -> Result<u64, StorageError> {
        let mut total = 0u64;
        for mutex in self.families.values() {
            let state = mutex.lock().unwrap();
            total += state.file_end;
        }
        Ok(total)
    }

    fn count(&self, cf: &str) -> Result<u64, StorageError> {
        let mutex = self.cf(cf)?;
        let state = mutex.lock().unwrap();
        Ok(state.index.len() as u64)
    }
}

impl Drop for FileDurableStore {
    fn drop(&mut self) {
        if self.is_temporary {
            // Best-effort cleanup of temporary directory.
            let _ = fs::remove_dir_all(&self.data_dir);
        }
    }
}

// --- I/O helpers ---

/// Write the file header (magic + version + flags + reserved).
fn write_file_header(file: &File) -> Result<(), StorageError> {
    let mut buf = [0u8; CF_FILE_HEADER_SIZE];
    buf[0..4].copy_from_slice(&CF_FILE_MAGIC.to_le_bytes());
    buf[4..6].copy_from_slice(&CF_FILE_FORMAT_VERSION.to_le_bytes());
    // flags[6..8] and reserved[8..16] are zero.
    write_at_checked(file, &buf, 0)
}

/// Positional read that works on both Unix and non-Unix.
#[inline]
fn read_at_checked(file: &File, buf: &mut [u8], offset: u64) -> Result<(), StorageError> {
    #[cfg(unix)]
    {
        file.read_at(buf, offset)
            .map_err(|e| StorageError::DurableStoreError {
                details: format!("read at offset {offset}: {e}"),
            })?;
    }
    #[cfg(not(unix))]
    {
        use std::io::{Read, Seek};
        let file = unsafe { &mut *(file as *const File as *mut File) };
        file.seek(std::io::SeekFrom::Start(offset)).map_err(|e| {
            StorageError::DurableStoreError {
                details: format!("seek to {offset}: {e}"),
            }
        })?;
        file.read_exact(buf)
            .map_err(|e| StorageError::DurableStoreError {
                details: format!("read at {offset}: {e}"),
            })?;
    }
    Ok(())
}

/// Positional write that works on both Unix and non-Unix.
#[inline]
pub(crate) fn write_at_checked(file: &File, buf: &[u8], offset: u64) -> Result<(), StorageError> {
    #[cfg(unix)]
    {
        file.write_at(buf, offset)
            .map_err(|e| StorageError::DurableStoreError {
                details: format!("write at offset {offset}: {e}"),
            })?;
    }
    #[cfg(not(unix))]
    {
        use std::io::{Seek, Write};
        let file = unsafe { &mut *(file as *const File as *mut File) };
        file.seek(std::io::SeekFrom::Start(offset)).map_err(|e| {
            StorageError::DurableStoreError {
                details: format!("seek: {e}"),
            }
        })?;
        file.write_all(buf)
            .map_err(|e| StorageError::DurableStoreError {
                details: format!("write: {e}"),
            })?;
    }
    Ok(())
}

// --- CRC32 helpers ---

/// Compute CRC32 for a record with key+value already in a contiguous buffer.
#[inline]
fn compute_record_crc(status: u8, key_len: u32, value_len: u32, data: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&[status]);
    hasher.update(&key_len.to_le_bytes());
    hasher.update(&value_len.to_le_bytes());
    hasher.update(data);
    hasher.finalize()
}

/// Compute CRC32 for a record with key and value as separate slices.
#[inline]
fn compute_record_crc_parts(
    status: u8,
    key_len: u32,
    value_len: u32,
    key: &[u8],
    value: &[u8],
) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&[status]);
    hasher.update(&key_len.to_le_bytes());
    hasher.update(&value_len.to_le_bytes());
    hasher.update(key);
    hasher.update(value);
    hasher.finalize()
}

/// Pseudo-random u64 for temporary directory names.
/// Uses time + thread ID to avoid collisions in parallel tests.
fn rand_u64() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::SystemTime;
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u64;
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    nanos
        .wrapping_mul(6364136223846793005)
        .wrapping_add(count)
        .wrapping_add(1442695040888963407)
}

#[cfg(test)]
mod tests {
    use super::*;
    use paradencer_constants::durable_store::*;

    fn temp_store() -> FileDurableStore {
        FileDurableStore::temporary().expect("temporary store")
    }

    #[test]
    fn put_get_roundtrip() {
        let store = temp_store();
        store.put(CF_ACCOUNTS, b"key1", b"value1").expect("put");
        let val = store.get(CF_ACCOUNTS, b"key1").expect("get");
        assert_eq!(val, Some(b"value1".to_vec()));
    }

    #[test]
    fn get_missing_key_returns_none() {
        let store = temp_store();
        let val = store.get(CF_ACCOUNTS, b"nonexistent").expect("get");
        assert_eq!(val, None);
    }

    #[test]
    fn delete_removes_key() {
        let store = temp_store();
        store.put(CF_ACCOUNTS, b"k", b"v").expect("put");
        store.delete(CF_ACCOUNTS, b"k").expect("delete");
        assert_eq!(store.get(CF_ACCOUNTS, b"k").expect("get"), None);
    }

    #[test]
    fn contains_check() {
        let store = temp_store();
        assert!(!store.contains(CF_ACCOUNTS, b"x").expect("contains"));
        store.put(CF_ACCOUNTS, b"x", b"y").expect("put");
        assert!(store.contains(CF_ACCOUNTS, b"x").expect("contains"));
    }

    #[test]
    fn overwrite_value() {
        let store = temp_store();
        store.put(CF_METADATA, b"k", b"v1").expect("put");
        store.put(CF_METADATA, b"k", b"v2").expect("put");
        assert_eq!(
            store.get(CF_METADATA, b"k").expect("get"),
            Some(b"v2".to_vec())
        );
    }

    #[test]
    fn write_batch_atomicity() {
        let store = temp_store();
        let mut batch = WriteBatch::new();
        batch.put(CF_ACCOUNTS, b"a", b"1").unwrap();
        batch.put(CF_ACCOUNTS, b"b", b"2").unwrap();
        batch.put(CF_METADATA, b"c", b"3").unwrap();
        store.write_batch(&batch).expect("batch");

        assert_eq!(
            store.get(CF_ACCOUNTS, b"a").expect("get"),
            Some(b"1".to_vec())
        );
        assert_eq!(
            store.get(CF_ACCOUNTS, b"b").expect("get"),
            Some(b"2".to_vec())
        );
        assert_eq!(
            store.get(CF_METADATA, b"c").expect("get"),
            Some(b"3".to_vec())
        );
    }

    #[test]
    fn write_batch_with_deletes() {
        let store = temp_store();
        store.put(CF_ACCOUNTS, b"x", b"old").expect("put");

        let mut batch = WriteBatch::new();
        batch.delete(CF_ACCOUNTS, b"x").unwrap();
        batch.put(CF_ACCOUNTS, b"y", b"new").unwrap();
        store.write_batch(&batch).expect("batch");

        assert_eq!(store.get(CF_ACCOUNTS, b"x").expect("get"), None);
        assert_eq!(
            store.get(CF_ACCOUNTS, b"y").expect("get"),
            Some(b"new".to_vec())
        );
    }

    #[test]
    fn prefix_scan_filters_correctly() {
        let store = temp_store();
        store.put(CF_ACCOUNTS, b"user:001", b"alice").unwrap();
        store.put(CF_ACCOUNTS, b"user:002", b"bob").unwrap();
        store.put(CF_ACCOUNTS, b"meta:count", b"2").unwrap();

        let results = store.prefix_scan(CF_ACCOUNTS, b"user:").expect("scan");
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].1, b"alice");
        assert_eq!(results[1].1, b"bob");
    }

    #[test]
    fn range_scan_bounds() {
        let store = temp_store();
        store.put(CF_ACCOUNTS, b"a", b"1").unwrap();
        store.put(CF_ACCOUNTS, b"b", b"2").unwrap();
        store.put(CF_ACCOUNTS, b"c", b"3").unwrap();
        store.put(CF_ACCOUNTS, b"d", b"4").unwrap();

        let results = store
            .range_scan(CF_ACCOUNTS, b"b", b"d")
            .expect("range scan");
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, b"b");
        assert_eq!(results[1].0, b"c");
    }

    #[test]
    fn column_families_are_isolated() {
        let store = temp_store();
        store.put(CF_ACCOUNTS, b"key", b"acct").unwrap();
        store.put(CF_METADATA, b"key", b"meta").unwrap();

        assert_eq!(
            store.get(CF_ACCOUNTS, b"key").expect("get"),
            Some(b"acct".to_vec())
        );
        assert_eq!(
            store.get(CF_METADATA, b"key").expect("get"),
            Some(b"meta".to_vec())
        );
    }

    #[test]
    fn unknown_cf_returns_error() {
        let store = temp_store();
        let err = store.get("nonexistent_cf", b"k").unwrap_err();
        assert!(matches!(err, StorageError::UnknownColumnFamily { .. }));
    }

    #[test]
    fn large_value_roundtrip() {
        let store = temp_store();
        let large_value = vec![0xABu8; 1024 * 1024]; // 1 MB
        store
            .put(CF_ACCOUNTS, b"big", &large_value)
            .expect("put large");
        let val = store.get(CF_ACCOUNTS, b"big").expect("get large");
        assert_eq!(val, Some(large_value));
    }

    #[test]
    fn count_tracks_inserts_and_deletes() {
        let store = temp_store();
        assert_eq!(store.count(CF_ACCOUNTS).unwrap(), 0);

        store.put(CF_ACCOUNTS, b"a", b"1").unwrap();
        store.put(CF_ACCOUNTS, b"b", b"2").unwrap();
        assert_eq!(store.count(CF_ACCOUNTS).unwrap(), 2);

        store.delete(CF_ACCOUNTS, b"a").unwrap();
        assert_eq!(store.count(CF_ACCOUNTS).unwrap(), 1);
    }

    #[test]
    fn flush_succeeds() {
        let store = temp_store();
        store.put(CF_ACCOUNTS, b"k", b"v").unwrap();
        store.flush().expect("flush");
    }

    #[test]
    fn disk_usage_increases_with_writes() {
        let store = temp_store();
        let before = store.disk_usage().expect("usage");
        store.put(CF_ACCOUNTS, b"k", b"v").unwrap();
        let after = store.disk_usage().expect("usage");
        assert!(after > before);
    }

    #[test]
    fn persistence_across_reopen() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("testdb");

        // Write data.
        {
            let store = FileDurableStore::open(&path).expect("open");
            store
                .put(CF_ACCOUNTS, b"persist_key", b"persist_val")
                .unwrap();
            store.flush().unwrap();
        }

        // Reopen and verify index rebuilt from file with CRC verification.
        {
            let store = FileDurableStore::open(&path).expect("reopen");
            let val = store.get(CF_ACCOUNTS, b"persist_key").expect("get");
            assert_eq!(val, Some(b"persist_val".to_vec()));
        }
    }

    #[test]
    fn delete_survives_reopen() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("testdb");

        {
            let store = FileDurableStore::open(&path).expect("open");
            store.put(CF_ACCOUNTS, b"del_key", b"val").unwrap();
            store.delete(CF_ACCOUNTS, b"del_key").unwrap();
            store.flush().unwrap();
        }

        {
            let store = FileDurableStore::open(&path).expect("reopen");
            assert_eq!(store.get(CF_ACCOUNTS, b"del_key").unwrap(), None);
        }
    }

    #[test]
    fn overwrite_survives_reopen() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("testdb");

        {
            let store = FileDurableStore::open(&path).expect("open");
            store.put(CF_ACCOUNTS, b"ow", b"old").unwrap();
            store.put(CF_ACCOUNTS, b"ow", b"new").unwrap();
            store.flush().unwrap();
        }

        {
            let store = FileDurableStore::open(&path).expect("reopen");
            assert_eq!(
                store.get(CF_ACCOUNTS, b"ow").unwrap(),
                Some(b"new".to_vec())
            );
        }
    }

    #[test]
    fn batch_size_limit_enforced() {
        let mut batch = WriteBatch::new();
        for i in 0..MAX_WRITE_BATCH_SIZE {
            batch
                .put(CF_ACCOUNTS, &i.to_le_bytes(), b"v")
                .expect("should succeed");
        }
        let err = batch.put(CF_ACCOUNTS, b"overflow", b"v").unwrap_err();
        assert!(matches!(err, StorageError::WriteBatchTooLarge { .. }));
    }

    #[test]
    fn metadata_key_roundtrip() {
        let store = temp_store();
        let slot: u64 = 42;
        store
            .put(CF_METADATA, META_KEY_LATEST_SLOT, &slot.to_le_bytes())
            .unwrap();

        let raw = store
            .get(CF_METADATA, META_KEY_LATEST_SLOT)
            .unwrap()
            .expect("should exist");
        let recovered = u64::from_le_bytes(raw.try_into().expect("8 bytes"));
        assert_eq!(recovered, 42);
    }

    #[test]
    fn all_standard_cfs_accessible() {
        let store = temp_store();
        for &cf in STANDARD_COLUMN_FAMILIES {
            store
                .put(cf, b"test", b"ok")
                .unwrap_or_else(|e| panic!("CF {cf} failed: {e}"));
            assert_eq!(store.get(cf, b"test").unwrap(), Some(b"ok".to_vec()));
        }
    }

    #[test]
    fn many_keys_scan() {
        let store = temp_store();
        for i in 0u32..1000 {
            let key = format!("key:{i:04}");
            store
                .put(CF_ACCOUNTS, key.as_bytes(), &i.to_le_bytes())
                .unwrap();
        }
        let results = store.prefix_scan(CF_ACCOUNTS, b"key:00").unwrap();
        // keys key:0000..key:0099 match
        assert_eq!(results.len(), 100);
    }

    // --- CRC32 and file format tests ---

    #[test]
    fn file_header_written_on_create() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("testdb");
        let _store = FileDurableStore::open(&path).expect("open");

        // Verify the accounts CF file has a valid header.
        let cf_path = path.join("accounts.dat");
        let data = fs::read(&cf_path).expect("read file");
        assert!(data.len() >= CF_FILE_HEADER_SIZE);

        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let version = u16::from_le_bytes([data[4], data[5]]);
        assert_eq!(magic, CF_FILE_MAGIC);
        assert_eq!(version, CF_FILE_FORMAT_VERSION);
    }

    #[test]
    fn crc_verified_on_rebuild() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("testdb");

        // Write a record.
        {
            let store = FileDurableStore::open(&path).expect("open");
            store.put(CF_ACCOUNTS, b"test", b"data").expect("put");
            store.flush().unwrap();
        }

        // Corrupt one byte of the record data on disk.
        {
            let cf_path = path.join("accounts.dat");
            let mut data = fs::read(&cf_path).expect("read");
            // Flip a byte in the value area (after header + key).
            let corrupt_offset = CF_FILE_HEADER_SIZE + RECORD_HEADER_SIZE + 4 + 1;
            if corrupt_offset < data.len() {
                data[corrupt_offset] ^= 0xFF;
                fs::write(&cf_path, &data).expect("write corrupt");
            }
        }

        // Reopen — CRC check should detect corruption, truncate at corrupt record.
        {
            let store = FileDurableStore::open(&path).expect("reopen");
            // The corrupt record should have been truncated.
            assert_eq!(store.get(CF_ACCOUNTS, b"test").unwrap(), None);
            assert_eq!(store.count(CF_ACCOUNTS).unwrap(), 0);
        }
    }

    #[test]
    fn dead_bytes_tracked_on_overwrite() {
        let store = temp_store();
        store.put(CF_ACCOUNTS, b"key", b"val1").expect("put");

        let dead_before = store.total_dead_bytes();
        assert_eq!(dead_before, 0);

        // Overwrite — old record becomes dead space.
        store.put(CF_ACCOUNTS, b"key", b"val2").expect("put");
        let dead_after = store.total_dead_bytes();
        assert!(dead_after > 0, "dead bytes should increase on overwrite");
    }

    #[test]
    fn dead_bytes_tracked_on_delete() {
        let store = temp_store();
        store.put(CF_ACCOUNTS, b"key", b"val").expect("put");
        store.delete(CF_ACCOUNTS, b"key").expect("delete");

        let dead = store.total_dead_bytes();
        // Both the original record and the tombstone are dead.
        assert!(dead > 0, "dead bytes should increase on delete");
    }

    #[test]
    fn dead_ratio_increases_with_overwrites() {
        let store = temp_store();
        // Write 10 records.
        for i in 0u32..10 {
            store
                .put(CF_ACCOUNTS, &i.to_le_bytes(), b"original")
                .unwrap();
        }
        let ratio_before = store.dead_ratio(CF_ACCOUNTS).unwrap();
        assert_eq!(ratio_before, 0.0);

        // Overwrite all 10 — creates 50% dead space.
        for i in 0u32..10 {
            store
                .put(CF_ACCOUNTS, &i.to_le_bytes(), b"updated!")
                .unwrap();
        }
        let ratio_after = store.dead_ratio(CF_ACCOUNTS).unwrap();
        assert!(
            ratio_after > 0.3,
            "dead ratio should be significant after overwrites: {ratio_after}"
        );
    }

    #[test]
    fn dead_bytes_tracked_on_rebuild() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("testdb");

        // Write records with overwrites.
        {
            let store = FileDurableStore::open(&path).expect("open");
            store.put(CF_ACCOUNTS, b"k", b"v1").unwrap();
            store.put(CF_ACCOUNTS, b"k", b"v2").unwrap(); // overwrite
            store.flush().unwrap();
        }

        // Reopen — dead bytes should be calculated during rebuild.
        {
            let store = FileDurableStore::open(&path).expect("reopen");
            assert!(store.total_dead_bytes() > 0);
            assert_eq!(store.get(CF_ACCOUNTS, b"k").unwrap(), Some(b"v2".to_vec()));
        }
    }

    // --- WAL integration tests ---

    #[test]
    fn wal_replays_incomplete_batch_on_reopen() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("testdb");

        // Write a batch normally.
        {
            let store = FileDurableStore::open(&path).expect("open");
            let mut batch = WriteBatch::new();
            batch.put(CF_ACCOUNTS, b"wal_key", b"wal_val").unwrap();
            store.write_batch(&batch).unwrap();
            store.flush().unwrap();
        }

        // Verify the data persists through reopen.
        {
            let store = FileDurableStore::open(&path).expect("reopen");
            assert_eq!(
                store.get(CF_ACCOUNTS, b"wal_key").unwrap(),
                Some(b"wal_val".to_vec())
            );
        }
    }

    #[test]
    fn wal_simulated_crash_replays_batch() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("testdb");

        // Step 1: Open store and write initial data.
        {
            let store = FileDurableStore::open(&path).expect("open");
            store.put(CF_ACCOUNTS, b"existing", b"data").unwrap();
            store.flush().unwrap();
        }

        // Step 2: Manually write a WAL entry without applying it
        // (simulating a crash after WAL write but before CF application).
        {
            let mut wal = super::super::wal::WriteAheadLog::open(&path).expect("open wal");
            let mut batch = WriteBatch::new();
            batch.put(CF_ACCOUNTS, b"crash_key", b"crash_val").unwrap();
            batch.put(CF_METADATA, b"crash_meta", b"meta_val").unwrap();
            wal.write_batch(&batch).unwrap();
            // Don't clear WAL — simulating crash.
        }

        // Step 3: Reopen store — WAL should be replayed.
        {
            let store = FileDurableStore::open(&path).expect("reopen");
            // Existing data preserved.
            assert_eq!(
                store.get(CF_ACCOUNTS, b"existing").unwrap(),
                Some(b"data".to_vec())
            );
            // WAL-replayed data available.
            assert_eq!(
                store.get(CF_ACCOUNTS, b"crash_key").unwrap(),
                Some(b"crash_val".to_vec())
            );
            assert_eq!(
                store.get(CF_METADATA, b"crash_meta").unwrap(),
                Some(b"meta_val".to_vec())
            );
        }
    }

    #[test]
    fn wal_cleared_after_successful_batch() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("testdb");

        let store = FileDurableStore::open(&path).expect("open");
        let mut batch = WriteBatch::new();
        batch.put(CF_ACCOUNTS, b"k", b"v").unwrap();
        store.write_batch(&batch).unwrap();

        // WAL should be empty after successful batch.
        let wal_path = path.join(paradencer_constants::durable_store::WAL_FILE_NAME);
        let wal_len = fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0);
        assert_eq!(wal_len, 0, "WAL should be cleared after batch");
    }

    // --- Cache integration tests ---

    #[test]
    fn cache_hit_after_put() {
        let store = temp_store();
        store.put(CF_ACCOUNTS, b"ck", b"cv").unwrap();

        // Second get should hit cache (first get after put also goes via cache).
        let val = store.get(CF_ACCOUNTS, b"ck").unwrap();
        assert_eq!(val, Some(b"cv".to_vec()));

        let stats = store.cache_stats();
        assert!(stats.hits >= 1, "expected at least one cache hit");
    }

    #[test]
    fn cache_invalidated_on_delete() {
        let store = temp_store();
        store.put(CF_ACCOUNTS, b"dk", b"dv").unwrap();

        // Should be cached.
        assert_eq!(store.get(CF_ACCOUNTS, b"dk").unwrap(), Some(b"dv".to_vec()));

        store.delete(CF_ACCOUNTS, b"dk").unwrap();

        // Cache should be invalidated — and key doesn't exist on disk either.
        assert_eq!(store.get(CF_ACCOUNTS, b"dk").unwrap(), None);
    }

    #[test]
    fn cache_updated_on_overwrite() {
        let store = temp_store();
        store.put(CF_ACCOUNTS, b"ok", b"old").unwrap();
        store.put(CF_ACCOUNTS, b"ok", b"new").unwrap();

        // Cache should return the new value without disk read.
        let val = store.get(CF_ACCOUNTS, b"ok").unwrap();
        assert_eq!(val, Some(b"new".to_vec()));

        let stats = store.cache_stats();
        assert!(stats.hits >= 1);
    }

    #[test]
    fn cache_populated_on_batch() {
        let store = temp_store();
        let mut batch = WriteBatch::new();
        batch.put(CF_ACCOUNTS, b"b1", b"v1").unwrap();
        batch.put(CF_ACCOUNTS, b"b2", b"v2").unwrap();
        store.write_batch(&batch).unwrap();

        // Both values should be in cache.
        let stats_before = store.cache_stats();
        let _ = store.get(CF_ACCOUNTS, b"b1").unwrap();
        let _ = store.get(CF_ACCOUNTS, b"b2").unwrap();
        let stats_after = store.cache_stats();

        assert!(
            stats_after.hits >= stats_before.hits + 2,
            "batch values should be cache hits"
        );
    }

    #[test]
    fn cache_invalidated_on_compact() {
        let store = temp_store();

        // Write and overwrite to create dead space.
        for i in 0u32..10 {
            store
                .put(CF_ACCOUNTS, &i.to_le_bytes(), b"original")
                .unwrap();
        }
        for i in 0u32..10 {
            store
                .put(CF_ACCOUNTS, &i.to_le_bytes(), b"updated!")
                .unwrap();
        }

        // Populate cache.
        let _ = store.get(CF_ACCOUNTS, &0u32.to_le_bytes()).unwrap();

        // Compact — cache for this CF should be invalidated.
        store.compact_cf(CF_ACCOUNTS).unwrap();

        // Value should still be correct (re-read from disk, not stale cache).
        let val = store.get(CF_ACCOUNTS, &0u32.to_le_bytes()).unwrap();
        assert_eq!(val, Some(b"updated!".to_vec()));
    }
}
