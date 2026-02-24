//! Solana snapshot restore pipeline.
//!
//! Reads a real Solana snapshot archive (tar.zst), parses the manifest,
//! extracts AppendVec account storage files, and populates the
//! AccountDatabase with all accounts found.
//!
//! Supports both full and incremental snapshots. Incremental snapshots
//! are applied on top of an existing database state.

use super::append_vec::AppendVecIter;
use super::bank_fields::{self, SnapshotBankState};
use super::solana_archive::{ArchiveError, SnapshotArchive, SnapshotArchiveEntry};
use super::status_cache::{self, StatusCacheParseResult};
use crate::accounts::{AccountDatabase, Pubkey};
use crate::StorageError;
use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Result of restoring a Solana snapshot.
#[derive(Debug, Clone)]
pub struct RestoreResult {
    /// Snapshot slot number.
    pub slot: u64,
    /// Format version string from the archive.
    pub version: String,
    /// Total number of accounts loaded.
    pub accounts_loaded: u64,
    /// Total lamports across all loaded accounts.
    pub total_lamports: u64,
    /// Number of AppendVec files processed.
    pub append_vecs_processed: u64,
    /// Number of accounts that failed validation (skipped).
    pub validation_errors: u64,
    /// Parsed bank state from the snapshot manifest (if present).
    pub bank_state: Option<SnapshotBankState>,
    /// Parsed status cache entries (if present).
    pub status_cache: Option<StatusCacheParseResult>,
    /// Bank hash from the manifest (accounts hash expected value).
    /// Zeroed if not present in the snapshot manifest.
    pub expected_accounts_hash: [u8; 32],
}

/// Progress tracking for snapshot restoration.
#[derive(Debug)]
pub struct RestoreProgress {
    accounts_loaded: AtomicU64,
    total_lamports: AtomicU64,
    append_vecs_processed: AtomicU64,
    validation_errors: AtomicU64,
}

impl RestoreProgress {
    fn new() -> Self {
        Self {
            accounts_loaded: AtomicU64::new(0),
            total_lamports: AtomicU64::new(0),
            append_vecs_processed: AtomicU64::new(0),
            validation_errors: AtomicU64::new(0),
        }
    }

    /// Get current progress snapshot.
    pub fn current(&self) -> RestoreProgressInfo {
        RestoreProgressInfo {
            accounts_loaded: self.accounts_loaded.load(Ordering::Relaxed),
            total_lamports: self.total_lamports.load(Ordering::Relaxed),
            append_vecs_processed: self.append_vecs_processed.load(Ordering::Relaxed),
            validation_errors: self.validation_errors.load(Ordering::Relaxed),
        }
    }
}

/// Point-in-time progress information.
#[derive(Debug, Clone)]
pub struct RestoreProgressInfo {
    pub accounts_loaded: u64,
    pub total_lamports: u64,
    pub append_vecs_processed: u64,
    pub validation_errors: u64,
}

/// Restores a Solana snapshot into an AccountDatabase.
pub struct SnapshotRestorer {
    progress: Arc<RestoreProgress>,
}

impl Default for SnapshotRestorer {
    fn default() -> Self {
        Self::new()
    }
}

impl SnapshotRestorer {
    pub fn new() -> Self {
        Self {
            progress: Arc::new(RestoreProgress::new()),
        }
    }

    /// Get the progress tracker for monitoring.
    pub fn progress(&self) -> &RestoreProgress {
        &self.progress
    }

    /// Restore a compressed Solana snapshot from a reader.
    ///
    /// Decompresses the tar.zst archive, parses all entries, extracts
    /// accounts from AppendVec files, and inserts them into the database.
    pub fn restore_compressed<R: Read>(
        &self,
        reader: R,
        db: &AccountDatabase,
    ) -> Result<RestoreResult, StorageError> {
        let entries = SnapshotArchive::parse_compressed(reader).map_err(archive_error)?;
        self.restore_from_entries(entries, db)
    }

    /// Restore an uncompressed tar snapshot from a reader.
    pub fn restore_tar<R: Read>(
        &self,
        reader: R,
        db: &AccountDatabase,
    ) -> Result<RestoreResult, StorageError> {
        let entries = SnapshotArchive::parse_tar(reader).map_err(archive_error)?;
        self.restore_from_entries(entries, db)
    }

    /// Restore from a byte buffer (compressed).
    pub fn restore_bytes(
        &self,
        data: &[u8],
        db: &AccountDatabase,
    ) -> Result<RestoreResult, StorageError> {
        let entries = SnapshotArchive::parse_bytes(data).map_err(archive_error)?;
        self.restore_from_entries(entries, db)
    }

    /// Restore from a byte buffer (uncompressed tar).
    pub fn restore_tar_bytes(
        &self,
        data: &[u8],
        db: &AccountDatabase,
    ) -> Result<RestoreResult, StorageError> {
        let entries = SnapshotArchive::parse_tar_bytes(data).map_err(archive_error)?;
        self.restore_from_entries(entries, db)
    }

    /// Apply an incremental snapshot on top of existing database state.
    ///
    /// Accounts in the incremental snapshot override existing accounts
    /// with the same pubkey. Accounts not in the increment are unchanged.
    pub fn apply_incremental<R: Read>(
        &self,
        reader: R,
        db: &AccountDatabase,
    ) -> Result<RestoreResult, StorageError> {
        // Same mechanism as full restore — inserts/updates accounts.
        self.restore_compressed(reader, db)
    }

    fn restore_from_entries(
        &self,
        entries: Vec<SnapshotArchiveEntry>,
        db: &AccountDatabase,
    ) -> Result<RestoreResult, StorageError> {
        let mut version = String::new();
        let mut slot = 0u64;
        let mut bank_state: Option<SnapshotBankState> = None;
        let mut status_cache: Option<StatusCacheParseResult> = None;

        for entry in &entries {
            match entry {
                SnapshotArchiveEntry::Version(v) => {
                    version = v.clone();
                }
                SnapshotArchiveEntry::AccountVec {
                    slot: vec_slot,
                    data,
                    ..
                } => {
                    if *vec_slot > slot {
                        slot = *vec_slot;
                    }
                    self.process_append_vec(data, db, slot)?;
                }
                SnapshotArchiveEntry::Manifest(data) => {
                    match bank_fields::parse_bank_state(data) {
                        Ok(state) => {
                            // Use the manifest slot as the authoritative slot.
                            slot = state.slot;
                            bank_state = Some(state);
                        }
                        Err(_) => {
                            // TODO: Log manifest parse failure. Non-fatal for
                            // account restoration — accounts can still be loaded
                            // even if the manifest is unparseable (version mismatch, etc.)
                        }
                    }
                }
                SnapshotArchiveEntry::StatusCache(data) => {
                    match status_cache::parse_status_cache(data) {
                        Ok(result) => {
                            status_cache = Some(result);
                        }
                        Err(_) => {
                            // Non-fatal — accounts can still be loaded without
                            // the status cache. Transaction dedup will start empty.
                        }
                    }
                }
                SnapshotArchiveEntry::Unknown { .. } => {}
            }
        }

        // Extract the bank hash (accounts hash) from the parsed manifest.
        let expected_accounts_hash = bank_state
            .as_ref()
            .map(|state| state.hash)
            .unwrap_or([0u8; 32]);

        let info = self.progress.current();
        Ok(RestoreResult {
            slot,
            version,
            accounts_loaded: info.accounts_loaded,
            total_lamports: info.total_lamports,
            append_vecs_processed: info.append_vecs_processed,
            validation_errors: info.validation_errors,
            bank_state,
            status_cache,
            expected_accounts_hash,
        })
    }

    /// Verify accounts hash after a restore completes.
    ///
    /// Computes the current accounts hash from the database and compares
    /// against the expected hash from the snapshot. Returns `Ok` on match
    /// or when the expected hash is zeroed (not available in the snapshot).
    /// Returns `Err` on mismatch.
    pub fn verify_restore(
        &self,
        db: &AccountDatabase,
        result: &RestoreResult,
    ) -> Result<[u8; 32], StorageError> {
        let expected = &result.expected_accounts_hash;

        // Skip verification if no hash was provided.
        if *expected == [0u8; 32] {
            let (computed, _) = db.compute_accounts_hash();
            return Ok(computed);
        }

        db.verify_accounts_hash(expected)
            .map_err(|mismatch| StorageError::AccountDatabaseError {
                details: format!(
                    "Snapshot accounts hash verification failed at slot {}: {}",
                    result.slot, mismatch
                ),
            })
    }

    fn process_append_vec(
        &self,
        data: &[u8],
        db: &AccountDatabase,
        slot: u64,
    ) -> Result<(), StorageError> {
        self.progress
            .append_vecs_processed
            .fetch_add(1, Ordering::Relaxed);

        for result in AppendVecIter::new(data) {
            match result {
                Ok(av_account) => {
                    let pubkey = av_account.pubkey;
                    let lamports = av_account.lamports;
                    let (pk, account) = av_account.into_account();

                    // Skip tombstone accounts (zero lamports + zero data + default owner).
                    if lamports == 0
                        && account.data.is_empty()
                        && account.meta.owner == Pubkey::zeroed()
                    {
                        continue;
                    }

                    db.store_published_account_at_slot(pk, account, slot);
                    self.progress
                        .accounts_loaded
                        .fetch_add(1, Ordering::Relaxed);
                    self.progress
                        .total_lamports
                        .fetch_add(lamports, Ordering::Relaxed);
                    let _ = pubkey;
                }
                Err(_) => {
                    self.progress
                        .validation_errors
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        Ok(())
    }
}

fn archive_error(e: ArchiveError) -> StorageError {
    StorageError::AccountDatabaseError {
        details: format!("Snapshot archive error: {}", e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::Account;

    /// Build a minimal AppendVec record in memory.
    fn make_append_vec_record(
        pubkey: [u8; 32],
        lamports: u64,
        owner: [u8; 32],
        data: &[u8],
    ) -> Vec<u8> {
        let mut buf = Vec::new();

        // Bytes 0-7: reserved
        buf.extend_from_slice(&[0u8; 8]);
        // Bytes 8-15: data_len
        buf.extend_from_slice(&(data.len() as u64).to_le_bytes());
        // Bytes 16-47: pubkey
        buf.extend_from_slice(&pubkey);
        // Bytes 48-55: lamports
        buf.extend_from_slice(&lamports.to_le_bytes());
        // Bytes 56-63: rent_epoch
        buf.extend_from_slice(&0u64.to_le_bytes());
        // Bytes 64-95: owner
        buf.extend_from_slice(&owner);
        // Byte 96: executable
        buf.push(0);
        // Bytes 97-103: padding
        buf.extend_from_slice(&[0u8; 7]);
        // Bytes 104-135: hash
        buf.extend_from_slice(&[0u8; 32]);

        assert_eq!(buf.len(), 136);

        buf.extend_from_slice(data);

        // Alignment padding to 8 bytes.
        let unpadded = buf.len();
        let padded = (unpadded + 7) & !7;
        buf.resize(padded, 0);

        buf
    }

    /// Build a minimal tar archive for testing.
    fn make_tar(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut archive = Vec::new();
        for (name, content) in files {
            let mut header = [0u8; 512];
            let name_bytes = name.as_bytes();
            let copy_len = name_bytes.len().min(100);
            header[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
            let size_str = format!("{:011o}", content.len());
            header[124..124 + size_str.len()].copy_from_slice(size_str.as_bytes());
            header[156] = b'0';
            header[257..263].copy_from_slice(b"ustar\0");
            header[148..156].copy_from_slice(b"        ");
            let checksum: u32 = header.iter().map(|&b| b as u32).sum();
            let cksum_str = format!("{checksum:06o}\0 ");
            header[148..156].copy_from_slice(&cksum_str.as_bytes()[..8]);
            archive.extend_from_slice(&header);
            archive.extend_from_slice(content);
            let pad = (512 - (content.len() % 512)) % 512;
            archive.extend(std::iter::repeat_n(0u8, pad));
        }
        archive.extend(std::iter::repeat_n(0u8, 512 * 2));
        archive
    }

    #[test]
    fn restore_single_account_from_tar() {
        let av_data = make_append_vec_record([1u8; 32], 1000, [2u8; 32], &[10, 20, 30]);
        let tar = make_tar(&[("version", b"1.2.0"), ("accounts/100.0", &av_data)]);

        let db = AccountDatabase::new();
        let restorer = SnapshotRestorer::new();
        let result = restorer.restore_tar_bytes(&tar, &db).unwrap();

        assert_eq!(result.version, "1.2.0");
        assert_eq!(result.accounts_loaded, 1);
        assert_eq!(result.total_lamports, 1000);
        assert_eq!(result.append_vecs_processed, 1);

        let account = db.get_published_account(&Pubkey::new([1u8; 32])).unwrap();
        assert_eq!(account.meta.lamports, 1000);
        assert_eq!(account.meta.owner, Pubkey::new([2u8; 32]));
        assert_eq!(account.data.as_slice(), &[10, 20, 30]);
    }

    #[test]
    fn restore_multiple_append_vecs() {
        let av0 = make_append_vec_record([1u8; 32], 100, [10u8; 32], &[]);
        let av1 = make_append_vec_record([2u8; 32], 200, [20u8; 32], &[1, 2]);
        let tar = make_tar(&[
            ("version", b"1.2.0"),
            ("accounts/100.0", &av0),
            ("accounts/100.1", &av1),
        ]);

        let db = AccountDatabase::new();
        let restorer = SnapshotRestorer::new();
        let result = restorer.restore_tar_bytes(&tar, &db).unwrap();

        assert_eq!(result.accounts_loaded, 2);
        assert_eq!(result.total_lamports, 300);
        assert_eq!(result.append_vecs_processed, 2);
    }

    #[test]
    fn restore_skips_tombstone_accounts() {
        // Tombstone: lamports=0, data empty, owner=zeroed.
        let tombstone = make_append_vec_record([3u8; 32], 0, [0u8; 32], &[]);
        let live = make_append_vec_record([1u8; 32], 500, [2u8; 32], &[]);
        let tar = make_tar(&[
            ("version", b"1.2.0"),
            ("accounts/50.0", &[tombstone, live].concat()),
        ]);

        let db = AccountDatabase::new();
        let restorer = SnapshotRestorer::new();
        let result = restorer.restore_tar_bytes(&tar, &db).unwrap();

        assert_eq!(result.accounts_loaded, 1);
        assert!(db.get_published_account(&Pubkey::new([3u8; 32])).is_none());
        assert!(db.get_published_account(&Pubkey::new([1u8; 32])).is_some());
    }

    #[test]
    fn restore_with_compressed_archive() {
        let av_data = make_append_vec_record([5u8; 32], 999, [6u8; 32], &[42]);
        let tar = make_tar(&[("version", b"1.2.0"), ("accounts/200.0", &av_data)]);
        let compressed = zstd::bulk::compress(&tar, 3).unwrap();

        let db = AccountDatabase::new();
        let restorer = SnapshotRestorer::new();
        let result = restorer.restore_bytes(&compressed, &db).unwrap();

        assert_eq!(result.accounts_loaded, 1);
        assert_eq!(result.total_lamports, 999);
    }

    #[test]
    fn restore_empty_archive() {
        let tar = make_tar(&[("version", b"1.2.0")]);

        let db = AccountDatabase::new();
        let restorer = SnapshotRestorer::new();
        let result = restorer.restore_tar_bytes(&tar, &db).unwrap();

        assert_eq!(result.accounts_loaded, 0);
        assert_eq!(result.append_vecs_processed, 0);
    }

    #[test]
    fn incremental_restore_overrides_existing() {
        let db = AccountDatabase::new();
        let pk = Pubkey::new([1u8; 32]);
        let owner = Pubkey::new([10u8; 32]);

        // Pre-populate with initial state.
        db.store_published_account(pk, Account::new(100, vec![], owner));

        // Incremental snapshot updates the account.
        let av_data = make_append_vec_record([1u8; 32], 500, [10u8; 32], &[1, 2, 3]);
        let tar = make_tar(&[("version", b"1.2.0"), ("accounts/300.0", &av_data)]);
        let compressed = zstd::bulk::compress(&tar, 3).unwrap();

        let restorer = SnapshotRestorer::new();
        restorer
            .apply_incremental(std::io::Cursor::new(&compressed), &db)
            .unwrap();

        let account = db.get_published_account(&pk).unwrap();
        assert_eq!(account.meta.lamports, 500);
        assert_eq!(account.data.as_slice(), &[1, 2, 3]);
    }

    #[test]
    fn progress_tracking_works() {
        let av0 = make_append_vec_record([1u8; 32], 100, [10u8; 32], &[]);
        let av1 = make_append_vec_record([2u8; 32], 200, [20u8; 32], &[]);
        let tar = make_tar(&[
            ("version", b"1.2.0"),
            ("accounts/100.0", &av0),
            ("accounts/100.1", &av1),
        ]);

        let db = AccountDatabase::new();
        let restorer = SnapshotRestorer::new();
        restorer.restore_tar_bytes(&tar, &db).unwrap();

        let info = restorer.progress().current();
        assert_eq!(info.accounts_loaded, 2);
        assert_eq!(info.total_lamports, 300);
        assert_eq!(info.append_vecs_processed, 2);
        assert_eq!(info.validation_errors, 0);
    }

    #[test]
    fn owner_index_populated_after_restore() {
        let av_data = make_append_vec_record([1u8; 32], 100, [10u8; 32], &[]);
        let tar = make_tar(&[("version", b"1.2.0"), ("accounts/100.0", &av_data)]);

        let db = AccountDatabase::new();
        let restorer = SnapshotRestorer::new();
        restorer.restore_tar_bytes(&tar, &db).unwrap();

        // Owner index should be populated via store_published_account_at_slot.
        assert_eq!(db.indexed_account_count(), 1);
        assert_eq!(db.indexed_total_lamports(), 100);
        assert_eq!(db.accounts_owned_by(&Pubkey::new([10u8; 32])), 1);
    }

    #[test]
    fn verify_restore_with_zero_expected_hash_returns_computed() {
        let av_data = make_append_vec_record([1u8; 32], 500, [2u8; 32], &[10, 20]);
        let tar = make_tar(&[("version", b"1.2.0"), ("accounts/100.0", &av_data)]);

        let db = AccountDatabase::new();
        let restorer = SnapshotRestorer::new();
        let result = restorer.restore_tar_bytes(&tar, &db).unwrap();

        // expected_accounts_hash is zero (no manifest with bank hash).
        assert_eq!(result.expected_accounts_hash, [0u8; 32]);

        // verify_restore should succeed and return computed hash.
        let computed = restorer.verify_restore(&db, &result).unwrap();
        assert_ne!(computed, [0u8; 32]);

        // Matches directly computed hash from DB.
        let (direct, _) = db.compute_accounts_hash();
        assert_eq!(computed, direct);
    }

    #[test]
    fn multiple_accounts_in_single_append_vec() {
        let mut av_data = Vec::new();
        av_data.extend(make_append_vec_record([1u8; 32], 100, [10u8; 32], &[]));
        av_data.extend(make_append_vec_record([2u8; 32], 200, [10u8; 32], &[1]));
        av_data.extend(make_append_vec_record([3u8; 32], 300, [20u8; 32], &[1, 2]));

        let tar = make_tar(&[("version", b"1.2.0"), ("accounts/100.0", &av_data)]);

        let db = AccountDatabase::new();
        let restorer = SnapshotRestorer::new();
        let result = restorer.restore_tar_bytes(&tar, &db).unwrap();

        assert_eq!(result.accounts_loaded, 3);
        assert_eq!(result.total_lamports, 600);
        assert_eq!(db.indexed_account_count(), 3);
    }
}
