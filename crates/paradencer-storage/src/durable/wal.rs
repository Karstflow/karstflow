// Write-Ahead Log for crash recovery of batch operations.
//
// Records batch intent before applying to CF files. On crash, incomplete
// batches are replayed from the WAL on next startup. After successful
// application, the WAL is truncated.
//
// WAL entry format:
//   [entry_len: u64 LE]    Total size of payload (CRC through sentinel)
//   [entry_crc: u32 LE]    CRC32 of [op_count through sentinel]
//   [op_count: u32 LE]     Number of operations
//   [operations...]        Sequence of:
//     [op_type: u8]        0=put, 1=delete
//     [cf_len: u16 LE]     Column family name length
//     [cf: cf_len bytes]   Column family name
//     [key_len: u32 LE]
//     [key: key_len bytes]
//     [value_len: u32 LE]  (0 for delete)
//     [value: value_len bytes]
//   [sentinel: u32 LE]     0x454E4421 ("END!")
//
// The WAL contains at most one active entry. After successful batch
// application, the file is truncated to zero.

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

use paradencer_constants::durable_store::{
    WAL_ENTRY_SENTINEL, WAL_FILE_NAME, WAL_OP_DELETE, WAL_OP_PUT,
};

use super::batch::WriteOp;
use super::WriteBatch;
use crate::StorageError;

/// A parsed WAL operation ready for replay.
#[derive(Debug, Clone)]
pub(crate) enum WalOp {
    Put {
        cf: String,
        key: Vec<u8>,
        value: Vec<u8>,
    },
    Delete {
        cf: String,
        key: Vec<u8>,
    },
}

/// Write-Ahead Log for durable batch operations.
pub(crate) struct WriteAheadLog {
    file: File,
    #[allow(dead_code)]
    path: PathBuf,
}

impl WriteAheadLog {
    /// Open or create the WAL file.
    pub fn open(data_dir: &Path) -> Result<Self, StorageError> {
        let path = data_dir.join(WAL_FILE_NAME);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| StorageError::DurableStoreError {
                details: format!("open WAL {}: {}", path.display(), e),
            })?;

        Ok(Self { file, path })
    }

    /// Check for a pending WAL entry and return its operations for replay.
    ///
    /// Returns `None` if the WAL is empty or contains only incomplete data.
    pub fn read_pending(&mut self) -> Result<Option<Vec<WalOp>>, StorageError> {
        let file_len = self
            .file
            .metadata()
            .map_err(|e| StorageError::DurableStoreError {
                details: format!("WAL metadata: {e}"),
            })?
            .len();

        if file_len < 8 {
            // Not enough for entry_len field.
            return Ok(None);
        }

        // Read entire WAL into memory (it's small — one batch at most).
        let mut data = Vec::with_capacity(file_len as usize);
        self.file
            .seek_to_start()
            .map_err(|e| StorageError::DurableStoreError {
                details: format!("WAL seek: {e}"),
            })?;
        self.file
            .read_to_end(&mut data)
            .map_err(|e| StorageError::DurableStoreError {
                details: format!("WAL read: {e}"),
            })?;

        parse_wal_entry(&data)
    }

    /// Write a batch of operations to the WAL, fsync, then return.
    ///
    /// The caller applies operations to CF files after this returns.
    pub fn write_batch(&mut self, batch: &WriteBatch) -> Result<(), StorageError> {
        if batch.is_empty() {
            return Ok(());
        }

        let entry = encode_wal_entry(batch);

        // Truncate WAL and write the new entry.
        self.file
            .set_len(0)
            .map_err(|e| StorageError::DurableStoreError {
                details: format!("WAL truncate: {e}"),
            })?;

        super::file_store::write_at_checked(&self.file, &entry, 0)?;

        // Fsync to ensure WAL is durable before applying.
        self.file
            .sync_data()
            .map_err(|e| StorageError::DurableStoreError {
                details: format!("WAL fsync: {e}"),
            })?;

        Ok(())
    }

    /// Clear the WAL after successful batch application.
    pub fn clear(&mut self) -> Result<(), StorageError> {
        self.file
            .set_len(0)
            .map_err(|e| StorageError::DurableStoreError {
                details: format!("WAL clear truncate: {e}"),
            })?;
        self.file
            .sync_data()
            .map_err(|e| StorageError::DurableStoreError {
                details: format!("WAL clear fsync: {e}"),
            })?;
        Ok(())
    }

    /// Path to the WAL file (for testing).
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Helper: seek file to start.
trait SeekToStart {
    fn seek_to_start(&mut self) -> std::io::Result<()>;
}

impl SeekToStart for File {
    fn seek_to_start(&mut self) -> std::io::Result<()> {
        use std::io::Seek;
        self.seek(std::io::SeekFrom::Start(0))?;
        Ok(())
    }
}

/// Encode a WriteBatch into WAL entry bytes.
fn encode_wal_entry(batch: &WriteBatch) -> Vec<u8> {
    // Pre-calculate payload size.
    let ops = batch.ops();
    let op_count = ops.len() as u32;

    let mut payload = Vec::new();
    // op_count
    payload.extend_from_slice(&op_count.to_le_bytes());

    // Operations
    for op in ops {
        match op {
            WriteOp::Put { cf, key, value } => {
                payload.push(WAL_OP_PUT);
                payload.extend_from_slice(&(cf.len() as u16).to_le_bytes());
                payload.extend_from_slice(cf.as_bytes());
                payload.extend_from_slice(&(key.len() as u32).to_le_bytes());
                payload.extend_from_slice(key);
                payload.extend_from_slice(&(value.len() as u32).to_le_bytes());
                payload.extend_from_slice(value);
            }
            WriteOp::Delete { cf, key } => {
                payload.push(WAL_OP_DELETE);
                payload.extend_from_slice(&(cf.len() as u16).to_le_bytes());
                payload.extend_from_slice(cf.as_bytes());
                payload.extend_from_slice(&(key.len() as u32).to_le_bytes());
                payload.extend_from_slice(key);
                payload.extend_from_slice(&0u32.to_le_bytes());
            }
        }
    }

    // Sentinel
    payload.extend_from_slice(&WAL_ENTRY_SENTINEL.to_le_bytes());

    // CRC covers the entire payload (op_count through sentinel).
    let crc = crc32fast::hash(&payload);

    // Build final entry: entry_len + crc + payload.
    let entry_len = (4 + payload.len()) as u64; // CRC(4) + payload
    let mut entry = Vec::with_capacity(8 + entry_len as usize);
    entry.extend_from_slice(&entry_len.to_le_bytes());
    entry.extend_from_slice(&crc.to_le_bytes());
    entry.extend_from_slice(&payload);

    entry
}

/// Parse a WAL entry from raw bytes. Returns `None` for empty or corrupt entries.
fn parse_wal_entry(data: &[u8]) -> Result<Option<Vec<WalOp>>, StorageError> {
    if data.len() < 8 {
        return Ok(None);
    }

    let entry_len = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]) as usize;

    if entry_len < 4 || data.len() < 8 + entry_len {
        // Incomplete entry.
        return Ok(None);
    }

    let entry_data = &data[8..8 + entry_len];

    // First 4 bytes are CRC.
    let stored_crc =
        u32::from_le_bytes([entry_data[0], entry_data[1], entry_data[2], entry_data[3]]);
    let payload = &entry_data[4..];

    // Verify CRC.
    let computed_crc = crc32fast::hash(payload);
    if stored_crc != computed_crc {
        return Ok(None);
    }

    // Check sentinel at the end.
    if payload.len() < 8 {
        return Ok(None);
    }
    let sentinel_offset = payload.len() - 4;
    let sentinel = u32::from_le_bytes([
        payload[sentinel_offset],
        payload[sentinel_offset + 1],
        payload[sentinel_offset + 2],
        payload[sentinel_offset + 3],
    ]);
    if sentinel != WAL_ENTRY_SENTINEL {
        return Ok(None);
    }

    // Parse operations.
    let ops_data = &payload[..sentinel_offset]; // Everything before sentinel
    let mut cursor = 0usize;

    if ops_data.len() < 4 {
        return Ok(None);
    }
    let op_count =
        u32::from_le_bytes([ops_data[0], ops_data[1], ops_data[2], ops_data[3]]) as usize;
    cursor += 4;

    let mut ops = Vec::with_capacity(op_count);

    for _ in 0..op_count {
        if cursor >= ops_data.len() {
            return Ok(None); // Truncated
        }

        let op_type = ops_data[cursor];
        cursor += 1;

        // CF name
        if cursor + 2 > ops_data.len() {
            return Ok(None);
        }
        let cf_len = u16::from_le_bytes([ops_data[cursor], ops_data[cursor + 1]]) as usize;
        cursor += 2;
        if cursor + cf_len > ops_data.len() {
            return Ok(None);
        }
        let cf = String::from_utf8_lossy(&ops_data[cursor..cursor + cf_len]).into_owned();
        cursor += cf_len;

        // Key
        if cursor + 4 > ops_data.len() {
            return Ok(None);
        }
        let key_len = u32::from_le_bytes([
            ops_data[cursor],
            ops_data[cursor + 1],
            ops_data[cursor + 2],
            ops_data[cursor + 3],
        ]) as usize;
        cursor += 4;
        if cursor + key_len > ops_data.len() {
            return Ok(None);
        }
        let key = ops_data[cursor..cursor + key_len].to_vec();
        cursor += key_len;

        // Value
        if cursor + 4 > ops_data.len() {
            return Ok(None);
        }
        let value_len = u32::from_le_bytes([
            ops_data[cursor],
            ops_data[cursor + 1],
            ops_data[cursor + 2],
            ops_data[cursor + 3],
        ]) as usize;
        cursor += 4;
        if cursor + value_len > ops_data.len() {
            return Ok(None);
        }
        let value = ops_data[cursor..cursor + value_len].to_vec();
        cursor += value_len;

        match op_type {
            WAL_OP_PUT => ops.push(WalOp::Put { cf, key, value }),
            WAL_OP_DELETE => ops.push(WalOp::Delete { cf, key }),
            _ => return Ok(None), // Unknown op type
        }
    }

    Ok(Some(ops))
}

#[cfg(test)]
mod tests {
    use super::*;
    use paradencer_constants::durable_store::CF_ACCOUNTS;

    #[test]
    fn encode_decode_roundtrip() {
        let mut batch = WriteBatch::new();
        batch.put(CF_ACCOUNTS, b"key1", b"val1").unwrap();
        batch.put(CF_ACCOUNTS, b"key2", b"val2").unwrap();
        batch.delete(CF_ACCOUNTS, b"key3").unwrap();

        let encoded = encode_wal_entry(&batch);
        let ops = parse_wal_entry(&encoded).unwrap().expect("should parse");

        assert_eq!(ops.len(), 3);
        match &ops[0] {
            WalOp::Put { cf, key, value } => {
                assert_eq!(cf, CF_ACCOUNTS);
                assert_eq!(key, b"key1");
                assert_eq!(value, b"val1");
            }
            _ => panic!("expected put"),
        }
        match &ops[2] {
            WalOp::Delete { cf, key } => {
                assert_eq!(cf, CF_ACCOUNTS);
                assert_eq!(key, b"key3");
            }
            _ => panic!("expected delete"),
        }
    }

    #[test]
    fn empty_data_returns_none() {
        assert!(parse_wal_entry(&[]).unwrap().is_none());
        assert!(parse_wal_entry(&[0; 7]).unwrap().is_none());
    }

    #[test]
    fn truncated_entry_returns_none() {
        let mut batch = WriteBatch::new();
        batch.put(CF_ACCOUNTS, b"k", b"v").unwrap();
        let encoded = encode_wal_entry(&batch);

        // Truncate at various points.
        for len in [8, 12, encoded.len() - 4, encoded.len() - 1] {
            if len < encoded.len() {
                assert!(
                    parse_wal_entry(&encoded[..len]).unwrap().is_none(),
                    "should be None at truncation point {len}"
                );
            }
        }
    }

    #[test]
    fn corrupt_crc_returns_none() {
        let mut batch = WriteBatch::new();
        batch.put(CF_ACCOUNTS, b"k", b"v").unwrap();
        let mut encoded = encode_wal_entry(&batch);

        // Flip a byte in the CRC.
        encoded[8] ^= 0xFF;
        assert!(parse_wal_entry(&encoded).unwrap().is_none());
    }

    #[test]
    fn corrupt_sentinel_returns_none() {
        let mut batch = WriteBatch::new();
        batch.put(CF_ACCOUNTS, b"k", b"v").unwrap();
        let mut encoded = encode_wal_entry(&batch);

        // Flip the last byte (sentinel).
        let last = encoded.len() - 1;
        encoded[last] ^= 0xFF;
        assert!(parse_wal_entry(&encoded).unwrap().is_none());
    }

    #[test]
    fn wal_write_and_read_back() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut wal = WriteAheadLog::open(dir.path()).expect("open");

        // No pending entry initially.
        assert!(wal.read_pending().unwrap().is_none());

        // Write a batch.
        let mut batch = WriteBatch::new();
        batch.put(CF_ACCOUNTS, b"hello", b"world").unwrap();
        wal.write_batch(&batch).unwrap();

        // Read back.
        let ops = wal.read_pending().unwrap().expect("should have entry");
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            WalOp::Put { key, value, .. } => {
                assert_eq!(key, b"hello");
                assert_eq!(value, b"world");
            }
            _ => panic!("expected put"),
        }

        // Clear WAL.
        wal.clear().unwrap();
        assert!(wal.read_pending().unwrap().is_none());
    }

    #[test]
    fn wal_survives_reopen() {
        let dir = tempfile::tempdir().expect("tmpdir");

        // Write entry.
        {
            let mut wal = WriteAheadLog::open(dir.path()).expect("open");
            let mut batch = WriteBatch::new();
            batch.put(CF_ACCOUNTS, b"persist", b"data").unwrap();
            wal.write_batch(&batch).unwrap();
        }

        // Reopen and read.
        {
            let mut wal = WriteAheadLog::open(dir.path()).expect("reopen");
            let ops = wal.read_pending().unwrap().expect("should persist");
            assert_eq!(ops.len(), 1);
        }
    }

    #[test]
    fn large_batch_roundtrip() {
        let mut batch = WriteBatch::new();
        for i in 0u32..500 {
            batch
                .put(CF_ACCOUNTS, &i.to_le_bytes(), &vec![0xAB; 1024])
                .unwrap();
        }

        let encoded = encode_wal_entry(&batch);
        let ops = parse_wal_entry(&encoded).unwrap().expect("should parse");
        assert_eq!(ops.len(), 500);
    }
}
