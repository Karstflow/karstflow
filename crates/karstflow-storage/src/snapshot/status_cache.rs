//! Solana snapshot status cache parser.
//!
//! Parses the `snapshots/status_cache` file from a Solana snapshot archive.
//! The status cache records recently processed transactions for deduplication.
//!
//! Binary format (bincode 1.x with fixint encoding):
//! ```text
//! Vec<SlotDelta>
//!   SlotDelta = (slot: u64, is_root: bool, HashMap<blockhash, entries>)
//!     entries = (key_index: usize, Vec<(key_slice: [u8; 20], Result<(), TransactionError>)>)
//! ```
//!
//! The key_slice is the first 20 bytes of the transaction message hash,
//! which is sufficient for deduplication (collision probability ~2^-160).

use crate::StorageError;

/// Size of the transaction hash prefix stored in status cache entries.
const KEY_SLICE_BYTES: usize = 20;

/// Maximum number of slot deltas allowed in a status cache.
/// Matches Firedancer's FD_SLOT_DELTA_MAX_ENTRIES.
const MAX_SLOT_DELTAS: u64 = 300;

/// Parsed status cache entry.
///
/// Each entry records that a transaction (identified by message hash prefix)
/// was processed at a given slot under a specific blockhash.
#[derive(Debug, Clone)]
pub struct StatusCacheEntry {
    /// Slot where the transaction was processed.
    pub slot: u64,
    /// Recent blockhash referenced by the transaction.
    pub blockhash: [u8; 32],
    /// First 20 bytes of the transaction message hash.
    pub message_hash: [u8; KEY_SLICE_BYTES],
    /// Whether the transaction succeeded (true) or failed (false).
    pub succeeded: bool,
}

/// Result of parsing a status cache.
#[derive(Debug, Clone)]
pub struct StatusCacheParseResult {
    /// All parsed entries.
    pub entries: Vec<StatusCacheEntry>,
    /// Number of slot deltas processed.
    pub slot_deltas_processed: u64,
    /// Number of entries that failed to parse (skipped).
    pub parse_errors: u64,
}

/// Parse the status cache from raw bincode data.
///
/// The data comes from `snapshots/status_cache` in a Solana snapshot archive.
/// Uses fixint bincode encoding (same as Solana's serializer).
pub fn parse_status_cache(data: &[u8]) -> Result<StatusCacheParseResult, StorageError> {
    let mut reader = CacheReader::new(data);
    let mut entries = Vec::new();
    let mut slot_deltas_processed = 0u64;

    // Read Vec<SlotDelta> length.
    let num_deltas = reader.read_u64()?;
    if num_deltas > MAX_SLOT_DELTAS {
        return Err(storage_error(format!(
            "too many slot deltas: {} (max {})",
            num_deltas, MAX_SLOT_DELTAS
        )));
    }

    for _ in 0..num_deltas {
        // SlotDelta = (slot, is_root, HashMap<Hash, (usize, Vec<(KeySlice, Result)>)>)
        let slot = reader.read_u64()?;
        let _is_root = reader.read_u8()?;

        // Read HashMap length.
        let num_blockhashes = reader.read_u64()?;

        for _ in 0..num_blockhashes {
            // Read blockhash (32 bytes).
            let blockhash = reader.read_bytes_32()?;

            // Read key_index (usize = u64 on 64-bit).
            let _key_index = reader.read_u64()?;

            // Read Vec<(KeySlice, Result<(), TransactionError>)> length.
            let num_txns = reader.read_u64()?;

            for _ in 0..num_txns {
                // Read key_slice (20 bytes).
                let message_hash = reader.read_bytes_20()?;

                // Read and skip Result<(), TransactionError>.
                let succeeded = skip_transaction_result(&mut reader)?;

                entries.push(StatusCacheEntry {
                    slot,
                    blockhash,
                    message_hash,
                    succeeded,
                });
            }
        }

        slot_deltas_processed += 1;
    }

    Ok(StatusCacheParseResult {
        entries,
        slot_deltas_processed,
        parse_errors: 0,
    })
}

/// Skip past a `Result<(), TransactionError>` in the bincode stream.
///
/// Returns true if the result was Ok, false if Err.
///
/// The encoding is:
/// - Ok(()): u32(0)
/// - Err(e): u32(1) + TransactionError encoding
fn skip_transaction_result(reader: &mut CacheReader) -> Result<bool, StorageError> {
    let discriminant = reader.read_u32()?;
    match discriminant {
        0 => Ok(true), // Ok(())
        1 => {
            // Err(TransactionError)
            skip_transaction_error(reader)?;
            Ok(false)
        }
        _ => Err(storage_error(format!(
            "invalid Result discriminant: {}",
            discriminant
        ))),
    }
}

/// Skip a serialized TransactionError enum variant.
///
/// Most variants are unit types (just the u32 discriminant).
/// Special cases with inner data:
/// - 8: InstructionError(u8, InstructionError)
/// - 30: DuplicateInstruction(u8)
/// - 31: InsufficientFundsForRent { account_index: u8 }
/// - 35: ProgramExecutionTemporarilyRestricted { account_index: u8 }
fn skip_transaction_error(reader: &mut CacheReader) -> Result<(), StorageError> {
    let variant = reader.read_u32()?;
    match variant {
        // InstructionError(u8, InstructionError)
        8 => {
            reader.skip(1)?; // instruction index (u8)
            skip_instruction_error(reader)?;
        }
        // DuplicateInstruction(u8)
        // InsufficientFundsForRent { account_index: u8 }
        // ProgramExecutionTemporarilyRestricted { account_index: u8 }
        30 | 31 | 35 => {
            reader.skip(1)?; // u8 field
        }
        // All other variants are unit types — no additional data.
        _ => {}
    }
    Ok(())
}

/// Skip a serialized InstructionError enum variant.
///
/// Most variants are unit types.
/// Special cases:
/// - 25: Custom(u32)
/// - 44: BorshIoError(String)
fn skip_instruction_error(reader: &mut CacheReader) -> Result<(), StorageError> {
    let variant = reader.read_u32()?;
    match variant {
        // Custom(u32)
        25 => {
            reader.skip(4)?;
        }
        // BorshIoError(String) — bincode String = u64 length + bytes
        44 => {
            let len = reader.read_u64()?;
            if len > 10_000 {
                return Err(storage_error(format!(
                    "BorshIoError string too long: {}",
                    len
                )));
            }
            reader.skip(len as usize)?;
        }
        // All other variants are unit types.
        _ => {}
    }
    Ok(())
}

/// Lightweight positional reader for bincode fixint-encoded data.
struct CacheReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> CacheReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn ensure(&self, n: usize) -> Result<(), StorageError> {
        if self.pos + n > self.data.len() {
            Err(storage_error(format!(
                "unexpected end of status cache data at offset {} (need {} more bytes, have {})",
                self.pos,
                n,
                self.data.len() - self.pos
            )))
        } else {
            Ok(())
        }
    }

    fn read_u8(&mut self) -> Result<u8, StorageError> {
        self.ensure(1)?;
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn read_u32(&mut self) -> Result<u32, StorageError> {
        self.ensure(4)?;
        let v = u32::from_le_bytes(self.data[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }

    fn read_u64(&mut self) -> Result<u64, StorageError> {
        self.ensure(8)?;
        let v = u64::from_le_bytes(self.data[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok(v)
    }

    fn read_bytes_20(&mut self) -> Result<[u8; KEY_SLICE_BYTES], StorageError> {
        self.ensure(KEY_SLICE_BYTES)?;
        let mut buf = [0u8; KEY_SLICE_BYTES];
        buf.copy_from_slice(&self.data[self.pos..self.pos + KEY_SLICE_BYTES]);
        self.pos += KEY_SLICE_BYTES;
        Ok(buf)
    }

    fn read_bytes_32(&mut self) -> Result<[u8; 32], StorageError> {
        self.ensure(32)?;
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&self.data[self.pos..self.pos + 32]);
        self.pos += 32;
        Ok(buf)
    }

    fn skip(&mut self, n: usize) -> Result<(), StorageError> {
        self.ensure(n)?;
        self.pos += n;
        Ok(())
    }
}

fn storage_error(details: String) -> StorageError {
    StorageError::AccountDatabaseError { details }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to write bincode fixint-encoded status cache test data.
    struct CacheWriter {
        buf: Vec<u8>,
    }

    impl CacheWriter {
        fn new() -> Self {
            Self { buf: Vec::new() }
        }

        fn write_u8(&mut self, v: u8) {
            self.buf.push(v);
        }

        fn write_u32(&mut self, v: u32) {
            self.buf.extend_from_slice(&v.to_le_bytes());
        }

        fn write_u64(&mut self, v: u64) {
            self.buf.extend_from_slice(&v.to_le_bytes());
        }

        fn write_bytes(&mut self, data: &[u8]) {
            self.buf.extend_from_slice(data);
        }

        /// Write Result::Ok(())
        fn write_ok_result(&mut self) {
            self.write_u32(0);
        }

        /// Write Result::Err with a unit TransactionError variant.
        fn write_err_unit(&mut self, variant: u32) {
            self.write_u32(1); // Err discriminant
            self.write_u32(variant); // TransactionError variant
        }

        /// Write Result::Err(InstructionError(idx, unit_variant))
        fn write_err_instruction_error_unit(&mut self, instr_idx: u8, ie_variant: u32) {
            self.write_u32(1); // Err discriminant
            self.write_u32(8); // InstructionError variant
            self.write_u8(instr_idx);
            self.write_u32(ie_variant); // InstructionError variant (unit)
        }

        /// Write Result::Err(InstructionError(idx, Custom(code)))
        fn write_err_instruction_error_custom(&mut self, instr_idx: u8, code: u32) {
            self.write_u32(1); // Err discriminant
            self.write_u32(8); // InstructionError variant
            self.write_u8(instr_idx);
            self.write_u32(25); // Custom variant
            self.write_u32(code);
        }

        /// Write Result::Err(InstructionError(idx, BorshIoError(msg)))
        fn write_err_instruction_error_borsh(&mut self, instr_idx: u8, msg: &str) {
            self.write_u32(1); // Err
            self.write_u32(8); // InstructionError
            self.write_u8(instr_idx);
            self.write_u32(44); // BorshIoError
            self.write_u64(msg.len() as u64);
            self.write_bytes(msg.as_bytes());
        }

        /// Write Result::Err(DuplicateInstruction(idx))
        fn write_err_duplicate_instruction(&mut self, idx: u8) {
            self.write_u32(1); // Err
            self.write_u32(30); // DuplicateInstruction
            self.write_u8(idx);
        }

        /// Write Result::Err(InsufficientFundsForRent { account_index })
        fn write_err_insufficient_funds_for_rent(&mut self, idx: u8) {
            self.write_u32(1); // Err
            self.write_u32(31); // InsufficientFundsForRent
            self.write_u8(idx);
        }

        fn finish(self) -> Vec<u8> {
            self.buf
        }
    }

    fn make_blockhash(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn make_message_hash(seed: u8) -> [u8; 20] {
        [seed; 20]
    }

    #[test]
    fn parse_empty_status_cache() {
        let mut w = CacheWriter::new();
        w.write_u64(0); // zero slot deltas

        let result = parse_status_cache(&w.finish()).unwrap();
        assert_eq!(result.entries.len(), 0);
        assert_eq!(result.slot_deltas_processed, 0);
    }

    #[test]
    fn parse_single_success_entry() {
        let mut w = CacheWriter::new();
        w.write_u64(1); // 1 slot delta

        // SlotDelta
        w.write_u64(100); // slot
        w.write_u8(1); // is_root = true

        // HashMap<Hash, (usize, Vec<...>)>
        w.write_u64(1); // 1 blockhash entry

        // Blockhash entry
        w.write_bytes(&make_blockhash(0xAA));
        w.write_u64(0); // key_index

        // Vec<(KeySlice, Result)>
        w.write_u64(1); // 1 transaction
        w.write_bytes(&make_message_hash(0xBB));
        w.write_ok_result();

        let result = parse_status_cache(&w.finish()).unwrap();
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.slot_deltas_processed, 1);

        let entry = &result.entries[0];
        assert_eq!(entry.slot, 100);
        assert_eq!(entry.blockhash, make_blockhash(0xAA));
        assert_eq!(entry.message_hash, make_message_hash(0xBB));
        assert!(entry.succeeded);
    }

    #[test]
    fn parse_failed_transaction_unit_error() {
        let mut w = CacheWriter::new();
        w.write_u64(1);
        w.write_u64(200);
        w.write_u8(1);
        w.write_u64(1); // 1 blockhash
        w.write_bytes(&make_blockhash(0x11));
        w.write_u64(0);
        w.write_u64(1); // 1 txn
        w.write_bytes(&make_message_hash(0x22));
        w.write_err_unit(6); // AlreadyProcessed

        let result = parse_status_cache(&w.finish()).unwrap();
        assert_eq!(result.entries.len(), 1);
        assert!(!result.entries[0].succeeded);
    }

    #[test]
    fn parse_instruction_error_unit() {
        let mut w = CacheWriter::new();
        w.write_u64(1);
        w.write_u64(300);
        w.write_u8(1);
        w.write_u64(1);
        w.write_bytes(&make_blockhash(0x33));
        w.write_u64(0);
        w.write_u64(1);
        w.write_bytes(&make_message_hash(0x44));
        w.write_err_instruction_error_unit(2, 5); // InstructionError(2, InsufficientFunds)

        let result = parse_status_cache(&w.finish()).unwrap();
        assert_eq!(result.entries.len(), 1);
        assert!(!result.entries[0].succeeded);
    }

    #[test]
    fn parse_instruction_error_custom() {
        let mut w = CacheWriter::new();
        w.write_u64(1);
        w.write_u64(400);
        w.write_u8(1);
        w.write_u64(1);
        w.write_bytes(&make_blockhash(0x55));
        w.write_u64(0);
        w.write_u64(1);
        w.write_bytes(&make_message_hash(0x66));
        w.write_err_instruction_error_custom(0, 42);

        let result = parse_status_cache(&w.finish()).unwrap();
        assert_eq!(result.entries.len(), 1);
        assert!(!result.entries[0].succeeded);
    }

    #[test]
    fn parse_instruction_error_borsh() {
        let mut w = CacheWriter::new();
        w.write_u64(1);
        w.write_u64(500);
        w.write_u8(1);
        w.write_u64(1);
        w.write_bytes(&make_blockhash(0x77));
        w.write_u64(0);
        w.write_u64(1);
        w.write_bytes(&make_message_hash(0x88));
        w.write_err_instruction_error_borsh(1, "some io error");

        let result = parse_status_cache(&w.finish()).unwrap();
        assert_eq!(result.entries.len(), 1);
        assert!(!result.entries[0].succeeded);
    }

    #[test]
    fn parse_duplicate_instruction_error() {
        let mut w = CacheWriter::new();
        w.write_u64(1);
        w.write_u64(600);
        w.write_u8(1);
        w.write_u64(1);
        w.write_bytes(&make_blockhash(0x99));
        w.write_u64(0);
        w.write_u64(1);
        w.write_bytes(&make_message_hash(0xAA));
        w.write_err_duplicate_instruction(3);

        let result = parse_status_cache(&w.finish()).unwrap();
        assert_eq!(result.entries.len(), 1);
        assert!(!result.entries[0].succeeded);
    }

    #[test]
    fn parse_insufficient_funds_for_rent() {
        let mut w = CacheWriter::new();
        w.write_u64(1);
        w.write_u64(700);
        w.write_u8(1);
        w.write_u64(1);
        w.write_bytes(&make_blockhash(0xCC));
        w.write_u64(0);
        w.write_u64(1);
        w.write_bytes(&make_message_hash(0xDD));
        w.write_err_insufficient_funds_for_rent(5);

        let result = parse_status_cache(&w.finish()).unwrap();
        assert_eq!(result.entries.len(), 1);
        assert!(!result.entries[0].succeeded);
    }

    #[test]
    fn parse_multiple_slot_deltas() {
        let mut w = CacheWriter::new();
        w.write_u64(2); // 2 slot deltas

        // Delta 1: slot 100, 1 blockhash, 2 txns
        w.write_u64(100);
        w.write_u8(1);
        w.write_u64(1);
        w.write_bytes(&make_blockhash(0x01));
        w.write_u64(0);
        w.write_u64(2);
        // txn 1: success
        w.write_bytes(&make_message_hash(0x10));
        w.write_ok_result();
        // txn 2: failure
        w.write_bytes(&make_message_hash(0x20));
        w.write_err_unit(2); // AccountNotFound

        // Delta 2: slot 200, 1 blockhash, 1 txn
        w.write_u64(200);
        w.write_u8(1);
        w.write_u64(1);
        w.write_bytes(&make_blockhash(0x02));
        w.write_u64(0);
        w.write_u64(1);
        w.write_bytes(&make_message_hash(0x30));
        w.write_ok_result();

        let result = parse_status_cache(&w.finish()).unwrap();
        assert_eq!(result.entries.len(), 3);
        assert_eq!(result.slot_deltas_processed, 2);

        assert_eq!(result.entries[0].slot, 100);
        assert!(result.entries[0].succeeded);

        assert_eq!(result.entries[1].slot, 100);
        assert!(!result.entries[1].succeeded);

        assert_eq!(result.entries[2].slot, 200);
        assert!(result.entries[2].succeeded);
    }

    #[test]
    fn parse_multiple_blockhashes_per_slot() {
        let mut w = CacheWriter::new();
        w.write_u64(1);
        w.write_u64(42);
        w.write_u8(1);
        w.write_u64(2); // 2 blockhash entries

        // Blockhash 1
        w.write_bytes(&make_blockhash(0xAA));
        w.write_u64(0);
        w.write_u64(1);
        w.write_bytes(&make_message_hash(0x01));
        w.write_ok_result();

        // Blockhash 2
        w.write_bytes(&make_blockhash(0xBB));
        w.write_u64(1);
        w.write_u64(1);
        w.write_bytes(&make_message_hash(0x02));
        w.write_ok_result();

        let result = parse_status_cache(&w.finish()).unwrap();
        assert_eq!(result.entries.len(), 2);
        assert_eq!(result.entries[0].blockhash, make_blockhash(0xAA));
        assert_eq!(result.entries[1].blockhash, make_blockhash(0xBB));
    }

    #[test]
    fn parse_empty_blockhash_map() {
        let mut w = CacheWriter::new();
        w.write_u64(1);
        w.write_u64(99);
        w.write_u8(1);
        w.write_u64(0); // no blockhash entries

        let result = parse_status_cache(&w.finish()).unwrap();
        assert_eq!(result.entries.len(), 0);
        assert_eq!(result.slot_deltas_processed, 1);
    }

    #[test]
    fn parse_empty_transaction_list() {
        let mut w = CacheWriter::new();
        w.write_u64(1);
        w.write_u64(50);
        w.write_u8(1);
        w.write_u64(1);
        w.write_bytes(&make_blockhash(0xFF));
        w.write_u64(0);
        w.write_u64(0); // no transactions

        let result = parse_status_cache(&w.finish()).unwrap();
        assert_eq!(result.entries.len(), 0);
        assert_eq!(result.slot_deltas_processed, 1);
    }

    #[test]
    fn reject_too_many_slot_deltas() {
        let mut w = CacheWriter::new();
        w.write_u64(MAX_SLOT_DELTAS + 1);

        let err = parse_status_cache(&w.finish());
        assert!(err.is_err());
    }

    #[test]
    fn reject_truncated_data() {
        // Only write the vector length, then truncate.
        let mut w = CacheWriter::new();
        w.write_u64(1);
        // Missing slot delta fields.

        let err = parse_status_cache(&w.finish());
        assert!(err.is_err());
    }

    #[test]
    fn mixed_error_types_in_sequence() {
        let mut w = CacheWriter::new();
        w.write_u64(1);
        w.write_u64(1000);
        w.write_u8(1);
        w.write_u64(1);
        w.write_bytes(&make_blockhash(0x42));
        w.write_u64(0);
        w.write_u64(5); // 5 transactions with different error types

        // 1: Ok
        w.write_bytes(&make_message_hash(0x01));
        w.write_ok_result();

        // 2: Err(AccountNotFound) — unit variant
        w.write_bytes(&make_message_hash(0x02));
        w.write_err_unit(2);

        // 3: Err(InstructionError(0, Custom(99)))
        w.write_bytes(&make_message_hash(0x03));
        w.write_err_instruction_error_custom(0, 99);

        // 4: Err(InstructionError(1, BorshIoError("test")))
        w.write_bytes(&make_message_hash(0x04));
        w.write_err_instruction_error_borsh(1, "test");

        // 5: Err(DuplicateInstruction(7))
        w.write_bytes(&make_message_hash(0x05));
        w.write_err_duplicate_instruction(7);

        let result = parse_status_cache(&w.finish()).unwrap();
        assert_eq!(result.entries.len(), 5);
        assert!(result.entries[0].succeeded);
        assert!(!result.entries[1].succeeded);
        assert!(!result.entries[2].succeeded);
        assert!(!result.entries[3].succeeded);
        assert!(!result.entries[4].succeeded);

        // Verify message hashes are preserved correctly.
        assert_eq!(result.entries[0].message_hash, make_message_hash(0x01));
        assert_eq!(result.entries[4].message_hash, make_message_hash(0x05));
    }
}
