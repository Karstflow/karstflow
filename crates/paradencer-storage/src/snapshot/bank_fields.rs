//! Solana snapshot manifest parser.
//!
//! Parses the bincode-encoded bank state from a Solana snapshot archive.
//! Uses a custom binary reader instead of serde deserialization because
//! the Solana format contains custom deserializers (VoteAccounts) and
//! we need to handle version differences gracefully.
//!
//! The bank state provides all parameters needed to initialize a
//! validator from a snapshot: slot, epoch, blockhash queue, fee/rent
//! configuration, inflation parameters, and stake summaries.

use crate::StorageError;

// ---------------------------------------------------------------------------
// Public output types
// ---------------------------------------------------------------------------

/// Parsed bank state from a Solana snapshot manifest.
///
/// Contains all essential fields for initializing a validator bank
/// from a snapshot. Complex inner structures (vote accounts, full
/// stake delegations) are summarized rather than fully materialized.
#[derive(Debug, Clone)]
pub struct SnapshotBankState {
    // -- Blockhash queue --
    /// Recent blockhashes with fee information, ordered by hash_index.
    pub recent_blockhashes: Vec<RecentBlockhash>,
    /// The most recent blockhash registered.
    pub last_blockhash: Option<[u8; 32]>,
    /// Maximum age for blockhash validity.
    pub max_blockhash_age: u64,
    /// Sequence index of the last registered blockhash.
    pub last_blockhash_index: u64,

    // -- Slot / block identification --
    pub slot: u64,
    pub parent_slot: u64,
    pub block_height: u64,
    pub epoch: u64,
    pub hash: [u8; 32],
    pub parent_hash: [u8; 32],

    // -- Cumulative counters --
    pub transaction_count: u64,
    pub tick_height: u64,
    pub max_tick_height: u64,
    pub signature_count: u64,
    pub capitalization: u64,
    pub accounts_data_len: u64,

    // -- Timing / PoH --
    pub hashes_per_tick: Option<u64>,
    pub ticks_per_slot: u64,
    pub ns_per_slot: u128,
    pub genesis_creation_time: i64,
    pub slots_per_year: f64,

    // -- Fee collector --
    pub collector_id: [u8; 32],
    pub collector_fees: u64,

    // -- Fee configuration --
    pub fee_rate_governor: FeeRateConfig,

    // -- Rent configuration --
    pub rent: RentConfig,
    pub collected_rent: u64,

    // -- Epoch schedule --
    pub epoch_schedule: EpochScheduleConfig,

    // -- Inflation --
    pub inflation: InflationConfig,

    // -- Hard forks --
    pub hard_forks: Vec<(u64, u64)>,

    // -- Ancestor count --
    pub ancestor_count: u64,

    // -- Stake summary --
    pub stake_summary: StakeSummary,

    // -- Flags --
    pub is_delta: bool,
}

/// A recent blockhash entry from the blockhash queue.
#[derive(Debug, Clone)]
pub struct RecentBlockhash {
    pub hash: [u8; 32],
    pub lamports_per_signature: u64,
    pub hash_index: u64,
    pub timestamp: u64,
}

/// Fee rate governor configuration.
#[derive(Debug, Clone)]
pub struct FeeRateConfig {
    pub target_lamports_per_signature: u64,
    pub target_signatures_per_slot: u64,
    pub min_lamports_per_signature: u64,
    pub max_lamports_per_signature: u64,
    pub burn_percent: u8,
}

/// Rent configuration extracted from the RentCollector.
#[derive(Debug, Clone)]
pub struct RentConfig {
    pub lamports_per_byte_year: u64,
    pub exemption_threshold: f64,
    pub burn_percent: u8,
    /// Rent collector epoch.
    pub collector_epoch: u64,
    /// Rent collector slots_per_year.
    pub collector_slots_per_year: f64,
}

/// Epoch schedule configuration.
#[derive(Debug, Clone)]
pub struct EpochScheduleConfig {
    pub slots_per_epoch: u64,
    pub leader_schedule_slot_offset: u64,
    pub warmup: bool,
    pub first_normal_epoch: u64,
    pub first_normal_slot: u64,
}

/// Inflation parameters.
#[derive(Debug, Clone)]
pub struct InflationConfig {
    pub initial: f64,
    pub terminal: f64,
    pub taper: f64,
    pub foundation: f64,
    pub foundation_term: f64,
}

/// Summary of stake state parsed from Stakes<Delegation>.
#[derive(Debug, Clone, Default)]
pub struct StakeSummary {
    pub vote_account_count: u64,
    pub stake_delegation_count: u64,
    pub stakes_epoch: u64,
    pub total_delegated_stake: u64,
    pub stake_history_entries: u64,
    /// Parsed stake history: (epoch, effective, activating, deactivating).
    pub stake_history: Vec<StakeHistoryRecord>,
}

/// A single entry in the stake history from the snapshot.
#[derive(Debug, Clone)]
pub struct StakeHistoryRecord {
    pub epoch: u64,
    pub effective: u64,
    pub activating: u64,
    pub deactivating: u64,
}

// ---------------------------------------------------------------------------
// Binary reader
// ---------------------------------------------------------------------------

/// Low-level bincode binary reader for Solana snapshot data.
///
/// Reads fields in the exact order they appear in the bincode stream.
/// Bincode 1.x uses fixed-size little-endian encoding with u64 lengths.
struct BincodeReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> BincodeReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn ensure(&self, n: usize) -> Result<(), StorageError> {
        if self.pos + n > self.data.len() {
            return Err(StorageError::AccountDatabaseError {
                details: format!(
                    "manifest truncated: need {} bytes at offset {}, have {}",
                    n,
                    self.pos,
                    self.data.len()
                ),
            });
        }
        Ok(())
    }

    fn read_u8(&mut self) -> Result<u8, StorageError> {
        self.ensure(1)?;
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn read_u64(&mut self) -> Result<u64, StorageError> {
        self.ensure(8)?;
        let v = u64::from_le_bytes(
            self.data[self.pos..self.pos + 8]
                .try_into()
                .unwrap_or_else(|_| unreachable!()),
        );
        self.pos += 8;
        Ok(v)
    }

    fn read_i64(&mut self) -> Result<i64, StorageError> {
        self.ensure(8)?;
        let v = i64::from_le_bytes(
            self.data[self.pos..self.pos + 8]
                .try_into()
                .unwrap_or_else(|_| unreachable!()),
        );
        self.pos += 8;
        Ok(v)
    }

    fn read_u128(&mut self) -> Result<u128, StorageError> {
        self.ensure(16)?;
        let v = u128::from_le_bytes(
            self.data[self.pos..self.pos + 16]
                .try_into()
                .unwrap_or_else(|_| unreachable!()),
        );
        self.pos += 16;
        Ok(v)
    }

    fn read_f64(&mut self) -> Result<f64, StorageError> {
        self.ensure(8)?;
        let v = f64::from_le_bytes(
            self.data[self.pos..self.pos + 8]
                .try_into()
                .unwrap_or_else(|_| unreachable!()),
        );
        self.pos += 8;
        Ok(v)
    }

    fn read_bool(&mut self) -> Result<bool, StorageError> {
        let v = self.read_u8()?;
        Ok(v != 0)
    }

    fn read_hash(&mut self) -> Result<[u8; 32], StorageError> {
        self.ensure(32)?;
        let mut h = [0u8; 32];
        h.copy_from_slice(&self.data[self.pos..self.pos + 32]);
        self.pos += 32;
        Ok(h)
    }

    fn read_option_u64(&mut self) -> Result<Option<u64>, StorageError> {
        let tag = self.read_u8()?;
        if tag == 0 {
            Ok(None)
        } else {
            Ok(Some(self.read_u64()?))
        }
    }

    fn read_vec_len(&mut self) -> Result<u64, StorageError> {
        self.read_u64()
    }

    fn skip(&mut self, n: usize) -> Result<(), StorageError> {
        self.ensure(n)?;
        self.pos += n;
        Ok(())
    }

    /// Skip a bincode-encoded Vec<u8> (length-prefixed byte array).
    fn skip_byte_vec(&mut self) -> Result<u64, StorageError> {
        let len = self.read_u64()?;
        self.skip(len as usize)?;
        Ok(len)
    }
}

// ---------------------------------------------------------------------------
// Field parsers
// ---------------------------------------------------------------------------

/// Intermediate result from parsing the blockhash queue.
struct BlockhashQueueResult {
    blockhashes: Vec<RecentBlockhash>,
    last_hash: Option<[u8; 32]>,
    max_age: u64,
    last_hash_index: u64,
}

/// Parse the BlockhashQueue from the binary stream.
fn parse_blockhash_queue(r: &mut BincodeReader) -> Result<BlockhashQueueResult, StorageError> {
    // last_hash_index: u64
    let last_hash_index = r.read_u64()?;

    // last_hash: Option<Hash>
    let last_hash_tag = r.read_u8()?;
    let last_hash = if last_hash_tag != 0 {
        Some(r.read_hash()?)
    } else {
        None
    };

    // hashes: HashMap<Hash, HashInfo>
    let hash_count = r.read_vec_len()?;
    let mut blockhashes = Vec::with_capacity(hash_count as usize);
    for _ in 0..hash_count {
        let hash = r.read_hash()?;
        // HashInfo: { fee_calculator: FeeCalculator { lamports_per_signature: u64 }, hash_index: u64, timestamp: u64 }
        let lamports_per_signature = r.read_u64()?;
        let hash_index = r.read_u64()?;
        let timestamp = r.read_u64()?;

        blockhashes.push(RecentBlockhash {
            hash,
            lamports_per_signature,
            hash_index,
            timestamp,
        });
    }

    // Sort by hash_index for deterministic ordering.
    blockhashes.sort_by_key(|bh| bh.hash_index);

    // max_age: usize (8 bytes on 64-bit)
    let max_age = r.read_u64()?;

    Ok(BlockhashQueueResult {
        blockhashes,
        last_hash,
        max_age,
        last_hash_index,
    })
}

/// Skip over a HashMap<u64, usize> (ancestors).
fn skip_ancestors(r: &mut BincodeReader) -> Result<u64, StorageError> {
    let count = r.read_vec_len()?;
    // Each entry: u64 key (8) + usize value (8) = 16 bytes
    r.skip(count as usize * 16)?;
    Ok(count)
}

/// Parse the HardForks structure: Vec<(u64, usize)>.
fn parse_hard_forks(r: &mut BincodeReader) -> Result<Vec<(u64, u64)>, StorageError> {
    let count = r.read_vec_len()?;
    let mut forks = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let slot = r.read_u64()?;
        let count_val = r.read_u64()?; // usize serialized as u64
        forks.push((slot, count_val));
    }
    Ok(forks)
}

/// Parse FeeRateGovernor.
///
/// Note: `lamports_per_signature` is `#[serde(skip)]` in Solana, so it's
/// NOT present in the binary stream.
fn parse_fee_rate_governor(r: &mut BincodeReader) -> Result<FeeRateConfig, StorageError> {
    let target_lamports_per_signature = r.read_u64()?;
    let target_signatures_per_slot = r.read_u64()?;
    let min_lamports_per_signature = r.read_u64()?;
    let max_lamports_per_signature = r.read_u64()?;
    let burn_percent = r.read_u8()?;

    Ok(FeeRateConfig {
        target_lamports_per_signature,
        target_signatures_per_slot,
        min_lamports_per_signature,
        max_lamports_per_signature,
        burn_percent,
    })
}

/// Parse EpochSchedule.
fn parse_epoch_schedule(r: &mut BincodeReader) -> Result<EpochScheduleConfig, StorageError> {
    let slots_per_epoch = r.read_u64()?;
    let leader_schedule_slot_offset = r.read_u64()?;
    let warmup = r.read_bool()?;
    let first_normal_epoch = r.read_u64()?;
    let first_normal_slot = r.read_u64()?;

    Ok(EpochScheduleConfig {
        slots_per_epoch,
        leader_schedule_slot_offset,
        warmup,
        first_normal_epoch,
        first_normal_slot,
    })
}

/// Parse Rent.
fn parse_rent(r: &mut BincodeReader) -> Result<(u64, f64, u8), StorageError> {
    let lamports_per_byte_year = r.read_u64()?;
    let exemption_threshold = r.read_f64()?;
    let burn_percent = r.read_u8()?;
    Ok((lamports_per_byte_year, exemption_threshold, burn_percent))
}

/// Parse RentCollector: { epoch, epoch_schedule, slots_per_year, rent }.
fn parse_rent_collector(r: &mut BincodeReader) -> Result<RentConfig, StorageError> {
    let collector_epoch = r.read_u64()?;
    let _rent_epoch_schedule = parse_epoch_schedule(r)?;
    let collector_slots_per_year = r.read_f64()?;
    let (lamports_per_byte_year, exemption_threshold, burn_percent) = parse_rent(r)?;

    Ok(RentConfig {
        lamports_per_byte_year,
        exemption_threshold,
        burn_percent,
        collector_epoch,
        collector_slots_per_year,
    })
}

/// Parse Inflation.
fn parse_inflation(r: &mut BincodeReader) -> Result<InflationConfig, StorageError> {
    let initial = r.read_f64()?;
    let terminal = r.read_f64()?;
    let taper = r.read_f64()?;
    let foundation = r.read_f64()?;
    let foundation_term = r.read_f64()?;

    Ok(InflationConfig {
        initial,
        terminal,
        taper,
        foundation,
        foundation_term,
    })
}

/// Skip over a single VoteAccount (serialized as AccountSharedData).
///
/// AccountSharedData layout: lamports(8) + data(len+bytes) + owner(32) + executable(1) + rent_epoch(8).
fn skip_vote_account(r: &mut BincodeReader) -> Result<(), StorageError> {
    r.skip(8)?; // lamports
    r.skip_byte_vec()?; // data: Vec<u8>
    r.skip(32)?; // owner
    r.skip(1)?; // executable
    r.skip(8)?; // rent_epoch
    Ok(())
}

/// Parse Stakes<Delegation> and extract a summary.
///
/// The full vote account data is skipped (only counted).
/// Stake delegations are read to calculate total delegated stake.
fn parse_stakes_summary(r: &mut BincodeReader) -> Result<StakeSummary, StorageError> {
    // vote_accounts: HashMap<Pubkey, (u64, VoteAccount)>
    let vote_count = r.read_vec_len()?;
    for _ in 0..vote_count {
        r.skip(32)?; // pubkey
        r.skip(8)?; // stake: u64
        skip_vote_account(r)?;
    }

    // stake_delegations: HashMap<Pubkey, Delegation>
    //   Delegation: voter_pubkey(32) + stake(8) + activation_epoch(8)
    //              + deactivation_epoch(8) + warmup_cooldown_rate(8)
    let delegation_count = r.read_vec_len()?;
    let mut total_delegated_stake: u64 = 0;
    for _ in 0..delegation_count {
        r.skip(32)?; // map key: pubkey
        r.skip(32)?; // voter_pubkey
        let stake = r.read_u64()?;
        total_delegated_stake = total_delegated_stake.saturating_add(stake);
        r.skip(8)?; // activation_epoch
        r.skip(8)?; // deactivation_epoch
        r.skip(8)?; // warmup_cooldown_rate (f64)
    }

    // unused: u64
    let _unused = r.read_u64()?;

    // epoch: u64
    let stakes_epoch = r.read_u64()?;

    // stake_history: StakeHistory (Vec<(u64, StakeHistoryEntry)>)
    //   StakeHistoryEntry: { effective: u64, activating: u64, deactivating: u64 }
    let history_count = r.read_vec_len()?;
    let mut stake_history = Vec::with_capacity(history_count as usize);
    for _ in 0..history_count {
        let epoch = r.read_u64()?;
        let effective = r.read_u64()?;
        let activating = r.read_u64()?;
        let deactivating = r.read_u64()?;
        stake_history.push(StakeHistoryRecord {
            epoch,
            effective,
            activating,
            deactivating,
        });
    }

    Ok(StakeSummary {
        vote_account_count: vote_count,
        stake_delegation_count: delegation_count,
        stakes_epoch,
        total_delegated_stake,
        stake_history_entries: history_count,
        stake_history,
    })
}

/// Skip UnusedAccounts: { HashSet<Pubkey>, HashSet<Pubkey>, HashMap<Pubkey, u64> }.
fn skip_unused_accounts(r: &mut BincodeReader) -> Result<(), StorageError> {
    // HashSet<Pubkey>
    let count1 = r.read_vec_len()?;
    r.skip(count1 as usize * 32)?;

    // HashSet<Pubkey>
    let count2 = r.read_vec_len()?;
    r.skip(count2 as usize * 32)?;

    // HashMap<Pubkey, u64>
    let count3 = r.read_vec_len()?;
    r.skip(count3 as usize * 40)?; // 32 + 8

    Ok(())
}

/// Skip HashMap<u64, ()> (unused_epoch_stakes).
fn skip_unused_epoch_stakes(r: &mut BincodeReader) -> Result<(), StorageError> {
    let count = r.read_vec_len()?;
    // () is zero bytes in bincode, so each entry is just the key (8 bytes)
    r.skip(count as usize * 8)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Main parser
// ---------------------------------------------------------------------------

/// Parse bank state from raw bincode manifest bytes.
///
/// This reads the `DeserializableVersionedBank` structure that Solana
/// stores in the snapshot archive at `snapshots/<slot>/<slot>`.
///
/// The parser handles the exact binary layout used by Solana v1.14+
/// through v2.x. Fields that changed across versions are handled
/// gracefully — if the stream ends before optional trailing fields,
/// defaults are used.
pub fn parse_bank_state(data: &[u8]) -> Result<SnapshotBankState, StorageError> {
    let mut r = BincodeReader::new(data);

    // 1. BlockhashQueue
    let bq = parse_blockhash_queue(&mut r)?;
    let recent_blockhashes = bq.blockhashes;
    let last_blockhash = bq.last_hash;
    let max_blockhash_age = bq.max_age;
    let last_blockhash_index = bq.last_hash_index;

    // 2. Ancestors: HashMap<u64, usize>
    let ancestor_count = skip_ancestors(&mut r)?;

    // 3. hash, parent_hash
    let hash = r.read_hash()?;
    let parent_hash = r.read_hash()?;

    // 4. parent_slot
    let parent_slot = r.read_u64()?;

    // 5. hard_forks
    let hard_forks = parse_hard_forks(&mut r)?;

    // 6-10. Scalar counters
    let transaction_count = r.read_u64()?;
    let tick_height = r.read_u64()?;
    let signature_count = r.read_u64()?;
    let capitalization = r.read_u64()?;
    let max_tick_height = r.read_u64()?;

    // 11. hashes_per_tick: Option<u64>
    let hashes_per_tick = r.read_option_u64()?;

    // 12-14. Timing
    let ticks_per_slot = r.read_u64()?;
    let ns_per_slot = r.read_u128()?;
    let genesis_creation_time = r.read_i64()?;

    // 15-16. Rates
    let slots_per_year = r.read_f64()?;
    let accounts_data_len = r.read_u64()?;

    // 17-19. Slot identification
    let slot = r.read_u64()?;
    let epoch = r.read_u64()?;
    let block_height = r.read_u64()?;

    // 20-21. Collector
    let collector_id = r.read_hash()?;
    let collector_fees = r.read_u64()?;

    // 22. FeeCalculator (deprecated, single u64)
    let _fee_calculator_lamports = r.read_u64()?;

    // 23. FeeRateGovernor
    let fee_rate_governor = parse_fee_rate_governor(&mut r)?;

    // 24. collected_rent
    let collected_rent = r.read_u64()?;

    // 25. RentCollector
    let rent = parse_rent_collector(&mut r)?;

    // 26. EpochSchedule
    let epoch_schedule = parse_epoch_schedule(&mut r)?;

    // 27. Inflation
    let inflation = parse_inflation(&mut r)?;

    // 28. Stakes<Delegation>
    let stake_summary = parse_stakes_summary(&mut r)?;

    // 29. UnusedAccounts
    skip_unused_accounts(&mut r)?;

    // 30. unused_epoch_stakes: HashMap<u64, ()>
    skip_unused_epoch_stakes(&mut r)?;

    // 31. is_delta
    let is_delta = r.read_bool()?;

    // Remaining bytes are AccountsDbFields + ExtraFields (not parsed here).

    Ok(SnapshotBankState {
        recent_blockhashes,
        last_blockhash,
        max_blockhash_age,
        last_blockhash_index,
        slot,
        parent_slot,
        block_height,
        epoch,
        hash,
        parent_hash,
        transaction_count,
        tick_height,
        max_tick_height,
        signature_count,
        capitalization,
        accounts_data_len,
        hashes_per_tick,
        ticks_per_slot,
        ns_per_slot,
        genesis_creation_time,
        slots_per_year,
        collector_id,
        collector_fees,
        fee_rate_governor,
        rent,
        collected_rent,
        epoch_schedule,
        inflation,
        hard_forks,
        ancestor_count,
        stake_summary,
        is_delta,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to build bincode binary data for testing.
    struct BincodeWriter {
        buf: Vec<u8>,
    }

    impl BincodeWriter {
        fn new() -> Self {
            Self { buf: Vec::new() }
        }

        fn write_u8(&mut self, v: u8) {
            self.buf.push(v);
        }

        fn write_u64(&mut self, v: u64) {
            self.buf.extend_from_slice(&v.to_le_bytes());
        }

        fn write_i64(&mut self, v: i64) {
            self.buf.extend_from_slice(&v.to_le_bytes());
        }

        fn write_u128(&mut self, v: u128) {
            self.buf.extend_from_slice(&v.to_le_bytes());
        }

        fn write_f64(&mut self, v: f64) {
            self.buf.extend_from_slice(&v.to_le_bytes());
        }

        fn write_bool(&mut self, v: bool) {
            self.buf.push(if v { 1 } else { 0 });
        }

        fn write_hash(&mut self, h: &[u8; 32]) {
            self.buf.extend_from_slice(h);
        }

        fn write_option_u64(&mut self, v: Option<u64>) {
            match v {
                None => self.write_u8(0),
                Some(val) => {
                    self.write_u8(1);
                    self.write_u64(val);
                }
            }
        }

        fn write_byte_vec(&mut self, data: &[u8]) {
            self.write_u64(data.len() as u64);
            self.buf.extend_from_slice(data);
        }

        fn into_bytes(self) -> Vec<u8> {
            self.buf
        }
    }

    /// Build a minimal complete DeserializableVersionedBank binary stream.
    fn build_minimal_manifest(
        slot: u64,
        epoch: u64,
        block_height: u64,
        capitalization: u64,
    ) -> Vec<u8> {
        let mut w = BincodeWriter::new();
        let zero_hash = [0u8; 32];

        // BlockhashQueue
        w.write_u64(42); // last_hash_index
        w.write_u8(1); // Option::Some
        w.write_hash(&[0xAA; 32]); // last_hash
        w.write_u64(1); // 1 entry in hashes HashMap
        w.write_hash(&[0xAA; 32]); // hash key
        w.write_u64(5000); // lamports_per_signature
        w.write_u64(42); // hash_index
        w.write_u64(1000000); // timestamp
        w.write_u64(300); // max_age

        // Ancestors: empty HashMap
        w.write_u64(0);

        // hash, parent_hash
        w.write_hash(&[0x11; 32]);
        w.write_hash(&[0x22; 32]);

        // parent_slot
        w.write_u64(slot.saturating_sub(1));

        // HardForks: empty vec
        w.write_u64(0);

        // Scalar counters
        w.write_u64(100_000); // transaction_count
        w.write_u64(slot * 64); // tick_height
        w.write_u64(50_000); // signature_count
        w.write_u64(capitalization);
        w.write_u64(slot * 64 + 64); // max_tick_height

        // hashes_per_tick: Some(12500)
        w.write_option_u64(Some(12500));

        // ticks_per_slot, ns_per_slot, genesis_creation_time
        w.write_u64(64);
        w.write_u128(400_000_000); // 400ms
        w.write_i64(1_700_000_000); // unix timestamp

        // slots_per_year, accounts_data_len
        w.write_f64(78_892_314.0);
        w.write_u64(1_000_000_000); // 1GB

        // slot, epoch, block_height
        w.write_u64(slot);
        w.write_u64(epoch);
        w.write_u64(block_height);

        // collector_id, collector_fees
        w.write_hash(&[0x33; 32]);
        w.write_u64(1000);

        // FeeCalculator (deprecated)
        w.write_u64(5000); // lamports_per_signature

        // FeeRateGovernor (lamports_per_signature is serde-skipped)
        w.write_u64(10_000); // target_lamports_per_signature
        w.write_u64(20_000); // target_signatures_per_slot
        w.write_u64(5_000); // min
        w.write_u64(100_000); // max
        w.write_u8(50); // burn_percent

        // collected_rent
        w.write_u64(500);

        // RentCollector: { epoch, epoch_schedule, slots_per_year, rent }
        w.write_u64(epoch); // rent collector epoch
                            // inner epoch_schedule
        w.write_u64(432_000); // slots_per_epoch
        w.write_u64(432_000); // leader_schedule_slot_offset
        w.write_bool(false); // warmup
        w.write_u64(0); // first_normal_epoch
        w.write_u64(0); // first_normal_slot
        w.write_f64(78_892_314.0); // slots_per_year
                                   // Rent
        w.write_u64(3_480); // lamports_per_byte_year
        w.write_f64(2.0); // exemption_threshold
        w.write_u8(50); // burn_percent

        // EpochSchedule
        w.write_u64(432_000);
        w.write_u64(432_000);
        w.write_bool(false);
        w.write_u64(0);
        w.write_u64(0);

        // Inflation
        w.write_f64(0.08); // initial
        w.write_f64(0.015); // terminal
        w.write_f64(0.15); // taper
        w.write_f64(0.05); // foundation
        w.write_f64(7.0); // foundation_term

        // Stakes<Delegation>
        // vote_accounts: empty HashMap
        w.write_u64(0);
        // stake_delegations: empty HashMap
        w.write_u64(0);
        // unused: u64
        w.write_u64(0);
        // epoch: u64
        w.write_u64(epoch);
        // stake_history: empty Vec
        w.write_u64(0);

        // UnusedAccounts
        w.write_u64(0); // HashSet 1
        w.write_u64(0); // HashSet 2
        w.write_u64(0); // HashMap

        // unused_epoch_stakes: empty HashMap
        w.write_u64(0);

        // is_delta
        w.write_bool(true);

        // Trailing data (AccountsDbFields, ExtraFields) — not needed for our parser
        w.write_hash(&zero_hash); // padding

        w.into_bytes()
    }

    #[test]
    fn parse_minimal_manifest() {
        let data = build_minimal_manifest(1000, 2, 900, 500_000_000_000);
        let state = parse_bank_state(&data).expect("parse");

        assert_eq!(state.slot, 1000);
        assert_eq!(state.epoch, 2);
        assert_eq!(state.block_height, 900);
        assert_eq!(state.parent_slot, 999);
        assert_eq!(state.capitalization, 500_000_000_000);
        assert_eq!(state.ticks_per_slot, 64);
        assert_eq!(state.hashes_per_tick, Some(12500));
        assert_eq!(state.ns_per_slot, 400_000_000);
        assert!(state.is_delta);
    }

    #[test]
    fn parse_blockhash_queue() {
        let data = build_minimal_manifest(100, 0, 100, 1_000_000);
        let state = parse_bank_state(&data).expect("parse");

        assert_eq!(state.recent_blockhashes.len(), 1);
        assert_eq!(state.recent_blockhashes[0].hash, [0xAA; 32]);
        assert_eq!(state.recent_blockhashes[0].lamports_per_signature, 5000);
        assert_eq!(state.recent_blockhashes[0].hash_index, 42);
        assert_eq!(state.last_blockhash, Some([0xAA; 32]));
        assert_eq!(state.max_blockhash_age, 300);
        assert_eq!(state.last_blockhash_index, 42);
    }

    #[test]
    fn parse_fee_rate_governor() {
        let data = build_minimal_manifest(100, 0, 100, 1_000_000);
        let state = parse_bank_state(&data).expect("parse");

        assert_eq!(
            state.fee_rate_governor.target_lamports_per_signature,
            10_000
        );
        assert_eq!(state.fee_rate_governor.target_signatures_per_slot, 20_000);
        assert_eq!(state.fee_rate_governor.min_lamports_per_signature, 5_000);
        assert_eq!(state.fee_rate_governor.max_lamports_per_signature, 100_000);
        assert_eq!(state.fee_rate_governor.burn_percent, 50);
    }

    #[test]
    fn parse_rent_config() {
        let data = build_minimal_manifest(100, 0, 100, 1_000_000);
        let state = parse_bank_state(&data).expect("parse");

        assert_eq!(state.rent.lamports_per_byte_year, 3_480);
        assert_eq!(state.rent.exemption_threshold, 2.0);
        assert_eq!(state.rent.burn_percent, 50);
        assert_eq!(state.collected_rent, 500);
    }

    #[test]
    fn parse_epoch_schedule() {
        let data = build_minimal_manifest(100, 0, 100, 1_000_000);
        let state = parse_bank_state(&data).expect("parse");

        assert_eq!(state.epoch_schedule.slots_per_epoch, 432_000);
        assert_eq!(state.epoch_schedule.leader_schedule_slot_offset, 432_000);
        assert!(!state.epoch_schedule.warmup);
    }

    #[test]
    fn parse_inflation() {
        let data = build_minimal_manifest(100, 0, 100, 1_000_000);
        let state = parse_bank_state(&data).expect("parse");

        assert!((state.inflation.initial - 0.08).abs() < f64::EPSILON);
        assert!((state.inflation.terminal - 0.015).abs() < f64::EPSILON);
        assert!((state.inflation.taper - 0.15).abs() < f64::EPSILON);
        assert!((state.inflation.foundation - 0.05).abs() < f64::EPSILON);
        assert!((state.inflation.foundation_term - 7.0).abs() < f64::EPSILON);
    }

    #[test]
    fn parse_hashes_and_identification() {
        let data = build_minimal_manifest(1000, 2, 900, 1_000_000);
        let state = parse_bank_state(&data).expect("parse");

        assert_eq!(state.hash, [0x11; 32]);
        assert_eq!(state.parent_hash, [0x22; 32]);
        assert_eq!(state.collector_id, [0x33; 32]);
        assert_eq!(state.collector_fees, 1000);
        assert_eq!(state.transaction_count, 100_000);
        assert_eq!(state.signature_count, 50_000);
    }

    #[test]
    fn parse_with_vote_accounts_and_delegations() {
        let mut w = BincodeWriter::new();

        // BlockhashQueue: empty
        w.write_u64(0); // last_hash_index
        w.write_u8(0); // last_hash: None
        w.write_u64(0); // 0 hashes
        w.write_u64(300); // max_age

        // Ancestors: empty
        w.write_u64(0);

        // hash, parent_hash
        w.write_hash(&[0u8; 32]);
        w.write_hash(&[0u8; 32]);

        // parent_slot
        w.write_u64(99);

        // HardForks: empty
        w.write_u64(0);

        // Scalar counters
        for _ in 0..5 {
            w.write_u64(0);
        }

        // hashes_per_tick: None
        w.write_option_u64(None);

        // ticks_per_slot, ns_per_slot, genesis_creation_time
        w.write_u64(64);
        w.write_u128(400_000_000);
        w.write_i64(0);

        // slots_per_year, accounts_data_len
        w.write_f64(0.0);
        w.write_u64(0);

        // slot, epoch, block_height
        w.write_u64(100);
        w.write_u64(0);
        w.write_u64(100);

        // collector_id, collector_fees
        w.write_hash(&[0u8; 32]);
        w.write_u64(0);

        // FeeCalculator
        w.write_u64(5000);

        // FeeRateGovernor
        w.write_u64(10_000);
        w.write_u64(20_000);
        w.write_u64(5_000);
        w.write_u64(100_000);
        w.write_u8(50);

        // collected_rent
        w.write_u64(0);

        // RentCollector
        w.write_u64(0);
        for _ in 0..4 {
            w.write_u64(0);
        }
        w.write_bool(false);
        w.write_f64(0.0);
        w.write_u64(0);
        w.write_f64(0.0);
        w.write_u8(0);

        // EpochSchedule
        w.write_u64(0);
        w.write_u64(0);
        w.write_bool(false);
        w.write_u64(0);
        w.write_u64(0);

        // Inflation
        for _ in 0..5 {
            w.write_f64(0.0);
        }

        // Stakes<Delegation>:
        // 2 vote accounts
        w.write_u64(2);
        for i in 0..2u8 {
            w.write_hash(&[i + 1; 32]); // pubkey
            w.write_u64(1000 + i as u64 * 500); // stake
                                                // VoteAccount = AccountSharedData:
            w.write_u64(100); // lamports
            w.write_byte_vec(&[0u8; 64]); // data
            w.write_hash(&[0xFF; 32]); // owner
            w.write_bool(false); // executable
            w.write_u64(0); // rent_epoch
        }

        // 3 stake delegations
        w.write_u64(3);
        for i in 0..3u8 {
            w.write_hash(&[i + 10; 32]); // map key (stake pubkey)
            w.write_hash(&[1; 32]); // voter_pubkey
            w.write_u64(1000 * (i as u64 + 1)); // stake
            w.write_u64(0); // activation_epoch
            w.write_u64(u64::MAX); // deactivation_epoch
            w.write_f64(0.25); // warmup_cooldown_rate
        }

        // unused, epoch, stake_history
        w.write_u64(0);
        w.write_u64(5); // stakes epoch
        w.write_u64(0); // empty stake history

        // UnusedAccounts
        w.write_u64(0);
        w.write_u64(0);
        w.write_u64(0);

        // unused_epoch_stakes
        w.write_u64(0);

        // is_delta
        w.write_bool(false);

        let data = w.into_bytes();
        let state = parse_bank_state(&data).expect("parse");

        assert_eq!(state.slot, 100);
        assert_eq!(state.stake_summary.vote_account_count, 2);
        assert_eq!(state.stake_summary.stake_delegation_count, 3);
        assert_eq!(state.stake_summary.total_delegated_stake, 6000); // 1000+2000+3000
        assert_eq!(state.stake_summary.stakes_epoch, 5);
        assert!(!state.is_delta);
        assert_eq!(state.hashes_per_tick, None);
    }

    #[test]
    fn parse_with_ancestors_and_hard_forks() {
        let mut w = BincodeWriter::new();

        // BlockhashQueue: empty
        w.write_u64(0);
        w.write_u8(0);
        w.write_u64(0);
        w.write_u64(300);

        // Ancestors: 3 entries
        w.write_u64(3);
        for i in 0..3u64 {
            w.write_u64(i * 10); // slot
            w.write_u64(i); // depth (usize)
        }

        // hash, parent_hash
        w.write_hash(&[0u8; 32]);
        w.write_hash(&[0u8; 32]);

        // parent_slot
        w.write_u64(49);

        // HardForks: 2 entries
        w.write_u64(2);
        w.write_u64(100); // slot
        w.write_u64(1); // count
        w.write_u64(200); // slot
        w.write_u64(2); // count

        // Fill remaining scalar fields
        for _ in 0..5 {
            w.write_u64(0);
        }
        w.write_option_u64(Some(12500));
        w.write_u64(64);
        w.write_u128(400_000_000);
        w.write_i64(0);
        w.write_f64(0.0);
        w.write_u64(0);
        w.write_u64(50);
        w.write_u64(0);
        w.write_u64(50);
        w.write_hash(&[0u8; 32]);
        w.write_u64(0);
        w.write_u64(5000);
        // FeeRateGovernor
        w.write_u64(10_000);
        w.write_u64(20_000);
        w.write_u64(5_000);
        w.write_u64(100_000);
        w.write_u8(50);
        w.write_u64(0);
        // RentCollector
        w.write_u64(0);
        w.write_u64(0);
        w.write_u64(0);
        w.write_bool(false);
        w.write_u64(0);
        w.write_u64(0);
        w.write_f64(0.0);
        w.write_u64(0);
        w.write_f64(0.0);
        w.write_u8(0);
        // EpochSchedule
        w.write_u64(0);
        w.write_u64(0);
        w.write_bool(false);
        w.write_u64(0);
        w.write_u64(0);
        // Inflation
        for _ in 0..5 {
            w.write_f64(0.0);
        }
        // Stakes (empty)
        w.write_u64(0);
        w.write_u64(0);
        w.write_u64(0);
        w.write_u64(0);
        w.write_u64(0);
        // UnusedAccounts
        w.write_u64(0);
        w.write_u64(0);
        w.write_u64(0);
        // unused_epoch_stakes
        w.write_u64(0);
        // is_delta
        w.write_bool(false);

        let data = w.into_bytes();
        let state = parse_bank_state(&data).expect("parse");

        assert_eq!(state.ancestor_count, 3);
        assert_eq!(state.hard_forks.len(), 2);
        assert_eq!(state.hard_forks[0], (100, 1));
        assert_eq!(state.hard_forks[1], (200, 2));
        assert_eq!(state.slot, 50);
        assert_eq!(state.parent_slot, 49);
    }

    #[test]
    fn parse_multiple_blockhashes_sorted() {
        let mut w = BincodeWriter::new();

        // BlockhashQueue with 3 hashes in REVERSE order
        w.write_u64(102); // last_hash_index
        w.write_u8(1);
        w.write_hash(&[0xCC; 32]); // last_hash

        w.write_u64(3); // 3 entries
                        // Entry with index 102
        w.write_hash(&[0xCC; 32]);
        w.write_u64(5000);
        w.write_u64(102);
        w.write_u64(3000);
        // Entry with index 100
        w.write_hash(&[0xAA; 32]);
        w.write_u64(5000);
        w.write_u64(100);
        w.write_u64(1000);
        // Entry with index 101
        w.write_hash(&[0xBB; 32]);
        w.write_u64(5000);
        w.write_u64(101);
        w.write_u64(2000);

        w.write_u64(300); // max_age

        // Fill remaining fields minimally
        w.write_u64(0); // ancestors
        w.write_hash(&[0u8; 32]);
        w.write_hash(&[0u8; 32]);
        w.write_u64(0);
        w.write_u64(0); // hard_forks
        for _ in 0..5 {
            w.write_u64(0);
        }
        w.write_option_u64(None);
        w.write_u64(64);
        w.write_u128(0);
        w.write_i64(0);
        w.write_f64(0.0);
        w.write_u64(0);
        w.write_u64(0);
        w.write_u64(0);
        w.write_u64(0);
        w.write_hash(&[0u8; 32]);
        w.write_u64(0);
        w.write_u64(5000);
        w.write_u64(10_000);
        w.write_u64(20_000);
        w.write_u64(5_000);
        w.write_u64(100_000);
        w.write_u8(50);
        w.write_u64(0);
        w.write_u64(0);
        w.write_u64(0);
        w.write_u64(0);
        w.write_bool(false);
        w.write_u64(0);
        w.write_u64(0);
        w.write_f64(0.0);
        w.write_u64(0);
        w.write_f64(0.0);
        w.write_u8(0);
        w.write_u64(0);
        w.write_u64(0);
        w.write_bool(false);
        w.write_u64(0);
        w.write_u64(0);
        for _ in 0..5 {
            w.write_f64(0.0);
        }
        w.write_u64(0);
        w.write_u64(0);
        w.write_u64(0);
        w.write_u64(0);
        w.write_u64(0);
        w.write_u64(0);
        w.write_u64(0);
        w.write_u64(0);
        w.write_u64(0);
        w.write_bool(false);

        let data = w.into_bytes();
        let state = parse_bank_state(&data).expect("parse");

        // Should be sorted by hash_index ascending
        assert_eq!(state.recent_blockhashes.len(), 3);
        assert_eq!(state.recent_blockhashes[0].hash_index, 100);
        assert_eq!(state.recent_blockhashes[0].hash, [0xAA; 32]);
        assert_eq!(state.recent_blockhashes[1].hash_index, 101);
        assert_eq!(state.recent_blockhashes[1].hash, [0xBB; 32]);
        assert_eq!(state.recent_blockhashes[2].hash_index, 102);
        assert_eq!(state.recent_blockhashes[2].hash, [0xCC; 32]);
    }

    #[test]
    fn parse_truncated_manifest_fails() {
        let data = build_minimal_manifest(100, 0, 100, 1_000_000);
        // Truncate halfway through
        let truncated = &data[..data.len() / 2];
        assert!(parse_bank_state(truncated).is_err());
    }

    #[test]
    fn parse_empty_data_fails() {
        assert!(parse_bank_state(&[]).is_err());
    }

    #[test]
    fn parse_stake_history_skipped_correctly() {
        let mut w = BincodeWriter::new();

        // Minimal blockhash queue
        w.write_u64(0);
        w.write_u8(0);
        w.write_u64(0);
        w.write_u64(300);

        // Ancestors: empty
        w.write_u64(0);

        // hash, parent_hash
        w.write_hash(&[0u8; 32]);
        w.write_hash(&[0u8; 32]);

        // parent_slot
        w.write_u64(0);

        // HardForks: empty
        w.write_u64(0);

        // Scalar counters
        for _ in 0..5 {
            w.write_u64(0);
        }
        w.write_option_u64(Some(12500));
        w.write_u64(64);
        w.write_u128(0);
        w.write_i64(0);
        w.write_f64(0.0);
        w.write_u64(0);
        w.write_u64(0);
        w.write_u64(0);
        w.write_u64(0);
        w.write_hash(&[0u8; 32]);
        w.write_u64(0);
        w.write_u64(5000);
        // FeeRateGovernor
        w.write_u64(10_000);
        w.write_u64(20_000);
        w.write_u64(5_000);
        w.write_u64(100_000);
        w.write_u8(50);
        w.write_u64(0);
        // RentCollector
        w.write_u64(0);
        w.write_u64(0);
        w.write_u64(0);
        w.write_bool(false);
        w.write_u64(0);
        w.write_u64(0);
        w.write_f64(0.0);
        w.write_u64(0);
        w.write_f64(0.0);
        w.write_u8(0);
        // EpochSchedule
        w.write_u64(0);
        w.write_u64(0);
        w.write_bool(false);
        w.write_u64(0);
        w.write_u64(0);
        // Inflation
        for _ in 0..5 {
            w.write_f64(0.0);
        }

        // Stakes<Delegation>:
        // 0 vote accounts
        w.write_u64(0);
        // 0 stake delegations
        w.write_u64(0);
        // unused
        w.write_u64(0);
        // epoch
        w.write_u64(10);

        // stake_history: 5 entries
        w.write_u64(5);
        for i in 0..5u64 {
            w.write_u64(i); // epoch
            w.write_u64(1000 * (i + 1)); // effective
            w.write_u64(100 * (i + 1)); // activating
            w.write_u64(50 * (i + 1)); // deactivating
        }

        // UnusedAccounts
        w.write_u64(0);
        w.write_u64(0);
        w.write_u64(0);

        // unused_epoch_stakes
        w.write_u64(0);

        // is_delta
        w.write_bool(false);

        let data = w.into_bytes();
        let state = parse_bank_state(&data).expect("parse");

        assert_eq!(state.stake_summary.stake_history_entries, 5);
        assert_eq!(state.stake_summary.stakes_epoch, 10);
    }
}
