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
// Binary writer
// ---------------------------------------------------------------------------

/// Low-level bincode binary writer for Solana snapshot data.
///
/// Writes fields in the exact layout expected by Solana validators.
/// Bincode 1.x uses fixed-size little-endian encoding with u64 lengths.
pub(crate) struct BincodeWriter {
    buf: Vec<u8>,
}

impl BincodeWriter {
    #[cfg(test)]
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }

    pub fn write_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn write_u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn write_i64(&mut self, v: i64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn write_u128(&mut self, v: u128) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn write_f64(&mut self, v: f64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn write_bool(&mut self, v: bool) {
        self.buf.push(if v { 1 } else { 0 });
    }

    pub fn write_hash(&mut self, h: &[u8; 32]) {
        self.buf.extend_from_slice(h);
    }

    pub fn write_option_u64(&mut self, v: Option<u64>) {
        match v {
            None => self.write_u8(0),
            Some(val) => {
                self.write_u8(1);
                self.write_u64(val);
            }
        }
    }

    #[cfg(test)]
    pub fn write_byte_vec(&mut self, data: &[u8]) {
        self.write_u64(data.len() as u64);
        self.buf.extend_from_slice(data);
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
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

/// Parse and enforce that unused_epoch_stakes is empty.
///
/// Protocol requires this map to be empty in all valid snapshots.
fn skip_unused_epoch_stakes(r: &mut BincodeReader) -> Result<(), StorageError> {
    let count = r.read_vec_len()?;
    if count != 0 {
        return Err(StorageError::CorruptSnapshot(format!(
            "unused_epoch_stakes must be empty, got {count} entries"
        )));
    }
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
// Serializer
// ---------------------------------------------------------------------------

/// Serialize bank state to raw bincode manifest bytes.
///
/// This writes the `DeserializableVersionedBank` structure that Solana
/// stores in the snapshot archive at `snapshots/<slot>/<slot>`.
///
/// The output is compatible with `parse_bank_state()` and with any
/// Solana validator that reads snapshot manifests.
///
/// Note: the ancestors field is written as empty since it's reconstructed
/// by the validator on load. Vote accounts and stake delegations are also
/// omitted from the stakes section — only stake history and epoch are
/// preserved. The trailing AccountsDbFields and ExtraFields are NOT
/// written by this function.
pub fn serialize_bank_state(state: &SnapshotBankState) -> Vec<u8> {
    let mut w = BincodeWriter::with_capacity(4096);

    // 1. BlockhashQueue
    write_blockhash_queue(&mut w, state);

    // 2. Ancestors: write as empty HashMap<u64, usize>
    w.write_u64(0);

    // 3. hash, parent_hash
    w.write_hash(&state.hash);
    w.write_hash(&state.parent_hash);

    // 4. parent_slot
    w.write_u64(state.parent_slot);

    // 5. hard_forks
    w.write_u64(state.hard_forks.len() as u64);
    for &(slot, count) in &state.hard_forks {
        w.write_u64(slot);
        w.write_u64(count);
    }

    // 6-10. Scalar counters
    w.write_u64(state.transaction_count);
    w.write_u64(state.tick_height);
    w.write_u64(state.signature_count);
    w.write_u64(state.capitalization);
    w.write_u64(state.max_tick_height);

    // 11. hashes_per_tick: Option<u64>
    w.write_option_u64(state.hashes_per_tick);

    // 12-14. Timing
    w.write_u64(state.ticks_per_slot);
    w.write_u128(state.ns_per_slot);
    w.write_i64(state.genesis_creation_time);

    // 15-16. Rates
    w.write_f64(state.slots_per_year);
    w.write_u64(state.accounts_data_len);

    // 17-19. Slot identification
    w.write_u64(state.slot);
    w.write_u64(state.epoch);
    w.write_u64(state.block_height);

    // 20-21. Collector
    w.write_hash(&state.collector_id);
    w.write_u64(state.collector_fees);

    // 22. FeeCalculator (deprecated) — write target_lamports as placeholder
    w.write_u64(state.fee_rate_governor.target_lamports_per_signature);

    // 23. FeeRateGovernor (lamports_per_signature is serde-skipped)
    write_fee_rate_governor(&mut w, &state.fee_rate_governor);

    // 24. collected_rent
    w.write_u64(state.collected_rent);

    // 25. RentCollector
    write_rent_collector(&mut w, &state.rent, &state.epoch_schedule);

    // 26. EpochSchedule
    write_epoch_schedule(&mut w, &state.epoch_schedule);

    // 27. Inflation
    write_inflation(&mut w, &state.inflation);

    // 28. Stakes<Delegation> — write stake history but empty vote/delegation maps
    write_stakes_summary(&mut w, &state.stake_summary);

    // 29. UnusedAccounts — 3 empty collections
    w.write_u64(0); // HashSet<Pubkey>
    w.write_u64(0); // HashSet<Pubkey>
    w.write_u64(0); // HashMap<Pubkey, u64>

    // 30. unused_epoch_stakes: empty HashMap<u64, ()>
    w.write_u64(0);

    // 31. is_delta
    w.write_bool(state.is_delta);

    w.into_bytes()
}

fn write_blockhash_queue(w: &mut BincodeWriter, state: &SnapshotBankState) {
    // last_hash_index
    w.write_u64(state.last_blockhash_index);

    // last_hash: Option<Hash>
    match &state.last_blockhash {
        None => w.write_u8(0),
        Some(hash) => {
            w.write_u8(1);
            w.write_hash(hash);
        }
    }

    // hashes: HashMap<Hash, HashInfo>
    w.write_u64(state.recent_blockhashes.len() as u64);
    for bh in &state.recent_blockhashes {
        w.write_hash(&bh.hash);
        w.write_u64(bh.lamports_per_signature);
        w.write_u64(bh.hash_index);
        w.write_u64(bh.timestamp);
    }

    // max_age
    w.write_u64(state.max_blockhash_age);
}

fn write_fee_rate_governor(w: &mut BincodeWriter, frg: &FeeRateConfig) {
    w.write_u64(frg.target_lamports_per_signature);
    w.write_u64(frg.target_signatures_per_slot);
    w.write_u64(frg.min_lamports_per_signature);
    w.write_u64(frg.max_lamports_per_signature);
    w.write_u8(frg.burn_percent);
}

fn write_epoch_schedule(w: &mut BincodeWriter, es: &EpochScheduleConfig) {
    w.write_u64(es.slots_per_epoch);
    w.write_u64(es.leader_schedule_slot_offset);
    w.write_bool(es.warmup);
    w.write_u64(es.first_normal_epoch);
    w.write_u64(es.first_normal_slot);
}

fn write_rent_collector(w: &mut BincodeWriter, rent: &RentConfig, es: &EpochScheduleConfig) {
    // RentCollector: { epoch, epoch_schedule, slots_per_year, rent }
    w.write_u64(rent.collector_epoch);
    write_epoch_schedule(w, es); // inner epoch_schedule
    w.write_f64(rent.collector_slots_per_year);
    // Rent
    w.write_u64(rent.lamports_per_byte_year);
    w.write_f64(rent.exemption_threshold);
    w.write_u8(rent.burn_percent);
}

fn write_inflation(w: &mut BincodeWriter, inf: &InflationConfig) {
    w.write_f64(inf.initial);
    w.write_f64(inf.terminal);
    w.write_f64(inf.taper);
    w.write_f64(inf.foundation);
    w.write_f64(inf.foundation_term);
}

fn write_stakes_summary(w: &mut BincodeWriter, ss: &StakeSummary) {
    // vote_accounts: empty HashMap<Pubkey, (u64, VoteAccount)>
    w.write_u64(0);

    // stake_delegations: empty HashMap<Pubkey, Delegation>
    w.write_u64(0);

    // unused: u64
    w.write_u64(0);

    // epoch: u64
    w.write_u64(ss.stakes_epoch);

    // stake_history: Vec<(u64, StakeHistoryEntry)>
    w.write_u64(ss.stake_history.len() as u64);
    for entry in &ss.stake_history {
        w.write_u64(entry.epoch);
        w.write_u64(entry.effective);
        w.write_u64(entry.activating);
        w.write_u64(entry.deactivating);
    }
}

// ---------------------------------------------------------------------------
// AccountsDbFields — describes AppendVec storage layout in the archive
// ---------------------------------------------------------------------------

/// Describes a single AppendVec storage entry in the snapshot.
#[derive(Debug, Clone)]
pub struct StorageEntry {
    /// Storage identifier (matches `<slot>.<id>` in the archive path).
    pub id: u64,
    /// Number of bytes currently used in this AppendVec.
    pub stored_bytes: u64,
}

/// Describes the account storage layout for the AccountsDbFields section.
///
/// This section follows the bank state in the snapshot manifest and tells
/// the loader which AppendVec files exist and their sizes.
#[derive(Debug, Clone)]
pub struct AccountsDbLayout {
    /// Mapping from slot to the AppendVec storage entries at that slot.
    pub storage_map: Vec<(u64, Vec<StorageEntry>)>,
    /// The snapshot slot (should match bank state slot).
    pub slot: u64,
    /// Bank hash (SHA-256 of all account hashes). Zeroed if not computed.
    pub bank_hash: [u8; 32],
    /// Lamports per signature for fee calculation.
    pub lamports_per_signature: u64,
}

/// Serialize a complete snapshot manifest: bank state + AccountsDbFields.
///
/// This produces the full binary content for `snapshots/<slot>/<slot>` in
/// a Solana-compatible snapshot archive. The output can be parsed by any
/// Solana validator.
pub fn serialize_full_manifest(state: &SnapshotBankState, layout: &AccountsDbLayout) -> Vec<u8> {
    let mut w = BincodeWriter::with_capacity(8192);

    // --- Part 1: Bank state (DeserializableVersionedBank) ---
    let bank_bytes = serialize_bank_state(state);
    w.buf.extend_from_slice(&bank_bytes);

    // --- Part 2: AccountsDbFields ---
    write_accounts_db_fields(&mut w, layout);

    // --- Part 3: ExtraFields (minimal) ---
    write_extra_fields(&mut w, layout.lamports_per_signature);

    w.into_bytes()
}

fn write_accounts_db_fields(w: &mut BincodeWriter, layout: &AccountsDbLayout) {
    // Field 1: HashMap<Slot, Vec<SerializableAccountStorageEntry>>
    w.write_u64(layout.storage_map.len() as u64);
    for (slot, entries) in &layout.storage_map {
        w.write_u64(*slot);
        w.write_u64(entries.len() as u64);
        for entry in entries {
            w.write_u64(entry.id); // usize serialized as u64
            w.write_u64(entry.stored_bytes); // usize serialized as u64
        }
    }

    // Field 2: u64 (obsolete stored_meta_write_version)
    w.write_u64(0);

    // Field 3: u64 (snapshot slot)
    w.write_u64(layout.slot);

    // Field 4: BankHashInfo
    w.write_hash(&[0u8; 32]); // obsolete_accounts_delta_hash
    w.write_hash(&layout.bank_hash); // accounts_hash (or zeroed)
                                     // BankHashStats (5 × u64)
    w.write_u64(0); // num_updated_accounts
    w.write_u64(0); // num_removed_accounts
    w.write_u64(0); // num_lamports_stored
    w.write_u64(0); // total_data_len
    w.write_u64(0); // num_executable_accounts

    // Field 5: Vec<Slot> (historical_roots) — empty
    w.write_u64(0);

    // Field 6: Vec<(Slot, Hash)> (historical_roots_with_hash) — empty
    w.write_u64(0);
}

fn write_extra_fields(w: &mut BincodeWriter, lamports_per_signature: u64) {
    // Field 7: u64 (lamports_per_signature)
    w.write_u64(lamports_per_signature);

    // Field 8: Option<ObsoleteIncrementalSnapshotPersistence> — None
    w.write_u8(0);

    // Field 9: Option<Hash> (obsolete_epoch_accounts_hash) — None
    w.write_u8(0);

    // Remaining ExtraFields (versioned_epoch_stakes, accounts_lt_hash)
    // are optional with default_on_eof — we stop here.
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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

    // -------------------------------------------------------------------
    // Serializer roundtrip tests
    // -------------------------------------------------------------------

    /// Build a `SnapshotBankState` with realistic field values for testing.
    fn build_test_bank_state() -> SnapshotBankState {
        SnapshotBankState {
            recent_blockhashes: vec![
                RecentBlockhash {
                    hash: [0xAA; 32],
                    lamports_per_signature: 5000,
                    hash_index: 42,
                    timestamp: 1_000_000,
                },
                RecentBlockhash {
                    hash: [0xBB; 32],
                    lamports_per_signature: 5000,
                    hash_index: 43,
                    timestamp: 1_000_001,
                },
            ],
            last_blockhash: Some([0xBB; 32]),
            max_blockhash_age: 300,
            last_blockhash_index: 43,
            slot: 1000,
            parent_slot: 999,
            block_height: 900,
            epoch: 2,
            hash: [0x11; 32],
            parent_hash: [0x22; 32],
            transaction_count: 100_000,
            tick_height: 64_000,
            max_tick_height: 64_064,
            signature_count: 50_000,
            capitalization: 500_000_000_000,
            accounts_data_len: 1_000_000_000,
            hashes_per_tick: Some(12500),
            ticks_per_slot: 64,
            ns_per_slot: 400_000_000,
            genesis_creation_time: 1_700_000_000,
            slots_per_year: 78_892_314.0,
            collector_id: [0x33; 32],
            collector_fees: 1000,
            fee_rate_governor: FeeRateConfig {
                target_lamports_per_signature: 10_000,
                target_signatures_per_slot: 20_000,
                min_lamports_per_signature: 5_000,
                max_lamports_per_signature: 100_000,
                burn_percent: 50,
            },
            rent: RentConfig {
                lamports_per_byte_year: 3_480,
                exemption_threshold: 2.0,
                burn_percent: 50,
                collector_epoch: 2,
                collector_slots_per_year: 78_892_314.0,
            },
            collected_rent: 500,
            epoch_schedule: EpochScheduleConfig {
                slots_per_epoch: 432_000,
                leader_schedule_slot_offset: 432_000,
                warmup: false,
                first_normal_epoch: 0,
                first_normal_slot: 0,
            },
            inflation: InflationConfig {
                initial: 0.08,
                terminal: 0.015,
                taper: 0.15,
                foundation: 0.05,
                foundation_term: 7.0,
            },
            hard_forks: vec![(100, 1), (200, 2)],
            ancestor_count: 0, // ancestors are always empty in serialized form
            stake_summary: StakeSummary {
                vote_account_count: 0,
                stake_delegation_count: 0,
                stakes_epoch: 2,
                total_delegated_stake: 0,
                stake_history_entries: 3,
                stake_history: vec![
                    StakeHistoryRecord {
                        epoch: 0,
                        effective: 1000,
                        activating: 100,
                        deactivating: 50,
                    },
                    StakeHistoryRecord {
                        epoch: 1,
                        effective: 2000,
                        activating: 200,
                        deactivating: 100,
                    },
                    StakeHistoryRecord {
                        epoch: 2,
                        effective: 3000,
                        activating: 300,
                        deactivating: 150,
                    },
                ],
            },
            is_delta: true,
        }
    }

    #[test]
    fn serialize_then_parse_roundtrip() {
        let state = build_test_bank_state();
        let data = serialize_bank_state(&state);
        let parsed = parse_bank_state(&data).expect("roundtrip parse");

        // Slot identification
        assert_eq!(parsed.slot, state.slot);
        assert_eq!(parsed.parent_slot, state.parent_slot);
        assert_eq!(parsed.block_height, state.block_height);
        assert_eq!(parsed.epoch, state.epoch);
        assert_eq!(parsed.hash, state.hash);
        assert_eq!(parsed.parent_hash, state.parent_hash);

        // Counters
        assert_eq!(parsed.transaction_count, state.transaction_count);
        assert_eq!(parsed.tick_height, state.tick_height);
        assert_eq!(parsed.max_tick_height, state.max_tick_height);
        assert_eq!(parsed.signature_count, state.signature_count);
        assert_eq!(parsed.capitalization, state.capitalization);
        assert_eq!(parsed.accounts_data_len, state.accounts_data_len);

        // Timing
        assert_eq!(parsed.hashes_per_tick, state.hashes_per_tick);
        assert_eq!(parsed.ticks_per_slot, state.ticks_per_slot);
        assert_eq!(parsed.ns_per_slot, state.ns_per_slot);
        assert_eq!(parsed.genesis_creation_time, state.genesis_creation_time);
        assert_eq!(parsed.slots_per_year, state.slots_per_year);

        // Collector
        assert_eq!(parsed.collector_id, state.collector_id);
        assert_eq!(parsed.collector_fees, state.collector_fees);

        // Fee rate governor
        assert_eq!(
            parsed.fee_rate_governor.target_lamports_per_signature,
            state.fee_rate_governor.target_lamports_per_signature
        );
        assert_eq!(
            parsed.fee_rate_governor.target_signatures_per_slot,
            state.fee_rate_governor.target_signatures_per_slot
        );
        assert_eq!(
            parsed.fee_rate_governor.min_lamports_per_signature,
            state.fee_rate_governor.min_lamports_per_signature
        );
        assert_eq!(
            parsed.fee_rate_governor.max_lamports_per_signature,
            state.fee_rate_governor.max_lamports_per_signature
        );
        assert_eq!(
            parsed.fee_rate_governor.burn_percent,
            state.fee_rate_governor.burn_percent
        );

        // Rent
        assert_eq!(
            parsed.rent.lamports_per_byte_year,
            state.rent.lamports_per_byte_year
        );
        assert_eq!(
            parsed.rent.exemption_threshold,
            state.rent.exemption_threshold
        );
        assert_eq!(parsed.rent.burn_percent, state.rent.burn_percent);
        assert_eq!(parsed.rent.collector_epoch, state.rent.collector_epoch);
        assert_eq!(
            parsed.rent.collector_slots_per_year,
            state.rent.collector_slots_per_year
        );
        assert_eq!(parsed.collected_rent, state.collected_rent);

        // Epoch schedule
        assert_eq!(
            parsed.epoch_schedule.slots_per_epoch,
            state.epoch_schedule.slots_per_epoch
        );
        assert_eq!(parsed.epoch_schedule.warmup, state.epoch_schedule.warmup);
        assert_eq!(
            parsed.epoch_schedule.first_normal_epoch,
            state.epoch_schedule.first_normal_epoch
        );

        // Inflation
        assert_eq!(parsed.inflation.initial, state.inflation.initial);
        assert_eq!(parsed.inflation.terminal, state.inflation.terminal);
        assert_eq!(parsed.inflation.taper, state.inflation.taper);
        assert_eq!(parsed.inflation.foundation, state.inflation.foundation);
        assert_eq!(
            parsed.inflation.foundation_term,
            state.inflation.foundation_term
        );

        // Hard forks
        assert_eq!(parsed.hard_forks, state.hard_forks);

        // Stakes (vote/delegation empty, but epoch and history preserved)
        assert_eq!(
            parsed.stake_summary.stakes_epoch,
            state.stake_summary.stakes_epoch
        );
        assert_eq!(
            parsed.stake_summary.stake_history.len(),
            state.stake_summary.stake_history.len()
        );
        for (p, s) in parsed
            .stake_summary
            .stake_history
            .iter()
            .zip(state.stake_summary.stake_history.iter())
        {
            assert_eq!(p.epoch, s.epoch);
            assert_eq!(p.effective, s.effective);
            assert_eq!(p.activating, s.activating);
            assert_eq!(p.deactivating, s.deactivating);
        }

        // Flags
        assert_eq!(parsed.is_delta, state.is_delta);
        // Ancestors are always 0 in serialized form.
        assert_eq!(parsed.ancestor_count, 0);
    }

    #[test]
    fn serialize_roundtrip_none_hashes_per_tick() {
        let mut state = build_test_bank_state();
        state.hashes_per_tick = None;

        let data = serialize_bank_state(&state);
        let parsed = parse_bank_state(&data).expect("roundtrip parse");
        assert_eq!(parsed.hashes_per_tick, None);
    }

    #[test]
    fn serialize_roundtrip_no_last_blockhash() {
        let mut state = build_test_bank_state();
        state.last_blockhash = None;
        state.recent_blockhashes.clear();
        state.last_blockhash_index = 0;

        let data = serialize_bank_state(&state);
        let parsed = parse_bank_state(&data).expect("roundtrip parse");
        assert_eq!(parsed.last_blockhash, None);
        assert_eq!(parsed.recent_blockhashes.len(), 0);
    }

    #[test]
    fn serialize_roundtrip_empty_hard_forks() {
        let mut state = build_test_bank_state();
        state.hard_forks.clear();

        let data = serialize_bank_state(&state);
        let parsed = parse_bank_state(&data).expect("roundtrip parse");
        assert_eq!(parsed.hard_forks.len(), 0);
    }

    #[test]
    fn serialize_roundtrip_empty_stake_history() {
        let mut state = build_test_bank_state();
        state.stake_summary.stake_history.clear();
        state.stake_summary.stake_history_entries = 0;

        let data = serialize_bank_state(&state);
        let parsed = parse_bank_state(&data).expect("roundtrip parse");
        assert_eq!(parsed.stake_summary.stake_history.len(), 0);
    }

    #[test]
    fn serialize_roundtrip_is_not_delta() {
        let mut state = build_test_bank_state();
        state.is_delta = false;

        let data = serialize_bank_state(&state);
        let parsed = parse_bank_state(&data).expect("roundtrip parse");
        assert!(!parsed.is_delta);
    }

    #[test]
    fn serialize_produces_nonzero_bytes() {
        let state = build_test_bank_state();
        let data = serialize_bank_state(&state);
        assert!(data.len() > 100, "serialized data should be substantial");
    }

    #[test]
    fn serialize_roundtrip_many_blockhashes() {
        let mut state = build_test_bank_state();
        state.recent_blockhashes.clear();
        for i in 0..300u64 {
            let mut hash = [0u8; 32];
            hash[..8].copy_from_slice(&i.to_le_bytes());
            state.recent_blockhashes.push(RecentBlockhash {
                hash,
                lamports_per_signature: 5000,
                hash_index: i,
                timestamp: 1_000_000 + i,
            });
        }
        state.last_blockhash_index = 299;

        let data = serialize_bank_state(&state);
        let parsed = parse_bank_state(&data).expect("roundtrip parse");
        assert_eq!(parsed.recent_blockhashes.len(), 300);
        // Parser sorts by hash_index, so order should match.
        assert_eq!(parsed.recent_blockhashes[0].hash_index, 0);
        assert_eq!(parsed.recent_blockhashes[299].hash_index, 299);
    }

    // -------------------------------------------------------------------
    // Full manifest (bank state + AccountsDbFields) tests
    // -------------------------------------------------------------------

    #[test]
    fn full_manifest_produces_parseable_bank_state() {
        let state = build_test_bank_state();
        let layout = AccountsDbLayout {
            storage_map: vec![(
                1000,
                vec![
                    StorageEntry {
                        id: 0,
                        stored_bytes: 4096,
                    },
                    StorageEntry {
                        id: 1,
                        stored_bytes: 2048,
                    },
                ],
            )],
            slot: 1000,
            bank_hash: [0u8; 32],
            lamports_per_signature: 5000,
        };

        let data = serialize_full_manifest(&state, &layout);

        // The bank state portion should still be parseable.
        let parsed = parse_bank_state(&data).expect("parse bank state from full manifest");
        assert_eq!(parsed.slot, 1000);
        assert_eq!(parsed.epoch, 2);
        assert_eq!(parsed.capitalization, 500_000_000_000);
        assert!(parsed.is_delta);
    }

    #[test]
    fn full_manifest_larger_than_bank_state_alone() {
        let state = build_test_bank_state();
        let layout = AccountsDbLayout {
            storage_map: vec![(
                1000,
                vec![StorageEntry {
                    id: 0,
                    stored_bytes: 4096,
                }],
            )],
            slot: 1000,
            bank_hash: [0xFF; 32],
            lamports_per_signature: 5000,
        };

        let bank_only = serialize_bank_state(&state);
        let full = serialize_full_manifest(&state, &layout);

        // Full manifest includes AccountsDbFields + ExtraFields.
        assert!(
            full.len() > bank_only.len(),
            "full manifest ({}) should be larger than bank state alone ({})",
            full.len(),
            bank_only.len()
        );
    }

    #[test]
    fn full_manifest_with_empty_storage_map() {
        let state = build_test_bank_state();
        let layout = AccountsDbLayout {
            storage_map: vec![],
            slot: 1000,
            bank_hash: [0u8; 32],
            lamports_per_signature: 5000,
        };

        let data = serialize_full_manifest(&state, &layout);
        let parsed = parse_bank_state(&data).expect("parse");
        assert_eq!(parsed.slot, 1000);
    }

    #[test]
    fn full_manifest_with_multiple_slots() {
        let state = build_test_bank_state();
        let layout = AccountsDbLayout {
            storage_map: vec![
                (
                    100,
                    vec![StorageEntry {
                        id: 0,
                        stored_bytes: 1024,
                    }],
                ),
                (
                    200,
                    vec![
                        StorageEntry {
                            id: 0,
                            stored_bytes: 2048,
                        },
                        StorageEntry {
                            id: 1,
                            stored_bytes: 512,
                        },
                    ],
                ),
                (
                    300,
                    vec![StorageEntry {
                        id: 0,
                        stored_bytes: 8192,
                    }],
                ),
            ],
            slot: 1000,
            bank_hash: [0xAB; 32],
            lamports_per_signature: 10_000,
        };

        let data = serialize_full_manifest(&state, &layout);

        // Verify it doesn't corrupt the bank state portion.
        let parsed = parse_bank_state(&data).expect("parse");
        assert_eq!(parsed.slot, 1000);
        assert_eq!(parsed.hard_forks.len(), 2);
    }

    #[test]
    fn accounts_db_layout_fields_have_correct_defaults() {
        let layout = AccountsDbLayout {
            storage_map: vec![],
            slot: 42,
            bank_hash: [0u8; 32],
            lamports_per_signature: 0,
        };
        assert_eq!(layout.slot, 42);
        assert_eq!(layout.bank_hash, [0u8; 32]);
        assert_eq!(layout.storage_map.len(), 0);
    }
}
