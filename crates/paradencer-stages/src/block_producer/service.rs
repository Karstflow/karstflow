//! Block Producer Service
//!
//! This module implements the main block producer service that orchestrates
//! the entire block production pipeline for leader validators.

use super::entry_creator::{EntryCreator, EntryCreatorConfig};
use super::poh::{PohEntry, PohService};
use super::shredder::{EntryShredder, ShredderConfig, ShredderError};
use paradencer_consensus::LeaderSchedule;
use paradencer_mesh::{Receiver, Sender};
use paradencer_storage::Pubkey;
use paradencer_types::shred::Shred;
use paradencer_types::Hash;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{error, info};

/// Errors that can occur in the block producer
#[derive(Debug, Error)]
pub enum BlockProducerError {
    #[error("Not the leader for slot {slot}")]
    NotLeader { slot: u64 },

    #[error("Shredding failed: {0}")]
    ShreddingFailed(#[from] ShredderError),

    #[error("Transaction receive failed: {0}")]
    TransactionReceiveFailed(String),

    #[error("Shred send failed: {0}")]
    ShredSendFailed(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),

    #[error("Service already running")]
    AlreadyRunning,

    #[error("Service not running")]
    NotRunning,

    #[error("Thread join failed")]
    ThreadJoinFailed,
}

/// Result type for block producer operations
pub type BlockProducerResult<T> = Result<T, BlockProducerError>;

/// Configuration for the block producer
#[derive(Debug, Clone)]
pub struct BlockProducerConfig {
    /// PoH hashes per tick
    pub hashes_per_tick: u64,

    /// Ticks per slot
    pub ticks_per_slot: u64,

    /// Maximum transactions per entry
    pub max_txs_per_entry: usize,

    /// Maximum bytes per entry
    pub max_bytes_per_entry: usize,

    /// FEC configuration
    pub shredder_config: ShredderConfig,

    /// Tick interval (how often to generate ticks if no transactions)
    pub tick_duration: Duration,

    /// Maximum batch size for processing transactions
    pub max_batch_size: usize,

    /// Enable verbose logging
    pub verbose: bool,
}

impl Default for BlockProducerConfig {
    fn default() -> Self {
        Self {
            hashes_per_tick: 12_500,
            ticks_per_slot: 64,
            max_txs_per_entry: 64,
            max_bytes_per_entry: 1024 * 1024, // 1 MB
            shredder_config: ShredderConfig::default(),
            tick_duration: Duration::from_millis(6250), // ~6.25ms for 160 ticks/sec
            max_batch_size: 128,
            verbose: false,
        }
    }
}

/// Statistics for block production
#[derive(Debug, Clone, Default)]
pub struct BlockProducerStats {
    /// Current slot being produced
    pub current_slot: u64,

    /// Total entries produced
    pub total_entries: u64,

    /// Total data shreds produced
    pub total_data_shreds: u64,

    /// Total coding shreds produced
    pub total_coding_shreds: u64,

    /// Total transactions processed
    pub total_transactions: u64,

    /// Total ticks generated
    pub total_ticks: u64,

    /// Time spent producing blocks
    pub production_time_ms: u64,

    /// Number of slots produced
    pub slots_produced: u64,
}

/// Block producer service for leader validators
pub struct BlockProducer {
    /// Configuration
    config: BlockProducerConfig,

    /// Leader schedule
    leader_schedule: Arc<LeaderSchedule>,

    /// This validator's public key
    validator_pubkey: Pubkey,

    /// Leader's keypair for signing (if leader)
    leader_keypair: Option<ed25519_dalek::SigningKey>,

    /// Current slot
    current_slot: Arc<Mutex<u64>>,

    /// PoH service (shared)
    poh: Arc<Mutex<PohService>>,

    /// Entry creator
    entry_creator: Arc<Mutex<EntryCreator>>,

    /// Transaction receiver
    tx_receiver: Arc<Receiver<Vec<u8>>>,

    /// Shred sender
    shred_sender: Arc<Sender<Shred>>,

    /// Running flag
    running: Arc<AtomicBool>,

    /// Worker thread handle
    worker_thread: Option<JoinHandle<()>>,

    /// Statistics
    stats: Arc<Mutex<BlockProducerStats>>,
}

impl BlockProducer {
    /// Create a new block producer
    pub fn new(
        config: BlockProducerConfig,
        leader_schedule: LeaderSchedule,
        validator_pubkey: Pubkey,
        leader_keypair: Option<ed25519_dalek::SigningKey>,
        tx_receiver: Receiver<Vec<u8>>,
        shred_sender: Sender<Shred>,
    ) -> Self {
        let poh = Arc::new(Mutex::new(PohService::with_hashes_per_tick(
            Hash::new_unique(),
            config.hashes_per_tick,
        )));

        let entry_creator_config = EntryCreatorConfig {
            max_txs_per_entry: config.max_txs_per_entry,
            max_bytes_per_entry: config.max_bytes_per_entry,
            ticks_per_slot: config.ticks_per_slot,
        };

        let entry_creator = Arc::new(Mutex::new(EntryCreator::new(
            poh.clone(),
            entry_creator_config,
        )));

        Self {
            config,
            leader_schedule: Arc::new(leader_schedule),
            validator_pubkey,
            leader_keypair,
            current_slot: Arc::new(Mutex::new(0)),
            poh,
            entry_creator,
            tx_receiver: Arc::new(tx_receiver),
            shred_sender: Arc::new(shred_sender),
            running: Arc::new(AtomicBool::new(false)),
            worker_thread: None,
            stats: Arc::new(Mutex::new(BlockProducerStats::default())),
        }
    }

    /// Start the block producer
    pub fn start(&mut self, starting_slot: u64) -> BlockProducerResult<()> {
        if self.running.load(Ordering::Relaxed) {
            return Err(BlockProducerError::AlreadyRunning);
        }

        *self
            .current_slot
            .lock()
            .expect("current_slot lock poisoned") = starting_slot;
        self.running.store(true, Ordering::Relaxed);

        let running = self.running.clone();
        let current_slot = self.current_slot.clone();
        let poh = self.poh.clone();
        let entry_creator = self.entry_creator.clone();
        let tx_receiver = self.tx_receiver.clone();
        let shred_sender = self.shred_sender.clone();
        let leader_schedule = self.leader_schedule.clone();
        let validator_pubkey = self.validator_pubkey;
        let leader_keypair = self.leader_keypair.clone();
        let config = self.config.clone();
        let stats = self.stats.clone();

        self.worker_thread = Some(thread::spawn(move || {
            Self::worker_loop(
                running,
                current_slot,
                poh,
                entry_creator,
                tx_receiver,
                shred_sender,
                leader_schedule,
                validator_pubkey,
                leader_keypair,
                config,
                stats,
            );
        }));

        Ok(())
    }

    /// Stop the block producer
    pub fn stop(&mut self) -> BlockProducerResult<()> {
        if !self.running.load(Ordering::Relaxed) {
            return Err(BlockProducerError::NotRunning);
        }

        self.running.store(false, Ordering::Relaxed);

        if let Some(handle) = self.worker_thread.take() {
            handle
                .join()
                .map_err(|_| BlockProducerError::ThreadJoinFailed)?;
        }

        Ok(())
    }

    /// Worker thread main loop
    #[allow(clippy::too_many_arguments)]
    fn worker_loop(
        running: Arc<AtomicBool>,
        current_slot: Arc<Mutex<u64>>,
        poh: Arc<Mutex<PohService>>,
        entry_creator: Arc<Mutex<EntryCreator>>,
        tx_receiver: Arc<Receiver<Vec<u8>>>,
        shred_sender: Arc<Sender<Shred>>,
        leader_schedule: Arc<LeaderSchedule>,
        validator_pubkey: Pubkey,
        leader_keypair: Option<ed25519_dalek::SigningKey>,
        config: BlockProducerConfig,
        stats: Arc<Mutex<BlockProducerStats>>,
    ) {
        let mut last_tick_time = Instant::now();
        let mut tick_count_in_slot = 0u64;

        while running.load(Ordering::Relaxed) {
            let slot = *current_slot.lock().expect("current_slot lock poisoned");

            // Update stats
            {
                let mut stats = stats.lock().expect("stats lock poisoned");
                stats.current_slot = slot;
            }

            // Check if we're the leader for this slot
            let is_leader = leader_schedule
                .get_leader(slot)
                .map(|leader| leader == validator_pubkey)
                .unwrap_or(false);

            if !is_leader {
                // Not leader, just wait and advance slot
                thread::sleep(Duration::from_millis(400)); // Wait for slot to pass
                Self::advance_slot(&current_slot, &mut tick_count_in_slot);
                continue;
            }

            // We're the leader, produce the block!
            if config.verbose {
                info!(slot, "block producer: leading slot");
            }

            let result = Self::produce_slot(
                slot,
                &poh,
                &entry_creator,
                &tx_receiver,
                &shred_sender,
                validator_pubkey,
                leader_keypair.as_ref(),
                &config,
                &stats,
                &running,
                &mut last_tick_time,
                &mut tick_count_in_slot,
            );

            if let Err(e) = result {
                error!(slot, error = %e, "block producer error");
            }

            // Advance to next slot
            Self::advance_slot(&current_slot, &mut tick_count_in_slot);
        }
    }

    /// Produce a single slot as leader
    #[allow(clippy::too_many_arguments)]
    fn produce_slot(
        slot: u64,
        poh: &Arc<Mutex<PohService>>,
        entry_creator: &Arc<Mutex<EntryCreator>>,
        tx_receiver: &Arc<Receiver<Vec<u8>>>,
        shred_sender: &Arc<Sender<Shred>>,
        validator_pubkey: Pubkey,
        leader_keypair: Option<&ed25519_dalek::SigningKey>,
        config: &BlockProducerConfig,
        stats: &Arc<Mutex<BlockProducerStats>>,
        running: &Arc<AtomicBool>,
        last_tick_time: &mut Instant,
        tick_count_in_slot: &mut u64,
    ) -> BlockProducerResult<()> {
        let slot_start = Instant::now();
        let mut shredder = EntryShredder::new(
            validator_pubkey,
            leader_keypair.cloned(),
            slot,
            config.shredder_config.clone(),
        )?;

        let mut entries_in_slot = Vec::new();
        let mut transactions_in_slot = 0u64;

        // Produce entries for this slot
        while *tick_count_in_slot < config.ticks_per_slot && running.load(Ordering::Relaxed) {
            // Try to collect transactions
            let mut tx_batch = Vec::new();
            let batch_deadline = Instant::now() + Duration::from_millis(10);

            while tx_batch.len() < config.max_batch_size && Instant::now() < batch_deadline {
                match tx_receiver.try_recv() {
                    Ok(Some(tx)) => tx_batch.push(tx),
                    Ok(None) | Err(_) => break,
                }
            }

            if !tx_batch.is_empty() {
                // Add transactions to entry creator
                let mut creator = entry_creator.lock().expect("entry_creator lock poisoned");
                for tx in tx_batch {
                    creator.add_transaction(tx);
                }

                // Create entry if buffer is full
                if creator.should_flush() {
                    if let Some(entry) = creator.create_entry() {
                        transactions_in_slot += entry.transactions.len() as u64;
                        entries_in_slot.push(entry);
                    }
                }
                drop(creator);
            }

            // Generate tick if enough time has passed
            if last_tick_time.elapsed() >= config.tick_duration {
                let mut creator = entry_creator.lock().expect("entry_creator lock poisoned");

                // Flush any pending transactions first
                if let Some(entry) = creator.flush() {
                    transactions_in_slot += entry.transactions.len() as u64;
                    entries_in_slot.push(entry);
                }

                // Create tick entry
                let tick_entry = creator.create_tick_entry();
                entries_in_slot.push(tick_entry);
                drop(creator);

                *tick_count_in_slot += 1;
                *last_tick_time = Instant::now();

                // Update stats
                let mut stats = stats.lock().expect("stats lock poisoned");
                stats.total_ticks += 1;
                drop(stats);
            }

            // Shred and send entries if we have enough
            if entries_in_slot.len() >= 8 {
                Self::shred_and_send_entries(
                    &mut entries_in_slot,
                    &mut shredder,
                    shred_sender,
                    stats,
                )?;
            }

            // Small sleep to avoid busy waiting
            thread::sleep(Duration::from_micros(100));
        }

        // Ensure we have exactly ticks_per_slot ticks
        while *tick_count_in_slot < config.ticks_per_slot {
            let mut creator = entry_creator.lock().expect("entry_creator lock poisoned");

            // Flush any pending transactions
            if let Some(entry) = creator.flush() {
                transactions_in_slot += entry.transactions.len() as u64;
                entries_in_slot.push(entry);
            }

            // Create tick entry
            let tick_entry = creator.create_tick_entry();
            entries_in_slot.push(tick_entry);
            drop(creator);

            *tick_count_in_slot += 1;

            let mut stats = stats.lock().expect("stats lock poisoned");
            stats.total_ticks += 1;
            drop(stats);
        }

        // Shred and send any remaining entries
        if !entries_in_slot.is_empty() {
            Self::shred_and_send_entries(&mut entries_in_slot, &mut shredder, shred_sender, stats)?;
        }

        // Update final stats
        let slot_duration = slot_start.elapsed();
        let mut stats = stats.lock().expect("stats lock poisoned");
        stats.slots_produced += 1;
        stats.total_transactions += transactions_in_slot;
        stats.production_time_ms += slot_duration.as_millis() as u64;
        drop(stats);

        if config.verbose {
            info!(
                slot,
                transactions = transactions_in_slot,
                duration_ms = slot_duration.as_millis() as u64,
                "block producer: slot completed",
            );
        }

        Ok(())
    }

    /// Shred entries and send to network
    fn shred_and_send_entries(
        entries: &mut Vec<PohEntry>,
        shredder: &mut EntryShredder,
        shred_sender: &Arc<Sender<Shred>>,
        stats: &Arc<Mutex<BlockProducerStats>>,
    ) -> BlockProducerResult<()> {
        // Create data shreds from entries
        let data_shreds = shredder.create_data_shreds(entries)?;
        let data_count = data_shreds.len();

        // Create coding shreds for FEC
        let coding_shreds = shredder.create_coding_shreds(&data_shreds)?;
        let coding_count = coding_shreds.len();

        // Send all shreds to network
        for shred in data_shreds {
            shred_sender
                .try_send(shred)
                .map_err(|e| BlockProducerError::ShredSendFailed(format!("{:?}", e)))?;
        }

        for shred in coding_shreds {
            shred_sender
                .try_send(shred)
                .map_err(|e| BlockProducerError::ShredSendFailed(format!("{:?}", e)))?;
        }

        // Update stats
        let mut stats = stats.lock().expect("stats lock poisoned");
        stats.total_entries += entries.len() as u64;
        stats.total_data_shreds += data_count as u64;
        stats.total_coding_shreds += coding_count as u64;
        drop(stats);

        // Clear entries
        entries.clear();

        Ok(())
    }

    /// Advance to the next slot
    fn advance_slot(current_slot: &Arc<Mutex<u64>>, tick_count: &mut u64) {
        let mut slot = current_slot.lock().expect("current_slot lock poisoned");
        *slot += 1;
        *tick_count = 0;
    }

    /// Get current slot
    pub fn current_slot(&self) -> u64 {
        *self
            .current_slot
            .lock()
            .expect("current_slot lock poisoned")
    }

    /// Check if currently running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Get statistics
    pub fn stats(&self) -> BlockProducerStats {
        self.stats.lock().expect("stats lock poisoned").clone()
    }

    /// Reset statistics
    pub fn reset_stats(&self) {
        let mut stats = self.stats.lock().expect("stats lock poisoned");
        *stats = BlockProducerStats::default();
    }

    /// Get validator public key
    pub fn validator_pubkey(&self) -> Pubkey {
        self.validator_pubkey
    }

    /// Check if this validator is the leader for a slot
    pub fn is_leader_for_slot(&self, slot: u64) -> bool {
        self.leader_schedule
            .get_leader(slot)
            .map(|leader| leader == self.validator_pubkey)
            .unwrap_or(false)
    }
}

impl Drop for BlockProducer {
    fn drop(&mut self) {
        if self.running.load(Ordering::Relaxed) {
            let _ = self.stop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paradencer_mesh::bounded_link;

    #[test]
    fn test_block_producer_creation() {
        let validators = vec![(Pubkey::new_unique(), 1000)];
        let leader_schedule = LeaderSchedule::new(0, &validators).unwrap();
        let validator_pubkey = validators[0].0;

        let (tx_sender, tx_receiver) = bounded_link(100);
        let (shred_sender, _shred_receiver) = bounded_link(100);

        let config = BlockProducerConfig::default();
        let producer = BlockProducer::new(
            config,
            leader_schedule,
            validator_pubkey,
            None,
            tx_receiver,
            shred_sender,
        );

        assert_eq!(producer.validator_pubkey(), validator_pubkey);
        assert!(!producer.is_running());
        assert_eq!(producer.current_slot(), 0);
    }

    #[test]
    fn test_block_producer_start_stop() {
        let validators = vec![(Pubkey::new_unique(), 1000)];
        let leader_schedule = LeaderSchedule::new(0, &validators).unwrap();
        let validator_pubkey = validators[0].0;

        let (_tx_sender, tx_receiver) = bounded_link(100);
        let (shred_sender, _shred_receiver) = bounded_link(100);

        let config = BlockProducerConfig::default();
        let mut producer = BlockProducer::new(
            config,
            leader_schedule,
            validator_pubkey,
            None,
            tx_receiver,
            shred_sender,
        );

        assert!(producer.start(0).is_ok());
        assert!(producer.is_running());

        // Starting again should fail
        assert!(matches!(
            producer.start(0),
            Err(BlockProducerError::AlreadyRunning)
        ));

        assert!(producer.stop().is_ok());
        assert!(!producer.is_running());
    }

    #[test]
    fn test_is_leader_for_slot() {
        let validator_a = Pubkey::new_unique();
        let validator_b = Pubkey::new_unique();
        let validators = vec![(validator_a, 1000), (validator_b, 1000)];
        let leader_schedule = LeaderSchedule::new(0, &validators).unwrap();

        let (_tx_sender, tx_receiver) = bounded_link(100);
        let (shred_sender, _shred_receiver) = bounded_link(100);

        let config = BlockProducerConfig::default();
        let producer = BlockProducer::new(
            config,
            leader_schedule.clone(),
            validator_a,
            None,
            tx_receiver,
            shred_sender,
        );

        // Check if we're leader for various slots
        for slot in 0..100 {
            let is_leader = producer.is_leader_for_slot(slot);
            let scheduled_leader = leader_schedule.get_leader(slot);
            assert_eq!(is_leader, scheduled_leader == Some(validator_a));
        }
    }

    #[test]
    fn test_stats_tracking() {
        let validators = vec![(Pubkey::new_unique(), 1000)];
        let leader_schedule = LeaderSchedule::new(0, &validators).unwrap();
        let validator_pubkey = validators[0].0;

        let (_tx_sender, tx_receiver) = bounded_link(100);
        let (shred_sender, _shred_receiver) = bounded_link(100);

        let config = BlockProducerConfig::default();
        let producer = BlockProducer::new(
            config,
            leader_schedule,
            validator_pubkey,
            None,
            tx_receiver,
            shred_sender,
        );

        let stats = producer.stats();
        assert_eq!(stats.total_entries, 0);
        assert_eq!(stats.total_transactions, 0);

        producer.reset_stats();
        let stats = producer.stats();
        assert_eq!(stats.current_slot, 0);
    }

    #[test]
    fn test_config_default() {
        let config = BlockProducerConfig::default();
        assert_eq!(config.hashes_per_tick, 12_500);
        assert_eq!(config.ticks_per_slot, 64);
        assert_eq!(config.max_txs_per_entry, 64);
        assert!(config.tick_duration.as_millis() > 0);
    }
}
