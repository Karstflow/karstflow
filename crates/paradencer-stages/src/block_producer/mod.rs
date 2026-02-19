//! Block Producer for Leader Validators
//!
//! This module implements the block production pipeline for leader validators in Paradencer.
//! When a validator is the leader for a slot, it produces blocks by:
//! 1. Collecting transactions from the transaction queue
//! 2. Recording them into entries using Proof of History (PoH)
//! 3. Converting entries into data shreds
//! 4. Generating coding shreds for FEC
//! 5. Signing and broadcasting shreds to the network
//!
//! # Components
//!
//! - **PoH Service**: Maintains a hash chain for ordering transactions
//! - **Entry Creator**: Assembles transactions into entries with PoH hashes
//! - **Entry Shredder**: Converts entries into data and coding shreds
//! - **Block Producer**: Orchestrates the entire production pipeline
//!
//! # Example
//!
//! ```rust,ignore
//! use paradencer_stages::block_producer::{BlockProducer, BlockProducerConfig};
//! use paradencer_consensus::LeaderSchedule;
//! use paradencer_mesh::bounded_link;
//!
//! // Create communication channels
//! let (tx_sender, tx_receiver) = bounded_link(1000);
//! let (shred_sender, shred_receiver) = bounded_link(1000);
//!
//! // Setup leader schedule
//! let validators = vec![(/* validator_pubkey */, 100)];
//! # let validators: Vec<(paradencer_storage::Pubkey, u64)> = vec![];
//! let leader_schedule = LeaderSchedule::new(0, &validators).unwrap();
//!
//! // Create block producer
//! let config = BlockProducerConfig::default();
//! // let mut producer = BlockProducer::new(
//! //     config,
//! //     leader_schedule,
//! //     validator_pubkey,
//! //     tx_receiver,
//! //     shred_sender,
//! // );
//!
//! // Run the producer (blocks until stopped)
//! // producer.run().unwrap();
//! ```

mod entry_creator;
mod poh;
mod service;
mod shredder;

#[cfg(test)]
mod tests;

pub use entry_creator::{EntryCreator, EntryCreatorConfig};
pub use poh::{
    Entry, MicroblockEntry, PohEntry, PohRecord, PohService, PohState, SlotComplete, TickEntry,
    MAX_TRANSACTIONS_PER_ENTRY,
};
pub use service::{BlockProducer, BlockProducerConfig, BlockProducerError, BlockProducerResult};
pub use shredder::{EntryShredder, ShredderConfig, ShredderError};
