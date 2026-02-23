//! Entry Shredder - Converts Entries to Shreds
//!
//! This module converts PoH entries into data shreds and generates coding shreds
//! for Forward Error Correction (FEC). Shreds are the fundamental unit of block
//! transmission in Paradencer/Solana.

use super::poh::PohEntry;
use paradencer_storage::Pubkey;
use paradencer_types::shred::{
    CodingShredHeader, DataShredHeader, Shred, ShredCommonHeader, ShredVariant,
    DATA_SHRED_PAYLOAD_SIZE, MAX_DATA_SHREDS_PER_FEC_BLOCK, SHRED_CODE_FLAG, SHRED_DATA_FLAG,
    SHRED_LAST_IN_SLOT, SHRED_MERKLE_FLAG, SIGNATURE_SIZE,
};
use reed_solomon_erasure::galois_8::ReedSolomon;
use thiserror::Error;

/// Default FEC configuration: 32 data + 32 coding shreds
pub const DEFAULT_FEC_DATA: usize = 32;
pub const DEFAULT_FEC_CODING: usize = 32;

/// Errors that can occur during shredding
#[derive(Debug, Error)]
pub enum ShredderError {
    #[error("Entry too large: {size} bytes (max {max})")]
    EntryTooLarge { size: usize, max: usize },

    #[error("Too many data shreds: {count} (max {max})")]
    TooManyDataShreds { count: usize, max: usize },

    #[error("FEC encoding failed: {0}")]
    FecEncodingFailed(String),

    #[error("Invalid shred configuration: {0}")]
    InvalidConfiguration(String),

    #[error("Signing failed: {0}")]
    SigningFailed(String),
}

/// Result type for shredder operations
pub type ShredderResult<T> = Result<T, ShredderError>;

/// Configuration for entry shredder
#[derive(Debug, Clone)]
pub struct ShredderConfig {
    /// Number of data shreds per FEC block
    pub fec_data_shreds: usize,

    /// Number of coding shreds per FEC block
    pub fec_coding_shreds: usize,

    /// Use Merkle proofs for shreds
    pub use_merkle_proofs: bool,

    /// Shred version for replay protection
    pub shred_version: u16,

    /// Enable shred signing
    pub sign_shreds: bool,
}

impl Default for ShredderConfig {
    fn default() -> Self {
        Self {
            fec_data_shreds: DEFAULT_FEC_DATA,
            fec_coding_shreds: DEFAULT_FEC_CODING,
            use_merkle_proofs: false,
            shred_version: 1,
            sign_shreds: true,
        }
    }
}

/// Entry shredder for creating data and coding shreds
pub struct EntryShredder {
    /// Leader's public key
    leader_pubkey: Pubkey,

    /// Leader's keypair for signing (if available)
    leader_keypair: Option<ed25519_dalek::SigningKey>,

    /// Current slot being produced
    slot: u64,

    /// Next shred index within the slot
    next_index: u32,

    /// FEC set index
    fec_set_index: u32,

    /// Configuration
    config: ShredderConfig,

    /// Reed-Solomon encoder for FEC
    fec_encoder: Option<ReedSolomon>,

    /// Statistics
    data_shreds_created: u64,
    coding_shreds_created: u64,
}

impl EntryShredder {
    /// Create a new entry shredder
    pub fn new(
        leader_pubkey: Pubkey,
        leader_keypair: Option<ed25519_dalek::SigningKey>,
        slot: u64,
        config: ShredderConfig,
    ) -> ShredderResult<Self> {
        let fec_encoder = if config.fec_coding_shreds > 0 {
            Some(
                ReedSolomon::new(config.fec_data_shreds, config.fec_coding_shreds).map_err(
                    |e| {
                        ShredderError::FecEncodingFailed(format!("Failed to create encoder: {}", e))
                    },
                )?,
            )
        } else {
            None
        };

        Ok(Self {
            leader_pubkey,
            leader_keypair,
            slot,
            next_index: 0,
            fec_set_index: 0,
            config,
            fec_encoder,
            data_shreds_created: 0,
            coding_shreds_created: 0,
        })
    }

    /// Create shredder with default configuration
    pub fn with_defaults(
        leader_pubkey: Pubkey,
        leader_keypair: Option<ed25519_dalek::SigningKey>,
        slot: u64,
    ) -> ShredderResult<Self> {
        Self::new(
            leader_pubkey,
            leader_keypair,
            slot,
            ShredderConfig::default(),
        )
    }

    /// Create data shreds from entries
    pub fn create_data_shreds(&mut self, entries: &[PohEntry]) -> ShredderResult<Vec<Shred>> {
        let mut shreds = Vec::new();

        if entries.is_empty() {
            return Ok(shreds);
        }

        // Serialize all entries as a bincode Vec — matches Solana wire format
        let entry_data = PohEntry::batch_to_bytes(entries);

        // Split data into shred-sized chunks
        let chunks: Vec<&[u8]> = entry_data.chunks(DATA_SHRED_PAYLOAD_SIZE).collect();

        if chunks.len() > MAX_DATA_SHREDS_PER_FEC_BLOCK {
            return Err(ShredderError::TooManyDataShreds {
                count: chunks.len(),
                max: MAX_DATA_SHREDS_PER_FEC_BLOCK,
            });
        }

        let is_last_entry = entries.last().map(|e| e.is_tick()).unwrap_or(false);

        for (i, chunk) in chunks.iter().enumerate() {
            let is_last_shred = is_last_entry && i == chunks.len() - 1;
            let shred = self.create_data_shred(chunk, is_last_shred)?;
            shreds.push(shred);
        }

        Ok(shreds)
    }

    /// Create a single data shred
    fn create_data_shred(&mut self, data: &[u8], is_last_in_slot: bool) -> ShredderResult<Shred> {
        let flags = if is_last_in_slot {
            SHRED_LAST_IN_SLOT
        } else {
            0
        };

        let data_header = DataShredHeader {
            parent_offset: 1, // Assume parent is previous slot
            flags,
            size: data.len() as u16,
        };

        let variant_byte = if self.config.use_merkle_proofs {
            SHRED_DATA_FLAG | SHRED_MERKLE_FLAG
        } else {
            SHRED_DATA_FLAG
        };

        let common_header = ShredCommonHeader {
            signature: [0; SIGNATURE_SIZE],
            variant: variant_byte,
            slot: self.slot,
            index: self.next_index,
            version: self.config.shred_version,
            fec_set_index: self.fec_set_index,
        };

        let variant = if self.config.use_merkle_proofs {
            ShredVariant::MerkleData(
                data_header,
                paradencer_types::shred::MerkleProof { proof: Vec::new() },
            )
        } else {
            ShredVariant::LegacyData(data_header)
        };

        let mut payload = data.to_vec();
        // Pad to payload size
        if payload.len() < DATA_SHRED_PAYLOAD_SIZE {
            payload.resize(DATA_SHRED_PAYLOAD_SIZE, 0);
        }

        let mut shred = Shred::new(common_header, variant, payload);

        // Sign if keypair is available
        if self.config.sign_shreds {
            if let Some(ref keypair) = self.leader_keypair {
                self.sign_shred(&mut shred, keypair)?;
            }
        }

        self.next_index += 1;
        self.data_shreds_created += 1;

        Ok(shred)
    }

    /// Create coding shreds from data shreds using Reed-Solomon FEC
    pub fn create_coding_shreds(&mut self, data_shreds: &[Shred]) -> ShredderResult<Vec<Shred>> {
        if data_shreds.is_empty() {
            return Ok(Vec::new());
        }

        let encoder = self.fec_encoder.as_ref().ok_or_else(|| {
            ShredderError::InvalidConfiguration("FEC encoder not initialized".to_string())
        })?;

        // Extract payloads from data shreds
        let mut data_payloads: Vec<Vec<u8>> =
            data_shreds.iter().map(|s| s.payload.clone()).collect();

        // Pad to FEC block size if needed
        while data_payloads.len() < self.config.fec_data_shreds {
            data_payloads.push(vec![0; DATA_SHRED_PAYLOAD_SIZE]);
        }

        // Create coding shard buffers
        let mut coding_payloads =
            vec![vec![0u8; DATA_SHRED_PAYLOAD_SIZE]; self.config.fec_coding_shreds];

        // Prepare for Reed-Solomon encoding
        let mut all_payloads: Vec<&mut [u8]> = data_payloads
            .iter_mut()
            .map(|v| v.as_mut_slice())
            .chain(coding_payloads.iter_mut().map(|v| v.as_mut_slice()))
            .collect();

        // Encode to generate coding shreds
        encoder
            .encode(&mut all_payloads)
            .map_err(|e| ShredderError::FecEncodingFailed(e.to_string()))?;

        // Create coding shred objects
        let mut coding_shreds = Vec::new();
        let base_index = self.next_index;

        for (i, payload) in coding_payloads.iter().enumerate() {
            let coding_header = CodingShredHeader {
                num_data_shreds: data_shreds.len() as u16,
                num_coding_shreds: self.config.fec_coding_shreds as u16,
                position: i as u16,
            };

            let variant_byte = if self.config.use_merkle_proofs {
                SHRED_CODE_FLAG | SHRED_MERKLE_FLAG
            } else {
                SHRED_CODE_FLAG
            };

            let common_header = ShredCommonHeader {
                signature: [0; SIGNATURE_SIZE],
                variant: variant_byte,
                slot: self.slot,
                index: base_index + i as u32,
                version: self.config.shred_version,
                fec_set_index: self.fec_set_index,
            };

            let variant = if self.config.use_merkle_proofs {
                ShredVariant::MerkleCoding(
                    coding_header,
                    paradencer_types::shred::MerkleProof { proof: Vec::new() },
                )
            } else {
                ShredVariant::LegacyCoding(coding_header)
            };

            let mut shred = Shred::new(common_header, variant, payload.clone());

            // Sign if keypair is available
            if self.config.sign_shreds {
                if let Some(ref keypair) = self.leader_keypair {
                    self.sign_shred(&mut shred, keypair)?;
                }
            }

            coding_shreds.push(shred);
            self.coding_shreds_created += 1;
        }

        self.next_index += self.config.fec_coding_shreds as u32;
        self.fec_set_index += 1;

        Ok(coding_shreds)
    }

    /// Sign a shred with the leader's keypair
    fn sign_shred(
        &self,
        shred: &mut Shred,
        keypair: &ed25519_dalek::SigningKey,
    ) -> ShredderResult<()> {
        use ed25519_dalek::Signer;

        // Create message to sign (slot + index + payload hash)
        let mut message = Vec::new();
        message.extend_from_slice(&shred.slot().to_le_bytes());
        message.extend_from_slice(&shred.index().to_le_bytes());
        message.extend_from_slice(&shred.payload);

        let signature = keypair.sign(&message);
        shred
            .common_header
            .signature
            .copy_from_slice(&signature.to_bytes());

        Ok(())
    }

    /// Sign multiple shreds
    pub fn sign_shreds(&mut self, shreds: &mut [Shred]) -> ShredderResult<()> {
        if let Some(ref keypair) = self.leader_keypair {
            for shred in shreds {
                self.sign_shred(shred, keypair)?;
            }
        }
        Ok(())
    }

    /// Reset for a new slot
    pub fn reset_for_slot(&mut self, slot: u64) {
        self.slot = slot;
        self.next_index = 0;
        self.fec_set_index = 0;
    }

    /// Get current slot
    pub fn slot(&self) -> u64 {
        self.slot
    }

    /// Get next shred index
    pub fn next_index(&self) -> u32 {
        self.next_index
    }

    /// Get statistics
    pub fn stats(&self) -> (u64, u64) {
        (self.data_shreds_created, self.coding_shreds_created)
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.data_shreds_created = 0;
        self.coding_shreds_created = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paradencer_types::Hash;

    fn create_test_entry(num_txs: usize) -> PohEntry {
        let transactions: Vec<Vec<u8>> = (0..num_txs).map(|i| vec![i as u8; 100]).collect();

        PohEntry::new(100, Hash::new_unique(), transactions)
    }

    #[test]
    fn test_shredder_creation() {
        let pubkey = Pubkey::new_unique();
        let shredder = EntryShredder::with_defaults(pubkey, None, 100).unwrap();

        assert_eq!(shredder.slot(), 100);
        assert_eq!(shredder.next_index(), 0);
    }

    #[test]
    fn test_create_data_shreds_empty() {
        let pubkey = Pubkey::new_unique();
        let mut shredder = EntryShredder::with_defaults(pubkey, None, 100).unwrap();

        let shreds = shredder.create_data_shreds(&[]).unwrap();
        assert!(shreds.is_empty());
    }

    #[test]
    fn test_create_data_shreds_single_entry() {
        let pubkey = Pubkey::new_unique();
        let mut shredder = EntryShredder::with_defaults(pubkey, None, 100).unwrap();

        let entry = create_test_entry(2);
        let shreds = shredder.create_data_shreds(&[entry]).unwrap();

        assert!(!shreds.is_empty());
        for shred in &shreds {
            assert_eq!(shred.slot(), 100);
            assert!(shred.is_data());
        }
    }

    #[test]
    fn test_create_data_shreds_multiple_entries() {
        let pubkey = Pubkey::new_unique();
        let mut shredder = EntryShredder::with_defaults(pubkey, None, 100).unwrap();

        let entries = vec![create_test_entry(2), create_test_entry(3)];
        let shreds = shredder.create_data_shreds(&entries).unwrap();

        assert!(!shreds.is_empty());
        // All shreds should have sequential indices
        for (i, shred) in shreds.iter().enumerate() {
            assert_eq!(shred.index(), i as u32);
        }
    }

    #[test]
    fn test_create_coding_shreds() {
        let pubkey = Pubkey::new_unique();
        let mut shredder = EntryShredder::with_defaults(pubkey, None, 100).unwrap();

        let entry = create_test_entry(5);
        let data_shreds = shredder.create_data_shreds(&[entry]).unwrap();
        let coding_shreds = shredder.create_coding_shreds(&data_shreds).unwrap();

        assert_eq!(coding_shreds.len(), DEFAULT_FEC_CODING);
        for shred in &coding_shreds {
            assert!(shred.is_coding());
            assert_eq!(shred.slot(), 100);
        }
    }

    #[test]
    fn test_shred_indices_increment() {
        let pubkey = Pubkey::new_unique();
        let mut shredder = EntryShredder::with_defaults(pubkey, None, 100).unwrap();

        let entry1 = create_test_entry(1);
        let shreds1 = shredder.create_data_shreds(&[entry1]).unwrap();
        let start_index1 = shreds1[0].index();

        let entry2 = create_test_entry(1);
        let shreds2 = shredder.create_data_shreds(&[entry2]).unwrap();
        let start_index2 = shreds2[0].index();

        assert!(start_index2 > start_index1);
    }

    #[test]
    fn test_reset_for_slot() {
        let pubkey = Pubkey::new_unique();
        let mut shredder = EntryShredder::with_defaults(pubkey, None, 100).unwrap();

        let entry = create_test_entry(1);
        shredder.create_data_shreds(&[entry]).unwrap();

        assert!(shredder.next_index() > 0);

        shredder.reset_for_slot(200);
        assert_eq!(shredder.slot(), 200);
        assert_eq!(shredder.next_index(), 0);
    }

    #[test]
    fn test_stats_tracking() {
        let pubkey = Pubkey::new_unique();
        let mut shredder = EntryShredder::with_defaults(pubkey, None, 100).unwrap();

        let entry = create_test_entry(2);
        let data_shreds = shredder.create_data_shreds(&[entry]).unwrap();
        let _coding_shreds = shredder.create_coding_shreds(&data_shreds).unwrap();

        let (data_count, coding_count) = shredder.stats();
        assert!(data_count > 0);
        assert_eq!(coding_count, DEFAULT_FEC_CODING as u64);
    }

    #[test]
    fn test_last_shred_flag() {
        let pubkey = Pubkey::new_unique();
        let mut shredder = EntryShredder::with_defaults(pubkey, None, 100).unwrap();

        // Create a tick entry (should be marked as last)
        let tick_entry = PohEntry::new(100, Hash::new_unique(), vec![]);
        let shreds = shredder.create_data_shreds(&[tick_entry]).unwrap();

        if let Some(last_shred) = shreds.last() {
            assert!(last_shred.is_last_in_slot());
        }
    }

    #[test]
    fn test_merkle_mode() {
        let pubkey = Pubkey::new_unique();
        let config = ShredderConfig {
            use_merkle_proofs: true,
            ..Default::default()
        };
        let mut shredder = EntryShredder::new(pubkey, None, 100, config).unwrap();

        let entry = create_test_entry(1);
        let shreds = shredder.create_data_shreds(&[entry]).unwrap();

        for shred in &shreds {
            assert!(shred.is_merkle());
        }
    }

    #[test]
    fn test_coding_shreds_have_correct_headers() {
        let pubkey = Pubkey::new_unique();
        let mut shredder = EntryShredder::with_defaults(pubkey, None, 100).unwrap();

        let entry = create_test_entry(2);
        let data_shreds = shredder.create_data_shreds(&[entry]).unwrap();
        let coding_shreds = shredder.create_coding_shreds(&data_shreds).unwrap();

        for shred in &coding_shreds {
            if let Some(header) = shred.coding_header() {
                assert_eq!(header.num_data_shreds, data_shreds.len() as u16);
                assert_eq!(header.num_coding_shreds, DEFAULT_FEC_CODING as u16);
            } else {
                panic!("Expected coding header");
            }
        }
    }

    #[test]
    fn test_shred_signing_disabled() {
        let pubkey = Pubkey::new_unique();
        let keypair = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let config = ShredderConfig {
            sign_shreds: false,
            ..Default::default()
        };
        let mut shredder = EntryShredder::new(pubkey, Some(keypair), 100, config).unwrap();

        let entry = create_test_entry(1);
        let shreds = shredder.create_data_shreds(&[entry]).unwrap();

        // Signature should be all zeros
        for shred in &shreds {
            assert_eq!(shred.common_header.signature, [0; SIGNATURE_SIZE]);
        }
    }
}
