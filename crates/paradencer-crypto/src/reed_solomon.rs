//! Reed-Solomon erasure coding for shred reconstruction
//!
//! This module provides Forward Error Correction (FEC) using Reed-Solomon
//! erasure codes to recover missing data shreds from coding shreds.

use reed_solomon_erasure::galois_8::ReedSolomon;
use thiserror::Error;

/// Maximum number of data shreds in a FEC set (matches Solana's default)
pub const MAX_FEC_DATA_SHREDS: usize = 67;

/// Maximum number of coding shreds in a FEC set
pub const MAX_FEC_CODING_SHREDS: usize = 67;

/// Default FEC configuration: 32 data + 32 coding shreds
pub const DEFAULT_FEC_DATA: usize = 32;
pub const DEFAULT_FEC_CODING: usize = 32;

/// Errors that can occur during FEC operations
#[derive(Debug, Error)]
pub enum FecError {
    #[error("Invalid FEC parameters: data={data}, coding={coding}")]
    InvalidParameters { data: usize, coding: usize },

    #[error("Insufficient shreds for reconstruction: have {have}, need {need}")]
    InsufficientShreds { have: usize, need: usize },

    #[error("Shred size mismatch: expected {expected}, got {actual}")]
    SizeMismatch { expected: usize, actual: usize },

    #[error("Reed-Solomon reconstruction failed: {0}")]
    ReconstructionFailed(String),

    #[error("Invalid shred index: {0}")]
    InvalidIndex(usize),
}

/// Result type for FEC operations
pub type FecResult<T> = Result<T, FecError>;

/// Reed-Solomon FEC reconstructor for shred recovery
pub struct FecReconstructor {
    /// Reed-Solomon codec
    codec: ReedSolomon,

    /// Number of data shreds
    num_data: usize,

    /// Number of coding shreds
    num_coding: usize,
}

/// Reconstructed FEC set result
#[derive(Debug, Clone)]
pub struct ReconstructedSet {
    /// Reconstructed data shreds (None if already present)
    pub data_shreds: Vec<Option<Vec<u8>>>,

    /// Number of shreds that were reconstructed
    pub num_reconstructed: usize,
}

impl FecReconstructor {
    /// Create a new FEC reconstructor with the given parameters
    pub fn new(num_data: usize, num_coding: usize) -> FecResult<Self> {
        if num_data == 0 || num_data > MAX_FEC_DATA_SHREDS {
            return Err(FecError::InvalidParameters {
                data: num_data,
                coding: num_coding,
            });
        }

        if num_coding == 0 || num_coding > MAX_FEC_CODING_SHREDS {
            return Err(FecError::InvalidParameters {
                data: num_data,
                coding: num_coding,
            });
        }

        let codec = ReedSolomon::new(num_data, num_coding)
            .map_err(|e| FecError::ReconstructionFailed(e.to_string()))?;

        Ok(Self {
            codec,
            num_data,
            num_coding,
        })
    }

    /// Create a reconstructor with default parameters (32, 32)
    pub fn default_config() -> FecResult<Self> {
        Self::new(DEFAULT_FEC_DATA, DEFAULT_FEC_CODING)
    }

    /// Reconstruct missing data shreds from available data and coding shreds
    ///
    /// # Arguments
    ///
    /// * `data_shreds` - Vector of data shreds (None for missing shreds)
    /// * `coding_shreds` - Vector of coding shreds (None for missing shreds)
    ///
    /// # Returns
    ///
    /// Reconstructed data shreds with None for shreds that were already present
    pub fn reconstruct(
        &self,
        data_shreds: Vec<Option<Vec<u8>>>,
        coding_shreds: Vec<Option<Vec<u8>>>,
    ) -> FecResult<ReconstructedSet> {
        // Validate input sizes
        if data_shreds.len() != self.num_data {
            return Err(FecError::InvalidParameters {
                data: data_shreds.len(),
                coding: self.num_coding,
            });
        }

        if coding_shreds.len() != self.num_coding {
            return Err(FecError::InvalidParameters {
                data: self.num_data,
                coding: coding_shreds.len(),
            });
        }

        // Count available shreds
        let num_data_available = data_shreds.iter().filter(|s| s.is_some()).count();
        let num_coding_available = coding_shreds.iter().filter(|s| s.is_some()).count();
        let total_available = num_data_available + num_coding_available;

        // Check if we have enough shreds to reconstruct
        if total_available < self.num_data {
            return Err(FecError::InsufficientShreds {
                have: total_available,
                need: self.num_data,
            });
        }

        // If all data shreds are present, no reconstruction needed
        if num_data_available == self.num_data {
            return Ok(ReconstructedSet {
                data_shreds,
                num_reconstructed: 0,
            });
        }

        // Prepare shreds for Reed-Solomon
        let _shred_size = Self::get_uniform_size(&data_shreds, &coding_shreds)?;
        let mut all_shreds: Vec<Option<Vec<u8>>> =
            Vec::with_capacity(self.num_data + self.num_coding);
        all_shreds.extend(data_shreds.clone());
        all_shreds.extend(coding_shreds.clone());

        // Perform reconstruction (works in-place on owned data)
        self.codec
            .reconstruct(&mut all_shreds)
            .map_err(|e| FecError::ReconstructionFailed(e.to_string()))?;

        // Extract reconstructed data shreds
        let mut reconstructed_data = Vec::with_capacity(self.num_data);
        let mut num_reconstructed = 0;

        for i in 0..self.num_data {
            if data_shreds[i].is_none() {
                // This shred was reconstructed
                if let Some(shred) = &all_shreds[i] {
                    reconstructed_data.push(Some(shred.clone()));
                    num_reconstructed += 1;
                } else {
                    reconstructed_data.push(None);
                }
            } else {
                // This shred was already present
                reconstructed_data.push(None);
            }
        }

        Ok(ReconstructedSet {
            data_shreds: reconstructed_data,
            num_reconstructed,
        })
    }

    /// Reconstruct a single FEC set with specific indices
    ///
    /// This method is optimized for the case where you know which shreds are missing
    pub fn reconstruct_with_indices(
        &self,
        shreds: Vec<(usize, Vec<u8>)>,
        shred_size: usize,
    ) -> FecResult<Vec<Vec<u8>>> {
        if shreds.len() < self.num_data {
            return Err(FecError::InsufficientShreds {
                have: shreds.len(),
                need: self.num_data,
            });
        }

        // Build full shred array with gaps
        let mut all_shreds: Vec<Option<Vec<u8>>> = vec![None; self.num_data + self.num_coding];
        for (idx, shred) in shreds {
            if idx >= all_shreds.len() {
                return Err(FecError::InvalidIndex(idx));
            }
            if shred.len() != shred_size {
                return Err(FecError::SizeMismatch {
                    expected: shred_size,
                    actual: shred.len(),
                });
            }
            all_shreds[idx] = Some(shred);
        }

        // Reconstruct (works in-place on owned data)
        self.codec
            .reconstruct(&mut all_shreds)
            .map_err(|e| FecError::ReconstructionFailed(e.to_string()))?;

        // Extract all data shreds
        let mut result = Vec::with_capacity(self.num_data);
        for shred in all_shreds.iter().take(self.num_data) {
            if let Some(shred) = shred {
                result.push(shred.clone());
            } else {
                return Err(FecError::ReconstructionFailed(
                    "Failed to reconstruct all data shreds".to_string(),
                ));
            }
        }

        Ok(result)
    }

    /// Get the uniform size from available shreds
    fn get_uniform_size(
        data_shreds: &[Option<Vec<u8>>],
        coding_shreds: &[Option<Vec<u8>>],
    ) -> FecResult<usize> {
        let size = data_shreds
            .iter()
            .chain(coding_shreds.iter())
            .filter_map(|s| s.as_ref())
            .map(|s| s.len())
            .next()
            .ok_or(FecError::InsufficientShreds { have: 0, need: 1 })?;

        // Verify all shreds have the same size
        for s in data_shreds.iter().chain(coding_shreds.iter()).flatten() {
            if s.len() != size {
                return Err(FecError::SizeMismatch {
                    expected: size,
                    actual: s.len(),
                });
            }
        }

        Ok(size)
    }

    /// Get number of data shreds
    pub fn num_data(&self) -> usize {
        self.num_data
    }

    /// Get number of coding shreds
    pub fn num_coding(&self) -> usize {
        self.num_coding
    }
}

/// Helper function to reconstruct a FEC set with default configuration
pub fn reconstruct_fec_set(
    data_shreds: Vec<Option<Vec<u8>>>,
    coding_shreds: Vec<Option<Vec<u8>>>,
) -> FecResult<ReconstructedSet> {
    let num_data = data_shreds.len();
    let num_coding = coding_shreds.len();

    let reconstructor = FecReconstructor::new(num_data, num_coding)?;
    reconstructor.reconstruct(data_shreds, coding_shreds)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_shreds(num_data: usize, size: usize) -> Vec<Vec<u8>> {
        (0..num_data)
            .map(|i| {
                let mut shred = vec![0u8; size];
                // Fill with deterministic pattern
                for (j, byte) in shred.iter_mut().enumerate() {
                    *byte = ((i * 256 + j) % 256) as u8;
                }
                shred
            })
            .collect()
    }

    #[test]
    fn test_fec_reconstructor_creation() {
        let reconstructor = FecReconstructor::new(32, 32).unwrap();
        assert_eq!(reconstructor.num_data(), 32);
        assert_eq!(reconstructor.num_coding(), 32);
    }

    #[test]
    fn test_invalid_parameters() {
        assert!(FecReconstructor::new(0, 32).is_err());
        assert!(FecReconstructor::new(32, 0).is_err());
        assert!(FecReconstructor::new(100, 32).is_err());
    }

    #[test]
    fn test_no_reconstruction_needed() {
        let reconstructor = FecReconstructor::new(4, 4).unwrap();
        let data = create_test_shreds(4, 128);

        let data_shreds: Vec<Option<Vec<u8>>> = data.into_iter().map(Some).collect();
        let coding_shreds: Vec<Option<Vec<u8>>> = vec![None; 4];

        let result = reconstructor
            .reconstruct(data_shreds, coding_shreds)
            .unwrap();
        assert_eq!(result.num_reconstructed, 0);
    }

    #[test]
    fn test_reconstruct_with_coding_shreds() {
        let reconstructor = FecReconstructor::new(4, 4).unwrap();
        let original_data = create_test_shreds(4, 128);

        // Create coding shreds using reed-solomon
        let codec = ReedSolomon::new(4, 4).unwrap();
        let mut all_shreds: Vec<_> = original_data.to_vec();
        all_shreds.extend(vec![vec![0u8; 128]; 4]);

        let mut shreds_refs: Vec<_> = all_shreds.iter_mut().map(|s| s.as_mut_slice()).collect();
        codec.encode(&mut shreds_refs).unwrap();

        // Simulate loss of first 2 data shreds
        let mut data_shreds: Vec<Option<Vec<u8>>> = vec![None, None];
        data_shreds.extend(original_data[2..].iter().map(|s| Some(s.clone())));

        let coding_shreds: Vec<Option<Vec<u8>>> =
            all_shreds[4..].iter().map(|s| Some(s.clone())).collect();

        let result = reconstructor
            .reconstruct(data_shreds, coding_shreds)
            .unwrap();
        assert_eq!(result.num_reconstructed, 2);

        // Verify reconstructed shreds match original
        assert_eq!(result.data_shreds[0].as_ref().unwrap(), &original_data[0]);
        assert_eq!(result.data_shreds[1].as_ref().unwrap(), &original_data[1]);
    }

    #[test]
    fn test_insufficient_shreds() {
        let reconstructor = FecReconstructor::new(4, 4).unwrap();

        // Only 3 shreds available (need at least 4)
        let data_shreds: Vec<Option<Vec<u8>>> =
            vec![Some(vec![0u8; 128]), None, Some(vec![0u8; 128]), None];
        let coding_shreds: Vec<Option<Vec<u8>>> = vec![Some(vec![0u8; 128]), None, None, None];

        let result = reconstructor.reconstruct(data_shreds, coding_shreds);
        assert!(matches!(result, Err(FecError::InsufficientShreds { .. })));
    }

    #[test]
    fn test_reconstruct_with_indices() {
        let reconstructor = FecReconstructor::new(4, 4).unwrap();
        let original_data = create_test_shreds(4, 128);

        // Create full FEC set
        let codec = ReedSolomon::new(4, 4).unwrap();
        let mut all_shreds: Vec<_> = original_data.to_vec();
        all_shreds.extend(vec![vec![0u8; 128]; 4]);

        let mut shreds_refs: Vec<_> = all_shreds.iter_mut().map(|s| s.as_mut_slice()).collect();
        codec.encode(&mut shreds_refs).unwrap();

        // Use indices 2, 3, 4, 5 (data 2, 3, coding 0, 1)
        let shreds_with_indices = vec![
            (2, all_shreds[2].clone()),
            (3, all_shreds[3].clone()),
            (4, all_shreds[4].clone()),
            (5, all_shreds[5].clone()),
        ];

        let result = reconstructor
            .reconstruct_with_indices(shreds_with_indices, 128)
            .unwrap();

        assert_eq!(result.len(), 4);
        assert_eq!(result[0], original_data[0]);
        assert_eq!(result[1], original_data[1]);
        assert_eq!(result[2], original_data[2]);
        assert_eq!(result[3], original_data[3]);
    }

    #[test]
    fn test_default_config() {
        let reconstructor = FecReconstructor::default_config().unwrap();
        assert_eq!(reconstructor.num_data(), DEFAULT_FEC_DATA);
        assert_eq!(reconstructor.num_coding(), DEFAULT_FEC_CODING);
    }
}
