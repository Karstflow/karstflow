//! On-chain state for BPF upgradeable-loader accounts.
//!
//! The codec lives here rather than beside the loader executor because it is a
//! byte-level state machine with no execution semantics, and both the runtime
//! that migrates these accounts and the loader that writes them need to read
//! it. `karstflow-sbpf` re-exports it under its original name.

use crate::Pubkey;
use karstflow_constants::bpf_loader_program as constants;

/// On-chain state for BPF Upgradeable Loader accounts.
///
/// This enum represents the metadata header stored at the beginning of
/// account data.  Buffer and ProgramData accounts have ELF binary data
/// following the fixed-size header.
///
/// The bincode-compatible on-chain layout:
///   - Uninitialized:  4 bytes (u32 discriminant only)
///   - Buffer:         37 bytes header (disc + option<authority>) + ELF data
///   - Program:        36 bytes total (disc + programdata_address)
///   - ProgramData:    45 bytes header (disc + slot + option<authority>) + ELF data
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpgradeableLoaderState {
    /// Account created but not yet initialized.
    Uninitialized,
    /// Buffer holding uploaded program data before deployment.
    Buffer { authority: Option<Pubkey> },
    /// Deployed program account pointing to its ProgramData account.
    Program { programdata_address: Pubkey },
    /// ProgramData account holding deployment slot, authority, and ELF data.
    ProgramData {
        slot: u64,
        upgrade_authority: Option<Pubkey>,
    },
}

/// Backward-compatible alias for the old name.
pub type ProgramAccountState = UpgradeableLoaderState;

impl UpgradeableLoaderState {
    /// Size of account data for a buffer with `program_len` bytes of ELF data.
    pub fn size_of_buffer(program_len: usize) -> usize {
        constants::SIZE_OF_BUFFER_METADATA + program_len
    }

    /// Size of the program account (fixed).
    pub fn size_of_program() -> usize {
        constants::SIZE_OF_PROGRAM
    }

    /// Size of account data for programdata with `program_len` bytes of ELF data.
    pub fn size_of_programdata(program_len: usize) -> usize {
        constants::SIZE_OF_PROGRAMDATA_METADATA + program_len
    }

    /// Serialize the state header into the beginning of account data.
    ///
    /// Only writes the metadata header.  For Buffer and ProgramData, the
    /// ELF binary data is written separately at the appropriate offset.
    pub fn serialize_into(&self, data: &mut [u8]) -> Result<usize, String> {
        match self {
            Self::Uninitialized => {
                if data.len() < constants::SIZE_OF_UNINITIALIZED {
                    return Err("Account data too small for uninitialized state".into());
                }
                data[0..4].copy_from_slice(&constants::STATE_UNINITIALIZED.to_le_bytes());
                Ok(constants::SIZE_OF_UNINITIALIZED)
            }
            Self::Buffer { authority } => {
                if data.len() < constants::SIZE_OF_BUFFER_METADATA {
                    return Err("Account data too small for buffer metadata".into());
                }
                data[0..4].copy_from_slice(&constants::STATE_BUFFER.to_le_bytes());
                match authority {
                    Some(pubkey) => {
                        data[4] = 1;
                        data[5..37].copy_from_slice(pubkey.as_bytes());
                    }
                    None => {
                        data[4] = 0;
                        data[5..37].fill(0);
                    }
                }
                Ok(constants::SIZE_OF_BUFFER_METADATA)
            }
            Self::Program {
                programdata_address,
            } => {
                if data.len() < constants::SIZE_OF_PROGRAM {
                    return Err("Account data too small for program state".into());
                }
                data[0..4].copy_from_slice(&constants::STATE_PROGRAM.to_le_bytes());
                data[4..36].copy_from_slice(programdata_address.as_bytes());
                Ok(constants::SIZE_OF_PROGRAM)
            }
            Self::ProgramData {
                slot,
                upgrade_authority,
            } => {
                if data.len() < constants::SIZE_OF_PROGRAMDATA_METADATA {
                    return Err("Account data too small for programdata metadata".into());
                }
                data[0..4].copy_from_slice(&constants::STATE_PROGRAM_DATA.to_le_bytes());
                data[4..12].copy_from_slice(&slot.to_le_bytes());
                match upgrade_authority {
                    Some(pubkey) => {
                        data[12] = 1;
                        data[13..45].copy_from_slice(pubkey.as_bytes());
                    }
                    None => {
                        data[12] = 0;
                        data[13..45].fill(0);
                    }
                }
                Ok(constants::SIZE_OF_PROGRAMDATA_METADATA)
            }
        }
    }

    /// Serialize to a new Vec (includes only the header, no ELF data).
    pub fn serialize(&self) -> Vec<u8> {
        let size = match self {
            Self::Uninitialized => constants::SIZE_OF_UNINITIALIZED,
            Self::Buffer { .. } => constants::SIZE_OF_BUFFER_METADATA,
            Self::Program { .. } => constants::SIZE_OF_PROGRAM,
            Self::ProgramData { .. } => constants::SIZE_OF_PROGRAMDATA_METADATA,
        };
        let mut buf = vec![0u8; size];
        self.serialize_into(&mut buf).expect("pre-sized buffer");
        buf
    }

    /// Deserialize the state header from account data.
    pub fn deserialize(data: &[u8]) -> Result<Self, String> {
        if data.len() < 4 {
            return Ok(Self::Uninitialized);
        }
        let disc = u32::from_le_bytes(
            data[0..4]
                .try_into()
                .map_err(|_| "Failed to read discriminant")?,
        );

        match disc {
            constants::STATE_UNINITIALIZED => Ok(Self::Uninitialized),
            constants::STATE_BUFFER => {
                if data.len() < 5 {
                    return Err("Buffer state data too short".into());
                }
                let authority = if data[4] != 0 {
                    if data.len() < constants::SIZE_OF_BUFFER_METADATA {
                        return Err("Buffer authority data too short".into());
                    }
                    Some(Pubkey::new_from_array(
                        data[5..37].try_into().map_err(|_| "Bad authority bytes")?,
                    ))
                } else {
                    None
                };
                Ok(Self::Buffer { authority })
            }
            constants::STATE_PROGRAM => {
                if data.len() < constants::SIZE_OF_PROGRAM {
                    return Err("Program state data too short".into());
                }
                let programdata_address = Pubkey::new_from_array(
                    data[4..36]
                        .try_into()
                        .map_err(|_| "Bad programdata address")?,
                );
                Ok(Self::Program {
                    programdata_address,
                })
            }
            constants::STATE_PROGRAM_DATA => {
                if data.len() < 13 {
                    return Err("ProgramData state data too short".into());
                }
                let slot =
                    u64::from_le_bytes(data[4..12].try_into().map_err(|_| "Bad slot bytes")?);
                let upgrade_authority = if data[12] != 0 {
                    if data.len() < constants::SIZE_OF_PROGRAMDATA_METADATA {
                        return Err("ProgramData authority data too short".into());
                    }
                    Some(Pubkey::new_from_array(
                        data[13..45]
                            .try_into()
                            .map_err(|_| "Bad upgrade authority bytes")?,
                    ))
                } else {
                    None
                };
                Ok(Self::ProgramData {
                    slot,
                    upgrade_authority,
                })
            }
            _ => Err(format!("Unknown state discriminant: {}", disc)),
        }
    }

    pub fn is_uninitialized(&self) -> bool {
        matches!(self, Self::Uninitialized)
    }

    pub fn is_buffer(&self) -> bool {
        matches!(self, Self::Buffer { .. })
    }

    pub fn is_program(&self) -> bool {
        matches!(self, Self::Program { .. })
    }

    pub fn is_program_data(&self) -> bool {
        matches!(self, Self::ProgramData { .. })
    }
}
