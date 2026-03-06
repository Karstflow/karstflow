/// Tower state persistence for crash recovery.
///
/// Saves and loads the validator's Tower BFT state to/from disk so that
/// tower lockouts survive validator restarts. Uses versioned binary
/// serialization for forward compatibility.
use crate::{Tower, TowerVote};
use karstflow_constants::consensus::{TOWER_FILE_NAME, TOWER_PERSISTENCE_VERSION};
use karstflow_storage::Pubkey;
use std::io;
use std::path::Path;

/// Serializable representation of tower state for disk persistence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedTower {
    /// Format version for backward/forward compatibility.
    pub version: u32,
    /// Identity of the validator that produced this tower.
    pub validator_identity: Pubkey,
    /// Vote slots with their confirmation counts.
    pub votes: Vec<SavedVote>,
    /// Current root slot, if any.
    pub root: Option<u64>,
    /// Slot of the most recent vote (cached for quick access).
    pub last_voted_slot: Option<u64>,
}

/// A single vote entry within a saved tower.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedVote {
    /// Slot that was voted on.
    pub slot: u64,
    /// Current confirmation count for this vote.
    pub confirmation_count: u32,
}

/// Errors that can occur during tower persistence operations.
#[derive(Debug)]
pub enum TowerPersistenceError {
    /// I/O error during read or write.
    Io(io::Error),
    /// Serialization or deserialization failure.
    Serialization(String),
    /// Loaded tower has an incompatible version.
    IncompatibleVersion { found: u32, expected: u32 },
    /// The tower file does not exist.
    NotFound(String),
    /// Validator identity mismatch between loaded tower and expected identity.
    IdentityMismatch { expected: Pubkey, found: Pubkey },
}

impl std::fmt::Display for TowerPersistenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "tower persistence I/O error: {}", e),
            Self::Serialization(e) => write!(f, "tower serialization error: {}", e),
            Self::IncompatibleVersion { found, expected } => {
                write!(
                    f,
                    "incompatible tower version: found {}, expected {}",
                    found, expected
                )
            }
            Self::NotFound(path) => write!(f, "tower file not found: {}", path),
            Self::IdentityMismatch { expected, found } => {
                write!(
                    f,
                    "tower identity mismatch: expected {:?}, found {:?}",
                    expected, found
                )
            }
        }
    }
}

impl std::error::Error for TowerPersistenceError {}

impl From<io::Error> for TowerPersistenceError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl SavedTower {
    /// Create a SavedTower snapshot from the current live tower state.
    pub fn from_tower(tower: &Tower, validator_identity: Pubkey) -> Self {
        let votes = tower
            .votes()
            .iter()
            .map(|v| SavedVote {
                slot: v.slot,
                confirmation_count: v.confirmation_count,
            })
            .collect();

        Self {
            version: TOWER_PERSISTENCE_VERSION,
            validator_identity,
            votes,
            root: tower.root(),
            last_voted_slot: tower.last_vote_slot(),
        }
    }

    /// Reconstruct a live Tower from the saved state.
    pub fn to_tower(&self) -> Tower {
        let votes: Vec<TowerVote> = self
            .votes
            .iter()
            .map(|sv| TowerVote {
                slot: sv.slot,
                confirmation_count: sv.confirmation_count,
            })
            .collect();

        Tower::from_saved(votes, self.root)
    }

    /// Serialize the tower to bytes using a compact binary format.
    ///
    /// Format: version(4) + identity(32) + root_flag(1) + root(8?) +
    ///         last_voted_flag(1) + last_voted(8?) +
    ///         vote_count(4) + [slot(8) + conf(4)]*N
    pub fn serialize(&self) -> Result<Vec<u8>, TowerPersistenceError> {
        let mut buf = Vec::with_capacity(128);

        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.extend_from_slice(self.validator_identity.as_bytes());

        // Root slot (optional)
        match self.root {
            Some(root) => {
                buf.push(1);
                buf.extend_from_slice(&root.to_le_bytes());
            }
            None => buf.push(0),
        }

        // Last voted slot (optional)
        match self.last_voted_slot {
            Some(slot) => {
                buf.push(1);
                buf.extend_from_slice(&slot.to_le_bytes());
            }
            None => buf.push(0),
        }

        // Votes
        let vote_count = self.votes.len() as u32;
        buf.extend_from_slice(&vote_count.to_le_bytes());
        for vote in &self.votes {
            buf.extend_from_slice(&vote.slot.to_le_bytes());
            buf.extend_from_slice(&vote.confirmation_count.to_le_bytes());
        }

        Ok(buf)
    }

    /// Deserialize a tower from bytes, validating the version.
    pub fn deserialize(data: &[u8]) -> Result<Self, TowerPersistenceError> {
        let mut off = 0;

        if data.len() < 4 + 32 + 1 + 1 + 4 {
            return Err(TowerPersistenceError::Serialization(
                "data too short".to_string(),
            ));
        }

        let version = read_u32(data, &mut off)?;
        if version != TOWER_PERSISTENCE_VERSION {
            return Err(TowerPersistenceError::IncompatibleVersion {
                found: version,
                expected: TOWER_PERSISTENCE_VERSION,
            });
        }

        let identity_bytes: [u8; 32] = data[off..off + 32]
            .try_into()
            .map_err(|_| TowerPersistenceError::Serialization("invalid identity".to_string()))?;
        off += 32;
        let validator_identity = Pubkey::new(identity_bytes);

        let root = read_optional_u64(data, &mut off)?;
        let last_voted_slot = read_optional_u64(data, &mut off)?;

        let vote_count = read_u32(data, &mut off)? as usize;
        let mut votes = Vec::with_capacity(vote_count);
        for _ in 0..vote_count {
            let slot = read_u64(data, &mut off)?;
            let confirmation_count = read_u32(data, &mut off)?;
            votes.push(SavedVote {
                slot,
                confirmation_count,
            });
        }

        Ok(Self {
            version,
            validator_identity,
            votes,
            root,
            last_voted_slot,
        })
    }

    /// Save the tower state to a file at the given directory path.
    ///
    /// The file is written atomically by first writing to a temporary file
    /// and then renaming, to avoid corruption from partial writes.
    pub fn save_to_directory(&self, dir: &Path) -> Result<(), TowerPersistenceError> {
        let data = self.serialize()?;
        std::fs::create_dir_all(dir)?;
        let tower_path = dir.join(TOWER_FILE_NAME);
        let tmp_path = dir.join(format!("{}.tmp", TOWER_FILE_NAME));

        std::fs::write(&tmp_path, &data)?;
        std::fs::rename(&tmp_path, &tower_path)?;

        Ok(())
    }

    /// Load tower state from a file in the given directory.
    pub fn load_from_directory(dir: &Path) -> Result<Self, TowerPersistenceError> {
        let tower_path = dir.join(TOWER_FILE_NAME);

        if !tower_path.exists() {
            return Err(TowerPersistenceError::NotFound(
                tower_path.to_string_lossy().into_owned(),
            ));
        }

        let data = std::fs::read(&tower_path)?;
        Self::deserialize(&data)
    }

    /// Load and validate that the tower belongs to the expected validator.
    pub fn load_and_verify(
        dir: &Path,
        expected_identity: &Pubkey,
    ) -> Result<Self, TowerPersistenceError> {
        let saved = Self::load_from_directory(dir)?;

        if &saved.validator_identity != expected_identity {
            return Err(TowerPersistenceError::IdentityMismatch {
                expected: *expected_identity,
                found: saved.validator_identity,
            });
        }

        Ok(saved)
    }

    /// Check if the saved tower file exists in the given directory.
    pub fn exists_in_directory(dir: &Path) -> bool {
        dir.join(TOWER_FILE_NAME).exists()
    }

    /// Delete the saved tower file from the given directory.
    pub fn delete_from_directory(dir: &Path) -> Result<(), TowerPersistenceError> {
        let tower_path = dir.join(TOWER_FILE_NAME);
        if tower_path.exists() {
            std::fs::remove_file(&tower_path)?;
        }
        Ok(())
    }
}

fn read_u32(data: &[u8], off: &mut usize) -> Result<u32, TowerPersistenceError> {
    if *off + 4 > data.len() {
        return Err(TowerPersistenceError::Serialization(
            "data too short for u32".to_string(),
        ));
    }
    let val = u32::from_le_bytes(
        data[*off..*off + 4]
            .try_into()
            .map_err(|_| TowerPersistenceError::Serialization("invalid u32".to_string()))?,
    );
    *off += 4;
    Ok(val)
}

fn read_u64(data: &[u8], off: &mut usize) -> Result<u64, TowerPersistenceError> {
    if *off + 8 > data.len() {
        return Err(TowerPersistenceError::Serialization(
            "data too short for u64".to_string(),
        ));
    }
    let val = u64::from_le_bytes(
        data[*off..*off + 8]
            .try_into()
            .map_err(|_| TowerPersistenceError::Serialization("invalid u64".to_string()))?,
    );
    *off += 8;
    Ok(val)
}

fn read_optional_u64(data: &[u8], off: &mut usize) -> Result<Option<u64>, TowerPersistenceError> {
    if *off >= data.len() {
        return Err(TowerPersistenceError::Serialization(
            "data too short for flag".to_string(),
        ));
    }
    let flag = data[*off];
    *off += 1;
    if flag == 1 {
        Ok(Some(read_u64(data, off)?))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tower_with_votes(slots: &[u64]) -> Tower {
        let mut tower = Tower::new();
        for &slot in slots {
            tower.push_vote(slot);
        }
        tower
    }

    #[test]
    fn saved_tower_roundtrip_from_tower() {
        let tower = make_tower_with_votes(&[100, 101, 102, 103]);
        let identity = Pubkey::new_unique();

        let saved = SavedTower::from_tower(&tower, identity);
        assert_eq!(saved.version, TOWER_PERSISTENCE_VERSION);
        assert_eq!(saved.validator_identity, identity);
        assert_eq!(saved.votes.len(), 4);
        assert_eq!(saved.root, tower.root());
        assert_eq!(saved.last_voted_slot, Some(103));
    }

    #[test]
    fn saved_tower_to_tower_preserves_state() {
        let mut tower = Tower::new();
        tower.push_vote(100);
        tower.push_vote(101);
        tower.push_vote(102);

        let identity = Pubkey::new_unique();
        let saved = SavedTower::from_tower(&tower, identity);

        let restored = saved.to_tower();
        assert_eq!(restored.votes().len(), tower.votes().len());
        assert_eq!(restored.root(), tower.root());
        for (orig, rest) in tower.votes().iter().zip(restored.votes().iter()) {
            assert_eq!(orig.slot, rest.slot);
            assert_eq!(orig.confirmation_count, rest.confirmation_count);
        }
    }

    #[test]
    fn saved_tower_serialize_deserialize() {
        let tower = make_tower_with_votes(&[10, 11, 12]);
        let identity = Pubkey::new_unique();
        let saved = SavedTower::from_tower(&tower, identity);

        let bytes = saved.serialize().unwrap();
        let restored = SavedTower::deserialize(&bytes).unwrap();

        assert_eq!(saved, restored);
    }

    #[test]
    fn saved_tower_rejects_incompatible_version() {
        let tower = make_tower_with_votes(&[10]);
        let identity = Pubkey::new_unique();
        let mut saved = SavedTower::from_tower(&tower, identity);
        saved.version = 999;

        let bytes = saved.serialize().unwrap();
        // Patch the version in the bytes directly (first 4 bytes)
        let mut patched = bytes;
        patched[0..4].copy_from_slice(&999u32.to_le_bytes());
        let result = SavedTower::deserialize(&patched);

        assert!(matches!(
            result,
            Err(TowerPersistenceError::IncompatibleVersion { .. })
        ));
    }

    #[test]
    fn saved_tower_rejects_corrupted_data() {
        let result = SavedTower::deserialize(&[0xFF, 0xFE, 0xFD]);
        assert!(matches!(
            result,
            Err(TowerPersistenceError::Serialization(_)
                | TowerPersistenceError::IncompatibleVersion { .. })
        ));
    }

    #[test]
    fn saved_tower_file_roundtrip() {
        let dir = std::env::temp_dir().join(format!("tower_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let tower = make_tower_with_votes(&[100, 101, 102]);
        let identity = Pubkey::new_unique();
        let saved = SavedTower::from_tower(&tower, identity);

        saved.save_to_directory(&dir).unwrap();
        assert!(SavedTower::exists_in_directory(&dir));

        let loaded = SavedTower::load_from_directory(&dir).unwrap();
        assert_eq!(saved, loaded);

        SavedTower::delete_from_directory(&dir).unwrap();
        assert!(!SavedTower::exists_in_directory(&dir));
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn saved_tower_load_nonexistent_directory() {
        let dir = Path::new("/tmp/nonexistent_tower_test_dir_abc123");
        let result = SavedTower::load_from_directory(dir);
        assert!(matches!(result, Err(TowerPersistenceError::NotFound(_))));
    }

    #[test]
    fn saved_tower_load_and_verify_identity() {
        let dir = std::env::temp_dir().join(format!("tower_verify_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let tower = make_tower_with_votes(&[50, 51]);
        let identity = Pubkey::new_unique();
        let wrong_identity = Pubkey::new_unique();

        let saved = SavedTower::from_tower(&tower, identity);
        saved.save_to_directory(&dir).unwrap();

        let loaded = SavedTower::load_and_verify(&dir, &identity);
        assert!(loaded.is_ok());

        let loaded = SavedTower::load_and_verify(&dir, &wrong_identity);
        assert!(matches!(
            loaded,
            Err(TowerPersistenceError::IdentityMismatch { .. })
        ));

        let _ = SavedTower::delete_from_directory(&dir);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn saved_tower_preserves_root() {
        let mut tower = Tower::new();
        for i in 0..32 {
            tower.push_vote(100 + i);
        }
        assert!(tower.root().is_some());

        let identity = Pubkey::new_unique();
        let saved = SavedTower::from_tower(&tower, identity);
        assert_eq!(saved.root, tower.root());

        let restored = saved.to_tower();
        assert_eq!(restored.root(), tower.root());
    }

    #[test]
    fn saved_tower_empty_tower() {
        let tower = Tower::new();
        let identity = Pubkey::new_unique();

        let saved = SavedTower::from_tower(&tower, identity);
        assert!(saved.votes.is_empty());
        assert_eq!(saved.root, None);
        assert_eq!(saved.last_voted_slot, None);

        let bytes = saved.serialize().unwrap();
        let restored = SavedTower::deserialize(&bytes).unwrap();
        assert_eq!(saved, restored);

        let tower_restored = restored.to_tower();
        assert!(tower_restored.is_empty());
        assert_eq!(tower_restored.root(), None);
    }
}
