use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StorageError {
    #[error("fragment id regression: last={last_fragment_id}, new={new_fragment_id}")]
    FragmentRegression {
        last_fragment_id: u64,
        new_fragment_id: u64,
    },
    #[error("snapshot not found for fragment id {fragment_id}")]
    SnapshotNotFound { fragment_id: u64 },
    #[error("snapshot regression: last_snapshot_fragment_id={last_snapshot_fragment_id}, new_snapshot_fragment_id={new_snapshot_fragment_id}")]
    SnapshotRegression {
        last_snapshot_fragment_id: u64,
        new_snapshot_fragment_id: u64,
    },
    #[error("snapshot catalog file is missing: {path}")]
    CatalogFileMissing { path: PathBuf },
    #[error("failed to read snapshot catalog file '{path}': {message}")]
    CatalogFileRead { path: PathBuf, message: String },
    #[error("failed to write snapshot catalog file '{path}': {message}")]
    CatalogFileWrite { path: PathBuf, message: String },
    #[error("failed to deserialize snapshot catalog file '{path}': {message}")]
    CatalogDeserialize { path: PathBuf, message: String },
    #[error("unsupported snapshot catalog schema_version {found}, expected {expected}")]
    UnsupportedCatalogSchema { found: u32, expected: u32 },
    #[error(
        "snapshot checksum mismatch in '{path}' for fragment {fragment_id}: expected {expected}, found {found}"
    )]
    SnapshotChecksumMismatch {
        path: PathBuf,
        fragment_id: u64,
        expected: u64,
        found: u64,
    },
    #[error("snapshot catalog invariant violation in '{path}': {message}")]
    CatalogInvariantViolation { path: PathBuf, message: String },
    #[error(
        "runtime state rollback order violation: expected last fragment {expected_last_fragment_id}, receipt fragment {receipt_fragment_id}"
    )]
    RuntimeStateRollbackOrderViolation {
        expected_last_fragment_id: u64,
        receipt_fragment_id: u64,
    },
    #[error(
        "runtime state rollback receipt invariant violation: receipt fragment {receipt_fragment_id}, previous fragment {previous_last_fragment_id}"
    )]
    RuntimeStateReceiptInvariantViolation {
        receipt_fragment_id: u64,
        previous_last_fragment_id: u64,
    },
    #[error(
        "runtime state rollback receipt mismatch: expected fragment {expected_fragment_id}, got {provided_fragment_id}"
    )]
    RuntimeStateReceiptMismatch {
        expected_fragment_id: u64,
        provided_fragment_id: u64,
    },
    #[error(
        "runtime state rewind target is ahead of current state: current={current_last_fragment_id}, target={target_fragment_id}"
    )]
    RuntimeStateRewindTargetAhead {
        current_last_fragment_id: u64,
        target_fragment_id: u64,
    },
    #[error(
        "runtime state rewind target is below rewind floor: floor={rewind_floor_fragment_id}, target={target_fragment_id}"
    )]
    RuntimeStateRewindTargetBelowFloor {
        rewind_floor_fragment_id: u64,
        target_fragment_id: u64,
    },
    #[error("runtime state underflow for field '{field}': current={current}, rollback={rollback}")]
    RuntimeStateUnderflow {
        field: &'static str,
        current: u64,
        rollback: u64,
    },
    #[error("state counter overflow for field '{field}': current={current}, delta={delta}")]
    StateCounterOverflow {
        field: &'static str,
        current: u64,
        delta: u64,
    },

    #[error("Cannot modify published transaction")]
    CannotModifyPublished,

    #[error("Cannot publish root transaction")]
    CannotPublishRoot,

    #[error("Cannot cancel root transaction")]
    CannotCancelRoot,

    #[error("Account not found: {pubkey:?}")]
    AccountNotFound { pubkey: String },

    #[error("Account database error: {details}")]
    AccountDatabaseError { details: String },

    #[error("Snapshot creation failed: {details}")]
    SnapshotCreationFailed { details: String },

    #[error("Snapshot loading failed: {details}")]
    SnapshotLoadingFailed { details: String },

    #[error("Snapshot verification failed: {details}")]
    SnapshotVerificationFailed { details: String },
}
