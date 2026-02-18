# Storage Snapshot Cycles 25-27

Date: 2026-02-18

## Context

After completing cycles 20-24 (incremental snapshot creation, snapshot loader DB integration, AppendVec writer, Solana-compatible archive creator, snapshot scheduler), these cycles complete the manifest serialization pipeline for Solana-compatible snapshot output.

## Cycle 25: Bank State Manifest Serializer
**Commit:** `207a8b4`

**Goal:** Serialize SnapshotBankState to bincode format matching Solana's DeserializableVersionedBank.

**What was done:**
- Promoted `BincodeWriter` from test-only to production code in `bank_fields.rs`
- Added `serialize_bank_state()` that writes all fields in exact parser-compatible order
- Handles all field types: blockhash queue, hard forks, Option<u64>, f64, u128, etc.
- Stakes section writes epoch and stake_history (vote/delegation maps empty)
- Wired into `create_solana_archive_with_state()` method on `SnapshotCreator`
- 8 new roundtrip tests (serialize → parse → verify field identity)
- Updated README with accurate project stats

**Effect:** Snapshot archives can now include a real bank state manifest instead of empty placeholder.

## Cycle 26: Incremental Solana-Compatible Archives
**Commit:** `4897b66`

**Goal:** Produce Solana-compatible incremental snapshot archives using dirty-set tracking.

**What was done:**
- Added `create_incremental_solana_archive()` to `SnapshotCreator`
- Refactored into shared `build_solana_archive()` helper used by both full and incremental
- Incremental filenames follow Solana convention: `incremental-snapshot-{base}-{slot}-{hash}.tar.zst`
- Only includes accounts modified since base_slot via dirty-set drain
- Drains dirty tracking after creation
- 6 new tests including full→incremental→restore→verify workflow

**Effect:** Complete incremental snapshot pipeline in Solana-compatible format.

## Cycle 27: AccountsDbFields Serialization + Full Manifest
**Commit:** `32f2340`

**Goal:** Serialize the AccountsDbFields section that follows bank state in the manifest.

**What was done:**
- Added `StorageEntry` struct (id + stored_bytes per AppendVec)
- Added `AccountsDbLayout` struct (storage_map, slot, bank_hash, lamports_per_signature)
- Added `serialize_full_manifest()` that writes bank state + AccountsDbFields + ExtraFields
- AccountsDbFields includes: storage map, write version, snapshot slot, BankHashInfo, roots
- ExtraFields includes: lamports_per_signature, None for obsolete fields
- Wired into `build_solana_archive()` — archives with bank state now get full manifest
- 5 new tests

**Effect:** Snapshot manifests now include proper storage layout information for Solana validators.

## Test Impact
- Before cycles 25-27: 2,990 tests
- After cycles 25-27: 3,009 tests (+19 new)
- Storage: 385→396 tests
- Bank fields module: 13→26 tests (parser + serializer + full manifest)
- Creator module: 14→20 tests (+ incremental Solana archive)

## Storage Progress
- Before: 64%
- After: 67%
- Key achievements:
  - Complete manifest serialization (bank state + AccountsDbFields + ExtraFields)
  - Incremental Solana-compatible archives with dirty-set tracking
  - Full roundtrip: create → manifest → archive → restore → verify
- Key remaining gaps:
  - Snapshot network download protocol
  - Write-ahead log for crash recovery
  - Account index persistence optimization
  - Full vote/delegation serialization in stakes section
