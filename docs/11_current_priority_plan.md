# Current Priority Plan

Last updated: 2026-02-19

## Active Priority Queue

Tasks ordered by priority (highest first). Each task improves Firedancer logic parity.

### Priority 1: Status Cache Error Preservation (#24)
**Status**: Pending
**Impact**: Runtime correctness — ensures transaction error codes are preserved and nonce transactions are properly filtered
**Scope**: paradencer-consensus status_cache module
**Details**:
- Current status cache parser is lossy — doesn't preserve error codes from slot history
- Missing nonce transaction filtering (Firedancer excludes nonce txns from cache)
- Fix: Store `TransactionStatusMeta` with error codes, add nonce account detection

### Priority 2: PoH Enhancement (#25)
**Status**: Pending
**Impact**: Consensus correctness — PoH must match Firedancer's hashes_per_tick behavior
**Scope**: paradencer-consensus poh module
**Details**:
- Add feature-gated hashes_per_tick (Firedancer supports dynamic hashing rates)
- Add missing PoH states for tile integration readiness
- Currently ~75% complete, needs tile-aware state machine transitions

### Priority 3: Bank → sBPF VM Integration (#26)
**Status**: Pending
**Impact**: Critical for end-to-end transaction execution
**Scope**: paradencer-consensus bank + paradencer-sbpf integration
**Details**:
- Bank currently has transaction processing skeleton but doesn't invoke sBPF VM
- Need: execution context construction, account loading, VM invocation, state commit
- This is the critical path for a working validator

### Priority 4: Optimistic Confirmation Pipeline (#27)
**Status**: Pending
**Impact**: Required for consensus participation
**Scope**: paradencer-consensus
**Details**:
- Add optimistic confirmation tracking (supermajority vote observation)
- Needed for commitment level reporting and proper fork choice weighting

## Completed Tasks

| Task | Date | Commit |
|------|------|--------|
| Missing VM syscalls (abort, panic, BLS12-381) | 2026-02-19 | 78234a9 |
| Storage metrics + auto-compaction | 2026-02-19 | ff3647b |
| LRU read cache | 2026-02-19 | 413b53c |
| Write-Ahead Log | 2026-02-19 | 090d69d |
| True compaction | 2026-02-18 | fe5dc8c |
| CRC32 checksums + file format versioning | 2026-02-18 | 6a38cbb |

## Backlog (not yet scheduled)

- JIT compiler for sBPF (large effort, ~5K lines)
- Tango-style IPC (shared-memory lock-free queues)
- AF_XDP kernel bypass (Linux-only, performance)
- BLS12-381 full crypto implementation
- Full CRDS gossip with Bloom filters
- Snapshot network download (gossip + HTTP)
- Transaction scheduler / pack tile
