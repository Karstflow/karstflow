# Current Priority Plan

Last updated: 2026-02-19

## Active Priority Queue

Tasks ordered by priority (highest first). Each task improves Firedancer logic parity.

(No active tasks — scanning for next priority.)

## Completed Tasks

| Task | Date | Commit |
|------|------|--------|
| Optimistic Confirmation Pipeline (multi-threshold: 1/3, 52%, 2/3, 4/5) | 2026-02-19 | pending |
| Bank → sBPF VM integration (verified end-to-end) | 2026-02-19 | — (already complete) |
| PoH 6-state machine + dynamic hashing | 2026-02-19 | 1dd0070 |
| Status cache analysis (matches Firedancer) | 2026-02-19 | — |
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
