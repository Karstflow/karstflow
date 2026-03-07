# karstflow-conformance

Conformance test harnesses for verifying karstflow's execution correctness at three layers: instruction, transaction, and block.

## Purpose

This crate provides structured test infrastructure that exercises the full execution stack — from individual instruction dispatch through transaction processing to block finalization and bank hash computation. Tests compare execution outcomes against expected post-states, catching regressions in:

- System program instruction semantics (transfer, create account)
- BPF program loading and execution
- Transaction fee calculation and payer deduction
- Multi-instruction transaction ordering
- Block-level bank hash determinism
- State diff accuracy between expected and actual outcomes

## Architecture

```
karstflow-conformance/
  src/
    lib.rs              # Crate root, module declarations
    fixture.rs          # Serializable fixture types for test vectors (JSON + base64)
    diff.rs             # State diff engine: compares HashMap<Pubkey, Account> states
    harness/
      mod.rs
      instruction.rs    # Single instruction execution via ExecutionBackend
      transaction.rs    # Full transaction processing via Bank::process_transaction
      block.rs          # Block execution with multiple transactions + bank hash
    tests/
      mod.rs
      instruction_conformance.rs   # 11 instruction-level tests
      transaction_conformance.rs   # 5 transaction-level tests
      block_conformance.rs         # 5 block-level tests
      diff_conformance.rs          # 11 state diff engine tests
  fixtures/             # (future) JSON fixture files for reproducible test vectors
```

### Harness Layers

| Layer | Harness | What it tests |
|---|---|---|
| **Instruction** | `execute_instruction()` | Single instruction via `ExecutionBackend::execute_instruction` with provided accounts |
| **Transaction** | `execute_transaction()` + `TransactionSetup::execute()` | Full transaction lifecycle: bootstrap dev genesis bank, inject accounts, run `Bank::process_transaction` |
| **Block** | `execute_block()` | Sequence of transactions as a block, bank hash computation |

Each layer builds on the one below. Instruction tests are fastest and most isolated; block tests exercise the complete slot finalization pipeline.

### State Diff Engine

`diff.rs` provides `compare_accounts()` which produces a `StateDiff` showing:
- Field-level mismatches (lamports, owner, executable, data)
- Missing expected accounts
- Unexpected modified accounts

This enables precise diagnostics when conformance tests fail.

### Fixture System

`fixture.rs` defines serializable types (`FixtureAccount`, `InstructionFixture`, `TransactionFixture`, `BlockFixture`) with base64-encoded account data. These support:
- Generating test vectors from execution results
- Loading fixture files for regression testing
- Cross-implementation comparison (same fixture, different validator)

## Test Inventory

### Instruction Conformance (11 tests, `#[ignore]`)
- System transfer: moves lamports, insufficient funds, zero amount, self-transfer, exact balance
- System create account: allocates space, insufficient funds
- Unknown program: fails with error
- Compute budget: instruction consumes CU
- BPF: noop program executes

### Transaction Conformance (5 tests, `#[ignore]`)
- Transfer updates balances
- Insufficient funds transfer fails
- Multiple transfers in one transaction
- Fee deducted from payer
- Execution produces logs

### Block Conformance (5 tests, `#[ignore]`)
- Empty block produces bank hash
- Single transfer block
- Multiple transactions block
- Mixed success/failure block
- Bank hash is deterministic

### Diff Engine (15 tests, run normally)
- 4 unit tests in `diff.rs`
- 11 conformance tests in `diff_conformance.rs`

## Running

```bash
# Run non-ignored tests (diff engine, always fast)
cargo test -p karstflow-conformance

# Run conformance tests (require full execution stack)
just conformance
# or:
cargo test -p karstflow-conformance -- --ignored --test-threads=1
```

## Progress

- [x] Fixture types with JSON/base64 serialization
- [x] State diff engine with field-level comparison
- [x] Instruction harness + 11 tests
- [x] Transaction harness + 5 tests
- [x] Block harness + 5 tests
- [x] Diff conformance tests (11 tests)
- [x] Workspace integration + justfile command
- [ ] Fixture file loading from disk
- [ ] Block replay from recorded ledger data
- [ ] Cross-implementation fixture generation
