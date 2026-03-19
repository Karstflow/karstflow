//! Conformance test harnesses for karstflow.
//!
//! Provides structured test infrastructure for verifying instruction,
//! transaction, and block execution correctness. Tests compare execution
//! outcomes against expected post-states defined in fixture files or
//! inline expectations.
//!
//! Run: `just conformance` or
//! `cargo test -p karstflow-conformance -- --ignored --test-threads=1`

pub mod diff;
pub mod fixture;
pub mod harness;

#[cfg(test)]
mod tests;
