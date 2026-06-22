//! Alpenglow consensus engine (Votor voting + certificates + aggregate BLS).
//!
//! This crate is a feature-gated, **disabled-by-default** Rust port of the
//! Solana Alpenglow consensus protocol, tracking the reference implementation
//! (firedancer `origin/alpenglow` / the Solana Alpenglow Rust reference). It is
//! deliberately NOT wired into the running validator: the live node continues to
//! use Tower BFT. The crate exists in the workspace so the engine is compiled
//! and unit-tested, but nothing here is instantiated until the engine is
//! explicitly enabled (the `engine` cargo feature plus a runtime switch).
//!
//! Port status (see `.bgv` plan `190000-alpenglow-engine-port-plan.md`):
//! - P0 base — DONE (this module).
//! - P1 messages (vote/cert), P2 aggsig, P3 slot_state, P4 trackers, P5 votor,
//!   P6 pool, P7 scaffolding, P8 validation — pending.

pub mod aggsig;
pub mod base;
pub mod cert;
pub mod epoch_info;
pub mod finality_tracker;
pub mod parent_ready_state;
pub mod parent_ready_tracker;
pub mod pool;
pub mod slot_state;
pub mod vote;
pub mod votor;

pub use base::{
    fraction_is_met, is_genesis_window, is_quorum, is_start_of_window, is_strong_quorum,
    is_weak_quorum, is_weakest_quorum, BlockHash, BlockId, DELTA_BLOCK_NS, DELTA_FIRST_SLICE_NS,
    DELTA_NS, DELTA_STANDSTILL_NS, DELTA_TIMEOUT_NS, GENESIS_BLOCK_HASH, QUORUM_DENOM,
    QUORUM_NUMER, SLOTS_PER_EPOCH, SLOTS_PER_WINDOW, STRONG_QUORUM_NUMER, WEAKEST_QUORUM_NUMER,
    WEAK_QUORUM_NUMER,
};
