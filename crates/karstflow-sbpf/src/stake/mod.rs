/// Stake program execution and state management.
///
/// Provides self-contained stake state types and serialization for the
/// stake program executor. Binary format matches the consensus crate's
/// serialization exactly, enabling interoperability without circular
/// dependencies.
mod program;
mod state;

pub use program::StakeProgramExecutor;
pub use state::{
    deserialize_stake_state, serialize_stake_state, AuthorityType, Authorized, Delegation, Lockup,
    Meta, StakeAccount, StakeError, StakeFlags, StakeState,
};
