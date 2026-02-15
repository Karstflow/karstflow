//! Get/set return data between CPI calls.
//!
//! Programs can set return data that the caller can read after a CPI
//! call returns. Only the most recent return data is available.

use super::{SyscallContext, SyscallError};
use paradencer_constants::syscalls::*;

/// Store return data for the calling program to read.
///
/// The data is tagged with the current program ID and replaces any
/// previously stored return data. Size is limited to
/// `MAX_RETURN_DATA_SIZE` bytes.
pub fn set_return_data(ctx: &mut SyscallContext, data: &[u8]) -> Result<(), SyscallError> {
    let cost = SET_RETURN_DATA_COST + SET_RETURN_DATA_PER_BYTE * data.len() as u64;
    ctx.consume_compute(cost)?;

    if data.len() > MAX_RETURN_DATA_SIZE {
        return Err(SyscallError::MaxReturnDataSizeExceeded);
    }

    ctx.return_data = Some((ctx.program_id, data.to_vec()));
    Ok(())
}

/// Retrieve the return data set by the most recent CPI callee.
///
/// Returns `None` if no return data has been set, otherwise returns the
/// (program_id, data) pair from the callee that set it.
pub fn get_return_data(
    ctx: &mut SyscallContext,
) -> Result<Option<(paradencer_types::Pubkey, Vec<u8>)>, SyscallError> {
    ctx.consume_compute(GET_RETURN_DATA_COST)?;

    Ok(ctx.return_data.clone())
}
