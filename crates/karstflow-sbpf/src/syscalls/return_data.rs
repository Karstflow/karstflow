//! Get/set return data between CPI calls.
//!
//! Programs can set return data that the caller can read after a CPI
//! call returns. Only the most recent return data is available.

use super::{SyscallContext, SyscallError};
use karstflow_constants::syscalls::*;

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
) -> Result<Option<(karstflow_types::Pubkey, Vec<u8>)>, SyscallError> {
    ctx.consume_compute(GET_RETURN_DATA_COST)?;

    Ok(ctx.return_data.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use karstflow_types::Pubkey;

    fn ctx(budget: u64) -> SyscallContext {
        SyscallContext::new(Pubkey::new([1u8; 32]), budget)
    }

    #[test]
    fn set_and_get_return_data() {
        let mut c = ctx(100_000);
        set_return_data(&mut c, b"hello").unwrap();
        let result = get_return_data(&mut c).unwrap();
        assert!(result.is_some());
        let (program_id, data) = result.unwrap();
        assert_eq!(program_id, Pubkey::new([1u8; 32]));
        assert_eq!(data, b"hello");
    }

    #[test]
    fn get_return_data_returns_none_initially() {
        let mut c = ctx(100_000);
        let result = get_return_data(&mut c).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn set_return_data_replaces_previous() {
        let mut c = ctx(100_000);
        set_return_data(&mut c, b"first").unwrap();
        set_return_data(&mut c, b"second").unwrap();
        let result = get_return_data(&mut c).unwrap().unwrap();
        assert_eq!(result.1, b"second");
    }

    #[test]
    fn set_return_data_empty_is_valid() {
        let mut c = ctx(100_000);
        set_return_data(&mut c, b"").unwrap();
        let result = get_return_data(&mut c).unwrap().unwrap();
        assert!(result.1.is_empty());
    }

    #[test]
    fn set_return_data_rejects_oversized() {
        let mut c = ctx(10_000_000);
        let big_data = vec![0u8; MAX_RETURN_DATA_SIZE + 1];
        let result = set_return_data(&mut c, &big_data);
        assert!(matches!(
            result,
            Err(SyscallError::MaxReturnDataSizeExceeded)
        ));
    }

    #[test]
    fn set_return_data_accepts_max_size() {
        let mut c = ctx(100_000_000);
        let data = vec![0u8; MAX_RETURN_DATA_SIZE];
        assert!(set_return_data(&mut c, &data).is_ok());
    }

    #[test]
    fn set_return_data_consumes_compute() {
        let mut c = ctx(5);
        assert!(set_return_data(&mut c, b"hello").is_err());
    }

    #[test]
    fn get_return_data_consumes_compute() {
        let mut c = ctx(5);
        assert!(get_return_data(&mut c).is_err());
    }

    #[test]
    fn return_data_tagged_with_program_id() {
        let pid = Pubkey::new([42u8; 32]);
        let mut c = SyscallContext::new(pid, 100_000);
        set_return_data(&mut c, b"tagged").unwrap();
        let (returned_pid, _) = get_return_data(&mut c).unwrap().unwrap();
        assert_eq!(returned_pid, pid);
    }
}
