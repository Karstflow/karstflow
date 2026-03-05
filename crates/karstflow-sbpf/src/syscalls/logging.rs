//! Program logging syscalls.
//!
//! Allows programs to emit log messages that are captured in the
//! transaction's execution trace. All logging operations consume
//! compute units proportional to the data size.

use super::{SyscallContext, SyscallError};
use karstflow_constants::syscalls::*;

/// Log a UTF-8 message from a program.
///
/// The message is appended to the context's log buffer and the cost
/// scales with message length.
pub fn sol_log(ctx: &mut SyscallContext, message: &str) -> Result<(), SyscallError> {
    let cost = LOG_BASE_COST + LOG_PER_BYTE_COST * message.len() as u64;
    ctx.consume_compute(cost)?;

    ctx.logs.push(format!("Program log: {}", message));

    Ok(())
}

/// Log binary data slices, each encoded as base64 in the output.
///
/// Multiple data slices can be logged in a single call. Each slice is
/// base64-encoded and joined by spaces in the log line.
pub fn sol_log_data(ctx: &mut SyscallContext, data: &[&[u8]]) -> Result<(), SyscallError> {
    let total_bytes: usize = data.iter().map(|d| d.len()).sum();
    let cost = LOG_DATA_BASE_COST + LOG_PER_BYTE_COST * total_bytes as u64;
    ctx.consume_compute(cost)?;

    // Simple base64 encoding (basic implementation without external dependency).
    let encoded_parts: Vec<String> = data.iter().map(|d| encode_base64(d)).collect();

    ctx.logs
        .push(format!("Program data: {}", encoded_parts.join(" ")));

    Ok(())
}

/// Log the remaining compute units available to the program.
pub fn sol_log_compute_units(ctx: &mut SyscallContext) -> Result<(), SyscallError> {
    ctx.consume_compute(LOG_COMPUTE_UNITS_COST)?;

    ctx.logs.push(format!(
        "Program consumption: {} units remaining",
        ctx.compute_meter
    ));

    Ok(())
}

/// Log a public key as a base58-encoded string.
///
/// Reads 32 bytes from the given address and logs the base58 representation.
pub fn sol_log_pubkey(
    ctx: &mut SyscallContext,
    pubkey_bytes: &[u8; 32],
) -> Result<(), SyscallError> {
    ctx.consume_compute(LOG_PUBKEY_COST)?;

    let encoded = bs58::encode(pubkey_bytes).into_string();
    ctx.logs.push(format!("Program log: {}", encoded));

    Ok(())
}

/// Minimal base64 encoding without external dependencies.
fn encode_base64(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);
    let chunks = data.chunks(3);

    for chunk in chunks {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };

        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);

        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use karstflow_types::Pubkey;

    fn ctx(budget: u64) -> SyscallContext {
        SyscallContext::new(Pubkey::new([0u8; 32]), budget)
    }

    #[test]
    fn sol_log_appends_message() {
        let mut c = ctx(100_000);
        sol_log(&mut c, "hello world").unwrap();
        assert_eq!(c.logs.len(), 1);
        assert!(c.logs[0].contains("hello world"));
    }

    #[test]
    fn sol_log_consumes_compute() {
        let mut c = ctx(5);
        assert!(sol_log(&mut c, "this message exceeds budget").is_err());
    }

    #[test]
    fn sol_log_data_encodes_base64() {
        let mut c = ctx(100_000);
        sol_log_data(&mut c, &[b"test"]).unwrap();
        assert_eq!(c.logs.len(), 1);
        assert!(c.logs[0].starts_with("Program data: "));
    }

    #[test]
    fn sol_log_data_multiple_slices() {
        let mut c = ctx(100_000);
        sol_log_data(&mut c, &[b"ab", b"cd"]).unwrap();
        assert_eq!(c.logs.len(), 1);
        // Should have two base64 parts separated by space
        let data_part = c.logs[0].strip_prefix("Program data: ").unwrap();
        assert_eq!(data_part.split(' ').count(), 2);
    }

    #[test]
    fn sol_log_compute_units_reports_remaining() {
        let mut c = ctx(50_000);
        sol_log_compute_units(&mut c).unwrap();
        assert_eq!(c.logs.len(), 1);
        assert!(c.logs[0].contains("remaining"));
    }

    #[test]
    fn sol_log_pubkey_logs_base58() {
        let mut c = ctx(100_000);
        let pk = [1u8; 32];
        sol_log_pubkey(&mut c, &pk).unwrap();
        assert_eq!(c.logs.len(), 1);
        // base58 of [1;32] is a specific string
        assert!(c.logs[0].starts_with("Program log: "));
    }

    #[test]
    fn encode_base64_empty() {
        assert_eq!(encode_base64(b""), "");
    }

    #[test]
    fn encode_base64_known_values() {
        assert_eq!(encode_base64(b"f"), "Zg==");
        assert_eq!(encode_base64(b"fo"), "Zm8=");
        assert_eq!(encode_base64(b"foo"), "Zm9v");
    }
}
