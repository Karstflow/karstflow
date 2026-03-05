/// Compact encoding utilities for Solana's wire format.
///
/// Solana uses a compact-u16 encoding for array lengths in transaction
/// messages. This is a variable-length encoding where:
/// - Values 0..0x7F use 1 byte
/// - Values 0x80..0x3FFF use 2 bytes
/// - Values 0x4000..0xFFFF use 3 bytes
///
/// This differs from standard LEB128 in that it uses the low 7 bits of
/// each byte for data and the high bit as a continuation flag.
use std::io::{self, Read, Write};

/// Maximum encoded size of a compact-u16 value.
pub const COMPACT_U16_MAX_ENCODED_SIZE: usize = 3;

/// Encode a u16 value in compact format.
/// Returns the number of bytes written (1, 2, or 3).
pub fn encode_compact_u16(value: u16, buf: &mut [u8]) -> usize {
    let mut rem = value;
    let mut i = 0;
    loop {
        let low = (rem & 0x7F) as u8;
        rem >>= 7;
        if rem == 0 {
            buf[i] = low;
            return i + 1;
        }
        buf[i] = low | 0x80;
        i += 1;
    }
}

/// Decode a compact-u16 value from a byte slice.
/// Returns (value, bytes_consumed) or an error if the encoding is invalid.
pub fn decode_compact_u16(data: &[u8]) -> Result<(u16, usize), CompactError> {
    if data.is_empty() {
        return Err(CompactError::UnexpectedEnd);
    }

    let mut value: u16 = 0;
    let mut shift: u32 = 0;

    for (i, &byte) in data.iter().enumerate() {
        if i >= COMPACT_U16_MAX_ENCODED_SIZE {
            return Err(CompactError::TooManyBytes);
        }

        let low = (byte & 0x7F) as u16;
        value |= low.checked_shl(shift).ok_or(CompactError::Overflow)?;
        shift += 7;

        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
    }

    Err(CompactError::UnexpectedEnd)
}

/// Write a compact-u16 to a writer.
pub fn write_compact_u16<W: Write>(writer: &mut W, value: u16) -> io::Result<usize> {
    let mut buf = [0u8; COMPACT_U16_MAX_ENCODED_SIZE];
    let len = encode_compact_u16(value, &mut buf);
    writer.write_all(&buf[..len])?;
    Ok(len)
}

/// Read a compact-u16 from a reader.
pub fn read_compact_u16<R: Read>(reader: &mut R) -> io::Result<u16> {
    let mut value: u16 = 0;
    let mut shift: u32 = 0;

    for i in 0..COMPACT_U16_MAX_ENCODED_SIZE {
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte)?;

        let low = (byte[0] & 0x7F) as u16;
        value |= low
            .checked_shl(shift)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "compact-u16 overflow"))?;
        shift += 7;

        if byte[0] & 0x80 == 0 {
            return Ok(value);
        }

        if i == COMPACT_U16_MAX_ENCODED_SIZE - 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "compact-u16 too many bytes",
            ));
        }
    }

    Err(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "compact-u16 unexpected end",
    ))
}

/// Errors in compact encoding/decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompactError {
    /// Not enough bytes to decode.
    UnexpectedEnd,
    /// Value overflows u16.
    Overflow,
    /// More than 3 bytes in encoding.
    TooManyBytes,
}

impl std::fmt::Display for CompactError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompactError::UnexpectedEnd => write!(f, "unexpected end of compact-u16 data"),
            CompactError::Overflow => write!(f, "compact-u16 value overflow"),
            CompactError::TooManyBytes => write!(f, "compact-u16 encoding exceeds 3 bytes"),
        }
    }
}

impl std::error::Error for CompactError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_zero() {
        let mut buf = [0u8; 3];
        let len = encode_compact_u16(0, &mut buf);
        assert_eq!(len, 1);
        assert_eq!(buf[0], 0);
    }

    #[test]
    fn encode_small_value() {
        let mut buf = [0u8; 3];
        let len = encode_compact_u16(42, &mut buf);
        assert_eq!(len, 1);
        assert_eq!(buf[0], 42);
    }

    #[test]
    fn encode_boundary_127() {
        let mut buf = [0u8; 3];
        let len = encode_compact_u16(0x7F, &mut buf);
        assert_eq!(len, 1);
        assert_eq!(buf[0], 0x7F);
    }

    #[test]
    fn encode_boundary_128() {
        let mut buf = [0u8; 3];
        let len = encode_compact_u16(0x80, &mut buf);
        assert_eq!(len, 2);
        assert_eq!(buf[0], 0x80); // low 7 bits = 0, continuation bit set
        assert_eq!(buf[1], 0x01); // remaining value = 1
    }

    #[test]
    fn encode_u16_max() {
        let mut buf = [0u8; 3];
        let len = encode_compact_u16(u16::MAX, &mut buf);
        assert_eq!(len, 3);
    }

    #[test]
    fn roundtrip_all_important_values() {
        let test_values: Vec<u16> = vec![0, 1, 127, 128, 255, 256, 16383, 16384, 32767, 65535];
        for &value in &test_values {
            let mut buf = [0u8; 3];
            let encoded_len = encode_compact_u16(value, &mut buf);
            let (decoded, consumed) = decode_compact_u16(&buf[..encoded_len]).unwrap();
            assert_eq!(decoded, value, "roundtrip failed for {}", value);
            assert_eq!(consumed, encoded_len);
        }
    }

    #[test]
    fn decode_empty_slice_errors() {
        let result = decode_compact_u16(&[]);
        assert_eq!(result, Err(CompactError::UnexpectedEnd));
    }

    #[test]
    fn decode_truncated_errors() {
        // 0x80 means "more bytes follow" but there are none
        let result = decode_compact_u16(&[0x80]);
        assert_eq!(result, Err(CompactError::UnexpectedEnd));
    }

    #[test]
    fn writer_reader_roundtrip() {
        let test_values: Vec<u16> = vec![0, 1, 127, 128, 16383, 16384, 65535];
        for &value in &test_values {
            let mut buf = Vec::new();
            write_compact_u16(&mut buf, value).unwrap();

            let mut cursor = std::io::Cursor::new(&buf);
            let decoded = read_compact_u16(&mut cursor).unwrap();
            assert_eq!(
                decoded, value,
                "writer/reader roundtrip failed for {}",
                value
            );
        }
    }

    #[test]
    fn encoding_sizes() {
        let mut buf = [0u8; 3];

        // 1 byte: 0..127
        assert_eq!(encode_compact_u16(0, &mut buf), 1);
        assert_eq!(encode_compact_u16(127, &mut buf), 1);

        // 2 bytes: 128..16383
        assert_eq!(encode_compact_u16(128, &mut buf), 2);
        assert_eq!(encode_compact_u16(16383, &mut buf), 2);

        // 3 bytes: 16384..65535
        assert_eq!(encode_compact_u16(16384, &mut buf), 3);
        assert_eq!(encode_compact_u16(65535, &mut buf), 3);
    }
}
