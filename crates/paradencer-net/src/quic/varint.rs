/// QUIC variable-length integer encoding (RFC 9000 Section 16).
///
/// Values are encoded in 1, 2, 4, or 8 bytes. The two most-significant bits
/// of the first byte indicate the encoding length:
///   00 → 1 byte  (6-bit value,  max 63)
///   01 → 2 bytes (14-bit value, max 16383)
///   10 → 4 bytes (30-bit value, max 1073741823)
///   11 → 8 bytes (62-bit value, max 4611686018427387903)
use paradencer_constants::network::QUIC_VARINT_MAX;

/// Error returned when varint encoding or decoding fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VarintError {
    /// Buffer too small for the encoded varint.
    BufferTooSmall,
    /// Value exceeds the 62-bit maximum.
    ValueTooLarge,
    /// Input buffer is empty (no bytes to decode).
    EmptyInput,
}

/// Minimum number of bytes needed to encode `value`.
#[inline]
pub fn encoded_size(value: u64) -> Result<usize, VarintError> {
    if value <= 0x3f {
        Ok(1)
    } else if value <= 0x3fff {
        Ok(2)
    } else if value <= 0x3fff_ffff {
        Ok(4)
    } else if value <= QUIC_VARINT_MAX {
        Ok(8)
    } else {
        Err(VarintError::ValueTooLarge)
    }
}

/// Decode a varint from the start of `buf`.
///
/// Returns `(value, bytes_consumed)` on success.
#[inline]
pub fn decode(buf: &[u8]) -> Result<(u64, usize), VarintError> {
    if buf.is_empty() {
        return Err(VarintError::EmptyInput);
    }

    let first = buf[0];
    let length_bits = first >> 6;
    let width = 1usize << length_bits;

    if buf.len() < width {
        return Err(VarintError::BufferTooSmall);
    }

    let value = match width {
        1 => u64::from(first & 0x3f),
        2 => {
            let raw = u16::from_be_bytes([buf[0], buf[1]]);
            u64::from(raw & 0x3fff)
        }
        4 => {
            let raw = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
            u64::from(raw & 0x3fff_ffff)
        }
        8 => {
            let raw = u64::from_be_bytes([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ]);
            raw & QUIC_VARINT_MAX
        }
        _ => unreachable!(),
    };

    Ok((value, width))
}

/// Encode `value` into `buf` using the minimum number of bytes.
///
/// Returns the number of bytes written.
#[inline]
pub fn encode(buf: &mut [u8], value: u64) -> Result<usize, VarintError> {
    let width = encoded_size(value)?;

    if buf.len() < width {
        return Err(VarintError::BufferTooSmall);
    }

    match width {
        1 => {
            buf[0] = value as u8;
        }
        2 => {
            let encoded = (value as u16) | 0x4000;
            let bytes = encoded.to_be_bytes();
            buf[0] = bytes[0];
            buf[1] = bytes[1];
        }
        4 => {
            let encoded = (value as u32) | 0x8000_0000;
            let bytes = encoded.to_be_bytes();
            buf[..4].copy_from_slice(&bytes);
        }
        8 => {
            let encoded = value | 0xc000_0000_0000_0000;
            let bytes = encoded.to_be_bytes();
            buf[..8].copy_from_slice(&bytes);
        }
        _ => unreachable!(),
    }

    Ok(width)
}

/// Encode `value` into `buf` using exactly `width` bytes.
///
/// `width` must be 1, 2, 4, or 8. The value must fit in the given width.
#[inline]
pub fn encode_fixed(buf: &mut [u8], value: u64, width: usize) -> Result<(), VarintError> {
    if buf.len() < width {
        return Err(VarintError::BufferTooSmall);
    }

    match width {
        1 => {
            if value > 0x3f {
                return Err(VarintError::ValueTooLarge);
            }
            buf[0] = value as u8;
        }
        2 => {
            if value > 0x3fff {
                return Err(VarintError::ValueTooLarge);
            }
            let encoded = (value as u16) | 0x4000;
            buf[..2].copy_from_slice(&encoded.to_be_bytes());
        }
        4 => {
            if value > 0x3fff_ffff {
                return Err(VarintError::ValueTooLarge);
            }
            let encoded = (value as u32) | 0x8000_0000;
            buf[..4].copy_from_slice(&encoded.to_be_bytes());
        }
        8 => {
            if value > QUIC_VARINT_MAX {
                return Err(VarintError::ValueTooLarge);
            }
            let encoded = value | 0xc000_0000_0000_0000;
            buf[..8].copy_from_slice(&encoded.to_be_bytes());
        }
        _ => return Err(VarintError::ValueTooLarge),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_one_byte() {
        let mut buf = [0u8; 8];
        assert_eq!(encode(&mut buf, 0).unwrap(), 1);
        assert_eq!(buf[0], 0x00);
        assert_eq!(decode(&buf).unwrap(), (0, 1));

        assert_eq!(encode(&mut buf, 37).unwrap(), 1);
        assert_eq!(buf[0], 37);
        assert_eq!(decode(&buf).unwrap(), (37, 1));

        assert_eq!(encode(&mut buf, 63).unwrap(), 1);
        assert_eq!(buf[0], 63);
        assert_eq!(decode(&buf).unwrap(), (63, 1));
    }

    #[test]
    fn encode_decode_two_bytes() {
        let mut buf = [0u8; 8];
        assert_eq!(encode(&mut buf, 64).unwrap(), 2);
        assert_eq!(decode(&buf).unwrap(), (64, 2));

        assert_eq!(encode(&mut buf, 16383).unwrap(), 2);
        assert_eq!(decode(&buf).unwrap(), (16383, 2));
    }

    #[test]
    fn encode_decode_four_bytes() {
        let mut buf = [0u8; 8];
        assert_eq!(encode(&mut buf, 16384).unwrap(), 4);
        assert_eq!(decode(&buf).unwrap(), (16384, 4));

        assert_eq!(encode(&mut buf, 0x3fff_ffff).unwrap(), 4);
        assert_eq!(decode(&buf).unwrap(), (0x3fff_ffff, 4));
    }

    #[test]
    fn encode_decode_eight_bytes() {
        let mut buf = [0u8; 8];
        assert_eq!(encode(&mut buf, 0x4000_0000).unwrap(), 8);
        assert_eq!(decode(&buf).unwrap(), (0x4000_0000, 8));

        assert_eq!(encode(&mut buf, QUIC_VARINT_MAX).unwrap(), 8);
        assert_eq!(decode(&buf).unwrap(), (QUIC_VARINT_MAX, 8));
    }

    #[test]
    fn value_too_large() {
        let mut buf = [0u8; 8];
        assert_eq!(
            encode(&mut buf, QUIC_VARINT_MAX + 1),
            Err(VarintError::ValueTooLarge)
        );
    }

    #[test]
    fn buffer_too_small_encode() {
        let mut buf = [0u8; 1];
        assert_eq!(encode(&mut buf, 100), Err(VarintError::BufferTooSmall));
    }

    #[test]
    fn buffer_too_small_decode() {
        // 2-byte encoding but only 1 byte available
        let buf = [0x40]; // MSB = 01 → 2-byte encoding
        assert_eq!(decode(&buf), Err(VarintError::BufferTooSmall));
    }

    #[test]
    fn empty_decode() {
        assert_eq!(decode(&[]), Err(VarintError::EmptyInput));
    }

    #[test]
    fn rfc_examples() {
        // RFC 9000 Section 16, Table 4
        let mut buf = [0u8; 8];

        // 151288809941952652 → 0xc2197c5eff14e88c
        let val = 151288809941952652u64;
        encode(&mut buf, val).unwrap();
        assert_eq!(buf, [0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]);
        assert_eq!(decode(&buf).unwrap(), (val, 8));

        // 494878333 → 0x9d7f3e7d
        let val = 494878333u64;
        encode(&mut buf, val).unwrap();
        assert_eq!(buf[..4], [0x9d, 0x7f, 0x3e, 0x7d]);
        assert_eq!(decode(&buf).unwrap(), (val, 4));

        // 15293 → 0x7bbd
        let val = 15293u64;
        encode(&mut buf, val).unwrap();
        assert_eq!(buf[..2], [0x7b, 0xbd]);
        assert_eq!(decode(&buf).unwrap(), (val, 2));

        // 37 → 0x25
        encode(&mut buf, 37).unwrap();
        assert_eq!(buf[0], 0x25);
        assert_eq!(decode(&buf).unwrap(), (37, 1));
    }

    #[test]
    fn encode_fixed_width() {
        let mut buf = [0u8; 8];

        // Encode 5 in 4 bytes (oversize)
        encode_fixed(&mut buf, 5, 4).unwrap();
        assert_eq!(decode(&buf).unwrap(), (5, 4));

        // Encode 5 in 2 bytes
        encode_fixed(&mut buf, 5, 2).unwrap();
        assert_eq!(decode(&buf).unwrap(), (5, 2));

        // Cannot encode 100 in 1 byte (max 63)
        assert_eq!(
            encode_fixed(&mut buf, 100, 1),
            Err(VarintError::ValueTooLarge)
        );
    }

    #[test]
    fn all_boundary_values() {
        let mut buf = [0u8; 8];
        let boundaries = [
            0,
            63,
            64,
            16383,
            16384,
            0x3fff_ffff,
            0x4000_0000,
            QUIC_VARINT_MAX,
        ];

        for &val in &boundaries {
            let n = encode(&mut buf, val).unwrap();
            let (decoded, consumed) = decode(&buf).unwrap();
            assert_eq!(decoded, val, "roundtrip failed for {val}");
            assert_eq!(n, consumed);
        }
    }
}
