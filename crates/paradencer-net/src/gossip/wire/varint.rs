//! Varint encoding helpers for the gossip wire format.
//!
//! Two encoding schemes are used:
//! - **Compact-u16**: Encodes lengths up to 0xFFFF using 1–3 bytes.
//!   Used for short-vec lengths in the Solana binary format.
//! - **Varint-u64**: Standard LEB128 encoding for 64-bit values.
//!   Used for ContactInfo v2 wallclock and socket port offsets.
//!
//! Serde helper modules are provided for use with `#[serde(with = "...")]`:
//! - [`short_vec`]: Short-vec encoded `Vec<T>` (compact-u16 length prefix).
//! - [`serde_varint_u16`]: LEB128-encoded u16 field.
//! - [`serde_varint_u64`]: LEB128-encoded u64 field.

use std::io;

/// Encode a u16 value using compact-u16 (short-vec) format.
///
/// Encoding uses 7 bits per byte with the MSB as a continuation flag:
/// - `0x00..0x7F`: 1 byte
/// - `0x80..0x3FFF`: 2 bytes
/// - `0x4000..0xFFFF`: 3 bytes
pub fn encode_short_u16(val: u16) -> Vec<u8> {
    let mut rem = val;
    let mut out = Vec::with_capacity(3);
    loop {
        let byte = (rem & 0x7f) as u8;
        rem >>= 7;
        if rem == 0 {
            out.push(byte);
            break;
        } else {
            out.push(byte | 0x80);
        }
    }
    out
}

/// Decode a compact-u16 value from a byte slice.
///
/// Returns `(value, bytes_consumed)` on success.
pub fn decode_short_u16(bytes: &[u8]) -> io::Result<(u16, usize)> {
    let mut val: u16 = 0;
    let mut shift = 0u32;
    for (i, &byte) in bytes.iter().enumerate().take(3) {
        val |= ((byte & 0x7f) as u16)
            .checked_shl(shift)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short-u16 overflow"))?;
        if byte & 0x80 == 0 {
            return Ok((val, i + 1));
        }
        shift += 7;
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "short-u16: unterminated encoding",
    ))
}

/// Encode a u64 value using LEB128 variable-length encoding.
pub fn encode_varint_u64(val: u64) -> Vec<u8> {
    let mut rem = val;
    let mut out = Vec::with_capacity(10);
    loop {
        let byte = (rem & 0x7f) as u8;
        rem >>= 7;
        if rem == 0 {
            out.push(byte);
            break;
        } else {
            out.push(byte | 0x80);
        }
    }
    out
}

/// Decode a LEB128 varint-u64 from a byte slice.
///
/// Returns `(value, bytes_consumed)` on success.
pub fn decode_varint_u64(bytes: &[u8]) -> io::Result<(u64, usize)> {
    let mut val: u64 = 0;
    let mut shift = 0u32;
    for (i, &byte) in bytes.iter().enumerate().take(10) {
        val |= ((byte & 0x7f) as u64)
            .checked_shl(shift)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "varint-u64 overflow"))?;
        if byte & 0x80 == 0 {
            return Ok((val, i + 1));
        }
        shift += 7;
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "varint-u64: unterminated encoding",
    ))
}

// ---------------------------------------------------------------------------
// Serde helper: short-vec encoded Vec<T>
// ---------------------------------------------------------------------------

/// Serde helper for short-vec encoded `Vec<T>`.
///
/// Uses compact-u16 length prefix instead of bincode's default u64.
/// Compatible with the Solana `solana-short-vec` crate layout.
///
/// Usage: `#[serde(with = "crate::gossip::wire::varint::short_vec")]`
pub mod short_vec {
    use serde::de::{self, SeqAccess, Visitor};
    use serde::ser::SerializeTuple;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::marker::PhantomData;

    pub fn serialize<T: Serialize, S: Serializer>(
        vec: &Vec<T>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let len = vec.len();
        let short_len_bytes = super::encode_short_u16(len as u16);
        let tuple_len = short_len_bytes.len() + len;
        let mut seq = serializer.serialize_tuple(tuple_len)?;
        for &byte in &short_len_bytes {
            seq.serialize_element(&byte)?;
        }
        for element in vec {
            seq.serialize_element(element)?;
        }
        seq.end()
    }

    pub fn deserialize<'de, T: Deserialize<'de>, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<T>, D::Error> {
        struct ShortVecVisitor<T>(PhantomData<T>);

        impl<'de, T: Deserialize<'de>> Visitor<'de> for ShortVecVisitor<T> {
            type Value = Vec<T>;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a short-vec encoded sequence")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<T>, A::Error> {
                let mut len: usize = 0;
                let mut shift = 0;
                loop {
                    let byte: u8 = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::custom("truncated short-vec length"))?;
                    len |= ((byte & 0x7f) as usize) << shift;
                    if byte & 0x80 == 0 {
                        break;
                    }
                    shift += 7;
                    if shift > 14 {
                        return Err(de::Error::custom("short-vec length overflow"));
                    }
                }

                let mut vec = Vec::with_capacity(len.min(4096));
                for _ in 0..len {
                    vec.push(
                        seq.next_element()?
                            .ok_or_else(|| de::Error::custom("short-vec element missing"))?,
                    );
                }
                Ok(vec)
            }
        }

        deserializer.deserialize_tuple(65539, ShortVecVisitor(PhantomData))
    }
}

// ---------------------------------------------------------------------------
// Serde helper: LEB128-encoded u16
// ---------------------------------------------------------------------------

/// Serde helper for LEB128-encoded u16 fields.
///
/// Usage: `#[serde(with = "crate::gossip::wire::varint::serde_varint_u16")]`
pub mod serde_varint_u16 {
    use serde::de::{self, SeqAccess, Visitor};
    use serde::ser::SerializeTuple;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(val: &u16, serializer: S) -> Result<S::Ok, S::Error> {
        let encoded = super::encode_short_u16(*val);
        let mut seq = serializer.serialize_tuple(encoded.len())?;
        for &byte in &encoded {
            seq.serialize_element(&byte)?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u16, D::Error> {
        struct VarintU16Visitor;

        impl<'de> Visitor<'de> for VarintU16Visitor {
            type Value = u16;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a varint-encoded u16")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<u16, A::Error> {
                let mut val: u16 = 0;
                let mut shift = 0u32;
                loop {
                    let byte: u8 = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::custom("truncated varint-u16"))?;
                    val |= ((byte & 0x7f) as u16)
                        .checked_shl(shift)
                        .ok_or_else(|| de::Error::custom("varint-u16 overflow"))?;
                    if byte & 0x80 == 0 {
                        return Ok(val);
                    }
                    shift += 7;
                    if shift > 14 {
                        return Err(de::Error::custom("varint-u16 too many bytes"));
                    }
                }
            }
        }

        deserializer.deserialize_tuple(3, VarintU16Visitor)
    }
}

// ---------------------------------------------------------------------------
// Serde helper: LEB128-encoded u64
// ---------------------------------------------------------------------------

/// Serde helper for LEB128-encoded u64 fields.
///
/// Usage: `#[serde(with = "crate::gossip::wire::varint::serde_varint_u64")]`
pub mod serde_varint_u64 {
    use serde::de::{self, SeqAccess, Visitor};
    use serde::ser::SerializeTuple;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(val: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        let encoded = super::encode_varint_u64(*val);
        let mut seq = serializer.serialize_tuple(encoded.len())?;
        for &byte in &encoded {
            seq.serialize_element(&byte)?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        struct VarintU64Visitor;

        impl<'de> Visitor<'de> for VarintU64Visitor {
            type Value = u64;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a varint-encoded u64")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<u64, A::Error> {
                let mut val: u64 = 0;
                let mut shift = 0u32;
                loop {
                    let byte: u8 = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::custom("truncated varint-u64"))?;
                    val |= ((byte & 0x7f) as u64)
                        .checked_shl(shift)
                        .ok_or_else(|| de::Error::custom("varint-u64 overflow"))?;
                    if byte & 0x80 == 0 {
                        return Ok(val);
                    }
                    shift += 7;
                    if shift >= 70 {
                        return Err(de::Error::custom("varint-u64 too many bytes"));
                    }
                }
            }
        }

        deserializer.deserialize_tuple(10, VarintU64Visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_u16_single_byte() {
        for val in 0..0x80u16 {
            let encoded = encode_short_u16(val);
            assert_eq!(encoded.len(), 1);
            let (decoded, consumed) = decode_short_u16(&encoded).unwrap();
            assert_eq!(decoded, val);
            assert_eq!(consumed, 1);
        }
    }

    #[test]
    fn short_u16_two_bytes() {
        for val in [0x80u16, 0xFF, 0x100, 0x3FFF] {
            let encoded = encode_short_u16(val);
            assert_eq!(encoded.len(), 2, "val={val:#x}");
            let (decoded, consumed) = decode_short_u16(&encoded).unwrap();
            assert_eq!(decoded, val);
            assert_eq!(consumed, 2);
        }
    }

    #[test]
    fn short_u16_three_bytes() {
        for val in [0x4000u16, 0x7FFF, 0xFFFF] {
            let encoded = encode_short_u16(val);
            assert_eq!(encoded.len(), 3, "val={val:#x}");
            let (decoded, consumed) = decode_short_u16(&encoded).unwrap();
            assert_eq!(decoded, val);
            assert_eq!(consumed, 3);
        }
    }

    #[test]
    fn short_u16_round_trip_exhaustive() {
        for val in 0..=u16::MAX {
            let encoded = encode_short_u16(val);
            let (decoded, _) = decode_short_u16(&encoded).unwrap();
            assert_eq!(decoded, val);
        }
    }

    #[test]
    fn varint_u64_single_byte() {
        for val in 0..0x80u64 {
            let encoded = encode_varint_u64(val);
            assert_eq!(encoded.len(), 1);
            let (decoded, consumed) = decode_varint_u64(&encoded).unwrap();
            assert_eq!(decoded, val);
            assert_eq!(consumed, 1);
        }
    }

    #[test]
    fn varint_u64_multi_byte() {
        let cases: &[(u64, usize)] = &[
            (0x80, 2),
            (0x3FFF, 2),
            (0x4000, 3),
            (0x1F_FFFF, 3),
            (0x20_0000, 4),
            (u64::MAX, 10),
        ];
        for &(val, expected_len) in cases {
            let encoded = encode_varint_u64(val);
            assert_eq!(encoded.len(), expected_len, "val={val:#x}");
            let (decoded, consumed) = decode_varint_u64(&encoded).unwrap();
            assert_eq!(decoded, val);
            assert_eq!(consumed, expected_len);
        }
    }

    #[test]
    fn varint_u64_round_trip_powers_of_two() {
        for shift in 0..64 {
            let val = 1u64 << shift;
            let encoded = encode_varint_u64(val);
            let (decoded, _) = decode_varint_u64(&encoded).unwrap();
            assert_eq!(decoded, val);
        }
    }

    #[test]
    fn decode_empty_slice_errors() {
        assert!(decode_short_u16(&[]).is_err());
        assert!(decode_varint_u64(&[]).is_err());
    }

    #[test]
    fn decode_truncated_errors() {
        // Continuation bit set but no following byte
        assert!(decode_short_u16(&[0x80]).is_err());
        assert!(decode_varint_u64(&[0x80]).is_err());
    }

    #[test]
    fn short_vec_serde_round_trip_bincode() {
        let original: Vec<u32> = vec![1, 2, 3, 42, 999];

        // Wrapper to use #[serde(with = "short_vec")]
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct Wrapper {
            #[serde(with = "super::short_vec")]
            items: Vec<u32>,
        }

        let w = Wrapper {
            items: original.clone(),
        };
        let bytes = bincode::serialize(&w).unwrap();
        let decoded: Wrapper = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded.items, original);

        // Verify the compact-u16 length prefix: 5 items = [0x05]
        assert_eq!(bytes[0], 5u8);
        // Followed by 5 * 4 bytes (u32 in bincode)
        assert_eq!(bytes.len(), 1 + 5 * 4);
    }

    #[test]
    fn short_vec_serde_empty() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct Wrapper {
            #[serde(with = "super::short_vec")]
            items: Vec<u8>,
        }

        let w = Wrapper { items: vec![] };
        let bytes = bincode::serialize(&w).unwrap();
        assert_eq!(bytes, &[0x00]); // compact-u16 of 0
        let decoded: Wrapper = bincode::deserialize(&bytes).unwrap();
        assert!(decoded.items.is_empty());
    }

    #[test]
    fn serde_varint_u16_round_trip() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct Wrapper {
            #[serde(with = "super::serde_varint_u16")]
            val: u16,
        }

        for val in [0u16, 1, 127, 128, 255, 16383, 16384, 65535] {
            let w = Wrapper { val };
            let bytes = bincode::serialize(&w).unwrap();
            let decoded: Wrapper = bincode::deserialize(&bytes).unwrap();
            assert_eq!(decoded.val, val, "failed for {val}");
        }
    }

    #[test]
    fn serde_varint_u64_round_trip() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct Wrapper {
            #[serde(with = "super::serde_varint_u64")]
            val: u64,
        }

        for val in [0u64, 1, 127, 128, 16383, 1_000_000, u64::MAX] {
            let w = Wrapper { val };
            let bytes = bincode::serialize(&w).unwrap();
            let decoded: Wrapper = bincode::deserialize(&bytes).unwrap();
            assert_eq!(decoded.val, val, "failed for {val}");
        }
    }
}
