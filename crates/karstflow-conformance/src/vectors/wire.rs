//! Minimal protobuf wire-format reader.
//!
//! Upstream conformance fixtures are serialized with a small, flat protobuf
//! schema: six messages using three wire types (varint, 64-bit, and
//! length-delimited). Decoding them needs a field walker, not a protobuf
//! runtime, so this module implements the wire format directly rather than
//! taking a code-generation dependency for six message shapes.
//!
//! The reader is total: every input either yields fields or a [`WireError`].
//! It never panics and never trusts a length prefix, because the corpus is
//! externally generated and is read by the megabyte.

/// Error produced while walking a protobuf byte stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// Input ended in the middle of a value.
    Truncated,
    /// A varint exceeded the 10-byte maximum for a 64-bit value.
    VarintOverflow,
    /// A length prefix pointed past the end of the buffer.
    LengthOutOfBounds,
    /// Wire type 3/4 (deprecated groups) or 6/7 (unassigned) appeared.
    UnsupportedWireType(u8),
    /// A packed repeated `fixed64` field had a length that is not a multiple of 8.
    MisalignedPackedField,
    /// A field expected to hold exactly 32 bytes held a different count.
    BadKeyLength(usize),
}

/// One decoded field: its number and its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Value<'a> {
    /// Wire type 0 — `int32`, `int64`, `uint32`, `uint64`, `bool`, `enum`.
    Varint(u64),
    /// Wire type 1 — `fixed64`, `sfixed64`, `double`.
    Fixed64(u64),
    /// Wire type 5 — `fixed32`, `sfixed32`, `float`.
    Fixed32(u32),
    /// Wire type 2 — `bytes`, `string`, embedded messages, packed repeated.
    Bytes(&'a [u8]),
}

impl Value<'_> {
    /// Interpret the field as an unsigned integer, defaulting non-varints to 0.
    pub fn as_u64(&self) -> u64 {
        match self {
            Value::Varint(v) => *v,
            Value::Fixed64(v) => *v,
            Value::Fixed32(v) => u64::from(*v),
            Value::Bytes(_) => 0,
        }
    }

    /// Interpret the field as a `bool` (proto3: any non-zero varint is true).
    pub fn as_bool(&self) -> bool {
        self.as_u64() != 0
    }

    /// Interpret the field as a signed 32-bit integer.
    ///
    /// Proto3 `int32` is sign-extended to 64 bits on the wire, so a negative
    /// value arrives as a 10-byte varint whose low 32 bits carry the value.
    pub fn as_i32(&self) -> i32 {
        self.as_u64() as u32 as i32
    }

    /// Borrow the field as bytes; non-length-delimited fields yield empty.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Value::Bytes(b) => b,
            _ => &[],
        }
    }

    /// Copy the field into a 32-byte key, rejecting any other length.
    ///
    /// Proto3 omits empty fields entirely, so a zero-length value is a
    /// legitimately absent key and decodes to all-zero rather than an error.
    pub fn as_key32(&self) -> Result<[u8; 32], WireError> {
        let bytes = self.as_bytes();
        if bytes.is_empty() {
            return Ok([0u8; 32]);
        }
        if bytes.len() != 32 {
            return Err(WireError::BadKeyLength(bytes.len()));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(bytes);
        Ok(key)
    }
}

/// Cursor over a protobuf-encoded message.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Start reading `buf` from the beginning.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Whether every byte has been consumed.
    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn varint(&mut self) -> Result<u64, WireError> {
        let mut result: u64 = 0;
        for shift in 0..10u32 {
            let byte = *self.buf.get(self.pos).ok_or(WireError::Truncated)?;
            self.pos += 1;
            result |= u64::from(byte & 0x7F) << (shift * 7);
            if byte & 0x80 == 0 {
                return Ok(result);
            }
        }
        Err(WireError::VarintOverflow)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(len).ok_or(WireError::Truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(WireError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    /// Read the next `(field_number, value)` pair, or `None` at end of input.
    pub fn next_field(&mut self) -> Result<Option<(u32, Value<'a>)>, WireError> {
        if self.is_empty() {
            return Ok(None);
        }
        let key = self.varint()?;
        let field = (key >> 3) as u32;
        let wire_type = (key & 7) as u8;
        let value = match wire_type {
            0 => Value::Varint(self.varint()?),
            1 => {
                let bytes = self.take(8)?;
                let mut raw = [0u8; 8];
                raw.copy_from_slice(bytes);
                Value::Fixed64(u64::from_le_bytes(raw))
            }
            2 => {
                let len = self.varint()?;
                let len = usize::try_from(len).map_err(|_| WireError::LengthOutOfBounds)?;
                if len > self.buf.len().saturating_sub(self.pos) {
                    return Err(WireError::LengthOutOfBounds);
                }
                Value::Bytes(self.take(len)?)
            }
            5 => {
                let bytes = self.take(4)?;
                let mut raw = [0u8; 4];
                raw.copy_from_slice(bytes);
                Value::Fixed32(u32::from_le_bytes(raw))
            }
            other => return Err(WireError::UnsupportedWireType(other)),
        };
        Ok(Some((field, value)))
    }
}

/// Decode a packed repeated `fixed64` field into a vector of values.
///
/// Proto3 packs repeated scalars into one length-delimited field, which is how
/// the fixture feature sets arrive.
pub fn packed_fixed64(bytes: &[u8]) -> Result<Vec<u64>, WireError> {
    if !bytes.len().is_multiple_of(8) {
        return Err(WireError::MisalignedPackedField);
    }
    Ok(bytes
        .chunks_exact(8)
        .map(|chunk| {
            let mut raw = [0u8; 8];
            raw.copy_from_slice(chunk);
            u64::from_le_bytes(raw)
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a `(field, varint)` pair the way a protobuf writer would, so the
    /// reader is exercised against bytes this module did not produce itself.
    fn varint_field(field: u32, mut value: u64) -> Vec<u8> {
        let mut out = encode_varint(u64::from(field) << 3);
        loop {
            let byte = (value & 0x7F) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                break;
            }
            out.push(byte | 0x80);
        }
        out
    }

    fn encode_varint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (value & 0x7F) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }

    fn bytes_field(field: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = encode_varint((u64::from(field) << 3) | 2);
        out.extend(encode_varint(payload.len() as u64));
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn reads_single_byte_and_multi_byte_varints() {
        let mut buf = varint_field(1, 0);
        buf.extend(varint_field(2, 127));
        buf.extend(varint_field(3, 128));
        buf.extend(varint_field(4, u64::MAX));

        let mut reader = Reader::new(&buf);
        let mut seen = Vec::new();
        while let Some((field, value)) = reader.next_field().unwrap() {
            seen.push((field, value.as_u64()));
        }
        assert_eq!(seen, vec![(1, 0), (2, 127), (3, 128), (4, u64::MAX)]);
    }

    #[test]
    fn reads_length_delimited_payloads() {
        let buf = bytes_field(5, b"karstflow");
        let mut reader = Reader::new(&buf);
        let (field, value) = reader.next_field().unwrap().unwrap();
        assert_eq!(field, 5);
        assert_eq!(value.as_bytes(), b"karstflow");
        assert!(reader.next_field().unwrap().is_none());
    }

    #[test]
    fn negative_int32_survives_sign_extension() {
        // Proto3 writes a negative int32 as a sign-extended 64-bit varint.
        let buf = varint_field(1, (-1i32) as u32 as u64 | 0xFFFF_FFFF_0000_0000);
        let mut reader = Reader::new(&buf);
        let (_, value) = reader.next_field().unwrap().unwrap();
        assert_eq!(value.as_i32(), -1);
    }

    #[test]
    fn truncated_input_is_an_error_not_a_panic() {
        // Length prefix claims 16 bytes; only 3 follow.
        let mut buf = encode_varint((1u64 << 3) | 2);
        buf.extend(encode_varint(16));
        buf.extend_from_slice(b"abc");
        let mut reader = Reader::new(&buf);
        assert_eq!(reader.next_field(), Err(WireError::LengthOutOfBounds));
    }

    #[test]
    fn truncated_varint_is_an_error_not_a_panic() {
        // Continuation bit set on the final byte.
        let buf = vec![0x08, 0x80];
        let mut reader = Reader::new(&buf);
        assert_eq!(reader.next_field(), Err(WireError::Truncated));
    }

    #[test]
    fn overlong_varint_is_rejected() {
        let mut buf = vec![0x08];
        buf.extend(std::iter::repeat_n(0x80u8, 11));
        let mut reader = Reader::new(&buf);
        assert_eq!(reader.next_field(), Err(WireError::VarintOverflow));
    }

    #[test]
    fn group_wire_types_are_rejected() {
        // Wire type 3 is a deprecated start-group marker.
        let buf = vec![0x0B];
        let mut reader = Reader::new(&buf);
        assert_eq!(reader.next_field(), Err(WireError::UnsupportedWireType(3)));
    }

    #[test]
    fn packed_fixed64_round_trips() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1u64.to_le_bytes());
        payload.extend_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(packed_fixed64(&payload).unwrap(), vec![1, u64::MAX]);
        assert_eq!(packed_fixed64(&[]).unwrap(), Vec::<u64>::new());
        assert_eq!(
            packed_fixed64(&[0u8; 7]),
            Err(WireError::MisalignedPackedField)
        );
    }

    #[test]
    fn key_fields_require_exactly_32_bytes_or_absence() {
        assert_eq!(Value::Bytes(&[7u8; 32]).as_key32().unwrap(), [7u8; 32]);
        // Proto3 omits empty fields, so absence decodes to the zero key.
        assert_eq!(Value::Bytes(&[]).as_key32().unwrap(), [0u8; 32]);
        assert_eq!(
            Value::Bytes(&[1u8; 31]).as_key32(),
            Err(WireError::BadKeyLength(31))
        );
    }

    #[test]
    fn unknown_fields_are_skipped_by_wire_type_not_guessed() {
        // Field 99 is not in any schema this crate decodes; walking past it
        // must land exactly on field 1.
        let mut buf = bytes_field(99, &[0xAB; 12]);
        buf.extend(varint_field(1, 42));
        let mut reader = Reader::new(&buf);
        let (unknown, _) = reader.next_field().unwrap().unwrap();
        assert_eq!(unknown, 99);
        let (known, value) = reader.next_field().unwrap().unwrap();
        assert_eq!((known, value.as_u64()), (1, 42));
    }
}
