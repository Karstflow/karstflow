/// QUIC connection identifier with inline storage.
///
/// Stores up to 20 bytes (RFC 9000 maximum) on the stack. Unused bytes are
/// always zeroed to allow direct comparison.
use paradencer_constants::network::QUIC_MAX_CONN_ID_LEN;

/// Inline connection ID (up to 20 bytes, no heap allocation).
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ConnectionId {
    /// Raw connection ID bytes. Bytes beyond `len` are always zero.
    data: [u8; QUIC_MAX_CONN_ID_LEN],
    /// Actual length of the connection ID (0..=20).
    len: u8,
}

impl ConnectionId {
    /// Empty connection ID (length zero).
    pub const EMPTY: Self = Self {
        data: [0; QUIC_MAX_CONN_ID_LEN],
        len: 0,
    };

    /// Create a connection ID from a byte slice.
    ///
    /// Returns `None` if `bytes` exceeds 20 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > QUIC_MAX_CONN_ID_LEN {
            return None;
        }
        let mut data = [0u8; QUIC_MAX_CONN_ID_LEN];
        data[..bytes.len()].copy_from_slice(bytes);
        Some(Self {
            data,
            len: bytes.len() as u8,
        })
    }

    /// Create a connection ID from a fixed-size array.
    pub fn from_array<const N: usize>(bytes: [u8; N]) -> Option<Self> {
        if N > QUIC_MAX_CONN_ID_LEN {
            return None;
        }
        let mut data = [0u8; QUIC_MAX_CONN_ID_LEN];
        data[..N].copy_from_slice(&bytes);
        Some(Self { data, len: N as u8 })
    }

    /// Length of the connection ID in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// Whether this is an empty (zero-length) connection ID.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Get the connection ID bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len as usize]
    }

    /// Read a connection ID from `buf` given its known `length`.
    ///
    /// Returns `(connection_id, bytes_consumed)` on success.
    pub fn decode(buf: &[u8], length: usize) -> Option<(Self, usize)> {
        if length > QUIC_MAX_CONN_ID_LEN || buf.len() < length {
            return None;
        }
        let mut data = [0u8; QUIC_MAX_CONN_ID_LEN];
        data[..length].copy_from_slice(&buf[..length]);
        Some((
            Self {
                data,
                len: length as u8,
            },
            length,
        ))
    }

    /// Read a length-prefixed connection ID from `buf`.
    ///
    /// First byte is the length, followed by that many ID bytes.
    /// Returns `(connection_id, total_bytes_consumed)`.
    pub fn decode_with_length(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.is_empty() {
            return None;
        }
        let length = buf[0] as usize;
        if length > QUIC_MAX_CONN_ID_LEN || buf.len() < 1 + length {
            return None;
        }
        let mut data = [0u8; QUIC_MAX_CONN_ID_LEN];
        data[..length].copy_from_slice(&buf[1..1 + length]);
        Some((
            Self {
                data,
                len: length as u8,
            },
            1 + length,
        ))
    }

    /// Write the connection ID bytes (without length prefix) to `buf`.
    ///
    /// Returns bytes written.
    pub fn encode(&self, buf: &mut [u8]) -> Option<usize> {
        let len = self.len as usize;
        if buf.len() < len {
            return None;
        }
        buf[..len].copy_from_slice(&self.data[..len]);
        Some(len)
    }

    /// Write a length-prefixed connection ID to `buf`.
    ///
    /// Returns total bytes written (1 + len).
    pub fn encode_with_length(&self, buf: &mut [u8]) -> Option<usize> {
        let len = self.len as usize;
        if buf.len() < 1 + len {
            return None;
        }
        buf[0] = self.len;
        buf[1..1 + len].copy_from_slice(&self.data[..len]);
        Some(1 + len)
    }
}

impl PartialEq for ConnectionId {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len && self.data[..self.len as usize] == other.data[..other.len as usize]
    }
}

impl Eq for ConnectionId {}

impl core::hash::Hash for ConnectionId {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.len.hash(state);
        self.data[..self.len as usize].hash(state);
    }
}

impl core::fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ConnectionId(")?;
        for byte in self.as_bytes() {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}

impl Default for ConnectionId {
    fn default() -> Self {
        Self::EMPTY
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_connection_id() {
        let cid = ConnectionId::EMPTY;
        assert!(cid.is_empty());
        assert_eq!(cid.len(), 0);
        assert_eq!(cid.as_bytes(), &[]);
    }

    #[test]
    fn from_bytes() {
        let cid = ConnectionId::from_bytes(&[0x01, 0x02, 0x03]).unwrap();
        assert_eq!(cid.len(), 3);
        assert_eq!(cid.as_bytes(), &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn from_bytes_max_length() {
        let data = [0xAA; 20];
        let cid = ConnectionId::from_bytes(&data).unwrap();
        assert_eq!(cid.len(), 20);
        assert_eq!(cid.as_bytes(), &data);
    }

    #[test]
    fn from_bytes_too_long() {
        let data = [0; 21];
        assert!(ConnectionId::from_bytes(&data).is_none());
    }

    #[test]
    fn equality() {
        let a = ConnectionId::from_bytes(&[1, 2, 3]).unwrap();
        let b = ConnectionId::from_bytes(&[1, 2, 3]).unwrap();
        let c = ConnectionId::from_bytes(&[1, 2, 4]).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn equality_different_lengths() {
        let a = ConnectionId::from_bytes(&[1, 2]).unwrap();
        let b = ConnectionId::from_bytes(&[1, 2, 0]).unwrap();
        assert_ne!(a, b); // Different lengths → not equal
    }

    #[test]
    fn encode_decode_round_trip() {
        let original = ConnectionId::from_bytes(&[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
        let mut buf = [0u8; 32];

        let n = original.encode(&mut buf).unwrap();
        assert_eq!(n, 4);

        let (decoded, consumed) = ConnectionId::decode(&buf, 4).unwrap();
        assert_eq!(consumed, 4);
        assert_eq!(decoded, original);
    }

    #[test]
    fn encode_decode_with_length() {
        let original = ConnectionId::from_bytes(&[0xCA, 0xFE]).unwrap();
        let mut buf = [0u8; 32];

        let n = original.encode_with_length(&mut buf).unwrap();
        assert_eq!(n, 3); // 1 byte length + 2 bytes data

        let (decoded, consumed) = ConnectionId::decode_with_length(&buf).unwrap();
        assert_eq!(consumed, 3);
        assert_eq!(decoded, original);
    }

    #[test]
    fn debug_format() {
        let cid = ConnectionId::from_bytes(&[0xAB, 0xCD]).unwrap();
        assert_eq!(format!("{cid:?}"), "ConnectionId(abcd)");
    }

    #[test]
    fn hash_consistency() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let a = ConnectionId::from_bytes(&[1, 2, 3]).unwrap();
        let b = ConnectionId::from_bytes(&[1, 2, 3]).unwrap();

        let hash = |cid: &ConnectionId| {
            let mut h = DefaultHasher::new();
            cid.hash(&mut h);
            h.finish()
        };

        assert_eq!(hash(&a), hash(&b));
    }
}
