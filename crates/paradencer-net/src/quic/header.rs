/// QUIC v1 packet header encoding and decoding (RFC 9000 Section 17).
///
/// Supports both long headers (Initial, Handshake, 0-RTT, Retry) and
/// short headers (1-RTT). All multi-byte fields use network byte order.
use super::conn_id::ConnectionId;
use super::varint;
use paradencer_constants::network::{
    QUIC_MAX_CONN_ID_LEN, QUIC_PKT_HANDSHAKE, QUIC_PKT_INITIAL, QUIC_PKT_RETRY, QUIC_PKT_ZERO_RTT,
    QUIC_SHORTEST_PACKET, QUIC_VERSION_1,
};

/// Parsed long header (Initial, Handshake, 0-RTT).
#[derive(Debug, Clone)]
pub struct LongHeader {
    /// Packet type (0=Initial, 1=0-RTT, 2=Handshake, 3=Retry).
    pub packet_type: u8,
    /// QUIC version.
    pub version: u32,
    /// Destination connection ID.
    pub dst_conn_id: ConnectionId,
    /// Source connection ID.
    pub src_conn_id: ConnectionId,
    /// Token (Initial packets only, empty for others).
    pub token: Vec<u8>,
    /// Declared payload length (packet number + encrypted payload).
    pub payload_length: u64,
    /// Byte offset of the packet number within the original buffer.
    pub pkt_num_offset: usize,
    /// Packet number length in bytes (1, 2, 3, or 4).
    pub pkt_num_len: usize,
}

/// Parsed short header (1-RTT).
#[derive(Debug, Clone)]
pub struct ShortHeader {
    /// Destination connection ID.
    pub dst_conn_id: ConnectionId,
    /// Spin bit for latency measurement.
    pub spin_bit: bool,
    /// Key phase bit for key updates.
    pub key_phase: bool,
    /// Byte offset of the packet number within the original buffer.
    pub pkt_num_offset: usize,
    /// Packet number length in bytes (1, 2, 3, or 4).
    pub pkt_num_len: usize,
}

/// Result of parsing a QUIC packet header.
#[derive(Debug)]
pub enum PacketHeader {
    Long(LongHeader),
    Short(ShortHeader),
    VersionNegotiation {
        dst_conn_id: ConnectionId,
        src_conn_id: ConnectionId,
    },
}

/// Error during header parsing or encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderError {
    BufferTooSmall,
    InvalidConnIdLength,
    InvalidPacketType,
    InvalidTokenLength,
    VarintError,
}

impl From<varint::VarintError> for HeaderError {
    fn from(_: varint::VarintError) -> Self {
        HeaderError::VarintError
    }
}

/// Check if the first byte indicates a long header (bit 7 set).
#[inline]
pub fn is_long_header(first_byte: u8) -> bool {
    first_byte & 0x80 != 0
}

/// Extract long packet type from the first byte.
#[inline]
pub fn long_packet_type(first_byte: u8) -> u8 {
    (first_byte >> 4) & 0x03
}

/// Extract packet number length from the first byte (bits 0-1).
#[inline]
pub fn pkt_num_length(first_byte: u8) -> usize {
    ((first_byte & 0x03) + 1) as usize
}

/// Construct the first byte for an Initial packet.
#[inline]
pub fn initial_first_byte(pkt_num_len: usize) -> u8 {
    0xc0 | ((pkt_num_len as u8) - 1)
}

/// Construct the first byte for a Handshake packet.
#[inline]
pub fn handshake_first_byte(pkt_num_len: usize) -> u8 {
    0xe0 | ((pkt_num_len as u8) - 1)
}

/// Construct the first byte for a 1-RTT (short header) packet.
#[inline]
pub fn one_rtt_first_byte(spin_bit: bool, key_phase: bool, pkt_num_len: usize) -> u8 {
    0x40 | ((spin_bit as u8) << 5) | ((key_phase as u8) << 2) | ((pkt_num_len as u8) - 1)
}

/// Decode a packet header from `buf`.
///
/// `dcid_len` is needed for short headers (connection ID length is implicit).
/// For long headers this parameter is ignored.
pub fn decode_header(buf: &[u8], dcid_len: usize) -> Result<PacketHeader, HeaderError> {
    if buf.len() < QUIC_SHORTEST_PACKET {
        return Err(HeaderError::BufferTooSmall);
    }

    let first = buf[0];

    if is_long_header(first) {
        decode_long_header(buf)
    } else {
        decode_short_header(buf, dcid_len)
    }
}

fn decode_long_header(buf: &[u8]) -> Result<PacketHeader, HeaderError> {
    let first = buf[0];
    let mut pos = 1;

    // Version (4 bytes)
    if buf.len() < pos + 4 {
        return Err(HeaderError::BufferTooSmall);
    }
    let version = u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
    pos += 4;

    // Destination Connection ID
    if buf.len() < pos + 1 {
        return Err(HeaderError::BufferTooSmall);
    }
    let dcid_len = buf[pos] as usize;
    pos += 1;
    if dcid_len > QUIC_MAX_CONN_ID_LEN || buf.len() < pos + dcid_len {
        return Err(HeaderError::InvalidConnIdLength);
    }
    let dst_conn_id = ConnectionId::from_bytes(&buf[pos..pos + dcid_len])
        .ok_or(HeaderError::InvalidConnIdLength)?;
    pos += dcid_len;

    // Source Connection ID
    if buf.len() < pos + 1 {
        return Err(HeaderError::BufferTooSmall);
    }
    let scid_len = buf[pos] as usize;
    pos += 1;
    if scid_len > QUIC_MAX_CONN_ID_LEN || buf.len() < pos + scid_len {
        return Err(HeaderError::InvalidConnIdLength);
    }
    let src_conn_id = ConnectionId::from_bytes(&buf[pos..pos + scid_len])
        .ok_or(HeaderError::InvalidConnIdLength)?;
    pos += scid_len;

    // Version Negotiation: version == 0
    if version == 0 {
        return Ok(PacketHeader::VersionNegotiation {
            dst_conn_id,
            src_conn_id,
        });
    }

    let packet_type = long_packet_type(first);

    match packet_type {
        QUIC_PKT_INITIAL => {
            // Token length (varint) + token
            let (token_len, n) = varint::decode(&buf[pos..])?;
            pos += n;
            let token_len = token_len as usize;
            if buf.len() < pos + token_len {
                return Err(HeaderError::InvalidTokenLength);
            }
            let token = buf[pos..pos + token_len].to_vec();
            pos += token_len;

            // Payload length (varint)
            let (payload_length, n) = varint::decode(&buf[pos..])?;
            pos += n;

            let pkt_num_len = pkt_num_length(first);

            Ok(PacketHeader::Long(LongHeader {
                packet_type,
                version,
                dst_conn_id,
                src_conn_id,
                token,
                payload_length,
                pkt_num_offset: pos,
                pkt_num_len,
            }))
        }
        QUIC_PKT_HANDSHAKE | QUIC_PKT_ZERO_RTT => {
            // Payload length (varint)
            let (payload_length, n) = varint::decode(&buf[pos..])?;
            pos += n;

            let pkt_num_len = pkt_num_length(first);

            Ok(PacketHeader::Long(LongHeader {
                packet_type,
                version,
                dst_conn_id,
                src_conn_id,
                token: Vec::new(),
                payload_length,
                pkt_num_offset: pos,
                pkt_num_len,
            }))
        }
        QUIC_PKT_RETRY => Ok(PacketHeader::Long(LongHeader {
            packet_type,
            version,
            dst_conn_id,
            src_conn_id,
            token: Vec::new(),
            payload_length: 0,
            pkt_num_offset: pos,
            pkt_num_len: 0,
        })),
        _ => Err(HeaderError::InvalidPacketType),
    }
}

fn decode_short_header(buf: &[u8], dcid_len: usize) -> Result<PacketHeader, HeaderError> {
    let first = buf[0];
    let mut pos = 1;

    if dcid_len > QUIC_MAX_CONN_ID_LEN || buf.len() < pos + dcid_len {
        return Err(HeaderError::InvalidConnIdLength);
    }
    let dst_conn_id = ConnectionId::from_bytes(&buf[pos..pos + dcid_len])
        .ok_or(HeaderError::InvalidConnIdLength)?;
    pos += dcid_len;

    let spin_bit = (first >> 5) & 1 != 0;
    let key_phase = (first >> 2) & 1 != 0;
    let pkt_num_len = pkt_num_length(first);

    Ok(PacketHeader::Short(ShortHeader {
        dst_conn_id,
        spin_bit,
        key_phase,
        pkt_num_offset: pos,
        pkt_num_len,
    }))
}

/// Decode the packet number from `buf` at the given offset and length.
pub fn decode_pkt_num(buf: &[u8], offset: usize, len: usize) -> Option<u32> {
    if buf.len() < offset + len {
        return None;
    }
    let bytes = &buf[offset..offset + len];
    let value = match len {
        1 => u32::from(bytes[0]),
        2 => u32::from(u16::from_be_bytes([bytes[0], bytes[1]])),
        3 => u32::from(bytes[0]) << 16 | u32::from(bytes[1]) << 8 | u32::from(bytes[2]),
        4 => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        _ => return None,
    };
    Some(value)
}

/// Encode a packet number into `buf` at the given offset.
pub fn encode_pkt_num(buf: &mut [u8], offset: usize, value: u32, len: usize) -> Option<usize> {
    if buf.len() < offset + len {
        return None;
    }
    match len {
        1 => buf[offset] = value as u8,
        2 => buf[offset..offset + 2].copy_from_slice(&(value as u16).to_be_bytes()),
        3 => {
            buf[offset] = (value >> 16) as u8;
            buf[offset + 1] = (value >> 8) as u8;
            buf[offset + 2] = value as u8;
        }
        4 => buf[offset..offset + 4].copy_from_slice(&value.to_be_bytes()),
        _ => return None,
    }
    Some(len)
}

/// Recover a full packet number from a truncated value (RFC 9000 Section A).
pub fn recover_pkt_num(largest_acked: u64, truncated: u32, pn_len: usize) -> u64 {
    let pn_nbits = pn_len * 8;
    let pn_win = 1u64 << pn_nbits;
    let pn_hwin = pn_win / 2;
    let pn_mask = pn_win - 1;

    let expected = largest_acked.wrapping_add(1);
    let candidate_pn = (expected & !pn_mask) | u64::from(truncated);

    if candidate_pn.wrapping_add(pn_hwin) <= expected && candidate_pn < (1u64 << 62) - pn_win {
        candidate_pn + pn_win
    } else if candidate_pn > expected.wrapping_add(pn_hwin) && candidate_pn >= pn_win {
        candidate_pn - pn_win
    } else {
        candidate_pn
    }
}

/// Encode an Initial packet header into `buf`.
///
/// Returns the header size (byte offset where packet number starts).
pub fn encode_initial_header(
    buf: &mut [u8],
    dst_conn_id: &ConnectionId,
    src_conn_id: &ConnectionId,
    token: &[u8],
    payload_length: u64,
    pkt_num_len: usize,
) -> Result<usize, HeaderError> {
    let mut pos = 0;

    if buf.is_empty() {
        return Err(HeaderError::BufferTooSmall);
    }
    buf[pos] = initial_first_byte(pkt_num_len);
    pos += 1;

    if buf.len() < pos + 4 {
        return Err(HeaderError::BufferTooSmall);
    }
    buf[pos..pos + 4].copy_from_slice(&QUIC_VERSION_1.to_be_bytes());
    pos += 4;

    pos += dst_conn_id
        .encode_with_length(&mut buf[pos..])
        .ok_or(HeaderError::BufferTooSmall)?;
    pos += src_conn_id
        .encode_with_length(&mut buf[pos..])
        .ok_or(HeaderError::BufferTooSmall)?;

    pos += varint::encode(&mut buf[pos..], token.len() as u64)?;
    if buf.len() < pos + token.len() {
        return Err(HeaderError::BufferTooSmall);
    }
    buf[pos..pos + token.len()].copy_from_slice(token);
    pos += token.len();

    pos += varint::encode(&mut buf[pos..], payload_length)?;

    Ok(pos)
}

/// Encode a Handshake packet header into `buf`.
pub fn encode_handshake_header(
    buf: &mut [u8],
    dst_conn_id: &ConnectionId,
    src_conn_id: &ConnectionId,
    payload_length: u64,
    pkt_num_len: usize,
) -> Result<usize, HeaderError> {
    let mut pos = 0;

    if buf.is_empty() {
        return Err(HeaderError::BufferTooSmall);
    }
    buf[pos] = handshake_first_byte(pkt_num_len);
    pos += 1;

    if buf.len() < pos + 4 {
        return Err(HeaderError::BufferTooSmall);
    }
    buf[pos..pos + 4].copy_from_slice(&QUIC_VERSION_1.to_be_bytes());
    pos += 4;

    pos += dst_conn_id
        .encode_with_length(&mut buf[pos..])
        .ok_or(HeaderError::BufferTooSmall)?;
    pos += src_conn_id
        .encode_with_length(&mut buf[pos..])
        .ok_or(HeaderError::BufferTooSmall)?;

    pos += varint::encode(&mut buf[pos..], payload_length)?;

    Ok(pos)
}

/// Encode a 1-RTT (short header) packet header into `buf`.
pub fn encode_short_header(
    buf: &mut [u8],
    dst_conn_id: &ConnectionId,
    spin_bit: bool,
    key_phase: bool,
    pkt_num_len: usize,
) -> Result<usize, HeaderError> {
    let mut pos = 0;

    if buf.is_empty() {
        return Err(HeaderError::BufferTooSmall);
    }
    buf[pos] = one_rtt_first_byte(spin_bit, key_phase, pkt_num_len);
    pos += 1;

    pos += dst_conn_id
        .encode(&mut buf[pos..])
        .ok_or(HeaderError::BufferTooSmall)?;

    Ok(pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_header_round_trip() {
        let dcid =
            ConnectionId::from_bytes(&[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]).unwrap();
        let scid = ConnectionId::EMPTY;
        let mut buf = [0u8; 256];

        let hdr_len = encode_initial_header(&mut buf, &dcid, &scid, &[], 1182, 4).unwrap();

        match decode_header(&buf, 0).unwrap() {
            PacketHeader::Long(hdr) => {
                assert_eq!(hdr.packet_type, QUIC_PKT_INITIAL);
                assert_eq!(hdr.version, QUIC_VERSION_1);
                assert_eq!(hdr.dst_conn_id, dcid);
                assert_eq!(hdr.src_conn_id, scid);
                assert!(hdr.token.is_empty());
                assert_eq!(hdr.payload_length, 1182);
                assert_eq!(hdr.pkt_num_len, 4);
                assert_eq!(hdr.pkt_num_offset, hdr_len);
            }
            _ => panic!("expected long header"),
        }
    }

    #[test]
    fn handshake_header_round_trip() {
        let dcid = ConnectionId::from_bytes(&[0xAA, 0xBB]).unwrap();
        let scid = ConnectionId::from_bytes(&[0xCC, 0xDD]).unwrap();
        let mut buf = [0u8; 256];

        let hdr_len = encode_handshake_header(&mut buf, &dcid, &scid, 500, 2).unwrap();

        match decode_header(&buf, 0).unwrap() {
            PacketHeader::Long(hdr) => {
                assert_eq!(hdr.packet_type, QUIC_PKT_HANDSHAKE);
                assert_eq!(hdr.dst_conn_id, dcid);
                assert_eq!(hdr.src_conn_id, scid);
                assert_eq!(hdr.payload_length, 500);
                assert_eq!(hdr.pkt_num_len, 2);
                assert_eq!(hdr.pkt_num_offset, hdr_len);
            }
            _ => panic!("expected long header"),
        }
    }

    #[test]
    fn short_header_round_trip() {
        let dcid =
            ConnectionId::from_bytes(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]).unwrap();
        let mut buf = [0u8; 256];

        let hdr_len = encode_short_header(&mut buf, &dcid, true, false, 2).unwrap();

        match decode_header(&buf, 8).unwrap() {
            PacketHeader::Short(hdr) => {
                assert_eq!(hdr.dst_conn_id, dcid);
                assert!(hdr.spin_bit);
                assert!(!hdr.key_phase);
                assert_eq!(hdr.pkt_num_len, 2);
                assert_eq!(hdr.pkt_num_offset, hdr_len);
            }
            _ => panic!("expected short header"),
        }
    }

    #[test]
    fn pkt_num_encode_decode() {
        let mut buf = [0u8; 32];

        encode_pkt_num(&mut buf, 0, 42, 1).unwrap();
        assert_eq!(decode_pkt_num(&buf, 0, 1).unwrap(), 42);

        encode_pkt_num(&mut buf, 4, 0x1234, 2).unwrap();
        assert_eq!(decode_pkt_num(&buf, 4, 2).unwrap(), 0x1234);

        encode_pkt_num(&mut buf, 8, 0xABCDEF, 3).unwrap();
        assert_eq!(decode_pkt_num(&buf, 8, 3).unwrap(), 0xABCDEF);

        encode_pkt_num(&mut buf, 12, 0xDEADBEEF, 4).unwrap();
        assert_eq!(decode_pkt_num(&buf, 12, 4).unwrap(), 0xDEADBEEF);
    }

    #[test]
    fn version_negotiation() {
        let mut buf = [0u8; 64];
        buf[0] = 0x80; // Long header form
        buf[1..5].copy_from_slice(&[0, 0, 0, 0]); // Version = 0
        buf[5] = 4; // DCID len
        buf[6..10].copy_from_slice(&[1, 2, 3, 4]);
        buf[10] = 2; // SCID len
        buf[11..13].copy_from_slice(&[5, 6]);

        match decode_header(&buf, 0).unwrap() {
            PacketHeader::VersionNegotiation {
                dst_conn_id,
                src_conn_id,
            } => {
                assert_eq!(dst_conn_id.as_bytes(), &[1, 2, 3, 4]);
                assert_eq!(src_conn_id.as_bytes(), &[5, 6]);
            }
            _ => panic!("expected version negotiation"),
        }
    }

    #[test]
    fn initial_with_token() {
        let dcid = ConnectionId::from_bytes(&[0x01]).unwrap();
        let scid = ConnectionId::EMPTY;
        let token = [0xAA, 0xBB, 0xCC];
        let mut buf = [0u8; 256];

        encode_initial_header(&mut buf, &dcid, &scid, &token, 100, 1).unwrap();

        match decode_header(&buf, 0).unwrap() {
            PacketHeader::Long(hdr) => {
                assert_eq!(hdr.token, token);
            }
            _ => panic!("expected long header"),
        }
    }

    #[test]
    fn first_byte_helpers() {
        assert_eq!(initial_first_byte(1), 0xc0);
        assert_eq!(initial_first_byte(4), 0xc3);
        assert_eq!(handshake_first_byte(1), 0xe0);
        assert_eq!(handshake_first_byte(2), 0xe1);
        assert_eq!(one_rtt_first_byte(false, false, 1), 0x40);
        assert_eq!(one_rtt_first_byte(true, true, 4), 0x67);
    }

    #[test]
    fn is_long_header_check() {
        assert!(is_long_header(0xC0)); // Initial
        assert!(is_long_header(0xE0)); // Handshake
        assert!(!is_long_header(0x40)); // 1-RTT
    }

    #[test]
    fn buffer_too_small() {
        assert!(decode_header(&[0x40], 0).is_err());
    }

    #[test]
    fn recover_pkt_number_basic() {
        // Simple case: no wrapping needed
        assert_eq!(recover_pkt_num(0, 1, 1), 1);
        assert_eq!(recover_pkt_num(100, 101, 1), 101);

        // 2-byte truncation
        assert_eq!(recover_pkt_num(0xABCD, 0xABCE, 2), 0xABCE);
    }
}
