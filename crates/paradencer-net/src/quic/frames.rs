/// QUIC v1 frame encoding and decoding (RFC 9000 Section 19).
///
/// Provides zero-copy parsing of all 20+ frame types and efficient encoding
/// for outgoing frames. Frame data references (crypto/stream payloads) point
/// into the original packet buffer to avoid copies.
use super::conn_id::ConnectionId;
use super::varint;
use paradencer_constants::network::*;

/// A parsed QUIC frame.
#[derive(Debug, Clone)]
pub enum Frame {
    Padding,
    Ping,
    Ack(AckFrame),
    ResetStream(ResetStreamFrame),
    StopSending(StopSendingFrame),
    Crypto(CryptoFrame),
    NewToken(NewTokenFrame),
    Stream(StreamFrame),
    MaxData(u64),
    MaxStreamData(MaxStreamDataFrame),
    MaxStreamsBidi(u64),
    MaxStreamsUni(u64),
    DataBlocked(u64),
    StreamDataBlocked(StreamDataBlockedFrame),
    StreamsBlockedBidi(u64),
    StreamsBlockedUni(u64),
    NewConnectionId(NewConnectionIdFrame),
    RetireConnectionId(u64),
    PathChallenge([u8; 8]),
    PathResponse([u8; 8]),
    ConnectionClose(ConnectionCloseFrame),
    HandshakeDone,
}

/// ACK frame with range list.
#[derive(Debug, Clone)]
pub struct AckFrame {
    pub largest_acked: u64,
    pub ack_delay: u64,
    pub first_range: u64,
    pub ranges: Vec<AckRange>,
    pub ecn: Option<EcnCounts>,
}

/// A gap+length pair in an ACK frame.
#[derive(Debug, Clone, Copy)]
pub struct AckRange {
    pub gap: u64,
    pub length: u64,
}

/// ECN counts appended to ACK_ECN frames.
#[derive(Debug, Clone, Copy)]
pub struct EcnCounts {
    pub ect0: u64,
    pub ect1: u64,
    pub ecn_ce: u64,
}

/// RESET_STREAM frame.
#[derive(Debug, Clone, Copy)]
pub struct ResetStreamFrame {
    pub stream_id: u64,
    pub error_code: u64,
    pub final_size: u64,
}

/// STOP_SENDING frame.
#[derive(Debug, Clone, Copy)]
pub struct StopSendingFrame {
    pub stream_id: u64,
    pub error_code: u64,
}

/// CRYPTO frame (carries TLS handshake data).
#[derive(Debug, Clone)]
pub struct CryptoFrame {
    pub offset: u64,
    pub length: u64,
    /// Byte offset into the original buffer where data starts.
    pub data_offset: usize,
}

/// NEW_TOKEN frame.
#[derive(Debug, Clone)]
pub struct NewTokenFrame {
    pub length: u64,
    pub data_offset: usize,
}

/// STREAM frame with optional offset, length, and FIN.
#[derive(Debug, Clone)]
pub struct StreamFrame {
    pub stream_id: u64,
    pub offset: u64,
    pub length: u64,
    pub fin: bool,
    /// Byte offset into the original buffer where stream data starts.
    pub data_offset: usize,
}

/// MAX_STREAM_DATA frame.
#[derive(Debug, Clone, Copy)]
pub struct MaxStreamDataFrame {
    pub stream_id: u64,
    pub max_data: u64,
}

/// STREAM_DATA_BLOCKED frame.
#[derive(Debug, Clone, Copy)]
pub struct StreamDataBlockedFrame {
    pub stream_id: u64,
    pub limit: u64,
}

/// NEW_CONNECTION_ID frame.
#[derive(Debug, Clone)]
pub struct NewConnectionIdFrame {
    pub sequence: u64,
    pub retire_prior_to: u64,
    pub connection_id: ConnectionId,
    pub reset_token: [u8; 16],
}

/// CONNECTION_CLOSE frame (transport or application layer).
#[derive(Debug, Clone)]
pub struct ConnectionCloseFrame {
    pub error_code: u64,
    pub frame_type: Option<u64>,
    pub reason_length: u64,
    pub reason_offset: usize,
}

/// Error during frame parsing or encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    BufferTooSmall,
    InvalidFrameType(u8),
    VarintError,
    InvalidData,
}

impl From<varint::VarintError> for FrameError {
    fn from(_: varint::VarintError) -> Self {
        FrameError::VarintError
    }
}

/// Decode a single frame from `buf`.
///
/// Returns `(frame, bytes_consumed)`.
pub fn decode_frame(buf: &[u8]) -> Result<(Frame, usize), FrameError> {
    if buf.is_empty() {
        return Err(FrameError::BufferTooSmall);
    }

    let frame_type = buf[0];

    match frame_type {
        FRAME_PADDING => Ok((Frame::Padding, 1)),
        FRAME_PING => Ok((Frame::Ping, 1)),
        FRAME_ACK | FRAME_ACK_ECN => decode_ack(buf),
        FRAME_RESET_STREAM => decode_reset_stream(buf),
        FRAME_STOP_SENDING => decode_stop_sending(buf),
        FRAME_CRYPTO => decode_crypto(buf),
        FRAME_NEW_TOKEN => decode_new_token(buf),
        FRAME_STREAM_BASE..=FRAME_STREAM_END => decode_stream(buf),
        FRAME_MAX_DATA => decode_single_varint(buf, Frame::MaxData),
        FRAME_MAX_STREAM_DATA => decode_max_stream_data(buf),
        FRAME_MAX_STREAMS_BIDI => decode_single_varint(buf, Frame::MaxStreamsBidi),
        FRAME_MAX_STREAMS_UNI => decode_single_varint(buf, Frame::MaxStreamsUni),
        FRAME_DATA_BLOCKED => decode_single_varint(buf, Frame::DataBlocked),
        FRAME_STREAM_DATA_BLOCKED => decode_stream_data_blocked(buf),
        FRAME_STREAMS_BLOCKED_BIDI => decode_single_varint(buf, Frame::StreamsBlockedBidi),
        FRAME_STREAMS_BLOCKED_UNI => decode_single_varint(buf, Frame::StreamsBlockedUni),
        FRAME_NEW_CONNECTION_ID => decode_new_connection_id(buf),
        FRAME_RETIRE_CONNECTION_ID => decode_single_varint(buf, Frame::RetireConnectionId),
        FRAME_PATH_CHALLENGE => decode_path_data(buf, true),
        FRAME_PATH_RESPONSE => decode_path_data(buf, false),
        FRAME_CONNECTION_CLOSE => decode_connection_close(buf, true),
        FRAME_CONNECTION_CLOSE_APP => decode_connection_close(buf, false),
        FRAME_HANDSHAKE_DONE => Ok((Frame::HandshakeDone, 1)),
        _ => Err(FrameError::InvalidFrameType(frame_type)),
    }
}

/// Decode all frames in a decrypted packet payload.
pub fn decode_all_frames(buf: &[u8]) -> Result<Vec<Frame>, FrameError> {
    let mut frames = Vec::new();
    let mut pos = 0;

    while pos < buf.len() {
        if buf[pos] == FRAME_PADDING {
            pos += 1;
            continue;
        }
        let (frame, consumed) = decode_frame(&buf[pos..])?;
        let frame = adjust_data_offset(frame, pos);
        pos += consumed;
        frames.push(frame);
    }

    Ok(frames)
}

fn adjust_data_offset(frame: Frame, base: usize) -> Frame {
    match frame {
        Frame::Crypto(mut f) => {
            f.data_offset += base;
            Frame::Crypto(f)
        }
        Frame::Stream(mut f) => {
            f.data_offset += base;
            Frame::Stream(f)
        }
        Frame::NewToken(mut f) => {
            f.data_offset += base;
            Frame::NewToken(f)
        }
        Frame::ConnectionClose(mut f) => {
            f.reason_offset += base;
            Frame::ConnectionClose(f)
        }
        other => other,
    }
}

fn decode_ack(buf: &[u8]) -> Result<(Frame, usize), FrameError> {
    let has_ecn = buf[0] == FRAME_ACK_ECN;
    let mut pos = 1;

    let (largest_acked, n) = varint::decode(&buf[pos..])?;
    pos += n;
    let (ack_delay, n) = varint::decode(&buf[pos..])?;
    pos += n;
    let (range_count, n) = varint::decode(&buf[pos..])?;
    pos += n;
    let (first_range, n) = varint::decode(&buf[pos..])?;
    pos += n;

    let mut ranges = Vec::with_capacity(range_count.min(64) as usize);
    for _ in 0..range_count {
        let (gap, n) = varint::decode(&buf[pos..])?;
        pos += n;
        let (length, n) = varint::decode(&buf[pos..])?;
        pos += n;
        ranges.push(AckRange { gap, length });
    }

    let ecn = if has_ecn {
        let (ect0, n) = varint::decode(&buf[pos..])?;
        pos += n;
        let (ect1, n) = varint::decode(&buf[pos..])?;
        pos += n;
        let (ecn_ce, n) = varint::decode(&buf[pos..])?;
        pos += n;
        Some(EcnCounts { ect0, ect1, ecn_ce })
    } else {
        None
    };

    Ok((
        Frame::Ack(AckFrame {
            largest_acked,
            ack_delay,
            first_range,
            ranges,
            ecn,
        }),
        pos,
    ))
}

fn decode_reset_stream(buf: &[u8]) -> Result<(Frame, usize), FrameError> {
    let mut pos = 1;
    let (stream_id, n) = varint::decode(&buf[pos..])?;
    pos += n;
    let (error_code, n) = varint::decode(&buf[pos..])?;
    pos += n;
    let (final_size, n) = varint::decode(&buf[pos..])?;
    pos += n;
    Ok((
        Frame::ResetStream(ResetStreamFrame {
            stream_id,
            error_code,
            final_size,
        }),
        pos,
    ))
}

fn decode_stop_sending(buf: &[u8]) -> Result<(Frame, usize), FrameError> {
    let mut pos = 1;
    let (stream_id, n) = varint::decode(&buf[pos..])?;
    pos += n;
    let (error_code, n) = varint::decode(&buf[pos..])?;
    pos += n;
    Ok((
        Frame::StopSending(StopSendingFrame {
            stream_id,
            error_code,
        }),
        pos,
    ))
}

fn decode_crypto(buf: &[u8]) -> Result<(Frame, usize), FrameError> {
    let mut pos = 1;
    let (offset, n) = varint::decode(&buf[pos..])?;
    pos += n;
    let (length, n) = varint::decode(&buf[pos..])?;
    pos += n;
    let data_offset = pos;
    let length_usize = length as usize;
    if buf.len() < pos + length_usize {
        return Err(FrameError::BufferTooSmall);
    }
    pos += length_usize;
    Ok((
        Frame::Crypto(CryptoFrame {
            offset,
            length,
            data_offset,
        }),
        pos,
    ))
}

fn decode_new_token(buf: &[u8]) -> Result<(Frame, usize), FrameError> {
    let mut pos = 1;
    let (length, n) = varint::decode(&buf[pos..])?;
    pos += n;
    let data_offset = pos;
    let length_usize = length as usize;
    if buf.len() < pos + length_usize {
        return Err(FrameError::BufferTooSmall);
    }
    pos += length_usize;
    Ok((
        Frame::NewToken(NewTokenFrame {
            length,
            data_offset,
        }),
        pos,
    ))
}

fn decode_stream(buf: &[u8]) -> Result<(Frame, usize), FrameError> {
    let type_byte = buf[0];
    let has_offset = type_byte & 0x04 != 0;
    let has_length = type_byte & 0x02 != 0;
    let fin = type_byte & 0x01 != 0;

    let mut pos = 1;
    let (stream_id, n) = varint::decode(&buf[pos..])?;
    pos += n;

    let offset = if has_offset {
        let (off, n) = varint::decode(&buf[pos..])?;
        pos += n;
        off
    } else {
        0
    };

    let length = if has_length {
        let (len, n) = varint::decode(&buf[pos..])?;
        pos += n;
        len
    } else {
        (buf.len() - pos) as u64
    };

    let data_offset = pos;
    let length_usize = length as usize;
    if buf.len() < pos + length_usize {
        return Err(FrameError::BufferTooSmall);
    }
    pos += length_usize;

    Ok((
        Frame::Stream(StreamFrame {
            stream_id,
            offset,
            length,
            fin,
            data_offset,
        }),
        pos,
    ))
}

fn decode_single_varint<F>(buf: &[u8], constructor: F) -> Result<(Frame, usize), FrameError>
where
    F: FnOnce(u64) -> Frame,
{
    let mut pos = 1;
    let (value, n) = varint::decode(&buf[pos..])?;
    pos += n;
    Ok((constructor(value), pos))
}

fn decode_max_stream_data(buf: &[u8]) -> Result<(Frame, usize), FrameError> {
    let mut pos = 1;
    let (stream_id, n) = varint::decode(&buf[pos..])?;
    pos += n;
    let (max_data, n) = varint::decode(&buf[pos..])?;
    pos += n;
    Ok((
        Frame::MaxStreamData(MaxStreamDataFrame {
            stream_id,
            max_data,
        }),
        pos,
    ))
}

fn decode_stream_data_blocked(buf: &[u8]) -> Result<(Frame, usize), FrameError> {
    let mut pos = 1;
    let (stream_id, n) = varint::decode(&buf[pos..])?;
    pos += n;
    let (limit, n) = varint::decode(&buf[pos..])?;
    pos += n;
    Ok((
        Frame::StreamDataBlocked(StreamDataBlockedFrame { stream_id, limit }),
        pos,
    ))
}

fn decode_new_connection_id(buf: &[u8]) -> Result<(Frame, usize), FrameError> {
    let mut pos = 1;
    let (sequence, n) = varint::decode(&buf[pos..])?;
    pos += n;
    let (retire_prior_to, n) = varint::decode(&buf[pos..])?;
    pos += n;

    if buf.len() < pos + 1 {
        return Err(FrameError::BufferTooSmall);
    }
    let cid_len = buf[pos] as usize;
    pos += 1;

    if cid_len > QUIC_MAX_CONN_ID_LEN || buf.len() < pos + cid_len + 16 {
        return Err(FrameError::InvalidData);
    }
    let connection_id =
        ConnectionId::from_bytes(&buf[pos..pos + cid_len]).ok_or(FrameError::InvalidData)?;
    pos += cid_len;

    let mut reset_token = [0u8; 16];
    reset_token.copy_from_slice(&buf[pos..pos + 16]);
    pos += 16;

    Ok((
        Frame::NewConnectionId(NewConnectionIdFrame {
            sequence,
            retire_prior_to,
            connection_id,
            reset_token,
        }),
        pos,
    ))
}

fn decode_path_data(buf: &[u8], is_challenge: bool) -> Result<(Frame, usize), FrameError> {
    if buf.len() < 9 {
        return Err(FrameError::BufferTooSmall);
    }
    let mut data = [0u8; 8];
    data.copy_from_slice(&buf[1..9]);
    if is_challenge {
        Ok((Frame::PathChallenge(data), 9))
    } else {
        Ok((Frame::PathResponse(data), 9))
    }
}

fn decode_connection_close(buf: &[u8], is_transport: bool) -> Result<(Frame, usize), FrameError> {
    let mut pos = 1;
    let (error_code, n) = varint::decode(&buf[pos..])?;
    pos += n;

    let frame_type = if is_transport {
        let (ft, n) = varint::decode(&buf[pos..])?;
        pos += n;
        Some(ft)
    } else {
        None
    };

    let (reason_length, n) = varint::decode(&buf[pos..])?;
    pos += n;
    let reason_offset = pos;
    let reason_len = reason_length as usize;
    if buf.len() < pos + reason_len {
        return Err(FrameError::BufferTooSmall);
    }
    pos += reason_len;

    Ok((
        Frame::ConnectionClose(ConnectionCloseFrame {
            error_code,
            frame_type,
            reason_length,
            reason_offset,
        }),
        pos,
    ))
}

// --- Encoders ---

/// Encode a PADDING frame.
pub fn encode_padding(buf: &mut [u8]) -> Result<usize, FrameError> {
    if buf.is_empty() {
        return Err(FrameError::BufferTooSmall);
    }
    buf[0] = FRAME_PADDING;
    Ok(1)
}

/// Encode a PING frame.
pub fn encode_ping(buf: &mut [u8]) -> Result<usize, FrameError> {
    if buf.is_empty() {
        return Err(FrameError::BufferTooSmall);
    }
    buf[0] = FRAME_PING;
    Ok(1)
}

/// Encode an ACK frame.
pub fn encode_ack(buf: &mut [u8], frame: &AckFrame) -> Result<usize, FrameError> {
    let mut pos = 0;
    if buf.is_empty() {
        return Err(FrameError::BufferTooSmall);
    }
    buf[pos] = if frame.ecn.is_some() {
        FRAME_ACK_ECN
    } else {
        FRAME_ACK
    };
    pos += 1;
    pos += varint::encode(&mut buf[pos..], frame.largest_acked)?;
    pos += varint::encode(&mut buf[pos..], frame.ack_delay)?;
    pos += varint::encode(&mut buf[pos..], frame.ranges.len() as u64)?;
    pos += varint::encode(&mut buf[pos..], frame.first_range)?;
    for range in &frame.ranges {
        pos += varint::encode(&mut buf[pos..], range.gap)?;
        pos += varint::encode(&mut buf[pos..], range.length)?;
    }
    if let Some(ecn) = &frame.ecn {
        pos += varint::encode(&mut buf[pos..], ecn.ect0)?;
        pos += varint::encode(&mut buf[pos..], ecn.ect1)?;
        pos += varint::encode(&mut buf[pos..], ecn.ecn_ce)?;
    }
    Ok(pos)
}

/// Encode a CRYPTO frame with data.
pub fn encode_crypto(buf: &mut [u8], offset: u64, data: &[u8]) -> Result<usize, FrameError> {
    let mut pos = 0;
    if buf.is_empty() {
        return Err(FrameError::BufferTooSmall);
    }
    buf[pos] = FRAME_CRYPTO;
    pos += 1;
    pos += varint::encode(&mut buf[pos..], offset)?;
    pos += varint::encode(&mut buf[pos..], data.len() as u64)?;
    if buf.len() < pos + data.len() {
        return Err(FrameError::BufferTooSmall);
    }
    buf[pos..pos + data.len()].copy_from_slice(data);
    pos += data.len();
    Ok(pos)
}

/// Encode a STREAM frame with data.
pub fn encode_stream(
    buf: &mut [u8],
    stream_id: u64,
    offset: u64,
    data: &[u8],
    fin: bool,
    include_length: bool,
) -> Result<usize, FrameError> {
    let mut pos = 0;
    if buf.is_empty() {
        return Err(FrameError::BufferTooSmall);
    }
    let mut type_byte = FRAME_STREAM_BASE;
    if offset > 0 {
        type_byte |= 0x04;
    }
    if include_length {
        type_byte |= 0x02;
    }
    if fin {
        type_byte |= 0x01;
    }
    buf[pos] = type_byte;
    pos += 1;
    pos += varint::encode(&mut buf[pos..], stream_id)?;
    if offset > 0 {
        pos += varint::encode(&mut buf[pos..], offset)?;
    }
    if include_length {
        pos += varint::encode(&mut buf[pos..], data.len() as u64)?;
    }
    if buf.len() < pos + data.len() {
        return Err(FrameError::BufferTooSmall);
    }
    buf[pos..pos + data.len()].copy_from_slice(data);
    pos += data.len();
    Ok(pos)
}

/// Encode a CONNECTION_CLOSE frame (transport error).
pub fn encode_connection_close(
    buf: &mut [u8],
    error_code: u64,
    frame_type: u64,
    reason: &[u8],
) -> Result<usize, FrameError> {
    let mut pos = 0;
    if buf.is_empty() {
        return Err(FrameError::BufferTooSmall);
    }
    buf[pos] = FRAME_CONNECTION_CLOSE;
    pos += 1;
    pos += varint::encode(&mut buf[pos..], error_code)?;
    pos += varint::encode(&mut buf[pos..], frame_type)?;
    pos += varint::encode(&mut buf[pos..], reason.len() as u64)?;
    if buf.len() < pos + reason.len() {
        return Err(FrameError::BufferTooSmall);
    }
    buf[pos..pos + reason.len()].copy_from_slice(reason);
    pos += reason.len();
    Ok(pos)
}

/// Encode a MAX_DATA frame.
pub fn encode_max_data(buf: &mut [u8], max_data: u64) -> Result<usize, FrameError> {
    let mut pos = 0;
    if buf.is_empty() {
        return Err(FrameError::BufferTooSmall);
    }
    buf[pos] = FRAME_MAX_DATA;
    pos += 1;
    pos += varint::encode(&mut buf[pos..], max_data)?;
    Ok(pos)
}

/// Encode a MAX_STREAM_DATA frame.
pub fn encode_max_stream_data(
    buf: &mut [u8],
    stream_id: u64,
    max_data: u64,
) -> Result<usize, FrameError> {
    let mut pos = 0;
    if buf.is_empty() {
        return Err(FrameError::BufferTooSmall);
    }
    buf[pos] = FRAME_MAX_STREAM_DATA;
    pos += 1;
    pos += varint::encode(&mut buf[pos..], stream_id)?;
    pos += varint::encode(&mut buf[pos..], max_data)?;
    Ok(pos)
}

/// Encode a HANDSHAKE_DONE frame.
pub fn encode_handshake_done(buf: &mut [u8]) -> Result<usize, FrameError> {
    if buf.is_empty() {
        return Err(FrameError::BufferTooSmall);
    }
    buf[0] = FRAME_HANDSHAKE_DONE;
    Ok(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_round_trip() {
        let mut buf = [0u8; 16];
        let n = encode_padding(&mut buf).unwrap();
        assert_eq!(n, 1);
        let (frame, consumed) = decode_frame(&buf).unwrap();
        assert_eq!(consumed, 1);
        assert!(matches!(frame, Frame::Padding));
    }

    #[test]
    fn ping_round_trip() {
        let mut buf = [0u8; 16];
        let n = encode_ping(&mut buf).unwrap();
        assert_eq!(n, 1);
        let (frame, consumed) = decode_frame(&buf).unwrap();
        assert_eq!(consumed, 1);
        assert!(matches!(frame, Frame::Ping));
    }

    #[test]
    fn handshake_done_round_trip() {
        let mut buf = [0u8; 16];
        let n = encode_handshake_done(&mut buf).unwrap();
        assert_eq!(n, 1);
        let (frame, consumed) = decode_frame(&buf).unwrap();
        assert_eq!(consumed, 1);
        assert!(matches!(frame, Frame::HandshakeDone));
    }

    #[test]
    fn ack_round_trip() {
        let ack = AckFrame {
            largest_acked: 100,
            ack_delay: 25,
            first_range: 10,
            ranges: vec![
                AckRange { gap: 5, length: 3 },
                AckRange { gap: 2, length: 7 },
            ],
            ecn: None,
        };
        let mut buf = [0u8; 128];
        let n = encode_ack(&mut buf, &ack).unwrap();
        let (frame, consumed) = decode_frame(&buf[..n]).unwrap();
        assert_eq!(consumed, n);
        if let Frame::Ack(decoded) = frame {
            assert_eq!(decoded.largest_acked, 100);
            assert_eq!(decoded.ack_delay, 25);
            assert_eq!(decoded.first_range, 10);
            assert_eq!(decoded.ranges.len(), 2);
            assert_eq!(decoded.ranges[0].gap, 5);
            assert!(decoded.ecn.is_none());
        } else {
            panic!("expected ACK frame");
        }
    }

    #[test]
    fn ack_ecn_round_trip() {
        let ack = AckFrame {
            largest_acked: 50,
            ack_delay: 10,
            first_range: 5,
            ranges: vec![],
            ecn: Some(EcnCounts {
                ect0: 100,
                ect1: 200,
                ecn_ce: 1,
            }),
        };
        let mut buf = [0u8; 128];
        let n = encode_ack(&mut buf, &ack).unwrap();
        let (frame, _) = decode_frame(&buf[..n]).unwrap();
        if let Frame::Ack(decoded) = frame {
            let ecn = decoded.ecn.unwrap();
            assert_eq!(ecn.ect0, 100);
            assert_eq!(ecn.ect1, 200);
            assert_eq!(ecn.ecn_ce, 1);
        } else {
            panic!("expected ACK ECN frame");
        }
    }

    #[test]
    fn crypto_round_trip() {
        let data = b"TLS handshake data here";
        let mut buf = [0u8; 128];
        let n = encode_crypto(&mut buf, 0, data).unwrap();
        let (frame, consumed) = decode_frame(&buf[..n]).unwrap();
        assert_eq!(consumed, n);
        if let Frame::Crypto(cf) = frame {
            assert_eq!(cf.offset, 0);
            assert_eq!(cf.length, data.len() as u64);
            assert_eq!(
                &buf[cf.data_offset..cf.data_offset + cf.length as usize],
                data
            );
        } else {
            panic!("expected CRYPTO frame");
        }
    }

    #[test]
    fn stream_basic() {
        let data = b"hello stream";
        let mut buf = [0u8; 128];
        let n = encode_stream(&mut buf, 4, 0, data, false, true).unwrap();
        let (frame, consumed) = decode_frame(&buf[..n]).unwrap();
        assert_eq!(consumed, n);
        if let Frame::Stream(sf) = frame {
            assert_eq!(sf.stream_id, 4);
            assert_eq!(sf.offset, 0);
            assert_eq!(sf.length, data.len() as u64);
            assert!(!sf.fin);
        } else {
            panic!("expected STREAM frame");
        }
    }

    #[test]
    fn stream_with_offset_and_fin() {
        let data = b"final";
        let mut buf = [0u8; 128];
        let n = encode_stream(&mut buf, 8, 1000, data, true, true).unwrap();
        let (frame, _) = decode_frame(&buf[..n]).unwrap();
        if let Frame::Stream(sf) = frame {
            assert_eq!(sf.stream_id, 8);
            assert_eq!(sf.offset, 1000);
            assert!(sf.fin);
        } else {
            panic!("expected STREAM frame");
        }
    }

    #[test]
    fn connection_close_round_trip() {
        let reason = b"bad frame";
        let mut buf = [0u8; 128];
        let n = encode_connection_close(&mut buf, 0x07, 0x06, reason).unwrap();
        let (frame, consumed) = decode_frame(&buf[..n]).unwrap();
        assert_eq!(consumed, n);
        if let Frame::ConnectionClose(cc) = frame {
            assert_eq!(cc.error_code, 0x07);
            assert_eq!(cc.frame_type, Some(0x06));
            assert_eq!(cc.reason_length, reason.len() as u64);
        } else {
            panic!("expected CONNECTION_CLOSE frame");
        }
    }

    #[test]
    fn max_data_round_trip() {
        let mut buf = [0u8; 32];
        let n = encode_max_data(&mut buf, 1_000_000).unwrap();
        let (frame, consumed) = decode_frame(&buf[..n]).unwrap();
        assert_eq!(consumed, n);
        assert!(matches!(frame, Frame::MaxData(1_000_000)));
    }

    #[test]
    fn max_stream_data_round_trip() {
        let mut buf = [0u8; 32];
        let n = encode_max_stream_data(&mut buf, 12, 500_000).unwrap();
        let (frame, consumed) = decode_frame(&buf[..n]).unwrap();
        assert_eq!(consumed, n);
        if let Frame::MaxStreamData(msd) = frame {
            assert_eq!(msd.stream_id, 12);
            assert_eq!(msd.max_data, 500_000);
        } else {
            panic!("expected MAX_STREAM_DATA frame");
        }
    }

    #[test]
    fn path_challenge_round_trip() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut buf = [0u8; 16];
        buf[0] = FRAME_PATH_CHALLENGE;
        buf[1..9].copy_from_slice(&data);
        let (frame, consumed) = decode_frame(&buf).unwrap();
        assert_eq!(consumed, 9);
        assert!(matches!(frame, Frame::PathChallenge(d) if d == data));
    }

    #[test]
    fn decode_multiple_frames() {
        let mut buf = [0u8; 256];
        let mut pos = 0;
        pos += encode_ping(&mut buf[pos..]).unwrap();
        pos += encode_crypto(&mut buf[pos..], 0, b"hello").unwrap();
        pos += encode_handshake_done(&mut buf[pos..]).unwrap();
        let frames = decode_all_frames(&buf[..pos]).unwrap();
        assert_eq!(frames.len(), 3);
        assert!(matches!(frames[0], Frame::Ping));
        assert!(matches!(frames[1], Frame::Crypto(_)));
        assert!(matches!(frames[2], Frame::HandshakeDone));
    }

    #[test]
    fn decode_padding_skipped() {
        let buf = [0u8; 10];
        let frames = decode_all_frames(&buf).unwrap();
        assert!(frames.is_empty());
    }

    #[test]
    fn invalid_frame_type() {
        let buf = [0xFF];
        assert!(matches!(
            decode_frame(&buf),
            Err(FrameError::InvalidFrameType(0xFF))
        ));
    }

    #[test]
    fn new_connection_id_round_trip() {
        let cid = ConnectionId::from_bytes(&[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
        let token = [0xAA; 16];
        let mut buf = [0u8; 64];
        buf[0] = FRAME_NEW_CONNECTION_ID;
        let mut pos = 1;
        pos += varint::encode(&mut buf[pos..], 5).unwrap();
        pos += varint::encode(&mut buf[pos..], 2).unwrap();
        buf[pos] = 4;
        pos += 1;
        buf[pos..pos + 4].copy_from_slice(cid.as_bytes());
        pos += 4;
        buf[pos..pos + 16].copy_from_slice(&token);
        pos += 16;
        let (frame, consumed) = decode_frame(&buf[..pos]).unwrap();
        assert_eq!(consumed, pos);
        if let Frame::NewConnectionId(ncid) = frame {
            assert_eq!(ncid.sequence, 5);
            assert_eq!(ncid.retire_prior_to, 2);
            assert_eq!(ncid.connection_id, cid);
            assert_eq!(ncid.reset_token, token);
        } else {
            panic!("expected NEW_CONNECTION_ID");
        }
    }

    #[test]
    fn reset_stream_round_trip() {
        let mut buf = [0u8; 32];
        buf[0] = FRAME_RESET_STREAM;
        let mut pos = 1;
        pos += varint::encode(&mut buf[pos..], 4).unwrap();
        pos += varint::encode(&mut buf[pos..], 0x0a).unwrap();
        pos += varint::encode(&mut buf[pos..], 1024).unwrap();
        let (frame, consumed) = decode_frame(&buf[..pos]).unwrap();
        assert_eq!(consumed, pos);
        if let Frame::ResetStream(rs) = frame {
            assert_eq!(rs.stream_id, 4);
            assert_eq!(rs.error_code, 0x0a);
            assert_eq!(rs.final_size, 1024);
        } else {
            panic!("expected RESET_STREAM");
        }
    }
}
