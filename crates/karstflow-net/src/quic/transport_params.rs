/// QUIC transport parameters encoding and decoding (RFC 9000 Section 18).
///
/// Transport parameters are exchanged during the TLS handshake to negotiate
/// connection settings like flow control windows, maximum streams, and
/// connection ID management.
use super::conn_id::ConnectionId;
use super::varint;
use karstflow_constants::network::*;

/// Decoded QUIC transport parameters.
#[derive(Debug, Clone)]
pub struct TransportParams {
    pub original_dst_conn_id: Option<ConnectionId>,
    pub max_idle_timeout_ms: u64,
    pub stateless_reset_token: Option<[u8; 16]>,
    pub max_udp_payload_size: u64,
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub ack_delay_exponent: u64,
    pub max_ack_delay: u64,
    pub disable_active_migration: bool,
    pub active_conn_id_limit: u64,
    pub initial_source_conn_id: Option<ConnectionId>,
    pub retry_source_conn_id: Option<ConnectionId>,
}

impl Default for TransportParams {
    fn default() -> Self {
        Self {
            original_dst_conn_id: None,
            max_idle_timeout_ms: 0,
            stateless_reset_token: None,
            max_udp_payload_size: 65527,
            initial_max_data: 0,
            initial_max_stream_data_bidi_local: 0,
            initial_max_stream_data_bidi_remote: 0,
            initial_max_stream_data_uni: 0,
            initial_max_streams_bidi: 0,
            initial_max_streams_uni: 0,
            ack_delay_exponent: 3,
            max_ack_delay: 25,
            disable_active_migration: false,
            active_conn_id_limit: 2,
            initial_source_conn_id: None,
            retry_source_conn_id: None,
        }
    }
}

/// Error during transport parameter encoding or decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportParamsError {
    BufferTooSmall,
    VarintError,
    InvalidParameter,
    InvalidConnectionId,
}

impl From<varint::VarintError> for TransportParamsError {
    fn from(_: varint::VarintError) -> Self {
        TransportParamsError::VarintError
    }
}

/// Decode transport parameters from wire format.
///
/// Unknown parameter IDs are silently ignored per RFC 9000.
pub fn decode(buf: &[u8]) -> Result<TransportParams, TransportParamsError> {
    let mut params = TransportParams::default();
    let mut pos = 0;

    while pos < buf.len() {
        let (param_id, n) =
            varint::decode(&buf[pos..]).map_err(|_| TransportParamsError::VarintError)?;
        pos += n;

        let (param_len, n) =
            varint::decode(&buf[pos..]).map_err(|_| TransportParamsError::VarintError)?;
        pos += n;

        let param_len = param_len as usize;
        if buf.len() < pos + param_len {
            return Err(TransportParamsError::BufferTooSmall);
        }
        let param_data = &buf[pos..pos + param_len];
        pos += param_len;

        match param_id {
            TP_ORIGINAL_DST_CONN_ID => {
                params.original_dst_conn_id = Some(
                    ConnectionId::from_bytes(param_data)
                        .ok_or(TransportParamsError::InvalidConnectionId)?,
                );
            }
            TP_MAX_IDLE_TIMEOUT => {
                params.max_idle_timeout_ms = decode_varint_param(param_data)?;
            }
            TP_STATELESS_RESET_TOKEN => {
                if param_data.len() != 16 {
                    return Err(TransportParamsError::InvalidParameter);
                }
                let mut token = [0u8; 16];
                token.copy_from_slice(param_data);
                params.stateless_reset_token = Some(token);
            }
            TP_MAX_UDP_PAYLOAD_SIZE => {
                params.max_udp_payload_size = decode_varint_param(param_data)?;
            }
            TP_INITIAL_MAX_DATA => {
                params.initial_max_data = decode_varint_param(param_data)?;
            }
            TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL => {
                params.initial_max_stream_data_bidi_local = decode_varint_param(param_data)?;
            }
            TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE => {
                params.initial_max_stream_data_bidi_remote = decode_varint_param(param_data)?;
            }
            TP_INITIAL_MAX_STREAM_DATA_UNI => {
                params.initial_max_stream_data_uni = decode_varint_param(param_data)?;
            }
            TP_INITIAL_MAX_STREAMS_BIDI => {
                params.initial_max_streams_bidi = decode_varint_param(param_data)?;
            }
            TP_INITIAL_MAX_STREAMS_UNI => {
                params.initial_max_streams_uni = decode_varint_param(param_data)?;
            }
            TP_ACK_DELAY_EXPONENT => {
                params.ack_delay_exponent = decode_varint_param(param_data)?;
            }
            TP_MAX_ACK_DELAY => {
                params.max_ack_delay = decode_varint_param(param_data)?;
            }
            TP_DISABLE_ACTIVE_MIGRATION => {
                if !param_data.is_empty() {
                    return Err(TransportParamsError::InvalidParameter);
                }
                params.disable_active_migration = true;
            }
            TP_ACTIVE_CONN_ID_LIMIT => {
                params.active_conn_id_limit = decode_varint_param(param_data)?;
            }
            TP_INITIAL_SOURCE_CONN_ID => {
                params.initial_source_conn_id = Some(
                    ConnectionId::from_bytes(param_data)
                        .ok_or(TransportParamsError::InvalidConnectionId)?,
                );
            }
            TP_RETRY_SOURCE_CONN_ID => {
                params.retry_source_conn_id = Some(
                    ConnectionId::from_bytes(param_data)
                        .ok_or(TransportParamsError::InvalidConnectionId)?,
                );
            }
            _ => {} // Unknown parameters silently ignored
        }
    }

    Ok(params)
}

/// Encode transport parameters to wire format.
pub fn encode(buf: &mut [u8], params: &TransportParams) -> Result<usize, TransportParamsError> {
    let mut pos = 0;

    if let Some(ref cid) = params.original_dst_conn_id {
        pos += encode_conn_id_param(&mut buf[pos..], TP_ORIGINAL_DST_CONN_ID, cid)?;
    }
    if params.max_idle_timeout_ms > 0 {
        pos += encode_varint_param(
            &mut buf[pos..],
            TP_MAX_IDLE_TIMEOUT,
            params.max_idle_timeout_ms,
        )?;
    }
    if let Some(token) = &params.stateless_reset_token {
        pos += encode_raw_param(&mut buf[pos..], TP_STATELESS_RESET_TOKEN, token)?;
    }
    if params.max_udp_payload_size != 65527 {
        pos += encode_varint_param(
            &mut buf[pos..],
            TP_MAX_UDP_PAYLOAD_SIZE,
            params.max_udp_payload_size,
        )?;
    }
    if params.initial_max_data > 0 {
        pos += encode_varint_param(
            &mut buf[pos..],
            TP_INITIAL_MAX_DATA,
            params.initial_max_data,
        )?;
    }
    if params.initial_max_stream_data_bidi_local > 0 {
        pos += encode_varint_param(
            &mut buf[pos..],
            TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            params.initial_max_stream_data_bidi_local,
        )?;
    }
    if params.initial_max_stream_data_bidi_remote > 0 {
        pos += encode_varint_param(
            &mut buf[pos..],
            TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            params.initial_max_stream_data_bidi_remote,
        )?;
    }
    if params.initial_max_stream_data_uni > 0 {
        pos += encode_varint_param(
            &mut buf[pos..],
            TP_INITIAL_MAX_STREAM_DATA_UNI,
            params.initial_max_stream_data_uni,
        )?;
    }
    if params.initial_max_streams_bidi > 0 {
        pos += encode_varint_param(
            &mut buf[pos..],
            TP_INITIAL_MAX_STREAMS_BIDI,
            params.initial_max_streams_bidi,
        )?;
    }
    if params.initial_max_streams_uni > 0 {
        pos += encode_varint_param(
            &mut buf[pos..],
            TP_INITIAL_MAX_STREAMS_UNI,
            params.initial_max_streams_uni,
        )?;
    }
    if params.ack_delay_exponent != 3 {
        pos += encode_varint_param(
            &mut buf[pos..],
            TP_ACK_DELAY_EXPONENT,
            params.ack_delay_exponent,
        )?;
    }
    if params.max_ack_delay != 25 {
        pos += encode_varint_param(&mut buf[pos..], TP_MAX_ACK_DELAY, params.max_ack_delay)?;
    }
    if params.disable_active_migration {
        pos += encode_empty_param(&mut buf[pos..], TP_DISABLE_ACTIVE_MIGRATION)?;
    }
    if params.active_conn_id_limit != 2 {
        pos += encode_varint_param(
            &mut buf[pos..],
            TP_ACTIVE_CONN_ID_LIMIT,
            params.active_conn_id_limit,
        )?;
    }
    if let Some(ref cid) = params.initial_source_conn_id {
        pos += encode_conn_id_param(&mut buf[pos..], TP_INITIAL_SOURCE_CONN_ID, cid)?;
    }
    if let Some(ref cid) = params.retry_source_conn_id {
        pos += encode_conn_id_param(&mut buf[pos..], TP_RETRY_SOURCE_CONN_ID, cid)?;
    }

    Ok(pos)
}

fn decode_varint_param(data: &[u8]) -> Result<u64, TransportParamsError> {
    if data.is_empty() {
        return Err(TransportParamsError::InvalidParameter);
    }
    let (value, _) = varint::decode(data).map_err(|_| TransportParamsError::VarintError)?;
    Ok(value)
}

fn encode_varint_param(
    buf: &mut [u8],
    param_id: u64,
    value: u64,
) -> Result<usize, TransportParamsError> {
    let mut pos = 0;
    pos += varint::encode(&mut buf[pos..], param_id)?;
    let value_size = varint::encoded_size(value).map_err(|_| TransportParamsError::VarintError)?;
    pos += varint::encode(&mut buf[pos..], value_size as u64)?;
    pos += varint::encode(&mut buf[pos..], value)?;
    Ok(pos)
}

fn encode_conn_id_param(
    buf: &mut [u8],
    param_id: u64,
    cid: &ConnectionId,
) -> Result<usize, TransportParamsError> {
    let mut pos = 0;
    pos += varint::encode(&mut buf[pos..], param_id)?;
    pos += varint::encode(&mut buf[pos..], cid.len() as u64)?;
    if buf.len() < pos + cid.len() {
        return Err(TransportParamsError::BufferTooSmall);
    }
    cid.encode(&mut buf[pos..])
        .ok_or(TransportParamsError::BufferTooSmall)?;
    pos += cid.len();
    Ok(pos)
}

fn encode_raw_param(
    buf: &mut [u8],
    param_id: u64,
    data: &[u8],
) -> Result<usize, TransportParamsError> {
    let mut pos = 0;
    pos += varint::encode(&mut buf[pos..], param_id)?;
    pos += varint::encode(&mut buf[pos..], data.len() as u64)?;
    if buf.len() < pos + data.len() {
        return Err(TransportParamsError::BufferTooSmall);
    }
    buf[pos..pos + data.len()].copy_from_slice(data);
    pos += data.len();
    Ok(pos)
}

fn encode_empty_param(buf: &mut [u8], param_id: u64) -> Result<usize, TransportParamsError> {
    let mut pos = 0;
    pos += varint::encode(&mut buf[pos..], param_id)?;
    pos += varint::encode(&mut buf[pos..], 0)?;
    Ok(pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_params() {
        let params = TransportParams::default();
        assert_eq!(params.max_idle_timeout_ms, 0);
        assert_eq!(params.max_udp_payload_size, 65527);
        assert_eq!(params.ack_delay_exponent, 3);
        assert_eq!(params.max_ack_delay, 25);
        assert_eq!(params.active_conn_id_limit, 2);
        assert!(!params.disable_active_migration);
    }

    #[test]
    fn encode_decode_defaults_empty() {
        let params = TransportParams::default();
        let mut buf = [0u8; 512];
        let n = encode(&mut buf, &params).unwrap();
        assert_eq!(n, 0); // Defaults produce no output
        let decoded = decode(&buf[..n]).unwrap();
        assert_eq!(decoded.max_idle_timeout_ms, 0);
        assert_eq!(decoded.active_conn_id_limit, 2);
    }

    #[test]
    fn encode_decode_full_params() {
        let cid = ConnectionId::from_bytes(&[0xDE, 0xAD]).unwrap();
        let scid = ConnectionId::from_bytes(&[0xBE, 0xEF]).unwrap();

        let params = TransportParams {
            original_dst_conn_id: Some(cid),
            max_idle_timeout_ms: 30000,
            stateless_reset_token: Some([0xAA; 16]),
            max_udp_payload_size: 1472,
            initial_max_data: 1_000_000,
            initial_max_stream_data_bidi_local: 256_000,
            initial_max_stream_data_bidi_remote: 256_000,
            initial_max_stream_data_uni: 128_000,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 100,
            ack_delay_exponent: 5,
            max_ack_delay: 50,
            disable_active_migration: true,
            active_conn_id_limit: 8,
            initial_source_conn_id: Some(scid),
            retry_source_conn_id: None,
        };

        let mut buf = [0u8; 512];
        let n = encode(&mut buf, &params).unwrap();
        assert!(n > 0);

        let decoded = decode(&buf[..n]).unwrap();
        assert_eq!(decoded.max_idle_timeout_ms, 30000);
        assert_eq!(decoded.max_udp_payload_size, 1472);
        assert_eq!(decoded.initial_max_data, 1_000_000);
        assert_eq!(decoded.initial_max_streams_bidi, 100);
        assert_eq!(decoded.ack_delay_exponent, 5);
        assert_eq!(decoded.max_ack_delay, 50);
        assert!(decoded.disable_active_migration);
        assert_eq!(decoded.active_conn_id_limit, 8);
        assert_eq!(decoded.original_dst_conn_id.unwrap(), cid);
        assert_eq!(decoded.initial_source_conn_id.unwrap(), scid);
        assert!(decoded.retry_source_conn_id.is_none());
        assert_eq!(decoded.stateless_reset_token.unwrap(), [0xAA; 16]);
    }

    #[test]
    fn unknown_params_ignored() {
        let mut buf = [0u8; 32];
        let mut pos = 0;
        // Unknown param ID 0xFF
        pos += varint::encode(&mut buf[pos..], 0xFF).unwrap();
        pos += varint::encode(&mut buf[pos..], 2).unwrap();
        buf[pos] = 0x01;
        buf[pos + 1] = 0x02;
        pos += 2;
        // Known param
        pos += varint::encode(&mut buf[pos..], TP_MAX_IDLE_TIMEOUT).unwrap();
        let sz = varint::encoded_size(5000).unwrap();
        pos += varint::encode(&mut buf[pos..], sz as u64).unwrap();
        pos += varint::encode(&mut buf[pos..], 5000).unwrap();

        let decoded = decode(&buf[..pos]).unwrap();
        assert_eq!(decoded.max_idle_timeout_ms, 5000);
    }

    #[test]
    fn disable_migration_zero_length() {
        let mut buf = [0u8; 16];
        let mut pos = 0;
        pos += varint::encode(&mut buf[pos..], TP_DISABLE_ACTIVE_MIGRATION).unwrap();
        pos += varint::encode(&mut buf[pos..], 0).unwrap();
        let decoded = decode(&buf[..pos]).unwrap();
        assert!(decoded.disable_active_migration);
    }

    #[test]
    fn connection_id_params() {
        let dcid = ConnectionId::from_bytes(&[0x01, 0x02, 0x03, 0x04]).unwrap();
        let scid = ConnectionId::from_bytes(&[0xAA, 0xBB]).unwrap();
        let params = TransportParams {
            original_dst_conn_id: Some(dcid),
            initial_source_conn_id: Some(scid),
            retry_source_conn_id: Some(ConnectionId::EMPTY),
            ..TransportParams::default()
        };
        let mut buf = [0u8; 256];
        let n = encode(&mut buf, &params).unwrap();
        let decoded = decode(&buf[..n]).unwrap();
        assert_eq!(decoded.original_dst_conn_id.unwrap(), dcid);
        assert_eq!(decoded.initial_source_conn_id.unwrap(), scid);
        assert_eq!(decoded.retry_source_conn_id.unwrap(), ConnectionId::EMPTY);
    }

    #[test]
    fn empty_input() {
        let decoded = decode(&[]).unwrap();
        assert_eq!(decoded.max_idle_timeout_ms, 0);
    }
}
