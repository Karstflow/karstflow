/// QUIC engine callback interface.
///
/// The engine invokes these callbacks during `service()` and
/// `process_packet()` to notify the application of connection and
/// stream events. Callbacks are non-reentrant — the application must
/// not call back into the engine from within a callback.
///
/// Stream notification types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamNotify {
    /// Stream reached FIN (normal end).
    End,
    /// Peer reset the stream with an error code.
    PeerReset,
    /// Peer sent STOP_SENDING.
    PeerStop,
    /// Stream dropped due to connection closing.
    Drop,
    /// Connection closed while stream was open.
    ConnectionClose,
}

/// Engine event callbacks.
///
/// All callbacks receive a context pointer (`ctx`) that was provided
/// during engine initialization. The `conn_idx` and `stream_idx`
/// parameters are indices into the engine's pre-allocated arrays.
pub trait EngineCallbacks {
    /// A new connection has been accepted (server) or initiated (client).
    ///
    /// Called after the handshake begins, before it completes.
    fn on_connection_new(&mut self, conn_idx: usize) {
        let _ = conn_idx;
    }

    /// TLS handshake completed successfully.
    ///
    /// Application-layer communication can begin after this callback.
    fn on_handshake_complete(&mut self, conn_idx: usize) {
        let _ = conn_idx;
    }

    /// Connection has been terminated and will be freed.
    ///
    /// This is the last callback for a connection. The application must
    /// release any references to the connection after this call.
    fn on_connection_final(&mut self, conn_idx: usize) {
        let _ = conn_idx;
    }

    /// Stream received data.
    ///
    /// `offset` is the byte offset within the stream. `fin` indicates
    /// this is the final data on the stream. Data may arrive out of order.
    fn on_stream_data(
        &mut self,
        conn_idx: usize,
        stream_id: u64,
        offset: u64,
        data: &[u8],
        fin: bool,
    ) {
        let _ = (conn_idx, stream_id, offset, data, fin);
    }

    /// Stream state changed (closed, reset, etc.).
    fn on_stream_notify(&mut self, conn_idx: usize, stream_id: u64, notify: StreamNotify) {
        let _ = (conn_idx, stream_id, notify);
    }

    /// TLS key log line for debugging (NSS SSLKEYLOGFILE format).
    fn on_tls_keylog(&mut self, _line: &str) {}
}

/// No-op callback implementation for testing.
pub struct NoopCallbacks;

impl EngineCallbacks for NoopCallbacks {}

/// Callback wrapper that collects events for testing.
#[cfg(test)]
#[derive(Default)]
pub struct RecordingCallbacks {
    pub events: Vec<String>,
}

#[cfg(test)]
impl RecordingCallbacks {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
impl EngineCallbacks for RecordingCallbacks {
    fn on_connection_new(&mut self, conn_idx: usize) {
        self.events.push(format!("conn_new:{conn_idx}"));
    }

    fn on_handshake_complete(&mut self, conn_idx: usize) {
        self.events.push(format!("hs_complete:{conn_idx}"));
    }

    fn on_connection_final(&mut self, conn_idx: usize) {
        self.events.push(format!("conn_final:{conn_idx}"));
    }

    fn on_stream_data(
        &mut self,
        conn_idx: usize,
        stream_id: u64,
        _offset: u64,
        data: &[u8],
        fin: bool,
    ) {
        self.events.push(format!(
            "stream_data:{conn_idx}:{stream_id}:{}:fin={fin}",
            data.len()
        ));
    }

    fn on_stream_notify(&mut self, conn_idx: usize, stream_id: u64, notify: StreamNotify) {
        self.events
            .push(format!("stream_notify:{conn_idx}:{stream_id}:{notify:?}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_callbacks_compile() {
        let mut cb = NoopCallbacks;
        cb.on_connection_new(0);
        cb.on_handshake_complete(0);
        cb.on_connection_final(0);
        cb.on_stream_data(0, 0, 0, b"test", false);
        cb.on_stream_notify(0, 0, StreamNotify::End);
        cb.on_tls_keylog("test");
    }

    #[test]
    fn recording_callbacks_capture_events() {
        let mut cb = RecordingCallbacks::new();
        cb.on_connection_new(0);
        cb.on_handshake_complete(0);
        cb.on_stream_data(0, 4, 0, b"hello", true);
        cb.on_stream_notify(0, 4, StreamNotify::End);
        cb.on_connection_final(0);

        assert_eq!(cb.events.len(), 5);
        assert_eq!(cb.events[0], "conn_new:0");
        assert_eq!(cb.events[1], "hs_complete:0");
        assert_eq!(cb.events[2], "stream_data:0:4:5:fin=true");
        assert_eq!(cb.events[3], "stream_notify:0:4:End");
        assert_eq!(cb.events[4], "conn_final:0");
    }

    #[test]
    fn stream_notify_variants() {
        assert_ne!(StreamNotify::End, StreamNotify::PeerReset);
        assert_ne!(StreamNotify::PeerStop, StreamNotify::Drop);
        assert_ne!(StreamNotify::Drop, StreamNotify::ConnectionClose);
    }
}
