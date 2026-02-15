use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum IngressError {
    #[error("max_payload_bytes must be greater than zero")]
    MaxPayloadMustBePositive,
    #[error("dedup_window_capacity must be greater than zero")]
    DedupWindowMustBePositive,
    #[error("egress_retry_buffer_capacity must be greater than zero")]
    EgressRetryBufferCapacityMustBePositive,
    #[error("egress_retry_max_wait_ticks must be greater than zero")]
    EgressRetryMaxWaitTicksMustBePositive,
    #[error("synthetic_batch_size_per_tick must be greater than zero")]
    SyntheticBatchSizeMustBePositive,
    #[error("synthetic_payload_bytes must be greater than zero")]
    SyntheticPayloadBytesMustBePositive,
    #[error("synthetic source weights total must be greater than zero")]
    SyntheticSourceWeightsMustHavePositiveTotal,
    #[error("udp_bind_address must be configured when ingress_mode='udp'")]
    UdpIngressModeRequiresBindAddress,
    #[error("udp_max_packets_per_tick must be greater than zero")]
    UdpMaxPacketsPerTickMustBePositive,
    #[error("quic configuration error: {detail}")]
    QuicConfiguration { detail: String },
    #[error("quic endpoint bind failed: {detail}")]
    QuicEndpointBind { detail: String },
    #[error("quic connection error: {detail}")]
    QuicConnection { detail: String },
    #[error("quic stream error: {detail}")]
    QuicStream { detail: String },
    #[error("quic i/o error: {detail}")]
    QuicIo { detail: String },
}
