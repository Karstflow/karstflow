mod config;
mod endpoint;
mod packet;
mod processor;
mod stream;

pub use config::{QuicConfig, QuicLimits};
pub use endpoint::{QuicEndpoint, QuicEndpointStats};
pub use packet::{QuicPacket, QuicPacketBatch};
pub use paradencer_constants::quic::*;
pub use processor::{QuicProcessor, QuicProcessorStats};
pub use stream::{QuicStream, StreamStats};

use crate::IngressError;

pub type QuicResult<T> = Result<T, IngressError>;
