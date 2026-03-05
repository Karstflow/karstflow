//! Constants for replay pipeline configuration.

/// Default capacity for replay signal broadcast channels.
///
/// Each subscriber gets a bounded channel of this capacity.
/// If a subscriber falls behind, new signals are dropped for
/// that subscriber (non-blocking emit).
pub const SIGNAL_CHANNEL_CAPACITY: usize = 256;

/// Maximum number of concurrent signal subscribers.
pub const MAX_SIGNAL_SUBSCRIBERS: usize = 16;

/// Default number of parallel execution lanes for replay dispatch.
///
/// Each lane corresponds to an execution tile that can process
/// transactions concurrently. Transactions with no account
/// conflicts are dispatched to different lanes in parallel.
pub const DEFAULT_EXECUTION_LANES: usize = 4;

/// Maximum transactions in a single dispatch graph (per block).
pub const MAX_DISPATCH_GRAPH_SIZE: usize = 8_000_000;

/// Maximum dependency chain depth before flagging as suspicious.
///
/// A long chain means all transactions in the block are serialized
/// through a single account, which limits parallelism.
pub const MAX_DEPENDENCY_CHAIN_DEPTH: usize = 1024;
