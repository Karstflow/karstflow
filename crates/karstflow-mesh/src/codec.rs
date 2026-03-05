/// Codec for serializing typed messages to/from raw byte fragments.
///
/// Types that implement `FragmentCodec` can be transmitted over both
/// crossbeam channels (typed, zero-copy via `Clone`) and zero-copy tile
/// links (raw bytes via `encode`/`decode`).
///
/// The encode/decode contract:
/// - `encode` writes the message into a caller-provided buffer and returns
///   the number of bytes written. The buffer is guaranteed to be at least
///   `max_encoded_size()` bytes.
/// - `decode` reconstructs the message from the bytes previously written
///   by `encode`. The slice length matches the value returned by `encode`.
/// - `signature` returns a 64-bit value used for fast fragment filtering
///   on the consumer side (e.g., hash of a dedup key). Defaults to 0.
pub trait FragmentCodec: Send + 'static + Sized {
    /// Encode this message into `buf`, returning the number of bytes written.
    ///
    /// # Panics
    ///
    /// May panic if `buf.len() < max_encoded_size()`.
    fn encode(&self, buf: &mut [u8]) -> usize;

    /// Decode a message from bytes previously produced by `encode`.
    fn decode(bytes: &[u8]) -> Self;

    /// Maximum number of bytes `encode` will ever write.
    ///
    /// This determines the MTU of the tile link backing this codec.
    fn max_encoded_size() -> usize;

    /// Application-defined signature for fast consumer-side filtering.
    ///
    /// The signature is stored in fragment metadata and can be inspected
    /// without reading the payload. Returns 0 by default.
    fn signature(&self) -> u64 {
        0
    }
}
