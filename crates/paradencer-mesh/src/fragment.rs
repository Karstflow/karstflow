/// Fragment metadata and sequence number operations for zero-copy IPC.
///
/// A fragment is the unit of inter-tile communication. Each fragment has
/// 32 bytes of metadata (sequence number, signature, payload location,
/// size, control bits, timestamps) stored in a ring buffer, and a variable-
/// length payload stored in a separate data region referenced by chunk index.
use paradencer_constants::ipc::{CTL_EOM_BIT, CTL_ERR_BIT, CTL_ORIGIN_SHIFT, CTL_SOM_BIT};

// ---------------------------------------------------------------------------
// Fragment metadata
// ---------------------------------------------------------------------------

/// Metadata for a single message fragment.
///
/// This struct has the same layout as the kernel ABI for shared-memory
/// interoperability. All fields are naturally aligned for atomic access
/// on x86-64 (u64 fields are 8-byte aligned, u32 are 4-byte aligned).
///
/// The `seq` field is used for lock-free publish/consume protocol:
/// producer writes `seq-1` first (marks entry as being written),
/// then writes the body fields, then writes the real `seq`.
/// Consumer reads `seq`, reads body, re-reads `seq` — if both reads
/// match the expected value, the body is consistent (no torn read).
#[repr(C, align(32))]
#[derive(Debug, Clone, Copy)]
pub struct FragmentMeta {
    /// Fragment sequence number. Monotonically increasing across all
    /// producers for a given link. Used for ordering and overrun detection.
    pub seq: u64,

    /// Application-defined message signature for fast consumer-side
    /// filtering. Consumers can skip fragments without reading payload
    /// if the signature indicates the message is not relevant.
    pub sig: u64,

    /// Compressed relative location of the fragment payload in the data
    /// region. The actual byte offset is `chunk * CHUNK_SIZE` relative
    /// to the data region base address.
    pub chunk: u32,

    /// Fragment payload size in bytes.
    pub sz: u16,

    /// Control bits: origin ID (bits 15:3), ERR (bit 2), EOM (bit 1), SOM (bit 0).
    pub ctl: u16,

    /// Timestamp when the origin first started producing this fragment.
    /// Compressed to 32 bits from a 64-bit wall clock (see `ts_compress`).
    pub tsorig: u32,

    /// Timestamp when this fragment was published (made available to consumers).
    /// Compressed to 32 bits.
    pub tspub: u32,
}

impl FragmentMeta {
    /// Create a zeroed fragment metadata entry.
    pub const fn zeroed() -> Self {
        Self {
            seq: 0,
            sig: 0,
            chunk: 0,
            sz: 0,
            ctl: 0,
            tsorig: 0,
            tspub: 0,
        }
    }

    /// Create an "invalid" entry suitable for initializing a ring buffer.
    /// The ERR bit is set so consumers know this is not real data.
    /// SOM + EOM bits are set so consumers don't try to reassemble.
    pub fn invalid(seq: u64) -> Self {
        Self {
            seq,
            sig: 0,
            chunk: 0,
            sz: 0,
            ctl: ctl_pack(0, true, true, true),
            tsorig: 0,
            tspub: 0,
        }
    }
}

impl Default for FragmentMeta {
    fn default() -> Self {
        Self::zeroed()
    }
}

// ---------------------------------------------------------------------------
// Control bit packing
// ---------------------------------------------------------------------------

/// Pack control bits into the 16-bit ctl field.
#[inline]
pub fn ctl_pack(origin: u16, som: bool, eom: bool, err: bool) -> u16 {
    (u16::from(som) << CTL_SOM_BIT)
        | (u16::from(eom) << CTL_EOM_BIT)
        | (u16::from(err) << CTL_ERR_BIT)
        | (origin << CTL_ORIGIN_SHIFT)
}

/// Extract the origin ID from a ctl field.
#[inline]
pub fn ctl_origin(ctl: u16) -> u16 {
    ctl >> CTL_ORIGIN_SHIFT
}

/// Extract the Start-of-Message flag.
#[inline]
pub fn ctl_som(ctl: u16) -> bool {
    (ctl >> CTL_SOM_BIT) & 1 != 0
}

/// Extract the End-of-Message flag.
#[inline]
pub fn ctl_eom(ctl: u16) -> bool {
    (ctl >> CTL_EOM_BIT) & 1 != 0
}

/// Extract the Error flag.
#[inline]
pub fn ctl_err(ctl: u16) -> bool {
    (ctl >> CTL_ERR_BIT) & 1 != 0
}

// ---------------------------------------------------------------------------
// Sequence number operations (wrapping arithmetic)
// ---------------------------------------------------------------------------

/// Compare sequence numbers with proper wrapping: a < b.
#[inline]
pub fn seq_lt(a: u64, b: u64) -> bool {
    (a.wrapping_sub(b) as i64) < 0
}

/// Compare sequence numbers with proper wrapping: a <= b.
#[inline]
pub fn seq_le(a: u64, b: u64) -> bool {
    (a.wrapping_sub(b) as i64) <= 0
}

/// Compare sequence numbers with proper wrapping: a == b.
#[inline]
pub fn seq_eq(a: u64, b: u64) -> bool {
    a == b
}

/// Compare sequence numbers with proper wrapping: a != b.
#[inline]
pub fn seq_ne(a: u64, b: u64) -> bool {
    a != b
}

/// Compare sequence numbers with proper wrapping: a >= b.
#[inline]
pub fn seq_ge(a: u64, b: u64) -> bool {
    (a.wrapping_sub(b) as i64) >= 0
}

/// Compare sequence numbers with proper wrapping: a > b.
#[inline]
pub fn seq_gt(a: u64, b: u64) -> bool {
    (a.wrapping_sub(b) as i64) > 0
}

/// Increment a sequence number.
#[inline]
pub fn seq_inc(a: u64, delta: u64) -> u64 {
    a.wrapping_add(delta)
}

/// Decrement a sequence number.
#[inline]
pub fn seq_dec(a: u64, delta: u64) -> u64 {
    a.wrapping_sub(delta)
}

/// Signed difference between two sequence numbers.
/// Positive means `a` is ahead of `b`, negative means behind.
#[inline]
pub fn seq_diff(a: u64, b: u64) -> i64 {
    a.wrapping_sub(b) as i64
}

// ---------------------------------------------------------------------------
// Timestamp compression
// ---------------------------------------------------------------------------

/// Compress a 64-bit wall clock timestamp to 32 bits.
/// Retains the lower 32 bits — valid for offsets within ~4.3 seconds
/// of the reference timestamp.
#[inline]
pub fn ts_compress(ts: i64) -> u32 {
    ts as u32
}

/// Decompress a 32-bit timestamp back to 64-bit using a reference.
/// The reference should be within ~2.1 seconds of the original.
#[inline]
pub fn ts_decompress(compressed: u32, reference: i64) -> i64 {
    let msb = (reference as u64)
        .wrapping_add(0x7FFF_FFFF)
        .wrapping_sub(compressed as u64);
    ((msb & !0xFFFF_FFFF) | (compressed as u64)) as i64
}

// ---------------------------------------------------------------------------
// Chunk arithmetic
// ---------------------------------------------------------------------------

/// Convert a chunk index to a byte offset.
#[inline]
pub fn chunk_to_offset(chunk: u32) -> usize {
    (chunk as usize) << paradencer_constants::ipc::CHUNK_LG_SIZE
}

/// Convert a byte offset to a chunk index.
#[inline]
pub fn offset_to_chunk(offset: usize) -> u32 {
    (offset >> paradencer_constants::ipc::CHUNK_LG_SIZE) as u32
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use paradencer_constants::ipc::{FRAGMENT_META_ALIGN, FRAGMENT_META_SIZE};

    #[test]
    fn fragment_meta_size_and_alignment() {
        assert_eq!(std::mem::size_of::<FragmentMeta>(), FRAGMENT_META_SIZE);
        assert_eq!(std::mem::align_of::<FragmentMeta>(), FRAGMENT_META_ALIGN);
    }

    #[test]
    fn fragment_meta_field_offsets() {
        // Verify fields are at expected offsets for shared-memory compatibility.
        let meta = FragmentMeta::zeroed();
        let base = &meta as *const FragmentMeta as usize;
        assert_eq!(&meta.seq as *const u64 as usize - base, 0);
        assert_eq!(&meta.sig as *const u64 as usize - base, 8);
        assert_eq!(&meta.chunk as *const u32 as usize - base, 16);
        assert_eq!(&meta.sz as *const u16 as usize - base, 20);
        assert_eq!(&meta.ctl as *const u16 as usize - base, 22);
        assert_eq!(&meta.tsorig as *const u32 as usize - base, 24);
        assert_eq!(&meta.tspub as *const u32 as usize - base, 28);
    }

    #[test]
    fn ctl_packing() {
        let ctl = ctl_pack(42, true, false, true);
        assert!(ctl_som(ctl));
        assert!(!ctl_eom(ctl));
        assert!(ctl_err(ctl));
        assert_eq!(ctl_origin(ctl), 42);
    }

    #[test]
    fn ctl_all_flags() {
        let ctl = ctl_pack(0, true, true, true);
        assert!(ctl_som(ctl));
        assert!(ctl_eom(ctl));
        assert!(ctl_err(ctl));
        assert_eq!(ctl_origin(ctl), 0);
    }

    #[test]
    fn ctl_no_flags() {
        let ctl = ctl_pack(100, false, false, false);
        assert!(!ctl_som(ctl));
        assert!(!ctl_eom(ctl));
        assert!(!ctl_err(ctl));
        assert_eq!(ctl_origin(ctl), 100);
    }

    #[test]
    fn seq_comparison_no_wrap() {
        assert!(seq_lt(5, 10));
        assert!(!seq_lt(10, 5));
        assert!(seq_le(5, 5));
        assert!(seq_eq(42, 42));
        assert!(seq_ne(1, 2));
        assert!(seq_ge(10, 5));
        assert!(seq_gt(10, 5));
    }

    #[test]
    fn seq_comparison_wrapping() {
        // Test near u64::MAX boundary.
        let a = u64::MAX;
        let b = 0u64;
        // a is "before" b in wrapping arithmetic (a < b).
        assert!(seq_lt(a, b));
        assert!(!seq_gt(a, b));
        assert_eq!(seq_diff(b, a), 1);
    }

    #[test]
    fn seq_inc_dec() {
        assert_eq!(seq_inc(10, 3), 13);
        assert_eq!(seq_dec(10, 3), 7);
        // Wrapping
        assert_eq!(seq_inc(u64::MAX, 1), 0);
        assert_eq!(seq_dec(0, 1), u64::MAX);
    }

    #[test]
    fn seq_diff_values() {
        assert_eq!(seq_diff(10, 5), 5);
        assert_eq!(seq_diff(5, 10), -5);
        assert_eq!(seq_diff(100, 100), 0);
    }

    #[test]
    fn timestamp_roundtrip() {
        let ts: i64 = 1_700_000_000_123;
        let compressed = ts_compress(ts);
        let decompressed = ts_decompress(compressed, ts);
        assert_eq!(decompressed, ts);
    }

    #[test]
    fn timestamp_roundtrip_near_reference() {
        let reference: i64 = 1_700_000_000_000;
        let ts = reference + 500_000; // 500µs later
        let compressed = ts_compress(ts);
        let decompressed = ts_decompress(compressed, reference);
        assert_eq!(decompressed, ts);
    }

    #[test]
    fn chunk_arithmetic() {
        assert_eq!(chunk_to_offset(0), 0);
        assert_eq!(chunk_to_offset(1), 64);
        assert_eq!(chunk_to_offset(100), 6400);
        assert_eq!(offset_to_chunk(0), 0);
        assert_eq!(offset_to_chunk(64), 1);
        assert_eq!(offset_to_chunk(6400), 100);
    }

    #[test]
    fn invalid_fragment_has_err_bit() {
        let meta = FragmentMeta::invalid(42);
        assert_eq!(meta.seq, 42);
        assert!(ctl_err(meta.ctl));
        assert!(ctl_som(meta.ctl));
        assert!(ctl_eom(meta.ctl));
        assert_eq!(meta.sz, 0);
    }
}
