//! Constants for the zero-copy inter-tile IPC subsystem.
//!
//! Defines alignment, sizing, and layout constants for the fragment-based
//! messaging system used for high-performance tile communication.

// ---------------------------------------------------------------------------
// Chunk granularity — payload allocation units
// ---------------------------------------------------------------------------

/// Log2 of chunk size. Chunks are the smallest payload allocation unit.
pub const CHUNK_LG_SIZE: u32 = 6;

/// Chunk alignment and size in bytes (64 bytes = cache line).
pub const CHUNK_SIZE: usize = 1 << CHUNK_LG_SIZE;

/// Chunk alignment (same as CHUNK_SIZE).
pub const CHUNK_ALIGN: usize = CHUNK_SIZE;

// ---------------------------------------------------------------------------
// Fragment metadata layout
// ---------------------------------------------------------------------------

/// Alignment of a single FragmentMeta entry (32 bytes).
pub const FRAGMENT_META_ALIGN: usize = 32;

/// Size of a single FragmentMeta entry in bytes.
pub const FRAGMENT_META_SIZE: usize = 32;

/// Maximum number of distinct message origins.
pub const FRAGMENT_ORIGIN_MAX: usize = 8192;

// ---------------------------------------------------------------------------
// Control bit layout within the 16-bit ctl field
// ---------------------------------------------------------------------------

/// Bit position for Start-of-Message flag.
pub const CTL_SOM_BIT: u16 = 0;

/// Bit position for End-of-Message flag.
pub const CTL_EOM_BIT: u16 = 1;

/// Bit position for Error flag.
pub const CTL_ERR_BIT: u16 = 2;

/// Bit shift for origin ID within ctl field.
pub const CTL_ORIGIN_SHIFT: u16 = 3;

// ---------------------------------------------------------------------------
// MetaRing (metadata cache) layout
// ---------------------------------------------------------------------------

/// Alignment of the MetaRing structure (double cache line to avoid false sharing).
pub const META_RING_ALIGN: usize = 128;

/// Number of sequence number entries in the MetaRing header region.
/// seq[0] is the producer watermark; remaining are application-defined.
pub const META_RING_SEQ_COUNT: usize = 16;

/// Minimum depth for a MetaRing (must be power of 2).
pub const META_RING_MIN_DEPTH: usize = 1;

/// Default depth for a MetaRing.
pub const META_RING_DEFAULT_DEPTH: usize = 256;

// ---------------------------------------------------------------------------
// DataRegion (payload cache) layout
// ---------------------------------------------------------------------------

/// Alignment of the DataRegion (page-aligned for optimal I/O).
pub const DATA_REGION_ALIGN: usize = 4096;

/// Alignment of individual slots within the DataRegion.
pub const DATA_REGION_SLOT_ALIGN: usize = 128;

/// Size of the guard region before the data area.
/// Provides alignment flexibility for producers writing directly into the region.
pub const DATA_REGION_GUARD_SIZE: usize = 3968;

/// Default MTU for fragment payloads (max single-fragment payload size).
pub const DATA_REGION_DEFAULT_MTU: usize = 1280;

/// Default depth for DataRegion sizing (matches MetaRing).
pub const DATA_REGION_DEFAULT_DEPTH: usize = 256;

// ---------------------------------------------------------------------------
// FlowSequence layout
// ---------------------------------------------------------------------------

/// Alignment of a FlowSequence (double cache line to avoid false sharing).
pub const FLOW_SEQ_ALIGN: usize = 128;

/// Total footprint of a FlowSequence including padding.
pub const FLOW_SEQ_FOOTPRINT: usize = 128;

/// Size of the application region within a FlowSequence.
pub const FLOW_SEQ_APP_SIZE: usize = 96;

/// Alignment of the application region within a FlowSequence.
pub const FLOW_SEQ_APP_ALIGN: usize = 32;

// ---------------------------------------------------------------------------
// Pipeline channel sizing
// ---------------------------------------------------------------------------

/// Channel depth from TxFilter to ValidatorPipeline per sanitizer worker.
/// Sized to buffer one full tick's worth of transactions with headroom.
pub const PIPELINE_CHANNEL_DEPTH_PER_WORKER: usize = 1024;
