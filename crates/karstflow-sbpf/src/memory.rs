/// Virtual memory model for the sBPF virtual machine.
///
/// Programs execute within a segmented virtual address space with four
/// regions: read-only program data, read-write stack, read-write heap,
/// and read-write input (serialized accounts). Each region is mapped to
/// a distinct 4 GB range identified by the high nibble of the address.
use karstflow_constants::vm::{
    MAX_CALL_DEPTH, REGION_HEAP_BASE, REGION_INDEX_MASK, REGION_INPUT_BASE, REGION_OFFSET_MASK,
    REGION_PROGRAM_BASE, REGION_STACK_BASE, STACK_FRAME_SIZE,
};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors during memory access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoryError {
    /// Address falls in an unmapped region.
    UnmappedAddress { addr: u64 },
    /// Access extends beyond the end of a region.
    OutOfBounds {
        addr: u64,
        size: usize,
        region_len: usize,
    },
    /// Write to a read-only region.
    ReadOnlyRegion { addr: u64 },
    /// Address is not properly aligned for the access width.
    UnalignedAccess { addr: u64, alignment: usize },
    /// Stack overflow: maximum call depth exceeded.
    StackOverflow,
    /// Stack underflow: pop on empty call stack.
    StackUnderflow,
}

impl std::fmt::Display for MemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnmappedAddress { addr } => {
                write!(f, "unmapped virtual address 0x{:016X}", addr)
            }
            Self::OutOfBounds {
                addr,
                size,
                region_len,
            } => {
                write!(
                    f,
                    "access at 0x{:016X} size {} exceeds region length {}",
                    addr, size, region_len
                )
            }
            Self::ReadOnlyRegion { addr } => {
                write!(f, "write to read-only address 0x{:016X}", addr)
            }
            Self::UnalignedAccess { addr, alignment } => {
                write!(
                    f,
                    "unaligned access at 0x{:016X} (required alignment: {})",
                    addr, alignment
                )
            }
            Self::StackOverflow => write!(f, "stack overflow: maximum call depth exceeded"),
            Self::StackUnderflow => write!(f, "stack underflow: no frames to pop"),
        }
    }
}

impl std::error::Error for MemoryError {}

// ---------------------------------------------------------------------------
// Memory region
// ---------------------------------------------------------------------------

/// A contiguous region of virtual memory.
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    /// Base virtual address of this region.
    base: u64,
    /// Backing storage.
    data: Vec<u8>,
    /// Whether this region is writable.
    writable: bool,
}

impl MemoryRegion {
    /// Create a new memory region.
    pub fn new(base: u64, data: Vec<u8>, writable: bool) -> Self {
        Self {
            base,
            data,
            writable,
        }
    }

    /// Length of the region in bytes.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether the region is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Virtual base address.
    pub fn base(&self) -> u64 {
        self.base
    }

    /// Whether writes are allowed.
    pub fn is_writable(&self) -> bool {
        self.writable
    }

    /// Read-only view of the backing data.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Mutable view of the backing data.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

// ---------------------------------------------------------------------------
// Region index (from high nibble)
// ---------------------------------------------------------------------------

/// Region identifier derived from the virtual address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegionId {
    Program,
    Stack,
    Heap,
    Input,
}

impl RegionId {
    fn from_addr(addr: u64) -> Option<Self> {
        match addr & REGION_INDEX_MASK {
            REGION_PROGRAM_BASE => Some(Self::Program),
            REGION_STACK_BASE => Some(Self::Stack),
            REGION_HEAP_BASE => Some(Self::Heap),
            REGION_INPUT_BASE => Some(Self::Input),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Memory map
// ---------------------------------------------------------------------------

/// Virtual memory map combining all four regions.
///
/// Provides typed load/store operations that translate virtual addresses
/// to the appropriate backing region and enforce access permissions.
#[derive(Debug, Clone)]
pub struct MemoryMap {
    /// Read-only program/rodata region.
    program: MemoryRegion,
    /// Read-write stack region.
    stack: MemoryRegion,
    /// Read-write heap region.
    heap: MemoryRegion,
    /// Read-write input region (serialized accounts).
    input: MemoryRegion,
    /// Current stack frame index (0-based).
    frame_index: usize,
    /// V1+ dynamic stack frames (downward growth) vs V0 fixed (upward growth).
    dynamic_frames: bool,
}

impl MemoryMap {
    /// Create a new memory map with the given region contents.
    ///
    /// - `program_data`: read-only bytecode and rodata
    /// - `stack_size`: total stack size in bytes
    /// - `heap_size`: heap size in bytes
    /// - `input_data`: serialized input accounts
    pub fn new(
        program_data: &[u8],
        stack_size: usize,
        heap_size: usize,
        input_data: Vec<u8>,
    ) -> Self {
        Self {
            program: MemoryRegion::new(REGION_PROGRAM_BASE, program_data.to_vec(), false),
            stack: MemoryRegion::new(REGION_STACK_BASE, vec![0u8; stack_size], true),
            heap: MemoryRegion::new(REGION_HEAP_BASE, vec![0u8; heap_size], true),
            input: MemoryRegion::new(REGION_INPUT_BASE, input_data, true),
            frame_index: 0,
            dynamic_frames: false,
        }
    }

    /// Set whether dynamic stack frames are enabled (V1+).
    pub fn set_dynamic_frames(&mut self, dynamic: bool) {
        self.dynamic_frames = dynamic;
    }

    /// Whether dynamic stack frames are enabled.
    pub fn has_dynamic_frames(&self) -> bool {
        self.dynamic_frames
    }

    /// Get the current stack frame pointer address.
    ///
    /// **V0 (dynamic_frames=false):** Stack grows upward from bottom.
    /// Initial fp = STACK_BASE + FRAME_SIZE. Each CALL increases fp by FRAME_SIZE.
    /// Matches Solana rbpf V0 behavior.
    ///
    /// **V1+ (dynamic_frames=true):** Stack grows downward from top.
    /// Initial fp = STACK_BASE + stack_size. Each CALL decreases fp by FRAME_SIZE.
    ///
    /// Programs always use negative offsets from r10: `[r10 - offset]`.
    pub fn frame_pointer(&self) -> u64 {
        if self.dynamic_frames {
            // V1+: downward from top
            REGION_STACK_BASE + self.stack.len() as u64
                - (self.frame_index as u64) * (STACK_FRAME_SIZE as u64)
        } else {
            // V0: upward from bottom
            REGION_STACK_BASE + ((self.frame_index + 1) as u64) * (STACK_FRAME_SIZE as u64)
        }
    }

    /// Push a new stack frame, returning the new frame pointer.
    ///
    /// Both V0 and V1+ advance by one frame slot per call.
    /// V0: fp increases (upward). V1+: fp decreases (downward).
    pub fn push_frame(&mut self) -> Result<u64, MemoryError> {
        if self.frame_index + 1 >= self.max_frames() {
            return Err(MemoryError::StackOverflow);
        }
        self.frame_index += 1;
        Ok(self.frame_pointer())
    }

    /// Pop the current stack frame, returning the restored frame pointer.
    pub fn pop_frame(&mut self) -> Result<u64, MemoryError> {
        if self.frame_index < 1 {
            return Err(MemoryError::StackUnderflow);
        }
        self.frame_index -= 1;
        Ok(self.frame_pointer())
    }

    /// Maximum number of frame slots based on total stack size.
    fn max_frames(&self) -> usize {
        self.stack.len() / STACK_FRAME_SIZE
    }

    /// Current frame depth (0 = initial frame).
    pub fn frame_depth(&self) -> usize {
        self.frame_index
    }

    // -----------------------------------------------------------------------
    // Load operations
    // -----------------------------------------------------------------------

    /// Load a single byte from a virtual address.
    pub fn load8(&self, addr: u64) -> Result<u64, MemoryError> {
        let (region, offset) = self.resolve_read(addr, 1)?;
        Ok(region.data[offset] as u64)
    }

    /// Load a 16-bit value (little-endian) from a virtual address.
    pub fn load16(&self, addr: u64) -> Result<u64, MemoryError> {
        let (region, offset) = self.resolve_read(addr, 2)?;
        let bytes: [u8; 2] = region.data[offset..offset + 2]
            .try_into()
            .expect("2-byte slice");
        Ok(u16::from_le_bytes(bytes) as u64)
    }

    /// Load a 32-bit value (little-endian) from a virtual address.
    pub fn load32(&self, addr: u64) -> Result<u64, MemoryError> {
        let (region, offset) = self.resolve_read(addr, 4)?;
        let bytes: [u8; 4] = region.data[offset..offset + 4]
            .try_into()
            .expect("4-byte slice");
        Ok(u32::from_le_bytes(bytes) as u64)
    }

    /// Load a 64-bit value (little-endian) from a virtual address.
    pub fn load64(&self, addr: u64) -> Result<u64, MemoryError> {
        let (region, offset) = self.resolve_read(addr, 8)?;
        let bytes: [u8; 8] = region.data[offset..offset + 8]
            .try_into()
            .expect("8-byte slice");
        Ok(u64::from_le_bytes(bytes))
    }

    // -----------------------------------------------------------------------
    // Store operations
    // -----------------------------------------------------------------------

    /// Store a single byte to a virtual address.
    pub fn store8(&mut self, addr: u64, value: u64) -> Result<(), MemoryError> {
        let (region, offset) = self.resolve_write(addr, 1)?;
        region.data[offset] = value as u8;
        Ok(())
    }

    /// Store a 16-bit value (little-endian) to a virtual address.
    pub fn store16(&mut self, addr: u64, value: u64) -> Result<(), MemoryError> {
        let (region, offset) = self.resolve_write(addr, 2)?;
        region.data[offset..offset + 2].copy_from_slice(&(value as u16).to_le_bytes());
        Ok(())
    }

    /// Store a 32-bit value (little-endian) to a virtual address.
    pub fn store32(&mut self, addr: u64, value: u64) -> Result<(), MemoryError> {
        let (region, offset) = self.resolve_write(addr, 4)?;
        region.data[offset..offset + 4].copy_from_slice(&(value as u32).to_le_bytes());
        Ok(())
    }

    /// Store a 64-bit value (little-endian) to a virtual address.
    pub fn store64(&mut self, addr: u64, value: u64) -> Result<(), MemoryError> {
        let (region, offset) = self.resolve_write(addr, 8)?;
        region.data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Bulk memory operations
    // -----------------------------------------------------------------------

    /// Read a contiguous byte slice from virtual memory.
    pub fn read_slice(&self, addr: u64, len: usize) -> Result<Vec<u8>, MemoryError> {
        let (region, offset) = self.resolve_read(addr, len)?;
        Ok(region.data[offset..offset + len].to_vec())
    }

    /// Write a byte slice to virtual memory.
    pub fn write_slice(&mut self, addr: u64, data: &[u8]) -> Result<(), MemoryError> {
        let (region, offset) = self.resolve_write(addr, data.len())?;
        region.data[offset..offset + data.len()].copy_from_slice(data);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Slice translation (zero-copy access for syscalls)
    // -----------------------------------------------------------------------

    /// Translate a virtual address range to a read-only byte slice.
    ///
    /// Returns a direct reference into the backing memory, avoiding copies.
    /// Used by syscall handlers to read program data efficiently.
    pub fn translate_slice(&self, addr: u64, len: usize) -> Result<&[u8], MemoryError> {
        if len == 0 {
            return Ok(&[]);
        }
        let (region, offset) = self.resolve_read(addr, len)?;
        Ok(&region.data[offset..offset + len])
    }

    /// Translate a virtual address range to a mutable byte slice.
    ///
    /// Returns a direct mutable reference into the backing memory.
    /// Used by syscall handlers to write results back efficiently.
    pub fn translate_slice_mut(&mut self, addr: u64, len: usize) -> Result<&mut [u8], MemoryError> {
        if len == 0 {
            return Ok(&mut []);
        }
        let (region, offset) = self.resolve_write(addr, len)?;
        Ok(&mut region.data[offset..offset + len])
    }

    /// Translate a virtual address to a reference to a typed value.
    ///
    /// Checks alignment to `align_of::<T>()` and bounds.
    pub fn translate_type<T: Copy>(&self, addr: u64) -> Result<&T, MemoryError> {
        let size = std::mem::size_of::<T>();
        let align = std::mem::align_of::<T>();
        let offset = (addr & REGION_OFFSET_MASK) as usize;

        if align > 1 && !offset.is_multiple_of(align) {
            return Err(MemoryError::UnalignedAccess {
                addr,
                alignment: align,
            });
        }

        let (region, offset) = self.resolve_read(addr, size)?;
        // SAFETY: bounds checked, alignment checked above
        let ptr = region.data[offset..offset + size].as_ptr() as *const T;
        Ok(unsafe { &*ptr })
    }

    /// Translate a virtual address to a mutable reference to a typed value.
    pub fn translate_type_mut<T: Copy>(&mut self, addr: u64) -> Result<&mut T, MemoryError> {
        let size = std::mem::size_of::<T>();
        let align = std::mem::align_of::<T>();
        let offset = (addr & REGION_OFFSET_MASK) as usize;

        if align > 1 && !offset.is_multiple_of(align) {
            return Err(MemoryError::UnalignedAccess {
                addr,
                alignment: align,
            });
        }

        let (region, offset) = self.resolve_write(addr, size)?;
        let ptr = region.data[offset..offset + size].as_mut_ptr() as *mut T;
        Ok(unsafe { &mut *ptr })
    }

    // -----------------------------------------------------------------------
    // Region access
    // -----------------------------------------------------------------------

    /// Get a reference to the input region data (for reading accounts back).
    pub fn input_data(&self) -> &[u8] {
        &self.input.data
    }

    /// Get a mutable reference to the heap region.
    pub fn heap_mut(&mut self) -> &mut MemoryRegion {
        &mut self.heap
    }

    /// Get the heap size.
    pub fn heap_size(&self) -> usize {
        self.heap.len()
    }

    /// Get the stack size.
    pub fn stack_size(&self) -> usize {
        self.stack.len()
    }

    // -----------------------------------------------------------------------
    // Address resolution (private)
    // -----------------------------------------------------------------------

    /// Resolve a virtual address for reading, returning the region and byte offset.
    fn resolve_read(&self, addr: u64, size: usize) -> Result<(&MemoryRegion, usize), MemoryError> {
        let region = self.region_for_addr(addr)?;
        let offset = (addr & REGION_OFFSET_MASK) as usize;

        if offset + size > region.data.len() {
            return Err(MemoryError::OutOfBounds {
                addr,
                size,
                region_len: region.data.len(),
            });
        }

        Ok((region, offset))
    }

    /// Resolve a virtual address for writing, returning the region and byte offset.
    fn resolve_write(
        &mut self,
        addr: u64,
        size: usize,
    ) -> Result<(&mut MemoryRegion, usize), MemoryError> {
        let region_id = RegionId::from_addr(addr).ok_or(MemoryError::UnmappedAddress { addr })?;
        let offset = (addr & REGION_OFFSET_MASK) as usize;

        let region = match region_id {
            RegionId::Program => &mut self.program,
            RegionId::Stack => &mut self.stack,
            RegionId::Heap => &mut self.heap,
            RegionId::Input => &mut self.input,
        };

        if !region.writable {
            return Err(MemoryError::ReadOnlyRegion { addr });
        }

        if offset + size > region.data.len() {
            return Err(MemoryError::OutOfBounds {
                addr,
                size,
                region_len: region.data.len(),
            });
        }

        Ok((region, offset))
    }

    /// Get the region for a virtual address.
    fn region_for_addr(&self, addr: u64) -> Result<&MemoryRegion, MemoryError> {
        match RegionId::from_addr(addr) {
            Some(RegionId::Program) => Ok(&self.program),
            Some(RegionId::Stack) => Ok(&self.stack),
            Some(RegionId::Heap) => Ok(&self.heap),
            Some(RegionId::Input) => Ok(&self.input),
            None => Err(MemoryError::UnmappedAddress { addr }),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_map() -> MemoryMap {
        let program = vec![0xB7, 0x01, 0x00, 0x00, 42, 0, 0, 0]; // mov64 r1, 42
        let input = vec![1, 2, 3, 4, 5, 6, 7, 8];
        MemoryMap::new(&program, 4096, 1024, input)
    }

    #[test]
    fn program_region_is_read_only() {
        let mut map = make_map();
        let result = map.store8(REGION_PROGRAM_BASE, 0xFF);
        assert!(matches!(result, Err(MemoryError::ReadOnlyRegion { .. })));
    }

    #[test]
    fn read_program_data() {
        let map = make_map();
        let val = map.load8(REGION_PROGRAM_BASE).unwrap();
        assert_eq!(val, 0xB7);
        let val = map.load8(REGION_PROGRAM_BASE + 4).unwrap();
        assert_eq!(val, 42);
    }

    #[test]
    fn stack_read_write_byte() {
        let mut map = make_map();
        map.store8(REGION_STACK_BASE, 0xAB).unwrap();
        assert_eq!(map.load8(REGION_STACK_BASE).unwrap(), 0xAB);
    }

    #[test]
    fn stack_read_write_16() {
        let mut map = make_map();
        map.store16(REGION_STACK_BASE, 0x1234).unwrap();
        assert_eq!(map.load16(REGION_STACK_BASE).unwrap(), 0x1234);
    }

    #[test]
    fn stack_read_write_32() {
        let mut map = make_map();
        map.store32(REGION_STACK_BASE, 0xDEADBEEF).unwrap();
        assert_eq!(map.load32(REGION_STACK_BASE).unwrap(), 0xDEADBEEF);
    }

    #[test]
    fn stack_read_write_64() {
        let mut map = make_map();
        map.store64(REGION_STACK_BASE, 0x0102030405060708).unwrap();
        assert_eq!(map.load64(REGION_STACK_BASE).unwrap(), 0x0102030405060708);
    }

    #[test]
    fn heap_read_write() {
        let mut map = make_map();
        map.store32(REGION_HEAP_BASE + 100, 999).unwrap();
        assert_eq!(map.load32(REGION_HEAP_BASE + 100).unwrap(), 999);
    }

    #[test]
    fn input_read() {
        let map = make_map();
        let val = map.load8(REGION_INPUT_BASE).unwrap();
        assert_eq!(val, 1);
        let val = map.load8(REGION_INPUT_BASE + 7).unwrap();
        assert_eq!(val, 8);
    }

    #[test]
    fn input_write() {
        let mut map = make_map();
        map.store8(REGION_INPUT_BASE + 3, 0xFF).unwrap();
        assert_eq!(map.load8(REGION_INPUT_BASE + 3).unwrap(), 0xFF);
    }

    #[test]
    fn unmapped_address() {
        let map = make_map();
        let result = map.load8(0x5_0000_0000);
        assert!(matches!(result, Err(MemoryError::UnmappedAddress { .. })));
    }

    #[test]
    fn out_of_bounds_read() {
        let map = make_map();
        // Program is 8 bytes, reading at offset 7 with size 4 should fail
        let result = map.load32(REGION_PROGRAM_BASE + 7);
        assert!(matches!(result, Err(MemoryError::OutOfBounds { .. })));
    }

    #[test]
    fn out_of_bounds_write() {
        let mut map = make_map();
        // Stack is 4096 bytes, writing at offset 4095 with size 2 should fail
        let result = map.store16(REGION_STACK_BASE + 4095, 0);
        assert!(matches!(result, Err(MemoryError::OutOfBounds { .. })));
    }

    #[test]
    fn frame_pointer_initial() {
        let map = make_map();
        // Initial frame index is 0, so FP = base + 1 * frame_size
        assert_eq!(
            map.frame_pointer(),
            REGION_STACK_BASE + STACK_FRAME_SIZE as u64
        );
    }

    #[test]
    fn push_pop_frames_v0_upward() {
        // V0 fixed frames: upward growth, 1 frame per push
        let mut map = MemoryMap::new(&[], 256 * 1024, 1024, vec![]);
        // dynamic_frames=false (default) → V0 upward
        assert_eq!(map.frame_depth(), 0);
        // Initial fp = STACK_BASE + 1 * FRAME_SIZE
        assert_eq!(
            map.frame_pointer(),
            REGION_STACK_BASE + STACK_FRAME_SIZE as u64
        );

        let fp1 = map.push_frame().unwrap();
        assert_eq!(map.frame_depth(), 1);
        assert_eq!(fp1, REGION_STACK_BASE + 2 * STACK_FRAME_SIZE as u64);

        let fp2 = map.push_frame().unwrap();
        assert_eq!(map.frame_depth(), 2);
        assert_eq!(fp2, REGION_STACK_BASE + 3 * STACK_FRAME_SIZE as u64);

        let fp_after_pop = map.pop_frame().unwrap();
        assert_eq!(map.frame_depth(), 1);
        assert_eq!(fp_after_pop, fp1);
    }

    #[test]
    fn push_pop_frames_v1_downward() {
        // V1+ dynamic frames: downward growth
        let stack_size = 256 * 1024;
        let mut map = MemoryMap::new(&[], stack_size, 1024, vec![]);
        map.set_dynamic_frames(true);
        assert_eq!(map.frame_depth(), 0);
        // Initial fp = STACK_BASE + stack_size
        assert_eq!(map.frame_pointer(), REGION_STACK_BASE + stack_size as u64);

        let fp1 = map.push_frame().unwrap();
        assert_eq!(map.frame_depth(), 1);
        // fp decreases: STACK_BASE + stack_size - 1 * FRAME_SIZE
        assert_eq!(
            fp1,
            REGION_STACK_BASE + stack_size as u64 - STACK_FRAME_SIZE as u64
        );

        let fp2 = map.push_frame().unwrap();
        assert_eq!(map.frame_depth(), 2);
        assert_eq!(
            fp2,
            REGION_STACK_BASE + stack_size as u64 - 2 * STACK_FRAME_SIZE as u64
        );

        let fp_after_pop = map.pop_frame().unwrap();
        assert_eq!(map.frame_depth(), 1);
        assert_eq!(fp_after_pop, fp1);
    }

    #[test]
    fn stack_overflow() {
        let mut map = MemoryMap::new(&[], MAX_CALL_DEPTH * STACK_FRAME_SIZE, 1024, vec![]);
        for _ in 0..MAX_CALL_DEPTH - 1 {
            map.push_frame().unwrap();
        }
        let result = map.push_frame();
        assert!(matches!(result, Err(MemoryError::StackOverflow)));
    }

    #[test]
    fn stack_underflow() {
        let mut map = make_map();
        let result = map.pop_frame();
        assert!(matches!(result, Err(MemoryError::StackUnderflow)));
    }

    #[test]
    fn read_write_slice() {
        let mut map = make_map();
        let data = vec![10, 20, 30, 40, 50];
        map.write_slice(REGION_HEAP_BASE, &data).unwrap();
        let read_back = map.read_slice(REGION_HEAP_BASE, 5).unwrap();
        assert_eq!(read_back, data);
    }

    #[test]
    fn input_data_accessor() {
        let map = make_map();
        let input = map.input_data();
        assert_eq!(input, &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    // -------------------------------------------------------------------
    // Null pointer and unmapped region tests
    // -------------------------------------------------------------------

    #[test]
    fn null_pointer_read_fails() {
        let map = make_map();
        let result = map.load8(0x0);
        assert!(matches!(
            result,
            Err(MemoryError::UnmappedAddress { addr: 0 })
        ));
    }

    #[test]
    fn null_pointer_write_fails() {
        let mut map = make_map();
        let result = map.store8(0x0, 42);
        assert!(matches!(
            result,
            Err(MemoryError::UnmappedAddress { addr: 0 })
        ));
    }

    #[test]
    fn region_5_unmapped() {
        let map = make_map();
        let result = map.load8(0x5_0000_0000);
        assert!(matches!(result, Err(MemoryError::UnmappedAddress { .. })));
    }

    #[test]
    fn region_f_unmapped() {
        let map = make_map();
        let result = map.load8(0xF_0000_0000);
        assert!(matches!(result, Err(MemoryError::UnmappedAddress { .. })));
    }

    // -------------------------------------------------------------------
    // translate_slice tests
    // -------------------------------------------------------------------

    #[test]
    fn translate_slice_read_program() {
        let map = make_map();
        let slice = map.translate_slice(REGION_PROGRAM_BASE, 4).unwrap();
        assert_eq!(slice, &[0xB7, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn translate_slice_zero_length() {
        let map = make_map();
        let slice = map.translate_slice(REGION_PROGRAM_BASE, 0).unwrap();
        assert!(slice.is_empty());
    }

    #[test]
    fn translate_slice_full_input() {
        let map = make_map();
        let slice = map.translate_slice(REGION_INPUT_BASE, 8).unwrap();
        assert_eq!(slice, &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn translate_slice_out_of_bounds() {
        let map = make_map();
        let result = map.translate_slice(REGION_PROGRAM_BASE, 100);
        assert!(matches!(result, Err(MemoryError::OutOfBounds { .. })));
    }

    #[test]
    fn translate_slice_unmapped() {
        let map = make_map();
        let result = map.translate_slice(0x0, 4);
        assert!(matches!(result, Err(MemoryError::UnmappedAddress { .. })));
    }

    #[test]
    fn translate_slice_mut_heap() {
        let mut map = make_map();
        let slice = map.translate_slice_mut(REGION_HEAP_BASE, 4).unwrap();
        slice.copy_from_slice(&[10, 20, 30, 40]);
        assert_eq!(map.load8(REGION_HEAP_BASE).unwrap(), 10);
        assert_eq!(map.load8(REGION_HEAP_BASE + 3).unwrap(), 40);
    }

    #[test]
    fn translate_slice_mut_zero_length() {
        let mut map = make_map();
        let slice = map.translate_slice_mut(REGION_HEAP_BASE, 0).unwrap();
        assert!(slice.is_empty());
    }

    #[test]
    fn translate_slice_mut_read_only_fails() {
        let mut map = make_map();
        let result = map.translate_slice_mut(REGION_PROGRAM_BASE, 4);
        assert!(matches!(result, Err(MemoryError::ReadOnlyRegion { .. })));
    }

    // -------------------------------------------------------------------
    // translate_type tests
    // -------------------------------------------------------------------

    #[test]
    fn translate_type_u32_from_input() {
        let map = make_map();
        // Input region has [1, 2, 3, 4, 5, 6, 7, 8]
        let val: &u32 = map.translate_type::<u32>(REGION_INPUT_BASE).unwrap();
        assert_eq!(*val, u32::from_le_bytes([1, 2, 3, 4]));
    }

    #[test]
    fn translate_type_u64_from_input() {
        let map = make_map();
        let val: &u64 = map.translate_type::<u64>(REGION_INPUT_BASE).unwrap();
        assert_eq!(*val, u64::from_le_bytes([1, 2, 3, 4, 5, 6, 7, 8]));
    }

    #[test]
    fn translate_type_unaligned_u32_fails() {
        let map = make_map();
        // Offset 1 is not 4-byte aligned
        let result = map.translate_type::<u32>(REGION_INPUT_BASE + 1);
        assert!(matches!(
            result,
            Err(MemoryError::UnalignedAccess { alignment: 4, .. })
        ));
    }

    #[test]
    fn translate_type_unaligned_u64_fails() {
        let map = make_map();
        // Offset 4 is 4-byte aligned but NOT 8-byte aligned
        let result = map.translate_type::<u64>(REGION_INPUT_BASE + 4);
        assert!(matches!(
            result,
            Err(MemoryError::UnalignedAccess { alignment: 8, .. })
        ));
    }

    #[test]
    fn translate_type_u8_no_alignment_required() {
        let map = make_map();
        // u8 has alignment 1, so any address works
        let val = map.translate_type::<u8>(REGION_INPUT_BASE + 3).unwrap();
        assert_eq!(*val, 4);
    }

    #[test]
    fn translate_type_out_of_bounds() {
        let map = make_map();
        // Input is 8 bytes, reading u64 at offset 4 goes out of bounds
        let result = map.translate_type::<u64>(REGION_INPUT_BASE + 8);
        assert!(matches!(result, Err(MemoryError::OutOfBounds { .. })));
    }

    #[test]
    fn translate_type_mut_u32() {
        let mut map = make_map();
        // Write to heap (writable, starts at 0)
        map.store32(REGION_HEAP_BASE, 0).unwrap();
        let val: &mut u32 = map.translate_type_mut::<u32>(REGION_HEAP_BASE).unwrap();
        *val = 0xCAFEBABE;
        assert_eq!(map.load32(REGION_HEAP_BASE).unwrap(), 0xCAFEBABE);
    }

    #[test]
    fn translate_type_mut_read_only_fails() {
        let mut map = make_map();
        let result = map.translate_type_mut::<u32>(REGION_PROGRAM_BASE);
        assert!(matches!(result, Err(MemoryError::ReadOnlyRegion { .. })));
    }

    #[test]
    fn translate_type_mut_unaligned_fails() {
        let mut map = make_map();
        let result = map.translate_type_mut::<u32>(REGION_HEAP_BASE + 1);
        assert!(matches!(
            result,
            Err(MemoryError::UnalignedAccess { alignment: 4, .. })
        ));
    }
}
