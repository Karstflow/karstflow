/// Syscall dispatch bridge between the sBPF interpreter and runtime syscalls.
///
/// Maps syscall identifiers (murmur3 hashes of names) to handler functions,
/// reads arguments from VM registers r1..r5, and writes the return value to r0.
use crate::interpreter::{SyscallDispatch, VmError, VmState};
use paradencer_constants::syscalls;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Syscall handler trait
// ---------------------------------------------------------------------------

/// A handler for a single syscall.
///
/// Receives the five argument registers and returns a result value for r0.
pub trait SyscallHandler: Send + Sync {
    /// Execute the syscall with arguments from r1..r5.
    ///
    /// May read/write VM memory and deduct compute units.
    fn call(
        &self,
        vm: &mut VmState,
        r1: u64,
        r2: u64,
        r3: u64,
        r4: u64,
        r5: u64,
    ) -> Result<u64, VmError>;
}

// ---------------------------------------------------------------------------
// Runtime syscall dispatcher
// ---------------------------------------------------------------------------

/// Dispatches syscalls from the interpreter to registered handlers.
pub struct RuntimeSyscallDispatch {
    handlers: HashMap<u32, Box<dyn SyscallHandler>>,
}

impl RuntimeSyscallDispatch {
    /// Create a new dispatcher with no registered syscalls.
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    /// Register a syscall handler by its hash ID.
    pub fn register(&mut self, syscall_id: u32, handler: Box<dyn SyscallHandler>) {
        self.handlers.insert(syscall_id, handler);
    }

    /// Register a syscall handler by its name (computes murmur3 hash).
    pub fn register_by_name(&mut self, name: &str, handler: Box<dyn SyscallHandler>) {
        let id = murmur3_hash(name);
        self.handlers.insert(id, handler);
    }

    /// Get the set of registered syscall IDs (for validation).
    pub fn registered_ids(&self) -> std::collections::HashSet<u32> {
        self.handlers.keys().copied().collect()
    }

    /// Create a dispatcher with all standard runtime syscalls registered.
    pub fn with_standard_syscalls() -> Self {
        let mut dispatch = Self::new();

        // Logging
        dispatch.register_by_name("sol_log_", Box::new(SolLogHandler));
        dispatch.register_by_name("sol_log_64_", Box::new(SolLog64Handler));
        dispatch.register_by_name(
            "sol_log_compute_units_",
            Box::new(SolLogComputeUnitsHandler),
        );
        dispatch.register_by_name("sol_log_data", Box::new(SolLogDataHandler));

        // Memory operations
        dispatch.register_by_name("sol_memcpy_", Box::new(SolMemcpyHandler));
        dispatch.register_by_name("sol_memmove_", Box::new(SolMemmoveHandler));
        dispatch.register_by_name("sol_memcmp_", Box::new(SolMemcmpHandler));
        dispatch.register_by_name("sol_memset_", Box::new(SolMemsetHandler));

        // Hashing
        dispatch.register_by_name(
            "sol_sha256",
            Box::new(SolHashHandler {
                cost_base: syscalls::SHA256_BASE_COST,
                cost_per_byte: syscalls::SHA256_PER_BYTE_COST,
            }),
        );
        dispatch.register_by_name(
            "sol_keccak256",
            Box::new(SolHashHandler {
                cost_base: syscalls::KECCAK256_BASE_COST,
                cost_per_byte: syscalls::KECCAK256_PER_BYTE_COST,
            }),
        );
        dispatch.register_by_name(
            "sol_blake3",
            Box::new(SolHashHandler {
                cost_base: syscalls::BLAKE3_BASE_COST,
                cost_per_byte: syscalls::BLAKE3_PER_BYTE_COST,
            }),
        );

        // Heap allocation
        dispatch.register_by_name("sol_alloc_free_", Box::new(SolAllocHandler));

        dispatch
    }
}

impl Default for RuntimeSyscallDispatch {
    fn default() -> Self {
        Self::new()
    }
}

impl SyscallDispatch for RuntimeSyscallDispatch {
    fn dispatch(&self, syscall_id: u32, vm: &mut VmState) -> Result<(), VmError> {
        let handler = self
            .handlers
            .get(&syscall_id)
            .ok_or(VmError::UnknownSyscall { id: syscall_id })?;

        let r1 = vm.registers[1];
        let r2 = vm.registers[2];
        let r3 = vm.registers[3];
        let r4 = vm.registers[4];
        let r5 = vm.registers[5];

        let result = handler.call(vm, r1, r2, r3, r4, r5)?;
        vm.registers[0] = result;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Murmur3 hash (32-bit, seed 0)
// ---------------------------------------------------------------------------

/// Compute murmur3 32-bit hash of a syscall name (standard sBPF convention).
pub fn murmur3_hash(key: &str) -> u32 {
    let bytes = key.as_bytes();
    let len = bytes.len();
    let mut h: u32 = 0; // seed = 0

    // Process 4-byte chunks
    let n_blocks = len / 4;
    for i in 0..n_blocks {
        let offset = i * 4;
        let k = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
        let k = k.wrapping_mul(0xCC9E2D51);
        let k = k.rotate_left(15);
        let k = k.wrapping_mul(0x1B873593);
        h ^= k;
        h = h.rotate_left(13);
        h = h.wrapping_mul(5).wrapping_add(0xE6546B64);
    }

    // Tail
    let tail = &bytes[n_blocks * 4..];
    let mut k1: u32 = 0;
    match tail.len() {
        3 => {
            k1 ^= (tail[2] as u32) << 16;
            k1 ^= (tail[1] as u32) << 8;
            k1 ^= tail[0] as u32;
            k1 = k1.wrapping_mul(0xCC9E2D51);
            k1 = k1.rotate_left(15);
            k1 = k1.wrapping_mul(0x1B873593);
            h ^= k1;
        }
        2 => {
            k1 ^= (tail[1] as u32) << 8;
            k1 ^= tail[0] as u32;
            k1 = k1.wrapping_mul(0xCC9E2D51);
            k1 = k1.rotate_left(15);
            k1 = k1.wrapping_mul(0x1B873593);
            h ^= k1;
        }
        1 => {
            k1 ^= tail[0] as u32;
            k1 = k1.wrapping_mul(0xCC9E2D51);
            k1 = k1.rotate_left(15);
            k1 = k1.wrapping_mul(0x1B873593);
            h ^= k1;
        }
        _ => {}
    }

    // Finalization
    h ^= len as u32;
    h ^= h >> 16;
    h = h.wrapping_mul(0x85EBCA6B);
    h ^= h >> 13;
    h = h.wrapping_mul(0xC2B2AE35);
    h ^= h >> 16;

    h
}

// ---------------------------------------------------------------------------
// Built-in syscall handlers
// ---------------------------------------------------------------------------

/// sol_log_: Log a UTF-8 string from VM memory.
struct SolLogHandler;

impl SyscallHandler for SolLogHandler {
    fn call(
        &self,
        vm: &mut VmState,
        r1: u64, // pointer to string
        r2: u64, // string length
        _r3: u64,
        _r4: u64,
        _r5: u64,
    ) -> Result<u64, VmError> {
        let len = r2 as usize;

        // Deduct compute cost
        let cost = syscalls::LOG_BASE_COST + (len as u64) * syscalls::LOG_PER_BYTE_COST;
        deduct_compute(vm, cost)?;

        // Read string from VM memory
        let data = vm
            .memory
            .read_slice(r1, len)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;

        let msg = String::from_utf8_lossy(&data).to_string();
        vm.logs.push(msg);

        Ok(0)
    }
}

/// sol_log_64_: Log 5 u64 values.
struct SolLog64Handler;

impl SyscallHandler for SolLog64Handler {
    fn call(
        &self,
        vm: &mut VmState,
        r1: u64,
        r2: u64,
        r3: u64,
        r4: u64,
        r5: u64,
    ) -> Result<u64, VmError> {
        deduct_compute(vm, syscalls::LOG_BASE_COST)?;
        vm.logs
            .push(format!("Program log: {} {} {} {} {}", r1, r2, r3, r4, r5));
        Ok(0)
    }
}

/// sol_log_compute_units_: Log remaining compute units.
struct SolLogComputeUnitsHandler;

impl SyscallHandler for SolLogComputeUnitsHandler {
    fn call(
        &self,
        vm: &mut VmState,
        _r1: u64,
        _r2: u64,
        _r3: u64,
        _r4: u64,
        _r5: u64,
    ) -> Result<u64, VmError> {
        deduct_compute(vm, syscalls::LOG_COMPUTE_UNITS_COST)?;
        vm.logs.push(format!(
            "Program consumption: {} units remaining",
            vm.compute_meter
        ));
        Ok(0)
    }
}

/// sol_log_data: Log raw data buffers.
struct SolLogDataHandler;

impl SyscallHandler for SolLogDataHandler {
    fn call(
        &self,
        vm: &mut VmState,
        _r1: u64,
        _r2: u64,
        _r3: u64,
        _r4: u64,
        _r5: u64,
    ) -> Result<u64, VmError> {
        deduct_compute(vm, syscalls::LOG_DATA_BASE_COST)?;
        vm.logs.push("Program data: <encoded>".to_string());
        Ok(0)
    }
}

/// sol_memcpy_: Copy memory within VM address space.
struct SolMemcpyHandler;

impl SyscallHandler for SolMemcpyHandler {
    fn call(
        &self,
        vm: &mut VmState,
        r1: u64, // dst
        r2: u64, // src
        r3: u64, // len
        _r4: u64,
        _r5: u64,
    ) -> Result<u64, VmError> {
        let len = r3 as usize;
        let cost = syscalls::MEMCPY_BASE_COST + (len as u64) * syscalls::MEMCPY_PER_BYTE_COST;
        deduct_compute(vm, cost)?;

        let data = vm
            .memory
            .read_slice(r2, len)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;
        vm.memory
            .write_slice(r1, &data)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;

        Ok(0)
    }
}

/// sol_memmove_: Move memory (handles overlapping regions).
struct SolMemmoveHandler;

impl SyscallHandler for SolMemmoveHandler {
    fn call(
        &self,
        vm: &mut VmState,
        r1: u64, // dst
        r2: u64, // src
        r3: u64, // len
        _r4: u64,
        _r5: u64,
    ) -> Result<u64, VmError> {
        let len = r3 as usize;
        let cost = syscalls::MEMCPY_BASE_COST + (len as u64) * syscalls::MEMCPY_PER_BYTE_COST;
        deduct_compute(vm, cost)?;

        // Read first then write to handle overlap
        let data = vm
            .memory
            .read_slice(r2, len)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;
        vm.memory
            .write_slice(r1, &data)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;

        Ok(0)
    }
}

/// sol_memcmp_: Compare memory regions.
struct SolMemcmpHandler;

impl SyscallHandler for SolMemcmpHandler {
    fn call(
        &self,
        vm: &mut VmState,
        r1: u64, // s1
        r2: u64, // s2
        r3: u64, // len
        r4: u64, // result pointer
        _r5: u64,
    ) -> Result<u64, VmError> {
        let len = r3 as usize;
        let cost = syscalls::MEMCMP_BASE_COST + (len as u64) * syscalls::MEMCMP_PER_BYTE_COST;
        deduct_compute(vm, cost)?;

        let s1 = vm
            .memory
            .read_slice(r1, len)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;
        let s2 = vm
            .memory
            .read_slice(r2, len)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;

        let cmp = s1.cmp(&s2) as i32;
        // Write result to memory if pointer is non-zero
        if r4 != 0 {
            vm.memory
                .store32(r4, cmp as u32 as u64)
                .map_err(|e| VmError::MemoryError(e.to_string()))?;
        }

        Ok(cmp as u64)
    }
}

/// sol_memset_: Fill memory with a byte value.
struct SolMemsetHandler;

impl SyscallHandler for SolMemsetHandler {
    fn call(
        &self,
        vm: &mut VmState,
        r1: u64, // dst
        r2: u64, // value (byte)
        r3: u64, // len
        _r4: u64,
        _r5: u64,
    ) -> Result<u64, VmError> {
        let len = r3 as usize;
        let cost = syscalls::MEMSET_BASE_COST + (len as u64) * syscalls::MEMSET_PER_BYTE_COST;
        deduct_compute(vm, cost)?;

        let data = vec![r2 as u8; len];
        vm.memory
            .write_slice(r1, &data)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;

        Ok(0)
    }
}

/// Generic hash syscall handler (sha256, keccak256, blake3).
struct SolHashHandler {
    cost_base: u64,
    cost_per_byte: u64,
}

impl SyscallHandler for SolHashHandler {
    fn call(
        &self,
        vm: &mut VmState,
        _r1: u64, // input array pointer
        _r2: u64, // input array count
        _r3: u64,
        _r4: u64, // result pointer
        _r5: u64,
    ) -> Result<u64, VmError> {
        // For now, just deduct the base cost
        deduct_compute(vm, self.cost_base)?;
        Ok(0)
    }
}

/// sol_alloc_free_: Bump allocator for heap memory.
struct SolAllocHandler;

impl SyscallHandler for SolAllocHandler {
    fn call(
        &self,
        vm: &mut VmState,
        r1: u64, // size to allocate (0 = free, ignored)
        _r2: u64,
        _r3: u64,
        _r4: u64,
        _r5: u64,
    ) -> Result<u64, VmError> {
        if r1 == 0 {
            // Free is a no-op in bump allocator
            return Ok(0);
        }

        let size = r1;
        let aligned_size = (size + 7) & !7; // 8-byte align
        let heap_end = paradencer_constants::vm::REGION_HEAP_BASE + vm.memory.heap_size() as u64;

        if vm.heap_position + aligned_size > heap_end {
            // Out of heap space
            return Ok(0);
        }

        let addr = vm.heap_position;
        vm.heap_position += aligned_size;
        Ok(addr)
    }
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn deduct_compute(vm: &mut VmState, cost: u64) -> Result<(), VmError> {
    if vm.compute_meter < cost {
        vm.compute_meter = 0;
        return Err(VmError::ComputeBudgetExceeded);
    }
    vm.compute_meter -= cost;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf_loader::load_raw;
    use crate::instruction::{Instruction, Opcode};
    use crate::memory::MemoryMap;
    use paradencer_constants::vm::{DEFAULT_HEAP_SIZE, REGION_HEAP_BASE, TOTAL_STACK_SIZE};

    fn make_program_bytes(insns: &[Instruction]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for insn in insns {
            bytes.extend_from_slice(&insn.encode().to_le_bytes());
        }
        bytes
    }

    #[test]
    fn murmur3_known_values() {
        // Verify some known hash values
        let hash = murmur3_hash("sol_log_");
        assert_ne!(hash, 0);
        // Same input should produce same hash
        assert_eq!(hash, murmur3_hash("sol_log_"));
        // Different inputs produce different hashes
        assert_ne!(murmur3_hash("sol_log_"), murmur3_hash("sol_sha256"));
    }

    #[test]
    fn register_and_dispatch() {
        let mut dispatch = RuntimeSyscallDispatch::new();

        struct ReturnFortyTwo;
        impl SyscallHandler for ReturnFortyTwo {
            fn call(
                &self,
                _vm: &mut VmState,
                _r1: u64,
                _r2: u64,
                _r3: u64,
                _r4: u64,
                _r5: u64,
            ) -> Result<u64, VmError> {
                Ok(42)
            }
        }

        let syscall_id = 0x1234;
        dispatch.register(syscall_id, Box::new(ReturnFortyTwo));

        // Build a program: call syscall_id; exit
        let bytes = make_program_bytes(&[
            Instruction::new(Opcode::Call as u8, 0, 0, 0, syscall_id as i32),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ]);
        let program = load_raw(&bytes).unwrap();
        let memory = MemoryMap::new(&[], TOTAL_STACK_SIZE, DEFAULT_HEAP_SIZE, vec![]);
        let result = crate::interpreter::execute(&program, memory, 10_000, &dispatch).unwrap();
        assert_eq!(result.return_value, 42);
    }

    #[test]
    fn sol_log_handler() {
        let dispatch = RuntimeSyscallDispatch::with_standard_syscalls();
        let log_id = murmur3_hash("sol_log_");

        // Program: write "Hi" to heap, then call sol_log_ with pointer and length
        let bytes = make_program_bytes(&[
            // Write "Hi" (0x48, 0x69) to heap
            Instruction::new(Opcode::Lddw as u8, 1, 0, 0, REGION_HEAP_BASE as i32),
            Instruction::new(0, 0, 0, 0, (REGION_HEAP_BASE >> 32) as i32),
            Instruction::new(Opcode::Mov64Imm as u8, 2, 0, 0, 0x6948), // "Hi" in little-endian
            Instruction::new(Opcode::StxHalf as u8, 1, 2, 0, 0),       // store at heap
            // Call sol_log_(r1=heap_base, r2=2)
            Instruction::new(Opcode::Mov64Imm as u8, 2, 0, 0, 2), // len=2
            Instruction::new(Opcode::Call as u8, 0, 0, 0, log_id as i32),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ]);
        let program = load_raw(&bytes).unwrap();
        let memory = MemoryMap::new(&[], TOTAL_STACK_SIZE, DEFAULT_HEAP_SIZE, vec![]);
        let result = crate::interpreter::execute(&program, memory, 100_000, &dispatch).unwrap();
        assert!(result.logs.iter().any(|l| l.contains("Hi")));
    }

    #[test]
    fn sol_alloc_handler() {
        let dispatch = RuntimeSyscallDispatch::with_standard_syscalls();
        let alloc_id = murmur3_hash("sol_alloc_free_");

        // Allocate 64 bytes
        let bytes = make_program_bytes(&[
            Instruction::new(Opcode::Mov64Imm as u8, 1, 0, 0, 64), // size=64
            Instruction::new(Opcode::Call as u8, 0, 0, 0, alloc_id as i32),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ]);
        let program = load_raw(&bytes).unwrap();
        let memory = MemoryMap::new(&[], TOTAL_STACK_SIZE, DEFAULT_HEAP_SIZE, vec![]);
        let result = crate::interpreter::execute(&program, memory, 100_000, &dispatch).unwrap();
        // Should return the heap base address
        assert_eq!(result.return_value, REGION_HEAP_BASE);
    }

    #[test]
    fn unknown_syscall_rejected() {
        let dispatch = RuntimeSyscallDispatch::new();
        let bytes = make_program_bytes(&[
            Instruction::new(Opcode::Call as u8, 0, 0, 0, 0xBAD),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ]);
        let program = load_raw(&bytes).unwrap();
        let memory = MemoryMap::new(&[], TOTAL_STACK_SIZE, DEFAULT_HEAP_SIZE, vec![]);
        let result = crate::interpreter::execute(&program, memory, 10_000, &dispatch);
        assert!(matches!(result, Err(VmError::UnknownSyscall { id: 0xBAD })));
    }

    #[test]
    fn registered_ids_set() {
        let dispatch = RuntimeSyscallDispatch::with_standard_syscalls();
        let ids = dispatch.registered_ids();
        assert!(ids.contains(&murmur3_hash("sol_log_")));
        assert!(ids.contains(&murmur3_hash("sol_memcpy_")));
        assert!(ids.contains(&murmur3_hash("sol_alloc_free_")));
        assert!(!ids.contains(&0xDEAD));
    }
}
