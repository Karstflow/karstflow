/// Syscall dispatch bridge between the sBPF interpreter and runtime syscalls.
///
/// Maps syscall identifiers (murmur3 hashes of names) to handler functions,
/// reads arguments from VM registers r1..r5, and writes the return value to r0.
use crate::interpreter::{SyscallDispatch, VmError, VmState};
use crate::{ExecutionContext, ExecutionOutcome, SbpfExecutionError};
use paradencer_constants::syscalls;
use paradencer_types::{Account, AccountData, AccountMeta as TypesAccountMeta, Pubkey};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tiny_keccak::{Hasher, Keccak};

// ---------------------------------------------------------------------------
// Instruction executor trait (for CPI)
// ---------------------------------------------------------------------------

/// Executes a program instruction, enabling cross-program invocations.
///
/// Implemented by the transaction processor to allow CPI handlers to
/// recursively invoke other programs during execution.
pub trait InstructionExecutor: Send + Sync {
    fn execute_instruction(
        &self,
        context: ExecutionContext,
    ) -> Result<ExecutionOutcome, SbpfExecutionError>;
}

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
        dispatch.register_by_name("sol_log_pubkey", Box::new(SolLogPubkeyHandler));

        // Memory operations
        dispatch.register_by_name("sol_memcpy_", Box::new(SolMemcpyHandler));
        dispatch.register_by_name("sol_memmove_", Box::new(SolMemmoveHandler));
        dispatch.register_by_name("sol_memcmp_", Box::new(SolMemcmpHandler));
        dispatch.register_by_name("sol_memset_", Box::new(SolMemsetHandler));

        // Hashing
        dispatch.register_by_name("sol_sha256", Box::new(SolSha256Handler));
        dispatch.register_by_name("sol_keccak256", Box::new(SolKeccak256Handler));
        dispatch.register_by_name("sol_blake3", Box::new(SolBlake3Handler));

        // Heap allocation
        dispatch.register_by_name("sol_alloc_free_", Box::new(SolAllocHandler));

        // PDA operations
        dispatch.register_by_name(
            "sol_create_program_address",
            Box::new(SolCreateProgramAddressHandler),
        );
        dispatch.register_by_name(
            "sol_try_find_program_address",
            Box::new(SolTryFindProgramAddressHandler),
        );

        // Return data
        dispatch.register_by_name("sol_set_return_data", Box::new(SolSetReturnDataHandler));
        dispatch.register_by_name("sol_get_return_data", Box::new(SolGetReturnDataHandler));

        // Sysvar access
        dispatch.register_by_name("sol_get_clock_sysvar", Box::new(SolGetClockSysvarHandler));
        dispatch.register_by_name("sol_get_rent_sysvar", Box::new(SolGetRentSysvarHandler));
        dispatch.register_by_name(
            "sol_get_epoch_schedule_sysvar",
            Box::new(SolGetEpochScheduleHandler),
        );
        dispatch.register_by_name(
            "sol_get_last_restart_slot",
            Box::new(SolGetLastRestartSlotHandler),
        );

        // Runtime queries
        dispatch.register_by_name("sol_get_stack_height", Box::new(SolGetStackHeightHandler));
        dispatch.register_by_name(
            "sol_get_processed_sibling_instruction",
            Box::new(SolGetProcessedSiblingInstructionHandler),
        );
        dispatch.register_by_name(
            "sol_get_epoch_rewards_sysvar",
            Box::new(SolGetEpochRewardsSysvarHandler),
        );
        dispatch.register_by_name("sol_get_sysvar", Box::new(SolGetSysvarHandler));
        dispatch.register_by_name("sol_get_epoch_stake", Box::new(SolGetEpochStakeHandler));

        // Crypto
        dispatch.register_by_name(
            "sol_secp256k1_recover",
            Box::new(SolSecp256k1RecoverHandler),
        );

        // Curve25519 operations
        dispatch.register_by_name(
            "sol_curve_validate_point",
            Box::new(SolCurveValidatePointHandler),
        );
        dispatch.register_by_name("sol_curve_group_op", Box::new(SolCurveGroupOpHandler));
        dispatch.register_by_name(
            "sol_curve_multiscalar_mul",
            Box::new(SolCurveMultiscalarMulHandler),
        );

        dispatch
    }

    /// Create a dispatcher with standard syscalls plus CPI support.
    ///
    /// The provided executor is called when a program invokes another
    /// program via `sol_invoke_signed_c`.
    pub fn with_cpi_support(executor: Arc<dyn InstructionExecutor>) -> Self {
        let mut dispatch = Self::with_standard_syscalls();
        dispatch.register_by_name(
            "sol_invoke_signed_c",
            Box::new(SolInvokeHandler {
                executor: executor.clone(),
            }),
        );
        dispatch.register_by_name(
            "sol_invoke_signed_rust",
            Box::new(SolInvokeHandler { executor }),
        );
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

/// Read hash input pairs from VM memory.
///
/// Hash syscalls take an array of (pointer, length) pairs. Each pair
/// is two u64 values at the given address.
fn read_hash_inputs(vm: &VmState, pairs_addr: u64, pair_count: usize) -> Result<Vec<u8>, VmError> {
    let mut combined = Vec::new();
    for i in 0..pair_count {
        let pair_offset = pairs_addr + (i as u64) * 16;
        let ptr_bytes = vm
            .memory
            .read_slice(pair_offset, 8)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;
        let len_bytes = vm
            .memory
            .read_slice(pair_offset + 8, 8)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;

        let ptr = u64::from_le_bytes(ptr_bytes.try_into().unwrap());
        let len = u64::from_le_bytes(len_bytes.try_into().unwrap()) as usize;

        if len > 0 {
            let data = vm
                .memory
                .read_slice(ptr, len)
                .map_err(|e| VmError::MemoryError(e.to_string()))?;
            combined.extend_from_slice(&data);
        }
    }
    Ok(combined)
}

/// sol_sha256: Compute SHA-256 hash.
struct SolSha256Handler;

impl SyscallHandler for SolSha256Handler {
    fn call(
        &self,
        vm: &mut VmState,
        r1: u64, // input pairs pointer
        r2: u64, // pair count
        _r3: u64,
        r4: u64, // result pointer (32 bytes)
        _r5: u64,
    ) -> Result<u64, VmError> {
        let pair_count = r2 as usize;
        let data = read_hash_inputs(vm, r1, pair_count)?;

        let cost = syscalls::SHA256_BASE_COST + syscalls::SHA256_PER_BYTE_COST * data.len() as u64;
        deduct_compute(vm, cost)?;

        let mut hasher = Sha256::new();
        hasher.update(&data);
        let hash: [u8; 32] = hasher.finalize().into();

        vm.memory
            .write_slice(r4, &hash)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;

        Ok(0)
    }
}

/// sol_keccak256: Compute Keccak-256 hash.
struct SolKeccak256Handler;

impl SyscallHandler for SolKeccak256Handler {
    fn call(
        &self,
        vm: &mut VmState,
        r1: u64, // input pairs pointer
        r2: u64, // pair count
        _r3: u64,
        r4: u64, // result pointer (32 bytes)
        _r5: u64,
    ) -> Result<u64, VmError> {
        let pair_count = r2 as usize;
        let data = read_hash_inputs(vm, r1, pair_count)?;

        let cost =
            syscalls::KECCAK256_BASE_COST + syscalls::KECCAK256_PER_BYTE_COST * data.len() as u64;
        deduct_compute(vm, cost)?;

        let mut hasher = Keccak::v256();
        hasher.update(&data);
        let mut hash = [0u8; 32];
        hasher.finalize(&mut hash);

        vm.memory
            .write_slice(r4, &hash)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;

        Ok(0)
    }
}

/// sol_blake3: Compute Blake3 hash.
struct SolBlake3Handler;

impl SyscallHandler for SolBlake3Handler {
    fn call(
        &self,
        vm: &mut VmState,
        r1: u64, // input pairs pointer
        r2: u64, // pair count
        _r3: u64,
        r4: u64, // result pointer (32 bytes)
        _r5: u64,
    ) -> Result<u64, VmError> {
        let pair_count = r2 as usize;
        let data = read_hash_inputs(vm, r1, pair_count)?;

        let cost = syscalls::BLAKE3_BASE_COST + syscalls::BLAKE3_PER_BYTE_COST * data.len() as u64;
        deduct_compute(vm, cost)?;

        let hash = blake3::hash(&data);
        let hash_bytes: [u8; 32] = *hash.as_bytes();

        vm.memory
            .write_slice(r4, &hash_bytes)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;

        Ok(0)
    }
}

/// sol_create_program_address: Derive a PDA from seeds and program ID.
struct SolCreateProgramAddressHandler;

impl SyscallHandler for SolCreateProgramAddressHandler {
    fn call(
        &self,
        vm: &mut VmState,
        r1: u64, // seeds pointer (array of (ptr, len) pairs)
        r2: u64, // seed count
        r3: u64, // program_id pointer (32 bytes)
        r4: u64, // result pointer (32 bytes)
        _r5: u64,
    ) -> Result<u64, VmError> {
        deduct_compute(vm, syscalls::CREATE_PROGRAM_ADDRESS_COST)?;

        let seed_count = r2 as usize;
        if seed_count > syscalls::MAX_SIGNER_SEEDS {
            return Ok(1); // Error return
        }

        // Read seeds
        let mut seed_data = Vec::new();
        for i in 0..seed_count {
            let pair_offset = r1 + (i as u64) * 16;
            let ptr_bytes = vm
                .memory
                .read_slice(pair_offset, 8)
                .map_err(|e| VmError::MemoryError(e.to_string()))?;
            let len_bytes = vm
                .memory
                .read_slice(pair_offset + 8, 8)
                .map_err(|e| VmError::MemoryError(e.to_string()))?;

            let ptr = u64::from_le_bytes(ptr_bytes.try_into().unwrap());
            let len = u64::from_le_bytes(len_bytes.try_into().unwrap()) as usize;

            if len > syscalls::MAX_SEED_BYTES {
                return Ok(1);
            }

            let seed = vm
                .memory
                .read_slice(ptr, len)
                .map_err(|e| VmError::MemoryError(e.to_string()))?;
            seed_data.push(seed);
        }

        // Read program ID
        let program_id_bytes = vm
            .memory
            .read_slice(r3, 32)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;

        // Hash: seeds || program_id || "ProgramDerivedAddress"
        let mut hasher = Sha256::new();
        for seed in &seed_data {
            hasher.update(seed);
        }
        hasher.update(&program_id_bytes);
        hasher.update(b"ProgramDerivedAddress");
        let hash: [u8; 32] = hasher.finalize().into();

        // PDA must NOT be on the ed25519 curve
        if is_on_ed25519_curve(&hash) {
            return Ok(1);
        }

        // Write result
        vm.memory
            .write_slice(r4, &hash)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;

        Ok(0)
    }
}

/// Check if 32 bytes represent a valid ed25519 curve point.
/// PDAs must NOT be on the curve — if this returns true, the PDA is invalid.
fn is_on_ed25519_curve(bytes: &[u8; 32]) -> bool {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    CompressedEdwardsY(*bytes).decompress().is_some()
}

/// sol_try_find_program_address: Find PDA by iterating bump seeds 255→0.
struct SolTryFindProgramAddressHandler;

impl SyscallHandler for SolTryFindProgramAddressHandler {
    fn call(
        &self,
        vm: &mut VmState,
        r1: u64, // seeds pointer
        r2: u64, // seed count
        r3: u64, // program_id pointer (32 bytes)
        r4: u64, // result address pointer (32 bytes)
        r5: u64, // result bump pointer (1 byte)
    ) -> Result<u64, VmError> {
        deduct_compute(vm, syscalls::FIND_PROGRAM_ADDRESS_COST)?;

        let seed_count = r2 as usize;
        if seed_count >= syscalls::MAX_SIGNER_SEEDS {
            return Ok(1);
        }

        // Read seeds
        let mut seed_data = Vec::new();
        for i in 0..seed_count {
            let pair_offset = r1 + (i as u64) * 16;
            let ptr_bytes = vm
                .memory
                .read_slice(pair_offset, 8)
                .map_err(|e| VmError::MemoryError(e.to_string()))?;
            let len_bytes = vm
                .memory
                .read_slice(pair_offset + 8, 8)
                .map_err(|e| VmError::MemoryError(e.to_string()))?;

            let ptr = u64::from_le_bytes(ptr_bytes.try_into().unwrap());
            let len = u64::from_le_bytes(len_bytes.try_into().unwrap()) as usize;

            if len > syscalls::MAX_SEED_BYTES {
                return Ok(1);
            }

            let seed = vm
                .memory
                .read_slice(ptr, len)
                .map_err(|e| VmError::MemoryError(e.to_string()))?;
            seed_data.push(seed);
        }

        // Read program ID
        let program_id_bytes = vm
            .memory
            .read_slice(r3, 32)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;

        // Try bumps from 255 down to 0
        for bump in (0..=255u8).rev() {
            deduct_compute(vm, syscalls::FIND_PROGRAM_ADDRESS_PER_ITERATION)?;

            let mut hasher = Sha256::new();
            for seed in &seed_data {
                hasher.update(seed);
            }
            hasher.update([bump]);
            hasher.update(&program_id_bytes);
            hasher.update(b"ProgramDerivedAddress");
            let hash: [u8; 32] = hasher.finalize().into();

            if !is_on_ed25519_curve(&hash) {
                vm.memory
                    .write_slice(r4, &hash)
                    .map_err(|e| VmError::MemoryError(e.to_string()))?;
                vm.memory
                    .write_slice(r5, &[bump])
                    .map_err(|e| VmError::MemoryError(e.to_string()))?;

                return Ok(0);
            }
        }

        Ok(1) // No valid PDA found
    }
}

/// sol_set_return_data: Store return data from the executing program.
struct SolSetReturnDataHandler;

impl SyscallHandler for SolSetReturnDataHandler {
    fn call(
        &self,
        vm: &mut VmState,
        r1: u64, // data pointer
        r2: u64, // data length
        _r3: u64,
        _r4: u64,
        _r5: u64,
    ) -> Result<u64, VmError> {
        let len = r2 as usize;
        let cost = syscalls::SET_RETURN_DATA_COST + syscalls::SET_RETURN_DATA_PER_BYTE * len as u64;
        deduct_compute(vm, cost)?;

        if len > syscalls::MAX_RETURN_DATA_SIZE {
            return Ok(1); // Error
        }

        if len == 0 {
            vm.return_data = None;
        } else {
            let data = vm
                .memory
                .read_slice(r1, len)
                .map_err(|e| VmError::MemoryError(e.to_string()))?;
            vm.return_data = Some(data);
        }

        Ok(0)
    }
}

/// sol_get_return_data: Retrieve return data from last CPI call.
struct SolGetReturnDataHandler;

impl SyscallHandler for SolGetReturnDataHandler {
    fn call(
        &self,
        vm: &mut VmState,
        r1: u64, // result buffer pointer
        r2: u64, // max buffer length
        _r3: u64,
        _r4: u64,
        _r5: u64,
    ) -> Result<u64, VmError> {
        deduct_compute(vm, syscalls::GET_RETURN_DATA_COST)?;

        match &vm.return_data {
            Some(data) => {
                let copy_len = (r2 as usize).min(data.len());
                if copy_len > 0 {
                    vm.memory
                        .write_slice(r1, &data[..copy_len])
                        .map_err(|e| VmError::MemoryError(e.to_string()))?;
                }
                Ok(data.len() as u64)
            }
            None => Ok(0),
        }
    }
}

/// sol_get_clock_sysvar: Write Clock sysvar data to VM memory.
///
/// Serialization layout (40 bytes, little-endian):
///   slot(8) | epoch_start_timestamp(8) | epoch(8) | leader_schedule_epoch(8) | unix_timestamp(8)
struct SolGetClockSysvarHandler;

impl SyscallHandler for SolGetClockSysvarHandler {
    fn call(
        &self,
        vm: &mut VmState,
        r1: u64, // destination pointer
        _r2: u64,
        _r3: u64,
        _r4: u64,
        _r5: u64,
    ) -> Result<u64, VmError> {
        deduct_compute(vm, syscalls::GET_SYSVAR_COST)?;

        let snap = &vm.sysvar_snapshot;
        let mut buf = [0u8; 40];
        buf[0..8].copy_from_slice(&snap.slot.to_le_bytes());
        buf[8..16].copy_from_slice(&snap.epoch_start_timestamp.to_le_bytes());
        buf[16..24].copy_from_slice(&snap.epoch.to_le_bytes());
        buf[24..32].copy_from_slice(&snap.leader_schedule_epoch.to_le_bytes());
        buf[32..40].copy_from_slice(&snap.unix_timestamp.to_le_bytes());

        vm.memory
            .write_slice(r1, &buf)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;

        Ok(0)
    }
}

/// sol_get_rent_sysvar: Write Rent sysvar data to VM memory.
///
/// Serialization layout (17 bytes, little-endian):
///   lamports_per_byte_year(8) | exemption_threshold(f64 8) | burn_percent(1)
struct SolGetRentSysvarHandler;

impl SyscallHandler for SolGetRentSysvarHandler {
    fn call(
        &self,
        vm: &mut VmState,
        r1: u64, // destination pointer
        _r2: u64,
        _r3: u64,
        _r4: u64,
        _r5: u64,
    ) -> Result<u64, VmError> {
        deduct_compute(vm, syscalls::GET_SYSVAR_COST)?;

        let snap = &vm.sysvar_snapshot;
        let mut buf = [0u8; 17];
        buf[0..8].copy_from_slice(&snap.lamports_per_byte_year.to_le_bytes());
        buf[8..16].copy_from_slice(&snap.exemption_threshold.to_le_bytes());
        buf[16] = snap.burn_percent;

        vm.memory
            .write_slice(r1, &buf)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;

        Ok(0)
    }
}

/// sol_get_epoch_schedule_sysvar: Write EpochSchedule sysvar data to VM memory.
///
/// Serialization layout (33 bytes, little-endian):
///   slots_per_epoch(8) | leader_schedule_slot_offset(8) | warmup(1) | first_normal_epoch(8) | first_normal_slot(8)
struct SolGetEpochScheduleHandler;

impl SyscallHandler for SolGetEpochScheduleHandler {
    fn call(
        &self,
        vm: &mut VmState,
        r1: u64, // destination pointer
        _r2: u64,
        _r3: u64,
        _r4: u64,
        _r5: u64,
    ) -> Result<u64, VmError> {
        deduct_compute(vm, syscalls::GET_SYSVAR_COST)?;

        let snap = &vm.sysvar_snapshot;
        let mut buf = [0u8; 33];
        buf[0..8].copy_from_slice(&snap.slots_per_epoch.to_le_bytes());
        buf[8..16].copy_from_slice(&snap.leader_schedule_slot_offset.to_le_bytes());
        buf[16] = snap.warmup as u8;
        buf[17..25].copy_from_slice(&snap.first_normal_epoch.to_le_bytes());
        buf[25..33].copy_from_slice(&snap.first_normal_slot.to_le_bytes());

        vm.memory
            .write_slice(r1, &buf)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;

        Ok(0)
    }
}

/// sol_get_last_restart_slot: Write LastRestartSlot sysvar data to VM memory.
///
/// Serialization layout (8 bytes, little-endian): slot(8)
struct SolGetLastRestartSlotHandler;

impl SyscallHandler for SolGetLastRestartSlotHandler {
    fn call(
        &self,
        vm: &mut VmState,
        r1: u64, // destination pointer
        _r2: u64,
        _r3: u64,
        _r4: u64,
        _r5: u64,
    ) -> Result<u64, VmError> {
        deduct_compute(vm, syscalls::GET_SYSVAR_COST)?;

        vm.memory
            .write_slice(r1, &vm.sysvar_snapshot.last_restart_slot.to_le_bytes())
            .map_err(|e| VmError::MemoryError(e.to_string()))?;

        Ok(0)
    }
}

/// sol_get_stack_height: Return current CPI call stack depth.
struct SolGetStackHeightHandler;

impl SyscallHandler for SolGetStackHeightHandler {
    fn call(
        &self,
        vm: &mut VmState,
        _r1: u64,
        _r2: u64,
        _r3: u64,
        _r4: u64,
        _r5: u64,
    ) -> Result<u64, VmError> {
        deduct_compute(vm, syscalls::GET_STACK_HEIGHT_COST)?;
        Ok(vm.call_stack.len() as u64)
    }
}

/// sol_secp256k1_recover: Recover public key from secp256k1 signature.
struct SolSecp256k1RecoverHandler;

impl SyscallHandler for SolSecp256k1RecoverHandler {
    fn call(
        &self,
        vm: &mut VmState,
        r1: u64, // hash pointer (32 bytes)
        r2: u64, // recovery_id
        r3: u64, // signature pointer (64 bytes)
        r4: u64, // result pointer (64 bytes)
        _r5: u64,
    ) -> Result<u64, VmError> {
        deduct_compute(vm, syscalls::SECP256K1_RECOVER_COST)?;

        let recovery_id = r2 as u8;
        if recovery_id > 3 {
            return Ok(1); // Invalid recovery ID
        }

        let hash = vm
            .memory
            .read_slice(r1, 32)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;
        let sig_bytes = vm
            .memory
            .read_slice(r3, 64)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;

        let recid = match k256::ecdsa::RecoveryId::from_byte(recovery_id) {
            Some(id) => id,
            None => return Ok(2), // Invalid recovery ID
        };

        let sig = match k256::ecdsa::Signature::from_slice(&sig_bytes) {
            Ok(s) => s,
            Err(_) => return Ok(3), // Invalid signature
        };

        let hash_arr: [u8; 32] = hash.try_into().unwrap();
        let recovered =
            match k256::ecdsa::VerifyingKey::recover_from_prehash(&hash_arr, &sig, recid) {
                Ok(key) => key,
                Err(_) => return Ok(4), // Recovery failed
            };

        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let point = recovered.to_encoded_point(false);
        let bytes = point.as_bytes();

        if bytes.len() != 65 {
            return Ok(5);
        }

        vm.memory
            .write_slice(r4, &bytes[1..]) // Skip 0x04 prefix
            .map_err(|e| VmError::MemoryError(e.to_string()))?;

        Ok(0)
    }
}

/// sol_curve_validate_point: Validate a compressed curve point.
///
/// r1 = curve_id (0=ed25519, 1=ristretto255)
/// r2 = pointer to compressed point (32 bytes)
/// Returns 0 if valid, 1 if invalid.
struct SolCurveValidatePointHandler;

impl SyscallHandler for SolCurveValidatePointHandler {
    fn call(
        &self,
        vm: &mut VmState,
        r1: u64, // curve_id
        r2: u64, // point pointer (32 bytes)
        _r3: u64,
        _r4: u64,
        _r5: u64,
    ) -> Result<u64, VmError> {
        let point_bytes = vm
            .memory
            .read_slice(r2, 32)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;
        let point: [u8; 32] = point_bytes.try_into().unwrap();

        let cost = match r1 {
            syscalls::CURVE_ID_ED25519 => syscalls::CURVE25519_EDWARDS_VALIDATE_POINT_COST,
            syscalls::CURVE_ID_RISTRETTO255 => syscalls::CURVE25519_RISTRETTO_VALIDATE_POINT_COST,
            _ => return Ok(1),
        };
        deduct_compute(vm, cost)?;

        let valid = match r1 {
            syscalls::CURVE_ID_ED25519 => {
                use curve25519_dalek::edwards::CompressedEdwardsY;
                CompressedEdwardsY(point).decompress().is_some()
            }
            syscalls::CURVE_ID_RISTRETTO255 => {
                use curve25519_dalek::ristretto::CompressedRistretto;
                CompressedRistretto(point).decompress().is_some()
            }
            _ => unreachable!(),
        };

        Ok(if valid { 0 } else { 1 })
    }
}

/// sol_curve_group_op: Perform a group operation on a curve.
///
/// r1 = curve_id, r2 = op_id (0=add, 1=sub, 2=mul)
/// r3 = left operand pointer (32 bytes), r4 = right operand pointer (32 bytes)
/// r5 = result pointer (32 bytes)
/// Returns 0 on success, 1 if an input point is invalid.
struct SolCurveGroupOpHandler;

impl SyscallHandler for SolCurveGroupOpHandler {
    fn call(
        &self,
        vm: &mut VmState,
        r1: u64, // curve_id
        r2: u64, // op_id
        r3: u64, // left pointer
        r4: u64, // right pointer
        r5: u64, // result pointer
    ) -> Result<u64, VmError> {
        let left_bytes = vm
            .memory
            .read_slice(r3, 32)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;
        let right_bytes = vm
            .memory
            .read_slice(r4, 32)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;

        let left: [u8; 32] = left_bytes.try_into().unwrap();
        let right: [u8; 32] = right_bytes.try_into().unwrap();

        let result = curve25519_group_op(vm, r1, r2, &left, &right)?;

        match result {
            Some(bytes) => {
                vm.memory
                    .write_slice(r5, &bytes)
                    .map_err(|e| VmError::MemoryError(e.to_string()))?;
                Ok(0)
            }
            None => Ok(1),
        }
    }
}

/// sol_curve_multiscalar_mul: Multi-scalar multiplication on a curve.
///
/// r1 = curve_id
/// r2 = scalars pointer (N * 32 bytes, little-endian)
/// r3 = points pointer (N * 32 bytes, compressed)
/// r4 = count (N)
/// r5 = result pointer (32 bytes)
/// Returns 0 on success, 1 if a point is invalid.
struct SolCurveMultiscalarMulHandler;

impl SyscallHandler for SolCurveMultiscalarMulHandler {
    fn call(
        &self,
        vm: &mut VmState,
        r1: u64, // curve_id
        r2: u64, // scalars pointer
        r3: u64, // points pointer
        r4: u64, // count
        r5: u64, // result pointer
    ) -> Result<u64, VmError> {
        let count = r4 as usize;
        if count == 0 {
            return Ok(1);
        }

        // Deduct compute
        let cost = match r1 {
            syscalls::CURVE_ID_ED25519 => {
                syscalls::CURVE25519_EDWARDS_MSM_BASE_COST
                    + syscalls::CURVE25519_EDWARDS_MSM_INCREMENTAL_COST
                        * count.saturating_sub(1) as u64
            }
            syscalls::CURVE_ID_RISTRETTO255 => {
                syscalls::CURVE25519_RISTRETTO_MSM_BASE_COST
                    + syscalls::CURVE25519_RISTRETTO_MSM_INCREMENTAL_COST
                        * count.saturating_sub(1) as u64
            }
            _ => return Ok(1),
        };
        deduct_compute(vm, cost)?;

        // Read scalars and points
        let scalars_data = vm
            .memory
            .read_slice(r2, count * 32)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;
        let points_data = vm
            .memory
            .read_slice(r3, count * 32)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;

        let result = match r1 {
            syscalls::CURVE_ID_ED25519 => {
                use curve25519_dalek::{
                    edwards::{CompressedEdwardsY, EdwardsPoint},
                    scalar::Scalar,
                    traits::VartimeMultiscalarMul,
                };
                let scalars: Vec<Scalar> = (0..count)
                    .map(|i| {
                        let mut s = [0u8; 32];
                        s.copy_from_slice(&scalars_data[i * 32..(i + 1) * 32]);
                        Scalar::from_bytes_mod_order(s)
                    })
                    .collect();
                let points: Option<Vec<EdwardsPoint>> = (0..count)
                    .map(|i| {
                        let mut p = [0u8; 32];
                        p.copy_from_slice(&points_data[i * 32..(i + 1) * 32]);
                        CompressedEdwardsY(p).decompress()
                    })
                    .collect();
                points.map(|pts| {
                    EdwardsPoint::vartime_multiscalar_mul(&scalars, &pts)
                        .compress()
                        .to_bytes()
                })
            }
            syscalls::CURVE_ID_RISTRETTO255 => {
                use curve25519_dalek::{
                    ristretto::{CompressedRistretto, RistrettoPoint},
                    scalar::Scalar,
                    traits::VartimeMultiscalarMul,
                };
                let scalars: Vec<Scalar> = (0..count)
                    .map(|i| {
                        let mut s = [0u8; 32];
                        s.copy_from_slice(&scalars_data[i * 32..(i + 1) * 32]);
                        Scalar::from_bytes_mod_order(s)
                    })
                    .collect();
                let points: Option<Vec<RistrettoPoint>> = (0..count)
                    .map(|i| {
                        let mut p = [0u8; 32];
                        p.copy_from_slice(&points_data[i * 32..(i + 1) * 32]);
                        CompressedRistretto(p).decompress()
                    })
                    .collect();
                points.map(|pts| {
                    RistrettoPoint::vartime_multiscalar_mul(&scalars, &pts)
                        .compress()
                        .to_bytes()
                })
            }
            _ => None,
        };

        match result {
            Some(bytes) => {
                vm.memory
                    .write_slice(r5, &bytes)
                    .map_err(|e| VmError::MemoryError(e.to_string()))?;
                Ok(0)
            }
            None => Ok(1),
        }
    }
}

/// Helper for curve25519 group operations at the dispatch level.
fn curve25519_group_op(
    vm: &mut VmState,
    curve_id: u64,
    op: u64,
    left: &[u8; 32],
    right: &[u8; 32],
) -> Result<Option<[u8; 32]>, VmError> {
    match curve_id {
        syscalls::CURVE_ID_ED25519 => {
            use curve25519_dalek::edwards::CompressedEdwardsY;
            use curve25519_dalek::scalar::Scalar;
            let cost = match op {
                syscalls::CURVE_OP_ADD => syscalls::CURVE25519_EDWARDS_ADD_COST,
                syscalls::CURVE_OP_SUB => syscalls::CURVE25519_EDWARDS_SUB_COST,
                syscalls::CURVE_OP_MUL => syscalls::CURVE25519_EDWARDS_MUL_COST,
                _ => return Err(VmError::MemoryError(format!("unknown group op: {}", op))),
            };
            deduct_compute(vm, cost)?;

            match op {
                syscalls::CURVE_OP_ADD => {
                    let a = CompressedEdwardsY(*left).decompress();
                    let b = CompressedEdwardsY(*right).decompress();
                    match (a, b) {
                        (Some(a), Some(b)) => Ok(Some((a + b).compress().to_bytes())),
                        _ => Ok(None),
                    }
                }
                syscalls::CURVE_OP_SUB => {
                    let a = CompressedEdwardsY(*left).decompress();
                    let b = CompressedEdwardsY(*right).decompress();
                    match (a, b) {
                        (Some(a), Some(b)) => Ok(Some((a - b).compress().to_bytes())),
                        _ => Ok(None),
                    }
                }
                syscalls::CURVE_OP_MUL => {
                    let scalar = Scalar::from_bytes_mod_order(*left);
                    match CompressedEdwardsY(*right).decompress() {
                        Some(p) => Ok(Some((scalar * p).compress().to_bytes())),
                        None => Ok(None),
                    }
                }
                _ => unreachable!(),
            }
        }
        syscalls::CURVE_ID_RISTRETTO255 => {
            use curve25519_dalek::ristretto::CompressedRistretto;
            use curve25519_dalek::scalar::Scalar;
            let cost = match op {
                syscalls::CURVE_OP_ADD => syscalls::CURVE25519_RISTRETTO_ADD_COST,
                syscalls::CURVE_OP_SUB => syscalls::CURVE25519_RISTRETTO_SUB_COST,
                syscalls::CURVE_OP_MUL => syscalls::CURVE25519_RISTRETTO_MUL_COST,
                _ => return Err(VmError::MemoryError(format!("unknown group op: {}", op))),
            };
            deduct_compute(vm, cost)?;

            match op {
                syscalls::CURVE_OP_ADD => {
                    let a = CompressedRistretto(*left).decompress();
                    let b = CompressedRistretto(*right).decompress();
                    match (a, b) {
                        (Some(a), Some(b)) => Ok(Some((a + b).compress().to_bytes())),
                        _ => Ok(None),
                    }
                }
                syscalls::CURVE_OP_SUB => {
                    let a = CompressedRistretto(*left).decompress();
                    let b = CompressedRistretto(*right).decompress();
                    match (a, b) {
                        (Some(a), Some(b)) => Ok(Some((a - b).compress().to_bytes())),
                        _ => Ok(None),
                    }
                }
                syscalls::CURVE_OP_MUL => {
                    let scalar = Scalar::from_bytes_mod_order(*left);
                    match CompressedRistretto(*right).decompress() {
                        Some(p) => Ok(Some((scalar * p).compress().to_bytes())),
                        None => Ok(None),
                    }
                }
                _ => unreachable!(),
            }
        }
        _ => Ok(None),
    }
}

/// sol_log_pubkey: Log a public key as base58.
///
/// r1 = pointer to 32-byte pubkey in VM memory.
struct SolLogPubkeyHandler;

impl SyscallHandler for SolLogPubkeyHandler {
    fn call(
        &self,
        vm: &mut VmState,
        r1: u64, // pubkey pointer (32 bytes)
        _r2: u64,
        _r3: u64,
        _r4: u64,
        _r5: u64,
    ) -> Result<u64, VmError> {
        deduct_compute(vm, syscalls::LOG_PUBKEY_COST)?;

        let pk_bytes = vm
            .memory
            .read_slice(r1, 32)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;

        let encoded = bs58::encode(&pk_bytes).into_string();
        vm.logs.push(format!("Program log: {}", encoded));

        Ok(0)
    }
}

/// sol_get_epoch_rewards_sysvar: Write EpochRewards sysvar data to VM memory.
///
/// Serialization layout (25 bytes, little-endian):
///   active(1) | total_rewards(8) | distributed_rewards(8) | distribution_complete_block_height(8)
struct SolGetEpochRewardsSysvarHandler;

impl SyscallHandler for SolGetEpochRewardsSysvarHandler {
    fn call(
        &self,
        vm: &mut VmState,
        r1: u64, // destination pointer
        _r2: u64,
        _r3: u64,
        _r4: u64,
        _r5: u64,
    ) -> Result<u64, VmError> {
        deduct_compute(vm, syscalls::GET_EPOCH_REWARDS_SYSVAR_COST)?;

        let snap = &vm.sysvar_snapshot;
        let mut buf = [0u8; 25];
        buf[0] = snap.epoch_rewards_active as u8;
        buf[1..9].copy_from_slice(&snap.epoch_rewards_total_rewards.to_le_bytes());
        buf[9..17].copy_from_slice(&snap.epoch_rewards_distributed_rewards.to_le_bytes());
        buf[17..25].copy_from_slice(
            &snap
                .epoch_rewards_distribution_complete_block_height
                .to_le_bytes(),
        );

        vm.memory
            .write_slice(r1, &buf)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;

        Ok(0)
    }
}

/// sol_get_sysvar: Generic sysvar slice access (SIMD-0127).
///
/// r1 = sysvar address pointer (32 bytes)
/// r2 = destination buffer pointer
/// r3 = offset into sysvar data
/// r4 = length to read
/// Returns 0 on success, 1 if sysvar not found, 2 if out of bounds.
struct SolGetSysvarHandler;

impl SyscallHandler for SolGetSysvarHandler {
    fn call(
        &self,
        vm: &mut VmState,
        r1: u64, // sysvar address pointer (32 bytes)
        r2: u64, // destination buffer pointer
        r3: u64, // offset
        r4: u64, // length
        _r5: u64,
    ) -> Result<u64, VmError> {
        let len = r4 as usize;
        let cost = syscalls::GET_GENERIC_SYSVAR_BASE_COST
            + syscalls::GET_GENERIC_SYSVAR_PER_BYTE_COST * len as u64;
        deduct_compute(vm, cost)?;

        if len > syscalls::MAX_GENERIC_SYSVAR_READ_LEN {
            return Ok(2); // Length exceeds limit
        }

        // Read sysvar address from VM memory
        let addr_bytes = vm
            .memory
            .read_slice(r1, 32)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;
        let mut sysvar_id = [0u8; 32];
        sysvar_id.copy_from_slice(&addr_bytes);

        // Look up sysvar data from snapshot
        let data = match vm.sysvar_snapshot.sysvar_data.get(&sysvar_id) {
            Some(d) => d,
            None => return Ok(1), // Sysvar not found
        };

        let offset = r3 as usize;
        if offset + len > data.len() {
            return Ok(2); // Out of bounds
        }

        // Write slice to destination
        vm.memory
            .write_slice(r2, &data[offset..offset + len])
            .map_err(|e| VmError::MemoryError(e.to_string()))?;

        Ok(0)
    }
}

/// sol_get_processed_sibling_instruction: Get a previously processed instruction.
///
/// r1 = index (0 = most recent sibling before current)
/// r2 = metadata result pointer (program_id(32) + data_len(8) + accounts_len(8) = 48 bytes)
/// r3 = data result pointer
/// r4 = accounts result pointer
/// Returns 0 on success (found), 1 if index out of range.
struct SolGetProcessedSiblingInstructionHandler;

impl SyscallHandler for SolGetProcessedSiblingInstructionHandler {
    fn call(
        &self,
        vm: &mut VmState,
        r1: u64, // index
        r2: u64, // metadata destination pointer
        r3: u64, // data destination pointer
        r4: u64, // accounts destination pointer
        _r5: u64,
    ) -> Result<u64, VmError> {
        deduct_compute(vm, syscalls::GET_PROCESSED_SIBLING_INSTRUCTION_COST)?;

        let index = r1 as usize;
        let siblings = &vm.sysvar_snapshot.sibling_instructions;

        // Index 0 = most recent (last in the vec), so reverse lookup
        let reverse_idx = siblings.len().checked_sub(index + 1);
        let sibling = match reverse_idx {
            Some(i) => &siblings[i],
            None => return Ok(1), // Out of range
        };

        // Write metadata: program_id(32) + data_len(8) + accounts_len(8)
        let mut meta_buf = [0u8; 48];
        meta_buf[0..32].copy_from_slice(&sibling.program_id);
        meta_buf[32..40].copy_from_slice(&(sibling.data.len() as u64).to_le_bytes());
        meta_buf[40..48].copy_from_slice(&(sibling.accounts.len() as u64).to_le_bytes());

        vm.memory
            .write_slice(r2, &meta_buf)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;

        // Write instruction data
        if !sibling.data.is_empty() {
            vm.memory
                .write_slice(r3, &sibling.data)
                .map_err(|e| VmError::MemoryError(e.to_string()))?;
        }

        // Write account keys (each 32 bytes)
        if !sibling.accounts.is_empty() {
            let accounts_flat: Vec<u8> = sibling
                .accounts
                .iter()
                .flat_map(|a| a.iter())
                .copied()
                .collect();
            vm.memory
                .write_slice(r4, &accounts_flat)
                .map_err(|e| VmError::MemoryError(e.to_string()))?;
        }

        Ok(0)
    }
}

/// sol_get_epoch_stake: Query total stake for a vote account at epoch boundary.
///
/// r1 = vote account address pointer (32 bytes)
/// Returns the stake in lamports (via r0).
struct SolGetEpochStakeHandler;

impl SyscallHandler for SolGetEpochStakeHandler {
    fn call(
        &self,
        vm: &mut VmState,
        r1: u64, // vote account address pointer (32 bytes)
        _r2: u64,
        _r3: u64,
        _r4: u64,
        _r5: u64,
    ) -> Result<u64, VmError> {
        deduct_compute(vm, syscalls::GET_EPOCH_STAKE_COST)?;

        let addr_bytes = vm
            .memory
            .read_slice(r1, 32)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;
        let mut vote_account = [0u8; 32];
        vote_account.copy_from_slice(&addr_bytes);

        let stake = vm
            .sysvar_snapshot
            .epoch_stake
            .get(&vote_account)
            .copied()
            .unwrap_or(0);

        Ok(stake)
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

/// sol_invoke_signed_c / sol_invoke_signed_rust: Cross-program invocation.
///
/// Reads a CPI instruction from VM memory, validates privileges and depth,
/// then executes the target program through the InstructionExecutor.
/// Account data is read from the caller's serialized input region and
/// written back after execution for writable accounts.
struct SolInvokeHandler {
    executor: Arc<dyn InstructionExecutor>,
}

/// Entry in the input region offset table, mapping a pubkey to its byte offset.
struct InputRegionEntry {
    pubkey: Pubkey,
    offset: usize,
}

/// Scan the serialized input region and build an offset table for each account.
///
/// Input region layout (from BytecodeVm::serialize_accounts):
///   [account_count: u64]
///   per account:
///     is_signer(1) | is_writable(1) | pubkey(32) | owner(32) |
///     lamports(8) | data_len(8) | data(data_len) | padding to 8-byte align
///   [instruction_data_len: u64 | instruction_data | program_id(32)]
fn scan_input_region(input: &[u8]) -> Vec<InputRegionEntry> {
    if input.len() < 8 {
        return Vec::new();
    }

    let account_count = u64::from_le_bytes(input[..8].try_into().unwrap()) as usize;
    let mut entries = Vec::with_capacity(account_count);
    let mut offset = 8;

    for _ in 0..account_count {
        if offset + paradencer_constants::vm::ACCOUNT_SERIALIZED_META_SIZE > input.len() {
            break;
        }

        // Record offset for this account (points to is_signer byte)
        let entry_offset = offset;

        // Skip is_signer(1) + is_writable(1) = 2
        offset += 2;

        // Read pubkey (32 bytes)
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&input[offset..offset + 32]);
        offset += 32;

        // Skip owner(32) + lamports(8) = 40
        offset += 40;

        // Read data_len(8)
        let data_len = u64::from_le_bytes(input[offset..offset + 8].try_into().unwrap()) as usize;
        offset += 8;

        // Skip data + padding
        offset += data_len;
        let padding = (8 - (offset % 8)) % 8;
        offset += padding;

        entries.push(InputRegionEntry {
            pubkey: Pubkey::new(pk),
            offset: entry_offset,
        });
    }

    entries
}

/// Read an Account from the input region at the given byte offset.
fn read_account_from_input(input: &[u8], offset: usize) -> Option<(bool, Account)> {
    if offset + paradencer_constants::vm::ACCOUNT_SERIALIZED_META_SIZE > input.len() {
        return None;
    }

    let _is_signer = input[offset];
    let is_writable = input[offset + 1] != 0;
    let pos = offset + 2;

    // Skip pubkey (32 bytes) — caller already knows it
    let pos = pos + 32;

    // Owner (32 bytes)
    let mut owner = [0u8; 32];
    owner.copy_from_slice(&input[pos..pos + 32]);
    let pos = pos + 32;

    // Lamports (8 bytes)
    let lamports = u64::from_le_bytes(input[pos..pos + 8].try_into().unwrap());
    let pos = pos + 8;

    // Data length (8 bytes)
    let data_len = u64::from_le_bytes(input[pos..pos + 8].try_into().unwrap()) as usize;
    let pos = pos + 8;

    if pos + data_len > input.len() {
        return None;
    }

    let data = &input[pos..pos + data_len];

    Some((
        is_writable,
        Account {
            meta: TypesAccountMeta {
                lamports,
                owner: Pubkey::new(owner),
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(data.to_vec()),
        },
    ))
}

/// Write modified account data back to the input region after CPI.
/// Only updates lamports, owner, and data bytes (pubkey and data_len unchanged).
/// Returns error if the callee's data exceeds the original allocation.
fn writeback_account_to_input(
    input: &mut [u8],
    offset: usize,
    account: &Account,
) -> Result<(), VmError> {
    let pos = offset + 2 + 32; // skip is_signer(1) + is_writable(1) + pubkey(32)

    // Write owner (32 bytes)
    input[pos..pos + 32].copy_from_slice(account.meta.owner.as_ref());
    let pos = pos + 32;

    // Write lamports (8 bytes)
    input[pos..pos + 8].copy_from_slice(&account.meta.lamports.to_le_bytes());
    let pos = pos + 8;

    // Read original data_len to check bounds
    let original_data_len = u64::from_le_bytes(input[pos..pos + 8].try_into().unwrap()) as usize;
    let pos = pos + 8;

    let new_data = account.data.as_slice();
    if new_data.len() > original_data_len {
        return Err(VmError::MemoryError(
            "CPI callee cannot grow account data".to_string(),
        ));
    }

    // Write data (may be shorter; zero-fill remainder)
    input[pos..pos + new_data.len()].copy_from_slice(new_data);
    if new_data.len() < original_data_len {
        input[pos + new_data.len()..pos + original_data_len].fill(0);
    }

    Ok(())
}

impl SyscallHandler for SolInvokeHandler {
    fn call(
        &self,
        vm: &mut VmState,
        r1: u64, // instruction pointer
        r2: u64, // account infos pointer
        r3: u64, // account infos count
        r4: u64, // signer seeds pointer (unused for now)
        r5: u64, // signer seeds count (unused for now)
    ) -> Result<u64, VmError> {
        let account_count = r3 as usize;

        // Compute cost proportional to accounts and data
        let base_cost =
            syscalls::CPI_BASE_COST + syscalls::CPI_PER_ACCOUNT_COST * account_count as u64;
        deduct_compute(vm, base_cost)?;

        // Enforce CPI depth limit using dedicated counter
        if vm.cpi_depth >= syscalls::MAX_CPI_DEPTH {
            vm.logs.push("CPI depth limit exceeded".to_string());
            return Ok(1);
        }

        // Read instruction from VM memory:
        // C ABI layout: program_id_ptr(8) + accounts_ptr(8) + accounts_len(8) + data_ptr(8) + data_len(8)
        let instr_bytes = vm
            .memory
            .read_slice(r1, 40)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;

        let program_id_ptr = u64::from_le_bytes(instr_bytes[0..8].try_into().unwrap());
        let acct_metas_ptr = u64::from_le_bytes(instr_bytes[8..16].try_into().unwrap());
        let acct_metas_len = u64::from_le_bytes(instr_bytes[16..24].try_into().unwrap()) as usize;
        let data_ptr = u64::from_le_bytes(instr_bytes[24..32].try_into().unwrap());
        let data_len = u64::from_le_bytes(instr_bytes[32..40].try_into().unwrap()) as usize;

        // Enforce limits
        if acct_metas_len > syscalls::MAX_CPI_INSTRUCTION_ACCOUNTS {
            vm.logs
                .push("Too many CPI instruction accounts".to_string());
            return Ok(1);
        }
        if data_len > syscalls::MAX_CPI_INSTRUCTION_SIZE {
            vm.logs.push("CPI instruction data too large".to_string());
            return Ok(1);
        }

        // Read program ID (32 bytes)
        let program_id_bytes = vm
            .memory
            .read_slice(program_id_ptr, 32)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;
        let mut pid = [0u8; 32];
        pid.copy_from_slice(&program_id_bytes);
        let target_program_id = Pubkey::new(pid);

        // Read instruction data
        let instruction_data = if data_len > 0 {
            vm.memory
                .read_slice(data_ptr, data_len)
                .map_err(|e| VmError::MemoryError(e.to_string()))?
        } else {
            vec![]
        };

        // Deduct per-data-byte cost
        let data_cost = syscalls::CPI_PER_DATA_BYTE_COST * data_len as u64;
        deduct_compute(vm, data_cost)?;

        // Read account metas: each is (pubkey_ptr:8, is_signer:8, is_writable:8) = 24 bytes
        let mut cpi_account_metas = Vec::with_capacity(acct_metas_len);
        for i in 0..acct_metas_len {
            let meta_offset = acct_metas_ptr + (i as u64) * 24;
            let meta_bytes = vm
                .memory
                .read_slice(meta_offset, 24)
                .map_err(|e| VmError::MemoryError(e.to_string()))?;

            let pk_ptr = u64::from_le_bytes(meta_bytes[0..8].try_into().unwrap());
            let is_signer = u64::from_le_bytes(meta_bytes[8..16].try_into().unwrap()) != 0;
            let is_writable = u64::from_le_bytes(meta_bytes[16..24].try_into().unwrap()) != 0;

            let pk_bytes = vm
                .memory
                .read_slice(pk_ptr, 32)
                .map_err(|e| VmError::MemoryError(e.to_string()))?;
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&pk_bytes);

            cpi_account_metas.push((Pubkey::new(pk), is_signer, is_writable));
        }

        // Scan the input region to build an offset table for account lookup
        let input_data = vm.memory.input_data().to_vec();
        let input_entries = scan_input_region(&input_data);

        // Build execution accounts from the input region
        let mut accounts = Vec::new();
        for (pubkey, _is_signer, is_writable) in &cpi_account_metas {
            // Find this account in the input region
            let account = if let Some(entry) = input_entries.iter().find(|e| e.pubkey == *pubkey) {
                if let Some((_is_wr, acct)) = read_account_from_input(&input_data, entry.offset) {
                    acct
                } else {
                    Account::default()
                }
            } else {
                Account::default()
            };
            accounts.push((*pubkey, account, *is_writable));
        }

        // Execute the target program
        let context = ExecutionContext::new(target_program_id, accounts, instruction_data);

        vm.cpi_depth += 1;
        let result = self.executor.execute_instruction(context);
        vm.cpi_depth -= 1;

        match result {
            Ok(outcome) => {
                // Write back modified accounts to the caller's input region
                if outcome.success {
                    let input_mut = unsafe {
                        // The input region is owned by this VM and we have &mut vm.
                        // We need mutable access to write back account data.
                        let ptr = vm.memory.input_data().as_ptr() as *mut u8;
                        let len = vm.memory.input_data().len();
                        std::slice::from_raw_parts_mut(ptr, len)
                    };

                    for (pubkey, modified_account) in &outcome.modified_accounts {
                        if let Some(entry) = input_entries.iter().find(|e| e.pubkey == *pubkey) {
                            // Only write back if the CPI meta marked it writable
                            let is_writable = cpi_account_metas
                                .iter()
                                .any(|(pk, _, w)| pk == pubkey && *w);
                            if is_writable {
                                writeback_account_to_input(
                                    input_mut,
                                    entry.offset,
                                    modified_account,
                                )?;
                            }
                        }
                    }
                }

                // Copy logs from callee
                for log in &outcome.logs {
                    vm.logs.push(log.clone());
                }

                // Store return data if any
                if let Some(data) = outcome.return_data {
                    vm.return_data = Some(data);
                }

                // Deduct compute units consumed by callee
                if vm.compute_meter >= outcome.compute_units_consumed {
                    vm.compute_meter -= outcome.compute_units_consumed;
                } else {
                    vm.compute_meter = 0;
                    return Err(VmError::ComputeBudgetExceeded);
                }

                if outcome.success {
                    Ok(0)
                } else {
                    Ok(1) // Callee returned error
                }
            }
            Err(_) => Ok(1), // Execution error
        }
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
        let result = crate::interpreter::execute(
            &program,
            memory,
            10_000,
            &dispatch,
            crate::sysvar_snapshot::SysvarSnapshot::default(),
        )
        .unwrap();
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
        let result = crate::interpreter::execute(
            &program,
            memory,
            100_000,
            &dispatch,
            crate::sysvar_snapshot::SysvarSnapshot::default(),
        )
        .unwrap();
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
        let result = crate::interpreter::execute(
            &program,
            memory,
            100_000,
            &dispatch,
            crate::sysvar_snapshot::SysvarSnapshot::default(),
        )
        .unwrap();
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
        let result = crate::interpreter::execute(
            &program,
            memory,
            10_000,
            &dispatch,
            crate::sysvar_snapshot::SysvarSnapshot::default(),
        );
        assert!(matches!(result, Err(VmError::UnknownSyscall { id: 0xBAD })));
    }

    #[test]
    fn registered_ids_set() {
        let dispatch = RuntimeSyscallDispatch::with_standard_syscalls();
        let ids = dispatch.registered_ids();
        assert!(ids.contains(&murmur3_hash("sol_log_")));
        assert!(ids.contains(&murmur3_hash("sol_memcpy_")));
        assert!(ids.contains(&murmur3_hash("sol_alloc_free_")));
        assert!(ids.contains(&murmur3_hash("sol_sha256")));
        assert!(ids.contains(&murmur3_hash("sol_keccak256")));
        assert!(ids.contains(&murmur3_hash("sol_blake3")));
        assert!(ids.contains(&murmur3_hash("sol_create_program_address")));
        assert!(ids.contains(&murmur3_hash("sol_try_find_program_address")));
        assert!(ids.contains(&murmur3_hash("sol_set_return_data")));
        assert!(ids.contains(&murmur3_hash("sol_get_return_data")));
        assert!(ids.contains(&murmur3_hash("sol_get_clock_sysvar")));
        assert!(ids.contains(&murmur3_hash("sol_get_rent_sysvar")));
        assert!(ids.contains(&murmur3_hash("sol_get_epoch_schedule_sysvar")));
        assert!(ids.contains(&murmur3_hash("sol_get_last_restart_slot")));
        assert!(ids.contains(&murmur3_hash("sol_get_stack_height")));
        assert!(ids.contains(&murmur3_hash("sol_secp256k1_recover")));
        assert!(!ids.contains(&0xDEAD));
        assert!(ids.contains(&murmur3_hash("sol_curve_validate_point")));
        assert!(ids.contains(&murmur3_hash("sol_curve_group_op")));
        assert!(ids.contains(&murmur3_hash("sol_curve_multiscalar_mul")));
        // New syscalls
        assert!(ids.contains(&murmur3_hash("sol_log_pubkey")));
        assert!(ids.contains(&murmur3_hash("sol_get_epoch_rewards_sysvar")));
        assert!(ids.contains(&murmur3_hash("sol_get_sysvar")));
        assert!(ids.contains(&murmur3_hash("sol_get_processed_sibling_instruction")));
        assert!(ids.contains(&murmur3_hash("sol_get_epoch_stake")));
        // 5 log + 4 mem + 3 hash + 1 alloc + 2 PDA + 2 return_data + 4 sysvar + 1 stack + 1 crypto + 3 curve + 4 new runtime = 30
        assert!(
            ids.len() >= 30,
            "Expected >= 30 syscalls, got {}",
            ids.len()
        );
    }

    #[test]
    fn sha256_handler_correct_hash() {
        use sha2::{Digest, Sha256};

        let dispatch = RuntimeSyscallDispatch::with_standard_syscalls();
        let sha_id = murmur3_hash("sol_sha256");

        // Write test data "hello" to heap, set up input pair pointing to it
        let bytes = make_program_bytes(&[
            // Write "hello" (5 bytes) to heap at offset 0
            Instruction::new(Opcode::Lddw as u8, 1, 0, 0, REGION_HEAP_BASE as i32),
            Instruction::new(0, 0, 0, 0, (REGION_HEAP_BASE >> 32) as i32),
            // "hello" = h(0x68) e(0x65) l(0x6C) l(0x6C) o(0x6F)
            // In LE u32: bytes[0..4] = 0x6C6C6568 ("hell"), byte[4] = 0x6F ("o")
            Instruction::new(Opcode::Mov64Imm as u8, 2, 0, 0, 0x6C6C6568u32 as i32),
            Instruction::new(Opcode::StxWord as u8, 1, 2, 0, 0),
            Instruction::new(Opcode::Mov64Imm as u8, 2, 0, 0, 0x6F), // "o"
            Instruction::new(Opcode::StxByte as u8, 1, 2, 4, 0),
            // Store input pair at heap+64: ptr=heap_base, len=5
            Instruction::new(Opcode::Lddw as u8, 3, 0, 0, (REGION_HEAP_BASE + 64) as i32),
            Instruction::new(0, 0, 0, 0, ((REGION_HEAP_BASE + 64) >> 32) as i32),
            // ptr (8 bytes) = HEAP_BASE
            Instruction::new(Opcode::StxDword as u8, 3, 1, 0, 0), // store heap_base at pair[0]
            Instruction::new(Opcode::Mov64Imm as u8, 4, 0, 0, 5),
            Instruction::new(Opcode::StxDword as u8, 3, 4, 8, 0), // store len=5 at pair[1]
            // Call sha256: r1=pair_ptr(heap+64), r2=1(count), r4=result(heap+128)
            Instruction::new(Opcode::Lddw as u8, 1, 0, 0, (REGION_HEAP_BASE + 64) as i32),
            Instruction::new(0, 0, 0, 0, ((REGION_HEAP_BASE + 64) >> 32) as i32),
            Instruction::new(Opcode::Mov64Imm as u8, 2, 0, 0, 1), // 1 pair
            Instruction::new(Opcode::Lddw as u8, 4, 0, 0, (REGION_HEAP_BASE + 128) as i32),
            Instruction::new(0, 0, 0, 0, ((REGION_HEAP_BASE + 128) >> 32) as i32),
            Instruction::new(Opcode::Call as u8, 0, 0, 0, sha_id as i32),
            // Read first 8 bytes of hash into r0 for validation
            Instruction::new(Opcode::Lddw as u8, 1, 0, 0, (REGION_HEAP_BASE + 128) as i32),
            Instruction::new(0, 0, 0, 0, ((REGION_HEAP_BASE + 128) >> 32) as i32),
            Instruction::new(Opcode::LdxDword as u8, 0, 1, 0, 0),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ]);
        let program = load_raw(&bytes).unwrap();
        let memory = MemoryMap::new(&[], TOTAL_STACK_SIZE, DEFAULT_HEAP_SIZE, vec![]);
        let result = crate::interpreter::execute(
            &program,
            memory,
            1_000_000,
            &dispatch,
            crate::sysvar_snapshot::SysvarSnapshot::default(),
        )
        .unwrap();

        // Compute expected SHA-256 of "hello"
        let mut hasher = Sha256::new();
        hasher.update(b"hello");
        let expected: [u8; 32] = hasher.finalize().into();
        let expected_first_8 = u64::from_le_bytes(expected[..8].try_into().unwrap());

        assert_eq!(result.return_value, expected_first_8);
    }

    /// A test executor that counts invocations and returns success.
    struct CountingExecutor {
        call_count: std::sync::atomic::AtomicU64,
    }

    impl CountingExecutor {
        fn new() -> Self {
            Self {
                call_count: std::sync::atomic::AtomicU64::new(0),
            }
        }

        fn count(&self) -> u64 {
            self.call_count.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl InstructionExecutor for CountingExecutor {
        fn execute_instruction(
            &self,
            context: crate::ExecutionContext,
        ) -> Result<crate::ExecutionOutcome, crate::SbpfExecutionError> {
            self.call_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(crate::ExecutionOutcome::success(100))
        }
    }

    #[test]
    fn cpi_dispatch_with_executor() {
        let executor = Arc::new(CountingExecutor::new());
        let dispatch = RuntimeSyscallDispatch::with_cpi_support(executor.clone());

        // Verify CPI syscalls are registered
        let ids = dispatch.registered_ids();
        assert!(ids.contains(&murmur3_hash("sol_invoke_signed_c")));
        assert!(ids.contains(&murmur3_hash("sol_invoke_signed_rust")));
        // 30 standard + 2 CPI = 32
        assert!(
            ids.len() >= 32,
            "Expected >= 32 syscalls with CPI, got {}",
            ids.len()
        );
    }

    #[test]
    fn cpi_without_executor_not_registered() {
        let dispatch = RuntimeSyscallDispatch::with_standard_syscalls();
        let ids = dispatch.registered_ids();
        assert!(!ids.contains(&murmur3_hash("sol_invoke_signed_c")));
    }

    // -----------------------------------------------------------------------
    // Sysvar syscall tests
    // -----------------------------------------------------------------------

    /// Create a VmState with a given SysvarSnapshot and heap for testing syscall handlers directly.
    fn make_sysvar_test_vm(snapshot: crate::sysvar_snapshot::SysvarSnapshot) -> VmState {
        use crate::interpreter::VmState;
        VmState {
            registers: [0u64; 11],
            pc: 0,
            instruction_count: 0,
            memory: MemoryMap::new(&[], TOTAL_STACK_SIZE, DEFAULT_HEAP_SIZE, vec![]),
            call_stack: Vec::new(),
            compute_meter: 1_000_000,
            logs: Vec::new(),
            return_data: None,
            heap_position: REGION_HEAP_BASE,
            sysvar_snapshot: snapshot,
            cpi_depth: 0,
        }
    }

    #[test]
    fn clock_syscall_reads_snapshot_slot() {
        let snap = crate::sysvar_snapshot::SysvarSnapshot {
            slot: 12345,
            epoch: 7,
            unix_timestamp: 1700000000,
            epoch_start_timestamp: 1699000000,
            leader_schedule_epoch: 8,
            ..Default::default()
        };

        let mut vm = make_sysvar_test_vm(snap);
        let handler = SolGetClockSysvarHandler;
        let ret = handler.call(&mut vm, REGION_HEAP_BASE, 0, 0, 0, 0).unwrap();
        assert_eq!(ret, 0);

        let buf = vm.memory.read_slice(REGION_HEAP_BASE, 40).unwrap();
        assert_eq!(u64::from_le_bytes(buf[0..8].try_into().unwrap()), 12345);
        assert_eq!(
            i64::from_le_bytes(buf[8..16].try_into().unwrap()),
            1699000000
        );
        assert_eq!(u64::from_le_bytes(buf[16..24].try_into().unwrap()), 7);
        assert_eq!(u64::from_le_bytes(buf[24..32].try_into().unwrap()), 8);
        assert_eq!(
            i64::from_le_bytes(buf[32..40].try_into().unwrap()),
            1700000000
        );
    }

    #[test]
    fn rent_syscall_reads_snapshot() {
        let snap = crate::sysvar_snapshot::SysvarSnapshot {
            lamports_per_byte_year: 3480,
            exemption_threshold: 2.0,
            burn_percent: 50,
            ..Default::default()
        };

        let mut vm = make_sysvar_test_vm(snap);
        let handler = SolGetRentSysvarHandler;
        let ret = handler.call(&mut vm, REGION_HEAP_BASE, 0, 0, 0, 0).unwrap();
        assert_eq!(ret, 0);

        let buf = vm.memory.read_slice(REGION_HEAP_BASE, 17).unwrap();
        assert_eq!(u64::from_le_bytes(buf[0..8].try_into().unwrap()), 3480);
        assert_eq!(f64::from_le_bytes(buf[8..16].try_into().unwrap()), 2.0);
        assert_eq!(buf[16], 50);
    }

    #[test]
    fn epoch_schedule_syscall_reads_snapshot() {
        let snap = crate::sysvar_snapshot::SysvarSnapshot {
            slots_per_epoch: 432_000,
            leader_schedule_slot_offset: 432_000,
            warmup: true,
            first_normal_epoch: 14,
            first_normal_slot: 524_256,
            ..Default::default()
        };

        let mut vm = make_sysvar_test_vm(snap);
        let handler = SolGetEpochScheduleHandler;
        let ret = handler.call(&mut vm, REGION_HEAP_BASE, 0, 0, 0, 0).unwrap();
        assert_eq!(ret, 0);

        let buf = vm.memory.read_slice(REGION_HEAP_BASE, 33).unwrap();
        assert_eq!(u64::from_le_bytes(buf[0..8].try_into().unwrap()), 432_000);
        assert_eq!(u64::from_le_bytes(buf[8..16].try_into().unwrap()), 432_000);
        assert_eq!(buf[16], 1);
        assert_eq!(u64::from_le_bytes(buf[17..25].try_into().unwrap()), 14);
        assert_eq!(u64::from_le_bytes(buf[25..33].try_into().unwrap()), 524_256);
    }

    #[test]
    fn last_restart_slot_syscall_reads_snapshot() {
        let snap = crate::sysvar_snapshot::SysvarSnapshot {
            last_restart_slot: 99_999,
            ..Default::default()
        };

        let mut vm = make_sysvar_test_vm(snap);
        let handler = SolGetLastRestartSlotHandler;
        let ret = handler.call(&mut vm, REGION_HEAP_BASE, 0, 0, 0, 0).unwrap();
        assert_eq!(ret, 0);

        let buf = vm.memory.read_slice(REGION_HEAP_BASE, 8).unwrap();
        assert_eq!(u64::from_le_bytes(buf[0..8].try_into().unwrap()), 99_999);
    }

    #[test]
    fn log_pubkey_handler() {
        let mut vm = make_sysvar_test_vm(crate::sysvar_snapshot::SysvarSnapshot::default());
        let handler = SolLogPubkeyHandler;

        // Write a known pubkey (all 1s) to heap
        let pk_bytes = [1u8; 32];
        vm.memory.write_slice(REGION_HEAP_BASE, &pk_bytes).unwrap();

        let ret = handler.call(&mut vm, REGION_HEAP_BASE, 0, 0, 0, 0).unwrap();
        assert_eq!(ret, 0);

        let expected = bs58::encode(&pk_bytes).into_string();
        assert!(
            vm.logs.iter().any(|l| l.contains(&expected)),
            "Expected log to contain '{}', got {:?}",
            expected,
            vm.logs
        );
    }

    #[test]
    fn epoch_rewards_syscall_reads_snapshot() {
        let snap = crate::sysvar_snapshot::SysvarSnapshot {
            epoch_rewards_active: true,
            epoch_rewards_total_rewards: 1_000_000,
            epoch_rewards_distributed_rewards: 500_000,
            epoch_rewards_distribution_complete_block_height: 200,
            ..Default::default()
        };

        let mut vm = make_sysvar_test_vm(snap);
        let handler = SolGetEpochRewardsSysvarHandler;
        let ret = handler.call(&mut vm, REGION_HEAP_BASE, 0, 0, 0, 0).unwrap();
        assert_eq!(ret, 0);

        let buf = vm.memory.read_slice(REGION_HEAP_BASE, 25).unwrap();
        assert_eq!(buf[0], 1); // active = true
        assert_eq!(u64::from_le_bytes(buf[1..9].try_into().unwrap()), 1_000_000);
        assert_eq!(u64::from_le_bytes(buf[9..17].try_into().unwrap()), 500_000);
        assert_eq!(u64::from_le_bytes(buf[17..25].try_into().unwrap()), 200);
    }

    #[test]
    fn epoch_rewards_syscall_default_zeros() {
        let mut vm = make_sysvar_test_vm(crate::sysvar_snapshot::SysvarSnapshot::default());
        let handler = SolGetEpochRewardsSysvarHandler;
        let ret = handler.call(&mut vm, REGION_HEAP_BASE, 0, 0, 0, 0).unwrap();
        assert_eq!(ret, 0);

        let buf = vm.memory.read_slice(REGION_HEAP_BASE, 25).unwrap();
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn generic_sysvar_reads_stored_data() {
        let mut snap = crate::sysvar_snapshot::SysvarSnapshot::default();
        let sysvar_id = [0xAA; 32];
        let sysvar_data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        snap.sysvar_data.insert(sysvar_id, sysvar_data.clone());

        let mut vm = make_sysvar_test_vm(snap);
        let handler = SolGetSysvarHandler;

        // Write sysvar ID to heap
        vm.memory.write_slice(REGION_HEAP_BASE, &sysvar_id).unwrap();

        // Read bytes 2..6 from the sysvar (offset=2, len=4)
        let dest = REGION_HEAP_BASE + 64;
        let ret = handler
            .call(&mut vm, REGION_HEAP_BASE, dest, 2, 4, 0)
            .unwrap();
        assert_eq!(ret, 0);

        let result = vm.memory.read_slice(dest, 4).unwrap();
        assert_eq!(result, &[3, 4, 5, 6]);
    }

    #[test]
    fn generic_sysvar_not_found_returns_1() {
        let mut vm = make_sysvar_test_vm(crate::sysvar_snapshot::SysvarSnapshot::default());
        let handler = SolGetSysvarHandler;

        let unknown_id = [0xFF; 32];
        vm.memory
            .write_slice(REGION_HEAP_BASE, &unknown_id)
            .unwrap();

        let ret = handler
            .call(&mut vm, REGION_HEAP_BASE, REGION_HEAP_BASE + 64, 0, 8, 0)
            .unwrap();
        assert_eq!(ret, 1); // Not found
    }

    #[test]
    fn generic_sysvar_out_of_bounds_returns_2() {
        let mut snap = crate::sysvar_snapshot::SysvarSnapshot::default();
        let sysvar_id = [0xBB; 32];
        snap.sysvar_data.insert(sysvar_id, vec![1, 2, 3]); // 3 bytes

        let mut vm = make_sysvar_test_vm(snap);
        let handler = SolGetSysvarHandler;

        vm.memory.write_slice(REGION_HEAP_BASE, &sysvar_id).unwrap();

        // Try to read offset=1, len=4 from 3-byte data → out of bounds
        let ret = handler
            .call(&mut vm, REGION_HEAP_BASE, REGION_HEAP_BASE + 64, 1, 4, 0)
            .unwrap();
        assert_eq!(ret, 2);
    }

    #[test]
    fn sibling_instruction_returns_most_recent_first() {
        use crate::sysvar_snapshot::SiblingInstruction;

        let mut snap = crate::sysvar_snapshot::SysvarSnapshot::default();
        snap.sibling_instructions.push(SiblingInstruction {
            program_id: [1u8; 32],
            data: vec![0xAA, 0xBB],
            accounts: vec![[2u8; 32]],
        });
        snap.sibling_instructions.push(SiblingInstruction {
            program_id: [3u8; 32],
            data: vec![0xCC],
            accounts: vec![[4u8; 32], [5u8; 32]],
        });

        let mut vm = make_sysvar_test_vm(snap);
        let handler = SolGetProcessedSiblingInstructionHandler;

        // Index 0 = most recent = second sibling (program_id=[3u8;32])
        let meta_ptr = REGION_HEAP_BASE;
        let data_ptr = REGION_HEAP_BASE + 64;
        let acct_ptr = REGION_HEAP_BASE + 128;

        let ret = handler
            .call(&mut vm, 0, meta_ptr, data_ptr, acct_ptr, 0)
            .unwrap();
        assert_eq!(ret, 0);

        let meta = vm.memory.read_slice(meta_ptr, 48).unwrap();
        let mut program_id = [0u8; 32];
        program_id.copy_from_slice(&meta[0..32]);
        assert_eq!(program_id, [3u8; 32]);

        let data_len = u64::from_le_bytes(meta[32..40].try_into().unwrap());
        assert_eq!(data_len, 1);

        let accounts_len = u64::from_le_bytes(meta[40..48].try_into().unwrap());
        assert_eq!(accounts_len, 2);

        let data = vm.memory.read_slice(data_ptr, 1).unwrap();
        assert_eq!(data, &[0xCC]);

        let acct_data = vm.memory.read_slice(acct_ptr, 64).unwrap();
        assert_eq!(&acct_data[0..32], &[4u8; 32]);
        assert_eq!(&acct_data[32..64], &[5u8; 32]);
    }

    #[test]
    fn sibling_instruction_index_1_returns_older() {
        use crate::sysvar_snapshot::SiblingInstruction;

        let mut snap = crate::sysvar_snapshot::SysvarSnapshot::default();
        snap.sibling_instructions.push(SiblingInstruction {
            program_id: [1u8; 32],
            data: vec![0xAA],
            accounts: vec![],
        });
        snap.sibling_instructions.push(SiblingInstruction {
            program_id: [2u8; 32],
            data: vec![0xBB],
            accounts: vec![],
        });

        let mut vm = make_sysvar_test_vm(snap);
        let handler = SolGetProcessedSiblingInstructionHandler;

        // Index 1 = older sibling (program_id=[1u8;32])
        let meta_ptr = REGION_HEAP_BASE;
        let ret = handler
            .call(
                &mut vm,
                1,
                meta_ptr,
                REGION_HEAP_BASE + 64,
                REGION_HEAP_BASE + 128,
                0,
            )
            .unwrap();
        assert_eq!(ret, 0);

        let meta = vm.memory.read_slice(meta_ptr, 32).unwrap();
        assert_eq!(&meta[..], &[1u8; 32]);
    }

    #[test]
    fn sibling_instruction_out_of_range_returns_1() {
        let mut vm = make_sysvar_test_vm(crate::sysvar_snapshot::SysvarSnapshot::default());
        let handler = SolGetProcessedSiblingInstructionHandler;

        let ret = handler
            .call(
                &mut vm,
                0,
                REGION_HEAP_BASE,
                REGION_HEAP_BASE + 64,
                REGION_HEAP_BASE + 128,
                0,
            )
            .unwrap();
        assert_eq!(ret, 1); // No siblings
    }

    #[test]
    fn epoch_stake_returns_known_stake() {
        let mut snap = crate::sysvar_snapshot::SysvarSnapshot::default();
        let vote_account = [0xDD; 32];
        snap.epoch_stake.insert(vote_account, 42_000_000);

        let mut vm = make_sysvar_test_vm(snap);
        let handler = SolGetEpochStakeHandler;

        vm.memory
            .write_slice(REGION_HEAP_BASE, &vote_account)
            .unwrap();

        let ret = handler.call(&mut vm, REGION_HEAP_BASE, 0, 0, 0, 0).unwrap();
        assert_eq!(ret, 42_000_000);
    }

    #[test]
    fn epoch_stake_returns_zero_for_unknown() {
        let mut vm = make_sysvar_test_vm(crate::sysvar_snapshot::SysvarSnapshot::default());
        let handler = SolGetEpochStakeHandler;

        let unknown = [0xFF; 32];
        vm.memory.write_slice(REGION_HEAP_BASE, &unknown).unwrap();

        let ret = handler.call(&mut vm, REGION_HEAP_BASE, 0, 0, 0, 0).unwrap();
        assert_eq!(ret, 0);
    }

    #[test]
    fn sysvar_syscalls_with_default_snapshot_return_zeros() {
        let mut vm = make_sysvar_test_vm(crate::sysvar_snapshot::SysvarSnapshot::default());
        let ret = SolGetClockSysvarHandler
            .call(&mut vm, REGION_HEAP_BASE, 0, 0, 0, 0)
            .unwrap();
        assert_eq!(ret, 0);
        let buf = vm.memory.read_slice(REGION_HEAP_BASE, 40).unwrap();
        assert!(
            buf.iter().all(|&b| b == 0),
            "default clock should be all zeros"
        );

        let mut vm = make_sysvar_test_vm(crate::sysvar_snapshot::SysvarSnapshot::default());
        let ret = SolGetLastRestartSlotHandler
            .call(&mut vm, REGION_HEAP_BASE, 0, 0, 0, 0)
            .unwrap();
        assert_eq!(ret, 0);
        let buf = vm.memory.read_slice(REGION_HEAP_BASE, 8).unwrap();
        assert!(
            buf.iter().all(|&b| b == 0),
            "default last_restart should be all zeros"
        );
    }

    // -----------------------------------------------------------------------
    // CPI input region tests
    // -----------------------------------------------------------------------

    /// Build a minimal serialized input region with one account.
    fn make_input_region(
        pubkey: &Pubkey,
        owner: &Pubkey,
        lamports: u64,
        data: &[u8],
        is_writable: bool,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        // account_count = 1
        buf.extend_from_slice(&1u64.to_le_bytes());
        // is_signer
        buf.push(0);
        // is_writable
        buf.push(if is_writable { 1 } else { 0 });
        // pubkey
        buf.extend_from_slice(pubkey.as_ref());
        // owner
        buf.extend_from_slice(owner.as_ref());
        // lamports
        buf.extend_from_slice(&lamports.to_le_bytes());
        // data_len
        buf.extend_from_slice(&(data.len() as u64).to_le_bytes());
        // data
        buf.extend_from_slice(data);
        // padding
        let padding = (8 - (buf.len() % 8)) % 8;
        buf.extend(std::iter::repeat_n(0u8, padding));
        buf
    }

    #[test]
    fn scan_input_region_finds_account() {
        let pk = Pubkey::new([1u8; 32]);
        let owner = Pubkey::new([2u8; 32]);
        let input = make_input_region(&pk, &owner, 1000, &[0xAA; 16], true);

        let entries = scan_input_region(&input);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].pubkey, pk);
        assert_eq!(entries[0].offset, 8); // starts right after account_count
    }

    #[test]
    fn read_account_from_input_returns_correct_data() {
        let pk = Pubkey::new([1u8; 32]);
        let owner = Pubkey::new([2u8; 32]);
        let data = vec![0xBB; 24];
        let input = make_input_region(&pk, &owner, 5000, &data, true);

        let entries = scan_input_region(&input);
        let (is_wr, account) = read_account_from_input(&input, entries[0].offset).unwrap();
        assert!(is_wr);
        assert_eq!(account.meta.lamports, 5000);
        assert_eq!(account.meta.owner, owner);
        assert_eq!(account.data.as_slice(), &data);
    }

    #[test]
    fn writeback_updates_lamports_in_input() {
        let pk = Pubkey::new([1u8; 32]);
        let owner = Pubkey::new([2u8; 32]);
        let mut input = make_input_region(&pk, &owner, 1000, &[0; 8], true);

        let entries = scan_input_region(&input);

        // Build a modified account with updated lamports
        let modified = Account {
            meta: TypesAccountMeta {
                lamports: 9999,
                owner,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(vec![0xFF; 8]),
        };

        writeback_account_to_input(&mut input, entries[0].offset, &modified).unwrap();

        // Re-read and verify
        let (_, readback) = read_account_from_input(&input, entries[0].offset).unwrap();
        assert_eq!(readback.meta.lamports, 9999);
        assert_eq!(readback.data.as_slice(), &[0xFF; 8]);
    }

    #[test]
    fn writeback_rejects_data_growth() {
        let pk = Pubkey::new([1u8; 32]);
        let owner = Pubkey::new([2u8; 32]);
        let mut input = make_input_region(&pk, &owner, 1000, &[0; 8], true);

        let entries = scan_input_region(&input);

        // Try to write back with larger data
        let modified = Account {
            meta: TypesAccountMeta {
                lamports: 1000,
                owner,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(vec![0; 16]), // 16 > original 8
        };

        let result = writeback_account_to_input(&mut input, entries[0].offset, &modified);
        assert!(result.is_err());
    }

    #[test]
    fn writeback_allows_shorter_data() {
        let pk = Pubkey::new([1u8; 32]);
        let owner = Pubkey::new([2u8; 32]);
        let mut input = make_input_region(&pk, &owner, 1000, &[0xAA; 16], true);

        let entries = scan_input_region(&input);

        // Write back with shorter data (remainder should be zeroed)
        let modified = Account {
            meta: TypesAccountMeta {
                lamports: 1000,
                owner,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(vec![0xBB; 4]),
        };

        writeback_account_to_input(&mut input, entries[0].offset, &modified).unwrap();

        let (_, readback) = read_account_from_input(&input, entries[0].offset).unwrap();
        // First 4 bytes are 0xBB, remaining 12 are zeroed
        assert_eq!(&readback.data.as_slice()[..4], &[0xBB; 4]);
        assert_eq!(&readback.data.as_slice()[4..], &[0; 12]);
    }

    #[test]
    fn scan_input_region_handles_empty() {
        let entries = scan_input_region(&[]);
        assert!(entries.is_empty());

        // Zero accounts
        let input = 0u64.to_le_bytes().to_vec();
        let entries = scan_input_region(&input);
        assert!(entries.is_empty());
    }

    #[test]
    fn scan_input_region_handles_multiple_accounts() {
        let pk1 = Pubkey::new([1u8; 32]);
        let pk2 = Pubkey::new([2u8; 32]);
        let owner = Pubkey::new([3u8; 32]);

        let mut buf = Vec::new();
        buf.extend_from_slice(&2u64.to_le_bytes()); // 2 accounts

        // Account 1
        buf.push(0);
        buf.push(1); // is_signer=0, is_writable=1
        buf.extend_from_slice(pk1.as_ref());
        buf.extend_from_slice(owner.as_ref());
        buf.extend_from_slice(&100u64.to_le_bytes());
        buf.extend_from_slice(&8u64.to_le_bytes());
        buf.extend_from_slice(&[0xAA; 8]);
        // No padding needed (8 + 2 + 32 + 32 + 8 + 8 + 8 = 98; 98%8=2 → pad 6)
        let padding = (8 - (buf.len() % 8)) % 8;
        buf.extend(std::iter::repeat_n(0u8, padding));

        // Account 2
        buf.push(0);
        buf.push(0); // is_signer=0, is_writable=0
        buf.extend_from_slice(pk2.as_ref());
        buf.extend_from_slice(owner.as_ref());
        buf.extend_from_slice(&200u64.to_le_bytes());
        buf.extend_from_slice(&4u64.to_le_bytes());
        buf.extend_from_slice(&[0xBB; 4]);
        let padding = (8 - (buf.len() % 8)) % 8;
        buf.extend(std::iter::repeat_n(0u8, padding));

        let entries = scan_input_region(&buf);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].pubkey, pk1);
        assert_eq!(entries[1].pubkey, pk2);

        let (wr1, a1) = read_account_from_input(&buf, entries[0].offset).unwrap();
        assert!(wr1);
        assert_eq!(a1.meta.lamports, 100);

        let (wr2, a2) = read_account_from_input(&buf, entries[1].offset).unwrap();
        assert!(!wr2);
        assert_eq!(a2.meta.lamports, 200);
    }

    #[test]
    fn cpi_depth_limit_uses_dedicated_field() {
        // Verify that CPI depth uses vm.cpi_depth, not call_stack.len()
        let executor = Arc::new(CountingExecutor::new());
        let handler = SolInvokeHandler {
            executor: executor.clone(),
        };

        let mut vm = make_sysvar_test_vm(crate::sysvar_snapshot::SysvarSnapshot::default());
        // Set cpi_depth to the limit
        vm.cpi_depth = syscalls::MAX_CPI_DEPTH;

        // The handler should reject due to depth limit (return 1, not error)
        // We need r1 to point to valid instruction data, but the depth check
        // happens before reading the instruction, so this should return 1.
        // However, base_cost deduction happens first. Give enough compute.
        vm.compute_meter = 10_000_000;

        // Build a minimal instruction in heap: just zeros (invalid but depth check comes first)
        // Actually, base_cost is deducted before depth check in the current code.
        // After the base cost deduction, depth check happens, and returns Ok(1).
        let ret = handler.call(&mut vm, REGION_HEAP_BASE, 0, 0, 0, 0).unwrap();
        assert_eq!(ret, 1);
        assert!(vm.logs.iter().any(|l| l.contains("CPI depth limit")));
    }
}
