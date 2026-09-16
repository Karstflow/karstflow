/// Syscall dispatch bridge between the sBPF interpreter and runtime syscalls.
///
/// Maps syscall identifiers (murmur3 hashes of names) to handler functions,
/// reads arguments from VM registers r1..r5, and writes the return value to r0.
use crate::interpreter::{SyscallDispatch, VmError, VmState};
use crate::{ExecutionContext, ExecutionOutcome, SbpfExecutionError};
use karstflow_constants::syscalls;
use karstflow_types::{Account, AccountData, AccountMeta as TypesAccountMeta, Pubkey};
use sha2::{Digest, Sha256, Sha512};
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
        dispatch.register_by_name("sol_sha512", Box::new(SolSha512Handler));

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

        // ALT-BN128 group operations and compression.
        // This constructor registers every syscall unconditionally, so the
        // sub-operation gates are open too. Feature-aware construction goes
        // through `with_active_feature_ids`.
        dispatch.register_by_name(
            "sol_alt_bn128_group_op",
            Box::new(SolAltBn128GroupOpHandler {
                little_endian_enabled: true,
                g2_enabled: true,
            }),
        );
        dispatch.register_by_name(
            "sol_alt_bn128_compression",
            Box::new(SolAltBn128CompressionHandler {
                little_endian_enabled: true,
            }),
        );

        // Poseidon hash
        dispatch.register_by_name("sol_poseidon", Box::new(SolPoseidonHandler));

        // VM termination
        dispatch.register_by_name("abort", Box::new(AbortHandler));
        dispatch.register_by_name("sol_panic_", Box::new(SolPanicHandler));

        // BLS12-381 curve operations
        dispatch.register_by_name("sol_curve_decompress", Box::new(SolCurveDecompressHandler));
        dispatch.register_by_name("sol_curve_pairing_map", Box::new(SolCurvePairingMapHandler));

        dispatch
    }

    /// Create a dispatcher with feature-gated syscall registration.
    ///
    /// Registers the always-available syscalls unconditionally, then
    /// conditionally registers feature-gated syscalls only when their
    /// corresponding feature is present in `active_features`.
    ///
    /// Feature names match the protocol feature strings:
    /// - `enable_alt_bn128_syscall` — sol_alt_bn128_group_op
    /// - `enable_alt_bn128_compression_syscall` — sol_alt_bn128_compression
    /// - `enable_poseidon_syscall` — sol_poseidon
    /// - `get_sysvar_syscall_enabled` — sol_get_sysvar
    /// - `enable_get_epoch_stake_syscall` — sol_get_epoch_stake
    pub fn with_features(active_features: &std::collections::HashSet<&str>) -> Self {
        use karstflow_constants::features::{
            FEATURE_ALT_BN128_LITTLE_ENDIAN, FEATURE_ENABLE_ALT_BN128_COMPRESSION,
            FEATURE_ENABLE_ALT_BN128_G2_SYSCALLS, FEATURE_ENABLE_ALT_BN128_SYSCALL,
            FEATURE_ENABLE_BLS12_381_SYSCALL, FEATURE_ENABLE_GET_EPOCH_STAKE,
            FEATURE_ENABLE_POSEIDON_SYSCALL, FEATURE_GET_SYSVAR_SYSCALL,
        };

        let mut dispatch = Self::new();

        // Always-available syscalls (no feature gate)
        dispatch.register_by_name("sol_log_", Box::new(SolLogHandler));
        dispatch.register_by_name("sol_log_64_", Box::new(SolLog64Handler));
        dispatch.register_by_name(
            "sol_log_compute_units_",
            Box::new(SolLogComputeUnitsHandler),
        );
        dispatch.register_by_name("sol_log_data", Box::new(SolLogDataHandler));
        dispatch.register_by_name("sol_log_pubkey", Box::new(SolLogPubkeyHandler));
        dispatch.register_by_name("sol_memcpy_", Box::new(SolMemcpyHandler));
        dispatch.register_by_name("sol_memmove_", Box::new(SolMemmoveHandler));
        dispatch.register_by_name("sol_memcmp_", Box::new(SolMemcmpHandler));
        dispatch.register_by_name("sol_memset_", Box::new(SolMemsetHandler));
        dispatch.register_by_name("sol_sha256", Box::new(SolSha256Handler));
        dispatch.register_by_name("sol_keccak256", Box::new(SolKeccak256Handler));
        dispatch.register_by_name("sol_blake3", Box::new(SolBlake3Handler));
        dispatch.register_by_name("sol_sha512", Box::new(SolSha512Handler));
        dispatch.register_by_name("sol_alloc_free_", Box::new(SolAllocHandler));
        dispatch.register_by_name(
            "sol_create_program_address",
            Box::new(SolCreateProgramAddressHandler),
        );
        dispatch.register_by_name(
            "sol_try_find_program_address",
            Box::new(SolTryFindProgramAddressHandler),
        );
        dispatch.register_by_name("sol_set_return_data", Box::new(SolSetReturnDataHandler));
        dispatch.register_by_name("sol_get_return_data", Box::new(SolGetReturnDataHandler));
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
        dispatch.register_by_name("sol_get_stack_height", Box::new(SolGetStackHeightHandler));
        dispatch.register_by_name(
            "sol_get_processed_sibling_instruction",
            Box::new(SolGetProcessedSiblingInstructionHandler),
        );
        dispatch.register_by_name(
            "sol_get_epoch_rewards_sysvar",
            Box::new(SolGetEpochRewardsSysvarHandler),
        );
        dispatch.register_by_name(
            "sol_secp256k1_recover",
            Box::new(SolSecp256k1RecoverHandler),
        );
        dispatch.register_by_name(
            "sol_curve_validate_point",
            Box::new(SolCurveValidatePointHandler),
        );
        dispatch.register_by_name("sol_curve_group_op", Box::new(SolCurveGroupOpHandler));
        dispatch.register_by_name(
            "sol_curve_multiscalar_mul",
            Box::new(SolCurveMultiscalarMulHandler),
        );
        dispatch.register_by_name("abort", Box::new(AbortHandler));
        dispatch.register_by_name("sol_panic_", Box::new(SolPanicHandler));

        // Feature-gated: ALT-BN128 group operations. The syscall itself is gated by
        // `enable_alt_bn128_syscall`; its little-endian and G2 sub-operations carry
        // their own gates inside the handler (SIMD-0284 / SIMD-0302).
        let little_endian_enabled = active_features.contains(FEATURE_ALT_BN128_LITTLE_ENDIAN);
        if active_features.contains(FEATURE_ENABLE_ALT_BN128_SYSCALL) {
            dispatch.register_by_name(
                "sol_alt_bn128_group_op",
                Box::new(SolAltBn128GroupOpHandler {
                    little_endian_enabled,
                    g2_enabled: active_features.contains(FEATURE_ENABLE_ALT_BN128_G2_SYSCALLS),
                }),
            );
        }

        // Feature-gated: ALT-BN128 compression
        if active_features.contains(FEATURE_ENABLE_ALT_BN128_COMPRESSION) {
            dispatch.register_by_name(
                "sol_alt_bn128_compression",
                Box::new(SolAltBn128CompressionHandler {
                    little_endian_enabled,
                }),
            );
        }

        // Feature-gated: Poseidon hash
        if active_features.contains(FEATURE_ENABLE_POSEIDON_SYSCALL) {
            dispatch.register_by_name("sol_poseidon", Box::new(SolPoseidonHandler));
        }

        // Feature-gated: Generic sysvar access (SIMD-0127)
        if active_features.contains(FEATURE_GET_SYSVAR_SYSCALL) {
            dispatch.register_by_name("sol_get_sysvar", Box::new(SolGetSysvarHandler));
        }

        // Feature-gated: Epoch stake query
        if active_features.contains(FEATURE_ENABLE_GET_EPOCH_STAKE) {
            dispatch.register_by_name("sol_get_epoch_stake", Box::new(SolGetEpochStakeHandler));
        }

        // Feature-gated: BLS12-381 curve operations
        if active_features.contains(FEATURE_ENABLE_BLS12_381_SYSCALL) {
            dispatch.register_by_name("sol_curve_decompress", Box::new(SolCurveDecompressHandler));
            dispatch.register_by_name("sol_curve_pairing_map", Box::new(SolCurvePairingMapHandler));
        }

        dispatch
    }

    /// Create a dispatcher using pubkey-based feature gate IDs.
    ///
    /// Unlike `with_features` (which uses string-based feature names),
    /// this constructor accepts the `active_features` set that flows through
    /// the `SysvarSnapshot` — the same 32-byte keys used throughout the
    /// execution pipeline. This is the preferred constructor for production
    /// execution paths.
    pub fn with_active_feature_ids(active_features: &std::collections::HashSet<[u8; 32]>) -> Self {
        use karstflow_ids::features;

        let mut dispatch = Self::new();

        // Always-available syscalls
        dispatch.register_by_name("sol_log_", Box::new(SolLogHandler));
        dispatch.register_by_name("sol_log_64_", Box::new(SolLog64Handler));
        dispatch.register_by_name(
            "sol_log_compute_units_",
            Box::new(SolLogComputeUnitsHandler),
        );
        dispatch.register_by_name("sol_log_data", Box::new(SolLogDataHandler));
        dispatch.register_by_name("sol_log_pubkey", Box::new(SolLogPubkeyHandler));
        dispatch.register_by_name("sol_memcpy_", Box::new(SolMemcpyHandler));
        dispatch.register_by_name("sol_memmove_", Box::new(SolMemmoveHandler));
        dispatch.register_by_name("sol_memcmp_", Box::new(SolMemcmpHandler));
        dispatch.register_by_name("sol_memset_", Box::new(SolMemsetHandler));
        dispatch.register_by_name("sol_sha256", Box::new(SolSha256Handler));
        dispatch.register_by_name("sol_keccak256", Box::new(SolKeccak256Handler));
        dispatch.register_by_name("sol_alloc_free_", Box::new(SolAllocHandler));
        dispatch.register_by_name(
            "sol_create_program_address",
            Box::new(SolCreateProgramAddressHandler),
        );
        dispatch.register_by_name(
            "sol_try_find_program_address",
            Box::new(SolTryFindProgramAddressHandler),
        );
        dispatch.register_by_name("sol_set_return_data", Box::new(SolSetReturnDataHandler));
        dispatch.register_by_name("sol_get_return_data", Box::new(SolGetReturnDataHandler));
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
        dispatch.register_by_name("sol_get_stack_height", Box::new(SolGetStackHeightHandler));
        dispatch.register_by_name(
            "sol_get_processed_sibling_instruction",
            Box::new(SolGetProcessedSiblingInstructionHandler),
        );
        dispatch.register_by_name(
            "sol_get_epoch_rewards_sysvar",
            Box::new(SolGetEpochRewardsSysvarHandler),
        );
        dispatch.register_by_name(
            "sol_secp256k1_recover",
            Box::new(SolSecp256k1RecoverHandler),
        );
        dispatch.register_by_name("abort", Box::new(AbortHandler));
        dispatch.register_by_name("sol_panic_", Box::new(SolPanicHandler));

        // Feature-gated: blake3
        if features::is_feature_active(active_features, &features::BLAKE3_SYSCALL_ENABLED) {
            dispatch.register_by_name("sol_blake3", Box::new(SolBlake3Handler));
        }

        // Feature-gated: sha512 (SIMD-0512)
        if features::is_feature_active(active_features, &features::ENABLE_SHA512_SYSCALL) {
            dispatch.register_by_name("sol_sha512", Box::new(SolSha512Handler));
        }

        // Feature-gated: curve25519 operations
        if features::is_feature_active(active_features, &features::CURVE25519_SYSCALL_ENABLED) {
            dispatch.register_by_name(
                "sol_curve_validate_point",
                Box::new(SolCurveValidatePointHandler),
            );
            dispatch.register_by_name("sol_curve_group_op", Box::new(SolCurveGroupOpHandler));
            dispatch.register_by_name(
                "sol_curve_multiscalar_mul",
                Box::new(SolCurveMultiscalarMulHandler),
            );
        }

        // Feature-gated: alt_bn128 group operations. The syscall as a whole is gated by
        // `enable_alt_bn128_syscall`; two families of sub-operations carry separate
        // gates that the handler enforces per call — the little-endian variants
        // (SIMD-0284) and the G2 operations (SIMD-0302).
        let little_endian_enabled =
            features::is_feature_active(active_features, &features::ALT_BN128_LITTLE_ENDIAN);
        if features::is_feature_active(active_features, &features::ENABLE_ALT_BN128_SYSCALL) {
            dispatch.register_by_name(
                "sol_alt_bn128_group_op",
                Box::new(SolAltBn128GroupOpHandler {
                    little_endian_enabled,
                    g2_enabled: features::is_feature_active(
                        active_features,
                        &features::ENABLE_ALT_BN128_G2_SYSCALLS,
                    ),
                }),
            );
        }

        // Feature-gated: alt_bn128 compression
        if features::is_feature_active(
            active_features,
            &features::ENABLE_ALT_BN128_COMPRESSION_SYSCALL,
        ) {
            dispatch.register_by_name(
                "sol_alt_bn128_compression",
                Box::new(SolAltBn128CompressionHandler {
                    little_endian_enabled,
                }),
            );
        }

        // Feature-gated: Poseidon hash
        if features::is_feature_active(active_features, &features::ENABLE_POSEIDON_SYSCALL) {
            dispatch.register_by_name("sol_poseidon", Box::new(SolPoseidonHandler));
        }

        // Feature-gated: generic sysvar access (SIMD-0127)
        // Always enabled since it's gated at a higher level by the consensus layer
        dispatch.register_by_name("sol_get_sysvar", Box::new(SolGetSysvarHandler));

        // Feature-gated: epoch stake query
        if features::is_feature_active(active_features, &features::ENABLE_GET_EPOCH_STAKE_SYSCALL) {
            dispatch.register_by_name("sol_get_epoch_stake", Box::new(SolGetEpochStakeHandler));
        }

        // Feature-gated: remaining compute units query
        if features::is_feature_active(
            active_features,
            &features::REMAINING_COMPUTE_UNITS_SYSCALL_ENABLED,
        ) {
            dispatch.register_by_name(
                "sol_remaining_compute_units",
                Box::new(SolRemainingComputeUnitsHandler),
            );
        }

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
            Box::new(SolInvokeCHandler {
                executor: executor.clone(),
            }),
        );
        dispatch.register_by_name(
            "sol_invoke_signed_rust",
            Box::new(SolInvokeRustHandler { executor }),
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
    fn has_handler(&self, syscall_id: u32) -> bool {
        self.handlers.contains_key(&syscall_id)
    }

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

        #[cfg(test)]
        eprintln!(
            "[SYSCALL] PC={} id=0x{:08X} r1=0x{:X} r2=0x{:X} r3=0x{:X} r4=0x{:X} r5=0x{:X}",
            vm.pc, syscall_id, r1, r2, r3, r4, r5
        );
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

/// Try to append a log message, enforcing the per-transaction log size limit.
///
/// Returns `true` if the message was appended, `false` if logs have been
/// truncated. On first truncation, emits a "Log truncated" sentinel.
fn try_append_log(vm: &mut VmState, msg: String) -> bool {
    use karstflow_constants::syscalls::MAX_LOG_COLLECTOR_SIZE;

    let new_total = vm.log_bytes_written.saturating_add(msg.len());
    if new_total > MAX_LOG_COLLECTOR_SIZE {
        if !vm.log_truncated {
            vm.log_truncated = true;
            vm.logs.push("Log truncated".to_string());
        }
        return false;
    }
    vm.log_bytes_written = new_total;
    vm.logs.push(msg);
    true
}

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
        try_append_log(vm, msg);

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
        try_append_log(
            vm,
            format!("Program log: {} {} {} {} {}", r1, r2, r3, r4, r5),
        );
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
        try_append_log(
            vm,
            format!("Program consumption: {} units remaining", vm.compute_meter),
        );
        Ok(0)
    }
}

/// sol_log_data: Log raw data buffers.
///
/// r1 = pointer to array of `SolBytes` entries (each: ptr u64, len u64),
/// r2 = number of entries.
struct SolLogDataHandler;

impl SyscallHandler for SolLogDataHandler {
    fn call(
        &self,
        vm: &mut VmState,
        r1: u64,
        r2: u64,
        _r3: u64,
        _r4: u64,
        _r5: u64,
    ) -> Result<u64, VmError> {
        let count = r2 as usize;
        deduct_compute(vm, syscalls::LOG_DATA_BASE_COST)?;

        if count == 0 {
            try_append_log(vm, "Program data: ".to_string());
            return Ok(0);
        }

        // Each SolBytes entry is 16 bytes: ptr (u64 LE) + len (u64 LE)
        let entries_bytes = vm
            .memory
            .read_slice(r1, count * 16)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;

        let mut parts = Vec::with_capacity(count);
        let mut total_bytes = 0u64;

        for i in 0..count {
            let base = i * 16;
            let ptr = u64::from_le_bytes(
                entries_bytes[base..base + 8]
                    .try_into()
                    .map_err(|_| VmError::MemoryError("invalid SolBytes ptr".to_string()))?,
            );
            let len = u64::from_le_bytes(
                entries_bytes[base + 8..base + 16]
                    .try_into()
                    .map_err(|_| VmError::MemoryError("invalid SolBytes len".to_string()))?,
            );
            total_bytes = total_bytes.saturating_add(len);

            let data = vm
                .memory
                .read_slice(ptr, len as usize)
                .map_err(|e| VmError::MemoryError(e.to_string()))?;
            parts.push(encode_base64(&data));
        }

        deduct_compute(vm, syscalls::LOG_PER_BYTE_COST * total_bytes)?;
        try_append_log(vm, format!("Program data: {}", parts.join(" ")));
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

        let data = vm.memory.read_slice(r2, len).map_err(|e| {
            #[cfg(test)]
            eprintln!(
                "[MEMCPY] read fail: src=0x{:X} len={} err={e} PC={}",
                r2, len, vm.pc
            );
            VmError::MemoryError(e.to_string())
        })?;
        vm.memory.write_slice(r1, &data).map_err(|e| {
            #[cfg(test)]
            eprintln!(
                "[MEMCPY] write fail: dst=0x{:X} len={} err={e} PC={}",
                r1, len, vm.pc
            );
            VmError::MemoryError(e.to_string())
        })?;

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
        r3: u64, // result pointer (32 bytes)
        _r4: u64,
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
            .write_slice(r3, &hash)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;

        Ok(0)
    }
}

/// sol_sha512: Compute SHA-512 hash (SIMD-0512). Gated behind the
/// `enable_sha512_syscall` feature; output is 64 bytes.
struct SolSha512Handler;

impl SyscallHandler for SolSha512Handler {
    fn call(
        &self,
        vm: &mut VmState,
        r1: u64, // input pairs pointer
        r2: u64, // pair count
        r3: u64, // result pointer (64 bytes)
        _r4: u64,
        _r5: u64,
    ) -> Result<u64, VmError> {
        let pair_count = r2 as usize;
        let data = read_hash_inputs(vm, r1, pair_count)?;

        let cost = syscalls::SHA512_BASE_COST + syscalls::SHA512_PER_BYTE_COST * data.len() as u64;
        deduct_compute(vm, cost)?;

        let mut hasher = Sha512::new();
        hasher.update(&data);
        let hash: [u8; 64] = hasher.finalize().into();

        vm.memory
            .write_slice(r3, &hash)
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
        r3: u64, // result pointer (32 bytes)
        _r4: u64,
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
            .write_slice(r3, &hash)
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
        r3: u64, // result pointer (32 bytes)
        _r4: u64,
        _r5: u64,
    ) -> Result<u64, VmError> {
        let pair_count = r2 as usize;
        let data = read_hash_inputs(vm, r1, pair_count)?;

        let cost = syscalls::BLAKE3_BASE_COST + syscalls::BLAKE3_PER_BYTE_COST * data.len() as u64;
        deduct_compute(vm, cost)?;

        let hash = blake3::hash(&data);
        let hash_bytes: [u8; 32] = *hash.as_bytes();

        vm.memory
            .write_slice(r3, &hash_bytes)
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

/// Refuse a syscall output pointer that targets the program input region.
///
/// A program can otherwise ask a sysvar getter to write over its own serialized
/// account buffer, which aliases memory the runtime also owns. The restriction
/// is feature-gated: before activation the write is permitted, so applying it
/// unconditionally would change behaviour on slots that predate the gate.
fn reject_input_region_output(vm: &VmState, out_vaddr: u64) -> Result<(), VmError> {
    if vm.syscall_parameter_address_restrictions
        && out_vaddr >= karstflow_constants::vm::REGION_INPUT_BASE
    {
        return Err(VmError::SyscallError(
            "invalid pointer: syscall output may not target the input region".to_string(),
        ));
    }
    Ok(())
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
        reject_input_region_output(vm, r1)?;

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
        reject_input_region_output(vm, r1)?;

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
        reject_input_region_output(vm, r1)?;

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
        reject_input_region_output(vm, r1)?;

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

/// Error text for an alt_bn128 operation rejected by an inactive feature gate.
///
/// Matches the `SyscallError::InvalidAttribute` outcome: a hard syscall failure
/// that aborts the instruction, not the soft `Ok(1)` return used for bad points.
const ALT_BN128_INVALID_ATTRIBUTE: &str = "invalid attribute";

/// sol_alt_bn128_group_op: BN254 elliptic curve group operation.
///
/// r1 = group_op (operation ID with optional LE flag in bit 7)
/// r2 = input address in VM memory
/// r3 = input size in bytes
/// r4 = result address in VM memory
/// Returns 0 on success, 1 on soft error (invalid point/input).
struct SolAltBn128GroupOpHandler {
    /// Whether `alt_bn128_little_endian` (SIMD-0284) is active.
    little_endian_enabled: bool,
    /// Whether `enable_alt_bn128_g2_syscalls` (SIMD-0302) is active.
    g2_enabled: bool,
}

impl SyscallHandler for SolAltBn128GroupOpHandler {
    fn call(
        &self,
        vm: &mut VmState,
        r1: u64, // group_op
        r2: u64, // input_addr
        r3: u64, // input_sz
        r4: u64, // result_addr
        _r5: u64,
    ) -> Result<u64, VmError> {
        // SIMD-0284: the little-endian variants of G1 add, G1 mul and pairing are
        // rejected until the feature activates. The G2 little-endian variants are
        // covered by the G2 gate below, not by this one.
        if !self.little_endian_enabled
            && matches!(
                r1,
                syscalls::ALT_BN128_G1_ADD_LE
                    | syscalls::ALT_BN128_G1_MUL_LE
                    | syscalls::ALT_BN128_PAIRING_LE
            )
        {
            return Err(VmError::SyscallError(
                ALT_BN128_INVALID_ATTRIBUTE.to_string(),
            ));
        }

        // SIMD-0302: the G2 operations are rejected until the feature activates,
        // in both endiannesses.
        if !self.g2_enabled
            && matches!(
                r1,
                syscalls::ALT_BN128_G2_ADD_BE
                    | syscalls::ALT_BN128_G2_MUL_BE
                    | syscalls::ALT_BN128_G2_ADD_LE
                    | syscalls::ALT_BN128_G2_MUL_LE
            )
        {
            return Err(VmError::SyscallError(
                ALT_BN128_INVALID_ATTRIBUTE.to_string(),
            ));
        }

        let input_sz = r3 as usize;
        let input = vm
            .memory
            .read_slice(r2, input_sz)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;

        // Determine output size based on operation
        let base_op = r1 & !syscalls::ALT_BN128_LITTLE_ENDIAN_FLAG;
        let output_sz = match base_op {
            syscalls::ALT_BN128_G1_ADD_BE
            | syscalls::ALT_BN128_G1_SUB_BE
            | syscalls::ALT_BN128_G1_MUL_BE => syscalls::ALT_BN128_G1_POINT_SIZE,
            syscalls::ALT_BN128_PAIRING_BE => syscalls::ALT_BN128_PAIRING_OUTPUT_SIZE,
            syscalls::ALT_BN128_G2_ADD_BE
            | syscalls::ALT_BN128_G2_SUB_BE
            | syscalls::ALT_BN128_G2_MUL_BE => syscalls::ALT_BN128_G2_POINT_SIZE,
            _ => {
                return Err(VmError::SyscallError(format!(
                    "invalid alt_bn128 group op: {}",
                    r1
                )));
            }
        };

        let mut output = vec![0u8; output_sz];
        let mut ctx = create_syscall_context(vm);

        let ret = match crate::syscalls::alt_bn128::group_op(&mut ctx, r1, &input, &mut output) {
            Ok(ret) => {
                vm.compute_meter = ctx.compute_meter;
                if ret == 0 {
                    vm.memory
                        .write_slice(r4, &output)
                        .map_err(|e| VmError::MemoryError(e.to_string()))?;
                }
                ret
            }
            Err(e) => {
                vm.compute_meter = ctx.compute_meter;
                return Err(VmError::SyscallError(e.to_string()));
            }
        };

        Ok(ret)
    }
}

/// sol_alt_bn128_compression: BN254 point compression/decompression.
///
/// r1 = operation ID (compress/decompress G1/G2, with optional LE flag)
/// r2 = input address in VM memory
/// r3 = input size in bytes
/// r4 = result address in VM memory
/// Returns 0 on success, 1 on soft error.
struct SolAltBn128CompressionHandler {
    /// Whether `alt_bn128_little_endian` (SIMD-0284) is active.
    little_endian_enabled: bool,
}

impl SyscallHandler for SolAltBn128CompressionHandler {
    fn call(
        &self,
        vm: &mut VmState,
        r1: u64, // op
        r2: u64, // input_addr
        r3: u64, // input_sz
        r4: u64, // result_addr
        _r5: u64,
    ) -> Result<u64, VmError> {
        // SIMD-0284: the little-endian compression variants are rejected until the
        // feature activates. Compression carries no G2 gate — the big-endian G2
        // compress/decompress operations are available unconditionally.
        if !self.little_endian_enabled
            && matches!(
                r1,
                syscalls::ALT_BN128_G1_COMPRESS_LE
                    | syscalls::ALT_BN128_G2_COMPRESS_LE
                    | syscalls::ALT_BN128_G1_DECOMPRESS_LE
                    | syscalls::ALT_BN128_G2_DECOMPRESS_LE
            )
        {
            return Err(VmError::SyscallError(
                ALT_BN128_INVALID_ATTRIBUTE.to_string(),
            ));
        }

        let input_sz = r3 as usize;
        let input = vm
            .memory
            .read_slice(r2, input_sz)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;

        // Determine output size based on operation
        let base_op = r1 & !syscalls::ALT_BN128_LITTLE_ENDIAN_FLAG;
        let output_sz = match base_op {
            syscalls::ALT_BN128_G1_COMPRESS_BE => syscalls::ALT_BN128_G1_COMPRESSED_SIZE,
            syscalls::ALT_BN128_G1_DECOMPRESS_BE => syscalls::ALT_BN128_G1_POINT_SIZE,
            syscalls::ALT_BN128_G2_COMPRESS_BE => syscalls::ALT_BN128_G2_COMPRESSED_SIZE,
            syscalls::ALT_BN128_G2_DECOMPRESS_BE => syscalls::ALT_BN128_G2_POINT_SIZE,
            _ => {
                return Err(VmError::SyscallError(format!(
                    "invalid alt_bn128 compression op: {}",
                    r1
                )));
            }
        };

        let mut output = vec![0u8; output_sz];
        let mut ctx = create_syscall_context(vm);

        let ret = match crate::syscalls::alt_bn128::compression(&mut ctx, r1, &input, &mut output) {
            Ok(ret) => {
                vm.compute_meter = ctx.compute_meter;
                if ret == 0 {
                    vm.memory
                        .write_slice(r4, &output)
                        .map_err(|e| VmError::MemoryError(e.to_string()))?;
                }
                ret
            }
            Err(e) => {
                vm.compute_meter = ctx.compute_meter;
                return Err(VmError::SyscallError(e.to_string()));
            }
        };

        Ok(ret)
    }
}

/// sol_poseidon: Poseidon hash over BN254 field elements.
///
/// r1 = parameter set (0 = Light protocol)
/// r2 = endianness (0 = big-endian, 1 = little-endian)
/// r3 = pointer to array of (addr, len) pairs in VM memory
/// r4 = number of input values
/// r5 = result address (32 bytes)
/// Returns 0 on success, 1 on soft error.
struct SolPoseidonHandler;

impl SyscallHandler for SolPoseidonHandler {
    fn call(
        &self,
        vm: &mut VmState,
        r1: u64, // params
        r2: u64, // endianness
        r3: u64, // vals_addr (pointer to array of vm_vec_t structs)
        r4: u64, // vals_len
        r5: u64, // result_addr
    ) -> Result<u64, VmError> {
        let vals_len = r4 as usize;

        // Validate parameter set
        if r1 != syscalls::POSEIDON_PARAMS_LIGHT {
            return Err(VmError::SyscallError(
                "invalid poseidon parameter set".into(),
            ));
        }

        // Validate endianness
        if r2 != syscalls::POSEIDON_ENDIAN_BIG && r2 != syscalls::POSEIDON_ENDIAN_LITTLE {
            return Err(VmError::SyscallError("invalid poseidon endianness".into()));
        }

        // Validate input count
        if vals_len > syscalls::POSEIDON_MAX_INPUTS {
            return Err(VmError::SyscallError(format!(
                "Poseidon hashing {} sequences is not supported",
                vals_len
            )));
        }

        // Compute cost: A * n^2 + C
        let cost = syscalls::POSEIDON_COST_COEFFICIENT_A
            .saturating_mul((vals_len as u64).saturating_mul(vals_len as u64))
            .saturating_add(syscalls::POSEIDON_COST_COEFFICIENT_C);
        deduct_compute(vm, cost)?;

        // Empty input returns soft error
        if vals_len == 0 {
            return Ok(1);
        }

        // Read the vector of (addr, len) pairs
        // Each entry is a vm_vec_t: u64 addr + u64 len = 16 bytes
        let vec_data = vm
            .memory
            .read_slice(r3, vals_len * 16)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;

        // Collect all input slices
        let mut inputs: Vec<Vec<u8>> = Vec::with_capacity(vals_len);
        for i in 0..vals_len {
            let offset = i * 16;
            let addr = u64::from_le_bytes(vec_data[offset..offset + 8].try_into().unwrap());
            let len = u64::from_le_bytes(vec_data[offset + 8..offset + 16].try_into().unwrap());
            let data = vm
                .memory
                .read_slice(addr, len as usize)
                .map_err(|e| VmError::MemoryError(e.to_string()))?;
            inputs.push(data);
        }

        let input_refs: Vec<&[u8]> = inputs.iter().map(|v| v.as_slice()).collect();
        let mut result = [0u8; 32];

        let mut ctx = create_syscall_context(vm);
        // We already deducted compute above, so give the poseidon_hash a large budget
        // and don't let it deduct again. Instead we pass directly to the internal function.
        let is_big_endian = r2 == syscalls::POSEIDON_ENDIAN_BIG;
        let ret = match compute_poseidon_hash(&input_refs, is_big_endian) {
            Ok(hash) => {
                result.copy_from_slice(&hash);
                vm.memory
                    .write_slice(r5, &result)
                    .map_err(|e| VmError::MemoryError(e.to_string()))?;
                0u64
            }
            Err(_) => 1u64,
        };

        // Restore compute meter from ctx (unused in this path)
        let _ = ctx;

        Ok(ret)
    }
}

/// Internal Poseidon computation helper.
fn compute_poseidon_hash(
    inputs: &[&[u8]],
    big_endian: bool,
) -> Result<[u8; 32], light_poseidon::PoseidonError> {
    use light_poseidon::{Poseidon, PoseidonBytesHasher};
    let mut hasher = Poseidon::<ark_bn254::Fr>::new_circom(inputs.len())?;
    if big_endian {
        hasher.hash_bytes_be(inputs)
    } else {
        hasher.hash_bytes_le(inputs)
    }
}

/// Create a SyscallContext from a VmState for use with the higher-level
/// syscall functions in the `syscalls` module.
fn create_syscall_context(vm: &VmState) -> crate::syscalls::SyscallContext {
    crate::syscalls::SyscallContext::new(karstflow_types::Pubkey::zeroed(), vm.compute_meter)
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
        try_append_log(vm, format!("Program log: {}", encoded));

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
        reject_input_region_output(vm, r1)?;

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
        reject_input_region_output(vm, r2)?;

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
        let heap_end = karstflow_constants::vm::REGION_HEAP_BASE + vm.memory.heap_size() as u64;

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
/// CPI handler for the C ABI (`sol_invoke_signed_c`).
/// Account data is read from the caller's serialized input region and
/// written back after execution for writable accounts.
struct SolInvokeCHandler {
    executor: Arc<dyn InstructionExecutor>,
}

/// CPI handler for the Rust ABI (`sol_invoke_signed_rust`).
/// Rust programs compiled with solana-program SDK use this variant.
struct SolInvokeRustHandler {
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
    let mut entries: Vec<InputRegionEntry> = Vec::with_capacity(account_count);
    let mut offset = 8;

    for _ in 0..account_count {
        if offset >= input.len() {
            break;
        }

        let marker = input[offset];
        if marker != karstflow_constants::vm::NON_DUP_MARKER {
            // Duplicate account — 8 bytes total, first byte is index to original
            let first_idx = marker as usize;
            if first_idx < entries.len() {
                entries.push(InputRegionEntry {
                    pubkey: entries[first_idx].pubkey,
                    offset: entries[first_idx].offset,
                });
            }
            offset += 8;
            continue;
        }

        // Non-duplicate: aligned format
        // NON_DUP_MARKER(1) + is_signer(1) + is_writable(1) + is_executable(1) + padding(4)
        let entry_offset = offset;
        let header_size = 8; // 1+1+1+1+4
        if offset + header_size + 32 > input.len() {
            break;
        }
        offset += header_size;

        // Read pubkey (32 bytes)
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&input[offset..offset + 32]);
        offset += 32;

        // Skip owner(32) + lamports(8) = 40
        offset += 40;

        // Read data_len(8)
        if offset + 8 > input.len() {
            break;
        }
        let data_len = u64::from_le_bytes(input[offset..offset + 8].try_into().unwrap()) as usize;
        offset += 8;

        // Skip data + realloc buffer + alignment padding + rent_epoch
        if offset + data_len > input.len() {
            break;
        }
        offset += data_len;
        offset += karstflow_constants::vm::MAX_PERMITTED_DATA_INCREASE;
        let align_offset = data_len.wrapping_neg() & (karstflow_constants::vm::ALIGN_OF_U128 - 1);
        offset += align_offset;
        offset += 8; // rent_epoch

        entries.push(InputRegionEntry {
            pubkey: Pubkey::new(pk),
            offset: entry_offset,
        });
    }

    entries
}

/// Read an Account from the input region at the given byte offset.
/// Offset must point to the NON_DUP_MARKER byte of a non-duplicate account.
fn read_account_from_input(input: &[u8], offset: usize) -> Option<(bool, Account)> {
    // Aligned format: NON_DUP_MARKER(1) + is_signer(1) + is_writable(1) + is_executable(1) + padding(4)
    //                 + pubkey(32) + owner(32) + lamports(8) + data_len(8) + data
    let header_size = 8; // 1+1+1+1+4
    if offset + header_size + 32 + 32 + 8 + 8 > input.len() {
        return None;
    }

    let _marker = input[offset]; // NON_DUP_MARKER
    let _is_signer = input[offset + 1];
    let is_writable = input[offset + 2] != 0;
    let is_executable = input[offset + 3] != 0;
    let pos = offset + header_size;

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
                executable: is_executable,
                rent_epoch: 0,
            },
            data: AccountData::new(data.to_vec()),
        },
    ))
}

/// Write modified account data back to the input region after CPI.
/// Updates lamports, owner, data_len, and data bytes.
/// Account data may grow within the realloc buffer (MAX_PERMITTED_DATA_INCREASE).
fn writeback_account_to_input(
    input: &mut [u8],
    offset: usize,
    account: &Account,
) -> Result<(), VmError> {
    // Aligned format: skip NON_DUP_MARKER(1) + is_signer(1) + is_writable(1) + is_executable(1) + padding(4) + pubkey(32)
    let pos = offset + 8 + 32;

    // Write owner (32 bytes)
    input[pos..pos + 32].copy_from_slice(account.meta.owner.as_ref());
    let pos = pos + 32;

    // Write lamports (8 bytes)
    input[pos..pos + 8].copy_from_slice(&account.meta.lamports.to_le_bytes());
    let pos = pos + 8;

    // Read original data_len to check growth bounds
    let original_data_len = u64::from_le_bytes(input[pos..pos + 8].try_into().unwrap()) as usize;

    let new_data = account.data.as_slice();
    let max_allowed =
        original_data_len.saturating_add(karstflow_constants::vm::MAX_PERMITTED_DATA_INCREASE);
    if new_data.len() > max_allowed {
        return Err(VmError::MemoryError(
            "CPI callee cannot grow account data beyond realloc limit".to_string(),
        ));
    }

    // Update data_len to new size
    input[pos..pos + 8].copy_from_slice(&(new_data.len() as u64).to_le_bytes());
    let pos = pos + 8;

    // Write data (may be shorter or longer than original; zero-fill remainder within original allocation)
    input[pos..pos + new_data.len()].copy_from_slice(new_data);
    if new_data.len() < original_data_len {
        input[pos + new_data.len()..pos + original_data_len].fill(0);
    }

    Ok(())
}

/// Result of PDA signer derivation from CPI signer seeds.
enum PdaSignerResult {
    /// Successfully derived PDA signers.
    Ok(std::collections::HashSet<Pubkey>),
    /// Validation failure — return this value to the caller program.
    Failed(u64),
    /// VM-level error (memory access violation).
    VmError(VmError),
}

/// Derive PDA signers from signer seeds in VM memory.
/// Layout: r4 points to array of (addr: u64, len: u64) = 16 bytes each.
/// Each entry points to an array of seed slices (addr: u64, len: u64).
fn derive_pda_signers(vm: &mut VmState, r4: u64, r5: u64) -> PdaSignerResult {
    let signer_seeds_count = r5 as usize;
    let mut pda_signers = std::collections::HashSet::new();
    if signer_seeds_count == 0 || signer_seeds_count > syscalls::MAX_CPI_SIGNERS {
        return PdaSignerResult::Ok(pda_signers);
    }
    let caller_program_id = vm.program_id;
    for s in 0..signer_seeds_count {
        let entry_offset = r4 + (s as u64) * 16;
        let entry_bytes = match vm.memory.read_slice(entry_offset, 16) {
            Ok(b) => b,
            Err(e) => return PdaSignerResult::VmError(VmError::MemoryError(e.to_string())),
        };
        let seeds_ptr = u64::from_le_bytes(entry_bytes[0..8].try_into().unwrap());
        let seeds_len = u64::from_le_bytes(entry_bytes[8..16].try_into().unwrap()) as usize;

        if seeds_len > syscalls::MAX_SIGNER_SEEDS {
            try_append_log(vm, "Too many seeds for PDA signer".to_string());
            return PdaSignerResult::Failed(1);
        }

        let mut seed_data = Vec::with_capacity(seeds_len);
        for i in 0..seeds_len {
            let pair_offset = seeds_ptr + (i as u64) * 16;
            let ptr_bytes = match vm.memory.read_slice(pair_offset, 8) {
                Ok(b) => b,
                Err(e) => return PdaSignerResult::VmError(VmError::MemoryError(e.to_string())),
            };
            let len_bytes = match vm.memory.read_slice(pair_offset + 8, 8) {
                Ok(b) => b,
                Err(e) => return PdaSignerResult::VmError(VmError::MemoryError(e.to_string())),
            };
            let ptr = u64::from_le_bytes(ptr_bytes.try_into().unwrap());
            let len = u64::from_le_bytes(len_bytes.try_into().unwrap()) as usize;
            if len > syscalls::MAX_SEED_BYTES {
                try_append_log(vm, "Seed too long for PDA signer".to_string());
                return PdaSignerResult::Failed(1);
            }
            let seed = match vm.memory.read_slice(ptr, len) {
                Ok(b) => b,
                Err(e) => return PdaSignerResult::VmError(VmError::MemoryError(e.to_string())),
            };
            seed_data.push(seed);
        }

        let mut hasher = Sha256::new();
        for seed in &seed_data {
            hasher.update(seed);
        }
        hasher.update(caller_program_id.as_ref());
        hasher.update(b"ProgramDerivedAddress");
        let hash: [u8; 32] = hasher.finalize().into();

        if is_on_ed25519_curve(&hash) {
            try_append_log(vm, "Derived address is on ed25519 curve".to_string());
            return PdaSignerResult::Failed(1);
        }

        pda_signers.insert(Pubkey::new(hash));
    }
    PdaSignerResult::Ok(pda_signers)
}

/// Which ABI the CPI caller uses — determines how to update AccountInfo after CPI.
enum CpiCallerAbi {
    /// C ABI: SolAccountInfo has `data_len` at offset 16 and each struct is 56 bytes.
    C,
    /// Rust ABI: AccountInfo has Rc<RefCell<&mut [u8]>> at offset 16; data len is
    /// inside the RcBox at +32 from the Rc pointer.
    Rust,
}

/// Common CPI execution: resolve accounts, dispatch, writeback.
#[allow(clippy::too_many_arguments)]
fn execute_cpi(
    executor: &Arc<dyn InstructionExecutor>,
    vm: &mut VmState,
    target_program_id: Pubkey,
    instruction_data: Vec<u8>,
    cpi_account_metas: &[(Pubkey, bool, bool)], // (pubkey, is_signer, is_writable)
    pda_signers: std::collections::HashSet<Pubkey>,
    caller_abi: CpiCallerAbi,
    account_infos_addr: u64,
    account_infos_count: usize,
) -> Result<u64, VmError> {
    // Scan the input region to build an offset table for account lookup
    let input_data = vm.memory.input_data().to_vec();
    let input_entries = scan_input_region(&input_data);

    // Build the signers set: accounts marked as signer + PDA-derived signers
    let mut signers = pda_signers;
    for (pubkey, is_signer, _is_writable) in cpi_account_metas {
        if *is_signer {
            signers.insert(*pubkey);
        }
    }

    // Capture original data lengths before CPI for writeback comparison
    let mut original_data_lens: Vec<(Pubkey, usize)> = Vec::new();
    let mut accounts = Vec::new();
    for (pubkey, _is_signer, is_writable) in cpi_account_metas {
        let account = if let Some(entry) = input_entries.iter().find(|e| e.pubkey == *pubkey) {
            if let Some((_is_wr, acct)) = read_account_from_input(&input_data, entry.offset) {
                original_data_lens.push((*pubkey, acct.data.as_slice().len()));
                acct
            } else {
                original_data_lens.push((*pubkey, 0));
                Account::default()
            }
        } else {
            original_data_lens.push((*pubkey, 0));
            Account::default()
        };
        accounts.push((*pubkey, account, *is_writable));
    }

    let context =
        ExecutionContext::new(target_program_id, accounts, instruction_data).with_signers(signers);

    vm.cpi_depth += 1;
    let result = executor.execute_instruction(context);
    vm.cpi_depth -= 1;

    match result {
        Ok(outcome) => {
            if outcome.success {
                let input_mut = unsafe {
                    let ptr = vm.memory.input_data().as_ptr() as *mut u8;
                    let len = vm.memory.input_data().len();
                    std::slice::from_raw_parts_mut(ptr, len)
                };

                // Collect data len changes for caller account update
                let mut data_len_changes: Vec<(Pubkey, usize)> = Vec::new();

                for (pubkey, modified_account) in &outcome.modified_accounts {
                    if let Some(entry) = input_entries.iter().find(|e| e.pubkey == *pubkey) {
                        let is_writable = cpi_account_metas
                            .iter()
                            .any(|(pk, _, w)| pk == pubkey && *w);
                        if is_writable {
                            let new_data_len = modified_account.data.as_slice().len();
                            let old_data_len = original_data_lens
                                .iter()
                                .find(|(pk, _)| pk == pubkey)
                                .map(|(_, len)| *len)
                                .unwrap_or(0);
                            if new_data_len != old_data_len {
                                data_len_changes.push((*pubkey, new_data_len));
                            }
                            writeback_account_to_input(input_mut, entry.offset, modified_account)?;
                        }
                    }
                }

                // Update caller's AccountInfo data lengths in BPF memory
                if !data_len_changes.is_empty() {
                    update_caller_account_data_lens(
                        vm,
                        &caller_abi,
                        account_infos_addr,
                        account_infos_count,
                        &data_len_changes,
                    );
                }
            }

            for log in &outcome.logs {
                if !try_append_log(vm, log.clone()) {
                    break;
                }
            }

            if let Some(data) = outcome.return_data {
                vm.return_data = Some(data);
            }

            if vm.compute_meter >= outcome.compute_units_consumed {
                vm.compute_meter -= outcome.compute_units_consumed;
            } else {
                vm.compute_meter = 0;
                return Err(VmError::ComputeBudgetExceeded);
            }

            if outcome.success {
                Ok(0)
            } else {
                Ok(1)
            }
        }
        Err(_) => Ok(1),
    }
}

/// Update the caller BPF program's AccountInfo data lengths after CPI changed them.
///
/// For C ABI: `SolAccountInfo.data_len` is a plain u64 field at offset 16 in a 56-byte struct.
/// For Rust ABI: `AccountInfo.data` is `Rc<RefCell<&mut [u8]>>` at offset 16; the fat pointer
/// length lives at RcBox + 32 (after strong:8 + weak:8 + borrow_flag:8 + data_ptr:8).
fn update_caller_account_data_lens(
    vm: &mut VmState,
    caller_abi: &CpiCallerAbi,
    account_infos_addr: u64,
    account_infos_count: usize,
    data_len_changes: &[(Pubkey, usize)],
) {
    for i in 0..account_infos_count {
        let (pubkey, key_ok) = match caller_abi {
            CpiCallerAbi::C => read_c_account_info_pubkey(vm, account_infos_addr, i),
            CpiCallerAbi::Rust => read_rust_account_info_pubkey(vm, account_infos_addr, i),
        };
        if !key_ok {
            continue;
        }

        if let Some((_, new_len)) = data_len_changes.iter().find(|(pk, _)| *pk == pubkey) {
            match caller_abi {
                CpiCallerAbi::C => {
                    // SolAccountInfo is 56 bytes; data_len at offset 16
                    let data_len_addr = account_infos_addr + (i as u64) * 56 + 16;
                    let _ = vm
                        .memory
                        .write_slice(data_len_addr, &(*new_len as u64).to_le_bytes());
                }
                CpiCallerAbi::Rust => {
                    // AccountInfo is 48 bytes; Rc pointer at offset 16
                    let rc_ptr_addr = account_infos_addr + (i as u64) * 48 + 16;
                    if let Ok(rc_ptr_bytes) = vm.memory.read_slice(rc_ptr_addr, 8) {
                        let rc_ptr = u64::from_le_bytes(rc_ptr_bytes.try_into().unwrap());
                        // RcBox layout: strong(8) + weak(8) + borrow_flag(8) + data_ptr(8) + len(8)
                        // len is at rc_ptr + 32
                        let len_addr = rc_ptr + 32;
                        let _ = vm
                            .memory
                            .write_slice(len_addr, &(*new_len as u64).to_le_bytes());
                    }
                }
            }
        }
    }
}

/// Read pubkey from C ABI SolAccountInfo at index `i`.
fn read_c_account_info_pubkey(vm: &VmState, account_infos_addr: u64, i: usize) -> (Pubkey, bool) {
    // SolAccountInfo is 56 bytes; key pointer at offset 0
    let info_addr = account_infos_addr + (i as u64) * 56;
    let key_ptr_bytes = match vm.memory.read_slice(info_addr, 8) {
        Ok(b) => b,
        Err(_) => return (Pubkey::default(), false),
    };
    let key_ptr = u64::from_le_bytes(key_ptr_bytes.try_into().unwrap());
    let pk_bytes = match vm.memory.read_slice(key_ptr, 32) {
        Ok(b) => b,
        Err(_) => return (Pubkey::default(), false),
    };
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&pk_bytes);
    (Pubkey::new(pk), true)
}

/// Read pubkey from Rust ABI AccountInfo at index `i`.
fn read_rust_account_info_pubkey(
    vm: &VmState,
    account_infos_addr: u64,
    i: usize,
) -> (Pubkey, bool) {
    // AccountInfo is 48 bytes; key pointer at offset 0
    let info_addr = account_infos_addr + (i as u64) * 48;
    let key_ptr_bytes = match vm.memory.read_slice(info_addr, 8) {
        Ok(b) => b,
        Err(_) => return (Pubkey::default(), false),
    };
    let key_ptr = u64::from_le_bytes(key_ptr_bytes.try_into().unwrap());
    let pk_bytes = match vm.memory.read_slice(key_ptr, 32) {
        Ok(b) => b,
        Err(_) => return (Pubkey::default(), false),
    };
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&pk_bytes);
    (Pubkey::new(pk), true)
}

impl SyscallHandler for SolInvokeCHandler {
    fn call(
        &self,
        vm: &mut VmState,
        r1: u64, // instruction pointer (C ABI)
        r2: u64, // account infos pointer
        r3: u64, // account infos count
        r4: u64, // signer seeds pointer
        r5: u64, // signer seeds count
    ) -> Result<u64, VmError> {
        let account_count = r3 as usize;
        // Flat invoke cost (reference CPI compute model, SIMD-0339).
        deduct_compute(vm, syscalls::CPI_INVOKE_UNITS)?;

        if vm.cpi_depth >= syscalls::MAX_CPI_DEPTH {
            try_append_log(vm, "CPI depth limit exceeded".to_string());
            return Ok(1);
        }

        // C ABI layout: program_id_ptr(8) + accounts_ptr(8) + accounts_len(8) + data_ptr(8) + data_len(8) = 40
        let instr_bytes = vm
            .memory
            .read_slice(r1, 40)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;

        let program_id_ptr = u64::from_le_bytes(instr_bytes[0..8].try_into().unwrap());
        let acct_metas_ptr = u64::from_le_bytes(instr_bytes[8..16].try_into().unwrap());
        let acct_metas_len = u64::from_le_bytes(instr_bytes[16..24].try_into().unwrap()) as usize;
        let data_ptr = u64::from_le_bytes(instr_bytes[24..32].try_into().unwrap());
        let data_len = u64::from_le_bytes(instr_bytes[32..40].try_into().unwrap()) as usize;

        if acct_metas_len > syscalls::MAX_CPI_INSTRUCTION_ACCOUNTS {
            try_append_log(vm, "Too many CPI instruction accounts".to_string());
            return Ok(1);
        }
        if data_len > syscalls::MAX_CPI_INSTRUCTION_SIZE {
            try_append_log(vm, "CPI instruction data too large".to_string());
            return Ok(1);
        }

        let program_id_bytes = vm
            .memory
            .read_slice(program_id_ptr, 32)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;
        let mut pid = [0u8; 32];
        pid.copy_from_slice(&program_id_bytes);
        let target_program_id = Pubkey::new(pid);

        let instruction_data = if data_len > 0 {
            vm.memory
                .read_slice(data_ptr, data_len)
                .map_err(|e| VmError::MemoryError(e.to_string()))?
        } else {
            vec![]
        };
        // Instruction translation cost: instruction data + account metas.
        let instr_translation = (data_len as u64) / syscalls::CPI_BYTES_PER_UNIT
            + (acct_metas_len as u64).saturating_mul(syscalls::CPI_RUST_ACCOUNT_META_SIZE)
                / syscalls::CPI_BYTES_PER_UNIT;
        deduct_compute(vm, instr_translation)?;
        // Account-info translation: cap then proportional cost.
        if account_count > syscalls::MAX_CPI_ACCOUNT_INFOS {
            try_append_log(vm, "Too many CPI account infos".to_string());
            return Ok(1);
        }
        deduct_compute(
            vm,
            (account_count as u64).saturating_mul(syscalls::CPI_ACCOUNT_INFO_BYTE_SIZE)
                / syscalls::CPI_BYTES_PER_UNIT,
        )?;

        // C ABI AccountMeta: (pubkey_addr:u64, is_writable:u8, is_signer:u8, pad[6]) = 16 bytes
        let mut cpi_account_metas = Vec::with_capacity(acct_metas_len);
        for i in 0..acct_metas_len {
            let meta_offset = acct_metas_ptr + (i as u64) * 16;
            let meta_bytes = vm
                .memory
                .read_slice(meta_offset, 16)
                .map_err(|e| VmError::MemoryError(e.to_string()))?;

            let pk_ptr = u64::from_le_bytes(meta_bytes[0..8].try_into().unwrap());
            let is_writable = meta_bytes[8] != 0;
            let is_signer = meta_bytes[9] != 0;

            let pk_bytes = vm
                .memory
                .read_slice(pk_ptr, 32)
                .map_err(|e| VmError::MemoryError(e.to_string()))?;
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&pk_bytes);

            cpi_account_metas.push((Pubkey::new(pk), is_signer, is_writable));
        }

        // Derive PDA signers
        let pda_signers = match derive_pda_signers(vm, r4, r5) {
            PdaSignerResult::Ok(signers) => signers,
            PdaSignerResult::Failed(code) => return Ok(code),
            PdaSignerResult::VmError(e) => return Err(e),
        };

        execute_cpi(
            &self.executor,
            vm,
            target_program_id,
            instruction_data,
            &cpi_account_metas,
            pda_signers,
            CpiCallerAbi::C,
            r2,
            account_count,
        )
    }
}

impl SyscallHandler for SolInvokeRustHandler {
    fn call(
        &self,
        vm: &mut VmState,
        r1: u64, // instruction pointer (Rust ABI)
        r2: u64, // account infos pointer (unused — accounts come from input region)
        r3: u64, // account infos count
        r4: u64, // signer seeds pointer
        r5: u64, // signer seeds count
    ) -> Result<u64, VmError> {
        let account_count = r3 as usize;
        // Flat invoke cost (reference CPI compute model, SIMD-0339).
        deduct_compute(vm, syscalls::CPI_INVOKE_UNITS)?;

        if vm.cpi_depth >= syscalls::MAX_CPI_DEPTH {
            try_append_log(vm, "CPI depth limit exceeded".to_string());
            return Ok(1);
        }

        // Rust ABI Instruction layout (80 bytes):
        //   [0..24]  accounts Vec: (addr:8, cap:8, len:8)
        //   [24..48] data Vec:     (addr:8, cap:8, len:8)
        //   [48..80] program_id:   [u8; 32] inline
        let instr_bytes = vm
            .memory
            .read_slice(r1, 80)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;

        let acct_metas_ptr = u64::from_le_bytes(instr_bytes[0..8].try_into().unwrap());
        let _acct_metas_cap = u64::from_le_bytes(instr_bytes[8..16].try_into().unwrap());
        let acct_metas_len = u64::from_le_bytes(instr_bytes[16..24].try_into().unwrap()) as usize;
        let data_ptr = u64::from_le_bytes(instr_bytes[24..32].try_into().unwrap());
        let _data_cap = u64::from_le_bytes(instr_bytes[32..40].try_into().unwrap());
        let data_len = u64::from_le_bytes(instr_bytes[40..48].try_into().unwrap()) as usize;
        let mut pid = [0u8; 32];
        pid.copy_from_slice(&instr_bytes[48..80]);
        let target_program_id = Pubkey::new(pid);

        if acct_metas_len > syscalls::MAX_CPI_INSTRUCTION_ACCOUNTS {
            try_append_log(vm, "Too many CPI instruction accounts".to_string());
            return Ok(1);
        }
        if data_len > syscalls::MAX_CPI_INSTRUCTION_SIZE {
            try_append_log(vm, "CPI instruction data too large".to_string());
            return Ok(1);
        }

        let instruction_data = if data_len > 0 {
            vm.memory
                .read_slice(data_ptr, data_len)
                .map_err(|e| VmError::MemoryError(e.to_string()))?
        } else {
            vec![]
        };
        // Instruction translation cost: instruction data + account metas.
        let instr_translation = (data_len as u64) / syscalls::CPI_BYTES_PER_UNIT
            + (acct_metas_len as u64).saturating_mul(syscalls::CPI_RUST_ACCOUNT_META_SIZE)
                / syscalls::CPI_BYTES_PER_UNIT;
        deduct_compute(vm, instr_translation)?;
        // Account-info translation: cap then proportional cost.
        if account_count > syscalls::MAX_CPI_ACCOUNT_INFOS {
            try_append_log(vm, "Too many CPI account infos".to_string());
            return Ok(1);
        }
        deduct_compute(
            vm,
            (account_count as u64).saturating_mul(syscalls::CPI_ACCOUNT_INFO_BYTE_SIZE)
                / syscalls::CPI_BYTES_PER_UNIT,
        )?;

        // Rust ABI AccountMeta: (pubkey:[u8;32], is_signer:u8, is_writable:u8) = 34 bytes packed
        let mut cpi_account_metas = Vec::with_capacity(acct_metas_len);
        for i in 0..acct_metas_len {
            let meta_offset = acct_metas_ptr + (i as u64) * 34;
            let meta_bytes = vm
                .memory
                .read_slice(meta_offset, 34)
                .map_err(|e| VmError::MemoryError(e.to_string()))?;

            let mut pk = [0u8; 32];
            pk.copy_from_slice(&meta_bytes[0..32]);
            let is_signer = meta_bytes[32] != 0;
            let is_writable = meta_bytes[33] != 0;

            cpi_account_metas.push((Pubkey::new(pk), is_signer, is_writable));
        }

        // Derive PDA signers
        let pda_signers = match derive_pda_signers(vm, r4, r5) {
            PdaSignerResult::Ok(signers) => signers,
            PdaSignerResult::Failed(code) => return Ok(code),
            PdaSignerResult::VmError(e) => return Err(e),
        };

        execute_cpi(
            &self.executor,
            vm,
            target_program_id,
            instruction_data,
            &cpi_account_metas,
            pda_signers,
            CpiCallerAbi::Rust,
            r2,
            account_count,
        )
    }
}

// ---------------------------------------------------------------------------
// abort / sol_panic_ — VM termination syscalls
// ---------------------------------------------------------------------------

/// abort: Immediately fail the transaction with no compute cost.
struct AbortHandler;

impl SyscallHandler for AbortHandler {
    fn call(
        &self,
        _vm: &mut VmState,
        _r1: u64,
        _r2: u64,
        _r3: u64,
        _r4: u64,
        _r5: u64,
    ) -> Result<u64, VmError> {
        Err(VmError::SyscallError("abort".to_string()))
    }
}

/// sol_panic_: Log a panic message and fail the transaction.
///
/// r1 = pointer to message, r2 = message length, r3 = line, r4 = column.
/// Compute cost: proportional to message length.
struct SolPanicHandler;

impl SyscallHandler for SolPanicHandler {
    fn call(
        &self,
        vm: &mut VmState,
        r1: u64,
        r2: u64,
        _r3: u64,
        _r4: u64,
        _r5: u64,
    ) -> Result<u64, VmError> {
        let msg_len = r2 as usize;

        // Deduct compute proportional to message length.
        deduct_compute(vm, msg_len as u64 * syscalls::PANIC_PER_BYTE_COST)?;

        // Read and validate the message string from VM memory.
        let msg_bytes = vm
            .memory
            .read_slice(r1, msg_len)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;

        // Validate UTF-8 — invalid strings produce an error.
        let msg = std::str::from_utf8(&msg_bytes)
            .map_err(|_| VmError::SyscallError("panic: invalid UTF-8 string".to_string()))?;

        try_append_log(vm, format!("Program panic: {}", msg));
        Err(VmError::SyscallError(format!("panic: {}", msg)))
    }
}

// ---------------------------------------------------------------------------
// BLS12-381 syscalls
// ---------------------------------------------------------------------------

/// sol_curve_decompress: Decompress BLS12-381 curve points (G1/G2).
///
/// Feature-gated by `enable_bls12_381_syscall`. Supports both big-endian
/// and little-endian encodings via the 0x80 flag on the curve_id.
struct SolCurveDecompressHandler;

impl SyscallHandler for SolCurveDecompressHandler {
    fn call(
        &self,
        vm: &mut VmState,
        r1: u64, // curve_id (with optional LE flag in bit 7)
        r2: u64, // point_addr
        r3: u64, // result_addr
        _r4: u64,
        _r5: u64,
    ) -> Result<u64, VmError> {
        let base_id = r1 & !syscalls::BLS12_381_LITTLE_ENDIAN_FLAG;
        let big_endian = (r1 & syscalls::BLS12_381_LITTLE_ENDIAN_FLAG) == 0;

        let (input_sz, output_sz, cost) = match base_id {
            syscalls::CURVE_ID_BLS12_381_G1 => (
                syscalls::BLS12_381_G1_COMPRESSED_SIZE,
                syscalls::BLS12_381_G1_POINT_SIZE,
                syscalls::BLS12_381_G1_DECOMPRESS_COST,
            ),
            syscalls::CURVE_ID_BLS12_381_G2 => (
                syscalls::BLS12_381_G2_COMPRESSED_SIZE,
                syscalls::BLS12_381_G2_POINT_SIZE,
                syscalls::BLS12_381_G2_DECOMPRESS_COST,
            ),
            _ => return Ok(1),
        };
        deduct_compute(vm, cost)?;

        let input = vm
            .memory
            .read_slice(r2, input_sz)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;

        let mut output = vec![0u8; output_sz];
        let mut ctx = create_syscall_context(vm);

        let ret = match base_id {
            syscalls::CURVE_ID_BLS12_381_G1 => {
                crate::syscalls::g1_decompress(&mut ctx, &input, &mut output, big_endian)
                    .unwrap_or(1)
            }
            syscalls::CURVE_ID_BLS12_381_G2 => {
                crate::syscalls::g2_decompress(&mut ctx, &input, &mut output, big_endian)
                    .unwrap_or(1)
            }
            _ => 1,
        };

        vm.compute_meter = ctx.compute_meter;
        if ret == 0 {
            vm.memory
                .write_slice(r3, &output)
                .map_err(|e| VmError::MemoryError(e.to_string()))?;
        }

        Ok(ret)
    }
}

/// sol_curve_pairing_map: Compute BLS12-381 multi-pairing.
///
/// Takes N pairs of (G1, G2) affine points and computes the product of
/// pairings. Supports big-endian and little-endian via the 0x80 flag.
struct SolCurvePairingMapHandler;

impl SyscallHandler for SolCurvePairingMapHandler {
    fn call(
        &self,
        vm: &mut VmState,
        r1: u64, // curve_id (with optional LE flag in bit 7)
        r2: u64, // num_pairs
        r3: u64, // g1_points_addr
        r4: u64, // g2_points_addr
        r5: u64, // result_addr
    ) -> Result<u64, VmError> {
        let base_id = r1 & !syscalls::BLS12_381_LITTLE_ENDIAN_FLAG;
        let big_endian = (r1 & syscalls::BLS12_381_LITTLE_ENDIAN_FLAG) == 0;

        if base_id != syscalls::CURVE_ID_BLS12_381_G1 {
            return Ok(1);
        }

        let num_pairs = r2 as usize;
        if num_pairs == 0 || num_pairs > syscalls::BLS12_381_MAX_PAIRING_PAIRS {
            return Ok(1);
        }

        let cost = syscalls::BLS12_381_PAIRING_BASE_COST
            + (num_pairs as u64).saturating_sub(1) * syscalls::BLS12_381_PAIRING_PER_PAIR_COST;
        deduct_compute(vm, cost)?;

        let g1_sz = num_pairs * syscalls::BLS12_381_G1_POINT_SIZE;
        let g2_sz = num_pairs * syscalls::BLS12_381_G2_POINT_SIZE;

        let g1_data = vm
            .memory
            .read_slice(r3, g1_sz)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;
        let g2_data = vm
            .memory
            .read_slice(r4, g2_sz)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;

        let mut output = vec![0u8; syscalls::BLS12_381_GT_ELEMENT_SIZE];
        let mut ctx = create_syscall_context(vm);

        let ret = crate::syscalls::pairing_map(
            &mut ctx,
            &g1_data,
            &g2_data,
            num_pairs,
            &mut output,
            big_endian,
        )
        .unwrap_or(1);

        vm.compute_meter = ctx.compute_meter;
        if ret == 0 {
            vm.memory
                .write_slice(r5, &output)
                .map_err(|e| VmError::MemoryError(e.to_string()))?;
        }

        Ok(ret)
    }
}

// ---------------------------------------------------------------------------
// Remaining compute units syscall
// ---------------------------------------------------------------------------

/// sol_remaining_compute_units: Returns the number of compute units remaining.
struct SolRemainingComputeUnitsHandler;

impl SyscallHandler for SolRemainingComputeUnitsHandler {
    fn call(
        &self,
        vm: &mut VmState,
        _r1: u64,
        _r2: u64,
        _r3: u64,
        _r4: u64,
        _r5: u64,
    ) -> Result<u64, VmError> {
        deduct_compute(vm, syscalls::GET_REMAINING_COMPUTE_UNITS_COST)?;
        Ok(vm.compute_meter)
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

/// Minimal base64 encoding without external dependencies.
fn encode_base64(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
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
    use karstflow_constants::vm::{
        DEFAULT_HEAP_SIZE, REGION_HEAP_BASE, REGION_INPUT_BASE, TOTAL_STACK_SIZE,
    };

    /// Reference CPI compute model (agave v4 / SIMD-0339): flat invoke cost plus
    /// per-component translation costs at CPI_BYTES_PER_UNIT. Guards against
    /// accidental drift of the CPI cost constants away from the reference.
    fn cpi_total_cost(data_len: u64, instr_accounts: u64, account_infos: u64) -> u64 {
        syscalls::CPI_INVOKE_UNITS
            + data_len / syscalls::CPI_BYTES_PER_UNIT
            + instr_accounts.saturating_mul(syscalls::CPI_RUST_ACCOUNT_META_SIZE)
                / syscalls::CPI_BYTES_PER_UNIT
            + account_infos.saturating_mul(syscalls::CPI_ACCOUNT_INFO_BYTE_SIZE)
                / syscalls::CPI_BYTES_PER_UNIT
    }

    #[test]
    fn cpi_compute_cost_matches_reference_model() {
        // Constants pinned to the reference (FD_VM_*).
        assert_eq!(syscalls::CPI_INVOKE_UNITS, 946);
        assert_eq!(syscalls::CPI_BYTES_PER_UNIT, 250);
        assert_eq!(syscalls::CPI_RUST_ACCOUNT_META_SIZE, 34);
        assert_eq!(syscalls::CPI_ACCOUNT_INFO_BYTE_SIZE, 80);
        assert_eq!(syscalls::MAX_CPI_ACCOUNT_INFOS, 255);

        // Minimal CPI: only the flat invoke cost (all divided terms round to 0).
        assert_eq!(cpi_total_cost(0, 0, 0), 946);
        // data 100/250=0, metas 3*34/250=0, infos 5*80/250=400/250=1 → 947.
        assert_eq!(cpi_total_cost(100, 3, 5), 947);
        // data 1000/250=4, metas 10*34/250=1, infos 10*80/250=3 → 954.
        assert_eq!(cpi_total_cost(1000, 10, 10), 954);
    }

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
            karstflow_types::Pubkey::default(),
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
            karstflow_types::Pubkey::default(),
        )
        .unwrap();
        assert!(result.logs.iter().any(|l| l.contains("Hi")));
    }

    #[test]
    fn log_truncation_enforces_limit() {
        let mut vm = make_test_vm(1_000_000);

        // Fill up to near the limit with large messages
        let big_msg = "x".repeat(5000);
        assert!(try_append_log(&mut vm, big_msg.clone()));
        assert_eq!(vm.log_bytes_written, 5000);
        assert!(!vm.log_truncated);

        // This push would exceed 10_000 bytes
        assert!(try_append_log(&mut vm, big_msg.clone()));
        assert_eq!(vm.log_bytes_written, 10_000);

        // Next push exceeds limit — should be truncated
        assert!(!try_append_log(&mut vm, "one more".to_string()));
        assert!(vm.log_truncated);
        assert!(vm.logs.last().unwrap().contains("Log truncated"));

        // Subsequent pushes are silently dropped
        let count_before = vm.logs.len();
        assert!(!try_append_log(&mut vm, "ignored".to_string()));
        assert_eq!(vm.logs.len(), count_before);
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
            karstflow_types::Pubkey::default(),
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
            karstflow_types::Pubkey::default(),
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
            // Call sha256: r1=pair_ptr(heap+64), r2=1(count), r3=result(heap+128)
            Instruction::new(Opcode::Lddw as u8, 1, 0, 0, (REGION_HEAP_BASE + 64) as i32),
            Instruction::new(0, 0, 0, 0, ((REGION_HEAP_BASE + 64) >> 32) as i32),
            Instruction::new(Opcode::Mov64Imm as u8, 2, 0, 0, 1), // 1 pair
            Instruction::new(Opcode::Lddw as u8, 3, 0, 0, (REGION_HEAP_BASE + 128) as i32),
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
            karstflow_types::Pubkey::default(),
        )
        .unwrap();

        // Compute expected SHA-256 of "hello"
        let mut hasher = Sha256::new();
        hasher.update(b"hello");
        let expected: [u8; 32] = hasher.finalize().into();
        let expected_first_8 = u64::from_le_bytes(expected[..8].try_into().unwrap());

        assert_eq!(result.return_value, expected_first_8);
    }

    #[test]
    fn sha512_handler_correct_hash() {
        use sha2::{Digest, Sha512};

        let dispatch = RuntimeSyscallDispatch::with_standard_syscalls();
        let sha_id = murmur3_hash("sol_sha512");

        // Write test data "hello" to heap, set up input pair pointing to it,
        // call sol_sha512, then read the first 8 bytes of the 64-byte digest.
        let bytes = make_program_bytes(&[
            Instruction::new(Opcode::Lddw as u8, 1, 0, 0, REGION_HEAP_BASE as i32),
            Instruction::new(0, 0, 0, 0, (REGION_HEAP_BASE >> 32) as i32),
            // "hell" + "o"
            Instruction::new(Opcode::Mov64Imm as u8, 2, 0, 0, 0x6C6C6568u32 as i32),
            Instruction::new(Opcode::StxWord as u8, 1, 2, 0, 0),
            Instruction::new(Opcode::Mov64Imm as u8, 2, 0, 0, 0x6F),
            Instruction::new(Opcode::StxByte as u8, 1, 2, 4, 0),
            // Input pair at heap+64: ptr=heap_base, len=5
            Instruction::new(Opcode::Lddw as u8, 3, 0, 0, (REGION_HEAP_BASE + 64) as i32),
            Instruction::new(0, 0, 0, 0, ((REGION_HEAP_BASE + 64) >> 32) as i32),
            Instruction::new(Opcode::StxDword as u8, 3, 1, 0, 0),
            Instruction::new(Opcode::Mov64Imm as u8, 4, 0, 0, 5),
            Instruction::new(Opcode::StxDword as u8, 3, 4, 8, 0),
            // Call sha512: r1=pair_ptr(heap+64), r2=1, r3=result(heap+128)
            Instruction::new(Opcode::Lddw as u8, 1, 0, 0, (REGION_HEAP_BASE + 64) as i32),
            Instruction::new(0, 0, 0, 0, ((REGION_HEAP_BASE + 64) >> 32) as i32),
            Instruction::new(Opcode::Mov64Imm as u8, 2, 0, 0, 1),
            Instruction::new(Opcode::Lddw as u8, 3, 0, 0, (REGION_HEAP_BASE + 128) as i32),
            Instruction::new(0, 0, 0, 0, ((REGION_HEAP_BASE + 128) >> 32) as i32),
            Instruction::new(Opcode::Call as u8, 0, 0, 0, sha_id as i32),
            // Read first 8 bytes of the digest into r0
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
            karstflow_types::Pubkey::default(),
        )
        .unwrap();

        let mut hasher = Sha512::new();
        hasher.update(b"hello");
        let expected: [u8; 64] = hasher.finalize().into();
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
            log_bytes_written: 0,
            log_truncated: false,
            return_data: None,
            heap_position: REGION_HEAP_BASE,
            sysvar_snapshot: snapshot,
            cpi_depth: 0,
            sbpf_version: crate::elf_loader::SbpfVersion::V0,
            program_id: karstflow_types::Pubkey::default(),
            syscall_parameter_address_restrictions: false,
        }
    }

    /// A VM whose input region is large enough to be a plausible syscall
    /// output target, so the address restriction is what rejects the write
    /// rather than an unmapped-memory error.
    fn make_input_region_vm(restrictions_active: bool) -> VmState {
        use crate::interpreter::VmState;
        VmState {
            registers: [0u64; 11],
            pc: 0,
            instruction_count: 0,
            memory: MemoryMap::new(&[], TOTAL_STACK_SIZE, DEFAULT_HEAP_SIZE, vec![0u8; 512]),
            call_stack: Vec::new(),
            compute_meter: 1_000_000,
            logs: Vec::new(),
            log_bytes_written: 0,
            log_truncated: false,
            return_data: None,
            heap_position: REGION_HEAP_BASE,
            sysvar_snapshot: crate::sysvar_snapshot::SysvarSnapshot::default(),
            cpi_depth: 0,
            sbpf_version: crate::elf_loader::SbpfVersion::V0,
            program_id: karstflow_types::Pubkey::default(),
            syscall_parameter_address_restrictions: restrictions_active,
        }
    }

    /// The six sysvar getters upstream guards, each invoked through its handler
    /// with `r1` as the destination pointer.
    fn call_sysvar_handler(index: usize, vm: &mut VmState, dst: u64) -> Result<u64, VmError> {
        match index {
            0 => SolGetClockSysvarHandler.call(vm, dst, 0, 0, 0, 0),
            1 => SolGetRentSysvarHandler.call(vm, dst, 0, 0, 0, 0),
            2 => SolGetEpochScheduleHandler.call(vm, dst, 0, 0, 0, 0),
            3 => SolGetLastRestartSlotHandler.call(vm, dst, 0, 0, 0, 0),
            4 => SolGetEpochRewardsSysvarHandler.call(vm, dst, 0, 0, 0, 0),
            // sol_get_sysvar takes the destination in r2, with the sysvar id in r1.
            5 => SolGetSysvarHandler.call(vm, REGION_HEAP_BASE, dst, 0, 32, 0),
            _ => unreachable!("only six guarded sysvar getters"),
        }
    }

    const GUARDED_SYSVAR_HANDLERS: usize = 6;

    #[test]
    fn sysvar_output_into_input_region_is_rejected_when_gated() {
        for index in 0..GUARDED_SYSVAR_HANDLERS {
            let mut vm = make_input_region_vm(true);
            let result = call_sysvar_handler(index, &mut vm, REGION_INPUT_BASE);

            assert!(
                result.is_err(),
                "handler {index}: an output pointer in the input region must be refused \
                 while the restriction is active"
            );
        }
    }

    #[test]
    fn sysvar_output_into_input_region_is_allowed_when_ungated() {
        // Pre-activation behaviour must be preserved exactly: the same call
        // that the gate refuses has to succeed while the gate is inactive,
        // otherwise the restriction is applied to slots that predate it.
        for index in 0..GUARDED_SYSVAR_HANDLERS {
            let mut vm = make_input_region_vm(false);
            let result = call_sysvar_handler(index, &mut vm, REGION_INPUT_BASE);

            assert!(
                result.is_ok(),
                "handler {index}: must still write into the input region while the \
                 restriction is inactive, got {result:?}"
            );
        }
    }

    #[test]
    fn sysvar_output_outside_the_input_region_is_unaffected_by_the_gate() {
        for index in 0..GUARDED_SYSVAR_HANDLERS {
            let mut vm = make_input_region_vm(true);
            let result = call_sysvar_handler(index, &mut vm, REGION_HEAP_BASE);

            assert!(
                result.is_ok(),
                "handler {index}: the gate must only reject the input region, got {result:?}"
            );
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

    /// Build a minimal serialized input region with one account (aligned format).
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
        // NON_DUP_MARKER
        buf.push(karstflow_constants::vm::NON_DUP_MARKER);
        // is_signer
        buf.push(0);
        // is_writable
        buf.push(if is_writable { 1 } else { 0 });
        // is_executable
        buf.push(0);
        // padding (4 bytes)
        buf.extend_from_slice(&0u32.to_le_bytes());
        // pubkey
        buf.extend_from_slice(pubkey.as_ref());
        // owner
        buf.extend_from_slice(owner.as_ref());
        // lamports
        buf.extend_from_slice(&lamports.to_le_bytes());
        // data_len
        let data_len = data.len();
        buf.extend_from_slice(&(data_len as u64).to_le_bytes());
        // data
        buf.extend_from_slice(data);
        // realloc buffer (MAX_PERMITTED_DATA_INCREASE bytes, zeroed)
        buf.resize(
            buf.len() + karstflow_constants::vm::MAX_PERMITTED_DATA_INCREASE,
            0,
        );
        // alignment padding
        let align_offset = data_len.wrapping_neg() & (karstflow_constants::vm::ALIGN_OF_U128 - 1);
        buf.resize(buf.len() + align_offset, 0);
        // rent_epoch (8 bytes)
        buf.extend_from_slice(&u64::MAX.to_le_bytes());
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
    fn writeback_allows_data_growth_within_realloc_limit() {
        let pk = Pubkey::new([1u8; 32]);
        let owner = Pubkey::new([2u8; 32]);
        let mut input = make_input_region(&pk, &owner, 1000, &[0; 8], true);

        let entries = scan_input_region(&input);

        // Growing from 8 to 16 bytes is within realloc buffer (MAX_PERMITTED_DATA_INCREASE)
        let modified = Account {
            meta: TypesAccountMeta {
                lamports: 1000,
                owner,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(vec![0xCC; 16]),
        };

        writeback_account_to_input(&mut input, entries[0].offset, &modified).unwrap();

        let (_, readback) = read_account_from_input(&input, entries[0].offset).unwrap();
        assert_eq!(readback.data.as_slice(), &[0xCC; 16]);
    }

    #[test]
    fn writeback_rejects_data_growth_beyond_realloc_limit() {
        let pk = Pubkey::new([1u8; 32]);
        let owner = Pubkey::new([2u8; 32]);
        let mut input = make_input_region(&pk, &owner, 1000, &[0; 8], true);

        let entries = scan_input_region(&input);

        // Exceeding original + MAX_PERMITTED_DATA_INCREASE should fail
        let too_large = vec![0; 8 + karstflow_constants::vm::MAX_PERMITTED_DATA_INCREASE + 1];
        let modified = Account {
            meta: TypesAccountMeta {
                lamports: 1000,
                owner,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(too_large),
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
        // data_len is updated to 4; only the written bytes are returned
        assert_eq!(readback.data.as_slice(), &[0xBB; 4]);
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

        // Account 1 (aligned format)
        buf.push(karstflow_constants::vm::NON_DUP_MARKER);
        buf.push(0); // is_signer
        buf.push(1); // is_writable
        buf.push(0); // is_executable
        buf.extend_from_slice(&0u32.to_le_bytes()); // padding
        buf.extend_from_slice(pk1.as_ref());
        buf.extend_from_slice(owner.as_ref());
        buf.extend_from_slice(&100u64.to_le_bytes());
        let data1_len: usize = 8;
        buf.extend_from_slice(&(data1_len as u64).to_le_bytes());
        buf.extend_from_slice(&[0xAA; 8]);
        buf.resize(
            buf.len() + karstflow_constants::vm::MAX_PERMITTED_DATA_INCREASE,
            0,
        );
        let align1 = data1_len.wrapping_neg() & (karstflow_constants::vm::ALIGN_OF_U128 - 1);
        buf.resize(buf.len() + align1, 0);
        buf.extend_from_slice(&u64::MAX.to_le_bytes()); // rent_epoch

        // Account 2 (aligned format)
        buf.push(karstflow_constants::vm::NON_DUP_MARKER);
        buf.push(0); // is_signer
        buf.push(0); // is_writable
        buf.push(0); // is_executable
        buf.extend_from_slice(&0u32.to_le_bytes()); // padding
        buf.extend_from_slice(pk2.as_ref());
        buf.extend_from_slice(owner.as_ref());
        buf.extend_from_slice(&200u64.to_le_bytes());
        let data2_len: usize = 4;
        buf.extend_from_slice(&(data2_len as u64).to_le_bytes());
        buf.extend_from_slice(&[0xBB; 4]);
        buf.resize(
            buf.len() + karstflow_constants::vm::MAX_PERMITTED_DATA_INCREASE,
            0,
        );
        let align2 = data2_len.wrapping_neg() & (karstflow_constants::vm::ALIGN_OF_U128 - 1);
        buf.resize(buf.len() + align2, 0);
        buf.extend_from_slice(&u64::MAX.to_le_bytes()); // rent_epoch

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
        let handler = SolInvokeCHandler {
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

    // -----------------------------------------------------------------------
    // Feature-gated syscall registration tests
    // -----------------------------------------------------------------------

    #[test]
    fn feature_gated_all_features_active() {
        use karstflow_constants::features::*;
        let features: std::collections::HashSet<&str> = [
            FEATURE_ENABLE_ALT_BN128_SYSCALL,
            FEATURE_ENABLE_ALT_BN128_COMPRESSION,
            FEATURE_ENABLE_POSEIDON_SYSCALL,
            FEATURE_GET_SYSVAR_SYSCALL,
            FEATURE_ENABLE_GET_EPOCH_STAKE,
            FEATURE_ENABLE_BLS12_381_SYSCALL,
        ]
        .into_iter()
        .collect();

        let dispatch = RuntimeSyscallDispatch::with_features(&features);
        let ids = dispatch.registered_ids();

        // All gated syscalls should be present
        assert!(ids.contains(&murmur3_hash("sol_alt_bn128_group_op")));
        assert!(ids.contains(&murmur3_hash("sol_alt_bn128_compression")));
        assert!(ids.contains(&murmur3_hash("sol_poseidon")));
        assert!(ids.contains(&murmur3_hash("sol_get_sysvar")));
        assert!(ids.contains(&murmur3_hash("sol_get_epoch_stake")));
        assert!(ids.contains(&murmur3_hash("sol_curve_decompress")));
        assert!(ids.contains(&murmur3_hash("sol_curve_pairing_map")));

        // Always-available syscalls still present
        assert!(ids.contains(&murmur3_hash("sol_log_")));
        assert!(ids.contains(&murmur3_hash("sol_sha256")));
        assert!(ids.contains(&murmur3_hash("abort")));
        assert!(ids.contains(&murmur3_hash("sol_panic_")));
    }

    #[test]
    fn feature_gated_no_features_active() {
        let features: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let dispatch = RuntimeSyscallDispatch::with_features(&features);
        let ids = dispatch.registered_ids();

        // Gated syscalls should NOT be present
        assert!(!ids.contains(&murmur3_hash("sol_alt_bn128_group_op")));
        assert!(!ids.contains(&murmur3_hash("sol_alt_bn128_compression")));
        assert!(!ids.contains(&murmur3_hash("sol_poseidon")));
        assert!(!ids.contains(&murmur3_hash("sol_get_sysvar")));
        assert!(!ids.contains(&murmur3_hash("sol_get_epoch_stake")));
        assert!(!ids.contains(&murmur3_hash("sol_curve_decompress")));
        assert!(!ids.contains(&murmur3_hash("sol_curve_pairing_map")));

        // Always-available syscalls still present
        assert!(ids.contains(&murmur3_hash("sol_log_")));
        assert!(ids.contains(&murmur3_hash("sol_sha256")));
        assert!(ids.contains(&murmur3_hash("sol_memcpy_")));
        assert!(ids.contains(&murmur3_hash("sol_get_clock_sysvar")));
        assert!(ids.contains(&murmur3_hash("abort")));
        assert!(ids.contains(&murmur3_hash("sol_panic_")));
    }

    #[test]
    fn feature_gated_partial_activation() {
        use karstflow_constants::features::*;
        let features: std::collections::HashSet<&str> =
            [FEATURE_ENABLE_POSEIDON_SYSCALL, FEATURE_GET_SYSVAR_SYSCALL]
                .into_iter()
                .collect();

        let dispatch = RuntimeSyscallDispatch::with_features(&features);
        let ids = dispatch.registered_ids();

        // Only poseidon and get_sysvar should be gated-in
        assert!(ids.contains(&murmur3_hash("sol_poseidon")));
        assert!(ids.contains(&murmur3_hash("sol_get_sysvar")));

        // ALT-BN128, epoch_stake, and BLS12-381 should NOT be present
        assert!(!ids.contains(&murmur3_hash("sol_alt_bn128_group_op")));
        assert!(!ids.contains(&murmur3_hash("sol_alt_bn128_compression")));
        assert!(!ids.contains(&murmur3_hash("sol_get_epoch_stake")));
        assert!(!ids.contains(&murmur3_hash("sol_curve_decompress")));
        assert!(!ids.contains(&murmur3_hash("sol_curve_pairing_map")));
    }

    #[test]
    fn feature_gated_matches_standard_when_all_active() {
        use karstflow_constants::features::*;
        let features: std::collections::HashSet<&str> = [
            FEATURE_ENABLE_ALT_BN128_SYSCALL,
            FEATURE_ENABLE_ALT_BN128_COMPRESSION,
            FEATURE_ENABLE_POSEIDON_SYSCALL,
            FEATURE_GET_SYSVAR_SYSCALL,
            FEATURE_ENABLE_GET_EPOCH_STAKE,
            FEATURE_ENABLE_BLS12_381_SYSCALL,
        ]
        .into_iter()
        .collect();

        let gated = RuntimeSyscallDispatch::with_features(&features);
        let standard = RuntimeSyscallDispatch::with_standard_syscalls();

        // Both should have the same syscall set
        assert_eq!(gated.registered_ids(), standard.registered_ids());
    }

    fn make_test_vm(compute_budget: u64) -> VmState {
        VmState {
            registers: [0u64; 11],
            pc: 0,
            instruction_count: 0,
            memory: MemoryMap::new(&[], TOTAL_STACK_SIZE, DEFAULT_HEAP_SIZE, vec![]),
            call_stack: Vec::new(),
            compute_meter: compute_budget,
            logs: Vec::new(),
            log_bytes_written: 0,
            log_truncated: false,
            return_data: None,
            heap_position: REGION_HEAP_BASE,
            sysvar_snapshot: crate::sysvar_snapshot::SysvarSnapshot::default(),
            cpi_depth: 0,
            sbpf_version: crate::elf_loader::SbpfVersion::V0,
            program_id: karstflow_types::Pubkey::default(),
            syscall_parameter_address_restrictions: false,
        }
    }

    #[test]
    fn abort_handler_returns_error() {
        let handler = AbortHandler;
        let mut vm = make_test_vm(10_000);

        let result = handler.call(&mut vm, 0, 0, 0, 0, 0);
        assert!(result.is_err());
        match result {
            Err(VmError::SyscallError(msg)) => assert_eq!(msg, "abort"),
            other => panic!("expected SyscallError(\"abort\"), got {:?}", other),
        }
    }

    #[test]
    fn sol_panic_handler_logs_and_fails() {
        let handler = SolPanicHandler;
        let mut vm = make_test_vm(10_000);

        // Write "oops" to heap region
        let msg = b"oops";
        let heap_addr = REGION_HEAP_BASE;
        vm.memory.write_slice(heap_addr, msg).unwrap();

        let result = handler.call(&mut vm, heap_addr, msg.len() as u64, 0, 0, 0);
        assert!(result.is_err());
        match result {
            Err(VmError::SyscallError(msg)) => assert_eq!(msg, "panic: oops"),
            other => panic!("expected SyscallError(\"panic: oops\"), got {:?}", other),
        }
        assert_eq!(vm.logs.len(), 1);
        assert!(vm.logs[0].contains("oops"));
    }

    #[test]
    fn sol_curve_decompress_g1_identity() {
        let handler = SolCurveDecompressHandler;
        let mut vm = make_test_vm(10_000);

        // G1 compressed identity: 0xC0 followed by 47 zero bytes.
        let mut compressed = [0u8; 48];
        compressed[0] = 0xC0;
        let input_addr = REGION_HEAP_BASE;
        let output_addr = REGION_HEAP_BASE + 64;
        vm.memory.write_slice(input_addr, &compressed).unwrap();

        let result = handler.call(
            &mut vm,
            syscalls::CURVE_ID_BLS12_381_G1,
            input_addr,
            output_addr,
            0,
            0,
        );
        assert_eq!(result.unwrap(), 0);
        assert_eq!(
            vm.compute_meter,
            10_000 - syscalls::BLS12_381_G1_DECOMPRESS_COST
        );
    }

    #[test]
    fn sol_curve_decompress_invalid_curve_id() {
        let handler = SolCurveDecompressHandler;
        let mut vm = make_test_vm(10_000);

        let result = handler.call(&mut vm, 99, 0, 0, 0, 0);
        assert_eq!(result.unwrap(), 1);
        assert_eq!(vm.compute_meter, 10_000); // no compute deducted
    }

    #[test]
    fn sol_curve_pairing_map_zero_pairs_rejected() {
        let handler = SolCurvePairingMapHandler;
        let mut vm = make_test_vm(200_000);

        let result = handler.call(&mut vm, syscalls::CURVE_ID_BLS12_381_G1, 0, 0, 0, 0);
        assert_eq!(result.unwrap(), 1);
        assert_eq!(vm.compute_meter, 200_000); // no compute deducted
    }

    #[test]
    fn sol_curve_pairing_map_too_many_pairs_rejected() {
        let handler = SolCurvePairingMapHandler;
        let mut vm = make_test_vm(1_000_000);

        let result = handler.call(&mut vm, syscalls::CURVE_ID_BLS12_381_G1, 9, 0, 0, 0);
        assert_eq!(result.unwrap(), 1);
        assert_eq!(vm.compute_meter, 1_000_000); // no compute deducted
    }

    // -----------------------------------------------------------------------
    // Feature-gated dispatcher (with_active_feature_ids) tests
    // -----------------------------------------------------------------------

    #[test]
    fn feature_gated_dispatch_no_features_excludes_gated_syscalls() {
        let empty: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        let dispatch = RuntimeSyscallDispatch::with_active_feature_ids(&empty);
        let ids = dispatch.registered_ids();

        // Always-available syscalls should be present
        assert!(ids.contains(&murmur3_hash("sol_log_")));
        assert!(ids.contains(&murmur3_hash("sol_memcpy_")));
        assert!(ids.contains(&murmur3_hash("sol_sha256")));
        assert!(ids.contains(&murmur3_hash("sol_keccak256")));
        assert!(ids.contains(&murmur3_hash("sol_alloc_free_")));
        assert!(ids.contains(&murmur3_hash("sol_create_program_address")));
        assert!(ids.contains(&murmur3_hash("sol_secp256k1_recover")));
        assert!(ids.contains(&murmur3_hash("abort")));
        assert!(ids.contains(&murmur3_hash("sol_panic_")));
        assert!(ids.contains(&murmur3_hash("sol_get_sysvar")));

        // Feature-gated syscalls should NOT be present
        assert!(!ids.contains(&murmur3_hash("sol_blake3")));
        assert!(!ids.contains(&murmur3_hash("sol_curve_validate_point")));
        assert!(!ids.contains(&murmur3_hash("sol_curve_group_op")));
        assert!(!ids.contains(&murmur3_hash("sol_curve_multiscalar_mul")));
        assert!(!ids.contains(&murmur3_hash("sol_alt_bn128_group_op")));
        assert!(!ids.contains(&murmur3_hash("sol_alt_bn128_compression")));
        assert!(!ids.contains(&murmur3_hash("sol_poseidon")));
        assert!(!ids.contains(&murmur3_hash("sol_get_epoch_stake")));
        assert!(!ids.contains(&murmur3_hash("sol_sha512")));
    }

    #[test]
    fn feature_gated_dispatch_all_features_registers_everything() {
        use karstflow_ids::features;

        let mut all_features: std::collections::HashSet<[u8; 32]> =
            std::collections::HashSet::new();
        all_features.insert(*features::BLAKE3_SYSCALL_ENABLED.as_bytes());
        all_features.insert(*features::CURVE25519_SYSCALL_ENABLED.as_bytes());
        all_features.insert(*features::ENABLE_ALT_BN128_SYSCALL.as_bytes());
        all_features.insert(*features::ENABLE_ALT_BN128_COMPRESSION_SYSCALL.as_bytes());
        all_features.insert(*features::ENABLE_POSEIDON_SYSCALL.as_bytes());
        all_features.insert(*features::ENABLE_GET_EPOCH_STAKE_SYSCALL.as_bytes());
        all_features.insert(*features::ENABLE_SHA512_SYSCALL.as_bytes());

        let dispatch = RuntimeSyscallDispatch::with_active_feature_ids(&all_features);
        let ids = dispatch.registered_ids();

        // All feature-gated syscalls should be registered
        assert!(ids.contains(&murmur3_hash("sol_blake3")));
        assert!(ids.contains(&murmur3_hash("sol_curve_validate_point")));
        assert!(ids.contains(&murmur3_hash("sol_curve_group_op")));
        assert!(ids.contains(&murmur3_hash("sol_curve_multiscalar_mul")));
        assert!(ids.contains(&murmur3_hash("sol_alt_bn128_group_op")));
        assert!(ids.contains(&murmur3_hash("sol_alt_bn128_compression")));
        assert!(ids.contains(&murmur3_hash("sol_poseidon")));
        assert!(ids.contains(&murmur3_hash("sol_get_epoch_stake")));
        assert!(ids.contains(&murmur3_hash("sol_sha512")));

        // Always-available too
        assert!(ids.contains(&murmur3_hash("sol_log_")));
        assert!(ids.contains(&murmur3_hash("sol_sha256")));
    }

    #[test]
    fn feature_gated_dispatch_individual_blake3() {
        use karstflow_ids::features;

        let mut features_set: std::collections::HashSet<[u8; 32]> =
            std::collections::HashSet::new();
        features_set.insert(*features::BLAKE3_SYSCALL_ENABLED.as_bytes());

        let dispatch = RuntimeSyscallDispatch::with_active_feature_ids(&features_set);
        let ids = dispatch.registered_ids();

        assert!(ids.contains(&murmur3_hash("sol_blake3")));
        // Other gated syscalls should remain absent
        assert!(!ids.contains(&murmur3_hash("sol_poseidon")));
        assert!(!ids.contains(&murmur3_hash("sol_get_epoch_stake")));
        assert!(!ids.contains(&murmur3_hash("sol_alt_bn128_group_op")));
    }

    #[test]
    fn feature_gated_dispatch_curve25519_registers_all_three() {
        use karstflow_ids::features;

        let mut features_set: std::collections::HashSet<[u8; 32]> =
            std::collections::HashSet::new();
        features_set.insert(*features::CURVE25519_SYSCALL_ENABLED.as_bytes());

        let dispatch = RuntimeSyscallDispatch::with_active_feature_ids(&features_set);
        let ids = dispatch.registered_ids();

        // Curve25519 enables 3 syscalls
        assert!(ids.contains(&murmur3_hash("sol_curve_validate_point")));
        assert!(ids.contains(&murmur3_hash("sol_curve_group_op")));
        assert!(ids.contains(&murmur3_hash("sol_curve_multiscalar_mul")));
        // But not alt_bn128 or others
        assert!(!ids.contains(&murmur3_hash("sol_alt_bn128_group_op")));
    }

    #[test]
    fn feature_gated_dispatch_sysvar_always_registered() {
        let empty: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        let dispatch = RuntimeSyscallDispatch::with_active_feature_ids(&empty);
        let ids = dispatch.registered_ids();

        // sol_get_sysvar is always enabled (gated at consensus layer)
        assert!(ids.contains(&murmur3_hash("sol_get_sysvar")));
    }

    #[test]
    fn remaining_compute_units_returns_meter_value() {
        let handler = SolRemainingComputeUnitsHandler;
        let mut vm = make_sysvar_test_vm(crate::sysvar_snapshot::SysvarSnapshot::default());
        vm.compute_meter = 50_000;

        let result = handler.call(&mut vm, 0, 0, 0, 0, 0).unwrap();
        // After deducting 100 CU cost, remaining should be 49900
        assert_eq!(result, 50_000 - syscalls::GET_REMAINING_COMPUTE_UNITS_COST);
        assert_eq!(
            vm.compute_meter,
            50_000 - syscalls::GET_REMAINING_COMPUTE_UNITS_COST
        );
    }

    #[test]
    fn remaining_compute_units_feature_gated() {
        use karstflow_ids::features;

        // Without the feature, syscall is not registered
        let empty: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        let dispatch = RuntimeSyscallDispatch::with_active_feature_ids(&empty);
        assert!(!dispatch
            .registered_ids()
            .contains(&murmur3_hash("sol_remaining_compute_units")));

        // With the feature, syscall is registered
        let mut features_set: std::collections::HashSet<[u8; 32]> =
            std::collections::HashSet::new();
        features_set.insert(*features::REMAINING_COMPUTE_UNITS_SYSCALL_ENABLED.as_bytes());
        let dispatch = RuntimeSyscallDispatch::with_active_feature_ids(&features_set);
        assert!(dispatch
            .registered_ids()
            .contains(&murmur3_hash("sol_remaining_compute_units")));
    }

    #[test]
    fn sol_log_data_encodes_buffers() {
        let handler = SolLogDataHandler;
        let mut vm = make_test_vm(100_000);

        // Write two SolBytes entries on the heap:
        // Entry 0: ptr=heap+32, len=3 ("foo")
        // Entry 1: ptr=heap+64, len=2 ("hi")
        let heap = REGION_HEAP_BASE;
        let entry0_ptr = heap + 32;
        let entry1_ptr = heap + 64;

        // SolBytes array at heap+0: [ptr0(8), len0(8), ptr1(8), len1(8)] = 32 bytes
        vm.memory
            .write_slice(heap, &(entry0_ptr).to_le_bytes())
            .unwrap();
        vm.memory
            .write_slice(heap + 8, &3u64.to_le_bytes())
            .unwrap();
        vm.memory
            .write_slice(heap + 16, &(entry1_ptr).to_le_bytes())
            .unwrap();
        vm.memory
            .write_slice(heap + 24, &2u64.to_le_bytes())
            .unwrap();

        // Write actual data
        vm.memory.write_slice(entry0_ptr, b"foo").unwrap();
        vm.memory.write_slice(entry1_ptr, b"hi").unwrap();

        let result = handler.call(&mut vm, heap, 2, 0, 0, 0).unwrap();
        assert_eq!(result, 0);
        assert_eq!(vm.logs.len(), 1);
        // "foo" -> "Zm9v", "hi" -> "aGk="
        assert_eq!(vm.logs[0], "Program data: Zm9v aGk=");
    }

    #[test]
    fn sol_log_data_empty_count() {
        let handler = SolLogDataHandler;
        let mut vm = make_test_vm(100_000);
        let result = handler.call(&mut vm, 0, 0, 0, 0, 0).unwrap();
        assert_eq!(result, 0);
        assert_eq!(vm.logs[0], "Program data: ");
    }

    // -----------------------------------------------------------------------
    // C ABI CPI handler unit test
    // -----------------------------------------------------------------------

    /// Executor that captures the context it receives for assertion.
    struct CapturingExecutor {
        captured: std::sync::Mutex<Option<crate::ExecutionContext>>,
    }

    impl CapturingExecutor {
        fn new() -> Self {
            Self {
                captured: std::sync::Mutex::new(None),
            }
        }

        fn take(&self) -> Option<crate::ExecutionContext> {
            self.captured.lock().unwrap().take()
        }
    }

    impl InstructionExecutor for CapturingExecutor {
        fn execute_instruction(
            &self,
            context: crate::ExecutionContext,
        ) -> Result<crate::ExecutionOutcome, crate::SbpfExecutionError> {
            *self.captured.lock().unwrap() = Some(context);
            Ok(crate::ExecutionOutcome::success(50))
        }
    }

    #[test]
    fn cpi_c_abi_parses_instruction_correctly() {
        use karstflow_constants::vm::REGION_INPUT_BASE;

        let executor = Arc::new(CapturingExecutor::new());
        let handler = SolInvokeCHandler {
            executor: executor.clone(),
        };

        // --- Lay out C ABI structures in heap memory ---
        // Heap layout:
        //   0x000: target program_id (32 bytes)
        //   0x020: account pubkey (32 bytes)
        //   0x040: C ABI AccountMeta[1] (16 bytes)
        //   0x050: instruction data (4 bytes)
        //   0x060: C ABI Instruction (40 bytes)
        let base = REGION_HEAP_BASE;
        let program_id_addr = base; // 0x000
        let acct_pubkey_addr = base + 0x20; // 0x020
        let acct_metas_addr = base + 0x40; // 0x040
        let idata_addr = base + 0x50; // 0x050
        let instr_addr = base + 0x60; // 0x060

        let target_pid = Pubkey::new([0xAA; 32]);
        let acct_pk = Pubkey::new([0xBB; 32]);
        let idata = [1u8, 2, 3, 4];

        // Build input region with one account matching acct_pk
        let owner = Pubkey::new([0xCC; 32]);
        let input_data = make_input_region(&acct_pk, &owner, 5000, &[0; 8], true);

        // Create VM with input region
        let mut vm = VmState {
            registers: [0u64; 11],
            pc: 0,
            instruction_count: 0,
            memory: MemoryMap::new(&[], TOTAL_STACK_SIZE, DEFAULT_HEAP_SIZE, input_data),
            call_stack: Vec::new(),
            compute_meter: 10_000_000,
            logs: Vec::new(),
            log_bytes_written: 0,
            log_truncated: false,
            return_data: None,
            heap_position: REGION_HEAP_BASE,
            sysvar_snapshot: crate::sysvar_snapshot::SysvarSnapshot::default(),
            cpi_depth: 0,
            sbpf_version: crate::elf_loader::SbpfVersion::V0,
            program_id: karstflow_types::Pubkey::default(),
            syscall_parameter_address_restrictions: false,
        };

        // Write target program ID
        vm.memory
            .write_slice(program_id_addr, target_pid.as_ref())
            .unwrap();

        // Write account pubkey
        vm.memory
            .write_slice(acct_pubkey_addr, acct_pk.as_ref())
            .unwrap();

        // Write C ABI AccountMeta: pubkey_addr(8) + is_writable(1) + is_signer(1) + pad(6) = 16
        let mut meta_buf = [0u8; 16];
        meta_buf[0..8].copy_from_slice(&acct_pubkey_addr.to_le_bytes());
        meta_buf[8] = 1; // is_writable
        meta_buf[9] = 1; // is_signer
        vm.memory.write_slice(acct_metas_addr, &meta_buf).unwrap();

        // Write instruction data
        vm.memory.write_slice(idata_addr, &idata).unwrap();

        // Write C ABI Instruction: program_id_ptr(8) + accounts_ptr(8) + accounts_len(8) + data_ptr(8) + data_len(8) = 40
        let mut instr_buf = [0u8; 40];
        instr_buf[0..8].copy_from_slice(&program_id_addr.to_le_bytes());
        instr_buf[8..16].copy_from_slice(&acct_metas_addr.to_le_bytes());
        instr_buf[16..24].copy_from_slice(&1u64.to_le_bytes()); // 1 account meta
        instr_buf[24..32].copy_from_slice(&idata_addr.to_le_bytes());
        instr_buf[32..40].copy_from_slice(&(idata.len() as u64).to_le_bytes());
        vm.memory.write_slice(instr_addr, &instr_buf).unwrap();

        // --- Call the handler (no signer seeds: r4=0, r5=0) ---
        let ret = handler
            .call(&mut vm, instr_addr, REGION_INPUT_BASE, 1, 0, 0)
            .unwrap();
        assert_eq!(ret, 0, "CPI should succeed");

        // --- Verify the executor received correctly parsed data ---
        let ctx = executor.take().expect("executor should have been called");
        assert_eq!(ctx.program_id, target_pid);
        assert_eq!(ctx.instruction_data, idata.to_vec());
        assert_eq!(ctx.accounts.len(), 1);
        let (pk, acct, writable) = &ctx.accounts[0];
        assert_eq!(*pk, acct_pk);
        assert!(writable);
        assert_eq!(acct.meta.lamports, 5000);
        assert_eq!(acct.meta.owner, owner);

        // Verify signer was tracked
        assert!(ctx.signers.contains(&acct_pk));
    }

    // -----------------------------------------------------------------------
    // alt_bn128 sub-operation feature gates (SIMD-0284 little-endian,
    // SIMD-0302 G2).
    //
    // Every test here builds its feature state explicitly. Dev mode activates
    // the whole registry at slot 0, so a test that leans on the ambient
    // environment cannot observe a feature gate at all.
    // -----------------------------------------------------------------------

    /// True when the call was refused by a feature gate rather than by
    /// anything downstream (bad op id, unreadable memory, invalid point).
    fn rejected_by_gate(result: &Result<u64, VmError>) -> bool {
        matches!(result, Err(VmError::SyscallError(msg)) if msg == ALT_BN128_INVALID_ATTRIBUTE)
    }

    fn call_group_op(little_endian: bool, g2: bool, op: u64) -> Result<u64, VmError> {
        let handler = SolAltBn128GroupOpHandler {
            little_endian_enabled: little_endian,
            g2_enabled: g2,
        };
        let mut vm = make_sysvar_test_vm(crate::sysvar_snapshot::SysvarSnapshot::default());
        handler.call(&mut vm, op, REGION_HEAP_BASE, 0, REGION_HEAP_BASE, 0)
    }

    fn call_compression(little_endian: bool, op: u64) -> Result<u64, VmError> {
        let handler = SolAltBn128CompressionHandler {
            little_endian_enabled: little_endian,
        };
        let mut vm = make_sysvar_test_vm(crate::sysvar_snapshot::SysvarSnapshot::default());
        handler.call(&mut vm, op, REGION_HEAP_BASE, 0, REGION_HEAP_BASE, 0)
    }

    #[test]
    fn alt_bn128_le_group_ops_rejected_when_feature_inactive() {
        for op in [
            syscalls::ALT_BN128_G1_ADD_LE,
            syscalls::ALT_BN128_G1_MUL_LE,
            syscalls::ALT_BN128_PAIRING_LE,
        ] {
            assert!(
                rejected_by_gate(&call_group_op(false, true, op)),
                "op {op:#x} must be refused while alt_bn128_little_endian is inactive"
            );
        }
    }

    #[test]
    fn alt_bn128_le_gate_covers_only_the_g1_and_pairing_variants() {
        // The big-endian forms are outside the gate entirely.
        for op in [
            syscalls::ALT_BN128_G1_ADD_BE,
            syscalls::ALT_BN128_G1_MUL_BE,
            syscalls::ALT_BN128_PAIRING_BE,
        ] {
            assert!(!rejected_by_gate(&call_group_op(false, true, op)));
        }
        // The little-endian G2 forms belong to the G2 gate, not this one — with
        // G2 active they pass even though the LE feature is inactive. Gating them
        // here would swap one divergence for another.
        for op in [syscalls::ALT_BN128_G2_ADD_LE, syscalls::ALT_BN128_G2_MUL_LE] {
            assert!(!rejected_by_gate(&call_group_op(false, true, op)));
        }
    }

    #[test]
    fn alt_bn128_g2_ops_rejected_when_feature_inactive() {
        for op in [
            syscalls::ALT_BN128_G2_ADD_BE,
            syscalls::ALT_BN128_G2_MUL_BE,
            syscalls::ALT_BN128_G2_ADD_LE,
            syscalls::ALT_BN128_G2_MUL_LE,
        ] {
            assert!(
                rejected_by_gate(&call_group_op(true, false, op)),
                "op {op:#x} must be refused while enable_alt_bn128_g2_syscalls is inactive"
            );
        }
    }

    #[test]
    fn alt_bn128_group_ops_pass_the_gates_when_both_features_active() {
        for op in [
            syscalls::ALT_BN128_G1_ADD_LE,
            syscalls::ALT_BN128_G1_MUL_LE,
            syscalls::ALT_BN128_PAIRING_LE,
            syscalls::ALT_BN128_G2_ADD_BE,
            syscalls::ALT_BN128_G2_MUL_LE,
        ] {
            assert!(!rejected_by_gate(&call_group_op(true, true, op)));
        }
    }

    #[test]
    fn alt_bn128_le_compression_ops_rejected_when_feature_inactive() {
        for op in [
            syscalls::ALT_BN128_G1_COMPRESS_LE,
            syscalls::ALT_BN128_G2_COMPRESS_LE,
            syscalls::ALT_BN128_G1_DECOMPRESS_LE,
            syscalls::ALT_BN128_G2_DECOMPRESS_LE,
        ] {
            assert!(
                rejected_by_gate(&call_compression(false, op)),
                "compression op {op:#x} must be refused while alt_bn128_little_endian is inactive"
            );
        }
        // Compression carries no G2 gate: the big-endian G2 forms stay available.
        for op in [
            syscalls::ALT_BN128_G2_COMPRESS_BE,
            syscalls::ALT_BN128_G2_DECOMPRESS_BE,
        ] {
            assert!(!rejected_by_gate(&call_compression(false, op)));
        }
    }

    #[test]
    fn alt_bn128_gate_state_follows_the_active_feature_ids() {
        use karstflow_ids::features as ids;

        let mut active: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        active.insert(ids::ENABLE_ALT_BN128_SYSCALL.to_bytes());
        active.insert(ids::ENABLE_ALT_BN128_COMPRESSION_SYSCALL.to_bytes());

        // Invoke through the dispatcher so the assertion is about the handler the
        // constructor actually built, not merely about which ids got registered.
        let invoke = |dispatch: &RuntimeSyscallDispatch, name: &str, op: u64| {
            let handler = dispatch
                .handlers
                .get(&murmur3_hash(name))
                .expect("syscall registered");
            let mut vm = make_sysvar_test_vm(crate::sysvar_snapshot::SysvarSnapshot::default());
            handler.call(&mut vm, op, REGION_HEAP_BASE, 0, REGION_HEAP_BASE, 0)
        };

        // The syscalls are registered, but both sub-operation gates are shut.
        let gated = RuntimeSyscallDispatch::with_active_feature_ids(&active);
        assert!(rejected_by_gate(&invoke(
            &gated,
            "sol_alt_bn128_group_op",
            syscalls::ALT_BN128_G1_ADD_LE
        )));
        assert!(rejected_by_gate(&invoke(
            &gated,
            "sol_alt_bn128_group_op",
            syscalls::ALT_BN128_G2_ADD_BE
        )));
        assert!(rejected_by_gate(&invoke(
            &gated,
            "sol_alt_bn128_compression",
            syscalls::ALT_BN128_G1_COMPRESS_LE
        )));

        active.insert(ids::ALT_BN128_LITTLE_ENDIAN.to_bytes());
        active.insert(ids::ENABLE_ALT_BN128_G2_SYSCALLS.to_bytes());
        let opened = RuntimeSyscallDispatch::with_active_feature_ids(&active);
        assert!(!rejected_by_gate(&invoke(
            &opened,
            "sol_alt_bn128_group_op",
            syscalls::ALT_BN128_G1_ADD_LE
        )));
        assert!(!rejected_by_gate(&invoke(
            &opened,
            "sol_alt_bn128_group_op",
            syscalls::ALT_BN128_G2_ADD_BE
        )));
        assert!(!rejected_by_gate(&invoke(
            &opened,
            "sol_alt_bn128_compression",
            syscalls::ALT_BN128_G1_COMPRESS_LE
        )));
    }
}
