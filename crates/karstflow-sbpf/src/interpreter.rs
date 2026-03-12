/// sBPF bytecode interpreter.
///
/// Implements the fetch-decode-execute loop for sBPF programs.
/// Supports all ALU32/ALU64 operations, conditional/unconditional jumps,
/// memory load/store, LDDW, function calls, and syscall dispatch.
use crate::elf_loader::{LoadedProgram, SbpfVersion};
use crate::instruction::Opcode;
use crate::memory::{MemoryError, MemoryMap};
use crate::sysvar_snapshot::SysvarSnapshot;
use karstflow_constants::vm::{
    CALLEE_SAVED_COUNT, CU_PER_INSTRUCTION, MAX_CALL_DEPTH, MAX_INSTRUCTIONS, REGISTER_COUNT,
    REG_CALLEE_SAVED_START,
};

// ---------------------------------------------------------------------------
// Syscall dispatch trait
// ---------------------------------------------------------------------------

/// Trait for dispatching syscalls from the interpreter.
///
/// When the interpreter encounters a CALL instruction whose target
/// is a registered syscall (not a local function), it invokes the
/// dispatch method with the syscall ID.
pub trait SyscallDispatch: Send + Sync {
    /// Execute a syscall.
    ///
    /// Arguments are in r1..r5, return value should be written to r0.
    /// The dispatcher may read/write VM memory and deduct compute units.
    fn dispatch(&self, syscall_id: u32, vm: &mut VmState) -> Result<(), VmError>;
}

/// No-op syscall dispatcher that rejects all syscalls.
pub struct NoSyscalls;

impl SyscallDispatch for NoSyscalls {
    fn dispatch(&self, syscall_id: u32, _vm: &mut VmState) -> Result<(), VmError> {
        Err(VmError::UnknownSyscall { id: syscall_id })
    }
}

// ---------------------------------------------------------------------------
// VM state
// ---------------------------------------------------------------------------

/// Runtime state of the virtual machine.
pub struct VmState {
    /// General-purpose registers r0..r10.
    pub registers: [u64; REGISTER_COUNT],
    /// Program counter (instruction index).
    pub pc: usize,
    /// Virtual memory map.
    pub memory: MemoryMap,
    /// Call stack for nested function frames.
    pub call_stack: Vec<CallFrame>,
    /// Remaining compute units.
    pub compute_meter: u64,
    /// Total instructions executed (for safety limit).
    pub instruction_count: u64,
    /// Accumulated program logs.
    pub logs: Vec<String>,
    /// Total bytes of log messages written (for truncation enforcement).
    pub log_bytes_written: usize,
    /// Whether log truncation has been signaled.
    pub log_truncated: bool,
    /// Return data set by the program or syscalls.
    pub return_data: Option<Vec<u8>>,
    /// Current heap allocation position (bump allocator).
    pub heap_position: u64,
    /// Frozen sysvar state for syscall reads.
    pub sysvar_snapshot: SysvarSnapshot,
    /// CPI invocation depth (separate from function call stack).
    pub cpi_depth: usize,
    /// sBPF version determining available features and instruction semantics.
    pub sbpf_version: SbpfVersion,
}

/// A saved function call frame.
#[derive(Debug, Clone)]
pub struct CallFrame {
    /// Instruction to return to after EXIT.
    pub return_pc: usize,
    /// Saved callee-saved registers (r6..r9).
    pub saved_registers: [u64; CALLEE_SAVED_COUNT],
    /// Saved frame pointer value.
    pub frame_pointer: u64,
}

// ---------------------------------------------------------------------------
// Execution result
// ---------------------------------------------------------------------------

/// Successful execution result.
#[derive(Debug, Clone)]
pub struct VmResult {
    /// Value in r0 at program exit.
    pub return_value: u64,
    /// Compute units consumed.
    pub compute_units_consumed: u64,
    /// Logs accumulated during execution.
    pub logs: Vec<String>,
    /// Return data set by the program.
    pub return_data: Option<Vec<u8>>,
    /// Snapshot of the input region after execution, containing modified account data.
    pub input_region: Vec<u8>,
}

// ---------------------------------------------------------------------------
// VM errors
// ---------------------------------------------------------------------------

/// Errors that can occur during VM execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmError {
    /// Compute budget exhausted.
    ComputeBudgetExceeded,
    /// Memory access violation.
    AccessViolation { addr: u64, size: usize, pc: usize },
    /// Division by zero at runtime.
    DivisionByZero { pc: usize },
    /// Call stack depth exceeded.
    CallDepthExceeded { pc: usize },
    /// Invalid or unknown instruction.
    InvalidInstruction { pc: usize, opcode: u8 },
    /// Program counter went out of bounds.
    PcOutOfBounds { pc: usize, len: usize },
    /// Unknown syscall identifier.
    UnknownSyscall { id: u32 },
    /// Syscall returned an error.
    SyscallError(String),
    /// Exceeded maximum instruction count (infinite loop protection).
    InstructionLimitExceeded,
    /// Memory error wrapper.
    MemoryError(String),
    /// Stack underflow on EXIT.
    StackUnderflow,
}

impl std::fmt::Display for VmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ComputeBudgetExceeded => write!(f, "compute budget exceeded"),
            Self::AccessViolation { addr, size, pc } => {
                write!(
                    f,
                    "PC {}: access violation at 0x{:016X} size {}",
                    pc, addr, size
                )
            }
            Self::DivisionByZero { pc } => write!(f, "PC {}: division by zero", pc),
            Self::CallDepthExceeded { pc } => {
                write!(f, "PC {}: call depth exceeded", pc)
            }
            Self::InvalidInstruction { pc, opcode } => {
                write!(f, "PC {}: invalid instruction 0x{:02X}", pc, opcode)
            }
            Self::PcOutOfBounds { pc, len } => {
                write!(f, "PC {} out of bounds (program length: {})", pc, len)
            }
            Self::UnknownSyscall { id } => {
                write!(f, "unknown syscall 0x{:08X}", id)
            }
            Self::SyscallError(msg) => write!(f, "syscall error: {}", msg),
            Self::InstructionLimitExceeded => write!(f, "instruction limit exceeded"),
            Self::MemoryError(msg) => write!(f, "memory error: {}", msg),
            Self::StackUnderflow => write!(f, "stack underflow on EXIT"),
        }
    }
}

impl std::error::Error for VmError {}

impl From<MemoryError> for VmError {
    fn from(e: MemoryError) -> Self {
        Self::MemoryError(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Segment-based compute unit accounting helpers
// ---------------------------------------------------------------------------

/// Deduct accumulated compute units at a segment boundary.
///
/// Instead of checking CU on every instruction, we accumulate instruction
/// costs within a straight-line segment and deduct the batch at control-flow
/// boundaries (jumps, calls, exits). This reduces per-instruction overhead
/// to a single counter increment.
#[inline(always)]
fn checkpoint_cu(vm: &mut VmState, segment_cu: &mut u64) -> Result<(), VmError> {
    let cost = *segment_cu;
    if vm.compute_meter < cost {
        return Err(VmError::ComputeBudgetExceeded);
    }
    vm.compute_meter -= cost;
    *segment_cu = 0;

    if vm.instruction_count > MAX_INSTRUCTIONS {
        return Err(VmError::InstructionLimitExceeded);
    }
    Ok(())
}

/// Compute the branch target PC from the current PC and signed offset.
#[inline(always)]
fn jump_target(pc: usize, off: i16) -> usize {
    ((pc as isize) + 1 + (off as isize)) as usize
}

// ---------------------------------------------------------------------------
// Interpreter
// ---------------------------------------------------------------------------

/// Execute an sBPF program.
///
/// Runs the fetch-decode-execute loop until the program exits,
/// exceeds its compute budget, or encounters an error.
pub fn execute(
    program: &LoadedProgram,
    memory: MemoryMap,
    compute_budget: u64,
    syscall_dispatch: &dyn SyscallDispatch,
    sysvar_snapshot: SysvarSnapshot,
) -> Result<VmResult, VmError> {
    let instructions = &program.instructions;

    if instructions.is_empty() {
        return Err(VmError::PcOutOfBounds { pc: 0, len: 0 });
    }

    let sbpf_version = program.sbpf_version;

    let mut vm = VmState {
        registers: [0u64; REGISTER_COUNT],
        pc: program.entry_point,
        memory,
        call_stack: Vec::with_capacity(MAX_CALL_DEPTH),
        compute_meter: compute_budget,
        instruction_count: 0,
        logs: Vec::new(),
        log_bytes_written: 0,
        log_truncated: false,
        return_data: None,
        heap_position: karstflow_constants::vm::REGION_HEAP_BASE,
        sysvar_snapshot,
        cpi_depth: 0,
        sbpf_version,
    };

    // Set initial frame pointer (r10)
    vm.registers[10] = vm.memory.frame_pointer();

    // Segment-based CU accounting: accumulate instruction cost within
    // straight-line segments and deduct the batch at control-flow boundaries
    // (jumps, calls, exits). Eliminates per-instruction branch overhead.
    let mut segment_cu: u64 = 0;

    loop {
        // Check PC bounds
        if vm.pc >= instructions.len() {
            return Err(VmError::PcOutOfBounds {
                pc: vm.pc,
                len: instructions.len(),
            });
        }

        // Accumulate CU cost — deduction happens at segment boundaries
        segment_cu += CU_PER_INSTRUCTION;
        vm.instruction_count += 1;

        let insn = &instructions[vm.pc];
        let dst = insn.dst as usize;
        let src = insn.src as usize;
        let imm = insn.immediate;
        let off = insn.offset;

        // Pre-fetch register values before dispatch to help the CPU
        // pipeline memory loads ahead of the match branch resolution.
        let reg_dst = vm.registers[dst];
        let reg_src = vm.registers[src];

        let opcode = match Opcode::from_raw(insn.opcode) {
            Some(op) => op,
            None => {
                return Err(VmError::InvalidInstruction {
                    pc: vm.pc,
                    opcode: insn.opcode,
                });
            }
        };

        match opcode {
            // =================================================================
            // ALU64 immediate
            // =================================================================
            Opcode::Add64Imm => {
                vm.registers[dst] = reg_dst.wrapping_add(imm as u64);
            }
            Opcode::Sub64Imm => {
                vm.registers[dst] = reg_dst.wrapping_sub(imm as u64);
            }
            Opcode::Mul64Imm => {
                vm.registers[dst] = reg_dst.wrapping_mul(imm as u64);
            }
            Opcode::Div64Imm => {
                if imm == 0 {
                    return Err(VmError::DivisionByZero { pc: vm.pc });
                }
                vm.registers[dst] = reg_dst / imm as u64;
            }
            Opcode::Or64Imm => {
                vm.registers[dst] = reg_dst | imm as u64;
            }
            Opcode::And64Imm => {
                vm.registers[dst] = reg_dst & imm as u64;
            }
            Opcode::Lsh64Imm => {
                vm.registers[dst] = reg_dst.wrapping_shl(imm as u32);
            }
            Opcode::Rsh64Imm => {
                vm.registers[dst] = reg_dst.wrapping_shr(imm as u32);
            }
            Opcode::Neg64 => {
                // NEG disabled in SBPF V2+
                if sbpf_version.neg_disabled() {
                    return Err(VmError::InvalidInstruction {
                        pc: vm.pc,
                        opcode: insn.opcode,
                    });
                }
                vm.registers[dst] = (-(reg_dst as i64)) as u64;
            }
            Opcode::Mod64Imm => {
                if imm == 0 {
                    return Err(VmError::DivisionByZero { pc: vm.pc });
                }
                vm.registers[dst] = reg_dst % imm as u64;
            }
            Opcode::Xor64Imm => {
                vm.registers[dst] = reg_dst ^ imm as u64;
            }
            Opcode::Mov64Imm => {
                vm.registers[dst] = imm as u64;
            }
            Opcode::Arsh64Imm => {
                vm.registers[dst] = ((reg_dst as i64).wrapping_shr(imm as u32)) as u64;
            }

            // =================================================================
            // ALU64 register
            // =================================================================
            Opcode::Add64Reg => {
                vm.registers[dst] = reg_dst.wrapping_add(reg_src);
            }
            Opcode::Sub64Reg => {
                vm.registers[dst] = reg_dst.wrapping_sub(reg_src);
            }
            Opcode::Mul64Reg => {
                vm.registers[dst] = reg_dst.wrapping_mul(reg_src);
            }
            Opcode::Div64Reg => {
                if reg_src == 0 {
                    return Err(VmError::DivisionByZero { pc: vm.pc });
                }
                vm.registers[dst] = reg_dst / reg_src;
            }
            Opcode::Or64Reg => {
                vm.registers[dst] = reg_dst | reg_src;
            }
            Opcode::And64Reg => {
                vm.registers[dst] = reg_dst & reg_src;
            }
            Opcode::Lsh64Reg => {
                vm.registers[dst] = reg_dst.wrapping_shl((reg_src & 0x3F) as u32);
            }
            Opcode::Rsh64Reg => {
                vm.registers[dst] = reg_dst.wrapping_shr((reg_src & 0x3F) as u32);
            }
            Opcode::Mod64Reg => {
                if reg_src == 0 {
                    return Err(VmError::DivisionByZero { pc: vm.pc });
                }
                vm.registers[dst] = reg_dst % reg_src;
            }
            Opcode::Xor64Reg => {
                vm.registers[dst] = reg_dst ^ reg_src;
            }
            Opcode::Mov64Reg => {
                vm.registers[dst] = reg_src;
            }
            Opcode::Arsh64Reg => {
                vm.registers[dst] = ((reg_dst as i64).wrapping_shr((reg_src & 0x3F) as u32)) as u64;
            }

            // =================================================================
            // ALU32 immediate (result zero-extended to 64 bits)
            // =================================================================
            Opcode::Add32Imm => {
                vm.registers[dst] = (reg_dst as u32).wrapping_add(imm as u32) as u64;
            }
            Opcode::Sub32Imm => {
                vm.registers[dst] = (reg_dst as u32).wrapping_sub(imm as u32) as u64;
            }
            Opcode::Mul32Imm => {
                vm.registers[dst] = (reg_dst as u32).wrapping_mul(imm as u32) as u64;
            }
            Opcode::Div32Imm => {
                if imm == 0 {
                    return Err(VmError::DivisionByZero { pc: vm.pc });
                }
                vm.registers[dst] = ((reg_dst as u32) / (imm as u32)) as u64;
            }
            Opcode::Or32Imm => {
                vm.registers[dst] = ((reg_dst as u32) | (imm as u32)) as u64;
            }
            Opcode::And32Imm => {
                vm.registers[dst] = ((reg_dst as u32) & (imm as u32)) as u64;
            }
            Opcode::Lsh32Imm => {
                vm.registers[dst] = (reg_dst as u32).wrapping_shl(imm as u32) as u64;
            }
            Opcode::Rsh32Imm => {
                vm.registers[dst] = (reg_dst as u32).wrapping_shr(imm as u32) as u64;
            }
            Opcode::Neg32 => {
                if sbpf_version.neg_disabled() {
                    return Err(VmError::InvalidInstruction {
                        pc: vm.pc,
                        opcode: insn.opcode,
                    });
                }
                vm.registers[dst] = (-(reg_dst as i32)) as u32 as u64;
            }
            Opcode::Mod32Imm => {
                if imm == 0 {
                    return Err(VmError::DivisionByZero { pc: vm.pc });
                }
                vm.registers[dst] = ((reg_dst as u32) % (imm as u32)) as u64;
            }
            Opcode::Xor32Imm => {
                vm.registers[dst] = ((reg_dst as u32) ^ (imm as u32)) as u64;
            }
            Opcode::Mov32Imm => {
                vm.registers[dst] = imm as u32 as u64;
            }
            Opcode::Arsh32Imm => {
                vm.registers[dst] = ((reg_dst as i32).wrapping_shr(imm as u32)) as u32 as u64;
            }

            // =================================================================
            // ALU32 register (result zero-extended to 64 bits)
            // =================================================================
            Opcode::Add32Reg => {
                vm.registers[dst] = (reg_dst as u32).wrapping_add(reg_src as u32) as u64;
            }
            Opcode::Sub32Reg => {
                vm.registers[dst] = (reg_dst as u32).wrapping_sub(reg_src as u32) as u64;
            }
            Opcode::Mul32Reg => {
                vm.registers[dst] = (reg_dst as u32).wrapping_mul(reg_src as u32) as u64;
            }
            Opcode::Div32Reg => {
                if (reg_src as u32) == 0 {
                    return Err(VmError::DivisionByZero { pc: vm.pc });
                }
                vm.registers[dst] = ((reg_dst as u32) / (reg_src as u32)) as u64;
            }
            Opcode::Or32Reg => {
                vm.registers[dst] = ((reg_dst as u32) | (reg_src as u32)) as u64;
            }
            Opcode::And32Reg => {
                vm.registers[dst] = ((reg_dst as u32) & (reg_src as u32)) as u64;
            }
            Opcode::Lsh32Reg => {
                vm.registers[dst] = (reg_dst as u32).wrapping_shl((reg_src & 0x1F) as u32) as u64;
            }
            Opcode::Rsh32Reg => {
                vm.registers[dst] = (reg_dst as u32).wrapping_shr((reg_src & 0x1F) as u32) as u64;
            }
            Opcode::Mod32Reg => {
                if (reg_src as u32) == 0 {
                    return Err(VmError::DivisionByZero { pc: vm.pc });
                }
                vm.registers[dst] = ((reg_dst as u32) % (reg_src as u32)) as u64;
            }
            Opcode::Xor32Reg => {
                vm.registers[dst] = ((reg_dst as u32) ^ (reg_src as u32)) as u64;
            }
            Opcode::Mov32Reg => {
                vm.registers[dst] = reg_src as u32 as u64;
            }
            Opcode::Arsh32Reg => {
                vm.registers[dst] =
                    ((reg_dst as i32).wrapping_shr((reg_src & 0x1F) as u32)) as u32 as u64;
            }

            // =================================================================
            // Byte-order conversion
            // =================================================================
            Opcode::Le => {
                // LE instruction disabled in SBPF V2+
                if sbpf_version.le_disabled() {
                    return Err(VmError::InvalidInstruction {
                        pc: vm.pc,
                        opcode: insn.opcode,
                    });
                }
                // Already little-endian on LE hosts; truncate to width
                vm.registers[dst] = match imm {
                    16 => reg_dst & 0xFFFF,
                    32 => reg_dst & 0xFFFF_FFFF,
                    64 => reg_dst,
                    _ => reg_dst,
                };
            }
            Opcode::Be => {
                vm.registers[dst] = match imm {
                    16 => (reg_dst as u16).swap_bytes() as u64,
                    32 => (reg_dst as u32).swap_bytes() as u64,
                    64 => reg_dst.swap_bytes(),
                    _ => reg_dst,
                };
            }

            // =================================================================
            // LDDW (load 64-bit immediate, consumes two instruction slots)
            // =================================================================
            Opcode::Lddw => {
                // LDDW disabled in SBPF V2+
                if sbpf_version.lddw_disabled() {
                    return Err(VmError::InvalidInstruction {
                        pc: vm.pc,
                        opcode: insn.opcode,
                    });
                }
                let lo = imm as u32 as u64;
                // Read the high 32 bits from the next instruction slot
                if vm.pc + 1 >= instructions.len() {
                    return Err(VmError::InvalidInstruction {
                        pc: vm.pc,
                        opcode: insn.opcode,
                    });
                }
                let hi = instructions[vm.pc + 1].immediate as u32 as u64;
                vm.registers[dst] = lo | (hi << 32);
                // LDDW consumes two instruction slots; account for the second
                segment_cu += CU_PER_INSTRUCTION;
                vm.instruction_count += 1;
                vm.pc += 2; // Skip both slots
                continue;
            }

            // =================================================================
            // Memory load (LDX)
            // =================================================================
            Opcode::LdxByte => {
                let addr = reg_src.wrapping_add(off as i64 as u64);
                vm.registers[dst] =
                    vm.memory
                        .load8(addr)
                        .map_err(|_| VmError::AccessViolation {
                            addr,
                            size: 1,
                            pc: vm.pc,
                        })?;
            }
            Opcode::LdxHalf => {
                let addr = reg_src.wrapping_add(off as i64 as u64);
                vm.registers[dst] =
                    vm.memory
                        .load16(addr)
                        .map_err(|_| VmError::AccessViolation {
                            addr,
                            size: 2,
                            pc: vm.pc,
                        })?;
            }
            Opcode::LdxWord => {
                let addr = reg_src.wrapping_add(off as i64 as u64);
                vm.registers[dst] =
                    vm.memory
                        .load32(addr)
                        .map_err(|_| VmError::AccessViolation {
                            addr,
                            size: 4,
                            pc: vm.pc,
                        })?;
            }
            Opcode::LdxDword => {
                let addr = reg_src.wrapping_add(off as i64 as u64);
                vm.registers[dst] =
                    vm.memory
                        .load64(addr)
                        .map_err(|_| VmError::AccessViolation {
                            addr,
                            size: 8,
                            pc: vm.pc,
                        })?;
            }

            // =================================================================
            // Memory store immediate (ST)
            // =================================================================
            Opcode::StByte => {
                let addr = reg_dst.wrapping_add(off as i64 as u64);
                vm.memory
                    .store8(addr, imm as u64)
                    .map_err(|_| VmError::AccessViolation {
                        addr,
                        size: 1,
                        pc: vm.pc,
                    })?;
            }
            Opcode::StHalf => {
                let addr = reg_dst.wrapping_add(off as i64 as u64);
                vm.memory
                    .store16(addr, imm as u64)
                    .map_err(|_| VmError::AccessViolation {
                        addr,
                        size: 2,
                        pc: vm.pc,
                    })?;
            }
            Opcode::StWord => {
                let addr = reg_dst.wrapping_add(off as i64 as u64);
                vm.memory
                    .store32(addr, imm as u64)
                    .map_err(|_| VmError::AccessViolation {
                        addr,
                        size: 4,
                        pc: vm.pc,
                    })?;
            }
            Opcode::StDword => {
                let addr = reg_dst.wrapping_add(off as i64 as u64);
                vm.memory
                    .store64(addr, imm as u64)
                    .map_err(|_| VmError::AccessViolation {
                        addr,
                        size: 8,
                        pc: vm.pc,
                    })?;
            }

            // =================================================================
            // Memory store register (STX)
            // =================================================================
            Opcode::StxByte => {
                let addr = reg_dst.wrapping_add(off as i64 as u64);
                vm.memory
                    .store8(addr, reg_src)
                    .map_err(|_| VmError::AccessViolation {
                        addr,
                        size: 1,
                        pc: vm.pc,
                    })?;
            }
            Opcode::StxHalf => {
                let addr = reg_dst.wrapping_add(off as i64 as u64);
                vm.memory
                    .store16(addr, reg_src)
                    .map_err(|_| VmError::AccessViolation {
                        addr,
                        size: 2,
                        pc: vm.pc,
                    })?;
            }
            Opcode::StxWord => {
                let addr = reg_dst.wrapping_add(off as i64 as u64);
                vm.memory
                    .store32(addr, reg_src)
                    .map_err(|_| VmError::AccessViolation {
                        addr,
                        size: 4,
                        pc: vm.pc,
                    })?;
            }
            Opcode::StxDword => {
                let addr = reg_dst.wrapping_add(off as i64 as u64);
                vm.memory
                    .store64(addr, reg_src)
                    .map_err(|_| VmError::AccessViolation {
                        addr,
                        size: 8,
                        pc: vm.pc,
                    })?;
            }

            // =================================================================
            // Jumps (64-bit comparison)
            // =================================================================
            Opcode::Ja => {
                checkpoint_cu(&mut vm, &mut segment_cu)?;
                vm.pc = jump_target(vm.pc, off);
                continue;
            }
            Opcode::JeqImm => {
                if reg_dst == imm as u64 {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::JeqReg => {
                if reg_dst == reg_src {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::JgtImm => {
                if reg_dst > imm as u64 {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::JgtReg => {
                if reg_dst > reg_src {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::JgeImm => {
                if reg_dst >= imm as u64 {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::JgeReg => {
                if reg_dst >= reg_src {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::JsetImm => {
                if (reg_dst & (imm as u64)) != 0 {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::JsetReg => {
                if (reg_dst & reg_src) != 0 {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::JneImm => {
                if reg_dst != imm as u64 {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::JneReg => {
                if reg_dst != reg_src {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::JsgtImm => {
                if (reg_dst as i64) > (imm as i64) {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::JsgtReg => {
                if (reg_dst as i64) > (reg_src as i64) {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::JsgeImm => {
                if (reg_dst as i64) >= (imm as i64) {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::JsgeReg => {
                if (reg_dst as i64) >= (reg_src as i64) {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::JltImm => {
                if reg_dst < imm as u64 {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::JltReg => {
                if reg_dst < reg_src {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::JleImm => {
                if reg_dst <= imm as u64 {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::JleReg => {
                if reg_dst <= reg_src {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::JsltImm => {
                if (reg_dst as i64) < (imm as i64) {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::JsltReg => {
                if (reg_dst as i64) < (reg_src as i64) {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::JsleImm => {
                if (reg_dst as i64) <= (imm as i64) {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::JsleReg => {
                if (reg_dst as i64) <= (reg_src as i64) {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }

            // =================================================================
            // Jump32 (32-bit comparison)
            // =================================================================
            Opcode::Jeq32Imm => {
                if (reg_dst as u32) == (imm as u32) {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::Jeq32Reg => {
                if (reg_dst as u32) == (reg_src as u32) {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::Jgt32Imm => {
                if (reg_dst as u32) > (imm as u32) {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::Jgt32Reg => {
                if (reg_dst as u32) > (reg_src as u32) {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::Jge32Imm => {
                if (reg_dst as u32) >= (imm as u32) {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::Jge32Reg => {
                if (reg_dst as u32) >= (reg_src as u32) {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::Jset32Imm => {
                if ((reg_dst as u32) & (imm as u32)) != 0 {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::Jset32Reg => {
                if ((reg_dst as u32) & (reg_src as u32)) != 0 {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::Jne32Imm => {
                if (reg_dst as u32) != (imm as u32) {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::Jne32Reg => {
                if (reg_dst as u32) != (reg_src as u32) {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::Jsgt32Imm => {
                if (reg_dst as i32) > imm {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::Jsgt32Reg => {
                if (reg_dst as i32) > (reg_src as i32) {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::Jsge32Imm => {
                if (reg_dst as i32) >= imm {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::Jsge32Reg => {
                if (reg_dst as i32) >= (reg_src as i32) {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::Jlt32Imm => {
                if (reg_dst as u32) < (imm as u32) {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::Jlt32Reg => {
                if (reg_dst as u32) < (reg_src as u32) {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::Jle32Imm => {
                if (reg_dst as u32) <= (imm as u32) {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::Jle32Reg => {
                if (reg_dst as u32) <= (reg_src as u32) {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::Jslt32Imm => {
                if (reg_dst as i32) < imm {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::Jslt32Reg => {
                if (reg_dst as i32) < (reg_src as i32) {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::Jsle32Imm => {
                if (reg_dst as i32) <= imm {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }
            Opcode::Jsle32Reg => {
                if (reg_dst as i32) <= (reg_src as i32) {
                    checkpoint_cu(&mut vm, &mut segment_cu)?;
                    vm.pc = jump_target(vm.pc, off);
                    continue;
                }
            }

            // =================================================================
            // CALL — function call or syscall
            // =================================================================
            Opcode::Call => {
                // Deduct accumulated CU at function call boundary
                checkpoint_cu(&mut vm, &mut segment_cu)?;

                let target_id = imm as u32;

                // Check if it's a local call (in call_targets)
                if let Some(&target_pc) = program.call_targets.get(&target_id) {
                    // Save callee-saved registers
                    let mut saved = [0u64; CALLEE_SAVED_COUNT];
                    for j in 0..CALLEE_SAVED_COUNT {
                        saved[j] = vm.registers[REG_CALLEE_SAVED_START as usize + j];
                    }

                    let frame = CallFrame {
                        return_pc: vm.pc + 1,
                        saved_registers: saved,
                        frame_pointer: vm.registers[10],
                    };

                    if vm.call_stack.len() >= MAX_CALL_DEPTH {
                        return Err(VmError::CallDepthExceeded { pc: vm.pc });
                    }

                    vm.call_stack.push(frame);

                    // Advance stack frame.
                    // V0 uses fixed stack with guard zones; V1+ uses dynamic frames.
                    let new_fp = vm
                        .memory
                        .push_frame(sbpf_version.has_dynamic_stack_frames())
                        .map_err(|_| VmError::CallDepthExceeded { pc: vm.pc })?;
                    vm.registers[10] = new_fp;

                    vm.pc = target_pc;
                    continue;
                }

                // Otherwise, it's a syscall
                syscall_dispatch.dispatch(target_id, &mut vm)?;
            }

            // =================================================================
            // SYSCALL (SBPFv2) — dedicated syscall invocation
            // =================================================================
            Opcode::Syscall => {
                checkpoint_cu(&mut vm, &mut segment_cu)?;
                let target_id = imm as u32;
                syscall_dispatch.dispatch(target_id, &mut vm)?;
            }

            // =================================================================
            // EXIT — return from function or halt
            // =================================================================
            Opcode::Exit => {
                // Deduct accumulated CU at exit boundary
                checkpoint_cu(&mut vm, &mut segment_cu)?;

                if vm.call_stack.is_empty() {
                    // Program halt — return r0
                    let consumed = compute_budget - vm.compute_meter;
                    let input_region = vm.memory.input_data().to_vec();
                    return Ok(VmResult {
                        return_value: vm.registers[0],
                        compute_units_consumed: consumed,
                        logs: vm.logs,
                        return_data: vm.return_data,
                        input_region,
                    });
                }

                // Pop frame
                let frame = vm.call_stack.pop().unwrap();

                // Restore callee-saved registers
                for j in 0..CALLEE_SAVED_COUNT {
                    vm.registers[REG_CALLEE_SAVED_START as usize + j] = frame.saved_registers[j];
                }
                vm.registers[10] = frame.frame_pointer;

                vm.memory
                    .pop_frame(sbpf_version.has_dynamic_stack_frames())
                    .map_err(|_| VmError::StackUnderflow)?;

                vm.pc = frame.return_pc;
                continue;
            }
        }

        // Advance PC (for non-jump, non-lddw instructions)
        vm.pc += 1;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf_loader::load_raw;
    use crate::instruction::Instruction;
    use crate::memory::MemoryMap;
    use karstflow_constants::vm::{DEFAULT_HEAP_SIZE, REGION_STACK_BASE, TOTAL_STACK_SIZE};

    fn make_program_bytes(insns: &[Instruction]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for insn in insns {
            bytes.extend_from_slice(&insn.encode().to_le_bytes());
        }
        bytes
    }

    fn run_program(insns: &[Instruction]) -> Result<VmResult, VmError> {
        let bytes = make_program_bytes(insns);
        let program = load_raw(&bytes).unwrap();
        let memory = MemoryMap::new(&[], TOTAL_STACK_SIZE, DEFAULT_HEAP_SIZE, vec![]);
        execute(
            &program,
            memory,
            10_000,
            &NoSyscalls,
            SysvarSnapshot::default(),
        )
    }

    #[test]
    fn return_zero() {
        let result = run_program(&[
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 0),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ])
        .unwrap();
        assert_eq!(result.return_value, 0);
    }

    #[test]
    fn return_immediate() {
        let result = run_program(&[
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 42),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ])
        .unwrap();
        assert_eq!(result.return_value, 42);
    }

    #[test]
    fn add64_imm() {
        let result = run_program(&[
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 10),
            Instruction::new(Opcode::Add64Imm as u8, 0, 0, 0, 32),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ])
        .unwrap();
        assert_eq!(result.return_value, 42);
    }

    #[test]
    fn add64_reg() {
        let result = run_program(&[
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 10),
            Instruction::new(Opcode::Mov64Imm as u8, 1, 0, 0, 32),
            Instruction::new(Opcode::Add64Reg as u8, 0, 1, 0, 0),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ])
        .unwrap();
        assert_eq!(result.return_value, 42);
    }

    #[test]
    fn sub_mul_div_mod() {
        // (100 - 10) * 3 / 9 % 7 = 90 * 3 = 270 / 9 = 30 % 7 = 2
        let result = run_program(&[
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 100),
            Instruction::new(Opcode::Sub64Imm as u8, 0, 0, 0, 10),
            Instruction::new(Opcode::Mul64Imm as u8, 0, 0, 0, 3),
            Instruction::new(Opcode::Div64Imm as u8, 0, 0, 0, 9),
            Instruction::new(Opcode::Mod64Imm as u8, 0, 0, 0, 7),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ])
        .unwrap();
        assert_eq!(result.return_value, 2);
    }

    #[test]
    fn bitwise_ops() {
        // 0xFF & 0x0F = 0x0F, | 0xF0 = 0xFF, ^ 0xAA = 0x55
        let result = run_program(&[
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 0xFF),
            Instruction::new(Opcode::And64Imm as u8, 0, 0, 0, 0x0F),
            Instruction::new(Opcode::Or64Imm as u8, 0, 0, 0, 0xF0u32 as i32),
            Instruction::new(Opcode::Xor64Imm as u8, 0, 0, 0, 0xAAu32 as i32),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ])
        .unwrap();
        assert_eq!(result.return_value, 0x55);
    }

    #[test]
    fn shift_ops() {
        // 1 << 4 = 16, >> 2 = 4
        let result = run_program(&[
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 1),
            Instruction::new(Opcode::Lsh64Imm as u8, 0, 0, 0, 4),
            Instruction::new(Opcode::Rsh64Imm as u8, 0, 0, 0, 2),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ])
        .unwrap();
        assert_eq!(result.return_value, 4);
    }

    #[test]
    fn neg64() {
        let result = run_program(&[
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 42),
            Instruction::new(Opcode::Neg64 as u8, 0, 0, 0, 0),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ])
        .unwrap();
        assert_eq!(result.return_value as i64, -42);
    }

    #[test]
    fn alu32_zero_extends() {
        let result = run_program(&[
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, -1), // 0xFFFFFFFFFFFFFFFF
            Instruction::new(Opcode::Add32Imm as u8, 0, 0, 0, 1), // (0xFFFFFFFF + 1) & 0xFFFFFFFF = 0
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ])
        .unwrap();
        assert_eq!(result.return_value, 0); // Zero-extended from 32-bit 0
    }

    #[test]
    fn unconditional_jump() {
        let result = run_program(&[
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 1),
            Instruction::new(Opcode::Ja as u8, 0, 0, 1, 0), // skip next
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 99),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ])
        .unwrap();
        assert_eq!(result.return_value, 1); // Skipped mov 99
    }

    #[test]
    fn conditional_jump_taken() {
        let result = run_program(&[
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 5),
            Instruction::new(Opcode::JeqImm as u8, 0, 0, 1, 5), // r0 == 5, jump
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 99),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ])
        .unwrap();
        assert_eq!(result.return_value, 5); // Jump was taken
    }

    #[test]
    fn conditional_jump_not_taken() {
        let result = run_program(&[
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 5),
            Instruction::new(Opcode::JeqImm as u8, 0, 0, 1, 10), // r0 != 10, fall through
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 99),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ])
        .unwrap();
        assert_eq!(result.return_value, 99); // Jump not taken
    }

    #[test]
    fn loop_with_counter() {
        // r0 = 0; r1 = 5; loop: r0 += 1; r1 -= 1; if r1 != 0 goto loop; exit
        let result = run_program(&[
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 0), // r0 = 0
            Instruction::new(Opcode::Mov64Imm as u8, 1, 0, 0, 5), // r1 = 5
            Instruction::new(Opcode::Add64Imm as u8, 0, 0, 0, 1), // r0 += 1
            Instruction::new(Opcode::Sub64Imm as u8, 1, 0, 0, 1), // r1 -= 1
            Instruction::new(Opcode::JneImm as u8, 1, 0, -3, 0),  // if r1 != 0 goto loop
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ])
        .unwrap();
        assert_eq!(result.return_value, 5);
    }

    #[test]
    fn memory_store_load() {
        let bytes = make_program_bytes(&[
            Instruction::new(Opcode::Mov64Imm as u8, 1, 0, 0, 0xBEEF),
            // Store r1 to stack[r10-8]
            Instruction::new(Opcode::StxDword as u8, 10, 1, -8, 0),
            // Load from stack[r10-8] into r0
            Instruction::new(Opcode::LdxDword as u8, 0, 10, -8, 0),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ]);
        let program = load_raw(&bytes).unwrap();
        let memory = MemoryMap::new(&[], TOTAL_STACK_SIZE, DEFAULT_HEAP_SIZE, vec![]);
        let result = execute(
            &program,
            memory,
            10_000,
            &NoSyscalls,
            SysvarSnapshot::default(),
        )
        .unwrap();
        assert_eq!(result.return_value, 0xBEEF);
    }

    #[test]
    fn lddw_loads_64bit() {
        // lddw r0, 0x0000000100000002 (lo=2, hi=1)
        let result = run_program(&[
            Instruction::new(Opcode::Lddw as u8, 0, 0, 0, 2), // lo = 2
            Instruction::new(0, 0, 0, 0, 1),                  // hi = 1
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ])
        .unwrap();
        assert_eq!(result.return_value, 0x0000_0001_0000_0002);
    }

    #[test]
    fn division_by_zero_runtime() {
        let result = run_program(&[
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 10),
            Instruction::new(Opcode::Mov64Imm as u8, 1, 0, 0, 0),
            Instruction::new(Opcode::Div64Reg as u8, 0, 1, 0, 0), // div by r1=0
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ]);
        assert!(matches!(result, Err(VmError::DivisionByZero { .. })));
    }

    #[test]
    fn compute_budget_exhausted() {
        // Program with loop that will exhaust 5 CU budget
        let result = run_program_with_budget(
            &[
                Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 0),
                Instruction::new(Opcode::Add64Imm as u8, 0, 0, 0, 1),
                Instruction::new(Opcode::Ja as u8, 0, 0, -2, 0), // infinite loop
                Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
            ],
            5,
        );
        assert!(matches!(result, Err(VmError::ComputeBudgetExceeded)));
    }

    fn run_program_with_budget(insns: &[Instruction], budget: u64) -> Result<VmResult, VmError> {
        let bytes = make_program_bytes(insns);
        let program = load_raw(&bytes).unwrap();
        let memory = MemoryMap::new(&[], TOTAL_STACK_SIZE, DEFAULT_HEAP_SIZE, vec![]);
        execute(
            &program,
            memory,
            budget,
            &NoSyscalls,
            SysvarSnapshot::default(),
        )
    }

    #[test]
    fn compute_units_tracked() {
        let result = run_program(&[
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 42),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ])
        .unwrap();
        assert_eq!(result.compute_units_consumed, 2); // 2 instructions executed
    }

    #[test]
    fn endian_swap() {
        let result = run_program(&[
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 0x0100), // 256
            Instruction::new(Opcode::Be as u8, 0, 0, 0, 16), // swap 16-bit: 0x0100 → 0x0001
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ])
        .unwrap();
        assert_eq!(result.return_value, 1);
    }

    #[test]
    fn local_function_call() {
        // Program:
        //   0: mov64 r1, 10       ; arg to function
        //   1: call +1             ; call function at PC 3
        //   2: exit                ; return from main
        //   3: mov64 r0, r1        ; function body: r0 = r1
        //   4: add64 r0, 5         ; r0 += 5
        //   5: exit                ; return from function
        let insns = [
            Instruction::new(Opcode::Mov64Imm as u8, 1, 0, 0, 10),
            Instruction::new(Opcode::Call as u8, 0, 0, 0, 1), // target_id=1, maps to pc=3
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
            Instruction::new(Opcode::Mov64Reg as u8, 0, 1, 0, 0),
            Instruction::new(Opcode::Add64Imm as u8, 0, 0, 0, 5),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ];
        let bytes = make_program_bytes(&insns);
        let program = load_raw(&bytes).unwrap();
        // Verify call_targets was built
        assert!(program.call_targets.contains_key(&1));

        let memory = MemoryMap::new(&[], TOTAL_STACK_SIZE, DEFAULT_HEAP_SIZE, vec![]);
        let result = execute(
            &program,
            memory,
            10_000,
            &NoSyscalls,
            SysvarSnapshot::default(),
        )
        .unwrap();
        assert_eq!(result.return_value, 15); // 10 + 5
    }

    #[test]
    fn access_violation() {
        let result = run_program(&[
            Instruction::new(Opcode::Mov64Imm as u8, 1, 0, 0, 0), // r1 = 0 (unmapped)
            Instruction::new(Opcode::LdxDword as u8, 0, 1, 0, 0), // load from addr 0
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ]);
        assert!(matches!(result, Err(VmError::AccessViolation { .. })));
    }

    #[test]
    fn jgt_signed_comparison() {
        // r0 = -1 (unsigned: very large), compare signed: -1 > 0 is false
        let result = run_program(&[
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, -1), // r0 = -1 (0xFFFFFFFFFFFFFFFF)
            Instruction::new(Opcode::JsgtImm as u8, 0, 0, 1, 0),   // if (i64)r0 > 0, skip
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 100), // not taken: r0=100
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ])
        .unwrap();
        assert_eq!(result.return_value, 100); // Signed comparison: -1 is not > 0
    }

    #[test]
    fn arsh_sign_extension() {
        let result = run_program(&[
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, -128), // 0xFFFFFF..80
            Instruction::new(Opcode::Arsh64Imm as u8, 0, 0, 0, 1),   // arithmetic right shift
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ])
        .unwrap();
        assert_eq!(result.return_value as i64, -64); // Sign-extended
    }

    // --- Version-aware execution tests ---

    fn run_program_v2(insns: &[Instruction]) -> Result<VmResult, VmError> {
        let bytes = make_program_bytes(insns);
        let mut program = load_raw(&bytes).unwrap();
        program.sbpf_version = SbpfVersion::V2;
        let memory = MemoryMap::new(&[], TOTAL_STACK_SIZE, DEFAULT_HEAP_SIZE, vec![]);
        execute(
            &program,
            memory,
            10_000,
            &NoSyscalls,
            SysvarSnapshot::default(),
        )
    }

    #[test]
    fn v0_lddw_succeeds() {
        // V0: LDDW is allowed
        let result = run_program(&[
            Instruction::new(Opcode::Lddw as u8, 0, 0, 0, 42),
            Instruction::new(0, 0, 0, 0, 0),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ])
        .unwrap();
        assert_eq!(result.return_value, 42);
    }

    #[test]
    fn v2_lddw_rejected() {
        // V2: LDDW should be rejected
        let result = run_program_v2(&[
            Instruction::new(Opcode::Lddw as u8, 0, 0, 0, 42),
            Instruction::new(0, 0, 0, 0, 0),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ]);
        assert!(matches!(result, Err(VmError::InvalidInstruction { .. })));
    }

    #[test]
    fn v0_le_succeeds() {
        let result = run_program(&[
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 0x0100),
            Instruction::new(Opcode::Le as u8, 0, 0, 0, 16),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ])
        .unwrap();
        assert_eq!(result.return_value, 0x0100);
    }

    #[test]
    fn v2_le_rejected() {
        let result = run_program_v2(&[
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 0x0100),
            Instruction::new(Opcode::Le as u8, 0, 0, 0, 16),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ]);
        assert!(matches!(result, Err(VmError::InvalidInstruction { .. })));
    }

    #[test]
    fn v0_neg64_succeeds() {
        let result = run_program(&[
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 42),
            Instruction::new(Opcode::Neg64 as u8, 0, 0, 0, 0),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ])
        .unwrap();
        assert_eq!(result.return_value as i64, -42);
    }

    #[test]
    fn v2_neg64_rejected() {
        let result = run_program_v2(&[
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 42),
            Instruction::new(Opcode::Neg64 as u8, 0, 0, 0, 0),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ]);
        assert!(matches!(result, Err(VmError::InvalidInstruction { .. })));
    }

    #[test]
    fn v2_neg32_rejected() {
        let result = run_program_v2(&[
            Instruction::new(Opcode::Mov32Imm as u8, 0, 0, 0, 42),
            Instruction::new(Opcode::Neg32 as u8, 0, 0, 0, 0),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ]);
        assert!(matches!(result, Err(VmError::InvalidInstruction { .. })));
    }

    #[test]
    fn version_propagated_to_vm_state() {
        // Verify version is accessible from VmState during execution
        let bytes = make_program_bytes(&[
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 0),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ]);
        let mut program = load_raw(&bytes).unwrap();
        program.sbpf_version = SbpfVersion::V3;
        let memory = MemoryMap::new(&[], TOTAL_STACK_SIZE, DEFAULT_HEAP_SIZE, vec![]);
        let result = execute(
            &program,
            memory,
            10_000,
            &NoSyscalls,
            SysvarSnapshot::default(),
        )
        .unwrap();
        assert_eq!(result.return_value, 0);
    }

    #[test]
    fn sbpf_version_feature_flags() {
        // Verify feature flag methods
        assert!(!SbpfVersion::V0.has_dynamic_stack_frames());
        assert!(SbpfVersion::V1.has_dynamic_stack_frames());
        assert!(SbpfVersion::V2.has_dynamic_stack_frames());
        assert!(SbpfVersion::V3.has_dynamic_stack_frames());

        assert!(!SbpfVersion::V0.lddw_disabled());
        assert!(!SbpfVersion::V1.lddw_disabled());
        assert!(SbpfVersion::V2.lddw_disabled());
        assert!(SbpfVersion::V3.lddw_disabled());

        assert!(!SbpfVersion::V0.neg_disabled());
        assert!(!SbpfVersion::V1.neg_disabled());
        assert!(SbpfVersion::V2.neg_disabled());
        assert!(SbpfVersion::V3.neg_disabled());

        assert!(!SbpfVersion::V0.le_disabled());
        assert!(!SbpfVersion::V1.le_disabled());
        assert!(SbpfVersion::V2.le_disabled());
        assert!(SbpfVersion::V3.le_disabled());

        assert!(!SbpfVersion::V0.has_static_syscalls());
        assert!(!SbpfVersion::V2.has_static_syscalls());
        assert!(SbpfVersion::V3.has_static_syscalls());
    }

    // --- Segment-based CU accounting tests ---

    #[test]
    fn segment_cu_deducted_at_exit() {
        // 3 instructions: mov, add, exit. CU should be 3 * CU_PER_INSTRUCTION.
        let result = run_program(&[
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 10),
            Instruction::new(Opcode::Add64Imm as u8, 0, 0, 0, 5),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ])
        .unwrap();
        assert_eq!(result.return_value, 15);
        // All 3 instructions charged via segment accounting at EXIT
        assert_eq!(result.compute_units_consumed, 3 * CU_PER_INSTRUCTION);
    }

    #[test]
    fn segment_cu_deducted_at_loop_boundary() {
        // Loop: 3 iterations of (add + sub + jne), then exit.
        // Total instructions: 2(init) + 3*3(loop body) + 1(exit) = 12
        let result = run_program(&[
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 0), // 0: r0 = 0
            Instruction::new(Opcode::Mov64Imm as u8, 1, 0, 0, 3), // 1: r1 = 3
            Instruction::new(Opcode::Add64Imm as u8, 0, 0, 0, 1), // 2: r0 += 1
            Instruction::new(Opcode::Sub64Imm as u8, 1, 0, 0, 1), // 3: r1 -= 1
            Instruction::new(Opcode::JneImm as u8, 1, 0, -3, 0),  // 4: if r1 != 0 goto 2
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),     // 5: exit
        ])
        .unwrap();
        assert_eq!(result.return_value, 3);
        // 2(init) + 3*3(loop: add, sub, jne-taken) + 2(add, sub in last iter before fall-through)
        // Actually: init(2) + iter1(add+sub+jne_taken=3) + iter2(3) + iter3(add+sub+jne_not_taken=3) + exit(1)
        // = 2 + 3 + 3 + 3 + 1 = 12
        assert_eq!(result.compute_units_consumed, 12 * CU_PER_INSTRUCTION);
    }

    #[test]
    fn segment_cu_budget_exceeded_in_loop() {
        // Tight loop should exceed a budget of 10 CU
        let result = run_program_with_budget(
            &[
                Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 0), // r0 = 0
                Instruction::new(Opcode::Add64Imm as u8, 0, 0, 0, 1), // r0 += 1
                Instruction::new(Opcode::Ja as u8, 0, 0, -2, 0),      // infinite loop back to add
                Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
            ],
            10,
        );
        assert!(matches!(result, Err(VmError::ComputeBudgetExceeded)));
    }

    #[test]
    fn segment_cu_exact_budget_succeeds() {
        // 2 instructions, budget = 2 * CU_PER_INSTRUCTION exactly
        let result = run_program_with_budget(
            &[
                Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 42),
                Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
            ],
            2 * CU_PER_INSTRUCTION,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap().return_value, 42);
    }

    #[test]
    fn segment_cu_one_short_fails() {
        // 2 instructions, budget = 2 * CU_PER_INSTRUCTION - 1 (one short)
        let result = run_program_with_budget(
            &[
                Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 42),
                Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
            ],
            2 * CU_PER_INSTRUCTION - 1,
        );
        assert!(matches!(result, Err(VmError::ComputeBudgetExceeded)));
    }

    #[test]
    fn lddw_charges_two_instruction_slots() {
        // LDDW is encoded as 2 instruction slots, should charge 2 CU
        let result = run_program(&[
            Instruction::new(Opcode::Lddw as u8, 0, 0, 0, 42), // slot 0: LDDW lo
            Instruction::new(0, 0, 0, 0, 0),                   // slot 1: LDDW hi
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),  // slot 2: exit
        ])
        .unwrap();
        assert_eq!(result.return_value, 42);
        // LDDW costs 2 CU (2 slots) + EXIT costs 1 CU = 3 total
        assert_eq!(result.compute_units_consumed, 3 * CU_PER_INSTRUCTION);
    }

    #[test]
    fn function_call_deducts_cu_at_boundary() {
        // Call a function and verify CU accounting is correct across the boundary
        let insns = [
            Instruction::new(Opcode::Mov64Imm as u8, 1, 0, 0, 10), // 0: r1 = 10
            Instruction::new(Opcode::Call as u8, 0, 0, 0, 1),      // 1: call func@3
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),      // 2: exit main
            Instruction::new(Opcode::Mov64Reg as u8, 0, 1, 0, 0),  // 3: func: r0 = r1
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),      // 4: return from func
        ];
        let bytes = make_program_bytes(&insns);
        let program = load_raw(&bytes).unwrap();
        let memory = MemoryMap::new(&[], TOTAL_STACK_SIZE, DEFAULT_HEAP_SIZE, vec![]);
        let result = execute(
            &program,
            memory,
            10_000,
            &NoSyscalls,
            SysvarSnapshot::default(),
        )
        .unwrap();
        assert_eq!(result.return_value, 10);
        // 5 instructions total: mov, call, mov(func), exit(func), exit(main)
        assert_eq!(result.compute_units_consumed, 5 * CU_PER_INSTRUCTION);
    }
}
