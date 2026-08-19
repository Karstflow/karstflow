/// Static validation of loaded sBPF programs.
///
/// Verifies that a program is well-formed before execution:
/// valid opcodes, register indices, jump targets, LDDW pairing,
/// call targets, and termination.
use crate::elf_loader::{LoadedProgram, SbpfVersion};
use crate::instruction::Opcode;
use karstflow_constants::vm::{MAX_DST_REGISTER, MAX_SRC_REGISTER};
use std::collections::HashSet;

// ---------------------------------------------------------------------------
// Validation errors
// ---------------------------------------------------------------------------

/// A single validation error in a loaded program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// Unrecognized opcode at a given program counter.
    InvalidOpcode { pc: usize, opcode: u8 },
    /// Register index out of valid range.
    InvalidRegister {
        pc: usize,
        register: u8,
        field: &'static str,
    },
    /// Jump target falls outside program bounds.
    JumpOutOfBounds { pc: usize, target: isize },
    /// LDDW instruction at end of program without second slot.
    UnpairedLddw { pc: usize },
    /// CALL target is neither a local function nor a registered syscall.
    InvalidCallTarget { pc: usize, target: u32 },
    /// Program does not end with an EXIT instruction.
    MissingExitInstruction,
    /// Division by zero in immediate operand.
    DivisionByZero { pc: usize },
    /// Program exceeds maximum instruction count.
    ProgramTooLarge { count: usize, max: usize },
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidOpcode { pc, opcode } => {
                write!(f, "PC {}: invalid opcode 0x{:02X}", pc, opcode)
            }
            Self::InvalidRegister {
                pc,
                register,
                field,
            } => {
                write!(f, "PC {}: invalid {} register r{}", pc, field, register)
            }
            Self::JumpOutOfBounds { pc, target } => {
                write!(f, "PC {}: jump target {} out of bounds", pc, target)
            }
            Self::UnpairedLddw { pc } => {
                write!(f, "PC {}: LDDW missing second instruction slot", pc)
            }
            Self::InvalidCallTarget { pc, target } => {
                write!(f, "PC {}: unknown call target 0x{:08X}", pc, target)
            }
            Self::MissingExitInstruction => {
                write!(f, "program does not end with EXIT instruction")
            }
            Self::DivisionByZero { pc } => {
                write!(f, "PC {}: division by zero in immediate", pc)
            }
            Self::ProgramTooLarge { count, max } => {
                write!(f, "program has {} instructions, maximum is {}", count, max)
            }
        }
    }
}

impl std::error::Error for ValidationError {}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Maximum number of instructions per program.
const MAX_PROGRAM_INSTRUCTIONS: usize = 1_000_000;

/// Validate a loaded program for correctness before execution.
///
/// `registered_syscalls` contains the set of known syscall hash IDs.
/// Returns `Ok(())` if the program is valid, or a list of all errors found.
pub fn validate(
    program: &LoadedProgram,
    registered_syscalls: &HashSet<u32>,
) -> Result<(), Vec<ValidationError>> {
    let instructions = &program.instructions;
    let mut errors = Vec::new();

    // Size check
    if instructions.len() > MAX_PROGRAM_INSTRUCTIONS {
        errors.push(ValidationError::ProgramTooLarge {
            count: instructions.len(),
            max: MAX_PROGRAM_INSTRUCTIONS,
        });
    }

    // Empty program
    if instructions.is_empty() {
        errors.push(ValidationError::MissingExitInstruction);
        return Err(errors);
    }

    let mut i = 0;
    while i < instructions.len() {
        let insn = &instructions[i];
        let opcode = Opcode::from_raw(insn.opcode);

        // Check for valid opcode (skip LDDW second slots which have opcode 0)
        if opcode.is_none() && !(i > 0 && instructions[i - 1].is_lddw() && insn.opcode == 0) {
            errors.push(ValidationError::InvalidOpcode {
                pc: i,
                opcode: insn.opcode,
            });
            i += 1;
            continue;
        }

        // For LDDW second slot, skip further validation
        if insn.opcode == 0 && i > 0 && instructions[i - 1].is_lddw() {
            i += 1;
            continue;
        }

        let op = opcode.unwrap();
        let version = program.sbpf_version;

        // Version-specific opcode restrictions
        if is_opcode_disabled_for_version(op, version) {
            errors.push(ValidationError::InvalidOpcode {
                pc: i,
                opcode: insn.opcode,
            });
            i += 1;
            continue;
        }

        // Validate LDDW pairing
        if op.is_lddw() {
            if i + 1 >= instructions.len() {
                errors.push(ValidationError::UnpairedLddw { pc: i });
                i += 1;
                continue;
            }
            // Next slot should have opcode 0 (filler)
            // We'll just skip it in the next iteration
            i += 2;
            continue;
        }

        // Validate registers
        validate_registers(insn, op, i, &mut errors);

        // Validate jump targets
        if op.is_jump() && op != Opcode::Call && op != Opcode::Syscall && op != Opcode::Exit {
            let target = (i as isize) + 1 + (insn.offset as isize);
            if target < 0 || target >= instructions.len() as isize {
                errors.push(ValidationError::JumpOutOfBounds { pc: i, target });
            }
        }

        // Validate division by zero with immediate
        validate_division(insn, op, i, &mut errors);

        // Validate call targets
        if op == Opcode::Call {
            let target_id = insn.immediate as u32;
            // Check if it's a registered syscall, a relocated local function,
            // or a valid PC-relative target
            let is_syscall = registered_syscalls.contains(&target_id);
            let is_relocated = program.call_targets.contains_key(&target_id);
            let is_relative = {
                let rel = if insn.immediate >= 0 {
                    i.wrapping_add(insn.immediate as usize).wrapping_add(1)
                } else {
                    i.wrapping_sub((-insn.immediate) as usize).wrapping_add(1)
                };
                rel < instructions.len()
            };
            if !is_syscall && !is_relocated && !is_relative {
                errors.push(ValidationError::InvalidCallTarget {
                    pc: i,
                    target: target_id,
                });
            }
        }

        // Note: Syscall (0x8D, SBPFv2) targets are small integer indices
        // resolved at runtime via the syscall dispatch table. No static
        // validation against hash-based registered_syscalls.

        i += 1;
    }

    // Check that the last real instruction is EXIT
    let last_real = instructions
        .iter()
        .rposition(|insn| insn.opcode != 0)
        .unwrap_or(0);
    if instructions[last_real].opcode != Opcode::Exit as u8 {
        errors.push(ValidationError::MissingExitInstruction);
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn validate_registers(
    insn: &crate::instruction::Instruction,
    op: Opcode,
    pc: usize,
    errors: &mut Vec<ValidationError>,
) {
    // Skip register checks for instructions that don't use them
    if op == Opcode::Ja || op == Opcode::Call || op == Opcode::Exit {
        return;
    }

    // Destination register check (not for store instructions where dst is a base addr)
    if op.is_alu() && insn.dst > MAX_DST_REGISTER {
        errors.push(ValidationError::InvalidRegister {
            pc,
            register: insn.dst,
            field: "destination",
        });
    }

    // Source register check for register-source instructions
    if !op.is_immediate_source() && insn.src > MAX_SRC_REGISTER {
        errors.push(ValidationError::InvalidRegister {
            pc,
            register: insn.src,
            field: "source",
        });
    }
}

/// Check if an opcode is disabled for the given SBPF version.
fn is_opcode_disabled_for_version(op: Opcode, version: SbpfVersion) -> bool {
    match op {
        // LDDW disabled in V2+
        Opcode::Lddw if version.lddw_disabled() => true,
        // LE (little-endian swap) disabled in V2+
        Opcode::Le if version.le_disabled() => true,
        // NEG disabled in V2+
        Opcode::Neg64 | Opcode::Neg32 if version.neg_disabled() => true,
        _ => false,
    }
}

fn validate_division(
    insn: &crate::instruction::Instruction,
    op: Opcode,
    pc: usize,
    errors: &mut Vec<ValidationError>,
) {
    let is_div_mod_imm = matches!(
        op,
        Opcode::Div32Imm | Opcode::Div64Imm | Opcode::Mod32Imm | Opcode::Mod64Imm
    );

    if is_div_mod_imm && insn.immediate == 0 {
        errors.push(ValidationError::DivisionByZero { pc });
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Deploy-time validation
// ---------------------------------------------------------------------------

/// The syscall ids a program may call when it is deployed at a slot with
/// `active_features` in force.
///
/// This is the standard set plus the two CPI entry points plus whatever the
/// active features add. The CPI ids are hashed by name rather than registered,
/// because enumerating what a program is allowed to call needs no handler to
/// call it with — and requiring one would mean inventing an executor purely to
/// ask a question about names.
pub fn deploy_syscall_ids(active_features: &HashSet<[u8; 32]>) -> HashSet<u32> {
    use crate::syscall_dispatch::{murmur3_hash, RuntimeSyscallDispatch};

    let mut ids = RuntimeSyscallDispatch::with_standard_syscalls().registered_ids();
    ids.insert(murmur3_hash("sol_invoke_signed_c"));
    ids.insert(murmur3_hash("sol_invoke_signed_rust"));
    ids.extend(RuntimeSyscallDispatch::with_active_feature_ids(active_features).registered_ids());
    ids
}

/// Load `elf` and check it would survive being deployed: it must parse, and
/// every instruction in it must pass the validation the loader applies before
/// execution.
///
/// Returns the loaded program so a caller that needs it does not parse twice;
/// callers that only want a verdict discard it. The error is a description, for
/// a caller that wants to say why.
///
/// Used both by the VM's own load path and by the core-BPF upgrade paths, which
/// must reject a source buffer whose bytecode could never run rather than
/// install it and fail at first invocation.
pub fn validate_elf_for_deploy(
    elf: &[u8],
    syscall_ids: &HashSet<u32>,
) -> Result<LoadedProgram, String> {
    let program = crate::elf_loader::load_elf(elf).map_err(|e| format!("ELF load: {e}"))?;
    validate(&program, syscall_ids).map_err(|errors| {
        let sample: Vec<String> = errors.iter().take(3).map(|e| e.to_string()).collect();
        format!(
            "validation: {} errors — {}",
            errors.len(),
            sample.join("; ")
        )
    })?;
    Ok(program)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf_loader::load_raw;
    use crate::instruction::Instruction;
    use std::collections::HashMap;

    fn make_program(insns: &[Instruction]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for insn in insns {
            bytes.extend_from_slice(&insn.encode().to_le_bytes());
        }
        bytes
    }

    fn empty_syscalls() -> HashSet<u32> {
        HashSet::new()
    }

    #[test]
    fn valid_minimal_program() {
        let bytes = make_program(&[
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 0),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ]);
        let program = load_raw(&bytes).unwrap();
        assert!(validate(&program, &empty_syscalls()).is_ok());
    }

    #[test]
    fn valid_with_jump() {
        let bytes = make_program(&[
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 0),
            Instruction::new(Opcode::Ja as u8, 0, 0, 1, 0), // skip next
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 1),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ]);
        let program = load_raw(&bytes).unwrap();
        assert!(validate(&program, &empty_syscalls()).is_ok());
    }

    #[test]
    fn invalid_opcode() {
        let bytes = make_program(&[
            Instruction::new(0xFF, 0, 0, 0, 0), // bad opcode
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ]);
        let program = load_raw(&bytes).unwrap();
        let result = validate(&program, &empty_syscalls());
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| matches!(
            e,
            ValidationError::InvalidOpcode {
                pc: 0,
                opcode: 0xFF
            }
        )));
    }

    #[test]
    fn jump_out_of_bounds() {
        let bytes = make_program(&[
            Instruction::new(Opcode::Ja as u8, 0, 0, 100, 0), // jumps way past end
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ]);
        let program = load_raw(&bytes).unwrap();
        let result = validate(&program, &empty_syscalls());
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors
            .iter()
            .any(|e| matches!(e, ValidationError::JumpOutOfBounds { .. })));
    }

    #[test]
    fn division_by_zero_immediate() {
        let bytes = make_program(&[
            Instruction::new(Opcode::Div64Imm as u8, 0, 0, 0, 0), // div r0, 0
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ]);
        let program = load_raw(&bytes).unwrap();
        let result = validate(&program, &empty_syscalls());
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors
            .iter()
            .any(|e| matches!(e, ValidationError::DivisionByZero { pc: 0 })));
    }

    #[test]
    fn missing_exit() {
        let bytes = make_program(&[
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 0),
            Instruction::new(Opcode::Mov64Imm as u8, 1, 0, 0, 1),
        ]);
        let program = load_raw(&bytes).unwrap();
        let result = validate(&program, &empty_syscalls());
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors
            .iter()
            .any(|e| matches!(e, ValidationError::MissingExitInstruction)));
    }

    #[test]
    fn invalid_call_target() {
        let bytes = make_program(&[
            Instruction::new(Opcode::Call as u8, 0, 0, 0, 0xDEAD), // unknown target
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ]);
        let program = load_raw(&bytes).unwrap();
        let result = validate(&program, &empty_syscalls());
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors
            .iter()
            .any(|e| matches!(e, ValidationError::InvalidCallTarget { .. })));
    }

    #[test]
    fn valid_call_to_registered_syscall() {
        let syscall_id = 0x12345678u32;
        let bytes = make_program(&[
            Instruction::new(Opcode::Call as u8, 0, 0, 0, syscall_id as i32),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ]);
        let program = load_raw(&bytes).unwrap();
        let mut syscalls = HashSet::new();
        syscalls.insert(syscall_id);
        assert!(validate(&program, &syscalls).is_ok());
    }

    #[test]
    fn multiple_errors_reported() {
        let bytes = make_program(&[
            Instruction::new(0xFF, 0, 0, 0, 0),                   // bad opcode
            Instruction::new(Opcode::Div32Imm as u8, 0, 0, 0, 0), // div by zero
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 0), // no exit
        ]);
        let program = load_raw(&bytes).unwrap();
        let result = validate(&program, &empty_syscalls());
        assert!(result.is_err());
        let errors = result.unwrap_err();
        // Should find at least 3 errors: bad opcode, div zero, missing exit
        assert!(errors.len() >= 3);
    }

    #[test]
    fn empty_program() {
        // Empty instruction list
        let program = LoadedProgram {
            instructions: Vec::new(),
            rodata: Vec::new(),
            entry_point: 0,
            call_targets: HashMap::new(),
            sbpf_version: crate::elf_loader::SbpfVersion::V0,
            text_bytes: Vec::new(),
            text_file_offset: 0,
        };
        let result = validate(&program, &empty_syscalls());
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors
            .iter()
            .any(|e| matches!(e, ValidationError::MissingExitInstruction)));
    }
}
