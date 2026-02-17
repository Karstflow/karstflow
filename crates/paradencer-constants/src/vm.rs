//! Constants for the sBPF virtual machine.
//!
//! Defines register layout, memory region addresses, stack/heap limits,
//! instruction encoding parameters, and ELF binary format constants.

// ---------------------------------------------------------------------------
// Registers
// ---------------------------------------------------------------------------

/// Number of general-purpose registers accessible to programs (r0..r10).
pub const REGISTER_COUNT: usize = 11;

/// Return value register (r0).
pub const REG_RETURN: u8 = 0;

/// First argument register (r1).
pub const REG_ARG0: u8 = 1;
/// Second argument register (r2).
pub const REG_ARG1: u8 = 2;
/// Third argument register (r3).
pub const REG_ARG2: u8 = 3;
/// Fourth argument register (r4).
pub const REG_ARG3: u8 = 4;
/// Fifth argument register (r5).
pub const REG_ARG4: u8 = 5;

/// First callee-saved register (r6).
pub const REG_CALLEE_SAVED_START: u8 = 6;
/// Last callee-saved register (r9).
pub const REG_CALLEE_SAVED_END: u8 = 9;
/// Number of callee-saved registers (r6..r9).
pub const CALLEE_SAVED_COUNT: usize = 4;

/// Frame pointer register (r10). Read-only for programs.
pub const REG_FRAME_POINTER: u8 = 10;

/// Maximum valid register index for destination operands.
pub const MAX_DST_REGISTER: u8 = 9;
/// Maximum valid register index for source operands.
pub const MAX_SRC_REGISTER: u8 = 10;

// ---------------------------------------------------------------------------
// Stack
// ---------------------------------------------------------------------------

/// Size of a single stack frame in bytes.
pub const STACK_FRAME_SIZE: usize = 4096;

/// Maximum number of nested call frames (function calls + CPI).
pub const MAX_CALL_DEPTH: usize = 64;

/// Total stack size: frames x frame_size.
pub const TOTAL_STACK_SIZE: usize = MAX_CALL_DEPTH * STACK_FRAME_SIZE;

// ---------------------------------------------------------------------------
// Heap
// ---------------------------------------------------------------------------

/// Minimum heap size in bytes (32 KB).
pub const MIN_HEAP_SIZE: usize = 32 * 1024;

/// Maximum heap size in bytes (256 KB).
pub const MAX_HEAP_SIZE: usize = 256 * 1024;

/// Default heap size in bytes (32 KB).
pub const DEFAULT_HEAP_SIZE: usize = 32 * 1024;

// ---------------------------------------------------------------------------
// Memory regions (virtual address space)
// ---------------------------------------------------------------------------

/// Base address for the program/rodata region (read-only).
pub const REGION_PROGRAM_BASE: u64 = 0x1_0000_0000;

/// Base address for the stack region (read-write).
pub const REGION_STACK_BASE: u64 = 0x2_0000_0000;

/// Base address for the heap region (read-write).
pub const REGION_HEAP_BASE: u64 = 0x3_0000_0000;

/// Base address for the input/accounts region (read-write).
pub const REGION_INPUT_BASE: u64 = 0x4_0000_0000;

/// Mask for extracting the region index from a virtual address.
pub const REGION_INDEX_MASK: u64 = 0xF_0000_0000;

/// Mask for extracting the offset within a region.
pub const REGION_OFFSET_MASK: u64 = 0x0_FFFF_FFFF;

// ---------------------------------------------------------------------------
// Instruction format
// ---------------------------------------------------------------------------

/// Size of a single sBPF instruction in bytes.
pub const INSTRUCTION_SIZE: usize = 8;

/// Size of a LDDW (load double-word) instruction in bytes (two slots).
pub const LDDW_INSTRUCTION_SIZE: usize = 16;

/// Bit width of the opcode field.
pub const OPCODE_BITS: u32 = 8;
/// Bit width of the destination register field.
pub const DST_REG_BITS: u32 = 4;
/// Bit width of the source register field.
pub const SRC_REG_BITS: u32 = 4;
/// Bit width of the offset field.
pub const OFFSET_BITS: u32 = 16;
/// Bit width of the immediate field.
pub const IMMEDIATE_BITS: u32 = 32;

// ---------------------------------------------------------------------------
// Opcode class masks
// ---------------------------------------------------------------------------

/// Mask to extract the instruction class (3 low bits of opcode).
pub const OPCODE_CLASS_MASK: u8 = 0x07;

/// ALU class with immediate source (32-bit).
pub const CLASS_ALU32_IMM: u8 = 0x04;
/// ALU class with register source (32-bit).
pub const CLASS_ALU32_REG: u8 = 0x0C;
/// ALU class with immediate source (64-bit).
pub const CLASS_ALU64_IMM: u8 = 0x07;
/// ALU class with register source (64-bit).
pub const CLASS_ALU64_REG: u8 = 0x0F;

/// Jump class (64-bit comparisons).
pub const CLASS_JMP: u8 = 0x05;
/// Jump class (32-bit comparisons).
pub const CLASS_JMP32: u8 = 0x06;

/// Load double-word class.
pub const CLASS_LD: u8 = 0x00;
/// Load from memory class.
pub const CLASS_LDX: u8 = 0x01;
/// Store immediate to memory class.
pub const CLASS_ST: u8 = 0x02;
/// Store register to memory class.
pub const CLASS_STX: u8 = 0x03;

// ---------------------------------------------------------------------------
// Memory access width (bits 4..5 of opcode for LDX/ST/STX)
// ---------------------------------------------------------------------------

/// 1-byte (8-bit) memory access.
pub const MEM_SIZE_BYTE: u8 = 0x10;
/// 2-byte (16-bit) memory access.
pub const MEM_SIZE_HALF: u8 = 0x08;
/// 4-byte (32-bit) memory access.
pub const MEM_SIZE_WORD: u8 = 0x00;
/// 8-byte (64-bit) memory access.
pub const MEM_SIZE_DWORD: u8 = 0x18;

// ---------------------------------------------------------------------------
// ALU operation codes (bits 4..7 of opcode)
// ---------------------------------------------------------------------------

/// Add operation.
pub const ALU_OP_ADD: u8 = 0x00;
/// Subtract operation.
pub const ALU_OP_SUB: u8 = 0x10;
/// Multiply operation.
pub const ALU_OP_MUL: u8 = 0x20;
/// Divide operation.
pub const ALU_OP_DIV: u8 = 0x30;
/// Bitwise OR operation.
pub const ALU_OP_OR: u8 = 0x40;
/// Bitwise AND operation.
pub const ALU_OP_AND: u8 = 0x50;
/// Left shift operation.
pub const ALU_OP_LSH: u8 = 0x60;
/// Right shift operation (logical).
pub const ALU_OP_RSH: u8 = 0x70;
/// Negate operation (two's complement).
pub const ALU_OP_NEG: u8 = 0x80;
/// Modulo operation.
pub const ALU_OP_MOD: u8 = 0x90;
/// Bitwise XOR operation.
pub const ALU_OP_XOR: u8 = 0xA0;
/// Move (register copy) operation.
pub const ALU_OP_MOV: u8 = 0xB0;
/// Arithmetic right shift operation (sign-extending).
pub const ALU_OP_ARSH: u8 = 0xC0;
/// Byte-order conversion (endianness swap).
pub const ALU_OP_END: u8 = 0xD0;

// ---------------------------------------------------------------------------
// Jump operation codes (bits 4..7 of opcode)
// ---------------------------------------------------------------------------

/// Unconditional jump.
pub const JMP_OP_JA: u8 = 0x00;
/// Jump if equal.
pub const JMP_OP_JEQ: u8 = 0x10;
/// Jump if greater than (unsigned).
pub const JMP_OP_JGT: u8 = 0x20;
/// Jump if greater than or equal (unsigned).
pub const JMP_OP_JGE: u8 = 0x30;
/// Jump if bits set (bitwise AND non-zero).
pub const JMP_OP_JSET: u8 = 0x40;
/// Jump if not equal.
pub const JMP_OP_JNE: u8 = 0x50;
/// Jump if greater than (signed).
pub const JMP_OP_JSGT: u8 = 0x60;
/// Jump if greater than or equal (signed).
pub const JMP_OP_JSGE: u8 = 0x70;
/// Function call.
pub const JMP_OP_CALL: u8 = 0x80;
/// Function exit / program halt.
pub const JMP_OP_EXIT: u8 = 0x90;
/// Jump if less than (unsigned).
pub const JMP_OP_JLT: u8 = 0xA0;
/// Jump if less than or equal (unsigned).
pub const JMP_OP_JLE: u8 = 0xB0;
/// Jump if less than (signed).
pub const JMP_OP_JSLT: u8 = 0xC0;
/// Jump if less than or equal (signed).
pub const JMP_OP_JSLE: u8 = 0xD0;

// ---------------------------------------------------------------------------
// ELF binary format
// ---------------------------------------------------------------------------

/// ELF magic number bytes (0x7F 'E' 'L' 'F').
pub const ELF_MAGIC: [u8; 4] = [0x7F, 0x45, 0x4C, 0x46];

/// ELF class: 64-bit.
pub const ELF_CLASS_64: u8 = 2;

/// ELF data encoding: little-endian.
pub const ELF_DATA_LSB: u8 = 1;

/// ELF machine type for sBPF programs.
pub const ELF_MACHINE_SBF: u16 = 0x00F7;

/// ELF machine type for classic BPF (older programs).
pub const ELF_MACHINE_BPF: u16 = 0x00F3;

/// ELF header size for 64-bit ELF files.
pub const ELF64_HEADER_SIZE: usize = 64;

/// ELF64 program header entry size.
pub const ELF64_PHDR_SIZE: usize = 56;

/// ELF64 section header entry size.
pub const ELF64_SHDR_SIZE: usize = 64;

/// Program header type: loadable segment.
pub const PT_LOAD: u32 = 1;
/// Program header type: dynamic segment.
pub const PT_DYNAMIC: u32 = 2;

/// Section header type: program data.
pub const SHT_PROGBITS: u32 = 1;
/// Section header type: symbol table.
pub const SHT_SYMTAB: u32 = 2;
/// Section header type: string table.
pub const SHT_STRTAB: u32 = 3;
/// Section header type: relocation entries.
pub const SHT_REL: u32 = 9;
/// Section header type: dynamic linking info.
pub const SHT_DYNAMIC: u32 = 6;
/// Section header type: dynamic symbol table.
pub const SHT_DYNSYM: u32 = 11;
/// Section header type: no bits (BSS).
pub const SHT_NOBITS: u32 = 8;

/// Relocation type: 64-bit absolute address.
pub const R_BPF_64_64: u32 = 1;
/// Relocation type: relative address.
pub const R_BPF_64_RELATIVE: u32 = 8;
/// Relocation type: 32-bit value.
pub const R_BPF_64_32: u32 = 10;

// ---------------------------------------------------------------------------
// sBPF version identifiers
// ---------------------------------------------------------------------------

/// SBPF version 0 (original).
pub const SBPF_VERSION_V0: u32 = 0;
/// SBPF version 1 (SIMD-0166, dynamic stack frames).
pub const SBPF_VERSION_V1: u32 = 1;
/// SBPF version 2 (SIMD-0173/0174, stricter validation).
pub const SBPF_VERSION_V2: u32 = 2;
/// SBPF version 3 (latest).
pub const SBPF_VERSION_V3: u32 = 3;

// ---------------------------------------------------------------------------
// Account serialization
// ---------------------------------------------------------------------------

/// Fixed-size metadata per account in the VM input region.
///
/// Layout: is_signer(1) + is_writable(1) + pubkey(32) + owner(32) + lamports(8) + data_len(8) = 82
pub const ACCOUNT_SERIALIZED_META_SIZE: usize = 82;

/// Maximum account data growth allowed per instruction (10 KiB realloc buffer).
pub const MAX_PERMITTED_DATA_INCREASE: usize = 10 * 1024;

/// Maximum total account data length (10 MiB).
pub const MAX_PERMITTED_DATA_LENGTH: usize = 10 * 1024 * 1024;

/// Alignment for u128 values in the serialized input region.
pub const ALIGN_OF_U128: usize = 16;

/// Marker byte indicating this account is not a duplicate in the input region.
pub const NON_DUP_MARKER: u8 = 0xFF;

/// Maximum number of accounts in a single BPF instruction.
pub const MAX_INSTRUCTION_ACCOUNTS: usize = 256;

/// Maximum number of accounts in a single transaction.
pub const MAX_TRANSACTION_ACCOUNTS: usize = 256;

// ---------------------------------------------------------------------------
// Compute metering
// ---------------------------------------------------------------------------

/// Compute units consumed per instruction executed.
pub const CU_PER_INSTRUCTION: u64 = 1;

/// Maximum instructions before forced halt (safety limit).
pub const MAX_INSTRUCTIONS: u64 = 10_000_000;

// ---------------------------------------------------------------------------
// Syscall conventions
// ---------------------------------------------------------------------------

/// Syscall identifiers are murmur3 hashes of their names.
/// The hash uses seed 0 and produces a u32 result.
pub const SYSCALL_HASH_SEED: u32 = 0;
