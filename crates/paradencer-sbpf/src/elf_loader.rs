/// ELF64 loader for sBPF programs.
///
/// Parses ELF64 little-endian binaries, extracts the .text section
/// (program instructions), .rodata (read-only data), processes
/// relocations, and builds a call target map for internal functions.
use crate::instruction::{decode_instructions, Instruction, Opcode};
use paradencer_constants::vm::{
    ELF64_HEADER_SIZE, ELF64_PHDR_SIZE, ELF64_SHDR_SIZE, ELF_CLASS_64, ELF_DATA_LSB,
    ELF_MACHINE_BPF, ELF_MACHINE_SBF, ELF_MAGIC, INSTRUCTION_SIZE, SBPF_VERSION_V1,
    SBPF_VERSION_V2, SBPF_VERSION_V3, SHT_PROGBITS, SHT_STRTAB,
};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// sBPF version
// ---------------------------------------------------------------------------

/// sBPF program version, determining available features and validation rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbpfVersion {
    /// Original sBPF instruction set.
    V0,
    /// Dynamic stack frames (SIMD-0166).
    V1,
    /// Stricter validation and new opcodes (SIMD-0173/0174).
    V2,
    /// Latest version with additional improvements.
    V3,
}

impl SbpfVersion {
    fn from_flags(flags: u32) -> Self {
        match flags {
            f if f == SBPF_VERSION_V3 => Self::V3,
            f if f == SBPF_VERSION_V2 => Self::V2,
            f if f == SBPF_VERSION_V1 => Self::V1,
            _ => Self::V0,
        }
    }
}

// ---------------------------------------------------------------------------
// Loaded program
// ---------------------------------------------------------------------------

/// A program loaded from an ELF binary, ready for validation and execution.
#[derive(Debug, Clone)]
pub struct LoadedProgram {
    /// Decoded instructions from the .text section.
    pub instructions: Vec<Instruction>,
    /// Read-only data from the .rodata section.
    pub rodata: Vec<u8>,
    /// Entry point as an instruction index.
    pub entry_point: usize,
    /// Map of call target hash/address → instruction index.
    pub call_targets: HashMap<u32, usize>,
    /// Detected sBPF version.
    pub sbpf_version: SbpfVersion,
    /// Raw .text section bytes (for memory mapping).
    pub text_bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// ELF errors
// ---------------------------------------------------------------------------

/// Errors during ELF loading and parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElfError {
    /// Input is too small to contain an ELF header.
    TooSmall { size: usize },
    /// Invalid ELF magic number.
    InvalidMagic,
    /// Unsupported ELF class (not 64-bit).
    InvalidClass { class: u8 },
    /// Unsupported data encoding (not little-endian).
    InvalidEncoding { encoding: u8 },
    /// Unsupported machine type.
    InvalidMachine { machine: u16 },
    /// No .text section found.
    MissingTextSection,
    /// .text section size is not aligned to instruction boundary.
    UnalignedTextSection { size: usize },
    /// Entry point is outside the .text section.
    InvalidEntryPoint {
        entry: u64,
        text_start: u64,
        text_end: u64,
    },
    /// Section header offset is out of bounds.
    InvalidSectionHeader { index: usize },
    /// String table index is out of bounds.
    InvalidStringTable,
    /// Relocation references invalid instruction.
    InvalidRelocation { offset: u64 },
    /// Instruction decoding error.
    InstructionDecodeError(String),
    /// Program exceeds maximum size.
    ProgramTooLarge { size: usize, max: usize },
}

impl std::fmt::Display for ElfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooSmall { size } => write!(f, "ELF too small: {} bytes", size),
            Self::InvalidMagic => write!(f, "invalid ELF magic number"),
            Self::InvalidClass { class } => write!(f, "unsupported ELF class: {}", class),
            Self::InvalidEncoding { encoding } => {
                write!(f, "unsupported ELF encoding: {}", encoding)
            }
            Self::InvalidMachine { machine } => {
                write!(f, "unsupported ELF machine type: 0x{:04X}", machine)
            }
            Self::MissingTextSection => write!(f, ".text section not found"),
            Self::UnalignedTextSection { size } => {
                write!(f, ".text section size {} not aligned to 8 bytes", size)
            }
            Self::InvalidEntryPoint {
                entry,
                text_start,
                text_end,
            } => {
                write!(
                    f,
                    "entry point 0x{:X} outside .text [0x{:X}..0x{:X}]",
                    entry, text_start, text_end
                )
            }
            Self::InvalidSectionHeader { index } => {
                write!(f, "section header {} out of bounds", index)
            }
            Self::InvalidStringTable => write!(f, "invalid string table"),
            Self::InvalidRelocation { offset } => {
                write!(f, "relocation at offset 0x{:X} is invalid", offset)
            }
            Self::InstructionDecodeError(msg) => {
                write!(f, "instruction decode error: {}", msg)
            }
            Self::ProgramTooLarge { size, max } => {
                write!(f, "program size {} exceeds maximum {}", size, max)
            }
        }
    }
}

impl std::error::Error for ElfError {}

// ---------------------------------------------------------------------------
// Internal ELF structures
// ---------------------------------------------------------------------------

/// Parsed ELF64 header fields we care about.
struct ElfHeader {
    machine: u16,
    entry: u64,
    phoff: u64,
    shoff: u64,
    flags: u32,
    phnum: u16,
    shnum: u16,
    shstrndx: u16,
}

/// Parsed ELF64 section header.
#[derive(Debug, Clone)]
struct SectionHeader {
    name_offset: u32,
    sh_type: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
}

/// Parsed ELF64 relocation entry.
struct RelEntry {
    offset: u64,
    info: u64,
}

impl RelEntry {
    fn rel_type(&self) -> u32 {
        (self.info & 0xFFFF_FFFF) as u32
    }

    fn sym_index(&self) -> u32 {
        (self.info >> 32) as u32
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Load an sBPF program from ELF64 bytes.
///
/// Validates the ELF header, extracts .text and .rodata sections,
/// processes relocations, decodes instructions, and builds the
/// call target map.
pub fn load_elf(bytes: &[u8]) -> Result<LoadedProgram, ElfError> {
    let max_size = paradencer_constants::program_cache::MAX_PROGRAM_SIZE;
    if bytes.len() > max_size {
        return Err(ElfError::ProgramTooLarge {
            size: bytes.len(),
            max: max_size,
        });
    }

    let header = parse_header(bytes)?;
    let sections = parse_section_headers(bytes, &header)?;
    let section_names = load_string_table(bytes, &sections, header.shstrndx as usize)?;

    // Find .text section
    let text_section = find_section_by_name(&sections, &section_names, ".text")
        .ok_or(ElfError::MissingTextSection)?;

    let text_start = text_section.offset as usize;
    let text_size = text_section.size as usize;

    if !text_size.is_multiple_of(INSTRUCTION_SIZE) {
        return Err(ElfError::UnalignedTextSection { size: text_size });
    }

    if text_start + text_size > bytes.len() {
        return Err(ElfError::InvalidSectionHeader { index: 0 });
    }

    let text_bytes = bytes[text_start..text_start + text_size].to_vec();

    // Find .rodata section (optional)
    let rodata = find_section_by_name(&sections, &section_names, ".rodata")
        .and_then(|s| {
            let start = s.offset as usize;
            let size = s.size as usize;
            if start + size <= bytes.len() {
                Some(bytes[start..start + size].to_vec())
            } else {
                None
            }
        })
        .unwrap_or_default();

    // Decode instructions
    let instructions = decode_instructions(&text_bytes)
        .map_err(|e| ElfError::InstructionDecodeError(e.to_string()))?;

    // Calculate entry point as instruction index
    let text_vaddr = text_section.addr;
    let entry_vaddr = header.entry;
    let entry_point = if entry_vaddr >= text_vaddr {
        let byte_offset = (entry_vaddr - text_vaddr) as usize;
        if !byte_offset.is_multiple_of(INSTRUCTION_SIZE) || byte_offset >= text_size {
            return Err(ElfError::InvalidEntryPoint {
                entry: entry_vaddr,
                text_start: text_vaddr,
                text_end: text_vaddr + text_size as u64,
            });
        }
        byte_offset / INSTRUCTION_SIZE
    } else {
        0 // Default to first instruction
    };

    // Build call target map from CALL instructions
    let call_targets = build_call_targets(&instructions);

    // Detect version from ELF flags
    let sbpf_version = SbpfVersion::from_flags(header.flags);

    Ok(LoadedProgram {
        instructions,
        rodata,
        entry_point,
        call_targets,
        sbpf_version,
        text_bytes,
    })
}

/// Create a LoadedProgram directly from raw instruction bytes (no ELF wrapping).
///
/// Useful for tests and synthetic programs.
pub fn load_raw(instruction_bytes: &[u8]) -> Result<LoadedProgram, ElfError> {
    if !instruction_bytes.len().is_multiple_of(INSTRUCTION_SIZE) {
        return Err(ElfError::UnalignedTextSection {
            size: instruction_bytes.len(),
        });
    }

    let instructions = decode_instructions(instruction_bytes)
        .map_err(|e| ElfError::InstructionDecodeError(e.to_string()))?;

    let call_targets = build_call_targets(&instructions);

    Ok(LoadedProgram {
        instructions,
        rodata: Vec::new(),
        entry_point: 0,
        call_targets,
        sbpf_version: SbpfVersion::V0,
        text_bytes: instruction_bytes.to_vec(),
    })
}

// ---------------------------------------------------------------------------
// Internal parsing
// ---------------------------------------------------------------------------

fn parse_header(bytes: &[u8]) -> Result<ElfHeader, ElfError> {
    if bytes.len() < ELF64_HEADER_SIZE {
        return Err(ElfError::TooSmall { size: bytes.len() });
    }

    // Magic number
    if bytes[0..4] != ELF_MAGIC {
        return Err(ElfError::InvalidMagic);
    }

    // Class (must be 64-bit)
    let class = bytes[4];
    if class != ELF_CLASS_64 {
        return Err(ElfError::InvalidClass { class });
    }

    // Data encoding (must be little-endian)
    let encoding = bytes[5];
    if encoding != ELF_DATA_LSB {
        return Err(ElfError::InvalidEncoding { encoding });
    }

    // Machine type
    let machine = u16::from_le_bytes([bytes[18], bytes[19]]);
    if machine != ELF_MACHINE_SBF && machine != ELF_MACHINE_BPF {
        return Err(ElfError::InvalidMachine { machine });
    }

    let entry = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
    let phoff = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
    let shoff = u64::from_le_bytes(bytes[40..48].try_into().unwrap());
    let flags = u32::from_le_bytes(bytes[48..52].try_into().unwrap());
    let phnum = u16::from_le_bytes(bytes[56..58].try_into().unwrap());
    let shnum = u16::from_le_bytes(bytes[58..60].try_into().unwrap());
    let shstrndx = u16::from_le_bytes(bytes[60..62].try_into().unwrap());

    Ok(ElfHeader {
        machine,
        entry,
        phoff,
        shoff,
        flags,
        phnum,
        shnum,
        shstrndx,
    })
}

fn parse_section_headers(bytes: &[u8], header: &ElfHeader) -> Result<Vec<SectionHeader>, ElfError> {
    let mut sections = Vec::with_capacity(header.shnum as usize);
    let shoff = header.shoff as usize;

    for i in 0..header.shnum as usize {
        let offset = shoff + i * ELF64_SHDR_SIZE;
        if offset + ELF64_SHDR_SIZE > bytes.len() {
            return Err(ElfError::InvalidSectionHeader { index: i });
        }

        let sh = &bytes[offset..offset + ELF64_SHDR_SIZE];
        sections.push(SectionHeader {
            name_offset: u32::from_le_bytes(sh[0..4].try_into().unwrap()),
            sh_type: u32::from_le_bytes(sh[4..8].try_into().unwrap()),
            flags: u64::from_le_bytes(sh[8..16].try_into().unwrap()),
            addr: u64::from_le_bytes(sh[16..24].try_into().unwrap()),
            offset: u64::from_le_bytes(sh[24..32].try_into().unwrap()),
            size: u64::from_le_bytes(sh[32..40].try_into().unwrap()),
            link: u32::from_le_bytes(sh[40..44].try_into().unwrap()),
            info: u32::from_le_bytes(sh[44..48].try_into().unwrap()),
        });
    }

    Ok(sections)
}

fn load_string_table(
    bytes: &[u8],
    sections: &[SectionHeader],
    index: usize,
) -> Result<Vec<u8>, ElfError> {
    if index >= sections.len() {
        return Err(ElfError::InvalidStringTable);
    }
    let sh = &sections[index];
    let start = sh.offset as usize;
    let size = sh.size as usize;
    if start + size > bytes.len() {
        return Err(ElfError::InvalidStringTable);
    }
    Ok(bytes[start..start + size].to_vec())
}

fn section_name(strtab: &[u8], name_offset: u32) -> &str {
    let start = name_offset as usize;
    if start >= strtab.len() {
        return "";
    }
    let end = strtab[start..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| start + p)
        .unwrap_or(strtab.len());
    std::str::from_utf8(&strtab[start..end]).unwrap_or("")
}

fn find_section_by_name<'a>(
    sections: &'a [SectionHeader],
    strtab: &[u8],
    name: &str,
) -> Option<&'a SectionHeader> {
    sections
        .iter()
        .find(|s| section_name(strtab, s.name_offset) == name)
}

fn build_call_targets(instructions: &[Instruction]) -> HashMap<u32, usize> {
    let mut targets = HashMap::new();

    for (i, insn) in instructions.iter().enumerate() {
        if insn.opcode == Opcode::Call as u8 {
            // The immediate is the target identifier (hash or relative offset)
            let target_id = insn.immediate as u32;
            // For local calls, the target is PC-relative in V0
            // For now, just record the call destination
            let target_pc = if insn.immediate >= 0 {
                i.wrapping_add(insn.immediate as usize).wrapping_add(1)
            } else {
                i.wrapping_sub((-insn.immediate) as usize).wrapping_add(1)
            };
            if target_pc < instructions.len() {
                targets.insert(target_id, target_pc);
            }
        }
    }

    targets
}

// ---------------------------------------------------------------------------
// ELF builder (for tests)
// ---------------------------------------------------------------------------

/// Minimal ELF64 builder for testing the loader.
pub struct TestElfBuilder {
    text: Vec<u8>,
    rodata: Vec<u8>,
    entry: u64,
    flags: u32,
}

impl Default for TestElfBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TestElfBuilder {
    /// Create a builder for a test ELF.
    pub fn new() -> Self {
        Self {
            text: Vec::new(),
            rodata: Vec::new(),
            entry: 0,
            flags: 0,
        }
    }

    /// Set the .text section contents.
    pub fn text(mut self, data: Vec<u8>) -> Self {
        self.text = data;
        self
    }

    /// Set the .rodata section contents.
    pub fn rodata(mut self, data: Vec<u8>) -> Self {
        self.rodata = data;
        self
    }

    /// Set the entry point virtual address.
    pub fn entry(mut self, addr: u64) -> Self {
        self.entry = addr;
        self
    }

    /// Set the ELF flags (sBPF version).
    pub fn flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    /// Build the ELF bytes.
    ///
    /// Layout: header | section headers | .shstrtab | .text | .rodata
    /// Sections: [null, .text, .rodata, .shstrtab]
    pub fn build(self) -> Vec<u8> {
        // String table: \0.text\0.rodata\0.shstrtab\0
        let shstrtab = b"\0.text\0.rodata\0.shstrtab\0";
        let name_text = 1u32; // offset of ".text" in shstrtab
        let name_rodata = 7u32; // offset of ".rodata" in shstrtab
        let name_shstrtab = 15u32; // offset of ".shstrtab" in shstrtab

        let shnum: u16 = 4; // null + .text + .rodata + .shstrtab
        let shstrndx: u16 = 3; // .shstrtab is section 3

        // Layout:
        //   [0..64)         ELF header
        //   [64..64+4*64)   Section headers (4 sections)
        //   [64+256..)      .shstrtab data, then .text, then .rodata
        let shoff = ELF64_HEADER_SIZE;
        let sh_total = (shnum as usize) * ELF64_SHDR_SIZE;
        let shstrtab_off = shoff + sh_total;
        let text_off = shstrtab_off + shstrtab.len();
        let rodata_off = text_off + self.text.len();
        let text_vaddr = 0x1000u64; // Virtual address for .text

        let entry = if self.entry == 0 {
            text_vaddr
        } else {
            self.entry
        };

        let mut elf = vec![0u8; rodata_off + self.rodata.len()];

        // ELF header
        elf[0..4].copy_from_slice(&ELF_MAGIC);
        elf[4] = ELF_CLASS_64;
        elf[5] = ELF_DATA_LSB;
        elf[6] = 1; // EV_CURRENT
                    // e_type = ET_EXEC (2)
        elf[16..18].copy_from_slice(&2u16.to_le_bytes());
        // e_machine
        elf[18..20].copy_from_slice(&ELF_MACHINE_SBF.to_le_bytes());
        // e_version
        elf[20..24].copy_from_slice(&1u32.to_le_bytes());
        // e_entry
        elf[24..32].copy_from_slice(&entry.to_le_bytes());
        // e_phoff (no program headers)
        elf[32..40].copy_from_slice(&0u64.to_le_bytes());
        // e_shoff
        elf[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
        // e_flags
        elf[48..52].copy_from_slice(&self.flags.to_le_bytes());
        // e_ehsize
        elf[52..54].copy_from_slice(&(ELF64_HEADER_SIZE as u16).to_le_bytes());
        // e_phentsize
        elf[54..56].copy_from_slice(&(ELF64_PHDR_SIZE as u16).to_le_bytes());
        // e_phnum
        elf[56..58].copy_from_slice(&0u16.to_le_bytes());
        // e_shentsize
        elf[58..60].copy_from_slice(&(ELF64_SHDR_SIZE as u16).to_le_bytes());
        // e_shnum
        elf[58..60].copy_from_slice(&shnum.to_le_bytes());
        // e_shstrndx
        elf[60..62].copy_from_slice(&shstrndx.to_le_bytes());

        // Section headers
        // Section 0: null
        // (all zeros, already done)

        // Section 1: .text
        let sh1_off = shoff + ELF64_SHDR_SIZE;
        elf[sh1_off..sh1_off + 4].copy_from_slice(&name_text.to_le_bytes());
        elf[sh1_off + 4..sh1_off + 8].copy_from_slice(&SHT_PROGBITS.to_le_bytes());
        elf[sh1_off + 8..sh1_off + 16].copy_from_slice(&0x6u64.to_le_bytes()); // SHF_ALLOC | SHF_EXECINSTR
        elf[sh1_off + 16..sh1_off + 24].copy_from_slice(&text_vaddr.to_le_bytes()); // sh_addr
        elf[sh1_off + 24..sh1_off + 32].copy_from_slice(&(text_off as u64).to_le_bytes());
        elf[sh1_off + 32..sh1_off + 40].copy_from_slice(&(self.text.len() as u64).to_le_bytes());

        // Section 2: .rodata
        let sh2_off = shoff + 2 * ELF64_SHDR_SIZE;
        elf[sh2_off..sh2_off + 4].copy_from_slice(&name_rodata.to_le_bytes());
        elf[sh2_off + 4..sh2_off + 8].copy_from_slice(&SHT_PROGBITS.to_le_bytes());
        elf[sh2_off + 8..sh2_off + 16].copy_from_slice(&0x2u64.to_le_bytes()); // SHF_ALLOC
        elf[sh2_off + 16..sh2_off + 24].copy_from_slice(&0u64.to_le_bytes()); // sh_addr
        elf[sh2_off + 24..sh2_off + 32].copy_from_slice(&(rodata_off as u64).to_le_bytes());
        elf[sh2_off + 32..sh2_off + 40].copy_from_slice(&(self.rodata.len() as u64).to_le_bytes());

        // Section 3: .shstrtab
        let sh3_off = shoff + 3 * ELF64_SHDR_SIZE;
        elf[sh3_off..sh3_off + 4].copy_from_slice(&name_shstrtab.to_le_bytes());
        elf[sh3_off + 4..sh3_off + 8].copy_from_slice(&SHT_STRTAB.to_le_bytes());
        elf[sh3_off + 24..sh3_off + 32].copy_from_slice(&(shstrtab_off as u64).to_le_bytes());
        elf[sh3_off + 32..sh3_off + 40].copy_from_slice(&(shstrtab.len() as u64).to_le_bytes());

        // Write data
        elf[shstrtab_off..shstrtab_off + shstrtab.len()].copy_from_slice(shstrtab);
        elf[text_off..text_off + self.text.len()].copy_from_slice(&self.text);
        elf[rodata_off..rodata_off + self.rodata.len()].copy_from_slice(&self.rodata);

        elf
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_simple_program() -> Vec<u8> {
        // mov64 r0, 0; exit
        let insns = [
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 0),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ];
        let mut bytes = Vec::new();
        for insn in &insns {
            bytes.extend_from_slice(&insn.encode().to_le_bytes());
        }
        bytes
    }

    fn build_test_elf(text: Vec<u8>) -> Vec<u8> {
        TestElfBuilder::new().text(text).build()
    }

    #[test]
    fn load_minimal_elf() {
        let text = make_simple_program();
        let elf = build_test_elf(text);
        let program = load_elf(&elf).unwrap();
        assert_eq!(program.instructions.len(), 2);
        assert_eq!(program.entry_point, 0);
        assert_eq!(program.sbpf_version, SbpfVersion::V0);
    }

    #[test]
    fn load_elf_with_rodata() {
        let text = make_simple_program();
        let rodata = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let elf = TestElfBuilder::new()
            .text(text)
            .rodata(rodata.clone())
            .build();
        let program = load_elf(&elf).unwrap();
        assert_eq!(program.rodata, rodata);
    }

    #[test]
    fn load_elf_detects_version() {
        let text = make_simple_program();
        let elf = TestElfBuilder::new()
            .text(text)
            .flags(SBPF_VERSION_V2)
            .build();
        let program = load_elf(&elf).unwrap();
        assert_eq!(program.sbpf_version, SbpfVersion::V2);
    }

    #[test]
    fn reject_too_small() {
        let result = load_elf(&[0; 32]);
        assert!(matches!(result, Err(ElfError::TooSmall { .. })));
    }

    #[test]
    fn reject_invalid_magic() {
        let mut elf = build_test_elf(make_simple_program());
        elf[0] = 0x00; // Corrupt magic
        let result = load_elf(&elf);
        assert!(matches!(result, Err(ElfError::InvalidMagic)));
    }

    #[test]
    fn reject_invalid_class() {
        let mut elf = build_test_elf(make_simple_program());
        elf[4] = 1; // 32-bit class
        let result = load_elf(&elf);
        assert!(matches!(result, Err(ElfError::InvalidClass { class: 1 })));
    }

    #[test]
    fn reject_invalid_encoding() {
        let mut elf = build_test_elf(make_simple_program());
        elf[5] = 2; // Big-endian
        let result = load_elf(&elf);
        assert!(matches!(
            result,
            Err(ElfError::InvalidEncoding { encoding: 2 })
        ));
    }

    #[test]
    fn reject_invalid_machine() {
        let mut elf = build_test_elf(make_simple_program());
        elf[18..20].copy_from_slice(&0x0003u16.to_le_bytes()); // x86
        let result = load_elf(&elf);
        assert!(matches!(
            result,
            Err(ElfError::InvalidMachine { machine: 0x0003 })
        ));
    }

    #[test]
    fn reject_unaligned_text() {
        // 5 bytes is not a multiple of 8
        let text = vec![0u8; 5];
        let elf = build_test_elf(text);
        let result = load_elf(&elf);
        assert!(matches!(result, Err(ElfError::UnalignedTextSection { .. })));
    }

    #[test]
    fn load_raw_simple() {
        let bytes = make_simple_program();
        let program = load_raw(&bytes).unwrap();
        assert_eq!(program.instructions.len(), 2);
        assert_eq!(program.entry_point, 0);
    }

    #[test]
    fn load_raw_unaligned() {
        let result = load_raw(&[0u8; 5]);
        assert!(matches!(result, Err(ElfError::UnalignedTextSection { .. })));
    }

    #[test]
    fn call_targets_built() {
        // mov64 r0, 0; call +1 (skips next insn); mov64 r0, 1; exit
        let insns = [
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 0),
            Instruction::new(Opcode::Call as u8, 0, 0, 0, 1), // call target at pc+1+1=3
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 1),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ];
        let mut bytes = Vec::new();
        for insn in &insns {
            bytes.extend_from_slice(&insn.encode().to_le_bytes());
        }
        let program = load_raw(&bytes).unwrap();
        // Call at PC=1 with imm=1 → target = 1 + 1 + 1 = 3
        assert!(program.call_targets.contains_key(&1));
        assert_eq!(program.call_targets[&1], 3);
    }
}
