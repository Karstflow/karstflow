/// sBPF instruction set: encoding, decoding, and opcode definitions.
///
/// Each instruction is an 8-byte word with the layout:
///   `opcode:8 | dst_reg:4 | src_reg:4 | offset:16 | immediate:32`
///
/// The LDDW (load double-word immediate) instruction spans two consecutive
/// 8-byte slots, encoding a full 64-bit immediate value.
use karstflow_constants::vm;

// ---------------------------------------------------------------------------
// Instruction representation
// ---------------------------------------------------------------------------

/// A decoded sBPF instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Instruction {
    /// Opcode byte (encodes operation, class, and source mode).
    pub opcode: u8,
    /// Destination register (0..=10).
    pub dst: u8,
    /// Source register (0..=10).
    pub src: u8,
    /// Signed 16-bit offset (used for jumps and memory access).
    pub offset: i16,
    /// Signed 32-bit immediate value.
    pub immediate: i32,
}

impl Instruction {
    /// Create a new instruction from its components.
    pub fn new(opcode: u8, dst: u8, src: u8, offset: i16, immediate: i32) -> Self {
        Self {
            opcode,
            dst,
            src,
            offset,
            immediate,
        }
    }

    /// Decode an instruction from a raw 64-bit word.
    ///
    /// Layout (little-endian):
    /// - bits  0..7  : opcode
    /// - bits  8..11 : dst register
    /// - bits 12..15 : src register
    /// - bits 16..31 : offset (signed)
    /// - bits 32..63 : immediate (signed)
    pub fn decode(raw: u64) -> Self {
        let opcode = (raw & 0xFF) as u8;
        let dst = ((raw >> 8) & 0x0F) as u8;
        let src = ((raw >> 12) & 0x0F) as u8;
        let offset = ((raw >> 16) & 0xFFFF) as i16;
        let immediate = ((raw >> 32) & 0xFFFF_FFFF) as i32;
        Self {
            opcode,
            dst,
            src,
            offset,
            immediate,
        }
    }

    /// Encode this instruction into a 64-bit word.
    pub fn encode(&self) -> u64 {
        (self.opcode as u64)
            | ((self.dst as u64 & 0x0F) << 8)
            | ((self.src as u64 & 0x0F) << 12)
            | (((self.offset as u16) as u64) << 16)
            | (((self.immediate as u32) as u64) << 32)
    }

    /// Whether this is a LDDW instruction (consumes two 8-byte slots).
    pub fn is_lddw(&self) -> bool {
        self.opcode == Opcode::Lddw as u8
    }

    /// Get the opcode classification for this instruction.
    pub fn opcode_class(&self) -> u8 {
        self.opcode & vm::OPCODE_CLASS_MASK
    }

    /// Whether this instruction is an ALU operation (32-bit or 64-bit).
    pub fn is_alu(&self) -> bool {
        let class = self.opcode;
        matches!(
            class,
            _ if (class & 0x07 == vm::CLASS_ALU32_IMM)
                || (class & 0x07 == vm::CLASS_ALU64_IMM)
                || (class & 0x0F == vm::CLASS_ALU32_REG)
                || (class & 0x0F == vm::CLASS_ALU64_REG)
        )
    }

    /// Whether this instruction is a jump/branch operation.
    pub fn is_jump(&self) -> bool {
        let class = self.opcode & vm::OPCODE_CLASS_MASK;
        class == vm::CLASS_JMP || class == vm::CLASS_JMP32
    }

    /// Whether this instruction is a memory access (load or store).
    pub fn is_memory(&self) -> bool {
        let class = self.opcode & vm::OPCODE_CLASS_MASK;
        class == vm::CLASS_LDX || class == vm::CLASS_ST || class == vm::CLASS_STX
    }
}

impl std::fmt::Display for Instruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(op) = Opcode::from_raw(self.opcode) {
            write!(
                f,
                "{:?} r{}, r{}, off={}, imm={}",
                op, self.dst, self.src, self.offset, self.immediate
            )
        } else {
            write!(f, "UNKNOWN(0x{:02X})", self.opcode)
        }
    }
}

// ---------------------------------------------------------------------------
// Opcode enumeration
// ---------------------------------------------------------------------------

/// All sBPF opcodes.
///
/// Opcode byte layout: `operation:4 | source:1 | class:3`
/// For memory: `width:2 | operation:1 | class:3`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Opcode {
    // --- LDDW ---
    /// Load 64-bit immediate (spans two instruction slots).
    Lddw = 0x18,

    // --- ALU64 immediate ---
    /// r[dst] += immediate (64-bit)
    Add64Imm = 0x07,
    /// r[dst] -= immediate (64-bit)
    Sub64Imm = 0x17,
    /// r[dst] *= immediate (64-bit)
    Mul64Imm = 0x27,
    /// r[dst] /= immediate (64-bit, unsigned)
    Div64Imm = 0x37,
    /// r[dst] |= immediate (64-bit)
    Or64Imm = 0x47,
    /// r[dst] &= immediate (64-bit)
    And64Imm = 0x57,
    /// r[dst] <<= immediate (64-bit)
    Lsh64Imm = 0x67,
    /// r[dst] >>= immediate (64-bit, logical)
    Rsh64Imm = 0x77,
    /// r[dst] = -r[dst] (64-bit, two's complement)
    Neg64 = 0x87,
    /// r[dst] %= immediate (64-bit, unsigned)
    Mod64Imm = 0x97,
    /// r[dst] ^= immediate (64-bit)
    Xor64Imm = 0xA7,
    /// r[dst] = immediate (64-bit)
    Mov64Imm = 0xB7,
    /// r[dst] >>= immediate (64-bit, arithmetic/sign-extending)
    Arsh64Imm = 0xC7,

    // --- ALU64 register ---
    /// r[dst] += r[src] (64-bit)
    Add64Reg = 0x0F,
    /// r[dst] -= r[src] (64-bit)
    Sub64Reg = 0x1F,
    /// r[dst] *= r[src] (64-bit)
    Mul64Reg = 0x2F,
    /// r[dst] /= r[src] (64-bit, unsigned)
    Div64Reg = 0x3F,
    /// r[dst] |= r[src] (64-bit)
    Or64Reg = 0x4F,
    /// r[dst] &= r[src] (64-bit)
    And64Reg = 0x5F,
    /// r[dst] <<= r[src] (64-bit)
    Lsh64Reg = 0x6F,
    /// r[dst] >>= r[src] (64-bit, logical)
    Rsh64Reg = 0x7F,
    /// r[dst] %= r[src] (64-bit, unsigned)
    Mod64Reg = 0x9F,
    /// r[dst] ^= r[src] (64-bit)
    Xor64Reg = 0xAF,
    /// r[dst] = r[src] (64-bit)
    Mov64Reg = 0xBF,
    /// r[dst] >>= r[src] (64-bit, arithmetic/sign-extending)
    Arsh64Reg = 0xCF,

    // --- ALU32 immediate ---
    /// r[dst] += immediate (32-bit, zero-extends)
    Add32Imm = 0x04,
    /// r[dst] -= immediate (32-bit)
    Sub32Imm = 0x14,
    /// r[dst] *= immediate (32-bit)
    Mul32Imm = 0x24,
    /// r[dst] /= immediate (32-bit, unsigned)
    Div32Imm = 0x34,
    /// r[dst] |= immediate (32-bit)
    Or32Imm = 0x44,
    /// r[dst] &= immediate (32-bit)
    And32Imm = 0x54,
    /// r[dst] <<= immediate (32-bit)
    Lsh32Imm = 0x64,
    /// r[dst] >>= immediate (32-bit, logical)
    Rsh32Imm = 0x74,
    /// r[dst] = -r[dst] (32-bit)
    Neg32 = 0x84,
    /// r[dst] %= immediate (32-bit, unsigned)
    Mod32Imm = 0x94,
    /// r[dst] ^= immediate (32-bit)
    Xor32Imm = 0xA4,
    /// r[dst] = immediate (32-bit, zero-extends)
    Mov32Imm = 0xB4,
    /// r[dst] >>= immediate (32-bit, arithmetic)
    Arsh32Imm = 0xC4,

    // --- ALU32 register ---
    /// r[dst] += r[src] (32-bit)
    Add32Reg = 0x0C,
    /// r[dst] -= r[src] (32-bit)
    Sub32Reg = 0x1C,
    /// r[dst] *= r[src] (32-bit)
    Mul32Reg = 0x2C,
    /// r[dst] /= r[src] (32-bit, unsigned)
    Div32Reg = 0x3C,
    /// r[dst] |= r[src] (32-bit)
    Or32Reg = 0x4C,
    /// r[dst] &= r[src] (32-bit)
    And32Reg = 0x5C,
    /// r[dst] <<= r[src] (32-bit)
    Lsh32Reg = 0x6C,
    /// r[dst] >>= r[src] (32-bit, logical)
    Rsh32Reg = 0x7C,
    /// r[dst] %= r[src] (32-bit, unsigned)
    Mod32Reg = 0x9C,
    /// r[dst] ^= r[src] (32-bit)
    Xor32Reg = 0xAC,
    /// r[dst] = r[src] (32-bit)
    Mov32Reg = 0xBC,
    /// r[dst] >>= r[src] (32-bit, arithmetic)
    Arsh32Reg = 0xCC,

    // --- Byte-order conversion ---
    /// Convert r[dst] to little-endian (16/32/64-bit based on immediate).
    Le = 0xD4,
    /// Convert r[dst] to big-endian (16/32/64-bit based on immediate).
    Be = 0xDC,

    // --- Memory load (LDX) ---
    /// r[dst] = *(u8 *)(r[src] + offset)
    LdxByte = 0x71,
    /// r[dst] = *(u16 *)(r[src] + offset)
    LdxHalf = 0x69,
    /// r[dst] = *(u32 *)(r[src] + offset)
    LdxWord = 0x61,
    /// r[dst] = *(u64 *)(r[src] + offset)
    LdxDword = 0x79,

    // --- Memory store immediate (ST) ---
    /// *(u8 *)(r[dst] + offset) = immediate
    StByte = 0x72,
    /// *(u16 *)(r[dst] + offset) = immediate
    StHalf = 0x6A,
    /// *(u32 *)(r[dst] + offset) = immediate
    StWord = 0x62,
    /// *(u64 *)(r[dst] + offset) = immediate
    StDword = 0x7A,

    // --- Memory store register (STX) ---
    /// *(u8 *)(r[dst] + offset) = r[src]
    StxByte = 0x73,
    /// *(u16 *)(r[dst] + offset) = r[src]
    StxHalf = 0x6B,
    /// *(u32 *)(r[dst] + offset) = r[src]
    StxWord = 0x63,
    /// *(u64 *)(r[dst] + offset) = r[src]
    StxDword = 0x7B,

    // --- Jump (64-bit comparisons) ---
    /// Unconditional jump: PC += offset.
    Ja = 0x05,
    /// Jump if r[dst] == immediate.
    JeqImm = 0x15,
    /// Jump if r[dst] == r[src].
    JeqReg = 0x1D,
    /// Jump if r[dst] > immediate (unsigned).
    JgtImm = 0x25,
    /// Jump if r[dst] > r[src] (unsigned).
    JgtReg = 0x2D,
    /// Jump if r[dst] >= immediate (unsigned).
    JgeImm = 0x35,
    /// Jump if r[dst] >= r[src] (unsigned).
    JgeReg = 0x3D,
    /// Jump if r[dst] & immediate != 0.
    JsetImm = 0x45,
    /// Jump if r[dst] & r[src] != 0.
    JsetReg = 0x4D,
    /// Jump if r[dst] != immediate.
    JneImm = 0x55,
    /// Jump if r[dst] != r[src].
    JneReg = 0x5D,
    /// Jump if r[dst] > immediate (signed).
    JsgtImm = 0x65,
    /// Jump if r[dst] > r[src] (signed).
    JsgtReg = 0x6D,
    /// Jump if r[dst] >= immediate (signed).
    JsgeImm = 0x75,
    /// Jump if r[dst] >= r[src] (signed).
    JsgeReg = 0x7D,
    /// Jump if r[dst] < immediate (unsigned).
    JltImm = 0xA5,
    /// Jump if r[dst] < r[src] (unsigned).
    JltReg = 0xAD,
    /// Jump if r[dst] <= immediate (unsigned).
    JleImm = 0xB5,
    /// Jump if r[dst] <= r[src] (unsigned).
    JleReg = 0xBD,
    /// Jump if r[dst] < immediate (signed).
    JsltImm = 0xC5,
    /// Jump if r[dst] < r[src] (signed).
    JsltReg = 0xCD,
    /// Jump if r[dst] <= immediate (signed).
    JsleImm = 0xD5,
    /// Jump if r[dst] <= r[src] (signed).
    JsleReg = 0xDD,

    // --- Jump32 (32-bit comparisons) ---
    /// Jump if (u32)r[dst] == immediate.
    Jeq32Imm = 0x16,
    /// Jump if (u32)r[dst] == (u32)r[src].
    Jeq32Reg = 0x1E,
    /// Jump if (u32)r[dst] > immediate (unsigned).
    Jgt32Imm = 0x26,
    /// Jump if (u32)r[dst] > (u32)r[src] (unsigned).
    Jgt32Reg = 0x2E,
    /// Jump if (u32)r[dst] >= immediate (unsigned).
    Jge32Imm = 0x36,
    /// Jump if (u32)r[dst] >= (u32)r[src] (unsigned).
    Jge32Reg = 0x3E,
    /// Jump if (u32)r[dst] & immediate != 0.
    Jset32Imm = 0x46,
    /// Jump if (u32)r[dst] & (u32)r[src] != 0.
    Jset32Reg = 0x4E,
    /// Jump if (u32)r[dst] != immediate.
    Jne32Imm = 0x56,
    /// Jump if (u32)r[dst] != (u32)r[src].
    Jne32Reg = 0x5E,
    /// Jump if (i32)r[dst] > (i32)immediate (signed).
    Jsgt32Imm = 0x66,
    /// Jump if (i32)r[dst] > (i32)r[src] (signed).
    Jsgt32Reg = 0x6E,
    /// Jump if (i32)r[dst] >= (i32)immediate (signed).
    Jsge32Imm = 0x76,
    /// Jump if (i32)r[dst] >= (i32)r[src] (signed).
    Jsge32Reg = 0x7E,
    /// Jump if (u32)r[dst] < immediate (unsigned).
    Jlt32Imm = 0xA6,
    /// Jump if (u32)r[dst] < (u32)r[src] (unsigned).
    Jlt32Reg = 0xAE,
    /// Jump if (u32)r[dst] <= immediate (unsigned).
    Jle32Imm = 0xB6,
    /// Jump if (u32)r[dst] <= (u32)r[src] (unsigned).
    Jle32Reg = 0xBE,
    /// Jump if (i32)r[dst] < (i32)immediate (signed).
    Jslt32Imm = 0xC6,
    /// Jump if (i32)r[dst] < (i32)r[src] (signed).
    Jslt32Reg = 0xCE,
    /// Jump if (i32)r[dst] <= (i32)immediate (signed).
    Jsle32Imm = 0xD6,
    /// Jump if (i32)r[dst] <= (i32)r[src] (signed).
    Jsle32Reg = 0xDE,

    // --- Call / Exit ---
    /// Call function (immediate = target hash or local function).
    Call = 0x85,
    /// Exit current function frame / halt program.
    Exit = 0x95,
}

impl Opcode {
    /// Decode an opcode byte into a known opcode variant.
    ///
    /// Returns `None` for unrecognized opcodes.
    pub fn from_raw(raw: u8) -> Option<Self> {
        // Use a lookup table for O(1) decode in hot path
        OPCODE_TABLE[raw as usize]
    }

    /// Whether this opcode is an ALU operation.
    pub fn is_alu(&self) -> bool {
        let raw = *self as u8;
        let class = raw & 0x07;
        class == vm::CLASS_ALU32_IMM
            || class == vm::CLASS_ALU64_IMM
            || (raw & 0x0F) == vm::CLASS_ALU32_REG
            || (raw & 0x0F) == vm::CLASS_ALU64_REG
    }

    /// Whether this opcode is a jump/branch operation.
    pub fn is_jump(&self) -> bool {
        let class = (*self as u8) & vm::OPCODE_CLASS_MASK;
        class == vm::CLASS_JMP || class == vm::CLASS_JMP32
    }

    /// Whether this opcode is a memory access (load or store).
    pub fn is_memory(&self) -> bool {
        let class = (*self as u8) & vm::OPCODE_CLASS_MASK;
        class == vm::CLASS_LDX || class == vm::CLASS_ST || class == vm::CLASS_STX
    }

    /// Whether this is the LDDW opcode.
    pub fn is_lddw(&self) -> bool {
        *self == Opcode::Lddw
    }

    /// Whether this opcode uses an immediate source (vs register).
    pub fn is_immediate_source(&self) -> bool {
        let raw = *self as u8;
        // Immediate ALU: class bottom 3 bits are 0x04 or 0x07
        // Immediate JMP: low bit is 0x05 or 0x06 (but src field used for condition)
        // For ALU: immediate forms have bottom nibble 0x04/0x07
        (raw & 0x08) == 0 && self.is_alu()
    }
}

// ---------------------------------------------------------------------------
// Opcode lookup table
// ---------------------------------------------------------------------------

/// O(1) opcode lookup table, indexed by raw opcode byte.
static OPCODE_TABLE: [Option<Opcode>; 256] = {
    let mut table = [None; 256];

    // LDDW
    table[0x18] = Some(Opcode::Lddw);

    // ALU64 immediate
    table[0x07] = Some(Opcode::Add64Imm);
    table[0x17] = Some(Opcode::Sub64Imm);
    table[0x27] = Some(Opcode::Mul64Imm);
    table[0x37] = Some(Opcode::Div64Imm);
    table[0x47] = Some(Opcode::Or64Imm);
    table[0x57] = Some(Opcode::And64Imm);
    table[0x67] = Some(Opcode::Lsh64Imm);
    table[0x77] = Some(Opcode::Rsh64Imm);
    table[0x87] = Some(Opcode::Neg64);
    table[0x97] = Some(Opcode::Mod64Imm);
    table[0xA7] = Some(Opcode::Xor64Imm);
    table[0xB7] = Some(Opcode::Mov64Imm);
    table[0xC7] = Some(Opcode::Arsh64Imm);

    // ALU64 register
    table[0x0F] = Some(Opcode::Add64Reg);
    table[0x1F] = Some(Opcode::Sub64Reg);
    table[0x2F] = Some(Opcode::Mul64Reg);
    table[0x3F] = Some(Opcode::Div64Reg);
    table[0x4F] = Some(Opcode::Or64Reg);
    table[0x5F] = Some(Opcode::And64Reg);
    table[0x6F] = Some(Opcode::Lsh64Reg);
    table[0x7F] = Some(Opcode::Rsh64Reg);
    table[0x9F] = Some(Opcode::Mod64Reg);
    table[0xAF] = Some(Opcode::Xor64Reg);
    table[0xBF] = Some(Opcode::Mov64Reg);
    table[0xCF] = Some(Opcode::Arsh64Reg);

    // ALU32 immediate
    table[0x04] = Some(Opcode::Add32Imm);
    table[0x14] = Some(Opcode::Sub32Imm);
    table[0x24] = Some(Opcode::Mul32Imm);
    table[0x34] = Some(Opcode::Div32Imm);
    table[0x44] = Some(Opcode::Or32Imm);
    table[0x54] = Some(Opcode::And32Imm);
    table[0x64] = Some(Opcode::Lsh32Imm);
    table[0x74] = Some(Opcode::Rsh32Imm);
    table[0x84] = Some(Opcode::Neg32);
    table[0x94] = Some(Opcode::Mod32Imm);
    table[0xA4] = Some(Opcode::Xor32Imm);
    table[0xB4] = Some(Opcode::Mov32Imm);
    table[0xC4] = Some(Opcode::Arsh32Imm);

    // ALU32 register
    table[0x0C] = Some(Opcode::Add32Reg);
    table[0x1C] = Some(Opcode::Sub32Reg);
    table[0x2C] = Some(Opcode::Mul32Reg);
    table[0x3C] = Some(Opcode::Div32Reg);
    table[0x4C] = Some(Opcode::Or32Reg);
    table[0x5C] = Some(Opcode::And32Reg);
    table[0x6C] = Some(Opcode::Lsh32Reg);
    table[0x7C] = Some(Opcode::Rsh32Reg);
    table[0x9C] = Some(Opcode::Mod32Reg);
    table[0xAC] = Some(Opcode::Xor32Reg);
    table[0xBC] = Some(Opcode::Mov32Reg);
    table[0xCC] = Some(Opcode::Arsh32Reg);

    // Byte-order conversion
    table[0xD4] = Some(Opcode::Le);
    table[0xDC] = Some(Opcode::Be);

    // Memory load (LDX)
    table[0x71] = Some(Opcode::LdxByte);
    table[0x69] = Some(Opcode::LdxHalf);
    table[0x61] = Some(Opcode::LdxWord);
    table[0x79] = Some(Opcode::LdxDword);

    // Memory store immediate (ST)
    table[0x72] = Some(Opcode::StByte);
    table[0x6A] = Some(Opcode::StHalf);
    table[0x62] = Some(Opcode::StWord);
    table[0x7A] = Some(Opcode::StDword);

    // Memory store register (STX)
    table[0x73] = Some(Opcode::StxByte);
    table[0x6B] = Some(Opcode::StxHalf);
    table[0x63] = Some(Opcode::StxWord);
    table[0x7B] = Some(Opcode::StxDword);

    // Jump 64-bit
    table[0x05] = Some(Opcode::Ja);
    table[0x15] = Some(Opcode::JeqImm);
    table[0x1D] = Some(Opcode::JeqReg);
    table[0x25] = Some(Opcode::JgtImm);
    table[0x2D] = Some(Opcode::JgtReg);
    table[0x35] = Some(Opcode::JgeImm);
    table[0x3D] = Some(Opcode::JgeReg);
    table[0x45] = Some(Opcode::JsetImm);
    table[0x4D] = Some(Opcode::JsetReg);
    table[0x55] = Some(Opcode::JneImm);
    table[0x5D] = Some(Opcode::JneReg);
    table[0x65] = Some(Opcode::JsgtImm);
    table[0x6D] = Some(Opcode::JsgtReg);
    table[0x75] = Some(Opcode::JsgeImm);
    table[0x7D] = Some(Opcode::JsgeReg);
    table[0xA5] = Some(Opcode::JltImm);
    table[0xAD] = Some(Opcode::JltReg);
    table[0xB5] = Some(Opcode::JleImm);
    table[0xBD] = Some(Opcode::JleReg);
    table[0xC5] = Some(Opcode::JsltImm);
    table[0xCD] = Some(Opcode::JsltReg);
    table[0xD5] = Some(Opcode::JsleImm);
    table[0xDD] = Some(Opcode::JsleReg);

    // Jump 32-bit
    table[0x16] = Some(Opcode::Jeq32Imm);
    table[0x1E] = Some(Opcode::Jeq32Reg);
    table[0x26] = Some(Opcode::Jgt32Imm);
    table[0x2E] = Some(Opcode::Jgt32Reg);
    table[0x36] = Some(Opcode::Jge32Imm);
    table[0x3E] = Some(Opcode::Jge32Reg);
    table[0x46] = Some(Opcode::Jset32Imm);
    table[0x4E] = Some(Opcode::Jset32Reg);
    table[0x56] = Some(Opcode::Jne32Imm);
    table[0x5E] = Some(Opcode::Jne32Reg);
    table[0x66] = Some(Opcode::Jsgt32Imm);
    table[0x6E] = Some(Opcode::Jsgt32Reg);
    table[0x76] = Some(Opcode::Jsge32Imm);
    table[0x7E] = Some(Opcode::Jsge32Reg);
    table[0xA6] = Some(Opcode::Jlt32Imm);
    table[0xAE] = Some(Opcode::Jlt32Reg);
    table[0xB6] = Some(Opcode::Jle32Imm);
    table[0xBE] = Some(Opcode::Jle32Reg);
    table[0xC6] = Some(Opcode::Jslt32Imm);
    table[0xCE] = Some(Opcode::Jslt32Reg);
    table[0xD6] = Some(Opcode::Jsle32Imm);
    table[0xDE] = Some(Opcode::Jsle32Reg);

    // Call / Exit
    table[0x85] = Some(Opcode::Call);
    table[0x95] = Some(Opcode::Exit);

    table
};

// ---------------------------------------------------------------------------
// Helper: decode a stream of bytes into instructions
// ---------------------------------------------------------------------------

/// Decode a byte slice into a vector of instructions.
///
/// The input must be aligned to 8-byte boundaries.
/// LDDW instructions consume two slots; the second slot is consumed
/// but not returned as a separate instruction (its immediate is merged
/// into the LDDW's 64-bit value in the returned `Instruction`).
pub fn decode_instructions(bytes: &[u8]) -> Result<Vec<Instruction>, InstructionError> {
    if !bytes.len().is_multiple_of(vm::INSTRUCTION_SIZE) {
        return Err(InstructionError::UnalignedInput { size: bytes.len() });
    }

    let slot_count = bytes.len() / vm::INSTRUCTION_SIZE;
    let mut instructions = Vec::with_capacity(slot_count);
    let mut i = 0;

    while i < slot_count {
        let offset = i * vm::INSTRUCTION_SIZE;
        let raw = u64::from_le_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .expect("slice is 8 bytes"),
        );
        let insn = Instruction::decode(raw);

        if insn.is_lddw() {
            // LDDW consumes the next slot for the high 32 bits
            if i + 1 >= slot_count {
                return Err(InstructionError::TruncatedLddw { pc: i });
            }
            let next_offset = (i + 1) * vm::INSTRUCTION_SIZE;
            let next_raw = u64::from_le_bytes(
                bytes[next_offset..next_offset + 8]
                    .try_into()
                    .expect("slice is 8 bytes"),
            );
            // The full 64-bit immediate: low 32 from first word, high 32 from second
            let _high_imm = (next_raw >> 32) as i32;
            // Store the combined value: we keep the instruction as-is,
            // the interpreter will read the next slot for the high bits.
            instructions.push(insn);
            // Push a placeholder for the second slot
            instructions.push(Instruction::decode(next_raw));
            i += 2;
        } else {
            instructions.push(insn);
            i += 1;
        }
    }

    Ok(instructions)
}

/// Errors during instruction decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstructionError {
    /// Input byte slice is not aligned to instruction size.
    UnalignedInput { size: usize },
    /// LDDW instruction at end of program without second slot.
    TruncatedLddw { pc: usize },
}

impl std::fmt::Display for InstructionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnalignedInput { size } => {
                write!(f, "input size {} not aligned to 8-byte boundary", size)
            }
            Self::TruncatedLddw { pc } => {
                write!(f, "LDDW at PC {} missing second instruction slot", pc)
            }
        }
    }
}

impl std::error::Error for InstructionError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let insn = Instruction::new(0xB7, 3, 0, 0, 42);
        let encoded = insn.encode();
        let decoded = Instruction::decode(encoded);
        assert_eq!(insn, decoded);
    }

    #[test]
    fn encode_decode_with_negative_offset() {
        let insn = Instruction::new(0x15, 1, 0, -5, 100);
        let encoded = insn.encode();
        let decoded = Instruction::decode(encoded);
        assert_eq!(decoded.offset, -5);
        assert_eq!(decoded.immediate, 100);
    }

    #[test]
    fn encode_decode_with_negative_immediate() {
        let insn = Instruction::new(0x07, 2, 0, 0, -1);
        let encoded = insn.encode();
        let decoded = Instruction::decode(encoded);
        assert_eq!(decoded.immediate, -1);
    }

    #[test]
    fn decode_mov64_imm() {
        // mov64 r1, 42
        let insn = Instruction::new(Opcode::Mov64Imm as u8, 1, 0, 0, 42);
        let encoded = insn.encode();
        let decoded = Instruction::decode(encoded);
        assert_eq!(decoded.opcode, Opcode::Mov64Imm as u8);
        assert_eq!(decoded.dst, 1);
        assert_eq!(decoded.immediate, 42);
    }

    #[test]
    fn decode_add64_reg() {
        // add64 r3, r5
        let insn = Instruction::new(Opcode::Add64Reg as u8, 3, 5, 0, 0);
        let encoded = insn.encode();
        let decoded = Instruction::decode(encoded);
        assert_eq!(decoded.opcode, Opcode::Add64Reg as u8);
        assert_eq!(decoded.dst, 3);
        assert_eq!(decoded.src, 5);
    }

    #[test]
    fn decode_jeq_imm_with_offset() {
        // jeq r1, 0, +10
        let insn = Instruction::new(Opcode::JeqImm as u8, 1, 0, 10, 0);
        let encoded = insn.encode();
        let decoded = Instruction::decode(encoded);
        assert_eq!(decoded.opcode, Opcode::JeqImm as u8);
        assert_eq!(decoded.dst, 1);
        assert_eq!(decoded.offset, 10);
    }

    #[test]
    fn decode_ldxw() {
        // ldxw r2, [r10 + (-8)]
        let insn = Instruction::new(Opcode::LdxWord as u8, 2, 10, -8, 0);
        let encoded = insn.encode();
        let decoded = Instruction::decode(encoded);
        assert_eq!(decoded.opcode, Opcode::LdxWord as u8);
        assert_eq!(decoded.dst, 2);
        assert_eq!(decoded.src, 10);
        assert_eq!(decoded.offset, -8);
    }

    #[test]
    fn decode_stxdw() {
        // stxdw [r10 + (-16)], r3
        let insn = Instruction::new(Opcode::StxDword as u8, 10, 3, -16, 0);
        let encoded = insn.encode();
        let decoded = Instruction::decode(encoded);
        assert_eq!(decoded.opcode, Opcode::StxDword as u8);
        assert_eq!(decoded.dst, 10);
        assert_eq!(decoded.src, 3);
        assert_eq!(decoded.offset, -16);
    }

    #[test]
    fn opcode_from_raw_known() {
        assert_eq!(Opcode::from_raw(0xB7), Some(Opcode::Mov64Imm));
        assert_eq!(Opcode::from_raw(0x85), Some(Opcode::Call));
        assert_eq!(Opcode::from_raw(0x95), Some(Opcode::Exit));
        assert_eq!(Opcode::from_raw(0x18), Some(Opcode::Lddw));
        assert_eq!(Opcode::from_raw(0x79), Some(Opcode::LdxDword));
    }

    #[test]
    fn opcode_from_raw_unknown() {
        assert_eq!(Opcode::from_raw(0xFF), None);
        assert_eq!(Opcode::from_raw(0x00), None);
        assert_eq!(Opcode::from_raw(0x08), None);
    }

    #[test]
    fn opcode_classification_alu() {
        assert!(Opcode::Add64Imm.is_alu());
        assert!(Opcode::Sub32Reg.is_alu());
        assert!(Opcode::Mov64Reg.is_alu());
        assert!(!Opcode::Ja.is_alu());
        assert!(!Opcode::LdxWord.is_alu());
    }

    #[test]
    fn opcode_classification_jump() {
        assert!(Opcode::Ja.is_jump());
        assert!(Opcode::JeqImm.is_jump());
        assert!(Opcode::JsleReg.is_jump());
        assert!(Opcode::Call.is_jump());
        assert!(Opcode::Exit.is_jump());
        assert!(!Opcode::Add64Imm.is_jump());
        assert!(!Opcode::LdxWord.is_jump());
    }

    #[test]
    fn opcode_classification_memory() {
        assert!(Opcode::LdxByte.is_memory());
        assert!(Opcode::LdxDword.is_memory());
        assert!(Opcode::StWord.is_memory());
        assert!(Opcode::StxHalf.is_memory());
        assert!(!Opcode::Add64Imm.is_memory());
        assert!(!Opcode::Ja.is_memory());
    }

    #[test]
    fn lddw_detection() {
        let insn = Instruction::new(Opcode::Lddw as u8, 1, 0, 0, 42);
        assert!(insn.is_lddw());

        let insn2 = Instruction::new(Opcode::Mov64Imm as u8, 1, 0, 0, 42);
        assert!(!insn2.is_lddw());
    }

    #[test]
    fn decode_instructions_simple() {
        // Program: mov64 r1, 42; exit
        let insns = [
            Instruction::new(Opcode::Mov64Imm as u8, 1, 0, 0, 42),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ];
        let mut bytes = Vec::new();
        for insn in &insns {
            bytes.extend_from_slice(&insn.encode().to_le_bytes());
        }

        let decoded = decode_instructions(&bytes).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].opcode, Opcode::Mov64Imm as u8);
        assert_eq!(decoded[1].opcode, Opcode::Exit as u8);
    }

    #[test]
    fn decode_instructions_with_lddw() {
        // Program: lddw r1, <value>; exit
        let lddw_lo = Instruction::new(Opcode::Lddw as u8, 1, 0, 0, 0x1234);
        let lddw_hi = Instruction::new(0, 0, 0, 0, 0x5678); // second slot

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&lddw_lo.encode().to_le_bytes());
        bytes.extend_from_slice(&lddw_hi.encode().to_le_bytes());

        let exit = Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0);
        bytes.extend_from_slice(&exit.encode().to_le_bytes());

        let decoded = decode_instructions(&bytes).unwrap();
        assert_eq!(decoded.len(), 3); // lddw_lo, lddw_hi, exit
        assert_eq!(decoded[0].opcode, Opcode::Lddw as u8);
    }

    #[test]
    fn decode_instructions_unaligned() {
        let bytes = vec![0u8; 5]; // Not a multiple of 8
        let result = decode_instructions(&bytes);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            InstructionError::UnalignedInput { size: 5 }
        ));
    }

    #[test]
    fn decode_instructions_truncated_lddw() {
        // Only one slot for a LDDW
        let lddw = Instruction::new(Opcode::Lddw as u8, 1, 0, 0, 42);
        let bytes = lddw.encode().to_le_bytes().to_vec();
        let result = decode_instructions(&bytes);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            InstructionError::TruncatedLddw { pc: 0 }
        ));
    }

    #[test]
    fn display_known_instruction() {
        let insn = Instruction::new(Opcode::Mov64Imm as u8, 1, 0, 0, 42);
        let s = format!("{}", insn);
        assert!(s.contains("Mov64Imm"));
        assert!(s.contains("r1"));
        assert!(s.contains("42"));
    }

    #[test]
    fn display_unknown_instruction() {
        let insn = Instruction::new(0xFF, 0, 0, 0, 0);
        let s = format!("{}", insn);
        assert!(s.contains("UNKNOWN(0xFF)"));
    }
}
