/// Solana transaction wire format types.
///
/// Defines the canonical on-wire representation of Solana transactions
/// including legacy and versioned message formats. These types support
/// bincode serialization matching the Solana protocol specification.
use crate::compact::{decode_compact_u16, encode_compact_u16, CompactError};
use crate::hash::Hash;
use crate::pubkey::Pubkey;
use serde::{Deserialize, Serialize};

/// 64-byte Ed25519 signature.
pub const SIGNATURE_BYTES: usize = 64;

/// A transaction signature (64 bytes).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Signature([u8; SIGNATURE_BYTES]);

impl Default for Signature {
    fn default() -> Self {
        Self([0u8; SIGNATURE_BYTES])
    }
}

impl Serialize for Signature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        let mut tup = serializer.serialize_tuple(SIGNATURE_BYTES)?;
        for byte in &self.0 {
            tup.serialize_element(byte)?;
        }
        tup.end()
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SignatureVisitor;

        impl<'de> serde::de::Visitor<'de> for SignatureVisitor {
            type Value = Signature;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "64 bytes")
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut bytes = [0u8; SIGNATURE_BYTES];
                for (i, byte) in bytes.iter_mut().enumerate() {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(Signature(bytes))
            }
        }

        deserializer.deserialize_tuple(SIGNATURE_BYTES, SignatureVisitor)
    }
}

impl Signature {
    pub const fn new(bytes: [u8; SIGNATURE_BYTES]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; SIGNATURE_BYTES] {
        &self.0
    }

    pub fn to_bytes(&self) -> [u8; SIGNATURE_BYTES] {
        self.0
    }

    pub const fn zeroed() -> Self {
        Self([0u8; SIGNATURE_BYTES])
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Sig({}..)", bs58::encode(&self.0[..8]).into_string())
    }
}

impl std::fmt::Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", bs58::encode(&self.0).into_string())
    }
}

impl From<[u8; SIGNATURE_BYTES]> for Signature {
    fn from(bytes: [u8; SIGNATURE_BYTES]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Header of a transaction message.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageHeader {
    /// Number of required signatures.
    pub num_required_signatures: u8,
    /// Number of read-only signed accounts.
    pub num_readonly_signed_accounts: u8,
    /// Number of read-only unsigned accounts.
    pub num_readonly_unsigned_accounts: u8,
}

impl MessageHeader {
    /// Number of writable signed accounts.
    pub fn num_writable_signed(&self) -> usize {
        self.num_required_signatures
            .saturating_sub(self.num_readonly_signed_accounts) as usize
    }

    /// Number of writable unsigned accounts.
    pub fn num_writable_unsigned(&self, total_accounts: usize) -> usize {
        total_accounts
            .saturating_sub(self.num_required_signatures as usize)
            .saturating_sub(self.num_readonly_unsigned_accounts as usize)
    }
}

/// A compiled instruction within a message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledInstruction {
    /// Index into the message's account_keys array for the program.
    pub program_id_index: u8,
    /// Indices into the message's account_keys array for accounts.
    pub accounts: Vec<u8>,
    /// Opaque instruction data.
    pub data: Vec<u8>,
}

impl CompiledInstruction {
    pub fn new(program_id_index: u8, accounts: Vec<u8>, data: Vec<u8>) -> Self {
        Self {
            program_id_index,
            accounts,
            data,
        }
    }

    /// Serialized size of this instruction in wire format.
    pub fn wire_size(&self) -> usize {
        let mut size = 1; // program_id_index
        let mut buf = [0u8; 3];
        size += encode_compact_u16(self.accounts.len() as u16, &mut buf);
        size += self.accounts.len();
        size += encode_compact_u16(self.data.len() as u16, &mut buf);
        size += self.data.len();
        size
    }
}

/// A legacy (pre-v0) transaction message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    /// Message header describing account roles.
    pub header: MessageHeader,
    /// Ordered list of account public keys referenced by instructions.
    pub account_keys: Vec<Pubkey>,
    /// Recent blockhash for transaction lifetime validation.
    pub recent_blockhash: Hash,
    /// Instructions to execute.
    pub instructions: Vec<CompiledInstruction>,
}

impl Message {
    /// Create a new empty message.
    pub fn new_empty(recent_blockhash: Hash) -> Self {
        Self {
            header: MessageHeader::default(),
            account_keys: Vec::new(),
            recent_blockhash,
            instructions: Vec::new(),
        }
    }

    /// Check if the account at the given index is a signer.
    pub fn is_signer(&self, index: usize) -> bool {
        index < self.header.num_required_signatures as usize
    }

    /// Check if the account at the given index is writable.
    pub fn is_writable(&self, index: usize) -> bool {
        let num_signed = self.header.num_required_signatures as usize;
        let num_ro_signed = self.header.num_readonly_signed_accounts as usize;
        let num_ro_unsigned = self.header.num_readonly_unsigned_accounts as usize;

        if index < num_signed {
            // Signed accounts: writable if not in the read-only signed range
            index < num_signed.saturating_sub(num_ro_signed)
        } else {
            // Unsigned accounts: writable if not in the read-only unsigned range
            let unsigned_start = num_signed;
            let ro_unsigned_start = self.account_keys.len().saturating_sub(num_ro_unsigned);
            index >= unsigned_start && index < ro_unsigned_start
        }
    }

    /// Get the fee payer (first account key).
    pub fn fee_payer(&self) -> Option<&Pubkey> {
        self.account_keys.first()
    }

    /// Get the program ID for an instruction.
    pub fn program_id(&self, instruction: &CompiledInstruction) -> Option<&Pubkey> {
        self.account_keys.get(instruction.program_id_index as usize)
    }
}

/// A complete legacy transaction (signatures + message).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    /// Transaction signatures (one per required signer).
    pub signatures: Vec<Signature>,
    /// The transaction message.
    pub message: Message,
}

impl Transaction {
    /// Create a new unsigned transaction.
    pub fn new_unsigned(message: Message) -> Self {
        let num_sigs = message.header.num_required_signatures as usize;
        Self {
            signatures: vec![Signature::zeroed(); num_sigs],
            message,
        }
    }

    /// The first signature (transaction ID).
    pub fn signature(&self) -> Option<&Signature> {
        self.signatures.first()
    }

    /// The message's recent blockhash.
    pub fn blockhash(&self) -> &Hash {
        &self.message.recent_blockhash
    }
}

/// Errors in transaction wire format parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionParseError {
    /// Not enough data.
    UnexpectedEnd,
    /// Invalid compact-u16 encoding.
    InvalidCompactEncoding(CompactError),
    /// Too many signatures.
    TooManySignatures(u16),
    /// Too many account keys.
    TooManyAccountKeys(u16),
    /// Too many instructions.
    TooManyInstructions(u16),
    /// Invalid version prefix.
    InvalidVersionPrefix(u8),
}

impl std::fmt::Display for TransactionParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedEnd => write!(f, "unexpected end of transaction data"),
            Self::InvalidCompactEncoding(e) => write!(f, "invalid compact encoding: {}", e),
            Self::TooManySignatures(n) => write!(f, "too many signatures: {}", n),
            Self::TooManyAccountKeys(n) => write!(f, "too many account keys: {}", n),
            Self::TooManyInstructions(n) => write!(f, "too many instructions: {}", n),
            Self::InvalidVersionPrefix(v) => write!(f, "invalid version prefix: {:#x}", v),
        }
    }
}

impl std::error::Error for TransactionParseError {}

impl From<CompactError> for TransactionParseError {
    fn from(e: CompactError) -> Self {
        Self::InvalidCompactEncoding(e)
    }
}

/// Maximum allowed signatures per transaction.
const MAX_SIGNATURES: u16 = 256;
/// Maximum allowed account keys per transaction.
const MAX_ACCOUNT_KEYS: u16 = 256;
/// Maximum allowed instructions per transaction.
const MAX_INSTRUCTIONS: u16 = 256;

/// Parse a legacy transaction from raw wire bytes.
pub fn parse_transaction(data: &[u8]) -> Result<Transaction, TransactionParseError> {
    let mut offset = 0;

    // Signatures
    let (num_sigs, consumed) =
        decode_compact_u16(&data[offset..]).map_err(TransactionParseError::from)?;
    offset += consumed;
    if num_sigs > MAX_SIGNATURES {
        return Err(TransactionParseError::TooManySignatures(num_sigs));
    }

    let mut signatures = Vec::with_capacity(num_sigs as usize);
    for _ in 0..num_sigs {
        if offset + SIGNATURE_BYTES > data.len() {
            return Err(TransactionParseError::UnexpectedEnd);
        }
        let mut sig = [0u8; SIGNATURE_BYTES];
        sig.copy_from_slice(&data[offset..offset + SIGNATURE_BYTES]);
        signatures.push(Signature::new(sig));
        offset += SIGNATURE_BYTES;
    }

    // Message header
    if offset + 3 > data.len() {
        return Err(TransactionParseError::UnexpectedEnd);
    }
    let header = MessageHeader {
        num_required_signatures: data[offset],
        num_readonly_signed_accounts: data[offset + 1],
        num_readonly_unsigned_accounts: data[offset + 2],
    };
    offset += 3;

    // Account keys
    let (num_keys, consumed) =
        decode_compact_u16(&data[offset..]).map_err(TransactionParseError::from)?;
    offset += consumed;
    if num_keys > MAX_ACCOUNT_KEYS {
        return Err(TransactionParseError::TooManyAccountKeys(num_keys));
    }

    let mut account_keys = Vec::with_capacity(num_keys as usize);
    for _ in 0..num_keys {
        if offset + 32 > data.len() {
            return Err(TransactionParseError::UnexpectedEnd);
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&data[offset..offset + 32]);
        account_keys.push(Pubkey::new(key));
        offset += 32;
    }

    // Recent blockhash
    if offset + 32 > data.len() {
        return Err(TransactionParseError::UnexpectedEnd);
    }
    let mut bh = [0u8; 32];
    bh.copy_from_slice(&data[offset..offset + 32]);
    let recent_blockhash = Hash::new(bh);
    offset += 32;

    // Instructions
    let (num_ix, consumed) =
        decode_compact_u16(&data[offset..]).map_err(TransactionParseError::from)?;
    offset += consumed;
    if num_ix > MAX_INSTRUCTIONS {
        return Err(TransactionParseError::TooManyInstructions(num_ix));
    }

    let mut instructions = Vec::with_capacity(num_ix as usize);
    for _ in 0..num_ix {
        if offset >= data.len() {
            return Err(TransactionParseError::UnexpectedEnd);
        }
        let program_id_index = data[offset];
        offset += 1;

        let (num_accounts, consumed) =
            decode_compact_u16(&data[offset..]).map_err(TransactionParseError::from)?;
        offset += consumed;
        if offset + num_accounts as usize > data.len() {
            return Err(TransactionParseError::UnexpectedEnd);
        }
        let accounts = data[offset..offset + num_accounts as usize].to_vec();
        offset += num_accounts as usize;

        let (data_len, consumed) =
            decode_compact_u16(&data[offset..]).map_err(TransactionParseError::from)?;
        offset += consumed;
        if offset + data_len as usize > data.len() {
            return Err(TransactionParseError::UnexpectedEnd);
        }
        let ix_data = data[offset..offset + data_len as usize].to_vec();
        offset += data_len as usize;

        instructions.push(CompiledInstruction::new(
            program_id_index,
            accounts,
            ix_data,
        ));
    }

    Ok(Transaction {
        signatures,
        message: Message {
            header,
            account_keys,
            recent_blockhash,
            instructions,
        },
    })
}

/// Serialize a legacy transaction to wire bytes.
pub fn serialize_transaction(tx: &Transaction) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    let mut compact_buf = [0u8; 3];

    // Signatures
    let len = encode_compact_u16(tx.signatures.len() as u16, &mut compact_buf);
    buf.extend_from_slice(&compact_buf[..len]);
    for sig in &tx.signatures {
        buf.extend_from_slice(sig.as_bytes());
    }

    // Message header
    buf.push(tx.message.header.num_required_signatures);
    buf.push(tx.message.header.num_readonly_signed_accounts);
    buf.push(tx.message.header.num_readonly_unsigned_accounts);

    // Account keys
    let len = encode_compact_u16(tx.message.account_keys.len() as u16, &mut compact_buf);
    buf.extend_from_slice(&compact_buf[..len]);
    for key in &tx.message.account_keys {
        buf.extend_from_slice(key.as_bytes());
    }

    // Recent blockhash
    buf.extend_from_slice(tx.message.recent_blockhash.as_bytes());

    // Instructions
    let len = encode_compact_u16(tx.message.instructions.len() as u16, &mut compact_buf);
    buf.extend_from_slice(&compact_buf[..len]);
    for ix in &tx.message.instructions {
        buf.push(ix.program_id_index);

        let len = encode_compact_u16(ix.accounts.len() as u16, &mut compact_buf);
        buf.extend_from_slice(&compact_buf[..len]);
        buf.extend_from_slice(&ix.accounts);

        let len = encode_compact_u16(ix.data.len() as u16, &mut compact_buf);
        buf.extend_from_slice(&compact_buf[..len]);
        buf.extend_from_slice(&ix.data);
    }

    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_transfer_tx() -> Transaction {
        let payer = Pubkey::new([1u8; 32]);
        let recipient = Pubkey::new([2u8; 32]);
        let system_program = Pubkey::zeroed();
        let blockhash = Hash::sha256(b"test blockhash");

        let mut data = vec![2, 0, 0, 0]; // transfer instruction type
        data.extend_from_slice(&100u64.to_le_bytes()); // 100 lamports

        Transaction {
            signatures: vec![Signature::zeroed()],
            message: Message {
                header: MessageHeader {
                    num_required_signatures: 1,
                    num_readonly_signed_accounts: 0,
                    num_readonly_unsigned_accounts: 1,
                },
                account_keys: vec![payer, recipient, system_program],
                recent_blockhash: blockhash,
                instructions: vec![CompiledInstruction::new(2, vec![0, 1], data)],
            },
        }
    }

    #[test]
    fn serialize_parse_roundtrip() {
        let tx = make_transfer_tx();
        let bytes = serialize_transaction(&tx);
        let parsed = parse_transaction(&bytes).unwrap();
        assert_eq!(parsed, tx);
    }

    #[test]
    fn message_header_writable_signed() {
        let header = MessageHeader {
            num_required_signatures: 3,
            num_readonly_signed_accounts: 1,
            num_readonly_unsigned_accounts: 2,
        };
        assert_eq!(header.num_writable_signed(), 2);
    }

    #[test]
    fn message_is_signer() {
        let msg = Message {
            header: MessageHeader {
                num_required_signatures: 2,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 1,
            },
            account_keys: vec![
                Pubkey::new([1u8; 32]),
                Pubkey::new([2u8; 32]),
                Pubkey::new([3u8; 32]),
            ],
            recent_blockhash: Hash::zeroed(),
            instructions: vec![],
        };

        assert!(msg.is_signer(0));
        assert!(msg.is_signer(1));
        assert!(!msg.is_signer(2));
    }

    #[test]
    fn message_is_writable() {
        let msg = Message {
            header: MessageHeader {
                num_required_signatures: 2,
                num_readonly_signed_accounts: 1,
                num_readonly_unsigned_accounts: 1,
            },
            account_keys: vec![
                Pubkey::new([1u8; 32]), // 0: writable signer
                Pubkey::new([2u8; 32]), // 1: readonly signer
                Pubkey::new([3u8; 32]), // 2: writable unsigned
                Pubkey::new([4u8; 32]), // 3: readonly unsigned
            ],
            recent_blockhash: Hash::zeroed(),
            instructions: vec![],
        };

        assert!(msg.is_writable(0)); // writable signer
        assert!(!msg.is_writable(1)); // readonly signer
        assert!(msg.is_writable(2)); // writable unsigned
        assert!(!msg.is_writable(3)); // readonly unsigned
    }

    #[test]
    fn fee_payer() {
        let tx = make_transfer_tx();
        assert_eq!(tx.message.fee_payer(), Some(&Pubkey::new([1u8; 32])));
    }

    #[test]
    fn program_id_lookup() {
        let tx = make_transfer_tx();
        let ix = &tx.message.instructions[0];
        assert_eq!(tx.message.program_id(ix), Some(&Pubkey::zeroed()));
    }

    #[test]
    fn parse_empty_errors() {
        let result = parse_transaction(&[]);
        assert!(matches!(
            result,
            Err(TransactionParseError::InvalidCompactEncoding(_))
        ));
    }

    #[test]
    fn parse_truncated_sig_errors() {
        let mut buf = [0u8; 3];
        let len = encode_compact_u16(1, &mut buf);
        // 1 signature expected but no signature data
        let data = &buf[..len];
        let result = parse_transaction(data);
        assert!(matches!(result, Err(TransactionParseError::UnexpectedEnd)));
    }

    #[test]
    fn signature_display() {
        let sig = Signature::zeroed();
        let s = format!("{}", sig);
        assert!(!s.is_empty());
    }

    #[test]
    fn signature_serde_roundtrip() {
        let sig = Signature::new([42u8; 64]);
        let encoded = bincode::serialize(&sig).unwrap();
        let decoded: Signature = bincode::deserialize(&encoded).unwrap();
        assert_eq!(sig, decoded);
        assert_eq!(encoded.len(), 64);
    }

    #[test]
    fn new_unsigned_has_correct_sigs() {
        let msg = Message {
            header: MessageHeader {
                num_required_signatures: 3,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 0,
            },
            account_keys: vec![
                Pubkey::new([1; 32]),
                Pubkey::new([2; 32]),
                Pubkey::new([3; 32]),
            ],
            recent_blockhash: Hash::zeroed(),
            instructions: vec![],
        };
        let tx = Transaction::new_unsigned(msg);
        assert_eq!(tx.signatures.len(), 3);
    }
}
