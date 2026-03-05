/// Versioned transaction types.
///
/// Solana v0 transactions support address lookup tables which reduce
/// transaction size by referencing accounts via table indices instead
/// of embedding full 32-byte pubkeys.
use crate::compact::{decode_compact_u16, encode_compact_u16};
use crate::hash::Hash;
use crate::pubkey::Pubkey;
use crate::transaction::{
    CompiledInstruction, Message, MessageHeader, Signature, TransactionParseError, SIGNATURE_BYTES,
};
use serde::{Deserialize, Serialize};

/// Reference to an address lookup table used in a v0 message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageAddressTableLookup {
    /// The address of the lookup table account.
    pub account_key: Pubkey,
    /// Indices into the lookup table for writable accounts.
    pub writable_indexes: Vec<u8>,
    /// Indices into the lookup table for read-only accounts.
    pub readonly_indexes: Vec<u8>,
}

/// A v0 transaction message with address lookup table support.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageV0 {
    /// Message header.
    pub header: MessageHeader,
    /// Static account keys embedded in the message.
    pub account_keys: Vec<Pubkey>,
    /// Recent blockhash.
    pub recent_blockhash: Hash,
    /// Instructions.
    pub instructions: Vec<CompiledInstruction>,
    /// Address table lookups for additional accounts.
    pub address_table_lookups: Vec<MessageAddressTableLookup>,
}

impl MessageV0 {
    /// Total number of account keys (static + lookup table resolved).
    pub fn total_account_keys(&self) -> usize {
        let lookup_keys: usize = self
            .address_table_lookups
            .iter()
            .map(|l| l.writable_indexes.len() + l.readonly_indexes.len())
            .sum();
        self.account_keys.len() + lookup_keys
    }

    /// Check if a static account at the given index is a signer.
    pub fn is_signer(&self, index: usize) -> bool {
        index < self.header.num_required_signatures as usize
    }
}

/// Versioned message enum supporting legacy and v0 formats.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VersionedMessage {
    Legacy(Message),
    V0(MessageV0),
}

impl VersionedMessage {
    /// Get the recent blockhash.
    pub fn recent_blockhash(&self) -> &Hash {
        match self {
            VersionedMessage::Legacy(m) => &m.recent_blockhash,
            VersionedMessage::V0(m) => &m.recent_blockhash,
        }
    }

    /// Get the message header.
    pub fn header(&self) -> &MessageHeader {
        match self {
            VersionedMessage::Legacy(m) => &m.header,
            VersionedMessage::V0(m) => &m.header,
        }
    }

    /// Get the static account keys.
    pub fn static_account_keys(&self) -> &[Pubkey] {
        match self {
            VersionedMessage::Legacy(m) => &m.account_keys,
            VersionedMessage::V0(m) => &m.account_keys,
        }
    }

    /// Get the instructions.
    pub fn instructions(&self) -> &[CompiledInstruction] {
        match self {
            VersionedMessage::Legacy(m) => &m.instructions,
            VersionedMessage::V0(m) => &m.instructions,
        }
    }

    /// Whether this is a v0 message.
    pub fn is_v0(&self) -> bool {
        matches!(self, VersionedMessage::V0(_))
    }

    /// Get address table lookups (empty for legacy).
    pub fn address_table_lookups(&self) -> &[MessageAddressTableLookup] {
        match self {
            VersionedMessage::Legacy(_) => &[],
            VersionedMessage::V0(m) => &m.address_table_lookups,
        }
    }
}

/// A versioned transaction (signatures + versioned message).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionedTransaction {
    /// Transaction signatures.
    pub signatures: Vec<Signature>,
    /// The versioned message.
    pub message: VersionedMessage,
}

impl VersionedTransaction {
    /// The first signature (transaction ID).
    pub fn signature(&self) -> Option<&Signature> {
        self.signatures.first()
    }

    /// The message's recent blockhash.
    pub fn blockhash(&self) -> &Hash {
        self.message.recent_blockhash()
    }

    /// Whether this transaction uses v0 format.
    pub fn is_v0(&self) -> bool {
        self.message.is_v0()
    }
}

/// The version prefix byte. If the high bit is set, it's a versioned message.
/// The version number is in the remaining 7 bits. Currently only v0 (0x80).
const VERSIONED_PREFIX_MASK: u8 = 0x80;

/// Parse a versioned transaction from raw wire bytes.
/// Detects legacy vs v0 format from the message prefix byte.
pub fn parse_versioned_transaction(
    data: &[u8],
) -> Result<VersionedTransaction, TransactionParseError> {
    let mut offset = 0;

    // Signatures
    let (num_sigs, consumed) =
        decode_compact_u16(&data[offset..]).map_err(TransactionParseError::from)?;
    offset += consumed;
    if num_sigs > 256 {
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

    // Check version prefix
    if offset >= data.len() {
        return Err(TransactionParseError::UnexpectedEnd);
    }

    let prefix = data[offset];
    let message = if prefix & VERSIONED_PREFIX_MASK != 0 {
        let version = prefix & !VERSIONED_PREFIX_MASK;
        if version != 0 {
            return Err(TransactionParseError::InvalidVersionPrefix(prefix));
        }
        offset += 1; // consume version byte
        VersionedMessage::V0(parse_message_v0(data, &mut offset)?)
    } else {
        // Legacy: prefix byte is actually num_required_signatures
        VersionedMessage::Legacy(parse_legacy_message(data, &mut offset)?)
    };

    Ok(VersionedTransaction {
        signatures,
        message,
    })
}

/// Parse a legacy message starting at the given offset.
fn parse_legacy_message(data: &[u8], offset: &mut usize) -> Result<Message, TransactionParseError> {
    if *offset + 3 > data.len() {
        return Err(TransactionParseError::UnexpectedEnd);
    }

    let header = MessageHeader {
        num_required_signatures: data[*offset],
        num_readonly_signed_accounts: data[*offset + 1],
        num_readonly_unsigned_accounts: data[*offset + 2],
    };
    *offset += 3;

    let account_keys = parse_pubkey_array(data, offset)?;
    let recent_blockhash = parse_hash(data, offset)?;
    let instructions = parse_instructions(data, offset)?;

    Ok(Message {
        header,
        account_keys,
        recent_blockhash,
        instructions,
    })
}

/// Parse a v0 message starting at the given offset.
fn parse_message_v0(data: &[u8], offset: &mut usize) -> Result<MessageV0, TransactionParseError> {
    if *offset + 3 > data.len() {
        return Err(TransactionParseError::UnexpectedEnd);
    }

    let header = MessageHeader {
        num_required_signatures: data[*offset],
        num_readonly_signed_accounts: data[*offset + 1],
        num_readonly_unsigned_accounts: data[*offset + 2],
    };
    *offset += 3;

    let account_keys = parse_pubkey_array(data, offset)?;
    let recent_blockhash = parse_hash(data, offset)?;
    let instructions = parse_instructions(data, offset)?;

    // Address table lookups
    let (num_lookups, consumed) =
        decode_compact_u16(&data[*offset..]).map_err(TransactionParseError::from)?;
    *offset += consumed;

    let mut lookups = Vec::with_capacity(num_lookups as usize);
    for _ in 0..num_lookups {
        if *offset + 32 > data.len() {
            return Err(TransactionParseError::UnexpectedEnd);
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&data[*offset..*offset + 32]);
        *offset += 32;

        let writable_indexes = parse_u8_array(data, offset)?;
        let readonly_indexes = parse_u8_array(data, offset)?;

        lookups.push(MessageAddressTableLookup {
            account_key: Pubkey::new(key),
            writable_indexes,
            readonly_indexes,
        });
    }

    Ok(MessageV0 {
        header,
        account_keys,
        recent_blockhash,
        instructions,
        address_table_lookups: lookups,
    })
}

fn parse_pubkey_array(
    data: &[u8],
    offset: &mut usize,
) -> Result<Vec<Pubkey>, TransactionParseError> {
    let (count, consumed) =
        decode_compact_u16(&data[*offset..]).map_err(TransactionParseError::from)?;
    *offset += consumed;
    if count > 256 {
        return Err(TransactionParseError::TooManyAccountKeys(count));
    }

    let mut keys = Vec::with_capacity(count as usize);
    for _ in 0..count {
        if *offset + 32 > data.len() {
            return Err(TransactionParseError::UnexpectedEnd);
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&data[*offset..*offset + 32]);
        keys.push(Pubkey::new(key));
        *offset += 32;
    }
    Ok(keys)
}

fn parse_hash(data: &[u8], offset: &mut usize) -> Result<Hash, TransactionParseError> {
    if *offset + 32 > data.len() {
        return Err(TransactionParseError::UnexpectedEnd);
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&data[*offset..*offset + 32]);
    *offset += 32;
    Ok(Hash::new(bytes))
}

fn parse_instructions(
    data: &[u8],
    offset: &mut usize,
) -> Result<Vec<CompiledInstruction>, TransactionParseError> {
    let (count, consumed) =
        decode_compact_u16(&data[*offset..]).map_err(TransactionParseError::from)?;
    *offset += consumed;
    if count > 256 {
        return Err(TransactionParseError::TooManyInstructions(count));
    }

    let mut instructions = Vec::with_capacity(count as usize);
    for _ in 0..count {
        if *offset >= data.len() {
            return Err(TransactionParseError::UnexpectedEnd);
        }
        let program_id_index = data[*offset];
        *offset += 1;

        let accounts = parse_u8_array(data, offset)?;
        let ix_data = parse_u8_array(data, offset)?;

        instructions.push(CompiledInstruction::new(
            program_id_index,
            accounts,
            ix_data,
        ));
    }
    Ok(instructions)
}

fn parse_u8_array(data: &[u8], offset: &mut usize) -> Result<Vec<u8>, TransactionParseError> {
    let (count, consumed) =
        decode_compact_u16(&data[*offset..]).map_err(TransactionParseError::from)?;
    *offset += consumed;
    if *offset + count as usize > data.len() {
        return Err(TransactionParseError::UnexpectedEnd);
    }
    let arr = data[*offset..*offset + count as usize].to_vec();
    *offset += count as usize;
    Ok(arr)
}

/// Serialize a versioned transaction to wire bytes.
pub fn serialize_versioned_transaction(tx: &VersionedTransaction) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);
    let mut compact_buf = [0u8; 3];

    // Signatures
    let len = encode_compact_u16(tx.signatures.len() as u16, &mut compact_buf);
    buf.extend_from_slice(&compact_buf[..len]);
    for sig in &tx.signatures {
        buf.extend_from_slice(sig.as_bytes());
    }

    match &tx.message {
        VersionedMessage::Legacy(msg) => {
            serialize_legacy_message(&mut buf, msg);
        }
        VersionedMessage::V0(msg) => {
            buf.push(0x80); // version 0 prefix
            serialize_v0_message(&mut buf, msg);
        }
    }

    buf
}

fn serialize_legacy_message(buf: &mut Vec<u8>, msg: &Message) {
    buf.push(msg.header.num_required_signatures);
    buf.push(msg.header.num_readonly_signed_accounts);
    buf.push(msg.header.num_readonly_unsigned_accounts);

    serialize_pubkey_array(buf, &msg.account_keys);
    buf.extend_from_slice(msg.recent_blockhash.as_bytes());
    serialize_instructions(buf, &msg.instructions);
}

fn serialize_v0_message(buf: &mut Vec<u8>, msg: &MessageV0) {
    let mut compact_buf = [0u8; 3];

    buf.push(msg.header.num_required_signatures);
    buf.push(msg.header.num_readonly_signed_accounts);
    buf.push(msg.header.num_readonly_unsigned_accounts);

    serialize_pubkey_array(buf, &msg.account_keys);
    buf.extend_from_slice(msg.recent_blockhash.as_bytes());
    serialize_instructions(buf, &msg.instructions);

    // Address table lookups
    let len = encode_compact_u16(msg.address_table_lookups.len() as u16, &mut compact_buf);
    buf.extend_from_slice(&compact_buf[..len]);

    for lookup in &msg.address_table_lookups {
        buf.extend_from_slice(lookup.account_key.as_bytes());
        serialize_u8_array(buf, &lookup.writable_indexes);
        serialize_u8_array(buf, &lookup.readonly_indexes);
    }
}

fn serialize_pubkey_array(buf: &mut Vec<u8>, keys: &[Pubkey]) {
    let mut compact_buf = [0u8; 3];
    let len = encode_compact_u16(keys.len() as u16, &mut compact_buf);
    buf.extend_from_slice(&compact_buf[..len]);
    for key in keys {
        buf.extend_from_slice(key.as_bytes());
    }
}

fn serialize_instructions(buf: &mut Vec<u8>, instructions: &[CompiledInstruction]) {
    let mut compact_buf = [0u8; 3];
    let len = encode_compact_u16(instructions.len() as u16, &mut compact_buf);
    buf.extend_from_slice(&compact_buf[..len]);

    for ix in instructions {
        buf.push(ix.program_id_index);
        serialize_u8_array(buf, &ix.accounts);
        serialize_u8_array(buf, &ix.data);
    }
}

fn serialize_u8_array(buf: &mut Vec<u8>, arr: &[u8]) {
    let mut compact_buf = [0u8; 3];
    let len = encode_compact_u16(arr.len() as u16, &mut compact_buf);
    buf.extend_from_slice(&compact_buf[..len]);
    buf.extend_from_slice(arr);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_legacy_versioned() -> VersionedTransaction {
        let payer = Pubkey::new([1u8; 32]);
        let recipient = Pubkey::new([2u8; 32]);
        let system = Pubkey::zeroed();

        VersionedTransaction {
            signatures: vec![Signature::zeroed()],
            message: VersionedMessage::Legacy(Message {
                header: MessageHeader {
                    num_required_signatures: 1,
                    num_readonly_signed_accounts: 0,
                    num_readonly_unsigned_accounts: 1,
                },
                account_keys: vec![payer, recipient, system],
                recent_blockhash: Hash::sha256(b"blockhash"),
                instructions: vec![CompiledInstruction::new(2, vec![0, 1], vec![2, 0, 0, 0])],
            }),
        }
    }

    fn make_v0_versioned() -> VersionedTransaction {
        let payer = Pubkey::new([1u8; 32]);
        let system = Pubkey::zeroed();
        let table = Pubkey::new([3u8; 32]);

        VersionedTransaction {
            signatures: vec![Signature::zeroed()],
            message: VersionedMessage::V0(MessageV0 {
                header: MessageHeader {
                    num_required_signatures: 1,
                    num_readonly_signed_accounts: 0,
                    num_readonly_unsigned_accounts: 1,
                },
                account_keys: vec![payer, system],
                recent_blockhash: Hash::sha256(b"v0 blockhash"),
                instructions: vec![CompiledInstruction::new(1, vec![0, 2], vec![5, 0, 0, 0])],
                address_table_lookups: vec![MessageAddressTableLookup {
                    account_key: table,
                    writable_indexes: vec![0],
                    readonly_indexes: vec![1, 2],
                }],
            }),
        }
    }

    #[test]
    fn legacy_roundtrip() {
        let tx = make_legacy_versioned();
        let bytes = serialize_versioned_transaction(&tx);
        let parsed = parse_versioned_transaction(&bytes).unwrap();
        assert_eq!(parsed, tx);
        assert!(!parsed.is_v0());
    }

    #[test]
    fn v0_roundtrip() {
        let tx = make_v0_versioned();
        let bytes = serialize_versioned_transaction(&tx);
        let parsed = parse_versioned_transaction(&bytes).unwrap();
        assert_eq!(parsed, tx);
        assert!(parsed.is_v0());
    }

    #[test]
    fn v0_total_account_keys() {
        let tx = make_v0_versioned();
        if let VersionedMessage::V0(msg) = &tx.message {
            // 2 static keys + 1 writable + 2 readonly from lookup = 5
            assert_eq!(msg.total_account_keys(), 5);
        } else {
            panic!("expected v0");
        }
    }

    #[test]
    fn versioned_message_accessors() {
        let tx = make_v0_versioned();
        assert!(tx.message.is_v0());
        assert_eq!(tx.message.static_account_keys().len(), 2);
        assert_eq!(tx.message.instructions().len(), 1);
        assert_eq!(tx.message.address_table_lookups().len(), 1);
    }

    #[test]
    fn legacy_has_no_lookups() {
        let tx = make_legacy_versioned();
        assert!(tx.message.address_table_lookups().is_empty());
    }

    #[test]
    fn invalid_version_prefix_rejected() {
        let tx = make_v0_versioned();
        let mut bytes = serialize_versioned_transaction(&tx);
        // Find the version byte and change it to version 1 (unsupported)
        // The version byte is right after signatures
        let sig_end = 1 + 64; // 1 byte compact-u16(1) + 64 sig bytes
        bytes[sig_end] = 0x81; // version 1

        let result = parse_versioned_transaction(&bytes);
        assert!(matches!(
            result,
            Err(TransactionParseError::InvalidVersionPrefix(0x81))
        ));
    }

    #[test]
    fn blockhash_accessor() {
        let tx = make_legacy_versioned();
        let bh = tx.blockhash();
        assert_eq!(*bh, Hash::sha256(b"blockhash"));
    }
}
