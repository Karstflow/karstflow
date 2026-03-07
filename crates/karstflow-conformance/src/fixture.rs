//! Fixture types for conformance test vectors.
//!
//! Fixtures define the pre-state, action, and expected post-state
//! for deterministic execution tests.

use karstflow_types::{Account, AccountData, AccountMeta, Pubkey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A single account in fixture format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureAccount {
    pub lamports: u64,
    pub owner: [u8; 32],
    pub executable: bool,
    pub rent_epoch: u64,
    #[serde(with = "base64_bytes")]
    pub data: Vec<u8>,
}

impl FixtureAccount {
    pub fn to_account(&self) -> Account {
        Account {
            meta: AccountMeta {
                lamports: self.lamports,
                owner: Pubkey::new(self.owner),
                executable: self.executable,
                rent_epoch: self.rent_epoch,
            },
            data: AccountData::new(self.data.clone()),
        }
    }

    pub fn from_account(account: &Account) -> Self {
        Self {
            lamports: account.meta.lamports,
            owner: *account.meta.owner.as_bytes(),
            executable: account.meta.executable,
            rent_epoch: account.meta.rent_epoch,
            data: account.data.as_ref().to_vec(),
        }
    }
}

/// Instruction-level test fixture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionFixture {
    pub name: String,
    pub program_id: [u8; 32],
    #[serde(with = "base64_bytes")]
    pub instruction_data: Vec<u8>,
    pub accounts: Vec<InstructionAccountFixture>,
    pub expected: InstructionExpectation,
}

/// An account referenced by an instruction fixture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionAccountFixture {
    pub pubkey: [u8; 32],
    pub account: FixtureAccount,
    pub is_writable: bool,
    pub is_signer: bool,
}

/// Expected instruction outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionExpectation {
    pub success: bool,
    pub modified_accounts: HashMap<String, FixtureAccount>,
    #[serde(default)]
    pub min_compute_units: u64,
    #[serde(default)]
    pub error_contains: Option<String>,
}

/// Transaction-level test fixture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionFixture {
    pub name: String,
    pub pre_accounts: HashMap<String, FixtureAccount>,
    #[serde(with = "base64_bytes")]
    pub transaction_bytes: Vec<u8>,
    pub expected: TransactionExpectation,
}

/// Expected transaction outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionExpectation {
    pub success: bool,
    pub post_accounts: HashMap<String, FixtureAccount>,
    #[serde(default)]
    pub fee: Option<u64>,
    #[serde(default)]
    pub error_contains: Option<String>,
}

/// Block-level test fixture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockFixture {
    pub name: String,
    pub slot: u64,
    pub parent_slot: u64,
    pub pre_accounts: HashMap<String, FixtureAccount>,
    pub transactions: Vec<BlockTransactionFixture>,
    pub expected_bank_hash: Option<[u8; 32]>,
}

/// A transaction within a block fixture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockTransactionFixture {
    #[serde(with = "base64_bytes")]
    pub bytes: Vec<u8>,
    pub expected_success: bool,
}

mod base64_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::Serialize;
        let encoded = base64_encode(bytes);
        encoded.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        base64_decode(&s).map_err(serde::de::Error::custom)
    }

    fn base64_encode(bytes: &[u8]) -> String {
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut result = String::with_capacity(bytes.len().div_ceil(3) * 4);
        for chunk in bytes.chunks(3) {
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

    fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
        let s = s.trim_end_matches('=');
        let mut result = Vec::with_capacity(s.len() * 3 / 4);
        let mut buf = 0u32;
        let mut bits = 0;
        for c in s.chars() {
            let val = match c {
                'A'..='Z' => c as u32 - 'A' as u32,
                'a'..='z' => c as u32 - 'a' as u32 + 26,
                '0'..='9' => c as u32 - '0' as u32 + 52,
                '+' => 62,
                '/' => 63,
                _ => return Err(format!("invalid base64 char: {c}")),
            };
            buf = (buf << 6) | val;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                result.push((buf >> bits) as u8);
                buf &= (1 << bits) - 1;
            }
        }
        Ok(result)
    }
}
