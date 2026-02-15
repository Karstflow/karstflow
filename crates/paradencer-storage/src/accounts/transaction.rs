use super::primitives::Pubkey;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Signature([u8; 64]);

impl Signature {
    pub const fn new(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    pub fn zeroed() -> Self {
        Self([0u8; 64])
    }
}

impl Default for Signature {
    fn default() -> Self {
        Self::zeroed()
    }
}

impl From<[u8; 64]> for Signature {
    fn from(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountAccessMode {
    ReadOnly,
    Writable,
}

#[derive(Debug, Clone)]
pub struct AccountRef {
    pub pubkey: Pubkey,
    pub mode: AccountAccessMode,
}

impl AccountRef {
    pub const fn new(pubkey: Pubkey, mode: AccountAccessMode) -> Self {
        Self { pubkey, mode }
    }

    pub const fn read_only(pubkey: Pubkey) -> Self {
        Self {
            pubkey,
            mode: AccountAccessMode::ReadOnly,
        }
    }

    pub const fn writable(pubkey: Pubkey) -> Self {
        Self {
            pubkey,
            mode: AccountAccessMode::Writable,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Instruction {
    pub program_id: Pubkey,
    pub accounts: Vec<AccountRef>,
    pub data: Vec<u8>,
}

impl Instruction {
    pub fn new(program_id: Pubkey, accounts: Vec<AccountRef>, data: Vec<u8>) -> Self {
        Self {
            program_id,
            accounts,
            data,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Transaction {
    pub signatures: Vec<Signature>,
    pub instructions: Vec<Instruction>,
    pub recent_blockhash: [u8; 32],
}

impl Transaction {
    pub fn new(
        signatures: Vec<Signature>,
        instructions: Vec<Instruction>,
        recent_blockhash: [u8; 32],
    ) -> Self {
        Self {
            signatures,
            instructions,
            recent_blockhash,
        }
    }

    pub fn fee_payer(&self) -> Option<&Signature> {
        self.signatures.first()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionStatus {
    Success,
    Failed,
}

#[derive(Debug, Clone)]
pub struct TransactionResult {
    pub signature: Signature,
    pub status: TransactionStatus,
    pub compute_units_consumed: u64,
    pub error_message: Option<String>,
}

impl TransactionResult {
    pub fn success(signature: Signature, compute_units_consumed: u64) -> Self {
        Self {
            signature,
            status: TransactionStatus::Success,
            compute_units_consumed,
            error_message: None,
        }
    }

    pub fn failed(signature: Signature, compute_units_consumed: u64, error: String) -> Self {
        Self {
            signature,
            status: TransactionStatus::Failed,
            compute_units_consumed,
            error_message: Some(error),
        }
    }
}
