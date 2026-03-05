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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pubkey(n: u8) -> Pubkey {
        Pubkey::new([n; 32])
    }

    fn test_sig(n: u8) -> Signature {
        Signature::new([n; 64])
    }

    // --- Signature ---

    #[test]
    fn signature_zeroed() {
        let sig = Signature::zeroed();
        assert_eq!(sig.as_bytes(), &[0u8; 64]);
    }

    #[test]
    fn signature_from_bytes() {
        let bytes = [42u8; 64];
        let sig: Signature = bytes.into();
        assert_eq!(sig.as_bytes(), &bytes);
    }

    #[test]
    fn signature_default_is_zeroed() {
        assert_eq!(Signature::default(), Signature::zeroed());
    }

    // --- AccountAccessMode ---

    #[test]
    fn account_access_modes() {
        assert_ne!(AccountAccessMode::ReadOnly, AccountAccessMode::Writable);
    }

    // --- AccountRef ---

    #[test]
    fn account_ref_read_only() {
        let pk = test_pubkey(1);
        let ar = AccountRef::read_only(pk);
        assert_eq!(ar.pubkey, pk);
        assert_eq!(ar.mode, AccountAccessMode::ReadOnly);
    }

    #[test]
    fn account_ref_writable() {
        let pk = test_pubkey(2);
        let ar = AccountRef::writable(pk);
        assert_eq!(ar.pubkey, pk);
        assert_eq!(ar.mode, AccountAccessMode::Writable);
    }

    // --- Instruction ---

    #[test]
    fn instruction_new() {
        let pid = test_pubkey(5);
        let accounts = vec![
            AccountRef::writable(test_pubkey(1)),
            AccountRef::read_only(test_pubkey(2)),
        ];
        let ix = Instruction::new(pid, accounts, vec![0xAA, 0xBB]);
        assert_eq!(ix.program_id, pid);
        assert_eq!(ix.accounts.len(), 2);
        assert_eq!(ix.data, vec![0xAA, 0xBB]);
    }

    // --- Transaction ---

    #[test]
    fn transaction_fee_payer() {
        let sig = test_sig(1);
        let tx = Transaction::new(vec![sig.clone()], vec![], [0u8; 32]);
        assert_eq!(tx.fee_payer(), Some(&sig));
    }

    #[test]
    fn transaction_no_fee_payer() {
        let tx = Transaction::new(vec![], vec![], [0u8; 32]);
        assert!(tx.fee_payer().is_none());
    }

    // --- TransactionResult ---

    #[test]
    fn transaction_result_success() {
        let sig = test_sig(1);
        let result = TransactionResult::success(sig, 5000);
        assert_eq!(result.status, TransactionStatus::Success);
        assert_eq!(result.compute_units_consumed, 5000);
        assert!(result.error_message.is_none());
    }

    #[test]
    fn transaction_result_failed() {
        let sig = test_sig(1);
        let result = TransactionResult::failed(sig, 3000, "out of CU".to_string());
        assert_eq!(result.status, TransactionStatus::Failed);
        assert_eq!(result.compute_units_consumed, 3000);
        assert_eq!(result.error_message.as_deref(), Some("out of CU"));
    }
}
