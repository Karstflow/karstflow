/// Durable transaction nonce for offline signing.
///
/// Nonce accounts allow transactions to remain valid indefinitely by replacing
/// the recent blockhash with a durable nonce value. This enables:
/// - Offline transaction signing (no recent blockhash expiry)
/// - Pre-signed transactions for future execution
/// - Multi-step workflows with long delays
use crate::FeeCalculator;
use paradencer_constants::ledger::NONCE_ACCOUNT_SIZE;
use paradencer_storage::Pubkey;

/// Nonce account state discriminant values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NonceState {
    /// Nonce account is not initialized
    Uninitialized = 0,
    /// Nonce account is initialized and ready for use
    Initialized = 1,
}

/// Data for an initialized nonce account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonceData {
    /// Authority that can advance the nonce and withdraw funds
    pub authority: Pubkey,
    /// Current durable nonce value (used in place of recent blockhash)
    pub durable_nonce: Pubkey, // Using Pubkey as 32-byte hash
    /// Fee calculator captured when nonce was last advanced
    pub fee_calculator: FeeCalculator,
}

impl NonceData {
    /// Create new nonce data.
    pub fn new(authority: Pubkey, durable_nonce: Pubkey, fee_calculator: FeeCalculator) -> Self {
        Self {
            authority,
            durable_nonce,
            fee_calculator,
        }
    }
}

/// Nonce account state.
///
/// Can be either uninitialized or initialized with nonce data.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Nonce {
    /// Account is not initialized
    #[default]
    Uninitialized,
    /// Account is initialized with nonce data
    Initialized(NonceData),
}

impl Nonce {
    /// Create an uninitialized nonce account.
    pub fn uninitialized() -> Self {
        Self::Uninitialized
    }

    /// Create an initialized nonce account.
    pub fn initialized(data: NonceData) -> Self {
        Self::Initialized(data)
    }

    /// Get the state discriminant.
    pub fn state(&self) -> NonceState {
        match self {
            Self::Uninitialized => NonceState::Uninitialized,
            Self::Initialized(_) => NonceState::Initialized,
        }
    }

    /// Check if nonce is initialized.
    pub fn is_initialized(&self) -> bool {
        matches!(self, Self::Initialized(_))
    }

    /// Get nonce data if initialized.
    pub fn data(&self) -> Option<&NonceData> {
        match self {
            Self::Initialized(data) => Some(data),
            Self::Uninitialized => None,
        }
    }

    /// Get mutable nonce data if initialized.
    pub fn data_mut(&mut self) -> Option<&mut NonceData> {
        match self {
            Self::Initialized(data) => Some(data),
            Self::Uninitialized => None,
        }
    }

    /// Get the durable nonce value if initialized.
    pub fn durable_nonce(&self) -> Option<&Pubkey> {
        self.data().map(|d| &d.durable_nonce)
    }

    /// Get the authority if initialized.
    pub fn authority(&self) -> Option<&Pubkey> {
        self.data().map(|d| &d.authority)
    }

    /// Get the fee calculator if initialized.
    pub fn fee_calculator(&self) -> Option<&FeeCalculator> {
        self.data().map(|d| &d.fee_calculator)
    }
}

/// Derive a durable nonce from a blockhash: SHA256("DURABLE_NONCE" || blockhash).
///
/// This is the deterministic derivation used both for initialization and
/// advancement. The next durable nonce is always computed from the most
/// recent blockhash in the blockhash queue.
pub fn derive_durable_nonce(blockhash: &[u8; 32]) -> [u8; 32] {
    use paradencer_constants::ledger::DURABLE_NONCE_PREFIX;
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(DURABLE_NONCE_PREFIX);
    hasher.update(blockhash);
    hasher.finalize().into()
}

/// Deserialize nonce state from raw account data.
///
/// Layout: u32 version (LE) | u32 state (LE) | 32 bytes authority |
/// 32 bytes durable_nonce | u64 lamports_per_signature (LE)
/// Total: 80 bytes (NONCE_ACCOUNT_SIZE)
pub fn deserialize_nonce_state(data: &[u8]) -> Option<Nonce> {
    if data.len() != NONCE_ACCOUNT_SIZE {
        return None;
    }

    let _version = u32::from_le_bytes(data[0..4].try_into().ok()?);
    let state = u32::from_le_bytes(data[4..8].try_into().ok()?);

    if state == paradencer_constants::ledger::NONCE_STATE_UNINITIALIZED {
        return Some(Nonce::Uninitialized);
    }

    if state != paradencer_constants::ledger::NONCE_STATE_INITIALIZED {
        return None;
    }

    let mut authority_bytes = [0u8; 32];
    authority_bytes.copy_from_slice(&data[8..40]);
    let authority = Pubkey::new(authority_bytes);

    let mut nonce_bytes = [0u8; 32];
    nonce_bytes.copy_from_slice(&data[40..72]);
    let durable_nonce = Pubkey::new(nonce_bytes);

    let lamports_per_sig = u64::from_le_bytes(data[72..80].try_into().ok()?);

    Some(Nonce::Initialized(NonceData {
        authority,
        durable_nonce,
        fee_calculator: FeeCalculator::new(lamports_per_sig),
    }))
}

/// Serialize nonce state into raw account data.
///
/// Always writes current version (1).
pub fn serialize_nonce_state(nonce: &Nonce) -> Vec<u8> {
    use paradencer_constants::ledger::{
        NONCE_STATE_INITIALIZED, NONCE_STATE_UNINITIALIZED, NONCE_VERSION_CURRENT,
    };

    let mut data = vec![0u8; NONCE_ACCOUNT_SIZE];

    match nonce {
        Nonce::Uninitialized => {
            data[0..4].copy_from_slice(&NONCE_VERSION_CURRENT.to_le_bytes());
            data[4..8].copy_from_slice(&NONCE_STATE_UNINITIALIZED.to_le_bytes());
        }
        Nonce::Initialized(nonce_data) => {
            data[0..4].copy_from_slice(&NONCE_VERSION_CURRENT.to_le_bytes());
            data[4..8].copy_from_slice(&NONCE_STATE_INITIALIZED.to_le_bytes());
            data[8..40].copy_from_slice(nonce_data.authority.as_bytes());
            data[40..72].copy_from_slice(nonce_data.durable_nonce.as_bytes());
            data[72..80].copy_from_slice(
                &nonce_data
                    .fee_calculator
                    .lamports_per_signature
                    .to_le_bytes(),
            );
        }
    }

    data
}

/// Operations on nonce accounts.
pub struct NonceAccount;

impl NonceAccount {
    /// Get the size of a nonce account in bytes.
    pub const fn size() -> usize {
        NONCE_ACCOUNT_SIZE
    }

    /// Initialize a nonce account.
    pub fn initialize(
        authority: Pubkey,
        durable_nonce: Pubkey,
        fee_calculator: FeeCalculator,
    ) -> Result<Nonce, NonceError> {
        let data = NonceData::new(authority, durable_nonce, fee_calculator);
        Ok(Nonce::initialized(data))
    }

    /// Advance the nonce to a new value.
    ///
    /// This must be done before using the same nonce again, to prevent replay attacks.
    pub fn advance(
        nonce: &mut Nonce,
        new_durable_nonce: Pubkey,
        new_fee_calculator: FeeCalculator,
    ) -> Result<(), NonceError> {
        let data = nonce.data_mut().ok_or(NonceError::NotInitialized)?;

        // Prevent advancing to same nonce (no-op would be dangerous)
        if data.durable_nonce == new_durable_nonce {
            return Err(NonceError::DuplicateNonce);
        }

        data.durable_nonce = new_durable_nonce;
        data.fee_calculator = new_fee_calculator;

        Ok(())
    }

    /// Change the authority of a nonce account.
    pub fn authorize(nonce: &mut Nonce, new_authority: Pubkey) -> Result<(), NonceError> {
        let data = nonce.data_mut().ok_or(NonceError::NotInitialized)?;

        data.authority = new_authority;
        Ok(())
    }

    /// Verify that a nonce value matches the current durable nonce.
    pub fn verify_nonce(nonce: &Nonce, expected_nonce: &Pubkey) -> Result<(), NonceError> {
        let current_nonce = nonce.durable_nonce().ok_or(NonceError::NotInitialized)?;

        if current_nonce != expected_nonce {
            return Err(NonceError::InvalidNonce);
        }

        Ok(())
    }

    /// Check if authority is valid for this nonce account.
    pub fn verify_authority(nonce: &Nonce, signer: &Pubkey) -> Result<(), NonceError> {
        let authority = nonce.authority().ok_or(NonceError::NotInitialized)?;

        if authority != signer {
            return Err(NonceError::InvalidAuthority);
        }

        Ok(())
    }
}

/// Errors that can occur with nonce operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceError {
    /// Nonce account is not initialized
    NotInitialized,
    /// Nonce account is already initialized
    AlreadyInitialized,
    /// Invalid nonce value (doesn't match expected)
    InvalidNonce,
    /// Invalid authority (signer doesn't match)
    InvalidAuthority,
    /// Attempted to advance nonce to same value
    DuplicateNonce,
    /// Insufficient lamports for rent exemption
    InsufficientFunds,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_creates_uninitialized() {
        let nonce = Nonce::uninitialized();

        assert_eq!(nonce.state(), NonceState::Uninitialized);
        assert!(!nonce.is_initialized());
        assert_eq!(nonce.data(), None);
    }

    #[test]
    fn nonce_creates_initialized() {
        let authority = Pubkey::new_unique();
        let durable_nonce = Pubkey::new_unique();
        let fee_calc = FeeCalculator::new(5000);

        let data = NonceData::new(authority, durable_nonce, fee_calc);
        let nonce = Nonce::initialized(data.clone());

        assert_eq!(nonce.state(), NonceState::Initialized);
        assert!(nonce.is_initialized());
        assert_eq!(nonce.data(), Some(&data));
    }

    #[test]
    fn nonce_account_initializes() {
        let authority = Pubkey::new_unique();
        let durable_nonce = Pubkey::new_unique();
        let fee_calc = FeeCalculator::new(5000);

        let nonce = NonceAccount::initialize(authority, durable_nonce, fee_calc).unwrap();

        assert!(nonce.is_initialized());
        assert_eq!(nonce.authority(), Some(&authority));
        assert_eq!(nonce.durable_nonce(), Some(&durable_nonce));
        assert_eq!(nonce.fee_calculator(), Some(&fee_calc));
    }

    #[test]
    fn nonce_account_advances() {
        let authority = Pubkey::new_unique();
        let old_nonce = Pubkey::new_unique();
        let new_nonce = Pubkey::new_unique();
        let old_fee = FeeCalculator::new(5000);
        let new_fee = FeeCalculator::new(6000);

        let mut nonce = NonceAccount::initialize(authority, old_nonce, old_fee).unwrap();

        NonceAccount::advance(&mut nonce, new_nonce, new_fee).unwrap();

        assert_eq!(nonce.durable_nonce(), Some(&new_nonce));
        assert_eq!(nonce.fee_calculator(), Some(&new_fee));
    }

    #[test]
    fn nonce_account_rejects_duplicate_advance() {
        let authority = Pubkey::new_unique();
        let durable_nonce = Pubkey::new_unique();
        let fee_calc = FeeCalculator::new(5000);

        let mut nonce = NonceAccount::initialize(authority, durable_nonce, fee_calc).unwrap();

        // Try to advance to same nonce
        let result = NonceAccount::advance(&mut nonce, durable_nonce, fee_calc);
        assert_eq!(result, Err(NonceError::DuplicateNonce));
    }

    #[test]
    fn nonce_account_rejects_advance_uninitialized() {
        let mut nonce = Nonce::uninitialized();
        let new_nonce = Pubkey::new_unique();
        let fee_calc = FeeCalculator::new(5000);

        let result = NonceAccount::advance(&mut nonce, new_nonce, fee_calc);
        assert_eq!(result, Err(NonceError::NotInitialized));
    }

    #[test]
    fn nonce_account_changes_authority() {
        let old_authority = Pubkey::new_unique();
        let new_authority = Pubkey::new_unique();
        let durable_nonce = Pubkey::new_unique();
        let fee_calc = FeeCalculator::new(5000);

        let mut nonce = NonceAccount::initialize(old_authority, durable_nonce, fee_calc).unwrap();

        NonceAccount::authorize(&mut nonce, new_authority).unwrap();

        assert_eq!(nonce.authority(), Some(&new_authority));
    }

    #[test]
    fn nonce_account_verifies_nonce() {
        let authority = Pubkey::new_unique();
        let durable_nonce = Pubkey::new_unique();
        let fee_calc = FeeCalculator::new(5000);

        let nonce = NonceAccount::initialize(authority, durable_nonce, fee_calc).unwrap();

        // Correct nonce
        assert!(NonceAccount::verify_nonce(&nonce, &durable_nonce).is_ok());

        // Wrong nonce
        let wrong_nonce = Pubkey::new_unique();
        assert_eq!(
            NonceAccount::verify_nonce(&nonce, &wrong_nonce),
            Err(NonceError::InvalidNonce)
        );
    }

    #[test]
    fn nonce_account_verifies_authority() {
        let authority = Pubkey::new_unique();
        let durable_nonce = Pubkey::new_unique();
        let fee_calc = FeeCalculator::new(5000);

        let nonce = NonceAccount::initialize(authority, durable_nonce, fee_calc).unwrap();

        // Correct authority
        assert!(NonceAccount::verify_authority(&nonce, &authority).is_ok());

        // Wrong authority
        let wrong_authority = Pubkey::new_unique();
        assert_eq!(
            NonceAccount::verify_authority(&nonce, &wrong_authority),
            Err(NonceError::InvalidAuthority)
        );
    }

    #[test]
    fn nonce_account_verifies_uninitialized_fails() {
        let nonce = Nonce::uninitialized();
        let some_nonce = Pubkey::new_unique();

        assert_eq!(
            NonceAccount::verify_nonce(&nonce, &some_nonce),
            Err(NonceError::NotInitialized)
        );
    }

    #[test]
    fn nonce_account_has_correct_size() {
        assert_eq!(NonceAccount::size(), NONCE_ACCOUNT_SIZE);
    }
}
