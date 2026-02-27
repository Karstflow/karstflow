/// Centralized signing service for the validator.
///
/// Manages the validator identity keypair and up to 16 authorized voter
/// keypairs. All cryptographic signing operations (shreds, votes, gossip,
/// repair) are routed through this service.
///
/// Supports multiple signing modes:
/// - **Ed25519**: Direct payload signing (shreds, gossip, repair)
/// - **Sha256Ed25519**: Sign SHA-256 hash of payload (vote messages)
/// - **PubkeyConcat**: Sign base58(pubkey) + "-" + payload (bundle auth)
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// Signing mode determining how the payload is transformed before signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignType {
    /// Sign the raw payload directly with Ed25519.
    Ed25519,
    /// Sign SHA-256(payload) with Ed25519. Used for vote transactions
    /// where the message hash is signed rather than the raw message.
    Sha256Ed25519,
    /// Sign base58(pubkey) + "-" + payload. Used for bundle authentication.
    PubkeyConcat,
}

/// Result of a signing operation.
#[derive(Debug, Clone)]
pub struct SignResult {
    /// Primary Ed25519 signature (64 bytes).
    pub signature: [u8; 64],
    /// Optional secondary signature from an authorized voter key.
    /// Present only for dual-signed vote transactions.
    pub voter_signature: Option<[u8; 64]>,
}

/// Signing service statistics.
#[derive(Debug, Clone, Default)]
pub struct SignServiceStats {
    /// Total signing operations performed.
    pub total_signs: u64,
    /// Shred signing operations.
    pub shred_signs: u64,
    /// Vote signing operations.
    pub vote_signs: u64,
    /// Gossip signing operations.
    pub gossip_signs: u64,
    /// Repair signing operations.
    pub repair_signs: u64,
    /// Failed signing operations (e.g., invalid voter index).
    pub sign_errors: u64,
}

/// Centralized signing service holding validator keys.
///
/// In production, this service is the sole holder of private keys.
/// All other components request signatures through this service
/// rather than holding keys directly.
pub struct SignService {
    /// Validator identity keypair.
    identity: SigningKey,
    /// Cached identity public key (32 bytes).
    identity_pubkey: [u8; 32],
    /// Cached base58-encoded identity public key for PubkeyConcat signing.
    identity_pubkey_base58: String,
    /// Authorized voter keypairs (up to MAX_AUTHORIZED_VOTERS).
    authorized_voters: Vec<SigningKey>,
    /// Statistics.
    stats: SignServiceStats,
}

impl SignService {
    /// Create a new signing service with the given identity keypair.
    pub fn new(identity: SigningKey) -> Self {
        let pubkey = identity.verifying_key().to_bytes();
        let pubkey_base58 = bs58::encode(&pubkey).into_string();
        Self {
            identity,
            identity_pubkey: pubkey,
            identity_pubkey_base58: pubkey_base58,
            authorized_voters: Vec::new(),
            stats: SignServiceStats::default(),
        }
    }

    /// Create a signing service from raw identity key bytes (32 bytes).
    pub fn from_identity_bytes(bytes: &[u8; 32]) -> Self {
        Self::new(SigningKey::from_bytes(bytes))
    }

    /// Add an authorized voter keypair.
    ///
    /// Returns the index of the added voter, or `None` if the maximum
    /// number of authorized voters has been reached.
    pub fn add_authorized_voter(&mut self, voter_key: SigningKey) -> Option<usize> {
        if self.authorized_voters.len() >= paradencer_constants::signing::MAX_AUTHORIZED_VOTERS {
            return None;
        }
        let index = self.authorized_voters.len();
        self.authorized_voters.push(voter_key);
        Some(index)
    }

    /// Get the validator identity public key (32 bytes).
    pub fn identity_pubkey(&self) -> &[u8; 32] {
        &self.identity_pubkey
    }

    /// Get the identity keypair reference.
    pub fn identity_keypair(&self) -> &SigningKey {
        &self.identity
    }

    /// Get an authorized voter's public key.
    pub fn authorized_voter_pubkey(&self, index: usize) -> Option<[u8; 32]> {
        self.authorized_voters
            .get(index)
            .map(|k| k.verifying_key().to_bytes())
    }

    /// Number of authorized voters registered.
    pub fn authorized_voter_count(&self) -> usize {
        self.authorized_voters.len()
    }

    /// Sign a payload using the specified signing mode.
    pub fn sign(&mut self, payload: &[u8], sign_type: SignType) -> [u8; 64] {
        self.stats.total_signs += 1;
        match sign_type {
            SignType::Ed25519 => {
                let sig = self.identity.sign(payload);
                sig.to_bytes()
            }
            SignType::Sha256Ed25519 => {
                let hash = Sha256::digest(payload);
                let sig = self.identity.sign(&hash);
                sig.to_bytes()
            }
            SignType::PubkeyConcat => {
                // Concatenate: base58(pubkey) + "-" + payload
                let mut message =
                    Vec::with_capacity(self.identity_pubkey_base58.len() + 1 + payload.len());
                message.extend_from_slice(self.identity_pubkey_base58.as_bytes());
                message.push(b'-');
                message.extend_from_slice(payload);
                let sig = self.identity.sign(&message);
                sig.to_bytes()
            }
        }
    }

    /// Sign a shred's merkle root (32 bytes).
    ///
    /// Uses direct Ed25519 signing of the merkle root bytes.
    pub fn sign_shred(&mut self, merkle_root: &[u8; 32]) -> [u8; 64] {
        self.stats.shred_signs += 1;
        self.sign(merkle_root, SignType::Ed25519)
    }

    /// Sign a vote transaction message.
    ///
    /// Uses SHA-256 pre-hash before Ed25519 signing (matching Solana's
    /// vote signing convention). Optionally returns a secondary signature
    /// from an authorized voter key for dual-signed vote transactions.
    pub fn sign_vote(
        &mut self,
        message: &[u8],
        voter_index: Option<usize>,
    ) -> Result<SignResult, SignError> {
        self.stats.vote_signs += 1;

        // Primary signature with identity key (SHA-256 + Ed25519).
        let identity_sig = self.sign(message, SignType::Sha256Ed25519);

        // Optional secondary signature with authorized voter key.
        let voter_sig = if let Some(idx) = voter_index {
            let voter_key = self.authorized_voters.get(idx).ok_or_else(|| {
                self.stats.sign_errors += 1;
                SignError::InvalidVoterIndex(idx)
            })?;
            let hash = Sha256::digest(message);
            let sig = voter_key.sign(&hash);
            Some(sig.to_bytes())
        } else {
            None
        };

        Ok(SignResult {
            signature: identity_sig,
            voter_signature: voter_sig,
        })
    }

    /// Sign a gossip protocol message.
    ///
    /// Uses direct Ed25519 signing of the raw message bytes.
    pub fn sign_gossip(&mut self, message: &[u8]) -> [u8; 64] {
        self.stats.gossip_signs += 1;
        self.sign(message, SignType::Ed25519)
    }

    /// Sign a repair protocol message.
    ///
    /// Uses direct Ed25519 signing of the raw message bytes.
    pub fn sign_repair(&mut self, message: &[u8]) -> [u8; 64] {
        self.stats.repair_signs += 1;
        self.sign(message, SignType::Ed25519)
    }

    /// Get current statistics.
    pub fn stats(&self) -> &SignServiceStats {
        &self.stats
    }

    /// Reset statistics counters.
    pub fn reset_stats(&mut self) {
        self.stats = SignServiceStats::default();
    }
}

/// Errors from signing operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignError {
    /// Requested voter index does not exist.
    InvalidVoterIndex(usize),
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidVoterIndex(idx) => {
                write!(f, "invalid authorized voter index: {idx}")
            }
        }
    }
}

impl std::error::Error for SignError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    fn make_service() -> SignService {
        let key = SigningKey::from_bytes(&[42u8; 32]);
        SignService::new(key)
    }

    #[test]
    fn identity_pubkey_matches_signing_key() {
        let service = make_service();
        let key = SigningKey::from_bytes(&[42u8; 32]);
        assert_eq!(*service.identity_pubkey(), key.verifying_key().to_bytes());
    }

    #[test]
    fn sign_ed25519_produces_valid_signature() {
        let mut service = make_service();
        let message = b"test message for signing";
        let sig = service.sign(message, SignType::Ed25519);

        // Verify the signature.
        let verifying_key = VerifyingKey::from_bytes(service.identity_pubkey()).unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig);
        assert!(verifying_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn sign_sha256_ed25519_signs_hash() {
        let mut service = make_service();
        let message = b"vote transaction message";
        let sig = service.sign(message, SignType::Sha256Ed25519);

        // Verify against SHA-256 hash of the message.
        let hash = Sha256::digest(message);
        let verifying_key = VerifyingKey::from_bytes(service.identity_pubkey()).unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig);
        assert!(verifying_key.verify(&hash, &signature).is_ok());
    }

    #[test]
    fn sign_pubkey_concat_includes_pubkey() {
        let mut service = make_service();
        let payload = b"challenge";
        let sig = service.sign(payload, SignType::PubkeyConcat);

        // Reconstruct the message that was signed.
        let pubkey_b58 = bs58::encode(service.identity_pubkey()).into_string();
        let mut expected_message = Vec::new();
        expected_message.extend_from_slice(pubkey_b58.as_bytes());
        expected_message.push(b'-');
        expected_message.extend_from_slice(payload);

        let verifying_key = VerifyingKey::from_bytes(service.identity_pubkey()).unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig);
        assert!(verifying_key.verify(&expected_message, &signature).is_ok());
    }

    #[test]
    fn sign_shred_merkle_root() {
        let mut service = make_service();
        let merkle_root = [0xAB; 32];
        let sig = service.sign_shred(&merkle_root);

        let verifying_key = VerifyingKey::from_bytes(service.identity_pubkey()).unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig);
        assert!(verifying_key.verify(&merkle_root, &signature).is_ok());
    }

    #[test]
    fn sign_gossip_message() {
        let mut service = make_service();
        let message = b"gossip crds value";
        let sig = service.sign_gossip(message);

        let verifying_key = VerifyingKey::from_bytes(service.identity_pubkey()).unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig);
        assert!(verifying_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn sign_repair_message() {
        let mut service = make_service();
        let message = b"repair request payload";
        let sig = service.sign_repair(message);

        let verifying_key = VerifyingKey::from_bytes(service.identity_pubkey()).unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig);
        assert!(verifying_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn sign_vote_identity_only() {
        let mut service = make_service();
        let message = b"vote message body";
        let result = service.sign_vote(message, None).unwrap();

        // Primary signature should verify against SHA-256 hash.
        let hash = Sha256::digest(message);
        let verifying_key = VerifyingKey::from_bytes(service.identity_pubkey()).unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&result.signature);
        assert!(verifying_key.verify(&hash, &signature).is_ok());

        // No voter signature.
        assert!(result.voter_signature.is_none());
    }

    #[test]
    fn sign_vote_with_authorized_voter() {
        let mut service = make_service();
        let voter_key = SigningKey::from_bytes(&[99u8; 32]);
        let voter_pubkey = voter_key.verifying_key().to_bytes();
        let idx = service.add_authorized_voter(voter_key).unwrap();

        let message = b"vote with authorized voter";
        let result = service.sign_vote(message, Some(idx)).unwrap();

        // Primary signature valid.
        let hash = Sha256::digest(message);
        let identity_vk = VerifyingKey::from_bytes(service.identity_pubkey()).unwrap();
        let sig1 = ed25519_dalek::Signature::from_bytes(&result.signature);
        assert!(identity_vk.verify(&hash, &sig1).is_ok());

        // Voter signature valid.
        let voter_sig = result.voter_signature.unwrap();
        let voter_vk = VerifyingKey::from_bytes(&voter_pubkey).unwrap();
        let sig2 = ed25519_dalek::Signature::from_bytes(&voter_sig);
        assert!(voter_vk.verify(&hash, &sig2).is_ok());
    }

    #[test]
    fn sign_vote_invalid_voter_index() {
        let mut service = make_service();
        let result = service.sign_vote(b"msg", Some(5));
        assert_eq!(result.unwrap_err(), SignError::InvalidVoterIndex(5));
    }

    #[test]
    fn add_authorized_voters_up_to_limit() {
        let mut service = make_service();
        for i in 0..paradencer_constants::signing::MAX_AUTHORIZED_VOTERS {
            let key = SigningKey::from_bytes(&[i as u8; 32]);
            assert_eq!(service.add_authorized_voter(key), Some(i));
        }

        // One more should fail.
        let key = SigningKey::from_bytes(&[0xFF; 32]);
        assert_eq!(service.add_authorized_voter(key), None);
        assert_eq!(
            service.authorized_voter_count(),
            paradencer_constants::signing::MAX_AUTHORIZED_VOTERS
        );
    }

    #[test]
    fn authorized_voter_pubkey_lookup() {
        let mut service = make_service();
        let voter_key = SigningKey::from_bytes(&[77u8; 32]);
        let expected_pubkey = voter_key.verifying_key().to_bytes();
        let idx = service.add_authorized_voter(voter_key).unwrap();

        assert_eq!(service.authorized_voter_pubkey(idx), Some(expected_pubkey));
        assert_eq!(service.authorized_voter_pubkey(99), None);
    }

    #[test]
    fn from_identity_bytes_constructs_correctly() {
        let bytes = [42u8; 32];
        let service = SignService::from_identity_bytes(&bytes);
        let key = SigningKey::from_bytes(&bytes);
        assert_eq!(*service.identity_pubkey(), key.verifying_key().to_bytes());
    }

    #[test]
    fn stats_track_sign_operations() {
        let mut service = make_service();

        service.sign_shred(&[0; 32]);
        service.sign_shred(&[1; 32]);
        service.sign_gossip(b"gossip");
        service.sign_repair(b"repair");
        let _ = service.sign_vote(b"vote", None);

        let stats = service.stats();
        assert_eq!(stats.total_signs, 5);
        assert_eq!(stats.shred_signs, 2);
        assert_eq!(stats.gossip_signs, 1);
        assert_eq!(stats.repair_signs, 1);
        assert_eq!(stats.vote_signs, 1);
    }

    #[test]
    fn different_payloads_produce_different_signatures() {
        let mut service = make_service();
        let sig1 = service.sign(b"payload_a", SignType::Ed25519);
        let sig2 = service.sign(b"payload_b", SignType::Ed25519);
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn reset_stats_clears_counters() {
        let mut service = make_service();
        service.sign_shred(&[0; 32]);
        assert_eq!(service.stats().shred_signs, 1);

        service.reset_stats();
        assert_eq!(service.stats().shred_signs, 0);
        assert_eq!(service.stats().total_signs, 0);
    }
}
