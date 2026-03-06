/// Parallel Merkle tree construction for snapshot verification.
///
/// Computes account hashes and the bank hash in parallel using rayon.
/// Account data is split into chunks, each chunk is hashed in parallel,
/// and the per-chunk hashes are combined into a Merkle tree.
///
/// This matches the reference implementation's parallel hash computation
/// during snapshot restore and creation.
use karstflow_crypto::sha256::{Sha256Hasher, Sha256StreamingHasher};
use rayon::prelude::*;

/// A leaf in the account Merkle tree.
#[derive(Debug, Clone, Copy)]
pub struct AccountHash {
    pub hash: [u8; 32],
}

/// Compute the Merkle root of a list of account hashes in parallel.
///
/// Returns the 32-byte root hash. If the list is empty, returns
/// a zero hash. If the list has one element, returns that element's hash.
pub fn parallel_merkle_root(hashes: &[AccountHash]) -> [u8; 32] {
    if hashes.is_empty() {
        return [0u8; 32];
    }
    if hashes.len() == 1 {
        return hashes[0].hash;
    }

    // Build the tree bottom-up, combining pairs in parallel.
    let mut level: Vec<[u8; 32]> = hashes.iter().map(|h| h.hash).collect();

    while level.len() > 1 {
        // If odd number of nodes, the last one is promoted as-is.
        let pairs = level.len() / 2;
        let has_odd = level.len() % 2 == 1;

        let mut next_level: Vec<[u8; 32]> = (0..pairs)
            .into_par_iter()
            .map(|i| {
                let left = &level[i * 2];
                let right = &level[i * 2 + 1];
                let mut combined = [0u8; 64];
                combined[..32].copy_from_slice(left);
                combined[32..].copy_from_slice(right);
                Sha256Hasher::hash(&combined)
            })
            .collect();

        if has_odd {
            next_level.push(*level.last().unwrap());
        }

        level = next_level;
    }

    level[0]
}

/// Hash a single account for Merkle tree inclusion.
///
/// The account hash includes: lamports, owner, executable flag,
/// rent_epoch, data hash, and the pubkey. This matches the reference
/// implementation's account hash computation.
pub fn hash_account(
    lamports: u64,
    owner: &[u8; 32],
    executable: bool,
    rent_epoch: u64,
    data: &[u8],
    pubkey: &[u8; 32],
) -> AccountHash {
    let mut hasher = Sha256StreamingHasher::new();
    hasher.update(&lamports.to_le_bytes());
    hasher.update(&(rent_epoch.to_le_bytes()));
    hasher.update(data);
    let executable_byte = if executable { 1u8 } else { 0u8 };
    hasher.update(&[executable_byte]);
    hasher.update(owner);
    hasher.update(pubkey);
    AccountHash {
        hash: hasher.finalize(),
    }
}

/// Compute account hashes in parallel for a batch of accounts.
///
/// Each element is (lamports, owner, executable, rent_epoch, data, pubkey).
pub fn parallel_hash_accounts(
    accounts: &[(u64, [u8; 32], bool, u64, Vec<u8>, [u8; 32])],
) -> Vec<AccountHash> {
    accounts
        .par_iter()
        .map(|(lamports, owner, executable, rent_epoch, data, pubkey)| {
            hash_account(*lamports, owner, *executable, *rent_epoch, data, pubkey)
        })
        .collect()
}

/// Compute the bank hash: Merkle root of all account hashes.
pub fn compute_bank_hash(
    accounts: &[(u64, [u8; 32], bool, u64, Vec<u8>, [u8; 32])],
) -> [u8; 32] {
    let hashes = parallel_hash_accounts(accounts);
    parallel_merkle_root(&hashes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_merkle_root_is_zero() {
        assert_eq!(parallel_merkle_root(&[]), [0u8; 32]);
    }

    #[test]
    fn single_element_merkle_root() {
        let hash = Sha256Hasher::hash(b"test account");
        let hashes = vec![AccountHash { hash }];
        assert_eq!(parallel_merkle_root(&hashes), hash);
    }

    #[test]
    fn two_element_merkle_root() {
        let h1 = Sha256Hasher::hash(b"account 1");
        let h2 = Sha256Hasher::hash(b"account 2");
        let hashes = vec![AccountHash { hash: h1 }, AccountHash { hash: h2 }];

        let root = parallel_merkle_root(&hashes);

        // Manual: SHA256(h1 || h2)
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&h1);
        combined[32..].copy_from_slice(&h2);
        let expected = Sha256Hasher::hash(&combined);

        assert_eq!(root, expected);
    }

    #[test]
    fn four_element_merkle_root() {
        let hashes: Vec<AccountHash> = (0..4)
            .map(|i| AccountHash {
                hash: Sha256Hasher::hash(&[i as u8]),
            })
            .collect();

        let root = parallel_merkle_root(&hashes);
        assert_ne!(root, [0u8; 32]);
    }

    #[test]
    fn odd_element_merkle_tree() {
        let hashes: Vec<AccountHash> = (0..3)
            .map(|i| AccountHash {
                hash: Sha256Hasher::hash(&[i as u8]),
            })
            .collect();

        let root = parallel_merkle_root(&hashes);
        assert_ne!(root, [0u8; 32]);
    }

    #[test]
    fn hash_account_deterministic() {
        let owner = [1u8; 32];
        let pubkey = [2u8; 32];
        let data = b"account data".to_vec();

        let h1 = hash_account(1000, &owner, false, 0, &data, &pubkey);
        let h2 = hash_account(1000, &owner, false, 0, &data, &pubkey);
        assert_eq!(h1.hash, h2.hash);
    }

    #[test]
    fn hash_account_changes_with_lamports() {
        let owner = [1u8; 32];
        let pubkey = [2u8; 32];

        let h1 = hash_account(1000, &owner, false, 0, b"data", &pubkey);
        let h2 = hash_account(2000, &owner, false, 0, b"data", &pubkey);
        assert_ne!(h1.hash, h2.hash);
    }

    #[test]
    fn parallel_hash_batch() {
        let accounts = vec![
            (1000u64, [1u8; 32], false, 0u64, b"data1".to_vec(), [10u8; 32]),
            (2000u64, [1u8; 32], false, 0u64, b"data2".to_vec(), [11u8; 32]),
        ];

        let hashes = parallel_hash_accounts(&accounts);
        assert_eq!(hashes.len(), 2);
        assert_ne!(hashes[0].hash, hashes[1].hash);
    }

    #[test]
    fn compute_bank_hash_works() {
        let accounts = vec![
            (1000u64, [1u8; 32], false, 0u64, b"data1".to_vec(), [10u8; 32]),
            (2000u64, [1u8; 32], true, 0u64, b"data2".to_vec(), [11u8; 32]),
        ];

        let bank_hash = compute_bank_hash(&accounts);
        assert_ne!(bank_hash, [0u8; 32]);

        // Deterministic
        let bank_hash2 = compute_bank_hash(&accounts);
        assert_eq!(bank_hash, bank_hash2);
    }
}
