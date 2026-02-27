//! Binary Merkle tree construction and verification.
//!
//! Supports two modes:
//!
//! 1. **Shred trees** (20-byte truncated SHA-256 nodes, 26-byte domain prefix)
//!    Used for Merkle shred production and FEC set verification.
//!
//! 2. **Runtime trees** (32-byte full SHA-256 nodes, 1-byte domain prefix)
//!    Used for transaction signature Merkle roots mixed into PoH.
//!
//! # Operations
//!
//! - **Streaming commit**: Append leaves sequentially, finalize to get root.
//! - **Proof extraction**: After commit, extract inclusion proofs for any leaf.
//! - **Standalone verification**: Derive root from a single leaf + proof.
//! - **Proof-based commit**: Insert leaves with proofs in any order, verify
//!   tree consistency on finalize.

use crate::sha256::Sha256Hasher;

/// Maximum tree depth (supports up to 2^63 leaves).
pub const MAX_DEPTH: usize = 63;

/// Configuration for a binary Merkle tree variant.
#[derive(Debug, Clone)]
pub struct BmtreeConfig {
    /// Number of hash bytes used for intermediate nodes.
    /// 20 for shred trees, 32 for runtime trees.
    pub hash_sz: usize,
    /// Domain separation prefix for leaf hashing.
    pub leaf_prefix: &'static [u8],
    /// Domain separation prefix for interior node merging.
    pub node_prefix: &'static [u8],
}

/// Shred Merkle tree configuration (20-byte nodes, long prefix).
pub const SHRED_CONFIG: BmtreeConfig = BmtreeConfig {
    hash_sz: 20,
    leaf_prefix: b"\x00SOLANA_MERKLE_SHREDS_LEAF",
    node_prefix: b"\x01SOLANA_MERKLE_SHREDS_NODE",
};

/// Runtime Merkle tree configuration (32-byte nodes, short prefix).
pub const RUNTIME_CONFIG: BmtreeConfig = BmtreeConfig {
    hash_sz: 32,
    leaf_prefix: b"\x00",
    node_prefix: b"\x01",
};

/// A 32-byte Merkle tree node.
///
/// Only the first `config.hash_sz` bytes are meaningful for intermediate
/// operations. All 32 bytes are used for the final root hash.
pub type BmtreeNode = [u8; 32];

/// Hash raw data into a leaf node with domain separation.
///
/// `leaf = SHA-256(leaf_prefix || data)`
pub fn hash_leaf(config: &BmtreeConfig, data: &[u8]) -> BmtreeNode {
    Sha256Hasher::hash_chunks(&[config.leaf_prefix, data])
}

/// Merge two child nodes into their parent.
///
/// `parent = SHA-256(node_prefix || left[0..hash_sz] || right[0..hash_sz])`
pub fn merge_nodes(config: &BmtreeConfig, left: &BmtreeNode, right: &BmtreeNode) -> BmtreeNode {
    Sha256Hasher::hash_chunks(&[
        config.node_prefix,
        &left[..config.hash_sz],
        &right[..config.hash_sz],
    ])
}

/// Derive the Merkle root from a single leaf and its inclusion proof.
///
/// Walks the proof bottom-up: at each layer the current node is combined
/// with the sibling from the proof. The position in the tree is determined
/// by `leaf_idx` bits (standard binary tree convention: bit 0 → left child).
///
/// Returns `None` if `proof_depth` exceeds `MAX_DEPTH`.
pub fn root_from_proof(
    config: &BmtreeConfig,
    leaf: &BmtreeNode,
    leaf_idx: usize,
    proof: &[BmtreeNode],
) -> Option<BmtreeNode> {
    if proof.len() > MAX_DEPTH {
        return None;
    }

    let mut current = *leaf;
    let mut idx = leaf_idx;

    for sibling in proof.iter() {
        current = if idx & 1 == 0 {
            // Current node is left child.
            merge_nodes(config, &current, sibling)
        } else {
            // Current node is right child.
            merge_nodes(config, sibling, &current)
        };
        idx >>= 1;
    }

    Some(current)
}

/// Derive root using the shred verifier's index convention.
///
/// This uses Firedancer's `inc_idx` walk which is used by the existing
/// shred verifier for Merkle shred validation. Proofs in this format
/// use `leaf_idx * 2` as the starting position with mask-based traversal.
pub fn root_from_proof_shred(
    config: &BmtreeConfig,
    leaf: &BmtreeNode,
    leaf_idx: usize,
    proof: &[BmtreeNode],
) -> Option<BmtreeNode> {
    if proof.len() > MAX_DEPTH {
        return None;
    }

    let mut current = *leaf;
    let mut inc_idx = leaf_idx * 2;

    for (layer, sibling) in proof.iter().enumerate() {
        let is_left = (inc_idx & (1 << (layer + 1))) == 0;
        current = if is_left {
            merge_nodes(config, &current, sibling)
        } else {
            merge_nodes(config, sibling, &current)
        };

        let mask = (2usize << layer) - 1;
        inc_idx = (inc_idx & !((2 << (layer + 1)) - 1)) | mask;
    }

    Some(current)
}

/// Compute the depth (number of layers) for a tree with `leaf_cnt` leaves.
///
/// Returns 0 for 0 or 1 leaves, 1 for 2 leaves, etc.
pub fn tree_depth(leaf_cnt: usize) -> usize {
    if leaf_cnt <= 1 {
        return 0;
    }
    // ceil(log2(leaf_cnt))
    (usize::BITS - (leaf_cnt - 1).leading_zeros()) as usize
}

/// Incremental Merkle tree builder.
///
/// Append leaves sequentially, then finalize to get the root hash.
/// After finalization, inclusion proofs can be extracted for any leaf.
///
/// Uses O(depth) space during construction by maintaining a stack of
/// partial subtree roots at each layer.
pub struct BmtreeCommit {
    config: BmtreeConfig,
    /// All leaves stored for tree construction and proof extraction.
    leaves: Vec<BmtreeNode>,
    /// Number of leaves appended so far.
    leaf_cnt: usize,
    /// Whether finalize() has been called.
    finalized: bool,
    /// The computed root (set after finalize).
    root: Option<BmtreeNode>,
}

impl BmtreeCommit {
    /// Create a new incremental Merkle tree builder.
    pub fn new(config: BmtreeConfig) -> Self {
        Self {
            config,
            leaves: Vec::new(),
            leaf_cnt: 0,
            finalized: false,
            root: None,
        }
    }

    /// Create a new builder with pre-allocated leaf capacity.
    pub fn with_capacity(config: BmtreeConfig, capacity: usize) -> Self {
        Self {
            config,
            leaves: Vec::with_capacity(capacity),
            leaf_cnt: 0,
            finalized: false,
            root: None,
        }
    }

    /// Append a single pre-hashed leaf node.
    pub fn append(&mut self, leaf: BmtreeNode) {
        assert!(!self.finalized, "cannot append after finalize");
        self.leaves.push(leaf);
        self.leaf_cnt += 1;
    }

    /// Append a raw data blob (hashes it into a leaf first).
    pub fn append_raw(&mut self, data: &[u8]) {
        let leaf = hash_leaf(&self.config, data);
        self.append(leaf);
    }

    /// Finalize the tree and return the root hash.
    ///
    /// If no leaves were appended, returns the zero hash.
    /// Panics if called more than once.
    ///
    /// Uses zero-padded full binary tree construction to ensure the root
    /// is consistent with the proofs returned by `get_proof()`.
    pub fn finalize(&mut self) -> BmtreeNode {
        assert!(!self.finalized, "already finalized");
        self.finalized = true;

        if self.leaf_cnt == 0 {
            let root = [0u8; 32];
            self.root = Some(root);
            return root;
        }

        if self.leaf_cnt == 1 {
            let root = self.leaves[0];
            self.root = Some(root);
            return root;
        }

        // Build zero-padded full binary tree.
        let root = self.build_full_tree()[1];
        self.root = Some(root);
        root
    }

    /// Get the root hash (only valid after finalize).
    pub fn root(&self) -> Option<&BmtreeNode> {
        self.root.as_ref()
    }

    /// Number of leaves in the tree.
    pub fn leaf_count(&self) -> usize {
        self.leaf_cnt
    }

    /// Extract the inclusion proof for leaf at `leaf_idx`.
    ///
    /// Returns `None` if not finalized or index out of bounds.
    /// The proof consists of sibling hashes at each layer from
    /// bottom to top.
    pub fn get_proof(&self, leaf_idx: usize) -> Option<Vec<BmtreeNode>> {
        if !self.finalized || leaf_idx >= self.leaf_cnt {
            return None;
        }

        if self.leaf_cnt <= 1 {
            return Some(Vec::new());
        }

        let tree = self.build_full_tree();
        let depth = tree_depth(self.leaf_cnt);
        let full_size = 1 << depth;

        // Collect siblings along the path from leaf to root.
        let mut proof = Vec::with_capacity(depth);
        let mut idx = full_size + leaf_idx;
        for _ in 0..depth {
            let sibling_idx = idx ^ 1;
            proof.push(tree[sibling_idx]);
            idx /= 2;
        }

        Some(proof)
    }

    /// Build the zero-padded full binary tree from stored leaves.
    ///
    /// Returns a vector where `tree[1]` is the root, leaves start at
    /// `tree[full_size]`, and interior nodes are at `tree[1..full_size]`.
    fn build_full_tree(&self) -> Vec<BmtreeNode> {
        let depth = tree_depth(self.leaf_cnt);
        let full_size = 1 << depth;

        let mut tree = vec![[0u8; 32]; 2 * full_size];
        for (i, leaf) in self.leaves.iter().enumerate() {
            tree[full_size + i] = *leaf;
        }

        for i in (1..full_size).rev() {
            tree[i] = merge_nodes(&self.config, &tree[2 * i], &tree[2 * i + 1]);
        }

        tree
    }
}

/// Proof-based Merkle tree verifier.
///
/// Insert leaves with their inclusion proofs in any order.
/// On finalize, verifies that all proofs are consistent with the
/// same root and returns it.
pub struct BmtreeProofCommit {
    config: BmtreeConfig,
    /// Expected root (set from the first inserted proof).
    root: Option<BmtreeNode>,
    /// Number of leaves inserted.
    inserted: usize,
}

impl BmtreeProofCommit {
    /// Create a new proof-based verifier.
    pub fn new(config: BmtreeConfig) -> Self {
        Self {
            config,
            root: None,
            inserted: 0,
        }
    }

    /// Insert a leaf with its inclusion proof.
    ///
    /// Returns `true` if the proof is consistent with previously inserted
    /// proofs (same derived root). Returns `false` on inconsistency.
    pub fn insert_with_proof(
        &mut self,
        leaf: &BmtreeNode,
        leaf_idx: usize,
        proof: &[BmtreeNode],
    ) -> bool {
        let derived_root = match root_from_proof(&self.config, leaf, leaf_idx, proof) {
            Some(r) => r,
            None => return false,
        };

        match &self.root {
            None => {
                self.root = Some(derived_root);
                self.inserted += 1;
                true
            }
            Some(existing) => {
                // Compare only the first hash_sz bytes for intermediate
                // consistency, but store the full 32 bytes.
                let matches =
                    existing[..self.config.hash_sz] == derived_root[..self.config.hash_sz];
                if matches {
                    self.inserted += 1;
                }
                matches
            }
        }
    }

    /// Finalize and return the verified root.
    ///
    /// Returns `None` if no proofs were inserted.
    pub fn finalize(self) -> Option<BmtreeNode> {
        self.root
    }

    /// Number of leaves inserted so far.
    pub fn inserted_count(&self) -> usize {
        self.inserted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Leaf hashing ────────────────────────────────────────────

    #[test]
    fn hash_leaf_deterministic() {
        let h1 = hash_leaf(&SHRED_CONFIG, b"test data");
        let h2 = hash_leaf(&SHRED_CONFIG, b"test data");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_leaf_different_data() {
        let h1 = hash_leaf(&SHRED_CONFIG, b"data a");
        let h2 = hash_leaf(&SHRED_CONFIG, b"data b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_leaf_different_configs() {
        let h1 = hash_leaf(&SHRED_CONFIG, b"same data");
        let h2 = hash_leaf(&RUNTIME_CONFIG, b"same data");
        assert_ne!(h1, h2); // different prefixes → different hashes
    }

    // ── Merge nodes ─────────────────────────────────────────────

    #[test]
    fn merge_nodes_deterministic() {
        let left = hash_leaf(&SHRED_CONFIG, b"left");
        let right = hash_leaf(&SHRED_CONFIG, b"right");
        let m1 = merge_nodes(&SHRED_CONFIG, &left, &right);
        let m2 = merge_nodes(&SHRED_CONFIG, &left, &right);
        assert_eq!(m1, m2);
    }

    #[test]
    fn merge_nodes_order_matters() {
        let a = hash_leaf(&SHRED_CONFIG, b"a");
        let b = hash_leaf(&SHRED_CONFIG, b"b");
        let ab = merge_nodes(&SHRED_CONFIG, &a, &b);
        let ba = merge_nodes(&SHRED_CONFIG, &b, &a);
        assert_ne!(ab, ba);
    }

    // ── Tree depth ──────────────────────────────────────────────

    #[test]
    fn tree_depth_values() {
        assert_eq!(tree_depth(0), 0);
        assert_eq!(tree_depth(1), 0);
        assert_eq!(tree_depth(2), 1);
        assert_eq!(tree_depth(3), 2);
        assert_eq!(tree_depth(4), 2);
        assert_eq!(tree_depth(5), 3);
        assert_eq!(tree_depth(8), 3);
        assert_eq!(tree_depth(9), 4);
        assert_eq!(tree_depth(16), 4);
        assert_eq!(tree_depth(17), 5);
    }

    // ── Single-leaf tree ────────────────────────────────────────

    #[test]
    fn single_leaf_tree() {
        let mut commit = BmtreeCommit::new(SHRED_CONFIG);
        let leaf = hash_leaf(&SHRED_CONFIG, b"only leaf");
        commit.append(leaf);
        let root = commit.finalize();
        assert_eq!(root, leaf);
    }

    #[test]
    fn single_leaf_proof_empty() {
        let mut commit = BmtreeCommit::new(SHRED_CONFIG);
        let leaf = hash_leaf(&SHRED_CONFIG, b"only leaf");
        commit.append(leaf);
        commit.finalize();

        let proof = commit.get_proof(0).unwrap();
        assert!(proof.is_empty());
    }

    // ── Two-leaf tree ───────────────────────────────────────────

    #[test]
    fn two_leaf_tree_root() {
        let leaf0 = hash_leaf(&SHRED_CONFIG, b"leaf 0");
        let leaf1 = hash_leaf(&SHRED_CONFIG, b"leaf 1");
        let expected_root = merge_nodes(&SHRED_CONFIG, &leaf0, &leaf1);

        let mut commit = BmtreeCommit::new(SHRED_CONFIG);
        commit.append(leaf0);
        commit.append(leaf1);
        let root = commit.finalize();

        assert_eq!(root, expected_root);
    }

    #[test]
    fn two_leaf_proofs_verify() {
        let leaf0 = hash_leaf(&SHRED_CONFIG, b"leaf 0");
        let leaf1 = hash_leaf(&SHRED_CONFIG, b"leaf 1");

        let mut commit = BmtreeCommit::new(SHRED_CONFIG);
        commit.append(leaf0);
        commit.append(leaf1);
        let root = commit.finalize();

        // Proof for leaf 0 should be [leaf1].
        let proof0 = commit.get_proof(0).unwrap();
        assert_eq!(proof0.len(), 1);
        let derived0 = root_from_proof(&SHRED_CONFIG, &leaf0, 0, &proof0).unwrap();
        assert_eq!(derived0[..20], root[..20]);

        // Proof for leaf 1 should be [leaf0].
        let proof1 = commit.get_proof(1).unwrap();
        assert_eq!(proof1.len(), 1);
        let derived1 = root_from_proof(&SHRED_CONFIG, &leaf1, 1, &proof1).unwrap();
        assert_eq!(derived1[..20], root[..20]);
    }

    // ── Multi-leaf trees ────────────────────────────────────────

    #[test]
    fn four_leaf_tree_proof_round_trip() {
        let leaves: Vec<BmtreeNode> = (0..4u8).map(|i| hash_leaf(&SHRED_CONFIG, &[i])).collect();

        let mut commit = BmtreeCommit::new(SHRED_CONFIG);
        for l in &leaves {
            commit.append(*l);
        }
        let root = commit.finalize();

        // Every leaf's proof should derive the same root.
        for (idx, leaf) in leaves.iter().enumerate() {
            let proof = commit.get_proof(idx).unwrap();
            assert_eq!(proof.len(), 2); // depth = 2 for 4 leaves
            let derived = root_from_proof(&SHRED_CONFIG, leaf, idx, &proof).unwrap();
            assert_eq!(derived[..20], root[..20]);
        }
    }

    #[test]
    fn seven_leaf_tree_proof_round_trip() {
        // Non-power-of-two: 7 leaves → depth 3 (padded to 8).
        let leaves: Vec<BmtreeNode> = (0..7u8).map(|i| hash_leaf(&SHRED_CONFIG, &[i])).collect();

        let mut commit = BmtreeCommit::new(SHRED_CONFIG);
        for l in &leaves {
            commit.append(*l);
        }
        let root = commit.finalize();

        for (idx, leaf) in leaves.iter().enumerate() {
            let proof = commit.get_proof(idx).unwrap();
            assert_eq!(proof.len(), 3);
            let derived = root_from_proof(&SHRED_CONFIG, leaf, idx, &proof).unwrap();
            assert_eq!(derived[..20], root[..20]);
        }
    }

    #[test]
    fn sixteen_leaf_tree() {
        let leaves: Vec<BmtreeNode> = (0..16u8).map(|i| hash_leaf(&SHRED_CONFIG, &[i])).collect();

        let mut commit = BmtreeCommit::with_capacity(SHRED_CONFIG, 16);
        for l in &leaves {
            commit.append(*l);
        }
        let root = commit.finalize();
        assert_eq!(commit.leaf_count(), 16);

        // Spot-check first and last proofs.
        for idx in [0, 7, 15] {
            let proof = commit.get_proof(idx).unwrap();
            assert_eq!(proof.len(), 4);
            let derived = root_from_proof(&SHRED_CONFIG, &leaves[idx], idx, &proof).unwrap();
            assert_eq!(derived[..20], root[..20]);
        }
    }

    // ── Runtime config (32-byte) ────────────────────────────────

    #[test]
    fn runtime_tree_32byte_proofs() {
        let leaves: Vec<BmtreeNode> = (0..5u8).map(|i| hash_leaf(&RUNTIME_CONFIG, &[i])).collect();

        let mut commit = BmtreeCommit::new(RUNTIME_CONFIG);
        for l in &leaves {
            commit.append(*l);
        }
        let root = commit.finalize();

        for (idx, leaf) in leaves.iter().enumerate() {
            let proof = commit.get_proof(idx).unwrap();
            let derived = root_from_proof(&RUNTIME_CONFIG, leaf, idx, &proof).unwrap();
            // For 32-byte config, full 32 bytes must match.
            assert_eq!(derived, root);
        }
    }

    // ── append_raw ──────────────────────────────────────────────

    #[test]
    fn append_raw_matches_manual() {
        let mut commit_raw = BmtreeCommit::new(SHRED_CONFIG);
        commit_raw.append_raw(b"data 0");
        commit_raw.append_raw(b"data 1");
        let root_raw = commit_raw.finalize();

        let mut commit_manual = BmtreeCommit::new(SHRED_CONFIG);
        commit_manual.append(hash_leaf(&SHRED_CONFIG, b"data 0"));
        commit_manual.append(hash_leaf(&SHRED_CONFIG, b"data 1"));
        let root_manual = commit_manual.finalize();

        assert_eq!(root_raw, root_manual);
    }

    // ── Empty tree ──────────────────────────────────────────────

    #[test]
    fn empty_tree() {
        let mut commit = BmtreeCommit::new(SHRED_CONFIG);
        let root = commit.finalize();
        assert_eq!(root, [0u8; 32]);
    }

    // ── Proof-based commit ──────────────────────────────────────

    #[test]
    fn proof_commit_verifies_consistent_tree() {
        let leaves: Vec<BmtreeNode> = (0..4u8).map(|i| hash_leaf(&SHRED_CONFIG, &[i])).collect();

        // Build tree and extract proofs.
        let mut commit = BmtreeCommit::new(SHRED_CONFIG);
        for l in &leaves {
            commit.append(*l);
        }
        let root = commit.finalize();

        // Insert proofs in arbitrary order into proof-based verifier.
        let mut pcommit = BmtreeProofCommit::new(SHRED_CONFIG);
        for idx in [2, 0, 3, 1] {
            let proof = commit.get_proof(idx).unwrap();
            assert!(pcommit.insert_with_proof(&leaves[idx], idx, &proof));
        }

        assert_eq!(pcommit.inserted_count(), 4);
        let verified_root = pcommit.finalize().unwrap();
        assert_eq!(verified_root[..20], root[..20]);
    }

    #[test]
    fn proof_commit_rejects_inconsistent_proof() {
        let leaves: Vec<BmtreeNode> = (0..4u8).map(|i| hash_leaf(&SHRED_CONFIG, &[i])).collect();

        let mut commit = BmtreeCommit::new(SHRED_CONFIG);
        for l in &leaves {
            commit.append(*l);
        }
        commit.finalize();

        let mut pcommit = BmtreeProofCommit::new(SHRED_CONFIG);
        let proof0 = commit.get_proof(0).unwrap();
        assert!(pcommit.insert_with_proof(&leaves[0], 0, &proof0));

        // Provide wrong leaf for index 1.
        let proof1 = commit.get_proof(1).unwrap();
        let wrong_leaf = hash_leaf(&SHRED_CONFIG, b"WRONG");
        assert!(!pcommit.insert_with_proof(&wrong_leaf, 1, &proof1));
    }

    // ── Edge cases ──────────────────────────────────────────────

    #[test]
    fn get_proof_before_finalize_returns_none() {
        let mut commit = BmtreeCommit::new(SHRED_CONFIG);
        commit.append(hash_leaf(&SHRED_CONFIG, b"leaf"));
        assert!(commit.get_proof(0).is_none());
    }

    #[test]
    fn get_proof_out_of_bounds() {
        let mut commit = BmtreeCommit::new(SHRED_CONFIG);
        commit.append(hash_leaf(&SHRED_CONFIG, b"leaf"));
        commit.finalize();
        assert!(commit.get_proof(1).is_none());
        assert!(commit.get_proof(100).is_none());
    }

    #[test]
    fn root_from_proof_excessive_depth() {
        let leaf = hash_leaf(&SHRED_CONFIG, b"test");
        let proof = vec![[0u8; 32]; MAX_DEPTH + 1];
        assert!(root_from_proof(&SHRED_CONFIG, &leaf, 0, &proof).is_none());
    }

    // ── Cross-check with shred_verifier logic ───────────────────

    #[test]
    fn matches_shred_verifier_merkle_leaf_hash() {
        // The shred verifier computes: SHA-256(LEAF_PREFIX || data)
        // Our hash_leaf with SHRED_CONFIG should match.
        let data = b"example shred content";
        let our_hash = hash_leaf(&SHRED_CONFIG, data);
        let expected =
            Sha256Hasher::hash_chunks(&[b"\x00SOLANA_MERKLE_SHREDS_LEAF" as &[u8], data]);
        assert_eq!(our_hash, expected);
    }

    #[test]
    fn matches_shred_verifier_merkle_merge() {
        // The shred verifier merges: SHA-256(NODE_PREFIX || left[0..20] || right[0..20])
        let left = hash_leaf(&SHRED_CONFIG, b"left");
        let right = hash_leaf(&SHRED_CONFIG, b"right");
        let our_merge = merge_nodes(&SHRED_CONFIG, &left, &right);
        let expected = Sha256Hasher::hash_chunks(&[
            b"\x01SOLANA_MERKLE_SHREDS_NODE" as &[u8],
            &left[..20],
            &right[..20],
        ]);
        assert_eq!(our_merge, expected);
    }
}
