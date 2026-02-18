use super::record::TransactionId;
use std::collections::HashMap;

/// Tracks parent/child relationships between transactions,
/// enabling fork-aware speculative execution.
///
/// Transactions form a tree rooted at the "root" transaction (xid=0).
/// Each non-root transaction has exactly one parent, and can have
/// multiple children (competing forks). Publishing a transaction
/// linearizes its ancestry chain and cancels all sibling branches.
#[derive(Debug)]
pub struct ForkTree {
    nodes: HashMap<TransactionId, ForkNode>,
}

#[derive(Debug, Clone)]
struct ForkNode {
    parent: TransactionId,
    children: Vec<TransactionId>,
}

impl ForkTree {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
        }
    }

    /// Register a new child transaction forked from `parent`.
    ///
    /// Returns `Err` if `child` already exists in the tree.
    /// The parent must be either root or an existing node.
    pub fn prepare(
        &mut self,
        parent: TransactionId,
        child: TransactionId,
    ) -> Result<(), ForkTreeError> {
        if child.is_root() {
            return Err(ForkTreeError::CannotPrepareRoot);
        }
        if self.nodes.contains_key(&child) {
            return Err(ForkTreeError::TransactionAlreadyExists);
        }
        // Parent must be root or an existing node.
        if !parent.is_root() && !self.nodes.contains_key(&parent) {
            return Err(ForkTreeError::ParentNotFound);
        }

        // Add child to parent's children list.
        if !parent.is_root() {
            if let Some(parent_node) = self.nodes.get_mut(&parent) {
                parent_node.children.push(child);
            }
        }

        self.nodes.insert(
            child,
            ForkNode {
                parent,
                children: Vec::new(),
            },
        );

        Ok(())
    }

    /// Return whether a transaction has children (is frozen).
    ///
    /// A frozen transaction's records should not be modified because
    /// child transactions may depend on them.
    pub fn is_frozen(&self, xid: TransactionId) -> bool {
        if xid.is_root() {
            return true;
        }
        self.nodes
            .get(&xid)
            .map(|node| !node.children.is_empty())
            .unwrap_or(false)
    }

    /// Return the ordered ancestor chain: [xid, parent, grandparent, ...].
    ///
    /// Stops before root (root is not included). Returns empty vec
    /// if xid is root or not found.
    pub fn ancestors(&self, xid: TransactionId) -> Vec<TransactionId> {
        let mut chain = Vec::new();
        let mut current = xid;

        while !current.is_root() {
            if let Some(node) = self.nodes.get(&current) {
                chain.push(current);
                current = node.parent;
            } else {
                // xid not in tree — just return it as standalone
                if chain.is_empty() {
                    chain.push(current);
                }
                break;
            }
        }

        chain
    }

    /// Collect all descendant transaction IDs (children, grandchildren, etc.).
    pub fn descendants(&self, xid: TransactionId) -> Vec<TransactionId> {
        let mut result = Vec::new();
        let mut stack = vec![xid];

        while let Some(current) = stack.pop() {
            if let Some(node) = self.nodes.get(&current) {
                for &child in &node.children {
                    result.push(child);
                    stack.push(child);
                }
            }
        }

        result
    }

    /// Collect all sibling transaction IDs that compete with `xid`.
    ///
    /// For each ancestor in the chain, collects the other children
    /// of that ancestor's parent (i.e. competing branches).
    pub fn competing_branches(&self, xid: TransactionId) -> Vec<TransactionId> {
        let mut competitors = Vec::new();
        let chain = self.ancestors(xid);

        for &ancestor in &chain {
            if let Some(node) = self.nodes.get(&ancestor) {
                let parent = node.parent;
                // Get siblings: other children of the same parent
                let siblings = if parent.is_root() {
                    // Root's children are all top-level transactions
                    self.nodes
                        .iter()
                        .filter(|(_, n)| n.parent.is_root())
                        .map(|(&id, _)| id)
                        .filter(|&id| id != ancestor)
                        .collect::<Vec<_>>()
                } else if let Some(parent_node) = self.nodes.get(&parent) {
                    parent_node
                        .children
                        .iter()
                        .copied()
                        .filter(|&id| id != ancestor)
                        .collect()
                } else {
                    Vec::new()
                };

                for sibling in siblings {
                    competitors.push(sibling);
                    // Also collect all descendants of sibling
                    competitors.extend(self.descendants(sibling));
                }
            }
        }

        competitors
    }

    /// Remove a transaction and optionally its descendants from the tree.
    pub fn remove(&mut self, xid: TransactionId) {
        // Remove from parent's children list
        if let Some(node) = self.nodes.get(&xid) {
            let parent = node.parent;
            if !parent.is_root() {
                if let Some(parent_node) = self.nodes.get_mut(&parent) {
                    parent_node.children.retain(|&id| id != xid);
                }
            }
        }

        // Remove all descendants first
        let desc = self.descendants(xid);
        for d in desc {
            self.nodes.remove(&d);
        }

        self.nodes.remove(&xid);
    }

    /// Remove the entire ancestor chain after publish (linearize).
    ///
    /// Removes all nodes in the chain from the tree, including
    /// cleaning up parent references.
    pub fn remove_chain(&mut self, chain: &[TransactionId]) {
        for &xid in chain {
            self.nodes.remove(&xid);
        }

        // Clean up any remaining parent references
        for node in self.nodes.values_mut() {
            node.children.retain(|c| !chain.contains(c));
        }
    }

    /// Return the parent of a transaction, or None if root/not found.
    #[allow(dead_code)]
    pub fn parent(&self, xid: TransactionId) -> Option<TransactionId> {
        self.nodes.get(&xid).map(|n| n.parent)
    }

    /// Number of in-preparation transactions.
    pub fn transaction_count(&self) -> usize {
        self.nodes.len()
    }

    /// Check whether a transaction exists in the tree.
    pub fn contains(&self, xid: TransactionId) -> bool {
        self.nodes.contains_key(&xid)
    }
}

impl Default for ForkTree {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForkTreeError {
    CannotPrepareRoot,
    TransactionAlreadyExists,
    ParentNotFound,
}

impl std::fmt::Display for ForkTreeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CannotPrepareRoot => write!(f, "cannot prepare root transaction"),
            Self::TransactionAlreadyExists => write!(f, "transaction already exists in tree"),
            Self::ParentNotFound => write!(f, "parent transaction not found"),
        }
    }
}

impl std::error::Error for ForkTreeError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn xid(slot: u64) -> TransactionId {
        TransactionId::from_slot(slot)
    }

    #[test]
    fn prepare_creates_child() {
        let mut tree = ForkTree::new();
        tree.prepare(TransactionId::root(), xid(1)).unwrap();
        assert!(tree.contains(xid(1)));
        assert_eq!(tree.transaction_count(), 1);
    }

    #[test]
    fn prepare_nested_children() {
        let mut tree = ForkTree::new();
        tree.prepare(TransactionId::root(), xid(1)).unwrap();
        tree.prepare(xid(1), xid(2)).unwrap();
        tree.prepare(xid(2), xid(3)).unwrap();

        assert_eq!(tree.transaction_count(), 3);
        assert_eq!(tree.parent(xid(2)), Some(xid(1)));
        assert_eq!(tree.parent(xid(3)), Some(xid(2)));
    }

    #[test]
    fn prepare_root_fails() {
        let mut tree = ForkTree::new();
        let err = tree.prepare(TransactionId::root(), TransactionId::root());
        assert_eq!(err, Err(ForkTreeError::CannotPrepareRoot));
    }

    #[test]
    fn prepare_duplicate_fails() {
        let mut tree = ForkTree::new();
        tree.prepare(TransactionId::root(), xid(1)).unwrap();
        let err = tree.prepare(TransactionId::root(), xid(1));
        assert_eq!(err, Err(ForkTreeError::TransactionAlreadyExists));
    }

    #[test]
    fn prepare_missing_parent_fails() {
        let mut tree = ForkTree::new();
        let err = tree.prepare(xid(99), xid(1));
        assert_eq!(err, Err(ForkTreeError::ParentNotFound));
    }

    #[test]
    fn ancestors_chain() {
        let mut tree = ForkTree::new();
        tree.prepare(TransactionId::root(), xid(1)).unwrap();
        tree.prepare(xid(1), xid(2)).unwrap();
        tree.prepare(xid(2), xid(3)).unwrap();

        let chain = tree.ancestors(xid(3));
        assert_eq!(chain, vec![xid(3), xid(2), xid(1)]);
    }

    #[test]
    fn ancestors_root_returns_empty() {
        let tree = ForkTree::new();
        assert!(tree.ancestors(TransactionId::root()).is_empty());
    }

    #[test]
    fn is_frozen_when_has_children() {
        let mut tree = ForkTree::new();
        tree.prepare(TransactionId::root(), xid(1)).unwrap();
        assert!(!tree.is_frozen(xid(1)));

        tree.prepare(xid(1), xid(2)).unwrap();
        assert!(tree.is_frozen(xid(1)));
        assert!(!tree.is_frozen(xid(2)));
    }

    #[test]
    fn descendants_collects_all() {
        let mut tree = ForkTree::new();
        tree.prepare(TransactionId::root(), xid(1)).unwrap();
        tree.prepare(xid(1), xid(2)).unwrap();
        tree.prepare(xid(1), xid(3)).unwrap();
        tree.prepare(xid(2), xid(4)).unwrap();

        let mut desc = tree.descendants(xid(1));
        desc.sort_by_key(|x| *x.as_bytes());
        let mut expected = vec![xid(2), xid(3), xid(4)];
        expected.sort_by_key(|x| *x.as_bytes());
        assert_eq!(desc, expected);
    }

    #[test]
    fn competing_branches_finds_siblings() {
        let mut tree = ForkTree::new();
        // Fork: root -> xid(1) -> xid(3)
        //        root -> xid(2) -> xid(4)
        tree.prepare(TransactionId::root(), xid(1)).unwrap();
        tree.prepare(TransactionId::root(), xid(2)).unwrap();
        tree.prepare(xid(1), xid(3)).unwrap();
        tree.prepare(xid(2), xid(4)).unwrap();

        let competitors = tree.competing_branches(xid(3));
        // Should include xid(2) (sibling of xid(1)) and xid(4) (descendant of xid(2))
        assert!(competitors.contains(&xid(2)));
        assert!(competitors.contains(&xid(4)));
        assert!(!competitors.contains(&xid(1)));
        assert!(!competitors.contains(&xid(3)));
    }

    #[test]
    fn remove_cascades_to_descendants() {
        let mut tree = ForkTree::new();
        tree.prepare(TransactionId::root(), xid(1)).unwrap();
        tree.prepare(xid(1), xid(2)).unwrap();
        tree.prepare(xid(2), xid(3)).unwrap();

        tree.remove(xid(1));
        assert!(!tree.contains(xid(1)));
        assert!(!tree.contains(xid(2)));
        assert!(!tree.contains(xid(3)));
        assert_eq!(tree.transaction_count(), 0);
    }

    #[test]
    fn remove_preserves_siblings() {
        let mut tree = ForkTree::new();
        tree.prepare(TransactionId::root(), xid(1)).unwrap();
        tree.prepare(TransactionId::root(), xid(2)).unwrap();
        tree.prepare(xid(1), xid(3)).unwrap();

        tree.remove(xid(1));
        assert!(!tree.contains(xid(1)));
        assert!(!tree.contains(xid(3)));
        assert!(tree.contains(xid(2)));
    }

    #[test]
    fn remove_chain_cleans_up() {
        let mut tree = ForkTree::new();
        tree.prepare(TransactionId::root(), xid(1)).unwrap();
        tree.prepare(xid(1), xid(2)).unwrap();
        tree.prepare(TransactionId::root(), xid(5)).unwrap();

        tree.remove_chain(&[xid(1), xid(2)]);
        assert!(!tree.contains(xid(1)));
        assert!(!tree.contains(xid(2)));
        assert!(tree.contains(xid(5)));
    }
}
