//! The tree of uncommitted blocks ([`ForkTree`]): which block builds on which, which are saved,
//! and which one is finalized. Pure bookkeeping, without databases.
//!
//! Every rule is checked before anything changes, so a refused call leaves the tree as it was.
//! The rules (upstream's storage manager checked none of them):
//! - A block is registered on its parent before it is executed: the parent must be the
//!   finalized block or a *saved* block, and the block's height must be its parent's plus one
//!   (DA heights, which follow each other on a DA chain). A block is never its own parent, and
//!   a block is registered once (again with the same parent and height: a no-op). With these,
//!   the tree has no cycles and every walk to the finalized block ends within the tree's size.
//! - With nothing finalized (empty databases), a block whose parent is not in the tree is a
//!   genesis candidate. Any parent is accepted until a genesis candidate is saved; from then on
//!   the parent and height of the saved one are required (all genesis candidates are children
//!   of the same DA block). A candidate that is registered but never saved fixes nothing.
//! - Finalizing a block keeps only its descendants: every other block, saved or not, is
//!   discarded.

use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::hash::Hash;

/// One uncommitted block.
#[derive(Debug, Clone)]
struct Node<K> {
    parent: K,
    height: u64,
    children: Vec<K>,
    saved: bool,
}

/// What [`ForkTree::register`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Registered {
    /// The block is new.
    New,
    /// The block was registered already, with the same parent and height.
    Existing,
}

/// The tree of uncommitted blocks, keyed by block hash (see the [module docs](self)).
#[derive(Debug, Clone)]
pub(crate) struct ForkTree<K> {
    nodes: HashMap<K, Node<K>>,
    /// The finalized block and its height (`None`: nothing finalized).
    finalized: Option<(K, u64)>,
    /// With nothing finalized: the parent and height of the saved genesis candidates (`None`
    /// until one is saved).
    genesis: Option<(K, u64)>,
}

impl<K: Clone + Eq + Hash + Debug> ForkTree<K> {
    /// An empty tree on the finalized block `finalized` (hash, height); `None` for empty
    /// databases.
    pub(crate) fn new(finalized: Option<(K, u64)>) -> Self {
        Self {
            nodes: HashMap::new(),
            finalized,
            genesis: None,
        }
    }

    /// The number of blocks in the tree (saved or not).
    pub(crate) fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether `hash` is in the tree.
    pub(crate) fn contains(&self, hash: &K) -> bool {
        self.nodes.contains_key(hash)
    }

    /// Whether `hash` is a saved block of the tree.
    #[cfg(test)]
    pub(crate) fn is_saved(&self, hash: &K) -> bool {
        self.nodes.get(hash).is_some_and(|node| node.saved)
    }

    /// The parent and height `hash` was registered with, and whether it is saved.
    pub(crate) fn get(&self, hash: &K) -> Option<(&K, u64, bool)> {
        self.nodes
            .get(hash)
            .map(|node| (&node.parent, node.height, node.saved))
    }

    /// The saved blocks (any order).
    #[cfg(test)]
    pub(crate) fn saved(&self) -> impl Iterator<Item = &K> {
        self.nodes
            .iter()
            .filter(|(_, node)| node.saved)
            .map(|(hash, _)| hash)
    }

    /// The finalized block and its height.
    #[cfg(test)]
    pub(crate) fn finalized(&self) -> Option<&(K, u64)> {
        self.finalized.as_ref()
    }

    /// Checks that a block at `height` may build on `prev` (see the [module docs](self)).
    fn check_parent(&self, prev: &K, height: u64) -> anyhow::Result<()> {
        let expected_after = |parent_height: u64| {
            parent_height
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("block height overflow"))
        };
        if let Some(node) = self.nodes.get(prev) {
            anyhow::ensure!(
                node.saved,
                "the parent block {prev:?} is not saved (it was not executed, or its changes \
                 were not saved)"
            );
            let expected = expected_after(node.height)?;
            anyhow::ensure!(
                height == expected,
                "a block at height {height} cannot be a child of block {prev:?} at height {}",
                node.height
            );
            return Ok(());
        }
        match (&self.finalized, &self.genesis) {
            (Some((finalized, finalized_height)), _) => {
                anyhow::ensure!(
                    prev == finalized,
                    "unknown parent block {prev:?}: it is neither the finalized block \
                     {finalized:?} nor a saved block (it may be older than the finalized block, \
                     on a discarded fork, or never seen)"
                );
                let expected = expected_after(*finalized_height)?;
                anyhow::ensure!(
                    height == expected,
                    "a block at height {height} cannot be a child of the finalized block \
                     {finalized:?} at height {finalized_height}"
                );
            }
            (None, Some((genesis_parent, genesis_height))) => {
                anyhow::ensure!(
                    prev == genesis_parent && height == *genesis_height,
                    "the genesis block must be a child of {genesis_parent:?} at height \
                     {genesis_height} (a saved genesis block is), not of {prev:?} at height \
                     {height}"
                );
            }
            // Nothing saved yet: any genesis candidate.
            (None, None) => {}
        }
        Ok(())
    }

    /// Registers block `hash` at `height` on its parent `prev` (see the [module docs](self)).
    ///
    /// # Errors
    /// If `prev == hash`, `hash` is the finalized block, `hash` was registered with another
    /// parent or height, or `prev` is not a valid parent for it. Nothing changes then.
    pub(crate) fn register(&mut self, hash: K, prev: K, height: u64) -> anyhow::Result<Registered> {
        anyhow::ensure!(prev != hash, "block {hash:?} cannot be its own parent");
        if let Some((finalized, _)) = &self.finalized {
            anyhow::ensure!(
                *finalized != hash,
                "block {hash:?} is the finalized block: it cannot be executed again"
            );
        }
        if let Some(node) = self.nodes.get(&hash) {
            anyhow::ensure!(
                node.parent == prev && node.height == height,
                "block {hash:?} is registered with parent {:?} at height {}, not parent \
                 {prev:?} at height {height}",
                node.parent,
                node.height
            );
            return Ok(Registered::Existing);
        }
        self.check_parent(&prev, height)?;
        if let Some(parent) = self.nodes.get_mut(&prev) {
            parent.children.push(hash.clone());
        }
        self.nodes.insert(
            hash,
            Node {
                parent: prev,
                height,
                children: Vec::new(),
                saved: false,
            },
        );
        Ok(Registered::New)
    }

    /// Marks the registered block `hash` saved: its changes are kept, and blocks may build on
    /// it. A saved genesis candidate fixes the genesis parent.
    ///
    /// # Errors
    /// If `hash` is not registered, is saved already, or its parent is no longer valid for it
    /// (another genesis candidate was saved). Nothing changes then.
    pub(crate) fn mark_saved(&mut self, hash: &K) -> anyhow::Result<()> {
        let Some(node) = self.nodes.get(hash) else {
            anyhow::bail!("block {hash:?} is not registered");
        };
        anyhow::ensure!(!node.saved, "block {hash:?} is saved already");
        let (parent, height) = (node.parent.clone(), node.height);
        self.check_parent(&parent, height)?;
        if self.finalized.is_none() && !self.nodes.contains_key(&parent) {
            self.genesis.get_or_insert((parent, height));
        }
        if let Some(node) = self.nodes.get_mut(hash) {
            node.saved = true;
        }
        Ok(())
    }

    /// The saved blocks from the oldest uncommitted one to `hash` (oldest first): the chain a
    /// finalization of `hash` commits, and the snapshots a storage after `hash` reads.
    ///
    /// # Errors
    /// If `hash` or one of its ancestors in the tree is not saved, or `hash` is not in the tree.
    pub(crate) fn chain_to_finalized(&self, hash: &K) -> anyhow::Result<Vec<K>> {
        let mut chain = Vec::new();
        let mut current = hash;
        // Every step goes to a block registered before (its parent), so this ends within the
        // tree's size; the bound only guards against a bug.
        for _ in 0..=self.nodes.len() {
            let Some(node) = self.nodes.get(current) else {
                anyhow::bail!(
                    "block {current:?} is not an uncommitted block (unknown, discarded, or \
                     committed)"
                );
            };
            anyhow::ensure!(node.saved, "block {current:?} is not saved");
            chain.push(current.clone());
            if !self.nodes.contains_key(&node.parent) {
                chain.reverse();
                return Ok(chain);
            }
            current = &node.parent;
        }
        anyhow::bail!("bug: the walk from block {hash:?} to the finalized block does not end")
    }

    /// Finalizes the saved block `hash`, a child of the finalized block (or a saved genesis
    /// candidate): it becomes the finalized block and leaves the tree, with every block that is
    /// not its descendant. Returns those discarded blocks.
    ///
    /// # Errors
    /// If `hash` is not saved or not a child of the finalized block. Nothing changes then.
    pub(crate) fn finalize_child(&mut self, hash: &K) -> anyhow::Result<Vec<K>> {
        let Some(node) = self.nodes.get(hash) else {
            anyhow::bail!("block {hash:?} is not an uncommitted block");
        };
        anyhow::ensure!(node.saved, "block {hash:?} is not saved");
        anyhow::ensure!(
            !self.nodes.contains_key(&node.parent),
            "block {hash:?} is not a child of the finalized block: its parent {:?} is \
             uncommitted",
            node.parent
        );
        let height = node.height;
        let mut descendants = HashSet::new();
        let mut queue = node.children.clone();
        while let Some(child) = queue.pop() {
            if let Some(child_node) = self.nodes.get(&child) {
                queue.extend(child_node.children.iter().cloned());
            }
            descendants.insert(child);
        }
        let discarded: Vec<K> = self
            .nodes
            .keys()
            .filter(|key| *key != hash && !descendants.contains(*key))
            .cloned()
            .collect();
        for key in &discarded {
            self.nodes.remove(key);
        }
        self.nodes.remove(hash);
        self.finalized = Some((hash.clone(), height));
        self.genesis = None;
        Ok(discarded)
    }

    /// Finalizes the saved block `hash` and its uncommitted ancestors: returns them (oldest
    /// first) and the blocks discarded (see [`finalize_child`](Self::finalize_child)).
    ///
    /// # Errors
    /// See [`chain_to_finalized`](Self::chain_to_finalized). Nothing changes then.
    #[cfg(test)]
    pub(crate) fn finalize(&mut self, hash: &K) -> anyhow::Result<(Vec<K>, Vec<K>)> {
        let chain = self.chain_to_finalized(hash)?;
        let mut discarded = Vec::new();
        for block in &chain {
            discarded.extend(self.finalize_child(block)?);
        }
        Ok((chain, discarded))
    }

    /// Checks the tree's invariants (tests): parents and children agree, heights follow each
    /// other, saved blocks build on saved blocks.
    #[cfg(test)]
    pub(crate) fn check_invariants(&self) {
        for (hash, node) in &self.nodes {
            match self.nodes.get(&node.parent) {
                Some(parent) => {
                    assert!(parent.children.contains(hash), "{hash:?} not a child");
                    assert_eq!(parent.height.checked_add(1), Some(node.height));
                    assert!(parent.saved, "{hash:?} on an unsaved parent");
                }
                None => match &self.finalized {
                    Some((finalized, height)) => {
                        assert_eq!(&node.parent, finalized);
                        assert_eq!(height.checked_add(1), Some(node.height));
                    }
                    None => {
                        if node.saved {
                            assert_eq!(
                                self.genesis.as_ref(),
                                Some(&(node.parent.clone(), node.height))
                            );
                        }
                    }
                },
            }
            for child in &node.children {
                assert_eq!(self.nodes.get(child).map(|c| &c.parent), Some(hash));
            }
        }
        let children: usize = self.nodes.values().map(|node| node.children.len()).sum();
        let with_parent = self
            .nodes
            .values()
            .filter(|node| self.nodes.contains_key(&node.parent))
            .count();
        assert_eq!(children, with_parent);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Tree = ForkTree<u64>;

    /// A tree on the finalized block 0 (height 10) with `1 → 2 → 3` and `1 → 4` saved.
    fn tree() -> Tree {
        let mut tree = Tree::new(Some((0, 10)));
        for (hash, prev, height) in [(1, 0, 11), (2, 1, 12), (3, 2, 13), (4, 1, 12)] {
            assert_eq!(tree.register(hash, prev, height).unwrap(), Registered::New);
            tree.mark_saved(&hash).unwrap();
        }
        tree.check_invariants();
        tree
    }

    fn err(result: anyhow::Result<impl Debug>) -> String {
        format!("{:#}", result.unwrap_err())
    }

    /// Registration needs a saved or finalized parent one height below; a block registers once
    /// with one parent; a refused registration changes nothing.
    #[test]
    fn register_rules() {
        let mut tree = tree();
        // Unknown parent, and a parent older than the finalized block.
        assert!(err(tree.register(9, 99, 11)).contains("unknown parent"));
        assert!(err(tree.register(9, 98, 10)).contains("unknown parent"));
        // A late sibling of the finalized block (its parent is the finalized block's parent).
        assert!(err(tree.register(9, 77, 10)).contains("unknown parent"));
        // Wrong height on the finalized block and on a saved block.
        assert!(err(tree.register(9, 0, 12)).contains("height 12"));
        assert!(err(tree.register(9, 3, 13)).contains("height 13"));
        // The finalized block itself.
        assert!(err(tree.register(0, 3, 14)).contains("is the finalized block"));
        // An unsaved parent.
        tree.register(5, 3, 14).unwrap();
        assert!(err(tree.register(6, 5, 15)).contains("not saved"));
        // Again with the same parent: a no-op; with another parent or height: refused.
        assert_eq!(tree.register(5, 3, 14).unwrap(), Registered::Existing);
        assert!(err(tree.register(5, 4, 13)).contains("registered with parent 3"));
        assert!(err(tree.register(5, 3, 15)).contains("registered with parent 3"));
        assert_eq!(tree.len(), 5);
        tree.check_invariants();
        // Saved once.
        tree.mark_saved(&5).unwrap();
        assert!(err(tree.mark_saved(&5)).contains("saved already"));
        assert!(err(tree.mark_saved(&99)).contains("not registered"));
        tree.check_invariants();
    }

    /// B4: no self-parent, no cycle (a registered block's parent must exist before it), and the
    /// walk to the finalized block always ends.
    #[test]
    fn cycle_and_self_parent_rejected() {
        let mut tree = tree();
        assert!(err(tree.register(7, 7, 11)).contains("its own parent"));
        // 3 → 2 → 1 → 0: making 1 a child of 3 is a re-registration with another parent.
        assert!(err(tree.register(1, 3, 14)).contains("registered with parent 0"));
        // A new block whose parent is itself in the future (not registered yet).
        assert!(err(tree.register(8, 9, 14)).contains("unknown parent"));
        assert_eq!(tree.chain_to_finalized(&3).unwrap(), [1, 2, 3]);
        assert!(err(tree.chain_to_finalized(&7)).contains("not an uncommitted block"));
        tree.check_invariants();
    }

    /// Finalizing a block keeps only its descendants, finalizing it with its ancestors in order.
    #[test]
    fn finalize_keeps_only_descendants() {
        let mut tree = tree();
        tree.register(5, 3, 14).unwrap();
        tree.register(6, 4, 13).unwrap();
        // Not saved, and not a child of the finalized block.
        assert!(err(tree.finalize(&5)).contains("not saved"));
        assert!(err(tree.finalize_child(&2)).contains("not a child of the finalized block"));
        assert_eq!(tree.len(), 6);

        let (committed, mut discarded) = tree.finalize(&2).unwrap();
        assert_eq!(committed, [1, 2]);
        discarded.sort_unstable();
        // 4 (sibling of 2) and its unsaved child 6.
        assert_eq!(discarded, [4, 6]);
        assert_eq!(tree.finalized(), Some(&(2, 12)));
        // 3 and its unsaved child 5 remain.
        assert_eq!(tree.len(), 2);
        assert!(tree.is_saved(&3) && !tree.is_saved(&5));
        tree.check_invariants();
        // 3 builds on the finalized block now; a discarded block is unknown.
        assert_eq!(tree.chain_to_finalized(&3).unwrap(), [3]);
        assert!(err(tree.register(9, 4, 13)).contains("unknown parent"));
        assert!(err(tree.mark_saved(&4)).contains("not registered"));

        let (committed, discarded) = tree.finalize(&3).unwrap();
        assert_eq!((committed, discarded), (vec![3], vec![]));
        // The unsaved child 5 stays, on the finalized block 3.
        assert_eq!(tree.len(), 1);
        tree.check_invariants();
    }

    /// A5: registered blocks that were never saved are dropped by a finalization unless they
    /// descend from the finalized block (upstream kept them in its maps forever).
    #[test]
    fn registered_unsaved_blocks_are_dropped_on_finalize() {
        let mut tree = tree();
        // Unsaved children of the finalized block, of a sibling, and of the finalized chain.
        tree.register(10, 0, 11).unwrap();
        tree.register(11, 4, 13).unwrap();
        tree.register(12, 1, 12).unwrap();
        tree.register(13, 3, 14).unwrap();
        let (_, mut discarded) = tree.finalize(&3).unwrap();
        discarded.sort_unstable();
        assert_eq!(discarded, [4, 10, 11, 12]);
        assert_eq!(tree.len(), 1);
        assert!(tree.contains(&13));
        tree.check_invariants();
    }

    /// With nothing finalized, any parent is accepted until a genesis candidate is saved, which
    /// then fixes the parent and height; a candidate registered but never saved fixes nothing
    /// (critique: it locked out every other genesis candidate until a restart).
    #[test]
    fn genesis_parent_is_fixed_by_the_first_saved_candidate() {
        let mut tree = Tree::new(None);
        tree.register(1, 100, 5).unwrap();
        // 1 is never saved: another candidate with another parent and height is accepted.
        tree.register(2, 200, 7).unwrap();
        tree.register(3, 200, 7).unwrap();
        tree.mark_saved(&2).unwrap();
        tree.check_invariants();
        // Now the genesis parent is 200 at height 7.
        assert!(err(tree.register(4, 100, 5)).contains("must be a child of 200"));
        assert!(err(tree.register(4, 200, 8)).contains("must be a child of 200"));
        assert!(err(tree.mark_saved(&1)).contains("must be a child of 200"));
        tree.mark_saved(&3).unwrap();
        tree.register(5, 2, 8).unwrap();
        tree.mark_saved(&5).unwrap();
        tree.check_invariants();

        let (committed, mut discarded) = tree.finalize(&5).unwrap();
        discarded.sort_unstable();
        assert_eq!((committed, discarded), (vec![2, 5], vec![1, 3]));
        assert_eq!(tree.finalized(), Some(&(5, 8)));
        assert!(err(tree.register(6, 200, 7)).contains("unknown parent"));
        tree.register(6, 5, 9).unwrap();
        tree.check_invariants();
    }
}
