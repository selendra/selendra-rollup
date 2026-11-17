//! The transaction journal: the writes of one transaction over a block's
//! [`StateCheckpoint`](crate::StateCheckpoint), with nested scopes that commit into their
//! parent or revert.
//!
//! One journal replaces upstream's three overlays (`RevertableWriter` under `TxScratchpad`, the
//! working set's writes, `RevertableTxState`'s writes). A write records the entry it replaces in
//! an undo log while a scope is open; reverting a scope replays its part of the log backwards,
//! committing one hands its part to the parent scope. Accessory writes are journaled like the
//! others, so a reverted transaction leaves none behind.

use std::collections::BTreeMap;

use crate::{Namespace, SlotKey, SlotValue};

/// An open scope: where it starts in the undo log, and its serial number (unique within the
/// metered phase that opened it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OpenScope {
    serial: u64,
    undo_len: usize,
}

/// A scope's position: its depth (1 for the outermost open scope) and serial number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Level {
    pub(crate) depth: usize,
    pub(crate) serial: u64,
}

/// The entry a write replaced: `None` if the key was not in the journal.
type Undo = ((Namespace, SlotKey), Option<Option<SlotValue>>);

/// A transaction's writes (`None` is a delete), an undo log and a stack of open scopes.
#[derive(Debug, Default)]
pub(crate) struct Journal {
    writes: BTreeMap<(Namespace, SlotKey), Option<SlotValue>>,
    undo: Vec<Undo>,
    scopes: Vec<OpenScope>,
}

impl Journal {
    /// The journaled entry of `key`: `None` if the key was not written (read the checkpoint),
    /// `Some(None)` if it was deleted.
    pub(crate) fn get(&self, namespace: Namespace, key: &SlotKey) -> Option<&Option<SlotValue>> {
        self.writes.get(&(namespace, key.clone()))
    }

    /// Writes `value` (`None`: a delete) to `key`, recording the replaced entry while a scope is
    /// open.
    pub(crate) fn set(&mut self, namespace: Namespace, key: &SlotKey, value: Option<SlotValue>) {
        let entry = (namespace, key.clone());
        let replaced = self.writes.insert(entry.clone(), value);
        if !self.scopes.is_empty() {
            self.undo.push((entry, replaced));
        }
    }

    /// Opens a scope with `serial` on top of the stack and returns its level.
    pub(crate) fn open(&mut self, serial: u64) -> Level {
        self.scopes.push(OpenScope {
            serial,
            undo_len: self.undo.len(),
        });
        Level {
            depth: self.scopes.len(),
            serial,
        }
    }

    /// The number of open scopes.
    pub(crate) fn depth(&self) -> usize {
        self.scopes.len()
    }

    /// Whether the scope at `level` is open.
    pub(crate) fn is_open(&self, level: Level) -> bool {
        level
            .depth
            .checked_sub(1)
            .and_then(|index| self.scopes.get(index))
            .is_some_and(|scope| scope.serial == level.serial)
    }

    /// Commits the top scope into its parent (its writes stay; the parent can still revert
    /// them). Does nothing if no scope is open.
    pub(crate) fn commit_top(&mut self) {
        if self.scopes.pop().is_some() && self.scopes.is_empty() {
            // No scope left that could revert these writes.
            self.undo.clear();
        }
    }

    /// Reverts the top scope: undoes its writes, newest first. Does nothing if no scope is
    /// open.
    pub(crate) fn revert_top(&mut self) {
        let Some(scope) = self.scopes.pop() else {
            return;
        };
        for (entry, replaced) in self.undo.drain(scope.undo_len..).rev() {
            match replaced {
                Some(value) => self.writes.insert(entry, value),
                None => self.writes.remove(&entry),
            };
        }
    }

    /// Reverts every scope deeper than `depth`, innermost first.
    pub(crate) fn revert_above(&mut self, depth: usize) {
        while self.scopes.len() > depth {
            self.revert_top();
        }
    }

    /// The writes in key order (by namespace, then key), once no scope is open.
    pub(crate) fn into_writes(self) -> BTreeMap<(Namespace, SlotKey), Option<SlotValue>> {
        debug_assert!(
            self.scopes.is_empty(),
            "a transaction journal is applied with open scopes"
        );
        self.writes
    }

    /// The number of journaled keys.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.writes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Prefix;

    fn key(k: u8) -> SlotKey {
        SlotKey::from_parts(&Prefix::new(1, 1), &[k])
    }

    fn value(v: u8) -> Option<SlotValue> {
        Some(SlotValue::from(vec![v]))
    }

    fn entries(journal: &Journal) -> Vec<(Namespace, SlotKey, Option<SlotValue>)> {
        journal
            .writes
            .iter()
            .map(|((ns, k), v)| (*ns, k.clone(), v.clone()))
            .collect()
    }

    #[test]
    fn nested_scopes_commit_into_their_parent_and_revert() {
        let mut journal = Journal::default();
        journal.set(Namespace::User, &key(0), value(0));
        let outer = journal.open(1);
        journal.set(Namespace::User, &key(1), value(1));
        let inner = journal.open(2);
        assert_eq!(
            (outer, inner),
            (
                Level {
                    depth: 1,
                    serial: 1
                },
                Level {
                    depth: 2,
                    serial: 2
                }
            )
        );
        journal.set(Namespace::User, &key(0), value(9));
        journal.set(Namespace::Kernel, &key(2), None);
        journal.commit_top();
        assert!(journal.is_open(outer) && !journal.is_open(inner));
        // The committed inner writes now belong to the outer scope: reverting it undoes them.
        journal.revert_top();
        assert_eq!(entries(&journal), [(Namespace::User, key(0), value(0))]);
        assert_eq!(journal.depth(), 0);
        assert!(journal.undo.is_empty());
    }

    #[test]
    fn revert_restores_overwritten_and_deleted_entries() {
        let mut journal = Journal::default();
        journal.set(Namespace::User, &key(0), value(0));
        journal.set(Namespace::Accessory, &key(1), value(1));
        let before = entries(&journal);
        journal.open(7);
        journal.set(Namespace::User, &key(0), value(1));
        journal.set(Namespace::User, &key(0), None);
        journal.set(Namespace::Accessory, &key(1), None);
        journal.set(Namespace::Accessory, &key(3), value(3));
        journal.open(8);
        journal.set(Namespace::User, &key(0), value(5));
        journal.revert_above(0);
        assert_eq!(entries(&journal), before);
    }

    #[test]
    fn writes_come_out_in_namespace_then_key_order() {
        let mut journal = Journal::default();
        for (ns, k) in [
            (Namespace::Accessory, 0),
            (Namespace::Kernel, 2),
            (Namespace::User, 3),
            (Namespace::Kernel, 1),
            (Namespace::User, 0),
        ] {
            journal.set(ns, &key(k), value(k));
        }
        let order: Vec<_> = journal
            .into_writes()
            .into_keys()
            .map(|(ns, k)| (ns, k.without_prefix()[0]))
            .collect();
        assert_eq!(
            order,
            [
                (Namespace::User, 0),
                (Namespace::User, 3),
                (Namespace::Kernel, 1),
                (Namespace::Kernel, 2),
                (Namespace::Accessory, 0)
            ]
        );
    }

    #[test]
    fn levels_are_checked_by_depth_and_serial() {
        let mut journal = Journal::default();
        let level = journal.open(4);
        assert!(journal.is_open(level));
        assert!(!journal.is_open(Level {
            depth: 1,
            serial: 5
        }));
        assert!(!journal.is_open(Level {
            depth: 0,
            serial: 4
        }));
        assert!(!journal.is_open(Level {
            depth: 2,
            serial: 4
        }));
        journal.revert_top();
        assert!(!journal.is_open(level));
        // Closing with nothing open does nothing.
        journal.revert_top();
        journal.commit_top();
        assert_eq!(journal.depth(), 0);
    }
}
