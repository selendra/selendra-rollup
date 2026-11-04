//! The read/write cache of a provable namespace ([`ProvableStorageCache`]) and the ordered
//! accesses it produces for the state update ([`StateAccesses`]).
//!
//! Every map here is a `BTreeMap` (upstream: `HashMap`, with the writes sorted at freeze, so
//! upstream was deterministic too). This is a simplicity/performance trade: no hasher in the
//! guest and no sort at freeze, but native lookups are about 3x slower.
// TODO(Phase 11): benchmark the caches when the sequencer state is ported; if needed, use a
// `HashMap` with a fixed, seedless hasher natively and sort at freeze (see TODO.md).

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::marker::PhantomData;
use std::mem;

use crate::namespaces::ProvableCompileTimeNamespace;
use crate::storage::{NodeLeaf, NodeLeafAndMaybeValue, ReadType, Storage};
use crate::{SlotKey, SlotValue};

/// Whether a value is already in a cache, i.e. whether reading it would be a first
/// (storage) read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IsValueCached {
    /// The value is cached, with the last access type. Writes supersede reads: once a value is
    /// written, this is `Yes(Write)` even if the value is read afterwards.
    Yes(AccessSize),
    /// The value was never fetched from storage nor written.
    No,
}

/// A sequence of events on a particular value: a transaction might read a value, then take
/// some action which causes it to be updated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Access {
    /// Read access to a storage value.
    Read {
        original: Option<NodeLeafAndMaybeValue>,
    },
    /// Write access to a storage value.
    Write { modified: Option<SlotValue> },
}

/// A cache event that occurred on a particular value, with the size of the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessSize {
    /// Read access to a storage value.
    Read(u32),
    /// Write access to a storage value.
    Write(u32),
}

impl AccessSize {
    /// Returns the size of the value contained in the access.
    pub fn size(&self) -> u32 {
        match self {
            AccessSize::Read(size) | AccessSize::Write(size) => *size,
        }
    }
}

impl Access {
    /// Returns the size of the value contained in the access.
    fn as_access_size(&self) -> AccessSize {
        match self {
            Access::Read { original } => {
                AccessSize::Read(original.as_ref().map_or(0, NodeLeafAndMaybeValue::size))
            }
            Access::Write { modified } => {
                AccessSize::Write(modified.as_ref().map_or(0, SlotValue::size))
            }
        }
    }

    fn add_write(&mut self, write: Option<SlotValue>) {
        match self {
            Access::Read { .. } => *self = Access::Write { modified: write },
            // Simply override the modified value with the new one.
            Access::Write { modified } => *modified = write,
        }
    }
}

/// Keeps track of the accesses of each key: a revertable part (the current transaction) on
/// top of a committed part.
#[derive(Debug, Clone, Default)]
struct CacheLog {
    revertable_log: BTreeMap<SlotKey, Access>,
    log: BTreeMap<SlotKey, Access>,
}

impl CacheLog {
    /// All committed accesses, in key order.
    ///
    /// # Panics
    /// If the revertable log was neither committed nor discarded (a bug).
    fn iter(&self) -> impl Iterator<Item = (&SlotKey, &Access)> {
        assert!(
            self.revertable_log.is_empty(),
            "Revertable cache should be merged or discarded before calling `iter`"
        );
        self.log.iter()
    }

    /// The committed writes, in key order.
    ///
    /// # Panics
    /// If the revertable log was neither committed nor discarded (a bug).
    fn take_writes(self) -> Vec<(SlotKey, Option<SlotValue>)> {
        assert!(
            self.revertable_log.is_empty(),
            "Revertable cache should be merged or discarded before calling `take_writes`"
        );
        self.log
            .into_iter()
            .filter_map(|(key, access)| match access {
                Access::Read { .. } => None,
                Access::Write { modified } => Some((key, modified)),
            })
            .collect()
    }

    fn get(&self, key: &SlotKey) -> Option<&Access> {
        self.revertable_log.get(key).or_else(|| self.log.get(key))
    }

    fn get_mut(&mut self, key: &SlotKey) -> Option<&mut Access> {
        self.revertable_log
            .get_mut(key)
            .or_else(|| self.log.get_mut(key))
    }

    /// Adds a read entry to the cache.
    ///
    /// # Panics
    /// If the key is already in the revertable log: callers add a read only for keys absent from
    /// both logs (a bug otherwise).
    fn add_read(&mut self, key: SlotKey, value: Option<NodeLeafAndMaybeValue>) {
        match self.revertable_log.entry(key) {
            Entry::Occupied(existing) => panic!(
                "Detected multiple calls to `add_read` for the same key: {}",
                existing.key()
            ),
            Entry::Vacant(vacancy) => {
                vacancy.insert(Access::Read { original: value });
            }
        }
    }

    /// Adds a write entry to the revertable log.
    fn add_write(&mut self, key: SlotKey, value: Option<SlotValue>) {
        match self.revertable_log.entry(key) {
            Entry::Occupied(mut existing) => existing.get_mut().add_write(value),
            Entry::Vacant(vacancy) => {
                vacancy.insert(Access::Write { modified: value });
            }
        }
    }

    fn commit_revertable_log(&mut self) {
        // Fast path: the first commit can move the revertable log into place.
        if self.log.is_empty() {
            mem::swap(&mut self.log, &mut self.revertable_log);
            return;
        }

        for (key, access) in mem::take(&mut self.revertable_log) {
            match access {
                Access::Read { .. } => {
                    let is_new = self.log.insert(key, access).is_none();
                    assert!(
                        is_new,
                        "The same value was read twice from storage in a single block; this is a bug"
                    );
                }
                Access::Write { modified } => match self.log.entry(key) {
                    Entry::Occupied(mut existing) => existing.get_mut().add_write(modified),
                    Entry::Vacant(vacancy) => {
                        vacancy.insert(Access::Write { modified });
                    }
                },
            }
        }
    }

    fn discard_revertable_log(&mut self) {
        self.revertable_log.clear();
    }
}

/// Caches reads and writes of one provable namespace `N` on top of a [`Storage`].
///
/// The first read of a key goes to storage (and so into the witness) and is recorded, in order,
/// as a read the state update must verify; later reads are served from the cache. Writes stay
/// in the cache until the state update.
///
/// # Revertable part
/// Accesses go to a revertable part first, which is either committed
/// ([`commit_revertable_storage_cache`](Self::commit_revertable_storage_cache)) or discarded
/// ([`discard_revertable_storage_cache`](Self::discard_revertable_storage_cache)).
///
/// ⚠️ Discarding also drops the revertable *reads* from the reads the state update verifies,
/// while their hints stay in the witness. In the zk guest those reads are then never checked
/// against the state root, so a discard is sound only if the discarded execution is not part of
/// what is being proven: upstream discards only in the sequencer, for transactions it drops
/// from the batch. The state transition function must never discard on a path the guest
/// executes, or a prover could pick the values of the discarded reads (and with them, e.g.,
/// whether a transaction is dropped).
///
/// # Reading a size, then a value
/// - Natively, [`get_size_or_fetch`](Self::get_size_or_fetch) loads the full value but puts only
///   its leaf in the witness; if the value is then read with
///   [`get_or_fetch`](Self::get_or_fetch), it is put in the witness at that point
///   ([`Storage::put_in_witness`]).
/// - In the guest, the size query takes only the leaf from the witness (a large value need not
///   be in the witness just to learn its size). A later full read takes the value from the
///   witness and checks that it matches the leaf.
#[derive(Default, Debug, Clone)]
pub struct ProvableStorageCache<N> {
    cache: CacheLog,
    /// Reads that were retrieved from storage for the first time but can still be reverted.
    revertable_ordered_reads: Vec<(SlotKey, Option<NodeLeafAndMaybeValue>)>,
    /// Committed first reads, in the order they happened.
    ordered_db_reads: Vec<(SlotKey, Option<NodeLeaf>)>,
    phantom: PhantomData<N>,
}

impl<N: ProvableCompileTimeNamespace> ProvableStorageCache<N> {
    /// Returns the first reads that can still be reverted, in the order they happened.
    pub fn revertable_ordered_reads(&self) -> &[(SlotKey, Option<NodeLeafAndMaybeValue>)] {
        &self.revertable_ordered_reads
    }

    /// Commits the revertable part of the cache.
    pub fn commit_revertable_storage_cache(&mut self) {
        let reads = mem::take(&mut self.revertable_ordered_reads);
        self.ordered_db_reads.extend(
            reads
                .into_iter()
                .map(|(key, node)| (key, node.map(|n| n.leaf))),
        );
        self.cache.commit_revertable_log();
    }

    /// Discards the revertable part of the cache. See the ⚠️ in the type docs.
    pub fn discard_revertable_storage_cache(&mut self) {
        self.revertable_ordered_reads.clear();
        self.cache.discard_revertable_log();
    }

    /// Returns an iterator over the committed writes, in key order.
    ///
    /// # Panics
    /// If the revertable part was neither committed nor discarded.
    pub fn get_writes(&self) -> impl Iterator<Item = (&SlotKey, Option<&SlotValue>)> {
        self.cache.iter().filter_map(|(key, access)| match access {
            Access::Write { modified } => Some((key, modified.as_ref())),
            Access::Read { .. } => None,
        })
    }

    /// Takes the committed writes, in key order.
    ///
    /// # Panics
    /// If the revertable part was neither committed nor discarded.
    pub fn take_writes(self) -> Vec<(SlotKey, Option<SlotValue>)> {
        self.cache.take_writes()
    }

    /// Commits the revertable part and converts the cache into [`OrderedReadsAndWrites`]: the
    /// first reads in the order they happened, the writes in key order.
    pub fn to_ordered_writes_and_reads(mut self) -> OrderedReadsAndWrites {
        self.commit_revertable_storage_cache();
        OrderedReadsAndWrites {
            ordered_reads: self.ordered_db_reads,
            // Sorted: the log is a `BTreeMap` (upstream sorted a `HashMap`'s writes here).
            ordered_writes: self.cache.take_writes(),
        }
    }

    /// Checks if a value corresponding to a given key is cached.
    pub fn is_value_cached(&self, key: &SlotKey) -> IsValueCached {
        match self.cache.get(key) {
            Some(access) => IsValueCached::Yes(access.as_access_size()),
            None => IsValueCached::No,
        }
    }

    /// Gets the size of the value, from the cache or (first read) from storage. See the type
    /// docs for what goes into the witness.
    pub fn get_size_or_fetch<S: Storage>(
        &mut self,
        key: &SlotKey,
        storage: &S,
        witness: &S::Witness,
    ) -> Option<u32> {
        match self.cache.get(key) {
            Some(Access::Read { original }) => original.as_ref().map(NodeLeafAndMaybeValue::size),
            Some(Access::Write { modified }) => modified.as_ref().map(SlotValue::size),
            None => {
                let maybe_leaf = storage.get_leaf::<N>(key, witness);
                let size = maybe_leaf.as_ref().map(NodeLeafAndMaybeValue::size);
                self.add_read(key.clone(), maybe_leaf);
                size
            }
        }
    }

    /// Gets a value from the cache or (first read) from storage.
    ///
    /// # Panics
    /// If the value's leaf was fetched earlier (a size query) and the value now fetched is
    /// absent or does not match that leaf. In the zk guest both come from the witness, so this
    /// is an invalid witness (no proof, the intended result); natively it is a storage bug.
    pub fn get_or_fetch<S: Storage>(
        &mut self,
        key: &SlotKey,
        storage: &S,
        witness: &S::Witness,
    ) -> Option<SlotValue> {
        let Some(access) = self.cache.get_mut(key) else {
            let value = storage.get::<N>(key, witness);
            let read = value
                .clone()
                .map(NodeLeafAndMaybeValue::new_read::<S::Hasher>);
            self.add_read(key.clone(), read);
            return value;
        };

        match access {
            Access::Read {
                original: Some(node),
            } => match &node.value {
                ReadType::GetSizeValueNotFetched => {
                    let Some(value) = storage.get::<N>(key, witness) else {
                        panic!(
                            "Invalid read of {key}: its leaf exists but the value is absent; the witness is invalid"
                        )
                    };
                    assert!(
                        NodeLeaf::make_leaf::<S::Hasher>(&value) == node.leaf,
                        "Invalid read of {key}: the value does not match its leaf; the witness is invalid"
                    );
                    node.value = ReadType::Read(value.clone());
                    Some(value)
                }
                ReadType::GetSizeValueFetched(value) => {
                    let value = value.clone();
                    storage.put_in_witness(Some(value.clone()), witness);
                    node.value = ReadType::Read(value.clone());
                    Some(value)
                }
                ReadType::Read(value) => Some(value.clone()),
            },
            Access::Read { original: None } => None,
            Access::Write { modified } => modified.clone(),
        }
    }

    /// Replaces the keyed value in the cache.
    pub fn set(&mut self, key: &SlotKey, value: SlotValue) {
        self.cache.add_write(key.clone(), Some(value));
    }

    /// Deletes a keyed value from the cache.
    pub fn delete(&mut self, key: &SlotKey) {
        self.cache.add_write(key.clone(), None);
    }

    /// Records a first read. The key must be absent from the cache.
    fn add_read(&mut self, key: SlotKey, node: Option<NodeLeafAndMaybeValue>) {
        self.revertable_ordered_reads
            .push((key.clone(), node.clone()));
        self.cache.add_read(key, node);
    }

    /// Adds, as first reads, the reads whose keys are not already in the cache (sequencer
    /// warm-up with reads made by another checkpoint).
    ///
    /// These reads get no witness hints; they are verified by the state update like any other
    /// read, so they must be values of the same previous state.
    pub fn add_read_if_not_present_in_cache(
        &mut self,
        reads: Vec<(SlotKey, Option<NodeLeafAndMaybeValue>)>,
    ) {
        for (key, node) in reads {
            if self.cache.get(&key).is_none() {
                self.add_read(key, node);
            }
        }
    }
}

/// The values read from storage and the values to be written, both in deterministic order.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OrderedReadsAndWrites {
    /// First reads, in the order they happened (each key at most once): the leaf read, or
    /// `None` if the key was absent.
    pub ordered_reads: Vec<(SlotKey, Option<NodeLeaf>)>,
    /// Writes in ascending key order (each key at most once): the new value, or `None` for a
    /// delete.
    pub ordered_writes: Vec<(SlotKey, Option<SlotValue>)>,
}

/// The read/write sets of the user and kernel namespaces.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StateAccesses {
    /// The reads and writes to the user namespace.
    pub user: OrderedReadsAndWrites,
    /// The reads and writes to the kernel namespace.
    pub kernel: OrderedReadsAndWrites,
}

#[cfg(test)]
mod tests {
    use sha2::Sha256;

    use super::*;
    use crate::{Prefix, User};

    fn key(k: u8) -> SlotKey {
        SlotKey::from_parts(&Prefix::new(k, 0), &[0])
    }

    fn value(v: u8) -> Option<SlotValue> {
        Some(SlotValue::from(vec![v]))
    }

    fn read(v: u8) -> Option<NodeLeafAndMaybeValue> {
        value(v).map(NodeLeafAndMaybeValue::new_read::<Sha256>)
    }

    #[test]
    fn test_cache_read_write() {
        let key = key(1);

        // A read is not a write.
        let mut log = CacheLog::default();
        log.add_read(key.clone(), read(2));
        log.commit_revertable_log();
        assert!(log.take_writes().is_empty());

        // A write.
        let mut log = CacheLog::default();
        log.add_write(key.clone(), value(3));
        log.commit_revertable_log();
        assert_eq!(log.take_writes(), [(key.clone(), value(3))]);

        // A write overrides a read.
        let mut log = CacheLog::default();
        log.add_read(key.clone(), read(4));
        log.add_write(key.clone(), value(5));
        log.commit_revertable_log();
        assert_eq!(log.take_writes(), [(key.clone(), value(5))]);

        // A write overrides another write, also across commits.
        let mut log = CacheLog::default();
        log.add_write(key.clone(), value(4));
        log.commit_revertable_log();
        log.add_write(key.clone(), None);
        log.commit_revertable_log();
        assert_eq!(log.take_writes(), [(key.clone(), None)]);

        // A discarded write is gone.
        let mut log = CacheLog::default();
        log.add_write(key.clone(), value(3));
        log.discard_revertable_log();
        assert!(log.take_writes().is_empty());
    }

    #[test]
    #[should_panic(expected = "multiple calls to `add_read`")]
    fn double_read_is_a_bug() {
        let mut log = CacheLog::default();
        log.add_read(key(1), None);
        log.add_read(key(1), None);
    }

    #[test]
    #[should_panic(expected = "Revertable cache should be merged or discarded")]
    fn writes_need_a_committed_cache() {
        let mut cache = ProvableStorageCache::<User>::default();
        cache.set(&key(1), SlotValue::from(vec![1]));
        let _ = cache.take_writes();
    }

    #[test]
    fn writes_are_sorted_and_reads_keep_their_order() {
        let mut cache = ProvableStorageCache::<User>::default();
        for k in [5, 1, 3] {
            cache.add_read(key(k), read(k));
        }
        cache.commit_revertable_storage_cache();
        for k in [9, 2, 7, 2] {
            cache.set(&key(k), SlotValue::from(vec![k]));
        }
        cache.delete(&key(5));
        assert!(matches!(
            cache.is_value_cached(&key(5)),
            IsValueCached::Yes(AccessSize::Write(0))
        ));
        assert!(matches!(
            cache.is_value_cached(&key(1)),
            IsValueCached::Yes(AccessSize::Read(1))
        ));
        assert_eq!(cache.is_value_cached(&key(4)), IsValueCached::No);
        cache.commit_revertable_storage_cache();
        let writes: Vec<_> = cache.get_writes().map(|(k, _)| k.clone()).collect();
        assert_eq!(writes, [key(2), key(5), key(7), key(9)]);

        let ordered = cache.to_ordered_writes_and_reads();
        let reads: Vec<_> = ordered
            .ordered_reads
            .iter()
            .map(|(k, _)| k.clone())
            .collect();
        assert_eq!(reads, [key(5), key(1), key(3)]);
        assert_eq!(
            ordered.ordered_reads[0].1,
            Some(NodeLeaf::make_leaf::<Sha256>(&SlotValue::from(vec![5])))
        );
        let writes: Vec<_> = ordered
            .ordered_writes
            .iter()
            .map(|(k, _)| k.clone())
            .collect();
        assert_eq!(writes, [key(2), key(5), key(7), key(9)]);
        assert_eq!(ordered.ordered_writes[1].1, None);
    }

    #[test]
    fn warm_up_reads_skip_cached_keys() {
        let mut cache = ProvableStorageCache::<User>::default();
        cache.set(&key(1), SlotValue::from(vec![1]));
        cache.add_read(key(2), read(2));
        cache.add_read_if_not_present_in_cache(vec![
            (key(1), read(9)),
            (key(2), read(9)),
            (key(3), read(3)),
            (key(4), None),
        ]);
        let reads: Vec<_> = cache
            .revertable_ordered_reads()
            .iter()
            .map(|(k, _)| k.clone())
            .collect();
        assert_eq!(reads, [key(2), key(3), key(4)]);
    }

    #[test]
    fn access_size() {
        assert_eq!(AccessSize::Read(3).size(), 3);
        assert_eq!(AccessSize::Write(4).size(), 4);
        assert_eq!(
            Access::Read { original: None }.as_access_size(),
            AccessSize::Read(0)
        );
        assert_eq!(
            Access::Write { modified: value(1) }.as_access_size(),
            AccessSize::Write(1)
        );
    }
}
