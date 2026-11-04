//! [`StateCheckpoint`]: the read/write set of a block over a [`Storage`], and the accessor
//! the state transition function runs on.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::marker::PhantomData;

use crate::cache::{AccessSize, IsValueCached, ProvableStorageCache, StateAccesses};
use crate::namespaces::{Accessory, Kernel, Namespace, ProvableNamespace, User};
use crate::storage::{NodeLeafAndMaybeValue, Storage};
use crate::{SlotKey, SlotValue, StateReader, StateWriter};

/// The read/write set of a block on top of a [`Storage`]: a cache per provable namespace, the
/// accessory writes and the witness.
///
/// When a value is read, the checkpoint first checks its own cache. On a miss it queries the
/// storage, which adds a hint to the witness, and records the read, which the state update
/// later verifies. Writes stay in the checkpoint until it is frozen
/// ([`freeze`](Self::freeze), [`materialize_update`](Self::materialize_update)).
///
/// # Access rights
/// [`StateReader`] and [`StateWriter`] (both infallible) for [`User`] and [`Kernel`], and
/// [`StateWriter`] for [`Accessory`]. The accessory state is not provable, so the state
/// transition function may write it but never read it (the guest could not answer): there is
/// no `StateReader<Accessory>`, and native code reads it through
/// `accessory_state` (native only) instead.
///
/// ```
/// use selendra_state::{AccessoryStateValue, BorshCodec, Prefix, StateCheckpoint, Storage};
///
/// fn write<St: Storage>(state: &mut StateCheckpoint<St>) {
///     let mut value = AccessoryStateValue::<u8>::with_codec(Prefix::new(1, 1), BorshCodec);
///     let Ok(()) = value.set(&1, state);
///     let Ok(()) = value.delete(state);
/// }
/// ```
///
/// ```compile_fail,E0277
/// use selendra_state::{AccessoryStateValue, BorshCodec, Prefix, StateCheckpoint, Storage};
///
/// fn read<St: Storage>(state: &mut StateCheckpoint<St>) {
///     let value = AccessoryStateValue::<u8>::with_codec(Prefix::new(1, 1), BorshCodec);
///     let _ = value.get(state);
/// }
/// ```
///
/// ```compile_fail,E0277
/// use selendra_state::{AccessoryStateMap, BorshCodec, Prefix, StateCheckpoint, Storage};
///
/// fn remove<St: Storage>(state: &mut StateCheckpoint<St>) {
///     let mut map = AccessoryStateMap::<u8, u8>::with_codec(Prefix::new(1, 2), BorshCodec);
///     let _ = map.remove(&1, state);
/// }
/// ```
///
/// ```compile_fail,E0277
/// use selendra_state::{AccessoryStateVec, BorshCodec, Prefix, StateCheckpoint, Storage};
///
/// fn push<St: Storage>(state: &mut StateCheckpoint<St>) {
///     let mut vec = AccessoryStateVec::<u8>::with_codec(Prefix::new(1, 3), BorshCodec);
///     let _ = vec.push(&1, state);
/// }
/// ```
///
/// # Not yet here
/// Upstream's checkpoint also carries the visible slot number and rollup height (read from the
/// kernel when it is created, `VersionReader`), a per-block cache (`TempCache`), metrics, gas
/// metering and the sequencer's uncommitted-changes overlay. Those come with the module system
/// (Phase 5), the kernel (Phase 8) and the sequencer (Phase 11).
pub struct StateCheckpoint<St: Storage> {
    storage: St,
    witness: St::Witness,
    user_cache: ProvableStorageCache<User>,
    kernel_cache: ProvableStorageCache<Kernel>,
    /// `None` is a delete.
    accessory_writes: BTreeMap<SlotKey, Option<SlotValue>>,
}

impl<St: Storage> std::fmt::Debug for StateCheckpoint<St> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateCheckpoint").finish_non_exhaustive()
    }
}

/// The first reads of a checkpoint that can still be reverted (see
/// [`StateCheckpoint::first_reads`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FirstTimeReads {
    /// User space reads, in the order they happened.
    pub user: Vec<(SlotKey, Option<NodeLeafAndMaybeValue>)>,
    /// Kernel space reads, in the order they happened.
    pub kernel: Vec<(SlotKey, Option<NodeLeafAndMaybeValue>)>,
}

impl<St: Storage> StateCheckpoint<St> {
    /// Creates a checkpoint with no changes over `storage`, with an empty witness (native
    /// execution, which fills it).
    pub fn new(storage: St) -> Self {
        Self::with_witness(storage, Default::default())
    }

    /// Creates a checkpoint with no changes over `storage` and `witness` (the zk guest replays
    /// the witness the native execution recorded).
    pub fn with_witness(storage: St, witness: St::Witness) -> Self {
        Self {
            storage,
            witness,
            user_cache: Default::default(),
            kernel_cache: Default::default(),
            accessory_writes: BTreeMap::new(),
        }
    }

    /// Returns the storage underlying the checkpoint.
    pub fn storage(&self) -> &St {
        &self.storage
    }

    /// Checks if a key is in the checkpoint's cache (i.e. a read would not go to storage).
    pub fn is_value_cached(&self, namespace: Namespace, key: &SlotKey) -> IsValueCached {
        match namespace {
            Namespace::User => self.user_cache.is_value_cached(key),
            Namespace::Kernel => self.kernel_cache.is_value_cached(key),
            Namespace::Accessory => match self.accessory_writes.get(key) {
                Some(value) => {
                    IsValueCached::Yes(AccessSize::Write(value.as_ref().map_or(0, SlotValue::size)))
                }
                None => IsValueCached::No,
            },
        }
    }

    /// Gets the size of a value without reading it in full (in the zk guest only its leaf is
    /// taken from the witness). For gas metering (Phase 5).
    pub fn get_size(&mut self, namespace: ProvableNamespace, key: &SlotKey) -> Option<u32> {
        match namespace {
            ProvableNamespace::User => {
                self.user_cache
                    .get_size_or_fetch(key, &self.storage, &self.witness)
            }
            ProvableNamespace::Kernel => {
                self.kernel_cache
                    .get_size_or_fetch(key, &self.storage, &self.witness)
            }
        }
    }

    fn get_value(&mut self, namespace: ProvableNamespace, key: &SlotKey) -> Option<SlotValue> {
        match namespace {
            ProvableNamespace::User => {
                self.user_cache
                    .get_or_fetch(key, &self.storage, &self.witness)
            }
            ProvableNamespace::Kernel => {
                self.kernel_cache
                    .get_or_fetch(key, &self.storage, &self.witness)
            }
        }
    }

    fn set_value(&mut self, namespace: ProvableNamespace, key: &SlotKey, value: SlotValue) {
        match namespace {
            ProvableNamespace::User => self.user_cache.set(key, value),
            ProvableNamespace::Kernel => self.kernel_cache.set(key, value),
        }
    }

    fn delete_value(&mut self, namespace: ProvableNamespace, key: &SlotKey) {
        match namespace {
            ProvableNamespace::User => self.user_cache.delete(key),
            ProvableNamespace::Kernel => self.kernel_cache.delete(key),
        }
    }

    /// The first reads that can still be reverted (since the last commit or discard), for the
    /// sequencer's cache warm-up.
    pub fn first_reads(&self) -> FirstTimeReads {
        FirstTimeReads {
            user: self.user_cache.revertable_ordered_reads().to_vec(),
            kernel: self.kernel_cache.revertable_ordered_reads().to_vec(),
        }
    }

    /// Warms up the cache with reads whose keys are not already present (sequencer). They add
    /// no witness hints and are verified by the state update like any other read.
    pub fn add_read_if_not_present(&mut self, reads: FirstTimeReads) {
        self.user_cache.add_read_if_not_present_in_cache(reads.user);
        self.kernel_cache
            .add_read_if_not_present_in_cache(reads.kernel);
    }

    /// Commits the revertable part of the checkpoint's caches.
    pub fn commit_revertable_storage_cache(&mut self) {
        self.user_cache.commit_revertable_storage_cache();
        self.kernel_cache.commit_revertable_storage_cache();
    }

    /// Discards the revertable part of the checkpoint's caches.
    ///
    /// ⚠️ The discarded reads are then never verified against the state root, while their
    /// hints stay in the witness: never discard on a path the zk guest executes (see
    /// [`ProvableStorageCache`]). Upstream discards only in the sequencer, for transactions it
    /// drops from the batch. Accessory writes are not revertable here.
    pub fn discard_revertable_storage_cache(&mut self) {
        self.user_cache.discard_revertable_storage_cache();
        self.kernel_cache.discard_revertable_storage_cache();
    }

    /// Extracts the ordered reads and writes, the accessory writes and the witness.
    ///
    /// The revertable part of the caches is committed first.
    pub fn freeze(self) -> (StateAccesses, AccessoryDelta<St>, St::Witness) {
        let (accesses, accessory, witness, _storage) = self.freeze_with_storage();
        (accesses, accessory, witness)
    }

    fn freeze_with_storage(self) -> (StateAccesses, AccessoryDelta<St>, St::Witness, St) {
        let Self {
            storage,
            witness,
            user_cache,
            kernel_cache,
            accessory_writes,
        } = self;
        let accesses = StateAccesses {
            user: user_cache.to_ordered_writes_and_reads(),
            kernel: kernel_cache.to_ordered_writes_and_reads(),
        };
        let accessory = AccessoryDelta {
            writes: accessory_writes,
            #[cfg(feature = "native")]
            storage: storage.clone(),
            _storage: PhantomData,
        };
        (accesses, accessory, witness, storage)
    }

    /// Freezes the checkpoint and computes the state update it makes on top of
    /// `prev_state_root`, returning the new root, the update, the accessory writes, the witness
    /// and the storage.
    ///
    /// # Panics
    /// If [`Storage::compute_state_update`] fails. In the zk guest that means the witness is
    /// invalid (a read does not match the previous state, or a hint is missing): no proof is
    /// the intended result, and it must not become a recoverable error that execution continues
    /// past. Natively it means the storage is stale, corrupt or buggy, and the node must not
    /// commit a root it could not compute.
    #[allow(clippy::type_complexity)]
    pub fn materialize_update(
        self,
        prev_state_root: St::Root,
    ) -> (
        St::Root,
        St::StateUpdate,
        AccessoryDelta<St>,
        St::Witness,
        St,
    ) {
        let (accesses, accessory, witness, storage) = self.freeze_with_storage();
        let (root, update) = match storage.compute_state_update(accesses, &witness, prev_state_root)
        {
            Ok(computed) => computed,
            Err(err) => panic!("state update computation failed: {err:#}"),
        };
        (root, update, accessory, witness, storage)
    }
}

/// `StateCheckpoint` reads and writes its own caches without metering.
///
/// Phase 5 adds a metering hook trait with blanket `StateReader`/`StateWriter` impls in this
/// crate (TODO.md). These concrete impls stay coherent with those blankets only as long as
/// `StateCheckpoint` never implements the hook trait (gas belongs to the transaction accessors
/// built on top of a checkpoint, not to the checkpoint).
macro_rules! impl_provable_access {
    ($namespace:ty, $provable:expr) => {
        impl<St: Storage> StateReader<$namespace> for StateCheckpoint<St> {
            type Error = Infallible;

            fn get(&mut self, key: &SlotKey) -> Result<Option<SlotValue>, Self::Error> {
                Ok(self.get_value($provable, key))
            }
        }

        impl<St: Storage> StateWriter<$namespace> for StateCheckpoint<St> {
            type Error = Infallible;

            fn set(&mut self, key: &SlotKey, value: SlotValue) -> Result<(), Self::Error> {
                self.set_value($provable, key, value);
                Ok(())
            }

            fn delete(&mut self, key: &SlotKey) -> Result<(), Self::Error> {
                self.delete_value($provable, key);
                Ok(())
            }
        }
    };
}

impl_provable_access!(User, ProvableNamespace::User);
impl_provable_access!(Kernel, ProvableNamespace::Kernel);

impl<St: Storage> StateWriter<Accessory> for StateCheckpoint<St> {
    type Error = Infallible;

    fn set(&mut self, key: &SlotKey, value: SlotValue) -> Result<(), Self::Error> {
        self.accessory_writes.insert(key.clone(), Some(value));
        Ok(())
    }

    /// Records the delete. Upstream removed the pending write instead, so deleting a value
    /// already in storage did nothing.
    fn delete(&mut self, key: &SlotKey) -> Result<(), Self::Error> {
        self.accessory_writes.insert(key.clone(), None);
        Ok(())
    }
}

/// The accessory writes of a frozen checkpoint, still writable (e.g. by finalize hooks after
/// the state root is known), and natively readable.
pub struct AccessoryDelta<St: Storage> {
    /// `None` is a delete.
    writes: BTreeMap<SlotKey, Option<SlotValue>>,
    #[cfg(feature = "native")]
    storage: St,
    _storage: PhantomData<fn() -> St>,
}

impl<St: Storage> std::fmt::Debug for AccessoryDelta<St> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessoryDelta")
            .field("writes", &self.writes)
            .finish_non_exhaustive()
    }
}

impl<St: Storage> AccessoryDelta<St> {
    /// Returns the writes in ascending key order (`None` is a delete), e.g. for
    /// [`StateUpdate::add_accessory_items`](crate::StateUpdate::add_accessory_items).
    pub fn freeze(self) -> Vec<(SlotKey, Option<SlotValue>)> {
        self.writes.into_iter().collect()
    }
}

impl<St: Storage> StateWriter<Accessory> for AccessoryDelta<St> {
    type Error = Infallible;

    fn set(&mut self, key: &SlotKey, value: SlotValue) -> Result<(), Self::Error> {
        self.writes.insert(key.clone(), Some(value));
        Ok(())
    }

    fn delete(&mut self, key: &SlotKey) -> Result<(), Self::Error> {
        self.writes.insert(key.clone(), None);
        Ok(())
    }
}

#[cfg(feature = "native")]
pub use native::AccessoryStateCheckpoint;

#[cfg(feature = "native")]
mod native {
    use std::collections::BTreeMap;
    use std::convert::Infallible;

    use super::{AccessoryDelta, StateCheckpoint};
    use crate::namespaces::Accessory;
    use crate::{NativeStorage, SlotKey, SlotValue, StateReader, StateWriter};

    /// Reads the pending write of `key`, or the committed value.
    fn read_accessory<St: NativeStorage>(
        writes: &BTreeMap<SlotKey, Option<SlotValue>>,
        storage: &St,
        key: &SlotKey,
    ) -> Option<SlotValue> {
        match writes.get(key) {
            Some(pending) => pending.clone(),
            None => storage.get_accessory(key),
        }
    }

    impl<St: NativeStorage> StateCheckpoint<St> {
        /// Returns a handle to the accessory state (native only), for reading and writing
        /// accessory containers such as `AccessoryStateMap`.
        pub fn accessory_state(&mut self) -> AccessoryStateCheckpoint<'_, St> {
            AccessoryStateCheckpoint { checkpoint: self }
        }

        /// Takes the accessory writes out of the checkpoint (e.g. to run finalize hooks on
        /// them), leaving none.
        pub fn take_accessory_delta(&mut self) -> AccessoryDelta<St> {
            AccessoryDelta {
                writes: std::mem::take(&mut self.accessory_writes),
                storage: self.storage.clone(),
                _storage: std::marker::PhantomData,
            }
        }

        /// Puts accessory writes taken with
        /// [`take_accessory_delta`](Self::take_accessory_delta) back, replacing any made
        /// since.
        pub fn set_accessory_delta(&mut self, accessory_delta: AccessoryDelta<St>) {
            self.accessory_writes = accessory_delta.writes;
        }
    }

    /// A wrapper over a [`StateCheckpoint`] that only allows access to the accessory state,
    /// including reads (native only). Reads see the checkpoint's pending accessory writes, then
    /// the committed accessory state.
    pub struct AccessoryStateCheckpoint<'a, St: NativeStorage> {
        checkpoint: &'a mut StateCheckpoint<St>,
    }

    impl<St: NativeStorage> StateReader<Accessory> for AccessoryStateCheckpoint<'_, St> {
        type Error = Infallible;

        fn get(&mut self, key: &SlotKey) -> Result<Option<SlotValue>, Self::Error> {
            Ok(read_accessory(
                &self.checkpoint.accessory_writes,
                &self.checkpoint.storage,
                key,
            ))
        }
    }

    impl<St: NativeStorage> StateWriter<Accessory> for AccessoryStateCheckpoint<'_, St> {
        type Error = Infallible;

        fn set(&mut self, key: &SlotKey, value: SlotValue) -> Result<(), Self::Error> {
            StateWriter::<Accessory>::set(self.checkpoint, key, value)
        }

        fn delete(&mut self, key: &SlotKey) -> Result<(), Self::Error> {
            StateWriter::<Accessory>::delete(self.checkpoint, key)
        }
    }

    impl<St: NativeStorage> StateReader<Accessory> for AccessoryDelta<St> {
        type Error = Infallible;

        fn get(&mut self, key: &SlotKey) -> Result<Option<SlotValue>, Self::Error> {
            Ok(read_accessory(&self.writes, &self.storage, key))
        }
    }
}

#[cfg(test)]
mod tests;
