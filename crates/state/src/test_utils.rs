//! Test helpers shared with the node's storage tests (`selendra-db`): random operations on
//! state containers ([`Op`], [`run`]) that run on a checkpoint or on a plain model ([`Model`],
//! [`InMemoryState`]), and witness helpers.
//!
//! Compiled for this crate's tests and with the `test-utils` feature only: never in the zk guest
//! or a node build.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Once;

use crate::namespaces::{Accessory, Kernel, ProvableNamespace, User};
use crate::{
    AccessoryStateMap, ArrayWitness, BorshCodec, InfallibleStateReaderAndWriter, KernelStateMap,
    Prefix, SlotKey, SlotValue, StateCheckpoint, StateMap, StateReader, StateValue, StateVec,
    StateWriter, Storage,
};

/// In-memory state with one map per namespace.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct InMemoryState {
    /// The user namespace.
    pub user: BTreeMap<SlotKey, SlotValue>,
    /// The kernel namespace.
    pub kernel: BTreeMap<SlotKey, SlotValue>,
    /// The accessory namespace.
    pub accessory: BTreeMap<SlotKey, SlotValue>,
}

macro_rules! impl_namespace {
    ($namespace:ty, $field:ident) => {
        impl StateReader<$namespace> for InMemoryState {
            type Error = Infallible;

            fn get(&mut self, key: &SlotKey) -> Result<Option<SlotValue>, Self::Error> {
                Ok(self.$field.get(key).cloned())
            }
        }

        impl StateWriter<$namespace> for InMemoryState {
            type Error = Infallible;

            fn set(&mut self, key: &SlotKey, value: SlotValue) -> Result<(), Self::Error> {
                self.$field.insert(key.clone(), value);
                Ok(())
            }

            fn delete(&mut self, key: &SlotKey) -> Result<(), Self::Error> {
                self.$field.remove(key);
                Ok(())
            }
        }
    };
}

impl_namespace!(User, user);
impl_namespace!(Kernel, kernel);
impl_namespace!(Accessory, accessory);

/// The prefix of [`value`].
pub const VALUE: Prefix = Prefix::new(1, 0);
/// The prefix of [`map`].
pub const MAP: Prefix = Prefix::new(1, 1);
/// The prefix of [`vec()`].
pub const VEC: Prefix = Prefix::new(1, 2);
/// The prefix of [`kernel_map`].
pub const KERNEL_MAP: Prefix = Prefix::new(2, 0);
/// The prefix of [`accessory_map`].
pub const ACCESSORY_MAP: Prefix = Prefix::new(3, 0);

/// The user `StateValue` [`Op`]s use.
pub fn value() -> StateValue<u32> {
    StateValue::with_codec(VALUE, BorshCodec)
}

/// The user `StateMap` [`Op`]s use.
pub fn map() -> StateMap<u8, u32> {
    StateMap::with_codec(MAP, BorshCodec)
}

/// The user `StateVec` [`Op`]s use.
pub fn vec() -> StateVec<u32> {
    StateVec::with_codec(VEC, BorshCodec)
}

/// The kernel map [`Op`]s use.
pub fn kernel_map() -> KernelStateMap<u8, u32> {
    KernelStateMap::with_codec(KERNEL_MAP, BorshCodec)
}

/// The accessory map [`Op`]s use.
pub fn accessory_map() -> AccessoryStateMap<u8, u32> {
    AccessoryStateMap::with_codec(ACCESSORY_MAP, BorshCodec)
}

/// Something the replayed operations run on: a checkpoint, or a model of one.
pub trait Harness:
    InfallibleStateReaderAndWriter<User>
    + InfallibleStateReaderAndWriter<Kernel>
    + StateWriter<Accessory, Error = Infallible>
{
    /// The size of the value of `key` (a size query, `StateCheckpoint::get_size`).
    fn size(&mut self, namespace: ProvableNamespace, key: &SlotKey) -> Option<u32>;
    /// Commits the revertable writes.
    fn commit(&mut self);
    /// Discards the revertable writes.
    fn discard(&mut self);
}

impl<St: Storage> Harness for StateCheckpoint<St> {
    fn size(&mut self, namespace: ProvableNamespace, key: &SlotKey) -> Option<u32> {
        self.get_size(namespace, key)
    }

    fn commit(&mut self) {
        self.commit_revertable_storage_cache();
    }

    fn discard(&mut self) {
        self.discard_revertable_storage_cache();
    }
}

/// A checkpoint modeled with plain maps: `pending` on top of `committed`. Accessory writes are
/// not revertable, like in the checkpoint.
#[derive(Debug, Default)]
pub struct Model {
    /// The committed state.
    pub committed: InMemoryState,
    /// The state with the revertable writes.
    pub pending: InMemoryState,
}

macro_rules! impl_model {
    ($namespace:ty) => {
        impl StateReader<$namespace> for Model {
            type Error = Infallible;

            fn get(&mut self, key: &SlotKey) -> Result<Option<SlotValue>, Self::Error> {
                StateReader::<$namespace>::get(&mut self.pending, key)
            }
        }

        impl StateWriter<$namespace> for Model {
            type Error = Infallible;

            fn set(&mut self, key: &SlotKey, value: SlotValue) -> Result<(), Self::Error> {
                StateWriter::<$namespace>::set(&mut self.pending, key, value)
            }

            fn delete(&mut self, key: &SlotKey) -> Result<(), Self::Error> {
                StateWriter::<$namespace>::delete(&mut self.pending, key)
            }
        }
    };
}

impl_model!(User);
impl_model!(Kernel);
impl_model!(Accessory);

impl Harness for Model {
    fn size(&mut self, namespace: ProvableNamespace, key: &SlotKey) -> Option<u32> {
        let state = match namespace {
            ProvableNamespace::User => &self.pending.user,
            ProvableNamespace::Kernel => &self.pending.kernel,
        };
        state.get(key).map(SlotValue::size)
    }

    fn commit(&mut self) {
        self.committed = self.pending.clone();
    }

    fn discard(&mut self) {
        let accessory = std::mem::take(&mut self.pending.accessory);
        self.pending = self.committed.clone();
        self.pending.accessory = accessory;
    }
}

/// One operation on the containers above, or a commit or discard of the revertable writes.
///
/// Each variant is named after the container (`Value`: [`value`], `Map`: [`map`], `Kernel`:
/// [`kernel_map`], `Vec`: [`vec()`], `Accessory`: [`accessory_map`]) and the method it calls.
#[allow(missing_docs)]
#[derive(Debug, Clone, test_strategy::Arbitrary)]
pub enum Op {
    ValueSet(u32),
    ValueGet,
    ValueRemove,
    ValueDelete,
    MapSet(#[strategy(0u8..6)] u8, u32),
    MapGet(#[strategy(0u8..6)] u8),
    MapRemove(#[strategy(0u8..6)] u8),
    MapSetIfAbsent(#[strategy(0u8..6)] u8, u32),
    MapSize(#[strategy(0u8..6)] u8),
    KernelSet(#[strategy(0u8..6)] u8, u32),
    KernelGet(#[strategy(0u8..6)] u8),
    KernelRemove(#[strategy(0u8..6)] u8),
    KernelSize(#[strategy(0u8..6)] u8),
    VecPush(u32),
    VecPop,
    VecGet(#[strategy(0u64..6)] u64),
    VecRemove(#[strategy(0u64..6)] u64),
    AccessorySet(#[strategy(0u8..4)] u8, u32),
    AccessoryDelete(#[strategy(0u8..4)] u8),
    Commit,
    Discard,
}

/// Runs `ops`, returning every result (as `Debug` strings).
pub fn run<H: Harness>(ops: &[Op], state: &mut H) -> Vec<String> {
    let (mut value, mut map, mut vec, mut kernel, mut accessory) =
        (value(), map(), vec(), kernel_map(), accessory_map());
    let mut out = Vec::new();
    for op in ops {
        let result = match op {
            Op::ValueSet(v) => format!("{:?}", value.set(v, state)),
            Op::ValueGet => format!("{:?}", value.get(state)),
            Op::ValueRemove => format!("{:?}", value.remove(state)),
            Op::ValueDelete => format!("{:?}", value.delete(state)),
            Op::MapSet(k, v) => format!("{:?}", map.set(k, v, state)),
            Op::MapGet(k) => format!("{:?}", map.get(k, state)),
            Op::MapRemove(k) => format!("{:?}", map.remove(k, state)),
            Op::MapSetIfAbsent(k, v) => format!("{:?}", map.set_if_absent(k, v, state)),
            Op::MapSize(k) => format!(
                "{:?}",
                state.size(ProvableNamespace::User, &map.slot_key(k))
            ),
            Op::KernelSet(k, v) => format!("{:?}", kernel.set(k, v, state)),
            Op::KernelGet(k) => format!("{:?}", kernel.get(k, state)),
            Op::KernelRemove(k) => format!("{:?}", kernel.remove(k, state)),
            Op::KernelSize(k) => {
                format!(
                    "{:?}",
                    state.size(ProvableNamespace::Kernel, &kernel.slot_key(k))
                )
            }
            Op::VecPush(v) => format!("{:?}", vec.push(v, state)),
            Op::VecPop => format!("{:?}", vec.pop(state)),
            Op::VecGet(i) => format!("{:?}", vec.get(*i, state)),
            Op::VecRemove(i) => format!("{:?}", vec.remove(*i, state)),
            Op::AccessorySet(k, v) => format!("{:?}", accessory.set(k, v, state)),
            Op::AccessoryDelete(k) => format!("{:?}", accessory.delete(k, state)),
            Op::Commit => {
                state.commit();
                "commit".into()
            }
            Op::Discard => {
                state.discard();
                "discard".into()
            }
        };
        out.push(result);
    }
    out
}

/// `witness` through its borsh encoding.
pub fn borsh_roundtrip(witness: &ArrayWitness) -> ArrayWitness {
    borsh::from_slice(&borsh::to_vec(witness).unwrap()).unwrap()
}

/// The hints of `witness`, each as its borsh bytes.
pub fn hints(witness: &ArrayWitness) -> Vec<Vec<u8>> {
    borsh::from_slice(&borsh::to_vec(witness).unwrap()).unwrap()
}

thread_local! {
    static QUIET: Cell<bool> = const { Cell::new(false) };
}

/// Runs `f`, catching a panic without printing it (for the thousands of expected
/// invalid-witness panics of the tamper tests; other panics, on any thread, still print).
pub fn catch_quietly<R>(f: impl FnOnce() -> R) -> std::thread::Result<R> {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let default = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if !QUIET.with(Cell::get) {
                default(info);
            }
        }));
    });
    QUIET.with(|quiet| quiet.set(true));
    let result = catch_unwind(AssertUnwindSafe(f));
    QUIET.with(|quiet| quiet.set(false));
    result
}
