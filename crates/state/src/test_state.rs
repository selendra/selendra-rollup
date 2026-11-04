//! An in-memory accessor for tests: one `BTreeMap` per namespace, never fails.

use std::collections::BTreeMap;
use std::convert::Infallible;

use crate::namespaces::{Accessory, Kernel, User};
use crate::{SlotKey, SlotValue, StateReader, StateWriter};

/// In-memory state with one map per namespace.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct InMemoryState {
    pub(crate) user: BTreeMap<SlotKey, SlotValue>,
    pub(crate) kernel: BTreeMap<SlotKey, SlotValue>,
    pub(crate) accessory: BTreeMap<SlotKey, SlotValue>,
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

/// `Result<T, Infallible>::unwrap` without a panic path.
pub(crate) trait UnwrapInfallible<T> {
    fn unwrap_infallible(self) -> T;
}

impl<T> UnwrapInfallible<T> for Result<T, Infallible> {
    fn unwrap_infallible(self) -> T {
        let Ok(value) = self;
        value
    }
}
