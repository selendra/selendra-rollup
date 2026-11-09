//! An in-memory accessor for tests ([`InMemoryState`], one `BTreeMap` per namespace, never
//! fails; in `test_utils`, shared with the node's tests) and `UnwrapInfallible`.

use std::convert::Infallible;

pub(crate) use crate::test_utils::InMemoryState;

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
