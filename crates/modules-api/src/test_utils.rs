//! Test support for this crate and the crates built on it (`test-utils` feature; never in a
//! node or guest build): specs over the mock DA layer and zkVM.

pub use selendra_mock_da::{MockAddress, MockDaSpec};
pub use selendra_mock_zkvm::MockZkvm;
pub use selendra_state::test_storage::TestStorage;

use crate::SelendraSpec;

/// [`SelendraSpec`] over the mock DA layer and zkVM, with `selendra-state`'s in-memory
/// [`TestStorage`] (prover and verifier modes; works on 32-bit targets and in the guest
/// configuration).
pub type TestSpec = SelendraSpec<MockDaSpec, MockZkvm, MockZkvm, TestStorage>;

/// [`SelendraSpec`] over the mock DA layer and zkVM, with the zk guest's storage
/// (`NomtVerifierStorage<StateStorageSpec>`, the default).
pub type TestGuestSpec = SelendraSpec<MockDaSpec, MockZkvm, MockZkvm>;
