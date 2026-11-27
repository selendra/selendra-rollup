//! The module system's derives (`selendra-macros`), used through this crate's re-exports the way
//! module crates use them: what they generate, checked against known answers and run through
//! the state accessors. Every test also runs in the zk guest configuration (`make guest`: no
//! `native`), so the layouts and ids are pinned there too.
//!
//! The derives' errors are tested with their exact messages in `selendra-macros`.

mod consensus_type;
mod module_event;
mod module_info;
mod runtime;

use selendra_modules_api::test_utils::{MockKernel, TestStorage};
use selendra_modules_api::{Amount, BasicGasMeter, Gas, Spec, WorkingSet};
use selendra_state::{ArrayWitness, TxScratchpad};

/// A transaction's working set over an empty `TestStorage`, with `budget` gas in each
/// dimension at a price of 1.
fn working_set<S: Spec<Storage = TestStorage>>(budget: u64) -> WorkingSet<S> {
    let checkpoint = MockKernel::checkpoint(TestStorage::default(), ArrayWitness::default());
    let meter = BasicGasMeter::new_with_gas(
        <S::Gas as From<[u64; 2]>>::from([budget, budget]),
        <<S::Gas as Gas>::Price as From<[Amount; 2]>>::from([Amount::new(1); 2]),
    );
    WorkingSet::new(TxScratchpad::new(checkpoint), meter)
}
