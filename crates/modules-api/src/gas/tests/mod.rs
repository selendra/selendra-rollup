//! The gas errors' size and messages (`errors`), and the metered utilities' tests (upstream
//! `gas/tests/`), through a [`WorkingSet`] over the test storage whose meter has the most gas
//! and a budget of funds at a price of 1 per unit of gas (so the funds are the sum of the gas
//! over both dimensions).

mod errors;
mod metered_reader;
mod metered_utils;

use selendra_state::{StateCheckpoint, TxScratchpad};

use crate::test_utils::{TestSpec, TestStorage};
use crate::{Amount, BasicGasMeter, Gas, GasArray, GasPrice, GasUnit, WorkingSet};

type S = TestSpec;

const TEST_GAS_PRICE: GasPrice<2> = GasPrice::from_dimensions([Amount::new(1); 2]);

/// A working set whose meter has a budget of `remaining_funds` at [`TEST_GAS_PRICE`].
fn working_set(remaining_funds: Amount) -> WorkingSet<S> {
    let scratchpad = TxScratchpad::new(StateCheckpoint::new(TestStorage::default()));
    let meter =
        BasicGasMeter::new_with_funds_and_gas(remaining_funds, GasUnit::MAX, TEST_GAS_PRICE);
    WorkingSet::new(scratchpad, meter)
}

/// The value of `gas` at [`TEST_GAS_PRICE`].
fn value(gas: GasUnit<2>) -> Amount {
    gas.checked_value(TEST_GAS_PRICE).unwrap()
}

/// The gas of a sequence of reads through `MeteredReader`, each charging
/// `per_read_bias + per_byte × n`.
fn budget_for_reader_calls(
    per_byte: GasUnit<2>,
    per_read_bias: GasUnit<2>,
    reads: &[u32],
) -> GasUnit<2> {
    let mut total = GasUnit::<2>::ZEROED;
    for &n in reads {
        total = total
            .checked_combine(per_read_bias)
            .unwrap()
            .checked_combine(per_byte.checked_scalar_product(u64::from(n)).unwrap())
            .unwrap();
    }
    total
}
