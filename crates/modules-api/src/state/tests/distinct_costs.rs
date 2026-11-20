//! Known answers on [`DistinctCostSpec`], whose gas costs are all distinct (and distinct in each
//! dimension): they pin which cost each spec-driven charge reads. `SELENDRA_GAS_SCHEDULE`'s
//! placeholders are mostly `[1, 1]`, so the known answers on `TestSpec` cannot tell e.g.
//! `event_base` from `accessory_write`, or `decode_per_byte` from `read_per_byte`.
//!
//! Every answer is computed independently from the formulas (`python3 -I -c '…'`, with the costs
//! of `DISTINCT_GAS_SCHEDULE`: access [2, 3], hash_update [5, 7], hash_per_byte [11, 13], read
//! [17, 19], read_per_byte [23, 29], write [31, 37], write_per_byte [41, 43], decode_per_byte
//! [47, 53], accessory_write [59, 61], accessory_write_per_byte [67, 71], scope_open [73, 79],
//! event_base [157, 163], event_per_byte [167, 173]).

use selendra_state::test_utils::{accessory_map, kernel_map, map, value};
use selendra_state::{ArrayWitness, TxScratchpad};

use super::{storage, storage_at_genesis};
use crate::state::{GenesisStateAccessor, PreExecWorkingSet, TxState, WorkingSet};
use crate::test_utils::{DistinctCostSpec, MockKernel};
use crate::{
    Amount, BasicGasMeter, GasArray, GasMeter, GasPrice, GasUnit, MeteredBorshDeserialize,
    MeteredHasher, MeteredReader,
};

type D = DistinctCostSpec;

fn meter() -> BasicGasMeter<D> {
    BasicGasMeter::new_with_gas(
        GasUnit::from([1_000_000; 2]),
        GasPrice::from([Amount::new(1); 2]),
    )
}

fn scratchpad() -> TxScratchpad<<D as crate::Spec>::Storage> {
    TxScratchpad::new(MockKernel::checkpoint(storage(), ArrayWitness::default()))
}

fn working_set() -> WorkingSet<D> {
    WorkingSet::new(scratchpad(), meter())
}

/// The gas `f` uses on `state`, per dimension.
fn gas_of<T: GasMeter<D>, R>(state: &mut T, f: impl FnOnce(&mut T) -> R) -> ([u64; 2], R) {
    let before = state.gas_info().gas_used;
    let result = f(state);
    let used = state.gas_info().gas_used.checked_sub(before).unwrap();
    (used.dimensions(), result)
}

/// `value()` has a 2-byte key and a 4-byte value, `map()`/`kernel_map()`/`accessory_map()`
/// 3-byte keys and 4-byte values.
fn known_answers<T: TxState<D>>(state: &mut T) {
    // access + hash_update + hash_per_byte·2 + read + read_per_byte·4 + hash_update +
    // hash_per_byte·4 + decode_per_byte·4
    assert_eq!(gas_of(state, |s| value().get(s)), ([375, 442], Ok(Some(5))));
    assert_eq!(
        gas_of(state, |s| map().get(&1, s)),
        ([386, 455], Ok(Some(10)))
    );
    // access + hash_update + hash_per_byte·3 + read
    assert_eq!(gas_of(state, |s| map().get(&3, s)), ([57, 68], Ok(None)));
    assert_eq!(
        gas_of(state, |s| kernel_map().get(&1, s)),
        ([386, 455], Ok(Some(100)))
    );
    // access + hash_update + hash_per_byte·2 + write + write_per_byte·4 + hash_update +
    // hash_per_byte·4
    assert_eq!(gas_of(state, |s| value().set(&9, s)), ([273, 304], Ok(())));
    assert_eq!(
        gas_of(state, |s| kernel_map().set(&1, &9, s)),
        ([284, 317], Ok(()))
    );
    // A delete is a set of 0 bytes.
    assert_eq!(gas_of(state, |s| map().delete(&2, s)), ([76, 93], Ok(())));
    // accessory_write + accessory_write_per_byte·(3 + 4), then ·3 for a delete.
    assert_eq!(
        gas_of(state, |s| accessory_map().set(&1, &9, s)),
        ([528, 558], Ok(()))
    );
    assert_eq!(
        gas_of(state, |s| accessory_map().delete(&1, s)),
        ([260, 274], Ok(()))
    );
    // event_base + event_per_byte·(8 + 8), then ·(1 + 4).
    assert_eq!(
        gas_of(state, |s| s.add_event(7, "Transfer", 5u64)),
        ([2829, 2931], Ok(()))
    );
    assert_eq!(
        gas_of(state, |s| s.add_event(7, "E", 5u32)),
        ([992, 1028], Ok(()))
    );
    // scope_open, then a 3-byte-key set inside the scope.
    assert_eq!(
        gas_of(state, |s| {
            let mut nested = s.to_revertable();
            map().set(&1, &7, &mut nested)?;
            nested.commit().map(drop)
        }),
        ([357, 396], Ok(()))
    );
    assert!(!state.metered_view().is_poisoned());
}

/// Every transaction accessor charges the cost the formula names, in each dimension (P5-17's
/// known answers, with costs that tell the terms apart; P5-14's event charge reads
/// `event_base`/`event_per_byte`).
#[test]
fn every_accessor_charges_the_named_costs() {
    known_answers(&mut working_set());

    let mut ws = working_set();
    known_answers(&mut ws.to_revertable());

    let mut ws = working_set();
    let mut nested = ws.to_revertable();
    known_answers(&mut nested.to_revertable());

    let checkpoint = MockKernel::checkpoint(storage_at_genesis(), ArrayWitness::default());
    known_answers(&mut GenesisStateAccessor::<D>::new(checkpoint).unwrap());

    let mut pre = PreExecWorkingSet::new(scratchpad(), meter());
    assert_eq!(
        gas_of(&mut pre, |s| value().get(s)),
        ([375, 442], Ok(Some(5)))
    );
    assert_eq!(
        gas_of(&mut pre, |s| map().set(&1, &9, s)),
        ([284, 317], Ok(()))
    );
}

/// The metered utilities' spec-driven constructors read their own costs: `MeteredReader::new`
/// and `metered_from_slice` `decode_per_byte` per byte, `MeteredHasher`
/// `hash_update + hash_per_byte·n`.
#[test]
fn metered_utilities_charge_the_named_costs() {
    use std::io::Read;

    let mut ws = working_set();
    let data = [7u8; 20];
    let (used, read) = gas_of(&mut ws, |s| {
        let mut out = Vec::new();
        MeteredReader::new(data.as_slice(), s)
            .read_to_end(&mut out)
            .map(|_| out)
    });
    assert_eq!(used, [940, 1060]);
    assert_eq!(read.unwrap(), data);

    let bytes = borsh::to_vec(&(1u32, 2u32)).unwrap();
    assert_eq!(
        gas_of(&mut ws, |s| <(u32, u32)>::metered_from_slice(&bytes, s)
            .ok()),
        ([376, 424], Some((1, 2)))
    );

    let (used, hash) = gas_of(&mut ws, |s| MeteredHasher::digest(&[1; 32], s));
    assert_eq!(used, [357, 423]);
    hash.unwrap();
}
