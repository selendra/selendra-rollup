//! Metered state access against the test storage: gas known answers, poison, the revert
//! layering, scopes, the journal, the view, and a prover/verifier replay with random budgets.

use std::mem::ManuallyDrop;

use proptest::collection::vec as prop_vec;
use proptest::prelude::any;
use selendra_interface::common::{RollupHeight, VisibleSlotNumber};

use super::*;
use crate::test_state::UnwrapInfallible;
use crate::test_storage::TestStorage;
use crate::test_utils::{Op, accessory_map, kernel_map, map, run, value, vec};
use crate::{
    ArrayWitness, BorshCodec, CheckpointVersions, KernelStateValue, Namespace, Prefix, SlotKey,
    SlotValue, StateAccesses, StateCheckpoint, StateReader, StateValue, StateWriter, User,
    VersionReader, Witness,
};

// -------------------------------------------------------------------------------------------
// The meter and costs of these tests

/// A one-dimensional meter with a budget.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Meter {
    remaining: u64,
    used: u64,
}

impl Meter {
    fn new(budget: u64) -> Self {
        Self {
            remaining: budget,
            used: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("out of gas: {needed} needed, {remaining} left")]
struct OutOfGas {
    needed: u64,
    remaining: u64,
}

impl StateGasMeter for Meter {
    type Gas = u64;
    type Error = OutOfGas;

    fn charge(&mut self, gas: u64) -> Result<(), OutOfGas> {
        let Some(remaining) = self.remaining.checked_sub(gas) else {
            return Err(OutOfGas {
                needed: gas,
                remaining: self.remaining,
            });
        };
        self.remaining = remaining;
        self.used += gas;
        Ok(())
    }
}

/// Distinct costs, so that every term of a formula shows in its known answer.
const COSTS: StateAccessCosts<u64> = StateAccessCosts {
    access: 2,
    hash_update: 30,
    hash_per_byte: 10,
    read: 3,
    read_per_byte: 5,
    write: 7,
    write_per_byte: 11,
    decode_per_byte: 13,
    accessory_write: 17,
    accessory_write_per_byte: 19,
    scope_open: 23,
};

type Tx<R = TxRights> = MeteredTx<TestStorage, Meter, R>;
type Ref<'a, R = TxRights> = MeteredRef<'a, TestStorage, Meter, R>;
type Error = StateAccessError<OutOfGas>;

/// A storage holding the `value()` 5, `map()` {1: 10, 2: 20}, `kernel_map()` {1: 100} and
/// `vec()` [0, 1, 2, 3].
fn storage() -> TestStorage {
    TestStorage::default().commit_with(|state| {
        value().set(&5, state).unwrap_infallible();
        map().set(&1, &10, state).unwrap_infallible();
        map().set(&2, &20, state).unwrap_infallible();
        kernel_map().set(&1, &100, state).unwrap_infallible();
        for i in 0..4 {
            vec().push(&i, state).unwrap_infallible();
        }
    })
}

fn scratchpad(storage: TestStorage) -> TxScratchpad<TestStorage> {
    TxScratchpad::new(StateCheckpoint::new(storage))
}

fn new_tx<R: AccessRights>(storage: TestStorage, budget: u64) -> Tx<R> {
    MeteredTx::new(scratchpad(storage), Meter::new(budget), COSTS)
}

/// The gas used by `f` on a fresh phase over [`storage`] with an unlimited budget, and its
/// result.
fn gas_of<T>(f: impl FnOnce(&mut Ref<'_>) -> T) -> (u64, T) {
    let mut tx = new_tx::<TxRights>(storage(), u64::MAX);
    let result = f(&mut tx.metered());
    (tx.metered_view().meter().used, result)
}

/// What [`finalize_and_freeze`] returns: the outcome, the accesses, the accessory writes and
/// the witness.
type Frozen = (
    PhaseOutcome<OutOfGas, &'static str>,
    StateAccesses,
    Vec<(SlotKey, Option<SlotValue>)>,
    ArrayWitness,
);

/// Finalizes `tx` with `result`, commits the scratchpad and freezes the checkpoint.
fn finalize_and_freeze<R: AccessRights>(tx: Tx<R>, result: Result<(), &'static str>) -> Frozen {
    let finalized = tx.finalize(result);
    let (accesses, accessory, witness) = finalized.scratchpad.commit().freeze();
    (finalized.outcome, accesses, accessory.freeze(), witness)
}

fn writes(accesses: &StateAccesses) -> usize {
    accesses.user.ordered_writes.len() + accesses.kernel.ordered_writes.len()
}

/// `MeteredTx::journal_len` and `journal_depth` for the tests.
impl<St: crate::Storage, M: StateGasMeter, R: AccessRights> MeteredTx<St, M, R> {
    fn journal_len(&mut self) -> usize {
        self.metered().tx.scratchpad.journal().len()
    }

    /// The number of open scopes, the base scope included.
    fn journal_depth(&mut self) -> usize {
        self.metered().tx.scratchpad.journal().depth()
    }
}

// -------------------------------------------------------------------------------------------
// Regressions of upstream's state-gas bugs

/// P5-15: upstream's state-gas formula tests were all `#[ignore]`d. Known answers, computed
/// independently from the formulas with [`COSTS`] (`python3 -I -c '…'`): key length `k` bytes
/// (prefix included), value `n` bytes.
#[test]
fn state_access_gas_known_answers() {
    let value_key = value().slot_key(); // k = 2, n = 4 (a borsh `u32`)
    let map_key = map().slot_key(&1); // k = 3, n = 4
    let absent_map_key = map().slot_key(&3);
    let kernel_key = kernel_map().slot_key(&1);
    let raw = |key: SlotKey| move |state: &mut Ref<'_>| StateReader::<User>::get(state, &key);

    // get: access + hash_update + hash_per_byte·k + read, then (present)
    // read_per_byte·n + hash_update + hash_per_byte·n.
    assert_eq!(gas_of(raw(value_key.clone())).0, 145);
    assert_eq!(gas_of(raw(map_key.clone())).0, 155);
    // An absent value: the key part only. One more key byte: one more hash_per_byte.
    assert_eq!(gas_of(raw(absent_map_key)).0, 65);
    assert_eq!(gas_of(|state| value().delete(state)).0, 89);
    assert_eq!(
        gas_of(|state| {
            value().delete(state).unwrap();
            StateReader::<User>::get(state, &value_key)
        })
        .0,
        89 + 55
    );
    // get_decoded (every typed container read): + decode_per_byte·n.
    assert_eq!(gas_of(|state| value().get(state)).0, 197);
    // set: access + hash_update + hash_per_byte·k + write + write_per_byte·n + hash_update +
    // hash_per_byte·n; delete: the same with n = 0.
    assert_eq!(gas_of(|state| value().set(&9, state)).0, 173);
    assert_eq!(gas_of(|state| map().set(&1, &9, state)).0, 183);
    // Kernel: the same formulas.
    assert_eq!(gas_of(|state| kernel_map().set(&1, &9, state)).0, 183);
    assert_eq!(
        gas_of(|state| StateReader::<crate::Kernel>::get(state, &kernel_key)).0,
        155
    );
    // Accessory: accessory_write + accessory_write_per_byte·(k + n).
    assert_eq!(gas_of(|state| accessory_map().set(&1, &9, state)).0, 150);
    assert_eq!(gas_of(|state| accessory_map().delete(&1, state)).0, 74);
    // A warm read (a journal hit) costs the full formula.
    assert_eq!(
        gas_of(|state| {
            value().set(&9, state).unwrap();
            StateReader::<User>::get(state, &value_key)
        })
        .0,
        173 + 145
    );
    // `StateVec::get` reads the length (k = 2, n = 8) and then the element (k = 10, n = 4).
    assert_eq!(
        gas_of(|state| vec().get(1, state)).0,
        205 + 8 * 13 + 225 + 4 * 13
    );
    // Opening a scope: scope_open; closing it is free, so a scope around a write adds
    // exactly scope_open.
    assert_eq!(gas_of(|state| state.open_scope()).0, 23);
    assert_eq!(
        gas_of(|state| {
            let token = state.open_scope();
            map().set(&1, &9, &mut state.metered().scoped(&token))?;
            state.close_scope(token, ScopeEnd::Commit)
        }),
        (206, Ok(()))
    );
    assert_eq!(
        gas_of(|state| {
            let outer = state.open_scope();
            let inner = state.metered().scoped(&outer).open_scope();
            value().set(&9, &mut state.metered().scoped(&inner))?;
            state
                .metered()
                .scoped(&outer)
                .close_scope(inner, ScopeEnd::Revert)?;
            state.close_scope(outer, ScopeEnd::Commit)
        }),
        (219, Ok(()))
    );
}

/// TODO.md: the metered `get_decoded` of an N-byte value costs exactly N × `decode_per_byte`
/// more than `get`.
#[test]
fn get_decoded_costs_decode_per_byte_more() {
    let big = || StateValue::<Vec<u8>>::with_codec(Prefix::new(7, 0), BorshCodec);
    let storage = TestStorage::default().commit_with(|state| {
        big().set(&vec![1; 996], state).unwrap_infallible(); // 1000 bytes with the length
    });
    let gas = |decoded: bool| {
        let mut tx = new_tx::<TxRights>(storage.clone(), u64::MAX);
        let mut state = tx.metered();
        let value = if decoded {
            big().get(&mut state).unwrap().map(|v| v.len())
        } else {
            StateReader::<User>::get(&mut state, &big().slot_key())
                .unwrap()
                .map(|v| v.len() - 4)
        };
        assert_eq!(value, Some(996));
        tx.metered_view().meter().used
    };
    assert_eq!(gas(true) - gas(false), 13_000);
}

/// P5-14: upstream charged nothing for accessory writes, which cost guest memory and node
/// storage.
#[test]
fn accessory_write_is_charged() {
    let (gas, result) = gas_of(|state| accessory_map().set(&1, &9, state));
    result.unwrap();
    assert_eq!(gas, 150);
    // Out of gas: refused, nothing written.
    let mut tx = new_tx::<TxRights>(storage(), 149);
    let err = accessory_map().set(&1, &9, &mut tx.metered()).unwrap_err();
    assert!(matches!(err, StateAccessError::OutOfGas { .. }), "{err:?}");
    assert_eq!(tx.journal_len(), 0);
    let (outcome, _, accessory, _) = finalize_and_freeze(tx, Ok(()));
    assert!(matches!(outcome, PhaseOutcome::Reverted(_)));
    assert!(accessory.is_empty());
}

/// P5-13 (state side): upstream's accessors did not remember a failure, so a module that
/// swallowed an out-of-gas error and returned `Ok` had its partial writes committed. Now the
/// failure poisons the phase: later accesses fail before touching the meter or storage (no gas,
/// no witness hint), and the phase is reverted even though the module returned `Ok`.
#[test]
fn swallowed_out_of_gas_reverts_tx() {
    // Enough for the write and the key part of the read (the value part runs out after the
    // size query, which adds a hint).
    let budget = 183 + 65;
    let run = |swallow_and_continue: bool| {
        let mut tx = new_tx::<TxRights>(storage(), budget);
        let mut state = tx.metered();
        map().set(&3, &30, &mut state).unwrap();
        let err = map().get(&1, &mut state).unwrap_err();
        assert!(
            matches!(
                &err,
                StateAccessError::OutOfGas {
                    op: StateOp::Read { .. },
                    ..
                }
            ),
            "{err:?}"
        );
        if swallow_and_continue {
            // A module ignoring the error and carrying on.
            assert_eq!(value().get(&mut state), Err(Error::Poisoned));
            assert_eq!(map().set(&4, &40, &mut state), Err(Error::Poisoned));
            assert_eq!(state.charge(0), Err(Error::Poisoned));
            assert!(state.view().is_poisoned());
        }
        let used = tx.metered_view().meter().used;
        let (outcome, accesses, _, witness) = finalize_and_freeze(tx, Ok(()));
        (used, outcome, writes(&accesses), witness.len())
    };
    let (used, outcome, writes, hints) = run(true);
    assert_eq!((used, outcome.clone(), writes, hints), {
        let (used, outcome, writes, hints) = run(false);
        (used, outcome, writes, hints)
    });
    assert_eq!(used, 183 + 65);
    assert_eq!(hints, 1);
    assert_eq!(writes, 0);
    let PhaseOutcome::Reverted(RevertReason::Poisoned(StateAccessError::OutOfGas { op, .. })) =
        outcome
    else {
        panic!("{outcome:?}")
    };
    assert_eq!(
        op,
        StateOp::Read {
            namespace: Namespace::User,
            key: map().slot_key(&1)
        }
    );
}

/// P5-13: out of gas in the middle of `StateVec::remove` (after some of its writes) leaves no
/// write once the phase is finalized, at every budget.
#[test]
fn oog_in_vec_remove_leaves_no_write() {
    let (full, removed) = gas_of(|state| vec().remove(0, state));
    assert_eq!(removed, Ok(Some(0)));
    let mut failed_after_a_write = false;
    for budget in 0..full {
        let mut tx = new_tx::<TxRights>(storage(), budget);
        let result = vec().remove(0, &mut tx.metered());
        assert!(
            matches!(result, Err(StateAccessError::OutOfGas { .. })),
            "{budget}: {result:?}"
        );
        failed_after_a_write |= tx.journal_len() > 0;
        // The module returns `Ok` anyway.
        let (outcome, accesses, _, _) = finalize_and_freeze(tx, Ok(()));
        assert!(matches!(
            outcome,
            PhaseOutcome::Reverted(RevertReason::Poisoned(_))
        ));
        assert_eq!(writes(&accesses), 0, "{budget}");
    }
    assert!(failed_after_a_write);
    // With the full budget it is committed.
    let mut tx = new_tx::<TxRights>(storage(), full);
    assert_eq!(vec().remove(0, &mut tx.metered()), Ok(Some(0)));
    let (outcome, accesses, _, _) = finalize_and_freeze(tx, Ok(()));
    assert_eq!(outcome, PhaseOutcome::Committed);
    assert_eq!(writes(&accesses), 5); // the length, three shifts, the old last element
}

/// P5-13: out of gas inside a scope, then a revert of the scope, then `Ok`: still reverted.
/// Reverting a scope does not clear the poison.
#[test]
fn scope_revert_keeps_poison() {
    let mut tx = new_tx::<TxRights>(storage(), 183 + 60);
    map().set(&3, &30, &mut tx.metered()).unwrap();
    let token = tx.metered().open_scope();
    let err = map()
        .set(&4, &40, &mut tx.metered().scoped(&token))
        .unwrap_err();
    assert!(matches!(err, StateAccessError::OutOfGas { .. }));
    // Closing it is refused (poisoned): the scope is reverted at finalize anyway.
    assert_eq!(
        tx.metered().close_scope(token, ScopeEnd::Revert),
        Err(Error::Poisoned)
    );
    assert!(tx.metered_view().is_poisoned());
    assert_eq!(map().get(&3, &mut tx.metered()), Err(Error::Poisoned));
    let (outcome, accesses, _, _) = finalize_and_freeze(tx, Ok(()));
    assert!(matches!(
        outcome,
        PhaseOutcome::Reverted(RevertReason::Poisoned(_))
    ));
    assert_eq!(writes(&accesses), 0);
}

// -------------------------------------------------------------------------------------------
// Failures

#[test]
fn gas_overflow_poisons_without_panicking() {
    let max = StateAccessCosts {
        access: u64::MAX,
        hash_update: u64::MAX,
        hash_per_byte: u64::MAX,
        read: u64::MAX,
        read_per_byte: u64::MAX,
        write: u64::MAX,
        write_per_byte: u64::MAX,
        decode_per_byte: u64::MAX,
        accessory_write: u64::MAX,
        accessory_write_per_byte: u64::MAX,
        // One term, no arithmetic: opening a scope cannot overflow, only be refused
        // (`open_scope_out_of_gas_poisons_and_opens_nothing`).
        scope_open: u64::MAX,
    };
    type Operation = fn(&mut Ref<'_>) -> Result<(), Error>;
    let operations: [Operation; 4] = [
        |state| value().get(state).map(drop),
        |state| value().set(&1, state),
        |state| value().delete(state),
        |state| accessory_map().set(&1, &1, state),
    ];
    for operation in operations {
        let mut tx =
            MeteredTx::<_, _, TxRights>::new(scratchpad(storage()), Meter::new(u64::MAX), max);
        let err = operation(&mut tx.metered()).unwrap_err();
        assert!(
            matches!(err, StateAccessError::GasOverflow { .. }),
            "{err:?}"
        );
        assert_eq!(tx.metered_view().meter().used, 0);
        assert_eq!(operation(&mut tx.metered()), Err(Error::Poisoned));
    }
    // Only a per-byte product overflows (2^63 times at least 2 bytes), every other cost is
    // small: a wrapping multiplication would give 0 or 2^63 and no overflow at all.
    const HALF: u64 = u64::MAX / 2 + 1;
    let per_byte: [(StateAccessCosts<u64>, Operation); 5] = [
        (
            StateAccessCosts {
                hash_per_byte: HALF,
                ..COSTS
            },
            |state| value().get(state).map(drop),
        ),
        (
            StateAccessCosts {
                read_per_byte: HALF,
                ..COSTS
            },
            |state| value().get(state).map(drop),
        ),
        (
            StateAccessCosts {
                decode_per_byte: HALF,
                ..COSTS
            },
            |state| value().get(state).map(drop),
        ),
        (
            StateAccessCosts {
                write_per_byte: HALF,
                ..COSTS
            },
            |state| value().set(&1, state),
        ),
        (
            StateAccessCosts {
                accessory_write_per_byte: HALF,
                ..COSTS
            },
            |state| accessory_map().set(&1, &1, state),
        ),
    ];
    // A read charges its key part (55: `access + hash_update + hash_per_byte·2 + read`) before
    // its value part.
    let used_before_overflow = [0, 55, 55, 0, 0];
    for ((costs, operation), used) in per_byte.into_iter().zip(used_before_overflow) {
        let mut tx =
            MeteredTx::<_, _, TxRights>::new(scratchpad(storage()), Meter::new(u64::MAX), costs);
        let err = operation(&mut tx.metered()).unwrap_err();
        assert!(
            matches!(err, StateAccessError::GasOverflow { .. }),
            "{costs:?}: {err:?}"
        );
        assert_eq!(tx.metered_view().meter().used, used, "{costs:?}");
        assert_eq!(operation(&mut tx.metered()), Err(Error::Poisoned));
        assert_eq!(tx.metered_view().meter().used, used, "{costs:?}");
    }
}

/// `charge_linear(base, per_unit, units)` charges `base + per_unit·units` as one sum; more than
/// `u32::MAX` units or an overflow is `GasOverflow` (nothing charged, the phase poisoned), never
/// a panic or a wrap.
#[test]
fn charge_linear_is_one_checked_sum() {
    assert_eq!(gas_of(|state| state.charge_linear(7, 3, 5)), (22, Ok(())));
    assert_eq!(gas_of(|state| state.charge_linear(7, 3, 0)), (7, Ok(())));
    assert_eq!(
        gas_of(|state| state.charge_linear(0, 1, u64::from(u32::MAX))),
        (u64::from(u32::MAX), Ok(()))
    );
    let overflows: [(u64, u64, u64); 3] = [
        (0, 1, u64::from(u32::MAX) + 1),
        (0, u64::MAX / 2 + 1, 2),
        (1, u64::MAX, 1),
    ];
    for (base, per_unit, units) in overflows {
        let mut tx: Tx = new_tx(storage(), u64::MAX);
        assert_eq!(
            tx.metered().charge_linear(base, per_unit, units),
            Err(Error::GasOverflow {
                op: StateOp::Charge
            })
        );
        assert_eq!(tx.metered_view().meter().used, 0);
        assert_eq!(tx.metered().charge(1), Err(Error::Poisoned));
    }
    // A refused sum charges nothing and poisons.
    let mut tx: Tx = new_tx(storage(), 21);
    assert!(matches!(
        tx.metered().charge_linear(7, 3, 5),
        Err(Error::OutOfGas {
            op: StateOp::Charge,
            ..
        })
    ));
    assert_eq!(tx.metered_view().meter().used, 0);
    assert_eq!(tx.metered().charge_linear(0, 0, 0), Err(Error::Poisoned));
}

#[test]
fn value_too_large_poisons_before_charging() {
    let key = SlotKey::singleton(&Prefix::new(7, 0));
    let mut tx = new_tx::<TxRights>(storage(), u64::MAX);
    let limit = SlotValue::from(vec![0; MAX_STATE_VALUE_SIZE]);
    StateWriter::<User>::set(&mut tx.metered(), &key, limit).unwrap();
    let used = tx.metered_view().meter().used;
    let too_large = SlotValue::from(vec![0; MAX_STATE_VALUE_SIZE + 1]);
    for namespace in [Namespace::User, Namespace::Accessory] {
        let mut tx = new_tx::<TxRights>(storage(), u64::MAX);
        let result = match namespace {
            Namespace::Accessory => {
                StateWriter::<crate::Accessory>::set(&mut tx.metered(), &key, too_large.clone())
            }
            _ => StateWriter::<User>::set(&mut tx.metered(), &key, too_large.clone()),
        };
        assert_eq!(
            result,
            Err(Error::ValueTooLarge {
                op: StateOp::Write {
                    namespace,
                    key: key.clone()
                },
                len: MAX_STATE_VALUE_SIZE + 1
            })
        );
        assert_eq!(tx.metered_view().meter().used, 0);
        assert!(tx.metered_view().is_poisoned());
    }
    assert!(used > 0);
}

/// D3 / P5-13: a phase poisoned with budget left (`ValueTooLarge`, `ScopeMisuse`) charges
/// nothing more and touches no storage: later reads, writes and charges fail with `Poisoned`
/// before the meter, and add no read and no witness hint.
#[test]
fn poisoned_phase_with_budget_left_touches_nothing() {
    type Poison = fn(&mut Tx);
    let poisons: [Poison; 2] = [
        |tx| {
            let key = SlotKey::singleton(&Prefix::new(7, 0));
            let too_large = SlotValue::from(vec![0; MAX_STATE_VALUE_SIZE + 1]);
            let result = StateWriter::<User>::set(&mut tx.metered(), &key, too_large);
            assert!(
                matches!(result, Err(Error::ValueTooLarge { .. })),
                "{result:?}"
            );
        },
        |tx| {
            let outer = tx.metered().open_scope();
            let inner = tx.metered().scoped(&outer).open_scope();
            assert_eq!(
                tx.metered().close_scope(inner, ScopeEnd::Commit),
                Err(Error::ScopeMisuse)
            );
        },
    ];
    for poison in poisons {
        let mut tx: Tx = new_tx(storage(), u64::MAX);
        map().set(&3, &30, &mut tx.metered()).unwrap();
        poison(&mut tx);
        assert!(tx.metered_view().is_poisoned());
        let used = tx.metered_view().meter().used;
        assert!(used > 0);
        let depth = tx.journal_depth();
        let mut state = tx.metered();
        assert_eq!(state.charge(5), Err(Error::Poisoned));
        // `open_scope` is refused before `scope_open` is charged, and pushes no scope.
        let token = state.open_scope();
        assert_eq!(
            map().set(&5, &50, &mut state.metered().scoped(&token)),
            Err(Error::Poisoned)
        );
        assert_eq!(
            state.close_scope(token, ScopeEnd::Commit),
            Err(Error::Poisoned)
        );
        assert_eq!(map().get(&1, &mut state), Err(Error::Poisoned));
        assert_eq!(
            StateReader::<crate::Kernel>::get(&mut state, &kernel_map().slot_key(&1)),
            Err(Error::Poisoned)
        );
        assert_eq!(map().set(&4, &40, &mut state), Err(Error::Poisoned));
        assert_eq!(map().delete(&2, &mut state), Err(Error::Poisoned));
        assert_eq!(
            accessory_map().set(&4, &40, &mut state),
            Err(Error::Poisoned)
        );
        assert_eq!(tx.metered_view().meter().used, used);
        assert_eq!(tx.journal_depth(), depth);
        let (outcome, accesses, accessory, witness) = finalize_and_freeze(tx, Ok(()));
        assert!(matches!(
            outcome,
            PhaseOutcome::Reverted(RevertReason::Poisoned(_))
        ));
        assert!(accesses.user.ordered_reads.is_empty());
        assert!(accesses.kernel.ordered_reads.is_empty());
        assert_eq!(writes(&accesses), 0);
        assert!(accessory.is_empty());
        assert_eq!(witness.len(), 0);
    }
}

// -------------------------------------------------------------------------------------------
// Layering

/// A write to the scratchpad before the phase (e.g. the gas reservation) survives a poisoned
/// phase; the phase's writes do not.
#[test]
fn scratchpad_write_survives_poisoned_phase() {
    let mut scratchpad = scratchpad(storage());
    map().set(&5, &50, &mut scratchpad).unwrap_infallible();
    let mut tx: Tx = MeteredTx::new(scratchpad, Meter::new(183 + 207 + 10), COSTS);
    map().set(&3, &30, &mut tx.metered()).unwrap();
    // The phase sees the scratchpad's write.
    assert_eq!(map().get(&5, &mut tx.metered()), Ok(Some(50)));
    assert!(map().set(&4, &40, &mut tx.metered()).is_err());
    let finalized = tx.finalize(Ok::<(), ()>(()));
    assert!(matches!(
        finalized.outcome,
        PhaseOutcome::Reverted(RevertReason::Poisoned(_))
    ));
    let mut checkpoint = finalized.scratchpad.commit();
    assert_eq!(map().get(&5, &mut checkpoint).unwrap_infallible(), Some(50));
    assert_eq!(map().get(&3, &mut checkpoint).unwrap_infallible(), None);
    // The gas used is kept.
    assert_eq!(finalized.meter.used, 183 + 207);
}

/// `finalize(Err)` reverts exactly the base scope: the scratchpad's own writes stay.
#[test]
fn finalize_err_reverts_only_base_scope() {
    let mut scratchpad = scratchpad(storage());
    map().set(&5, &50, &mut scratchpad).unwrap_infallible();
    let mut tx: Tx = MeteredTx::new(scratchpad, Meter::new(u64::MAX), COSTS);
    map().set(&3, &30, &mut tx.metered()).unwrap();
    accessory_map().set(&3, &30, &mut tx.metered()).unwrap();
    let token = tx.metered().open_scope();
    map()
        .set(&4, &40, &mut tx.metered().scoped(&token))
        .unwrap();
    tx.metered().close_scope(token, ScopeEnd::Commit).unwrap();
    let finalized = tx.finalize(Err("module error"));
    assert_eq!(
        finalized.outcome,
        PhaseOutcome::Reverted(RevertReason::Module("module error"))
    );
    let mut checkpoint = finalized.scratchpad.commit();
    assert_eq!(map().get(&5, &mut checkpoint).unwrap_infallible(), Some(50));
    for key in [3, 4] {
        assert_eq!(map().get(&key, &mut checkpoint).unwrap_infallible(), None);
    }
    let (_, accessory, _) = checkpoint.freeze();
    assert!(accessory.freeze().is_empty());
}

/// Two phases on one scratchpad (pre-execution, then the call), each finalized on its own.
#[test]
fn phases_commit_into_the_scratchpad_and_the_scratchpad_into_the_checkpoint() {
    let mut pre: Tx<PreExecRights> = new_tx(storage(), u64::MAX);
    map().set(&3, &30, &mut pre.metered()).unwrap();
    let pre = pre.finalize(Ok::<(), ()>(()));
    assert_eq!(pre.outcome, PhaseOutcome::Committed);
    let mut call: Tx = MeteredTx::new(pre.scratchpad, Meter::new(u64::MAX), COSTS);
    assert_eq!(map().get(&3, &mut call.metered()), Ok(Some(30)));
    kernel_map().set(&3, &300, &mut call.metered()).unwrap();
    let call = call.finalize(Ok::<(), ()>(()));
    // The scratchpad can still be reverted as a whole.
    let mut checkpoint = call.scratchpad.revert();
    assert_eq!(map().get(&3, &mut checkpoint).unwrap_infallible(), None);
    assert_eq!(
        kernel_map().get(&3, &mut checkpoint).unwrap_infallible(),
        None
    );
}

// -------------------------------------------------------------------------------------------
// Scopes

#[test]
fn nested_scopes_commit_and_revert() {
    let mut tx: Tx = new_tx(storage(), u64::MAX);
    let outer = tx.metered().open_scope();
    map()
        .set(&3, &30, &mut tx.metered().scoped(&outer))
        .unwrap();
    let inner = tx.metered().scoped(&outer).open_scope();
    {
        let mut state = tx.metered().scoped(&inner);
        map().set(&3, &31, &mut state).unwrap();
        map().set(&4, &40, &mut state).unwrap();
        // Read-your-writes inside the scope.
        assert_eq!(map().get(&3, &mut state), Ok(Some(31)));
    }
    tx.metered()
        .scoped(&outer)
        .close_scope(inner, ScopeEnd::Revert)
        .unwrap();
    {
        let mut state = tx.metered().scoped(&outer);
        assert_eq!(map().get(&3, &mut state), Ok(Some(30)));
        assert_eq!(map().get(&4, &mut state), Ok(None));
    }
    let inner = tx.metered().scoped(&outer).open_scope();
    map()
        .set(&4, &41, &mut tx.metered().scoped(&inner))
        .unwrap();
    tx.metered()
        .scoped(&outer)
        .close_scope(inner, ScopeEnd::Commit)
        .unwrap();
    tx.metered().close_scope(outer, ScopeEnd::Commit).unwrap();
    let finalized = tx.finalize(Ok::<(), ()>(()));
    assert_eq!(finalized.outcome, PhaseOutcome::Committed);
    let mut checkpoint = finalized.scratchpad.commit();
    assert_eq!(map().get(&3, &mut checkpoint).unwrap_infallible(), Some(30));
    assert_eq!(map().get(&4, &mut checkpoint).unwrap_infallible(), Some(41));
}

/// Closing a scope that is not the innermost one directly inside the accessor is
/// `ScopeMisuse`, poisons the phase, and never panics.
#[test]
fn closing_a_non_top_token_is_scope_misuse() {
    // Out of order: the outer scope through the base while the inner one is open... is fine
    // (the inner one is reverted first); the inner scope through the base is not.
    let mut tx: Tx = new_tx(storage(), u64::MAX);
    let outer = tx.metered().open_scope();
    let inner = tx.metered().scoped(&outer).open_scope();
    assert_eq!(
        tx.metered().close_scope(inner, ScopeEnd::Commit),
        Err(Error::ScopeMisuse)
    );
    assert!(tx.metered_view().is_poisoned());
    assert_eq!(
        tx.metered().close_scope(outer, ScopeEnd::Commit),
        Err(Error::Poisoned)
    );
    let finalized = tx.finalize(Ok::<(), ()>(()));
    assert_eq!(
        finalized.outcome,
        PhaseOutcome::Reverted(RevertReason::Poisoned(Error::ScopeMisuse))
    );

    // A sibling: the first scope was reverted by an access through the base.
    let mut tx: Tx = new_tx(storage(), u64::MAX);
    let first = tx.metered().open_scope();
    map().set(&3, &30, &mut tx.metered()).unwrap();
    assert_eq!(
        tx.metered().close_scope(first, ScopeEnd::Commit),
        Err(Error::ScopeMisuse)
    );

    // The scope of the accessor itself.
    let mut tx: Tx = new_tx(storage(), u64::MAX);
    let scope = tx.metered().open_scope();
    let mut state = tx.metered().scoped(&scope);
    assert_eq!(
        state.close_scope(scope, ScopeEnd::Commit),
        Err(Error::ScopeMisuse)
    );
}

/// A token of an earlier phase on the same checkpoint never matches a scope of this one,
/// even at the same depth.
#[test]
fn token_from_an_earlier_phase_is_scope_misuse() {
    let mut first: Tx = new_tx(storage(), u64::MAX);
    let stale = first.metered().open_scope();
    let first = first.finalize(Ok::<(), ()>(()));
    let mut second: Tx = MeteredTx::new(first.scratchpad, Meter::new(u64::MAX), COSTS);
    let current = second.metered().open_scope();
    map()
        .set(&3, &30, &mut second.metered().scoped(&current))
        .unwrap();
    assert_eq!(
        second.metered().close_scope(stale, ScopeEnd::Commit),
        Err(Error::ScopeMisuse)
    );
    assert!(second.metered_view().is_poisoned());

    // Narrowing to it gives an accessor that fails.
    let mut first: Tx = new_tx(storage(), u64::MAX);
    let stale = first.metered().open_scope();
    let first = first.finalize(Ok::<(), ()>(()));
    let mut second: Tx = MeteredTx::new(first.scratchpad, Meter::new(u64::MAX), COSTS);
    let current = second.metered().open_scope();
    assert_eq!(
        map().get(&1, &mut second.metered().scoped(&stale)),
        Err(Error::ScopeMisuse)
    );
    assert_eq!(
        second.metered().close_scope(current, ScopeEnd::Commit),
        Err(Error::Poisoned)
    );
}

/// A token of a phase on another checkpoint, alive at the same time, never matches a scope of
/// this phase, although its depth and serial number are the same: closing it is
/// `ScopeMisuse` and poisons this phase only, and narrowing to it gives an accessor that
/// fails.
#[test]
fn token_from_another_checkpoints_phase_is_scope_misuse() {
    let mut first: Tx = new_tx(storage(), u64::MAX);
    let mut second: Tx = new_tx(storage(), u64::MAX);
    let foreign = first.metered().open_scope();
    let own = second.metered().open_scope();
    assert_eq!(foreign.level(), own.level());
    map()
        .set(&3, &30, &mut second.metered().scoped(&own))
        .unwrap();
    assert_eq!(
        second.metered().close_scope(foreign, ScopeEnd::Commit),
        Err(Error::ScopeMisuse)
    );
    assert!(second.metered_view().is_poisoned());
    assert!(!first.metered_view().is_poisoned());
    let (outcome, accesses, _, _) = finalize_and_freeze(second, Ok(()));
    assert_eq!(
        outcome,
        PhaseOutcome::Reverted(RevertReason::Poisoned(Error::ScopeMisuse))
    );
    assert_eq!(writes(&accesses), 0);
    // The first phase is unaffected.
    assert_eq!(first.journal_depth(), 2);

    // Narrowing to it.
    let mut first: Tx = new_tx(storage(), u64::MAX);
    let mut second: Tx = new_tx(storage(), u64::MAX);
    let foreign = first.metered().open_scope();
    let own = second.metered().open_scope();
    assert_eq!(foreign.level(), own.level());
    assert_eq!(
        map().set(&3, &30, &mut second.metered().scoped(&foreign)),
        Err(Error::ScopeMisuse)
    );
    assert!(second.metered_view().is_poisoned());
    assert_eq!(second.journal_len(), 0);
    assert!(!first.metered_view().is_poisoned());
}

/// A phase stays `Send` (its identity is an `Arc` where the target has pointer-sized atomics);
/// its scope tokens are not (`compile_fail` doctest on `ScopeToken`).
#[cfg(target_has_atomic = "ptr")]
#[test]
fn phase_is_send() {
    fn send<T: Send>() {}
    send::<Tx>();
    send::<Tx<PreExecRights>>();
}

/// Opening a scope charges `scope_open` before pushing the scope: a refused charge poisons the
/// phase, opens nothing, and the token matches no scope.
#[test]
fn open_scope_out_of_gas_poisons_and_opens_nothing() {
    let mut tx: Tx = new_tx(storage(), 183 + COSTS.scope_open - 1);
    map().set(&3, &30, &mut tx.metered()).unwrap();
    let token = tx.metered().open_scope();
    assert!(tx.metered_view().is_poisoned());
    assert_eq!(tx.metered_view().meter().used, 183);
    assert_eq!(tx.journal_depth(), 1);
    assert_eq!(
        map().set(&4, &40, &mut tx.metered().scoped(&token)),
        Err(Error::Poisoned)
    );
    assert_eq!(
        tx.metered().close_scope(token, ScopeEnd::Commit),
        Err(Error::Poisoned)
    );
    assert_eq!(tx.metered_view().meter().used, 183);
    let (outcome, accesses, _, _) = finalize_and_freeze(tx, Ok(()));
    assert_eq!(
        outcome,
        PhaseOutcome::Reverted(RevertReason::Poisoned(Error::OutOfGas {
            op: StateOp::OpenScope,
            source: OutOfGas {
                needed: COSTS.scope_open,
                remaining: COSTS.scope_open - 1
            }
        }))
    );
    assert_eq!(writes(&accesses), 0);

    // The same budget plus one opens it.
    let mut tx: Tx = new_tx(storage(), 183 + COSTS.scope_open);
    map().set(&3, &30, &mut tx.metered()).unwrap();
    let token = tx.metered().open_scope();
    assert!(!tx.metered_view().is_poisoned());
    assert_eq!(tx.journal_depth(), 2);
    tx.metered().close_scope(token, ScopeEnd::Commit).unwrap();
}

/// Opening a scope through an accessor whose scope is no longer open is `ScopeMisuse` before
/// `scope_open` is charged: no gas, and the recorded failure is `ScopeMisuse` even when the
/// budget could not pay for the scope.
#[test]
fn open_scope_through_a_stale_accessor_charges_nothing() {
    let mut tx: Tx = new_tx(storage(), 2 * COSTS.scope_open);
    let outer = tx.metered().open_scope();
    let inner = tx.metered().scoped(&outer).open_scope();
    // Closing `outer` reverts `inner` (closing is free): the budget is spent.
    tx.metered().close_scope(outer, ScopeEnd::Revert).unwrap();
    assert!(!tx.metered_view().is_poisoned());
    assert_eq!(tx.metered_view().meter().used, 2 * COSTS.scope_open);
    assert_eq!(tx.journal_depth(), 1);

    let token = tx.metered().scoped(&inner).open_scope();
    assert!(tx.metered_view().is_poisoned());
    assert_eq!(tx.metered_view().meter().used, 2 * COSTS.scope_open);
    assert_eq!(tx.journal_depth(), 1);
    assert_eq!(
        tx.metered().close_scope(token, ScopeEnd::Commit),
        Err(Error::Poisoned)
    );
    let (outcome, accesses, _, _) = finalize_and_freeze(tx, Ok(()));
    assert_eq!(
        outcome,
        PhaseOutcome::Reverted(RevertReason::Poisoned(Error::ScopeMisuse))
    );
    assert_eq!(writes(&accesses), 0);
}

/// Narrowing an accessor to a scope that is not inside its own (the enclosing scope, or its
/// own) gives an accessor that fails with `ScopeMisuse`, instead of reverting the inner scope
/// and writing into the enclosing one.
#[test]
fn narrowing_to_a_scope_not_inside_the_accessor_is_scope_misuse() {
    // The enclosing scope.
    let mut tx: Tx = new_tx(storage(), u64::MAX);
    let outer = tx.metered().open_scope();
    let inner = tx.metered().scoped(&outer).open_scope();
    map()
        .set(&4, &40, &mut tx.metered().scoped(&inner))
        .unwrap();
    assert_eq!(
        map().set(&3, &30, &mut tx.metered().scoped(&inner).scoped(&outer)),
        Err(Error::ScopeMisuse)
    );
    assert!(tx.metered_view().is_poisoned());
    let (outcome, accesses, _, _) = finalize_and_freeze(tx, Ok(()));
    assert_eq!(
        outcome,
        PhaseOutcome::Reverted(RevertReason::Poisoned(Error::ScopeMisuse))
    );
    assert_eq!(writes(&accesses), 0);

    // Its own scope.
    let mut tx: Tx = new_tx(storage(), u64::MAX);
    let scope = tx.metered().open_scope();
    assert_eq!(
        map().get(&1, &mut tx.metered().scoped(&scope).scoped(&scope)),
        Err(Error::ScopeMisuse)
    );
    assert!(tx.metered_view().is_poisoned());
}

/// A guard over a nested scope, like `selendra-modules-api`'s `RevertableTxState`: dropping it
/// reverts the scope.
struct Guard<'a> {
    parent: Ref<'a>,
    token: Option<ScopeToken>,
}

impl<'a> Guard<'a> {
    fn new(mut parent: Ref<'a>) -> Self {
        let token = parent.open_scope();
        Self {
            parent,
            token: Some(token),
        }
    }
}

impl Metered for Guard<'_> {
    type Storage = TestStorage;
    type Meter = Meter;
    type Rights = TxRights;

    fn metered(&mut self) -> Ref<'_> {
        let token = self.token.as_ref().expect("open until dropped");
        self.parent.metered().scoped(token)
    }

    fn metered_view(&self) -> MeteredView<'_, Meter> {
        self.parent.view()
    }
}

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() {
            let _ = self.parent.close_scope(token, ScopeEnd::Revert);
        }
    }
}

/// A leaked scope guard (`ManuallyDrop`, `Box::leak`: not caught by the `mem_forget` lint) is
/// reverted by the next access through its parent, and at `finalize`: fail-closed.
#[test]
fn leaked_scope_is_reverted() {
    // The next access through the parent.
    let mut tx: Tx = new_tx(storage(), u64::MAX);
    {
        let mut guard = ManuallyDrop::new(Guard::new(tx.metered()));
        map().set(&3, &30, &mut *guard).unwrap();
        assert_eq!(map().get(&3, &mut *guard), Ok(Some(30)));
    }
    assert_eq!(map().get(&3, &mut tx.metered()), Ok(None));
    assert!(!tx.metered_view().is_poisoned());
    let (outcome, accesses, _, _) = finalize_and_freeze(tx, Ok(()));
    assert_eq!(outcome, PhaseOutcome::Committed);
    assert_eq!(writes(&accesses), 0);

    // Nested: a leaked inner guard is reverted when the outer one is accessed or dropped.
    let mut tx: Tx = new_tx(storage(), u64::MAX);
    {
        let mut outer = Guard::new(tx.metered());
        map().set(&3, &30, &mut outer).unwrap();
        {
            let inner = Box::leak(Box::new(Guard::new(outer.metered())));
            map().set(&4, &40, inner).unwrap();
        }
        assert_eq!(map().get(&4, &mut outer), Ok(None));
        assert_eq!(map().get(&3, &mut outer), Ok(Some(30)));
        let token = outer.token.take().unwrap();
        outer.parent.close_scope(token, ScopeEnd::Commit).unwrap();
    }
    let (_, accesses, _, _) = finalize_and_freeze(tx, Ok(()));
    assert_eq!(accesses.user.ordered_writes.len(), 1);

    // At finalize.
    let mut tx: Tx = new_tx(storage(), u64::MAX);
    map().set(&5, &50, &mut tx.metered()).unwrap();
    {
        let guard = Box::leak(Box::new(Guard::new(tx.metered())));
        map().set(&3, &30, guard).unwrap();
        accessory_map().set(&3, &30, guard).unwrap();
    }
    let (outcome, accesses, accessory, _) = finalize_and_freeze(tx, Ok(()));
    assert_eq!(outcome, PhaseOutcome::Committed);
    assert_eq!(
        accesses.user.ordered_writes,
        [(
            map().slot_key(&5),
            Some(SlotValue::from(borsh::to_vec(&50u32).unwrap()))
        )]
    );
    assert!(accessory.is_empty());
}

/// Dropping a guard reverts its scope; an accessor narrowed to a reverted scope fails.
#[test]
fn dropped_guard_reverts_and_stale_accessor_fails() {
    let mut tx: Tx = new_tx(storage(), u64::MAX);
    {
        let mut guard = Guard::new(tx.metered());
        map().set(&3, &30, &mut guard).unwrap();
    }
    assert_eq!(map().get(&3, &mut tx.metered()), Ok(None));

    let token = tx.metered().open_scope();
    map().get(&1, &mut tx.metered()).unwrap(); // reverts the scope
    assert_eq!(
        map().get(&1, &mut tx.metered().scoped(&token)),
        Err(Error::ScopeMisuse)
    );
    assert!(tx.metered_view().is_poisoned());
}

// -------------------------------------------------------------------------------------------
// The journal and the scratchpad

#[test]
fn scratchpad_reads_its_writes_and_commits_or_reverts() {
    let mut scratchpad = scratchpad(storage());
    assert_eq!(map().get(&1, &mut scratchpad).unwrap_infallible(), Some(10));
    map().set(&1, &11, &mut scratchpad).unwrap_infallible();
    map().delete(&2, &mut scratchpad).unwrap_infallible();
    assert_eq!(map().get(&1, &mut scratchpad).unwrap_infallible(), Some(11));
    assert_eq!(map().get(&2, &mut scratchpad).unwrap_infallible(), None);
    assert_eq!(
        kernel_map().get(&1, &mut scratchpad).unwrap_infallible(),
        Some(100)
    );
    assert_eq!(
        scratchpad.max_allowed_slot_number_to_access(),
        CheckpointVersions::GENESIS.visible_slot_number.as_true()
    );
    let (reverted, _, _) = scratchpad.revert().freeze();
    assert_eq!(writes(&reverted), 0);
    // The reads stay recorded (verified against the root).
    assert_eq!(reverted.user.ordered_reads.len(), 1);
    assert_eq!(reverted.kernel.ordered_reads.len(), 1);

    let mut scratchpad = self::scratchpad(storage());
    map().set(&2, &21, &mut scratchpad).unwrap_infallible();
    map().set(&1, &11, &mut scratchpad).unwrap_infallible();
    let (committed, _, _) = scratchpad.commit().freeze();
    assert_eq!(
        committed.user.ordered_writes,
        [1u8, 2].map(|k| (
            map().slot_key(&k),
            Some(SlotValue::from(
                borsh::to_vec(&(u32::from(k) * 10 + 1)).unwrap()
            ))
        ))
    );
}

/// Accessory writes go into the journal: a reverted phase or scratchpad leaves none behind
/// (upstream wrote them to the checkpoint directly).
#[test]
fn accessory_writes_are_reverted() {
    for revert_phase in [true, false] {
        let mut tx: Tx = new_tx(storage(), u64::MAX);
        accessory_map().set(&1, &9, &mut tx.metered()).unwrap();
        accessory_map().delete(&2, &mut tx.metered()).unwrap();
        let result = if revert_phase { Err(()) } else { Ok(()) };
        let finalized = tx.finalize(result);
        // Committed phase, reverted scratchpad: none either.
        let (_, accessory, _) = finalized.scratchpad.revert().freeze();
        assert!(accessory.freeze().is_empty());
    }
    let mut tx: Tx = new_tx(storage(), u64::MAX);
    accessory_map().set(&1, &9, &mut tx.metered()).unwrap();
    accessory_map().delete(&2, &mut tx.metered()).unwrap();
    let (_, _, accessory, _) = finalize_and_freeze(tx, Ok(()));
    assert_eq!(
        accessory,
        [
            (
                accessory_map().slot_key(&1),
                Some(SlotValue::from(borsh::to_vec(&9u32).unwrap()))
            ),
            (accessory_map().slot_key(&2), None)
        ]
    );
}

/// Reads of written keys come from the journal: no checkpoint access, no hint.
#[test]
fn journal_hits_touch_no_storage() {
    let mut tx: Tx = new_tx(storage(), u64::MAX);
    map().set(&1, &11, &mut tx.metered()).unwrap();
    value().delete(&mut tx.metered()).unwrap();
    assert_eq!(map().get(&1, &mut tx.metered()), Ok(Some(11)));
    assert_eq!(value().get(&mut tx.metered()), Ok(None));
    let (_, accesses, _, witness) = finalize_and_freeze(tx, Ok(()));
    assert!(accesses.user.ordered_reads.is_empty());
    assert_eq!(witness.len(), 0);
}

// -------------------------------------------------------------------------------------------
// The view

#[test]
fn metered_view_reads_versions_and_meter_from_a_shared_ref() {
    let height = KernelStateValue::<u64>::with_codec(Prefix::new(9, 0), BorshCodec);
    let storage = TestStorage::default().commit_with(|state| {
        height.clone().set(&42, state).unwrap_infallible();
    });
    let checkpoint = StateCheckpoint::new_with(storage, Default::default(), |reader| {
        let Ok(height) = height.get(reader);
        CheckpointVersions {
            visible_slot_number: VisibleSlotNumber::new_dangerous(7),
            rollup_height: RollupHeight::new(height.unwrap_or(0)),
        }
    });
    let mut tx: Tx = MeteredTx::new(TxScratchpad::new(checkpoint), Meter::new(1000), COSTS);
    let mut guard = Guard::new(tx.metered());
    map().set(&3, &30, &mut guard).unwrap();
    // `&self` only.
    let shared: &Guard<'_> = &guard;
    assert_eq!(shared.rollup_height_to_access(), RollupHeight::new(42));
    assert_eq!(
        shared.current_visible_slot_number(),
        VisibleSlotNumber::new_dangerous(7)
    );
    assert_eq!(
        shared.max_allowed_slot_number_to_access(),
        VisibleSlotNumber::new_dangerous(7).as_true()
    );
    let view = shared.metered_view();
    // The guard's scope (`scope_open`) and the write.
    assert_eq!(
        view.meter(),
        &Meter {
            remaining: 1000 - 23 - 183,
            used: 23 + 183
        }
    );
    assert!(!view.is_poisoned());
    assert_eq!(view.versions().rollup_height, RollupHeight::new(42));
}

// -------------------------------------------------------------------------------------------
// Replay

/// One step of a metered phase: a container operation through the innermost scope (`Commit`
/// and `Discard` close it instead; the size queries are plain reads), opening a scope,
/// forgetting the innermost one (a leak), an access through the enclosing scope, or a charge.
#[derive(Debug, Clone, test_strategy::Arbitrary)]
enum TxOp {
    State(Op),
    Open,
    Leak,
    Outer(Op),
    Charge(#[strategy(0u64..300)] u64),
}

/// The accessor of the innermost of `tokens` (the base if none).
fn innermost<'a>(tx: &'a mut Tx, tokens: &[ScopeToken]) -> Ref<'a> {
    match tokens.last() {
        Some(token) => tx.metered().scoped(token),
        None => tx.metered(),
    }
}

fn run_op(op: &Op, state: &mut Ref<'_>) -> String {
    let (mut value, mut map, mut vec, mut kernel, mut accessory) =
        (value(), map(), vec(), kernel_map(), accessory_map());
    match op {
        Op::ValueSet(v) => format!("{:?}", value.set(v, state)),
        Op::ValueGet => format!("{:?}", value.get(state)),
        Op::ValueRemove => format!("{:?}", value.remove(state)),
        Op::ValueDelete => format!("{:?}", value.delete(state)),
        Op::MapSet(k, v) => format!("{:?}", map.set(k, v, state)),
        Op::MapGet(k) => format!("{:?}", map.get(k, state)),
        Op::MapRemove(k) => format!("{:?}", map.remove(k, state)),
        Op::MapSetIfAbsent(k, v) => format!("{:?}", map.set_if_absent(k, v, state)),
        Op::MapSize(k) => format!("{:?}", StateReader::<User>::get(state, &map.slot_key(k))),
        Op::KernelSet(k, v) => format!("{:?}", kernel.set(k, v, state)),
        Op::KernelGet(k) => format!("{:?}", kernel.get(k, state)),
        Op::KernelRemove(k) => format!("{:?}", kernel.remove(k, state)),
        Op::KernelSize(k) => format!(
            "{:?}",
            StateReader::<crate::Kernel>::get(state, &kernel.slot_key(k))
        ),
        Op::VecPush(v) => format!("{:?}", vec.push(v, state)),
        Op::VecPop => format!("{:?}", vec.pop(state)),
        Op::VecGet(i) => format!("{:?}", vec.get(*i, state)),
        Op::VecRemove(i) => format!("{:?}", vec.remove(*i, state)),
        Op::AccessorySet(k, v) => format!("{:?}", accessory.set(k, v, state)),
        Op::AccessoryDelete(k) => format!("{:?}", accessory.delete(k, state)),
        Op::Commit | Op::Discard => unreachable!("closes a scope"),
    }
}

/// Runs `ops` on `tx`, returning every result (as `Debug` strings).
fn run_tx(ops: &[TxOp], tx: &mut Tx) -> Vec<String> {
    let mut tokens: Vec<ScopeToken> = Vec::new();
    ops.iter()
        .map(|op| match op {
            TxOp::State(Op::Commit | Op::Discard) => {
                let end = match op {
                    TxOp::State(Op::Commit) => ScopeEnd::Commit,
                    _ => ScopeEnd::Revert,
                };
                match tokens.pop() {
                    Some(token) => {
                        format!("{:?}", innermost(tx, &tokens).close_scope(token, end))
                    }
                    None => "no scope".into(),
                }
            }
            TxOp::State(op) => run_op(op, &mut innermost(tx, &tokens)),
            TxOp::Open => {
                let token = innermost(tx, &tokens).open_scope();
                tokens.push(token);
                "open".into()
            }
            TxOp::Leak => format!("leak {}", tokens.pop().is_some()),
            TxOp::Outer(Op::Commit | Op::Discard) => "skip".into(),
            TxOp::Outer(op) => {
                let len = tokens.len().saturating_sub(1);
                run_op(op, &mut innermost(tx, &tokens[..len]))
            }
            TxOp::Charge(gas) => format!("{:?}", innermost(tx, &tokens).charge(*gas)),
        })
        .collect()
}

/// Random metered phases (scopes, leaks, charges) with random budgets on a prover checkpoint
/// over a random genesis state, replayed on a verifier checkpoint that has only the prover's
/// witness: the same results, gas used, failure, outcome, accesses and root.
#[test_strategy::proptest]
fn verifier_replays_metered_phases(
    #[strategy(prop_vec(any::<Op>(), 0..16))] genesis: Vec<Op>,
    #[strategy(prop_vec(any::<TxOp>(), 0..48))] ops: Vec<TxOp>,
    #[strategy(0u64..20_000)] budget: u64,
    module_ok: bool,
    commit_scratchpad: bool,
) {
    let storage = TestStorage::default().commit_with(|state| {
        run(&genesis, state);
    });
    let prev_root = storage.root();

    let replay = |checkpoint: StateCheckpoint<TestStorage>| {
        let mut tx: Tx = MeteredTx::new(TxScratchpad::new(checkpoint), Meter::new(budget), COSTS);
        let results = run_tx(&ops, &mut tx);
        let result = if module_ok { Ok(()) } else { Err("module") };
        let finalized = tx.finalize(result);
        let checkpoint = if commit_scratchpad {
            finalized.scratchpad.commit()
        } else {
            finalized.scratchpad.revert()
        };
        let (root, _, accessory, witness, _) = checkpoint.materialize_update(prev_root);
        (
            results,
            finalized.meter,
            finalized.outcome,
            root,
            accessory.freeze(),
            witness,
        )
    };

    let (results, meter, outcome, root, accessory, witness) =
        replay(StateCheckpoint::new(storage.clone()));
    let verifier = StateCheckpoint::with_witness(
        TestStorage::Verifier,
        crate::test_utils::borsh_roundtrip(&witness),
    );
    let (v_results, v_meter, v_outcome, v_root, v_accessory, v_witness) = replay(verifier);
    assert_eq!(v_results, results);
    assert_eq!(v_meter, meter);
    assert_eq!(v_outcome, outcome);
    assert_eq!(v_root, root);
    assert_eq!(v_accessory, accessory);
    v_witness.ensure_consumed().unwrap();
    // The gas used never exceeds the budget, and a poisoned phase is never committed.
    assert!(meter.used <= budget);
    if outcome == PhaseOutcome::Committed {
        assert!(module_ok);
        assert!(results.iter().all(|r| !r.starts_with("Err")));
    }
}
