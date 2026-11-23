//! The transaction accessors against the test storage: gas known answers through every accessor
//! and namespace, events, nested scopes, the revert layering end to end (pre-execution, the call,
//! the state transition function's own writes), genesis, the block state, and a prover/verifier
//! replay.

use std::mem::ManuallyDrop;

use proptest::collection::vec as prop_vec;
use selendra_interface::common::{RollupHeight, SlotNumber, VisibleSlotNumber};
use selendra_state::metered::{RevertReason, StateOp};
use selendra_state::test_utils::{accessory_map, borsh_roundtrip, kernel_map, map, value, vec};
use selendra_state::{
    ArrayWitness, BorshCodec, CheckpointVersions, Prefix, StateCheckpoint, StateMap, StateReader,
    TxScratchpad, User, VersionReader, Witness,
};

use super::*;
use crate::test_utils::{MockKernel, TestSpec, TestStorage};
use crate::{
    Amount, BasicGasMeter, GasArray, GasMeter, GasMeteringError, GasPrice, GasUnit,
    MAX_EVENT_KEY_LEN, Metered, PhaseOutcome, StateAccessError,
};

mod distinct_costs;

type S = TestSpec;
type Error = TxStateError<S>;

const PRICE: GasPrice<2> = GasPrice::from_dimensions([Amount::new(1); 2]);

/// Gas with the same `n` in both dimensions (`SELENDRA_GAS_SCHEDULE`'s costs are equal in both).
const fn gas(n: u64) -> GasUnit<2> {
    GasUnit::from_dimensions([n, n])
}

/// A storage at rollup height 2, visible slot number 3 (in [`MockKernel`]'s kernel state),
/// holding `value()` 5, `map()` {1: 10, 2: 20}, `kernel_map()` {1: 100}, `vec()` [0, 1, 2].
fn storage() -> TestStorage {
    TestStorage::default().commit_with(|state| {
        MockKernel::write_versions(state, versions(3, 2));
        let Ok(()) = value().set(&5, state);
        let Ok(()) = map().set(&1, &10, state);
        let Ok(()) = map().set(&2, &20, state);
        let Ok(()) = kernel_map().set(&1, &100, state);
        for i in 0..3 {
            let Ok(()) = vec().push(&i, state);
        }
    })
}

fn versions(visible: u64, height: u64) -> CheckpointVersions {
    CheckpointVersions {
        visible_slot_number: VisibleSlotNumber::new_dangerous(visible),
        rollup_height: RollupHeight::new(height),
    }
}

fn scratchpad(storage: TestStorage) -> TxScratchpad<TestStorage> {
    TxScratchpad::new(MockKernel::checkpoint(storage, ArrayWitness::default()))
}

/// A meter with `budget` gas in each dimension at a price of 1.
fn meter(budget: u64) -> BasicGasMeter<S> {
    BasicGasMeter::new_with_gas(gas(budget), PRICE)
}

fn working_set(budget: u64) -> WorkingSet<S> {
    WorkingSet::new(scratchpad(storage()), meter(budget))
}

fn pre_exec(budget: u64) -> PreExecWorkingSet<S> {
    PreExecWorkingSet::new(scratchpad(storage()), meter(budget))
}

/// The gas `f` uses on `state` (one dimension: both are equal).
fn gas_of<T: GasMeter<S>, R>(state: &mut T, f: impl FnOnce(&mut T) -> R) -> (u64, R) {
    let before = state.gas_info().gas_used;
    let result = f(state);
    let used = state.gas_info().gas_used.checked_sub(before).unwrap();
    assert_eq!(used.dimensions()[0], used.dimensions()[1]);
    (used.dimensions()[0], result)
}

fn is_out_of_gas(err: &Error) -> bool {
    matches!(
        err,
        StateAccessError::OutOfGas {
            source: GasMeteringError::OutOfGas(_),
            ..
        }
    )
}

// -------------------------------------------------------------------------------------------
// Metering: every accessor, every namespace

/// The state-access known answers of every `TxState` accessor (and of pre-execution, for User
/// state), with `SelendraSpec`'s gas schedule. Computed independently from the formulas
/// (`python3 -I -c '…'`, costs: access 1, hash_update 30, hash_per_byte 10, read 1,
/// read_per_byte 1, write 1, write_per_byte 1, decode_per_byte 1, accessory_write 1,
/// accessory_write_per_byte 1, scope_open 1, event_base 1, event_per_byte 1): `value()` has a
/// 2-byte key and a 4-byte value, `map()`/`kernel_map()`/`accessory_map()` 3-byte keys.
fn tx_state_known_answers<T: TxState<S>>(state: &mut T) {
    assert_eq!(gas_of(state, |s| value().get(s)), (130, Ok(Some(5))));
    assert_eq!(gas_of(state, |s| map().get(&1, s)), (140, Ok(Some(10))));
    assert_eq!(gas_of(state, |s| map().get(&3, s)), (62, Ok(None)));
    assert_eq!(
        gas_of(state, |s| StateReader::<User>::get(s, &value().slot_key())).0,
        126
    );
    assert_eq!(gas_of(state, |s| value().set(&9, s)), (126, Ok(())));
    assert_eq!(gas_of(state, |s| map().set(&1, &9, s)), (136, Ok(())));
    assert_eq!(gas_of(state, |s| map().delete(&2, s)), (92, Ok(())));
    assert_eq!(
        gas_of(state, |s| kernel_map().get(&1, s)),
        (140, Ok(Some(100)))
    );
    assert_eq!(
        gas_of(state, |s| kernel_map().set(&1, &9, s)),
        (136, Ok(()))
    );
    assert_eq!(
        gas_of(state, |s| accessory_map().set(&1, &9, s)),
        (8, Ok(()))
    );
    assert_eq!(
        gas_of(state, |s| accessory_map().delete(&1, s)),
        (4, Ok(()))
    );
    assert_eq!(gas_of(state, |s| vec().get(1, s)), (388, Ok(Some(1))));
    // Events: event_base + event_per_byte·(key_len + borsh_len).
    assert_eq!(
        gas_of(state, |s| s.add_event(7, "Transfer", 5u64)),
        (17, Ok(()))
    );
    assert_eq!(gas_of(state, |s| s.add_event(7, "E", 5u32)), (6, Ok(())));
    // A nested scope: scope_open, then the same formulas inside it.
    assert_eq!(
        gas_of(state, |s| {
            let mut nested = s.to_revertable();
            map().set(&1, &7, &mut nested)?;
            nested.commit().map(drop)
        }),
        (137, Ok(()))
    );
    // Direct charges.
    assert_eq!(gas_of(state, |s| s.charge_gas(gas(11))), (11, Ok(())));
    assert_eq!(
        gas_of(state, |s| s.charge_linear_gas(gas(3), 4)),
        (12, Ok(()))
    );
    assert!(!state.metered_view().is_poisoned());
}

// Regressions of upstream's gas meter bugs

/// P5-17: upstream's `GasMeter` had default bodies that charged nothing, so an accessor that did
/// not override them (genesis, `RevertableTxState` delegated by hand) was free. Every
/// `TxState` implementor charges its phase's meter through the one blanket `GasMeter` impl, and
/// is metered in every namespace with the same formulas (the known answers above).
#[test]
fn every_tx_state_accessor_is_metered_in_every_namespace() {
    tx_state_known_answers(&mut working_set(1_000_000));

    let mut ws = working_set(1_000_000);
    tx_state_known_answers(&mut ws.to_revertable());

    let mut ws = working_set(1_000_000);
    let mut nested = ws.to_revertable();
    tx_state_known_answers(&mut nested.to_revertable());

    let mut genesis = genesis_state(storage_at_genesis());
    tx_state_known_answers(&mut genesis);
}

/// The storage of [`storage`] at the genesis versions.
fn storage_at_genesis() -> TestStorage {
    storage().commit_with(|state| MockKernel::write_versions(state, CheckpointVersions::GENESIS))
}

fn genesis_state(storage: TestStorage) -> GenesisStateAccessor<S> {
    GenesisStateAccessor::new(MockKernel::checkpoint(storage, ArrayWitness::default())).unwrap()
}

/// Pre-execution reads and writes User state with the same formulas.
#[test]
fn pre_exec_is_metered() {
    let mut pre = pre_exec(1_000_000);
    assert_eq!(gas_of(&mut pre, |s| value().get(s)), (130, Ok(Some(5))));
    assert_eq!(gas_of(&mut pre, |s| map().set(&1, &9, s)), (136, Ok(())));
    assert_eq!(gas_of(&mut pre, |s| s.charge_gas(gas(11))), (11, Ok(())));
    assert_eq!(pre.remaining_gas(), gas(1_000_000 - 277));
    assert_eq!(pre.gas_price(), PRICE);
}

// -------------------------------------------------------------------------------------------
// The gas meter

/// The gas meter's getters read the phase's meter, from `&self`.
#[test]
fn gas_meter_getters_read_the_phase_meter() {
    let mut ws = working_set(100);
    ws.charge_gas(gas(30)).unwrap();
    let ws = &ws;
    assert_eq!(ws.remaining_gas(), gas(70));
    assert_eq!(ws.gas_price(), PRICE);
    let info = ws.gas_info();
    assert_eq!(info.gas_used, gas(30));
    assert_eq!(info.gas_value, Amount::new(60));
}

/// A refused charge through the gas meter poisons the phase like a refused state access, and a
/// product that overflows is `GasOverflow`.
#[test]
fn refused_charge_poisons_the_phase() {
    let mut ws = working_set(100);
    assert!(is_out_of_gas(&ws.charge_gas(gas(101)).unwrap_err()));
    assert_eq!(ws.gas_info().gas_used, gas(0));
    assert_eq!(value().get(&mut ws), Err(StateAccessError::Poisoned));
    assert_eq!(ws.charge_gas(gas(1)), Err(StateAccessError::Poisoned));

    let mut ws = working_set(100);
    assert_eq!(
        ws.charge_linear_gas(GasUnit::MAX, 2),
        Err(StateAccessError::GasOverflow {
            op: StateOp::Charge
        })
    );
    assert!(ws.metered_view().is_poisoned());
}

// -------------------------------------------------------------------------------------------
// Events

/// Emits "First" (module 7, `1u64`), then "Second" (module 8, `2u32`) in a committed nested
/// scope, then "Third" (module 9, `"three"`) on `ws`, and checks the gas of each: D15's
/// `event_base + event_per_byte·(key_len + borsh_len)` (1 + 1·(5 + 8), 1 + 1·(6 + 4),
/// 1 + 1·(5 + 4 + 5)), plus `scope_open` (1) for the scope. The same in both builds: only
/// keeping the events depends on `native`.
fn emit_three_events(ws: &mut WorkingSet<S>) {
    let before = ws.gas_info().gas_used;
    assert_eq!(gas_of(ws, |s| s.add_event(7, "First", 1u64)), (14, Ok(())));
    {
        let mut nested = ws.to_revertable();
        assert_eq!(
            gas_of(&mut nested, |s| s.add_event(8, "Second", 2u32)),
            (11, Ok(()))
        );
        #[cfg(feature = "native")]
        assert_eq!(nested.events().len(), 1);
        #[cfg(not(feature = "native"))]
        assert!(nested.events().is_empty());
        nested.commit().unwrap();
    }
    assert_eq!(
        gas_of(ws, |s| s.add_event(9, "Third", String::from("three"))),
        (15, Ok(()))
    );
    let used = ws.gas_info().gas_used.checked_sub(before).unwrap();
    assert_eq!(used, gas(14 + 1 + 11 + 15));
}

/// Events are kept in the order emitted, natively, with their module and key.
#[cfg(feature = "native")]
#[test]
fn events_are_kept_natively() {
    let mut ws = working_set(1_000_000);
    emit_three_events(&mut ws);
    let events = ws.events();
    assert_eq!(events.len(), 3);
    assert_eq!((events[0].module(), events[0].key()), (7, "First"));
    assert_eq!(events[0].downcast_ref::<u64>(), Some(&1));
    assert_eq!(events[0].downcast_ref::<u32>(), None);
    assert_eq!((events[1].module(), events[1].key()), (8, "Second"));
    assert_eq!(
        events[2].downcast_ref::<String>().map(String::as_str),
        Some("three")
    );
    let finalized = ws.finalize(Ok::<(), ()>(()));
    assert_eq!(finalized.outcome, PhaseOutcome::Committed);
    let keys: Vec<_> = finalized.events.iter().map(TypeErasedEvent::key).collect();
    assert_eq!(keys, ["First", "Second", "Third"]);
    let first = finalized.events.into_iter().next().unwrap();
    assert_eq!(first.downcast::<u64>(), Some(1));
}

/// The guest twin of `events_are_kept_natively`: without `native` the same events are charged
/// exactly the same gas (D15), and none is kept, in the nested scope, the working set, or the
/// committed call's events.
#[cfg(not(feature = "native"))]
#[test]
fn events_are_charged_and_dropped_in_the_guest() {
    let mut ws = working_set(1_000_000);
    emit_three_events(&mut ws);
    assert!(ws.events().is_empty());
    let finalized = ws.finalize(Ok::<(), ()>(()));
    assert_eq!(finalized.outcome, PhaseOutcome::Committed);
    assert!(finalized.events.is_empty());
    assert_eq!(finalized.meter.gas_used(), gas(14 + 1 + 11 + 15));
}

/// The events of a reverted nested scope, of a reverted call and of a poisoned call are dropped.
#[test]
fn events_of_reverted_scopes_and_phases_are_dropped() {
    let mut ws = working_set(1_000_000);
    ws.add_event(7, "Kept", 1u8).unwrap();
    {
        let mut nested = ws.to_revertable();
        nested.add_event(7, "Reverted", 2u8).unwrap();
        nested.revert();
    }
    {
        let mut nested = ws.to_revertable();
        nested.add_event(7, "Dropped", 3u8).unwrap();
    }
    {
        let mut leaked = ManuallyDrop::new(ws.to_revertable());
        leaked.add_event(7, "Leaked", 4u8).unwrap();
    }
    let kept: Vec<_> = ws.events().iter().map(TypeErasedEvent::key).collect();
    #[cfg(feature = "native")]
    assert_eq!(kept, ["Kept"]);
    #[cfg(not(feature = "native"))]
    assert!(kept.is_empty());
    let finalized = ws.finalize(Err("module error"));
    assert!(finalized.events.is_empty());

    let mut ws = working_set(1_000_000);
    ws.add_event(7, "Kept", 1u8).unwrap();
    let _ = ws.charge_gas(GasUnit::MAX);
    let finalized = ws.finalize(Ok::<(), ()>(()));
    assert!(matches!(
        finalized.outcome,
        PhaseOutcome::Reverted(RevertReason::Poisoned(_))
    ));
    assert!(finalized.events.is_empty());
}

// Regressions of upstream's event bugs

/// P5-14: upstream's events were free. An event costs
/// `event_base + event_per_byte·(key_len + borsh_len)`, before it is kept; a refused charge
/// keeps nothing and poisons the phase.
#[test]
fn event_is_charged() {
    let mut ws = working_set(1_000_000);
    // A 4-byte key and a 13-byte borsh encoding (a 9-byte string: 4-byte length + 9 bytes).
    assert_eq!(
        gas_of(&mut ws, |s| s.add_event(
            7,
            "Mint",
            String::from("123456789")
        )),
        (18, Ok(()))
    );
    // Through a nested scope too.
    let mut nested = ws.to_revertable();
    assert_eq!(
        gas_of(&mut nested, |s| s.add_event(7, "Mint", 1u128)),
        (21, Ok(()))
    );
    nested.commit().unwrap();

    // 6 gas needed, 5 left.
    let mut ws = working_set(5);
    let err = ws.add_event(7, "E", 5u32).unwrap_err();
    assert!(is_out_of_gas(&err));
    assert!(ws.events().is_empty());
    assert_eq!(ws.gas_info().gas_used, gas(0));
    assert_eq!(ws.add_event(7, "E", 5u8), Err(StateAccessError::Poisoned));
}

/// Emits on `state` (a fresh phase, or a scope of one) an event with the longest key
/// (`MAX_EVENT_KEY_LEN` bytes), charged D15's `event_base + event_per_byte·(256 + 1)` = 258;
/// the same with 128 two-byte characters (the limit is in UTF-8 bytes, the ledger's measure);
/// then one byte more, which fails with `EventKeyTooLong`, charges nothing and poisons the
/// phase: a later read, and a later event with a short key, are `Poisoned` and charge nothing.
fn emit_longest_then_too_long_key<T: TxState<S>>(state: &mut T) {
    let longest = "k".repeat(MAX_EVENT_KEY_LEN);
    assert_eq!(
        gas_of(state, |s| s.add_event(7, &longest, 1u8)),
        (258, Ok(()))
    );
    let longest_utf8 = "\u{e9}".repeat(MAX_EVENT_KEY_LEN / 2);
    assert_eq!(
        gas_of(state, |s| s.add_event(7, &longest_utf8, 1u8)),
        (258, Ok(()))
    );
    let too_long = format!("{longest_utf8}k");
    assert_eq!(
        gas_of(state, |s| s.add_event(7, &too_long, 1u8)),
        (
            0,
            Err(StateAccessError::EventKeyTooLong {
                len: MAX_EVENT_KEY_LEN + 1
            })
        )
    );
    assert!(state.metered_view().is_poisoned());
    assert_eq!(
        gas_of(state, |s| value().get(s)),
        (0, Err(StateAccessError::Poisoned))
    );
    assert_eq!(
        gas_of(state, |s| s.add_event(7, "k", 1u8)),
        (0, Err(StateAccessError::Poisoned))
    );
}

/// An event key is at most `MAX_EVENT_KEY_LEN` (256) bytes, the node's ledger's limit (it
/// stores no longer key, so a transaction that kept one would stop the node from storing the
/// slot): through the working set, nested scopes on it, and genesis
/// ([`emit_longest_then_too_long_key`]). The longer key reverts the phase whatever the module
/// returns: no event and no write is kept. The same in both builds (only the events kept before
/// the failure depend on `native`).
#[test]
fn event_key_too_long_reverts_the_phase() {
    let refused = || {
        PhaseOutcome::Reverted(RevertReason::Poisoned(StateAccessError::EventKeyTooLong {
            len: MAX_EVENT_KEY_LEN + 1,
        }))
    };
    let kept_before = if cfg!(feature = "native") { 2 } else { 0 };
    for depth in 0..3 {
        let mut ws = working_set(1_000_000);
        map().set(&3, &30, &mut ws).unwrap();
        match depth {
            0 => emit_longest_then_too_long_key(&mut ws),
            1 => {
                let mut nested = ws.to_revertable();
                emit_longest_then_too_long_key(&mut nested);
                assert_eq!(nested.events().len(), kept_before);
                assert!(matches!(nested.commit(), Err(StateAccessError::Poisoned)));
            }
            _ => {
                let mut outer = ws.to_revertable();
                let mut inner = outer.to_revertable();
                emit_longest_then_too_long_key(&mut inner);
                assert!(matches!(inner.commit(), Err(StateAccessError::Poisoned)));
                assert!(matches!(outer.commit(), Err(StateAccessError::Poisoned)));
            }
        }
        // A failed commit hands the scope's events to no one.
        let on_ws = if depth == 0 { kept_before } else { 0 };
        assert_eq!(ws.events().len(), on_ws);
        let finalized = ws.finalize(Ok::<(), ()>(()));
        assert_eq!(finalized.outcome, refused(), "depth {depth}");
        assert!(finalized.events.is_empty());
        let mut scratchpad = finalized.scratchpad;
        assert_eq!(map().get(&3, &mut scratchpad), Ok(None));
    }

    let mut genesis = genesis_state(storage_at_genesis());
    map().set(&3, &30, &mut genesis).unwrap();
    emit_longest_then_too_long_key(&mut genesis);
    assert_eq!(genesis.events().len(), kept_before);
    let finalized = genesis.finalize(Ok::<(), ()>(()));
    assert_eq!(finalized.outcome, refused());
    assert!(finalized.events.is_empty());
    let (accesses, _, _) = finalized.checkpoint.freeze();
    assert!(accesses.user.ordered_writes.is_empty());
}

// -------------------------------------------------------------------------------------------
// Nested scopes (`RevertableTxState`)

/// A committed scope's writes reach the parent, a reverted or dropped one's do not.
#[test]
fn revertable_commit_revert_and_drop() {
    let mut ws = working_set(1_000_000);
    {
        let mut nested = ws.to_revertable();
        map().set(&3, &30, &mut nested).unwrap();
        assert_eq!(map().get(&3, &mut nested), Ok(Some(30)));
        nested.commit().unwrap();
    }
    assert_eq!(map().get(&3, &mut ws), Ok(Some(30)));
    {
        let mut nested = ws.to_revertable();
        map().set(&4, &40, &mut nested).unwrap();
        let ws_again = nested.revert();
        assert_eq!(map().get(&4, ws_again), Ok(None));
    }
    {
        let mut nested = ws.to_revertable();
        map().set(&5, &50, &mut nested).unwrap();
        // Dropped here (e.g. on `?`).
    }
    assert_eq!(map().get(&5, &mut ws), Ok(None));
    // Nested twice: an inner commit into a reverted outer scope is reverted with it.
    {
        let mut outer = ws.to_revertable();
        let mut inner = outer.to_revertable();
        map().set(&6, &60, &mut inner).unwrap();
        inner.commit().unwrap();
        assert_eq!(map().get(&6, &mut outer), Ok(Some(60)));
        outer.revert();
    }
    assert_eq!(map().get(&6, &mut ws), Ok(None));
    assert!(!ws.metered_view().is_poisoned());
    let finalized = ws.finalize(Ok::<(), ()>(()));
    assert_eq!(finalized.outcome, PhaseOutcome::Committed);
    let mut scratchpad = finalized.scratchpad;
    assert_eq!(map().get(&3, &mut scratchpad), Ok(Some(30)));
    assert_eq!(map().get(&4, &mut scratchpad), Ok(None));
}

/// A leaked `RevertableTxState` (`ManuallyDrop`, `Box::leak`: not caught by the `mem_forget`
/// lint) is reverted: by the next access through its parent, and at `finalize` (fail-closed).
#[test]
fn leaked_revertable_is_reverted() {
    let mut ws = working_set(1_000_000);
    {
        let mut leaked = ManuallyDrop::new(ws.to_revertable());
        map().set(&3, &30, &mut *leaked).unwrap();
        accessory_map().set(&3, &30, &mut *leaked).unwrap();
    }
    assert_eq!(map().get(&3, &mut ws), Ok(None));
    {
        let leaked = Box::leak(Box::new(ws.to_revertable()));
        map().set(&4, &40, leaked).unwrap();
    }
    let finalized = ws.finalize(Ok::<(), ()>(()));
    assert_eq!(finalized.outcome, PhaseOutcome::Committed);
    let (accesses, accessory, _) = finalized.scratchpad.commit().freeze();
    assert!(accesses.user.ordered_writes.is_empty());
    assert!(accessory.freeze().is_empty());
}

/// Opening a scope out of gas poisons the phase; every access through the scope and its parent
/// then fails, and the phase is reverted even if the module returns `Ok`.
#[test]
fn revertable_opened_out_of_gas_is_poisoned() {
    let mut ws = working_set(0);
    {
        let mut nested = ws.to_revertable();
        assert_eq!(map().get(&1, &mut nested), Err(StateAccessError::Poisoned));
        assert_eq!(nested.commit().map(drop), Err(StateAccessError::Poisoned));
    }
    assert_eq!(map().get(&1, &mut ws), Err(StateAccessError::Poisoned));
    let finalized = ws.finalize(Ok::<(), ()>(()));
    match finalized.outcome {
        PhaseOutcome::Reverted(RevertReason::Poisoned(StateAccessError::OutOfGas {
            op: StateOp::OpenScope,
            ..
        })) => {}
        outcome => panic!("{outcome:?}"),
    }
}

/// A scope's failure poisons the whole phase: reverting the scope does not clear it, and
/// committing it fails.
#[test]
fn revertable_shares_the_poison() {
    let mut ws = working_set(1_000);
    {
        let mut nested = ws.to_revertable();
        map().set(&3, &30, &mut nested).unwrap();
        assert!(is_out_of_gas(&nested.charge_gas(gas(1_000)).unwrap_err()));
        assert_eq!(nested.commit().map(drop), Err(StateAccessError::Poisoned));
    }
    assert_eq!(map().get(&3, &mut ws), Err(StateAccessError::Poisoned));
    assert!(matches!(
        ws.finalize(Ok::<(), ()>(())).outcome,
        PhaseOutcome::Reverted(RevertReason::Poisoned(_))
    ));
}

// -------------------------------------------------------------------------------------------
// The revert layering, end to end

/// Pre-execution's mock gas reservation (User state).
fn reservation() -> StateMap<u8, u64> {
    StateMap::with_codec(Prefix::new(240, 0), BorshCodec)
}

/// The state transition function's record of the fee (written on the scratchpad, unmetered).
fn fees() -> StateMap<u8, u64> {
    StateMap::with_codec(Prefix::new(240, 1), BorshCodec)
}

/// What [`run_tx`] returns: the call's outcome and events, the new root, the accessory writes.
struct TxRun {
    outcome: TxOutcome<S, String>,
    events: usize,
    root: <TestStorage as selendra_state::Storage>::Root,
    accessory: usize,
}

/// A transaction the way the state transition function (Phase 8) runs one: pre-execution
/// reserves gas on its own phase; the call runs on a working set with `budget` gas; the state
/// transition function records a fee on the scratchpad whatever the outcome, then commits the
/// scratchpad and materializes the checkpoint.
fn run_tx(budget: u64, call: impl FnOnce(&mut WorkingSet<S>) -> Result<(), String>) -> TxRun {
    let storage = storage();
    let prev_root = storage.root();

    let mut pre = PreExecWorkingSet::new(scratchpad(storage), meter(1_000_000));
    reservation().set(&1, &500, &mut pre).unwrap();
    let pre = pre.finalize(Ok::<(), String>(()));
    assert_eq!(pre.outcome, PhaseOutcome::Committed);

    let mut ws = WorkingSet::new(pre.scratchpad, meter(budget));
    let result = call(&mut ws);
    let finalized = ws.finalize(result);
    let mut scratchpad = finalized.scratchpad;
    let Ok(()) = fees().set(&1, &7, &mut scratchpad);
    let (root, _, accessory, witness, _) = scratchpad.commit().materialize_update(prev_root);
    drop(witness);
    TxRun {
        outcome: finalized.outcome,
        events: finalized.events.len(),
        root,
        accessory: accessory.freeze().len(),
    }
}

/// A call that writes in every namespace, emits an event, and then (with `swallow`) runs out of
/// gas, ignores it and returns `Ok`.
fn writing_call(swallow: bool) -> impl FnOnce(&mut WorkingSet<S>) -> Result<(), String> {
    move |ws| {
        map().set(&3, &30, ws).map_err(|e| e.to_string())?;
        kernel_map().set(&2, &200, ws).map_err(|e| e.to_string())?;
        accessory_map().set(&1, &1, ws).map_err(|e| e.to_string())?;
        vec().push(&3, ws).map_err(|e| e.to_string())?;
        ws.add_event(7, "Written", 1u8).map_err(|e| e.to_string())?;
        if swallow {
            // Out of gas in the middle of a `StateVec::remove`: its writes so far are partial.
            let err = vec().remove(0, ws).unwrap_err();
            assert!(is_out_of_gas(&err), "{err:?}");
            // Ignore it and carry on: later accesses fail, the module returns `Ok`.
            let _ = map().set(&4, &40, ws);
        }
        Ok(())
    }
}

/// The budget [`writing_call`] needs without the swallowed part, plus a little.
const WRITES_BUDGET: u64 = 1_200;

// Regressions of upstream's revert bugs

/// P5-13 (end to end): a module that swallows an out-of-gas error and returns `Ok` used to
/// commit its partial writes (upstream trusted the module's result). The call is reverted: the
/// root equals the root of a transaction whose call wrote nothing (only the pre-execution
/// reservation and the fee), with no accessory writes and no events.
#[test]
fn swallowed_out_of_gas_reverts_tx() {
    let swallowed = run_tx(WRITES_BUDGET, writing_call(true));
    match &swallowed.outcome {
        PhaseOutcome::Reverted(RevertReason::Poisoned(err)) => assert!(is_out_of_gas(err)),
        outcome => panic!("{outcome:?}"),
    }
    let nothing = run_tx(WRITES_BUDGET, |_| Ok(()));
    assert_eq!(nothing.outcome, PhaseOutcome::Committed);
    assert_eq!(swallowed.root, nothing.root);
    assert_eq!(swallowed.accessory, 0);
    assert_eq!(swallowed.events, 0);

    // The same call within its budget is committed (and changes the root).
    let committed = run_tx(WRITES_BUDGET, writing_call(false));
    assert_eq!(committed.outcome, PhaseOutcome::Committed);
    assert_ne!(committed.root, nothing.root);
    assert_eq!(committed.accessory, 1);
    // Its event is charged in both builds (`tx_state_known_answers`), kept only natively.
    #[cfg(feature = "native")]
    assert_eq!(committed.events, 1);
    #[cfg(not(feature = "native"))]
    assert_eq!(committed.events, 0);
}

/// P5-13 (layering): the pre-execution reservation, committed on its own phase, survives a
/// poisoned call, while the call's writes and events do not; a call that returns `Err` is
/// reverted the same way.
#[test]
fn pre_exec_write_survives_poisoned_call() {
    let storage = storage();
    let mut pre = PreExecWorkingSet::new(scratchpad(storage), meter(1_000_000));
    reservation().set(&1, &500, &mut pre).unwrap();
    let pre = pre.finalize(Ok::<(), String>(()));
    let mut ws = WorkingSet::new(pre.scratchpad, meter(WRITES_BUDGET));
    let result = writing_call(true)(&mut ws);
    assert_eq!(result, Ok(()));
    let finalized = ws.finalize(result);
    assert!(matches!(
        finalized.outcome,
        PhaseOutcome::Reverted(RevertReason::Poisoned(_))
    ));
    assert!(finalized.events.is_empty());
    let mut scratchpad = finalized.scratchpad;
    assert_eq!(reservation().get(&1, &mut scratchpad), Ok(Some(500)));
    assert_eq!(map().get(&3, &mut scratchpad), Ok(None));
    assert_eq!(kernel_map().get(&2, &mut scratchpad), Ok(None));
    assert_eq!(vec().len(&mut scratchpad), Ok(3));
    // The gas used is kept.
    assert!(
        finalized
            .meter
            .gas_used()
            .dim_is_less_or_eq(gas(WRITES_BUDGET))
    );
    assert!(!finalized.meter.gas_used().dim_is_less_or_eq(gas(0)));

    let module_error = run_tx(WRITES_BUDGET, |ws| {
        writing_call(false)(ws)?;
        Err("module error".to_string())
    });
    assert_eq!(
        module_error.outcome,
        PhaseOutcome::Reverted(RevertReason::Module("module error".to_string()))
    );
    assert_eq!(module_error.root, run_tx(WRITES_BUDGET, |_| Ok(())).root);
}

/// A poisoned pre-execution phase is reverted too (its own writes), and the scratchpad's
/// writes made before it are kept.
#[test]
fn poisoned_pre_exec_is_reverted() {
    let mut scratchpad = scratchpad(storage());
    let Ok(()) = fees().set(&9, &9, &mut scratchpad);
    let mut pre = PreExecWorkingSet::new(scratchpad, meter(200));
    reservation().set(&1, &500, &mut pre).unwrap();
    assert!(is_out_of_gas(&pre.charge_gas(gas(1_000)).unwrap_err()));
    let finalized = pre.finalize(Ok::<(), ()>(()));
    assert!(matches!(
        finalized.outcome,
        PhaseOutcome::Reverted(RevertReason::Poisoned(_))
    ));
    let mut scratchpad = finalized.scratchpad;
    assert_eq!(reservation().get(&1, &mut scratchpad), Ok(None));
    assert_eq!(fees().get(&9, &mut scratchpad), Ok(Some(9)));
}

// -------------------------------------------------------------------------------------------
// Genesis

fn genesis_writes<G: GenesisState<S>>(state: &mut G) -> Result<SlotNumber, Error> {
    kernel_map().set(&5, &55, state)?;
    value().set(&6, state)?;
    state.add_event(1, "Genesis", 0u8)?;
    Ok(state.true_slot_number())
}

/// The genesis accessor writes Kernel state, with the true slot number `GENESIS`, and is
/// committed into the checkpoint.
#[test]
fn genesis_writes_kernel_state_with_the_true_slot() {
    let mut genesis = genesis_state(storage_at_genesis());
    assert_eq!(genesis_writes(&mut genesis), Ok(SlotNumber::GENESIS));
    assert_eq!(
        genesis.current_visible_slot_number(),
        VisibleSlotNumber::GENESIS
    );
    assert_eq!(genesis.rollup_height_to_access(), RollupHeight::GENESIS);
    let finalized = genesis.finalize(Ok::<(), ()>(()));
    assert_eq!(finalized.outcome, PhaseOutcome::Committed);
    // Its event is charged in both builds (`distinct_costs`' known answers on the genesis
    // accessor), kept only natively.
    #[cfg(feature = "native")]
    assert_eq!(finalized.events.len(), 1);
    #[cfg(not(feature = "native"))]
    assert!(finalized.events.is_empty());
    let mut checkpoint = finalized.checkpoint;
    let Ok(kernel) = kernel_map().get(&5, &mut checkpoint);
    assert_eq!(kernel, Some(55));
    // Metered, at a zero price.
    assert!(!finalized.meter.gas_used().dim_is_less_or_eq(gas(0)));
    assert_eq!(finalized.meter.gas_info().gas_value, Amount::ZERO);

    // A failed genesis keeps nothing.
    let mut genesis = genesis_state(storage_at_genesis());
    genesis_writes(&mut genesis).unwrap();
    let finalized = genesis.finalize(Err("bad config"));
    assert!(finalized.events.is_empty());
    let mut checkpoint = finalized.checkpoint;
    let Ok(kernel) = kernel_map().get(&5, &mut checkpoint);
    assert_eq!(kernel, None);
}

/// Genesis runs only on a checkpoint at the genesis versions.
#[test]
fn genesis_needs_the_genesis_versions() {
    let err =
        GenesisStateAccessor::<S>::new(MockKernel::checkpoint(storage(), ArrayWitness::default()))
            .unwrap_err();
    assert_eq!(
        err,
        NotAtGenesis {
            versions: versions(3, 2)
        }
    );
    let mut checkpoint = MockKernel::checkpoint(storage_at_genesis(), ArrayWitness::default());
    MockKernel::advance(&mut checkpoint, versions(1, 1));
    assert!(GenesisStateAccessor::<S>::new(checkpoint).is_err());
}

// -------------------------------------------------------------------------------------------
// The block state and the mock kernel

/// The block state reads and writes the checkpoint, unmetered, at its versions.
#[test]
fn block_state_reads_and_writes_the_checkpoint() {
    let mut checkpoint = MockKernel::checkpoint(storage(), ArrayWitness::default());
    {
        let mut block = BlockState::<S>::new(&mut checkpoint);
        assert_eq!(
            block.current_visible_slot_number(),
            VisibleSlotNumber::new_dangerous(3)
        );
        assert_eq!(block.rollup_height_to_access(), RollupHeight::new(2));
        assert_eq!(
            block.max_allowed_slot_number_to_access(),
            SlotNumber::new(3)
        );
        let Ok(old) = map().get(&1, &mut block);
        assert_eq!(old, Some(10));
        let Ok(()) = map().set(&1, &11, &mut block);
        let Ok(()) = kernel_map().set(&1, &101, &mut block);
        let Ok(()) = accessory_map().set(&1, &1, &mut block);
        MockKernel::write_versions(&mut block, versions(4, 3));
        assert!(format!("{block:?}").starts_with("BlockState"));
    }
    checkpoint.refresh_versions(MockKernel::read_versions);
    assert_eq!(checkpoint.versions(), versions(4, 3));
    let Ok(new) = map().get(&1, &mut checkpoint);
    assert_eq!(new, Some(11));
}

/// The mock kernel's versions come from the checkpoint's own kernel state, and the working sets
/// execute at them.
#[test]
fn mock_kernel_versions_are_read_from_state() {
    let checkpoint = MockKernel::checkpoint(TestStorage::default(), ArrayWitness::default());
    assert_eq!(checkpoint.versions(), CheckpointVersions::GENESIS);

    let mut checkpoint = MockKernel::checkpoint(storage(), ArrayWitness::default());
    assert_eq!(checkpoint.versions(), versions(3, 2));
    MockKernel::advance(&mut checkpoint, versions(5, 4));
    let ws = WorkingSet::<S>::new(TxScratchpad::new(checkpoint), meter(10));
    assert_eq!(
        ws.current_visible_slot_number(),
        VisibleSlotNumber::new_dangerous(5)
    );
    assert_eq!(ws.max_allowed_slot_number_to_access(), SlotNumber::new(5));
    assert_eq!(ws.rollup_height_to_access(), RollupHeight::new(4));
}

// -------------------------------------------------------------------------------------------
// Prover/verifier replay

/// One step of a random transaction.
#[derive(Debug, Clone, test_strategy::Arbitrary)]
enum TxOp {
    ValueSet(u32),
    ValueGet,
    MapSet(#[strategy(0u8..6)] u8, u32),
    MapGet(#[strategy(0u8..6)] u8),
    MapRemove(#[strategy(0u8..6)] u8),
    KernelSet(#[strategy(0u8..4)] u8, u32),
    KernelGet(#[strategy(0u8..4)] u8),
    VecPush(u32),
    VecGet(#[strategy(0u64..5)] u64),
    VecRemove(#[strategy(0u64..5)] u64),
    AccessorySet(#[strategy(0u8..4)] u8, u32),
    Event(u16),
    Charge(#[strategy(0u64..400)] u64),
    /// Opens a nested scope (up to two deep; ignored deeper).
    Open,
    /// Ends the innermost nested scope (ignored at the top).
    Close(End),
}

#[derive(Debug, Clone, Copy, test_strategy::Arbitrary)]
enum End {
    Commit,
    Revert,
    Drop,
    Leak,
}

/// Runs the accesses of `op` on `state`, as a `Debug` string.
fn step<T: TxState<S>>(op: &TxOp, state: &mut T) -> String {
    match op {
        TxOp::ValueSet(v) => format!("{:?}", value().set(v, state)),
        TxOp::ValueGet => format!("{:?}", value().get(state)),
        TxOp::MapSet(k, v) => format!("{:?}", map().set(k, v, state)),
        TxOp::MapGet(k) => format!("{:?}", map().get(k, state)),
        TxOp::MapRemove(k) => format!("{:?}", map().remove(k, state)),
        TxOp::KernelSet(k, v) => format!("{:?}", kernel_map().set(k, v, state)),
        TxOp::KernelGet(k) => format!("{:?}", kernel_map().get(k, state)),
        TxOp::VecPush(v) => format!("{:?}", vec().push(v, state)),
        TxOp::VecGet(i) => format!("{:?}", vec().get(*i, state)),
        TxOp::VecRemove(i) => format!("{:?}", vec().remove(*i, state)),
        TxOp::AccessorySet(k, v) => format!("{:?}", accessory_map().set(k, v, state)),
        TxOp::Event(v) => format!("{:?}", state.add_event(7, "Event", *v)),
        TxOp::Charge(g) => format!("{:?}", state.charge_gas(gas(*g))),
        TxOp::Open | TxOp::Close(_) => String::new(),
    }
}

/// Ends `nested` as `end` says.
fn end<T: TxState<S>>(nested: RevertableTxState<'_, S, T>, end: End) -> String {
    match end {
        End::Commit => format!("{:?}", nested.commit().map(drop)),
        End::Revert => {
            nested.revert();
            "revert".into()
        }
        End::Drop => {
            drop(nested);
            "drop".into()
        }
        End::Leak => {
            let _ = ManuallyDrop::new(nested);
            "leak".into()
        }
    }
}

/// Runs `ops` on the working set, opening nested scopes up to two deep.
fn run_top(ops: &mut std::slice::Iter<'_, TxOp>, ws: &mut WorkingSet<S>, out: &mut Vec<String>) {
    while let Some(op) = ops.next() {
        match op {
            TxOp::Open => {
                let mut nested = ws.to_revertable();
                let how = run_nested(ops, &mut nested, out, true);
                out.push(end(nested, how));
            }
            TxOp::Close(_) => {}
            op => out.push(step(op, ws)),
        }
    }
}

/// Runs `ops` in a nested scope until a `Close` (returned) or the end (dropped), opening one
/// more level if `open`.
fn run_nested<T: TxState<S>>(
    ops: &mut std::slice::Iter<'_, TxOp>,
    state: &mut T,
    out: &mut Vec<String>,
    open: bool,
) -> End {
    while let Some(op) = ops.next() {
        match op {
            TxOp::Open if open => {
                let mut nested = state.to_revertable();
                let how = run_nested_leaf(ops, &mut nested, out);
                out.push(end(nested, how));
            }
            TxOp::Open => {}
            TxOp::Close(how) => return *how,
            op => out.push(step(op, state)),
        }
    }
    End::Drop
}

/// [`run_nested`] at the deepest level (no recursion: each level is another type).
fn run_nested_leaf<T: TxState<S>>(
    ops: &mut std::slice::Iter<'_, TxOp>,
    state: &mut T,
    out: &mut Vec<String>,
) -> End {
    for op in ops.by_ref() {
        match op {
            TxOp::Open => {}
            TxOp::Close(how) => return *how,
            op => out.push(step(op, state)),
        }
    }
    End::Drop
}

/// Random calls (nested scopes, leaks, events, charges) with random budgets on a working set
/// over a prover checkpoint, replayed on a verifier checkpoint that has only the prover's
/// witness: the same results, gas used, outcome, events, accessory writes and root.
#[test_strategy::proptest]
fn verifier_replays_working_sets(
    #[strategy(prop_vec(proptest::prelude::any::<TxOp>(), 0..48))] ops: Vec<TxOp>,
    #[strategy(0u64..6_000)] budget: u64,
    module_ok: bool,
) {
    let storage = storage();
    let prev_root = storage.root();

    let replay = |checkpoint: StateCheckpoint<TestStorage>| {
        let mut ws = WorkingSet::<S>::new(TxScratchpad::new(checkpoint), meter(budget));
        let mut out = Vec::new();
        run_top(&mut ops.iter(), &mut ws, &mut out);
        let result = if module_ok { Ok(()) } else { Err("module") };
        let finalized = ws.finalize(result);
        let gas_info = finalized.meter.gas_info();
        let (root, _, accessory, witness, _) =
            finalized.scratchpad.commit().materialize_update(prev_root);
        (
            out,
            gas_info,
            finalized.outcome,
            finalized.events.len(),
            root,
            accessory.freeze(),
            witness,
        )
    };

    let (out, gas_info, outcome, events, root, accessory, witness) = replay(
        MockKernel::checkpoint(storage.clone(), ArrayWitness::default()),
    );
    let verifier = MockKernel::checkpoint(TestStorage::Verifier, borsh_roundtrip(&witness));
    let (v_out, v_gas_info, v_outcome, v_events, v_root, v_accessory, v_witness) = replay(verifier);
    assert_eq!(v_out, out);
    assert_eq!(v_gas_info, gas_info);
    assert_eq!(v_outcome, outcome);
    assert_eq!(v_events, events);
    assert_eq!(v_root, root);
    assert_eq!(v_accessory, accessory);
    v_witness.ensure_consumed().unwrap();
    // The gas used never exceeds the budget; a committed call had no failed access.
    assert!(gas_info.gas_used.dim_is_less_or_eq(gas(budget)));
    if outcome == PhaseOutcome::Committed {
        assert!(module_ok);
        assert!(out.iter().all(|r| !r.starts_with("Err")), "{out:?}");
    } else {
        assert_eq!(events, 0);
    }
}
