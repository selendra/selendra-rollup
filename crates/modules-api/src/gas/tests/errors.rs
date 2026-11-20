//! The gas and state access errors: their size (small enough to return by value) and their
//! messages.

use core::mem::size_of;

use selendra_state::metered::{StateAccessError, StateOp};

use crate::test_utils::{DistinctCostSpec, TestGuestSpec, TestSpec};
use crate::{
    Amount, GasMeteringError, GasPrice, GasUnit, ImpossibleToRefundGasDetails,
    MeteredBorshDeserializeError, OutOfFundsDetails, OutOfGasDetails, SlotOutOfGasDetails, Spec,
    TxStateError,
};

/// The most bytes [`TxStateError`] and [`GasMeteringError`] may take, on every target.
///
/// Clippy's `result_large_err` fires on a function returning `Result<_, E>` with an `E` of
/// 128 bytes or more (its default `large-error-threshold`), and every metered state access of
/// a module returns `Result<_, TxStateError<S>>`. Half of that leaves room for a module's own
/// error enum to wrap it. On x86-64 the gas error is 32 bytes and `TxStateError` 56; before the
/// [`GasMeteringError`] variants holding several gas values were boxed, they were 96 and 128
/// (and this test failed).
const MAX_ERROR_SIZE: usize = 64;

/// The sizes of a spec's gas error, state access error and metered decode error.
fn error_sizes<S: Spec>() -> [usize; 3] {
    [
        size_of::<GasMeteringError<S::Gas>>(),
        size_of::<TxStateError<S>>(),
        size_of::<MeteredBorshDeserializeError<TxStateError<S>>>(),
    ]
}

/// `TxStateError` (and the gas error in it, and the metered decode error around it) is at most
/// [`MAX_ERROR_SIZE`] bytes for every spec in the repository (`SelendraSpec` over the test and
/// the guest storage, and `DistinctCostSpec`), so concrete-spec module code returning it does
/// not trip clippy's `result_large_err`.
#[test]
fn errors_are_small() {
    for (spec, sizes) in [
        ("TestSpec", error_sizes::<TestSpec>()),
        ("TestGuestSpec", error_sizes::<TestGuestSpec>()),
        ("DistinctCostSpec", error_sizes::<DistinctCostSpec>()),
    ] {
        for size in sizes {
            assert!(
                size <= MAX_ERROR_SIZE,
                "{spec}: {sizes:?} > {MAX_ERROR_SIZE}"
            );
        }
    }
}

type G = GasUnit<2>;

const PRICE: GasPrice<2> = GasPrice::from_dimensions([Amount::new(10), Amount::new(11)]);

const fn gas(a: u64, b: u64) -> G {
    GasUnit::from_dimensions([a, b])
}

/// The messages of the variants holding several gas values (boxed), unchanged from upstream.
#[test]
fn gas_error_messages() {
    let cases: [(GasMeteringError<G>, &str); 4] = [
        (
            GasMeteringError::SlotOutOfGas(Box::new(SlotOutOfGasDetails {
                initial_slot_gas: gas(100, 101),
                gas_to_charge: gas(7, 8),
                remaining_preferred_slot_gas: gas(3, 4),
                remaining_total_slot_gas: gas(5, 6),
                is_preferred: true,
            })),
            "The slot gas limit has been exhausted. Initial slot gas: GasUnit[100, 101], gas to \
             charge GasUnit[7, 8], remaining total slot gas GasUnit[5, 6], remaining preferred \
             slot gas GasUnit[3, 4], is preferred true",
        ),
        (
            GasMeteringError::OutOfGas(Box::new(OutOfGasDetails {
                gas_to_charge: gas(7, 8),
                gas_price: PRICE,
                initial_gas: gas(100, 101),
                remaining_gas: gas(5, 6),
            })),
            "The gas to charge is greater than the funds available in the meter. Gas to charge \
             GasUnit[7, 8], gas price GasPrice[10, 11], initial_gas GasUnit[100, 101], \
             remaining gas GasUnit[5, 6]",
        ),
        (
            GasMeteringError::OutOfFunds(Box::new(OutOfFundsDetails {
                amount_to_charge: Amount::new(158),
                remaining_funds: Amount::new(12),
                gas_price: PRICE,
            })),
            "The amount to charge is greater than the funds available in the meter. Amount to \
             charge 158, remaining_funds 12, price GasPrice[10, 11]",
        ),
        (
            GasMeteringError::ImpossibleToRefundGas(Box::new(ImpossibleToRefundGasDetails {
                gas_to_refund: gas(9, 10),
                gas_used: gas(1, 2),
            })),
            "The gas to refund is greater than the gas used. Gas to refund GasUnit[9, 10], gas \
             used GasUnit[1, 2]",
        ),
    ];
    for (error, message) in cases {
        assert_eq!(error.to_string(), message);
    }
}

/// A state access refused by the meter shows the meter's error, which is also its source.
#[test]
fn state_access_error_shows_the_gas_error() {
    let gas_error = GasMeteringError::OutOfFunds(Box::new(OutOfFundsDetails {
        amount_to_charge: Amount::new(158),
        remaining_funds: Amount::new(12),
        gas_price: PRICE,
    }));
    let error: TxStateError<TestSpec> = StateAccessError::OutOfGas {
        op: StateOp::Charge,
        source: gas_error.clone(),
    };
    assert_eq!(
        error.to_string(),
        "charge: the gas meter refused the charge: The amount to charge is greater than the \
         funds available in the meter. Amount to charge 158, remaining_funds 12, price \
         GasPrice[10, 11]"
    );
    let source = std::error::Error::source(&error).unwrap();
    assert_eq!(
        source.downcast_ref::<GasMeteringError<G>>(),
        Some(&gas_error)
    );
}
