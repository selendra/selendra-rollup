use borsh::{BorshDeserialize, BorshSerialize};
use selendra_state::metered::{StateAccessError, StateOp};

use super::{S, value, working_set};
use crate::{
    Amount, GasArray, GasMeter, GasMeteringError, GasUnit, Metered, MeteredBorshDeserialize,
    MeteredBorshDeserializeError, MeteredHasher, TxStateError,
};

const TEST_DATA: [u8; 32] = [1; 32];
/// SHA-256 of [`TEST_DATA`]: `python3 -I -c 'import hashlib;
/// print(hashlib.sha256(bytes([1]*32)).hexdigest())'`.
const TEST_DATA_SHA256: &str = "72cd6e8422c407fb6d098690f1130b7ded7ec2f7f5e1d30bd9d521f015363793";

const FINALIZE: GasUnit<2> = GasUnit::from_dimensions([2, 2]);
const PER_BYTE: GasUnit<2> = GasUnit::from_dimensions([5, 5]);

fn per_byte_times(n: u64) -> GasUnit<2> {
    PER_BYTE.checked_scalar_product(n).unwrap()
}

fn is_out_of_funds(err: &TxStateError<S>) -> bool {
    matches!(
        err,
        StateAccessError::OutOfGas {
            op: StateOp::Charge,
            source: GasMeteringError::OutOfFunds(_)
        }
    )
}

#[test]
fn test_metered_hasher_happy_path() {
    let funds = value(per_byte_times(32).checked_combine(FINALIZE).unwrap());
    let mut ws = working_set(funds);
    let mut hasher = MeteredHasher::new_with_custom_price(&mut ws, FINALIZE, PER_BYTE);
    hasher.update(&TEST_DATA).unwrap();
    let hash = hasher.finalize().unwrap();
    assert_eq!(hex(&hash), TEST_DATA_SHA256);
    assert_eq!(ws.gas_info().gas_used, GasUnit::from([162, 162]));
}

#[test]
fn test_metered_hasher_not_enough_gas_to_update() {
    let mut ws = working_set(value(per_byte_times(31)));
    let mut hasher = MeteredHasher::new_with_custom_price(&mut ws, FINALIZE, PER_BYTE);
    assert!(is_out_of_funds(&hasher.update(&TEST_DATA).unwrap_err()));
    assert_eq!(ws.gas_info().gas_used, GasUnit::ZEROED);
}

/// The hash is the same however the input is split, and so is the gas:
/// `hash_update + hash_per_byte·n` with the spec's costs (`[30, 30]`, `[10, 10]`), the same as
/// hashing a state value.
#[test]
fn metered_hasher_gas_does_not_depend_on_the_split() {
    let mut ws = working_set(Amount::MAX);
    let hash = MeteredHasher::digest(&TEST_DATA, &mut ws).unwrap();
    assert_eq!(hex(&hash), TEST_DATA_SHA256);
    assert_eq!(ws.gas_info().gas_used, GasUnit::from([350, 350]));

    let mut ws = working_set(Amount::MAX);
    let mut hasher = MeteredHasher::new(&mut ws);
    for chunk in TEST_DATA.chunks(5) {
        hasher.update(chunk).unwrap();
    }
    hasher.update(&[]).unwrap();
    assert_eq!(hex(&hasher.finalize().unwrap()), TEST_DATA_SHA256);
    assert_eq!(ws.gas_info().gas_used, GasUnit::from([350, 350]));

    // The empty input: the finalization only. `python3 -I -c 'import hashlib;
    // print(hashlib.sha256(b"").hexdigest())'`.
    let mut ws = working_set(Amount::MAX);
    assert_eq!(
        hex(&MeteredHasher::digest(&[], &mut ws).unwrap()),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(ws.gas_info().gas_used, GasUnit::from([30, 30]));
}

#[derive(Debug, Clone, Copy, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
struct BorshTestStruct {
    field1: u32,
    field2: u32,
}

const TEST_BORSH_STRUCT: BorshTestStruct = BorshTestStruct {
    field1: 1,
    field2: 2,
};

/// The gas of a metered decode of `n` bytes with the spec's `decode_per_byte` (`[1, 1]`; that
/// the decode reads that cost is pinned on `DistinctCostSpec`: `state::tests::distinct_costs`).
fn decode_gas(n: u64) -> GasUnit<2> {
    GasUnit::from([n, n])
}

#[test]
fn test_metered_deserializer() {
    let bytes = borsh::to_vec(&TEST_BORSH_STRUCT).unwrap();
    let mut ws = working_set(value(decode_gas(8)));
    let decoded = BorshTestStruct::metered_from_slice(&bytes, &mut ws).unwrap();
    assert_eq!(decoded, TEST_BORSH_STRUCT);
    assert_eq!(ws.gas_info().gas_used, decode_gas(8));
}

#[test]
fn test_metered_deserializer_not_enough_gas() {
    let bytes = borsh::to_vec(&TEST_BORSH_STRUCT).unwrap();
    let mut ws = working_set(value(decode_gas(8)).checked_sub(Amount::new(1)).unwrap());
    let result = BorshTestStruct::metered_from_slice(&bytes, &mut ws);
    assert!(matches!(result, Err(MeteredBorshDeserializeError::Gas(ref e)) if is_out_of_funds(e)));
    assert_eq!(ws.gas_info().gas_used, GasUnit::ZEROED);
}

/// Invalid bytes are a decode error, after the bytes were charged.
#[test]
fn test_metered_deserializer_invalid_data() {
    let bytes = borsh::to_vec(&TEST_BORSH_STRUCT).unwrap();
    let mut ws = working_set(value(decode_gas(8)));
    let result = BorshTestStruct::metered_from_slice(&bytes[1..], &mut ws);
    assert!(matches!(
        result,
        Err(MeteredBorshDeserializeError::Decode(_))
    ));
    assert_eq!(ws.gas_info().gas_used, decode_gas(7));
}

/// With an explicit per-byte price (upstream overrode `constants.toml` through environment
/// variables): the exact budget decodes, one unit less does not.
///
/// Changed: upstream charged a bias per decode plus a bias and the bytes per read call; the
/// whole input is charged per byte, up front.
#[test]
fn test_metered_deserializer_charges_per_byte() {
    let per_byte = GasUnit::<2>::from([10, 10]);
    let bytes = borsh::to_vec(&TEST_BORSH_STRUCT).unwrap();
    let total = value(per_byte.checked_scalar_product(8).unwrap());
    assert_eq!(total, Amount::new(160));

    let mut ws = working_set(total);
    let decoded =
        BorshTestStruct::metered_from_slice_with_price(&bytes, &mut ws, per_byte).unwrap();
    assert_eq!(decoded, TEST_BORSH_STRUCT);

    let mut ws = working_set(total.checked_sub(Amount::new(1)).unwrap());
    let result = BorshTestStruct::metered_from_slice_with_price(&bytes, &mut ws, per_byte);
    assert!(matches!(result, Err(MeteredBorshDeserializeError::Gas(_))));
}

/// Trailing bytes are rejected (and charged).
///
/// Changed: upstream's `deserialize_from_slice` decoded a prefix and advanced the input past it
/// (`test_metered_deserializer_advances_buf_by_bytes_consumed`), leaving the trailing bytes to
/// the caller; this decoder takes exactly one value, like `borsh::from_slice`.
#[test]
fn test_metered_deserializer_rejects_trailing_bytes() {
    let mut bytes = borsh::to_vec(&TEST_BORSH_STRUCT).unwrap();
    bytes.extend_from_slice(&[0xAB, 0xCD, 0xEF]);
    let mut ws = working_set(Amount::MAX);
    let result = BorshTestStruct::metered_from_slice(&bytes, &mut ws);
    assert!(matches!(
        result,
        Err(MeteredBorshDeserializeError::Decode(_))
    ));
    assert_eq!(ws.gas_info().gas_used, decode_gas(11));
}

/// A refused charge is the typed gas error, before any decoding, and poisons the phase.
///
/// Changed: upstream ran out of gas mid-decode (after the first field's read) and recovered the
/// typed error from the `io::Error` the reader wrapped it in
/// (`test_metered_deserializer_recovers_gas_error_mid_decode`); the charge is up front, so
/// there is no mid-decode failure.
#[test]
fn test_metered_deserializer_gas_error_is_typed() {
    let bytes = borsh::to_vec(&TEST_BORSH_STRUCT).unwrap();
    let mut ws = working_set(value(decode_gas(4)));
    let result = BorshTestStruct::metered_from_slice(&bytes, &mut ws);
    assert!(matches!(result, Err(MeteredBorshDeserializeError::Gas(ref e)) if is_out_of_funds(e)));
    assert!(ws.metered_view().is_poisoned());
    assert!(matches!(
        BorshTestStruct::metered_from_slice(&[], &mut ws),
        Err(MeteredBorshDeserializeError::Gas(
            StateAccessError::Poisoned
        ))
    ));
}

// Regressions of upstream's `MeteredHasher` bugs

/// P5-19: upstream's `MeteredHasher::finalize` charged nothing. With a budget for the bytes
/// only, the update succeeds and the finalization is refused (no hash).
#[test]
fn metered_hasher_finalize_charges() {
    let mut ws = working_set(value(per_byte_times(32)));
    let mut hasher = MeteredHasher::new_with_custom_price(&mut ws, FINALIZE, PER_BYTE);
    hasher.update(&TEST_DATA).unwrap();
    assert!(is_out_of_funds(&hasher.finalize().unwrap_err()));
    assert_eq!(ws.gas_info().gas_used, per_byte_times(32));

    let mut ws = working_set(Amount::MAX);
    let mut hasher = MeteredHasher::new_with_custom_price(&mut ws, FINALIZE, PER_BYTE);
    hasher.update(&TEST_DATA).unwrap();
    hasher.finalize().unwrap();
    assert_eq!(
        ws.gas_info().gas_used,
        per_byte_times(32).checked_combine(FINALIZE).unwrap()
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
