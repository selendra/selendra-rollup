use std::io::{self, Read};

use selendra_state::metered::{StateAccessError, StateOp};

use super::{S, budget_for_reader_calls, value, working_set};
use crate::{Amount, GasMeter, GasMeteringError, GasUnit, Metered, MeteredReader, TxStateError};

const PER_BYTE: GasUnit<2> = GasUnit::from_dimensions([10, 10]);
const PER_READ_BIAS: GasUnit<2> = GasUnit::from_dimensions([5, 5]);

fn budget_for_reads(reads: &[u32]) -> Amount {
    value(budget_for_reader_calls(PER_BYTE, PER_READ_BIAS, reads))
}

/// Whether `err` wraps a refused charge (out of gas or out of funds).
fn is_out_of_gas(err: io::Error) -> bool {
    matches!(
        err.downcast::<TxStateError<S>>(),
        Ok(StateAccessError::OutOfGas {
            op: StateOp::Charge,
            source: GasMeteringError::OutOfFunds(_)
        })
    )
}

#[test]
fn read_exact_charges_once_per_call() {
    // Budget exactly one read of 8 bytes. A second read of any size must run out of gas.
    let mut ws = working_set(budget_for_reads(&[8]));
    let data: Vec<u8> = (0..16).collect();
    let mut reader = MeteredReader::with_prices(data.as_slice(), &mut ws, PER_BYTE, PER_READ_BIAS);

    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf).unwrap();
    assert_eq!(buf, [0, 1, 2, 3, 4, 5, 6, 7]);

    // The returned io::Error wraps the typed error.
    let mut buf2 = [0u8; 1];
    let err = reader.read_exact(&mut buf2).unwrap_err();
    assert!(is_out_of_gas(err));
    assert_eq!(ws.gas_info().gas_used, GasUnit::from([85, 85]));
}

#[test]
fn read_charges_per_byte_and_per_read_bias() {
    // Budget exactly one read of 4 bytes. The source has more bytes, so the second read
    // delivers some and fails at the charge.
    let mut ws = working_set(budget_for_reads(&[4]));
    let data = [9u8; 8];
    let mut reader = MeteredReader::with_prices(data.as_slice(), &mut ws, PER_BYTE, PER_READ_BIAS);

    let mut buf = [0u8; 4];
    assert_eq!(reader.read(&mut buf).unwrap(), 4);
    assert_eq!(buf, [9, 9, 9, 9]);

    let mut buf2 = [0u8; 1];
    assert!(is_out_of_gas(reader.read(&mut buf2).unwrap_err()));
}

#[test]
fn partial_read_charges_only_actual_bytes() {
    // Delivers fewer bytes than asked for: only the delivered ones are charged.
    struct ShortReader<'a> {
        data: &'a [u8],
        delivered: bool,
    }
    impl Read for ShortReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.delivered {
                return Ok(0);
            }
            self.delivered = true;
            let n = self.data.len().min(buf.len()).min(3);
            buf[..n].copy_from_slice(&self.data[..n]);
            Ok(n)
        }
    }

    // Budget 3 bytes' worth, not 10: charging by the buffer's size would fail.
    let mut ws = working_set(budget_for_reads(&[3]));
    let data: Vec<u8> = (0..10).collect();
    let short = ShortReader {
        data: &data,
        delivered: false,
    };
    let mut reader = MeteredReader::with_prices(short, &mut ws, PER_BYTE, PER_READ_BIAS);
    let mut buf = [0u8; 10];
    assert_eq!(reader.read(&mut buf).unwrap(), 3);
}

/// Delivers 3 bytes, then fails.
struct PartialFailReader {
    delivered: bool,
}

impl Read for PartialFailReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.delivered {
            return Err(io::Error::other("BOOM"));
        }
        self.delivered = true;
        let n = buf.len().min(3);
        buf[..n].fill(0xCD);
        Ok(n)
    }
}

/// The inner reader's error reaches the caller once the bytes consumed before it are paid for.
///
/// Changed by P5-20: upstream's version of this test ran with a budget for 1 byte and expected
/// the inner error, because the refused charge for the 3 consumed bytes was discarded (they were
/// read for free); here the refused charge is the error (see
/// [`metered_reader_reports_out_of_gas_on_eof`]).
#[test]
fn read_exact_propagates_inner_error_when_the_consumed_bytes_are_paid() {
    let mut ws = working_set(budget_for_reads(&[3]));
    let mut reader = MeteredReader::with_prices(
        PartialFailReader { delivered: false },
        &mut ws,
        PER_BYTE,
        PER_READ_BIAS,
    );
    let mut buf = [0u8; 10];
    let err = reader.read_exact(&mut buf).unwrap_err();
    assert!(err.to_string().contains("BOOM"), "{err}");
    assert_eq!(ws.gas_info().gas_used, GasUnit::from([35, 35]));

    let mut ws = working_set(budget_for_reads(&[1]));
    let mut reader = MeteredReader::with_prices(
        PartialFailReader { delivered: false },
        &mut ws,
        PER_BYTE,
        PER_READ_BIAS,
    );
    assert!(is_out_of_gas(reader.read_exact(&mut buf).unwrap_err()));
}

#[test]
fn out_of_gas_during_read_wraps_typed_error() {
    // No funds: any read fails at the charge.
    let mut ws = working_set(Amount::ZERO);
    let data = [1u8; 16];
    let mut reader = MeteredReader::with_prices(data.as_slice(), &mut ws, PER_BYTE, PER_READ_BIAS);
    let mut buf = [0u8; 4];
    assert!(is_out_of_gas(reader.read(&mut buf).unwrap_err()));
}

#[test]
fn read_exact_zero_buf_does_not_charge() {
    let mut ws = working_set(Amount::ZERO);
    let data: &[u8] = &[1, 2, 3];
    let mut reader = MeteredReader::with_prices(data, &mut ws, PER_BYTE, PER_READ_BIAS);
    let mut buf: [u8; 0] = [];
    reader.read_exact(&mut buf).unwrap();
}

#[test]
fn eof_read_does_not_charge() {
    // Empty input and no funds: a charge for the end of the input would fail.
    let mut ws = working_set(Amount::ZERO);
    let data: &[u8] = &[];
    let mut reader = MeteredReader::with_prices(data, &mut ws, PER_BYTE, PER_READ_BIAS);
    let mut buf = [0u8; 4];
    assert_eq!(reader.read(&mut buf).unwrap(), 0);
}

/// `MeteredReader::new` charges the spec's `decode_per_byte` per byte delivered (`[1, 1]` in
/// `SELENDRA_GAS_SCHEDULE`) and nothing per call. (That it reads `decode_per_byte` and no other
/// `[1, 1]` cost is pinned on `DistinctCostSpec`: `state::tests::distinct_costs`.)
#[test]
fn new_charges_decode_per_byte() {
    let mut ws = working_set(Amount::MAX);
    let data = [7u8; 20];
    let mut reader = MeteredReader::new(data.as_slice(), &mut ws);
    let mut buf = [0u8; 6];
    reader.read_exact(&mut buf).unwrap();
    reader.read_exact(&mut buf).unwrap();
    let mut rest = Vec::new();
    assert_eq!(reader.read_to_end(&mut rest).unwrap(), 8);
    assert_eq!(ws.gas_info().gas_used, GasUnit::from([20, 20]));
}

// Regressions of upstream's `MeteredReader` bugs

/// P5-20: when `read_exact` hits the end of its input (or an inner error), upstream charged for
/// the bytes it had consumed with `let _ =`, discarding a refused charge: the bytes were
/// delivered for free and the caller saw only `UnexpectedEof`. The refused charge is the error
/// now (and it poisons the phase).
#[test]
fn metered_reader_reports_out_of_gas_on_eof() {
    // 3 bytes of input, 8 asked for, a budget for 1 byte.
    let mut ws = working_set(budget_for_reads(&[1]));
    let data = [1u8, 2, 3];
    let mut reader = MeteredReader::with_prices(data.as_slice(), &mut ws, PER_BYTE, PER_READ_BIAS);
    let mut buf = [0u8; 8];
    let err = reader.read_exact(&mut buf).unwrap_err();
    assert_ne!(err.kind(), io::ErrorKind::UnexpectedEof, "{err}");
    assert!(is_out_of_gas(err));
    assert!(ws.metered_view().is_poisoned());

    // With the budget for the 3 bytes, the end of the input is the error, and they are paid.
    let mut ws = working_set(budget_for_reads(&[3]));
    let mut reader = MeteredReader::with_prices(data.as_slice(), &mut ws, PER_BYTE, PER_READ_BIAS);
    let err = reader.read_exact(&mut buf).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(ws.gas_info().gas_used, GasUnit::from([35, 35]));
    assert!(!ws.metered_view().is_poisoned());
}
