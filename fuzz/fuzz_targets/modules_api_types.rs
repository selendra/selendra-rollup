//! `selendra-modules-api`'s types: decoders (borsh, JSON, `FromStr`; no panics, canonical, the
//! same value in every encoding), gas arithmetic (checked per dimension, like `u64`/`u128`
//! arithmetic) and the gas meters (a refused charge changes nothing; `remaining + used ==
//! initial`).
//!
//! Random text almost never carries a valid bech32m checksum or a complete `BlockGasInfo`
//! object, so ids and `BlockGasInfo` JSON are also built from the fuzz bytes (`id_strings`,
//! `block_gas_info_json`): well-formed but possibly non-canonical candidates, each checked
//! against an independent oracle.
#![no_main]

use std::str::FromStr;

use libfuzzer_sys::fuzz_target;
use selendra_modules_api::test_utils::{MockAddress, TestSpec};
use selendra_modules_api::{
    Amount, BasicGasMeter, BlockGasInfo, Gas, GasArray, GasPrice, GasUnit, ModuleId,
    NotInstantiable, OperatingMode, PriorityFeeBips, SequencerType, SlotGasMeter,
};

selendra_modules_api::hash32_id! {
    /// A second id type, with another prefix.
    pub struct TokenId, prefix = "token_"
}

fn borsh_canonical<T: borsh::BorshDeserialize + borsh::BorshSerialize>(data: &[u8]) -> Option<T> {
    let value = borsh::from_slice::<T>(data).ok()?;
    assert_eq!(
        borsh::to_vec(&value).unwrap(),
        data,
        "non-canonical borsh accepted"
    );
    Some(value)
}

/// String form: anything accepted must print back as exactly the input.
fn str_canonical<T: FromStr + std::fmt::Display>(s: &str) -> Option<T> {
    let value = T::from_str(s).ok()?;
    assert_eq!(value.to_string(), s, "non-canonical string accepted");
    Some(value)
}

/// JSON: anything accepted must serialize back to the same JSON value (whitespace aside).
fn json_canonical<T: serde::de::DeserializeOwned + serde::Serialize>(s: &str) -> Option<T> {
    let value = serde_json::from_str::<T>(s).ok()?;
    let input: serde_json::Value = serde_json::from_str(s).unwrap();
    assert_eq!(
        serde_json::to_value(&value).unwrap(),
        input,
        "non-canonical JSON accepted"
    );
    Some(value)
}

/// Every encoding of one value decodes to the same value.
fn round_trips<T>(value: &T)
where
    T: borsh::BorshSerialize
        + borsh::BorshDeserialize
        + serde::Serialize
        + serde::de::DeserializeOwned
        + PartialEq
        + std::fmt::Debug,
{
    let bytes = borsh::to_vec(value).unwrap();
    assert_eq!(&borsh::from_slice::<T>(&bytes).unwrap(), value);
    let json = serde_json::to_string(value).unwrap();
    assert_eq!(&serde_json::from_str::<T>(&json).unwrap(), value);
    let binary = postcard::to_allocvec(value).unwrap();
    assert_eq!(&postcard::from_bytes::<T>(&binary).unwrap(), value);
}

fn u64_at(data: &[u8], i: usize) -> u64 {
    let mut bytes = [0u8; 8];
    for (j, b) in bytes.iter_mut().enumerate() {
        *b = data.get(i * 8 + j).copied().unwrap_or(0);
    }
    u64::from_le_bytes(bytes)
}

/// The fuzz bytes as each type's borsh encoding.
fn binary(data: &[u8]) {
    if let Some(amount) = borsh_canonical::<Amount>(data) {
        assert_eq!(data.len(), 16);
        round_trips(&amount);
        assert_eq!(Amount::from_str(&amount.to_string()).unwrap(), amount);
    }
    let module = borsh_canonical::<ModuleId>(data);
    assert_eq!(module.is_some(), data.len() == 32);
    assert_eq!(ModuleId::try_from(data).ok(), module);
    if let Some(id) = module {
        round_trips(&id);
        assert_eq!(ModuleId::from_str(&id.to_string()).unwrap(), id);
        let token = TokenId::new(*id.as_bytes());
        assert_eq!(TokenId::from_str(&token.to_string()).unwrap(), token);
        assert!(ModuleId::from_str(&token.to_string()).is_err());
    }
    if let Some(gas) = borsh_canonical::<GasUnit<2>>(data) {
        round_trips(&gas);
    }
    if let Some(price) = borsh_canonical::<GasPrice<2>>(data) {
        round_trips(&price);
    }
    if let Some(info) = borsh_canonical::<BlockGasInfo<GasUnit<2>>>(data) {
        assert_eq!(data.len(), 64);
        round_trips(&info);
    }
    if let Some(mode) = borsh_canonical::<OperatingMode>(data) {
        assert!(data == [1] || data == [2]);
        round_trips(&mode);
    }
    if let Some(kind) = borsh_canonical::<SequencerType>(data) {
        assert!(data == [0] || data == [1]);
        let json = serde_json::to_string(&kind).unwrap();
        assert_eq!(serde_json::from_str::<SequencerType>(&json).unwrap(), kind);
    }
    if let Some(fee) = borsh_canonical::<PriorityFeeBips>(data) {
        round_trips(&fee);
    }
    assert!(borsh::from_slice::<NotInstantiable>(data).is_err());
    assert_eq!(borsh::from_slice::<TestSpec>(data).is_ok(), data.is_empty());
}

/// The fuzz bytes as text: `FromStr` and JSON.
fn text(s: &str) {
    if let Some(amount) = str_canonical::<Amount>(s) {
        assert_eq!(s.parse::<u128>().ok(), Some(amount.get()));
    }
    if let Some(id) = str_canonical::<ModuleId>(s) {
        assert!(s.starts_with("module_1"));
        assert_eq!(json_canonical::<ModuleId>(&format!("\"{s}\"")), Some(id));
    }
    let _ = str_canonical::<TokenId>(s);
    let _ = json_canonical::<Amount>(s);
    let _ = json_canonical::<ModuleId>(s);
    let _ = json_canonical::<GasUnit<2>>(s);
    let _ = json_canonical::<GasPrice<2>>(s);
    let _ = json_canonical::<BlockGasInfo<GasUnit<2>>>(s);
    let _ = json_canonical::<OperatingMode>(s);
    let _ = json_canonical::<SequencerType>(s);
    let _ = json_canonical::<PriorityFeeBips>(s);
    assert!(serde_json::from_str::<NotInstantiable>(s).is_err());
}

/// Gas arithmetic is per-dimension checked `u64` arithmetic; a price's is `u128`'s.
fn arithmetic(data: &[u8]) {
    let (a, b) = (
        [u64_at(data, 0), u64_at(data, 1)],
        [u64_at(data, 2), u64_at(data, 3)],
    );
    let (x, y) = (GasUnit::<2>::from(a), GasUnit::<2>::from(b));
    let per_dim = |op: fn(u64, u64) -> Option<u64>| -> Option<GasUnit<2>> {
        Some(GasUnit::from([op(a[0], b[0])?, op(a[1], b[1])?]))
    };
    assert_eq!(x.checked_combine(y), per_dim(u64::checked_add));
    assert_eq!(x.checked_sub(y), per_dim(u64::checked_sub));
    assert_eq!(
        x.checked_scalar_product(b[0]),
        a[0].checked_mul(b[0])
            .zip(a[1].checked_mul(b[0]))
            .map(|(p, q)| GasUnit::from([p, q]))
    );
    assert_eq!(
        x.checked_scalar_division(b[1]),
        a[0].checked_div(b[1])
            .zip(a[1].checked_div(b[1]))
            .map(|(p, q)| GasUnit::from([p, q]))
    );
    assert_eq!(x.dim_is_less_than(y), a[0] < b[0] && a[1] < b[1]);
    assert_eq!(x.dim_is_less_or_eq(y), a[0] <= b[0] && a[1] <= b[1]);
    assert_eq!(
        GasUnit::calculate_min(x, y),
        GasUnit::from([a[0].min(b[0]), a[1].min(b[1])])
    );

    let price = GasPrice::<2>::from([
        Amount::new(u128::from(u64_at(data, 2)) << (data.len() % 64)),
        Amount::new(u128::from(u64_at(data, 3))),
    ]);
    let expected = u128::from(a[0])
        .checked_mul(price.dimensions()[0].get())
        .zip(u128::from(a[1]).checked_mul(price.dimensions()[1].get()))
        .and_then(|(p, q)| p.checked_add(q))
        .map(Amount::new);
    assert_eq!(x.checked_value(price), expected);

    let bips = PriorityFeeBips(u64_at(data, 4));
    let quantity = u128::from(u64_at(data, 5)) << (data.len() % 72);
    let fee = bips.apply(Amount::new(quantity));
    if let Some(product) = quantity.checked_mul(u128::from(bips.0)) {
        assert_eq!(fee, Ok(Amount::new(product / 10_000)));
    }
}

/// A sequence of charges on a transaction meter and a slot meter.
fn meters(data: &[u8]) {
    let initial = GasUnit::<2>::from([u64_at(data, 0) >> 32, u64_at(data, 1) >> 32]);
    let price = GasPrice::<2>::from([
        Amount::new(u128::from(u64_at(data, 2) >> 40)),
        Amount::new(u128::from(u64_at(data, 3) >> 40)),
    ]);
    let funds = (data.first().copied().unwrap_or(0) % 2 == 0)
        .then(|| Amount::new(u128::from(u64_at(data, 4))));
    let mut meter = match funds {
        Some(funds) => BasicGasMeter::<TestSpec>::new_with_funds_and_gas(funds, initial, price),
        None => BasicGasMeter::<TestSpec>::new_with_gas(initial, price),
    };
    let preferred = MockAddress::new([1; 32]);
    let other = MockAddress::new([2; 32]);
    let mut slot = SlotGasMeter::<TestSpec>::new(initial, Some(preferred));

    for (i, chunk) in data.chunks(9).enumerate().skip(1) {
        let gas = GasUnit::<2>::from([
            u64::from(chunk.first().copied().unwrap_or(0))
                << (chunk.get(1).copied().unwrap_or(0) % 40),
            u64::from(chunk.get(2).copied().unwrap_or(0))
                << (chunk.get(3).copied().unwrap_or(0) % 40),
        ]);
        let before = (
            meter.remaining_gas(),
            meter.gas_used(),
            meter.remaining_funds(),
        );
        let result = if i % 2 == 0 {
            meter.charge_gas(gas)
        } else {
            meter.charge_linear_gas(gas, u32::from(chunk.get(4).copied().unwrap_or(0)))
        };
        if result.is_err() {
            assert_eq!(
                (
                    meter.remaining_gas(),
                    meter.gas_used(),
                    meter.remaining_funds()
                ),
                before
            );
        }
        assert_eq!(
            meter.remaining_gas().checked_combine(meter.gas_used()),
            Some(meter.initial_gas())
        );
        assert_eq!(
            meter.gas_used().checked_value(meter.gas_price()),
            Some(meter.gas_info().gas_value)
        );

        let sequencer = if chunk.get(5).copied().unwrap_or(0) % 2 == 0 {
            preferred
        } else {
            other
        };
        let before = (
            slot.remaining_preferred_slot_gas(),
            slot.remaining_slot_gas(&other),
            slot.total_gas_used(),
        );
        if slot.charge_gas(gas, &sequencer).is_err() {
            assert_eq!(
                (
                    slot.remaining_preferred_slot_gas(),
                    slot.remaining_slot_gas(&other),
                    slot.total_gas_used()
                ),
                before
            );
        }
        assert_eq!(
            slot.remaining_slot_gas(&other)
                .checked_combine(slot.total_gas_used()),
            Some(slot.initial_slot_gas())
        );
        assert!(
            slot.remaining_preferred_slot_gas()
                .dim_is_less_or_eq(slot.initial_slot_gas())
        );
    }
}

/// The bech32 charset, indexed by 5-bit symbol.
const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// BIP-350's checksum function, written out independently of the `bech32` crate.
fn polymod(values: &[u8]) -> u32 {
    const GENERATOR: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk: u32 = 1;
    for &value in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(value);
        for (i, generator) in GENERATOR.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= generator;
            }
        }
    }
    chk
}

/// `hrp` + `1` + the data symbols + a correct bech32m checksum, whatever the symbols.
fn bech32m(hrp: &str, symbols: &[u8]) -> String {
    let mut values: Vec<u8> = hrp.bytes().map(|b| b >> 5).collect();
    values.push(0);
    values.extend(hrp.bytes().map(|b| b & 31));
    values.extend_from_slice(symbols);
    values.extend([0; 6]);
    let residue = polymod(&values) ^ 0x2bc8_30a3;
    let checksum = (0..6).map(|i| ((residue >> (5 * (5 - i))) & 31) as u8);
    let data: String = symbols
        .iter()
        .copied()
        .chain(checksum)
        .map(|v| char::from(CHARSET[usize::from(v)]))
        .collect();
    format!("{hrp}1{data}")
}

/// Ids built from the fuzz bytes: 50 to 54 data symbols (the last one's padding bits are
/// fuzz-chosen) with a correct checksum. Accepted iff there are exactly 52 symbols (32 bytes)
/// and the 4 padding bits of the last are zero (P5-22), as the bytes the symbols spell; the
/// uppercase form and the other prefix are always rejected.
fn id_strings(data: &[u8]) {
    let Some((&first, rest)) = data.split_first() else {
        return;
    };
    let count = 50 + usize::from(first % 5);
    let symbols: Vec<u8> = (0..count)
        .map(|i| rest.get(i).copied().unwrap_or(0) & 31)
        .collect();
    let canonical = count == 52 && symbols[51] & 0b1111 == 0;
    let mut bytes = [0u8; 32];
    if canonical {
        let bits = symbols
            .iter()
            .flat_map(|s| (0..5).rev().map(move |i| (s >> i) & 1));
        for (i, bit) in bits.take(256).enumerate() {
            bytes[i / 8] |= bit << (7 - i % 8);
        }
    }

    let module = bech32m("module_", &symbols);
    let token = bech32m("token_", &symbols);
    match ModuleId::from_str(&module) {
        Ok(id) => {
            assert!(canonical, "non-canonical id accepted: {module}");
            assert_eq!(id.as_bytes(), &bytes);
            assert_eq!(id.to_string(), module);
            assert_eq!(
                json_canonical::<ModuleId>(&format!("\"{module}\"")),
                Some(id)
            );
        }
        Err(_) => assert!(!canonical, "canonical id rejected: {module}"),
    }
    match TokenId::from_str(&token) {
        Ok(id) => {
            assert!(canonical, "non-canonical id accepted: {token}");
            assert_eq!(id.as_bytes(), &bytes);
            assert_eq!(id.to_string(), token);
        }
        Err(_) => assert!(!canonical, "canonical id rejected: {token}"),
    }
    assert!(ModuleId::from_str(&token).is_err());
    assert!(TokenId::from_str(&module).is_err());
    assert!(ModuleId::from_str(&module.to_ascii_uppercase()).is_err());
    assert!(json_canonical::<ModuleId>(&format!("\"{}\"", module.to_ascii_uppercase())).is_none());
}

/// `BlockGasInfo` JSON objects built from the fuzz bytes, with fuzz-chosen flaws (a missing,
/// extra or duplicated field, a number where a string belongs or the other way round, a
/// leading zero on an amount). Accepted iff it has none, as the value written.
fn block_gas_info_json(data: &[u8]) {
    let flags = data.first().copied().unwrap_or(0);
    let flaw =
        |bit: u8| flags & (1 << bit) != 0 && data.get(1).copied().unwrap_or(0) & (1 << bit) != 0;
    let limit = [u64_at(data, 1), u64_at(data, 2)];
    let used = [u64_at(data, 3), u64_at(data, 4)];
    let fee = [
        u128::from(u64_at(data, 5)) << (u64_at(data, 6) % 65),
        u128::from(u64_at(data, 7)),
    ];
    let gas = |g: [u64; 2], quoted: bool| {
        if quoted {
            format!("[\"{}\",\"{}\"]", g[0], g[1])
        } else {
            format!("[{},{}]", g[0], g[1])
        }
    };
    let leading_zero = flaw(5) && fee[0] != 0;
    let fee_json = if flaw(4) {
        format!("[{},{}]", fee[0], fee[1])
    } else {
        let zero = if leading_zero { "0" } else { "" };
        format!("[\"{zero}{}\",\"{}\"]", fee[0], fee[1])
    };
    let mut fields = vec![
        ("gas_limit", gas(limit, flaw(3))),
        ("gas_used", gas(used, false)),
        ("base_fee_per_gas", fee_json),
    ];
    let missing = flaw(0);
    if missing {
        fields.remove(usize::from(flags >> 6) % 3);
    }
    let extra = flaw(1);
    if extra {
        fields.push(("gas_refunded", gas(used, false)));
    }
    let duplicate = flaw(2);
    if duplicate {
        fields.push(fields[0].clone());
    }
    let shift = usize::from(data.get(2).copied().unwrap_or(0)) % fields.len();
    fields.rotate_left(shift);
    let json = format!(
        "{{{}}}",
        fields
            .iter()
            .map(|(name, value)| format!("\"{name}\":{value}"))
            .collect::<Vec<_>>()
            .join(",")
    );

    let valid = !(missing || extra || duplicate || flaw(3) || flaw(4) || leading_zero);
    match serde_json::from_str::<BlockGasInfo<GasUnit<2>>>(&json) {
        Ok(info) => {
            assert!(valid, "flawed BlockGasInfo accepted: {json}");
            let expected = BlockGasInfo::with_usage(
                GasUnit::from(limit),
                GasPrice::from(fee.map(Amount::new)),
                GasUnit::from(used),
            );
            assert_eq!(info, expected);
            assert_eq!(
                json_canonical::<BlockGasInfo<GasUnit<2>>>(&json),
                Some(expected)
            );
        }
        Err(e) => assert!(!valid, "valid BlockGasInfo rejected: {json}: {e}"),
    }
}

fuzz_target!(|data: &[u8]| {
    binary(data);
    arithmetic(data);
    meters(data);
    id_strings(data);
    block_gas_info_json(data);
    if let Ok(s) = std::str::from_utf8(data) {
        text(s);
    }
});
