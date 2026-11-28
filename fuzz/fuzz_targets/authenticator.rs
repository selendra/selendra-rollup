//! The native authenticator (`selendra_modules_api::authenticator`) on a test runtime, over a
//! `FullyBakedTx` that is the fuzz bytes, or one of the signed S10 vectors in its envelope with
//! bytes changed, at a rollup height where version 1, both versions or version 2 are accepted:
//!
//! - no panic, ever;
//! - `Envelope::parse` accepts exactly what `AuthenticatorInput`'s borsh decoder accepts, with
//!   the same tag and bytes, and re-encodes to the input;
//! - with an unlimited budget authentication is never out of gas; a fatal error carries the
//!   SHA-256 of the transaction's data, and is `DeserializationFailed` for an envelope that
//!   parses only if its transaction is not a canonical encoding (stage 5 computes the payload's
//!   length from the transaction's: exact for every canonical one); a success has that hash, a replay hash that is the
//!   SHA-256 of the signed bytes (rebuilt here from the transaction, its version's window and
//!   the chain ID), and the call of the transaction in the envelope, which decodes canonically;
//!   the unregistered path agrees with it;
//! - with any budget, the result and the gas used are the unlimited run's if the budget covers
//!   that gas, and otherwise the result is out of gas with no more gas used than the budget or
//!   the unlimited run (every stage is charged before its work, and a refused charge changes
//!   nothing).
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use selendra_interface::Bytes;
use selendra_interface::common::{RollupHeight, VisibleSlotNumber};
use selendra_interface::stf::FullyBakedTx;
use selendra_modules_api::authenticator::{
    AuthenticatorInput, AuthenticatorKind, Envelope, RuntimeVersions, SelendraAuthenticator,
};
use selendra_modules_api::capabilities::{
    AuthenticationError, AuthenticationOutput, BatchFromUnregisteredSequencer, FatalError,
    TransactionAuthenticator,
};
use selendra_modules_api::test_utils::{MockKernel, TestSpec, TestStorage};
use selendra_modules_api::transaction::{
    Transaction, TransactionCallable, TxCryptoSpec, VersionTable, VersionWindow,
};
use selendra_modules_api::{
    BasicGasMeter, GasArray, GasMeter, GasPrice, GasUnit, Metered, PreExecWorkingSet,
};
use selendra_primitives::crypto::{Ed25519CryptoSpec, EvmCryptoSpec};
use selendra_state::{ArrayWitness, CheckpointVersions, TxScratchpad};
use sha2::Digest;

/// The call type of the vectors.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
    serde::Serialize,
    serde::Deserialize,
    selendra_modules_api::ConsensusType,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum VectorCall {
    Ping(u64),
    Data(Vec<u8>),
}

struct VectorRuntime;

impl TransactionCallable for VectorRuntime {
    type Call = VectorCall;
}

const CHAIN_ID: u64 = 1961;

/// Version 1 (the V0 vectors' schema hash `0x00 01 … 1f`) until height 20, version 2 (the V1
/// vectors', `[0x22; 32]`) from height 10.
struct Versions;

impl RuntimeVersions for Versions {
    const VERSIONS: VersionTable<'static> = VersionTable::new_or_panic(&[
        VersionWindow::closed(
            1,
            [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31,
            ],
            0,
            20,
        ),
        VersionWindow::open(2, [0x22; 32], 10),
    ]);
}

type S = TestSpec;
type Auth = SelendraAuthenticator<S, VectorRuntime, Versions>;

/// The signed transactions of `crates/modules-api/src/transaction/tests/vectors.rs`, with their
/// envelope tags: V0 ed25519, V0 secp256k1, V1 ed25519, V1 secp256k1.
const VECTORS: [(u8, &str); 4] = [
    (
        0,
        "00d66f77b9d6242cba123abab44188dabf454c58f818b60ee9079366835f9d98089b68430d5f15cdc8dd2159aa9c612be37f80392e594401c1a3aff4b9b0aefa0bd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a010800000073656c656e647261000500000000000000640000000000000040420f00000000000000000000000000011027000000000000204e0000000000000100000000",
    ),
    (
        1,
        "00441cb2b78cca7760c673a29e52a43ba3a2af92196c7cdf602a2de4750b826271599e9927312c6deb5d7da66f3a075cfd80ffd256617f44b3f01da1d9d5976ddc024e3b81af9c2234cad09d679ce6035ed1392347ce64ce405f5dcd36228a25de6e002a00000000000000010300000000000000000000000000000088130000000000000000000000000000000100000001010102030405060708090a0b0c0d0e0f1011121314",
    ),
    (
        0,
        "0102000000268db25b73ccef1b9f884bbab0c09a0eefce28c78293229b474712c4ad305774b276d9d9e37f5054bd4386115ce64319925644e9431ac3d21b20fcbf12545d0f3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c7c3a595eba9710218bc657b84cfec04e80be19cdaa6ebcc2308127189a00b0c7ffa73802ab7dfbb8ad0673ca141bce598552c309327d1a49b1b12d80d438a703d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a01000000ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1020100000000020900000000000000fa000000000000004d00000000000000000000000000000000020000000100abababababababababababababababababababababababababababab",
    ),
    (
        1,
        "01010000000a9668588ebf1af06e6f1d9787b6af0b1a0a575005b02d54aa3361894fd9aec82c3ae8f741727fd8dbf2f2474811caeab924e5acc7439afd4678ebef66147ba30279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179801000000024e3b81af9c2234cad09d679ce6035ed1392347ce64ce405f5dcd36228a25de6e0100070000000000000000000000000000000001000000000000000100000000000000000000000000000001010000000000000002000000000000000200000000",
    ),
];

/// Heights where version 1 only, both versions and version 2 only are accepted.
const HEIGHTS: [u64; 3] = [5, 15, 25];

fn unhex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// A storage per height of `HEIGHTS`, its kernel state holding the height.
fn storages() -> &'static [TestStorage; 3] {
    static STORAGES: OnceLock<[TestStorage; 3]> = OnceLock::new();
    STORAGES.get_or_init(|| {
        HEIGHTS.map(|height| {
            TestStorage::default().commit_with(|state| {
                MockKernel::write_versions(
                    state,
                    CheckpointVersions {
                        visible_slot_number: VisibleSlotNumber::new_dangerous(height),
                        rollup_height: RollupHeight::new(height),
                    },
                );
            })
        })
    })
}

fn state(height: usize, budget: GasUnit<2>) -> PreExecWorkingSet<S> {
    let checkpoint = MockKernel::checkpoint(storages()[height].clone(), ArrayWitness::default());
    PreExecWorkingSet::new(
        TxScratchpad::new(checkpoint),
        BasicGasMeter::new_with_gas(budget, GasPrice::ZEROED),
    )
}

type Output = Result<AuthenticationOutput<S, VectorCall>, AuthenticationError>;

fn run(tx: &FullyBakedTx, height: usize, budget: GasUnit<2>) -> (Output, GasUnit<2>, bool) {
    let mut state = state(height, budget);
    let result = Auth::authenticate(tx, CHAIN_ID, &mut state);
    let used = state.gas_info().gas_used;
    (result, used, state.metered_view().is_poisoned())
}

/// The replay hash a success must have: the SHA-256 of the transaction's signed bytes.
fn replay_hash<C: TxCryptoSpec>(raw: &[u8], height: usize) -> [u8; 32] {
    let tx: Transaction<VectorRuntime, S, C> = borsh::from_slice(raw).unwrap();
    assert_eq!(
        borsh::to_vec(&tx).unwrap(),
        raw,
        "non-canonical transaction accepted"
    );
    let window = Versions::VERSIONS
        .resolve(
            RollupHeight::new(HEIGHTS[height]),
            tx.details().runtime_version,
        )
        .unwrap();
    let signed = tx.signing_bytes(CHAIN_ID, &window.schema_hash).unwrap();
    sha2::Sha256::digest(signed.as_bytes()).into()
}

/// Whether `raw` is the canonical encoding of a transaction signed with `C`.
fn is_canonical<C: TxCryptoSpec>(raw: &[u8]) -> bool {
    borsh::from_slice::<Transaction<VectorRuntime, S, C>>(raw)
        .is_ok_and(|tx| borsh::to_vec(&tx).unwrap() == raw)
}

fn check(data: &[u8], height: usize, budget: [u64; 2]) {
    // The envelope reader agrees with the borsh decoder.
    let parsed = Envelope::parse(data);
    let decoded = borsh::from_slice::<AuthenticatorInput>(data);
    assert_eq!(parsed.is_ok(), decoded.is_ok());
    if let (Ok(envelope), Ok(input)) = (parsed, &decoded) {
        assert_eq!(envelope.kind(), input.kind());
        assert_eq!(envelope.raw_tx(), input.raw_tx().as_bytes());
        assert_eq!(input.to_bytes(), data);
        assert_eq!(input.to_fully_baked_tx().data()[..], *data);
    }

    let Ok(tx) = FullyBakedTx::new(Bytes::copy_from_slice(data)) else {
        return;
    };
    let tx_hash: [u8; 32] = sha2::Sha256::digest(data).into();
    let (unlimited, used, poisoned) = run(&tx, height, GasUnit::MAX);
    match &unlimited {
        Err(AuthenticationError::OutOfGas(error)) => panic!("out of gas without a limit: {error}"),
        Err(AuthenticationError::FatalError(error, hash)) => {
            assert_eq!(hash.0, tx_hash);
            assert!(!poisoned);
            if let (FatalError::DeserializationFailed(reason), Ok(envelope)) =
                (error, Envelope::parse(data))
            {
                let canonical = match envelope.kind() {
                    AuthenticatorKind::Ed25519 => {
                        is_canonical::<Ed25519CryptoSpec>(envelope.raw_tx())
                    }
                    AuthenticatorKind::Secp256k1 => {
                        is_canonical::<EvmCryptoSpec>(envelope.raw_tx())
                    }
                    kind => panic!("parsed under {kind:?}"),
                };
                assert!(
                    !canonical,
                    "a canonical transaction did not decode: {reason}"
                );
            }
        }
        Ok(output) => {
            assert!(!poisoned);
            assert_eq!(output.auth_data.tx_hash().0, tx_hash);
            let envelope = Envelope::parse(data).unwrap();
            let raw = envelope.raw_tx();
            let expected = match envelope.kind() {
                AuthenticatorKind::Ed25519 => replay_hash::<Ed25519CryptoSpec>(raw, height),
                AuthenticatorKind::Secp256k1 => replay_hash::<EvmCryptoSpec>(raw, height),
                kind => panic!("authenticated under {kind:?}"),
            };
            assert_eq!(output.auth_data.non_malleable_hash().0, expected);
            let mut state = state(height, GasUnit::MAX);
            let batch = BatchFromUnregisteredSequencer {
                tx: tx.clone(),
                id: [0; 32],
            };
            assert_eq!(
                Auth::authenticate_unregistered(&batch, CHAIN_ID, &mut state).as_ref(),
                Ok(output)
            );
        }
    }

    let budget = GasUnit::from(budget);
    let (limited, limited_used, _) = run(&tx, height, budget);
    if used.dim_is_less_or_eq(budget) {
        assert_eq!(limited, unlimited);
        assert_eq!(limited_used, used);
    } else {
        assert!(
            matches!(limited, Err(AuthenticationError::OutOfGas(_))),
            "{limited:?} with {budget} < {used}"
        );
        assert!(limited_used.dim_is_less_or_eq(budget));
        assert!(limited_used.dim_is_less_or_eq(used));
    }
}

/// Reads the fuzz bytes front to back, zeros once they run out.
struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn u8(&mut self) -> u8 {
        match self.0.split_first() {
            Some((first, rest)) => {
                self.0 = rest;
                *first
            }
            None => 0,
        }
    }

    fn u16(&mut self) -> u16 {
        u16::from_le_bytes([self.u8(), self.u8()])
    }
}

fuzz_target!(|data: &[u8]| {
    let mut reader = Reader(data);
    let mode = reader.u8();
    let height = usize::from(mode >> 2) % HEIGHTS.len();
    // A budget around the vectors' costs (tens of thousands of gas), per dimension.
    let budget = [u64::from(reader.u16()) * 4, u64::from(reader.u16()) * 4];
    if mode & 1 == 0 {
        check(reader.0, height, budget);
        return;
    }
    // A vector in its envelope (possibly under another tag), with bytes changed.
    let (tag, tx) = VECTORS[usize::from(reader.u8()) % VECTORS.len()];
    let raw = unhex(tx);
    let mut envelope = vec![if mode & 2 == 0 { tag } else { reader.u8() % 5 }];
    envelope.extend(u32::try_from(raw.len()).unwrap().to_le_bytes());
    envelope.extend(raw);
    let changes = reader.u8() % 4;
    for _ in 0..changes {
        let at = usize::from(reader.u16()) % envelope.len();
        envelope[at] ^= reader.u8();
    }
    match reader.u8() % 8 {
        0 => {
            let len = envelope.len() - usize::from(reader.u8()) % 8;
            envelope.truncate(len.max(1));
        }
        1 => envelope.extend_from_slice(reader.0),
        _ => {}
    }
    check(&envelope, height, budget);
});
