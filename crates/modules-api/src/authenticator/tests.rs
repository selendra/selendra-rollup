//! The native authenticator: the signing vectors through the envelope, the runtime binding, the
//! hashes, the envelope's rules, the gas of every stage, the unregistered path.
//!
//! Most tests use the signed transactions of the S10 vectors (`transaction/tests/vectors.rs`:
//! chain ID 1961, runtime version 1 with the schema hash `0x00 01 … 1f` and version 2 with
//! `[0x22; 32]`), so they run in the guest configuration too; the tests that sign need `native`.

use core::cell::Cell;

use borsh::{BorshDeserialize, BorshSerialize};
use selendra_interface::Bytes;
use selendra_interface::TxHash;
use selendra_interface::common::{HexHash, RollupHeight, VisibleSlotNumber};
use selendra_interface::stf::{FullyBakedTx, MAX_RAW_TX_SIZE, RawTx};
use selendra_primitives::crypto::{
    Ed25519CryptoSpec, Ed25519PublicKey, EthereumPublicKey, EvmCryptoSpec,
    count_ethereum_address_derivations,
};
use selendra_primitives::{Address, EthereumAddress, MultiAddressEvm};
use selendra_state::metered::Metered;
use selendra_state::{ArrayWitness, CheckpointVersions, TxScratchpad};
use sha2::Digest;

use super::*;
use crate::capabilities::{
    AuthenticationError, AuthenticationOutput, BatchFromUnregisteredSequencer, FatalError,
    TransactionAuthenticator, UnregisteredAuthenticationError,
};
use crate::test_utils::{DistinctCostSpec, MockKernel, TestSpec, TestStorage};
use crate::transaction::tests::{VectorCall, VectorRuntime, vectors};
use crate::transaction::{
    MultisigError, SchemaHash, Transaction, TransactionCallable, TransactionError, UniquenessData,
    Version0, VersionTable, VersionWindow,
};
use crate::{
    AccountAddress, BasicGasMeter, Credential, GasArray, GasMeter, GasPrice, GasUnit,
    PreExecWorkingSet, Spec,
};

const CHAIN_ID: u64 = 1961;
const SCHEMA_1: SchemaHash = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];
const SCHEMA_2: SchemaHash = [0x22; 32];

/// Version 1 from genesis until height 20, version 2 from height 10: both accepted at 10..20
/// (version 1's grace period).
struct Versions;

impl RuntimeVersions for Versions {
    const VERSIONS: VersionTable<'static> = VersionTable::new_or_panic(&[
        VersionWindow::closed(1, SCHEMA_1, 0, 20),
        VersionWindow::open(2, SCHEMA_2, 10),
    ]);
}

/// Like [`Versions`], but version 1 has another schema hash.
struct OtherSchema;

impl RuntimeVersions for OtherSchema {
    const VERSIONS: VersionTable<'static> = VersionTable::new_or_panic(&[
        VersionWindow::closed(1, [0x33; 32], 0, 20),
        VersionWindow::open(2, SCHEMA_2, 10),
    ]);
}

type Auth = SelendraAuthenticator<TestSpec, VectorRuntime, Versions>;

/// A height where both versions are accepted.
const GRACE: u64 = 15;

fn bytes(hex: &str) -> Vec<u8> {
    hex::decode(hex).unwrap()
}

fn parse<T: core::str::FromStr<Err = anyhow::Error>>(hex: &str) -> T {
    format!("0x{hex}").parse().unwrap()
}

fn hash(hex: &str) -> TxHash {
    HexHash::new(bytes(hex).try_into().unwrap())
}

/// `raw` in an envelope with `tag`, built by hand.
fn baked(tag: u8, raw: &[u8]) -> FullyBakedTx {
    let mut data = vec![tag];
    data.extend(u32::try_from(raw.len()).unwrap().to_le_bytes());
    data.extend_from_slice(raw);
    FullyBakedTx::new(Bytes::from(data)).unwrap()
}

/// A storage whose kernel state says rollup height `height`.
fn storage(height: u64) -> TestStorage {
    TestStorage::default().commit_with(|state| {
        MockKernel::write_versions(
            state,
            CheckpointVersions {
                visible_slot_number: VisibleSlotNumber::new_dangerous(height),
                rollup_height: RollupHeight::new(height),
            },
        );
    })
}

/// The pre-execution state at rollup height `height`, with `budget` gas (price zero, no funds
/// budget).
fn state_with<Sp: Spec<Storage = TestStorage, Gas = GasUnit<2>>>(
    height: u64,
    budget: [u64; 2],
) -> PreExecWorkingSet<Sp> {
    let checkpoint = MockKernel::checkpoint(storage(height), ArrayWitness::default());
    PreExecWorkingSet::new(
        TxScratchpad::new(checkpoint),
        BasicGasMeter::new_with_gas(GasUnit::from(budget), GasPrice::ZEROED),
    )
}

fn state(height: u64) -> PreExecWorkingSet<TestSpec> {
    state_with(height, [u64::MAX; 2])
}

fn gas_used<Sp: Spec<Gas = GasUnit<2>>>(state: &PreExecWorkingSet<Sp>) -> [u64; 2] {
    *state.gas_info().gas_used.as_ref()
}

/// A vector: its tag, its transaction, its signed bytes, its call.
struct Vector {
    tag: u8,
    tx: &'static str,
    signing_bytes: &'static str,
    /// `SHA-256` of the envelope (`python3 -I -c 'import hashlib …'`).
    tx_hash: &'static str,
    /// `SHA-256` of the signed bytes (likewise).
    non_malleable_hash: &'static str,
    call: fn() -> VectorCall,
}

impl Vector {
    fn baked(&self) -> FullyBakedTx {
        baked(self.tag, &bytes(self.tx))
    }
}

const V0_ED25519: Vector = Vector {
    tag: 0,
    tx: vectors::v0_ed25519::TX,
    signing_bytes: vectors::v0_ed25519::SIGNING_BYTES,
    tx_hash: "2047134903c7bb40296db96124dbe37fbcee81e86b82d62e3db25fd8323c9380",
    non_malleable_hash: "74626927a0a5972b666017a39cc6c8d302de26b683d0dbcada799b2d91c0f4c7",
    call: || VectorCall::Data(b"selendra".to_vec()),
};

const V0_SECP256K1: Vector = Vector {
    tag: 1,
    tx: vectors::v0_secp256k1::TX,
    signing_bytes: vectors::v0_secp256k1::SIGNING_BYTES,
    tx_hash: "c4cb00975df7d95dc74d10976b04bbc9e6676079c6868fb0c5f517db22ce4559",
    non_malleable_hash: "ff36435a1ec2f68c4121973d0933c28033dc4b419ad69d8bd3fdf7c353da2947",
    call: || VectorCall::Ping(42),
};

const V1_ED25519: Vector = Vector {
    tag: 0,
    tx: vectors::v1_ed25519::TX,
    signing_bytes: vectors::v1_ed25519::SIGNING_BYTES,
    tx_hash: "c7a07541f3f9ae5aee5f659ee99fa3a012998ed2b0f6704095db043ae8864115",
    non_malleable_hash: "cb7c7a00f14f3b6dde10289890d6cbe908fecdba94d65bdf3a887f05b94bf6d6",
    call: || VectorCall::Data(Vec::new()),
};

const V1_SECP256K1: Vector = Vector {
    tag: 1,
    tx: vectors::v1_secp256k1::TX,
    signing_bytes: vectors::v1_secp256k1::SIGNING_BYTES,
    tx_hash: "61d3fc17c6f9842f11186b36fea51dfbb7eff46837093add48ef3eeb1f5a1b50",
    non_malleable_hash: "437a593279068601b55184ab427918afb3841affdf3f6412ed2b20e7b76b1efe",
    call: || VectorCall::Ping(7),
};

const VECTORS: [&Vector; 4] = [&V0_ED25519, &V0_SECP256K1, &V1_ED25519, &V1_SECP256K1];

fn authenticate<Sp: Spec<Storage = TestStorage, Gas = GasUnit<2>>, V: RuntimeVersions>(
    tx: &FullyBakedTx,
    state: &mut PreExecWorkingSet<Sp>,
) -> Result<AuthenticationOutput<Sp, VectorCall>, AuthenticationError> {
    SelendraAuthenticator::<Sp, VectorRuntime, V>::authenticate(tx, CHAIN_ID, state)
}

fn fatal(
    result: Result<AuthenticationOutput<TestSpec, VectorCall>, AuthenticationError>,
) -> FatalError {
    match result {
        Err(AuthenticationError::FatalError(error, _)) => error,
        other => panic!("not a fatal error: {other:?}"),
    }
}

fn is_signature_failure(error: &FatalError) -> bool {
    matches!(error, FatalError::SigVerificationFailed(_))
}

// -------------------------------------------------------------------------------------------
// The vectors

/// Every vector authenticates in its envelope, with the hashes, credential, default address,
/// details and call it carries.
#[test]
fn vectors_authenticate() {
    let ed1: Ed25519PublicKey = parse(vectors::v0_ed25519::PUB_KEY);
    let secp: EthereumPublicKey = parse(vectors::v0_secp256k1::PUB_KEY);
    let eth: EthereumAddress = parse(vectors::v0_secp256k1::ETH_ADDRESS);
    let multisig_ed = selendra_interface::crypto::CredentialId::from_bytes(
        bytes(vectors::v1_ed25519::CREDENTIAL).try_into().unwrap(),
    );
    let multisig_secp = selendra_interface::crypto::CredentialId::from_bytes(
        bytes(vectors::v1_secp256k1::CREDENTIAL).try_into().unwrap(),
    );
    let expected = [
        (
            Credential::Ed25519(ed1.clone()),
            MultiAddressEvm::Standard(Address::from_hash_prefix(ed1.bytes())),
            UniquenessData::Nonce(5),
            1,
        ),
        (
            Credential::Secp256k1(secp),
            MultiAddressEvm::Vm(eth),
            UniquenessData::Generation(3),
            1,
        ),
        (
            Credential::Multisig(multisig_ed),
            MultiAddressEvm::Standard(Address::from_hash_prefix(multisig_ed.as_bytes())),
            UniquenessData::Window(9),
            2,
        ),
        (
            Credential::Multisig(multisig_secp),
            MultiAddressEvm::Standard(Address::from_hash_prefix(multisig_secp.as_bytes())),
            UniquenessData::Nonce(0),
            2,
        ),
    ];
    for (vector, (credential, address, uniqueness, version)) in VECTORS.into_iter().zip(expected) {
        let tx = vector.baked();
        let mut state = state(GRACE);
        let output = authenticate::<_, Versions>(&tx, &mut state).unwrap();
        assert_eq!(output.auth_data.tx_hash(), &hash(vector.tx_hash));
        assert_eq!(
            output.auth_data.non_malleable_hash(),
            &hash(vector.non_malleable_hash)
        );
        assert_eq!(output.auth_data.credential(), &credential);
        assert_eq!(
            output.auth_data.credential_id(),
            &credential.credential_id()
        );
        assert_eq!(output.auth_data.default_address(), &address);
        assert_eq!(output.auth_data.uniqueness(), uniqueness);
        assert_eq!(output.tx.0.runtime_version, version);
        assert_eq!(output.call, (vector.call)());
        assert!(!state.metered_view().is_poisoned());
        // The hash the node computes unmetered is the same.
        #[cfg(feature = "native")]
        {
            assert_eq!(Auth::compute_tx_hash(&tx), hash(vector.tx_hash));
            assert_eq!(Auth::decode_serialized_tx(&tx).unwrap(), (vector.call)());
        }
    }
    // The address overrides travel unchanged.
    let mut state = state(GRACE);
    let output = authenticate::<_, Versions>(&V0_SECP256K1.baked(), &mut state).unwrap();
    let vm: [u8; 20] = std::array::from_fn(|i| u8::try_from(i + 1).unwrap());
    assert_eq!(
        output.auth_data.address_override(),
        Some(&MultiAddressEvm::Vm(EthereumAddress::new(vm)))
    );
}

// Regressions of upstream's authenticator bugs

/// P5-08 (regression, the authenticator path): the account of an EVM key's transaction is its
/// `0x…` address (`Vm`) on the authenticator path, the same as `AccountAddress::default_for`.
/// Upstream's native authenticator set `default_address = credential_id.into()`, a `Standard`
/// address of the credential's first 28 bytes (here: the address of
/// `Credential::Multisig(credential_id)`, which is that rule), which nobody funds.
#[test]
fn evm_key_resolves_to_vm_on_every_path() {
    let secp: EthereumPublicKey = parse(vectors::v0_secp256k1::PUB_KEY);
    let eth: EthereumAddress = parse(vectors::v0_secp256k1::ETH_ADDRESS);
    let mut state = state(GRACE);
    let output = authenticate::<_, Versions>(&V0_SECP256K1.baked(), &mut state).unwrap();
    assert_eq!(
        output.auth_data.default_address(),
        &MultiAddressEvm::Vm(eth)
    );
    assert_eq!(
        output.auth_data.default_address(),
        &<TestSpec as Spec>::Address::default_for(&Credential::Secp256k1(secp))
    );
    // Upstream's rule gives another account.
    let upstream = <TestSpec as Spec>::Address::default_for(&Credential::Multisig(
        Credential::Secp256k1(secp).credential_id(),
    ));
    assert_ne!(output.auth_data.default_address(), &upstream);

    // The capabilities resolve the transaction to that account (without its override, which
    // they did not allow).
    let mut capabilities = crate::test_utils::MockCapabilities::<TestSpec>::new();
    let no_override = crate::transaction::AuthorizationData::<TestSpec>::new(
        output.auth_data.uniqueness(),
        *output.auth_data.tx_hash(),
        *output.auth_data.non_malleable_hash(),
        output.auth_data.credential().clone(),
        None,
    );
    let context = crate::capabilities::TransactionAuthorizer::resolve_context(
        &mut capabilities,
        &no_override,
        &crate::test_utils::MockAddress::new([1; 32]),
        MultiAddressEvm::Standard(Address::new([2; 28])),
        &mut state,
        None,
        crate::ExecutionContext::Node,
        crate::SequencerType::Preferred,
    )
    .unwrap();
    assert_eq!(context.sender(), &MultiAddressEvm::Vm(eth));
    assert!(
        crate::capabilities::TransactionAuthorizer::resolve_context(
            &mut capabilities,
            &output.auth_data,
            &crate::test_utils::MockAddress::new([1; 32]),
            MultiAddressEvm::Standard(Address::new([2; 28])),
            &mut state,
            None,
            crate::ExecutionContext::Node,
            crate::SequencerType::Preferred,
        )
        .is_err()
    );
}

/// P5-38 (regression): the transaction hash covers the envelope tag. The same transaction bytes
/// under two tags have two hashes (upstream hashed the inner bytes, so both had one hash: a
/// receipt could not tell which authenticator read the transaction).
#[test]
fn tx_hash_covers_envelope_tag() {
    let raw = bytes(V0_ED25519.tx);
    let as_ed25519 = baked(0, &raw);
    let as_secp256k1 = baked(1, &raw);
    let output = authenticate::<_, Versions>(&as_ed25519, &mut state(GRACE)).unwrap();
    // An ed25519 transaction does not decode as a secp256k1 one; the error carries its hash.
    let Err(AuthenticationError::FatalError(FatalError::DeserializationFailed(_), other)) =
        authenticate::<_, Versions>(&as_secp256k1, &mut state(GRACE))
    else {
        panic!("decoded as secp256k1");
    };
    assert_ne!(output.auth_data.tx_hash(), &other);
    assert_eq!(output.auth_data.tx_hash(), &hash(V0_ED25519.tx_hash));
    let digest = |data: &[u8]| HexHash::new(sha2::Sha256::digest(data).into());
    assert_eq!(other, digest(as_secp256k1.data()));
    // Upstream's hash: the inner bytes only.
    assert_ne!(output.auth_data.tx_hash(), &digest(&raw));
    assert_ne!(other, digest(&raw));
}

/// P5-35 (regression): the replay hash of every version is the hash of the signed bytes.
/// Upstream used the raw transaction hash as the V0 replay hash, so another encoding of the same
/// signed V0 transaction (in generation mode) was a new transaction.
#[test]
fn replay_hash_is_signing_bytes_hash() {
    for vector in VECTORS {
        let output = authenticate::<_, Versions>(&vector.baked(), &mut state(GRACE)).unwrap();
        let signed: [u8; 32] = sha2::Sha256::digest(bytes(vector.signing_bytes)).into();
        assert_eq!(output.auth_data.non_malleable_hash(), &HexHash::new(signed));
        assert_eq!(
            output.auth_data.non_malleable_hash(),
            &hash(vector.non_malleable_hash)
        );
        assert_ne!(
            output.auth_data.non_malleable_hash(),
            output.auth_data.tx_hash()
        );
    }
}

/// P5-35 (the encodings): re-encodings of one signed transaction have one replay hash, and the
/// key and signature encodings that would give a V0 transaction a second encoding are rejected
/// when it is decoded: a secp256k1 key in SEC1 compact form (`0x05`), a high-S signature (`n -
/// s`, computed with Python), a signature with a bit flipped.
#[test]
fn reencoded_transactions_share_the_replay_hash_or_do_not_decode() {
    // V1: the signatures listed in the other order.
    let tx: Transaction<VectorRuntime, TestSpec, Ed25519CryptoSpec> =
        borsh::from_slice(&bytes(V1_ED25519.tx)).unwrap();
    let Transaction::V1(mut swapped) = tx.clone() else {
        unreachable!()
    };
    swapped.signatures.reverse();
    let swapped = Transaction::V1(swapped);
    let reencoded = borsh::to_vec(&swapped).unwrap();
    assert_ne!(reencoded, bytes(V1_ED25519.tx));
    let original = authenticate::<_, Versions>(&V1_ED25519.baked(), &mut state(GRACE)).unwrap();
    let other = authenticate::<_, Versions>(&baked(0, &reencoded), &mut state(GRACE)).unwrap();
    assert_ne!(original.auth_data.tx_hash(), other.auth_data.tx_hash());
    assert_eq!(
        original.auth_data.non_malleable_hash(),
        other.auth_data.non_malleable_hash()
    );

    // V0 secp256k1: the signature is the first 64 bytes after the version tag, the key the next
    // 33.
    let raw = bytes(V0_SECP256K1.tx);
    let mut compact = raw.clone();
    assert!(matches!(compact[65], 0x02 | 0x03));
    compact[65] = 0x05;
    const HIGH_S: &str = "441cb2b78cca7760c673a29e52a43ba3a2af92196c7cdf602a2de4750b826271a66166d8ced39214a2825990c5f8a30139af0a904dc95b87cfb4bcb2fa9ed365";
    let mut high_s = raw.clone();
    assert_eq!(hex::encode(&raw[1..65]), vectors::v0_secp256k1::SIGNATURE);
    high_s[1..65].copy_from_slice(&bytes(HIGH_S));
    for rejected in [compact, high_s] {
        assert!(matches!(
            fatal(authenticate::<_, Versions>(
                &baked(1, &rejected),
                &mut state(GRACE)
            )),
            FatalError::DeserializationFailed(_)
        ));
    }
    // A flipped bit in the signature's `r`: still a valid encoding, which fails the signature
    // check.
    let mut flipped = raw;
    flipped[2] ^= 1;
    let error = fatal(authenticate::<_, Versions>(
        &baked(1, &flipped),
        &mut state(GRACE),
    ));
    assert!(is_signature_failure(&error), "{error:?}");
}

/// P5-37 (regression): the authenticator reads the envelope in place. Upstream decoded
/// `AuthenticatorInput` with borsh, copying up to 1 MiB before any gas was charged. Pinned here:
/// `Envelope::parse` borrows the transaction's bytes; the envelope the authenticator's own
/// stage-1 path (`hash_and_parse`, which both entry points use) hands on is that borrow of the
/// `FullyBakedTx`, after the transaction hash and nothing else was charged; and a budget that
/// does not cover the transaction hash (stage 1, the first work) stops authentication with
/// nothing charged. An `AuthenticatorInput` decoded and thrown away (upstream's copy) charges
/// nothing and changes no output: `one_authentication_decodes_and_encodes_the_call_once`
/// counts those decodes (none, on both entry points). A copy made otherwise (`to_vec` of the
/// bytes, a `RawTx` decoded or cloned) is not counted: no test shows it.
#[test]
fn out_of_gas_before_decode_copies_nothing() {
    let raw = vec![7u8; MAX_RAW_TX_SIZE];
    let tx = baked(0, &raw);
    let in_place = &tx.data()[ENVELOPE_HEADER_LEN..];
    let envelope = Envelope::parse(tx.data()).unwrap();
    assert_eq!(envelope.raw_tx().len(), MAX_RAW_TX_SIZE);
    assert!(core::ptr::eq(envelope.raw_tx(), in_place));

    let costs = <TestSpec as Spec>::GAS_SCHEDULE.state;
    let stage_1 = costs
        .hash_per_byte
        .checked_scalar_product(u64::try_from(tx.data().len()).unwrap())
        .unwrap();
    let mut state = state(GRACE);
    let Ok((tx_hash, envelope)) = Auth::hash_and_parse(&tx, &mut state) else {
        panic!("the envelope does not parse");
    };
    assert!(core::ptr::eq(envelope.raw_tx(), in_place));
    assert_eq!(envelope.kind(), AuthenticatorKind::Ed25519);
    assert_eq!(
        tx_hash,
        HexHash::new(sha2::Sha256::digest(tx.data()).into())
    );
    let through_stage_1 = stage_1.checked_combine(costs.hash_update).unwrap();
    assert_eq!(gas_used(&state), *through_stage_1.as_ref());
    let mut state = state_with::<TestSpec>(GRACE, [stage_1.as_ref()[0] - 1; 2]);
    assert!(matches!(
        authenticate::<_, Versions>(&tx, &mut state),
        Err(AuthenticationError::OutOfGas(_))
    ));
    assert_eq!(gas_used(&state), [0, 0]);
    assert!(state.metered_view().is_poisoned());
}

// -------------------------------------------------------------------------------------------
// Work no charge shows

thread_local! {
    /// How many times this thread decoded a [`CountedCall`].
    static CALL_DECODES: Cell<u64> = const { Cell::new(0) };
    /// How many times this thread encoded a [`CountedCall`] (`borsh::object_length` included:
    /// it encodes into a counter).
    static CALL_ENCODES: Cell<u64> = const { Cell::new(0) };
    /// How many times this thread decoded an [`AuthenticatorInput`] (its `BorshDeserialize`).
    pub(super) static ENVELOPE_DECODES: Cell<u64> = const { Cell::new(0) };
}

/// [`VectorCall`] with the same encodings, counting (per thread) its borsh decodes and encodes.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, crate::ConsensusType,
)]
#[serde(transparent)]
struct CountedCall(VectorCall);

impl BorshSerialize for CountedCall {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        CALL_ENCODES.with(|count| count.set(count.get() + 1));
        self.0.serialize(writer)
    }
}

impl BorshDeserialize for CountedCall {
    fn deserialize_reader<Rd: borsh::io::Read>(reader: &mut Rd) -> borsh::io::Result<Self> {
        CALL_DECODES.with(|count| count.set(count.get() + 1));
        VectorCall::deserialize_reader(reader).map(Self)
    }
}

/// A runtime whose calls are [`CountedCall`]s: the vectors decode and verify under it.
struct CountingRuntime;

impl TransactionCallable for CountingRuntime {
    type Call = CountedCall;
}

/// Work a function did that no gas charge shows, counted on this thread ([`count_work`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Work {
    /// [`CountedCall`] decodes.
    call_decodes: u64,
    /// [`CountedCall`] encodes.
    call_encodes: u64,
    /// Ethereum addresses derived from secp256k1 keys (every derivation:
    /// `EthereumPublicKey::ethereum_address`, counted by `selendra-primitives`).
    evm_addresses: u64,
    /// Multisigs built or tried (`Multisig::new`: the keys copied, sorted and compared).
    multisig_builds: u64,
    /// [`AuthenticatorInput`] decodes (the copy of the transaction upstream made, P5-37).
    envelope_decodes: u64,
}

/// The work `f` does ([`Work`]), and its result.
fn count_work<T>(f: impl FnOnce() -> T) -> (Work, T) {
    CALL_DECODES.with(|count| count.set(0));
    CALL_ENCODES.with(|count| count.set(0));
    ENVELOPE_DECODES.with(|count| count.set(0));
    let (evm_addresses, (multisig_builds, result)) =
        count_ethereum_address_derivations(|| crate::transaction::count_multisig_builds(f));
    let work = Work {
        call_decodes: CALL_DECODES.with(Cell::get),
        call_encodes: CALL_ENCODES.with(Cell::get),
        evm_addresses,
        multisig_builds,
        envelope_decodes: ENVELOPE_DECODES.with(Cell::get),
    };
    (work, result)
}

/// Work no gas charge shows, counted ([`Work`]). One authentication, for every vector (V0 and
/// V1, both schemes) on both entry points:
/// - decodes the call once (stage 2) and encodes it once (the signing payload, stage 5);
/// - never decodes the envelope into an [`AuthenticatorInput`] (P5-37: it is read in place);
/// - derives a V0 secp256k1 key's Ethereum address once (its credential id and its default
///   account are both that address, `AuthorizationData::new`), the other vectors' never (an
///   ed25519 key's id is its bytes, a multisig's a hash);
/// - builds a V1 vector's multisig once, a V0 vector's never.
///
/// With a charge refused (`DistinctCostSpec`, one unit short of it), nothing that charge pays
/// for ran: refused stage 5's encode or hash charge, the call was decoded and never encoded
/// (the payload's length comes from the transaction's, nothing walks the call before it is
/// paid for); refused the V1 credential's charge, the multisig was never built (its keys never
/// copied or sorted) and the call never encoded. An extra decode whose result is thrown away,
/// an extra walk of the call (`borsh::object_length` of the payload, as S11 first did), an
/// envelope decoded and thrown away, a multisig built before its charge (with its error
/// returned after it): each charges nothing and changes no output, and only counting shows it.
/// Not counted: a copy made otherwise (`to_vec` of the transaction's bytes, a `RawTx` decoded
/// or cloned, a key cloned outside `Multisig::new`).
#[test]
fn one_authentication_decodes_and_encodes_the_call_once() {
    for vector in VECTORS {
        let v1 = vector.tx == V1_ED25519.tx || vector.tx == V1_SECP256K1.tx;
        let expected = Work {
            call_decodes: 1,
            call_encodes: 1,
            evm_addresses: u64::from(core::ptr::eq(vector, &V0_SECP256K1)),
            multisig_builds: u64::from(v1),
            envelope_decodes: 0,
        };
        let (work, output) = count_work(|| {
            SelendraAuthenticator::<TestSpec, CountingRuntime, Versions>::authenticate(
                &vector.baked(),
                CHAIN_ID,
                &mut state(GRACE),
            )
        });
        assert_eq!(output.unwrap().call, CountedCall((vector.call)()));
        assert_eq!(work, expected, "{}", vector.tx);

        let batch = BatchFromUnregisteredSequencer {
            tx: vector.baked(),
            id: [9; 32],
        };
        let (work, output) = count_work(|| {
            SelendraAuthenticator::<TestSpec, CountingRuntime, Versions>::authenticate_unregistered(
                &batch,
                CHAIN_ID,
                &mut state(GRACE),
            )
        });
        assert_eq!(output.unwrap().call, CountedCall((vector.call)()));
        assert_eq!(work, expected, "unregistered {}", vector.tx);
    }

    // The index in `CHARGES` of the payload's encode charge (its hash charge is next): after
    // the key decodes, and for V1 the credential (the charge before it).
    for ((vector, charges), encode) in CHARGES.into_iter().zip([4, 4, 5, 5]) {
        let v1 = encode == 5;
        let refusals = if v1 {
            vec![encode - 1, encode, encode + 1]
        } else {
            vec![encode, encode + 1]
        };
        for refused in refusals {
            let before = sum(&charges[..refused]);
            let budget = [
                before[0] + charges[refused][0] - 1,
                before[1] + charges[refused][1] - 1,
            ];
            let mut state = state_with::<DistinctCostSpec>(GRACE, budget);
            let (work, result) = count_work(|| {
                SelendraAuthenticator::<DistinctCostSpec, CountingRuntime, Versions>::authenticate(
                    &vector.baked(),
                    CHAIN_ID,
                    &mut state,
                )
            });
            assert!(
                matches!(result, Err(AuthenticationError::OutOfGas(_))),
                "{refused}: {result:?}"
            );
            assert_eq!(gas_used(&state), before, "{refused}");
            let expected = Work {
                call_decodes: 1,
                // Built only once its credential is paid for.
                multisig_builds: u64::from(v1 && refused >= encode),
                ..Work::default()
            };
            assert_eq!(work, expected, "{}: charge {refused}", vector.tx);
        }
    }
}

/// A call type whose encoding is far longer than the bytes it decodes from: it decodes from a
/// `u16` LE `n` and encodes as `n` zero bytes, written one at a time, counting (per thread) the
/// writes it attempts and those the writer accepts.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, crate::ConsensusType,
)]
struct ExpandingCall(u16);

thread_local! {
    /// The 1-byte writes [`ExpandingCall`]s attempted, and those accepted.
    static EXPANDING_WRITES: Cell<[u64; 2]> = const { Cell::new([0, 0]) };
}

impl BorshSerialize for ExpandingCall {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        for _ in 0..self.0 {
            let written = writer.write_all(&[0]);
            EXPANDING_WRITES.with(|count| {
                let [attempted, accepted] = count.get();
                count.set([attempted + 1, accepted + u64::from(written.is_ok())]);
            });
            written?;
        }
        Ok(())
    }
}

impl BorshDeserialize for ExpandingCall {
    fn deserialize_reader<Rd: borsh::io::Read>(reader: &mut Rd) -> borsh::io::Result<Self> {
        u16::deserialize_reader(reader).map(Self)
    }
}

/// A runtime whose calls are [`ExpandingCall`]s.
struct ExpandingRuntime;

impl TransactionCallable for ExpandingRuntime {
    type Call = ExpandingCall;
}

/// Stage 5 encodes and hashes at most the payload length it charged for: the encoding stops at
/// the first write past it. Each vector with its call replaced by an [`ExpandingCall`] of 4096
/// bytes (decoded from 2): the payload's length, computed from the transaction's, is the
/// vector's payload length with the call's encoding replaced by those 2 bytes; the payload's
/// version tag (1 byte) comes before the call, so the call's writes are accepted up to that
/// length minus 1, the next one is refused and is the last attempted, and authentication is
/// `DeserializationFailed` (`NonCanonicalEncoding`). An encoding run to its end, its length
/// compared afterwards (or a writer that records the overflow and goes on), attempts all 4096.
#[test]
fn the_payload_encoding_stops_at_its_charged_length() {
    const EXPANDED: u16 = 4096;
    for vector in VECTORS {
        let raw = bytes(vector.tx);
        let call = borsh::to_vec(&(vector.call)()).unwrap();
        let at = raw
            .windows(call.len())
            .position(|window| window == call)
            .unwrap();
        assert!(
            raw[at + 1..]
                .windows(call.len())
                .all(|window| window != call),
            "the call's encoding is unique in {}",
            vector.tx
        );
        let expanded = [
            &raw[..at],
            &EXPANDED.to_le_bytes()[..],
            &raw[at + call.len()..],
        ]
        .concat();
        // The vector's payload length (its signed bytes' prehash is of it).
        let payload_len = if vector.tag == 0 {
            let tx: Transaction<VectorRuntime, TestSpec, Ed25519CryptoSpec> =
                borsh::from_slice(&raw).unwrap();
            tx.signing_payload(CHAIN_ID, schema(&tx))
                .unwrap()
                .encoded_len()
        } else {
            let tx: Transaction<VectorRuntime, TestSpec, EvmCryptoSpec> =
                borsh::from_slice(&raw).unwrap();
            tx.signing_payload(CHAIN_ID, schema(&tx))
                .unwrap()
                .encoded_len()
        }
        .unwrap();
        let charged = payload_len - call.len() + 2;
        let accepted = u64::try_from(charged - 1).unwrap();
        assert!(accepted < u64::from(EXPANDED));

        EXPANDING_WRITES.with(|count| count.set([0, 0]));
        let tx = baked(vector.tag, &expanded);
        let mut state = state(GRACE);
        let result = SelendraAuthenticator::<TestSpec, ExpandingRuntime, Versions>::authenticate(
            &tx, CHAIN_ID, &mut state,
        );
        let Err(AuthenticationError::FatalError(error, _)) = result else {
            panic!("{}: {result:?}", vector.tx);
        };
        assert_eq!(
            error,
            FatalError::DeserializationFailed(TransactionError::NonCanonicalEncoding.to_string()),
            "{}",
            vector.tx
        );
        assert_eq!(
            EXPANDING_WRITES.with(Cell::get),
            [accepted + 1, accepted],
            "{}",
            vector.tx
        );
        assert!(!state.metered_view().is_poisoned());
    }
}

/// The schema hash of the version `tx` names, in [`Versions`].
fn schema<R: TransactionCallable, S: Spec, C: crate::transaction::TxCryptoSpec>(
    tx: &Transaction<R, S, C>,
) -> &'static SchemaHash {
    match tx.details().runtime_version {
        1 => &SCHEMA_1,
        2 => &SCHEMA_2,
        other => panic!("version {other}"),
    }
}

/// A call type with a lax decoder: canonically `0xff` and the `u64` LE (9 bytes, what it
/// encodes to), but it also decodes a single byte below `0xfe` as that value, and `0xfe` with a
/// `u128` LE that fits a `u64` (17 bytes).
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, crate::ConsensusType,
)]
struct LaxCall(u64);

impl BorshSerialize for LaxCall {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        writer.write_all(&[0xff])?;
        self.0.serialize(writer)
    }
}

impl BorshDeserialize for LaxCall {
    fn deserialize_reader<Rd: borsh::io::Read>(reader: &mut Rd) -> borsh::io::Result<Self> {
        match u8::deserialize_reader(reader)? {
            0xff => u64::deserialize_reader(reader).map(Self),
            0xfe => u64::try_from(u128::deserialize_reader(reader)?)
                .map(Self)
                .map_err(borsh::io::Error::other),
            short => Ok(Self(u64::from(short))),
        }
    }
}

/// A runtime whose calls are [`LaxCall`]s.
struct LaxRuntime;

impl TransactionCallable for LaxRuntime {
    type Call = LaxCall;
}

/// Stage 5 charges for the payload's length as the transaction's encoding gives it (the bytes
/// stage 2 paid to decode, minus the signature, plus the runtime commitment), and the payload's
/// encoding stops at that length. A call decoded from bytes other than its own encoding
/// ([`LaxCall`]'s short and long forms) is `DeserializationFailed`
/// (`TransactionError::NonCanonicalEncoding`) having paid stages 1 to 5 for those bytes,
/// whether its encoding is longer than paid for (the 1-byte form: 8 bytes more, never encoded
/// past the charge: `the_payload_encoding_stops_at_its_charged_length` counts the writes) or
/// shorter (the 17-byte form). Its canonical form goes on to the signature
/// check (`SigVerificationFailed`: the vector's signature is over another call), having paid
/// for the payload exactly its length.
#[test]
fn the_payload_is_encoded_within_its_charged_length() {
    // The V0 ed25519 vector with its call (`Data(b"selendra")`: 13 bytes after the tag, the
    // signature and the key, 97 bytes) replaced.
    let vector = bytes(V0_ED25519.tx);
    assert_eq!(
        vector[97..110],
        borsh::to_vec(&VectorCall::Data(b"selendra".to_vec())).unwrap()[..]
    );
    let costs = DistinctCostSpec::GAS_SCHEDULE;
    let len = |n: usize| u64::try_from(n).unwrap();
    let canonical = [&[0xff][..], &7u64.to_le_bytes()].concat();
    let long = [&[0xfe][..], &7u128.to_le_bytes()].concat();
    for (call, canonical) in [(vec![7], false), (long, false), (canonical, true)] {
        let raw = [&vector[..97], &call, &vector[110..]].concat();
        let decoded: Transaction<LaxRuntime, DistinctCostSpec, Ed25519CryptoSpec> =
            borsh::from_slice(&raw).unwrap();
        assert_eq!(decoded.runtime_call(), &LaxCall(7));
        assert_eq!(borsh::to_vec(&decoded).unwrap() == raw, canonical);
        // What stage 5 charges for: the payload's length from the transaction's.
        let payload_len = raw.len() - 64 + 32;
        if canonical {
            let payload = decoded.signing_payload(CHAIN_ID, &SCHEMA_1).unwrap();
            assert_eq!(payload.encoded_len().unwrap(), payload_len);
        }
        let tx = baked(0, &raw);
        let through_payload = costs
            .state
            .hash_per_byte
            .checked_scalar_product(len(tx.data().len()))
            .and_then(|gas| gas.checked_combine(costs.state.hash_update))
            .and_then(|gas| {
                gas.checked_combine(
                    costs
                        .state
                        .decode_per_byte
                        .checked_scalar_product(len(raw.len()))?,
                )
            })
            .and_then(|gas| gas.checked_combine(costs.pubkey_decode.ed25519))
            .and_then(|gas| gas.checked_combine(costs.state.hash_update))
            .and_then(|gas| {
                gas.checked_combine(
                    costs
                        .encode_per_byte
                        .checked_scalar_product(len(payload_len))?,
                )
            })
            .and_then(|gas| {
                gas.checked_combine(
                    costs
                        .state
                        .hash_per_byte
                        .checked_scalar_product(len(payload_len))?,
                )
            })
            .unwrap();
        let mut state = state_with::<DistinctCostSpec>(GRACE, [u64::MAX; 2]);
        let result = SelendraAuthenticator::<DistinctCostSpec, LaxRuntime, Versions>::authenticate(
            &tx, CHAIN_ID, &mut state,
        );
        let Err(AuthenticationError::FatalError(error, _)) = result else {
            panic!("{call:?}: {result:?}");
        };
        if canonical {
            assert!(is_signature_failure(&error), "{error:?}");
            let rest = costs
                .state
                .hash_per_byte
                .checked_scalar_product(51)
                .and_then(|gas| gas.checked_combine(costs.state.hash_update))
                .and_then(|gas| gas.checked_combine(costs.sig_verify.ed25519))
                .and_then(|gas| {
                    gas.checked_combine(costs.sig_per_byte.ed25519.checked_scalar_product(51)?)
                })
                .unwrap();
            assert_eq!(
                gas_used(&state),
                *through_payload.checked_combine(rest).unwrap().as_ref()
            );
        } else {
            assert_eq!(
                error,
                FatalError::DeserializationFailed(
                    TransactionError::NonCanonicalEncoding.to_string()
                ),
                "{call:?}"
            );
            assert_eq!(gas_used(&state), *through_payload.as_ref(), "{call:?}");
        }
        assert!(!state.metered_view().is_poisoned());
    }
}

// -------------------------------------------------------------------------------------------
// Runtime binding

/// A transaction is accepted only for a version the table accepts at the accessor's height:
/// version 1 until 20, version 2 from 10 (both in between: version 1's grace period).
#[test]
fn runtime_version_must_be_accepted_at_the_height() {
    // Version 1 (V0 vectors) and version 2 (V1 vectors).
    for (height, v1_ok, v2_ok) in [(0, true, false), (9, true, false), (10, true, true)] {
        for (vector, ok) in [(&V0_ED25519, v1_ok), (&V1_ED25519, v2_ok)] {
            let result = authenticate::<_, Versions>(&vector.baked(), &mut state(height));
            assert_eq!(result.is_ok(), ok, "{height}: {result:?}");
        }
    }
    for (height, ok) in [(19, true), (20, false), (1000, false)] {
        assert_eq!(
            authenticate::<_, Versions>(&V0_SECP256K1.baked(), &mut state(height)).is_ok(),
            ok
        );
        assert!(authenticate::<_, Versions>(&V1_SECP256K1.baked(), &mut state(height)).is_ok());
    }
    // Outside its window: the error names the newest version accepted.
    assert_eq!(
        fatal(authenticate::<_, Versions>(
            &V0_ED25519.baked(),
            &mut state(20)
        )),
        FatalError::InvalidRuntimeVersion {
            expected: 2,
            got: 1
        }
    );
    assert_eq!(
        fatal(authenticate::<_, Versions>(
            &V1_ED25519.baked(),
            &mut state(3)
        )),
        FatalError::InvalidRuntimeVersion {
            expected: 1,
            got: 2
        }
    );
    // An unknown version.
    let mut tx: Transaction<VectorRuntime, TestSpec, Ed25519CryptoSpec> =
        borsh::from_slice(&bytes(V0_ED25519.tx)).unwrap();
    let Transaction::V0(inner) = &mut tx else {
        unreachable!()
    };
    inner.details.runtime_version = 7;
    let unknown = baked(0, &borsh::to_vec(&tx).unwrap());
    assert_eq!(
        fatal(authenticate::<_, Versions>(&unknown, &mut state(GRACE))),
        FatalError::InvalidRuntimeVersion {
            expected: 2,
            got: 7
        }
    );
}

/// The schema binding: a runtime whose table gives the transaction's version (1) another schema
/// hash rejects its signature, which commits to the schema hash it was signed for. Its twin,
/// the table it was signed for, accepts it.
#[test]
fn signature_for_other_schema_hash_is_rejected() {
    for vector in [&V0_ED25519, &V0_SECP256K1] {
        assert!(authenticate::<_, Versions>(&vector.baked(), &mut state(GRACE)).is_ok());
        let error = fatal(authenticate::<_, OtherSchema>(
            &vector.baked(),
            &mut state(GRACE),
        ));
        assert!(is_signature_failure(&error), "{error:?}");
    }
    // The V1 vectors are version 2, which the two tables map alike.
    assert!(authenticate::<_, OtherSchema>(&V1_ED25519.baked(), &mut state(GRACE)).is_ok());
}

/// A transaction signed for version 1, submitted as version 2 while both are accepted (the
/// grace period), is rejected: its signature commits to version 1's commitment. Its twin, the
/// transaction as signed, is accepted at the same height.
#[test]
fn runtime_version_swap_in_grace_window_is_rejected() {
    for vector in [&V0_ED25519, &V0_SECP256K1] {
        let raw = bytes(vector.tx);
        assert!(authenticate::<_, Versions>(&vector.baked(), &mut state(GRACE)).is_ok());
        let swapped = if vector.tag == 0 {
            let mut tx: Transaction<VectorRuntime, TestSpec, Ed25519CryptoSpec> =
                borsh::from_slice(&raw).unwrap();
            let Transaction::V0(inner) = &mut tx else {
                unreachable!()
            };
            assert_eq!(inner.details.runtime_version, 1);
            inner.details.runtime_version = 2;
            borsh::to_vec(&tx).unwrap()
        } else {
            let mut tx: Transaction<VectorRuntime, TestSpec, EvmCryptoSpec> =
                borsh::from_slice(&raw).unwrap();
            let Transaction::V0(inner) = &mut tx else {
                unreachable!()
            };
            inner.details.runtime_version = 2;
            borsh::to_vec(&tx).unwrap()
        };
        let error = fatal(authenticate::<_, Versions>(
            &baked(vector.tag, &swapped),
            &mut state(GRACE),
        ));
        assert!(is_signature_failure(&error), "{error:?}");
    }
}

/// P5-07 (regression, the authenticator): signatures by the vector's key over the bare payload,
/// over its prehash without the header, and over the right header in the `OffchainMessage`
/// domain (the S10 test's signatures, made with RFC 8032's reference code) are rejected; only the
/// signed bytes verify. (The `native` test below signs the other cases with both schemes.)
#[test]
fn bare_payload_signature_is_rejected() {
    const WRONG: [&str; 3] = [
        "fe5007fb6325cef9dae86127f4c3ffbe0087c5404f0a61f92da68da887018fb4ebd69444ea284c56033236879d1965d983d3caf189301a2a2200371b535c970e",
        "0d81d488f498bdd64e87440217e3db90a45eb14227f23bd39b67fe10ea0ded28a212802dfd26d2439c2c18437135f167bb5a583a53259784711245b66ca12c01",
        "23fcbe422c0c86e7a768d1fdf521260fc45eaeab8debc4b31c7eec0bdc3e1508b073252d601da0c973c0ec3942369b78f64ea4e75c8fb3d3a23a080582fb5c06",
    ];
    let raw = bytes(V0_ED25519.tx);
    assert!(authenticate::<_, Versions>(&baked(0, &raw), &mut state(GRACE)).is_ok());
    for wrong in WRONG {
        let mut forged = raw.clone();
        forged[1..65].copy_from_slice(&bytes(wrong));
        let error = fatal(authenticate::<_, Versions>(
            &baked(0, &forged),
            &mut state(GRACE),
        ));
        assert!(is_signature_failure(&error), "{error:?}");
    }
}

// -------------------------------------------------------------------------------------------
// The envelope

#[test]
fn reserved_and_unknown_tags_are_fatal() {
    let raw = bytes(V0_ED25519.tx);
    for tag in [2, 3] {
        assert_eq!(
            fatal(authenticate::<_, Versions>(
                &baked(tag, &raw),
                &mut state(GRACE)
            )),
            FatalError::UnsupportedAuthenticator { tag }
        );
        assert_eq!(
            Envelope::parse(baked(tag, &raw).data()),
            Err(EnvelopeError::Reserved { tag })
        );
    }
    for tag in [4, 0xb5, 0xff] {
        assert!(matches!(
            fatal(authenticate::<_, Versions>(
                &baked(tag, &raw),
                &mut state(GRACE)
            )),
            FatalError::DeserializationFailed(_)
        ));
    }
    assert_eq!(AuthenticatorKind::from_tag(4), None);
    for (tag, kind, enabled) in [
        (0, AuthenticatorKind::Ed25519, true),
        (1, AuthenticatorKind::Secp256k1, true),
        (2, AuthenticatorKind::Eip712, false),
        (3, AuthenticatorKind::EthereumRlp, false),
    ] {
        assert_eq!(AuthenticatorKind::from_tag(tag), Some(kind));
        assert_eq!(kind.tag(), tag);
        assert_eq!(kind.is_enabled(), enabled);
    }
}

/// [`AuthenticatorInput`] with its `BorshDeserialize` derived: the hand-written one must match it.
#[derive(Debug, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
enum DerivedInput {
    Ed25519(RawTx) = 0,
    Secp256k1(RawTx) = 1,
}

/// The envelope's rules: the tag, a `u32` LE length at most `MAX_RAW_TX_SIZE`, exactly that many
/// bytes. `Envelope::parse` accepts exactly what `AuthenticatorInput`'s borsh decoder accepts,
/// and that decoder (written by hand, to count its decodes) is the derive's.
#[test]
fn envelope_rules() {
    let max = u32::try_from(MAX_RAW_TX_SIZE).unwrap();
    let mut too_large = vec![0u8];
    too_large.extend((max + 1).to_le_bytes());
    type Parsed<'a> = Result<(AuthenticatorKind, &'a [u8]), EnvelopeError>;
    let cases: [(&[u8], Parsed<'_>); 12] = [
        (&[], Err(EnvelopeError::Empty)),
        (
            &[0, 3, 0, 0, 0, 1, 2, 3],
            Ok((AuthenticatorKind::Ed25519, &[1, 2, 3])),
        ),
        (&[1, 0, 0, 0, 0], Ok((AuthenticatorKind::Secp256k1, &[]))),
        (&[0, 3, 0, 0], Err(EnvelopeError::Truncated)),
        (&[0], Err(EnvelopeError::Truncated)),
        (
            &[0, 3, 0, 0, 0, 1, 2],
            Err(EnvelopeError::LengthMismatch {
                declared: 3,
                actual: 2,
            }),
        ),
        (
            &[1, 1, 0, 0, 0, 1, 2],
            Err(EnvelopeError::LengthMismatch {
                declared: 1,
                actual: 2,
            }),
        ),
        (&[9, 0, 0, 0, 0], Err(EnvelopeError::UnknownTag { tag: 9 })),
        (
            &[255, 0, 0, 0, 0],
            Err(EnvelopeError::UnknownTag { tag: 255 }),
        ),
        (&[2, 0, 0, 0, 0], Err(EnvelopeError::Reserved { tag: 2 })),
        (&[3, 0, 0, 0, 0], Err(EnvelopeError::Reserved { tag: 3 })),
        (&too_large, Err(EnvelopeError::TooLarge { len: max + 1 })),
    ];
    for (data, expected) in cases {
        let parsed = Envelope::parse(data).map(|envelope| (envelope.kind(), envelope.raw_tx()));
        assert_eq!(parsed, expected, "{data:?}");
        let decoded = borsh::from_slice::<AuthenticatorInput>(data);
        assert_eq!(decoded.is_ok(), parsed.is_ok(), "{data:?}");
        // The hand-written decoder is the derive's: the same values, the same errors.
        let derived = borsh::from_slice::<DerivedInput>(data);
        match (&decoded, derived) {
            (Ok(input), Ok(DerivedInput::Ed25519(raw))) => {
                assert_eq!(input, &AuthenticatorInput::Ed25519(raw));
            }
            (Ok(input), Ok(DerivedInput::Secp256k1(raw))) => {
                assert_eq!(input, &AuthenticatorInput::Secp256k1(raw));
            }
            (Err(error), Err(derived)) => {
                assert_eq!(
                    (error.kind(), error.to_string()),
                    (derived.kind(), derived.to_string()),
                    "{data:?}"
                );
            }
            (decoded, derived) => panic!("{data:?}: {decoded:?} but derived {derived:?}"),
        }
        if let Ok(input) = decoded {
            assert_eq!(input.kind(), parsed.unwrap().0);
            assert_eq!(input.raw_tx().as_bytes(), parsed.unwrap().1);
            assert_eq!(input.to_bytes(), data);
            assert_eq!(borsh::to_vec(&input).unwrap(), data);
            assert_eq!(input.to_fully_baked_tx().data(), data);
        }
    }
    // Known answer.
    let input = AuthenticatorInput::Secp256k1(RawTx::new(vec![0xaa, 0xbb]).unwrap());
    assert_eq!(input.to_bytes(), [1, 2, 0, 0, 0, 0xaa, 0xbb]);
    assert_eq!(
        Auth::encode_with_standard_auth(RawTx::new(vec![5]).unwrap()).data()[..],
        [0, 1, 0, 0, 0, 5]
    );
    assert_eq!(
        Auth::add_standard_auth(RawTx::new(vec![5]).unwrap()).kind(),
        AuthenticatorKind::Ed25519
    );
}

/// `AuthenticatorInput::from_transaction` puts a transaction behind its scheme's tag.
#[test]
fn transactions_are_put_behind_their_tag() {
    for vector in VECTORS {
        let baked = if vector.tag == 0 {
            let tx: Transaction<VectorRuntime, TestSpec, Ed25519CryptoSpec> =
                borsh::from_slice(&bytes(vector.tx)).unwrap();
            AuthenticatorInput::from_transaction(&tx)
                .unwrap()
                .to_fully_baked_tx()
        } else {
            let tx: Transaction<VectorRuntime, TestSpec, EvmCryptoSpec> =
                borsh::from_slice(&bytes(vector.tx)).unwrap();
            AuthenticatorInput::from_transaction(&tx)
                .unwrap()
                .to_fully_baked_tx()
        };
        assert_eq!(baked, vector.baked());
    }
    // Too large for an envelope.
    let unsigned = crate::transaction::UnsignedTransaction::<VectorRuntime, TestSpec>::new(
        VectorCall::Data(vec![0; MAX_RAW_TX_SIZE]),
        UniquenessData::Nonce(0),
        crate::TxDetails {
            max_priority_fee_bips: crate::PriorityFeeBips(0),
            max_fee: crate::Amount::ZERO,
            gas_limit: None,
            runtime_version: 1,
        },
        None,
    );
    let tx: Transaction<VectorRuntime, TestSpec, Ed25519CryptoSpec> = unsigned.to_signed_tx(
        parse(vectors::v0_ed25519::PUB_KEY),
        parse(vectors::v0_ed25519::SIGNATURE),
    );
    assert!(matches!(
        AuthenticatorInput::from_transaction(&tx),
        Err(EncodeTransactionError::TooLarge(_))
    ));
}

/// Trailing bytes after the transaction (inside the envelope's length) are rejected.
#[test]
fn trailing_bytes_are_rejected() {
    for vector in VECTORS {
        let mut raw = bytes(vector.tx);
        raw.push(0);
        assert!(matches!(
            fatal(authenticate::<_, Versions>(
                &baked(vector.tag, &raw),
                &mut state(GRACE)
            )),
            FatalError::DeserializationFailed(_)
        ));
    }
}

// -------------------------------------------------------------------------------------------
// Gas

/// Each charge of a vector's authentication with `DistinctCostSpec`'s costs, in order (each
/// cost a distinct prime per dimension, so a charge reading the wrong cost gives another
/// amount). Computed independently from the stage formulas and the vectors' lengths
/// (`python3 -I`): the hash of the envelope (per byte, then `hash_update`), the decode (per
/// byte), the key decodes (per key), for V1 the multisig credential (`hash_update` + per byte of
/// its 20 + 2 + 4 + keys bytes), the payload (`hash_update + encode_per_byte·n`, then
/// `hash_per_byte·n`), the replay hash of the 51 signed bytes (per byte, then `hash_update`), and
/// `sig_verify + sig_per_byte·51` per signature.
const CHARGES: [(&Vector, &[[u64; 2]]); 4] = [
    (
        &V0_ED25519,
        &[
            [1870, 2210],
            [5, 7],
            [7755, 8745],
            [97, 101],
            [11044, 11844],
            [1463, 1729],
            [561, 663],
            [5, 7],
            [7096, 7202],
        ],
    ),
    (
        &V0_SECP256K1,
        &[
            [1892, 2236],
            [5, 7],
            [7849, 8851],
            [103, 107],
            [11210, 12022],
            [1485, 1755],
            [561, 663],
            [5, 7],
            [7726, 7832],
        ],
    ),
    (
        &V1_ED25519,
        &[
            [3432, 4056],
            [5, 7],
            [14429, 16271],
            [291, 303],
            [1347, 1593],
            [11210, 12022],
            [1485, 1755],
            [561, 663],
            [5, 7],
            [7096, 7202],
            [7096, 7202],
        ],
    ),
    (
        &V1_SECP256K1,
        &[
            [2299, 2717],
            [5, 7],
            [9588, 10812],
            [206, 214],
            [1017, 1203],
            [10463, 11221],
            [1386, 1638],
            [561, 663],
            [5, 7],
            [7726, 7832],
        ],
    ),
];

/// The totals of `CHARGES` (likewise computed).
const TOTALS: [[u64; 2]; 4] = [
    [29896, 32508],
    [30836, 33480],
    [46957, 51081],
    [33256, 36314],
];

fn sum(charges: &[[u64; 2]]) -> [u64; 2] {
    charges.iter().fold([0, 0], |total, charge| {
        [total[0] + charge[0], total[1] + charge[1]]
    })
}

/// Known answers: a vector's authentication charges exactly its stages' costs, and a budget of
/// exactly that succeeds.
#[test]
fn gas_known_answers() {
    for ((vector, charges), total) in CHARGES.into_iter().zip(TOTALS) {
        assert_eq!(sum(charges), total);
        let mut state = state_with::<DistinctCostSpec>(GRACE, total);
        authenticate::<_, Versions>(&vector.baked(), &mut state).unwrap();
        assert_eq!(gas_used(&state), total);
        assert_eq!(*state.remaining_gas().as_ref(), [0, 0]);
    }
}

/// Out of gas at each charge of each stage (the hash, the decode, the key decode, the multisig
/// credential, the payload's encoding and prehash, the replay hash, each signature) is
/// `OutOfGas`, never a panic, and no later charge happens: the gas used is exactly the charges
/// before the refused one (a refused charge changes nothing), and the phase is poisoned. (The
/// key decodes happen inside the decode, before their charge: P5-62, documented.)
#[test]
fn out_of_gas_at_every_stage() {
    for (vector, charges) in CHARGES {
        for refused in 0..charges.len() {
            let before = sum(&charges[..refused]);
            let charge = charges[refused];
            // One unit short in each dimension.
            let budget = [before[0] + charge[0] - 1, before[1] + charge[1] - 1];
            let mut state = state_with::<DistinctCostSpec>(GRACE, budget);
            let result = authenticate::<_, Versions>(&vector.baked(), &mut state);
            assert!(
                matches!(result, Err(AuthenticationError::OutOfGas(_))),
                "charge {refused}: {result:?}"
            );
            assert_eq!(gas_used(&state), before, "charge {refused}");
            assert!(state.metered_view().is_poisoned());
        }
    }
}

/// P5-62 (regression): the key decodes are charged per key, the multisig's unused keys
/// included: a V1 transaction with two signers and an unused key (the vector) pays three
/// `pubkey_decode`s. Upstream priced keys only by their bytes (and V1's unused keys only by
/// theirs). A budget one unit short of three key decodes after the decode is out of gas at that
/// charge; with the unit back, authentication goes past it.
#[test]
fn v1_key_decode_is_charged_per_key() {
    let [hash_bytes, hash_update, decode, keys] = [0, 1, 2, 3].map(|i| CHARGES[2].1[i]);
    let pubkey_decode = DistinctCostSpec::GAS_SCHEDULE.pubkey_decode.ed25519;
    assert_eq!(
        keys,
        *pubkey_decode.checked_scalar_product(3).unwrap().as_ref()
    );
    let through_keys = sum(&[hash_bytes, hash_update, decode, keys]);
    let short = [through_keys[0] - 1, through_keys[1] - 1];
    let mut state = state_with::<DistinctCostSpec>(GRACE, short);
    assert!(matches!(
        authenticate::<_, Versions>(&V1_ED25519.baked(), &mut state),
        Err(AuthenticationError::OutOfGas(_))
    ));
    assert_eq!(gas_used(&state), sum(&[hash_bytes, hash_update, decode]));
    let mut state = state_with::<DistinctCostSpec>(GRACE, through_keys);
    assert!(matches!(
        authenticate::<_, Versions>(&V1_ED25519.baked(), &mut state),
        Err(AuthenticationError::OutOfGas(_))
    ));
    assert_eq!(gas_used(&state), through_keys);
}

/// The key decodes are charged before the runtime version is checked (D17: stage 4 right after
/// stage 2, before anything else can reject the transaction): a transaction naming a version
/// the table does not accept at the height (V0 vectors, version 1, at 20; V1 vectors,
/// version 2, at 3) pays its hash, its decode and its `pubkey_decode`s (`CHARGES[..4]`), then is
/// `InvalidRuntimeVersion`. A budget one unit short of the key decodes is `OutOfGas` at their
/// charge, not `InvalidRuntimeVersion`. (Checked the version first, a rejected version would
/// leave up to 42 key decodes unpaid.)
#[test]
fn a_rejected_runtime_version_pays_its_key_decodes() {
    for ((vector, charges), (height, keys, expected, got)) in
        CHARGES
            .into_iter()
            .zip([(20, 1, 2, 1), (20, 1, 2, 1), (3, 3, 1, 2), (3, 2, 1, 2)])
    {
        let pubkey_decode = if vector.tag == 0 {
            DistinctCostSpec::GAS_SCHEDULE.pubkey_decode.ed25519
        } else {
            DistinctCostSpec::GAS_SCHEDULE.pubkey_decode.secp256k1
        };
        assert_eq!(
            charges[3],
            *pubkey_decode.checked_scalar_product(keys).unwrap().as_ref()
        );
        let through_keys = sum(&charges[..4]);

        let mut state = state_with::<DistinctCostSpec>(height, [u64::MAX; 2]);
        let result = authenticate::<_, Versions>(&vector.baked(), &mut state);
        let Err(AuthenticationError::FatalError(error, tx_hash)) = result else {
            panic!("{height}: {result:?}");
        };
        assert_eq!(error, FatalError::InvalidRuntimeVersion { expected, got });
        assert_eq!(tx_hash, hash(vector.tx_hash));
        assert_eq!(gas_used(&state), through_keys, "{height}");
        assert!(!state.metered_view().is_poisoned());

        let short = [through_keys[0] - 1, through_keys[1] - 1];
        let mut state = state_with::<DistinctCostSpec>(height, short);
        let result = authenticate::<_, Versions>(&vector.baked(), &mut state);
        assert!(
            matches!(result, Err(AuthenticationError::OutOfGas(_))),
            "{height}: {result:?}"
        );
        assert_eq!(gas_used(&state), sum(&charges[..3]));
        assert!(state.metered_view().is_poisoned());
    }
}

/// An invalid multisig decodes (each key list fits its cap), then fails in stage 5: it is
/// `SigVerificationFailed` with the multisig's error, and pays only for the stages before its
/// check. Too many keys or a threshold of 0 or above the number of keys is found from the
/// lists' lengths and the threshold alone, before the credential is charged: it pays its hash,
/// its decode and one `pubkey_decode` per key (up to 22 here: 11 signers and 11 unused keys,
/// each list at most `MAX_SIGNERS`). A key listed twice is found by sorting the keys (copies of
/// them), which only runs once the credential's hash is charged (it hashes the same keys): it
/// pays that charge too. Nothing more (no payload, no signature). A budget one unit short of
/// the credential's charge leaves the first three cases unchanged and makes the duplicate
/// `OutOfGas` at that charge, its keys never sorted. Built from the V1 ed25519 vector (the
/// signatures are placeholders: no check reaches them).
#[test]
fn an_invalid_multisig_pays_only_up_to_its_check() {
    type Tx = Transaction<VectorRuntime, DistinctCostSpec, Ed25519CryptoSpec>;
    let Transaction::V1(base): Tx = borsh::from_slice(&bytes(V1_ED25519.tx)).unwrap() else {
        unreachable!()
    };
    let signer = base.signatures[0].clone();
    let keys: Vec<Ed25519PublicKey> = (0..22)
        .map(crate::transaction::tests::ed25519_key)
        .collect();

    // 0 of 3: no signature, the three keys unused.
    let mut zero = base.clone();
    zero.unused_pub_keys = base.multisig().unwrap().keys_vec();
    zero.signatures = Vec::new().try_into().unwrap();
    zero.min_signers = 0;
    // 4 of 3.
    let mut above = base.clone();
    above.min_signers = 4;
    // A signer's key among the unused keys too.
    let mut duplicate = base.clone();
    duplicate.unused_pub_keys = vec![signer.pub_key.clone()].try_into().unwrap();
    // 11 signers and 11 unused keys: 22 keys, more than `MAX_SIGNERS`.
    let mut many = base.clone();
    many.signatures = keys[..11]
        .iter()
        .map(|key| crate::transaction::PubKeyAndSignature {
            signature: signer.signature.clone(),
            pub_key: key.clone(),
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    many.unused_pub_keys = keys[11..].to_vec().try_into().unwrap();
    many.min_signers = 11;

    let costs = DistinctCostSpec::GAS_SCHEDULE;
    let len = |n: usize| u64::try_from(n).unwrap();
    // The totals, computed independently (`python3 -I`, from the vector's 307 bytes: 128 fewer
    // without the two signatures, 1184 more with 11 signers and 11 unused keys; the duplicate
    // also pays `hash_update + hash_per_byte·(20 + 2 + 4 + 3·32)` for the credential).
    for (invalid, key_count, multisig_error, total, credential_charged) in [
        (zero, 3, MultisigError::ZeroThreshold, [10733, 12189], false),
        (
            above,
            3,
            MultisigError::ThresholdAboveKeys {
                min_signers: 4,
                keys: 3,
            },
            [18157, 20637],
            false,
        ),
        (
            duplicate,
            3,
            MultisigError::DuplicateKey,
            [19504, 22230],
            true,
        ),
        (
            many,
            22,
            MultisigError::TooManyKeys { keys: 22 },
            [88672, 100700],
            false,
        ),
    ] {
        assert_eq!(invalid.multisig(), Err(multisig_error.clone()));
        let raw = borsh::to_vec(&Transaction::V1(invalid)).unwrap();
        let tx = baked(0, &raw);
        let through_keys = costs
            .state
            .hash_per_byte
            .checked_scalar_product(len(tx.data().len()))
            .and_then(|gas| gas.checked_combine(costs.state.hash_update))
            .and_then(|gas| {
                gas.checked_combine(
                    costs
                        .state
                        .decode_per_byte
                        .checked_scalar_product(len(raw.len()))?,
                )
            })
            .and_then(|gas| {
                gas.checked_combine(
                    costs
                        .pubkey_decode
                        .ed25519
                        .checked_scalar_product(key_count)?,
                )
            })
            .unwrap();
        let credential = costs
            .state
            .hash_per_byte
            .checked_scalar_product(len(20 + 2 + 4 + 32 * usize::try_from(key_count).unwrap()))
            .and_then(|gas| gas.checked_combine(costs.state.hash_update))
            .unwrap();
        let expected = if credential_charged {
            through_keys.checked_combine(credential).unwrap()
        } else {
            through_keys
        };
        assert_eq!(*expected.as_ref(), total, "{multisig_error}");

        let mut state = state_with::<DistinctCostSpec>(GRACE, [u64::MAX; 2]);
        let (builds, result) = crate::transaction::count_multisig_builds(|| {
            authenticate::<_, Versions>(&tx, &mut state)
        });
        // Built (its keys copied and sorted) only once its credential is paid for.
        assert_eq!(builds, u64::from(credential_charged), "{multisig_error}");
        let Err(AuthenticationError::FatalError(error, tx_hash)) = result else {
            panic!("{multisig_error}: {result:?}");
        };
        assert_eq!(
            error,
            FatalError::SigVerificationFailed(multisig_error.to_string())
        );
        assert_eq!(
            tx_hash,
            HexHash::new(sha2::Sha256::digest(tx.data()).into())
        );
        assert_eq!(gas_used(&state), total, "{multisig_error}");
        assert!(!state.metered_view().is_poisoned());

        // One unit short of the credential's charge.
        let through = *through_keys.checked_combine(credential).unwrap().as_ref();
        let mut state = state_with::<DistinctCostSpec>(GRACE, [through[0] - 1, through[1] - 1]);
        let (builds, result) = crate::transaction::count_multisig_builds(|| {
            authenticate::<_, Versions>(&tx, &mut state)
        });
        assert_eq!(builds, 0, "{multisig_error}");
        if credential_charged {
            assert!(
                matches!(result, Err(AuthenticationError::OutOfGas(_))),
                "{multisig_error}: {result:?}"
            );
            assert!(state.metered_view().is_poisoned());
        } else {
            assert_eq!(
                result.err(),
                Some(AuthenticationError::FatalError(
                    FatalError::SigVerificationFailed(multisig_error.to_string()),
                    tx_hash
                ))
            );
        }
        assert_eq!(gas_used(&state), *through_keys.as_ref(), "{multisig_error}");
    }
}

/// Known answer: the gas grows linearly with the call's size, `hash_per_byte` (the hash of the
/// envelope) + `decode_per_byte` + `encode_per_byte` + `hash_per_byte` (the payload's encoding and
/// prehash) per byte, `[152, 168]` with `DistinctCostSpec`; the signature costs the same for any
/// size (the prehash, Phase 5 O2). Totals computed independently (`python3 -I`) for a V0 ed25519
/// transaction whose call is `Data(n bytes)`: the envelope is `162 + n` bytes, the transaction
/// `157 + n`, the payload `125 + n`. The vector's signature does not verify for these calls, so
/// authentication fails at the very end, after every charge.
#[test]
fn gas_grows_linearly_with_the_call_size() {
    let mut previous: Option<(usize, [u64; 2])> = None;
    for (n, total) in [
        (0, [28680, 31164]),
        (8, [29896, 32508]),
        (1000, [180680, 199164]),
        (100_000, [15228680, 16831164]),
    ] {
        let mut tx: Transaction<VectorRuntime, DistinctCostSpec, Ed25519CryptoSpec> =
            borsh::from_slice(&bytes(V0_ED25519.tx)).unwrap();
        let Transaction::V0(Version0 { runtime_call, .. }) = &mut tx else {
            unreachable!()
        };
        // `n == 8`: the vector's own call, `b"selendra"`.
        let data = if n == 8 {
            b"selendra".to_vec()
        } else {
            vec![b'x'; n]
        };
        *runtime_call = VectorCall::Data(data);
        let raw = borsh::to_vec(&tx).unwrap();
        assert_eq!(raw.len(), 157 + n);
        let mut state = state_with::<DistinctCostSpec>(GRACE, [u64::MAX; 2]);
        let result = authenticate::<_, Versions>(&baked(0, &raw), &mut state);
        if n == 8 {
            // The vector's own call: the signature verifies.
            assert!(result.is_ok());
        } else {
            assert!(matches!(
                result,
                Err(AuthenticationError::FatalError(
                    FatalError::SigVerificationFailed(_),
                    _
                ))
            ));
        }
        assert_eq!(gas_used(&state), total, "{n}");
        if let Some((m, before)) = previous {
            let bytes = u64::try_from(n - m).unwrap();
            assert_eq!(
                [total[0] - before[0], total[1] - before[1]],
                [152 * bytes, 168 * bytes]
            );
        }
        previous = Some((n, total));
    }
}

/// A transaction that does not decode is charged its hash and its decode, nothing more.
#[test]
fn a_decode_failure_charges_the_hash_and_the_decode() {
    let raw = vec![0xff; 100];
    let tx = baked(0, &raw);
    let mut state = state_with::<DistinctCostSpec>(GRACE, [u64::MAX; 2]);
    assert!(matches!(
        authenticate::<_, Versions>(&tx, &mut state),
        Err(AuthenticationError::FatalError(
            FatalError::DeserializationFailed(_),
            _
        ))
    ));
    let costs = DistinctCostSpec::GAS_SCHEDULE.state;
    let expected = costs
        .hash_per_byte
        .checked_scalar_product(105)
        .and_then(|gas| gas.checked_combine(costs.hash_update))
        .and_then(|gas| gas.checked_combine(costs.decode_per_byte.checked_scalar_product(100)?))
        .unwrap();
    assert_eq!(gas_used(&state), *expected.as_ref());
    assert!(!state.metered_view().is_poisoned());
}

/// A poisoned pre-execution phase charges nothing more: authentication fails with `OutOfGas`
/// (the `Poisoned` error) at its first charge.
#[test]
fn a_poisoned_phase_authenticates_nothing() {
    let mut state = state_with::<TestSpec>(GRACE, [10, 10]);
    assert!(state.charge_gas(GasUnit::from([11, 11])).is_err());
    assert!(state.metered_view().is_poisoned());
    assert!(matches!(
        authenticate::<_, Versions>(&V0_ED25519.baked(), &mut state),
        Err(AuthenticationError::OutOfGas(_))
    ));
    assert_eq!(gas_used(&state), [0, 0]);
}

// -------------------------------------------------------------------------------------------
// The unregistered path

/// A forced registration authenticates like any transaction; an envelope no enabled
/// authenticator reads is an invalid discriminant; gas and transaction failures keep their kind.
#[test]
fn unregistered_path() {
    let unregistered = |tx: FullyBakedTx, state: &mut PreExecWorkingSet<TestSpec>| {
        Auth::authenticate_unregistered(
            &BatchFromUnregisteredSequencer { tx, id: [9; 32] },
            CHAIN_ID,
            state,
        )
    };
    for vector in VECTORS {
        let output = unregistered(vector.baked(), &mut state(GRACE)).unwrap();
        assert_eq!(
            output,
            authenticate::<_, Versions>(&vector.baked(), &mut state(GRACE)).unwrap()
        );
    }
    let raw = bytes(V0_ED25519.tx);
    for tx in [baked(2, &raw), baked(3, &raw), baked(7, &raw)] {
        assert_eq!(
            unregistered(tx, &mut state(GRACE)),
            Err(UnregisteredAuthenticationError::InvalidAuthenticationDiscriminant)
        );
    }
    let mut truncated = baked(0, &raw).data().to_vec();
    truncated.pop();
    assert_eq!(
        unregistered(
            FullyBakedTx::new(Bytes::from(truncated)).unwrap(),
            &mut state(GRACE)
        ),
        Err(UnregisteredAuthenticationError::InvalidAuthenticationDiscriminant)
    );
    assert!(matches!(
        unregistered(baked(1, &raw), &mut state(GRACE)),
        Err(UnregisteredAuthenticationError::FatalError(
            FatalError::DeserializationFailed(_),
            _
        ))
    ));
    assert!(matches!(
        unregistered(V0_ED25519.baked(), &mut state_with(GRACE, [1, 1])),
        Err(UnregisteredAuthenticationError::OutOfGas(_))
    ));
}

// -------------------------------------------------------------------------------------------
// Signing (node only)

#[cfg(feature = "native")]
mod native {
    use selendra_interface::crypto::PrivateKey;
    use selendra_primitives::crypto::{Ed25519PrivateKey, EthereumPrivateKey};
    use selendra_primitives::signing::{SigningDomain, signing_bytes};

    use super::*;
    use crate::test_utils::TestUser;
    use crate::transaction::{TxCryptoSpec, UnsignedTransaction};
    use crate::{Amount, PriorityFeeBips, TxDetails};

    fn ed25519_user() -> TestUser<Ed25519CryptoSpec> {
        TestUser::new(Ed25519PrivateKey::from_bytes([3; 32]))
    }

    fn secp256k1_user() -> TestUser<EvmCryptoSpec> {
        let mut one = [0; 32];
        one[31] = 1;
        TestUser::new(EthereumPrivateKey::from_bytes(one).unwrap())
    }

    fn unsigned(version: u32) -> UnsignedTransaction<VectorRuntime, TestSpec> {
        UnsignedTransaction::new(
            VectorCall::Ping(1),
            UniquenessData::Nonce(1),
            TxDetails {
                max_priority_fee_bips: PriorityFeeBips(0),
                max_fee: Amount::new(10),
                gas_limit: None,
                runtime_version: version,
            },
            None,
        )
    }

    /// The signing header and `prehash` in `domain` on `chain_id`.
    fn header(domain: SigningDomain, chain_id: u64, prehash: &[u8; 32]) -> Vec<u8> {
        signing_bytes(domain, chain_id, prehash).as_bytes().to_vec()
    }

    /// Signs with a private key, given the payload's encoding and its prehash.
    type Signer<C> = dyn Fn(
        &<C as selendra_interface::zk::CryptoSpec>::PrivateKey,
        &[u8],
        &[u8; 32],
    ) -> <C as selendra_interface::zk::CryptoSpec>::Signature;

    /// The V0 transaction of `unsigned(1)` by `user`, with the signature `sign` makes from the
    /// private key, the payload's encoding and its prehash, authenticated.
    fn forged<C: TxCryptoSpec>(
        user: &TestUser<C>,
        sign: &Signer<C>,
    ) -> Result<AuthenticationOutput<TestSpec, VectorCall>, AuthenticationError> {
        let unsigned = unsigned(1);
        let commitment = unsigned.runtime_commitment(CHAIN_ID, &SCHEMA_1);
        let payload = unsigned.signing_payload_v0::<C>(&user.pub_key(), commitment);
        let encoded = borsh::to_vec(&payload).unwrap();
        let signature = sign(user.private_key(), &encoded, &payload.prehash().unwrap());
        let tx = unsigned.to_signed_tx::<C>(user.pub_key(), signature);
        authenticate::<_, Versions>(&TestUser::bake(&tx).unwrap(), &mut state(GRACE))
    }

    /// P5-07 (regression, the authenticator, both schemes): signatures over the bare payload,
    /// over its prehash without the header, over the header and prehash in another domain
    /// (`OffchainMessage`, `SequencerBlob`) or for another chain ID are rejected
    /// (`SigVerificationFailed`); the twin, signed by hand over the signed bytes, is accepted.
    #[test]
    fn bare_payload_signature_is_rejected_for_both_schemes() {
        fn check<C: TxCryptoSpec>(user: &TestUser<C>) {
            let wrong: [&Signer<C>; 5] = [
                &|key, bare, _| key.sign(bare),
                &|key, _, prehash| key.sign(prehash),
                &|key, _, prehash| {
                    key.sign(&header(SigningDomain::OffchainMessage, CHAIN_ID, prehash))
                },
                &|key, _, prehash| {
                    key.sign(&header(SigningDomain::SequencerBlob, CHAIN_ID, prehash))
                },
                &|key, _, prehash| {
                    key.sign(&header(SigningDomain::Transaction, CHAIN_ID + 1, prehash))
                },
            ];
            for sign in wrong {
                let error = fatal(forged(user, sign));
                assert!(is_signature_failure(&error), "{error:?}");
            }
            forged(user, &|key, _, prehash| {
                key.sign(&header(SigningDomain::Transaction, CHAIN_ID, prehash))
            })
            .unwrap();
        }
        check(&ed25519_user());
        check(&secp256k1_user());
    }

    /// A transaction signed on another chain is rejected: the chain ID is in the signed bytes
    /// and the runtime commitment.
    #[test]
    fn another_chain_id_is_rejected() {
        let user = secp256k1_user();
        let tx = user.sign(unsigned(1), CHAIN_ID + 1, &SCHEMA_1).unwrap();
        let error = fatal(authenticate::<_, Versions>(
            &TestUser::bake(&tx).unwrap(),
            &mut state(GRACE),
        ));
        assert!(is_signature_failure(&error), "{error:?}");
    }

    /// P5-08 (the test users agree): a test user's address is the authenticator's default
    /// address for its transactions, `Vm(0x…)` for an EVM key (the key of 1: the well-known
    /// `0x7E5F…5Bdf`).
    #[test]
    fn test_users_have_the_authenticators_address() {
        let user = secp256k1_user();
        let eth: EthereumAddress = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
            .parse()
            .unwrap();
        assert_eq!(user.address::<TestSpec>(), MultiAddressEvm::Vm(eth));
        let tx = user.sign(unsigned(2), CHAIN_ID, &SCHEMA_2).unwrap();
        let output =
            authenticate::<_, Versions>(&TestUser::bake(&tx).unwrap(), &mut state(GRACE)).unwrap();
        assert_eq!(
            output.auth_data.default_address(),
            &user.address::<TestSpec>()
        );
        assert_eq!(output.auth_data.credential(), &user.credential());

        let user = ed25519_user();
        let tx = user.sign(unsigned(2), CHAIN_ID, &SCHEMA_2).unwrap();
        let output =
            authenticate::<_, Versions>(&TestUser::bake(&tx).unwrap(), &mut state(GRACE)).unwrap();
        assert_eq!(
            output.auth_data.default_address(),
            &user.address::<TestSpec>()
        );
        assert!(matches!(
            user.address::<TestSpec>(),
            MultiAddressEvm::Standard(_)
        ));
    }

    /// Multisig transactions signed by any sufficient subset of their keys authenticate, with
    /// one replay hash; an insufficient one is a signature failure.
    #[test]
    fn multisig_subsets() {
        let users = [1u8, 2, 3]
            .map(|i| TestUser::<Ed25519CryptoSpec>::new(Ed25519PrivateKey::from_bytes([i; 32])));
        let multisig = crate::transaction::Multisig::<Ed25519CryptoSpec>::new(
            2,
            users.iter().map(TestUser::pub_key).collect(),
        )
        .unwrap();
        let mut hashes = Vec::new();
        for signers in [[0, 1], [1, 2], [2, 0]] {
            let mut tx = unsigned(2).to_multisig_tx(multisig.clone());
            for signer in signers {
                tx.sign(users[signer].private_key(), CHAIN_ID, &SCHEMA_2)
                    .unwrap();
            }
            let tx = Transaction::V1(tx);
            let output =
                authenticate::<_, Versions>(&TestUser::bake(&tx).unwrap(), &mut state(GRACE))
                    .unwrap();
            hashes.push(*output.auth_data.non_malleable_hash());
        }
        assert!(hashes.windows(2).all(|pair| pair[0] == pair[1]));
        let mut tx = unsigned(2).to_multisig_tx(multisig);
        tx.sign(users[0].private_key(), CHAIN_ID, &SCHEMA_2)
            .unwrap();
        let error = fatal(authenticate::<_, Versions>(
            &TestUser::bake(&Transaction::V1(tx)).unwrap(),
            &mut state(GRACE),
        ));
        assert!(is_signature_failure(&error), "{error:?}");
    }
}

/// The errors' JSON (receipts and APIs): externally tagged, snake_case.
#[test]
fn error_json() {
    let error = AuthenticationError::FatalError(
        FatalError::InvalidRuntimeVersion {
            expected: 2,
            got: 7,
        },
        HexHash::new([0xab; 32]),
    );
    let json = serde_json::to_value(&error).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "fatal_error": [
                {"invalid_runtime_version": {"expected": 2, "got": 7}},
                format!("0x{}", "ab".repeat(32)),
            ]
        })
    );
    assert_eq!(
        serde_json::from_value::<AuthenticationError>(json).unwrap(),
        error
    );
    assert_eq!(
        serde_json::to_value(FatalError::UnsupportedAuthenticator { tag: 2 }).unwrap(),
        serde_json::json!({"unsupported_authenticator": {"tag": 2}})
    );
    assert_eq!(
        serde_json::to_value(AuthenticationError::OutOfGas("x".to_owned())).unwrap(),
        serde_json::json!({"out_of_gas": "x"})
    );
    assert_eq!(
        serde_json::to_value(UnregisteredAuthenticationError::InvalidAuthenticationDiscriminant)
            .unwrap(),
        serde_json::json!("invalid_authentication_discriminant")
    );
}

/// Upstream's `test_metered_signature`/`test_metered_signature_not_enough_gas`
/// (`gas/tests/metered_utils.rs`, on `MeteredSignature`), on `Transaction::charge_gas_for_signature`
/// with `DistinctCostSpec`: a budget of exactly `sig_verify + sig_per_byte·n` per signature (V1
/// vector: two ed25519 signatures over the 51 signed bytes) is enough; one `sig_per_byte` short is
/// out of gas, the first signature's charge kept and the phase poisoned. Then the signatures
/// verify (upstream verified inside the metered call; here the charge comes first and
/// `verify_signature` charges nothing).
#[test]
fn charge_gas_for_signature_known_answer() {
    let tx: Transaction<VectorRuntime, DistinctCostSpec, Ed25519CryptoSpec> =
        borsh::from_slice(&bytes(V1_ED25519.tx)).unwrap();
    let schedule = DistinctCostSpec::GAS_SCHEDULE;
    let one = schedule
        .sig_per_byte
        .ed25519
        .checked_scalar_product(51)
        .and_then(|gas| gas.checked_combine(schedule.sig_verify.ed25519))
        .unwrap();
    assert_eq!(*one.as_ref(), [7096, 7202]);
    let two = one.checked_combine(one).unwrap();

    let mut state = state_with::<DistinctCostSpec>(GRACE, *two.as_ref());
    tx.charge_gas_for_signature(51, &mut state).unwrap();
    assert_eq!(gas_used(&state), *two.as_ref());
    let signed = tx.signing_bytes(CHAIN_ID, &SCHEMA_2).unwrap();
    tx.verify_signature(&signed).unwrap();
    assert_eq!(gas_used(&state), *two.as_ref());

    let short = two.checked_sub(schedule.sig_per_byte.ed25519).unwrap();
    let mut state = state_with::<DistinctCostSpec>(GRACE, *short.as_ref());
    assert!(tx.charge_gas_for_signature(51, &mut state).is_err());
    assert_eq!(gas_used(&state), *one.as_ref());
    assert!(state.metered_view().is_poisoned());

    // The key decodes: `pubkey_decode` per key, three here.
    let mut state = state_with::<DistinctCostSpec>(GRACE, [u64::MAX; 2]);
    tx.charge_gas_for_key_decode(&mut state).unwrap();
    assert_eq!(gas_used(&state), [291, 303]);
}
