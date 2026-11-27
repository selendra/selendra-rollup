//! Native transactions (`selendra_modules_api::transaction`), with both crypto specs:
//!
//! - the fuzz bytes as a `Transaction` (ed25519 and secp256k1), `UnsignedTransaction`,
//!   `TransactionSigningPayload`, `UniquenessData` and `TxDetails`: whatever decodes is
//!   canonical (re-encodes to the input) and round trips through borsh, JSON and postcard;
//! - transactions built from the fuzz bytes (keys from a pool, so they decode): the signing
//!   payload exists exactly when the keys and threshold are a valid multisig (an independent
//!   oracle: `1 ≤ min ≤ keys ≤ 21`, distinct keys); its prehash is the SHA-256 of its borsh
//!   encoding (hashed here with `sha2` directly), the signed bytes are the 19-byte header and
//!   that prehash, and they do not depend on which keys signed or in what order;
//! - `Multisig::new` against the same oracle; the credential ignores the keys' order;
//! - version tables built from the fuzz bytes: whatever `VersionTable::new` accepts has one or
//!   two versions at every boundary height, the primary one being the newest, and `resolve`
//!   agrees with `contains`.
#![no_main]

use std::collections::BTreeSet;

use libfuzzer_sys::fuzz_target;
use selendra_interface::common::{RollupHeight, SafeVec};
use selendra_modules_api::test_utils::TestSpec;
use selendra_modules_api::transaction::{
    MAX_SIGNERS, Multisig, MultisigError, PubKeyAndSignature, Transaction, TransactionCallable,
    TransactionSigningPayload, TxCryptoSpec, UniquenessData, UnsignedTransaction, Version0,
    Version1, VersionTable, VersionWindow,
};
use selendra_modules_api::{
    AccountAddress, Amount, Credential, GasUnit, PriorityFeeBips, Spec, TxDetails,
};
use selendra_primitives::crypto::{Ed25519CryptoSpec, EvmCryptoSpec};
use selendra_primitives::signing::{SigningDomain, signing_bytes};
use sha2::Digest;

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
enum FuzzCall {
    Ping(u64),
    Data(Vec<u8>),
    Named { name: String, value: Option<u32> },
}

struct FuzzRuntime;

impl TransactionCallable for FuzzRuntime {
    type Call = FuzzCall;
}

type S = TestSpec;

/// ed25519 public keys of the seeds `[i; 32]`.
const ED25519_KEYS: [&str; 23] = [
    "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
    "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394",
    "ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1",
    "ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c",
    "6e7a1cdd29b0b78fd13af4c5598feff4ef2a97166e3ca6f2e4fbfccd80505bf1",
    "8a875fff1eb38451577acd5afee405456568dd7c89e090863a0557bc7af49f17",
    "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
    "1398f62c6d1a457c51ba6a4b5f3dbd2f69fca93216218dc8997e416bd17d93ca",
    "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618",
    "43a72e714401762df66b68c26dfbdf2682aaec9f2474eca4613e424a0fbafd3c",
    "66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a",
    "0b513ad9b4924015ca0902ed079044d3ac5dbec2306f06948c10da8eb6e39f2d",
    "91a28a0b74381593a4d9469579208926afc8ad82c8839b7644359b9eba9a4b3a",
    "0beef5a9e679e6a3e134fe27837bff32c7cb5f5d44ea09bcb0e542bad6a4c0cc",
    "d9bf2148748a85c89da5aad8ee0b0fc2d105fd39d41a4c796536354f0ae2900c",
    "5c9c6df261c9cb840475776aaefcd944b405328fab28f9b3a95ef40490d3de84",
    "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
    "204040e364c10f2bec9c1fe500a1cd4c247c89d650a01ed7e82caba867877c21",
    "66cd608b928b88e50e0efeaa33faf1c43cefe07294b0b87e9fe0aba6a3cf7633",
    "20828bf5c5bdcacb684863336c202fb5599da48be5596615742170705beca9f7",
    "d54207da194977dcf46adbfec2bc2e75b52d5a8a42184fedfdc00024f0e3e8da",
    "511c34a1a2cb521df16bb246b8de8e7997ce235c7e76b22a3d7503a24819dd8a",
    "31debe55d37c722768b137131caa6087080b2e0b60b94bd785d14575cfa498bc",
];

/// secp256k1 public keys (of 1, of `0x4c0883a6…`, and a key recovered from a signature).
const SECP256K1_KEYS: [&str; 3] = [
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    "024e3b81af9c2234cad09d679ce6035ed1392347ce64ce405f5dcd36228a25de6e",
    "026b8d59dd7bd21730dbbea830009d7c6fa2f9139a227209176f06fa762bd98ef3",
];

/// Valid signature encodings (they verify nothing here).
const ED25519_SIGNATURE: &str = "0x7c3a595eba9710218bc657b84cfec04e80be19cdaa6ebcc2308127189a00b0c7ffa73802ab7dfbb8ad0673ca141bce598552c309327d1a49b1b12d80d438a703";
const SECP256K1_SIGNATURE: &str = "0x441cb2b78cca7760c673a29e52a43ba3a2af92196c7cdf602a2de4750b826271599e9927312c6deb5d7da66f3a075cfd80ffd256617f44b3f01da1d9d5976ddc";

/// The test's handle on a crypto spec: its key pool and a signature.
trait Pool: TxCryptoSpec {
    fn key(index: usize) -> Self::PublicKey;
    fn pool_size() -> usize;
    fn signature() -> Self::Signature;
}

impl Pool for Ed25519CryptoSpec {
    fn key(index: usize) -> Self::PublicKey {
        format!("0x{}", ED25519_KEYS[index % ED25519_KEYS.len()])
            .parse()
            .unwrap()
    }

    fn pool_size() -> usize {
        ED25519_KEYS.len()
    }

    fn signature() -> Self::Signature {
        ED25519_SIGNATURE.parse().unwrap()
    }
}

impl Pool for EvmCryptoSpec {
    fn key(index: usize) -> Self::PublicKey {
        format!("0x{}", SECP256K1_KEYS[index % SECP256K1_KEYS.len()])
            .parse()
            .unwrap()
    }

    fn pool_size() -> usize {
        SECP256K1_KEYS.len()
    }

    fn signature() -> Self::Signature {
        SECP256K1_SIGNATURE.parse().unwrap()
    }
}

/// Reads the fuzz bytes front to back, zeros once they run out.
struct Bytes<'a>(&'a [u8]);

impl Bytes<'_> {
    fn u8(&mut self) -> u8 {
        match self.0.split_first() {
            Some((first, rest)) => {
                self.0 = rest;
                *first
            }
            None => 0,
        }
    }

    fn u64(&mut self) -> u64 {
        u64::from_le_bytes(std::array::from_fn(|_| self.u8()))
    }

    fn vec(&mut self, max: usize) -> Vec<u8> {
        let len = usize::from(self.u8()) % (max + 1);
        (0..len).map(|_| self.u8()).collect()
    }
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

/// Every encoding of one value decodes to the same value, and its JSON is canonical.
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
    let decoded = serde_json::from_str::<T>(&json).unwrap();
    assert_eq!(&decoded, value);
    assert_eq!(serde_json::to_string(&decoded).unwrap(), json);
    let binary = postcard::to_allocvec(value).unwrap();
    assert_eq!(&postcard::from_bytes::<T>(&binary).unwrap(), value);
}

/// Whether `keys` with `min` form a valid multisig, decided without the crate.
fn multisig_oracle<C: TxCryptoSpec>(min: u8, keys: &[C::PublicKey]) -> bool {
    let distinct: BTreeSet<&[u8]> = keys.iter().map(|key| key.as_ref()).collect();
    min >= 1
        && usize::from(min) <= keys.len()
        && keys.len() <= MAX_SIGNERS
        && distinct.len() == keys.len()
}

/// The properties of any transaction value.
fn check_transaction<C: Pool>(
    tx: &Transaction<FuzzRuntime, S, C>,
    chain_id: u64,
    schema: &[u8; 32],
) {
    round_trips(tx);
    let keys: Vec<C::PublicKey> = match tx {
        Transaction::V0(inner) => vec![inner.pub_key.clone()],
        Transaction::V1(inner) => inner
            .signatures
            .iter()
            .map(|signature| signature.pub_key.clone())
            .chain(inner.unused_pub_keys.iter().cloned())
            .collect(),
    };
    assert_eq!(tx.key_count(), keys.len());
    let valid = match tx {
        Transaction::V0(_) => true,
        Transaction::V1(inner) => multisig_oracle::<C>(inner.min_signers, &keys),
    };
    let payload = tx.signing_payload(chain_id, schema);
    assert_eq!(payload.is_ok(), valid, "{payload:?}");
    assert_eq!(tx.credential().is_ok(), valid);
    let signed = tx.signing_bytes(chain_id, schema);
    assert_eq!(signed.is_ok(), valid);
    let Ok(payload) = payload else {
        assert!(
            tx.verify_signature(&signing_bytes(SigningDomain::Transaction, chain_id, b""))
                .is_err()
        );
        return;
    };
    round_trips(&payload);
    let encoded = borsh::to_vec(&payload).unwrap();
    assert_eq!(payload.encoded_len().unwrap(), encoded.len());
    let prehash: [u8; 32] = sha2::Sha256::digest(&encoded).into();
    assert_eq!(payload.prehash().unwrap(), prehash);
    let signed = signed.unwrap();
    assert_eq!(
        signed,
        signing_bytes(SigningDomain::Transaction, chain_id, &prehash)
    );
    assert_eq!(signed.len(), 51);
    assert_eq!(payload.runtime_call(), tx.runtime_call());
    assert_eq!(payload.details(), tx.details());
    assert_eq!(payload.uniqueness(), tx.uniqueness());
    assert_eq!(payload.address_override(), tx.address_override());
    // The placeholder signatures never verify.
    assert!(tx.verify_signature(&signed).is_err());
    let credential = tx.credential().unwrap();
    match tx {
        Transaction::V0(inner) => {
            assert_eq!(payload.signer(), Some(&inner.pub_key));
            assert_eq!(credential, C::credential(&inner.pub_key));
            if let Credential::Secp256k1(key) = &credential {
                assert_eq!(
                    <S as Spec>::Address::default_for(&credential),
                    selendra_primitives::MultiAddressEvm::Vm(key.ethereum_address())
                );
            }
        }
        Transaction::V1(inner) => {
            assert_eq!(
                payload.credential_address(),
                Some(&<S as Spec>::Address::default_for(&credential))
            );
            // Who signed and in what order does not change the signed bytes.
            let mut shuffled = inner.clone();
            shuffled.signatures.reverse();
            shuffled.unused_pub_keys.reverse();
            if let Some(moved) = shuffled.signatures.pop() {
                shuffled.unused_pub_keys.try_push(moved.pub_key).unwrap();
            }
            assert_eq!(
                Transaction::V1(shuffled)
                    .signing_bytes(chain_id, schema)
                    .unwrap(),
                signed
            );
        }
    }
}

fn details(bytes: &mut Bytes<'_>) -> TxDetails<S> {
    let fee = bytes.u64();
    let max_fee = Amount::new(u128::from(bytes.u64()) << (bytes.u8() % 65));
    let gas_limit = (bytes.u8() & 1 == 1).then(|| GasUnit::from([bytes.u64(), bytes.u64()]));
    TxDetails {
        max_priority_fee_bips: PriorityFeeBips(fee),
        max_fee,
        gas_limit,
        runtime_version: u32::from(bytes.u8()),
    }
}

fn call(bytes: &mut Bytes<'_>) -> FuzzCall {
    match bytes.u8() % 3 {
        0 => FuzzCall::Ping(bytes.u64()),
        1 => FuzzCall::Data(bytes.vec(64)),
        _ => FuzzCall::Named {
            name: String::from_utf8_lossy(&bytes.vec(16)).into_owned(),
            value: (bytes.u8() & 1 == 1).then(|| bytes.u8().into()),
        },
    }
}

fn uniqueness(bytes: &mut Bytes<'_>) -> UniquenessData {
    let n = bytes.u64();
    match bytes.u8() % 3 {
        0 => UniquenessData::Nonce(n),
        1 => UniquenessData::Generation(n),
        _ => UniquenessData::Window(n),
    }
}

/// A transaction built from the fuzz bytes, with keys from the pool (possibly repeated).
fn built<C: Pool>(bytes: &mut Bytes<'_>) -> Transaction<FuzzRuntime, S, C> {
    let unsigned = UnsignedTransaction::<FuzzRuntime, S>::new(
        call(bytes),
        uniqueness(bytes),
        details(bytes),
        None,
    );
    if bytes.u8() & 1 == 0 {
        return unsigned.to_signed_tx(C::key(usize::from(bytes.u8())), C::signature());
    }
    let signers = usize::from(bytes.u8()) % (MAX_SIGNERS + 1);
    let unused = usize::from(bytes.u8()) % (MAX_SIGNERS + 1);
    let mut signatures = SafeVec::new();
    for _ in 0..signers {
        signatures
            .try_push(PubKeyAndSignature {
                signature: C::signature(),
                pub_key: C::key(usize::from(bytes.u8())),
            })
            .unwrap();
    }
    let mut unused_pub_keys = SafeVec::new();
    for _ in 0..unused {
        unused_pub_keys
            .try_push(C::key(usize::from(bytes.u8())))
            .unwrap();
    }
    Transaction::V1(Version1 {
        signatures,
        unused_pub_keys,
        min_signers: bytes.u8() % 24,
        runtime_call: unsigned.runtime_call,
        uniqueness: unsigned.uniqueness,
        details: unsigned.details,
        address_override: unsigned.address_override,
    })
}

fn multisig<C: Pool>(bytes: &mut Bytes<'_>) {
    let min = bytes.u8() % 24;
    let count = usize::from(bytes.u8()) % 24;
    let keys: Vec<C::PublicKey> = (0..count)
        .map(|_| C::key(usize::from(bytes.u8()) % C::pool_size()))
        .collect();
    let result = Multisig::<C>::new(min, keys.clone());
    assert_eq!(
        result.is_ok(),
        multisig_oracle::<C>(min, &keys),
        "{result:?}"
    );
    match result {
        Ok(multisig) => {
            let mut reversed = keys;
            reversed.reverse();
            let other = Multisig::<C>::new(min, reversed).unwrap();
            assert_eq!(other.credential_id(), multisig.credential_id());
            assert!(
                multisig
                    .keys()
                    .windows(2)
                    .all(|pair| pair[0].as_ref() < pair[1].as_ref())
            );
        }
        Err(MultisigError::TooManyKeys { keys }) => assert!(keys > MAX_SIGNERS),
        Err(_) => {}
    }
}

fn version_table(bytes: &mut Bytes<'_>) {
    let count = usize::from(bytes.u8() % 6);
    let mut windows = Vec::new();
    for _ in 0..count {
        let from = u64::from(bytes.u8());
        let until = bytes.u8();
        windows.push(VersionWindow {
            spec_version: u32::from(bytes.u8() % 8),
            schema_hash: [bytes.u8(); 32],
            from_height: RollupHeight::new(from),
            until_height: (until != 0).then(|| RollupHeight::new(u64::from(until))),
        });
    }
    let Ok(table) = VersionTable::new(&windows) else {
        return;
    };
    let mut heights = vec![u64::MAX];
    for window in &windows {
        let from = window.from_height.get();
        heights.extend([from.saturating_sub(1), from, from + 1]);
        if let Some(until) = window.until_height {
            heights.extend([until.get() - 1, until.get()]);
        }
    }
    for height in heights {
        let height = RollupHeight::new(height);
        let accepted: Vec<&VersionWindow> = windows
            .iter()
            .filter(|window| window.contains(height))
            .collect();
        assert!((1..=2).contains(&accepted.len()), "{windows:?} at {height}");
        assert_eq!(table.primary_at(height), *accepted.last().unwrap());
        assert_eq!(
            table.grace_at(height),
            (accepted.len() == 2).then(|| accepted[0])
        );
        for window in &windows {
            assert_eq!(
                table.resolve(height, window.spec_version),
                window.contains(height).then_some(window)
            );
        }
    }
}

fn decoded(data: &[u8]) {
    if let Some(tx) = borsh_canonical::<Transaction<FuzzRuntime, S, Ed25519CryptoSpec>>(data) {
        check_transaction(&tx, 1961, &[0; 32]);
    }
    if let Some(tx) = borsh_canonical::<Transaction<FuzzRuntime, S, EvmCryptoSpec>>(data) {
        check_transaction(&tx, 1961, &[0; 32]);
    }
    if let Some(tx) = borsh_canonical::<Version0<FuzzRuntime, S, EvmCryptoSpec>>(data) {
        round_trips(&tx);
    }
    if let Some(unsigned) = borsh_canonical::<UnsignedTransaction<FuzzRuntime, S>>(data) {
        round_trips(&unsigned);
    }
    if let Some(payload) =
        borsh_canonical::<TransactionSigningPayload<FuzzRuntime, S, Ed25519CryptoSpec>>(data)
    {
        round_trips(&payload);
        let prehash: [u8; 32] = sha2::Sha256::digest(data).into();
        assert_eq!(payload.prehash().unwrap(), prehash);
    }
    if let Some(uniqueness) = borsh_canonical::<UniquenessData>(data) {
        assert_eq!(data.len(), 9);
        round_trips(&uniqueness);
    }
    if let Some(details) = borsh_canonical::<TxDetails<S>>(data) {
        assert!(data.len() == 29 || data.len() == 45);
        round_trips(&details);
    }
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(tx) = serde_json::from_str::<Transaction<FuzzRuntime, S, EvmCryptoSpec>>(s) {
            let value: serde_json::Value = serde_json::from_str(s).unwrap();
            assert_eq!(
                serde_json::to_value(&tx).unwrap(),
                value,
                "non-canonical JSON accepted"
            );
        }
        if let Ok(uniqueness) = serde_json::from_str::<UniquenessData>(s) {
            let value: serde_json::Value = serde_json::from_str(s).unwrap();
            assert_eq!(serde_json::to_value(uniqueness).unwrap(), value);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    decoded(data);
    let mut bytes = Bytes(data);
    let chain_id = bytes.u64();
    let schema = [bytes.u8(); 32];
    match bytes.u8() % 4 {
        0 => check_transaction(&built::<Ed25519CryptoSpec>(&mut bytes), chain_id, &schema),
        1 => check_transaction(&built::<EvmCryptoSpec>(&mut bytes), chain_id, &schema),
        2 => {
            multisig::<Ed25519CryptoSpec>(&mut bytes);
            multisig::<EvmCryptoSpec>(&mut bytes);
        }
        _ => version_table(&mut bytes),
    }
    // A built transaction's encoding, with one byte changed, decodes only canonically.
    let mut again = Bytes(data);
    let tx = built::<Ed25519CryptoSpec>(&mut again);
    let mut encoded = borsh::to_vec(&tx).unwrap();
    if !encoded.is_empty() {
        let at = usize::from(again.u8()) * 7 % encoded.len();
        encoded[at] ^= again.u8() | 1;
        if let Some(changed) =
            borsh_canonical::<Transaction<FuzzRuntime, S, Ed25519CryptoSpec>>(&encoded)
        {
            check_transaction(&changed, chain_id, &schema);
        }
    }
});
