//! Native transactions: the signing known-answer vectors, the payload's commitments, multisig
//! transactions, encodings.

mod vectors;

use selendra_interface::crypto::PublicKey;
use selendra_interface::zk::CryptoSpec;
use selendra_primitives::crypto::{
    Ed25519CryptoSpec, Ed25519PublicKey, EthereumPublicKey, EvmCryptoSpec,
};
use selendra_primitives::signing::{HEADER_LEN, SigningDomain, signing_bytes};
use selendra_primitives::{Address, EthereumAddress, MultiAddressEvm};

use super::*;
use crate::test_utils::TestSpec;
use crate::{AccountAddress, Amount, Credential, GasUnit};

type S = TestSpec;

const CHAIN_ID: u64 = 1961;
const SCHEMA_1: SchemaHash = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];
const SCHEMA_2: SchemaHash = [0x22; 32];

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
    crate::ConsensusType,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum VectorCall {
    Ping(u64),
    Data(Vec<u8>),
}

/// A runtime whose calls are [`VectorCall`]s.
pub(super) struct VectorRuntime;

impl TransactionCallable for VectorRuntime {
    type Call = VectorCall;
}

type Ed<R = VectorRuntime> = Transaction<R, S, Ed25519CryptoSpec>;
type Secp<R = VectorRuntime> = Transaction<R, S, EvmCryptoSpec>;

fn bytes(hex: &str) -> Vec<u8> {
    hex::decode(hex).unwrap()
}

fn parse<T: core::str::FromStr<Err = anyhow::Error>>(hex: &str) -> T {
    format!("0x{hex}").parse().unwrap()
}

fn details(
    fee_bips: u64,
    max_fee: u128,
    gas_limit: Option<[u64; 2]>,
    version: u32,
) -> TxDetails<S> {
    TxDetails {
        max_priority_fee_bips: PriorityFeeBips(fee_bips),
        max_fee: Amount::new(max_fee),
        gas_limit: gas_limit.map(GasUnit::from),
        runtime_version: version,
    }
}

fn v0_ed25519_unsigned() -> UnsignedTransaction<VectorRuntime, S> {
    UnsignedTransaction::new(
        VectorCall::Data(b"selendra".to_vec()),
        UniquenessData::Nonce(5),
        details(100, 1_000_000, Some([10_000, 20_000]), 1),
        None,
    )
}

fn v0_secp256k1_unsigned() -> UnsignedTransaction<VectorRuntime, S> {
    let vm: [u8; 20] = std::array::from_fn(|i| u8::try_from(i + 1).unwrap());
    UnsignedTransaction::new(
        VectorCall::Ping(42),
        UniquenessData::Generation(3),
        details(0, 5000, None, 1),
        Some(MultiAddressEvm::Vm(EthereumAddress::new(vm))),
    )
}

fn v1_ed25519_unsigned() -> UnsignedTransaction<VectorRuntime, S> {
    UnsignedTransaction::new(
        VectorCall::Data(Vec::new()),
        UniquenessData::Window(9),
        details(250, 77, None, 2),
        Some(MultiAddressEvm::Standard(Address::new([0xab; 28]))),
    )
}

fn v1_secp256k1_unsigned() -> UnsignedTransaction<VectorRuntime, S> {
    UnsignedTransaction::new(
        VectorCall::Ping(7),
        UniquenessData::Nonce(0),
        details(1, 1, Some([1, 2]), 2),
        None,
    )
}

/// The vector's V1 ed25519 transaction: signed by key 2 then key 1, key 3 unused.
fn v1_ed25519_tx() -> Ed {
    use vectors::v1_ed25519 as v;
    let [k1, k2, k3] = v::KEYS.map(parse::<Ed25519PublicKey>);
    let mut tx = v1_ed25519_unsigned().to_multisig_tx(
        Multisig::<Ed25519CryptoSpec>::new(2, vec![k1.clone(), k2.clone(), k3]).unwrap(),
    );
    tx.add_signature(parse(v::SIGNATURE_2), k2).unwrap();
    tx.add_signature(parse(v::SIGNATURE_1), k1).unwrap();
    Transaction::V1(tx)
}

fn v1_secp256k1_tx() -> Secp {
    use vectors::v1_secp256k1 as v;
    let [a, b] = v::KEYS.map(parse::<EthereumPublicKey>);
    let mut tx = v1_secp256k1_unsigned()
        .to_multisig_tx(Multisig::<EvmCryptoSpec>::new(1, vec![a, b]).unwrap());
    tx.add_signature(parse(v::SIGNATURE), b).unwrap();
    Transaction::V1(tx)
}

/// Checks a transaction against its vector: the commitment, the payload's encoding, its
/// prehash, the signed bytes, the transaction's encoding (both ways), and that its signatures
/// verify.
fn check_vector<C: TxCryptoSpec>(
    tx: &Transaction<VectorRuntime, S, C>,
    schema_hash: &SchemaHash,
    commitment: &str,
    payload: &str,
    prehash: &str,
    signed: &str,
    encoded: &str,
) {
    assert_eq!(
        hex::encode(tx.runtime_commitment(CHAIN_ID, schema_hash).as_bytes()),
        commitment
    );
    let signing_payload = tx.signing_payload(CHAIN_ID, schema_hash).unwrap();
    assert_eq!(
        hex::encode(borsh::to_vec(&signing_payload).unwrap()),
        payload
    );
    assert_eq!(signing_payload.encoded_len().unwrap(), payload.len() / 2);
    assert_eq!(
        borsh::from_slice::<TransactionSigningPayload<VectorRuntime, S, C>>(&bytes(payload))
            .unwrap(),
        signing_payload
    );
    assert_eq!(hex::encode(signing_payload.prehash().unwrap()), prehash);
    let signing = tx.signing_bytes(CHAIN_ID, schema_hash).unwrap();
    assert_eq!(hex::encode(signing.as_bytes()), signed);
    assert_eq!(signing.len(), HEADER_LEN + 32);
    assert_eq!(hex::encode(borsh::to_vec(tx).unwrap()), encoded);
    assert_eq!(
        &borsh::from_slice::<Transaction<VectorRuntime, S, C>>(&bytes(encoded)).unwrap(),
        tx
    );
    tx.verify_signature(&signing).unwrap();
}

#[test]
fn signing_vector_v0_ed25519() {
    use vectors::v0_ed25519 as v;
    let tx: Ed = v0_ed25519_unsigned().to_signed_tx(parse(v::PUB_KEY), parse(v::SIGNATURE));
    check_vector(
        &tx,
        &SCHEMA_1,
        v::COMMITMENT,
        v::PAYLOAD,
        v::PREHASH,
        v::SIGNING_BYTES,
        v::TX,
    );
    assert_eq!(
        tx.credential().unwrap(),
        Credential::Ed25519(parse(v::PUB_KEY))
    );
}

#[test]
fn signing_vector_v0_secp256k1() {
    use vectors::v0_secp256k1 as v;
    let tx: Secp = v0_secp256k1_unsigned().to_signed_tx(parse(v::PUB_KEY), parse(v::SIGNATURE));
    check_vector(
        &tx,
        &SCHEMA_1,
        v::COMMITMENT,
        v::PAYLOAD,
        v::PREHASH,
        v::SIGNING_BYTES,
        v::TX,
    );
    let key: EthereumPublicKey = parse(v::PUB_KEY);
    assert_eq!(hex::encode(key.ethereum_address().as_ref()), v::ETH_ADDRESS);
    // P5-08: an EVM key's transaction runs as its `0x…` account.
    assert_eq!(
        <S as crate::Spec>::Address::default_for(&tx.credential().unwrap()),
        MultiAddressEvm::Vm(key.ethereum_address())
    );
}

#[test]
fn signing_vector_v1_ed25519() {
    use vectors::v1_ed25519 as v;
    let tx = v1_ed25519_tx();
    check_vector(
        &tx,
        &SCHEMA_2,
        v::COMMITMENT,
        v::PAYLOAD,
        v::PREHASH,
        v::SIGNING_BYTES,
        v::TX,
    );
    let credential = tx.credential().unwrap();
    assert_eq!(
        hex::encode(credential.credential_id().as_bytes()),
        v::CREDENTIAL
    );
    let mut first_28 = [0; 28];
    first_28.copy_from_slice(&bytes(v::CREDENTIAL)[..28]);
    assert_eq!(
        tx.signing_payload(CHAIN_ID, &SCHEMA_2)
            .unwrap()
            .credential_address(),
        Some(&MultiAddressEvm::Standard(Address::new(first_28)))
    );
}

#[test]
fn signing_vector_v1_secp256k1() {
    use vectors::v1_secp256k1 as v;
    let tx = v1_secp256k1_tx();
    check_vector(
        &tx,
        &SCHEMA_2,
        v::COMMITMENT,
        v::PAYLOAD,
        v::PREHASH,
        v::SIGNING_BYTES,
        v::TX,
    );
    assert_eq!(
        hex::encode(tx.credential().unwrap().credential_id().as_bytes()),
        v::CREDENTIAL
    );
}

/// The unsigned transaction builds the same signed bytes as the signed one.
#[test]
fn unsigned_and_signed_transactions_sign_the_same_bytes() {
    use vectors::{v0_ed25519, v1_ed25519};
    let signer: Ed25519PublicKey = parse(v0_ed25519::PUB_KEY);
    let signed = v0_ed25519_unsigned()
        .signing_bytes_v0::<Ed25519CryptoSpec>(&signer, CHAIN_ID, &SCHEMA_1)
        .unwrap();
    assert_eq!(hex::encode(signed.as_bytes()), v0_ed25519::SIGNING_BYTES);
    let multisig = Multisig::<Ed25519CryptoSpec>::new(
        2,
        v1_ed25519::KEYS.map(parse::<Ed25519PublicKey>).to_vec(),
    )
    .unwrap();
    let signed = v1_ed25519_unsigned()
        .signing_bytes_v1(&multisig, CHAIN_ID, &SCHEMA_2)
        .unwrap();
    assert_eq!(hex::encode(signed.as_bytes()), v1_ed25519::SIGNING_BYTES);
    assert_eq!(
        v1_ed25519_tx().to_unsigned_transaction(),
        v1_ed25519_unsigned()
    );
}

/// The signed bytes are the header, then the payload's SHA-256 (O2: native transactions sign
/// the prehash), checked here against the payload's encoding hashed independently of the
/// payload type (`sha2` directly).
#[test]
fn signed_bytes_are_the_header_and_the_prehash() {
    use sha2::Digest as _;
    let tx = v1_secp256k1_tx();
    let payload = borsh::to_vec(&tx.signing_payload(CHAIN_ID, &SCHEMA_2).unwrap()).unwrap();
    let prehash = sha2::Sha256::digest(&payload);
    let mut expected = b"\xb5SELENDRA\x01\x01".to_vec();
    expected.extend(CHAIN_ID.to_le_bytes());
    expected.extend(prehash);
    assert_eq!(
        tx.signing_bytes(CHAIN_ID, &SCHEMA_2).unwrap().as_bytes(),
        expected
    );
}

// Regressions of upstream's signing payload bugs

/// P5-36 (regression): upstream's V0 payload did not contain the signing key. An ECDSA
/// signature verifies under more than one key (here the vector's signature and a second key
/// recovered from it with the other `R` parity, computed independently in Python), so the
/// same signed bytes and signature made a valid transaction from another key: another sender.
/// The payload commits to the key, so the substitute key's transaction signs other bytes.
#[test]
fn v0_payload_commits_to_signer() {
    use vectors::v0_secp256k1 as v;
    const SUBSTITUTE: &str = "026b8d59dd7bd21730dbbea830009d7c6fa2f9139a227209176f06fa762bd98ef3";
    let real: EthereumPublicKey = parse(v::PUB_KEY);
    let substitute: EthereumPublicKey = parse(SUBSTITUTE);
    let signature: <EvmCryptoSpec as CryptoSpec>::Signature = parse(v::SIGNATURE);
    // The substitute key verifies the signature over the very bytes the real key signed.
    selendra_interface::crypto::Signature::verify(
        &signature,
        &substitute,
        &bytes(v::SIGNING_BYTES),
    )
    .unwrap();
    assert_ne!(real.credential_id(), substitute.credential_id());

    let tx: Secp = v0_secp256k1_unsigned().to_signed_tx(real, signature);
    tx.verify_signature(&tx.signing_bytes(CHAIN_ID, &SCHEMA_1).unwrap())
        .unwrap();
    let forged: Secp = v0_secp256k1_unsigned().to_signed_tx(substitute, signature);
    let forged_bytes = forged.signing_bytes(CHAIN_ID, &SCHEMA_1).unwrap();
    assert_ne!(hex::encode(forged_bytes.as_bytes()), v::SIGNING_BYTES);
    assert!(matches!(
        forged.verify_signature(&forged_bytes),
        Err(TransactionError::BadSignature { .. })
    ));
}

/// The signed bytes commit to the chain ID, the runtime version and its schema hash, and V0
/// and V1 payloads never coincide.
#[test]
fn signed_bytes_commit_to_the_runtime() {
    use vectors::v0_ed25519 as v;
    let tx: Ed = v0_ed25519_unsigned().to_signed_tx(parse(v::PUB_KEY), parse(v::SIGNATURE));
    let reference = tx.signing_bytes(CHAIN_ID, &SCHEMA_1).unwrap();
    let mut other_schema = SCHEMA_1;
    other_schema[31] ^= 1;
    let mut other_version = tx.clone();
    if let Transaction::V0(inner) = &mut other_version {
        inner.details.runtime_version = 2;
    }
    for other in [
        tx.signing_bytes(CHAIN_ID + 1, &SCHEMA_1).unwrap(),
        tx.signing_bytes(CHAIN_ID, &other_schema).unwrap(),
        other_version.signing_bytes(CHAIN_ID, &SCHEMA_1).unwrap(),
    ] {
        assert_ne!(other, reference);
        assert!(tx.verify_signature(&other).is_err());
    }
    tx.verify_signature(&reference).unwrap();
    // The header's chain ID and domain are the signing module's.
    assert_eq!(
        reference,
        signing_bytes(
            SigningDomain::Transaction,
            CHAIN_ID,
            &tx.signing_payload(CHAIN_ID, &SCHEMA_1)
                .unwrap()
                .prehash()
                .unwrap()
        )
    );
}

/// P5-07 (regression, the transaction part): a signature over the bare payload, over the
/// prehash without the header, or over the payload in another domain is not a transaction
/// signature (upstream signed and verified the bare borsh payload). Uses the vector key's
/// signatures over each wrong message, computed independently in Python (RFC 8032).
#[test]
fn bare_payload_signature_does_not_verify() {
    use vectors::v0_ed25519 as v;
    // Signatures by the RFC 8032 test 1 key over: the bare payload; its SHA-256 without the
    // header; the header and prehash in the `OffchainMessage` domain.
    const WRONG_BARE: &str = "\
        fe5007fb6325cef9dae86127f4c3ffbe0087c5404f0a61f92da68da887018fb4\
        ebd69444ea284c56033236879d1965d983d3caf189301a2a2200371b535c970e";
    const WRONG_PREHASH: &str = "\
        0d81d488f498bdd64e87440217e3db90a45eb14227f23bd39b67fe10ea0ded28\
        a212802dfd26d2439c2c18437135f167bb5a583a53259784711245b66ca12c01";
    const WRONG_DOMAIN: &str = "\
        23fcbe422c0c86e7a768d1fdf521260fc45eaeab8debc4b31c7eec0bdc3e1508\
        b073252d601da0c973c0ec3942369b78f64ea4e75c8fb3d3a23a080582fb5c06";
    let tx: Ed = v0_ed25519_unsigned().to_signed_tx(parse(v::PUB_KEY), parse(v::SIGNATURE));
    let signed = tx.signing_bytes(CHAIN_ID, &SCHEMA_1).unwrap();
    tx.verify_signature(&signed).unwrap();
    for wrong in [WRONG_BARE, WRONG_PREHASH, WRONG_DOMAIN] {
        let forged: Ed = v0_ed25519_unsigned().to_signed_tx(parse(v::PUB_KEY), parse(wrong));
        assert!(matches!(
            forged.verify_signature(&signed),
            Err(TransactionError::BadSignature { .. })
        ));
    }
}

/// Different subsets and orders of a multisig's signers sign the same bytes (the credential
/// covers every key and the threshold, not who signed).
#[test]
fn different_signature_subsets_give_same_signing_bytes() {
    use vectors::v1_ed25519 as v;
    let keys = v::KEYS.map(parse::<Ed25519PublicKey>);
    let placeholder: <Ed25519CryptoSpec as CryptoSpec>::Signature = parse(v::SIGNATURE_1);
    let reference = v1_ed25519_tx().signing_bytes(CHAIN_ID, &SCHEMA_2).unwrap();
    for (signers, unused) in [
        (vec![0, 1], vec![2]),
        (vec![1, 0], vec![2]),
        (vec![2], vec![0, 1]),
        (vec![], vec![2, 1, 0]),
        (vec![2, 1, 0], vec![]),
    ] {
        let tx = Version1::<VectorRuntime, S, Ed25519CryptoSpec> {
            signatures: signers
                .iter()
                .map(|&i: &usize| PubKeyAndSignature {
                    signature: placeholder.clone(),
                    pub_key: keys[i].clone(),
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            unused_pub_keys: unused
                .iter()
                .map(|&i: &usize| keys[i].clone())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            ..match v1_ed25519_tx() {
                Transaction::V1(tx) => tx,
                Transaction::V0(_) => unreachable!(),
            }
        };
        assert_eq!(
            Transaction::V1(tx)
                .signing_bytes(CHAIN_ID, &SCHEMA_2)
                .unwrap(),
            reference,
            "{signers:?} {unused:?}"
        );
    }
    // Another threshold, another key set: other bytes.
    let mut other = match v1_ed25519_tx() {
        Transaction::V1(tx) => tx,
        Transaction::V0(_) => unreachable!(),
    };
    other.min_signers = 1;
    assert_ne!(
        Transaction::V1(other.clone())
            .signing_bytes(CHAIN_ID, &SCHEMA_2)
            .unwrap(),
        reference
    );
    other.min_signers = 2;
    other.unused_pub_keys = SafeVecOf::try_from(vec![]).unwrap();
    assert_ne!(
        Transaction::V1(other)
            .signing_bytes(CHAIN_ID, &SCHEMA_2)
            .unwrap(),
        reference
    );
}

type SafeVecOf<T> = selendra_interface::common::SafeVec<T, MAX_SIGNERS>;

/// P5-34 (regression, the transaction side): a V1 transaction whose keys and threshold are not
/// a valid multisig has no credential and never verifies. Upstream accepted a 0-of-N
/// transaction with no signature, and up to 21 signers plus 21 unused keys.
#[test]
fn invalid_multisig_transactions_do_not_verify() {
    let base = match v1_ed25519_tx() {
        Transaction::V1(tx) => tx,
        Transaction::V0(_) => unreachable!(),
    };
    let signed = Transaction::V1(base.clone())
        .signing_bytes(CHAIN_ID, &SCHEMA_2)
        .unwrap();

    // 0 of N, no signature.
    let mut zero = base.clone();
    zero.signatures = SafeVecOf::default();
    zero.unused_pub_keys = base.multisig().unwrap().keys_vec();
    zero.min_signers = 0;
    let zero = Transaction::V1(zero);
    assert_eq!(zero.credential(), Err(MultisigError::ZeroThreshold));
    assert_eq!(
        zero.verify_signature(&signed),
        Err(TransactionError::Multisig(MultisigError::ZeroThreshold))
    );
    assert!(zero.signing_bytes(CHAIN_ID, &SCHEMA_2).is_err());

    // 11 signers and 11 unused keys: each list fits its cap, the total does not.
    let placeholder: <Ed25519CryptoSpec as CryptoSpec>::Signature =
        parse(vectors::v1_ed25519::SIGNATURE_1);
    let keys: Vec<Ed25519PublicKey> = (0..22).map(multisig::tests::ed25519_key).collect();
    let mut many = base.clone();
    many.signatures = keys[..11]
        .iter()
        .map(|key| PubKeyAndSignature {
            signature: placeholder.clone(),
            pub_key: key.clone(),
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    many.unused_pub_keys = keys[11..].to_vec().try_into().unwrap();
    many.min_signers = 11;
    let many = Transaction::V1(many);
    let encoded = borsh::to_vec(&many).unwrap();
    assert_eq!(borsh::from_slice::<Ed>(&encoded).unwrap(), many);
    assert_eq!(
        many.verify_signature(&signed),
        Err(TransactionError::Multisig(MultisigError::TooManyKeys {
            keys: 22
        }))
    );
    assert_eq!(many.key_count(), 22);
    assert_eq!(many.signature_count(), 11);

    // A signer's key among the unused keys too.
    let mut duplicate = base.clone();
    duplicate.unused_pub_keys = vec![base.signatures[0].pub_key.clone()].try_into().unwrap();
    assert_eq!(
        Transaction::V1(duplicate).verify_signature(&signed),
        Err(TransactionError::Multisig(MultisigError::DuplicateKey))
    );

    // Too few signatures for the threshold.
    let mut short = base.clone();
    let removed = short.signatures.pop().unwrap();
    short.unused_pub_keys.try_push(removed.pub_key).unwrap();
    assert!(!short.is_fully_signed());
    assert_eq!(
        Transaction::V1(short).verify_signature(&signed),
        Err(TransactionError::Multisig(
            MultisigError::NotEnoughSignatures {
                required: 2,
                got: 1
            }
        ))
    );
    assert!(base.is_fully_signed());
}

/// `add_signature` moves an unused key to the signers, and changes nothing when it fails.
#[test]
fn add_signature_rules() {
    use vectors::v1_ed25519 as v;
    let [k1, k2, k3] = v::KEYS.map(parse::<Ed25519PublicKey>);
    let multisig =
        Multisig::<Ed25519CryptoSpec>::new(2, vec![k1.clone(), k2.clone(), k3.clone()]).unwrap();
    let mut tx = v1_ed25519_unsigned().to_multisig_tx(multisig);
    assert_eq!(tx.unused_pub_keys.len(), 3);
    assert!(tx.signatures.is_empty());
    tx.add_signature(parse(v::SIGNATURE_1), k1.clone()).unwrap();
    let before = tx.clone();
    assert_eq!(
        tx.add_signature(parse(v::SIGNATURE_1), k1),
        Err(MultisigError::DuplicateSigner)
    );
    assert_eq!(
        tx.add_signature(parse(v::SIGNATURE_1), multisig::tests::ed25519_key(0)),
        Err(MultisigError::OutsiderSigner)
    );
    assert_eq!(tx, before);
    assert!(!tx.is_fully_signed());
    tx.add_signature(parse(v::SIGNATURE_2), k2).unwrap();
    assert!(tx.is_fully_signed());
    assert_eq!(tx.unused_pub_keys.as_ref(), [k3]);
}

/// JSON: externally tagged by version, fields in declaration order, lowercase hex; round trips
/// in JSON, borsh and postcard; trailing bytes and unknown tags rejected.
#[test]
fn transaction_encodings() {
    let tx = v1_secp256k1_tx();
    let json = serde_json::to_value(&tx).unwrap();
    let object = json["v1"].as_object().unwrap();
    assert_eq!(
        object.keys().map(String::as_str).collect::<Vec<_>>(),
        // Sorted (`serde_json::Map`).
        [
            "address_override",
            "details",
            "min_signers",
            "runtime_call",
            "signatures",
            "uniqueness",
            "unused_pub_keys",
        ]
    );
    // In declaration order in the text.
    assert!(
        serde_json::to_string(&tx)
            .unwrap()
            .starts_with(r#"{"v1":{"signatures":[{"signature":"0x"#)
    );
    assert_eq!(object["address_override"], serde_json::Value::Null);
    assert_eq!(
        object["signatures"][0]["pub_key"],
        format!("0x{}", vectors::v1_secp256k1::KEYS[1])
    );
    assert_eq!(serde_json::from_value::<Secp>(json.clone()).unwrap(), tx);
    // Missing and unknown fields: `transaction_json_is_strict`. Hex is lowercase.
    let mut upper = json;
    upper["v1"]["signatures"][0]["pub_key"] =
        format!("0x{}", vectors::v1_secp256k1::KEYS[1].to_uppercase()).into();
    assert!(serde_json::from_value::<Secp>(upper).is_err());

    for encoded in [
        borsh::to_vec(&tx).unwrap(),
        borsh::to_vec(&Secp::from(
            match v0_secp256k1_unsigned().to_signed_tx::<EvmCryptoSpec>(
                parse(vectors::v0_secp256k1::PUB_KEY),
                parse(vectors::v0_secp256k1::SIGNATURE),
            ) {
                Transaction::V0(inner) => inner,
                Transaction::V1(_) => unreachable!(),
            },
        ))
        .unwrap(),
    ] {
        let decoded = borsh::from_slice::<Secp>(&encoded).unwrap();
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(borsh::from_slice::<Secp>(&trailing).is_err());
        let mut bad_tag = encoded.clone();
        bad_tag[0] = 2;
        assert!(borsh::from_slice::<Secp>(&bad_tag).is_err());
        let binary = postcard::to_allocvec(&decoded).unwrap();
        assert_eq!(postcard::from_bytes::<Secp>(&binary).unwrap(), decoded);
        let json = serde_json::to_string(&decoded).unwrap();
        assert_eq!(serde_json::from_str::<Secp>(&json).unwrap(), decoded);
    }

    // The unsigned transaction and the payload have JSON forms too.
    let unsigned = v1_ed25519_unsigned();
    let json = serde_json::to_string(&unsigned).unwrap();
    assert_eq!(
        json,
        format!(
            r#"{{"runtime_call":{{"data":[]}},"uniqueness":{{"window":9}},"details":{{"max_priority_fee_bips":250,"max_fee":"77","gas_limit":null,"runtime_version":2}},"address_override":"{}"}}"#,
            Address::new([0xab; 28])
        )
    );
    assert_eq!(
        serde_json::from_str::<UnsignedTransaction<VectorRuntime, S>>(&json).unwrap(),
        unsigned
    );
    let payload = v1_ed25519_tx()
        .signing_payload(CHAIN_ID, &SCHEMA_2)
        .unwrap();
    let json = serde_json::to_string(&payload).unwrap();
    assert!(json.starts_with(r#"{"v1":{"runtime_call""#));
    assert_eq!(
        serde_json::from_str::<TransactionSigningPayload<VectorRuntime, S, Ed25519CryptoSpec>>(
            &json
        )
        .unwrap(),
        payload
    );
}

/// Checks that `value`'s JSON is strict: it round trips (the accepting twin), and with any field
/// of the object at `pointer` removed (`address_override` included: `null` for none, never
/// missing) or an unknown field added, it does not decode. For a version enum (`pointer` is its
/// tag), an unknown tag does not decode either.
fn check_strict_json<T>(value: &T, pointer: &str, fields: &[&str])
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + core::fmt::Debug,
{
    let json = serde_json::to_value(value).unwrap();
    assert_eq!(&serde_json::from_value::<T>(json.clone()).unwrap(), value);
    let object = json.pointer(pointer).unwrap().as_object().unwrap();
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    let mut expected = fields.to_vec();
    expected.sort_unstable();
    assert_eq!(keys, expected, "{json}");
    for field in fields {
        let mut missing = json.clone();
        missing
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(*field);
        assert!(
            serde_json::from_value::<T>(missing).is_err(),
            "decoded without `{field}`: {json}"
        );
    }
    let mut unknown = json.clone();
    unknown.pointer_mut(pointer).unwrap()["extra"] = 0.into();
    assert!(
        serde_json::from_value::<T>(unknown).is_err(),
        "decoded with an unknown field: {json}"
    );
    if let Some(tag) = pointer.strip_prefix('/') {
        let inner = json[tag].clone();
        for bad_tag in ["v2", &tag.to_uppercase()] {
            let renamed = serde_json::json!({ bad_tag: inner.clone() });
            assert!(
                serde_json::from_value::<T>(renamed).is_err(),
                "decoded with the tag `{bad_tag}`"
            );
        }
    }
}

/// Every strict JSON form (`Version0`, `Version1`, `UnsignedTransaction`, both signing payloads,
/// `PubKeyAndSignature`) rejects a missing field, a missing `address_override` included, and an
/// unknown field; the unmodified value decodes.
#[test]
fn transaction_json_is_strict() {
    const TX_V0: &[&str] = &[
        "address_override",
        "details",
        "pub_key",
        "runtime_call",
        "signature",
        "uniqueness",
    ];
    const TX_V1: &[&str] = &[
        "address_override",
        "details",
        "min_signers",
        "runtime_call",
        "signatures",
        "uniqueness",
        "unused_pub_keys",
    ];
    const UNSIGNED: &[&str] = &["address_override", "details", "runtime_call", "uniqueness"];
    const PAYLOAD_V0: &[&str] = &[
        "address_override",
        "details",
        "runtime_call",
        "runtime_commitment",
        "signer",
        "uniqueness",
    ];
    const PAYLOAD_V1: &[&str] = &[
        "address_override",
        "credential_address",
        "details",
        "runtime_call",
        "runtime_commitment",
        "uniqueness",
    ];

    let v0_ed = v0_ed25519_unsigned().to_signed_tx::<Ed25519CryptoSpec>(
        parse(vectors::v0_ed25519::PUB_KEY),
        parse(vectors::v0_ed25519::SIGNATURE),
    );
    let v0_secp = v0_secp256k1_unsigned().to_signed_tx::<EvmCryptoSpec>(
        parse(vectors::v0_secp256k1::PUB_KEY),
        parse(vectors::v0_secp256k1::SIGNATURE),
    );
    check_strict_json(&v0_ed, "/v0", TX_V0);
    check_strict_json(&v0_secp, "/v0", TX_V0);
    check_strict_json(&v1_ed25519_tx(), "/v1", TX_V1);
    check_strict_json(&v1_secp256k1_tx(), "/v1", TX_V1);

    for unsigned in [
        v0_ed25519_unsigned(),
        v0_secp256k1_unsigned(),
        v1_ed25519_unsigned(),
    ] {
        check_strict_json(&unsigned, "", UNSIGNED);
    }

    check_strict_json(
        &v0_ed.signing_payload(CHAIN_ID, &SCHEMA_1).unwrap(),
        "/v0",
        PAYLOAD_V0,
    );
    check_strict_json(
        &v0_secp.signing_payload(CHAIN_ID, &SCHEMA_1).unwrap(),
        "/v0",
        PAYLOAD_V0,
    );
    check_strict_json(
        &v1_ed25519_tx()
            .signing_payload(CHAIN_ID, &SCHEMA_2)
            .unwrap(),
        "/v1",
        PAYLOAD_V1,
    );

    let Transaction::V1(multisig) = v1_secp256k1_tx() else {
        unreachable!()
    };
    check_strict_json(&multisig.signatures[0], "", &["pub_key", "signature"]);
    let Transaction::V1(multisig) = v1_ed25519_tx() else {
        unreachable!()
    };
    check_strict_json(&multisig.signatures[0], "", &["pub_key", "signature"]);
}

/// Every transaction type is a consensus type, and the runtime's call type is what a
/// transaction of the runtime calls.
#[test]
fn transaction_types_are_consensus_types() {
    fn consensus<T: crate::ConsensusType>() {}
    consensus::<Transaction<VectorRuntime, S>>();
    consensus::<Transaction<VectorRuntime, S, EvmCryptoSpec>>();
    consensus::<Version0<VectorRuntime, S, EvmCryptoSpec>>();
    consensus::<Version1<VectorRuntime, S, Ed25519CryptoSpec>>();
    consensus::<PubKeyAndSignature<EvmCryptoSpec>>();
    consensus::<UnsignedTransaction<VectorRuntime, S>>();
    consensus::<TransactionSigningPayload<VectorRuntime, S, Ed25519CryptoSpec>>();
    consensus::<TransactionSigningPayloadV0<VectorRuntime, S, EvmCryptoSpec>>();
    consensus::<TransactionSigningPayloadV1<VectorRuntime, S>>();
    consensus::<UniquenessData>();
    consensus::<RuntimeCommitment>();
}

#[cfg(feature = "native")]
mod native {
    use selendra_interface::crypto::PrivateKey;
    use selendra_primitives::crypto::{Ed25519PrivateKey, EthereumPrivateKey};

    use super::*;

    fn rfc8032_1() -> Ed25519PrivateKey {
        Ed25519PrivateKey::from_bytes(
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap()
                .try_into()
                .unwrap(),
        )
    }

    fn rfc8032_2() -> Ed25519PrivateKey {
        Ed25519PrivateKey::from_bytes(
            hex::decode("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
                .unwrap()
                .try_into()
                .unwrap(),
        )
    }

    fn secp_a() -> EthereumPrivateKey {
        EthereumPrivateKey::from_bytes(
            hex::decode("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap()
    }

    fn secp_1() -> EthereumPrivateKey {
        let mut one = [0; 32];
        one[31] = 1;
        EthereumPrivateKey::from_bytes(one).unwrap()
    }

    /// Signing produces exactly the vectors (both schemes sign deterministically).
    #[test]
    fn signing_produces_the_vectors() {
        let tx = v0_ed25519_unsigned()
            .sign::<Ed25519CryptoSpec>(&rfc8032_1(), CHAIN_ID, &SCHEMA_1)
            .unwrap();
        assert_eq!(
            hex::encode(borsh::to_vec(&tx).unwrap()),
            vectors::v0_ed25519::TX
        );

        let tx = v0_secp256k1_unsigned()
            .sign::<EvmCryptoSpec>(&secp_a(), CHAIN_ID, &SCHEMA_1)
            .unwrap();
        assert_eq!(
            hex::encode(borsh::to_vec(&tx).unwrap()),
            vectors::v0_secp256k1::TX
        );

        let keys = [
            rfc8032_1().pub_key(),
            rfc8032_2().pub_key(),
            parse(vectors::v1_ed25519::KEYS[2]),
        ];
        let mut tx = v1_ed25519_unsigned()
            .to_multisig_tx(Multisig::<Ed25519CryptoSpec>::new(2, keys.to_vec()).unwrap());
        tx.sign(&rfc8032_2(), CHAIN_ID, &SCHEMA_2).unwrap();
        tx.sign(&rfc8032_1(), CHAIN_ID, &SCHEMA_2).unwrap();
        assert_eq!(
            hex::encode(borsh::to_vec(&Ed::from(tx)).unwrap()),
            vectors::v1_ed25519::TX
        );

        let mut tx = v1_secp256k1_unsigned().to_multisig_tx(
            Multisig::<EvmCryptoSpec>::new(1, vec![secp_a().pub_key(), secp_1().pub_key()])
                .unwrap(),
        );
        tx.sign(&secp_1(), CHAIN_ID, &SCHEMA_2).unwrap();
        assert_eq!(
            hex::encode(borsh::to_vec(&Secp::from(tx)).unwrap()),
            vectors::v1_secp256k1::TX
        );
    }

    /// Upstream: `failed_first_signature_does_not_change_chain_hash_fragment` (no fragment
    /// here): a key outside the multisig cannot sign, and nothing changes.
    #[test]
    fn failed_signature_leaves_the_transaction_unchanged() {
        let member = Ed25519PrivateKey::generate();
        let non_member = Ed25519PrivateKey::generate();
        let mut tx = v1_ed25519_unsigned()
            .to_multisig_tx(Multisig::<Ed25519CryptoSpec>::new(1, vec![member.pub_key()]).unwrap());
        let before = tx.clone();
        assert_eq!(
            tx.sign(&non_member, CHAIN_ID, &SCHEMA_2),
            Err(TransactionError::Multisig(MultisigError::OutsiderSigner))
        );
        assert_eq!(tx, before);
        tx.sign(&member, CHAIN_ID, &SCHEMA_2).unwrap();
        let tx = Ed::from(tx);
        tx.verify_signature(&tx.signing_bytes(CHAIN_ID, &SCHEMA_2).unwrap())
            .unwrap();
    }

    /// Any sufficient subset of signers verifies, in any order.
    #[test]
    fn multisig_transactions_verify_for_any_sufficient_subset() {
        let keys: Vec<EthereumPrivateKey> =
            (0..4).map(|_| EthereumPrivateKey::generate()).collect();
        let multisig =
            Multisig::<EvmCryptoSpec>::new(2, keys.iter().map(PrivateKey::pub_key).collect())
                .unwrap();
        for signers in [[0, 1], [3, 1], [2, 0]] {
            let mut tx = v1_secp256k1_unsigned().to_multisig_tx(multisig.clone());
            for i in signers {
                tx.sign(&keys[i], CHAIN_ID, &SCHEMA_2).unwrap();
            }
            let tx = Secp::from(tx);
            tx.verify_signature(&tx.signing_bytes(CHAIN_ID, &SCHEMA_2).unwrap())
                .unwrap();
            // Not for another chain or schema.
            assert!(
                tx.verify_signature(&tx.signing_bytes(CHAIN_ID + 1, &SCHEMA_2).unwrap())
                    .is_err()
            );
            assert!(
                tx.verify_signature(&tx.signing_bytes(CHAIN_ID, &SCHEMA_1).unwrap())
                    .is_err()
            );
        }
    }
}
