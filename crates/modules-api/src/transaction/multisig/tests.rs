use selendra_primitives::crypto::{
    Ed25519CryptoSpec, Ed25519PublicKey, EthereumPublicKey, EvmCryptoSpec,
};

use super::*;

/// ed25519 public keys of the seeds `[i; 32]`, `i` = 1..=23 (computed independently: RFC 8032's
/// reference code in Python).
pub(crate) const ED25519_KEYS: [&str; 23] = [
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

pub(crate) fn ed25519_key(i: usize) -> Ed25519PublicKey {
    format!("0x{}", ED25519_KEYS[i]).parse().unwrap()
}

fn ed25519_keys(n: usize) -> Vec<Ed25519PublicKey> {
    (0..n).map(ed25519_key).collect()
}

// Regressions of upstream's multisig bugs

/// P5-34 (regression): upstream's `Multisig::new` accepted a threshold of 0, so a multisig with
/// no signature at all verified (anyone could act for its account).
#[test]
fn zero_threshold_multisig_rejected() {
    assert_eq!(
        Multisig::<Ed25519CryptoSpec>::new(0, ed25519_keys(3)),
        Err(MultisigError::ZeroThreshold)
    );
    assert_eq!(
        Multisig::<Ed25519CryptoSpec>::new(0, Vec::new()),
        Err(MultisigError::ZeroThreshold)
    );
    assert!(Multisig::<Ed25519CryptoSpec>::new(1, ed25519_keys(3)).is_ok());
}

/// P5-34 (regression): a threshold above the number of keys (no set of signatures meets it).
#[test]
fn threshold_above_keys_rejected() {
    assert_eq!(
        Multisig::<Ed25519CryptoSpec>::new(4, ed25519_keys(3)),
        Err(MultisigError::ThresholdAboveKeys {
            min_signers: 4,
            keys: 3
        })
    );
    assert_eq!(
        Multisig::<Ed25519CryptoSpec>::new(1, Vec::new()),
        Err(MultisigError::ThresholdAboveKeys {
            min_signers: 1,
            keys: 0
        })
    );
    let multisig = Multisig::<Ed25519CryptoSpec>::new(3, ed25519_keys(3)).unwrap();
    assert_eq!(multisig.min_signers(), 3);
}

/// P5-34 (regression): upstream capped signers and unused keys separately (21 each), so a
/// multisig had up to 42 keys. At most [`MAX_SIGNERS`] in all.
#[test]
fn too_many_keys_rejected() {
    assert_eq!(
        Multisig::<Ed25519CryptoSpec>::new(1, ed25519_keys(22)),
        Err(MultisigError::TooManyKeys { keys: 22 })
    );
    let multisig = Multisig::<Ed25519CryptoSpec>::new(21, ed25519_keys(21)).unwrap();
    assert_eq!(multisig.keys().len(), MAX_SIGNERS);
}

/// P5-34 (regression): upstream did not check keys for duplicates, so one key could count
/// twice towards a threshold set by its holder alone, and the same keys had several
/// credentials.
#[test]
fn duplicate_key_rejected() {
    let mut keys = ed25519_keys(3);
    keys.push(ed25519_key(1));
    assert_eq!(
        Multisig::<Ed25519CryptoSpec>::new(2, keys),
        Err(MultisigError::DuplicateKey)
    );
    assert_eq!(
        Multisig::<Ed25519CryptoSpec>::new(1, vec![ed25519_key(0), ed25519_key(0)]),
        Err(MultisigError::DuplicateKey)
    );
}

/// Known answers computed independently (`python3 -I`: `hashlib.sha256(b"SELENDRA/multisig/v1"
/// + scheme + min + struct.pack("<I", n) + b"".join(sorted(keys)))`).
#[test]
fn credential_id_known_answers() {
    let rfc8032_1: Ed25519PublicKey =
        "0xd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
            .parse()
            .unwrap();
    let rfc8032_2: Ed25519PublicKey =
        "0x3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
            .parse()
            .unwrap();
    let keys = vec![rfc8032_1.clone(), rfc8032_2.clone(), ed25519_key(2)];
    let multisig = Multisig::<Ed25519CryptoSpec>::new(2, keys).unwrap();
    assert_eq!(
        hex::encode(multisig.credential_id().as_bytes()),
        "e85a6e5db1067ab422bbb62307d7004e6de17d87d90f8fb2f755704090a7bca6"
    );
    // Sorted by their bytes.
    assert_eq!(multisig.keys(), [rfc8032_2, rfc8032_1, ed25519_key(2)]);

    let a: EthereumPublicKey =
        "0x024e3b81af9c2234cad09d679ce6035ed1392347ce64ce405f5dcd36228a25de6e"
            .parse()
            .unwrap();
    let b: EthereumPublicKey =
        "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            .parse()
            .unwrap();
    let multisig = Multisig::<EvmCryptoSpec>::new(1, vec![b, a]).unwrap();
    assert_eq!(
        hex::encode(multisig.credential_id().as_bytes()),
        "2df96dfd554b87493f3884d5308065d409ab3b76f40d8288dadb5677592202a2"
    );
}

/// A key's bytes (what the multisig sorts and hashes) are its borsh encoding, for both schemes.
#[test]
fn key_bytes_are_their_borsh_encoding() {
    let ed = ed25519_key(0);
    assert_eq!(borsh::to_vec(&ed).unwrap(), ed.as_ref());
    let secp: EthereumPublicKey =
        "0x024e3b81af9c2234cad09d679ce6035ed1392347ce64ce405f5dcd36228a25de6e"
            .parse()
            .unwrap();
    assert_eq!(borsh::to_vec(&secp).unwrap(), secp.as_ref());
}

/// The credential depends on the keys and the threshold, not on their order.
#[test]
fn credential_ignores_order_only() {
    let keys = ed25519_keys(5);
    let mut reversed = keys.clone();
    reversed.reverse();
    let first = Multisig::<Ed25519CryptoSpec>::new(3, keys.clone()).unwrap();
    let second = Multisig::<Ed25519CryptoSpec>::new(3, reversed).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.credential_id(), second.credential_id());
    let other_threshold = Multisig::<Ed25519CryptoSpec>::new(2, keys.clone()).unwrap();
    assert_ne!(first.credential_id(), other_threshold.credential_id());
    let fewer_keys = Multisig::<Ed25519CryptoSpec>::new(3, keys[..4].to_vec()).unwrap();
    assert_ne!(first.credential_id(), fewer_keys.credential_id());
    assert!(first.contains(&keys[4]));
    assert!(!first.contains(&ed25519_key(5)));
}

/// The structural checks of `verify`, before any signature is verified (the signatures here
/// are arbitrary valid encodings that would not verify).
#[test]
fn verify_checks_signers_before_signatures() {
    let multisig = Multisig::<Ed25519CryptoSpec>::new(2, ed25519_keys(3)).unwrap();
    let bytes = selendra_primitives::signing::signing_bytes(
        selendra_primitives::signing::SigningDomain::Transaction,
        1961,
        b"x",
    );
    let signature: <Ed25519CryptoSpec as selendra_interface::zk::CryptoSpec>::Signature =
        format!("0x{}", "00".repeat(64)).parse().unwrap();
    let by = |i| PubKeyAndSignature::<Ed25519CryptoSpec> {
        signature: signature.clone(),
        pub_key: ed25519_key(i),
    };
    assert_eq!(
        multisig.verify(&bytes, &[by(0), by(3)]),
        Err(MultisigError::OutsiderSigner)
    );
    assert_eq!(
        multisig.verify(&bytes, &[by(1), by(1)]),
        Err(MultisigError::DuplicateSigner)
    );
    assert_eq!(
        multisig.verify(&bytes, &[by(2)]),
        Err(MultisigError::NotEnoughSignatures {
            required: 2,
            got: 1
        })
    );
    assert!(matches!(
        multisig.verify(&bytes, &[by(2), by(0)]),
        Err(MultisigError::BadSignature { .. })
    ));
}

#[cfg(feature = "native")]
mod native {
    use selendra_interface::crypto::PrivateKey;
    use selendra_primitives::crypto::{Ed25519PrivateKey, EthereumPrivateKey};
    use selendra_primitives::signing::{SigningDomain, sign_signing_bytes, signing_bytes};

    use super::*;

    fn ed25519(i: u8) -> Ed25519PrivateKey {
        Ed25519PrivateKey::from_bytes([i; 32])
    }

    /// The private keys behind [`ED25519_KEYS`].
    #[test]
    fn ed25519_keys_are_the_seeds_keys() {
        for i in 0..ED25519_KEYS.len() {
            assert_eq!(
                ed25519(u8::try_from(i + 1).unwrap()).pub_key(),
                ed25519_key(i)
            );
        }
    }

    fn signed<C: TxCryptoSpec>(key: &C::PrivateKey, bytes: &SigningBytes) -> PubKeyAndSignature<C> {
        PubKeyAndSignature {
            signature: sign_signing_bytes(key, bytes),
            pub_key: key.pub_key(),
        }
    }

    /// P5-34 (regression): upstream's `verify_signature` built its set of allowed signers from
    /// the signatures themselves, so a valid signature by a key outside the multisig counted
    /// towards the threshold.
    #[test]
    fn outsider_signature_rejected() {
        let members: Vec<Ed25519PrivateKey> = (1..=3).map(ed25519).collect();
        let outsider = ed25519(4);
        let multisig = Multisig::<Ed25519CryptoSpec>::new(
            2,
            members.iter().map(PrivateKey::pub_key).collect(),
        )
        .unwrap();
        let bytes = signing_bytes(SigningDomain::Transaction, 1961, b"payload");
        let member = signed(&members[0], &bytes);
        let stranger = signed(&outsider, &bytes);
        // The outsider's signature is valid: only membership rejects it.
        verify_signing_bytes(&stranger.signature, &stranger.pub_key, &bytes).unwrap();
        assert_eq!(
            multisig.verify(&bytes, &[member.clone(), stranger.clone()]),
            Err(MultisigError::OutsiderSigner)
        );
        assert_eq!(
            multisig.verify(&bytes, &[stranger, member.clone()]),
            Err(MultisigError::OutsiderSigner)
        );
        // Accepted twin: two members.
        multisig
            .verify(&bytes, &[member, signed(&members[2], &bytes)])
            .unwrap();
    }

    #[test]
    fn verify_accepts_any_sufficient_subset_and_rejects_bad_signatures() {
        let members: Vec<EthereumPrivateKey> =
            (0..3).map(|_| EthereumPrivateKey::generate()).collect();
        let multisig =
            Multisig::<EvmCryptoSpec>::new(2, members.iter().map(PrivateKey::pub_key).collect())
                .unwrap();
        let bytes = signing_bytes(SigningDomain::Transaction, 1961, b"payload");
        let all: Vec<_> = members.iter().map(|key| signed(key, &bytes)).collect();
        for subset in [
            &all[..2],
            &all[1..],
            &[all[2].clone(), all[0].clone()][..],
            &all[..],
        ] {
            multisig.verify(&bytes, subset).unwrap();
        }
        // A signature over other bytes (another domain) fails the whole set.
        let other = signing_bytes(SigningDomain::OffchainMessage, 1961, b"payload");
        let wrong = signed(&members[2], &other);
        assert!(matches!(
            multisig.verify(&bytes, &[all[0].clone(), all[1].clone(), wrong]),
            Err(MultisigError::BadSignature { .. })
        ));
    }
}
