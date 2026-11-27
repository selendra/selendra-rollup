//! Signing known-answer vectors for native transactions (`docs/serialization.md`, "Native
//! transactions"), for the SDKs (Phase 13).
//!
//! Computed independently of this crate: borsh written out by hand (`struct.pack`), SHA-256
//! from Python's `hashlib`, ed25519 signatures with RFC 8032's reference code, secp256k1
//! signatures with a pure-Python ECDSA (RFC 6979 nonces with HMAC-SHA256, over a pure-Python
//! keccak256, low-S), each implementation first checked against published vectors (RFC 8032
//! tests 1 and 2, keccak256 of "" and "abc", the RFC 6979 secp256k1 "Satoshi Nakamoto" vector).
//! Every signature was also reproduced with OpenSSL 3.5 (`pkeyutl -rawin` for ed25519;
//! `dgst -keccak-256`, then `pkeyutl` with `nonce-type:1` and `digest:sha256` for secp256k1).
//!
//! Keys: ed25519 RFC 8032 test 1 and test 2 secrets and the seed `[3; 32]`; secp256k1
//! `0x4c0883a6…3f362318` (whose address is `0x2c7536e3…96a65c23`) and `1`. Chain ID 1961. Calls
//! are [`super::VectorCall`]s.

/// V0, ed25519 (RFC 8032 test 1 key): `Data(b"selendra")`, `Nonce(5)`, 1% tip, max fee 1_000_000,
/// gas limit `[10_000, 20_000]`, runtime version 1 with the schema hash `0x00 01 … 1f`, no address
/// override.
pub(crate) mod v0_ed25519 {
    pub(crate) const PUB_KEY: &str =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    pub(crate) const COMMITMENT: &str =
        "898b8a52faf3f07978fb7a4aed043add96ab4678ee2c021e1abe29b0b4898346";
    pub(crate) const PAYLOAD: &str = "\
        00010800000073656c656e647261000500000000000000640000000000000040420f000000000000\
        00000000000000011027000000000000204e00000000000001000000d75a980182b10ab7d54bfed3\
        c964073a0ee172f3daa62325af021a68f707511a00898b8a52faf3f07978fb7a4aed043add96ab46\
        78ee2c021e1abe29b0b4898346";
    pub(crate) const PREHASH: &str =
        "7ea9e98a6d55392f96e7ad54b11d0b8868989d69a9b16d5bebfbf53a3475f7b3";
    pub(crate) const SIGNING_BYTES: &str = "\
        b553454c454e4452410101a9070000000000007ea9e98a6d55392f96e7ad54b11d0b8868989d69a9\
        b16d5bebfbf53a3475f7b3";
    pub(crate) const SIGNATURE: &str = "\
        d66f77b9d6242cba123abab44188dabf454c58f818b60ee9079366835f9d98089b68430d5f15cdc8\
        dd2159aa9c612be37f80392e594401c1a3aff4b9b0aefa0b";
    pub(crate) const TX: &str = "\
        00d66f77b9d6242cba123abab44188dabf454c58f818b60ee9079366835f9d98089b68430d5f15cd\
        c8dd2159aa9c612be37f80392e594401c1a3aff4b9b0aefa0bd75a980182b10ab7d54bfed3c96407\
        3a0ee172f3daa62325af021a68f707511a010800000073656c656e64726100050000000000000064\
        0000000000000040420f00000000000000000000000000011027000000000000204e000000000000\
        0100000000";
}

/// V0, secp256k1 (key `0x4c0883a6…`): `Ping(42)`, `Generation(3)`, no tip, max fee 5000, no gas
/// limit, runtime version 1 with the schema hash `0x00 01 … 1f`, address override `Vm(0x0102…14)`.
pub(crate) mod v0_secp256k1 {
    pub(crate) const PUB_KEY: &str =
        "024e3b81af9c2234cad09d679ce6035ed1392347ce64ce405f5dcd36228a25de6e";
    pub(crate) const ETH_ADDRESS: &str = "2c7536e3605d9c16a7a3d7b1898e529396a65c23";
    pub(crate) const COMMITMENT: &str =
        "898b8a52faf3f07978fb7a4aed043add96ab4678ee2c021e1abe29b0b4898346";
    pub(crate) const PAYLOAD: &str = "\
        00002a00000000000000010300000000000000000000000000000088130000000000000000000000\
        0000000001000000024e3b81af9c2234cad09d679ce6035ed1392347ce64ce405f5dcd36228a25de\
        6e01010102030405060708090a0b0c0d0e0f1011121314898b8a52faf3f07978fb7a4aed043add96\
        ab4678ee2c021e1abe29b0b4898346";
    pub(crate) const PREHASH: &str =
        "da337d55de713d196fa83b5a6f7ea407f3a02a45f74c8ae8917a3e7dff515ff0";
    pub(crate) const SIGNING_BYTES: &str = "\
        b553454c454e4452410101a907000000000000da337d55de713d196fa83b5a6f7ea407f3a02a45f7\
        4c8ae8917a3e7dff515ff0";
    pub(crate) const SIGNATURE: &str = "\
        441cb2b78cca7760c673a29e52a43ba3a2af92196c7cdf602a2de4750b826271599e9927312c6deb\
        5d7da66f3a075cfd80ffd256617f44b3f01da1d9d5976ddc";
    pub(crate) const TX: &str = "\
        00441cb2b78cca7760c673a29e52a43ba3a2af92196c7cdf602a2de4750b826271599e9927312c6d\
        eb5d7da66f3a075cfd80ffd256617f44b3f01da1d9d5976ddc024e3b81af9c2234cad09d679ce603\
        5ed1392347ce64ce405f5dcd36228a25de6e002a0000000000000001030000000000000000000000\
        0000000088130000000000000000000000000000000100000001010102030405060708090a0b0c0d\
        0e0f1011121314";
}

/// V1, ed25519: 2 of the three keys (RFC 8032 tests 1 and 2, seed `[3; 32]`), signed by test 2 then
/// test 1, the third unused: `Data(b"")`, `Window(9)`, 2.5% tip, max fee 77, no gas limit, runtime
/// version 2 with the schema hash `[0x22; 32]`, address override `Standard([0xab; 28])`.
pub(crate) mod v1_ed25519 {
    pub(crate) const KEYS: [&str; 3] = [
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1",
    ];
    pub(crate) const CREDENTIAL: &str =
        "e85a6e5db1067ab422bbb62307d7004e6de17d87d90f8fb2f755704090a7bca6";
    pub(crate) const COMMITMENT: &str =
        "43bffb8856145c5955773feabe77965ecda516450c7c26debed4959d9694b14a";
    pub(crate) const PAYLOAD: &str = "\
        010100000000020900000000000000fa000000000000004d00000000000000000000000000000000\
        0200000000e85a6e5db1067ab422bbb62307d7004e6de17d87d90f8fb2f75570400100ababababab\
        ababababababababababababababababababababababab43bffb8856145c5955773feabe77965ecd\
        a516450c7c26debed4959d9694b14a";
    pub(crate) const PREHASH: &str =
        "3d4e28f33632cca05fdefb166ce273f6640ada03a7eec5ee36ba131b721a33ce";
    pub(crate) const SIGNING_BYTES: &str = "\
        b553454c454e4452410101a9070000000000003d4e28f33632cca05fdefb166ce273f6640ada03a7\
        eec5ee36ba131b721a33ce";
    pub(crate) const SIGNATURE_2: &str = "\
        268db25b73ccef1b9f884bbab0c09a0eefce28c78293229b474712c4ad305774b276d9d9e37f5054\
        bd4386115ce64319925644e9431ac3d21b20fcbf12545d0f";
    pub(crate) const SIGNATURE_1: &str = "\
        7c3a595eba9710218bc657b84cfec04e80be19cdaa6ebcc2308127189a00b0c7ffa73802ab7dfbb8\
        ad0673ca141bce598552c309327d1a49b1b12d80d438a703";
    pub(crate) const TX: &str = "\
        0102000000268db25b73ccef1b9f884bbab0c09a0eefce28c78293229b474712c4ad305774b276d9\
        d9e37f5054bd4386115ce64319925644e9431ac3d21b20fcbf12545d0f3d4017c3e843895a92b70a\
        a74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c7c3a595eba9710218bc657b84cfec04e80be19\
        cdaa6ebcc2308127189a00b0c7ffa73802ab7dfbb8ad0673ca141bce598552c309327d1a49b1b12d\
        80d438a703d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a010000\
        00ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d102010000000002\
        0900000000000000fa000000000000004d00000000000000000000000000000000020000000100ab\
        ababababababababababababababababababababababababababab";
}

/// V1, secp256k1: 1 of the keys `0x4c0883a6…` and `1`, signed by `1`: `Ping(7)`, `Nonce(0)`, 0.01%
/// tip, max fee 1, gas limit `[1, 2]`, runtime version 2 with the schema hash `[0x22; 32]`, no
/// address override.
pub(crate) mod v1_secp256k1 {
    pub(crate) const KEYS: [&str; 2] = [
        "024e3b81af9c2234cad09d679ce6035ed1392347ce64ce405f5dcd36228a25de6e",
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    ];
    pub(crate) const CREDENTIAL: &str =
        "2df96dfd554b87493f3884d5308065d409ab3b76f40d8288dadb5677592202a2";
    pub(crate) const COMMITMENT: &str =
        "43bffb8856145c5955773feabe77965ecda516450c7c26debed4959d9694b14a";
    pub(crate) const PAYLOAD: &str = "\
        01000700000000000000000000000000000000010000000000000001000000000000000000000000\
        000000010100000000000000020000000000000002000000002df96dfd554b87493f3884d5308065\
        d409ab3b76f40d8288dadb56770043bffb8856145c5955773feabe77965ecda516450c7c26debed4\
        959d9694b14a";
    pub(crate) const PREHASH: &str =
        "0c31fe60b37bd04d1d8d3a45f2b4e7f84f55922d0ba8dc23ebd0e4fb80daa31b";
    pub(crate) const SIGNING_BYTES: &str = "\
        b553454c454e4452410101a9070000000000000c31fe60b37bd04d1d8d3a45f2b4e7f84f55922d0b\
        a8dc23ebd0e4fb80daa31b";
    pub(crate) const SIGNATURE: &str = "\
        0a9668588ebf1af06e6f1d9787b6af0b1a0a575005b02d54aa3361894fd9aec82c3ae8f741727fd8\
        dbf2f2474811caeab924e5acc7439afd4678ebef66147ba3";
    pub(crate) const TX: &str = "\
        01010000000a9668588ebf1af06e6f1d9787b6af0b1a0a575005b02d54aa3361894fd9aec82c3ae8\
        f741727fd8dbf2f2474811caeab924e5acc7439afd4678ebef66147ba30279be667ef9dcbbac55a0\
        6295ce870b07029bfcdb2dce28d959f2815b16f8179801000000024e3b81af9c2234cad09d679ce6\
        035ed1392347ce64ce405f5dcd36228a25de6e010007000000000000000000000000000000000100\
        00000000000001000000000000000000000000000000010100000000000000020000000000000002\
        00000000";
}
