//! Address decoders: bech32m `sel1…`, EIP-55 `0x…`, `MultiAddressEvm` in every encoding.
#![no_main]

use std::str::FromStr;

use libfuzzer_sys::fuzz_target;
use selendra_primitives::{Address, EthereumAddress, MultiAddressEvm};

/// borsh: decoding must not panic, and anything accepted must be its own canonical encoding.
fn borsh_canonical<T: borsh::BorshDeserialize + borsh::BorshSerialize>(data: &[u8]) {
    if let Ok(value) = borsh::from_slice::<T>(data) {
        assert_eq!(
            borsh::to_vec(&value).unwrap(),
            data,
            "non-canonical borsh accepted"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    borsh_canonical::<Address>(data);
    borsh_canonical::<EthereumAddress>(data);
    borsh_canonical::<MultiAddressEvm>(data);
    let _ = MultiAddressEvm::try_from(data);

    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(addr) = Address::from_str(s) {
        // Only the canonical string (case-insensitively) is accepted.
        assert_eq!(addr.to_string(), s.to_ascii_lowercase());
    }
    if let Ok(addr) = EthereumAddress::from_str(s) {
        assert_eq!(
            addr.to_string().to_ascii_lowercase(),
            s.to_ascii_lowercase()
        );
    }
    if let Ok(addr) = MultiAddressEvm::from_str(s) {
        assert_eq!(MultiAddressEvm::from_str(&addr.to_string()).unwrap(), addr);
    }
    let _ = selendra_primitives::bech32::decode::<32>("tok", s);
    let _ = serde_json::from_str::<MultiAddressEvm>(s);
    let _ = serde_json::from_str::<Address>(s);
    let _ = serde_json::from_str::<EthereumAddress>(s);
});
