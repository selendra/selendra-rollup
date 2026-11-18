//! [`ModuleId`]: a module's 32-byte identity.

use selendra_interface::reexports::digest::Digest;
use selendra_state::StateHasher;

crate::hash32_id! {
    /// A module's identity: 32 bytes, shown as bech32m with the `module_` prefix
    /// (`module_1…`). Module-owned accounts are derived from it.
    ///
    /// [`ModuleId::from_name`] derives it from the module's stable name only, so moving or
    /// renaming the Rust type does not change it (upstream hashed `module_path!()` and the
    /// struct name: a refactor was a fork; the derive uses this from S8 of Phase 5).
    pub struct ModuleId, prefix = "module_"
}

impl ModuleId {
    /// The domain tag of [`ModuleId::from_name`].
    pub const DOMAIN: &'static [u8] = b"SELENDRA/module-id/v1";

    /// The id of the module named `name`: `SHA-256("SELENDRA/module-id/v1" ‖ name)`, hashed with
    /// the state hasher (`selendra_state::StateHasher`) on every build, the zk guest's included.
    ///
    /// Module names are `^[a-z][a-z0-9_]{0,31}$` (checked by the module derive), so the tag and
    /// the name cannot be split another way.
    pub fn from_name(name: &str) -> Self {
        let mut hasher = StateHasher::new();
        hasher.update(Self::DOMAIN);
        hasher.update(name.as_bytes());
        Self::new(hasher.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known answers computed independently (Python's `hashlib.sha256`, BIP-350 bech32m).
    #[test]
    fn module_id_known_answer() {
        let bank = ModuleId::from_name("bank");
        assert_eq!(
            bank.as_bytes(),
            &[
                0xbf, 0x1a, 0x20, 0xf3, 0x13, 0xb3, 0xbc, 0x11, 0x18, 0xf9, 0x26, 0x4f, 0xdd, 0xd1,
                0x0f, 0x79, 0x3c, 0x65, 0xb7, 0x8e, 0x48, 0xe8, 0xdc, 0x73, 0x21, 0x64, 0xed, 0x77,
                0x0e, 0xce, 0xeb, 0xfd
            ]
        );
        assert_eq!(
            bank.to_string(),
            "module_1hudzpucnkw7pzx8eye8am5g00y7xtduwfr5dcuepvnkhwrkwa07shpzs2t"
        );
        assert_eq!(
            ModuleId::from_name("").as_bytes(),
            &[
                0x85, 0x6a, 0x65, 0x4b, 0xb0, 0xbf, 0x17, 0xab, 0x86, 0xb0, 0x2f, 0x83, 0x65, 0xd5,
                0x67, 0xff, 0x3c, 0xfe, 0x86, 0xa0, 0x4d, 0x46, 0x3a, 0xc5, 0xa7, 0xa7, 0x66, 0x52,
                0x38, 0xa9, 0xba, 0x50
            ]
        );
    }
}
