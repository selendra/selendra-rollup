//! The [`Spec`] trait every module is generic over, and the chain's [`SelendraSpec`].

use core::fmt::{self, Debug};
use core::hash::Hash;
use core::marker::PhantomData;

use borsh::{BorshDeserialize, BorshSerialize};
use selendra_interface::common::ConsensusType;
use selendra_interface::da::DaSpec;
use selendra_interface::zk::{CryptoSpec, Zkvm};
use selendra_primitives::MultiAddressEvm;
use selendra_primitives::crypto::Ed25519CryptoSpec;
use selendra_state::{NomtVerifierStorage, StateHasher, StateStorageSpec, Storage};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

#[cfg(feature = "native")]
use crate::PrivateKeyExt;
use crate::module::gas_schedule::SELENDRA_GAS_SCHEDULE;
use crate::{
    AccountAddress, GAS_DIMENSIONS, Gas, GasSchedule, GasUnit, PublicKeyExt, SignatureExt,
};

/// A [`CryptoSpec`] whose keys and signatures the module system can carry ([`PublicKeyExt`],
/// [`SignatureExt`]; natively also `PrivateKeyExt`). Implemented for every such spec; generic
/// code gets the bounds on the associated types from it (upstream needed a helper trait for
/// that).
#[cfg(not(feature = "native"))]
pub trait CryptoSpecExt: CryptoSpec<PublicKey: PublicKeyExt, Signature: SignatureExt> {}

#[cfg(not(feature = "native"))]
impl<C: CryptoSpec<PublicKey: PublicKeyExt, Signature: SignatureExt>> CryptoSpecExt for C {}

/// A [`CryptoSpec`] whose keys and signatures the module system can carry ([`PublicKeyExt`],
/// [`SignatureExt`]; natively also [`PrivateKeyExt`]). Implemented for every such spec; generic
/// code gets the bounds on the associated types from it (upstream needed a helper trait for
/// that).
#[cfg(feature = "native")]
pub trait CryptoSpecExt:
    CryptoSpec<PublicKey: PublicKeyExt, Signature: SignatureExt, PrivateKey: PrivateKeyExt>
{
}

#[cfg(feature = "native")]
impl<C> CryptoSpecExt for C where
    C: CryptoSpec<PublicKey: PublicKeyExt, Signature: SignatureExt, PrivateKey: PrivateKeyExt>
{
}

/// The primitives a rollup is built from: its DA layer, gas, account addresses, state storage,
/// cryptography, zkVMs, and gas schedule. Every module is generic over it.
///
/// Its bounds do not depend on features (upstream required `NativeStorage` with `native`, and
/// gave its zk storage `unimplemented!()` native methods to fit): a spec over the guest's
/// storage is a spec in every build, and node code that needs more says so
/// (`where S::Storage: NativeStorage`).
///
/// The state and the crypto spec hash with the state hasher, SHA-256
/// (`selendra_state::StateHasher`): one hash function for the whole chain, and the one the SP1
/// guest accelerates. A spec over storage that hashes with anything else does not compile
/// (upstream's storage hasher was unbounded):
///
/// ```compile_fail,E0271
/// use selendra_modules_api::test_utils::{MockDaSpec, MockZkvm};
/// use selendra_modules_api::{SelendraSpec, Spec};
/// use selendra_state::{DefaultStorageSpec, NomtVerifierStorage};
///
/// fn spec<S: Spec>() {}
/// spec::<SelendraSpec<MockDaSpec, MockZkvm, MockZkvm, NomtVerifierStorage<DefaultStorageSpec<sha2::Sha512_256>>>>();
/// ```
///
/// ```
/// use selendra_modules_api::test_utils::{MockDaSpec, MockZkvm};
/// use selendra_modules_api::{SelendraSpec, Spec};
/// use selendra_state::{DefaultStorageSpec, NomtVerifierStorage, StateHasher};
///
/// fn spec<S: Spec>() {}
/// spec::<SelendraSpec<MockDaSpec, MockZkvm, MockZkvm, NomtVerifierStorage<DefaultStorageSpec<StateHasher>>>>();
/// ```
///
/// The bound is on the trait, not only on [`SelendraSpec`]: no other spec can pair the state
/// with another hasher either.
///
/// ```compile_fail,E0271
/// use selendra_modules_api::test_utils::{MockZkvm, TestSpec};
/// use selendra_modules_api::{GasSchedule, Spec};
/// use selendra_state::{DefaultStorageSpec, NomtVerifierStorage};
///
/// #[derive(Default, Debug, Clone, PartialEq, Eq)]
/// #[derive(borsh::BorshSerialize, borsh::BorshDeserialize, serde::Serialize, serde::Deserialize)]
/// struct OtherSpec;
///
/// impl Spec for OtherSpec {
///     type Storage = NomtVerifierStorage<DefaultStorageSpec<sha2::Sha512_256>>;
/// #   type Da = <TestSpec as Spec>::Da;
/// #   type Gas = <TestSpec as Spec>::Gas;
/// #   type Address = <TestSpec as Spec>::Address;
/// #   type CryptoSpec = <TestSpec as Spec>::CryptoSpec;
/// #   type InnerZkvm = MockZkvm;
/// #   type OuterZkvm = MockZkvm;
/// #   const GAS_SCHEDULE: GasSchedule<Self::Gas> = <TestSpec as Spec>::GAS_SCHEDULE;
///     // …
/// }
/// ```
///
/// ```
/// use selendra_modules_api::test_utils::{MockZkvm, TestSpec};
/// use selendra_modules_api::{GasSchedule, Spec};
/// use selendra_state::{DefaultStorageSpec, NomtVerifierStorage, StateHasher};
///
/// #[derive(Default, Debug, Clone, PartialEq, Eq)]
/// #[derive(borsh::BorshSerialize, borsh::BorshDeserialize, serde::Serialize, serde::Deserialize)]
/// struct OtherSpec;
///
/// impl Spec for OtherSpec {
///     type Storage = NomtVerifierStorage<DefaultStorageSpec<StateHasher>>;
/// #   type Da = <TestSpec as Spec>::Da;
/// #   type Gas = <TestSpec as Spec>::Gas;
/// #   type Address = <TestSpec as Spec>::Address;
/// #   type CryptoSpec = <TestSpec as Spec>::CryptoSpec;
/// #   type InnerZkvm = MockZkvm;
/// #   type OuterZkvm = MockZkvm;
/// #   const GAS_SCHEDULE: GasSchedule<Self::Gas> = <TestSpec as Spec>::GAS_SCHEDULE;
///     // …
/// }
/// ```
pub trait Spec:
    BorshSerialize
    + BorshDeserialize
    + Serialize
    + DeserializeOwned
    + Default
    + Debug
    + Clone
    + PartialEq
    + Eq
    + Send
    + Sync
    + 'static
{
    /// The DA layer.
    type Da: DaSpec;

    /// Gas (for Selendra, [`GasUnit<2>`](GasUnit)).
    type Gas: Gas;

    /// Account addresses. Derived from the signer's key by kind
    /// ([`AccountAddress::default_for`]), never from a bare `CredentialId` (upstream's
    /// `From<CredentialId>` bound gave Ethereum keys `sel1…` accounts; P5-08).
    ///
    /// Addresses must be fixed-width, not user-chosen byte strings: their text forms appear in
    /// state paths and APIs.
    type Address: AccountAddress + ConsensusType + Sync;

    /// The state storage, hashing with the state hasher.
    type Storage: Storage<Hasher = StateHasher> + Send + Sync + 'static;

    /// The signature schemes, hashing with the state hasher.
    type CryptoSpec: CryptoSpecExt<Hasher = StateHasher>;

    /// The zkVM proving each slot (the inner circuit).
    type InnerZkvm: Zkvm;

    /// The zkVM proving the chain since genesis (the outer, aggregation circuit).
    type OuterZkvm: Zkvm;

    /// The gas cost of each metered operation.
    const GAS_SCHEDULE: GasSchedule<Self::Gas>;
}

/// Selendra's [`Spec`]: generic over the DA layer, the zkVMs and the state storage.
///
/// - `Gas = GasUnit<2>`, `Address = MultiAddressEvm` (`sel1…` and `0x…` accounts),
///   `CryptoSpec = Ed25519CryptoSpec` whatever the zkVM (upstream took the zkVM verifier's
///   crypto spec), `GAS_SCHEDULE = SELENDRA_GAS_SCHEDULE`.
/// - `St`, the storage, defaults to the zk guest's `NomtVerifierStorage<StateStorageSpec>`; the
///   node uses its NOMT prover storage (Phase 8/10), tests `selendra-state`'s `TestStorage`
///   (`test_utils::TestSpec`).
///
/// M1 runs on `SelendraSpec<MockDaSpec, MockZkvm, MockZkvm>`; the Avail and SP1 instance is
/// Phase 9.
///
/// It holds nothing: borsh encodes it as no bytes, serde as a unit struct (JSON `null`).
pub struct SelendraSpec<Da, InnerZkvm, OuterZkvm, St = NomtVerifierStorage<StateStorageSpec>>(
    Marker<(Da, InnerZkvm, OuterZkvm, St)>,
);

/// Holds no value of `T`: the spec is `Send` and `Sync` whatever its parameters.
type Marker<T> = PhantomData<fn() -> T>;

impl<Da, InnerZkvm, OuterZkvm, St> Spec for SelendraSpec<Da, InnerZkvm, OuterZkvm, St>
where
    Da: DaSpec,
    InnerZkvm: Zkvm,
    OuterZkvm: Zkvm,
    St: Storage<Hasher = StateHasher> + Send + Sync + 'static,
{
    type Da = Da;
    type Gas = GasUnit<GAS_DIMENSIONS>;
    type Address = MultiAddressEvm;
    type Storage = St;
    type CryptoSpec = Ed25519CryptoSpec;
    type InnerZkvm = InnerZkvm;
    type OuterZkvm = OuterZkvm;

    const GAS_SCHEDULE: GasSchedule<Self::Gas> = SELENDRA_GAS_SCHEDULE;
}

// The impls below hold for every parameter: the spec is a marker and stores nothing.

impl<Da, I, O, St> SelendraSpec<Da, I, O, St> {
    /// The spec (it holds nothing).
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<Da, I, O, St> Default for SelendraSpec<Da, I, O, St> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Da, I, O, St> Clone for SelendraSpec<Da, I, O, St> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Da, I, O, St> Copy for SelendraSpec<Da, I, O, St> {}

impl<Da, I, O, St> PartialEq for SelendraSpec<Da, I, O, St> {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl<Da, I, O, St> Eq for SelendraSpec<Da, I, O, St> {}

impl<Da, I, O, St> Hash for SelendraSpec<Da, I, O, St> {
    fn hash<H: core::hash::Hasher>(&self, _state: &mut H) {}
}

impl<Da, I, O, St> Debug for SelendraSpec<Da, I, O, St> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SelendraSpec<{}>",
            core::any::type_name::<(Da, I, O, St)>()
        )
    }
}

impl<Da, I, O, St> BorshSerialize for SelendraSpec<Da, I, O, St> {
    fn serialize<W: borsh::io::Write>(&self, _writer: &mut W) -> borsh::io::Result<()> {
        Ok(())
    }
}

impl<Da, I, O, St> BorshDeserialize for SelendraSpec<Da, I, O, St> {
    fn deserialize_reader<R: borsh::io::Read>(_reader: &mut R) -> borsh::io::Result<Self> {
        Ok(Self::new())
    }
}

/// No bytes on any target.
impl<Da, I, O, St> ConsensusType for SelendraSpec<Da, I, O, St> {}

impl<Da, I, O, St> Serialize for SelendraSpec<Da, I, O, St> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_unit_struct("SelendraSpec")
    }
}

impl<'de, Da, I, O, St> Deserialize<'de> for SelendraSpec<Da, I, O, St> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UnitVisitor;

        impl serde::de::Visitor<'_> for UnitVisitor {
            type Value = ();

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a unit struct")
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<(), E> {
                Ok(())
            }
        }

        deserializer.deserialize_unit_struct("SelendraSpec", UnitVisitor)?;
        Ok(Self::new())
    }
}

impl<Da, I, O, St> schemars::JsonSchema for SelendraSpec<Da, I, O, St> {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "SelendraSpec".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({ "type": "null" })
    }
}

/// Types generic over a spec can derive `Arbitrary` (the derives bound the parameter).
#[cfg(feature = "arbitrary")]
impl<'a, Da, I, O, St> arbitrary::Arbitrary<'a> for SelendraSpec<Da, I, O, St> {
    fn arbitrary(_u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::new())
    }
}

#[cfg(feature = "arbitrary")]
impl<Da, I, O, St> proptest::arbitrary::Arbitrary for SelendraSpec<Da, I, O, St> {
    type Parameters = ();
    type Strategy = proptest::strategy::Just<Self>;

    fn arbitrary_with((): ()) -> Self::Strategy {
        proptest::strategy::Just(Self::new())
    }
}

#[cfg(test)]
mod tests {
    use selendra_interface::zk::CryptoSpec;
    use selendra_state::test_storage::TestStorage;

    use super::*;
    use crate::test_utils::{MockDaSpec, MockZkvm, TestGuestSpec, TestSpec};

    fn spec<S: Spec>() {}
    fn same<T>(_: PhantomData<T>, _: PhantomData<T>) {}

    /// The spec's storage and crypto spec hash with the state hasher (checked at compile time).
    #[test]
    fn spec_hashers_are_the_state_hasher() {
        same(
            PhantomData::<<<TestSpec as Spec>::CryptoSpec as CryptoSpec>::Hasher>,
            PhantomData::<StateHasher>,
        );
        same(
            PhantomData::<<<TestSpec as Spec>::Storage as Storage>::Hasher>,
            PhantomData::<StateHasher>,
        );
        same(
            PhantomData::<<<TestGuestSpec as Spec>::Storage as Storage>::Hasher>,
            PhantomData::<StateHasher>,
        );
        same(
            PhantomData::<<TestSpec as Spec>::CryptoSpec>,
            PhantomData::<Ed25519CryptoSpec>,
        );
    }

    /// The storage the `compile_fail,E0271` doctests on [`Spec`] reject is a valid `Storage`:
    /// only the hasher bound rejects it.
    #[test]
    fn other_hasher_storage_is_a_storage() {
        fn storage<St: Storage + Send + Sync + 'static>() {}
        storage::<NomtVerifierStorage<selendra_state::DefaultStorageSpec<sha2::Sha512_256>>>();
    }

    #[test]
    fn selendra_spec_encodes_to_nothing() {
        let spec = TestSpec::default();
        assert_eq!(borsh::to_vec(&spec).unwrap(), Vec::<u8>::new());
        assert_eq!(borsh::from_slice::<TestSpec>(&[]).unwrap(), spec);
        assert!(borsh::from_slice::<TestSpec>(&[0]).is_err());
        assert_eq!(serde_json::to_string(&spec).unwrap(), "null");
        assert_eq!(serde_json::from_str::<TestSpec>("null").unwrap(), spec);
        assert!(serde_json::from_str::<TestSpec>("{}").is_err());
        assert!(postcard::to_allocvec(&spec).unwrap().is_empty());
        assert!(format!("{spec:?}").starts_with("SelendraSpec<"));
    }

    // Regressions of upstream's `Spec` bound bugs

    /// P5-24 (regression): upstream's `Spec` bounds were cfg-switched (`NativeStorage` with
    /// `native`). Both storages make a spec in every build (`make test` runs with
    /// `--all-features`, `make guest` with none): the bounds do not depend on features.
    #[test]
    fn verifier_storage_spec_is_a_spec() {
        spec::<SelendraSpec<MockDaSpec, MockZkvm, MockZkvm, TestStorage>>();
        spec::<SelendraSpec<MockDaSpec, MockZkvm, MockZkvm, NomtVerifierStorage<StateStorageSpec>>>(
        );
        spec::<SelendraSpec<MockDaSpec, MockZkvm, MockZkvm>>();
        spec::<TestSpec>();
        spec::<TestGuestSpec>();
    }

    /// P5-24 (regression): upstream's storage hasher was unbounded. Code generic over any
    /// `S: Spec` gets the state hasher for the storage and the crypto spec from the trait's
    /// bounds alone (this does not compile without them; the concrete checks above would).
    #[test]
    fn spec_bounds_pin_the_state_hasher() {
        fn hashers<S: Spec>() {
            same(
                PhantomData::<<S::Storage as Storage>::Hasher>,
                PhantomData::<StateHasher>,
            );
            same(
                PhantomData::<<S::CryptoSpec as CryptoSpec>::Hasher>,
                PhantomData::<StateHasher>,
            );
        }
        hashers::<TestSpec>();
        hashers::<TestGuestSpec>();
    }
}
