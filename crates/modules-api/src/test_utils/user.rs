//! [`TestUser`]: a key that signs native transactions, and the account it owns.

use selendra_interface::crypto::PrivateKey;
use selendra_interface::stf::FullyBakedTx;

use crate::authenticator::{AuthenticatorInput, EncodeTransactionError};
use crate::transaction::{
    SchemaHash, Transaction, TransactionCallable, TransactionError, TxCryptoSpec,
    UnsignedTransaction,
};
use crate::{AccountAddress, Credential, Spec};

/// A user of a test: a private key of the scheme `C` (ed25519 or secp256k1), the credential and
/// the account it owns, and its transactions, signed and wrapped in their envelope. Node only
/// (`native`: private keys).
///
/// Its address is the one the authenticator gives its transactions
/// ([`AccountAddress::default_for`] of its credential): an EVM key's is its `0x…` account
/// (`Vm`), never a `sel1…` one (upstream's test users took `credential_id.into()`; P5-08).
#[derive(Debug, Clone)]
pub struct TestUser<C: TxCryptoSpec> {
    private_key: C::PrivateKey,
}

impl<C: TxCryptoSpec> TestUser<C> {
    /// The user of `private_key`.
    pub const fn new(private_key: C::PrivateKey) -> Self {
        Self { private_key }
    }

    /// The private key.
    pub const fn private_key(&self) -> &C::PrivateKey {
        &self.private_key
    }

    /// The public key.
    pub fn pub_key(&self) -> C::PublicKey {
        self.private_key.pub_key()
    }

    /// The credential its transactions are authenticated with.
    pub fn credential(&self) -> Credential {
        C::credential(&self.pub_key())
    }

    /// The account it owns on a spec `S`, the sender of its transactions when they have no
    /// address override.
    pub fn address<S: Spec>(&self) -> S::Address {
        S::Address::default_for(&self.credential())
    }

    /// `unsigned` signed by the user (a V0 transaction) on `chain_id`, for the runtime version
    /// it names with `schema_hash`.
    ///
    /// # Errors
    /// The payload does not encode.
    pub fn sign<R: TransactionCallable, S: Spec>(
        &self,
        unsigned: UnsignedTransaction<R, S>,
        chain_id: u64,
        schema_hash: &SchemaHash,
    ) -> Result<Transaction<R, S, C>, TransactionError> {
        unsigned.sign::<C>(&self.private_key, chain_id, schema_hash)
    }

    /// `tx` in its envelope (the tag of its scheme), as the authenticator receives it.
    ///
    /// # Errors
    /// The transaction is too large for an envelope.
    pub fn bake<R: TransactionCallable, S: Spec>(
        tx: &Transaction<R, S, C>,
    ) -> Result<FullyBakedTx, EncodeTransactionError> {
        Ok(AuthenticatorInput::from_transaction(tx)?.to_fully_baked_tx())
    }
}
