//! [`Context`]: who sent a transaction and who included it.

use selendra_interface::da::DaSpec;
use selendra_interface::stf::ExecutionContext;

use super::{Credential, Spec};
use crate::SequencerType;

/// The context a transaction's call runs in: its sender (the account, and the credential that
/// authenticated it), the sequencer that included it (on the rollup and on the DA layer), who
/// gets the gas refund, and where it runs (a node, or a sequencer before inclusion).
///
/// The credential is typed ([`Credential`]: an ed25519 or secp256k1 key, or a multisig), so
/// module code matches on its kind instead of guessing a type (upstream kept credentials in a
/// `TypeId` map behind `Rc`, which made `Context` neither `Send` nor `Sync`). `Context` is
/// `Send` and `Sync`.
///
/// It carries no sequencing data (upstream's `SequencingContext`, the preferred sequencer's
/// timestamps and payloads): that is the sequencer's, Phase 11.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context<S: Spec> {
    sender: S::Address,
    sender_credential: Credential,
    sequencer: S::Address,
    sequencer_da_address: <S::Da as DaSpec>::Address,
    gas_refund_recipient: S::Address,
    execution_context: ExecutionContext,
    sequencer_type: SequencerType,
}

impl<S: Spec> Context<S> {
    /// The context of a transaction from `sender`, authenticated by `sender_credential`,
    /// included by `sequencer` (`sequencer_da_address` on the DA layer, of kind
    /// `sequencer_type`). The sender gets the gas refund.
    pub fn new(
        sender: S::Address,
        sender_credential: Credential,
        sequencer: S::Address,
        sequencer_da_address: <S::Da as DaSpec>::Address,
        execution_context: ExecutionContext,
        sequencer_type: SequencerType,
    ) -> Self {
        Self::with_payer(
            sender,
            sender_credential,
            sequencer,
            sequencer_da_address,
            sender,
            execution_context,
            sequencer_type,
        )
    }

    /// Like [`new`](Self::new), but `payer` gets the gas refund.
    pub fn with_payer(
        sender: S::Address,
        sender_credential: Credential,
        sequencer: S::Address,
        sequencer_da_address: <S::Da as DaSpec>::Address,
        payer: S::Address,
        execution_context: ExecutionContext,
        sequencer_type: SequencerType,
    ) -> Self {
        Self {
            sender,
            sender_credential,
            sequencer,
            sequencer_da_address,
            gas_refund_recipient: payer,
            execution_context,
            sequencer_type,
        }
    }

    /// The account that sent the transaction.
    pub fn sender(&self) -> &S::Address {
        &self.sender
    }

    /// The credential that authenticated the transaction.
    pub fn sender_credential(&self) -> &Credential {
        &self.sender_credential
    }

    /// The rollup account of the sequencer that included the transaction.
    pub fn sequencer(&self) -> &S::Address {
        &self.sequencer
    }

    /// The DA-layer address of the sequencer that included the transaction.
    pub fn sequencer_da_address(&self) -> &<S::Da as DaSpec>::Address {
        &self.sequencer_da_address
    }

    /// The account that gets the transaction's gas refund.
    pub fn gas_refund_recipient(&self) -> &S::Address {
        &self.gas_refund_recipient
    }

    /// Makes `recipient` get the transaction's gas refund (e.g. a fee sponsor that paid).
    pub fn set_gas_refund_recipient(&mut self, recipient: S::Address) {
        self.gas_refund_recipient = recipient;
    }

    /// Where the transaction runs.
    pub fn execution_context(&self) -> ExecutionContext {
        self.execution_context
    }

    /// Whether the preferred sequencer included the transaction.
    pub fn sequencer_is_preferred(&self) -> bool {
        self.sequencer_type == SequencerType::Preferred
    }

    /// The kind of sequencer that included the transaction.
    pub fn sequencer_type(&self) -> SequencerType {
        self.sequencer_type
    }
}
