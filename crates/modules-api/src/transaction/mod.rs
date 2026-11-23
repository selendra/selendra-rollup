//! Transaction data: a transaction's details ([`TxDetails`]), their authenticated form
//! ([`AuthenticatedTransactionData`]) and the priority fee ([`PriorityFeeBips`]).

mod data;

pub use data::{
    AuthenticatedTransactionData, PriorityFeeApplyOverflowError, PriorityFeeBips, TxDetails,
};
