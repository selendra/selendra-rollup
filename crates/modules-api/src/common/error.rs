//! Module errors: structured details for clients ([`ErrorDetail`], [`ErrorContext`]), the
//! type-erased [`ModuleError`] and the module system's own [`CoreModuleError`].
//!
//! Nothing here panics: building a detail object that is not a JSON object is an error
//! ([`ErrorDetailError`]), not a panic. `ModuleError` has no borsh encoding yet (receipts,
//! Phase 10).

use std::fmt::{self, Debug, Display};
use std::sync::Arc;

use serde::de::Error as _;
use serde::ser::Error as _;
use serde::{Deserialize, Serialize};

/// A structured error detail: a JSON object with an error code and its parameters, e.g.
/// `{"error_code": "insufficient_balance", "amount": "100", "balance": "50"}`.
pub type ErrorContext = serde_json::Map<String, serde_json::Value>;

/// Why a value could not be turned into an [`ErrorContext`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ErrorDetailError {
    /// The value failed to serialize to JSON.
    #[error("failed to serialize the error detail: {0}")]
    Serialize(String),
    /// The value serialized to JSON, but not to an object.
    #[error("an error detail must be a JSON object, got {0}")]
    NotAnObject(&'static str),
}

/// Serializes `value` to JSON and returns it if it is an object.
///
/// P5-21: upstream panicked when the value was not a JSON object (and on a serialization
/// error); a module's error formatting could crash the node.
pub fn to_json_object<T: Serialize>(value: T) -> Result<ErrorContext, ErrorDetailError> {
    let value =
        serde_json::to_value(value).map_err(|e| ErrorDetailError::Serialize(e.to_string()))?;
    match value {
        serde_json::Value::Object(object) => Ok(object),
        serde_json::Value::Null => Err(ErrorDetailError::NotAnObject("null")),
        serde_json::Value::Bool(_) => Err(ErrorDetailError::NotAnObject("a boolean")),
        serde_json::Value::Number(_) => Err(ErrorDetailError::NotAnObject("a number")),
        serde_json::Value::String(_) => Err(ErrorDetailError::NotAnObject("a string")),
        serde_json::Value::Array(_) => Err(ErrorDetailError::NotAnObject("an array")),
    }
}

/// Builds an [`ErrorContext`] with `serde_json::json!` syntax: `Ok` if the JSON is an object,
/// `Err(`[`ErrorDetailError`]`)` otherwise (upstream panicked, P5-21).
///
/// ```
/// use selendra_modules_api::{ErrorDetailError, err_detail};
///
/// let amount = 100u64;
/// let detail = err_detail!({
///     "error_code": "insufficient_balance",
///     "amount": amount.to_string(),
/// })
/// .unwrap();
/// assert_eq!(detail["amount"], "100");
///
/// assert_eq!(err_detail!([1, 2]), Err(ErrorDetailError::NotAnObject("an array")));
/// ```
#[macro_export]
macro_rules! err_detail {
    ($($json:tt)+) => {
        $crate::to_json_object($crate::__private::serde_json::json!($($json)+))
    };
}

/// Structured error details for clients: what a module's `Error` type implements.
///
/// The JSON object goes into the `detail` field of error responses (simulation, receipts), so
/// it should carry an `error_code` and the values that caused the failure.
pub trait ErrorDetail: Debug + Display {
    /// The error as a JSON object.
    ///
    /// # Errors
    /// If the detail cannot be built (e.g. it serializes to something other than an object).
    fn error_detail(&self) -> Result<ErrorContext, Box<dyn std::error::Error + Send + Sync>>;
}

impl ErrorDetail for anyhow::Error {
    fn error_detail(&self) -> Result<ErrorContext, Box<dyn std::error::Error + Send + Sync>> {
        Ok(err_detail!({ "message": format!("{self}") })?)
    }
}

/// The module system's own errors.
#[derive(Debug, thiserror::Error)]
pub enum CoreModuleError {
    /// Any other error.
    #[error(transparent)]
    Generic(#[from] anyhow::Error),
    /// Reading the module's state failed (e.g. out of gas).
    #[error(transparent)]
    StateRead(Box<dyn std::error::Error + Send + Sync>),
    /// Writing the module's state failed (e.g. out of gas, a value too large).
    #[error(transparent)]
    StateWrite(Box<dyn std::error::Error + Send + Sync>),
}

impl CoreModuleError {
    /// A [`CoreModuleError::StateRead`].
    pub fn state_read<E: std::error::Error + Send + Sync + 'static>(err: E) -> Self {
        Self::StateRead(Box::new(err))
    }

    /// A [`CoreModuleError::StateWrite`].
    pub fn state_write<E: std::error::Error + Send + Sync + 'static>(err: E) -> Self {
        Self::StateWrite(Box::new(err))
    }

    fn code(&self) -> &'static str {
        match self {
            Self::Generic(_) => "generic",
            Self::StateRead(_) => "state_read",
            Self::StateWrite(_) => "state_write",
        }
    }
}

/// `{"error_code": "generic" | "state_read" | "state_write", "message": …}`.
impl Serialize for CoreModuleError {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("CoreModuleError", 2)?;
        state.serialize_field("error_code", self.code())?;
        state.serialize_field("message", &self.to_string())?;
        state.end()
    }
}

impl ErrorDetail for CoreModuleError {
    fn error_detail(&self) -> Result<ErrorContext, Box<dyn std::error::Error + Send + Sync>> {
        Ok(to_json_object(self)?)
    }
}

/// What a deserialized [`ModuleError`] holds: the JSON object, without its original type.
#[derive(Clone, Debug)]
struct DeserializedError {
    data: ErrorContext,
}

impl ErrorDetail for DeserializedError {
    fn error_detail(&self) -> Result<ErrorContext, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.data.clone())
    }
}

impl Display for DeserializedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match serde_json::to_string(&self.data) {
            Ok(json) => f.write_str(&json),
            Err(e) => write!(f, "<unprintable error detail: {e}>"),
        }
    }
}

/// A module error with its type erased: any [`ErrorDetail`] behind an `Arc` (cheap to clone,
/// `Send + Sync`).
///
/// Serde: the detail object (a JSON object in JSON; a string holding that JSON in binary
/// formats). Two errors are equal when they print the same.
#[derive(Debug, Clone)]
pub struct ModuleError(Arc<dyn ErrorDetail + Send + Sync>);

impl ModuleError {
    /// The wrapped error's [`ErrorDetail::error_detail`].
    ///
    /// # Errors
    /// If the wrapped error fails to build its detail.
    pub fn error_detail(&self) -> Result<ErrorContext, Box<dyn std::error::Error + Send + Sync>> {
        self.0.error_detail()
    }
}

impl Display for ModuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl PartialEq for ModuleError {
    fn eq(&self, other: &Self) -> bool {
        self.to_string() == other.to_string()
    }
}

impl Eq for ModuleError {}

impl<T: ErrorDetail + Send + Sync + 'static> From<T> for ModuleError {
    fn from(value: T) -> Self {
        Self(Arc::new(value))
    }
}

impl Serialize for ModuleError {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let detail = self.0.error_detail().map_err(S::Error::custom)?;
        if serializer.is_human_readable() {
            detail.serialize(serializer)
        } else {
            let json = serde_json::to_string(&detail).map_err(S::Error::custom)?;
            serializer.serialize_str(&json)
        }
    }
}

impl<'de> Deserialize<'de> for ModuleError {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let data: ErrorContext = if deserializer.is_human_readable() {
            Deserialize::deserialize(deserializer)?
        } else {
            let json = String::deserialize(deserializer)?;
            serde_json::from_str(&json).map_err(D::Error::custom)?
        };
        Ok(Self(Arc::new(DeserializedError { data })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_module_error_detail() {
        let error = CoreModuleError::state_write(std::io::Error::other("out of gas"));
        let detail = error.error_detail().unwrap();
        assert_eq!(detail["error_code"], "state_write");
        assert_eq!(detail["message"], "out of gas");

        let error = CoreModuleError::from(anyhow::anyhow!("bad"));
        assert_eq!(error.error_detail().unwrap()["error_code"], "generic");
        assert_eq!(
            CoreModuleError::state_read(std::io::Error::other("r"))
                .error_detail()
                .unwrap()["error_code"],
            "state_read"
        );
    }

    /// Serializes identically (as JSON, what clients get) after a round trip through a binary
    /// format (upstream: bincode; here postcard).
    #[test]
    fn module_error_serialization_binary() {
        let error = ModuleError::from(anyhow::anyhow!("test error"));
        let bytes = postcard::to_allocvec(&error).unwrap();
        let decoded: ModuleError = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(
            serde_json::to_string(&error).unwrap(),
            serde_json::to_string(&decoded).unwrap()
        );
    }

    #[test]
    fn module_error_serialization_json() {
        let error = ModuleError::from(anyhow::anyhow!("test error"));
        let json = serde_json::to_string(&error).unwrap();
        assert_eq!(json, r#"{"message":"test error"}"#);
        let decoded: ModuleError = serde_json::from_str(&json).unwrap();
        assert_eq!(json, serde_json::to_string(&decoded).unwrap());
        assert_eq!(decoded.to_string(), json);
        assert!(serde_json::from_str::<ModuleError>("[1]").is_err());
    }

    /// An error whose detail fails reports it (no panic) when serialized.
    #[test]
    fn failing_detail_is_a_serialization_error() {
        #[derive(Debug)]
        struct Broken;
        impl Display for Broken {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("broken")
            }
        }
        impl ErrorDetail for Broken {
            fn error_detail(
                &self,
            ) -> Result<ErrorContext, Box<dyn std::error::Error + Send + Sync>> {
                Ok(err_detail!([1])?)
            }
        }
        let error = ModuleError::from(Broken);
        assert!(error.error_detail().is_err());
        assert!(serde_json::to_string(&error).is_err());
        assert_eq!(error, ModuleError::from(Broken));
    }

    // Regressions of upstream's error-detail bugs

    /// P5-21 (regression): `to_json_object`/`err_detail!` panicked on a value that is not a
    /// JSON object.
    #[test]
    fn non_object_error_detail_is_err() {
        assert_eq!(
            to_json_object(1u8),
            Err(ErrorDetailError::NotAnObject("a number"))
        );
        assert_eq!(
            to_json_object("x"),
            Err(ErrorDetailError::NotAnObject("a string"))
        );
        assert_eq!(
            to_json_object(()),
            Err(ErrorDetailError::NotAnObject("null"))
        );
        assert_eq!(
            to_json_object(true),
            Err(ErrorDetailError::NotAnObject("a boolean"))
        );
        assert_eq!(
            to_json_object([1u8, 2]),
            Err(ErrorDetailError::NotAnObject("an array"))
        );
        assert_eq!(
            err_detail!("text"),
            Err(ErrorDetailError::NotAnObject("a string"))
        );
        assert_eq!(
            err_detail!(null),
            Err(ErrorDetailError::NotAnObject("null"))
        );

        // A map with non-string keys does not serialize to JSON at all.
        let map = std::collections::BTreeMap::from([(vec![1u8], 1u8)]);
        assert!(matches!(
            to_json_object(map),
            Err(ErrorDetailError::Serialize(_))
        ));

        let object = err_detail!({ "error_code": "x", "n": 1 }).unwrap();
        assert_eq!(object["error_code"], "x");
        assert_eq!(object["n"], 1);
    }
}
