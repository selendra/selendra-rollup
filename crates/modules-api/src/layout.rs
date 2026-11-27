//! A runtime's layout: the rules between its modules ([`check_layout`]), checked at compile
//! time wherever the runtime is used, by its genesis, and by the node at startup
//! ([`DispatchCall`](crate::DispatchCall)'s layout check).

use std::fmt;

use crate::{ErrorContext, ErrorDetail, ModuleDescriptor, ModuleKey, err_detail};

/// Why a runtime's modules break the layout rules (the first broken rule, in the order of the
/// modules).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutError {
    /// A module has the reserved discriminant `0`.
    ReservedDiscriminant {
        /// The module.
        module: ModuleKey,
    },
    /// Two modules have the same discriminant.
    DuplicateDiscriminant {
        /// The module listed first.
        first: ModuleKey,
        /// The module listed later.
        second: ModuleKey,
    },
    /// Two modules have the same name.
    DuplicateName {
        /// The module listed first.
        first: ModuleKey,
        /// The module listed later.
        second: ModuleKey,
    },
    /// A module depends on a module that has neither the discriminant nor the name of any
    /// module of the runtime.
    DependencyNotInRuntime {
        /// The dependent module.
        module: ModuleKey,
        /// The dependency.
        dependency: ModuleKey,
    },
    /// A module depends on a module whose discriminant or name is that of a module of the
    /// runtime, but not both.
    DependencyMismatch {
        /// The dependent module.
        module: ModuleKey,
        /// The dependency.
        dependency: ModuleKey,
        /// The runtime's module with the dependency's discriminant (or, if none, its name).
        runtime_module: ModuleKey,
    },
}

/// Checks the layout rules on a runtime's `modules`. A `const fn`: the runtime derives evaluate
/// it at compile time ([`DispatchCall`](crate::DispatchCall)'s layout check), genesis and the
/// node at run time.
///
/// Modules are numbered once ([`ModuleInfo::DISCRIMINANT`](crate::ModuleInfo::DISCRIMINANT):
/// the first byte of their state prefixes, the tag of their calls and events) and named once
/// ([`ModuleInfo::NAME`](crate::ModuleInfo::NAME)). Within a runtime:
/// - no module has the reserved discriminant `0`;
/// - no two modules have the same discriminant, nor the same name (they would write under the
///   same prefixes, or a call would decode for the first of them only);
/// - each module's dependencies ([`ModuleInfo::DEPENDENCIES`](crate::ModuleInfo::DEPENDENCIES):
///   the modules it holds and calls) are modules of the runtime, with exactly that
///   discriminant and name. A held module is built with its own discriminant, so it writes
///   under the prefixes of the runtime module with that discriminant; one with a discriminant
///   that no module of the runtime has, or that another module has, would write under prefixes
///   nothing else checks.
///
/// Only the `(discriminant, name)` pairs are compared, not the module types: a dependency is
/// taken to be the runtime's module with its pair. When it is (the same type), its own
/// dependencies are checked as that module's, so by induction the whole closure is. A
/// different type that declares another module's pair (two semver-incompatible versions of
/// one module crate, or a copy) is not detected: it shares that module's prefixes with its own
/// item layout, and its own dependencies are never checked. Closing this is a Phase 6 TODO item
/// (module identity in the layout check).
///
/// Upstream checked only that the runtime's direct modules had distinct discriminants, at
/// genesis (never again after an upgrade), and not the modules they hold (P5-25).
///
/// ```
/// use selendra_modules_api::{LayoutError, ModuleDescriptor, ModuleKey, check_layout};
///
/// const BANK: ModuleDescriptor = ModuleDescriptor::new(1, "bank", &[]);
/// const ACCOUNTS: ModuleDescriptor = ModuleDescriptor::new(2, "accounts", &[(1, "bank")]);
/// assert_eq!(check_layout(&[BANK, ACCOUNTS]), Ok(()));
///
/// // Evaluated at compile time:
/// const _: () = assert!(check_layout(&[BANK, ACCOUNTS]).is_ok());
///
/// let other_bank = ModuleDescriptor::new(1, "other_bank", &[]);
/// assert_eq!(
///     check_layout(&[BANK, other_bank]),
///     Err(LayoutError::DuplicateDiscriminant {
///         first: ModuleKey { discriminant: 1, name: "bank" },
///         second: ModuleKey { discriminant: 1, name: "other_bank" },
///     })
/// );
/// ```
///
/// # Errors
/// The first rule broken, in the order of `modules`: for each module, its discriminant (`0`),
/// then whether an earlier module has its discriminant, then its name; then each module's
/// dependencies, in order.
pub const fn check_layout(modules: &[ModuleDescriptor]) -> Result<(), LayoutError> {
    let mut i = 0;
    while i < modules.len() {
        let module = modules[i].key();
        if module.discriminant == 0 {
            return Err(LayoutError::ReservedDiscriminant { module });
        }
        let mut j = 0;
        while j < i {
            let first = modules[j].key();
            if first.discriminant == module.discriminant {
                return Err(LayoutError::DuplicateDiscriminant {
                    first,
                    second: module,
                });
            }
            if str_eq(first.name, module.name) {
                return Err(LayoutError::DuplicateName {
                    first,
                    second: module,
                });
            }
            j += 1;
        }
        i += 1;
    }

    let mut i = 0;
    while i < modules.len() {
        let module = modules[i].key();
        let dependencies = modules[i].dependencies();
        let mut d = 0;
        while d < dependencies.len() {
            let (discriminant, name) = dependencies[d];
            let dependency = ModuleKey { discriminant, name };
            // The runtime's module with that discriminant, or else with that name.
            let mut by_discriminant = None;
            let mut by_name = None;
            let mut j = 0;
            while j < modules.len() {
                let candidate = modules[j].key();
                if candidate.discriminant == discriminant {
                    by_discriminant = Some(candidate);
                }
                if str_eq(candidate.name, name) {
                    by_name = Some(candidate);
                }
                j += 1;
            }
            let runtime_module = match (by_discriminant, by_name) {
                (Some(found), _) | (None, Some(found)) => found,
                (None, None) => {
                    return Err(LayoutError::DependencyNotInRuntime { module, dependency });
                }
            };
            if runtime_module.discriminant != discriminant || !str_eq(runtime_module.name, name) {
                return Err(LayoutError::DependencyMismatch {
                    module,
                    dependency,
                    runtime_module,
                });
            }
            d += 1;
        }
        i += 1;
    }
    Ok(())
}

/// [`check_layout`], panicking with the error's message: the runtime derives' compile-time
/// check (a panic in const evaluation is a compile error, E0080, with this message), through
/// [`DispatchCall`](crate::DispatchCall)'s hidden `__CHECK_LAYOUT`.
pub(crate) const fn assert_layout(modules: &[ModuleDescriptor]) {
    if let Err(error) = check_layout(modules) {
        let mut message = Message::new();
        message.push("invalid runtime layout: ");
        error.write(&mut message);
        panic!("{}", message.as_str());
    }
}

impl LayoutError {
    /// Writes the error's message (also its `Display`), in a `const fn`, so the compile-time
    /// check reports the same text.
    const fn write(&self, message: &mut Message) {
        match *self {
            Self::ReservedDiscriminant { module } => {
                message.push("module ");
                message.key(module);
                message.push(" has the discriminant 0, which is reserved");
            }
            Self::DuplicateDiscriminant { first, second } => {
                message.push("modules ");
                message.key(first);
                message.push(" and ");
                message.key(second);
                message.push(" have the same discriminant");
            }
            Self::DuplicateName { first, second } => {
                message.push("modules ");
                message.key(first);
                message.push(" and ");
                message.key(second);
                message.push(" have the same name");
            }
            Self::DependencyNotInRuntime { module, dependency } => {
                message.push("module ");
                message.key(module);
                message.push(" depends on ");
                message.key(dependency);
                message.push(", which is not a module of the runtime");
            }
            Self::DependencyMismatch {
                module,
                dependency,
                runtime_module,
            } => {
                message.push("module ");
                message.key(module);
                message.push(" depends on ");
                message.key(dependency);
                message.push(", but the runtime's module is ");
                message.key(runtime_module);
            }
        }
    }
}

impl fmt::Display for LayoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut message = Message::new();
        self.write(&mut message);
        f.write_str(message.as_str())
    }
}

impl std::error::Error for LayoutError {}

/// `{"error_code": "invalid_runtime_layout", "message": …}`, so genesis can return it as a
/// [`ModuleError`](crate::ModuleError).
impl ErrorDetail for LayoutError {
    fn error_detail(&self) -> Result<ErrorContext, Box<dyn std::error::Error + Send + Sync>> {
        Ok(err_detail!({
            "error_code": "invalid_runtime_layout",
            "message": self.to_string(),
        })?)
    }
}

/// Whether two strings are equal, in a `const fn`.
const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// A message built in a `const fn`: at most [`Message::CAPACITY`] bytes, every piece that does
/// not fit whole replaced by `…` (so the text is always valid UTF-8).
struct Message {
    bytes: [u8; Message::CAPACITY],
    len: usize,
}

impl Message {
    /// Room for the longest message with names of up to 64 bytes.
    const CAPACITY: usize = 320;
    const ELLIPSIS: &'static str = "…";

    const fn new() -> Self {
        Self {
            bytes: [0; Self::CAPACITY],
            len: 0,
        }
    }

    /// Appends `piece`, or `…` if it does not fit (and nothing if that does not fit either).
    const fn push(&mut self, piece: &str) {
        let piece = if piece.len() + Self::ELLIPSIS.len() <= Self::CAPACITY - self.len {
            piece
        } else {
            Self::ELLIPSIS
        };
        let piece = piece.as_bytes();
        if piece.len() > Self::CAPACITY - self.len {
            return;
        }
        let mut i = 0;
        while i < piece.len() {
            self.bytes[self.len + i] = piece[i];
            i += 1;
        }
        self.len += piece.len();
    }

    /// Appends `` `name` (discriminant) ``.
    const fn key(&mut self, key: ModuleKey) {
        self.push("`");
        self.push(key.name);
        self.push("` (");
        let mut digits = [0u8; 3];
        let mut n = key.discriminant;
        let mut count = 0;
        loop {
            digits[2 - count] = b'0' + n % 10;
            count += 1;
            n /= 10;
            if n == 0 {
                break;
            }
        }
        let (_, digits) = digits.split_at(3 - count);
        match core::str::from_utf8(digits) {
            Ok(digits) => self.push(digits),
            Err(_) => self.push("?"),
        }
        self.push(")");
    }

    const fn as_str(&self) -> &str {
        let (text, _) = self.bytes.split_at(self.len);
        match core::str::from_utf8(text) {
            Ok(text) => text,
            // Unreachable: only whole `&str`s are appended.
            Err(_) => "invalid runtime layout",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn module(
        discriminant: u8,
        name: &'static str,
        dependencies: &'static [(u8, &'static str)],
    ) -> ModuleDescriptor {
        ModuleDescriptor::new(discriminant, name, dependencies)
    }

    const fn key(discriminant: u8, name: &'static str) -> ModuleKey {
        ModuleKey { discriminant, name }
    }

    const BANK: ModuleDescriptor = module(1, "bank", &[]);
    const ACCOUNTS: ModuleDescriptor = module(2, "accounts", &[(1, "bank")]);
    /// Depends on a module that depends on another: the closure, by induction.
    const PAYMASTER: ModuleDescriptor = module(255, "paymaster", &[(2, "accounts"), (1, "bank")]);

    /// Valid layouts pass, also evaluated at compile time (like the runtime derives' check):
    /// dependencies in any order of the modules, discriminants up to 255, no modules at all.
    #[test]
    fn layout_validator_accepts_valid_layouts() {
        const VALID: [&[ModuleDescriptor]; 7] = [
            &[],
            &[BANK],
            &[BANK, ACCOUNTS],
            &[PAYMASTER, ACCOUNTS, BANK],
            &[ACCOUNTS, BANK, PAYMASTER],
            // Names of one length that differ in the last byte, or the first.
            &[BANK, module(2, "banj", &[])],
            &[BANK, module(2, "tank", &[(1, "bank")])],
        ];
        const _: () = {
            let mut i = 0;
            while i < VALID.len() {
                assert_layout(VALID[i]);
                i += 1;
            }
        };
        for modules in VALID {
            assert_eq!(check_layout(modules), Ok(()), "{modules:?}");
            assert_layout(modules);
        }
    }

    // Regressions of upstream's runtime layout bugs

    /// P5-25 (regression, the reserved discriminant): a module with discriminant 0 (possible
    /// with a hand-written `ModuleInfo`; the module derive rejects it) is rejected, wherever it
    /// is listed. Upstream never reserved 0.
    #[test]
    fn layout_validator_rejects_discriminant_zero() {
        let zero = module(0, "zero", &[]);
        for modules in [&[zero][..], &[BANK, zero], &[zero, BANK]] {
            assert_eq!(
                check_layout(modules),
                Err(LayoutError::ReservedDiscriminant {
                    module: key(0, "zero")
                })
            );
        }
        assert_eq!(
            LayoutError::ReservedDiscriminant {
                module: key(0, "zero")
            }
            .to_string(),
            "module `zero` (0) has the discriminant 0, which is reserved"
        );
    }

    /// P5-25 (regression, duplicates): two modules with the same discriminant, or the same name,
    /// are rejected (upstream checked discriminants at genesis only, and names never).
    #[test]
    fn layout_validator_rejects_duplicates() {
        let other_bank = module(1, "other_bank", &[]);
        assert_eq!(
            check_layout(&[BANK, ACCOUNTS, other_bank]),
            Err(LayoutError::DuplicateDiscriminant {
                first: key(1, "bank"),
                second: key(1, "other_bank"),
            })
        );
        let bank_again = module(3, "bank", &[]);
        assert_eq!(
            check_layout(&[BANK, bank_again]),
            Err(LayoutError::DuplicateName {
                first: key(1, "bank"),
                second: key(3, "bank"),
            })
        );
        // The same module twice: its discriminant first.
        assert_eq!(
            check_layout(&[BANK, BANK]),
            Err(LayoutError::DuplicateDiscriminant {
                first: key(1, "bank"),
                second: key(1, "bank"),
            })
        );
        assert_eq!(
            check_layout(&[BANK, other_bank]).unwrap_err().to_string(),
            "modules `bank` (1) and `other_bank` (1) have the same discriminant"
        );
        assert_eq!(
            check_layout(&[BANK, bank_again]).unwrap_err().to_string(),
            "modules `bank` (1) and `bank` (3) have the same name"
        );
    }

    /// P5-25 (regression, nested modules): a dependency must be a module of the runtime with
    /// exactly its discriminant and name. Upstream checked only the runtime's own fields, so a
    /// module held by another, with a discriminant no runtime module has (or another module's),
    /// wrote under prefixes nothing checked.
    #[test]
    fn layout_validator_rejects_dependencies_outside_the_runtime() {
        // Not in the runtime at all (also through a dependency's dependency).
        assert_eq!(
            check_layout(&[ACCOUNTS]),
            Err(LayoutError::DependencyNotInRuntime {
                module: key(2, "accounts"),
                dependency: key(1, "bank"),
            })
        );
        assert_eq!(
            check_layout(&[PAYMASTER, ACCOUNTS]),
            Err(LayoutError::DependencyNotInRuntime {
                module: key(255, "paymaster"),
                dependency: key(1, "bank"),
            })
        );
        assert_eq!(
            check_layout(&[ACCOUNTS]).unwrap_err().to_string(),
            "module `accounts` (2) depends on `bank` (1), which is not a module of the runtime"
        );
    }

    /// P5-25 (regression, mismatched dependencies): a dependency whose discriminant is a runtime
    /// module's but whose name is not (it would alias that module's prefixes), or whose name is
    /// but whose discriminant is not (it would write under another prefix), is rejected.
    #[test]
    fn layout_validator_rejects_mismatched_dependencies() {
        let aliasing = module(2, "accounts", &[(1, "vault")]);
        assert_eq!(
            check_layout(&[BANK, aliasing]),
            Err(LayoutError::DependencyMismatch {
                module: key(2, "accounts"),
                dependency: key(1, "vault"),
                runtime_module: key(1, "bank"),
            })
        );
        let renumbered = module(2, "accounts", &[(9, "bank")]);
        assert_eq!(
            check_layout(&[BANK, renumbered]),
            Err(LayoutError::DependencyMismatch {
                module: key(2, "accounts"),
                dependency: key(9, "bank"),
                runtime_module: key(1, "bank"),
            })
        );
        // Names of one length, differing in the last byte only.
        let last_byte = module(2, "accounts", &[(1, "banj")]);
        assert_eq!(
            check_layout(&[BANK, last_byte]),
            Err(LayoutError::DependencyMismatch {
                module: key(2, "accounts"),
                dependency: key(1, "banj"),
                runtime_module: key(1, "bank"),
            })
        );
        // The discriminant's module is reported when both match different modules.
        let crossed = module(3, "crossed", &[(1, "accounts")]);
        assert_eq!(
            check_layout(&[BANK, ACCOUNTS, crossed]),
            Err(LayoutError::DependencyMismatch {
                module: key(3, "crossed"),
                dependency: key(1, "accounts"),
                runtime_module: key(1, "bank"),
            })
        );
        assert_eq!(
            check_layout(&[BANK, aliasing]).unwrap_err().to_string(),
            "module `accounts` (2) depends on `vault` (1), but the runtime's module is `bank` (1)"
        );
    }

    /// The compile-time check panics with the same message (prefixed), for every rule.
    #[test]
    fn assert_layout_panics_with_the_message() {
        let cases: [&[ModuleDescriptor]; 5] = [
            &[module(0, "zero", &[])],
            &[BANK, module(1, "other_bank", &[])],
            &[BANK, module(3, "bank", &[])],
            &[ACCOUNTS],
            &[BANK, module(2, "accounts", &[(1, "vault")])],
        ];
        for modules in cases {
            let expected = format!(
                "invalid runtime layout: {}",
                check_layout(modules).unwrap_err()
            );
            let panic = std::panic::catch_unwind(|| assert_layout(modules)).unwrap_err();
            assert_eq!(panic.downcast_ref::<String>(), Some(&expected));
        }
    }

    /// Discriminants print in decimal; a name too long for the message is replaced by `…`.
    #[test]
    fn layout_error_messages() {
        for (discriminant, text) in [(1, "1"), (9, "9"), (10, "10"), (99, "99"), (100, "100")] {
            assert_eq!(
                LayoutError::DuplicateDiscriminant {
                    first: key(discriminant, "a"),
                    second: key(255, "b"),
                }
                .to_string(),
                format!("modules `a` ({text}) and `b` (255) have the same discriminant")
            );
        }
        let long: &'static str = "n".repeat(400).leak();
        assert_eq!(
            LayoutError::ReservedDiscriminant {
                module: key(0, long)
            }
            .to_string(),
            "module `…` (0) has the discriminant 0, which is reserved"
        );
        // Non-ASCII names are kept whole.
        assert_eq!(
            LayoutError::DuplicateName {
                first: key(1, "é"),
                second: key(2, "é"),
            }
            .to_string(),
            "modules `é` (1) and `é` (2) have the same name"
        );
        let detail = LayoutError::ReservedDiscriminant {
            module: key(0, "zero"),
        }
        .error_detail()
        .unwrap();
        assert_eq!(detail["error_code"], "invalid_runtime_layout");
        assert_eq!(
            detail["message"],
            "module `zero` (0) has the discriminant 0, which is reserved"
        );
    }
}
