//! The order a runtime runs its modules' genesis in: every module after the modules it depends
//! on ([`sort_values_by_modules_dependencies`]).

use std::collections::BTreeMap;
use std::fmt;

use crate::{ErrorContext, ErrorDetail, ModuleId, ModuleInfo, err_detail};

/// A module named by its discriminant and its name ([`ModuleInfo::DISCRIMINANT`],
/// [`ModuleInfo::NAME`]). Shown as `` `name` (discriminant) ``.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ModuleKey {
    /// The module's discriminant.
    pub discriminant: u8,
    /// The module's name.
    pub name: &'static str,
}

impl fmt::Display for ModuleKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "`{}` ({})", self.name, self.discriminant)
    }
}

/// A module's discriminant, name and dependencies ([`ModuleInfo`]'s constants) as a value, for
/// code that handles modules of different types together (the dependency sort).
///
/// ([`ModuleInfo`] has associated constants, so it cannot be a trait object; upstream sorted
/// `&dyn ModuleInfo`s.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleDescriptor {
    key: ModuleKey,
    dependencies: &'static [(u8, &'static str)],
}

impl ModuleDescriptor {
    /// The descriptor of `M`.
    pub const fn of<M: ModuleInfo>() -> Self {
        Self::new(M::DISCRIMINANT, M::NAME, M::DEPENDENCIES)
    }

    /// The module `(discriminant, name)`, which depends on the modules `dependencies`
    /// (`(discriminant, name)` each).
    pub const fn new(
        discriminant: u8,
        name: &'static str,
        dependencies: &'static [(u8, &'static str)],
    ) -> Self {
        Self {
            key: ModuleKey { discriminant, name },
            dependencies,
        }
    }

    /// The module's discriminant and name.
    pub const fn key(&self) -> ModuleKey {
        self.key
    }

    /// The `(discriminant, name)` of each module it depends on.
    pub const fn dependencies(&self) -> &'static [(u8, &'static str)] {
        self.dependencies
    }

    /// The module's id ([`ModuleId::from_name`] of its name).
    pub fn id(&self) -> ModuleId {
        ModuleId::from_name(self.key.name)
    }
}

/// Why modules cannot be sorted by their dependencies.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DependencyError {
    /// Two modules have the same discriminant (or a module is listed twice).
    #[error("modules {first} and {second} have the same discriminant")]
    DuplicateDiscriminant {
        /// The module listed first.
        first: ModuleKey,
        /// The module listed later.
        second: ModuleKey,
    },
    /// Two modules have the same name.
    #[error("modules {first} and {second} have the same name")]
    DuplicateName {
        /// The module listed first.
        first: ModuleKey,
        /// The module listed later.
        second: ModuleKey,
    },
    /// A module depends on a module that is not among them: no module has that discriminant,
    /// or the one that does has another name.
    #[error("module {module} depends on {dependency}, which is not one of the modules")]
    MissingDependency {
        /// The dependent module.
        module: ModuleKey,
        /// The dependency.
        dependency: ModuleKey,
    },
    /// Modules depend on each other in a cycle: each depends on the next, the last on the
    /// first.
    #[error("cyclic dependency of length {}: {}", .cycle.len(), CyclePath(.cycle))]
    Cycle {
        /// The modules of the cycle.
        cycle: Vec<ModuleKey>,
    },
}

/// `{"error_code": "invalid_module_dependencies", "message": …}`, so the runtime's genesis can
/// return it as a [`ModuleError`](crate::ModuleError).
impl ErrorDetail for DependencyError {
    fn error_detail(&self) -> Result<ErrorContext, Box<dyn std::error::Error + Send + Sync>> {
        Ok(err_detail!({
            "error_code": "invalid_module_dependencies",
            "message": self.to_string(),
        })?)
    }
}

/// Shows a cycle as `` `a` (1) -> `b` (2) -> `a` (1) ``.
struct CyclePath<'a>(&'a [ModuleKey]);

impl fmt::Display for CyclePath<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for module in self.0 {
            write!(f, "{module} -> ")?;
        }
        match self.0.first() {
            Some(first) => write!(f, "{first}"),
            None => Ok(()),
        }
    }
}

/// Orders the values of `modules` (one per module) so that each module's value comes after the
/// values of the modules it depends on; otherwise in the given order (a depth-first walk of the
/// modules in that order, each module's dependencies in the order it lists them). The runtime's
/// genesis runs the modules in this order.
///
/// Deterministic: it uses no hash collections (upstream's used `HashMap`/`HashSet`), and the
/// order depends only on the input.
///
/// # Errors
/// - two modules have the same discriminant or the same name (checked first: upstream
///   checked duplicates only after sorting, and its map kept only one of them);
/// - a dependency `(discriminant, name)` is not exactly one of the modules;
/// - a cycle.
pub fn sort_values_by_modules_dependencies<V>(
    modules: Vec<(ModuleDescriptor, V)>,
) -> Result<Vec<V>, DependencyError> {
    let (descriptors, values): (Vec<ModuleDescriptor>, Vec<V>) = modules.into_iter().unzip();

    let mut by_discriminant: BTreeMap<u8, usize> = BTreeMap::new();
    let mut by_name: BTreeMap<&str, usize> = BTreeMap::new();
    for (index, descriptor) in descriptors.iter().enumerate() {
        let key = descriptor.key;
        if let Some(&first) = by_discriminant.get(&key.discriminant) {
            return Err(DependencyError::DuplicateDiscriminant {
                first: descriptors[first].key,
                second: key,
            });
        }
        if let Some(&first) = by_name.get(key.name) {
            return Err(DependencyError::DuplicateName {
                first: descriptors[first].key,
                second: key,
            });
        }
        by_discriminant.insert(key.discriminant, index);
        by_name.insert(key.name, index);
    }

    let mut walk = Walk {
        descriptors: &descriptors,
        by_discriminant: &by_discriminant,
        visited: vec![false; descriptors.len()],
        path: Vec::new(),
        sorted: Vec::with_capacity(descriptors.len()),
    };
    for index in 0..descriptors.len() {
        walk.visit(index)?;
    }

    // Every module is visited once, so `sorted` holds each index exactly once.
    let sorted = walk.sorted;
    debug_assert_eq!(sorted.len(), values.len());
    let mut values: Vec<Option<V>> = values.into_iter().map(Some).collect();
    Ok(sorted
        .into_iter()
        .filter_map(|index| values.get_mut(index).and_then(Option::take))
        .collect())
}

/// The depth-first walk of [`sort_values_by_modules_dependencies`].
struct Walk<'a> {
    descriptors: &'a [ModuleDescriptor],
    by_discriminant: &'a BTreeMap<u8, usize>,
    /// Modules whose walk has started (finished, or on `path`).
    visited: Vec<bool>,
    /// The modules being walked, each a dependency of the one before.
    path: Vec<usize>,
    /// The modules walked, each after its dependencies.
    sorted: Vec<usize>,
}

impl Walk<'_> {
    /// Walks `index`'s dependencies, then adds it. The recursion is at most as deep as the
    /// number of modules (at most 256: their discriminants are distinct).
    fn visit(&mut self, index: usize) -> Result<(), DependencyError> {
        if let Some(position) = self.path.iter().position(|&i| i == index) {
            let cycle = self.path[position..]
                .iter()
                .map(|&i| self.descriptors[i].key)
                .collect();
            return Err(DependencyError::Cycle { cycle });
        }
        if self.visited[index] {
            return Ok(());
        }
        self.visited[index] = true;
        self.path.push(index);
        let descriptor = self.descriptors[index];
        for &(discriminant, name) in descriptor.dependencies {
            let dependency = self
                .by_discriminant
                .get(&discriminant)
                .copied()
                .filter(|&i| self.descriptors[i].key.name == name)
                .ok_or(DependencyError::MissingDependency {
                    module: descriptor.key,
                    dependency: ModuleKey { discriminant, name },
                })?;
            self.visit(dependency)?;
        }
        self.path.pop();
        self.sorted.push(index);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn module(
        discriminant: u8,
        name: &'static str,
        dependencies: &'static [(u8, &'static str)],
    ) -> ModuleDescriptor {
        ModuleDescriptor::new(discriminant, name, dependencies)
    }

    const A: (u8, &str) = (1, "a");
    const B: (u8, &str) = (2, "b");
    const D: (u8, &str) = (4, "d");
    const E: (u8, &str) = (5, "e");

    fn key((discriminant, name): (u8, &'static str)) -> ModuleKey {
        ModuleKey { discriminant, name }
    }

    // Upstream's dependency sort tests (`test_sorting_modules*`), on descriptors.

    #[test]
    fn sorting_modules() {
        let a = module(1, "a", &[]);
        let b = module(2, "b", &[A]);
        let c = module(3, "c", &[A, B]);
        let sorted = sort_values_by_modules_dependencies(vec![(b, 2), (c, 3), (a, 1)]).unwrap();
        assert_eq!(sorted, [1, 2, 3]);
    }

    #[test]
    fn sorting_modules_missing_module() {
        let b = module(2, "b", &[A]);
        let c = module(3, "c", &[A, B]);
        let error = sort_values_by_modules_dependencies(vec![(b, 2), (c, 3)]).unwrap_err();
        assert_eq!(
            error,
            DependencyError::MissingDependency {
                module: key(B),
                dependency: key(A),
            }
        );
        assert_eq!(
            error.to_string(),
            "module `b` (2) depends on `a` (1), which is not one of the modules"
        );
    }

    #[test]
    fn sorting_modules_cycle() {
        let a = module(1, "a", &[]);
        let b = module(2, "b", &[A]);
        let d = module(4, "d", &[E]);
        let e = module(5, "e", &[A, D]);
        let error =
            sort_values_by_modules_dependencies(vec![(b, 2), (d, 3), (a, 1), (e, 4)]).unwrap_err();
        assert_eq!(
            error,
            DependencyError::Cycle {
                cycle: vec![key(D), key(E)],
            }
        );
        assert_eq!(
            error.to_string(),
            "cyclic dependency of length 2: `d` (4) -> `e` (5) -> `d` (4)"
        );
    }

    #[test]
    fn sorting_modules_duplicate() {
        let a = module(1, "a", &[]);
        let b = module(2, "b", &[A]);
        let a2 = module(1, "a", &[]);
        let error = sort_values_by_modules_dependencies(vec![(b, 3), (a, 1), (a2, 2)]).unwrap_err();
        assert_eq!(
            error,
            DependencyError::DuplicateDiscriminant {
                first: key(A),
                second: key(A),
            }
        );
        assert_eq!(
            error.to_string(),
            "modules `a` (1) and `a` (1) have the same discriminant"
        );
    }

    // New.

    /// Names and discriminants are unique separately; a dependency must match both.
    #[test]
    fn duplicate_name_and_mismatched_dependency() {
        let error = sort_values_by_modules_dependencies(vec![
            (module(1, "a", &[]), ()),
            (module(2, "a", &[]), ()),
        ])
        .unwrap_err();
        assert_eq!(
            error,
            DependencyError::DuplicateName {
                first: key(A),
                second: key((2, "a")),
            }
        );
        assert_eq!(
            error.to_string(),
            "modules `a` (1) and `a` (2) have the same name"
        );

        // `b` depends on discriminant 1 under another name: it would alias `a`'s prefixes.
        let error = sort_values_by_modules_dependencies(vec![
            (module(1, "a", &[]), ()),
            (module(2, "b", &[(1, "other")]), ()),
        ])
        .unwrap_err();
        assert_eq!(
            error,
            DependencyError::MissingDependency {
                module: key(B),
                dependency: key((1, "other")),
            }
        );
        // And on name `a` under another discriminant.
        let error = sort_values_by_modules_dependencies(vec![
            (module(1, "a", &[]), ()),
            (module(2, "b", &[(3, "a")]), ()),
        ])
        .unwrap_err();
        assert!(matches!(error, DependencyError::MissingDependency { .. }));
    }

    /// A module depending on itself is a cycle of length 1; independent modules keep their
    /// order; no modules sort to nothing.
    #[test]
    fn self_dependency_order_and_empty() {
        let error =
            sort_values_by_modules_dependencies(vec![(module(1, "a", &[A]), ())]).unwrap_err();
        assert_eq!(
            error,
            DependencyError::Cycle {
                cycle: vec![key(A)],
            }
        );
        assert_eq!(
            error.to_string(),
            "cyclic dependency of length 1: `a` (1) -> `a` (1)"
        );

        let independent = (1..=5).map(|d| (module(d, NAMES[usize::from(d)], &[]), d));
        assert_eq!(
            sort_values_by_modules_dependencies(independent.rev().collect()).unwrap(),
            [5, 4, 3, 2, 1]
        );
        assert!(
            sort_values_by_modules_dependencies(Vec::<(ModuleDescriptor, ())>::new())
                .unwrap()
                .is_empty()
        );
    }

    /// Distinct names for generated modules: module `d` is `NAMES[d]`.
    const NAMES: [&str; 9] = ["m0", "m1", "m2", "m3", "m4", "m5", "m6", "m7", "m8"];

    /// Every dependency set of 8 modules where module `d` depends only on modules below it
    /// (one bit per possible dependency), in a shuffled order.
    fn acyclic() -> impl Strategy<Value = Vec<ModuleDescriptor>> {
        (
            proptest::collection::vec(any::<u8>(), 8),
            Just((1..=8).collect::<Vec<u8>>()).prop_shuffle(),
        )
            .prop_map(|(bits, order)| {
                order
                    .into_iter()
                    .map(|d| {
                        let dependencies: Vec<(u8, &'static str)> = (1..d)
                            .filter(|&below| bits[usize::from(d - 1)] & (1 << (below - 1)) != 0)
                            .map(|below| (below, NAMES[usize::from(below)]))
                            .collect();
                        module(d, NAMES[usize::from(d)], dependencies.leak())
                    })
                    .collect()
            })
    }

    proptest! {
        /// Acyclic dependencies always sort; every value comes out once, after its
        /// dependencies' values.
        #[test]
        fn sorted_values_respect_dependencies(modules in acyclic()) {
            let input: Vec<_> = modules.iter().map(|m| (*m, m.key().discriminant)).collect();
            let sorted = sort_values_by_modules_dependencies(input).unwrap();
            let mut seen = sorted.clone();
            seen.sort_unstable();
            prop_assert_eq!(seen, (1..=8).collect::<Vec<u8>>());
            for module in &modules {
                let position = |d: u8| sorted.iter().position(|&v| v == d).unwrap();
                for &(dependency, _) in module.dependencies() {
                    prop_assert!(position(dependency) < position(module.key().discriminant));
                }
            }
        }
    }

    #[test]
    fn dependency_error_detail() {
        let error = DependencyError::Cycle {
            cycle: vec![key(A)],
        };
        let detail = crate::ModuleError::from(error.clone())
            .error_detail()
            .unwrap();
        assert_eq!(detail["error_code"], "invalid_module_dependencies");
        assert_eq!(detail["message"], error.to_string());
    }

    #[test]
    fn descriptor_of_module_info() {
        assert_eq!(module(1, "bank", &[]).id(), ModuleId::from_name("bank"));
        assert_eq!(module(7, "x", &[A]).dependencies(), &[A]);
        assert_eq!(module(7, "x", &[]).key(), key((7, "x")));
    }
}
