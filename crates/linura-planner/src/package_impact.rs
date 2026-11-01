//! S23 deterministic, non-executable package impact analysis.
//! This module has no native ALPM or authority dependency. Its outputs are
//! advisory blockers and expected reverse-dependency impacts, never dispatch permits.
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub const MAX_PACKAGE_NODES: usize = 8192;
pub const MAX_PACKAGE_EDGES: usize = 131072;
pub const MAX_TARGETS: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackageChangeKind {
    Install,
    Remove,
    Reinstall,
    RemoveOrphans,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageFact {
    pub name: String,
    pub version: String,
    /// Canonical exact-name dependencies only. Version constraints and virtual
    /// provides are not safely solvable here and must block native execution.
    pub dependencies: Vec<String>,
    pub installed: bool,
    pub trusted_repository_member: bool,
    pub has_scriptlets_or_hooks: bool,
    pub protected: bool,
    pub shared_owner: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageUniverseFacts {
    /// These fields are evidence identifiers, not authority or signing proofs.
    pub local_db_digest: String,
    pub repository_digest: String,
    pub boot_id: String,
    pub signed_repository_verified: bool,
    pub dependency_closure_verified: bool,
    pub full_upgrade_not_required: bool,
    pub db_unlocked: bool,
    pub s24_idle: bool,
    pub recovery_qualified: bool,
    pub packages: Vec<PackageFact>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageImpactRequest {
    pub kind: PackageChangeKind,
    pub targets: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum PackageBlocker {
    InvalidUniverse,
    InvalidTarget,
    UnknownTarget,
    UntrustedRepository,
    MissingDependency,
    UnsupportedDependencyExpression,
    ReverseDependency,
    ProtectedPackage,
    SharedResourceOwner,
    ScriptletImpactUnqualified,
    UnsignedRepository,
    UnverifiedDependencyClosure,
    PartialUpgradeRisk,
    DatabaseLocked,
    S24Busy,
    RecoveryUnqualified,
    UnqualifiedExecutor,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageImpactPreview {
    pub requested: Vec<String>,
    pub direct_dependency_closure: Vec<String>,
    pub reverse_dependents: Vec<String>,
    pub blockers: Vec<PackageBlocker>,
    /// Reserved unconditionally. An advisor cannot produce an effect grant.
    pub execution_authorized: bool,
}

fn exact_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 190 && !value.starts_with('-')
        && value.bytes().all(|byte|
            byte.is_ascii_alphanumeric() || b"@._+-".contains(&byte))
}

fn add(blockers: &mut BTreeSet<PackageBlocker>, blocker: PackageBlocker) {
    blockers.insert(blocker);
}

/// Pure, bounded reachability + safety review. A package-name graph cannot
/// express ALPM versioned provides/replaces/conflicts, package file conflicts,
/// signature validity, disk impact, native locks, or external script side effects.
/// Consequently, native execution remains disabled even when no other blockers
/// are present.
#[must_use]
pub fn review_package_impact(
    universe: &PackageUniverseFacts,
    request: &PackageImpactRequest,
) -> PackageImpactPreview {
    let mut blockers = BTreeSet::new();
    add(&mut blockers, PackageBlocker::UnqualifiedExecutor);
    let mut requested = BTreeSet::new();
    if request.targets.is_empty() || request.targets.len() > MAX_TARGETS
        || universe.packages.is_empty() || universe.packages.len() > MAX_PACKAGE_NODES
        || universe.boot_id.len() < 8 || universe.boot_id.len() > 128
        || universe.local_db_digest.len() != 64 || universe.repository_digest.len() != 64
        || !universe.local_db_digest.bytes().all(|b| b.is_ascii_hexdigit())
        || !universe.repository_digest.bytes().all(|b| b.is_ascii_hexdigit())
    {
        add(&mut blockers, PackageBlocker::InvalidUniverse);
    }
    for target in &request.targets {
        if !exact_name(target) || !requested.insert(target.clone()) {
            add(&mut blockers, PackageBlocker::InvalidTarget);
        }
    }
    if !universe.signed_repository_verified {
        add(&mut blockers, PackageBlocker::UnsignedRepository);
    }
    if !universe.dependency_closure_verified {
        add(&mut blockers, PackageBlocker::UnverifiedDependencyClosure);
    }
    if !universe.full_upgrade_not_required {
        add(&mut blockers, PackageBlocker::PartialUpgradeRisk);
    }
    if !universe.db_unlocked {
        add(&mut blockers, PackageBlocker::DatabaseLocked);
    }
    if !universe.s24_idle {
        add(&mut blockers, PackageBlocker::S24Busy);
    }
    if !universe.recovery_qualified {
        add(&mut blockers, PackageBlocker::RecoveryUnqualified);
    }

    let mut package_map = BTreeMap::new();
    let mut edges = 0_usize;
    for package in &universe.packages {
        edges = edges.saturating_add(package.dependencies.len());
        if !exact_name(&package.name)
            || package.version.is_empty()
            || package.version.len() > 128
            || !package.version.bytes().all(|b| {
                b.is_ascii_alphanumeric() || b".:+_~@-".contains(&b)
            })
            || !package_map.insert(package.name.clone(),package).is_none()
        {
            add(&mut blockers, PackageBlocker::InvalidUniverse);
        }
        if package.dependencies.iter().any(|name| !exact_name(name)) {
            add(&mut blockers, PackageBlocker::UnsupportedDependencyExpression);
        }
    }
    if edges > MAX_PACKAGE_EDGES {
        add(&mut blockers, PackageBlocker::InvalidUniverse);
    }
    if blockers.contains(&PackageBlocker::InvalidUniverse)
        || blockers.contains(&PackageBlocker::InvalidTarget)
    {
        return PackageImpactPreview {
            requested: requested.into_iter().collect(),
            direct_dependency_closure: Vec::new(),
            reverse_dependents: Vec::new(),
            blockers: blockers.into_iter().collect(),
            execution_authorized: false,
        };
    }

    let mut dependents: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for package in &universe.packages {
        for dependency in &package.dependencies {
            dependents.entry(dependency).or_default().insert(&package.name);
        }
    }

    let mut closure = BTreeSet::new();
    let mut reverse = BTreeSet::new();
    let mut to_visit = VecDeque::from_iter(requested.iter().cloned());
    let is_removal = matches!(request.kind, PackageChangeKind::Remove | PackageChangeKind::RemoveOrphans);
    while let Some(name) = to_visit.pop_front() {
        if !closure.insert(name.clone()) { continue; }
        if closure.len() > MAX_PACKAGE_NODES {
            add(&mut blockers, PackageBlocker::InvalidUniverse);
            break;
        }
        let Some(package) = package_map.get(&name) else {
            add(&mut blockers, PackageBlocker::UnknownTarget);
            continue;
        };
        if is_removal && !package.installed {
            add(&mut blockers, PackageBlocker::UnknownTarget);
        }
        if !is_removal && !package.trusted_repository_member {
            add(&mut blockers, PackageBlocker::UntrustedRepository);
        }
        if package.protected {
            add(&mut blockers, PackageBlocker::ProtectedPackage);
        }
        if package.shared_owner {
            add(&mut blockers, PackageBlocker::SharedResourceOwner);
        }
        if package.has_scriptlets_or_hooks {
            add(&mut blockers, PackageBlocker::ScriptletImpactUnqualified);
        }
        if is_removal { continue; }
        for dep in &package.dependencies {
            if !exact_name(dep) {
                add(&mut blockers, PackageBlocker::UnsupportedDependencyExpression);
            } else if let Some(node) = package_map.get(dep) {
                if !node.installed {
                    to_visit.push_back(dep.clone());
                }
            } else {
                add(&mut blockers, PackageBlocker::MissingDependency);
            }
        }
    }

    if is_removal {
        let mut queue = VecDeque::from_iter(requested.iter().cloned());
        let mut seen = requested.clone();
        while let Some(name) = queue.pop_front() {
            for &other in dependents.get(name.as_str()).into_iter().flatten() {
                let Some(node) = package_map.get(other) else { continue };
                if node.installed && seen.insert(other.to_owned()) {
                    reverse.insert(other.to_owned());
                    queue.push_back(other.to_owned());
                    add(&mut blockers, PackageBlocker::ReverseDependency);
                    if node.protected { add(&mut blockers, PackageBlocker::ProtectedPackage); }
                    if node.shared_owner { add(&mut blockers, PackageBlocker::SharedResourceOwner); }
                }
            }
            if seen.len() > MAX_PACKAGE_NODES {
                add(&mut blockers, PackageBlocker::InvalidUniverse);
                break;
            }
        }
    }
    PackageImpactPreview {
        requested: requested.into_iter().collect(),
        direct_dependency_closure: closure.into_iter().collect(),
        reverse_dependents: reverse.into_iter().collect(),
        blockers: blockers.into_iter().collect(),
        execution_authorized: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fact(name: &str, deps: &[&str]) -> PackageFact {
        PackageFact {
            name: name.into(), version: "1.0-1".into(),
            dependencies: deps.iter().map(|s| s.to_string()).collect(),
            installed: true, trusted_repository_member: true,
            has_scriptlets_or_hooks: false, protected: false, shared_owner: false,
        }
    }
    fn universe() -> PackageUniverseFacts {
        PackageUniverseFacts {
            local_db_digest: "a".repeat(64),
            repository_digest: "b".repeat(64),
            boot_id: "01234567-aaaa-bbbb-cccc-012345678900".into(),
            signed_repository_verified: false, dependency_closure_verified: false,
            full_upgrade_not_required: false, db_unlocked: true,
            s24_idle: true, recovery_qualified: false,
            packages: vec![fact("library",&[]),fact("editor",&["library"]),fact("suite",&["editor"])],
        }
    }
    #[test]
    fn transitive_reverse_dependency_blocks_removal() {
        let preview=review_package_impact(&universe(),&PackageImpactRequest {
            kind: PackageChangeKind::Remove,targets:vec!["library".into()],
        });
        assert_eq!(preview.reverse_dependents,vec!["editor","suite"]);
        assert!(preview.blockers.contains(&PackageBlocker::ReverseDependency));
        assert!(!preview.execution_authorized);
    }
    #[test]
    fn mixed_install_graph_tracks_missing_targets_and_dependencies() {
        let mut u=universe();
        u.packages[1].installed=false;
        let preview=review_package_impact(&u,&PackageImpactRequest {
            kind: PackageChangeKind::Install,targets:vec!["suite".into()],
        });
        assert_eq!(preview.direct_dependency_closure,vec!["editor","suite"]);
        assert!(preview.blockers.contains(&PackageBlocker::UnqualifiedExecutor));
        assert!(!preview.execution_authorized);
    }
    #[test]
    fn invalid_and_untrusted_inputs_are_blocked() {
        let mut u=universe();
        u.packages[1].dependencies=vec!["libc>=2".into()];
        let preview=review_package_impact(&u,&PackageImpactRequest {
            kind: PackageChangeKind::Install,targets:vec!["editor".into()],
        });
        assert!(preview.blockers.contains(&PackageBlocker::UnsupportedDependencyExpression));
        assert!(!preview.execution_authorized);
        let preview=review_package_impact(&u,&PackageImpactRequest {
            kind: PackageChangeKind::Remove,targets:vec!["../etc/passwd".into()],
        });
        assert!(preview.blockers.contains(&PackageBlocker::InvalidTarget));
        assert!(!preview.execution_authorized);
    }
    #[test]
    fn even_complete_claims_never_produce_authority() {
        let mut u=universe();
        u.signed_repository_verified=true;
        u.dependency_closure_verified=true;
        u.full_upgrade_not_required=true;
        u.recovery_qualified=true;
        let p=review_package_impact(&u,&PackageImpactRequest {
            kind:PackageChangeKind::Reinstall,targets:vec!["editor".into()],
        });
        assert_eq!(p.blockers,vec![PackageBlocker::UnqualifiedExecutor]);
        assert!(!p.execution_authorized);
    }
}
