#![forbid(unsafe_code)]

use linura_core::{Actor, IntentId, ProfileId, RequirementId, SetupId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntentStatus {
    Proposed,
    Active,
    Suspended,
    Superseded,
    Retired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequirementKind {
    Goal,
    Constraint,
    Preference,
    Prohibition,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Requirement {
    pub id: RequirementId,
    pub kind: RequirementKind,
    pub statement: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Intent {
    pub id: IntentId,
    pub actor: Actor,
    pub statement: String,
    pub status: IntentStatus,
    pub requirements: Vec<Requirement>,
    pub supersedes: Vec<IntentId>,
}

/// A reusable, portable composition of intent rather than a recorded command
/// sequence or an exact filesystem snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Setup {
    pub id: SetupId,
    pub name: String,
    pub description: String,
    pub revision: u32,
    pub intent_ids: Vec<IntentId>,
    pub included_setup_ids: Vec<SetupId>,
    pub portable_constraints: Vec<String>,
    pub required_secret_refs: Vec<String>,
    pub hardware_hints: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupValidationError {
    EmptyName,
    ZeroRevision,
    EmptyComposition,
    SelfReference,
    EmptySecretReference,
    InvalidSecretReference,
}

pub const MAX_SECRET_REFERENCE_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretReferenceValidationError {
    Empty,
    TooLong,
    InvalidForm,
    UnsupportedCharacter,
}

pub fn validate_secret_reference(value: &str) -> Result<(), SecretReferenceValidationError> {
    if value.trim().is_empty() {
        return Err(SecretReferenceValidationError::Empty);
    }
    if value.len() > MAX_SECRET_REFERENCE_BYTES {
        return Err(SecretReferenceValidationError::TooLong);
    }
    let Some((namespace, name)) = value.split_once(':') else {
        return Err(SecretReferenceValidationError::InvalidForm);
    };
    if namespace.is_empty() || name.is_empty() || name.contains(':') {
        return Err(SecretReferenceValidationError::InvalidForm);
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(SecretReferenceValidationError::UnsupportedCharacter);
    }
    Ok(())
}

impl Setup {
    pub fn validate(&self) -> Result<(), SetupValidationError> {
        if self.name.trim().is_empty() {
            return Err(SetupValidationError::EmptyName);
        }
        if self.revision == 0 {
            return Err(SetupValidationError::ZeroRevision);
        }
        if self.intent_ids.is_empty() && self.included_setup_ids.is_empty() {
            return Err(SetupValidationError::EmptyComposition);
        }
        if self.included_setup_ids.iter().any(|id| id == &self.id) {
            return Err(SetupValidationError::SelfReference);
        }
        for reference in &self.required_secret_refs {
            match validate_secret_reference(reference) {
                Ok(()) => {}
                Err(SecretReferenceValidationError::Empty) => {
                    return Err(SetupValidationError::EmptySecretReference);
                }
                Err(_) => return Err(SetupValidationError::InvalidSecretReference),
            }
        }
        Ok(())
    }
}

/// Canonical target role of a machine profile.
///
/// This is deliberately separate from system domains such as networking,
/// services, storage or virtualization. Fleet/enterprise is also not a machine
/// class; it is an optional management overlay across locally authoritative
/// machines.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MachineClass {
    Workstation,
    Server,
    Edge,
}

impl MachineClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Workstation => "workstation",
            Self::Server => "server",
            Self::Edge => "edge",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachineProfile {
    pub id: ProfileId,
    pub name: String,
    pub machine_class: MachineClass,
    pub setup_ids: Vec<SetupId>,
    pub intent_ids: Vec<IntentId>,
    pub portable_constraints: Vec<String>,
    pub hardware_hints: Vec<String>,
}

impl Intent {
    /// Whether this intent currently participates in desired-state compilation
    /// and reconciliation.
    #[must_use]
    pub const fn is_managed(&self) -> bool {
        matches!(self.status, IntentStatus::Active)
    }

    /// Whether this intent remains part of the retained lifecycle state even
    /// when reconciliation is suspended.
    #[must_use]
    pub const fn is_retained(&self) -> bool {
        matches!(self.status, IntentStatus::Active | IntentStatus::Suspended)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_core::{ActorId, ActorKind, ValidationError};

    fn id<T>(result: Result<T, ValidationError>) -> T {
        result.unwrap_or_else(|error| unreachable!("{error}"))
    }

    fn intent(status: IntentStatus) -> Intent {
        Intent {
            id: id(IntentId::new("intent:test")),
            actor: Actor {
                id: id(ActorId::new("uid:1000")),
                kind: ActorKind::Human,
                interactive: true,
            },
            statement: "Manage Kubernetes".into(),
            status,
            requirements: vec![],
            supersedes: vec![],
        }
    }

    #[test]
    fn active_intent_is_managed_and_retained() {
        let intent = intent(IntentStatus::Active);
        assert!(intent.is_managed());
        assert!(intent.is_retained());
    }

    #[test]
    fn suspended_intent_is_retained_but_not_managed() {
        let intent = intent(IntentStatus::Suspended);
        assert!(!intent.is_managed());
        assert!(intent.is_retained());
    }

    #[test]
    fn retired_intent_is_neither_managed_nor_retained() {
        let intent = intent(IntentStatus::Retired);
        assert!(!intent.is_managed());
        assert!(!intent.is_retained());
    }

    #[test]
    fn setup_requires_portable_composition_and_revision() {
        let setup = Setup {
            id: id(SetupId::new("setup:rust-development")),
            name: "Rust development".into(),
            description: "Reusable Rust development environment".into(),
            revision: 1,
            intent_ids: vec![id(IntentId::new("intent:rust-development"))],
            included_setup_ids: vec![],
            portable_constraints: vec!["stable toolchain".into()],
            required_secret_refs: vec!["credential:github".into()],
            hardware_hints: vec![],
        };
        assert_eq!(setup.validate(), Ok(()));
    }

    #[test]
    fn setup_rejects_malformed_secret_references() {
        let mut setup = Setup {
            id: id(SetupId::new("setup:secret-validation")),
            name: "Secret validation".into(),
            description: String::new(),
            revision: 1,
            intent_ids: vec![id(IntentId::new("intent:secret-validation"))],
            included_setup_ids: vec![],
            portable_constraints: vec![],
            required_secret_refs: vec!["credential:github".into()],
            hardware_hints: vec![],
        };
        for invalid in [
            "hunter2",
            "credential:",
            ":github",
            "credential:github:token",
            "credential:github token",
        ] {
            setup.required_secret_refs = vec![invalid.into()];
            assert_eq!(
                setup.validate(),
                Err(SetupValidationError::InvalidSecretReference)
            );
        }

        setup.required_secret_refs = vec![format!("credential:{}", "a".repeat(256))];
        assert_eq!(
            setup.validate(),
            Err(SetupValidationError::InvalidSecretReference)
        );
    }

    #[test]
    fn setup_cannot_include_itself() {
        let setup_id = id(SetupId::new("setup:self"));
        let setup = Setup {
            id: setup_id.clone(),
            name: "Self".into(),
            description: String::new(),
            revision: 1,
            intent_ids: vec![],
            included_setup_ids: vec![setup_id],
            portable_constraints: vec![],
            required_secret_refs: vec![],
            hardware_hints: vec![],
        };
        assert_eq!(setup.validate(), Err(SetupValidationError::SelfReference));
    }

    #[test]
    fn machine_class_wire_names_are_canonical() {
        assert_eq!(MachineClass::Workstation.as_str(), "workstation");
        assert_eq!(MachineClass::Server.as_str(), "server");
        assert_eq!(MachineClass::Edge.as_str(), "edge");
    }

    #[test]
    fn machine_profile_retains_its_target_class() {
        let profile = MachineProfile {
            id: id(ProfileId::new("profile:container-host")),
            name: "Container host".into(),
            machine_class: MachineClass::Server,
            setup_ids: vec![],
            intent_ids: vec![],
            portable_constraints: vec!["headless".into()],
            hardware_hints: vec![],
        };
        assert_eq!(profile.machine_class, MachineClass::Server);
    }
}
