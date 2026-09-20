#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};

macro_rules! typed_id {
    ($name:ident, $label:literal) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
                let value = value.into();
                validate_token($label, &value)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

typed_id!(ActorId, "actor id");
typed_id!(PrincipalId, "principal id");
typed_id!(RequestId, "request id");
typed_id!(OperationId, "operation id");
typed_id!(PlanId, "plan id");
typed_id!(ApprovalRequestId, "approval request id");
typed_id!(ApprovalEvidenceId, "approval evidence id");
typed_id!(IntentId, "intent id");
typed_id!(SetupId, "setup id");
typed_id!(RequirementId, "requirement id");
typed_id!(ResourceId, "resource id");
typed_id!(CapabilityId, "capability id");
typed_id!(ProviderId, "provider id");
typed_id!(WorkflowId, "workflow id");
typed_id!(ProfileId, "profile id");
typed_id!(PolicyId, "policy id");
typed_id!(PolicyRevisionId, "policy revision id");

fn validate_token(label: &'static str, value: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::Empty(label));
    }
    if value.len() > 256 {
        return Err(ValidationError::TooLong(label));
    }
    if value.chars().any(char::is_control) {
        return Err(ValidationError::ControlCharacter(label));
    }
    Ok(())
}

fn has_duplicates<T: Ord>(values: &[T]) -> bool {
    let mut seen = BTreeSet::new();
    values.iter().any(|value| !seen.insert(value))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActorKind {
    Human,
    Service,
    Agent,
    Remote,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Actor {
    pub id: ActorId,
    pub kind: ActorKind,
    pub interactive: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupportLevel {
    Supported,
    Unsupported,
    Degraded,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Capability {
    pub id: CapabilityId,
    pub support: SupportLevel,
    pub provider: Option<ProviderId>,
    pub reason: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationClass {
    ExperienceEphemeral,
    AuthoritativeQuery,
    LinuraOwnedState,
    TransientExternalEffect,
    ManagedExternalEffect,
}

impl OperationClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExperienceEphemeral => "experience-ephemeral",
            Self::AuthoritativeQuery => "authoritative-query",
            Self::LinuraOwnedState => "linura-owned-state",
            Self::TransientExternalEffect => "transient-external-effect",
            Self::ManagedExternalEffect => "managed-external-effect",
        }
    }

    #[must_use]
    pub const fn control_mediated(self) -> bool {
        !matches!(self, Self::ExperienceEphemeral)
    }

    #[must_use]
    pub const fn permits_privileged_executor(self) -> bool {
        matches!(self, Self::ManagedExternalEffect)
    }

    #[must_use]
    pub const fn requires_canonical_managed_lifecycle(self) -> bool {
        matches!(self, Self::ManagedExternalEffect)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RiskClass {
    ReadOnly,
    UserState,
    SystemMutation,
    SecuritySensitive,
    Destructive,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityClass {
    Observed,
    Declared,
    Inferred,
    Proposed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticReason {
    pub summary: String,
    pub intent_ids: Vec<IntentId>,
    pub requirement_ids: Vec<RequirementId>,
    pub capability_ids: Vec<CapabilityId>,
}

impl SemanticReason {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.summary.trim().is_empty() {
            return Err(ValidationError::Empty("semantic reason"));
        }
        if self.intent_ids.is_empty()
            && self.requirement_ids.is_empty()
            && self.capability_ids.is_empty()
        {
            return Err(ValidationError::MissingSemanticOrigin);
        }
        if has_duplicates(&self.intent_ids) {
            return Err(ValidationError::DuplicateSemanticOrigin("intent"));
        }
        if has_duplicates(&self.requirement_ids) {
            return Err(ValidationError::DuplicateSemanticOrigin("requirement"));
        }
        if has_duplicates(&self.capability_ids) {
            return Err(ValidationError::DuplicateSemanticOrigin("capability"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValidationError {
    Empty(&'static str),
    TooLong(&'static str),
    ControlCharacter(&'static str),
    MissingSemanticOrigin,
    DuplicateSemanticOrigin(&'static str),
}

impl Display for ValidationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty(label) => write!(f, "{label} cannot be empty"),
            Self::TooLong(label) => write!(f, "{label} is too long"),
            Self::ControlCharacter(label) => write!(f, "{label} contains control characters"),
            Self::MissingSemanticOrigin => f.write_str(
                "managed state must retain an intent, requirement, or capability origin",
            ),
            Self::DuplicateSemanticOrigin(kind) => {
                write!(f, "semantic reason contains duplicate {kind} origin")
            }
        }
    }
}

impl std::error::Error for ValidationError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn id<T>(result: Result<T, ValidationError>) -> T {
        result.unwrap_or_else(|error| unreachable!("{error}"))
    }

    #[test]
    fn identifiers_reject_control_characters() {
        assert!(RequestId::new("bad\nvalue").is_err());
        assert!(ApprovalRequestId::new("approval\nrequest").is_err());
        assert!(ApprovalEvidenceId::new("approval\nevidence").is_err());
        assert!(ActorId::new("uid:1000\nspoof").is_err());
        assert!(PrincipalId::new("uid:1000\nspoof").is_err());
    }

    #[test]
    fn operation_classes_lock_authority_shape() {
        assert!(!OperationClass::ExperienceEphemeral.control_mediated());
        assert!(OperationClass::AuthoritativeQuery.control_mediated());
        assert!(OperationClass::LinuraOwnedState.control_mediated());
        assert!(OperationClass::TransientExternalEffect.control_mediated());
        assert!(OperationClass::ManagedExternalEffect.control_mediated());
        assert!(!OperationClass::TransientExternalEffect.permits_privileged_executor());
        assert!(OperationClass::ManagedExternalEffect.permits_privileged_executor());
        assert!(!OperationClass::TransientExternalEffect.requires_canonical_managed_lifecycle());
        assert!(OperationClass::ManagedExternalEffect.requires_canonical_managed_lifecycle());
        assert_eq!(
            OperationClass::ManagedExternalEffect.as_str(),
            "managed-external-effect"
        );
    }

    #[test]
    fn semantic_reason_rejects_duplicate_origins() {
        let intent = id(IntentId::new("intent:test"));
        let requirement = id(RequirementId::new("requirement:test"));
        let capability = id(CapabilityId::new("capability:test"));

        let duplicate_intent = SemanticReason {
            summary: "test".into(),
            intent_ids: vec![intent.clone(), intent],
            requirement_ids: vec![],
            capability_ids: vec![],
        };
        assert_eq!(
            duplicate_intent.validate(),
            Err(ValidationError::DuplicateSemanticOrigin("intent"))
        );

        let duplicate_requirement = SemanticReason {
            summary: "test".into(),
            intent_ids: vec![],
            requirement_ids: vec![requirement.clone(), requirement],
            capability_ids: vec![],
        };
        assert_eq!(
            duplicate_requirement.validate(),
            Err(ValidationError::DuplicateSemanticOrigin("requirement"))
        );

        let duplicate_capability = SemanticReason {
            summary: "test".into(),
            intent_ids: vec![],
            requirement_ids: vec![],
            capability_ids: vec![capability.clone(), capability],
        };
        assert_eq!(
            duplicate_capability.validate(),
            Err(ValidationError::DuplicateSemanticOrigin("capability"))
        );
    }
}
