#![forbid(unsafe_code)]

mod model;
mod proposal_v1;

pub use model::{
    Intent, IntentStatus, MAX_SECRET_REFERENCE_BYTES, MachineClass, MachineProfile, Requirement,
    RequirementKind, SecretReferenceValidationError, Setup, SetupValidationError,
    validate_secret_reference,
};
pub use proposal_v1::{
    AuthoritySourceKind, AuthoritySourceRevision, INTENT_PROPOSAL_SCHEMA_VERSION, IntentProposal,
    InterpretationContextBinding, ProposalAttribution, ProposalConfidence, ProposalDigest,
    ProposalValidationError,
};
