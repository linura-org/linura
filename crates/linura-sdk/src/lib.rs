#![forbid(unsafe_code)]

//! Public, non-privileged Linura SDK surface.
//!
//! This crate intentionally exposes domain and protocol types used by clients
//! and integrations. It does not expose Linura Control internals, policy-engine
//! implementation details, providers, or privileged executors.

pub use linura_capability_sdk::{
    CapabilityBlueprint, CapabilityCatalog, CapabilityRelation, CapabilityRelationKind,
    DesiredResourceBlueprint, Resolution,
};
pub use linura_core::{
    Actor, ActorId, ActorKind, AuthorityClass, Capability, CapabilityId, IntentId, PlanId,
    PolicyId, PolicyRevisionId, PrincipalId, ProfileId, ProviderId, RequestId, RequirementId,
    ResourceId, RiskClass, SemanticReason, SetupId, SupportLevel, ValidationError, WorkflowId,
};
pub use linura_dbus::{Control1Client as LocalControlClient, TransportError as LocalControlError};
pub use linura_graph::{
    Edge, EdgeKind, Node, NodeId, ObservationRecordOutcome, RemovalImpact, SystemGraph,
};
pub use linura_intent::{
    AuthoritySourceKind, AuthoritySourceRevision, INTENT_PROPOSAL_SCHEMA_VERSION, Intent,
    IntentProposal, IntentStatus, InterpretationContextBinding, MachineClass, MachineProfile,
    ProposalAttribution, ProposalConfidence, ProposalDigest, ProposalValidationError, Requirement,
    RequirementKind, Setup, SetupValidationError,
};
pub use linura_library::{
    AdoptionContext, AdoptionReport, IntentRevisionRef, IntentTransition, LIBRARY_SCHEMA_VERSION,
    LibraryError, LibrarySettings, LifecycleRecord, LifecycleRecordKind, LocalLibrary,
    ManagedResourceIdentity, PORTABLE_FORMAT_VERSION,
    PortableProfileBundle as DurablePortableProfileBundle,
    PortableSetupBundle as DurablePortableSetupBundle, ProfileIdentity, RemovalImpactReport,
    SetupRevisionRef, StoredIntent, StoredProfile, StoredSetup,
    decode_profile_bundle as decode_durable_profile_bundle,
    decode_setup_bundle as decode_durable_setup_bundle,
    encode_profile_bundle as encode_durable_profile_bundle,
    encode_setup_bundle as encode_durable_setup_bundle, restore_backup as restore_library_backup,
    validate_backup as validate_library_backup,
};
pub use linura_observation::{
    FreshnessState, ObservationAuthority, ObservationEnvelope, ObservationValidationError,
    ObservedValue, ProviderAvailability, ProviderHealth,
};
pub use linura_protocol::{
    CapabilitySnapshot, ExplainResponse, ExplainTarget, IntentCommand, ObservationExplanation,
    ObservationRequest, ObservationResponse, ObservationSystemSnapshot, PROTOCOL_MAJOR,
    PlanDesiredStateRequest, PlanPreview, PlanPreviewChange, PlanPreviewFinding,
    PlanPreviewFindingLevel, PlanPreviewStatus, PlanReview, PlanReviewApprovalClass,
    PlanReviewDecision, PortableProfileExport, PortableSetupExport, ProfileAdoptionRequest,
    ProfileAdoptionResponse, ProtocolVersion, ProviderSnapshot, SetupAdoptionRequest,
    SetupAdoptionResponse, SystemSnapshot,
};
pub use linura_provenance::{ProvenanceKind, ProvenanceRecord, WhyChain};
