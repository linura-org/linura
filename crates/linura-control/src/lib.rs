#![forbid(unsafe_code)]

//! Linura's unprivileged local authority/control-plane orchestration.
//!
//! The authority surface owns authenticated authoritative observation,
//! deterministic planning, trusted policy/risk review, exact-bound approval and
//! durable mutation authority. v0.4 established durable prepare/recovery, v0.5
//! qualified an isolated executor/verifier pair, and v0.6 integrates those
//! boundaries for one narrowly scoped Experimental managed external effect.
//!
//! The superseded 0.0.0 `Provider::plan -> ActionPlan -> ControlPlane::apply`
//! scaffold remains intentionally absent. The canonical eleven-stage lifecycle
//! is enforced by `linura-lifecycle`; `linura-control` owns its authority
//! orchestration without importing transport- or executor-specific mechanisms.

mod agent_interpretation;
mod approval;
mod approval_review;
mod authority_clock;
pub mod backlight_contract;
#[cfg(test)]
mod backlight_recovery_tests;
mod durable_authority;
mod managed_lifecycle;
mod operation_registry;
mod operation_semantics;
mod plan_preview;
mod platform_compatibility;
mod policy_review;
mod protective_lock_execution;
mod protective_sleep_gate;
pub use protective_sleep_gate::{
    NativeSleepCoveragePort, NativeSleepGateAttempt, NativeSleepGateMonitor,
    coordinate_native_sleep_coverage,
};
mod protective_lock_safety;
mod protective_lock_settings;
pub use protective_lock_settings::{
    PROTECTIVE_LOCK_SETTING_REQUEST_PREFIX, ProtectiveLockConfigurationReceipt,
    ProtectiveLockConfigurationRequest, ProtectiveLockSettingsControl,
};
#[path = "proposal_acceptance_secure.rs"]
mod proposal_acceptance;
mod proposal_authority;
mod retained_request;
mod review_projection;
mod risk_classification;
mod secure_agent_interpretation;
mod secure_proposal_acceptance;
mod session_power_plan;
mod session_safety;
mod session_transition;
mod transient_effect;

pub use agent_interpretation::{
    InterpretationControlError, InterpretationInvocation, InterpretationSessionBudget,
    InterpretationWork, ProviderInvocationGate, ProviderInvocationPermit, RawSemanticEntry,
    RawSemanticProjection, RawSemanticValue,
};
pub use approval::{
    ApprovalEvidence, ApprovalIssueError, ApprovalRequirement, ApprovalRevocation,
    ApprovalValidation, AuthenticatedApprover, MAX_APPROVAL_TTL_SECONDS,
};
pub use approval_review::{
    APPROVAL_TOMBSTONE_RETENTION_SECONDS, ApprovalControlError, ApprovalRequirementError,
    ApprovalReviewControl, MAX_APPROVAL_ENTRIES, MAX_APPROVAL_ENTRY_BYTES,
    MAX_APPROVAL_TOMBSTONE_BYTES, MAX_APPROVAL_TOMBSTONES, MAX_APPROVAL_TOTAL_BYTES,
    PolicyApprovalEvidence, PolicyApprovalIssueError, PolicyApprovalRequirement,
    PolicyAuthenticatedApprover,
};
pub use authority_clock::ControlAuthorityClock;
pub use durable_authority::{
    DispatchPermit, DurableAuthorityCandidate, DurableAuthorityControl, DurableAuthorityError,
    DurableRecoveryOutcome, FreshRecoveryApproval, PreparedDurableAuthority,
};
pub use managed_lifecycle::{
    AuthorizedEffect, AuthorizedEffectExecutor, IndependentManagedVerifier,
    MANAGED_SYSTEMD_CAPABILITY, MANAGED_SYSTEMD_INTENT_ORIGIN, MANAGED_SYSTEMD_OPERATION,
    MANAGED_SYSTEMD_PROVIDER, MANAGED_SYSTEMD_REGISTERED_OPERATION_ID, MANAGED_SYSTEMD_UNIT_PREFIX,
    ManagedApprovalAuthorizer, ManagedApprovalChallenge, ManagedApprovalClass,
    ManagedLifecycleControl, ManagedLifecycleError, ManagedMutationReceipt, TrustedHumanApproval,
    managed_request_id,
};
pub use operation_registry::{
    MANAGED_SESSION_LOCK_CAPABILITY, MANAGED_SESSION_LOCK_OPERATION_ID,
    MANAGED_SESSION_LOCK_PROVIDER, MANAGED_SESSION_TRANSITION_CAPABILITY,
    MANAGED_SESSION_TRANSITION_PROVIDER, TRANSIENT_AUDIO_CAPABILITY, TRANSIENT_AUDIO_PROVIDER,
    TRANSIENT_AUDIO_RESOURCE_PREFIX, TRANSIENT_AUDIO_VOLUME_CHANGE_KEY,
    TRANSIENT_AUDIO_VOLUME_OPERATION_ID,
};
pub use operation_semantics::{
    OperationPlanBindingMismatch, OperationSemanticsControl, OperationSemanticsError,
    TrustedExternalOperationSemantics,
};
pub use plan_preview::{
    AuthenticatedPrincipal, MAX_DESIRED_ATTRIBUTES, MAX_ORIGINS_PER_KIND, MAX_PREVIEW_ENTRIES,
    MAX_PREVIEW_ENTRY_BYTES, MAX_PREVIEW_TOTAL_BYTES, MAX_REQUEST_BYTES, MAX_SUMMARY_BYTES,
    MAX_TOTAL_ORIGINS, PlanPreviewControl, PlanPreviewControlError,
};
pub use platform_compatibility::PlatformCompatibilityControl;
pub use policy_review::{PolicySubjectError, TrustedPolicyReview, policy_subject_from_plan};
pub use proposal_acceptance::{
    AcceptProposalRequest, AcceptanceAuthoritySnapshot, AuthorityClockUnit,
    AuthorityValidityContributor, AuthorityValidityPredicate, ProposalAcceptanceControlError,
    ProposalAcceptanceDecision,
};
pub use proposal_authority::{ControlProposalAuthority, ProposalDecisionIssueRequest};
pub use protective_lock_safety::{ProtectiveLockSafetyError, ProtectiveLockSafetyReview};
pub use secure_agent_interpretation::{AdapterHealth, ControlInterpretationEngine};
pub use secure_proposal_acceptance::ProposalAcceptanceControl;
pub use session_safety::{
    SessionAction, SessionPowerSafetyReview, SessionSafetyError, SessionSafetyReview,
};
pub use session_transition::{
    SessionTransitionPostcondition, review_session_transition_postcondition,
};
pub use transient_effect::{
    AuthorizedTransientEffect, TransientEffectAuditDisposition, TransientEffectAuditError,
    TransientEffectAuditFailureCode, TransientEffectAuditRecord, TransientEffectAuditSink,
    TransientEffectControl, TransientEffectControlBuildError, TransientEffectError,
    TransientEffectExecutor, TransientEffectExecutorError, TransientEffectReceipt,
    TransientEffectReceiptStatus,
};
