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

mod approval;
mod approval_review;
mod durable_authority;
mod managed_lifecycle;
mod plan_preview;
mod policy_review;
mod review_projection;
mod risk_classification;

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
pub use durable_authority::{
    DispatchPermit, DurableAuthorityCandidate, DurableAuthorityControl, DurableAuthorityError,
    DurableRecoveryOutcome, FreshRecoveryApproval, PreparedDurableAuthority,
};
pub use managed_lifecycle::{
    AuthorizedEffect, AuthorizedEffectExecutor, IndependentManagedVerifier,
    MANAGED_SYSTEMD_CAPABILITY, MANAGED_SYSTEMD_INTENT_ORIGIN, MANAGED_SYSTEMD_OPERATION,
    MANAGED_SYSTEMD_PROVIDER, MANAGED_SYSTEMD_UNIT_PREFIX, ManagedApprovalAuthorizer,
    ManagedApprovalChallenge, ManagedLifecycleControl, ManagedLifecycleError,
    ManagedMutationReceipt, TrustedHumanApproval, managed_request_id,
};
pub use plan_preview::{
    AuthenticatedPrincipal, MAX_DESIRED_ATTRIBUTES, MAX_ORIGINS_PER_KIND, MAX_PREVIEW_ENTRIES,
    MAX_PREVIEW_ENTRY_BYTES, MAX_PREVIEW_TOTAL_BYTES, MAX_REQUEST_BYTES, MAX_SUMMARY_BYTES,
    MAX_TOTAL_ORIGINS, PlanPreviewControl, PlanPreviewControlError,
};
pub use policy_review::{PolicySubjectError, TrustedPolicyReview, policy_subject_from_plan};
