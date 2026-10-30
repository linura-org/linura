//! A protected human decision continues one already prepared canonical plan.
//! This is neither a second policy subject nor authorization to apply a layout.
use super::*;
use linura_transaction::{ContentDigest, TransactionSnapshot, digest_parts};

/// Control-created projection for the trusted protected-interaction adapter.
/// Clients cannot construct a challenge, choose its principal or change its
/// purpose. All layout and provenance data come from the retained request.
#[derive(Debug)]
pub struct DisplayDecisionChallenge {
    principal: PrincipalId,
    request: PlanDesiredStateRequest,
    transaction: TransactionId,
    action: DisplayContinuationAction,
    deadline_unix_ms: u64,
    digest: ContentDigest,
}

impl DisplayDecisionChallenge {
    pub(super) fn new(
        request: &PlanDesiredStateRequest,
        snapshot: &TransactionSnapshot,
        dispatched: &Record,
        observation: &ObservationEnvelope,
        action: DisplayContinuationAction,
    ) -> Result<Self, ManagedLifecycleError> {
        if snapshot.state != TransactionState::Indeterminate
            || snapshot.transaction_id != dispatched.transaction_id
            || snapshot.request_id != request.request_id
            || dispatched.request_digest != crate::durable_authority::digest_request(request)?
        {
            return Err(ManagedLifecycleError::ApprovalBoundary(
                "protected display decision differs from its durable canonical transaction".into(),
            ));
        }
        let principal = AuthenticatedPrincipal::new(snapshot.principal.as_str())
            .map_err(|e| ManagedLifecycleError::Contract(e.to_string()))?;
        require_owner(&principal, request)?;
        if attempt_state(observation, request, dispatched)? != "pending" {
            return Err(ManagedLifecycleError::ApprovalBoundary(
                "protected display decision requires a fresh pending native attempt".into(),
            ));
        }
        let observation_digest = crate::durable_authority::digest_observation(observation)?;
        let generation = snapshot.current_generation.to_be_bytes();
        let version = snapshot.state_version.to_be_bytes();
        let deadline = dispatched.deadline_unix_ms.to_be_bytes();
        let purpose: &[u8] = match action {
            DisplayContinuationAction::Confirm => b"keep",
            DisplayContinuationAction::Revert => b"revert",
        };
        let digest = digest_parts(
            "linura.display.protected-decision.v1",
            [
                snapshot.principal.as_str().as_bytes(),
                dispatched.request_digest.as_str().as_bytes(),
                dispatched.transaction_id.as_str().as_bytes(),
                snapshot.binding_digest.as_str().as_bytes(),
                generation.as_slice(),
                version.as_slice(),
                dispatched.digest().as_str().as_bytes(),
                observation_digest.as_str().as_bytes(),
                purpose,
                deadline.as_slice(),
            ],
        );
        Ok(Self {
            principal: snapshot.principal.clone(),
            request: request.clone(),
            transaction: snapshot.transaction_id.clone(),
            action,
            deadline_unix_ms: dispatched.deadline_unix_ms,
            digest,
        })
    }

    #[must_use]
    pub fn principal(&self) -> &PrincipalId {
        &self.principal
    }
    #[must_use]
    pub fn request(&self) -> &PlanDesiredStateRequest {
        &self.request
    }
    #[must_use]
    pub fn transaction_id(&self) -> &str {
        self.transaction.as_str()
    }
    #[must_use]
    pub const fn action(&self) -> DisplayContinuationAction {
        self.action
    }
    #[must_use]
    pub const fn deadline_unix_ms(&self) -> u64 {
        self.deadline_unix_ms
    }
    #[must_use]
    pub fn digest(&self) -> &str {
        self.digest.as_str()
    }
}

/// Ephemeral consumed native proof. It is deliberately distinct from original
/// apply approval, non-cloneable and never serialized as an execution grant.
#[derive(Debug)]
pub struct TrustedDisplayDecision {
    principal: PrincipalId,
    digest: ContentDigest,
}
impl TrustedDisplayDecision {
    /// Only a trusted composition adapter, after consuming the exact fresh
    /// protected human interaction, may call this. A UID, ordinary D-Bus call,
    /// original apply approval or successful Polkit check is insufficient.
    #[must_use]
    pub fn from_protected_boundary(
        principal: PrincipalId,
        challenge: &DisplayDecisionChallenge,
    ) -> Self {
        Self {
            principal,
            digest: challenge.digest.clone(),
        }
    }

    pub(super) fn consume(self, challenge: &DisplayDecisionChallenge) -> Result<(), String> {
        if self.principal != challenge.principal || self.digest != challenge.digest {
            return Err("protected display proof belongs to another decision".into());
        }
        Ok(())
    }
}

pub trait DisplayDecisionAuthorizer: Debug + Send {
    /// Complete and consume one native purpose-bound decision within the
    /// ORIGINAL deadline. Denial, cancellation, identity/topology/input changes,
    /// unavailable protected presentation or a late proof must return failure.
    fn authorize_decision(
        &self,
        challenge: &DisplayDecisionChallenge,
    ) -> Result<TrustedDisplayDecision, String>;
}
