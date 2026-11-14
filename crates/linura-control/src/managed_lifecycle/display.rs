//! Display-specific confirmation/recovery phases over the same canonical plan,
//! policy and durable authority engine. None of these data records are reusable
//! executor credentials. Existing requests are always reconciled without apply.
use super::*;
use crate::display_recovery_journal::{Phase, Record};
use linura_core::DisplayLayoutMaterial;
use linura_observation::{ObservationAuthority, ObservationEnvelope, ObservedValue};

/// One synchronous history-read scope after both durable stores passed their
/// full checks. It holds no approval, permit or current-provider evidence and
/// cannot be used across a mutable provider/effect boundary.
#[derive(Debug)]
struct CheckedDisplayHistoryRead<'a> {
    journal: &'a dyn ApprovedRequestJournal,
    _scope: Box<dyn linura_transaction::ApprovedRequestReadScope + 'a>,
}
impl CheckedDisplayHistoryRead<'_> {
    fn original_request(
        &self,
        principal: &AuthenticatedPrincipal,
        request_id: &RequestId,
    ) -> Result<PlanDesiredStateRequest, ManagedLifecycleError> {
        let principal_id = PrincipalId::new(principal.as_str())
            .map_err(|e| ManagedLifecycleError::Contract(e.to_string()))?;
        let retained = self
            .journal
            .load(&principal_id, request_id)
            .map_err(|e| ManagedLifecycleError::Authority(e.to_string()))?;
        if retained.principal() != &principal_id || retained.request_id() != request_id {
            return Err(ManagedLifecycleError::Authority(
                "display journal substituted the retained request identity".into(),
            ));
        }
        let request = crate::retained_request::decode(&retained)?;
        require_owner(principal, &request)?;
        if retained.digest() != &crate::durable_authority::digest_request(&request)? {
            return Err(ManagedLifecycleError::Authority(
                "display retained request digest mismatch".into(),
            ));
        }
        Ok(request)
    }
}

pub const DISPLAY_CONFIRMATION_WINDOW_MS: u64 = 15_000;
const MAX_DISPLAY_REVIEWS: usize = 32;
const MAX_DISPLAY_REVIEW_BYTES: usize = 256 * 1024;
const MAX_TOTAL_DISPLAY_REVIEW_BYTES: usize = 8 * 1024 * 1024;
/// Process-local refusal material can move forward exactly once. A durable
/// proof, a restart or an inspection cannot reconstruct either stage.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum DisplayReviewStage {
    Initial,
    HandoffVerified {
        spend: linura_transaction::ContentDigest,
        verification: linura_transaction::ContentDigest,
        expires_at_unix_ms: u64,
    },
    PowerDispatched,
    CurrentCommitDispatched,
    FinalRetirementDispatched,
    RootPowerDispatched {
        preparation: linura_transaction::ContentDigest,
    },
    CompletionDispatched {
        preparation: linura_transaction::ContentDigest,
        verification: linura_transaction::ContentDigest,
    },
}
#[derive(Debug)]
pub(super) struct RetainedDisplayReview {
    review: crate::durable_authority::DisplayRetainedReview,
    stage: DisplayReviewStage,
    created_unix_ms: u64,
    deadline_unix_ms: u64,
    retained_bytes: usize,
}
use linura_protocol::{DisplayLayoutReceipt, DisplayLayoutState};
mod decision;
mod finalization;
mod release;
mod restoration;

/// Exact immutable predecessor comparison. Only the final-retirement workflow
/// constructs this after checking ReleasedCurrent and its signed ancestry.
/// It is never a permit and never opens ordinary Begin admission.
#[derive(Debug, Eq, PartialEq)]
struct DisplaySuccessorContext {
    terminal: linura_transaction::TransactionSnapshot,
    restoration: linura_transaction::TransactionSnapshot,
    scope: linura_core::DisplayRecoveryScope,
    released: linura_transaction::ContentDigest,
    root_released: String,
    root_final: String,
}
pub use decision::{DisplayDecisionAuthorizer, DisplayDecisionChallenge, TrustedDisplayDecision};
pub use finalization::{
    AuthorizedOriginalDisplayCompletion, AuthorizedOriginalDisplayCurrentCommit,
    AuthorizedOriginalDisplayFinalRetirement, AuthorizedOriginalDisplayFinalization,
    AuthorizedOriginalDisplayNativePowerRetirement,
    AuthorizedOriginalDisplayNativeReleaseReservation, AuthorizedOriginalDisplayNativeReleaseSpend,
    AuthorizedOriginalDisplayRetirementPreparation, AuthorizedOriginalDisplayRootPowerRetirement,
    OriginalDisplayCompletionPort, OriginalDisplayCompletionReceipt, OriginalDisplayCurrentCommit,
    OriginalDisplayCurrentCommitPort, OriginalDisplayCurrentInspection,
    OriginalDisplayCurrentVerification, OriginalDisplayFinalRetirementPort,
    OriginalDisplayFinalRetirementVerification, OriginalDisplayFinalizationAuthorizer,
    OriginalDisplayFinalizationChallenge, OriginalDisplayFinalizationInspection,
    OriginalDisplayFinalizationPort, OriginalDisplayFinalizationReceipt,
    OriginalDisplayFinalizationRequest, OriginalDisplayNativeHandoffInspection,
    OriginalDisplayNativeHandoffVerification, OriginalDisplayNativePowerInspection,
    OriginalDisplayNativePowerRetirementPort, OriginalDisplayNativeReleaseReservationPort,
    OriginalDisplayNativeReleaseSpendPort, OriginalDisplayQualifiedCurrent,
    OriginalDisplayQuiescenceInspection, OriginalDisplayReleasedCurrent,
    OriginalDisplayReleasedCurrentCompletion, OriginalDisplayReleasedCurrentPort,
    OriginalDisplayRetirementPreparationPort, OriginalDisplayRootPowerInspection,
    OriginalDisplayRootPowerRetirementPort,
};
pub use release::{
    AuthorizedOrdinaryDisplayRelease, OrdinaryDisplayHandoffInspection,
    OrdinaryDisplayHandoffVerification, OrdinaryDisplayOriginalInspection,
    OrdinaryDisplayReleaseAuthorizer, OrdinaryDisplayReleaseChallenge,
    OrdinaryDisplayReleaseInspection, OrdinaryDisplayReleasePort, OrdinaryDisplayReleaseReceipt,
    OrdinaryDisplayReleaseRequest,
};
pub use restoration::{
    AuthorizedOriginalDisplayRestoration, OriginalDisplayRestorationPort,
    OriginalDisplayRestorationReceipt, OriginalDisplayRestorationRequest,
    OriginalDisplayRestorationTerminalReceipt,
};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisplayContinuationAction {
    Confirm,
    Revert,
}

/// A one-use continuation of an already durably dispatched exact display
/// transaction, minted only after the authenticated decision was retained.
/// It cannot request a different layout or initiate another apply operation.
#[derive(Debug)]
pub struct AuthorizedDisplayContinuation {
    request: PlanDesiredStateRequest,
    transaction_id: TransactionId,
    dispatch_digest: String,
    decision_digest: String,
    protected_decision_digest: String,
    deadline_unix_ms: u64,
    action: DisplayContinuationAction,
}
impl AuthorizedDisplayContinuation {
    #[must_use]
    pub fn request(&self) -> &PlanDesiredStateRequest {
        &self.request
    }
    #[must_use]
    pub fn transaction_id(&self) -> &str {
        self.transaction_id.as_str()
    }
    #[must_use]
    pub fn dispatch_digest(&self) -> &str {
        &self.dispatch_digest
    }
    #[must_use]
    pub fn decision_digest(&self) -> &str {
        &self.decision_digest
    }
    #[must_use]
    pub fn protected_decision_digest(&self) -> &str {
        &self.protected_decision_digest
    }
    #[must_use]
    pub const fn deadline_unix_ms(&self) -> u64 {
        self.deadline_unix_ms
    }
    #[must_use]
    pub const fn action(&self) -> DisplayContinuationAction {
        self.action
    }
}
/// Read-only projection of the validated durable dispatch record. A transaction
/// name alone cannot recover its exact native correlation after adapter restart.
/// This query is not a permit, approval, effect or continuation credential.
#[derive(Debug)]
pub struct DisplayAttemptQuery<'a> {
    request: &'a PlanDesiredStateRequest,
    transaction_id: &'a str,
    dispatch_digest: &'a str,
    deadline_unix_ms: u64,
}
impl<'a> DisplayAttemptQuery<'a> {
    fn new(
        request: &'a PlanDesiredStateRequest,
        dispatched: &'a Record,
    ) -> Result<Self, ManagedLifecycleError> {
        if dispatched.phase != Phase::Dispatched {
            return Err(ManagedLifecycleError::Contract(
                "display query has no dispatched record".into(),
            ));
        }
        Ok(Self {
            request,
            transaction_id: dispatched.transaction_id.as_str(),
            dispatch_digest: dispatched.dispatch_digest.as_deref().ok_or_else(|| {
                ManagedLifecycleError::Contract("display dispatch digest is missing".into())
            })?,
            deadline_unix_ms: dispatched.deadline_unix_ms,
        })
    }
    #[must_use]
    pub const fn request(&self) -> &PlanDesiredStateRequest {
        self.request
    }
    #[must_use]
    pub const fn transaction_id(&self) -> &str {
        self.transaction_id
    }
    #[must_use]
    pub const fn dispatch_digest(&self) -> &str {
        self.dispatch_digest
    }
    #[must_use]
    pub const fn deadline_unix_ms(&self) -> u64 {
        self.deadline_unix_ms
    }
}

/// Control seals the original canonical native precondition together with its
/// one-use effect. The digest is comparison data, never independent authority.
#[derive(Debug)]
pub struct AuthorizedDisplayApplication {
    authorization: AuthorizedEffect,
    native_baseline_guard: ComponentDigest,
    predecessor: Option<linura_core::DisplayRecoveryScope>,
}
impl AuthorizedDisplayApplication {
    #[must_use]
    pub fn into_executor_request(
        self,
    ) -> (
        AuthorizedEffect,
        ComponentDigest,
        Option<linura_core::DisplayRecoveryScope>,
    ) {
        (
            self.authorization,
            self.native_baseline_guard,
            self.predecessor,
        )
    }
}
pub trait DisplayTransactionPort: Debug + Send {
    fn dispatch_layout(
        &mut self,
        application: AuthorizedDisplayApplication,
        request: &PlanDesiredStateRequest,
        deadline_unix_ms: u64,
    ) -> Result<ExecutionOutcome, String>;
    fn observe_attempt(
        &mut self,
        query: &DisplayAttemptQuery<'_>,
    ) -> Result<ObservationEnvelope, String>;
    fn continue_layout(
        &mut self,
        continuation: AuthorizedDisplayContinuation,
    ) -> Result<(), String>;
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisplayVerificationTarget {
    Desired,
    Restored {
        native_baseline_guard: ComponentDigest,
    },
}
pub trait IndependentDisplayVerifier: Debug + Send {
    /// A single fresh native probe; scheduling and all retry limits stay here
    /// in Control. Restoration checks the retained baseline, not executor flags.
    fn verify_layout(
        &mut self,
        request: &PlanDesiredStateRequest,
        target: DisplayVerificationTarget,
        after_unix_ms: u64,
    ) -> Result<VerificationOutcome, String>;
}

fn now_ms() -> Result<u64, ManagedLifecycleError> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ManagedLifecycleError::Contract("display clock unavailable".into()))?
            .as_millis(),
    )
    .map_err(|_| ManagedLifecycleError::Contract("display clock overflow".into()))
}
fn material(
    request: &PlanDesiredStateRequest,
) -> Result<DisplayLayoutMaterial<'_>, ManagedLifecycleError> {
    DisplayLayoutMaterial::decode(request.desired_state.get("layout").ok_or_else(|| {
        ManagedLifecycleError::UnsupportedEffect("display intent is missing".into())
    })?)
    .map_err(|e| ManagedLifecycleError::UnsupportedEffect(e.to_string()))
}
fn require_owner(
    principal: &AuthenticatedPrincipal,
    request: &PlanDesiredStateRequest,
) -> Result<(), ManagedLifecycleError> {
    validate_public_request(request)?;
    validate_request_identity(request)?;
    if !is_display_request(request)
        || principal.as_str() != format!("unix:uid:{}", material(request)?.lock().epoch().uid())
    {
        return Err(ManagedLifecycleError::ApprovalBoundary(
            "display request is not owned by the exact native session principal".into(),
        ));
    }
    Ok(())
}
fn receipt(
    request: &PlanDesiredStateRequest,
    deadline: u64,
    state: DisplayLayoutState,
    principal: &PrincipalId,
) -> DisplayLayoutReceipt {
    DisplayLayoutReceipt {
        request_id: request.request_id.clone(),
        transaction_id: TransactionId::for_namespace(principal, &request.request_id)
            .as_str()
            .into(),
        resource: request.resource.clone(),
        state,
        confirmation_expires_at_unix_ms: deadline,
    }
}
fn attempt_state(
    observation: &ObservationEnvelope,
    request: &PlanDesiredStateRequest,
    dispatched: &Record,
) -> Result<String, ManagedLifecycleError> {
    attempt_state_at(observation, request, dispatched, now_ms()?)
}

fn attempt_state_at(
    observation: &ObservationEnvelope,
    request: &PlanDesiredStateRequest,
    dispatched: &Record,
    now: u64,
) -> Result<String, ManagedLifecycleError> {
    let fail = || {
        ManagedLifecycleError::Verification(
            "native display attempt evidence is stale, malformed or substituted".into(),
        )
    };
    let expected = material(request)?;
    let provider = ProviderId::new(linura_observation::DISPLAY_PROVIDER).map_err(|_| fail())?;
    let capability =
        linura_core::CapabilityId::new("display.layout-attempt.observe").map_err(|_| fail())?;
    let resource = ResourceId::new(format!(
        "display:attempt:{}",
        dispatched.transaction_id.as_str()
    ))
    .map_err(|_| fail())?;
    observation
        .validate(&provider, &resource, &capability)
        .map_err(|_| fail())?;
    if observation.authority != ObservationAuthority::NativeApi
        || observation.attributes.len() != 6
        || observation.sequence == 0
        || observation.observed_at_unix_ms == 0
        || observation.valid_for_ms == 0
        || observation.valid_for_ms > 2000
        || observation.observed_at_unix_ms > now
        || observation.observed_at_unix_ms <= dispatched.recorded_at_unix_ms
        || observation
            .observed_at_unix_ms
            .checked_add(observation.valid_for_ms)
            .is_none_or(|expiry| now >= expiry)
    {
        return Err(fail());
    }
    for (key, value) in [
        (
            "lock_resource",
            expected
                .lock()
                .resource_id()
                .map_err(|_| fail())?
                .as_str()
                .to_owned(),
        ),
        ("topology_resource", request.resource.as_str().to_owned()),
        (
            "effect_digest",
            effect_from_request(request)?.digest().to_hex(),
        ),
        (
            "dispatch_digest",
            dispatched.dispatch_digest.clone().ok_or_else(fail)?,
        ),
    ] {
        if observation.attributes.get(key) != Some(&ObservedValue::Text(value)) {
            return Err(fail());
        }
    }
    if observation.attributes.get("deadline_unix_ms")
        != Some(&ObservedValue::U64(dispatched.deadline_unix_ms))
    {
        return Err(fail());
    }
    match observation.attributes.get("state") {
        Some(ObservedValue::Text(state))
            if [
                "pending",
                "confirmed",
                "restored",
                "restoring",
                "recovery-failed",
                "absent",
            ]
            .contains(&state.as_str()) =>
        {
            Ok(state.clone())
        }
        _ => Err(fail()),
    }
}

/// One checked history for queries AND continuations. A valid dispatch payload
/// alone cannot stand in for its durable reservation and transaction anchor.
struct DisplayHistory {
    reserved: Record,
    dispatched: Option<Record>,
    confirmation: Option<Record>,
    revert: Option<Record>,
    confirmed: Option<Record>,
    restored: Option<Record>,
}
impl DisplayHistory {
    fn load(
        journal: &dyn ApprovedRequestJournal,
        principal: &PrincipalId,
        digest: &linura_transaction::ContentDigest,
        transaction: &TransactionId,
        state: TransactionState,
        now: u64,
    ) -> Result<Self, ManagedLifecycleError> {
        let read = |phase| Record::load(journal, principal, digest, phase);
        let reserved = read(Phase::Reserved)?.ok_or_else(|| {
            ManagedLifecycleError::Authority("display recovery reservation is missing".into())
        })?;
        reserved.validate_after(None)?;
        if &reserved.transaction_id != transaction {
            return Err(ManagedLifecycleError::Authority(
                "display recovery reservation belongs to another transaction".into(),
            ));
        }
        let history = Self {
            reserved,
            dispatched: read(Phase::Dispatched)?,
            confirmation: read(Phase::ConfirmRequested)?,
            revert: read(Phase::RevertRequested)?,
            confirmed: read(Phase::Confirmed)?,
            restored: read(Phase::Restored)?,
        };
        if std::iter::once(&history.reserved)
            .chain(
                [
                    &history.dispatched,
                    &history.confirmation,
                    &history.revert,
                    &history.confirmed,
                    &history.restored,
                ]
                .into_iter()
                .flatten(),
            )
            .any(|record| record.recorded_at_unix_ms > now)
        {
            return Err(ManagedLifecycleError::Authority(
                "display recovery clock precedes retained history".into(),
            ));
        }
        if history.confirmation.is_some() && history.revert.is_some()
            || history.confirmed.is_some() && history.restored.is_some()
        {
            return Err(ManagedLifecycleError::Authority(
                "display recovery history forked".into(),
            ));
        }
        let Some(dispatched) = &history.dispatched else {
            if history.confirmation.is_some()
                || history.revert.is_some()
                || history.confirmed.is_some()
                || history.restored.is_some()
            {
                return Err(ManagedLifecycleError::Authority(
                    "display recovery history is missing its dispatch reservation".into(),
                ));
            }
            return Ok(history);
        };
        dispatched.validate_after(Some(&history.reserved))?;
        if !matches!(
            state,
            TransactionState::Indeterminate
                | TransactionState::Verified
                | TransactionState::Committed
                | TransactionState::RecoveryBlocked
        ) {
            return Err(ManagedLifecycleError::Authority(
                "display dispatch history contradicts durable authority".into(),
            ));
        }
        for decision in [&history.confirmation, &history.revert]
            .into_iter()
            .flatten()
        {
            decision.validate_after(Some(dispatched))?;
            if decision.protected_decision_digest.is_none() {
                return Err(ManagedLifecycleError::ApprovalBoundary(
                    "legacy display decision has no protected proof; independent recovery is required".into(),
                ));
            }
        }
        if let Some(confirmed) = &history.confirmed {
            confirmed.validate_after(history.confirmation.as_ref())?;
            validate_terminal_display_history(Phase::Confirmed, state)?;
        }
        if let Some(restored) = &history.restored {
            restored.validate_after(
                history
                    .confirmation
                    .as_ref()
                    .or(history.revert.as_ref())
                    .or(Some(dispatched)),
            )?;
            validate_terminal_display_history(Phase::Restored, state)?;
        }
        Ok(history)
    }
}

fn validate_terminal_display_history(
    phase: Phase,
    state: TransactionState,
) -> Result<(), ManagedLifecycleError> {
    match (phase, state) {
        (Phase::Confirmed, TransactionState::Committed) => Ok(()),
        (Phase::Restored, TransactionState::RecoveryBlocked) => Ok(()),
        (Phase::Restored, _) | (Phase::Confirmed, _) => Err(ManagedLifecycleError::Authority(
            "display terminal record contradicts the durable authority state".into(),
        )),
        _ => Err(ManagedLifecycleError::Authority(
            "display journal supplied a non-terminal phase as terminal".into(),
        )),
    }
}

impl<S: TransactionStore> ManagedLifecycleControl<S> {
    fn check_display_review_capacity(&mut self, bytes: usize) -> Result<(), ManagedLifecycleError> {
        let now = now_ms()?;
        // Discarding this refusal-only review cache cannot cancel a native
        // reservation, replay an effect or keep it after expiry/clock rollback.
        self.display_reviews
            .retain(|_, value| now >= value.created_unix_ms && now < value.deadline_unix_ms);
        let retained = self
            .display_reviews
            .values()
            .map(|value| value.retained_bytes)
            .fold(0_usize, usize::saturating_add);
        if self.display_reviews.len() >= MAX_DISPLAY_REVIEWS
            || bytes > MAX_DISPLAY_REVIEW_BYTES
            || retained.saturating_add(bytes) > MAX_TOTAL_DISPLAY_REVIEW_BYTES
        {
            return Err(ManagedLifecycleError::Authority(
                "pending display review retention is at capacity".into(),
            ));
        }
        Ok(())
    }

    fn require_current_display_keep_review(
        &mut self,
        principal: &AuthenticatedPrincipal,
        request: &PlanDesiredStateRequest,
        snapshot: &linura_transaction::TransactionSnapshot,
    ) -> Result<(), ManagedLifecycleError> {
        let floor = self.registered_managed_risk_floor(request)?;
        let retained = self.display_reviews.get(&snapshot.transaction_id).ok_or_else(|| {
            ManagedLifecycleError::ApprovalBoundary("original display review is unavailable; observe and restore without reconstructing keep authority".into())
        })?;
        let now = now_ms()?;
        if retained.review.purpose() != crate::durable_authority::DisplayReviewPurpose::Keep
            || retained.stage != DisplayReviewStage::Initial
            || now < retained.created_unix_ms
            || now >= retained.deadline_unix_ms
        {
            return Err(ManagedLifecycleError::ApprovalBoundary(
                "original display review deadline expired".into(),
            ));
        }
        self.validate_registered_managed_plan(retained.review.plan(), retained.review.risk())?;
        self.authority.revalidate_display_review(
            principal,
            request,
            &retained.review,
            floor,
            snapshot,
        )?;
        Ok(())
    }

    // The compositor's reservation map is volatile. An owner/compositor
    // replacement must not make a new request bypass retained ambiguity.
    // Derive this fence from authenticated durable authority + original intent,
    // never a process-local cache, elapsed timeout or a fresh compositor's idle bit.
    fn pending_display_recovery(
        &self,
        principal: &PrincipalId,
        request: &PlanDesiredStateRequest,
    ) -> Result<Option<(AuthenticatedPrincipal, RequestId)>, ManagedLifecycleError> {
        const MAX_PENDING: usize = 32;
        let target = material(request)?;
        let own = TransactionId::for_namespace(principal, &request.request_id);
        let mut seen = BTreeSet::new();
        for state in [TransactionState::Indeterminate, TransactionState::Verified] {
            let pending = self.authority.recovery_snapshots_in_namespace(
                state,
                DISPLAY_REQUEST_PREFIX,
                MAX_PENDING,
            )?;
            for snapshot in pending {
                if !seen.insert(snapshot.transaction_id.clone()) || seen.len() > MAX_PENDING {
                    return Err(ManagedLifecycleError::Authority(
                        "display recovery inventory is ambiguous or exhausted".into(),
                    ));
                }
                if snapshot.transaction_id == own {
                    continue; // This invocation's sealed, once-only handoff.
                }
                let retained_principal =
                    AuthenticatedPrincipal::new(snapshot.principal.as_str())
                        .map_err(|e| ManagedLifecycleError::Authority(e.to_string()))?;
                let retained =
                    self.retained_display_request(&retained_principal, &snapshot.request_id)?;
                self.authority
                    .assert_request_matches(&retained_principal, &retained)?;
                if snapshot.transaction_id
                    != TransactionId::for_namespace(&snapshot.principal, &snapshot.request_id)
                {
                    return Err(ManagedLifecycleError::Authority(
                        "display recovery inventory substituted a transaction".into(),
                    ));
                }
                if material(&retained)?.topology().seat() != target.topology().seat() {
                    continue;
                }
                crate::display_checkpoint::Checkpoint::load(
                    self.display_journal()?,
                    &retained,
                    &snapshot,
                    now_ms()?,
                )?;
                // Validate the entire immutable phase chain, including missing
                // dispatch/decision records and contradictory terminal facts.
                DisplayHistory::load(
                    self.display_journal()?,
                    &snapshot.principal,
                    &crate::durable_authority::digest_request(&retained)?,
                    &snapshot.transaction_id,
                    snapshot.state,
                    now_ms()?,
                )?;
                return Ok(Some((retained_principal, snapshot.request_id)));
            }
        }
        Ok(None)
    }

    /// Signed Committed is a bookkeeping milestone. Retained restoration and
    /// finalization ownership still excludes a competing apply, including a
    /// new compositor/session UUID on the same seat. Only the separate future
    /// authenticated successor/adoption transition may transfer that ownership;
    /// ordinary Begin and status reconciliation cannot infer such a transfer.
    fn require_display_completion_ownership_settled(
        &self,
        request: &PlanDesiredStateRequest,
        successor: Option<&DisplaySuccessorContext>,
    ) -> Result<(), ManagedLifecycleError> {
        const MAX_OWNERS: usize = 32;
        let target = material(request)?;
        let mut seen = BTreeSet::new();
        self.display_journal()?.integrity_check().map_err(|_| {
            ManagedLifecycleError::Authority(
                "display completion ownership history unavailable".into(),
            )
        })?;
        for prefix in [
            DISPLAY_RESTORATION_REQUEST_PREFIX,
            DISPLAY_FINALIZATION_REQUEST_PREFIX,
            DISPLAY_ORDINARY_RELEASE_REQUEST_PREFIX,
        ] {
            for state in [
                TransactionState::Indeterminate,
                TransactionState::Verified,
                TransactionState::Committed,
                TransactionState::RecoveryBlocked,
            ] {
                for snapshot in self
                    .authority
                    .recovery_snapshots_in_namespace(state, prefix, MAX_OWNERS)?
                {
                    if !seen.insert(snapshot.transaction_id.clone()) || seen.len() > MAX_OWNERS {
                        return Err(ManagedLifecycleError::Authority(
                            "display completion ownership inventory is ambiguous or exhausted"
                                .into(),
                        ));
                    }
                    let historical = AuthenticatedPrincipal::new(snapshot.principal.as_str())
                        .map_err(|_| {
                            ManagedLifecycleError::Authority(
                                "display completion owner identity unavailable".into(),
                            )
                        })?;
                    let retained = self
                        .display_journal()?
                        .load(&snapshot.principal, &snapshot.request_id)
                        .map_err(|_| {
                            ManagedLifecycleError::Authority(
                                "display completion ownership request unavailable".into(),
                            )
                        })?;
                    if retained.principal() != &snapshot.principal
                        || retained.request_id() != &snapshot.request_id
                    {
                        return Err(ManagedLifecycleError::Authority(
                            "display completion ownership request substituted".into(),
                        ));
                    }
                    let retained_request = crate::retained_request::decode(&retained)?;
                    validate_public_request(&retained_request)?;
                    validate_request_identity(&retained_request)?;
                    if retained.digest()
                        != &crate::durable_authority::digest_request(&retained_request)?
                        || self
                            .authority
                            .matching_request_snapshot(&historical, &retained_request)?
                            != snapshot
                    {
                        return Err(ManagedLifecycleError::Authority(
                            "display completion ownership binding changed".into(),
                        ));
                    }
                    let blocked = if prefix == DISPLAY_RESTORATION_REQUEST_PREFIX {
                        let text = retained_request
                            .desired_state
                            .get("restore_original")
                            .ok_or_else(|| {
                                ManagedLifecycleError::Authority(
                                    "display restoration ownership material unavailable".into(),
                                )
                            })?;
                        let restoration = linura_core::DisplayRestorationMaterial::decode(text)
                            .map_err(|_| {
                                ManagedLifecycleError::Authority(
                                    "display restoration ownership material invalid".into(),
                                )
                            })?;
                        restoration.original().topology().seat() == target.topology().seat()
                    } else if prefix == DISPLAY_ORDINARY_RELEASE_REQUEST_PREFIX {
                        let intent =
                            crate::display_ordinary_release_intent::OrdinaryReleaseIntent::load(
                                self.display_journal()?,
                                &snapshot.principal,
                                &retained_request,
                            )?;
                        intent.require_claim(
                            self.display_journal()?,
                            &snapshot.principal,
                            &retained_request,
                        )?;
                        linura_core::DisplayOrdinaryReleaseMaterial::decode(intent.material())
                            .map_err(|_| {
                                ManagedLifecycleError::Authority(
                                    "ordinary display release ownership material invalid".into(),
                                )
                            })?
                            .original()
                            .topology()
                            .seat()
                            == target.topology().seat()
                    } else {
                        let intent = crate::display_finalization_intent::FinalizationIntent::load(
                            self.display_journal()?,
                            &snapshot.principal,
                            &retained_request,
                        )?;
                        intent.require_claim(
                            self.display_journal()?,
                            &snapshot.principal,
                            &retained_request,
                        )?;
                        let finalization =
                            linura_core::DisplayFinalizationMaterial::decode(intent.material())
                                .map_err(|_| {
                                    ManagedLifecycleError::Authority(
                                        "display finalization ownership material invalid".into(),
                                    )
                                })?;
                        finalization.restoration().original().topology().seat()
                            == target.topology().seat()
                    };
                    let transferred = successor.is_some_and(|owner| {
                        snapshot.principal == owner.terminal.principal
                            && (snapshot == owner.terminal || snapshot == owner.restoration)
                    });
                    if blocked && !transferred {
                        return Err(ManagedLifecycleError::Indeterminate("display completion ownership remains retained for this seat; Committed is not successor, release or cleanup authority".into()));
                    }
                }
            }
        }
        Ok(())
    }

    fn require_display_recovery_settled(
        &self,
        principal: &PrincipalId,
        request: &PlanDesiredStateRequest,
        successor: Option<&DisplaySuccessorContext>,
    ) -> Result<(), ManagedLifecycleError> {
        self.require_display_completion_ownership_settled(request, successor)?;
        if self.pending_display_recovery(principal, request)?.is_some() {
            return Err(ManagedLifecycleError::Indeterminate(
                "display recovery is unresolved for this seat; reconcile or restore it before another mutation".into(),
            ));
        }
        Ok(())
    }

    fn reconcile_prior_display_recovery<
        P: DisplayTransactionPort,
        V: IndependentDisplayVerifier,
    >(
        &mut self,
        principal: &PrincipalId,
        request: &PlanDesiredStateRequest,
        port: &mut P,
        verifier: &mut V,
    ) -> Result<(), ManagedLifecycleError> {
        if let Some((historical_principal, historical_request)) =
            self.pending_display_recovery(principal, request)?
        {
            // One bounded observe-only reconciliation per explicit request, not
            // an unbounded startup loop. Historical identity comes ONLY from
            // authenticated durable authority, never the new client's input.
            // It can retire freshly verified bookkeeping, never approve/dispatch
            // another apply, manufacture Keep or adopt a replacement owner.
            let recovery_actor = Actor {
                id: linura_core::ActorId::new("actor:linura-control:display-recovery")
                    .map_err(|e| ManagedLifecycleError::Contract(e.to_string()))?,
                kind: ActorKind::Service,
                interactive: false,
            };
            let _historical_status = self.display_layout_status(
                historical_principal,
                recovery_actor,
                &historical_request,
                port,
                verifier,
            )?;
        }
        self.require_display_recovery_settled(principal, request, None)
    }

    fn display_journal(&self) -> Result<&dyn ApprovedRequestJournal, ManagedLifecycleError> {
        self.request_journal.as_deref().ok_or_else(|| {
            ManagedLifecycleError::Authority(
                "display management requires its protected durable request/recovery journal".into(),
            )
        })
    }
    fn append_display_record(
        &mut self,
        record: &Record,
        principal: PrincipalId,
        previous: Option<&Record>,
    ) -> Result<(), ManagedLifecycleError> {
        record.append(
            self.request_journal.as_deref_mut().ok_or_else(|| {
                ManagedLifecycleError::Authority("display recovery journal is unavailable".into())
            })?,
            principal,
            previous,
        )
    }
    fn checked_display_history(
        &self,
    ) -> Result<CheckedDisplayHistoryRead<'_>, ManagedLifecycleError> {
        let journal = self.display_journal()?;
        let scope = journal
            .checked_read_scope()
            .map_err(|e| ManagedLifecycleError::Authority(e.to_string()))?;
        self.authority.integrity_check()?;
        Ok(CheckedDisplayHistoryRead {
            journal,
            _scope: scope,
        })
    }

    fn retained_display_request(
        &self,
        principal: &AuthenticatedPrincipal,
        request_id: &RequestId,
    ) -> Result<PlanDesiredStateRequest, ManagedLifecycleError> {
        self.checked_display_history()?
            .original_request(principal, request_id)
    }

    /// Prepare and dispatch once. Completion remains provisional until a separate
    /// authenticated confirmation; the independently owned native recovery timer
    /// must be armed before the first potentially effectful native request.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_display_layout<P: DisplayTransactionPort, V: IndependentDisplayVerifier>(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        request: PlanDesiredStateRequest,
        approval_authorizer: &dyn ManagedApprovalAuthorizer,
        port: &mut P,
        verifier: &mut V,
    ) -> Result<DisplayLayoutReceipt, ManagedLifecycleError> {
        self.begin_display_layout_inner(
            principal,
            actor,
            request,
            approval_authorizer,
            port,
            verifier,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn begin_display_layout_inner<P: DisplayTransactionPort, V: IndependentDisplayVerifier>(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        request: PlanDesiredStateRequest,
        approval_authorizer: &dyn ManagedApprovalAuthorizer,
        port: &mut P,
        verifier: &mut V,
        successor: Option<DisplaySuccessorContext>,
    ) -> Result<DisplayLayoutReceipt, ManagedLifecycleError> {
        require_owner(&principal, &request)?;
        if actor.kind != ActorKind::Human || !actor.interactive {
            return Err(ManagedLifecycleError::ApprovalBoundary(
                "display changes require authenticated interactive human provenance".into(),
            ));
        }
        let principal_id = PrincipalId::new(principal.as_str())
            .map_err(|e| ManagedLifecycleError::Contract(e.to_string()))?;
        let transaction_id = TransactionId::for_namespace(&principal_id, &request.request_id);
        match self.authority.snapshot(&transaction_id) {
            Ok(_) => {
                if self.retained_display_request(&principal, &request.request_id)? != request {
                    return Err(ManagedLifecycleError::Authority(
                        "display request identity was reused with different material".into(),
                    ));
                }
                return self.display_layout_status(
                    principal,
                    actor,
                    &request.request_id,
                    port,
                    verifier,
                );
            }
            Err(DurableAuthorityError::Transaction(detail))
                if detail == "durable transaction not found" => {}
            Err(error) => return Err(error.into()),
        }
        self.display_journal()?
            .integrity_check()
            .map_err(|e| ManagedLifecycleError::Authority(e.to_string()))?;
        if let Some(context) = successor.as_ref() {
            self.require_successor_context(&principal, context)?;
            self.require_display_recovery_settled(&principal_id, &request, Some(context))?;
        } else {
            self.reconcile_prior_display_recovery(&principal_id, &request, port, verifier)?;
        }
        self.check_display_review_capacity(0)?;
        let floor = self.registered_managed_risk_floor(&request)?;
        let candidate = self.authority.candidate_with_risk_floor(
            &mut self.previews,
            principal.clone(),
            actor.clone(),
            request.clone(),
            floor,
        )?;
        self.validate_registered_managed_candidate(&candidate)?;
        crate::display_checkpoint::require_baseline(
            candidate.display_checkpoint_observation(),
            &request,
            now_ms()?,
        )?;
        let effect = effect_from_request(&request)?;
        if effect_from_candidate(&candidate)? != effect {
            return Err(ManagedLifecycleError::Contract(
                "display canonical plan and effect differ".into(),
            ));
        }
        let approver = self.authorize_candidate(&candidate, &request, approval_authorizer)?;
        let (candidate, evidence) = if let Some(approver) = approver {
            let refreshed = self.refresh_candidate_after_approval(
                &candidate,
                principal.clone(),
                actor.clone(),
                request.clone(),
                &effect,
            )?;
            let id = ApprovalRequestId::new(format!(
                "approval:v010:display:{}",
                request.request_id.as_str()
            ))
            .map_err(|e| ManagedLifecycleError::Contract(e.to_string()))?;
            let expiry = now_unix_seconds()?
                .checked_add(MANAGED_APPROVAL_TTL_SECONDS)
                .ok_or_else(|| {
                    ManagedLifecycleError::Contract("display approval clock overflow".into())
                })?;
            let evidence = self
                .authority
                .issue_approval(id, &refreshed, &approver, expiry)?;
            (refreshed, Some(evidence.id().clone()))
        } else {
            (candidate, None)
        };
        if let Some(context) = successor.as_ref() {
            self.require_successor_root(&principal, context)?;
            self.retain_successor_claim(&principal_id, &request, context)?;
        }
        let retained = crate::retained_request::encode(principal_id.clone(), &request)?;
        self.request_journal
            .as_mut()
            .ok_or_else(|| {
                ManagedLifecycleError::Authority("display journal is unavailable".into())
            })?
            .retain(&retained)
            .map_err(|e| ManagedLifecycleError::Authority(e.to_string()))?;
        let mut prepared = self.authority.prepare(candidate, evidence)?;
        let checkpoint =
            crate::display_checkpoint::Checkpoint::capture(&prepared, &request, now_ms()?)?;
        checkpoint.append(
            self.request_journal
                .as_mut()
                .ok_or_else(|| {
                    ManagedLifecycleError::Authority("display journal is unavailable".into())
                })?
                .as_mut(),
            principal_id.clone(),
            &request,
        )?;
        // Read back the immutable exact binding before spending a permit. A
        // successful write reply alone cannot substitute retained recovery data.
        crate::display_checkpoint::Checkpoint::load(
            self.display_journal()?,
            &request,
            prepared.snapshot(),
            now_ms()?,
        )?;
        let retained_bytes =
            crate::durable_authority::DisplayRetainedReview::estimated_bytes(&prepared);
        self.check_display_review_capacity(retained_bytes)?;
        let started = now_ms()?;
        let deadline = started
            .checked_add(DISPLAY_CONFIRMATION_WINDOW_MS)
            .ok_or_else(|| {
                ManagedLifecycleError::Contract("display confirmation deadline overflow".into())
            })?;
        let reserved = Record::new(
            retained.digest().clone(),
            transaction_id.clone(),
            Phase::Reserved,
            deadline,
            started,
            None,
            None,
            None,
        )?;
        self.append_display_record(&reserved, principal_id.clone(), None)?;
        self.require_display_recovery_settled(&principal_id, &request, successor.as_ref())?;
        if let Some(context) = successor.as_ref() {
            self.require_successor_claim(&principal_id, &request, context)?;
            self.require_successor_root(&principal, context)?;
        }
        let permit = self.handoff_registered_managed(&principal, &mut prepared)?;
        let authorization = authorized_effect(effect, permit)?;
        let dispatch_digest = authorization.binding().dispatch_digest.to_hex();
        let dispatched = Record::new(
            retained.digest().clone(),
            transaction_id,
            Phase::Dispatched,
            deadline,
            now_ms()?,
            Some(dispatch_digest.clone()),
            Some(reserved.digest().clone()),
            None,
        )?;
        // Persist both baseline and ambiguity/dispatch correlation BEFORE calling
        // the effect port. A failed or uncertain journal write cannot dispatch.
        self.append_display_record(&dispatched, principal_id.clone(), Some(&reserved))?;
        self.display_reviews.insert(
            dispatched.transaction_id.clone(),
            RetainedDisplayReview {
                stage: DisplayReviewStage::Initial,
                review: crate::durable_authority::DisplayRetainedReview::from_spent(
                    prepared,
                    crate::durable_authority::DisplayReviewPurpose::Keep,
                )?,
                created_unix_ms: started,
                deadline_unix_ms: deadline,
                retained_bytes,
            },
        );
        if now_ms()? >= deadline {
            return Ok(receipt(
                &request,
                deadline,
                DisplayLayoutState::Indeterminate,
                &principal_id,
            ));
        }
        self.require_display_recovery_settled(&principal_id, &request, successor.as_ref())?;
        if let Some(context) = successor.as_ref() {
            self.require_successor_claim(&principal_id, &request, context)?;
            self.require_successor_root(&principal, context)?;
        }
        let application = AuthorizedDisplayApplication {
            authorization,
            native_baseline_guard: checkpoint.native_guard,
            predecessor: successor.map(|context| context.scope),
        };
        match port.dispatch_layout(application, &request, deadline) {
            Ok(outcome) if outcome.dispatch_digest.to_hex() != dispatch_digest => {
                return Err(ManagedLifecycleError::Contract(
                    "display executor substituted the dispatch digest".into(),
                ));
            }
            Ok(outcome) if outcome.disposition == ExecutionDisposition::RejectedBeforeDispatch => {
                // The dispatch reservation was retained before calling the port.
                // Without a separately durable rejection record, the same
                // request must remain indeterminate across a process restart.
                // A transient port reply cannot override durable uncertainty.
                return Ok(receipt(
                    &request,
                    deadline,
                    DisplayLayoutState::Indeterminate,
                    &principal_id,
                ));
            }
            _ => {} // Lost transport never authorizes retry or optimistic success.
        }
        self.display_layout_status(principal, actor, &request.request_id, port, verifier)
    }

    pub fn display_layout_status<P: DisplayTransactionPort, V: IndependentDisplayVerifier>(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        request_id: &RequestId,
        port: &mut P,
        verifier: &mut V,
    ) -> Result<DisplayLayoutReceipt, ManagedLifecycleError> {
        let request = self.retained_display_request(&principal, request_id)?;
        let principal_id = PrincipalId::new(principal.as_str())
            .map_err(|e| ManagedLifecycleError::Contract(e.to_string()))?;
        let digest = crate::durable_authority::digest_request(&request)?;
        self.authority
            .assert_request_matches(&principal, &request)?;
        let transaction = TransactionId::for_namespace(&principal_id, request_id);
        let snapshot = self.authority.snapshot(&transaction)?;
        let history = DisplayHistory::load(
            self.display_journal()?,
            &principal_id,
            &digest,
            &transaction,
            snapshot.state,
            now_ms()?,
        )?;
        let reserved = history.reserved;
        let Some(dispatched) = history.dispatched else {
            return Ok(receipt(
                &request,
                reserved.deadline_unix_ms,
                if matches!(
                    snapshot.state,
                    TransactionState::Prepared | TransactionState::Aborted
                ) {
                    DisplayLayoutState::NotDispatched
                } else {
                    DisplayLayoutState::Indeterminate
                },
                &principal_id,
            ));
        };
        let checkpoint = crate::display_checkpoint::Checkpoint::load(
            self.display_journal()?,
            &request,
            &snapshot,
            now_ms()?,
        )?;
        if let Some(context) = self.successor_for_request(&principal, &request)?
            && self
                .verify_successor_transfer(
                    &principal,
                    &request,
                    &context,
                    &dispatched,
                    &checkpoint.native_guard,
                    port,
                    verifier,
                )
                .is_err()
        {
            return Ok(receipt(
                &request,
                reserved.deadline_unix_ms,
                DisplayLayoutState::Indeterminate,
                &principal_id,
            ));
        }
        if history.confirmed.is_some() || history.restored.is_some() {
            self.display_reviews.remove(&transaction);
            return Ok(receipt(
                &request,
                reserved.deadline_unix_ms,
                if history.confirmed.is_some() {
                    DisplayLayoutState::Confirmed
                } else {
                    DisplayLayoutState::Restored
                },
                &principal_id,
            ));
        }
        let confirmation = history.confirmation;
        let revert = history.revert;
        let predecessor = confirmation
            .as_ref()
            .or(revert.as_ref())
            .unwrap_or(&dispatched);
        let observed = match port.observe_attempt(&DisplayAttemptQuery::new(&request, &dispatched)?)
        {
            Ok(observation) => observation,
            Err(_) => {
                return Ok(receipt(
                    &request,
                    reserved.deadline_unix_ms,
                    DisplayLayoutState::Indeterminate,
                    &principal_id,
                ));
            }
        };
        let state = attempt_state(&observed, &request, &dispatched)?;
        let after = observed.observed_at_unix_ms;
        let verified = |verifier: &mut V, restoration| {
            let target = if restoration {
                DisplayVerificationTarget::Restored {
                    native_baseline_guard: checkpoint.native_guard,
                }
            } else {
                DisplayVerificationTarget::Desired
            };
            matches!(verifier.verify_layout(&request, target, after), Ok(result) if result.disposition == VerificationDisposition::Satisfied)
                && attempt_state(&observed, &request, &dispatched).is_ok()
        };
        let state = match state.as_str() {
            "restored" if verified(verifier, true) => {
                let terminal = self.authority.retire_restored_display_without_replay(
                    &mut self.previews,
                    principal.clone(),
                    actor.clone(),
                    &request,
                    &checkpoint.native_guard,
                )?;
                validate_terminal_display_history(Phase::Restored, terminal.state)?;
                let restored = Record::new(
                    digest,
                    reserved.transaction_id,
                    Phase::Restored,
                    reserved.deadline_unix_ms,
                    now_ms()?,
                    dispatched.dispatch_digest.clone(),
                    Some(predecessor.digest().clone()),
                    Some(crate::durable_authority::digest_observation(&observed)?),
                )?;
                self.append_display_record(&restored, principal_id.clone(), Some(predecessor))?;
                DisplayLayoutState::Restored
            }
            "confirmed" if confirmation.is_some() && verified(verifier, false) => {
                let floor = self.registered_managed_risk_floor(&request)?;
                if snapshot.state == TransactionState::Indeterminate {
                    let recovered = self.authority.recover_indeterminate_without_replay(
                        &mut self.previews,
                        principal.clone(),
                        actor,
                        request.clone(),
                        floor,
                    )?;
                    let DurableRecoveryOutcome::Verified(verified) = recovered else {
                        return Ok(receipt(
                            &request,
                            reserved.deadline_unix_ms,
                            DisplayLayoutState::Indeterminate,
                            &principal_id,
                        ));
                    };
                    self.authority.commit_verified(&principal, verified)?;
                } else if snapshot.state == TransactionState::Verified {
                    let verified = self
                        .authority
                        .resume_verified(&principal, &reserved.transaction_id)?;
                    self.authority.commit_verified(&principal, verified)?;
                } else if snapshot.state != TransactionState::Committed {
                    return Ok(receipt(
                        &request,
                        reserved.deadline_unix_ms,
                        DisplayLayoutState::Indeterminate,
                        &principal_id,
                    ));
                }
                let confirmed = Record::new(
                    digest,
                    reserved.transaction_id,
                    Phase::Confirmed,
                    reserved.deadline_unix_ms,
                    now_ms()?,
                    dispatched.dispatch_digest,
                    confirmation.as_ref().map(|record| record.digest().clone()),
                    Some(crate::durable_authority::digest_observation(&observed)?),
                )?;
                self.append_display_record(
                    &confirmed,
                    principal_id.clone(),
                    confirmation.as_ref(),
                )?;
                DisplayLayoutState::Confirmed
            }
            "pending"
                if confirmation.is_none()
                    && revert.is_none()
                    && now_ms()? < reserved.deadline_unix_ms
                    && verified(verifier, false) =>
            {
                DisplayLayoutState::AwaitingConfirmation
            }
            _ => DisplayLayoutState::Indeterminate,
        };
        Ok(receipt(
            &request,
            reserved.deadline_unix_ms,
            state,
            &principal_id,
        ))
    }

    /// A repeat after an uncertain continuation reply observes only. It never
    /// sends the phase again or issues another layout apply.
    #[allow(clippy::too_many_arguments)]
    pub fn decide_display_layout<P: DisplayTransactionPort, V: IndependentDisplayVerifier>(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        request_id: &RequestId,
        action: DisplayContinuationAction,
        decision_authorizer: &dyn DisplayDecisionAuthorizer,
        port: &mut P,
        verifier: &mut V,
    ) -> Result<DisplayLayoutReceipt, ManagedLifecycleError> {
        if actor.kind != ActorKind::Human || !actor.interactive {
            return Err(ManagedLifecycleError::ApprovalBoundary(
                "display confirmation requires authenticated interactive human provenance".into(),
            ));
        }
        let request = self.retained_display_request(&principal, request_id)?;
        let principal_id = PrincipalId::new(principal.as_str())
            .map_err(|e| ManagedLifecycleError::Contract(e.to_string()))?;
        let digest = crate::durable_authority::digest_request(&request)?;
        self.authority
            .assert_request_matches(&principal, &request)?;
        let transaction = TransactionId::for_namespace(&principal_id, request_id);
        let snapshot = self.authority.snapshot(&transaction)?;
        let history = DisplayHistory::load(
            self.display_journal()?,
            &principal_id,
            &digest,
            &transaction,
            snapshot.state,
            now_ms()?,
        )?;
        if history.confirmation.is_some()
            || history.revert.is_some()
            || history.confirmed.is_some()
            || history.restored.is_some()
        {
            return self.display_layout_status(principal, actor, request_id, port, verifier);
        }
        let dispatched = history.dispatched.ok_or_else(|| {
            ManagedLifecycleError::Authority("display has no durable dispatch reservation".into())
        })?;
        let checkpoint = crate::display_checkpoint::Checkpoint::load(
            self.display_journal()?,
            &request,
            &snapshot,
            now_ms()?,
        )?;
        if let Some(context) = self.successor_for_request(&principal, &request)?
            && self
                .verify_successor_transfer(
                    &principal,
                    &request,
                    &context,
                    &dispatched,
                    &checkpoint.native_guard,
                    port,
                    verifier,
                )
                .is_err()
        {
            return Ok(receipt(
                &request,
                dispatched.deadline_unix_ms,
                DisplayLayoutState::Indeterminate,
                &principal_id,
            ));
        }
        if snapshot.state != TransactionState::Indeterminate {
            return Err(ManagedLifecycleError::Authority(
                "display decision has no active indeterminate transaction".into(),
            ));
        }
        if now_ms()? >= dispatched.deadline_unix_ms {
            return self.display_layout_status(principal, actor, request_id, port, verifier);
        }
        if action == DisplayContinuationAction::Confirm {
            self.require_current_display_keep_review(&principal, &request, &snapshot)?;
        }
        let observed = port
            .observe_attempt(&DisplayAttemptQuery::new(&request, &dispatched)?)
            .map_err(ManagedLifecycleError::Verification)?;
        if attempt_state(&observed, &request, &dispatched)? != "pending" {
            return self.display_layout_status(principal, actor, request_id, port, verifier);
        }
        if action == DisplayContinuationAction::Confirm
            && !matches!(verifier.verify_layout(&request, DisplayVerificationTarget::Desired, observed.observed_at_unix_ms), Ok(result) if result.disposition == VerificationDisposition::Satisfied)
        {
            return Ok(receipt(
                &request,
                dispatched.deadline_unix_ms,
                DisplayLayoutState::Indeterminate,
                &principal_id,
            ));
        }
        let phase = if action == DisplayContinuationAction::Confirm {
            Phase::ConfirmRequested
        } else {
            Phase::RevertRequested
        };
        // Caller provenance and the original apply approval are not a fresh
        // human keep/revert decision. Consume a separate protected proof bound
        // to this canonical request, durable authority and native attempt.
        let challenge =
            DisplayDecisionChallenge::new(&request, &snapshot, &dispatched, &observed, action)?;
        let interaction_started = std::time::Instant::now();
        let interaction_now = now_ms()?;
        let remaining = dispatched
            .deadline_unix_ms
            .checked_sub(interaction_now)
            .filter(|remaining| *remaining != 0)
            .ok_or_else(|| {
                ManagedLifecycleError::ApprovalBoundary(
                    "protected display decision deadline expired".into(),
                )
            })?;
        decision_authorizer
            .authorize_decision(&challenge)
            .and_then(|proof| proof.consume(&challenge))
            .map_err(ManagedLifecycleError::ApprovalBoundary)?;
        let interaction_completed = now_ms()?;
        if interaction_completed < interaction_now
            || interaction_completed >= dispatched.deadline_unix_ms
            || interaction_started.elapsed() >= Duration::from_millis(remaining)
        {
            return Err(ManagedLifecycleError::ApprovalBoundary(
                "protected display decision exceeded its original deadline".into(),
            ));
        }
        // Human interaction may outlive the first probe. Obtain fresh evidence;
        // never stamp its completion time onto the pre-interaction observation.
        let fresh = port
            .observe_attempt(&DisplayAttemptQuery::new(&request, &dispatched)?)
            .map_err(ManagedLifecycleError::Verification)?;
        if fresh.observed_at_unix_ms < interaction_completed
            || fresh.sequence <= observed.sequence
            || fresh.attributes != observed.attributes
            || attempt_state(&fresh, &request, &dispatched)? != "pending"
        {
            return Err(ManagedLifecycleError::Verification(
                "native display attempt changed during protected interaction".into(),
            ));
        }
        if action == DisplayContinuationAction::Confirm
            && !matches!(verifier.verify_layout(&request, DisplayVerificationTarget::Desired, fresh.observed_at_unix_ms), Ok(result) if result.disposition == VerificationDisposition::Satisfied)
        {
            return Ok(receipt(
                &request,
                dispatched.deadline_unix_ms,
                DisplayLayoutState::Indeterminate,
                &principal_id,
            ));
        }
        // The independent probe may have consumed the original native attempt
        // deadline. Never stamp its completion time onto expired decision facts.
        if attempt_state(&fresh, &request, &dispatched)? != "pending" {
            return Err(ManagedLifecycleError::Verification(
                "display attempt changed before decision".into(),
            ));
        }
        if action == DisplayContinuationAction::Confirm {
            self.require_current_display_keep_review(&principal, &request, &snapshot)?;
        }
        let decision = Record::new(
            digest,
            dispatched.transaction_id.clone(),
            phase,
            dispatched.deadline_unix_ms,
            now_ms()?,
            dispatched.dispatch_digest.clone(),
            Some(dispatched.digest().clone()),
            Some(crate::durable_authority::digest_observation(&fresh)?),
        )?
        .with_protected_decision(
            linura_transaction::ContentDigest::new(challenge.digest())
                .map_err(|e| ManagedLifecycleError::Contract(e.to_string()))?,
        )?;
        self.append_display_record(&decision, principal_id, Some(&dispatched))?;
        if now_ms()? >= dispatched.deadline_unix_ms {
            // Reservation is already durable. Observe only; a slow journal may
            // not extend the deadline or cause this decision to be replayed.
            return self.display_layout_status(principal, actor, request_id, port, verifier);
        }
        if action == DisplayContinuationAction::Confirm {
            // Journal I/O cannot extend original approval validity. A failure
            // leaves this durable decision observe-only; it is never replayed.
            self.require_current_display_keep_review(&principal, &request, &snapshot)?;
        }
        let continuation = AuthorizedDisplayContinuation {
            request,
            transaction_id: dispatched.transaction_id,
            dispatch_digest: dispatched.dispatch_digest.ok_or_else(|| {
                ManagedLifecycleError::Contract("display dispatch digest is missing".into())
            })?,
            decision_digest: decision.digest().as_str().into(),
            protected_decision_digest: challenge.digest().into(),
            deadline_unix_ms: dispatched.deadline_unix_ms,
            action,
        };
        let _ = port.continue_layout(continuation);
        self.display_layout_status(principal, actor, request_id, port, verifier)
    }
}

#[cfg(test)]
mod terminal_history_tests {
    use super::*;

    #[test]
    fn confirmed_requires_committed_authority_and_restoration_cannot_follow_commit() {
        assert!(
            validate_terminal_display_history(Phase::Confirmed, TransactionState::Committed,)
                .is_ok()
        );
        assert!(
            validate_terminal_display_history(Phase::Confirmed, TransactionState::Indeterminate,)
                .is_err()
        );
        assert!(
            validate_terminal_display_history(Phase::Restored, TransactionState::Committed,)
                .is_err()
        );
        assert!(
            validate_terminal_display_history(Phase::Restored, TransactionState::RecoveryBlocked,)
                .is_ok()
        );
        assert!(
            validate_terminal_display_history(Phase::Dispatched, TransactionState::Committed,)
                .is_err()
        );
    }
}

#[cfg(test)]
mod history_tests {
    use super::*;
    use linura_transaction::{ContentDigest, RetainedRequest, TransactionStoreError};

    #[derive(Debug, Default)]
    struct Journal(BTreeMap<(PrincipalId, RequestId), RetainedRequest>);
    impl ApprovedRequestJournal for Journal {
        fn retain(&mut self, record: &RetainedRequest) -> Result<(), TransactionStoreError> {
            let key = (record.principal().clone(), record.request_id().clone());
            if self.0.get(&key).is_some_and(|old| old != record) {
                return Err(TransactionStoreError::AuthorityRejected);
            }
            self.0.insert(key, record.clone());
            Ok(())
        }
        fn load(
            &self,
            principal: &PrincipalId,
            request: &RequestId,
        ) -> Result<RetainedRequest, TransactionStoreError> {
            self.0
                .get(&(principal.clone(), request.clone()))
                .cloned()
                .ok_or(TransactionStoreError::NotFound)
        }
        fn integrity_check(&self) -> Result<(), TransactionStoreError> {
            Ok(())
        }
    }
    fn id<T, E: Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| unreachable!("{error:?}"))
    }
    fn fixture() -> (PrincipalId, ContentDigest, Record, Record) {
        let principal = id(PrincipalId::new("unix:uid:1000"));
        let request = id(RequestId::new("request:v010:display-layout:history"));
        let digest =
            linura_transaction::digest_parts("display-history-test", [b"request".as_slice()]);
        let transaction = TransactionId::for_namespace(&principal, &request);
        let reserved = id(Record::new(
            digest.clone(),
            transaction.clone(),
            Phase::Reserved,
            200,
            100,
            None,
            None,
            None,
        ));
        let dispatched = id(Record::new(
            digest.clone(),
            transaction,
            Phase::Dispatched,
            200,
            110,
            Some("a".repeat(64)),
            Some(reserved.digest().clone()),
            None,
        ));
        (principal, digest, reserved, dispatched)
    }
    fn next(prior: &Record, phase: Phase, at: u64) -> Record {
        let record = id(Record::new(
            prior.request_digest.clone(),
            prior.transaction_id.clone(),
            phase,
            prior.deadline_unix_ms,
            at,
            prior.dispatch_digest.clone(),
            Some(prior.digest().clone()),
            Some(linura_transaction::digest_parts(
                "display-history-observation-test",
                [b"observation".as_slice()],
            )),
        ));
        if matches!(phase, Phase::ConfirmRequested | Phase::RevertRequested) {
            id(
                record.with_protected_decision(linura_transaction::digest_parts(
                    "display-history-protected-proof-test",
                    [b"protected".as_slice()],
                )),
            )
        } else {
            record
        }
    }
    fn load(
        journal: &Journal,
        p: &PrincipalId,
        r: &Record,
        state: TransactionState,
    ) -> Result<DisplayHistory, ManagedLifecycleError> {
        DisplayHistory::load(
            journal,
            p,
            &r.request_digest,
            &r.transaction_id,
            state,
            1000,
        )
    }

    #[test]
    fn missing_or_substituted_reservation_blocks_continuation_history() {
        let (p, _, reserved, dispatched) = fixture();
        let mut journal = Journal::default();
        // Payload and dispatch key are valid; the required parent is absent.
        id(dispatched.append(&mut journal, p.clone(), Some(&reserved)));
        assert!(load(&journal, &p, &reserved, TransactionState::Indeterminate).is_err());
        id(reserved.append(&mut journal, p.clone(), None));
        assert!(load(&journal, &p, &reserved, TransactionState::Indeterminate).is_ok());
        let other = id(TransactionId::new("transaction:substituted"));
        assert!(
            DisplayHistory::load(
                &journal,
                &p,
                &reserved.request_digest,
                &other,
                TransactionState::Indeterminate,
                1000,
            )
            .is_err()
        );
        assert!(load(&journal, &p, &reserved, TransactionState::Prepared).is_err());
    }

    #[test]
    fn legacy_decision_remains_retained_but_cannot_be_upgraded_to_protected_authority() {
        let (p, _, reserved, dispatched) = fixture();
        let mut journal = Journal::default();
        id(reserved.append(&mut journal, p.clone(), None));
        id(dispatched.append(&mut journal, p.clone(), Some(&reserved)));
        let legacy = id(Record::new(
            dispatched.request_digest.clone(),
            dispatched.transaction_id.clone(),
            Phase::ConfirmRequested,
            200,
            120,
            dispatched.dispatch_digest.clone(),
            Some(dispatched.digest().clone()),
            Some(linura_transaction::digest_parts(
                "legacy-observation-test",
                [b"native".as_slice()],
            )),
        ));
        id(legacy.append(&mut journal, p.clone(), Some(&dispatched)));
        assert!(matches!(
            load(&journal, &p, &reserved, TransactionState::Indeterminate),
            Err(ManagedLifecycleError::ApprovalBoundary(_))
        ));
        assert_eq!(
            id(Record::load(
                &journal,
                &p,
                &reserved.request_digest,
                Phase::ConfirmRequested
            )),
            Some(legacy)
        );
    }

    #[test]
    fn orphan_decision_is_rejected_even_when_no_dispatch_key_is_present() {
        let (p, _, reserved, dispatched) = fixture();
        let mut journal = Journal::default();
        id(reserved.append(&mut journal, p.clone(), None));
        let decision = next(&dispatched, Phase::ConfirmRequested, 120);
        id(decision.append(&mut journal, p.clone(), Some(&dispatched)));
        assert!(load(&journal, &p, &reserved, TransactionState::Prepared).is_err());
    }

    #[test]
    fn confirmation_and_reversion_fork_never_becomes_a_continuation() {
        let (p, _, reserved, dispatched) = fixture();
        let mut journal = Journal::default();
        id(reserved.append(&mut journal, p.clone(), None));
        id(dispatched.append(&mut journal, p.clone(), Some(&reserved)));
        for phase in [Phase::ConfirmRequested, Phase::RevertRequested] {
            id(next(&dispatched, phase, 120).append(&mut journal, p.clone(), Some(&dispatched)));
        }
        assert!(load(&journal, &p, &reserved, TransactionState::Indeterminate).is_err());
    }

    #[test]
    fn terminal_restore_is_incompatible_with_commit_and_dual_terminal_history() {
        let (p, _, reserved, dispatched) = fixture();
        let mut journal = Journal::default();
        id(reserved.append(&mut journal, p.clone(), None));
        id(dispatched.append(&mut journal, p.clone(), Some(&reserved)));
        let decision = next(&dispatched, Phase::ConfirmRequested, 120);
        id(decision.append(&mut journal, p.clone(), Some(&dispatched)));
        let restored = next(&decision, Phase::Restored, 220);
        id(restored.append(&mut journal, p.clone(), Some(&decision)));
        assert!(load(&journal, &p, &reserved, TransactionState::RecoveryBlocked).is_ok());
        assert!(load(&journal, &p, &reserved, TransactionState::Indeterminate).is_err());
        assert!(load(&journal, &p, &reserved, TransactionState::Committed).is_err());
        id(next(&decision, Phase::Confirmed, 150).append(&mut journal, p.clone(), Some(&decision)));
        assert!(load(&journal, &p, &reserved, TransactionState::Committed).is_err());
    }
}
