use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Debug, Display, Formatter};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod display;
pub use display::{
    AuthorizedDisplayApplication, AuthorizedDisplayContinuation, DISPLAY_CONFIRMATION_WINDOW_MS,
    DisplayAttemptQuery, DisplayContinuationAction, DisplayDecisionAuthorizer,
    DisplayDecisionChallenge, DisplayTransactionPort, DisplayVerificationTarget,
    IndependentDisplayVerifier, TrustedDisplayDecision,
};

use linura_core::{
    Actor, ActorKind, ApprovalRequestId, OperationClass, OperationId, PlanId, PrincipalId,
    ProviderId, RequestId, ResourceId, RiskClass, SessionLockId, SessionTransition,
    SessionTransitionId,
};
use linura_lifecycle::{MutationProgress, MutationStage};
use linura_policy::{ApprovalClass, PolicyDecision};
use linura_protocol::PlanDesiredStateRequest;
use linura_provider_sdk::{
    ComponentDigest, EffectDescriptor, ExecutionBinding, ExecutionDisposition, ExecutionOutcome,
    VerificationDisposition, VerificationOutcome,
};
use linura_transaction::{
    ApprovedRequestJournal, TransactionId, TransactionState, TransactionStore,
};

use crate::approval_review::PolicyAuthenticatedApprover;
use crate::durable_authority::TrustedRiskFloor;
use crate::operation_registry::{
    MANAGED_DISPLAY_LAYOUT_OPERATION_ID, MANAGED_DISPLAY_LAYOUT_RISK_FLOOR_RULE_ID,
    MANAGED_SESSION_LOCK_RISK_FLOOR_RULE_ID, MANAGED_SESSION_TRANSITION_CAPABILITY,
    MANAGED_SESSION_TRANSITION_PROVIDER, MANAGED_SYSTEMD_CHANGE_KEY,
    MANAGED_SYSTEMD_RESOURCE_PREFIX, MANAGED_SYSTEMD_RESOURCE_SUFFIX,
    MANAGED_SYSTEMD_RISK_FLOOR_RULE_ID, SESSION_TRANSITION_ROUTES,
    trusted_builtin_operation_registry,
};
pub use crate::operation_registry::{
    MANAGED_SESSION_LOCK_CAPABILITY, MANAGED_SESSION_LOCK_OPERATION_ID,
    MANAGED_SESSION_LOCK_PROVIDER, MANAGED_SYSTEMD_CAPABILITY, MANAGED_SYSTEMD_PROVIDER,
    MANAGED_SYSTEMD_REGISTERED_OPERATION_ID, MANAGED_SYSTEMD_UNIT_PREFIX,
};
use crate::policy_review::TrustedPolicyReview;
use crate::{
    AuthenticatedPrincipal, DispatchPermit, DurableAuthorityCandidate, DurableAuthorityControl,
    DurableAuthorityError, DurableRecoveryOutcome, FreshRecoveryApproval,
    OperationSemanticsControl, PlanPreviewControl, PreparedDurableAuthority,
};

pub const MANAGED_SYSTEMD_OPERATION: &str = "set-active-state";
pub const MANAGED_SYSTEMD_INTENT_ORIGIN: &str = "intent:v06:managed-systemd-active-state";
const MANAGED_APPROVAL_TTL_SECONDS: u64 = 300;
const MANAGED_REQUEST_PREFIX: &str = "request:v06:";
const SESSION_REQUEST_PREFIX: &str = "request:v010:session-lock:";
const TRANSITION_REQUEST_PREFIX: &str = "request:v010:session-transition:";
const DISPLAY_REQUEST_PREFIX: &str = "request:v010:display-layout:";
const MAX_OPERATION_ID_BYTES: usize = 64;
const MAX_POST_DISPATCH_VERIFY_ATTEMPTS: usize = 64;
const MAX_POST_DISPATCH_VERIFY_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Clone, Debug, Eq, PartialEq)]
struct ManagedApprovalBinding {
    plan_id: String,
    request_digest: String,
    observation_digest: String,
    review_digest: String,
}

/// Interaction requested by Control after policy review. This projection is
/// neither a policy decision nor proof of approval; adapters cannot manufacture
/// a challenge by selecting one of these values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedApprovalClass {
    InteractiveUser,
    SessionOwnerAuthentication,
    Administrator,
    DestructiveAction,
}

impl From<ApprovalClass> for ManagedApprovalClass {
    fn from(class: ApprovalClass) -> Self {
        match class {
            ApprovalClass::InteractiveUser => Self::InteractiveUser,
            ApprovalClass::SessionOwnerAuthentication => Self::SessionOwnerAuthentication,
            ApprovalClass::Administrator => Self::Administrator,
            ApprovalClass::DestructiveAction => Self::DestructiveAction,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedApprovalChallenge {
    principal: PrincipalId,
    request_id: RequestId,
    plan_id: PlanId,
    request_digest: String,
    observation_digest: String,
    review_digest: String,
    resource: ResourceId,
    change_key: String,
    approval_class: ApprovalClass,
    desired_value: String,
    reason: String,
}

impl ManagedApprovalChallenge {
    /// Linura-owned policy enrollment, NOT an external-effect plan or permit.
    /// The caller is the S17 settings controller after fresh owner/coverage
    /// validation; the distinct purpose cannot reuse lock/unlock/power proof.
    pub(crate) fn protective_setting(
        principal: PrincipalId,
        request: RequestId,
        lock: &SessionLockId,
        enabled: bool,
        digests: (&str, &str, &str),
    ) -> Result<Self, String> {
        Ok(Self {
            principal,
            plan_id: PlanId::new(request.as_str()).map_err(|e| e.to_string())?,
            request_id: request,
            request_digest: digests.0.into(),
            observation_digest: digests.1.into(),
            review_digest: digests.2.into(),
            resource: lock.resource_id().map_err(|e| e.to_string())?,
            change_key: "protective_lock.enabled".into(),
            approval_class: ApprovalClass::SessionOwnerAuthentication,
            desired_value: enabled.to_string(),
            reason: if enabled {
                "Allow protective locking before trusted native suspend during this login. Does not allow unlock or power actions. Protection failure may prevent sleep."
            } else {
                "Revoke protective-lock permission for this login. This does not unlock the session or authorize sleep."
            }.into(),
        })
    }
    fn from_candidate(
        candidate: &DurableAuthorityCandidate,
        request: &PlanDesiredStateRequest,
    ) -> Result<Self, ManagedLifecycleError> {
        let principal = PrincipalId::new(candidate.principal().as_str().to_owned())
            .map_err(|error| ManagedLifecycleError::Contract(error.to_string()))?;
        if candidate.plan_id().as_str() != request.request_id.as_str() {
            return Err(ManagedLifecycleError::Contract(
                "canonical planner changed the request-derived plan identity".into(),
            ));
        }
        let (change_key, desired_value) = managed_desired_attribute(request)?;
        let approval_class = required_approval_for_request(request)?;
        if !matches!(candidate.review().decision(), PolicyDecision::RequireApproval { class, .. } if *class == approval_class)
        {
            return Err(ManagedLifecycleError::ApprovalBoundary(
                "registered effect review has an unexpected approval purpose".into(),
            ));
        }
        Ok(Self {
            principal,
            request_id: request.request_id.clone(),
            plan_id: candidate.plan_id().clone(),
            request_digest: digest_managed_request(request)?,
            observation_digest: candidate.observation_digest().as_str().to_owned(),
            review_digest: candidate.review_digest().as_str().to_owned(),
            resource: request.resource.clone(),
            change_key,
            approval_class,
            desired_value,
            reason: request.reason.summary.clone(),
        })
    }

    fn recovery(
        principal: PrincipalId,
        request: &PlanDesiredStateRequest,
        plan_id: &str,
    ) -> Result<Self, ManagedLifecycleError> {
        let plan_id = PlanId::new(plan_id.to_owned())
            .map_err(|error| ManagedLifecycleError::Contract(error.to_string()))?;
        if plan_id.as_str() != request.request_id.as_str() {
            return Err(ManagedLifecycleError::Contract(
                "durable recovery plan identity differs from the stable request identity".into(),
            ));
        }
        let (change_key, desired_value) = managed_desired_attribute(request)?;
        let approval_class = required_approval_for_request(request)?;
        Ok(Self {
            principal,
            request_id: request.request_id.clone(),
            plan_id,
            request_digest: digest_managed_request(request)?,
            observation_digest: "recovery:fresh-control-revalidation-required".into(),
            review_digest: "recovery:fresh-policy-revalidation-required".into(),
            resource: request.resource.clone(),
            change_key,
            approval_class,
            desired_value,
            reason: request.reason.summary.clone(),
        })
    }

    fn binding(&self) -> ManagedApprovalBinding {
        ManagedApprovalBinding {
            plan_id: self.plan_id.as_str().to_owned(),
            request_digest: self.request_digest.clone(),
            observation_digest: self.observation_digest.clone(),
            review_digest: self.review_digest.clone(),
        }
    }

    #[must_use]
    pub fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    #[must_use]
    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    #[must_use]
    pub fn plan_id(&self) -> &PlanId {
        &self.plan_id
    }

    #[must_use]
    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    #[must_use]
    pub fn observation_digest(&self) -> &str {
        &self.observation_digest
    }

    #[must_use]
    pub fn review_digest(&self) -> &str {
        &self.review_digest
    }

    #[must_use]
    pub fn resource(&self) -> &ResourceId {
        &self.resource
    }

    #[must_use]
    pub fn desired_value(&self) -> &str {
        &self.desired_value
    }

    #[must_use]
    pub fn change_key(&self) -> &str {
        &self.change_key
    }

    #[must_use]
    pub fn approval_class(&self) -> ManagedApprovalClass {
        self.approval_class.into()
    }

    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedHumanApproval {
    principal: PrincipalId,
    binding: Option<ManagedApprovalBinding>,
}

impl TrustedHumanApproval {
    /// Construct a trusted local test/embedding authorizer. Production D-Bus
    /// calls use the candidate-bound Polkit authorizer and never mint this token
    /// before Control has produced a canonical approval challenge.
    #[must_use]
    pub fn from_privileged_local_boundary(principal: PrincipalId) -> Self {
        Self {
            principal,
            binding: None,
        }
    }

    #[must_use]
    pub fn from_authorized_challenge(
        principal: PrincipalId,
        challenge: &ManagedApprovalChallenge,
    ) -> Self {
        Self {
            principal,
            binding: Some(challenge.binding()),
        }
    }

    #[must_use]
    pub fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    pub(crate) fn matches_challenge(&self, challenge: &ManagedApprovalChallenge) -> bool {
        self.principal == *challenge.principal()
            && self.binding.as_ref() == Some(&challenge.binding())
    }
}

pub trait ManagedApprovalAuthorizer: Debug + Send {
    fn authorize(
        &self,
        challenge: &ManagedApprovalChallenge,
    ) -> Result<TrustedHumanApproval, String>;
}

impl ManagedApprovalAuthorizer for TrustedHumanApproval {
    fn authorize(
        &self,
        challenge: &ManagedApprovalChallenge,
    ) -> Result<TrustedHumanApproval, String> {
        if self.principal != *challenge.principal() {
            return Err(
                "trusted local approval principal does not match candidate principal".into(),
            );
        }
        Ok(TrustedHumanApproval::from_authorized_challenge(
            self.principal.clone(),
            challenge,
        ))
    }
}

#[derive(Debug)]
pub struct AuthorizedEffect {
    effect: EffectDescriptor,
    binding: ExecutionBinding,
    permit: DispatchPermit,
}

impl AuthorizedEffect {
    #[must_use]
    pub fn effect(&self) -> &EffectDescriptor {
        &self.effect
    }

    #[must_use]
    pub fn binding(&self) -> &ExecutionBinding {
        &self.binding
    }

    #[must_use]
    pub fn into_executor_request(self) -> (EffectDescriptor, ExecutionBinding) {
        let Self {
            effect,
            binding,
            permit: _permit,
        } = self;
        (effect, binding)
    }
}

pub trait AuthorizedEffectExecutor: Debug + Send {
    fn execute_authorized(
        &mut self,
        authorization: AuthorizedEffect,
    ) -> Result<ExecutionOutcome, String>;
}

pub trait IndependentManagedVerifier: Debug + Send {
    fn verify_effect(&mut self, effect: &EffectDescriptor) -> Result<VerificationOutcome, String>;

    /// Control owns bounded post-dispatch settling. Implementations may request
    /// more than one fresh independent observation for asynchronous native APIs;
    /// Control clamps both values to prevent an adapter from creating an
    /// unbounded authority stall.
    fn post_dispatch_settle_attempts(&self) -> usize {
        1
    }

    fn post_dispatch_settle_interval(&self) -> Duration {
        Duration::ZERO
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedMutationReceipt {
    pub transaction_id: String,
    pub plan_id: String,
    pub resource: String,
    pub change_key: String,
    pub desired_value: String,
    pub effect_digest: String,
    pub dispatch_digest: Option<String>,
    pub execution_disposition: Option<String>,
    pub verification_disposition: String,
    pub final_state: String,
    pub recovered: bool,
    pub stages: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManagedLifecycleError {
    UnsupportedEffect(String),
    InvalidRequestIdentity(String),
    ApprovalBoundary(String),
    Authority(String),
    Executor(String),
    ExecutionRejected(String),
    Verification(String),
    VerificationNotSatisfied(String),
    Indeterminate(String),
    TerminalState(String),
    Reconciliation(String),
    Contract(String),
}

impl Display for ManagedLifecycleError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedEffect(detail) => {
                write!(formatter, "unsupported v0.6 effect: {detail}")
            }
            Self::InvalidRequestIdentity(detail) => {
                write!(formatter, "invalid v0.6 request identity: {detail}")
            }
            Self::ApprovalBoundary(detail) => {
                write!(formatter, "trusted approval boundary failed: {detail}")
            }
            Self::Authority(detail) => write!(formatter, "durable authority failed: {detail}"),
            Self::Executor(detail) => write!(formatter, "privileged executor failed: {detail}"),
            Self::ExecutionRejected(detail) => {
                write!(formatter, "effect was rejected before dispatch: {detail}")
            }
            Self::Verification(detail) => {
                write!(formatter, "independent verification failed: {detail}")
            }
            Self::VerificationNotSatisfied(detail) => write!(
                formatter,
                "independent verification did not prove intended state: {detail}"
            ),
            Self::Indeterminate(detail) => write!(
                formatter,
                "managed mutation remains indeterminate: {detail}"
            ),
            Self::TerminalState(detail) => write!(
                formatter,
                "durable transaction is terminal and cannot be replayed: {detail}"
            ),
            Self::Reconciliation(detail) => {
                write!(formatter, "post-commit reconciliation failed: {detail}")
            }
            Self::Contract(detail) => {
                write!(formatter, "managed lifecycle contract failed: {detail}")
            }
        }
    }
}

impl std::error::Error for ManagedLifecycleError {}

impl From<DurableAuthorityError> for ManagedLifecycleError {
    fn from(error: DurableAuthorityError) -> Self {
        Self::Authority(error.to_string())
    }
}

pub fn managed_request_id(
    operation_id: &str,
    request: &PlanDesiredStateRequest,
) -> Result<RequestId, ManagedLifecycleError> {
    validate_operation_id(operation_id)?;
    let prefix = if request.provider.as_str() == MANAGED_SESSION_LOCK_PROVIDER {
        SESSION_REQUEST_PREFIX
    } else if is_session_transition(request) {
        TRANSITION_REQUEST_PREFIX
    } else if is_display_request(request) {
        DISPLAY_REQUEST_PREFIX
    } else {
        MANAGED_REQUEST_PREFIX
    };
    RequestId::new(format!("{prefix}{operation_id}"))
        .map_err(|error| ManagedLifecycleError::InvalidRequestIdentity(error.to_string()))
}

#[derive(Debug)]
pub struct ManagedLifecycleControl<S>
where
    S: TransactionStore,
{
    previews: PlanPreviewControl,
    operation_semantics: OperationSemanticsControl,
    authority: DurableAuthorityControl<S>,
    request_journal: Option<Box<dyn ApprovedRequestJournal>>,
    protective_settings: Option<crate::ProtectiveLockSettingsControl>,
    display_keep_reviews: BTreeMap<TransactionId, display::RetainedKeepReview>,
}

impl<S> ManagedLifecycleControl<S>
where
    S: TransactionStore,
{
    pub fn new(
        previews: PlanPreviewControl,
        store: S,
        authority_signer: linura_transaction::TransactionAuthoritySigner,
    ) -> Result<Self, ManagedLifecycleError> {
        let registry = trusted_builtin_operation_registry()
            .map_err(|error| ManagedLifecycleError::Contract(error.to_string()))?;
        let operation_semantics = OperationSemanticsControl::from_trusted_registry(registry);
        validate_managed_systemd_registration(&operation_semantics)?;

        Ok(Self {
            previews,
            operation_semantics,
            authority: DurableAuthorityControl::new(store, authority_signer)?,
            request_journal: None,
            protective_settings: None,
            display_keep_reviews: BTreeMap::new(),
        })
    }

    /// Install a validated request-retention port at the trusted composition
    /// root. Required for S17; this does not alter released v0.6 recovery state.
    pub fn with_request_journal(
        mut self,
        journal: Box<dyn ApprovedRequestJournal>,
    ) -> Result<Self, ManagedLifecycleError> {
        journal
            .integrity_check()
            .map_err(|error| ManagedLifecycleError::Authority(error.to_string()))?;
        self.request_journal = Some(journal);
        Ok(self)
    }

    /// Trusted composition installs the separate owner-policy store. Merely
    /// installing it does not activate protective locking or bypass manual policy.
    #[must_use]
    pub fn with_protective_lock_settings(
        mut self,
        settings: crate::ProtectiveLockSettingsControl,
    ) -> Self {
        self.protective_settings = Some(settings);
        self
    }

    pub fn configure_protective_lock(
        &mut self,
        principal: &AuthenticatedPrincipal,
        request: &linura_protocol::ProtectiveLockSettingRequest,
        authorizer: &dyn ManagedApprovalAuthorizer,
    ) -> Result<linura_protocol::ProtectiveLockSettingReceipt, String> {
        self.protective_settings
            .as_mut()
            .ok_or("protective-lock policy store is unavailable")?
            .configure(
                &mut self.previews,
                principal,
                &crate::ProtectiveLockConfigurationRequest {
                    operation_id: request.operation_id.clone(),
                    lock: request.lock.clone(),
                    enabled: request.enabled,
                },
                authorizer,
            )?
            .public_receipt()
    }

    pub fn recorded_protective_lock_setting(
        &self,
        principal: &AuthenticatedPrincipal,
        epoch: &linura_core::SessionEpoch,
    ) -> Result<Option<linura_protocol::ProtectiveLockSettingReceipt>, String> {
        self.protective_settings
            .as_ref()
            .ok_or("protective-lock policy store is unavailable")?
            .recorded_for_epoch(principal, epoch)?
            .map(|receipt| receipt.public_receipt())
            .transpose()
    }

    pub fn protective_lock_setting_request_status(
        &self,
        principal: &AuthenticatedPrincipal,
        request: &RequestId,
    ) -> Result<linura_protocol::ProtectiveLockSettingReceipt, String> {
        self.protective_settings
            .as_ref()
            .ok_or("protective-lock policy store is unavailable")?
            .request_status(principal, request)?
            .public_receipt()
    }

    /// Read historical structured intent only after authenticating both the
    /// journal record and its exact transaction anchor. This method observes
    /// no current state, creates no approval and cannot dispatch or reprepare.
    pub fn retained_session_request(
        &self,
        principal: &AuthenticatedPrincipal,
        request_id: &RequestId,
    ) -> Result<PlanDesiredStateRequest, ManagedLifecycleError> {
        let principal_id = PrincipalId::new(principal.as_str().to_owned())
            .map_err(|error| ManagedLifecycleError::Contract(error.to_string()))?;
        let journal = self.request_journal.as_ref().ok_or_else(|| {
            ManagedLifecycleError::Authority(
                "S17 requires a durable approved structured request journal".into(),
            )
        })?;
        let record = journal
            .load(&principal_id, request_id)
            .map_err(|error| ManagedLifecycleError::Authority(error.to_string()))?;
        if record.principal() != &principal_id || record.request_id() != request_id {
            return Err(ManagedLifecycleError::Authority(
                "retained request namespace mismatch".into(),
            ));
        }
        let request = crate::retained_request::decode(&record)?;
        validate_public_request(&request)?;
        let protective =
            crate::protective_lock_execution::retained_protective_request(principal, &request);
        if !protective {
            validate_request_identity(&request)?;
        }
        let lock = if is_session_transition(&request) {
            SessionTransitionId::from_resource(&request.resource)
                .map(|target| target.lock().clone())
                .map_err(|error| ManagedLifecycleError::Authority(error.to_string()))?
        } else if request.provider.as_str() == MANAGED_SESSION_LOCK_PROVIDER {
            SessionLockId::from_resource(&request.resource)
                .map_err(|error| ManagedLifecycleError::Authority(error.to_string()))?
        } else {
            return Err(ManagedLifecycleError::Authority(
                "retained request is not an S17 request".into(),
            ));
        };
        if !protective && principal.as_str() != format!("unix:uid:{}", lock.epoch().uid()) {
            return Err(ManagedLifecycleError::Authority(
                "retained request is not owned by this session principal".into(),
            ));
        }
        self.authority.assert_request_matches(principal, &request)?;
        Ok(request)
    }

    /// Historical status remains readable after native generation rotation or
    /// owner/session replacement. No observer, approver, verifier or executor
    /// is accepted. Never report this as fresh completion/reconciliation.
    pub fn session_lock_request_status(
        &self,
        principal: &AuthenticatedPrincipal,
        request_id: &RequestId,
    ) -> Result<linura_protocol::SessionLockRequestStatus, ManagedLifecycleError> {
        let request = self.retained_session_request(principal, request_id)?;
        self.authority.integrity_check()?;
        self.request_journal
            .as_ref()
            .ok_or_else(|| ManagedLifecycleError::Authority("S17 journal is unavailable".into()))?
            .integrity_check()
            .map_err(|error| ManagedLifecycleError::Authority(error.to_string()))?;
        let principal_id = PrincipalId::new(principal.as_str())
            .map_err(|error| ManagedLifecycleError::Contract(error.to_string()))?;
        let transaction_id = TransactionId::for_namespace(&principal_id, request_id);
        let snapshot = self.authority.snapshot(&transaction_id)?;
        let (_, desired) = managed_desired_attribute(&request)?;
        Ok(linura_protocol::SessionLockRequestStatus {
            request_id: request_id.clone(),
            transaction_id: transaction_id.as_str().into(),
            lock: SessionLockId::from_resource(&request.resource)
                .map_err(|error| ManagedLifecycleError::Contract(error.to_string()))?,
            secure: match desired.as_str() {
                "true" => true,
                "false" => false,
                _ => {
                    return Err(ManagedLifecycleError::Contract(
                        "retained session desired state is unsupported".into(),
                    ));
                }
            },
            state: snapshot.state.as_str().into(),
        })
    }

    /// Read authenticated historical power/session intent and transaction state.
    /// No live observer or executor is invoked and no completion is inferred.
    pub fn session_transition_request_status(
        &self,
        principal: &AuthenticatedPrincipal,
        request_id: &RequestId,
    ) -> Result<linura_protocol::SessionTransitionRequestStatus, ManagedLifecycleError> {
        let request = self.retained_session_request(principal, request_id)?;
        if !is_session_transition(&request) {
            return Err(ManagedLifecycleError::Contract(
                "retained request is not a session transition".into(),
            ));
        }
        self.authority.integrity_check()?;
        self.request_journal
            .as_ref()
            .ok_or_else(|| ManagedLifecycleError::Authority("S17 journal is unavailable".into()))?
            .integrity_check()
            .map_err(|e| ManagedLifecycleError::Authority(e.to_string()))?;
        let principal_id = PrincipalId::new(principal.as_str())
            .map_err(|e| ManagedLifecycleError::Contract(e.to_string()))?;
        let transaction_id = TransactionId::for_namespace(&principal_id, request_id);
        let snapshot = self.authority.snapshot(&transaction_id)?;
        Ok(linura_protocol::SessionTransitionRequestStatus {
            request_id: request_id.clone(),
            transaction_id: transaction_id.as_str().into(),
            target: SessionTransitionId::from_resource(&request.resource)
                .map_err(|e| ManagedLifecycleError::Contract(e.to_string()))?,
            state: snapshot.state.as_str().into(),
        })
    }

    /// Finish an already-dispatched S17 request from authenticated retained
    /// material and fresh independent native observations only. No approval or
    /// executor port is accepted. Absent/unknown state stays indeterminate; it
    /// can never turn into an automatic request retry or recovered credential.
    pub fn recover_session_request_without_replay<V: IndependentManagedVerifier>(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        request_id: &RequestId,
        verifier: &mut V,
    ) -> Result<ManagedMutationReceipt, ManagedLifecycleError> {
        let request = self.retained_session_request(&principal, request_id)?;
        let principal_id = PrincipalId::new(principal.as_str().to_owned())
            .map_err(|error| ManagedLifecycleError::Contract(error.to_string()))?;
        let transaction_id = TransactionId::for_namespace(&principal_id, request_id);
        let snapshot = self.authority.snapshot(&transaction_id)?;
        if matches!(snapshot.state, TransactionState::Prepared) {
            return Err(ManagedLifecycleError::Indeterminate(
                "prepared request must be retired by trusted restart recovery; it cannot be dispatched".into()));
        }
        if matches!(
            snapshot.state,
            TransactionState::Aborted | TransactionState::RecoveryBlocked
        ) {
            return Err(ManagedLifecycleError::TerminalState(
                "retained request is terminal; no replay is permitted".into(),
            ));
        }
        let effect = effect_from_request(&request)?;
        let verification = verifier
            .verify_effect(&effect)
            .map_err(ManagedLifecycleError::Verification)?;
        if verification.disposition != VerificationDisposition::Satisfied {
            return Err(ManagedLifecycleError::Indeterminate(
                "independent observation did not prove the retained request; no replay was attempted".into()));
        }
        let final_state = match snapshot.state {
            TransactionState::Indeterminate => {
                let risk_floor = self.registered_managed_risk_floor(&request)?;
                match self.authority.recover_indeterminate_without_replay(
                    &mut self.previews, principal.clone(), actor.clone(), request.clone(), risk_floor,
                )? {
                    DurableRecoveryOutcome::Verified(verified) => self.authority.commit_verified(&principal, verified)?.state,
                    DurableRecoveryOutcome::Blocked(_) => return Err(ManagedLifecycleError::TerminalState("fresh native recovery found conflicting state; no replay was attempted".into())),
                    DurableRecoveryOutcome::StillIndeterminate(_) => return Err(ManagedLifecycleError::Indeterminate("fresh Control observation did not prove completion; no replay was attempted".into())),
                    DurableRecoveryOutcome::Reprepared(_) => return Err(ManagedLifecycleError::Authority("observe-only recovery unexpectedly produced prepared authority".into())),
                }
            }
            TransactionState::Verified => {
                let verified = self
                    .authority
                    .resume_verified(&principal, &transaction_id)?;
                self.authority.commit_verified(&principal, verified)?.state
            }
            TransactionState::Committed => TransactionState::Committed,
            TransactionState::Prepared
            | TransactionState::Aborted
            | TransactionState::RecoveryBlocked => {
                return Err(ManagedLifecycleError::Authority(
                    "recovery state changed unexpectedly".into(),
                ));
            }
        };
        let mut progress = progress_through(MutationStage::Commit)?;
        self.authority.integrity_check()?;
        self.request_journal
            .as_ref()
            .ok_or_else(|| {
                ManagedLifecycleError::Authority("S17 journal disappeared during recovery".into())
            })?
            .integrity_check()
            .map_err(|error| ManagedLifecycleError::Authority(error.to_string()))?;
        advance(&mut progress, MutationStage::Audit)?;
        self.reconcile(&principal, &actor, &request, &effect, verifier)?;
        advance(&mut progress, MutationStage::Reconcile)?;
        Ok(receipt(ReceiptContext {
            transaction_id: &transaction_id,
            plan_id: request_id.as_str(),
            effect: &effect,
            execution: None,
            verification: &verification,
            final_state: &final_state,
            recovered: true,
            progress: &progress,
        }))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn converge_systemd_active_state<E, V>(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        request: PlanDesiredStateRequest,
        approval_authorizer: &dyn ManagedApprovalAuthorizer,
        executor: &mut E,
        verifier: &mut V,
    ) -> Result<ManagedMutationReceipt, ManagedLifecycleError>
    where
        E: AuthorizedEffectExecutor,
        V: IndependentManagedVerifier,
    {
        if request.provider.as_str() != MANAGED_SYSTEMD_PROVIDER {
            return Err(ManagedLifecycleError::UnsupportedEffect(
                "systemd entry point accepts only its registered systemd route".into(),
            ));
        }
        self.converge_registered_effect(
            principal,
            actor,
            request,
            approval_authorizer,
            executor,
            verifier,
            None,
        )
    }

    /// Full durable lifecycle for one exact native compositor-lock generation.
    /// Callers cannot select a risk class, approval purpose, or executor payload.
    /// Native ownership/coverage is independently revalidated by the adapters;
    /// this entry point is not a generic effect or authentication bypass.
    #[allow(clippy::too_many_arguments)]
    pub fn converge_session_lock<E, V>(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        request: PlanDesiredStateRequest,
        approval_authorizer: &dyn ManagedApprovalAuthorizer,
        executor: &mut E,
        verifier: &mut V,
    ) -> Result<ManagedMutationReceipt, ManagedLifecycleError>
    where
        E: AuthorizedEffectExecutor,
        V: IndependentManagedVerifier,
    {
        let lock = SessionLockId::from_resource(&request.resource).map_err(|_| {
            ManagedLifecycleError::UnsupportedEffect("native lock identity is not canonical".into())
        })?;
        if request.provider.as_str() != MANAGED_SESSION_LOCK_PROVIDER
            || principal.as_str() != format!("unix:uid:{}", lock.epoch().uid())
        {
            return Err(ManagedLifecycleError::ApprovalBoundary(
                "session-lock caller is not the exact native session owner".into(),
            ));
        }
        if self.request_journal.is_none() {
            return Err(ManagedLifecycleError::Authority(
                "S17 requires a durable approved structured request journal".into(),
            ));
        }
        self.converge_registered_effect(
            principal,
            actor,
            request,
            approval_authorizer,
            executor,
            verifier,
            None,
        )
    }

    /// Protective locking is a distinct authenticated service action, not an
    /// owner impersonation or an approval bypass for ordinary manual actions.
    /// The fixed request is derived from current durable owner consent and one
    /// exact native sleep invocation. An existing transaction is observe-only:
    /// revocation, event completion and owner restart can never cause replay.
    pub fn converge_protective_session_lock<
        E: AuthorizedEffectExecutor,
        V: IndependentManagedVerifier,
    >(
        &mut self,
        principal: AuthenticatedPrincipal,
        event: linura_core::SleepInvocationId,
        lock: SessionLockId,
        executor: &mut E,
        verifier: &mut V,
    ) -> Result<ManagedMutationReceipt, ManagedLifecycleError> {
        if principal.as_str() != linura_policy::PROTECTIVE_SLEEP_PRINCIPAL {
            return Err(ManagedLifecycleError::ApprovalBoundary(
                "protective locking requires the authenticated sleep service".into(),
            ));
        }
        let actor = crate::protective_lock_execution::protective_actor()
            .map_err(ManagedLifecycleError::Contract)?;
        let request_id = event
            .protective_request_id(lock.epoch())
            .map_err(|e| ManagedLifecycleError::Contract(e.to_string()))?;
        let principal_id = PrincipalId::new(principal.as_str())
            .map_err(|e| ManagedLifecycleError::Contract(e.to_string()))?;
        let transaction_id = TransactionId::for_namespace(&principal_id, &request_id);
        match self.authority.snapshot(&transaction_id) {
            Ok(_) => {
                let retained = self.retained_session_request(&principal, &request_id)?;
                if retained.resource
                    != lock
                        .resource_id()
                        .map_err(|e| ManagedLifecycleError::Contract(e.to_string()))?
                {
                    return Err(ManagedLifecycleError::Authority(
                        "protective retry cannot replace the retained native lock generation"
                            .into(),
                    ));
                }
                return self.recover_session_request_without_replay(
                    principal,
                    actor,
                    &request_id,
                    verifier,
                );
            }
            Err(DurableAuthorityError::Transaction(detail))
                if detail == "durable transaction not found" => {}
            Err(error) => return Err(error.into()),
        }
        if self.request_journal.is_none() {
            return Err(ManagedLifecycleError::Authority(
                "S17 requires a durable approved structured request journal".into(),
            ));
        }
        let settings = self.protective_settings.as_ref().ok_or_else(|| {
            ManagedLifecycleError::Authority("protective-lock policy store is unavailable".into())
        })?;
        let context = crate::protective_lock_execution::ProtectiveLockContext::from_current(
            settings, event, lock,
        )
        .map_err(ManagedLifecycleError::Authority)?;
        let request = context.request().map_err(ManagedLifecycleError::Contract)?;
        self.converge_registered_effect(
            principal,
            actor,
            request,
            &crate::protective_lock_execution::NoInteractiveProtectiveApproval,
            executor,
            verifier,
            Some(context),
        )
    }

    /// A one-shot exact transition uses the same durable authority lifecycle.
    /// No resume/retry path may redispatch a possibly executed power operation.
    #[allow(clippy::too_many_arguments)]
    pub fn converge_session_transition<
        E: AuthorizedEffectExecutor,
        V: IndependentManagedVerifier,
    >(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        request: PlanDesiredStateRequest,
        approval_authorizer: &dyn ManagedApprovalAuthorizer,
        executor: &mut E,
        verifier: &mut V,
    ) -> Result<ManagedMutationReceipt, ManagedLifecycleError> {
        let target = SessionTransitionId::from_resource(&request.resource)
            .map_err(|error| ManagedLifecycleError::UnsupportedEffect(error.to_string()))?;
        if !is_session_transition(&request)
            || principal.as_str() != format!("unix:uid:{}", target.lock().epoch().uid())
        {
            return Err(ManagedLifecycleError::ApprovalBoundary(
                "transition requires the exact authenticated session owner".into(),
            ));
        }
        if self.request_journal.is_none() {
            return Err(ManagedLifecycleError::Authority(
                "S17 requires a durable approved structured request journal".into(),
            ));
        }
        self.converge_registered_effect(
            principal,
            actor,
            request,
            approval_authorizer,
            executor,
            verifier,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn converge_registered_effect<E, V>(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        request: PlanDesiredStateRequest,
        approval_authorizer: &dyn ManagedApprovalAuthorizer,
        executor: &mut E,
        verifier: &mut V,
        protective: Option<crate::protective_lock_execution::ProtectiveLockContext>,
    ) -> Result<ManagedMutationReceipt, ManagedLifecycleError>
    where
        E: AuthorizedEffectExecutor,
        V: IndependentManagedVerifier,
    {
        validate_public_request(&request)?;
        if let Some(context) = &protective {
            context
                .require_request(&principal, &actor, &request)
                .map_err(ManagedLifecycleError::ApprovalBoundary)?;
        } else {
            validate_request_identity(&request)?;
            if actor.kind != ActorKind::Human || !actor.interactive {
                return Err(ManagedLifecycleError::ApprovalBoundary(
                    "v0.6 managed mutation requires an authenticated interactive human actor"
                        .into(),
                ));
            }
        }

        let principal_id = PrincipalId::new(principal.as_str().to_owned())
            .map_err(|error| ManagedLifecycleError::Contract(error.to_string()))?;
        let transaction_id = TransactionId::for_namespace(&principal_id, &request.request_id);
        let effect = effect_from_request(&request)?;

        match self.authority.snapshot(&transaction_id) {
            Ok(_) => {
                if protective.is_some() {
                    return self.recover_session_request_without_replay(
                        principal,
                        actor,
                        &request.request_id,
                        verifier,
                    );
                }
                return self.resume_existing(
                    principal,
                    actor,
                    request,
                    approval_authorizer,
                    effect,
                    transaction_id,
                    executor,
                    verifier,
                );
            }
            Err(DurableAuthorityError::Transaction(detail))
                if detail == "durable transaction not found" => {}
            Err(error) => return Err(error.into()),
        }

        let risk_floor = self.registered_managed_risk_floor(&request)?;
        let candidate_result = if let Some(context) = &protective {
            self.authority.protective_candidate(
                &mut self.previews,
                principal.clone(),
                actor.clone(),
                context.clone(),
                risk_floor,
            )
        } else {
            self.authority.candidate_with_risk_floor(
                &mut self.previews,
                principal.clone(),
                actor.clone(),
                request.clone(),
                risk_floor,
            )
        };
        let candidate = match candidate_result {
            Ok(candidate) => candidate,
            Err(DurableAuthorityError::CandidateNotMutation) => {
                return Err(ManagedLifecycleError::UnsupportedEffect(
                    "requested state already holds; no external effect is necessary".into(),
                ));
            }
            Err(error) => return Err(error.into()),
        };
        self.validate_registered_managed_candidate(&candidate)?;
        let canonical_effect = effect_from_candidate(&candidate)?;
        if canonical_effect != effect {
            return Err(ManagedLifecycleError::Contract(
                "trusted plan effect differs from the exact public request effect".into(),
            ));
        }
        if candidate.plan_id().as_str() != request.request_id.as_str() {
            return Err(ManagedLifecycleError::Contract(
                "canonical planner changed the request-derived plan identity".into(),
            ));
        }

        let human_approver = if protective.is_some() && candidate.is_protective() {
            if candidate.review().decision() != &PolicyDecision::Allow {
                return Err(ManagedLifecycleError::ApprovalBoundary(
                    "protective lock policy did not authorize the exact current invocation".into(),
                ));
            }
            None
        } else {
            self.authorize_candidate(&candidate, &request, approval_authorizer)?
        };
        let (candidate, approval_evidence_id) = if let Some(approver) = human_approver {
            let refreshed = self.refresh_candidate_after_approval(
                &candidate,
                principal.clone(),
                actor.clone(),
                request.clone(),
                &effect,
            )?;
            let approval_request =
                ApprovalRequestId::new(format!("approval:v06:{}", refreshed.plan_id().as_str()))
                    .map_err(|error| ManagedLifecycleError::Contract(error.to_string()))?;
            let expires_at = now_unix_seconds()?
                .checked_add(MANAGED_APPROVAL_TTL_SECONDS)
                .ok_or_else(|| ManagedLifecycleError::Contract("approval clock overflow".into()))?;
            let evidence = self.authority.issue_approval(
                approval_request,
                &refreshed,
                &approver,
                expires_at,
            )?;
            (refreshed, Some(evidence.id().clone()))
        } else {
            (candidate, None)
        };
        if request.provider.as_str() == MANAGED_SESSION_LOCK_PROVIDER
            || is_session_transition(&request)
        {
            let retained = crate::retained_request::encode(principal_id, &request)?;
            if retained.digest() != &crate::durable_authority::digest_request(&request)? {
                return Err(ManagedLifecycleError::Authority(
                    "retained request digest drift".into(),
                ));
            }
            self.request_journal
                .as_mut()
                .ok_or_else(|| {
                    ManagedLifecycleError::Authority("S17 request journal is unavailable".into())
                })?
                .retain(&retained)
                .map_err(|error| ManagedLifecycleError::Authority(error.to_string()))?;
        }
        let mut prepared = if protective.is_some() {
            let settings = self.protective_settings.as_ref().ok_or_else(|| {
                ManagedLifecycleError::Authority(
                    "protective-lock policy store is unavailable".into(),
                )
            })?;
            self.authority
                .prepare_protective(candidate, &mut self.previews, settings)?
        } else {
            self.authority.prepare(candidate, approval_evidence_id)?
        };

        let mut progress = MutationProgress::new();
        advance(&mut progress, MutationStage::Observe)?;
        advance(&mut progress, MutationStage::Plan)?;
        advance(&mut progress, MutationStage::Validate)?;
        advance(&mut progress, MutationStage::Authorize)?;
        advance(&mut progress, MutationStage::Prepare)?;

        let plan_id = prepared.binding().plan_id().as_str().to_owned();
        let permit = if protective.is_some() {
            self.validate_registered_managed_plan(
                prepared.plan(),
                prepared.binding().trusted_risk(),
            )?;
            let settings = self.protective_settings.as_ref().ok_or_else(|| {
                ManagedLifecycleError::Authority(
                    "protective-lock policy store is unavailable".into(),
                )
            })?;
            self.authority.handoff_protective(
                &principal,
                &mut prepared,
                &mut self.previews,
                settings,
            )?
        } else {
            self.handoff_registered_managed(&principal, &mut prepared)?
        };
        let authorization = authorized_effect(effect.clone(), permit)?;
        let dispatch_digest = authorization.binding().dispatch_digest.to_hex();
        let execution = executor
            .execute_authorized(authorization)
            .map_err(ManagedLifecycleError::Executor)?;
        if execution.dispatch_digest.to_hex() != dispatch_digest {
            return Err(ManagedLifecycleError::Contract(
                "executor returned a dispatch digest different from the authorized handoff".into(),
            ));
        }
        match execution.disposition {
            ExecutionDisposition::RejectedBeforeDispatch => {
                return Err(ManagedLifecycleError::ExecutionRejected(execution.detail));
            }
            ExecutionDisposition::Dispatched | ExecutionDisposition::Indeterminate => {
                advance(&mut progress, MutationStage::Execute)?;
            }
        }

        let verification = verify_after_dispatch(verifier, &effect)?;
        match verification.disposition {
            VerificationDisposition::Satisfied => advance(&mut progress, MutationStage::Verify)?,
            VerificationDisposition::NotSatisfied => {
                return Err(ManagedLifecycleError::VerificationNotSatisfied(
                    verification.detail,
                ));
            }
            VerificationDisposition::Inconclusive => {
                return Err(ManagedLifecycleError::Indeterminate(verification.detail));
            }
        }

        let recovery = if request.provider.as_str() == MANAGED_SESSION_LOCK_PROVIDER
            || is_session_transition(&request)
        {
            self.authority.recover_indeterminate_without_replay(
                &mut self.previews,
                principal.clone(),
                actor.clone(),
                request.clone(),
                risk_floor,
            )?
        } else {
            self.authority.recover_indeterminate_with_risk_floor(
                &mut self.previews,
                principal.clone(),
                actor.clone(),
                request.clone(),
                None,
                risk_floor,
            )?
        };
        let verified = match recovery {
            DurableRecoveryOutcome::Verified(verified) => verified,
            DurableRecoveryOutcome::Reprepared(_) => {
                return Err(ManagedLifecycleError::Indeterminate(
                    "state changed after independent verification; authority was reprepared and requires a new explicit invocation"
                        .into(),
                ));
            }
            DurableRecoveryOutcome::Blocked(snapshot) => {
                return Err(ManagedLifecycleError::TerminalState(format!(
                    "recovery blocked transaction {}",
                    snapshot.transaction_id.as_str()
                )));
            }
            DurableRecoveryOutcome::StillIndeterminate(snapshot) => {
                return Err(ManagedLifecycleError::Indeterminate(format!(
                    "transaction {} remains indeterminate after verification",
                    snapshot.transaction_id.as_str()
                )));
            }
        };
        let committed = self.authority.commit_verified(&principal, verified)?;
        advance(&mut progress, MutationStage::Commit)?;
        self.authority.integrity_check()?;
        advance(&mut progress, MutationStage::Audit)?;
        self.reconcile(&principal, &actor, &request, &effect, verifier)?;
        advance(&mut progress, MutationStage::Reconcile)?;

        Ok(receipt(ReceiptContext {
            transaction_id: &transaction_id,
            plan_id: &plan_id,
            effect: &effect,
            execution: Some(&execution),
            verification: &verification,
            final_state: &committed.state,
            recovered: false,
            progress: &progress,
        }))
    }

    #[allow(clippy::too_many_arguments)]
    fn resume_existing<E, V>(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        request: PlanDesiredStateRequest,
        approval_authorizer: &dyn ManagedApprovalAuthorizer,
        effect: EffectDescriptor,
        transaction_id: TransactionId,
        executor: &mut E,
        verifier: &mut V,
    ) -> Result<ManagedMutationReceipt, ManagedLifecycleError>
    where
        E: AuthorizedEffectExecutor,
        V: IndependentManagedVerifier,
    {
        self.authority
            .assert_request_matches(&principal, &request)?;
        if (request.provider.as_str() == MANAGED_SESSION_LOCK_PROVIDER
            || is_session_transition(&request))
            && self.retained_session_request(&principal, &request.request_id)? != request
        {
            return Err(ManagedLifecycleError::Authority(
                "retained request differs from retry".into(),
            ));
        }
        let snapshot = self.authority.snapshot(&transaction_id)?;
        let plan_id = request.request_id.as_str().to_owned();
        match snapshot.state {
            TransactionState::Prepared => Err(ManagedLifecycleError::Indeterminate(format!(
                "{} is still prepared after a failed pre-dispatch authority use; restart the trusted control composition root so restart recovery can retire it before retry",
                transaction_id.as_str()
            ))),
            // A client repeating Converge is not a different recovery policy.
            // Session lock/unlock/power can never enter the older systemd recovery
            // path that may reprepare and dispatch an approved retry.
            TransactionState::Indeterminate
                if request.provider.as_str() == MANAGED_SESSION_LOCK_PROVIDER
                    || is_session_transition(&request) =>
            {
                self.recover_session_request_without_replay(
                    principal,
                    actor,
                    &request.request_id,
                    verifier,
                )
            }
            TransactionState::Indeterminate => self.finish_indeterminate(
                principal,
                actor,
                request,
                approval_authorizer,
                effect,
                transaction_id,
                plan_id,
                executor,
                verifier,
            ),
            TransactionState::Verified => {
                let verification = verifier
                    .verify_effect(&effect)
                    .map_err(ManagedLifecycleError::Verification)?;
                if verification.disposition != VerificationDisposition::Satisfied {
                    return Err(ManagedLifecycleError::Indeterminate(format!(
                        "verified durable state is not independently re-proven: {}",
                        verification.detail
                    )));
                }
                let verified = self
                    .authority
                    .resume_verified(&principal, &transaction_id)?;
                let committed = self.authority.commit_verified(&principal, verified)?;
                let mut progress = progress_through(MutationStage::Commit)?;
                self.authority.integrity_check()?;
                advance(&mut progress, MutationStage::Audit)?;
                self.reconcile(&principal, &actor, &request, &effect, verifier)?;
                advance(&mut progress, MutationStage::Reconcile)?;
                Ok(receipt(ReceiptContext {
                    transaction_id: &transaction_id,
                    plan_id: &plan_id,
                    effect: &effect,
                    execution: None,
                    verification: &verification,
                    final_state: &committed.state,
                    recovered: true,
                    progress: &progress,
                }))
            }
            TransactionState::Committed => {
                let verification = verifier
                    .verify_effect(&effect)
                    .map_err(ManagedLifecycleError::Verification)?;
                if verification.disposition != VerificationDisposition::Satisfied {
                    return Err(ManagedLifecycleError::Reconciliation(format!(
                        "committed state no longer satisfies its managed postcondition: {}. Use a new operation id to authorize a new convergence.",
                        verification.detail
                    )));
                }
                let mut progress = progress_through(MutationStage::Commit)?;
                self.authority.integrity_check()?;
                advance(&mut progress, MutationStage::Audit)?;
                self.reconcile(&principal, &actor, &request, &effect, verifier)?;
                advance(&mut progress, MutationStage::Reconcile)?;
                Ok(receipt(ReceiptContext {
                    transaction_id: &transaction_id,
                    plan_id: &plan_id,
                    effect: &effect,
                    execution: None,
                    verification: &verification,
                    final_state: &snapshot.state,
                    recovered: true,
                    progress: &progress,
                }))
            }
            TransactionState::Aborted | TransactionState::RecoveryBlocked => {
                Err(ManagedLifecycleError::TerminalState(format!(
                    "{} is {}; use a new operation id after reviewing durable evidence",
                    transaction_id.as_str(),
                    snapshot.state.as_str()
                )))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_indeterminate<E, V>(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        request: PlanDesiredStateRequest,
        approval_authorizer: &dyn ManagedApprovalAuthorizer,
        effect: EffectDescriptor,
        transaction_id: TransactionId,
        plan_id: String,
        executor: &mut E,
        verifier: &mut V,
    ) -> Result<ManagedMutationReceipt, ManagedLifecycleError>
    where
        E: AuthorizedEffectExecutor,
        V: IndependentManagedVerifier,
    {
        let verification = verifier
            .verify_effect(&effect)
            .map_err(ManagedLifecycleError::Verification)?;

        if verification.disposition == VerificationDisposition::Inconclusive {
            return Err(ManagedLifecycleError::Indeterminate(verification.detail));
        }

        let recovery = if verification.disposition == VerificationDisposition::NotSatisfied {
            let principal_id = PrincipalId::new(principal.as_str().to_owned())
                .map_err(|error| ManagedLifecycleError::Contract(error.to_string()))?;
            let challenge = ManagedApprovalChallenge::recovery(principal_id, &request, &plan_id)?;
            let approval = approval_authorizer
                .authorize(&challenge)
                .map_err(ManagedLifecycleError::ApprovalBoundary)?;
            if !approval.matches_challenge(&challenge) {
                return Err(ManagedLifecycleError::ApprovalBoundary(
                    "recovery administrator approval is not bound to the exact durable request"
                        .into(),
                ));
            }
            let approver = PolicyAuthenticatedApprover::new(
                approval.principal().clone(),
                ActorKind::Human,
                BTreeSet::from([challenge.approval_class]),
            );
            let approval_request = ApprovalRequestId::new(format!(
                "approval:v06:recovery:{}",
                request.request_id.as_str()
            ))
            .map_err(|error| ManagedLifecycleError::Contract(error.to_string()))?;
            let expires_at = now_unix_seconds()?
                .checked_add(MANAGED_APPROVAL_TTL_SECONDS)
                .ok_or_else(|| ManagedLifecycleError::Contract("approval clock overflow".into()))?;
            let risk_floor = self.registered_managed_risk_floor(&request)?;
            self.authority
                .recover_indeterminate_with_approver_and_risk_floor(
                    &mut self.previews,
                    principal.clone(),
                    actor.clone(),
                    request.clone(),
                    FreshRecoveryApproval::new(approval_request, approver, expires_at),
                    risk_floor,
                )?
        } else {
            let risk_floor = self.registered_managed_risk_floor(&request)?;
            self.authority.recover_indeterminate_with_risk_floor(
                &mut self.previews,
                principal.clone(),
                actor.clone(),
                request.clone(),
                None,
                risk_floor,
            )?
        };

        match recovery {
            DurableRecoveryOutcome::Verified(verified) => {
                if verification.disposition != VerificationDisposition::Satisfied {
                    return Err(ManagedLifecycleError::Indeterminate(
                        "fresh Control observation reached intended state after the independent verifier did not; durable state is verified but commit is withheld until a later independent re-verification"
                            .into(),
                    ));
                }
                let committed = self.authority.commit_verified(&principal, verified)?;
                let mut progress = progress_through(MutationStage::Commit)?;
                self.authority.integrity_check()?;
                advance(&mut progress, MutationStage::Audit)?;
                self.reconcile(&principal, &actor, &request, &effect, verifier)?;
                advance(&mut progress, MutationStage::Reconcile)?;
                Ok(receipt(ReceiptContext {
                    transaction_id: &transaction_id,
                    plan_id: &plan_id,
                    effect: &effect,
                    execution: None,
                    verification: &verification,
                    final_state: &committed.state,
                    recovered: true,
                    progress: &progress,
                }))
            }
            DurableRecoveryOutcome::Reprepared(prepared) => self.execute_reprepared(
                principal,
                actor,
                request,
                effect,
                transaction_id,
                prepared,
                executor,
                verifier,
            ),
            DurableRecoveryOutcome::Blocked(snapshot) => {
                Err(ManagedLifecycleError::TerminalState(format!(
                    "recovery found conflicting state and blocked {}",
                    snapshot.transaction_id.as_str()
                )))
            }
            DurableRecoveryOutcome::StillIndeterminate(snapshot) => {
                Err(ManagedLifecycleError::Indeterminate(format!(
                    "{} remains indeterminate; no replay was attempted",
                    snapshot.transaction_id.as_str()
                )))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_reprepared<E, V>(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        request: PlanDesiredStateRequest,
        effect: EffectDescriptor,
        transaction_id: TransactionId,
        mut prepared: Box<PreparedDurableAuthority>,
        executor: &mut E,
        verifier: &mut V,
    ) -> Result<ManagedMutationReceipt, ManagedLifecycleError>
    where
        E: AuthorizedEffectExecutor,
        V: IndependentManagedVerifier,
    {
        let plan_id = prepared.binding().plan_id().as_str().to_owned();
        if plan_id != request.request_id.as_str() {
            return Err(ManagedLifecycleError::Contract(
                "reprepared authority changed the stable request-derived plan identity".into(),
            ));
        }

        let mut progress = progress_through(MutationStage::Prepare)?;
        let permit = self.handoff_registered_managed(&principal, prepared.as_mut())?;
        let authorization = authorized_effect(effect.clone(), permit)?;
        let dispatch_digest = authorization.binding().dispatch_digest.to_hex();
        let execution = executor
            .execute_authorized(authorization)
            .map_err(ManagedLifecycleError::Executor)?;
        if execution.dispatch_digest.to_hex() != dispatch_digest {
            return Err(ManagedLifecycleError::Contract(
                "executor returned a dispatch digest different from the reprepared authorized handoff"
                    .into(),
            ));
        }
        match execution.disposition {
            ExecutionDisposition::RejectedBeforeDispatch => {
                return Err(ManagedLifecycleError::ExecutionRejected(execution.detail));
            }
            ExecutionDisposition::Dispatched | ExecutionDisposition::Indeterminate => {
                advance(&mut progress, MutationStage::Execute)?;
            }
        }

        let verification = verify_after_dispatch(verifier, &effect)?;
        match verification.disposition {
            VerificationDisposition::Satisfied => advance(&mut progress, MutationStage::Verify)?,
            VerificationDisposition::NotSatisfied => {
                return Err(ManagedLifecycleError::VerificationNotSatisfied(
                    verification.detail,
                ));
            }
            VerificationDisposition::Inconclusive => {
                return Err(ManagedLifecycleError::Indeterminate(verification.detail));
            }
        }

        let risk_floor = self.registered_managed_risk_floor(&request)?;
        let verified = match self.authority.recover_indeterminate_with_risk_floor(
            &mut self.previews,
            principal.clone(),
            actor.clone(),
            request.clone(),
            None,
            risk_floor,
        )? {
            DurableRecoveryOutcome::Verified(verified) => verified,
            DurableRecoveryOutcome::Reprepared(_) => {
                return Err(ManagedLifecycleError::Indeterminate(
                    "fresh Control evidence changed again after the recovery dispatch; no further dispatch was attempted"
                        .into(),
                ));
            }
            DurableRecoveryOutcome::Blocked(snapshot) => {
                return Err(ManagedLifecycleError::TerminalState(format!(
                    "recovery dispatch was blocked for transaction {}",
                    snapshot.transaction_id.as_str()
                )));
            }
            DurableRecoveryOutcome::StillIndeterminate(snapshot) => {
                return Err(ManagedLifecycleError::Indeterminate(format!(
                    "transaction {} remains indeterminate after recovery dispatch",
                    snapshot.transaction_id.as_str()
                )));
            }
        };

        let committed = self.authority.commit_verified(&principal, verified)?;
        advance(&mut progress, MutationStage::Commit)?;
        self.authority.integrity_check()?;
        advance(&mut progress, MutationStage::Audit)?;
        self.reconcile(&principal, &actor, &request, &effect, verifier)?;
        advance(&mut progress, MutationStage::Reconcile)?;

        Ok(receipt(ReceiptContext {
            transaction_id: &transaction_id,
            plan_id: &plan_id,
            effect: &effect,
            execution: Some(&execution),
            verification: &verification,
            final_state: &committed.state,
            recovered: true,
            progress: &progress,
        }))
    }

    fn authorize_candidate(
        &mut self,
        candidate: &DurableAuthorityCandidate,
        request: &PlanDesiredStateRequest,
        approval_authorizer: &dyn ManagedApprovalAuthorizer,
    ) -> Result<Option<PolicyAuthenticatedApprover>, ManagedLifecycleError> {
        match candidate.review().decision() {
            PolicyDecision::Allow => Err(ManagedLifecycleError::ApprovalBoundary(
                "registered protected effect requires purpose-bound human approval".into(),
            )),
            PolicyDecision::RequireApproval { class, .. } => {
                if *class != required_approval_for_request(request)? {
                    return Err(ManagedLifecycleError::ApprovalBoundary(format!(
                        "v0.6 narrow effect requires unsupported approval class {class:?}"
                    )));
                }
                let challenge = ManagedApprovalChallenge::from_candidate(candidate, request)?;
                let approval = approval_authorizer
                    .authorize(&challenge)
                    .map_err(ManagedLifecycleError::ApprovalBoundary)?;
                if !approval.matches_challenge(&challenge) {
                    return Err(ManagedLifecycleError::ApprovalBoundary(
                        "administrator approval is not bound to the exact reviewed candidate"
                            .into(),
                    ));
                }
                Ok(Some(PolicyAuthenticatedApprover::new(
                    approval.principal().clone(),
                    ActorKind::Human,
                    BTreeSet::from([*class]),
                )))
            }
            PolicyDecision::Deny { reason } | PolicyDecision::Blocked { reason } => {
                Err(ManagedLifecycleError::ApprovalBoundary(reason.clone()))
            }
        }
    }

    fn refresh_candidate_after_approval(
        &mut self,
        approved: &DurableAuthorityCandidate,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        request: PlanDesiredStateRequest,
        effect: &EffectDescriptor,
    ) -> Result<DurableAuthorityCandidate, ManagedLifecycleError> {
        let approved_challenge = ManagedApprovalChallenge::from_candidate(approved, &request)?;
        let risk_floor = self.registered_managed_risk_floor(&request)?;
        let refreshed = match self.authority.candidate_with_risk_floor(
            &mut self.previews,
            principal,
            actor,
            request.clone(),
            risk_floor,
        ) {
            Ok(candidate) => candidate,
            Err(DurableAuthorityError::CandidateNotMutation) => {
                return Err(ManagedLifecycleError::ApprovalBoundary(
                    "approved mutation is no longer required after administrator interaction"
                        .into(),
                ));
            }
            Err(error) => return Err(error.into()),
        };
        self.validate_registered_managed_candidate(&refreshed)?;
        let refreshed_challenge = ManagedApprovalChallenge::from_candidate(&refreshed, &request)?;
        let semantics_unchanged = approved_challenge.principal == refreshed_challenge.principal
            && approved_challenge.request_id == refreshed_challenge.request_id
            && approved_challenge.plan_id == refreshed_challenge.plan_id
            && approved_challenge.request_digest == refreshed_challenge.request_digest
            && approved_challenge.resource == refreshed_challenge.resource
            && approved_challenge.change_key == refreshed_challenge.change_key
            && approved_challenge.approval_class == refreshed_challenge.approval_class
            && approved_challenge.desired_value == refreshed_challenge.desired_value
            && approved_challenge.reason == refreshed_challenge.reason
            && review_semantics_unchanged(approved.review(), refreshed.review())
            && effect_from_candidate(&refreshed)? == *effect;
        if !semantics_unchanged {
            return Err(ManagedLifecycleError::ApprovalBoundary(
                "authority semantics changed during administrator interaction; a fresh explicit approval is required"
                    .into(),
            ));
        }
        Ok(refreshed)
    }

    fn registered_managed_risk_floor(
        &self,
        request: &PlanDesiredStateRequest,
    ) -> Result<TrustedRiskFloor, ManagedLifecycleError> {
        let _ = effect_from_request(request)?;
        let (registered_id, floor_rule) = registered_route(
            request.provider.as_str(),
            request.observation_capability.as_str(),
            &request.resource,
        )?;
        let operation_id = OperationId::new(registered_id)
            .map_err(|error| ManagedLifecycleError::Contract(error.to_string()))?;
        let risk = self
            .operation_semantics
            .descriptor(&operation_id)
            .and_then(|descriptor| descriptor.risk_floor())
            .ok_or_else(|| {
                ManagedLifecycleError::Contract(
                    "registered managed-systemd operation is missing its trusted risk floor".into(),
                )
            })?;
        Ok(TrustedRiskFloor::new(risk, floor_rule))
    }

    fn validate_registered_managed_candidate(
        &self,
        candidate: &DurableAuthorityCandidate,
    ) -> Result<(), ManagedLifecycleError> {
        self.validate_registered_managed_plan(
            candidate.plan(),
            candidate.review().subject().prospective_risk(),
        )
    }

    fn validate_registered_managed_plan(
        &self,
        plan: &linura_planner::ReconciliationPlan,
        bound_risk: RiskClass,
    ) -> Result<(), ManagedLifecycleError> {
        let (registered_id, _) = registered_route(
            plan.provider.as_str(),
            plan.observation_capability.as_str(),
            &plan.resource,
        )?;
        let operation_id = OperationId::new(registered_id)
            .map_err(|error| ManagedLifecycleError::Contract(error.to_string()))?;
        let semantics = self
            .operation_semantics
            .resolve_external(&operation_id, plan)
            .map_err(|error| {
                ManagedLifecycleError::Contract(format!(
                    "registered managed-systemd operation rejected canonical plan: {error:?}"
                ))
            })?;
        if semantics.risk() != bound_risk {
            return Err(ManagedLifecycleError::Contract(format!(
                "registered managed-systemd risk {:?} is not bound into reviewed/durable authority risk {:?}",
                semantics.risk(),
                bound_risk
            )));
        }
        if !semantics.requires_durable_managed_lifecycle()
            || !semantics.permits_privileged_executor()
        {
            return Err(ManagedLifecycleError::Contract(
                "registered managed-systemd operation is not bound to the managed privileged lifecycle"
                    .into(),
            ));
        }
        Ok(())
    }

    fn handoff_registered_managed(
        &mut self,
        principal: &AuthenticatedPrincipal,
        prepared: &mut PreparedDurableAuthority,
    ) -> Result<DispatchPermit, ManagedLifecycleError> {
        self.validate_registered_managed_plan(prepared.plan(), prepared.binding().trusted_risk())?;
        self.authority
            .handoff(principal, prepared)
            .map_err(Into::into)
    }

    fn reconcile<V>(
        &mut self,
        principal: &AuthenticatedPrincipal,
        actor: &Actor,
        request: &PlanDesiredStateRequest,
        effect: &EffectDescriptor,
        verifier: &mut V,
    ) -> Result<(), ManagedLifecycleError>
    where
        V: IndependentManagedVerifier,
    {
        let verification = verifier
            .verify_effect(effect)
            .map_err(ManagedLifecycleError::Verification)?;
        if verification.disposition != VerificationDisposition::Satisfied {
            return Err(ManagedLifecycleError::Reconciliation(verification.detail));
        }
        let candidate =
            if crate::protective_lock_execution::retained_protective_request(principal, request) {
                self.previews.protective_recovery_candidate(
                    principal.clone(),
                    actor.clone(),
                    request.clone(),
                )
            } else {
                self.previews
                    .authority_candidate(principal.clone(), actor.clone(), request.clone())
            };
        let (plan, observation) =
            candidate.map_err(|error| ManagedLifecycleError::Reconciliation(error.to_string()))?;
        observation
            .validate(&plan.provider, &plan.resource, &plan.observation_capability)
            .map_err(|error| ManagedLifecycleError::Reconciliation(error.to_string()))?;
        if plan.status != linura_planner::PlanStatus::NoChange || !plan.changes.is_empty() {
            return Err(ManagedLifecycleError::Reconciliation(
                "fresh authoritative planning does not converge to no-change".into(),
            ));
        }
        Ok(())
    }
}

/// Compare the approval-relevant semantics of two trusted policy reviews while
/// deliberately excluding only the ephemeral observation-evidence identifier.
/// The exact fresh observation remains independently bound into durable authority
/// through its observation digest; human approval is transferable across the
/// interaction boundary only when the reviewed mutation itself is unchanged.
pub(crate) fn review_semantics_unchanged(
    left: &TrustedPolicyReview,
    right: &TrustedPolicyReview,
) -> bool {
    let left_subject = left.subject();
    let right_subject = right.subject();
    let left_binding = left.binding();
    let right_binding = right.binding();

    left_subject.principal() == right_subject.principal()
        && left_subject.plan_id() == right_subject.plan_id()
        && left_subject.request_id() == right_subject.request_id()
        && left_subject.actor() == right_subject.actor()
        && left_subject.provider() == right_subject.provider()
        && left_subject.resource() == right_subject.resource()
        && left_subject.capability() == right_subject.capability()
        && left_subject.reason() == right_subject.reason()
        && left_subject.prospective_risk() == right_subject.prospective_risk()
        && left_subject.status() == right_subject.status()
        && left_subject.changes() == right_subject.changes()
        && review_findings_unchanged(left_subject, right_subject)
        && left_binding.principal == right_binding.principal
        && left_binding.plan_id == right_binding.plan_id
        && left_binding.request_id == right_binding.request_id
        && left_binding.provider == right_binding.provider
        && left_binding.resource == right_binding.resource
        && left_binding.capability == right_binding.capability
        && left_binding.policy_id == right_binding.policy_id
        && left_binding.policy_revision_id == right_binding.policy_revision_id
        && left.decision() == right.decision()
}

fn review_findings_unchanged(
    left: &linura_policy::PolicySubject,
    right: &linura_policy::PolicySubject,
) -> bool {
    left.findings().len() == right.findings().len()
        && left
            .findings()
            .iter()
            .zip(right.findings())
            .all(|(left_finding, right_finding)| {
                if left_finding.code != right_finding.code
                    || left_finding.level != right_finding.level
                {
                    return false;
                }
                if left_finding.code == "authoritative-observation" {
                    left_finding
                        .message
                        .replace(left.observed_evidence_id(), "<observation-evidence>")
                        == right_finding
                            .message
                            .replace(right.observed_evidence_id(), "<observation-evidence>")
                } else {
                    left_finding.message == right_finding.message
                }
            })
}

fn verify_after_dispatch<V>(
    verifier: &mut V,
    effect: &EffectDescriptor,
) -> Result<VerificationOutcome, ManagedLifecycleError>
where
    V: IndependentManagedVerifier,
{
    let attempts = verifier
        .post_dispatch_settle_attempts()
        .clamp(1, MAX_POST_DISPATCH_VERIFY_ATTEMPTS);
    let interval = std::cmp::min(
        verifier.post_dispatch_settle_interval(),
        MAX_POST_DISPATCH_VERIFY_INTERVAL,
    );
    let mut fallback: Option<VerificationOutcome> = None;

    for attempt in 0..attempts {
        let outcome = verifier
            .verify_effect(effect)
            .map_err(ManagedLifecycleError::Verification)?;
        match outcome.disposition {
            VerificationDisposition::Satisfied => return Ok(outcome),
            VerificationDisposition::NotSatisfied => fallback = Some(outcome),
            VerificationDisposition::Inconclusive if fallback.is_none() => fallback = Some(outcome),
            VerificationDisposition::Inconclusive => {}
        }
        if attempt + 1 < attempts && !interval.is_zero() {
            thread::sleep(interval);
        }
    }

    fallback.ok_or_else(|| {
        ManagedLifecycleError::Verification(
            "post-dispatch verifier produced no bounded observation".into(),
        )
    })
}

fn validate_managed_systemd_registration(
    operation_semantics: &OperationSemanticsControl,
) -> Result<(), ManagedLifecycleError> {
    let operation_id = OperationId::new(MANAGED_SYSTEMD_REGISTERED_OPERATION_ID)
        .map_err(|error| ManagedLifecycleError::Contract(error.to_string()))?;
    let descriptor = operation_semantics
        .descriptor(&operation_id)
        .ok_or_else(|| {
            ManagedLifecycleError::Contract(
                "trusted registry is missing the qualified managed-systemd operation".into(),
            )
        })?;
    if descriptor.class() != OperationClass::ManagedExternalEffect
        || descriptor.risk_floor() != Some(RiskClass::SecuritySensitive)
    {
        return Err(ManagedLifecycleError::Contract(
            "qualified managed-systemd operation class or risk floor drifted".into(),
        ));
    }
    let binding = descriptor.effect_binding().ok_or_else(|| {
        ManagedLifecycleError::Contract(
            "qualified managed-systemd operation is missing its effect binding".into(),
        )
    })?;
    if binding.provider().as_str() != MANAGED_SYSTEMD_PROVIDER
        || binding.observation_capability().as_str() != MANAGED_SYSTEMD_CAPABILITY
        || binding.resource_prefix() != MANAGED_SYSTEMD_RESOURCE_PREFIX
        || binding.resource_suffix() != Some(MANAGED_SYSTEMD_RESOURCE_SUFFIX)
        || binding.change_keys().len() != 1
        || !binding.change_keys().contains(MANAGED_SYSTEMD_CHANGE_KEY)
    {
        return Err(ManagedLifecycleError::Contract(
            "qualified managed-systemd operation effect binding drifted".into(),
        ));
    }
    Ok(())
}

fn validate_public_request(request: &PlanDesiredStateRequest) -> Result<(), ManagedLifecycleError> {
    let _ = effect_from_request(request)?;
    Ok(())
}

fn registered_route(
    provider: &str,
    capability: &str,
    resource: &ResourceId,
) -> Result<(&'static str, &'static str), ManagedLifecycleError> {
    if provider == linura_observation::DISPLAY_PROVIDER
        && capability == linura_observation::DISPLAY_OUTPUTS_CAPABILITY
    {
        linura_core::DisplayTopologyId::from_resource(resource)
            .map_err(|e| ManagedLifecycleError::UnsupportedEffect(e.to_string()))?;
        return Ok((
            MANAGED_DISPLAY_LAYOUT_OPERATION_ID,
            MANAGED_DISPLAY_LAYOUT_RISK_FLOOR_RULE_ID,
        ));
    }
    if provider == MANAGED_SESSION_TRANSITION_PROVIDER
        && capability == MANAGED_SESSION_TRANSITION_CAPABILITY
    {
        let target = SessionTransitionId::from_resource(resource)
            .map_err(|error| ManagedLifecycleError::UnsupportedEffect(error.to_string()))?;
        return SESSION_TRANSITION_ROUTES
            .into_iter()
            .find(|(action, _, _, _, _)| *action == target.transition().as_str())
            .map(|(_, operation, _, rule, _)| (operation, rule))
            .ok_or_else(|| {
                ManagedLifecycleError::UnsupportedEffect("unknown transition action".into())
            });
    }
    match (provider, capability) {
        (MANAGED_SYSTEMD_PROVIDER, MANAGED_SYSTEMD_CAPABILITY) => Ok((
            MANAGED_SYSTEMD_REGISTERED_OPERATION_ID,
            MANAGED_SYSTEMD_RISK_FLOOR_RULE_ID,
        )),
        (MANAGED_SESSION_LOCK_PROVIDER, MANAGED_SESSION_LOCK_CAPABILITY) => Ok((
            MANAGED_SESSION_LOCK_OPERATION_ID,
            MANAGED_SESSION_LOCK_RISK_FLOOR_RULE_ID,
        )),
        _ => Err(ManagedLifecycleError::UnsupportedEffect(
            "route is not a sealed registered managed effect".into(),
        )),
    }
}

fn managed_desired_attribute(
    request: &PlanDesiredStateRequest,
) -> Result<(String, String), ManagedLifecycleError> {
    let _ = effect_from_request(request)?;
    let (key, value) = request
        .desired_state
        .first_key_value()
        .ok_or_else(|| ManagedLifecycleError::UnsupportedEffect("desired state is empty".into()))?;
    Ok((key.clone(), value.clone()))
}

fn required_approval_for_request(
    request: &PlanDesiredStateRequest,
) -> Result<ApprovalClass, ManagedLifecycleError> {
    let (key, value) = managed_desired_attribute(request)?;
    if is_session_transition(request) {
        let target = SessionTransitionId::from_resource(&request.resource)
            .map_err(|error| ManagedLifecycleError::UnsupportedEffect(error.to_string()))?;
        return Ok(match target.transition() {
            SessionTransition::Suspend { .. } => ApprovalClass::Administrator,
            SessionTransition::Logout | SessionTransition::Reboot | SessionTransition::PowerOff => {
                ApprovalClass::DestructiveAction
            }
        });
    }
    match (request.provider.as_str(), key.as_str(), value.as_str()) {
        (linura_observation::DISPLAY_PROVIDER, "layout", _) => Ok(ApprovalClass::Administrator),
        (MANAGED_SYSTEMD_PROVIDER, "active_state", "active" | "inactive") => {
            Ok(ApprovalClass::Administrator)
        }
        (MANAGED_SESSION_LOCK_PROVIDER, "secure", "true") => Ok(ApprovalClass::InteractiveUser),
        (MANAGED_SESSION_LOCK_PROVIDER, "secure", "false") => {
            Ok(ApprovalClass::SessionOwnerAuthentication)
        }
        _ => Err(ManagedLifecycleError::UnsupportedEffect(
            "effect has no exact approval purpose".into(),
        )),
    }
}

fn effect_from_request(
    request: &PlanDesiredStateRequest,
) -> Result<EffectDescriptor, ManagedLifecycleError> {
    let _ = registered_route(
        request.provider.as_str(),
        request.observation_capability.as_str(),
        &request.resource,
    )?;
    effect_from_parts(
        request.provider.clone(),
        request.resource.clone(),
        &request.desired_state,
    )
}

fn effect_from_candidate(
    candidate: &DurableAuthorityCandidate,
) -> Result<EffectDescriptor, ManagedLifecycleError> {
    let subject = candidate.review().subject();
    let _ = registered_route(
        subject.provider().as_str(),
        subject.capability().as_str(),
        subject.resource(),
    )?;
    if subject.changes().len() != 1 {
        return Err(ManagedLifecycleError::UnsupportedEffect(
            "trusted plan is outside the single systemd active-state capability".into(),
        ));
    }
    let change = &subject.changes()[0];
    let expected_key = if subject.provider().as_str() == linura_observation::DISPLAY_PROVIDER {
        "layout"
    } else if subject.provider().as_str() == MANAGED_SESSION_LOCK_PROVIDER {
        "secure"
    } else if subject.provider().as_str() == MANAGED_SESSION_TRANSITION_PROVIDER {
        "completed"
    } else {
        "active_state"
    };
    if change.key != expected_key {
        return Err(ManagedLifecycleError::UnsupportedEffect(
            "trusted plan contains a mutation other than active_state".into(),
        ));
    }
    let desired = BTreeMap::from([(change.key.clone(), change.desired.clone())]);
    effect_from_parts(
        subject.provider().clone(),
        subject.resource().clone(),
        &desired,
    )
}

fn effect_from_parts(
    provider: ProviderId,
    resource: ResourceId,
    desired_state: &BTreeMap<String, String>,
) -> Result<EffectDescriptor, ManagedLifecycleError> {
    if provider.as_str() == linura_observation::DISPLAY_PROVIDER {
        if desired_state.len() != 1 {
            return Err(ManagedLifecycleError::UnsupportedEffect(
                "display layout requires one complete intent".into(),
            ));
        }
        let material = desired_state.get("layout").ok_or_else(|| {
            ManagedLifecycleError::UnsupportedEffect("display layout intent is absent".into())
        })?;
        let effect = linura_provider_sdk::display_layout_effect(material)
            .map_err(ManagedLifecycleError::UnsupportedEffect)?;
        if effect.resource != resource {
            return Err(ManagedLifecycleError::UnsupportedEffect(
                "display effect refers to another topology".into(),
            ));
        }
        return Ok(effect);
    }
    if provider.as_str() == MANAGED_SESSION_TRANSITION_PROVIDER {
        let _ = SessionTransitionId::from_resource(&resource)
            .map_err(|error| ManagedLifecycleError::UnsupportedEffect(error.to_string()))?;
        if desired_state.len() != 1
            || desired_state.get("completed").map(String::as_str) != Some("true")
        {
            return Err(ManagedLifecycleError::UnsupportedEffect(
                "transition requires exactly completed=true".into(),
            ));
        }
        return EffectDescriptor::new(
            provider,
            resource.clone(),
            "execute-session-transition",
            format!("transition={}\n", resource.as_str()).into_bytes(),
        )
        .map_err(|error| ManagedLifecycleError::Contract(error.to_string()));
    }
    if provider.as_str() == MANAGED_SESSION_LOCK_PROVIDER {
        let lock = SessionLockId::from_resource(&resource).map_err(|_| {
            ManagedLifecycleError::UnsupportedEffect("native lock identity is not canonical".into())
        })?;
        if desired_state.len() != 1 {
            return Err(ManagedLifecycleError::UnsupportedEffect(
                "secure-lock accepts exactly one desired attribute".into(),
            ));
        }
        let secure = desired_state
            .get("secure")
            .filter(|value| matches!(value.as_str(), "true" | "false"))
            .ok_or_else(|| {
                ManagedLifecycleError::UnsupportedEffect(
                    "secure must be exactly true or false".into(),
                )
            })?;
        let canonical = lock
            .resource_id()
            .map_err(|error| ManagedLifecycleError::Contract(error.to_string()))?;
        return EffectDescriptor::new(
            provider,
            resource,
            "set-secure",
            format!("lock={}\nsecure={secure}\n", canonical.as_str()).into_bytes(),
        )
        .map_err(|error| ManagedLifecycleError::Contract(error.to_string()));
    }
    if provider.as_str() != MANAGED_SYSTEMD_PROVIDER {
        return Err(ManagedLifecycleError::UnsupportedEffect(
            "provider has no sealed managed effect factory".into(),
        ));
    }
    let unit = managed_unit_from_resource(resource.as_str())?.to_owned();
    if desired_state.len() != 1 {
        return Err(ManagedLifecycleError::UnsupportedEffect(
            "v0.6 accepts exactly one desired-state attribute".into(),
        ));
    }
    let desired = desired_state.get("active_state").ok_or_else(|| {
        ManagedLifecycleError::UnsupportedEffect("active_state is required".into())
    })?;
    if !matches!(desired.as_str(), "active" | "inactive") {
        return Err(ManagedLifecycleError::UnsupportedEffect(
            "active_state must be exactly active or inactive".into(),
        ));
    }
    EffectDescriptor::new(
        provider,
        resource,
        MANAGED_SYSTEMD_OPERATION,
        format!("unit={unit}\nactive_state={desired}\n").into_bytes(),
    )
    .map_err(|error| ManagedLifecycleError::Contract(error.to_string()))
}

fn managed_unit_from_resource(resource: &str) -> Result<&str, ManagedLifecycleError> {
    let unit = resource.strip_prefix("systemd:unit:").ok_or_else(|| {
        ManagedLifecycleError::UnsupportedEffect("resource is not a systemd unit".into())
    })?;
    if unit.is_empty() || unit.len() > 255 || !unit.ends_with(".service") || !unit.is_ascii() {
        return Err(ManagedLifecycleError::UnsupportedEffect(
            "unit must be a bounded ASCII .service name".into(),
        ));
    }
    let suffix = unit
        .strip_prefix(MANAGED_SYSTEMD_UNIT_PREFIX)
        .ok_or_else(|| {
            ManagedLifecycleError::UnsupportedEffect(
                "unit is outside the linura-managed- namespace".into(),
            )
        })?;
    let slug = suffix.strip_suffix(".service").ok_or_else(|| {
        ManagedLifecycleError::UnsupportedEffect("managed unit suffix is not canonical".into())
    })?;
    if slug.is_empty()
        || slug.len() > 96
        || !slug.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
        || slug.starts_with('-')
        || slug.ends_with('-')
        || slug.contains("--")
    {
        return Err(ManagedLifecycleError::UnsupportedEffect(
            "managed unit name is not canonical".into(),
        ));
    }
    Ok(unit)
}

fn authorized_effect(
    effect: EffectDescriptor,
    permit: DispatchPermit,
) -> Result<AuthorizedEffect, ManagedLifecycleError> {
    let binding = ExecutionBinding::new(
        permit.transaction_id().as_str(),
        permit.generation(),
        permit.state_version(),
        ComponentDigest::parse_hex(permit.binding_digest().hex())
            .map_err(|error| ManagedLifecycleError::Contract(error.to_string()))?,
        ComponentDigest::parse_hex(permit.authority_use_digest().hex())
            .map_err(|error| ManagedLifecycleError::Contract(error.to_string()))?,
        &effect,
    )
    .map_err(|error| ManagedLifecycleError::Contract(error.to_string()))?;
    Ok(AuthorizedEffect {
        effect,
        binding,
        permit,
    })
}

fn validate_operation_id(operation_id: &str) -> Result<(), ManagedLifecycleError> {
    if operation_id.is_empty()
        || operation_id.len() > MAX_OPERATION_ID_BYTES
        || !operation_id.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
        || operation_id.starts_with('-')
        || operation_id.ends_with('-')
        || operation_id.contains("--")
    {
        return Err(ManagedLifecycleError::InvalidRequestIdentity(
            "operation id must be 1..64 lowercase ASCII letters/digits/hyphens in canonical form"
                .into(),
        ));
    }
    Ok(())
}

fn validate_request_identity(
    request: &PlanDesiredStateRequest,
) -> Result<(), ManagedLifecycleError> {
    let prefix = if request.provider.as_str() == MANAGED_SESSION_LOCK_PROVIDER {
        SESSION_REQUEST_PREFIX
    } else if is_session_transition(request) {
        TRANSITION_REQUEST_PREFIX
    } else if is_display_request(request) {
        DISPLAY_REQUEST_PREFIX
    } else {
        MANAGED_REQUEST_PREFIX
    };
    let operation_id = request
        .request_id
        .as_str()
        .strip_prefix(prefix)
        .ok_or_else(|| {
            ManagedLifecycleError::InvalidRequestIdentity(format!(
                "request id must begin with {prefix}"
            ))
        })?;
    validate_operation_id(operation_id)
}

fn is_session_transition(request: &PlanDesiredStateRequest) -> bool {
    request.provider.as_str() == MANAGED_SESSION_TRANSITION_PROVIDER
        && request.observation_capability.as_str() == MANAGED_SESSION_TRANSITION_CAPABILITY
}
fn is_display_request(request: &PlanDesiredStateRequest) -> bool {
    request.provider.as_str() == linura_observation::DISPLAY_PROVIDER
        && request.observation_capability.as_str() == linura_observation::DISPLAY_OUTPUTS_CAPABILITY
}

fn now_unix_seconds() -> Result<u64, ManagedLifecycleError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ManagedLifecycleError::Contract("system clock is before unix epoch".into()))
}

fn digest_managed_request(
    request: &PlanDesiredStateRequest,
) -> Result<String, ManagedLifecycleError> {
    Ok(crate::durable_authority::digest_request(request)?
        .as_str()
        .to_owned())
}

fn advance(
    progress: &mut MutationProgress,
    stage: MutationStage,
) -> Result<(), ManagedLifecycleError> {
    progress.advance(stage).map_err(|error| {
        ManagedLifecycleError::Contract(format!("invalid lifecycle transition: {error:?}"))
    })
}

fn progress_through(last: MutationStage) -> Result<MutationProgress, ManagedLifecycleError> {
    let mut progress = MutationProgress::new();
    for stage in linura_lifecycle::MUTATION_STAGES.iter().copied().skip(1) {
        advance(&mut progress, stage)?;
        if stage == last {
            break;
        }
    }
    Ok(progress)
}

struct ReceiptContext<'a> {
    transaction_id: &'a TransactionId,
    plan_id: &'a str,
    effect: &'a EffectDescriptor,
    execution: Option<&'a ExecutionOutcome>,
    verification: &'a VerificationOutcome,
    final_state: &'a TransactionState,
    recovered: bool,
    progress: &'a MutationProgress,
}

fn receipt(context: ReceiptContext<'_>) -> ManagedMutationReceipt {
    let ReceiptContext {
        transaction_id,
        plan_id,
        effect,
        execution,
        verification,
        final_state,
        recovered,
        progress,
    } = context;
    let transition = effect.provider.as_str() == MANAGED_SESSION_TRANSITION_PROVIDER
        && effect.operation == "execute-session-transition";
    let change_key = if transition {
        "completed"
    } else if effect.provider.as_str() == MANAGED_SESSION_LOCK_PROVIDER {
        "secure"
    } else {
        "active_state"
    };
    let desired_value = if transition {
        "true".to_owned()
    } else {
        String::from_utf8_lossy(&effect.canonical_payload)
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{change_key}=")))
            .unwrap_or("unknown")
            .to_owned()
    };
    ManagedMutationReceipt {
        transaction_id: transaction_id.as_str().to_owned(),
        plan_id: plan_id.to_owned(),
        resource: effect.resource.as_str().to_owned(),
        change_key: change_key.into(),
        desired_value,
        effect_digest: effect.digest().to_hex(),
        dispatch_digest: execution.map(|value| value.dispatch_digest.to_hex()),
        execution_disposition: execution.map(|value| execution_name(value.disposition).to_owned()),
        verification_disposition: verification_name(verification.disposition).to_owned(),
        final_state: final_state.as_str().to_owned(),
        recovered,
        stages: progress
            .completed()
            .iter()
            .map(|stage| stage.as_str().to_owned())
            .collect(),
    }
}

const fn execution_name(disposition: ExecutionDisposition) -> &'static str {
    match disposition {
        ExecutionDisposition::RejectedBeforeDispatch => "rejected-before-dispatch",
        ExecutionDisposition::Dispatched => "dispatched",
        ExecutionDisposition::Indeterminate => "indeterminate",
    }
}

const fn verification_name(disposition: VerificationDisposition) -> &'static str {
    match disposition {
        VerificationDisposition::Satisfied => "satisfied",
        VerificationDisposition::NotSatisfied => "not-satisfied",
        VerificationDisposition::Inconclusive => "inconclusive",
    }
}

#[cfg(test)]
mod tests {
    use linura_core::{CapabilityId, SemanticReason};

    use super::*;

    fn request(resource: &str, desired: &str) -> PlanDesiredStateRequest {
        let mut request = PlanDesiredStateRequest {
            request_id: RequestId::new("request:v06:placeholder")
                .unwrap_or_else(|error| unreachable!("{error}")),
            provider: ProviderId::new("systemd").unwrap_or_else(|error| unreachable!("{error}")),
            resource: ResourceId::new(resource).unwrap_or_else(|error| unreachable!("{error}")),
            observation_capability: CapabilityId::new("systemd.unit.observe")
                .unwrap_or_else(|error| unreachable!("{error}")),
            reason: SemanticReason {
                summary: "v0.6 test".into(),
                intent_ids: vec![],
                requirement_ids: vec![],
                capability_ids: vec![],
            },
            desired_state: BTreeMap::from([("active_state".into(), desired.into())]),
        };
        request.request_id = managed_request_id("test-operation", &request)
            .unwrap_or_else(|error| unreachable!("{error}"));
        request
    }

    #[test]
    fn public_effect_is_exactly_one_reserved_systemd_active_state() {
        let effect = effect_from_request(&request(
            "systemd:unit:linura-managed-example.service",
            "active",
        ))
        .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(effect.operation, MANAGED_SYSTEMD_OPERATION);
        assert_eq!(
            effect.canonical_payload,
            b"unit=linura-managed-example.service\nactive_state=active\n"
        );
        assert!(effect_from_request(&request("systemd:unit:sshd.service", "active")).is_err());
        assert!(
            effect_from_request(&request(
                "systemd:unit:linura-managed-example.service",
                "failed",
            ))
            .is_err()
        );
    }

    #[test]
    fn request_id_is_stable_operation_namespace_and_plan_identity() {
        let request = request("systemd:unit:linura-managed-example.service", "active");
        assert!(validate_request_identity(&request).is_ok());
        assert!(PlanId::new(request.request_id.as_str().to_owned()).is_ok());

        let mut substituted = request.clone();
        substituted
            .desired_state
            .insert("active_state".into(), "inactive".into());
        assert_eq!(
            request.request_id,
            managed_request_id("test-operation", &substituted)
                .unwrap_or_else(|error| unreachable!("{error}"))
        );

        let mut other_operation = request.clone();
        other_operation.request_id = managed_request_id("other-operation", &other_operation)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_ne!(request.request_id, other_operation.request_id);
        assert_ne!(
            digest_managed_request(&request).unwrap_or_default(),
            digest_managed_request(&substituted).unwrap_or_default()
        );
    }

    #[test]
    fn lifecycle_progress_helper_never_skips_canonical_order() {
        let progress = progress_through(MutationStage::Reconcile)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(progress.is_complete());
        assert_eq!(
            progress.completed(),
            linura_lifecycle::MUTATION_STAGES.as_slice()
        );
    }
}
