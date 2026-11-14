//! Fresh ordinary-purpose review and durable, one-use managed dispatch.
//! Dispatch correlation never proves a physical handoff or releases a fence.
use super::*;
use crate::display_ordinary_release_intent::OrdinaryReleaseIntent;
use linura_core::DisplayOrdinaryReleaseMaterial;

pub struct OrdinaryDisplayReleaseChallenge {
    managed: ManagedApprovalChallenge,
    material: String,
}
impl Debug for OrdinaryDisplayReleaseChallenge {
    fn fmt(&self, out: &mut Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("OrdinaryDisplayReleaseChallenge")
            .field("managed", &self.managed)
            .field("material_bytes", &self.material.len())
            .finish()
    }
}
impl OrdinaryDisplayReleaseChallenge {
    pub const fn managed(&self) -> &ManagedApprovalChallenge {
        &self.managed
    }
    pub fn material(&self) -> &str {
        &self.material
    }
}
/// Trusted protected interaction adapter. Ordinary release is a separate
/// purpose from Apply, Keep, Revert, original restoration/finalization or unlock.
pub trait OrdinaryDisplayReleaseAuthorizer: Debug + Send {
    fn authorize_ordinary_release(
        &self,
        challenge: &OrdinaryDisplayReleaseChallenge,
    ) -> Result<TrustedHumanApproval, String>;
}
pub struct AuthorizedOrdinaryDisplayRelease {
    authorization: AuthorizedEffect,
    material: String,
    deadline_unix_ms: u64,
}
impl Debug for AuthorizedOrdinaryDisplayRelease {
    fn fmt(&self, out: &mut Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("AuthorizedOrdinaryDisplayRelease")
            .field("binding", self.authorization.binding())
            .field("deadline_unix_ms", &self.deadline_unix_ms)
            .finish_non_exhaustive()
    }
}
impl AuthorizedOrdinaryDisplayRelease {
    pub fn into_executor_request(self) -> (AuthorizedEffect, String, u64) {
        (self.authorization, self.material, self.deadline_unix_ms)
    }
}
/// Narrow original-Root grant preparation. Implementations must authenticate
/// the actual Root/native owners; an ACK is neither scanout nor completion.
pub trait OrdinaryDisplayReleasePort: Debug + Send {
    fn dispatch_ordinary_release(
        &mut self,
        release: AuthorizedOrdinaryDisplayRelease,
    ) -> Result<ExecutionOutcome, String>;
}
#[derive(Debug, Eq, PartialEq)]
pub struct OrdinaryDisplayReleaseReceipt {
    pub request_id: RequestId,
    pub transaction_id: TransactionId,
    pub dispatch_digest: Option<String>,
}

impl<S: TransactionStore> ManagedLifecycleControl<S> {
    pub(super) fn ordinary_release_receipt(
        &self,
        principal: &AuthenticatedPrincipal,
        request: &PlanDesiredStateRequest,
    ) -> Result<OrdinaryDisplayReleaseReceipt, ManagedLifecycleError> {
        let principal_id = PrincipalId::new(principal.as_str()).map_err(|_| invalid_original())?;
        let snapshot = self
            .authority
            .matching_request_snapshot(principal, request)?;
        let intent = OrdinaryReleaseIntent::load(self.display_journal()?, &principal_id, request)?;
        intent.require_claim(self.display_journal()?, &principal_id, request)?;
        let digest = crate::durable_authority::digest_request(request)?;
        let reserved = Record::load(
            self.display_journal()?,
            &principal_id,
            &digest,
            Phase::Reserved,
        )?
        .ok_or_else(invalid_original)?;
        reserved.validate_after(None)?;
        let dispatched = Record::load(
            self.display_journal()?,
            &principal_id,
            &digest,
            Phase::Dispatched,
        )?;
        if reserved.transaction_id != snapshot.transaction_id {
            return Err(invalid_original());
        }
        if let Some(record) = &dispatched {
            record.validate_after(Some(&reserved))?;
            if record.transaction_id != snapshot.transaction_id
                || snapshot.state != TransactionState::Indeterminate
            {
                return Err(invalid_original());
            }
        } else if !matches!(
            snapshot.state,
            TransactionState::Prepared | TransactionState::Indeterminate
        ) {
            return Err(invalid_original());
        }
        Ok(OrdinaryDisplayReleaseReceipt {
            request_id: request.request_id.clone(),
            transaction_id: snapshot.transaction_id,
            dispatch_digest: dispatched.and_then(|record| record.dispatch_digest),
        })
    }

    /// Begin a NEW canonical ordinary-release operation, including after loss
    /// of the original Keep review. Retained receipts never reconstruct this
    /// approval, prepared permit, process-local review or a Root/native grant.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_ordinary_display_release<
        P: DisplayTransactionPort,
        V: IndependentDisplayVerifier,
        R: OrdinaryDisplayReleasePort,
    >(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        input: OrdinaryDisplayReleaseRequest,
        authorizer: &dyn OrdinaryDisplayReleaseAuthorizer,
        attempt: &mut P,
        verifier: &mut V,
        port: &mut R,
    ) -> Result<OrdinaryDisplayReleaseReceipt, ManagedLifecycleError> {
        validate_operation_id(&input.operation_id)?;
        if actor.kind != ActorKind::Human || !actor.interactive {
            return Err(invalid_original());
        }
        let principal_id = PrincipalId::new(principal.as_str()).map_err(|_| invalid_original())?;
        let request_id = RequestId::new(format!(
            "{DISPLAY_ORDINARY_RELEASE_REQUEST_PREFIX}{}",
            input.operation_id
        ))
        .map_err(|_| invalid_original())?;
        let transaction = TransactionId::for_namespace(&principal_id, &request_id);
        self.display_journal()?
            .integrity_check()
            .map_err(|_| invalid_original())?;
        self.authority.integrity_check()?;
        match self.authority.snapshot(&transaction) {
            Ok(_) => {
                let retained = self
                    .display_journal()?
                    .load(&principal_id, &request_id)
                    .map_err(|_| invalid_original())?;
                if retained.principal() != &principal_id || retained.request_id() != &request_id {
                    return Err(invalid_original());
                }
                let request = crate::retained_request::decode(&retained)?;
                validate_public_request(&request)?;
                validate_request_identity(&request)?;
                let intent =
                    OrdinaryReleaseIntent::load(self.display_journal()?, &principal_id, &request)?;
                let material = DisplayOrdinaryReleaseMaterial::decode(intent.material())
                    .map_err(|_| invalid_original())?;
                let original =
                    self.retained_display_request(&principal, &input.original_request)?;
                let mut reason = input.reason.clone();
                crate::display_restoration_plan::inherit_original_reason(
                    &mut reason,
                    &original.reason,
                )
                .map_err(ManagedLifecycleError::Contract)?;
                if material.lineage().original_request != input.original_request
                    || material.original_text() != original.desired_state["layout"]
                    || request.reason != reason
                    || retained.digest() != &crate::durable_authority::digest_request(&request)?
                {
                    return Err(invalid_original());
                }
                return self.ordinary_release_receipt(&principal, &request);
            }
            Err(DurableAuthorityError::Transaction(detail))
                if detail == "durable transaction not found" => {}
            Err(error) => return Err(error.into()),
        }
        let (original, request, source) = self.ordinary_display_release_input(
            principal.clone(),
            actor.clone(),
            input.clone(),
            attempt,
            verifier,
        )?;
        let material = source.material.clone();
        let candidate = {
            let _scope = self
                .previews
                .enter_ordinary_display_release_context(source, &request)
                .map_err(|_| invalid_original())?;
            let floor = self.registered_managed_risk_floor(&request)?;
            self.authority.candidate_with_risk_floor(
                &mut self.previews,
                principal.clone(),
                actor.clone(),
                request.clone(),
                floor,
            )?
        };
        self.validate_registered_managed_candidate(&candidate)?;
        let effect = effect_from_request(&request)?;
        if effect
            != linura_provider_sdk::display_ordinary_release_effect(&material)
                .map_err(|_| invalid_original())?
            || effect_from_candidate(&candidate)? != effect
        {
            return Err(invalid_original());
        }
        if !matches!(
            candidate.review().decision(),
            PolicyDecision::RequireApproval {
                class: ApprovalClass::Administrator,
                ..
            }
        ) {
            return Err(ManagedLifecycleError::ApprovalBoundary(
                "ordinary release requires fresh protected administrator approval".into(),
            ));
        }
        let challenge = OrdinaryDisplayReleaseChallenge {
            managed: ManagedApprovalChallenge::from_candidate(&candidate, &request)?,
            material: material.clone(),
        };
        let approval = authorizer
            .authorize_ordinary_release(&challenge)
            .map_err(ManagedLifecycleError::ApprovalBoundary)?;
        if !approval.matches_challenge(challenge.managed()) {
            return Err(invalid_original());
        }
        let approver = PolicyAuthenticatedApprover::new(
            approval.principal().clone(),
            ActorKind::Human,
            BTreeSet::from([ApprovalClass::Administrator]),
        );
        let (fresh, fresh_request, fresh_source) = self.ordinary_display_release_input(
            principal.clone(),
            actor.clone(),
            input.clone(),
            attempt,
            verifier,
        )?;
        if fresh_request != request
            || fresh_source.material != material
            || fresh.original_snapshot() != original.original_snapshot()
            || fresh.root() != original.root()
        {
            return Err(ManagedLifecycleError::ApprovalBoundary("ordinary release history, native scope or complete sources changed during protected interaction".into()));
        }
        let refreshed = {
            let _scope = self
                .previews
                .enter_ordinary_display_release_context(fresh_source, &request)
                .map_err(|_| invalid_original())?;
            self.refresh_candidate_after_approval(
                &candidate,
                principal.clone(),
                actor,
                request.clone(),
                &effect,
            )?
        };
        self.require_ordinary_release_history(&principal, &fresh)?;
        let expiry = now_unix_seconds()?
            .checked_add(MANAGED_APPROVAL_TTL_SECONDS)
            .ok_or_else(invalid_original)?;
        let evidence = self.authority.issue_approval(
            ApprovalRequestId::new(format!(
                "approval:v010:display-ordinary-release:{}",
                input.operation_id
            ))
            .map_err(|_| invalid_original())?,
            &refreshed,
            &approver,
            expiry,
        )?;
        let retained = crate::retained_request::encode(principal_id.clone(), &request)?;
        let intent = OrdinaryReleaseIntent::capture(&request, &material)?;
        {
            let journal = self.request_journal.as_mut().ok_or_else(invalid_original)?;
            journal.retain(&retained).map_err(|_| invalid_original())?;
            intent.append(journal.as_mut(), principal_id.clone(), &request)?;
            intent.claim(journal.as_mut(), principal_id.clone(), &request)?;
        }
        if self
            .display_journal()?
            .load(&principal_id, &request_id)
            .map_err(|_| invalid_original())?
            != retained
            || OrdinaryReleaseIntent::load(self.display_journal()?, &principal_id, &request)?
                != intent
        {
            return Err(invalid_original());
        }
        intent.require_claim(self.display_journal()?, &principal_id, &request)?;
        let mut prepared = self
            .authority
            .prepare(refreshed, Some(evidence.id().clone()))?;
        let retained_bytes =
            crate::durable_authority::DisplayRetainedReview::estimated_bytes(&prepared);
        self.check_display_review_capacity(retained_bytes)?;
        let started = now_ms()?;
        let deadline = started
            .checked_add(DISPLAY_CONFIRMATION_WINDOW_MS)
            .ok_or_else(invalid_original)?;
        let reserved = Record::new(
            retained.digest().clone(),
            transaction.clone(),
            Phase::Reserved,
            deadline,
            started,
            None,
            None,
            None,
        )?;
        self.append_display_record(&reserved, principal_id.clone(), None)?;
        if Record::load(
            self.display_journal()?,
            &principal_id,
            retained.digest(),
            Phase::Reserved,
        )?
        .as_ref()
            != Some(&reserved)
        {
            return Err(invalid_original());
        }
        self.require_ordinary_release_history(&principal, &fresh)?;
        intent.require_claim(self.display_journal()?, &principal_id, &request)?;
        let permit = self.handoff_registered_managed(&principal, &mut prepared)?;
        let authorization = authorized_effect(effect, permit)?;
        let dispatch = authorization.binding().dispatch_digest.to_hex();
        let dispatched = Record::new(
            retained.digest().clone(),
            transaction,
            Phase::Dispatched,
            deadline,
            now_ms()?,
            Some(dispatch.clone()),
            Some(reserved.digest().clone()),
            None,
        )?;
        self.append_display_record(&dispatched, principal_id.clone(), Some(&reserved))?;
        if Record::load(
            self.display_journal()?,
            &principal_id,
            retained.digest(),
            Phase::Dispatched,
        )?
        .as_ref()
            != Some(&dispatched)
        {
            return Err(invalid_original());
        }
        intent.require_claim(self.display_journal()?, &principal_id, &request)?;
        if OrdinaryReleaseIntent::load(self.display_journal()?, &principal_id, &request)? != intent
        {
            return Err(invalid_original());
        }
        self.require_ordinary_release_history(&principal, &fresh)?;
        prepared
            .display_checkpoint_observation()
            .require_current(now_ms()?)
            .map_err(|_| invalid_original())?;
        self.display_reviews.insert(
            dispatched.transaction_id.clone(),
            RetainedDisplayReview {
                stage: DisplayReviewStage::Initial,
                review: crate::durable_authority::DisplayRetainedReview::from_spent(
                    prepared,
                    crate::durable_authority::DisplayReviewPurpose::OrdinaryRelease,
                )?,
                created_unix_ms: started,
                deadline_unix_ms: deadline,
                retained_bytes,
            },
        );
        if now_ms()? >= deadline {
            self.display_reviews.remove(&dispatched.transaction_id);
        } else {
            match port.dispatch_ordinary_release(AuthorizedOrdinaryDisplayRelease {
                authorization,
                material,
                deadline_unix_ms: deadline,
            }) {
                Ok(outcome) if outcome.dispatch_digest.to_hex() != dispatch => {
                    self.display_reviews.remove(&dispatched.transaction_id);
                    return Err(invalid_original());
                }
                Ok(outcome) if outcome.disposition == ExecutionDisposition::Dispatched => (),
                // A read-only receipt can reconcile ambiguous history, but it
                // cannot carry a lost preparation ACK into a live continuation.
                Err(_) | Ok(_) => {
                    self.display_reviews.remove(&dispatched.transaction_id);
                }
            }
        }
        self.ordinary_release_receipt(&principal, &request)
    }
}
