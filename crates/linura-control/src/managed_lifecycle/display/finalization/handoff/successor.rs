//! Same-invocation protected ownership transfer. The successor receives its
//! own canonical Apply review, preparation and dispatch. Historical completion
//! is only an exact precondition; it cannot reconstruct the native Root channel.
use super::*;
use completed::{Entry, Kind, content};
use linura_transaction::{RetainedRequest, TransactionStoreError, digest_bytes};

const DOMAIN: &str = "linura.display.successor-claim.v1";

fn claim_key(kind: &str, key: &str) -> Result<RequestId, ManagedLifecycleError> {
    RequestId::new(format!(
        "request:v010:display-successor-{kind}:{}",
        digest_bytes(DOMAIN, key.as_bytes()).hex()
    ))
    .map_err(|_| invalid())
}

fn record_fields(bytes: &[u8]) -> Result<Vec<String>, ManagedLifecycleError> {
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err(invalid());
    }
    let mut rest = bytes;
    let mut fields = Vec::new();
    while !rest.is_empty() {
        let (length, body) = rest.split_at_checked(8).ok_or_else(invalid)?;
        let size = usize::try_from(u64::from_be_bytes(
            length.try_into().map_err(|_| invalid())?,
        ))
        .map_err(|_| invalid())?;
        if size == 0 || size > 2048 || fields.len() >= 18 {
            return Err(invalid());
        }
        let (value, tail) = body.split_at_checked(size).ok_or_else(invalid)?;
        fields.push(std::str::from_utf8(value).map_err(|_| invalid())?.into());
        rest = tail;
    }
    Ok(fields)
}

impl DisplaySuccessorContext {
    fn claim(
        &self,
        principal: &PrincipalId,
        request: &PlanDesiredStateRequest,
        key: RequestId,
    ) -> Result<RetainedRequest, ManagedLifecycleError> {
        if self.terminal.principal != *principal
            || self.restoration.principal != *principal
            || self.terminal.state != TransactionState::Committed
            || self.restoration.state != TransactionState::Committed
        {
            return Err(invalid());
        }
        let mut fields = vec![
            DOMAIN.into(),
            principal.as_str().into(),
            request.request_id.as_str().into(),
            crate::durable_authority::digest_request(request)?
                .as_str()
                .into(),
            self.scope
                .resource_id()
                .map_err(|_| invalid())?
                .as_str()
                .into(),
            self.released.as_str().into(),
            self.root_released.clone(),
            self.root_final.clone(),
        ];
        for snapshot in [&self.terminal, &self.restoration] {
            fields.extend([
                snapshot.transaction_id.as_str().into(),
                snapshot.request_id.as_str().into(),
                snapshot.current_generation.to_string(),
                snapshot.state_version.to_string(),
                snapshot.binding_digest.as_str().into(),
            ]);
        }
        let mut bytes = Vec::new();
        for field in fields {
            if field.is_empty() || field.len() > 2048 || bytes.len() + field.len() + 8 > 4096 {
                return Err(invalid());
            }
            bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
            bytes.extend_from_slice(field.as_bytes());
        }
        RetainedRequest::new(principal.clone(), key, bytes).map_err(|_| invalid())
    }
    fn claims(
        &self,
        principal: &PrincipalId,
        request: &PlanDesiredStateRequest,
    ) -> Result<[RetainedRequest; 2], ManagedLifecycleError> {
        Ok([
            self.claim(
                principal,
                request,
                claim_key("owner", self.terminal.request_id.as_str())?,
            )?,
            self.claim(
                principal,
                request,
                claim_key("intent", request.request_id.as_str())?,
            )?,
        ])
    }
}

impl<S: TransactionStore> ManagedLifecycleControl<S> {
    pub(in crate::managed_lifecycle::display) fn successor_for_request(
        &self,
        principal: &AuthenticatedPrincipal,
        request: &PlanDesiredStateRequest,
    ) -> Result<Option<DisplaySuccessorContext>, ManagedLifecycleError> {
        let principal_id = PrincipalId::new(principal.as_str()).map_err(|_| invalid())?;
        let key = claim_key("intent", request.request_id.as_str())?;
        let record = match self.display_journal()?.load(&principal_id, &key) {
            Err(TransactionStoreError::NotFound) => return Ok(None),
            Ok(record) => record,
            Err(_) => return Err(invalid()),
        };
        if record.principal() != &principal_id || record.request_id() != &key {
            return Err(invalid());
        }
        let fields = record_fields(record.canonical())?;
        if fields.len() != 18
            || fields[0] != DOMAIN
            || fields[1] != principal.as_str()
            || fields[2] != request.request_id.as_str()
            || fields[3] != crate::durable_authority::digest_request(request)?.as_str()
        {
            return Err(invalid());
        }
        let predecessor = RequestId::new(&fields[9]).map_err(|_| invalid())?;
        let context = self.successor_context(principal, &predecessor)?;
        self.require_successor_claim(&principal_id, request, &context)?;
        Ok(Some(context))
    }

    /// Observe-only recovery. A Root spend is joined with the independently
    /// observed new attempt and verified current layout before recording proof.
    /// Missing ACKs never call either handoff port again.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::managed_lifecycle::display) fn verify_successor_transfer<
        P: DisplayTransactionPort,
        V: IndependentDisplayVerifier,
    >(
        &mut self,
        principal: &AuthenticatedPrincipal,
        request: &PlanDesiredStateRequest,
        context: &DisplaySuccessorContext,
        dispatched: &Record,
        guard: &ComponentDigest,
        port: &mut P,
        verifier: &mut V,
    ) -> Result<(), ManagedLifecycleError> {
        use linura_observation::{DISPLAY_SUCCESSOR_CAPABILITY, DisplaySuccessorFacts};
        self.require_successor_context(principal, context)?;
        let principal_id = PrincipalId::new(principal.as_str()).map_err(|_| invalid())?;
        self.require_successor_claim(&principal_id, request, context)?;
        let query = ObservationRequest {
            provider: ProviderId::new(DISPLAY_RECOVERY_PROVIDER).map_err(|_| invalid())?,
            capability: CapabilityId::new(DISPLAY_SUCCESSOR_CAPABILITY).map_err(|_| invalid())?,
            resource: context.scope.resource_id().map_err(|_| invalid())?,
        };
        let root = self
            .previews
            .observe(&query)
            .map_err(|_| invalid())?
            .observation;
        let facts = DisplaySuccessorFacts::from_envelope(&root, &context.scope, now_ms()?)
            .map_err(|_| invalid())?;
        let lineage = facts.lineage();
        if !facts.spent()
            || lineage.released_parent != context.root_released
            || lineage.native_guard != guard.to_hex()
            || lineage.transaction != dispatched.transaction_id.as_str()
            || Some(lineage.dispatch.as_str()) != dispatched.dispatch_digest.as_deref()
            || lineage.effect != effect_from_request(request)?.digest().to_hex()
        {
            return Err(invalid());
        }
        let native = port
            .observe_attempt(&DisplayAttemptQuery::new(request, dispatched)?)
            .map_err(|_| invalid())?;
        let state = attempt_state(&native, request, dispatched)?;
        let target = match state.as_str() {
            "pending" | "confirmed" => DisplayVerificationTarget::Desired,
            "restored" => DisplayVerificationTarget::Restored {
                native_baseline_guard: *guard,
            },
            _ => return Err(invalid()),
        };
        let after = native.observed_at_unix_ms.max(root.observed_at_unix_ms);
        if !matches!(verifier.verify_layout(request, target, after),
            Ok(result) if result.disposition == VerificationDisposition::Satisfied)
        {
            return Err(invalid());
        }
        let checked = self
            .previews
            .observe(&query)
            .map_err(|_| invalid())?
            .observation;
        if checked.sequence <= root.sequence
            || DisplaySuccessorFacts::from_envelope(&checked, &context.scope, now_ms()?)
                .map_err(|_| invalid())?
                != facts
        {
            return Err(invalid());
        }
        root.require_current(now_ms()?).map_err(|_| invalid())?;
        native.require_current(now_ms()?).map_err(|_| invalid())?;
        self.require_successor_context(principal, context)?;
        self.require_successor_claim(&principal_id, request, context)?;
        // First evidence is immutable. Later reads validate the same Root
        // spend/checkpoint and retain their own freshness, never rewrite it.
        let key = claim_key("verified", request.request_id.as_str())?;
        let fields = [
            "linura.display.successor-verified.v1".to_owned(),
            principal.as_str().into(),
            request.request_id.as_str().into(),
            crate::durable_authority::digest_request(request)?
                .as_str()
                .into(),
            lineage.record.clone(),
            lineage.checkpoint.clone(),
            lineage.dispatch.clone(),
            crate::durable_authority::digest_observation(&root)?
                .as_str()
                .into(),
            crate::durable_authority::digest_observation(&native)?
                .as_str()
                .into(),
            now_ms()?.to_string(),
        ];
        match self.display_journal()?.load(&principal_id, &key) {
            Ok(old) => {
                let old_fields = record_fields(old.canonical())?;
                if old.principal() != &principal_id
                    || old.request_id() != &key
                    || old_fields.len() != fields.len()
                    || old_fields[..7] != fields[..7]
                    || completed::unsigned(&old_fields[9])? == 0
                    || completed::unsigned(&old_fields[9])? > now_ms()?
                {
                    return Err(invalid());
                }
                content(&old_fields[7])?;
                content(&old_fields[8])?;
            }
            Err(TransactionStoreError::NotFound) => {
                let bytes = completed::encode(&fields)?;
                self.request_journal
                    .as_deref_mut()
                    .ok_or_else(invalid)?
                    .retain(
                        &RetainedRequest::new(principal_id.clone(), key.clone(), bytes.clone())
                            .map_err(|_| invalid())?,
                    )
                    .map_err(|_| invalid())?;
                if self
                    .display_journal()?
                    .load(&principal_id, &key)
                    .map_err(|_| invalid())?
                    .canonical()
                    != bytes
                {
                    return Err(invalid());
                }
            }
            Err(_) => return Err(invalid()),
        }
        root.require_current(now_ms()?).map_err(|_| invalid())?;
        native.require_current(now_ms()?).map_err(|_| invalid())?;
        Ok(())
    }
    /// A distinct managed entry point. Ordinary Begin continues to refuse all
    /// retained completion ownership. A retry inspects the existing successor
    /// only; neither this method nor restart recovery repeats the handoff.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_successor_display_layout<
        P: DisplayTransactionPort,
        V: IndependentDisplayVerifier,
    >(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        predecessor: &RequestId,
        request: PlanDesiredStateRequest,
        approval_authorizer: &dyn ManagedApprovalAuthorizer,
        port: &mut P,
        verifier: &mut V,
    ) -> Result<DisplayLayoutReceipt, ManagedLifecycleError> {
        require_owner(&principal, &request)?;
        if actor.kind != ActorKind::Human || !actor.interactive {
            return Err(invalid());
        }
        let context = self.successor_context(&principal, predecessor)?;
        let terminal = self.current_finalization_comparison_context(&principal, predecessor)?;
        let previous = DisplayFinalizationMaterial::decode(terminal.intent.material())
            .map_err(|_| invalid())?;
        let next = material(&request)?;
        if !next.continues_after(previous.restoration().replacement())
            || next.continues_after(&next)
        {
            return Err(invalid());
        }
        let principal_id = PrincipalId::new(principal.as_str()).map_err(|_| invalid())?;
        let id = TransactionId::for_namespace(&principal_id, &request.request_id);
        match self.authority.snapshot(&id) {
            Ok(_) => self.require_successor_claim(&principal_id, &request, &context)?,
            Err(DurableAuthorityError::Transaction(detail))
                if detail == "durable transaction not found" =>
            {
                // This fresh independent current-frame proof is obtained before
                // the successor's opaque approval UI covers the ordinary frame.
                let proof =
                    self.verify_original_display_final_retirement(principal.clone(), predecessor)?;
                if proof
                    .root()
                    .completed()
                    .is_none_or(|v| v.record != context.root_released)
                    || proof.root().lineage().record != context.root_final
                {
                    return Err(invalid());
                }
            }
            Err(error) => return Err(error.into()),
        }
        self.begin_display_layout_inner(
            principal,
            actor,
            request,
            approval_authorizer,
            port,
            verifier,
            Some(context),
        )
    }

    fn successor_context(
        &self,
        principal: &AuthenticatedPrincipal,
        predecessor: &RequestId,
    ) -> Result<DisplaySuccessorContext, ManagedLifecycleError> {
        let context = self.current_finalization_comparison_context(principal, predecessor)?;
        let material = DisplayFinalizationMaterial::decode(context.intent.material())
            .map_err(|_| invalid())?;
        let history = self.finalization_history(principal, material.restoration_request())?;
        let actual = self
            .authority
            .matching_request_snapshot(principal, &context.request)?;
        if actual.state != TransactionState::Committed {
            return Err(invalid());
        }
        let principal_id = PrincipalId::new(principal.as_str()).map_err(|_| invalid())?;
        let prepared = Entry::load(
            self.display_journal()?,
            Kind::FinalPrepared,
            &principal_id,
            &context.request,
        )?;
        let verified = Entry::load(
            self.display_journal()?,
            Kind::FinalVerified,
            &principal_id,
            &context.request,
        )?;
        let released = Entry::load(
            self.display_journal()?,
            Kind::Released,
            &principal_id,
            &context.request,
        )?;
        if content(&released.fields[5])? != prepared.digest(Kind::FinalPrepared)
            || content(&released.fields[6])? != verified.digest(Kind::FinalVerified)
            || content(&verified.fields[5])? != prepared.digest(Kind::FinalPrepared)
            || released.fields[7] != verified.fields[7]
            || completed::unsigned(&released.fields[9])? > now_ms()?
        {
            return Err(invalid());
        }
        Ok(DisplaySuccessorContext {
            terminal: actual,
            restoration: history.restoration_snapshot,
            scope: material.recovery_scope().map_err(|_| invalid())?,
            released: released.digest(Kind::Released),
            root_final: released.fields[7].clone(),
            root_released: released.fields[8].clone(),
        })
    }

    pub(in crate::managed_lifecycle::display) fn require_successor_context(
        &self,
        principal: &AuthenticatedPrincipal,
        context: &DisplaySuccessorContext,
    ) -> Result<(), ManagedLifecycleError> {
        if self.successor_context(principal, &context.terminal.request_id)? != *context {
            return Err(invalid());
        }
        Ok(())
    }
    pub(in crate::managed_lifecycle::display) fn require_successor_root(
        &mut self,
        principal: &AuthenticatedPrincipal,
        context: &DisplaySuccessorContext,
    ) -> Result<(), ManagedLifecycleError> {
        self.require_successor_context(principal, context)?;
        // The new opaque review intentionally covers the old ordinary frame.
        // Recheck the actual original Root lifetime and immutable ancestry here;
        // the new canonical candidate independently re-observes its baseline.
        let (_, root) = self.observe_final_retirement(&context.scope)?;
        if root.phase() != 3
            || root.lineage().record != context.root_final
            || root
                .completed()
                .is_none_or(|v| v.record != context.root_released)
        {
            return Err(invalid());
        }
        self.require_successor_context(principal, context)
    }
    pub(in crate::managed_lifecycle::display) fn retain_successor_claim(
        &mut self,
        principal: &PrincipalId,
        request: &PlanDesiredStateRequest,
        context: &DisplaySuccessorContext,
    ) -> Result<(), ManagedLifecycleError> {
        for record in context.claims(principal, request)? {
            self.request_journal
                .as_deref_mut()
                .ok_or_else(invalid)?
                .retain(&record)
                .map_err(|_| invalid())?;
        }
        self.require_successor_claim(principal, request, context)
    }
    pub(in crate::managed_lifecycle::display) fn require_successor_claim(
        &self,
        principal: &PrincipalId,
        request: &PlanDesiredStateRequest,
        context: &DisplaySuccessorContext,
    ) -> Result<(), ManagedLifecycleError> {
        self.display_journal()?
            .integrity_check()
            .map_err(|_| invalid())?;
        for expected in context.claims(principal, request)? {
            if self
                .display_journal()?
                .load(principal, expected.request_id())
                .map_err(|_| invalid())?
                != expected
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}
