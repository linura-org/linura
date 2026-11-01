//! Fresh display verification uses independent native mechanisms, never a
//! dispatch acknowledgement, retained desired state or native attempt flag.
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use linura_control::{
    AuthenticatedPrincipal, AuthorizedDisplayApplication, AuthorizedDisplayContinuation,
    DisplayAttemptQuery, DisplayLayoutSafetyReview, DisplayTransactionPort,
    DisplayVerificationTarget, IndependentDisplayVerifier,
};
use linura_core::{CapabilityId, DisplayLayoutMaterial};
use linura_observation::DisplayObservationFacts;
use linura_protocol::PlanDesiredStateRequest;
use linura_provider_sdk::{Observer, VerificationDisposition, VerificationOutcome};

use crate::session_adapter::{FreshSessionVerifier, SessionExecutorClient};

impl DisplayTransactionPort for SessionExecutorClient {
    fn dispatch_layout(
        &mut self,
        application: AuthorizedDisplayApplication,
        request: &PlanDesiredStateRequest,
        deadline_unix_ms: u64,
    ) -> Result<linura_provider_sdk::ExecutionOutcome, String> {
        let material = display_material(request)?;
        let (authorization, native_guard) = application.into_executor_request();
        let (effect, binding) = authorization.into_executor_request();
        if effect != linura_provider_sdk::display_layout_effect(material)? {
            return Err(
                "prepared display effect differs from its canonical structured request".into(),
            );
        }
        binding.validate_for(&effect).map_err(|e| e.to_string())?;
        self.channel
            .handoff_prepared_display(material, &binding, deadline_unix_ms, &native_guard)
    }

    fn observe_attempt(
        &mut self,
        query: &DisplayAttemptQuery<'_>,
    ) -> Result<linura_observation::ObservationEnvelope, String> {
        let material = display_material(query.request())?;
        self.display_sequence = self
            .display_sequence
            .checked_add(1)
            .ok_or("native display attempt sequence exhausted")?;
        self.channel.observe_display_attempt(
            material,
            query.transaction_id(),
            &linura_provider_sdk::ComponentDigest::parse_hex(query.dispatch_digest())
                .map_err(|e| e.to_string())?,
            query.deadline_unix_ms(),
            self.display_sequence,
        )
    }

    fn continue_layout(
        &mut self,
        continuation: AuthorizedDisplayContinuation,
    ) -> Result<(), String> {
        let material = display_material(continuation.request())?;
        let parse = |value: &str| {
            linura_provider_sdk::ComponentDigest::parse_hex(value).map_err(|e| e.to_string())
        };
        let decision_digest = |value: &str| {
            let value = linura_transaction::ContentDigest::new(value).map_err(|e| e.to_string())?;
            parse(value.hex())
        };
        let native = linura_linux_session::NativeDisplayContinuation::new(
            material,
            continuation.transaction_id(),
            parse(continuation.dispatch_digest())?,
            continuation.deadline_unix_ms(),
            decision_digest(continuation.decision_digest())?,
            decision_digest(continuation.protected_decision_digest())?,
            continuation.action() == linura_control::DisplayContinuationAction::Confirm,
        )?;
        self.channel.handoff_display_continuation(&native)?;
        // A native phase acknowledges only the attempted decision. Control
        // obtains independent fresh layout/coverage evidence before retirement.
        Ok(())
    }
}

pub(crate) fn display_material(request: &PlanDesiredStateRequest) -> Result<&str, String> {
    if request.provider.as_str() != linura_observation::DISPLAY_PROVIDER
        || request.observation_capability.as_str() != linura_observation::DISPLAY_OUTPUTS_CAPABILITY
        || request.desired_state.len() != 1
    {
        return Err("display adapter received an unsupported canonical effect shape".into());
    }
    let text = request
        .desired_state
        .get("layout")
        .ok_or("display intent is missing")?;
    let material = DisplayLayoutMaterial::decode(text).map_err(|e| e.to_string())?;
    if material
        .topology()
        .resource_id()
        .map_err(|e| e.to_string())?
        != request.resource
    {
        return Err("display adapter resource differs from its complete intent".into());
    }
    Ok(text)
}

impl IndependentDisplayVerifier for FreshSessionVerifier {
    fn verify_layout(
        &mut self,
        request: &PlanDesiredStateRequest,
        target: DisplayVerificationTarget,
        after_unix_ms: u64,
    ) -> Result<VerificationOutcome, String> {
        let started = Instant::now();
        if request.provider.as_str() != linura_observation::DISPLAY_PROVIDER
            || request.observation_capability.as_str()
                != linura_observation::DISPLAY_OUTPUTS_CAPABILITY
            || request.desired_state.len() != 1
        {
            return Err("display verifier received an unsupported effect shape".into());
        }
        let material = DisplayLayoutMaterial::decode(
            request
                .desired_state
                .get("layout")
                .ok_or("display intent is missing")?,
        )
        .map_err(|e| e.to_string())?;
        if material
            .topology()
            .resource_id()
            .map_err(|e| e.to_string())?
            != request.resource
        {
            return Err("display verifier resource differs from its intent".into());
        }
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or("display verifier sequence exhausted")?;
        // Both canonical capabilities are projected from one coherent native
        // sample, preserving its conservative boot-clock timestamp and expiry.
        let (display, coverage) = self.channel.observe_display_pair(
            material.topology(),
            material.lock(),
            self.sequence,
        )?;
        let session = self
            .transitions
            .observe_authoritative(
                &material
                    .topology()
                    .session()
                    .resource_id()
                    .map_err(|e| e.to_string())?,
                &CapabilityId::new("session.epoch.observe").map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
        let now = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| "display verification clock is unsupported")?
                .as_millis(),
        )
        .map_err(|_| "display verification clock overflow")?;
        // This is one probe per mechanism, with no hidden settling or retry.
        // Control owns any additional scheduling. Never widen native freshness.
        if started.elapsed() >= Duration::from_secs(2) {
            return Err("display verification exceeded its aggregate budget".into());
        }
        let facts = DisplayObservationFacts::from_envelope(&display, material.topology(), now)
            .map_err(|e| e.to_string())?;
        let intent = material
            .validate_native(facts.inventory(), facts.capabilities())
            .map_err(|e| e.to_string())?;
        let restoration = matches!(target, DisplayVerificationTarget::Restored { .. });
        let expected = match target {
            DisplayVerificationTarget::Restored {
                native_baseline_guard,
            } => {
                if linura_provider_sdk::display_baseline_guard(&facts)? != native_baseline_guard {
                    return VerificationOutcome::new(
                        VerificationDisposition::NotSatisfied,
                        "fresh native baseline ownership differs from the original checkpoint",
                    )
                    .map_err(|e| e.to_string());
                }
                intent.baseline()
            }
            DisplayVerificationTarget::Desired => {
                if facts
                    .recovery_metadata()
                    .is_none_or(|metadata| metadata.values().any(|output| !output.linura_owned()))
                {
                    return VerificationOutcome::new(
                        VerificationDisposition::NotSatisfied,
                        "fresh native desired layout has no complete Linura overlay ownership",
                    )
                    .map_err(|e| e.to_string());
                }
                intent.desired()
            }
        };
        let principal =
            AuthenticatedPrincipal::new(format!("unix:uid:{}", intent.lock().epoch().uid()))
                .map_err(|e| e.to_string())?;
        // This principal is only the retained request's expected observation
        // scope. It grants no approval; Control separately authenticates caller
        // ownership and the exact durable transaction before invoking us.
        match DisplayLayoutSafetyReview::review_current_postcondition(
            &principal,
            expected,
            intent.lock(),
            &display,
            &session,
            &coverage,
            after_unix_ms,
            now,
        ) {
            Ok(_) => VerificationOutcome::new(
                VerificationDisposition::Satisfied,
                if restoration {
                    "independent native baseline and coverage verified"
                } else {
                    "independent native desired layout and coverage verified"
                },
            ),
            Err(linura_control::DisplaySafetyError::Postcondition) => VerificationOutcome::new(
                VerificationDisposition::NotSatisfied,
                "fresh native layout differs from the retained postcondition",
            ),
            Err(error) => return Err(error.to_string()),
        }
        .map_err(|e| e.to_string())
    }
}
