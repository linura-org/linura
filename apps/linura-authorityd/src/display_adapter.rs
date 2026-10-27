//! Fresh display verification uses independent native mechanisms, never a
//! dispatch acknowledgement, retained desired state or native attempt flag.
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use linura_control::{
    AuthenticatedPrincipal, DisplayLayoutSafetyReview, IndependentDisplayVerifier,
};
use linura_core::{CapabilityId, DisplayLayoutMaterial};
use linura_observation::DisplayObservationFacts;
use linura_protocol::PlanDesiredStateRequest;
use linura_provider_sdk::{Observer, VerificationDisposition, VerificationOutcome};

use crate::session_adapter::FreshSessionVerifier;

impl IndependentDisplayVerifier for FreshSessionVerifier {
    fn verify_layout(
        &mut self,
        request: &PlanDesiredStateRequest,
        restoration: bool,
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
        let expected = if restoration {
            intent.baseline()
        } else {
            intent.desired()
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
