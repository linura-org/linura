use std::time::Duration;

use linura_control::{AuthorizedEffect, AuthorizedEffectExecutor, IndependentManagedVerifier};
use linura_core::{SessionLockId, SessionTransition, SessionTransitionId};
use linura_linux_session::NativeSessionChannel;
use linura_observation::{ObservationAuthority, ObservedValue};
use linura_provider_sdk::{
    EffectDescriptor, ExecutionOutcome, Observer, VerificationDisposition, VerificationOutcome,
};

#[derive(Debug)]
pub(crate) struct SessionExecutorClient {
    pub(crate) channel: NativeSessionChannel,
}
impl AuthorizedEffectExecutor for SessionExecutorClient {
    fn execute_authorized(
        &mut self,
        authorization: AuthorizedEffect,
    ) -> Result<ExecutionOutcome, String> {
        let (effect, binding) = authorization.into_executor_request();
        if effect.resource.as_str().starts_with("session:transition:") {
            let target = parse_transition_effect(&effect)?;
            binding.validate_for(&effect).map_err(|e| e.to_string())?;
            return self.channel.handoff_prepared_transition(&target, &binding);
        }
        let (lock, secure) = parse_effect(&effect)?;
        binding.validate_for(&effect).map_err(|e| e.to_string())?;
        self.channel.handoff_prepared_lock(&lock, secure, &binding)
    }
}

#[derive(Debug)]
pub(crate) struct FreshSessionVerifier {
    pub(crate) channel: NativeSessionChannel,
    pub(crate) sequence: u64,
    pub(crate) transitions: linura_linux_observation::LogindSessionObserver,
}
impl IndependentManagedVerifier for FreshSessionVerifier {
    fn verify_effect(&mut self, effect: &EffectDescriptor) -> Result<VerificationOutcome, String> {
        if effect.resource.as_str().starts_with("session:transition:") {
            return self.verify_transition(effect);
        }
        let (lock, desired) = parse_effect(effect)?;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or("native verifier sequence exhausted")?;
        let observation = self.channel.observe_lock(&lock, self.sequence)?;
        observation
            .validate(
                &effect.provider,
                &effect.resource,
                &linura_core::CapabilityId::new("session.secure-lock.observe")
                    .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
        let now = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| "native verification clock is unsupported")?
                .as_millis(),
        )
        .map_err(|_| "native verification clock overflow")?;
        observation
            .require_current(now)
            .map_err(|e| e.to_string())?;
        let observed = match observation.attributes.get("secure") {
            Some(ObservedValue::Bool(secure))
                if observation.authority == ObservationAuthority::NativeApi =>
            {
                *secure
            }
            _ => return Err("independent native lock evidence is unsupported".into()),
        };
        if observed != desired {
            return VerificationOutcome::new(
                VerificationDisposition::NotSatisfied,
                "fresh native lock state differs from the prepared postcondition",
            )
            .map_err(|e| e.to_string());
        }
        if !desired && !self.channel.verify_released(&lock)? {
            return Err("native owner did not independently confirm release".into());
        }
        VerificationOutcome::new(
            VerificationDisposition::Satisfied,
            "independent current native lock postcondition verified",
        )
        .map_err(|e| e.to_string())
    }
    fn post_dispatch_settle_attempts(&self) -> usize {
        50
    }
    fn post_dispatch_settle_interval(&self) -> Duration {
        Duration::from_millis(100)
    }
}

impl FreshSessionVerifier {
    fn verify_transition(
        &mut self,
        effect: &EffectDescriptor,
    ) -> Result<VerificationOutcome, String> {
        let target = parse_transition_effect(effect)?;
        let capability = linura_core::CapabilityId::new("session.transition.observe")
            .map_err(|e| e.to_string())?;
        // This observer has its own native connection and reads again after
        // dispatch. Neither the prepared plan nor the executor reply supplies
        // a completion flag to independent verification.
        let observation = self
            .transitions
            .observe_authoritative(&effect.resource, &capability)
            .map_err(|e| e.to_string())?;
        let coverage = if matches!(target.transition(), SessionTransition::Suspend { .. }) {
            self.sequence = self
                .sequence
                .checked_add(1)
                .ok_or("native verifier sequence exhausted")?;
            Some(self.channel.observe_lock(target.lock(), self.sequence)?)
        } else {
            None
        };
        let now = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| "native verification clock is unsupported")?
                .as_millis(),
        )
        .map_err(|_| "native verification clock overflow")?;
        let result = linura_control::review_session_transition_postcondition(
            &target,
            &observation,
            coverage.as_ref(),
            now,
        )
        .map_err(|e| e.to_string())?;
        use linura_control::SessionTransitionPostcondition as Postcondition;
        let (disposition, detail) = match result {
            Postcondition::ResumedSecurely => (
                VerificationDisposition::Satisfied,
                "independent native suspend cycle and retained secure coverage verified",
            ),
            Postcondition::OriginalSessionEnded => (
                VerificationDisposition::Satisfied,
                "independent native evidence proves the original session ended",
            ),
            Postcondition::OriginalBootEnded => (
                VerificationDisposition::Satisfied,
                "independent native evidence proves the original boot ended, not current power-off or causation",
            ),
            Postcondition::NotSatisfied => (
                VerificationDisposition::NotSatisfied,
                "fresh native transition postcondition is not satisfied",
            ),
            Postcondition::Indeterminate => (
                VerificationDisposition::Inconclusive,
                "native transition outcome remains ambiguous; replay is forbidden",
            ),
        };
        VerificationOutcome::new(disposition, detail).map_err(|e| e.to_string())
    }
}

pub(crate) fn parse_transition_effect(
    effect: &EffectDescriptor,
) -> Result<SessionTransitionId, String> {
    let target = SessionTransitionId::from_resource(&effect.resource).map_err(|e| e.to_string())?;
    if linura_executor_session::transition_effect(&target)? != *effect {
        return Err("session transition effect is not canonical".into());
    }
    Ok(target)
}

pub(crate) fn parse_effect(effect: &EffectDescriptor) -> Result<(SessionLockId, bool), String> {
    let lock = SessionLockId::from_resource(&effect.resource).map_err(|e| e.to_string())?;
    for secure in [true, false] {
        if linura_executor_session::lock_effect(&lock, secure)? == *effect {
            return Ok((lock, secure));
        }
    }
    Err("session effect is outside the canonical native lock contract".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transition_parser_rejects_encoding_provider_operation_and_action_substitution() {
        let resource = linura_core::ResourceId::new("session:transition:reboot:0:abcd1234-1234-4567-89ab-0123456789ab:1000:c2:42:98765432-1234-4567-89ab-0123456789ab:7")
            .unwrap_or_else(|e| unreachable!("{e}"));
        let target =
            SessionTransitionId::from_resource(&resource).unwrap_or_else(|e| unreachable!("{e}"));
        let effect = linura_executor_session::transition_effect(&target)
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(parse_transition_effect(&effect), Ok(target));
        assert!(parse_effect(&effect).is_err());
        for change in ["payload", "provider", "operation", "action"] {
            let mut bad = effect.clone();
            match change {
                "payload" => bad.canonical_payload.push(b'\n'),
                "provider" => {
                    bad.provider = linura_core::ProviderId::new("session-locker")
                        .unwrap_or_else(|e| unreachable!("{e}"))
                }
                "operation" => bad.operation = "power-off-now".into(),
                _ => {
                    bad.resource = linura_core::ResourceId::new(
                        resource.as_str().replace("reboot:", "power-off:"),
                    )
                    .unwrap_or_else(|e| unreachable!("{e}"))
                }
            }
            assert!(parse_transition_effect(&bad).is_err());
        }
    }
    #[test]
    fn parser_rejects_parallel_or_noncanonical_effect_encoding() {
        let resource = linura_core::ResourceId::new("session:lock:abcd1234-1234-4567-89ab-0123456789ab:1000:c2:42:98765432-1234-4567-89ab-0123456789ab:7").unwrap_or_else(|e| unreachable!("{e}"));
        let lock = SessionLockId::from_resource(&resource).unwrap_or_else(|e| unreachable!("{e}"));
        let effect = linura_executor_session::lock_effect(&lock, false)
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(parse_effect(&effect), Ok((lock, false)));
        for change in ["payload", "provider", "operation"] {
            let mut bad = effect.clone();
            match change {
                "payload" => bad.canonical_payload.push(b'\n'),
                "provider" => {
                    bad.provider = linura_core::ProviderId::new("untrusted")
                        .unwrap_or_else(|e| unreachable!("{e}"))
                }
                _ => bad.operation = "unlock-now".into(),
            }
            assert!(parse_effect(&bad).is_err());
        }
    }
}
