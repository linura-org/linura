use std::time::Duration;

use linura_control::{AuthorizedEffect, AuthorizedEffectExecutor, IndependentManagedVerifier};
use linura_core::{SessionLockId, SessionTransitionId};
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
        let Some(observation) = self.channel.observe_lock_if_settled(&lock, self.sequence)? else {
            return VerificationOutcome::new(
                VerificationDisposition::Inconclusive,
                "known native lock transition has no settled postcondition yet",
            )
            .map_err(|error| error.to_string());
        };
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
        if !desired
            && !verify_release_once_or_retained(
                || self.channel.verify_released(&lock),
                || self.channel.retained_verified_release(&lock),
            )?
        {
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

// The first verification is consuming; only an explicit false can fall back
// to a read-only retained result. Transport/identity errors cannot be retried
// as success, and a second pass cannot consume a second release event.
fn verify_release_once_or_retained<F, G>(first: F, retained: G) -> Result<bool, String>
where
    F: FnOnce() -> Result<bool, String>,
    G: FnOnce() -> Result<bool, String>,
{
    if first()? { Ok(true) } else { retained() }
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
        verify_native_transition(
            &target,
            &observation,
            || {
                self.sequence = self
                    .sequence
                    .checked_add(1)
                    .ok_or("native verifier sequence exhausted")?;
                self.channel
                    .observe_lock_if_settled(target.lock(), self.sequence)
            },
            || {
                u64::try_from(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|_| "native verification clock is unsupported")?
                        .as_millis(),
                )
                .map_err(|_| "native verification clock overflow".to_owned())
            },
        )
    }
}

fn verify_native_transition<C, T>(
    target: &SessionTransitionId,
    observation: &linura_observation::ObservationEnvelope,
    coverage: C,
    mut now: T,
) -> Result<VerificationOutcome, String>
where
    C: FnOnce() -> Result<Option<linura_observation::ObservationEnvelope>, String>,
    T: FnMut() -> Result<u64, String>,
{
    use linura_control::SessionTransitionPostcondition as Postcondition;
    // Canonical native review decides whether coverage can establish completion.
    // Probing the owner while logind is still preparing to sleep may span the
    // suspend itself and must not turn that known pending state into a failed
    // lock observation. No native fact or coverage result is accepted stale.
    let native =
        linura_control::review_session_transition_postcondition(target, observation, None, now()?)
            .map_err(|e| e.to_string())?;
    let result = if native == Postcondition::SecureCoverageRequired {
        let coverage = coverage()?;
        linura_control::review_session_transition_postcondition(
            target,
            observation,
            coverage.as_ref(),
            now()?,
        )
        .map_err(|e| e.to_string())?
    } else {
        native
    };
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
        Postcondition::Indeterminate | Postcondition::SecureCoverageRequired => (
            VerificationDisposition::Inconclusive,
            "native transition outcome remains ambiguous; replay is forbidden",
        ),
    };
    VerificationOutcome::new(disposition, detail).map_err(|e| e.to_string())
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
    use linura_core::{CapabilityId, ProviderId, ResourceId, SessionTransition};
    use linura_observation::ObservationEnvelope;
    use std::cell::Cell;
    use std::collections::BTreeMap;

    fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| unreachable!("{error:?}"))
    }

    fn transition_facts(
        action: SessionTransition,
    ) -> (
        SessionTransitionId,
        ObservationEnvelope,
        ObservationEnvelope,
    ) {
        let lock = value(SessionLockId::from_resource(&value(ResourceId::new(
            "session:lock:abcd1234-1234-4567-89ab-0123456789ab:1000:c2:42:98765432-1234-4567-89ab-0123456789ab:7",
        ))));
        let target = value(SessionTransitionId::new(lock.clone(), action));
        let native = ObservationEnvelope {
            provider: value(ProviderId::new("logind")),
            capability: value(CapabilityId::new("session.transition.observe")),
            resource: value(target.resource_id()),
            authority: ObservationAuthority::NativeApi,
            observed_at_unix_ms: 1000,
            valid_for_ms: 2000,
            sequence: 1,
            attributes: BTreeMap::from([
                (
                    "current_boot_id".into(),
                    ObservedValue::Text(lock.epoch().boot().as_str().into()),
                ),
                ("target_epoch_present".into(), ObservedValue::Bool(true)),
                ("successful_suspend_cycles".into(), ObservedValue::U64(11)),
                (
                    "suspend_test_mode".into(),
                    ObservedValue::Text("none".into()),
                ),
                ("preparing_for_sleep".into(), ObservedValue::Bool(false)),
            ]),
        };
        let mut coverage = native.clone();
        coverage.provider = value(ProviderId::new("session-locker"));
        coverage.capability = value(CapabilityId::new("session.secure-lock.observe"));
        coverage.resource = value(lock.resource_id());
        coverage.attributes = BTreeMap::from([
            (
                "boot_id".into(),
                ObservedValue::Text(lock.epoch().boot().as_str().into()),
            ),
            ("uid".into(), ObservedValue::U64(1000)),
            ("session_id".into(), ObservedValue::Text("c2".into())),
            ("created_monotonic_us".into(), ObservedValue::U64(42)),
            (
                "security_owner_invocation".into(),
                ObservedValue::Text(lock.security_owner_invocation().as_str().into()),
            ),
            (
                "lock_generation".into(),
                ObservedValue::U64(lock.generation()),
            ),
            ("secure".into(), ObservedValue::Bool(true)),
            (
                "lock_protocol".into(),
                ObservedValue::Text("ext-session-lock-v1".into()),
            ),
        ]);
        (target, native, coverage)
    }

    #[test]
    fn suspend_verifier_waits_for_typed_pending_coverage_without_inferring_a_kernel_cycle() {
        let (target, mut native, _) = transition_facts(SessionTransition::Suspend {
            successful_cycles_before: 10,
        });
        assert_eq!(
            value(verify_native_transition(
                &target,
                &native,
                || Ok(None),
                || Ok(1100)
            ))
            .disposition,
            VerificationDisposition::Inconclusive
        );
        native
            .attributes
            .insert("successful_suspend_cycles".into(), ObservedValue::U64(10));
        assert_eq!(
            value(verify_native_transition(
                &target,
                &native,
                || unreachable!("an unchanged native cycle cannot require coverage"),
                || Ok(1100)
            ))
            .disposition,
            VerificationDisposition::NotSatisfied
        );
        native
            .attributes
            .insert("successful_suspend_cycles".into(), ObservedValue::U64(11));
        assert!(
            verify_native_transition(
                &target,
                &native,
                || Err("unavailable native coverage".into()),
                || Ok(1100)
            )
            .is_err()
        );
        assert!(
            verify_native_transition(
                &target,
                &native,
                || Ok(None),
                || Err("unsupported clock".into())
            )
            .is_err()
        );
        assert!(verify_native_transition(&target, &native, || Ok(None), || Ok(4000)).is_err());
        native.provider = value(ProviderId::new("untrusted"));
        assert!(verify_native_transition(&target, &native, || Ok(None), || Ok(1100)).is_err());
    }

    #[test]
    fn suspend_verifier_keeps_native_preparation_inconclusive_until_resume() {
        let (target, mut native, coverage) = transition_facts(SessionTransition::Suspend {
            successful_cycles_before: 10,
        });
        native
            .attributes
            .insert("preparing_for_sleep".into(), ObservedValue::Bool(true));
        for cycles in [10, 11] {
            native.attributes.insert(
                "successful_suspend_cycles".into(),
                ObservedValue::U64(cycles),
            );
            assert_eq!(
                value(verify_native_transition(
                    &target,
                    &native,
                    || unreachable!("native preparation must not query lock coverage"),
                    || Ok(1100)
                ))
                .disposition,
                VerificationDisposition::Inconclusive
            );
        }
        native
            .attributes
            .insert("preparing_for_sleep".into(), ObservedValue::Bool(false));
        assert_eq!(
            value(verify_native_transition(
                &target,
                &native,
                || Ok(Some(coverage)),
                || Ok(1100)
            ))
            .disposition,
            VerificationDisposition::Satisfied
        );
    }

    #[test]
    fn suspend_verifier_still_requires_exact_fresh_secure_coverage_and_one_completed_cycle() {
        let (target, native, coverage) = transition_facts(SessionTransition::Suspend {
            successful_cycles_before: 10,
        });
        assert_eq!(
            value(verify_native_transition(
                &target,
                &native,
                || Ok(Some(coverage.clone())),
                || Ok(1100)
            ))
            .disposition,
            VerificationDisposition::Satisfied
        );
        let mut insecure = coverage.clone();
        insecure
            .attributes
            .insert("secure".into(), ObservedValue::Bool(false));
        assert_eq!(
            value(verify_native_transition(
                &target,
                &native,
                || Ok(Some(insecure)),
                || Ok(1100)
            ))
            .disposition,
            VerificationDisposition::Inconclusive
        );
        for cycles in [9, 12, u64::MAX] {
            let mut changed = native.clone();
            changed.attributes.insert(
                "successful_suspend_cycles".into(),
                ObservedValue::U64(cycles),
            );
            assert_eq!(
                value(verify_native_transition(
                    &target,
                    &changed,
                    || unreachable!("an ambiguous native cycle cannot require coverage"),
                    || Ok(1100)
                ))
                .disposition,
                VerificationDisposition::Inconclusive
            );
        }
        let mut replaced = coverage.clone();
        replaced
            .attributes
            .insert("lock_generation".into(), ObservedValue::U64(8));
        assert!(
            verify_native_transition(&target, &native, || Ok(Some(replaced)), || Ok(1100)).is_err()
        );
    }

    #[test]
    fn suspend_verifier_queries_coverage_once_only_after_native_completion() {
        let (target, native, coverage) = transition_facts(SessionTransition::Suspend {
            successful_cycles_before: 10,
        });
        let reads = Cell::new(0);
        let clocks = Cell::new(0);
        let result = value(verify_native_transition(
            &target,
            &native,
            || {
                // Native evidence has already passed canonical validation.
                assert_eq!(clocks.get(), 1);
                reads.set(reads.get() + 1);
                Ok(Some(coverage))
            },
            || {
                clocks.set(clocks.get() + 1);
                Ok(1100)
            },
        ));
        assert_eq!(result.disposition, VerificationDisposition::Satisfied);
        assert_eq!(reads.get(), 1);
        assert_eq!(clocks.get(), 2);
    }

    #[test]
    fn suspend_verifier_rejects_bad_native_evidence_before_requesting_coverage() {
        let (target, native, _) = transition_facts(SessionTransition::Suspend {
            successful_cycles_before: 10,
        });
        for attribute in [
            "preparing_for_sleep",
            "successful_suspend_cycles",
            "suspend_test_mode",
            "current_boot_id",
            "target_epoch_present",
        ] {
            for remove in [false, true] {
                let mut malformed = native.clone();
                if remove {
                    malformed.attributes.remove(attribute);
                } else {
                    malformed
                        .attributes
                        .insert(attribute.into(), ObservedValue::Text("unknown".into()));
                }
                assert!(
                    verify_native_transition(
                        &target,
                        &malformed,
                        || unreachable!("malformed native evidence cannot request coverage"),
                        || Ok(1100),
                    )
                    .is_err(),
                    "attribute={attribute}, remove={remove}"
                );
            }
        }
        for fault in [
            "provider",
            "authority",
            "capability",
            "resource",
            "freshness",
        ] {
            let mut invalid = native.clone();
            match fault {
                "provider" => invalid.provider = value(ProviderId::new("untrusted")),
                "authority" => invalid.authority = ObservationAuthority::SyntheticTest,
                "capability" => invalid.capability = value(CapabilityId::new("wrong.observe")),
                "resource" => invalid.resource = value(ResourceId::new("wrong:resource")),
                _ => invalid.observed_at_unix_ms = 1200,
            }
            assert!(
                verify_native_transition(
                    &target,
                    &invalid,
                    || unreachable!("invalid native envelope cannot request coverage"),
                    || Ok(1100),
                )
                .is_err(),
                "fault={fault}"
            );
        }
    }

    #[test]
    fn suspend_verifier_keeps_required_coverage_failures_hard_without_retry() {
        let (target, native, _) = transition_facts(SessionTransition::Suspend {
            successful_cycles_before: 10,
        });
        for failure in [
            "native-unavailable",
            "denied",
            "timeout",
            "identity-changed",
        ] {
            let reads = Cell::new(0);
            assert_eq!(
                verify_native_transition(
                    &target,
                    &native,
                    || {
                        reads.set(reads.get() + 1);
                        Err(failure.into())
                    },
                    || Ok(1100),
                ),
                Err(failure.into())
            );
            assert_eq!(reads.get(), 1);
        }
    }

    #[test]
    fn suspend_verifier_rechecks_original_native_freshness_after_coverage() {
        let (target, native, coverage) = transition_facts(SessionTransition::Suspend {
            successful_cycles_before: 10,
        });
        let mut fresh_coverage = coverage;
        fresh_coverage.observed_at_unix_ms = 2999;
        let reads = Cell::new(0);
        let mut times = [1100, 3000].into_iter();
        assert!(
            verify_native_transition(
                &target,
                &native,
                || {
                    reads.set(reads.get() + 1);
                    Ok(Some(fresh_coverage))
                },
                || Ok(times
                    .next()
                    .unwrap_or_else(|| unreachable!("extra clock read"))),
            )
            .is_err()
        );
        assert_eq!(reads.get(), 1);
        assert!(times.next().is_none());
    }

    #[test]
    fn suspend_verifier_rejects_stale_coverage_and_final_clock_failure() {
        let (target, native, mut coverage) = transition_facts(SessionTransition::Suspend {
            successful_cycles_before: 10,
        });
        coverage.observed_at_unix_ms = 1;
        coverage.valid_for_ms = 100;
        assert!(
            verify_native_transition(&target, &native, || Ok(Some(coverage)), || Ok(1100)).is_err()
        );
        let (_, _, fresh) = transition_facts(SessionTransition::Suspend {
            successful_cycles_before: 10,
        });
        let mut times = [Ok(1100), Err("unsupported final clock".into())].into_iter();
        assert_eq!(
            verify_native_transition(
                &target,
                &native,
                || Ok(Some(fresh)),
                || times
                    .next()
                    .unwrap_or_else(|| unreachable!("extra clock read")),
            ),
            Err("unsupported final clock".into())
        );
    }

    #[test]
    fn terminating_verification_never_queries_coverage_or_infers_current_power_state() {
        for action in [
            SessionTransition::Logout,
            SessionTransition::Reboot,
            SessionTransition::PowerOff,
        ] {
            let (target, mut native, _) = transition_facts(action);
            assert_eq!(
                value(verify_native_transition(
                    &target,
                    &native,
                    || unreachable!("terminating coverage query"),
                    || Ok(1100)
                ))
                .disposition,
                VerificationDisposition::NotSatisfied
            );
            native
                .attributes
                .insert("target_epoch_present".into(), ObservedValue::Bool(false));
            if !matches!(target.transition(), SessionTransition::Logout) {
                native.attributes.insert(
                    "current_boot_id".into(),
                    ObservedValue::Text("abcd1234-1234-4567-89ab-0123456789ac".into()),
                );
            }
            let result = value(verify_native_transition(
                &target,
                &native,
                || unreachable!("terminating coverage query"),
                || Ok(1100),
            ));
            assert_eq!(result.disposition, VerificationDisposition::Satisfied);
            if !matches!(target.transition(), SessionTransition::Logout) {
                assert!(result.detail.contains("not current power-off or causation"));
            }
        }
    }

    #[test]
    fn two_verification_passes_consume_once_and_read_retained_release() {
        let state = Cell::new(0_u8);
        let consumed = Cell::new(0_u8);
        let reread = Cell::new(0_u8);
        for _ in 0..2 {
            assert_eq!(
                verify_release_once_or_retained(
                    || {
                        if state.get() == 0 {
                            state.set(1);
                            consumed.set(consumed.get() + 1);
                            Ok(true)
                        } else {
                            Ok(false)
                        }
                    },
                    || {
                        reread.set(reread.get() + 1);
                        Ok(state.get() == 1)
                    },
                ),
                Ok(true)
            );
        }
        assert_eq!(consumed.get(), 1);
        assert_eq!(reread.get(), 1);
    }

    #[test]
    fn retained_release_does_not_mask_errors_or_unverified_state() {
        let fallback_calls = Cell::new(0);
        assert_eq!(
            verify_release_once_or_retained(
                || Ok(true),
                || {
                    fallback_calls.set(fallback_calls.get() + 1);
                    Ok(false)
                }
            ),
            Ok(true)
        );
        assert_eq!(fallback_calls.get(), 0);
        assert_eq!(
            verify_release_once_or_retained(
                || Ok(false),
                || {
                    fallback_calls.set(fallback_calls.get() + 1);
                    Ok(false)
                }
            ),
            Ok(false)
        );
        assert_eq!(fallback_calls.get(), 1);
        assert_eq!(
            verify_release_once_or_retained(
                || Err("native transport error".to_owned()),
                || {
                    fallback_calls.set(fallback_calls.get() + 1);
                    Ok(true)
                }
            ),
            Err("native transport error".to_owned())
        );
        assert_eq!(fallback_calls.get(), 1);
        assert!(
            verify_release_once_or_retained(
                || Ok(false),
                || Err("retained release unavailable".to_owned())
            )
            .is_err()
        );
    }

    #[test]
    fn transition_parser_rejects_encoding_provider_operation_and_action_substitution() {
        let resource = ResourceId::new("session:transition:reboot:0:abcd1234-1234-4567-89ab-0123456789ab:1000:c2:42:98765432-1234-4567-89ab-0123456789ab:7")
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
                    bad.provider =
                        ProviderId::new("session-locker").unwrap_or_else(|e| unreachable!("{e}"))
                }
                "operation" => bad.operation = "power-off-now".into(),
                _ => {
                    bad.resource =
                        ResourceId::new(resource.as_str().replace("reboot:", "power-off:"))
                            .unwrap_or_else(|e| unreachable!("{e}"))
                }
            }
            assert!(parse_transition_effect(&bad).is_err());
        }
    }
    #[test]
    fn parser_rejects_parallel_or_noncanonical_effect_encoding() {
        let resource = ResourceId::new("session:lock:abcd1234-1234-4567-89ab-0123456789ab:1000:c2:42:98765432-1234-4567-89ab-0123456789ab:7").unwrap_or_else(|e| unreachable!("{e}"));
        let lock = SessionLockId::from_resource(&resource).unwrap_or_else(|e| unreachable!("{e}"));
        let effect = linura_executor_session::lock_effect(&lock, false)
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(parse_effect(&effect), Ok((lock, false)));
        for change in ["payload", "provider", "operation"] {
            let mut bad = effect.clone();
            match change {
                "payload" => bad.canonical_payload.push(b'\n'),
                "provider" => {
                    bad.provider =
                        ProviderId::new("untrusted").unwrap_or_else(|e| unreachable!("{e}"))
                }
                _ => bad.operation = "unlock-now".into(),
            }
            assert!(parse_effect(&bad).is_err());
        }
    }
}
