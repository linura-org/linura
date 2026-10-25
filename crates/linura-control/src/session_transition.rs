//! Independent S17 transition postconditions. This module neither authorizes
//! nor dispatches effects. Unknown native state remains ambiguous, never a cue
//! to replay a terminating operation or infer success from a lost transport.

use linura_core::{BootId, SessionTransition, SessionTransitionId};
use linura_observation::{ObservationEnvelope, ObservedValue};

use crate::SessionSafetyError;
use crate::session_safety::{validate_envelope, validate_native_lock};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionTransitionPostcondition {
    NotSatisfied,
    Indeterminate,
    /// The native transition is complete enough to require an independent
    /// secure-lock sample. This is not a satisfied postcondition or authority
    /// to dispatch; callers must review both fresh envelopes again afterward.
    SecureCoverageRequired,
    ResumedSecurely,
    OriginalSessionEnded,
    /// This proves the old boot ended, NOT that a currently observable host is
    /// still powered off or that a particular caller caused the transition.
    OriginalBootEnded,
}

/// Classify fresh native evidence for the retained exact transition identity.
/// Review without coverage first. Only `SecureCoverageRequired` requests an
/// independent lock sample; known pending native state must not start a probe
/// that could cross kernel sleep. Review both envelopes again at the current
/// time after sampling. Callers must still reconcile and durably commit; this
/// result is not a transaction receipt or executor credential.
pub fn review_session_transition_postcondition(
    transition: &SessionTransitionId,
    native: &ObservationEnvelope,
    secure_coverage: Option<&ObservationEnvelope>,
    now_unix_ms: u64,
) -> Result<SessionTransitionPostcondition, SessionSafetyError> {
    let resource = transition
        .resource_id()
        .map_err(|_| SessionSafetyError::IdentityMismatch)?;
    validate_envelope(
        native,
        "logind",
        "session.transition.observe",
        &resource,
        now_unix_ms,
    )?;
    let current_boot = match native.attributes.get("current_boot_id") {
        Some(ObservedValue::Text(boot)) => {
            BootId::new(boot.clone()).map_err(|_| SessionSafetyError::IdentityMismatch)?
        }
        _ => return Err(SessionSafetyError::IdentityMismatch),
    };
    let present = match native.attributes.get("target_epoch_present") {
        Some(ObservedValue::Bool(value)) => *value,
        _ => return Err(SessionSafetyError::UnsupportedSession),
    };
    let original_boot = transition.lock().epoch().boot() == &current_boot;
    if !original_boot && present {
        return Err(SessionSafetyError::IdentityMismatch);
    }
    use SessionTransitionPostcondition as ResultState;
    match transition.transition() {
        SessionTransition::Logout => Ok(if present {
            ResultState::NotSatisfied
        } else {
            ResultState::OriginalSessionEnded
        }),
        SessionTransition::Reboot | SessionTransition::PowerOff => Ok(if original_boot {
            ResultState::NotSatisfied
        } else {
            ResultState::OriginalBootEnded
        }),
        SessionTransition::Suspend {
            successful_cycles_before,
        } => {
            if !original_boot || !present {
                return Ok(ResultState::Indeterminate);
            }
            if native.attributes.get("suspend_test_mode")
                != Some(&ObservedValue::Text("none".into()))
            {
                return Err(SessionSafetyError::UnsupportedSession);
            }
            let preparing = match native.attributes.get("preparing_for_sleep") {
                Some(ObservedValue::Bool(value)) => *value,
                _ => return Err(SessionSafetyError::UnsupportedSession),
            };
            let cycles = match native.attributes.get("successful_suspend_cycles") {
                Some(ObservedValue::U64(value)) => *value,
                _ => return Err(SessionSafetyError::UnsupportedSession),
            };
            // A native admission reply can precede PrepareForSleep(false).
            // This known in-flight state proves no completion. Keep it inside
            // Control's existing bounded observation loop; never replay an effect.
            if preparing {
                return Ok(ResultState::Indeterminate);
            }
            if cycles == successful_cycles_before {
                return Ok(ResultState::NotSatisfied);
            }
            if successful_cycles_before.checked_add(1) != Some(cycles) {
                return Ok(ResultState::Indeterminate);
            }
            let Some(coverage) = secure_coverage else {
                return Ok(ResultState::SecureCoverageRequired);
            };
            if !validate_native_lock(transition.lock(), coverage, now_unix_ms)? {
                return Ok(ResultState::Indeterminate);
            }
            Ok(ResultState::ResumedSecurely)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_core::{CapabilityId, ProviderId, SessionLockId};
    use linura_observation::ObservationAuthority;
    use std::collections::BTreeMap;
    fn id<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| unreachable!("{error:?}"))
    }
    fn target(action: SessionTransition) -> SessionTransitionId {
        let lock = id(SessionLockId::from_resource(&id(
            linura_core::ResourceId::new(
                "session:lock:abcd1234-1234-4567-89ab-0123456789ab:1000:c2:42:98765432-1234-4567-89ab-0123456789ab:7",
            ),
        )));
        id(SessionTransitionId::new(lock, action))
    }
    fn observation(target: &SessionTransitionId) -> ObservationEnvelope {
        ObservationEnvelope {
            provider: id(ProviderId::new("logind")),
            capability: id(CapabilityId::new("session.transition.observe")),
            resource: id(target.resource_id()),
            authority: ObservationAuthority::NativeApi,
            observed_at_unix_ms: 1_000,
            valid_for_ms: 2_000,
            sequence: 1,
            attributes: BTreeMap::from([
                (
                    "current_boot_id".into(),
                    ObservedValue::Text(target.lock().epoch().boot().as_str().into()),
                ),
                ("target_epoch_present".into(), ObservedValue::Bool(true)),
                ("successful_suspend_cycles".into(), ObservedValue::U64(11)),
                (
                    "suspend_test_mode".into(),
                    ObservedValue::Text("none".into()),
                ),
                ("preparing_for_sleep".into(), ObservedValue::Bool(false)),
            ]),
        }
    }
    fn coverage(target: &SessionTransitionId) -> ObservationEnvelope {
        let lock = target.lock();
        let mut value = observation(target);
        value.provider = id(ProviderId::new("session-locker"));
        value.capability = id(CapabilityId::new("session.secure-lock.observe"));
        value.resource = id(lock.resource_id());
        value.attributes = BTreeMap::from([
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
        value
    }
    #[test]
    fn suspend_requires_one_native_completed_cycle_and_exact_fresh_secure_coverage() {
        let target = target(SessionTransition::Suspend {
            successful_cycles_before: 10,
        });
        let native = observation(&target);
        let coverage = coverage(&target);
        assert_eq!(
            id(review_session_transition_postcondition(
                &target,
                &native,
                Some(&coverage),
                1_100
            )),
            SessionTransitionPostcondition::ResumedSecurely
        );
        assert_eq!(
            id(review_session_transition_postcondition(
                &target, &native, None, 1_100
            )),
            SessionTransitionPostcondition::SecureCoverageRequired
        );
        for (cycles, result) in [
            (10, SessionTransitionPostcondition::NotSatisfied),
            (9, SessionTransitionPostcondition::Indeterminate),
            (12, SessionTransitionPostcondition::Indeterminate),
            (u64::MAX, SessionTransitionPostcondition::Indeterminate),
        ] {
            let mut changed = native.clone();
            changed.attributes.insert(
                "successful_suspend_cycles".into(),
                ObservedValue::U64(cycles),
            );
            assert_eq!(
                id(review_session_transition_postcondition(
                    &target,
                    &changed,
                    Some(&coverage),
                    1_100
                )),
                result
            );
        }
        for key in native.attributes.keys() {
            let mut changed = native.clone();
            changed.attributes.remove(key);
            assert!(
                review_session_transition_postcondition(&target, &changed, Some(&coverage), 1_100)
                    .is_err()
            );
        }
        let mut changed = coverage.clone();
        changed
            .attributes
            .insert("secure".into(), ObservedValue::Bool(false));
        assert_eq!(
            id(review_session_transition_postcondition(
                &target,
                &native,
                Some(&changed),
                1_100
            )),
            SessionTransitionPostcondition::Indeterminate
        );
        let mut changed = coverage.clone();
        changed.observed_at_unix_ms = 0;
        changed.valid_for_ms = 100;
        assert!(
            review_session_transition_postcondition(&target, &native, Some(&changed), 1_100)
                .is_err()
        );
    }
    #[test]
    fn session_or_boot_termination_is_not_inferred_from_acknowledgement_or_sleep_hints() {
        for action in [
            SessionTransition::Logout,
            SessionTransition::Reboot,
            SessionTransition::PowerOff,
        ] {
            let target = target(action);
            let mut native = observation(&target);
            native
                .attributes
                .insert("dispatch_accepted".into(), ObservedValue::Bool(true));
            native
                .attributes
                .insert("awake".into(), ObservedValue::Bool(true));
            assert_eq!(
                id(review_session_transition_postcondition(
                    &target, &native, None, 1_100
                )),
                SessionTransitionPostcondition::NotSatisfied
            );
            native
                .attributes
                .insert("target_epoch_present".into(), ObservedValue::Bool(false));
            assert_eq!(
                id(review_session_transition_postcondition(
                    &target, &native, None, 1_100
                )),
                if action == SessionTransition::Logout {
                    SessionTransitionPostcondition::OriginalSessionEnded
                } else {
                    SessionTransitionPostcondition::NotSatisfied
                }
            );
            native.attributes.insert(
                "current_boot_id".into(),
                ObservedValue::Text("abcd1234-1234-4567-89ab-0123456789ac".into()),
            );
            assert_eq!(
                id(review_session_transition_postcondition(
                    &target, &native, None, 1_100
                )),
                if action == SessionTransition::Logout {
                    SessionTransitionPostcondition::OriginalSessionEnded
                } else {
                    SessionTransitionPostcondition::OriginalBootEnded
                }
            );
            native
                .attributes
                .insert("target_epoch_present".into(), ObservedValue::Bool(true));
            assert!(
                review_session_transition_postcondition(&target, &native, None, 1_100).is_err()
            );
        }
    }
    #[test]
    fn preparing_for_sleep_never_completes_and_unknown_facts_still_fail() {
        let target = target(SessionTransition::Suspend {
            successful_cycles_before: 10,
        });
        let coverage = coverage(&target);
        let mut native = observation(&target);
        native
            .attributes
            .insert("preparing_for_sleep".into(), ObservedValue::Bool(true));
        for cycles in [9, 10, 11, 12, u64::MAX] {
            native.attributes.insert(
                "successful_suspend_cycles".into(),
                ObservedValue::U64(cycles),
            );
            assert_eq!(
                id(review_session_transition_postcondition(
                    &target,
                    &native,
                    Some(&coverage),
                    1_100
                )),
                SessionTransitionPostcondition::Indeterminate
            );
        }
        for key in native.attributes.keys() {
            let mut missing = native.clone();
            missing.attributes.remove(key);
            assert!(
                review_session_transition_postcondition(&target, &missing, Some(&coverage), 1_100)
                    .is_err()
            );
        }
        for (key, value) in [
            ("preparing_for_sleep", ObservedValue::Text("true".into())),
            (
                "successful_suspend_cycles",
                ObservedValue::Text("11".into()),
            ),
            ("suspend_test_mode", ObservedValue::Text("devices".into())),
        ] {
            let mut malformed = native.clone();
            malformed.attributes.insert(key.into(), value);
            assert!(
                review_session_transition_postcondition(
                    &target,
                    &malformed,
                    Some(&coverage),
                    1_100
                )
                .is_err()
            );
        }
        native
            .attributes
            .insert("successful_suspend_cycles".into(), ObservedValue::U64(11));
        native
            .attributes
            .insert("preparing_for_sleep".into(), ObservedValue::Bool(false));
        assert_eq!(
            id(review_session_transition_postcondition(
                &target,
                &native,
                Some(&coverage),
                1_100
            )),
            SessionTransitionPostcondition::ResumedSecurely
        );
    }

    #[test]
    fn coverage_is_requested_only_for_a_valid_settled_exact_suspend_cycle() {
        let target = target(SessionTransition::Suspend {
            successful_cycles_before: 10,
        });
        let original = observation(&target);
        for preparing in [false, true] {
            for cycles in [9, 10, 11, 12, u64::MAX] {
                let mut native = original.clone();
                native
                    .attributes
                    .insert("preparing_for_sleep".into(), ObservedValue::Bool(preparing));
                native.attributes.insert(
                    "successful_suspend_cycles".into(),
                    ObservedValue::U64(cycles),
                );
                let expected = if preparing {
                    SessionTransitionPostcondition::Indeterminate
                } else if cycles == 10 {
                    SessionTransitionPostcondition::NotSatisfied
                } else if cycles == 11 {
                    SessionTransitionPostcondition::SecureCoverageRequired
                } else {
                    SessionTransitionPostcondition::Indeterminate
                };
                assert_eq!(
                    id(review_session_transition_postcondition(
                        &target, &native, None, 1_100
                    )),
                    expected
                );
            }
        }
        for changed_boot in [false, true] {
            let mut native = original.clone();
            native
                .attributes
                .insert("target_epoch_present".into(), ObservedValue::Bool(false));
            if changed_boot {
                native.attributes.insert(
                    "current_boot_id".into(),
                    ObservedValue::Text("abcd1234-1234-4567-89ab-0123456789ac".into()),
                );
            }
            assert_eq!(
                id(review_session_transition_postcondition(
                    &target, &native, None, 1_100
                )),
                SessionTransitionPostcondition::Indeterminate
            );
        }
        for key in original.attributes.keys() {
            let mut native = original.clone();
            native.attributes.remove(key);
            assert!(
                review_session_transition_postcondition(&target, &native, None, 1_100).is_err()
            );
        }
        for (key, value) in [
            ("preparing_for_sleep", ObservedValue::Text("false".into())),
            (
                "successful_suspend_cycles",
                ObservedValue::Text("11".into()),
            ),
            ("suspend_test_mode", ObservedValue::Text("devices".into())),
        ] {
            let mut native = original.clone();
            native.attributes.insert(key.into(), value);
            assert!(
                review_session_transition_postcondition(&target, &native, None, 1_100).is_err()
            );
        }
    }

    #[test]
    fn coverage_requirement_does_not_freshen_either_observation_or_accept_substitution() {
        let target = target(SessionTransition::Suspend {
            successful_cycles_before: 10,
        });
        let native = observation(&target);
        assert_eq!(
            id(review_session_transition_postcondition(
                &target, &native, None, 1_100
            )),
            SessionTransitionPostcondition::SecureCoverageRequired
        );
        let mut fresh_coverage = coverage(&target);
        fresh_coverage.observed_at_unix_ms = 2_500;
        assert_eq!(
            id(review_session_transition_postcondition(
                &target,
                &native,
                Some(&fresh_coverage),
                2_999
            )),
            SessionTransitionPostcondition::ResumedSecurely
        );
        // Even newly sampled secure coverage cannot extend the earlier native
        // envelope's two-second lifetime while the second probe runs.
        assert!(
            review_session_transition_postcondition(&target, &native, Some(&fresh_coverage), 3_000)
                .is_err()
        );
        for field in [
            "boot_id",
            "session_id",
            "security_owner_invocation",
            "lock_generation",
            "lock_protocol",
        ] {
            let mut changed = coverage(&target);
            changed
                .attributes
                .insert(field.into(), ObservedValue::Text("substituted".into()));
            assert!(
                review_session_transition_postcondition(&target, &native, Some(&changed), 1_100)
                    .is_err()
            );
        }
        for time in [999, 3_000, u64::MAX] {
            assert!(review_session_transition_postcondition(&target, &native, None, time).is_err());
        }
    }

    #[test]
    fn envelope_substitution_future_stale_and_dry_run_facts_cannot_complete_a_transition() {
        let target = target(SessionTransition::Suspend {
            successful_cycles_before: 10,
        });
        let native = observation(&target);
        let coverage = coverage(&target);
        for kind in [
            "provider",
            "capability",
            "resource",
            "authority",
            "sequence",
            "lifetime",
            "debug",
            "sleeping",
        ] {
            let mut bad = native.clone();
            match kind {
                "provider" => bad.provider = id(ProviderId::new("session-locker")),
                "capability" => bad.capability = id(CapabilityId::new("session.power.observe")),
                "resource" => bad.resource = id(target.lock().resource_id()),
                "authority" => bad.authority = ObservationAuthority::Filesystem,
                "sequence" => bad.sequence = 0,
                "lifetime" => bad.valid_for_ms = u64::MAX,
                "debug" => {
                    bad.attributes.insert(
                        "suspend_test_mode".into(),
                        ObservedValue::Text("devices".into()),
                    );
                }
                _ => {
                    bad.attributes
                        .insert("preparing_for_sleep".into(), ObservedValue::Bool(true));
                }
            }
            let reviewed =
                review_session_transition_postcondition(&target, &bad, Some(&coverage), 1_100);
            if kind == "sleeping" {
                assert_eq!(id(reviewed), SessionTransitionPostcondition::Indeterminate);
            } else {
                assert!(reviewed.is_err());
            }
        }
        for time in [999, 3_000, u64::MAX] {
            assert!(
                review_session_transition_postcondition(&target, &native, Some(&coverage), time)
                    .is_err()
            );
        }
    }
}
