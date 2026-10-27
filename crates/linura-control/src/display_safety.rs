//! Non-authorizing S21 display safety over separate canonical native facts.
//! There is intentionally no operation registration, executor or public apply
//! endpoint here. Native topology/lock binding must be implemented and qualified
//! before the managed lifecycle may consume this review.

use std::fmt::{Display, Formatter};

use linura_core::{DisplayLayout, DisplayOutputLayout, SessionLockId};
use linura_observation::{DisplayObservationFacts, ObservationEnvelope, ObservedValue};

use crate::AuthenticatedPrincipal;
use crate::session_safety::{validate_active_session, validate_native_lock_capability};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayLayoutSafetyReview {
    desired: DisplayLayout,
    last_known_good: DisplayLayout,
    lock: SessionLockId,
    secure: bool,
    reviewed_at_unix_ms: u64,
    sequences: [u64; 3],
    expires_at_unix_ms: u64,
}

impl DisplayLayoutSafetyReview {
    /// Independently re-observed current postcondition for a retained exact
    /// intent, including restoration after restart. This does not grant apply,
    /// continuation or commit authority. All contributing samples must originate
    /// strictly after the event being checked, with their original deadlines.
    #[allow(clippy::too_many_arguments)]
    pub fn review_current_postcondition(
        principal: &AuthenticatedPrincipal,
        expected: &DisplayLayout,
        lock: &SessionLockId,
        display: &ObservationEnvelope,
        session: &ObservationEnvelope,
        locker: &ObservationEnvelope,
        after_unix_ms: u64,
        now_unix_ms: u64,
    ) -> Result<Self, DisplaySafetyError> {
        if after_unix_ms == 0
            || after_unix_ms >= now_unix_ms
            || [display, session, locker]
                .into_iter()
                .any(|sample| sample.observed_at_unix_ms <= after_unix_ms)
        {
            return Err(DisplaySafetyError::Freshness);
        }
        let review = Self::review(principal, expected, display, session, locker, now_unix_ms)?;
        if &review.lock != lock {
            return Err(DisplaySafetyError::LockCoverage);
        }
        if &review.last_known_good != expected {
            return Err(DisplaySafetyError::Postcondition);
        }
        Ok(review)
    }

    /// All three envelopes must come through trusted observation composition.
    /// A generic S17 secure=true bit or a screen count does not bind a display
    /// topology. Require the independently attested exact output generations.
    pub fn review(
        principal: &AuthenticatedPrincipal,
        desired: &DisplayLayout,
        display: &ObservationEnvelope,
        session: &ObservationEnvelope,
        locker: &ObservationEnvelope,
        now_unix_ms: u64,
    ) -> Result<Self, DisplaySafetyError> {
        if [session, locker]
            .into_iter()
            .any(|source| source.observed_at_unix_ms == 0)
        {
            return Err(DisplaySafetyError::Freshness);
        }
        let topology = desired.topology();
        validate_active_session(
            principal,
            topology.session(),
            session,
            "session.epoch.observe",
            now_unix_ms,
        )
        .map_err(|_| DisplaySafetyError::Session)?;
        if session.attributes.get("seat") != Some(&ObservedValue::Text(topology.seat().into())) {
            return Err(DisplaySafetyError::Session);
        }
        let facts = DisplayObservationFacts::from_envelope(display, topology, now_unix_ms)
            .map_err(|_| DisplaySafetyError::Display)?;
        let validated = DisplayLayout::new(
            facts.inventory(),
            facts.capabilities(),
            desired.outputs().to_vec(),
        )
        .map_err(|_| DisplaySafetyError::Layout)?;
        if validated != *desired {
            return Err(DisplaySafetyError::Layout);
        }
        if !facts.has_powered_independent_output() {
            return Err(DisplaySafetyError::NoVisibleRecoveryOutput);
        }
        if !desired.outputs().iter().any(|entry| matches!(entry,
            DisplayOutputLayout::Enabled { output, mirror: None, .. } if facts.powered_outputs().contains(output))) {
            return Err(DisplaySafetyError::NoVisibleRecoveryOutput);
        }
        let lock = SessionLockId::from_resource(&locker.resource)
            .map_err(|_| DisplaySafetyError::LockCoverage)?;
        if lock.epoch() != topology.session() {
            return Err(DisplaySafetyError::LockCoverage);
        }
        let secure = validate_native_lock_capability(
            &lock,
            locker,
            linura_observation::DISPLAY_COVERAGE_CAPABILITY,
            now_unix_ms,
        )
        .map_err(|_| DisplaySafetyError::LockCoverage)?;
        let resource = topology
            .resource_id()
            .map_err(|_| DisplaySafetyError::Display)?;
        if locker.attributes.get("display_topology")
            != Some(&ObservedValue::Text(resource.as_str().into()))
        {
            return Err(DisplaySafetyError::LockCoverage);
        }
        let active = active_outputs(facts.layout());
        if locker.attributes.get("observed_outputs") != Some(&ObservedValue::Text(active.clone()))
            || locker.attributes.get("covered_outputs")
                != Some(&ObservedValue::Text(if secure {
                    active
                } else {
                    String::new()
                }))
        {
            return Err(DisplaySafetyError::LockCoverage);
        }
        let expires_at_unix_ms = [display, session, locker]
            .into_iter()
            .map(|e| {
                e.observed_at_unix_ms
                    .checked_add(e.valid_for_ms)
                    .ok_or(DisplaySafetyError::Freshness)
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .min()
            .ok_or(DisplaySafetyError::Freshness)?;
        Ok(Self {
            desired: desired.clone(),
            last_known_good: facts.layout().clone(),
            lock,
            secure,
            reviewed_at_unix_ms: now_unix_ms,
            sequences: [display.sequence, session.sequence, locker.sequence],
            expires_at_unix_ms,
        })
    }

    #[must_use]
    pub const fn desired_layout(&self) -> &DisplayLayout {
        &self.desired
    }

    /// Candidate recovery data only. It must be durably prepared and backed by
    /// a qualified UI-independent restoration route before any dispatch.
    #[must_use]
    pub const fn last_known_good(&self) -> &DisplayLayout {
        &self.last_known_good
    }

    #[must_use]
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }

    /// Pure postcondition review, never a receipt/commit or authority to retry.
    /// Caller supplies freshly re-observed native facts after dispatch. A
    /// changed lock/compositor/output generation or expired pre-dispatch review
    /// cannot be normalized into success.
    pub fn verify_postcondition(
        &self,
        principal: &AuthenticatedPrincipal,
        display: &ObservationEnvelope,
        session: &ObservationEnvelope,
        locker: &ObservationEnvelope,
        dispatch_started_unix_ms: u64,
        now_unix_ms: u64,
    ) -> Result<(), DisplaySafetyError> {
        if dispatch_started_unix_ms == 0
            || dispatch_started_unix_ms < self.reviewed_at_unix_ms
            || dispatch_started_unix_ms >= self.expires_at_unix_ms
            || dispatch_started_unix_ms > now_unix_ms
            || [display, session, locker]
                .into_iter()
                .zip(self.sequences)
                .any(|(e, sequence)| {
                    e.observed_at_unix_ms <= dispatch_started_unix_ms || e.sequence <= sequence
                })
        {
            return Err(DisplaySafetyError::Freshness);
        }
        let after = Self::review(
            principal,
            &self.desired,
            display,
            session,
            locker,
            now_unix_ms,
        )?;
        if after.lock != self.lock || after.secure != self.secure {
            return Err(DisplaySafetyError::LockCoverage);
        }
        if after.last_known_good != self.desired {
            return Err(DisplaySafetyError::Postcondition);
        }
        Ok(())
    }
}

fn active_outputs(layout: &DisplayLayout) -> String {
    layout
        .outputs()
        .iter()
        .filter_map(|entry| match entry {
            DisplayOutputLayout::Enabled { output, .. } => {
                Some(format!("{}:{}", output.handle(), output.generation()))
            }
            DisplayOutputLayout::Disabled { .. } => None,
        })
        .collect::<Vec<_>>()
        .join(",")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisplaySafetyError {
    Session,
    Display,
    Layout,
    LockCoverage,
    NoVisibleRecoveryOutput,
    Freshness,
    Postcondition,
}

impl Display for DisplaySafetyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Session => {
                "display request is not bound to the exact active owner session and seat"
            }
            Self::Display => "display observation is stale, unsupported or from another topology",
            Self::Layout => {
                "display layout does not match the complete native inventory and options"
            }
            Self::LockCoverage => {
                "independent native lock coverage does not bind this exact output topology"
            }
            Self::NoVisibleRecoveryOutput => {
                "no powered independent output establishes a last-known-good candidate"
            }
            Self::Freshness => "display evidence does not establish current post-dispatch ordering",
            Self::Postcondition => {
                "independent native observation does not match the requested display layout"
            }
        })
    }
}
impl std::error::Error for DisplaySafetyError {}

#[cfg(test)]
#[path = "display_safety_tests.rs"]
mod tests;
