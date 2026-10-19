//! Non-authorizing protective-lock preconditions. Native attestation remains in
//! adapters; Control combines canonical facts without accepting a UI event or
//! treating a service Actor, root UID or policy setting as execution authority.

use std::fmt::{Display, Formatter};

use linura_core::{RequestId, SessionLockId, SleepInvocationId};
use linura_observation::{ObservationEnvelope, ObservedValue};
use linura_policy::{PROTECTIVE_SLEEP_PRINCIPAL, ProtectiveLockSetting};

use crate::session_safety::{validate_envelope, validate_native_lock};
use crate::{AuthenticatedPrincipal, SessionAction, SessionSafetyError, SessionSafetyReview};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectiveLockSafetyReview {
    setting: ProtectiveLockSetting,
    event: SleepInvocationId,
    lock: SessionLockId,
    already_secure: bool,
    first_valid_unix_ms: u64,
    expires_at_unix_ms: u64,
}

impl ProtectiveLockSafetyReview {
    /// `setting` must be the current integrity-checked durable owner record,
    /// not an imported profile or caller payload. The three observations must
    /// come from registered trusted mechanisms. This method checks facts only;
    /// the result cannot be converted into an approval or dispatch permit.
    #[allow(clippy::too_many_arguments)]
    pub fn review(
        principal: &AuthenticatedPrincipal,
        setting: &ProtectiveLockSetting,
        event: &SleepInvocationId,
        lock: &SessionLockId,
        native_event: &ObservationEnvelope,
        native_session: &ObservationEnvelope,
        native_lock: &ObservationEnvelope,
        now_unix_ms: u64,
    ) -> Result<Self, ProtectiveLockSafetyError> {
        if principal.as_str() != PROTECTIVE_SLEEP_PRINCIPAL {
            return Err(ProtectiveLockSafetyError::PrincipalMismatch);
        }
        if !setting.enabled() {
            return Err(ProtectiveLockSafetyError::SettingDisabled);
        }
        if lock.epoch() != setting.epoch() || event.boot() != setting.epoch().boot() {
            return Err(ProtectiveLockSafetyError::ScopeChanged);
        }
        if [native_event, native_session, native_lock]
            .iter()
            .any(|sample| sample.observed_at_unix_ms == 0)
        {
            return Err(ProtectiveLockSafetyError::Native(
                SessionSafetyError::UntrustedEvidence,
            ));
        }
        let event_resource = event
            .resource_id()
            .map_err(|_| ProtectiveLockSafetyError::ScopeChanged)?;
        validate_envelope(
            native_event,
            "system-sleep",
            "session.sleep-entry.observe",
            &event_resource,
            now_unix_ms,
        )?;
        for (key, expected) in [
            ("boot_id", event.boot().as_str()),
            ("sleep_invocation", event.invocation()),
            ("sleep_operation", "suspend"),
        ] {
            if native_event.attributes.get(key) != Some(&ObservedValue::Text(expected.into())) {
                return Err(ProtectiveLockSafetyError::ScopeChanged);
            }
        }
        // PrepareForSleep alone is not an enforceable pre-kernel gate and does
        // not authenticate the original lid/button cause. A qualified native
        // adapter must attest BOTH the gate and the exact executing helper.
        for key in ["pre_kernel_gate", "helper_attested"] {
            if native_event.attributes.get(key) != Some(&ObservedValue::Bool(true)) {
                return Err(ProtectiveLockSafetyError::UnqualifiedSleepEntry);
            }
        }
        // Review the owner's independently observed predicates, NOT a rewrite
        // of the authenticated initiating principal. The latter remains the
        // protective service throughout canonical policy/prepare/audit.
        let owner = AuthenticatedPrincipal::new(setting.owner().as_str())
            .map_err(|_| ProtectiveLockSafetyError::ScopeChanged)?;
        let _ = SessionSafetyReview::review(
            &owner,
            setting.epoch(),
            SessionAction::Lock,
            native_session,
            now_unix_ms,
        )?;
        let already_secure = validate_native_lock(lock, native_lock, now_unix_ms)?;
        let samples = [native_event, native_session, native_lock];
        let first_valid_unix_ms = samples
            .iter()
            .map(|sample| sample.observed_at_unix_ms)
            .max()
            .ok_or(ProtectiveLockSafetyError::ClockUnavailable)?;
        let expires_at_unix_ms = samples.iter().try_fold(u64::MAX, |end, sample| {
            sample
                .observed_at_unix_ms
                .checked_add(sample.valid_for_ms)
                .map(|expiry| end.min(expiry))
                .ok_or(ProtectiveLockSafetyError::ClockUnavailable)
        })?;
        if first_valid_unix_ms >= expires_at_unix_ms || now_unix_ms >= expires_at_unix_ms {
            return Err(ProtectiveLockSafetyError::Native(
                SessionSafetyError::ExpiredEvidence,
            ));
        }
        Ok(Self {
            setting: setting.clone(),
            event: event.clone(),
            lock: lock.clone(),
            already_secure,
            first_valid_unix_ms,
            expires_at_unix_ms,
        })
    }

    /// Compare the newly read current setting immediately before use. Retaining
    /// this review never refreshes evidence or pins a revoked/superseded grant.
    pub fn require_current(
        &self,
        latest_setting: &ProtectiveLockSetting,
        now_unix_ms: u64,
    ) -> Result<(), ProtectiveLockSafetyError> {
        if !latest_setting.enabled() {
            return Err(ProtectiveLockSafetyError::SettingDisabled);
        }
        if latest_setting != &self.setting {
            return Err(ProtectiveLockSafetyError::ScopeChanged);
        }
        if now_unix_ms < self.first_valid_unix_ms || now_unix_ms >= self.expires_at_unix_ms {
            return Err(ProtectiveLockSafetyError::Native(
                SessionSafetyError::ExpiredEvidence,
            ));
        }
        Ok(())
    }

    pub fn request_id(&self) -> Result<RequestId, ProtectiveLockSafetyError> {
        self.event
            .protective_request_id(self.setting.epoch())
            .map_err(|_| ProtectiveLockSafetyError::ScopeChanged)
    }

    #[must_use]
    pub const fn lock(&self) -> &SessionLockId {
        &self.lock
    }
    #[must_use]
    pub const fn event(&self) -> &SleepInvocationId {
        &self.event
    }
    #[must_use]
    pub const fn already_secure(&self) -> bool {
        self.already_secure
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectiveLockSafetyError {
    PrincipalMismatch,
    SettingDisabled,
    ScopeChanged,
    UnqualifiedSleepEntry,
    ClockUnavailable,
    Native(SessionSafetyError),
}

impl From<SessionSafetyError> for ProtectiveLockSafetyError {
    fn from(error: SessionSafetyError) -> Self {
        Self::Native(error)
    }
}
impl Display for ProtectiveLockSafetyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PrincipalMismatch => formatter
                .write_str("protective-lock initiator is not the attested native sleep service"),
            Self::SettingDisabled => {
                formatter.write_str("owner protective-lock setting is disabled or revoked")
            }
            Self::ScopeChanged => {
                formatter.write_str("protective-lock policy, native event or session scope changed")
            }
            Self::UnqualifiedSleepEntry => formatter
                .write_str("native sleep entry has no qualified authenticated pre-kernel gate"),
            Self::ClockUnavailable => {
                formatter.write_str("protective-lock evidence clock is unavailable or overflowing")
            }
            Self::Native(error) => Display::fmt(error, formatter),
        }
    }
}
impl std::error::Error for ProtectiveLockSafetyError {}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_core::{
        BootId, CapabilityId, IntentId, PolicyRevisionId, PrincipalId, ProviderId,
        SecurityOwnerInvocationId, SessionEpoch,
    };
    use linura_observation::ObservationAuthority;
    use std::collections::BTreeMap;

    fn id<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|error| unreachable!("{error:?}"))
    }
    fn setting(enabled: bool, revision: char) -> ProtectiveLockSetting {
        id(ProtectiveLockSetting::new(
            id(PrincipalId::new("unix:uid:1000")),
            id(SessionEpoch::new(
                id(BootId::new("abcd1234-1234-4567-89ab-0123456789ab")),
                1000,
                "c2",
                42,
            )),
            id(IntentId::new("intent:s17:protective-lock:owner-approved")),
            id(PolicyRevisionId::new(format!(
                "policy:protective-lock:v1:{}",
                revision.to_string().repeat(64)
            ))),
            enabled,
        ))
    }
    struct Fixture {
        principal: AuthenticatedPrincipal,
        setting: ProtectiveLockSetting,
        event: SleepInvocationId,
        lock: SessionLockId,
        native_event: ObservationEnvelope,
        native_session: ObservationEnvelope,
        native_lock: ObservationEnvelope,
    }
    impl Fixture {
        fn new(secure: bool) -> Self {
            let setting = setting(true, 'a');
            let event = id(SleepInvocationId::new(
                setting.epoch().boot().clone(),
                "01234567-1234-4567-89ab-0123456789ab",
            ));
            let lock = id(SessionLockId::new(
                setting.epoch().clone(),
                id(SecurityOwnerInvocationId::new(
                    "98765432-1234-4567-89ab-0123456789ab",
                )),
                7,
            ));
            let sample = |provider: &str, capability: &str, resource| ObservationEnvelope {
                provider: id(ProviderId::new(provider)),
                resource,
                capability: id(CapabilityId::new(capability)),
                authority: ObservationAuthority::NativeApi,
                observed_at_unix_ms: 1000,
                valid_for_ms: 2000,
                sequence: 1,
                attributes: BTreeMap::new(),
            };
            let mut native_event = sample(
                "system-sleep",
                "session.sleep-entry.observe",
                id(event.resource_id()),
            );
            native_event.attributes.extend([
                (
                    "boot_id".into(),
                    ObservedValue::Text(event.boot().as_str().into()),
                ),
                (
                    "sleep_invocation".into(),
                    ObservedValue::Text(event.invocation().into()),
                ),
                (
                    "sleep_operation".into(),
                    ObservedValue::Text("suspend".into()),
                ),
                ("pre_kernel_gate".into(), ObservedValue::Bool(true)),
                ("helper_attested".into(), ObservedValue::Bool(true)),
            ]);
            let mut native_session = sample(
                "logind",
                "session.epoch.observe",
                id(setting.epoch().resource_id()),
            );
            native_session.attributes.extend([
                (
                    "boot_id".into(),
                    ObservedValue::Text(event.boot().as_str().into()),
                ),
                ("session_id".into(), ObservedValue::Text("c2".into())),
                ("uid".into(), ObservedValue::U64(1000)),
                ("created_monotonic_us".into(), ObservedValue::U64(42)),
                ("session_type".into(), ObservedValue::Text("wayland".into())),
                ("session_class".into(), ObservedValue::Text("user".into())),
                ("state".into(), ObservedValue::Text("active".into())),
                ("seat".into(), ObservedValue::Text("seat0".into())),
                ("active".into(), ObservedValue::Bool(true)),
                ("remote".into(), ObservedValue::Bool(false)),
                ("leader_present".into(), ObservedValue::Bool(true)),
            ]);
            let mut native_lock = native_session.clone();
            native_lock.provider = id(ProviderId::new("session-locker"));
            native_lock.capability = id(CapabilityId::new("session.secure-lock.observe"));
            native_lock.resource = id(lock.resource_id());
            native_lock.attributes.extend([
                (
                    "security_owner_invocation".into(),
                    ObservedValue::Text(lock.security_owner_invocation().as_str().into()),
                ),
                ("lock_generation".into(), ObservedValue::U64(7)),
                ("secure".into(), ObservedValue::Bool(secure)),
                (
                    "lock_protocol".into(),
                    ObservedValue::Text("ext-session-lock-v1".into()),
                ),
            ]);
            Self {
                principal: id(AuthenticatedPrincipal::new(PROTECTIVE_SLEEP_PRINCIPAL)),
                setting,
                event,
                lock,
                native_event,
                native_session,
                native_lock,
            }
        }
        fn review(
            &self,
            now: u64,
        ) -> Result<ProtectiveLockSafetyReview, ProtectiveLockSafetyError> {
            ProtectiveLockSafetyReview::review(
                &self.principal,
                &self.setting,
                &self.event,
                &self.lock,
                &self.native_event,
                &self.native_session,
                &self.native_lock,
                now,
            )
        }
    }

    #[test]
    fn current_native_event_is_reviewable_without_becoming_approval_or_sleep_authority() {
        for secure in [false, true] {
            let fixture = Fixture::new(secure);
            let reviewed = id(fixture.review(1100));
            assert_eq!(reviewed.already_secure(), secure);
            assert_eq!(reviewed.lock(), &fixture.lock);
            assert_eq!(reviewed.event(), &fixture.event);
            assert_eq!(
                id(reviewed.request_id()),
                id(fixture.event.protective_request_id(fixture.setting.epoch()))
            );
            assert!(reviewed.require_current(&fixture.setting, 1100).is_ok());
            // Ordinary manual-lock policy/ownership was not broadened for the service.
            assert_eq!(
                SessionSafetyReview::review(
                    &fixture.principal,
                    fixture.setting.epoch(),
                    SessionAction::Lock,
                    &fixture.native_session,
                    1100
                ),
                Err(SessionSafetyError::PrincipalMismatch)
            );
        }
    }

    #[test]
    fn ordinary_root_owner_agent_and_forged_service_principals_do_not_qualify() {
        for principal in [
            "unix:uid:0",
            "unix:uid:1000",
            "agent:trusted",
            "service:other",
        ] {
            let mut fixture = Fixture::new(false);
            fixture.principal = id(AuthenticatedPrincipal::new(principal));
            assert_eq!(
                fixture.review(1100),
                Err(ProtectiveLockSafetyError::PrincipalMismatch)
            );
        }
    }

    #[test]
    fn missing_unqualified_or_substituted_native_event_fails_closed() {
        for key in Fixture::new(false).native_event.attributes.keys() {
            let mut fixture = Fixture::new(false);
            fixture.native_event.attributes.remove(key);
            assert!(fixture.review(1100).is_err(), "{key}");
        }
        for (key, wrong) in [
            ("sleep_operation", ObservedValue::Text("hibernate".into())),
            (
                "sleep_invocation",
                ObservedValue::Text("01234567-1234-4567-89ab-0123456789ac".into()),
            ),
            (
                "boot_id",
                ObservedValue::Text("abcd1234-1234-4567-89ab-0123456789ac".into()),
            ),
            ("pre_kernel_gate", ObservedValue::Bool(false)),
            ("helper_attested", ObservedValue::Bool(false)),
        ] {
            let mut fixture = Fixture::new(false);
            fixture.native_event.attributes.insert(key.into(), wrong);
            assert!(fixture.review(1100).is_err(), "{key}");
        }
        for authority in [
            ObservationAuthority::Kernel,
            ObservationAuthority::Filesystem,
            ObservationAuthority::SyntheticTest,
        ] {
            let mut fixture = Fixture::new(false);
            fixture.native_event.authority = authority;
            assert!(fixture.review(1100).is_err());
        }
        for column in 0..8 {
            let mut fixture = Fixture::new(false);
            match column {
                0 => fixture.native_event.sequence = 0,
                1 => fixture.native_event.provider = id(ProviderId::new("logind")),
                2 => {
                    fixture.native_event.capability = id(CapabilityId::new("session.power.observe"))
                }
                3 => fixture.native_event.resource = id(fixture.lock.resource_id()),
                4 => fixture.native_event.observed_at_unix_ms = 1101,
                5 => fixture.native_event.valid_for_ms = 0,
                6 => fixture.native_event.valid_for_ms = 2001,
                _ => fixture.native_event.observed_at_unix_ms = 0,
            }
            assert!(fixture.review(1100).is_err());
        }
    }

    #[test]
    fn earliest_expiry_is_exclusive_and_never_refreshed_by_newer_facts() {
        let mut fixture = Fixture::new(false);
        fixture.native_event.valid_for_ms = 1200;
        fixture.native_session.observed_at_unix_ms = 1100;
        fixture.native_lock.observed_at_unix_ms = 1200;
        let review = id(fixture.review(1250));
        assert!(review.require_current(&fixture.setting, 2199).is_ok());
        for time in [1199, 2200, 3000] {
            assert!(review.require_current(&fixture.setting, time).is_err());
        }
        assert!(fixture.review(2200).is_err());
    }

    #[test]
    fn disabled_revoked_and_superseded_settings_invalidate_retained_review() {
        let mut fixture = Fixture::new(false);
        let reviewed = id(fixture.review(1100));
        fixture.setting = setting(false, 'b');
        assert_eq!(
            reviewed.require_current(&fixture.setting, 1100),
            Err(ProtectiveLockSafetyError::SettingDisabled)
        );
        assert_eq!(
            fixture.review(1100),
            Err(ProtectiveLockSafetyError::SettingDisabled)
        );
        assert_eq!(
            reviewed.require_current(&setting(true, 'b'), 1100),
            Err(ProtectiveLockSafetyError::ScopeChanged)
        );
    }

    #[test]
    fn other_session_stale_owner_hint_and_unknown_coverage_do_not_qualify() {
        for (key, wrong) in [
            ("uid", ObservedValue::U64(1001)),
            ("created_monotonic_us", ObservedValue::U64(43)),
            ("active", ObservedValue::Bool(false)),
            ("remote", ObservedValue::Bool(true)),
            ("state", ObservedValue::Text("closing".into())),
            ("leader_present", ObservedValue::Bool(false)),
        ] {
            let mut fixture = Fixture::new(false);
            fixture.native_session.attributes.insert(key.into(), wrong);
            assert!(fixture.review(1100).is_err(), "{key}");
        }
        for key in [
            "secure",
            "lock_generation",
            "security_owner_invocation",
            "lock_protocol",
        ] {
            let mut fixture = Fixture::new(false);
            fixture.native_lock.attributes.remove(key);
            fixture
                .native_lock
                .attributes
                .insert("locked_hint".into(), ObservedValue::Bool(true));
            assert!(fixture.review(1100).is_err(), "{key}");
        }
    }
}
