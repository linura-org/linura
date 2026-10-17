//! S17 safety preconditions. These reviews are not approval, dispatch authority,
//! or durable truth: the managed lifecycle must re-observe/review before handoff.

use std::fmt::{Display, Formatter};

use linura_core::{
    OperationClass, RiskClass, SessionEpoch, SessionLockId, SessionTransition, SessionTransitionId,
};
use linura_observation::{ObservationAuthority, ObservationEnvelope, ObservedValue};

use crate::AuthenticatedPrincipal;

const LOGIND_PROVIDER: &str = "logind";
const LOGIND_CAPABILITY: &str = "session.epoch.observe";
const POWER_CAPABILITY: &str = "session.power.observe";
const LOCKER_PROVIDER: &str = "session-locker";
const LOCKER_CAPABILITY: &str = "session.secure-lock.observe";

/// Validate native identity and protocol facts; no UI/authentication result is
/// accepted as compositor coverage. Transport attestation belongs to the adapter.
pub(crate) fn validate_native_lock(
    lock: &SessionLockId,
    observation: &ObservationEnvelope,
    now_unix_ms: u64,
) -> Result<bool, SessionSafetyError> {
    let resource = lock
        .resource_id()
        .map_err(|_| SessionSafetyError::IdentityMismatch)?;
    validate_envelope(
        observation,
        LOCKER_PROVIDER,
        LOCKER_CAPABILITY,
        &resource,
        now_unix_ms,
    )?;
    let epoch = lock.epoch();
    require_text(observation, "boot_id", epoch.boot().as_str())?;
    require_text(observation, "session_id", epoch.session_id())?;
    require_u64(observation, "uid", u64::from(epoch.uid()))?;
    require_u64(
        observation,
        "created_monotonic_us",
        epoch.created_monotonic_us(),
    )?;
    require_u64(observation, "lock_generation", lock.generation())?;
    require_text(
        observation,
        "security_owner_invocation",
        lock.security_owner_invocation().as_str(),
    )
    .map_err(|_| SessionSafetyError::IdentityMismatch)?;
    require_text(observation, "lock_protocol", "ext-session-lock-v1")?;
    match observation.attributes.get("secure") {
        Some(ObservedValue::Bool(value)) => Ok(*value),
        _ => Err(SessionSafetyError::UnverifiedScreenCoverage),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionAction {
    Lock,
    Unlock,
    Suspend,
    Logout,
    Reboot,
    PowerOff,
}

impl SessionAction {
    #[must_use]
    pub const fn operation_class(self) -> OperationClass {
        OperationClass::ManagedExternalEffect
    }

    #[must_use]
    pub const fn risk_floor(self) -> RiskClass {
        match self {
            Self::Lock | Self::Unlock | Self::Suspend => RiskClass::SecuritySensitive,
            Self::Logout | Self::Reboot | Self::PowerOff => RiskClass::Destructive,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lock => "lock",
            Self::Unlock => "unlock",
            Self::Suspend => "suspend",
            Self::Logout => "logout",
            Self::Reboot => "reboot",
            Self::PowerOff => "power-off",
        }
    }
}

/// An opaque, non-authorizing review of independently acquired native facts.
/// Principal is transport-authenticated, never an Actor or caller-selected uid.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionSafetyReview {
    epoch: SessionEpoch,
    action: SessionAction,
    observed_at_unix_ms: u64,
    valid_for_ms: u64,
}

impl SessionSafetyReview {
    pub fn review(
        principal: &AuthenticatedPrincipal,
        epoch: &SessionEpoch,
        action: SessionAction,
        logind: &ObservationEnvelope,
        now_unix_ms: u64,
    ) -> Result<Self, SessionSafetyError> {
        Self::review_native_session(
            principal,
            epoch,
            action,
            logind,
            now_unix_ms,
            LOGIND_CAPABILITY,
        )
    }

    fn review_native_session(
        principal: &AuthenticatedPrincipal,
        epoch: &SessionEpoch,
        action: SessionAction,
        logind: &ObservationEnvelope,
        now_unix_ms: u64,
        capability: &str,
    ) -> Result<Self, SessionSafetyError> {
        if principal.as_str() != format!("unix:uid:{}", epoch.uid()) {
            return Err(SessionSafetyError::PrincipalMismatch);
        }
        // Root's implicit native Polkit authorization is not fresh owner
        // authentication. Root graphical login is outside this qualification.
        if epoch.uid() == 0 {
            return Err(SessionSafetyError::UnsupportedSession);
        }
        let resource = epoch
            .resource_id()
            .map_err(|_| SessionSafetyError::IdentityMismatch)?;
        validate_envelope(logind, LOGIND_PROVIDER, capability, &resource, now_unix_ms)?;
        require_text(logind, "boot_id", epoch.boot().as_str())?;
        require_text(logind, "session_id", epoch.session_id())?;
        require_u64(logind, "uid", u64::from(epoch.uid()))?;
        require_u64(logind, "created_monotonic_us", epoch.created_monotonic_us())?;
        require_text(logind, "session_type", "wayland")?;
        require_text(logind, "session_class", "user")?;
        require_text(logind, "state", "active")?;
        require_bool(logind, "active", true)?;
        require_bool(logind, "remote", false)?;
        match logind.attributes.get("seat") {
            Some(ObservedValue::Text(seat))
                if !seat.is_empty()
                    && seat.len() <= 64
                    && seat.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
                    }) => {}
            _ => return Err(SessionSafetyError::UnsupportedSession),
        }
        require_bool(logind, "leader_present", true)?;
        Ok(Self {
            epoch: epoch.clone(),
            action,
            observed_at_unix_ms: logind.observed_at_unix_ms,
            valid_for_ms: logind.valid_for_ms,
        })
    }

    #[must_use]
    pub const fn epoch(&self) -> &SessionEpoch {
        &self.epoch
    }

    #[must_use]
    pub const fn action(&self) -> SessionAction {
        self.action
    }

    /// Before suspend, fresh compositor coverage is mandatory. A logind hint,
    /// cached lock state, PAM result, or executor acknowledgement cannot satisfy
    /// this check. Native coverage must belong to this exact session generation.
    pub fn require_secure_coverage(
        &self,
        locker: &ObservationEnvelope,
        now_unix_ms: u64,
    ) -> Result<SessionLockId, SessionSafetyError> {
        // New locker evidence cannot refresh old ownership/active-session facts.
        if now_unix_ms
            .checked_sub(self.observed_at_unix_ms)
            .is_none_or(|elapsed| elapsed >= self.valid_for_ms)
        {
            return Err(SessionSafetyError::ExpiredEvidence);
        }
        let lock = SessionLockId::from_resource(&locker.resource)
            .map_err(|_| SessionSafetyError::IdentityMismatch)?;
        if lock.epoch() != &self.epoch {
            return Err(SessionSafetyError::IdentityMismatch);
        }
        if !validate_native_lock(&lock, locker, now_unix_ms)? {
            return Err(SessionSafetyError::UnverifiedScreenCoverage);
        }
        // Screen counts are deliberately not used as proof: protocol-native
        // acknowledgement covers live output hotplug as well as initial outputs.
        Ok(lock)
    }
}

/// S17/S21 shared safety preconditions over one bounded native power snapshot.
/// This value is deliberately non-authorizing: approvals, durable prepare,
/// executor authorization, native delay-inhibitor ownership and independent
/// transition verification are still mandatory in the managed path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionPowerSafetyReview {
    session: SessionSafetyReview,
    native_authentication_required: bool,
    delay_inhibitors: u64,
    inhibit_delay_max_us: u64,
}

impl SessionPowerSafetyReview {
    pub fn review(
        principal: &AuthenticatedPrincipal,
        epoch: &SessionEpoch,
        action: SessionAction,
        power: &ObservationEnvelope,
        now_unix_ms: u64,
    ) -> Result<Self, SessionSafetyError> {
        let (availability_key, block_key, delay_key) = match action {
            SessionAction::Suspend => (
                "suspend_availability",
                "sleep_block_count",
                "sleep_delay_count",
            ),
            SessionAction::Reboot => (
                "reboot_availability",
                "shutdown_block_count",
                "shutdown_delay_count",
            ),
            SessionAction::PowerOff => (
                "power_off_availability",
                "shutdown_block_count",
                "shutdown_delay_count",
            ),
            _ => return Err(SessionSafetyError::UnsupportedSession),
        };
        let session = SessionSafetyReview::review_native_session(
            principal,
            epoch,
            action,
            power,
            now_unix_ms,
            POWER_CAPABILITY,
        )?;
        require_text(power, "permission_query_principal", principal.as_str())
            .map_err(|_| SessionSafetyError::IdentityMismatch)?;
        require_text(
            power,
            "permission_query_session_epoch",
            epoch
                .resource_id()
                .map_err(|_| SessionSafetyError::IdentityMismatch)?
                .as_str(),
        )
        .map_err(|_| SessionSafetyError::IdentityMismatch)?;
        let native_authentication_required = match power.attributes.get(availability_key) {
            Some(ObservedValue::Text(value)) if value == "yes" => false,
            Some(ObservedValue::Text(value)) if value == "challenge" => true,
            Some(ObservedValue::Text(value)) if matches!(value.as_str(), "no" | "na") => {
                return Err(SessionSafetyError::PowerUnavailable);
            }
            _ => return Err(SessionSafetyError::UnsupportedSession),
        };
        Self::review_conditions(
            session,
            power,
            native_authentication_required,
            block_key,
            delay_key,
        )
    }

    /// Dedicated authority services cannot reuse their own Can* permission
    /// snapshot for a graphical owner. Coordinate distinct canonical native
    /// observations here, preserving both identities and the earliest expiry.
    pub fn review_with_permission(
        principal: &AuthenticatedPrincipal,
        transition: &SessionTransitionId,
        conditions: &ObservationEnvelope,
        permission: &ObservationEnvelope,
        now_unix_ms: u64,
    ) -> Result<Self, SessionSafetyError> {
        let (action, block_key, delay_key) = match transition.transition() {
            SessionTransition::Suspend { .. } => (
                SessionAction::Suspend,
                "sleep_block_count",
                "sleep_delay_count",
            ),
            SessionTransition::Reboot => (
                SessionAction::Reboot,
                "shutdown_block_count",
                "shutdown_delay_count",
            ),
            SessionTransition::PowerOff => (
                SessionAction::PowerOff,
                "shutdown_block_count",
                "shutdown_delay_count",
            ),
            SessionTransition::Logout => return Err(SessionSafetyError::UnsupportedSession),
        };
        let epoch = transition.lock().epoch();
        let mut session = SessionSafetyReview::review_native_session(
            principal,
            epoch,
            action,
            conditions,
            now_unix_ms,
            "session.power.conditions.observe",
        )?;
        validate_envelope(
            permission,
            "polkit",
            "session.power.permission.observe",
            &transition
                .permission_resource_id()
                .map_err(|_| SessionSafetyError::IdentityMismatch)?,
            now_unix_ms,
        )?;
        require_text(permission, "permission_query_principal", principal.as_str())
            .map_err(|_| SessionSafetyError::IdentityMismatch)?;
        require_text(
            permission,
            "permission_query_session_epoch",
            epoch
                .resource_id()
                .map_err(|_| SessionSafetyError::IdentityMismatch)?
                .as_str(),
        )
        .map_err(|_| SessionSafetyError::IdentityMismatch)?;
        let native_authentication_required = match permission.attributes.get("availability") {
            Some(ObservedValue::Text(value)) if value == "yes" => false,
            Some(ObservedValue::Text(value)) if value == "challenge" => true,
            Some(ObservedValue::Text(value)) if value == "no" => {
                return Err(SessionSafetyError::PowerUnavailable);
            }
            _ => return Err(SessionSafetyError::UnsupportedSession),
        };
        let end = session
            .observed_at_unix_ms
            .checked_add(session.valid_for_ms)
            .zip(
                permission
                    .observed_at_unix_ms
                    .checked_add(permission.valid_for_ms),
            )
            .map(|(left, right)| left.min(right))
            .ok_or(SessionSafetyError::ExpiredEvidence)?;
        session.observed_at_unix_ms = session
            .observed_at_unix_ms
            .min(permission.observed_at_unix_ms);
        session.valid_for_ms = end
            .checked_sub(session.observed_at_unix_ms)
            .filter(|value| *value > 0)
            .ok_or(SessionSafetyError::ExpiredEvidence)?;
        Self::review_conditions(
            session,
            conditions,
            native_authentication_required,
            block_key,
            delay_key,
        )
    }

    fn review_conditions(
        session: SessionSafetyReview,
        power: &ObservationEnvelope,
        native_authentication_required: bool,
        block_key: &str,
        delay_key: &str,
    ) -> Result<Self, SessionSafetyError> {
        if power.attributes.get("preparing_for_sleep") != Some(&ObservedValue::Bool(false))
            || power.attributes.get("preparing_for_shutdown") != Some(&ObservedValue::Bool(false))
        {
            return Err(SessionSafetyError::TransitionInProgress);
        }
        let bounded_count = |key: &str, maximum: u64| match power.attributes.get(key) {
            Some(ObservedValue::U64(count)) if *count <= maximum => Ok(*count),
            _ => Err(SessionSafetyError::UnsupportedSession),
        };
        if bounded_count("other_user_session_count", 16)? != 0 {
            return Err(SessionSafetyError::OtherSessionsPresent);
        }
        if bounded_count(block_key, 32)? != 0 {
            return Err(SessionSafetyError::PowerInhibited);
        }
        let delay_inhibitors = bounded_count(delay_key, 32)?;
        let inhibit_delay_max_us = bounded_count("inhibit_delay_max_us", 60_000_000)?;
        if inhibit_delay_max_us == 0 {
            return Err(SessionSafetyError::UnsupportedSession);
        }
        Ok(Self {
            session,
            native_authentication_required,
            delay_inhibitors,
            inhibit_delay_max_us,
        })
    }

    #[must_use]
    pub const fn epoch(&self) -> &SessionEpoch {
        self.session.epoch()
    }

    #[must_use]
    pub const fn action(&self) -> SessionAction {
        self.session.action()
    }

    /// Native availability is informational and cannot satisfy Linura approval.
    #[must_use]
    pub const fn native_authentication_required(&self) -> bool {
        self.native_authentication_required
    }

    #[must_use]
    pub const fn delay_inhibitors(&self) -> u64 {
        self.delay_inhibitors
    }

    #[must_use]
    pub const fn inhibit_delay_max_us(&self) -> u64 {
        self.inhibit_delay_max_us
    }

    pub fn require_secure_suspend(
        &self,
        locker: &ObservationEnvelope,
        now_unix_ms: u64,
    ) -> Result<SessionLockId, SessionSafetyError> {
        if self.action() != SessionAction::Suspend {
            return Err(SessionSafetyError::UnsupportedSession);
        }
        self.session.require_secure_coverage(locker, now_unix_ms)
    }
}

pub(crate) fn validate_envelope(
    observation: &ObservationEnvelope,
    provider: &str,
    capability: &str,
    resource: &linura_core::ResourceId,
    now_unix_ms: u64,
) -> Result<(), SessionSafetyError> {
    if observation.provider.as_str() != provider
        || observation.capability.as_str() != capability
        || &observation.resource != resource
    {
        return Err(SessionSafetyError::IdentityMismatch);
    }
    if observation.authority != ObservationAuthority::NativeApi
        || observation.sequence == 0
        || observation.valid_for_ms == 0
        || observation.valid_for_ms > 2_000
    {
        return Err(SessionSafetyError::UntrustedEvidence);
    }
    if now_unix_ms
        .checked_sub(observation.observed_at_unix_ms)
        .is_none_or(|elapsed| elapsed >= observation.valid_for_ms)
    {
        return Err(SessionSafetyError::ExpiredEvidence);
    }
    Ok(())
}

fn require_text(
    observation: &ObservationEnvelope,
    key: &str,
    expected: &str,
) -> Result<(), SessionSafetyError> {
    match observation.attributes.get(key) {
        Some(ObservedValue::Text(value)) if value == expected => Ok(()),
        _ => Err(SessionSafetyError::UnsupportedSession),
    }
}

fn require_u64(
    observation: &ObservationEnvelope,
    key: &str,
    expected: u64,
) -> Result<(), SessionSafetyError> {
    match observation.attributes.get(key) {
        Some(ObservedValue::U64(value)) if *value == expected => Ok(()),
        _ => Err(SessionSafetyError::IdentityMismatch),
    }
}

fn require_bool(
    observation: &ObservationEnvelope,
    key: &str,
    expected: bool,
) -> Result<(), SessionSafetyError> {
    match observation.attributes.get(key) {
        Some(ObservedValue::Bool(value)) if *value == expected => Ok(()),
        _ => Err(SessionSafetyError::UnsupportedSession),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionSafetyError {
    PrincipalMismatch,
    IdentityMismatch,
    UntrustedEvidence,
    ExpiredEvidence,
    UnsupportedSession,
    UnverifiedScreenCoverage,
    PowerUnavailable,
    PowerInhibited,
    OtherSessionsPresent,
    TransitionInProgress,
}

impl Display for SessionSafetyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::PrincipalMismatch => "session owner differs from the authenticated principal",
            Self::IdentityMismatch => "session evidence does not bind the exact current epoch",
            Self::UntrustedEvidence => "session evidence is not a qualified native observation",
            Self::ExpiredEvidence => "session evidence is expired or from a future clock",
            Self::UnsupportedSession => "session state is unsupported, ambiguous or unsafe",
            Self::UnverifiedScreenCoverage => {
                "compositor has not verified exact-session secure coverage"
            }
            Self::PowerUnavailable => "native power operation is unavailable",
            Self::PowerInhibited => "native power operation is inhibited",
            Self::OtherSessionsPresent => "machine power operation affects another user session",
            Self::TransitionInProgress => {
                "native power transition is already in progress or unknown"
            }
        })
    }
}

impl std::error::Error for SessionSafetyError {}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_core::{BootId, CapabilityId, ProviderId, SecurityOwnerInvocationId};
    use std::collections::BTreeMap;
    use std::fmt::Debug;

    fn id<T, E: Debug>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|error| unreachable!("{error:?}"))
    }
    fn epoch() -> SessionEpoch {
        id(SessionEpoch::new(
            id(BootId::new("abcd1234-1234-4567-89ab-0123456789ab")),
            1000,
            "2",
            42,
        ))
    }
    fn principal() -> AuthenticatedPrincipal {
        id(AuthenticatedPrincipal::new("unix:uid:1000"))
    }
    fn invocation() -> SecurityOwnerInvocationId {
        id(SecurityOwnerInvocationId::new(
            "98765432-1234-4567-89ab-0123456789ab",
        ))
    }
    fn snapshot() -> ObservationEnvelope {
        let epoch = epoch();
        ObservationEnvelope {
            provider: id(ProviderId::new(LOGIND_PROVIDER)),
            resource: id(epoch.resource_id()),
            capability: id(CapabilityId::new(LOGIND_CAPABILITY)),
            authority: ObservationAuthority::NativeApi,
            observed_at_unix_ms: 1_000,
            valid_for_ms: 2_000,
            sequence: 1,
            attributes: BTreeMap::from([
                (
                    "boot_id".into(),
                    ObservedValue::Text(epoch.boot().as_str().into()),
                ),
                ("session_id".into(), ObservedValue::Text("2".into())),
                ("uid".into(), ObservedValue::U64(1000)),
                ("created_monotonic_us".into(), ObservedValue::U64(42)),
                ("session_type".into(), ObservedValue::Text("wayland".into())),
                ("session_class".into(), ObservedValue::Text("user".into())),
                ("state".into(), ObservedValue::Text("active".into())),
                ("seat".into(), ObservedValue::Text("seat0".into())),
                ("active".into(), ObservedValue::Bool(true)),
                ("remote".into(), ObservedValue::Bool(false)),
                ("leader_present".into(), ObservedValue::Bool(true)),
            ]),
        }
    }
    fn review(
        observation: &ObservationEnvelope,
    ) -> Result<SessionSafetyReview, SessionSafetyError> {
        SessionSafetyReview::review(
            &principal(),
            &epoch(),
            SessionAction::Suspend,
            observation,
            1_100,
        )
    }
    fn coverage() -> ObservationEnvelope {
        let mut observation = snapshot();
        observation.provider = id(ProviderId::new(LOCKER_PROVIDER));
        observation.capability = id(CapabilityId::new(LOCKER_CAPABILITY));
        observation.resource = id(id(SessionLockId::new(epoch(), invocation(), 1)).resource_id());
        observation
            .attributes
            .insert("secure".into(), ObservedValue::Bool(true));
        observation.attributes.insert(
            "lock_protocol".into(),
            ObservedValue::Text("ext-session-lock-v1".into()),
        );
        observation
            .attributes
            .insert("lock_generation".into(), ObservedValue::U64(1));
        observation.attributes.insert(
            "security_owner_invocation".into(),
            ObservedValue::Text(invocation().as_str().into()),
        );
        observation
    }

    fn power_snapshot() -> ObservationEnvelope {
        let mut observation = snapshot();
        observation.capability = id(CapabilityId::new(POWER_CAPABILITY));
        observation.attributes.extend([
            (
                "permission_query_principal".into(),
                ObservedValue::Text(principal().as_str().into()),
            ),
            (
                "permission_query_session_epoch".into(),
                ObservedValue::Text(id(epoch().resource_id()).as_str().into()),
            ),
            (
                "suspend_availability".into(),
                ObservedValue::Text("yes".into()),
            ),
            (
                "reboot_availability".into(),
                ObservedValue::Text("challenge".into()),
            ),
            (
                "power_off_availability".into(),
                ObservedValue::Text("yes".into()),
            ),
            ("preparing_for_sleep".into(), ObservedValue::Bool(false)),
            ("preparing_for_shutdown".into(), ObservedValue::Bool(false)),
            ("other_user_session_count".into(), ObservedValue::U64(0)),
            ("sleep_block_count".into(), ObservedValue::U64(0)),
            ("sleep_delay_count".into(), ObservedValue::U64(1)),
            ("shutdown_block_count".into(), ObservedValue::U64(0)),
            ("shutdown_delay_count".into(), ObservedValue::U64(0)),
            ("inhibit_delay_max_us".into(), ObservedValue::U64(5_000_000)),
        ]);
        observation
    }

    #[test]
    fn power_preconditions_reuse_exact_session_and_native_lock_generation() {
        let reviewed = id(SessionPowerSafetyReview::review(
            &principal(),
            &epoch(),
            SessionAction::Suspend,
            &power_snapshot(),
            1_100,
        ));
        assert_eq!(reviewed.epoch(), &epoch());
        assert_eq!(reviewed.delay_inhibitors(), 1);
        assert_eq!(reviewed.inhibit_delay_max_us(), 5_000_000);
        assert!(!reviewed.native_authentication_required());
        assert_eq!(
            id(reviewed.require_secure_suspend(&coverage(), 1_100)),
            id(SessionLockId::new(epoch(), invocation(), 1))
        );
        assert!(reviewed.require_secure_suspend(&coverage(), 3_000).is_err());
        let reboot = id(SessionPowerSafetyReview::review(
            &principal(),
            &epoch(),
            SessionAction::Reboot,
            &power_snapshot(),
            1_100,
        ));
        assert!(reboot.native_authentication_required());
        assert!(reboot.require_secure_suspend(&coverage(), 1_100).is_err());
        for action in [
            SessionAction::Lock,
            SessionAction::Unlock,
            SessionAction::Logout,
        ] {
            assert!(
                SessionPowerSafetyReview::review(
                    &principal(),
                    &epoch(),
                    action,
                    &power_snapshot(),
                    1_100
                )
                .is_err()
            );
        }
    }

    #[test]
    fn coordinated_power_conditions_never_relabel_service_permission_or_extend_either_deadline() {
        let transition = id(SessionTransitionId::new(
            id(SessionLockId::new(epoch(), invocation(), 1)),
            SessionTransition::Suspend {
                successful_cycles_before: 42,
            },
        ));
        let mut conditions = power_snapshot();
        conditions.capability = id(CapabilityId::new("session.power.conditions.observe"));
        conditions
            .attributes
            .retain(|key, _| !key.contains("availability") && !key.starts_with("permission_query"));
        let mut permission = conditions.clone();
        permission.provider = id(ProviderId::new("polkit"));
        permission.capability = id(CapabilityId::new("session.power.permission.observe"));
        permission.resource = id(transition.permission_resource_id());
        permission.observed_at_unix_ms = 900;
        permission.valid_for_ms = 300;
        permission.attributes = BTreeMap::from([
            (
                "permission_query_principal".into(),
                ObservedValue::Text(principal().as_str().into()),
            ),
            (
                "permission_query_session_epoch".into(),
                ObservedValue::Text(id(epoch().resource_id()).as_str().into()),
            ),
            ("availability".into(), ObservedValue::Text("yes".into())),
        ]);
        let review = id(SessionPowerSafetyReview::review_with_permission(
            &principal(),
            &transition,
            &conditions,
            &permission,
            1_100,
        ));
        assert!(review.require_secure_suspend(&coverage(), 1_199).is_ok());
        assert!(review.require_secure_suspend(&coverage(), 1_200).is_err());
        assert!(!review.native_authentication_required());
        // Conversely, a newer permission must never freshen old logind facts.
        let mut earlier_conditions = conditions.clone();
        earlier_conditions.valid_for_ms = 150;
        let reviewed = id(SessionPowerSafetyReview::review_with_permission(
            &principal(),
            &transition,
            &earlier_conditions,
            &permission,
            1_100,
        ));
        assert!(reviewed.require_secure_suspend(&coverage(), 1_149).is_ok());
        assert!(reviewed.require_secure_suspend(&coverage(), 1_150).is_err());
        for key in permission.attributes.keys() {
            let mut bad = permission.clone();
            bad.attributes.remove(key);
            assert!(
                SessionPowerSafetyReview::review_with_permission(
                    &principal(),
                    &transition,
                    &conditions,
                    &bad,
                    1_100
                )
                .is_err()
            );
        }
        for kind in [
            "provider",
            "capability",
            "resource",
            "principal",
            "epoch",
            "no",
            "unknown",
            "stale",
            "future",
        ] {
            let mut bad = permission.clone();
            match kind {
                "provider" => bad.provider = id(ProviderId::new("logind")),
                "capability" => bad.capability = id(CapabilityId::new("session.power.observe")),
                "resource" => {
                    bad.resource = id(id(SessionTransitionId::new(
                        transition.lock().clone(),
                        SessionTransition::Reboot,
                    ))
                    .resource_id())
                }
                "principal" => {
                    bad.attributes.insert(
                        "permission_query_principal".into(),
                        ObservedValue::Text("unix:uid:0".into()),
                    );
                }
                "epoch" => {
                    bad.attributes.insert(
                        "permission_query_session_epoch".into(),
                        ObservedValue::Text("session:epoch:other".into()),
                    );
                }
                "no" | "unknown" => {
                    bad.attributes
                        .insert("availability".into(), ObservedValue::Text(kind.into()));
                }
                "stale" => bad.valid_for_ms = 200,
                _ => bad.observed_at_unix_ms = 1_101,
            }
            assert!(
                SessionPowerSafetyReview::review_with_permission(
                    &principal(),
                    &transition,
                    &conditions,
                    &bad,
                    1_100
                )
                .is_err(),
                "{kind}"
            );
        }
        let mut bad_conditions = conditions.clone();
        bad_conditions
            .attributes
            .insert("sleep_block_count".into(), ObservedValue::U64(1));
        assert!(
            SessionPowerSafetyReview::review_with_permission(
                &principal(),
                &transition,
                &bad_conditions,
                &permission,
                1_100
            )
            .is_err()
        );
        bad_conditions = conditions.clone();
        bad_conditions.capability = id(CapabilityId::new(POWER_CAPABILITY));
        assert!(
            SessionPowerSafetyReview::review_with_permission(
                &principal(),
                &transition,
                &bad_conditions,
                &permission,
                1_100
            )
            .is_err()
        );
        permission.attributes.insert(
            "availability".into(),
            ObservedValue::Text("challenge".into()),
        );
        assert!(
            id(SessionPowerSafetyReview::review_with_permission(
                &principal(),
                &transition,
                &conditions,
                &permission,
                1_100
            ))
            .native_authentication_required()
        );
    }

    #[test]
    fn native_power_availability_never_overrides_inhibitors_other_sessions_or_unknown_state() {
        for (key, value, expected) in [
            (
                "permission_query_principal",
                ObservedValue::Text("unix:uid:0".into()),
                SessionSafetyError::IdentityMismatch,
            ),
            (
                "permission_query_session_epoch",
                ObservedValue::Text("session:epoch:other-session".into()),
                SessionSafetyError::IdentityMismatch,
            ),
            (
                "sleep_block_count",
                ObservedValue::U64(1),
                SessionSafetyError::PowerInhibited,
            ),
            (
                "other_user_session_count",
                ObservedValue::U64(1),
                SessionSafetyError::OtherSessionsPresent,
            ),
            (
                "preparing_for_sleep",
                ObservedValue::Bool(true),
                SessionSafetyError::TransitionInProgress,
            ),
            (
                "preparing_for_shutdown",
                ObservedValue::Bool(true),
                SessionSafetyError::TransitionInProgress,
            ),
            (
                "suspend_availability",
                ObservedValue::Text("na".into()),
                SessionSafetyError::PowerUnavailable,
            ),
            (
                "suspend_availability",
                ObservedValue::Text("unknown".into()),
                SessionSafetyError::UnsupportedSession,
            ),
            (
                "sleep_delay_count",
                ObservedValue::U64(33),
                SessionSafetyError::UnsupportedSession,
            ),
            (
                "inhibit_delay_max_us",
                ObservedValue::U64(0),
                SessionSafetyError::UnsupportedSession,
            ),
        ] {
            let mut observation = power_snapshot();
            observation.attributes.insert(key.into(), value);
            assert_eq!(
                SessionPowerSafetyReview::review(
                    &principal(),
                    &epoch(),
                    SessionAction::Suspend,
                    &observation,
                    1_100
                ),
                Err(expected)
            );
        }
        for key in [
            "permission_query_principal",
            "permission_query_session_epoch",
            "suspend_availability",
            "sleep_block_count",
            "sleep_delay_count",
            "other_user_session_count",
            "inhibit_delay_max_us",
        ] {
            let mut observation = power_snapshot();
            observation.attributes.remove(key);
            assert!(
                SessionPowerSafetyReview::review(
                    &principal(),
                    &epoch(),
                    SessionAction::Suspend,
                    &observation,
                    1_100
                )
                .is_err()
            );
        }
    }

    #[test]
    fn secure_coverage_identity_binds_generation_and_cannot_accept_a_bare_epoch() {
        let reviewed = id(review(&snapshot()));
        let mut coverage = coverage();
        coverage.resource = id(epoch().resource_id());
        assert_eq!(
            reviewed.require_secure_coverage(&coverage, 1_100),
            Err(SessionSafetyError::IdentityMismatch)
        );
        coverage.resource = id(id(SessionLockId::new(epoch(), invocation(), 2)).resource_id());
        assert_eq!(
            reviewed.require_secure_coverage(&coverage, 1_100),
            Err(SessionSafetyError::IdentityMismatch)
        );
    }

    #[test]
    fn replacement_security_owner_cannot_reuse_an_old_lock_identity() {
        let reviewed = id(review(&snapshot()));
        let mut observation = coverage();
        let replacement = id(SecurityOwnerInvocationId::new(
            "12345678-1234-4567-89ab-0123456789ab",
        ));
        observation.attributes.insert(
            "security_owner_invocation".into(),
            ObservedValue::Text(replacement.as_str().into()),
        );
        assert_eq!(
            reviewed.require_secure_coverage(&observation, 1_100),
            Err(SessionSafetyError::IdentityMismatch)
        );
        observation.resource =
            id(id(SessionLockId::new(epoch(), replacement.clone(), 1)).resource_id());
        assert_eq!(
            id(reviewed.require_secure_coverage(&observation, 1_100)),
            id(SessionLockId::new(epoch(), replacement, 1))
        );
    }

    #[test]
    fn every_session_action_is_managed_independently_of_presentation() {
        for action in [
            SessionAction::Lock,
            SessionAction::Unlock,
            SessionAction::Suspend,
            SessionAction::Logout,
            SessionAction::Reboot,
            SessionAction::PowerOff,
        ] {
            assert_eq!(
                action.operation_class(),
                OperationClass::ManagedExternalEffect
            );
            assert!(action.risk_floor() >= RiskClass::SecuritySensitive);
            assert!(!action.as_str().is_empty());
        }
    }

    #[test]
    fn exact_active_owner_session_is_reviewable_but_not_execution_authority() {
        let reviewed = id(review(&snapshot()));
        assert_eq!(reviewed.epoch(), &epoch());
        assert_eq!(reviewed.action(), SessionAction::Suspend);
        assert!(reviewed.require_secure_coverage(&coverage(), 1_100).is_ok());
    }

    #[test]
    fn root_cross_user_and_caller_lookalike_principals_do_not_bypass_ownership() {
        for value in [
            "unix:uid:0",
            "unix:uid:1001",
            "uid:1000",
            "unix:uid:01000",
            "actor:human",
        ] {
            let principal = id(AuthenticatedPrincipal::new(value));
            assert_eq!(
                SessionSafetyReview::review(
                    &principal,
                    &epoch(),
                    SessionAction::Unlock,
                    &snapshot(),
                    1_100
                ),
                Err(SessionSafetyError::PrincipalMismatch)
            );
        }
    }

    #[test]
    fn absent_ambiguous_foreign_and_inactive_facts_fail_closed() {
        for (key, value) in [
            ("uid", ObservedValue::U64(1001)),
            ("created_monotonic_us", ObservedValue::U64(43)),
            ("session_id", ObservedValue::Text("3".into())),
            ("session_type", ObservedValue::Text("x11".into())),
            ("session_class", ObservedValue::Text("greeter".into())),
            ("state", ObservedValue::Text("closing".into())),
            ("seat", ObservedValue::Text("".into())),
            ("leader_present", ObservedValue::Bool(false)),
            ("active", ObservedValue::Bool(false)),
            ("remote", ObservedValue::Bool(true)),
        ] {
            let mut observation = snapshot();
            observation.attributes.insert(key.into(), value);
            assert!(review(&observation).is_err(), "accepted {key}");
        }
        for key in snapshot().attributes.keys() {
            let mut observation = snapshot();
            observation.attributes.remove(key);
            assert!(review(&observation).is_err(), "defaulted {key}");
        }
    }

    #[test]
    fn cached_forged_and_future_evidence_cannot_satisfy_preconditions() {
        for time in [999, 3_000, u64::MAX] {
            assert_eq!(
                SessionSafetyReview::review(
                    &principal(),
                    &epoch(),
                    SessionAction::Lock,
                    &snapshot(),
                    time
                ),
                Err(SessionSafetyError::ExpiredEvidence)
            );
        }
        let mut untrusted = snapshot();
        untrusted.authority = ObservationAuthority::Filesystem;
        assert_eq!(
            review(&untrusted),
            Err(SessionSafetyError::UntrustedEvidence)
        );
        untrusted = snapshot();
        untrusted.sequence = 0;
        assert_eq!(
            review(&untrusted),
            Err(SessionSafetyError::UntrustedEvidence)
        );
        untrusted = snapshot();
        untrusted.valid_for_ms = u64::MAX;
        assert_eq!(
            review(&untrusted),
            Err(SessionSafetyError::UntrustedEvidence)
        );
    }

    #[test]
    fn hint_authentication_and_executor_self_report_never_prove_coverage() {
        let reviewed = id(review(&snapshot()));
        let mut hint = snapshot();
        hint.attributes
            .insert("locked_hint".into(), ObservedValue::Bool(true));
        hint.attributes
            .insert("authenticated".into(), ObservedValue::Bool(true));
        hint.attributes
            .insert("dispatch_accepted".into(), ObservedValue::Bool(true));
        assert!(reviewed.require_secure_coverage(&hint, 1_100).is_err());
        for key in [
            "secure",
            "lock_protocol",
            "lock_generation",
            "security_owner_invocation",
        ] {
            let mut incomplete = coverage();
            incomplete.attributes.remove(key);
            assert!(
                reviewed
                    .require_secure_coverage(&incomplete, 1_100)
                    .is_err(),
                "{key}"
            );
        }
        let mut stale = coverage();
        stale.observed_at_unix_ms = 0;
        stale.valid_for_ms = 100;
        assert!(reviewed.require_secure_coverage(&stale, 1_100).is_err());
        let mut failed = coverage();
        failed
            .attributes
            .insert("secure".into(), ObservedValue::Bool(false));
        assert!(reviewed.require_secure_coverage(&failed, 1_100).is_err());
        let mut absent = coverage();
        absent
            .attributes
            .insert("lock_generation".into(), ObservedValue::U64(0));
        assert_eq!(
            reviewed.require_secure_coverage(&absent, 1_100),
            Err(SessionSafetyError::IdentityMismatch)
        );
    }

    #[test]
    fn new_coverage_cannot_refresh_expired_session_ownership() {
        let reviewed = id(review(&snapshot()));
        let mut fresh_coverage = coverage();
        fresh_coverage.observed_at_unix_ms = 3_000;
        assert_eq!(
            reviewed.require_secure_coverage(&fresh_coverage, 3_000),
            Err(SessionSafetyError::ExpiredEvidence)
        );
        assert_eq!(
            reviewed.require_secure_coverage(&coverage(), 999),
            Err(SessionSafetyError::ExpiredEvidence)
        );
    }
}
