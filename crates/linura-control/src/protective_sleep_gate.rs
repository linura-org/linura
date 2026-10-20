//! S17 native-entry coverage coordination. This does not authorize sleep or
//! provide another mutation path: an uncovered session must enter the existing
//! protective managed lifecycle through the concrete trusted composition port.
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use linura_core::{SessionEpoch, SessionLockId, SleepInvocationId};
use linura_observation::{ObservationEnvelope, ObservedValue};
use linura_protocol::{NativeSleepGateState, NativeSleepGateStatus};

use crate::{AuthenticatedPrincipal, SessionAction, SessionSafetyReview};

const GATE_BUDGET: Duration = Duration::from_secs(20);
const MAX_SESSIONS: usize = 16;

/// Bounded, non-authoritative presentation diagnostics, separate from the managed
/// lifecycle mutex. Only the independently attested native-entry composition may
/// begin an attempt. Reading or retaining this state never creates authority.
#[derive(Clone, Debug, Default)]
pub struct NativeSleepGateMonitor {
    latest: Arc<Mutex<Option<(SleepInvocationId, NativeSleepGateState)>>>,
}

impl NativeSleepGateMonitor {
    pub fn begin_attested_entry(
        &self,
        event: &SleepInvocationId,
    ) -> Result<NativeSleepGateAttempt, String> {
        let mut latest = self
            .latest
            .lock()
            .map_err(|_| "sleep diagnostics unavailable")?;
        if latest
            .as_ref()
            .is_some_and(|(_, state)| *state == NativeSleepGateState::Checking)
        {
            return Err("sleep diagnostic attempt already active".into());
        }
        *latest = Some((event.clone(), NativeSleepGateState::Checking));
        Ok(NativeSleepGateAttempt {
            monitor: self.clone(),
            event: event.clone(),
        })
    }

    /// Composition must first independently observe the exact current epoch.
    pub fn snapshot(
        &self,
        principal: &AuthenticatedPrincipal,
        epoch: &SessionEpoch,
    ) -> Result<NativeSleepGateStatus, String> {
        if epoch.uid() == 0 || principal.as_str() != format!("unix:uid:{}", epoch.uid()) {
            return Err("sleep diagnostics belong to another principal".into());
        }
        let latest = self
            .latest
            .lock()
            .map_err(|_| "sleep diagnostics unavailable")?;
        let state = match latest.as_ref() {
            None => NativeSleepGateState::Unobserved,
            Some((event, state)) if event.boot() == epoch.boot() => *state,
            Some(_) => return Err("sleep diagnostic boot differs from current login".into()),
        };
        Ok(NativeSleepGateStatus {
            epoch: epoch.clone(),
            state,
        })
    }
}

/// Dropping an unfinished attempt records denial, including early error/unwind.
/// This is diagnostic bookkeeping, never a native coverage fence.
#[derive(Debug)]
pub struct NativeSleepGateAttempt {
    monitor: NativeSleepGateMonitor,
    event: SleepInvocationId,
}

impl NativeSleepGateAttempt {
    pub fn coverage_fenced(self) -> Result<(), String> {
        let mut latest = self
            .monitor
            .latest
            .lock()
            .map_err(|_| "sleep diagnostics unavailable")?;
        if latest.as_ref() != Some(&(self.event.clone(), NativeSleepGateState::Checking)) {
            return Err("sleep diagnostic attempt changed".into());
        }
        *latest = Some((self.event.clone(), NativeSleepGateState::CoverageFenced));
        Ok(())
    }
}

impl Drop for NativeSleepGateAttempt {
    fn drop(&mut self) {
        if let Ok(mut latest) = self.monitor.latest.lock()
            && latest.as_ref() == Some(&(self.event.clone(), NativeSleepGateState::Checking))
        {
            *latest = Some((self.event.clone(), NativeSleepGateState::Denied));
        }
    }
}

/// Trusted native composition only. Facts are canonical and independently
/// acquired, not client assertions. Mechanisms expose no transport handles.
pub trait NativeSleepCoveragePort {
    fn session_epochs(&mut self) -> Result<Vec<SessionEpoch>, String>;
    fn observe_session(&mut self, epoch: &SessionEpoch) -> Result<ObservationEnvelope, String>;
    fn observe_lock(&mut self, epoch: &SessionEpoch) -> Result<ObservationEnvelope, String>;
    /// MUST use the existing serialized managed protective-lock lifecycle.
    /// Busy/poisoned state denies; it may not wait behind a managed suspend.
    fn converge_protective_lock(
        &mut self,
        event: &SleepInvocationId,
        lock: &SessionLockId,
    ) -> Result<(), String>;
    fn fence_coverage(
        &mut self,
        event: &SleepInvocationId,
        lock: &SessionLockId,
    ) -> Result<bool, String>;
    fn revalidate_entry(&mut self, event: &SleepInvocationId) -> Result<(), String>;
}

/// Called only after independent received-helper attestation. There is no
/// caller-selected principal/Actor/approval or direct executor here. In
/// particular, already-secure coverage never requests automatic-lock consent.
pub fn coordinate_native_sleep_coverage(
    port: &mut impl NativeSleepCoveragePort,
    event: &SleepInvocationId,
) -> Result<(), String> {
    let started = Instant::now();
    let wall_started = SystemTime::now();
    // Wall time accounts for suspend; monotonic elapsed prevents a backwards
    // adjustment from renewing the original budget. Clock rollback denies.
    coordinate(
        port,
        event,
        &|| {
            SystemTime::now()
                .duration_since(wall_started)
                .map_or(Duration::MAX, |wall| wall.max(started.elapsed()))
        },
        GATE_BUDGET,
    )
}

fn coordinate(
    port: &mut impl NativeSleepCoveragePort,
    event: &SleepInvocationId,
    elapsed: &impl Fn() -> Duration,
    budget: Duration,
) -> Result<(), String> {
    let check = || {
        if elapsed() >= budget {
            Err("native sleep coverage gate exceeded its original deadline".to_owned())
        } else {
            Ok(())
        }
    };
    check()?;
    port.revalidate_entry(event)?;
    let epochs = inventory(port, event, &check)?;
    if epochs.is_empty() {
        return Err("native sleep gate has no qualified graphical session".into());
    }
    for epoch in &epochs {
        check()?;
        let sample = port.observe_lock(epoch)?;
        let lock = SessionLockId::from_resource(&sample.resource).map_err(|e| e.to_string())?;
        if lock.epoch() != epoch {
            return Err("native sleep locker does not belong to the enumerated epoch".into());
        }
        let native = port.observe_session(epoch)?;
        let owner = AuthenticatedPrincipal::new(format!("unix:uid:{}", epoch.uid()))
            .map_err(|e| e.to_string())?;
        // This owner selects read-only identity predicates, never the initiating
        // principal of the protective mutation (which remains the service).
        SessionSafetyReview::review(&owner, epoch, SessionAction::Lock, &native, now_ms()?)
            .map_err(|e| e.to_string())?;
        if !crate::session_safety::validate_native_lock(&lock, &sample, now_ms()?)
            .map_err(|e| e.to_string())?
        {
            check()?;
            port.revalidate_entry(event)?;
            port.converge_protective_lock(event, &lock)?;
        }
        check()?;
        // No pre-mutation/native acknowledgement is completion. Independently
        // re-read exact epoch/generation and coverage before the native fence.
        let native = port.observe_session(epoch)?;
        let coverage = port.observe_lock(epoch)?;
        let reviewed =
            SessionSafetyReview::review(&owner, epoch, SessionAction::Lock, &native, now_ms()?)
                .map_err(|e| e.to_string())?;
        if reviewed
            .require_secure_coverage(&coverage, now_ms()?)
            .map_err(|e| e.to_string())?
            != lock
        {
            return Err("native sleep coverage generation changed".into());
        }
        port.revalidate_entry(event)?;
        check()?;
        if !port.fence_coverage(event, &lock)? {
            return Err("native sleep coverage fence was refused".into());
        }
        check()?;
    }
    if inventory(port, event, &check)? != epochs {
        return Err("native graphical session inventory changed; sleep denied".into());
    }
    port.revalidate_entry(event)?;
    check()
}

fn inventory(
    port: &mut impl NativeSleepCoveragePort,
    event: &SleepInvocationId,
    check: &impl Fn() -> Result<(), String>,
) -> Result<BTreeSet<SessionEpoch>, String> {
    check()?;
    let resources = port.session_epochs()?;
    if resources.len() > MAX_SESSIONS {
        return Err("native sleep session inventory exceeds its bound".into());
    }
    let mut seen = BTreeSet::new();
    let mut selected = BTreeSet::new();
    for epoch in resources {
        check()?;
        if epoch.boot() != event.boot() || !seen.insert(epoch.clone()) {
            return Err(
                "native sleep session inventory has a duplicate epoch or changed boot".into(),
            );
        }
        let sample = port.observe_session(&epoch)?;
        let resource = epoch.resource_id().map_err(|e| e.to_string())?;
        crate::session_safety::validate_envelope(
            &sample,
            "logind",
            "session.epoch.observe",
            &resource,
            now_ms()?,
        )
        .map_err(|e| e.to_string())?;
        if sample.attributes.get("boot_id")
            != Some(&ObservedValue::Text(epoch.boot().as_str().into()))
            || sample.attributes.get("session_id")
                != Some(&ObservedValue::Text(epoch.session_id().into()))
            || sample.attributes.get("uid") != Some(&ObservedValue::U64(u64::from(epoch.uid())))
            || sample.attributes.get("created_monotonic_us")
                != Some(&ObservedValue::U64(epoch.created_monotonic_us()))
        {
            return Err("native sleep session inventory is not authoritative for its epoch".into());
        }
        if requires_coverage(&sample)? {
            if epoch.uid() == 0 {
                return Err("root graphical sleep coverage is unsupported".into());
            }
            selected.insert(epoch);
        }
    }
    check()?;
    Ok(selected)
}

fn requires_coverage(sample: &ObservationEnvelope) -> Result<bool, String> {
    let text = |key| match sample.attributes.get(key) {
        Some(ObservedValue::Text(value)) => Ok(value.as_str()),
        _ => Err("native session inventory has incomplete type/class state".to_owned()),
    };
    match (text("session_class")?, text("session_type")?) {
        ("user" | "user-early" | "user-light", "wayland") => Ok(true),
        ("user" | "user-early" | "user-light", "tty")
        | ("manager" | "manager-early" | "background" | "background-light", "unspecified") => {
            Ok(false)
        }
        _ => Err("native sleep inventory contains an unsupported session type/class".into()),
    }
}
fn now_ms() -> Result<u64, String> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "native sleep gate clock is unavailable")?
            .as_millis(),
    )
    .map_err(|_| "native sleep gate clock overflow".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_core::{BootId, CapabilityId, ProviderId, SecurityOwnerInvocationId};
    use linura_observation::ObservationAuthority;
    use std::collections::BTreeMap;

    fn id<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|e| unreachable!("{e:?}"))
    }
    fn epoch() -> SessionEpoch {
        id(SessionEpoch::new(
            id(BootId::new("abcd1234-1234-4567-89ab-0123456789ab")),
            1000,
            "c2",
            42,
        ))
    }
    fn event() -> SleepInvocationId {
        id(SleepInvocationId::new(
            epoch().boot().clone(),
            "01234567-1234-4567-89ab-0123456789ab",
        ))
    }

    #[test]
    fn diagnostic_lifecycle_defaults_unknown_denies_early_error_and_never_claims_sleep() {
        let monitor = NativeSleepGateMonitor::default();
        let owner = id(AuthenticatedPrincipal::new("unix:uid:1000"));
        let state = || id(monitor.snapshot(&owner, &epoch())).state;
        assert_eq!(state(), NativeSleepGateState::Unobserved);
        let attempt = id(monitor.begin_attested_entry(&event()));
        assert_eq!(state(), NativeSleepGateState::Checking);
        assert!(monitor.begin_attested_entry(&event()).is_err());
        drop(attempt);
        assert_eq!(state(), NativeSleepGateState::Denied);
        let attempt = id(monitor.begin_attested_entry(&event()));
        id(attempt.coverage_fenced());
        assert_eq!(state(), NativeSleepGateState::CoverageFenced);
        // Retained completion/drop cannot erase denial from a subsequent job.
        let next = id(SleepInvocationId::new(
            epoch().boot().clone(),
            "12345678-1234-4567-89ab-0123456789ab",
        ));
        drop(id(monitor.begin_attested_entry(&next)));
        assert_eq!(state(), NativeSleepGateState::Denied);
        // Restart is explicitly unknown, not restored success/authority.
        assert_eq!(
            id(NativeSleepGateMonitor::default().snapshot(&owner, &epoch())).state,
            NativeSleepGateState::Unobserved
        );
    }

    #[test]
    fn diagnostics_reject_principal_boot_drift_poison_and_superseded_attempt() {
        let monitor = NativeSleepGateMonitor::default();
        let owner = id(AuthenticatedPrincipal::new("unix:uid:1000"));
        let attempt = id(monitor.begin_attested_entry(&event()));
        for foreign in [
            "unix:uid:0",
            "unix:uid:1001",
            "service:system-sleep-protection",
        ] {
            assert!(
                monitor
                    .snapshot(&id(AuthenticatedPrincipal::new(foreign)), &epoch())
                    .is_err()
            );
        }
        let other_boot = id(SessionEpoch::new(
            id(BootId::new("12345678-1234-4567-89ab-0123456789ab")),
            1000,
            "c2",
            42,
        ));
        assert!(monitor.snapshot(&owner, &other_boot).is_err());
        // An interrupted/superseded diagnostic cannot clobber a newer record.
        let next = id(SleepInvocationId::new(
            epoch().boot().clone(),
            "12345678-1234-4567-89ab-0123456789ab",
        ));
        *id(monitor.latest.lock()) = Some((next, NativeSleepGateState::Denied));
        assert!(attempt.coverage_fenced().is_err());
        assert_eq!(
            id(monitor.snapshot(&owner, &epoch())).state,
            NativeSleepGateState::Denied
        );
        let poisoned = monitor.clone();
        let result = std::panic::catch_unwind(move || {
            let _lock = id(poisoned.latest.lock());
            std::panic::resume_unwind(Box::new(()));
        });
        assert!(result.is_err());
        assert!(monitor.snapshot(&owner, &epoch()).is_err());
        assert!(monitor.begin_attested_entry(&event()).is_err());
    }

    fn sample(epoch: &SessionEpoch, secure: Option<bool>, generation: u64) -> ObservationEnvelope {
        let lock = id(SessionLockId::new(
            epoch.clone(),
            id(SecurityOwnerInvocationId::new(
                "98765432-1234-4567-89ab-0123456789ab",
            )),
            generation,
        ));
        let mut attributes = BTreeMap::from([
            (
                "boot_id".into(),
                ObservedValue::Text(epoch.boot().as_str().into()),
            ),
            (
                "session_id".into(),
                ObservedValue::Text(epoch.session_id().into()),
            ),
            ("uid".into(), ObservedValue::U64(u64::from(epoch.uid()))),
            (
                "created_monotonic_us".into(),
                ObservedValue::U64(epoch.created_monotonic_us()),
            ),
        ]);
        let (provider, capability, resource) = if let Some(secure) = secure {
            attributes.extend([
                ("secure".into(), ObservedValue::Bool(secure)),
                ("lock_generation".into(), ObservedValue::U64(generation)),
                (
                    "security_owner_invocation".into(),
                    ObservedValue::Text(lock.security_owner_invocation().as_str().into()),
                ),
                (
                    "lock_protocol".into(),
                    ObservedValue::Text("ext-session-lock-v1".into()),
                ),
            ]);
            (
                "session-locker",
                "session.secure-lock.observe",
                id(lock.resource_id()),
            )
        } else {
            attributes.extend([
                ("session_type".into(), ObservedValue::Text("wayland".into())),
                ("session_class".into(), ObservedValue::Text("user".into())),
                ("state".into(), ObservedValue::Text("active".into())),
                ("seat".into(), ObservedValue::Text("seat0".into())),
                ("active".into(), ObservedValue::Bool(true)),
                ("remote".into(), ObservedValue::Bool(false)),
                ("leader_present".into(), ObservedValue::Bool(true)),
            ]);
            ("logind", "session.epoch.observe", id(epoch.resource_id()))
        };
        ObservationEnvelope {
            provider: id(ProviderId::new(provider)),
            capability: id(CapabilityId::new(capability)),
            resource,
            authority: ObservationAuthority::NativeApi,
            observed_at_unix_ms: id(now_ms()),
            valid_for_ms: 2000,
            sequence: 1,
            attributes,
        }
    }

    struct Fixture {
        secure: bool,
        protection_allowed: bool,
        post_secure: bool,
        fence_allowed: bool,
        entry_allowed: bool,
        synthetic: bool,
        stale: bool,
        drift: bool,
        generation_drift: bool,
        inventory_count: usize,
        epochs: Vec<SessionEpoch>,
        mutations: usize,
        fences: usize,
        session_type: &'static str,
        session_class: &'static str,
        replace_inventory_fact: Option<(String, ObservedValue)>,
        inventory_validity: u64,
    }
    impl Fixture {
        fn new(secure: bool) -> Self {
            Self {
                secure,
                protection_allowed: true,
                post_secure: true,
                fence_allowed: true,
                entry_allowed: true,
                synthetic: false,
                stale: false,
                drift: false,
                generation_drift: false,
                inventory_count: 0,
                epochs: vec![epoch()],
                mutations: 0,
                fences: 0,
                session_type: "wayland",
                session_class: "user",
                replace_inventory_fact: None,
                inventory_validity: 2000,
            }
        }
        fn run(&mut self) -> Result<(), String> {
            coordinate_native_sleep_coverage(self, &event())
        }
    }
    impl NativeSleepCoveragePort for Fixture {
        fn session_epochs(&mut self) -> Result<Vec<SessionEpoch>, String> {
            self.inventory_count += 1;
            let mut epochs = self.epochs.clone();
            if self.drift && self.inventory_count > 1 {
                epochs.clear();
            }
            Ok(epochs)
        }
        fn observe_session(&mut self, epoch: &SessionEpoch) -> Result<ObservationEnvelope, String> {
            let mut value = sample(epoch, None, 7);
            value.attributes.insert(
                "session_type".into(),
                ObservedValue::Text(self.session_type.into()),
            );
            value.attributes.insert(
                "session_class".into(),
                ObservedValue::Text(self.session_class.into()),
            );
            if self.synthetic {
                value.authority = ObservationAuthority::SyntheticTest;
            }
            if self.stale {
                value.observed_at_unix_ms = 1;
            }
            value.valid_for_ms = self.inventory_validity;
            if let Some((key, replacement)) = &self.replace_inventory_fact {
                value.attributes.insert(key.clone(), replacement.clone());
            }
            Ok(value)
        }
        fn observe_lock(&mut self, epoch: &SessionEpoch) -> Result<ObservationEnvelope, String> {
            Ok(sample(
                epoch,
                Some(self.secure),
                if self.generation_drift && self.mutations > 0 {
                    8
                } else {
                    7
                },
            ))
        }
        fn converge_protective_lock(
            &mut self,
            _: &SleepInvocationId,
            _: &SessionLockId,
        ) -> Result<(), String> {
            self.mutations += 1;
            if !self.protection_allowed {
                return Err("managed policy denied or Control busy".into());
            }
            self.secure = self.post_secure;
            Ok(())
        }
        fn fence_coverage(
            &mut self,
            _: &SleepInvocationId,
            _: &SessionLockId,
        ) -> Result<bool, String> {
            self.fences += 1;
            Ok(self.fence_allowed)
        }
        fn revalidate_entry(&mut self, _: &SleepInvocationId) -> Result<(), String> {
            if self.entry_allowed {
                Ok(())
            } else {
                Err("native helper is no longer attested".into())
            }
        }
    }

    #[test]
    fn already_secure_path_never_needs_consent_or_waits_for_managed_mutation() {
        let mut fixture = Fixture::new(true);
        fixture.protection_allowed = false; // Models unavailable/busy Control/consent.
        assert!(fixture.run().is_ok());
        assert_eq!((fixture.mutations, fixture.fences), (0, 1));
        let mut protective = Fixture::new(false);
        assert!(protective.run().is_ok());
        assert_eq!((protective.mutations, protective.fences), (1, 1));
    }

    #[test]
    fn unapproved_failed_unverified_and_replaced_protective_lock_never_fence() {
        let mut denied = Fixture::new(false);
        denied.protection_allowed = false;
        assert!(denied.run().is_err());
        assert_eq!((denied.mutations, denied.fences), (1, 0));
        let mut absent = Fixture::new(false);
        absent.post_secure = false;
        assert!(absent.run().is_err());
        assert_eq!(absent.fences, 0);
        let mut replaced = Fixture::new(false);
        replaced.generation_drift = true;
        assert!(replaced.run().is_err());
        assert_eq!(replaced.fences, 0);
    }

    #[test]
    fn unknown_or_changed_native_inventory_and_failed_fence_never_continue() {
        for (class, kind) in [
            ("future-user", "wayland"),
            ("user", "x11"),
            ("greeter", "wayland"),
            ("manager", "wayland"),
        ] {
            let mut fixture = Fixture::new(true);
            fixture.session_class = class;
            fixture.session_type = kind;
            assert!(fixture.run().is_err());
            assert_eq!((fixture.mutations, fixture.fences), (0, 0));
        }
        for (class, kind) in [("user", "tty"), ("manager", "unspecified")] {
            let mut fixture = Fixture::new(true);
            fixture.session_class = class;
            fixture.session_type = kind;
            assert!(fixture.run().is_err()); // No qualified graphical coverage, not guessed secure.
            assert_eq!(fixture.fences, 0);
        }
        let mut changed = Fixture::new(true);
        changed.drift = true;
        assert!(changed.run().is_err());
        assert_eq!(changed.fences, 1); // Failure cannot remove an already-armed native fence.
        let mut refused = Fixture::new(true);
        refused.fence_allowed = false;
        assert!(refused.run().is_err());
        let mut absent = Fixture::new(true);
        absent.entry_allowed = false;
        assert!(absent.run().is_err());
        assert_eq!(absent.inventory_count, 0);
    }

    #[test]
    fn synthetic_stale_root_duplicate_and_oversized_inventory_are_denied() {
        let mut synthetic = Fixture::new(true);
        synthetic.synthetic = true;
        assert!(synthetic.run().is_err());
        let mut stale = Fixture::new(true);
        stale.stale = true;
        assert!(stale.run().is_err());
        let mut root = Fixture::new(true);
        root.epochs = vec![id(SessionEpoch::new(epoch().boot().clone(), 0, "c1", 42))];
        assert!(root.run().is_err());
        let mut duplicate = Fixture::new(true);
        duplicate.epochs.push(epoch());
        assert!(duplicate.run().is_err());
        let mut oversized = Fixture::new(true);
        oversized.epochs = vec![epoch(); 17];
        assert!(oversized.run().is_err());
        for fixture in [synthetic, stale, root, duplicate, oversized] {
            assert_eq!((fixture.mutations, fixture.fences), (0, 0));
        }
    }

    #[test]
    fn multiple_qualified_seats_are_all_fenced_and_original_budget_never_renews() {
        let mut fixture = Fixture::new(true);
        fixture.epochs.push(id(SessionEpoch::new(
            epoch().boot().clone(),
            1001,
            "c3",
            43,
        )));
        assert!(fixture.run().is_ok());
        assert_eq!((fixture.mutations, fixture.fences), (0, 2));
        let mut expired = Fixture::new(true);
        assert!(
            coordinate(
                &mut expired,
                &event(),
                &|| Duration::from_secs(20),
                GATE_BUDGET
            )
            .is_err()
        );
        assert_eq!(expired.inventory_count, 0);
    }

    #[test]
    fn even_excluded_inventory_entries_must_bind_exact_fresh_native_epoch() {
        for (key, value) in [
            (
                "boot_id",
                ObservedValue::Text("abcd1234-1234-4567-89ab-0123456789ac".into()),
            ),
            ("session_id", ObservedValue::Text("c3".into())),
            ("uid", ObservedValue::U64(1001)),
            ("uid", ObservedValue::Text("1000".into())),
            ("created_monotonic_us", ObservedValue::U64(43)),
        ] {
            for kind in ["wayland", "tty"] {
                let mut fixture = Fixture::new(true);
                fixture.session_type = kind;
                fixture.replace_inventory_fact = Some((key.into(), value.clone()));
                assert!(fixture.run().is_err());
                assert_eq!((fixture.mutations, fixture.fences), (0, 0));
            }
        }
        for validity in [0, 2001, u64::MAX] {
            let mut fixture = Fixture::new(true);
            fixture.inventory_validity = validity;
            assert!(fixture.run().is_err());
            assert_eq!((fixture.mutations, fixture.fences), (0, 0));
        }
    }

    #[test]
    fn original_deadline_can_expire_at_any_coordination_boundary() {
        use std::cell::Cell;
        for secure in [false, true] {
            let calls = Cell::new(0_u32);
            let mut successful = Fixture::new(secure);
            assert!(
                coordinate(
                    &mut successful,
                    &event(),
                    &|| {
                        calls.set(calls.get() + 1);
                        Duration::ZERO
                    },
                    GATE_BUDGET
                )
                .is_ok()
            );
            let total = calls.get();
            for expiry in 0..total {
                let mut fixture = Fixture::new(secure);
                let calls = Cell::new(0_u32);
                assert!(
                    coordinate(
                        &mut fixture,
                        &event(),
                        &|| {
                            let current = calls.get();
                            calls.set(current + 1);
                            if current >= expiry {
                                GATE_BUDGET
                            } else {
                                Duration::ZERO
                            }
                        },
                        GATE_BUDGET
                    )
                    .is_err()
                );
                // It stops at the first expired original boundary. Native
                // fences already armed are never cleared by this denial.
                assert_eq!(calls.get(), expiry + 1);
            }
        }
    }
}
