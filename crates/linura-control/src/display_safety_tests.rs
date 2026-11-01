use super::*;
use crate::{DisplayLayoutPlanRequest, PlanPreviewControl};
use linura_core::{
    Actor, ActorId, ActorKind, BootId, Capability, CapabilityId, CompositorInvocationId,
    DisplayMode, DisplayOutputId, DisplayOutputSet, DisplayScale, DisplayTopologyId,
    DisplayTransform, NativeOutputCapabilities, ProviderId, RequestId, ResourceId,
    SecurityOwnerInvocationId, SemanticReason, SessionEpoch, SupportLevel,
};
use linura_observation::{
    DISPLAY_OUTPUTS_CAPABILITY, DISPLAY_PROVIDER, ObservationAuthority, ProviderAvailability,
    ProviderHealth, display_observation_attributes,
};
use linura_observation_control::ObservationCoordinator;
use linura_provider_sdk::{Observer, ProviderError};
use std::collections::{BTreeMap, BTreeSet};

fn id<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
    value.unwrap_or_else(|e| unreachable!("{e:?}"))
}

#[derive(Clone)]
struct Fixture {
    principal: AuthenticatedPrincipal,
    desired: DisplayLayout,
    display: ObservationEnvelope,
    session: ObservationEnvelope,
    locker: ObservationEnvelope,
}

#[test]
fn own_display_discovery_preserves_native_facts_without_asserting_mutation_safety() {
    let mut f = Fixture::new();
    let lock = id(SessionLockId::from_resource(&f.locker.resource));
    // A report may explain DPMS-off state without claiming a visible recovery
    // output, safe mutation, lock coverage or successful execution.
    for index in 0..2 {
        f.display.attributes.insert(
            format!("output.{index}.powered"),
            ObservedValue::Bool(false),
        );
    }
    f.session.observed_at_unix_ms = 1100;
    f.session.valid_for_ms = 500;
    let snapshot = id(DisplayLayoutSafetyReview::own_display_snapshot(
        &f.principal,
        &lock,
        &f.display,
        &f.session,
        1200,
    ));
    assert_eq!(snapshot.observed_at_unix_ms, 1000);
    assert_eq!(snapshot.valid_for_ms, 600);
    assert!(snapshot.powered_outputs.is_empty());
    assert_eq!(snapshot.capabilities.len(), 2);
    assert_eq!(snapshot.layout.topology(), f.desired.topology());
    assert!(snapshot.validate(1600).is_err());
    assert!(
        DisplayLayoutSafetyReview::review(
            &f.principal,
            &f.desired,
            &f.display,
            &f.session,
            &f.locker,
            1200,
        )
        .is_err()
    );
}

#[test]
fn own_display_discovery_rejects_other_principals_stale_native_and_ineligible_sessions() {
    let f = Fixture::new();
    let lock = id(SessionLockId::from_resource(&f.locker.resource));
    for principal in ["unix:uid:0", "unix:uid:1001", "unix:uid:01000"] {
        let principal = id(AuthenticatedPrincipal::new(principal));
        assert!(
            DisplayLayoutSafetyReview::own_display_snapshot(
                &principal, &lock, &f.display, &f.session, 1200,
            )
            .is_err()
        );
    }
    for now in [999, 3000, u64::MAX] {
        assert!(
            DisplayLayoutSafetyReview::own_display_snapshot(
                &f.principal,
                &lock,
                &f.display,
                &f.session,
                now,
            )
            .is_err()
        );
    }
    for (key, value) in [
        ("active", ObservedValue::Bool(false)),
        ("remote", ObservedValue::Bool(true)),
        ("leader_present", ObservedValue::Bool(false)),
        ("seat", ObservedValue::Text("seat1".into())),
        ("created_monotonic_us", ObservedValue::U64(43)),
    ] {
        let mut session = f.session.clone();
        session.attributes.insert(key.into(), value);
        assert!(
            DisplayLayoutSafetyReview::own_display_snapshot(
                &f.principal,
                &lock,
                &f.display,
                &session,
                1200,
            )
            .is_err(),
            "{key}"
        );
    }
    for synthetic in [false, true] {
        let mut display = f.display.clone();
        if synthetic {
            display.authority = ObservationAuthority::SyntheticTest;
        } else {
            display
                .attributes
                .insert("unexpected".into(), ObservedValue::Bool(true));
        }
        assert!(
            DisplayLayoutSafetyReview::own_display_snapshot(
                &f.principal,
                &lock,
                &display,
                &f.session,
                1200,
            )
            .is_err()
        );
    }
    let replaced_epoch = id(SessionEpoch::new(
        lock.epoch().boot().clone(),
        1000,
        "c2",
        43,
    ));
    let replaced = id(SessionLockId::new(
        replaced_epoch,
        lock.security_owner_invocation().clone(),
        lock.generation(),
    ));
    assert!(
        DisplayLayoutSafetyReview::own_display_snapshot(
            &f.principal,
            &replaced,
            &f.display,
            &f.session,
            1200,
        )
        .is_err()
    );
}

#[test]
fn own_display_query_stops_at_unavailable_or_wrong_owner_mechanisms_without_retry() {
    let f = Fixture::new();
    let lock = id(SessionLockId::from_resource(&f.locker.resource));
    assert_eq!(
        DisplayLayoutSafetyReview::query_own_display_snapshot(
            &f.principal,
            || Err("native owner unavailable".into()),
            |_| unreachable!("a failed native query must not fan out or retry"),
        ),
        Err(DisplaySafetyError::Display)
    );
    let other = id(AuthenticatedPrincipal::new("unix:uid:1001"));
    assert_eq!(
        DisplayLayoutSafetyReview::query_own_display_snapshot(
            &other,
            || Ok((f.display.clone(), lock.clone())),
            |_| unreachable!("another login must not be queried"),
        ),
        Err(DisplaySafetyError::Session)
    );
    assert_eq!(
        DisplayLayoutSafetyReview::query_own_display_snapshot(
            &f.principal,
            || Ok((f.display.clone(), lock.clone())),
            |_| Err("native session unavailable".into()),
        ),
        Err(DisplaySafetyError::Session)
    );
}

impl Fixture {
    fn new() -> Self {
        let epoch = id(SessionEpoch::new(
            id(BootId::new("abcd1234-1234-4567-89ab-0123456789ab")),
            1000,
            "c2",
            42,
        ));
        let topology = id(DisplayTopologyId::new(
            epoch.clone(),
            "seat0",
            id(CompositorInvocationId::new(
                "98765432-1234-4567-89ab-0123456789ab",
            )),
            7,
        ));
        let one = id(DisplayOutputId::new(topology.clone(), 0, 1));
        let two = id(DisplayOutputId::new(topology.clone(), 7, 9));
        let inventory = id(DisplayOutputSet::new(
            topology.clone(),
            vec![one.clone(), two.clone()],
        ));
        let mode = id(DisplayMode::new(1920, 1080, 60000));
        let caps = vec![
            id(NativeOutputCapabilities::new(
                one.clone(),
                vec![mode],
                false,
            )),
            id(NativeOutputCapabilities::new(two.clone(), vec![mode], true)),
        ];
        let enabled = |output: DisplayOutputId, x| DisplayOutputLayout::Enabled {
            output,
            mode,
            scale: id(DisplayScale::new(1000)),
            transform: DisplayTransform::Normal,
            x,
            y: 0,
            mirror: None,
        };
        let before = id(DisplayLayout::new(
            &inventory,
            &caps,
            vec![enabled(one.clone(), 0), enabled(two.clone(), 1920)],
        ));
        let desired = id(DisplayLayout::new(
            &inventory,
            &caps,
            vec![enabled(one.clone(), -1920), enabled(two.clone(), 0)],
        ));
        let envelope = |provider, capability, resource, attributes| ObservationEnvelope {
            provider: id(ProviderId::new(provider)),
            capability: id(CapabilityId::new(capability)),
            resource,
            authority: ObservationAuthority::NativeApi,
            observed_at_unix_ms: 1000,
            valid_for_ms: 2000,
            sequence: 1,
            attributes,
        };
        let display = envelope(
            DISPLAY_PROVIDER,
            DISPLAY_OUTPUTS_CAPABILITY,
            id(topology.resource_id()),
            id(display_observation_attributes(
                &inventory,
                &caps,
                &before,
                &BTreeSet::from([one, two]),
            )),
        );
        let session = envelope(
            "logind",
            "session.epoch.observe",
            id(epoch.resource_id()),
            BTreeMap::from([
                (
                    "boot_id".into(),
                    ObservedValue::Text(epoch.boot().as_str().into()),
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
            ]),
        );
        let lock = id(SessionLockId::new(
            epoch.clone(),
            id(SecurityOwnerInvocationId::new(
                "11223344-1234-4567-89ab-0123456789ab",
            )),
            3,
        ));
        let mut lock_attributes = session.attributes.clone();
        lock_attributes.extend(BTreeMap::from([
            ("lock_generation".into(), ObservedValue::U64(3)),
            (
                "security_owner_invocation".into(),
                ObservedValue::Text(lock.security_owner_invocation().as_str().into()),
            ),
            (
                "lock_protocol".into(),
                ObservedValue::Text("ext-session-lock-v1".into()),
            ),
            ("secure".into(), ObservedValue::Bool(true)),
            (
                "display_topology".into(),
                ObservedValue::Text(id(topology.resource_id()).as_str().into()),
            ),
            (
                "observed_outputs".into(),
                ObservedValue::Text("0:1,7:9".into()),
            ),
            (
                "covered_outputs".into(),
                ObservedValue::Text("0:1,7:9".into()),
            ),
        ]));
        let locker = envelope(
            "session-locker",
            linura_observation::DISPLAY_COVERAGE_CAPABILITY,
            id(lock.resource_id()),
            lock_attributes,
        );
        Self {
            principal: id(AuthenticatedPrincipal::new("unix:uid:1000")),
            desired,
            display,
            session,
            locker,
        }
    }
    fn review(&self, now: u64) -> Result<DisplayLayoutSafetyReview, DisplaySafetyError> {
        DisplayLayoutSafetyReview::review(
            &self.principal,
            &self.desired,
            &self.display,
            &self.session,
            &self.locker,
            now,
        )
    }
    fn after(&self) -> Self {
        let mut after = self.clone();
        after.display.attributes.insert(
            "layout".into(),
            ObservedValue::Text(id(self.desired.canonical_text())),
        );
        for observation in [&mut after.display, &mut after.session, &mut after.locker] {
            observation.observed_at_unix_ms = 1300;
            observation.sequence = 2;
        }
        after
    }
    fn verify(&self, review: &DisplayLayoutSafetyReview) -> Result<(), DisplaySafetyError> {
        review.verify_postcondition(
            &self.principal,
            &self.display,
            &self.session,
            &self.locker,
            1200,
            1400,
        )
    }
}

#[test]
fn exact_safety_review_preserves_recovery_candidate_and_independent_postcondition() {
    let f = Fixture::new();
    let review = id(f.review(1100));
    assert_ne!(review.last_known_good(), review.desired_layout());
    assert_eq!(review.expires_at_unix_ms(), 3000);
    assert_eq!(f.after().verify(&review), Ok(()));
    let mut unchanged = f.after();
    unchanged.display.attributes = f.display.attributes.clone();
    assert_eq!(
        unchanged.verify(&review),
        Err(DisplaySafetyError::Postcondition)
    );
    let mut unlit = f.clone();
    for index in 0..2 {
        unlit.display.attributes.insert(
            format!("output.{index}.powered"),
            ObservedValue::Bool(false),
        );
    }
    assert_eq!(
        unlit.review(1100),
        Err(DisplaySafetyError::NoVisibleRecoveryOutput)
    );
}

#[test]
fn restart_postcondition_requires_exact_lock_layout_and_all_new_native_facts() {
    let before = Fixture::new();
    let after = before.after();
    let lock = id(SessionLockId::from_resource(&before.locker.resource));
    let verify = |f: &Fixture, lock: &SessionLockId, since| {
        DisplayLayoutSafetyReview::review_current_postcondition(
            &f.principal,
            &f.desired,
            lock,
            &f.display,
            &f.session,
            &f.locker,
            since,
            1400,
        )
    };
    assert!(verify(&after, &lock, 1200).is_ok());
    assert_eq!(
        verify(&before, &lock, 900),
        Err(DisplaySafetyError::Postcondition)
    );
    for since in [0, 1300, 1400, u64::MAX] {
        assert_eq!(
            verify(&after, &lock, since),
            Err(DisplaySafetyError::Freshness)
        );
    }
    let replaced = id(SessionLockId::new(
        lock.epoch().clone(),
        lock.security_owner_invocation().clone(),
        lock.generation() + 1,
    ));
    assert_eq!(
        verify(&after, &replaced, 1200),
        Err(DisplaySafetyError::LockCoverage)
    );
    for source in 0..3 {
        let mut mixed = after.clone();
        let sample = match source {
            0 => &mut mixed.display,
            1 => &mut mixed.session,
            _ => &mut mixed.locker,
        };
        sample.observed_at_unix_ms = 1200;
        assert_eq!(
            verify(&mixed, &lock, 1200),
            Err(DisplaySafetyError::Freshness)
        );
    }
}

#[test]
fn principal_session_seat_and_native_lock_substitutions_fail_closed() {
    let original = Fixture::new();
    for principal in [
        "unix:uid:0",
        "unix:uid:1001",
        "unix:uid:01000",
        "actor:human",
    ] {
        let mut f = original.clone();
        f.principal = id(AuthenticatedPrincipal::new(principal));
        assert_eq!(f.review(1100), Err(DisplaySafetyError::Session));
    }
    for (key, value) in [
        ("seat", ObservedValue::Text("seat1".into())),
        ("remote", ObservedValue::Bool(true)),
        ("active", ObservedValue::Bool(false)),
        ("created_monotonic_us", ObservedValue::U64(43)),
    ] {
        let mut f = original.clone();
        f.session.attributes.insert(key.into(), value);
        assert_eq!(f.review(1100), Err(DisplaySafetyError::Session));
    }
    for (key, value) in [
        (
            "display_topology",
            ObservedValue::Text("display:current".into()),
        ),
        ("observed_outputs", ObservedValue::Text("0:1".into())),
        ("covered_outputs", ObservedValue::Text("0:1,7:8".into())),
        (
            "lock_protocol",
            ObservedValue::Text("logind-locked-hint".into()),
        ),
    ] {
        let mut f = original.clone();
        f.locker.attributes.insert(key.into(), value);
        assert_eq!(f.review(1100), Err(DisplaySafetyError::LockCoverage));
    }
    for key in [
        "display_topology",
        "observed_outputs",
        "covered_outputs",
        "secure",
    ] {
        let mut f = original.clone();
        f.locker.attributes.remove(key);
        assert_eq!(f.review(1100), Err(DisplaySafetyError::LockCoverage));
    }
}

#[test]
fn newer_coverage_never_freshens_old_session_or_display_evidence() {
    let original = Fixture::new();
    for index in 0..3 {
        for kind in [
            "old",
            "missing-time",
            "future",
            "authority",
            "sequence",
            "validity",
        ] {
            let mut f = original.clone();
            let source = match index {
                0 => &mut f.display,
                1 => &mut f.session,
                _ => &mut f.locker,
            };
            match kind {
                "old" => source.observed_at_unix_ms = 1,
                "missing-time" => source.observed_at_unix_ms = 0,
                "future" => source.observed_at_unix_ms = 4000,
                "authority" => source.authority = ObservationAuthority::SyntheticTest,
                "sequence" => source.sequence = 0,
                _ => source.valid_for_ms = 2001,
            }
            assert!(f.review(2500).is_err(), "{index}:{kind}");
        }
    }
    let mut f = original;
    f.locker.observed_at_unix_ms = 2900;
    assert!(f.review(3000).is_err());
}

#[test]
fn unlocked_state_requires_exact_native_topology_and_no_forged_coverage() {
    let mut f = Fixture::new();
    f.locker
        .attributes
        .insert("secure".into(), ObservedValue::Bool(false));
    assert_eq!(f.review(1100), Err(DisplaySafetyError::LockCoverage));
    f.locker
        .attributes
        .insert("covered_outputs".into(), ObservedValue::Text(String::new()));
    assert!(f.review(1100).is_ok());
    f.locker.attributes.remove("observed_outputs");
    assert_eq!(f.review(1100), Err(DisplaySafetyError::LockCoverage));
}

#[test]
fn the_last_currently_powered_independent_output_cannot_be_disabled() {
    let mut fixture = Fixture::new();
    fixture
        .display
        .attributes
        .insert("output.0.powered".into(), ObservedValue::Bool(false));
    let facts = id(DisplayObservationFacts::from_envelope(
        &fixture.display,
        fixture.desired.topology(),
        1100,
    ));
    let outputs = vec![
        fixture.desired.outputs()[0].clone(),
        DisplayOutputLayout::Disabled {
            output: fixture.desired.outputs()[1].output().clone(),
        },
    ];
    fixture.desired = id(DisplayLayout::new(
        facts.inventory(),
        facts.capabilities(),
        outputs,
    ));
    assert_eq!(
        fixture.review(1100),
        Err(DisplaySafetyError::NoVisibleRecoveryOutput)
    );
}

#[test]
fn verification_requires_newer_independent_samples_and_original_lock_generation() {
    let original = Fixture::new();
    let review = id(original.review(1100));
    for index in 0..3 {
        for (timestamp, sequence) in [(1200, 2), (1300, 1), (1199, 2), (1300, 0)] {
            let mut f = original.after();
            let source = match index {
                0 => &mut f.display,
                1 => &mut f.session,
                _ => &mut f.locker,
            };
            source.observed_at_unix_ms = timestamp;
            source.sequence = sequence;
            assert_eq!(f.verify(&review), Err(DisplaySafetyError::Freshness));
        }
    }
    for dispatch in [0, 1099, 3000, u64::MAX] {
        let f = original.after();
        assert_eq!(
            review.verify_postcondition(
                &f.principal,
                &f.display,
                &f.session,
                &f.locker,
                dispatch,
                1400
            ),
            Err(DisplaySafetyError::Freshness)
        );
    }
    let mut f = original.after();
    let previous = id(SessionLockId::from_resource(&f.locker.resource));
    let replaced = id(SessionLockId::new(
        previous.epoch().clone(),
        previous.security_owner_invocation().clone(),
        4,
    ));
    f.locker.resource = id(replaced.resource_id());
    f.locker
        .attributes
        .insert("lock_generation".into(), ObservedValue::U64(4));
    assert_eq!(f.verify(&review), Err(DisplaySafetyError::LockCoverage));
}

#[derive(Debug)]
struct FixtureObserver(ObservationEnvelope);
impl Observer for FixtureObserver {
    fn observer_id(&self) -> ProviderId {
        self.0.provider.clone()
    }
    fn observation_capabilities(&self) -> Vec<Capability> {
        vec![Capability {
            id: self.0.capability.clone(),
            provider: Some(self.observer_id()),
            support: SupportLevel::Supported,
            reason: None,
        }]
    }
    fn health(&self) -> ProviderHealth {
        ProviderHealth {
            provider: self.observer_id(),
            availability: ProviderAvailability::Available,
            reason: None,
        }
    }
    fn resources(&self) -> Result<Vec<ResourceId>, ProviderError> {
        Ok(vec![self.0.resource.clone()])
    }
    fn observe_authoritative(
        &self,
        resource: &ResourceId,
        capability: &CapabilityId,
    ) -> Result<ObservationEnvelope, ProviderError> {
        if resource != &self.0.resource || capability != &self.0.capability {
            return Err(ProviderError::Unsupported("fixture scope".into()));
        }
        Ok(self.0.clone())
    }
}

fn actor() -> Actor {
    Actor {
        id: id(ActorId::new("actor:display-component-test")),
        kind: ActorKind::Human,
        interactive: true,
    }
}
fn request(f: &Fixture) -> DisplayLayoutPlanRequest {
    DisplayLayoutPlanRequest {
        request_id: id(RequestId::new("request:display:component-test")),
        baseline: id(DisplayObservationFacts::from_envelope(
            &f.display,
            f.desired.topology(),
            f.display.observed_at_unix_ms,
        ))
        .layout()
        .clone(),
        layout: f.desired.clone(),
        lock: id(SessionLockId::from_resource(&f.locker.resource)),
        reason: SemanticReason {
            summary: "Arrange the two displays".into(),
            intent_ids: vec![],
            requirement_ids: vec![],
            capability_ids: vec![id(CapabilityId::new(DISPLAY_OUTPUTS_CAPABILITY))],
        },
    }
}

#[test]
fn preview_uses_canonical_planner_and_coordinator_without_dispatch_authority() {
    let mut f = Fixture::new();
    let now =
        id(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)).as_millis() as u64;
    let mut coordinator = ObservationCoordinator::new();
    for source in [&mut f.display, &mut f.session, &mut f.locker] {
        source.observed_at_unix_ms = now;
        source.attributes.insert(
            "unrelated_private_diagnostic".into(),
            ObservedValue::Text("do-not-copy".into()),
        );
        if source.provider.as_str() == DISPLAY_PROVIDER {
            source.attributes.remove("unrelated_private_diagnostic");
        }
        id(coordinator.register_observer(Box::new(FixtureObserver(source.clone()))));
    }
    let mut control = PlanPreviewControl::new(coordinator);
    let plan = id(control.plan_display_layout(&f.principal, actor(), &request(&f)));
    assert_eq!(plan.status, linura_planner::PlanStatus::ChangeProposed);
    assert_eq!(plan.changes.len(), 1);
    assert_eq!(plan.changes[0].key, "layout");
    assert_eq!(plan.reason, request(&f).reason);
    assert!(
        plan.findings
            .iter()
            .any(|finding| finding.code == "display-managed-activation-unavailable")
    );
    assert!(!format!("{:?}", plan.findings).contains("do-not-copy"));
    assert_eq!(
        id(control.plan_display_layout(&f.principal, actor(), &request(&f))),
        plan
    );
    let mut rebound = request(&f);
    rebound.reason.summary = "Changed material under a retained request ID".into();
    assert!(matches!(
        control.plan_display_layout(&f.principal, actor(), &rebound),
        Err(crate::PlanPreviewControlError::IdempotencyConflict { .. })
    ));
    let mut rebound = request(&f);
    rebound.lock = id(SessionLockId::new(
        rebound.lock.epoch().clone(),
        rebound.lock.security_owner_invocation().clone(),
        rebound.lock.generation() + 1,
    ));
    assert!(matches!(
        control.plan_display_layout(&f.principal, actor(), &rebound),
        Err(crate::PlanPreviewControlError::IdempotencyConflict { .. })
    ));
    let registry = id(crate::operation_registry::trusted_builtin_operation_registry());
    let descriptor = registry
        .descriptor(&id(linura_core::OperationId::new(
            "operation:display.layout.apply",
        )))
        .unwrap_or_else(|| unreachable!("trusted display descriptor"));
    assert_eq!(
        descriptor.class(),
        linura_core::OperationClass::ManagedExternalEffect
    );
    assert_eq!(
        descriptor.risk_floor(),
        Some(linura_core::RiskClass::SecuritySensitive)
    );
    let mut unavailable = PlanPreviewControl::new(ObservationCoordinator::new());
    assert!(
        unavailable
            .plan_display_layout(&f.principal, actor(), &request(&f))
            .is_err()
    );
}
