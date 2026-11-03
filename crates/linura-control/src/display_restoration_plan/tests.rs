//! Simulated canonical NativeApi envelopes exercise Control's joins, not native
//! continuity or compositor acceptance.
use super::*;
use linura_core::{
    ActorId, ActorKind, DisplayLayout, DisplayMode, DisplayOutputId, DisplayOutputSet,
    DisplayRecoveryScope, DisplayTopologyId, NativeOutputCapabilities, ResourceId,
};
use linura_observation::{
    DisplayRecoveryMetadata, ObservationAuthority, ProviderAvailability, ProviderHealth,
    display_recovery_observation_attributes,
};
use linura_observation_control::ObservationCoordinator;
use linura_provider_sdk::{Observer, ProviderError};
use std::collections::BTreeSet;

fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| unreachable!("{error:?}"))
}
fn actor() -> Actor {
    Actor {
        id: value(ActorId::new("actor:restoration-component")),
        kind: ActorKind::Human,
        interactive: true,
    }
}
fn reason() -> SemanticReason {
    SemanticReason {
        summary: "Restore the original two-output layout after compositor loss".into(),
        intent_ids: vec![],
        requirement_ids: vec![],
        capability_ids: vec![value(CapabilityId::new(
            DISPLAY_ORIGINAL_PROTECTION_CAPABILITY,
        ))],
    }
}
fn envelope(
    provider: &str,
    capability: &str,
    resource: ResourceId,
    attributes: BTreeMap<String, ObservedValue>,
) -> ObservationEnvelope {
    ObservationEnvelope {
        provider: value(ProviderId::new(provider)),
        capability: value(CapabilityId::new(capability)),
        resource,
        authority: ObservationAuthority::NativeApi,
        observed_at_unix_ms: value(now_ms()),
        valid_for_ms: 2000,
        sequence: 1,
        attributes,
    }
}
fn native(
    topology: &DisplayTopologyId,
    handles: [(u64, u64); 2],
    positions: [i32; 2],
    identity: [&str; 2],
) -> ObservationEnvelope {
    let ids: Vec<_> = handles
        .into_iter()
        .map(|(handle, generation)| {
            value(DisplayOutputId::new(topology.clone(), handle, generation))
        })
        .collect();
    let inventory = value(DisplayOutputSet::new(topology.clone(), ids.clone()));
    let mode = value(DisplayMode::new(1920, 1080, 60000));
    let caps: Vec<_> = ids
        .iter()
        .map(|id| value(NativeOutputCapabilities::new(id.clone(), vec![mode], true)))
        .collect();
    let rows = format!(
        "LNDL:1;{};{}:{}:enabled:1920:1080:60000:1000:0:{}:0:-;{}:{}:enabled:1920:1080:60000:1000:0:{}:0:-;",
        value(topology.resource_id()).as_str(),
        ids[0].handle(),
        ids[0].generation(),
        positions[0],
        ids[1].handle(),
        ids[1].generation(),
        positions[1]
    );
    let layout = value(DisplayLayout::from_canonical_text(&inventory, &caps, &rows));
    let metadata = ids
        .iter()
        .enumerate()
        .map(|(i, id)| {
            (
                id.clone(),
                value(DisplayRecoveryMetadata::new(
                    i == 1,
                    "c".repeat(64),
                    identity[i].repeat(64),
                )),
            )
        })
        .collect();
    envelope(
        DISPLAY_PROVIDER,
        DISPLAY_OUTPUTS_CAPABILITY,
        value(topology.resource_id()),
        value(display_recovery_observation_attributes(
            &inventory,
            &caps,
            &layout,
            &ids.into_iter().collect::<BTreeSet<_>>(),
            &metadata,
        )),
    )
}
struct Fixture {
    source: OriginalDisplayPlanningContext,
    protection: DisplayOriginalProtectionFacts,
    current: ObservationEnvelope,
    lock: SessionLockId,
}
impl Fixture {
    fn new() -> Self {
        let old = value(DisplayTopologyId::from_resource(&value(ResourceId::new(
            "display:topology:11111111-1111-4111-8111-111111111111:1000:c2:42:seat0:33333333-3333-4333-8333-333333333333:8",
        ))));
        let new = value(DisplayTopologyId::from_resource(&value(ResourceId::new(
            "display:topology:11111111-1111-4111-8111-111111111111:1000:c3:99:seat0:44444444-4444-4444-8444-444444444444:1",
        ))));
        let historical_sample = native(&old, [(1, 2), (7, 9)], [0, 1920], ["a", "b"]);
        let historical = value(DisplayObservationFacts::from_envelope(
            &historical_sample,
            &old,
            value(now_ms()),
        ));
        let failed = native(&old, [(1, 2), (7, 9)], [-1920, 0], ["a", "b"]);
        let failed = value(DisplayObservationFacts::from_envelope(
            &failed,
            &old,
            value(now_ms()),
        ));
        let original_lock = value(SessionLockId::from_resource(&value(ResourceId::new(
            "session:lock:11111111-1111-4111-8111-111111111111:1000:c2:42:22222222-2222-4222-8222-222222222222:1",
        ))));
        let original = value(DisplayLayoutIntent::new(
            original_lock,
            historical.layout().clone(),
            failed.layout().clone(),
        ));
        let principal = value(AuthenticatedPrincipal::new("unix:uid:1000"));
        let original_request = PlanDesiredStateRequest {
            request_id: value(RequestId::new("request:v010:display-layout:original")),
            provider: value(ProviderId::new(DISPLAY_PROVIDER)),
            resource: value(old.resource_id()),
            observation_capability: value(CapabilityId::new(DISPLAY_OUTPUTS_CAPABILITY)),
            desired_state: BTreeMap::from([("layout".into(), value(original.canonical_text()))]),
            reason: reason(),
        };
        let transaction = linura_transaction::TransactionId::for_namespace(
            &value(PrincipalId::new(principal.as_str())),
            &original_request.request_id,
        );
        let original_guard = value(linura_provider_sdk::display_baseline_guard(&historical));
        let protection = value(DisplayOriginalProtectionFacts::new(
            value(DisplayRecoveryScope::new(&"d".repeat(64), new.clone())),
            value(original.canonical_text()),
            transaction.as_str().into(),
            "e".repeat(64),
            original_guard.to_hex(),
            "f".repeat(64),
            1,
            10,
            historical
                .recovery_metadata()
                .cloned()
                .unwrap_or_else(|| unreachable!("metadata")),
        ));
        // Replacement enumeration is deliberately reversed. Full native identity,
        // not numeric ordering or handle equality, establishes the candidate.
        let current = native(&new, [(10, 1), (20, 2)], [0, 1920], ["b", "a"]);
        let lock = value(SessionLockId::from_resource(&value(ResourceId::new(
            "session:lock:11111111-1111-4111-8111-111111111111:1000:c3:99:55555555-5555-4555-8555-555555555555:1",
        ))));
        Self {
            source: OriginalDisplayPlanningContext {
                principal,
                original_request,
                original_transaction: transaction.as_str().into(),
                original_dispatch: value(ComponentDigest::parse_hex(&"d".repeat(64))),
                original_guard,
                original_deadline_unix_ms: 10,
                historical,
            },
            protection,
            current,
            lock,
        }
    }
    fn request(&self) -> PlanDesiredStateRequest {
        let current = value(DisplayObservationFacts::from_envelope(
            &self.current,
            self.protection.scope().replacement(),
            value(now_ms()),
        ));
        value(self.source.form_request(
            value(RequestId::new("request:v010:display-restoration:recover")),
            &self.protection,
            &current,
            self.lock.clone(),
            reason(),
        ))
    }
}

#[test]
fn candidate_restores_original_baseline_with_exact_native_identity_bijection() {
    let fixture = Fixture::new();
    let request = fixture.request();
    let material = value(DisplayRestorationMaterial::decode(
        &request.desired_state["restore_original"],
    ));
    assert_eq!(
        material.original_request(),
        &fixture.source.original_request.request_id
    );
    let current = value(DisplayObservationFacts::from_envelope(
        &fixture.current,
        fixture.protection.scope().replacement(),
        value(now_ms()),
    ));
    let (_, restored) = value(material.validate_native(
        fixture.source.historical.inventory(),
        fixture.source.historical.capabilities(),
        current.inventory(),
        current.capabilities(),
    ));
    let expected = format!(
        "LNDL:1;{};10:1:enabled:1920:1080:60000:1000:0:1920:0:-;20:2:enabled:1920:1080:60000:1000:0:0:0:-;",
        value(current.inventory().topology().resource_id()).as_str()
    );
    assert_eq!(value(restored.desired().canonical_text()), expected);
    assert_ne!(restored.desired(), restored.baseline());
    assert_eq!(
        value(crate::managed_request_id("recover", &request)),
        request.request_id
    );
    assert_eq!(
        value(linura_provider_sdk::display_restoration_effect(
            &request.desired_state["restore_original"]
        ))
        .operation,
        "restore-original-display-layout"
    );
}

#[test]
fn original_history_or_native_identity_substitution_cannot_form_recovery() {
    for case in 0..9 {
        let mut fixture = Fixture::new();
        match case {
            0 => fixture.source.original_transaction = "transaction:another".into(),
            1 => {
                fixture.source.original_dispatch =
                    value(ComponentDigest::parse_hex(&"1".repeat(64)))
            }
            2 => fixture.source.original_guard = value(ComponentDigest::parse_hex(&"2".repeat(64))),
            3 => {
                fixture
                    .source
                    .original_request
                    .desired_state
                    .insert("layout".into(), "different".into());
            }
            4 => {
                fixture.current.attributes.insert(
                    "output.0.native_identity_digest".into(),
                    ObservedValue::Text("3".repeat(64)),
                );
            }
            5 => {
                fixture.current.attributes.insert(
                    "output.0.native_identity_digest".into(),
                    ObservedValue::Text("a".repeat(64)),
                );
            }
            6 => {
                fixture
                    .current
                    .attributes
                    .insert("display_schema".into(), ObservedValue::U64(1));
            }
            7 => {
                fixture.source.original_deadline_unix_ms = 11;
            }
            _ => {
                fixture
                    .current
                    .attributes
                    .remove("output.1.native_identity_digest");
            }
        }
        let result = DisplayObservationFacts::from_envelope(
            &fixture.current,
            fixture.protection.scope().replacement(),
            value(now_ms()),
        )
        .map_err(fail)
        .and_then(|current| {
            fixture.source.form_request(
                value(RequestId::new("request:v010:display-restoration:recover")),
                &fixture.protection,
                &current,
                fixture.lock,
                reason(),
            )
        });
        assert!(result.is_err(), "case {case}");
    }
}

#[test]
fn generic_preview_without_private_authenticated_history_never_probes_or_falls_back() {
    let fixture = Fixture::new();
    let mut control = PlanPreviewControl::new(ObservationCoordinator::new());
    let failure = control
        .authority_candidate(fixture.source.principal.clone(), actor(), fixture.request())
        .err()
        .unwrap_or_else(|| unreachable!("expected fail-closed rejection"));
    assert!(
        failure
            .to_string()
            .contains("requires authenticated historical context")
    );
}

#[test]
fn private_context_is_bounded_exact_principal_request_and_raii_retired() {
    let fixture = Fixture::new();
    let request = fixture.request();
    let mut control = PlanPreviewControl::new(ObservationCoordinator::new());
    let principal = fixture.source.principal.clone();
    let context = value(control.enter_original_display_context(fixture.source, &request));
    assert!(
        control
            .enter_original_display_context(Fixture::new().source, &request)
            .is_err()
    );
    let mut other = request.clone();
    other.reason.summary.push('!');
    for (principal, request) in [
        (principal.clone(), other),
        (
            value(AuthenticatedPrincipal::new("unix:uid:1001")),
            request.clone(),
        ),
    ] {
        assert!(
            control
                .authority_candidate(principal, actor(), request)
                .err()
                .unwrap_or_else(|| unreachable!("expected fail-closed rejection"))
                .to_string()
                .contains("another exact principal/request")
        );
    }
    drop(context);
    assert!(
        control
            .authority_candidate(principal, actor(), request.clone())
            .err()
            .unwrap_or_else(|| unreachable!("expected fail-closed rejection"))
            .to_string()
            .contains("requires authenticated historical context")
    );
    assert!(
        control
            .enter_original_display_context(Fixture::new().source, &request)
            .is_ok()
    );
}

#[derive(Debug)]
struct FixtureObserver(ObservationEnvelope);
impl Observer for FixtureObserver {
    fn observer_id(&self) -> ProviderId {
        self.0.provider.clone()
    }
    fn observation_capabilities(&self) -> Vec<linura_core::Capability> {
        vec![linura_core::Capability {
            id: self.0.capability.clone(),
            provider: Some(self.observer_id()),
            support: linura_core::SupportLevel::Supported,
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
            return Err(ProviderError::Unsupported("fixture exact scope".into()));
        }
        Ok(self.0.clone())
    }
}
impl Fixture {
    fn sources(&self) -> Vec<ObservationEnvelope> {
        let epoch = self.lock.epoch();
        let session = envelope(
            "logind",
            "session.epoch.observe",
            value(epoch.resource_id()),
            BTreeMap::from([
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
                ("session_type".into(), ObservedValue::Text("wayland".into())),
                ("session_class".into(), ObservedValue::Text("user".into())),
                ("state".into(), ObservedValue::Text("active".into())),
                ("seat".into(), ObservedValue::Text("seat0".into())),
                ("active".into(), ObservedValue::Bool(true)),
                ("remote".into(), ObservedValue::Bool(false)),
                ("leader_present".into(), ObservedValue::Bool(true)),
            ]),
        );
        let mut attrs = session.attributes.clone();
        attrs.extend(BTreeMap::from([
            (
                "lock_generation".into(),
                ObservedValue::U64(self.lock.generation()),
            ),
            (
                "security_owner_invocation".into(),
                ObservedValue::Text(self.lock.security_owner_invocation().as_str().into()),
            ),
            (
                "lock_protocol".into(),
                ObservedValue::Text("ext-session-lock-v1".into()),
            ),
            ("secure".into(), ObservedValue::Bool(false)),
            (
                "display_topology".into(),
                ObservedValue::Text(
                    value(self.protection.scope().replacement().resource_id())
                        .as_str()
                        .into(),
                ),
            ),
            (
                "observed_outputs".into(),
                ObservedValue::Text("10:1,20:2".into()),
            ),
            ("covered_outputs".into(), ObservedValue::Text(String::new())),
        ]));
        vec![
            envelope(
                DISPLAY_RECOVERY_PROVIDER,
                DISPLAY_ORIGINAL_PROTECTION_CAPABILITY,
                value(self.protection.scope().resource_id()),
                self.protection.attributes(),
            ),
            self.current.clone(),
            session,
            envelope(
                "session-locker",
                DISPLAY_COVERAGE_CAPABILITY,
                value(self.lock.resource_id()),
                attrs,
            ),
        ]
    }
}
fn coordinator(sources: Vec<ObservationEnvelope>) -> ObservationCoordinator {
    let mut coordinator = ObservationCoordinator::new();
    for source in sources {
        value(coordinator.register_observer(Box::new(FixtureObserver(source))));
    }
    coordinator
}

#[test]
fn canonical_review_joins_all_four_fresh_sources_without_refreshing_original_clocks() {
    let fixture = Fixture::new();
    let request = fixture.request();
    let principal = fixture.source.principal.clone();
    let mut control = PlanPreviewControl::new(coordinator(fixture.sources()));
    let _context = value(control.enter_original_display_context(fixture.source, &request));
    let (plan, observed) = value(control.authority_candidate(principal, actor(), request));
    assert_eq!(plan.status, linura_planner::PlanStatus::ChangeProposed);
    assert_eq!(plan.changes.len(), 1);
    assert_eq!(plan.changes[0].key, "restore_original");
    assert_eq!(
        observed.attributes["original_confirmation_deadline_unix_ms"],
        ObservedValue::U64(10)
    );
    assert_eq!(
        observed.attributes["original_sampled_boot_ms"],
        ObservedValue::U64(1)
    );
    for key in [
        "control.replacement_display_digest",
        "control.replacement_session_digest",
        "control.replacement_coverage_digest",
    ] {
        assert!(observed.attributes.contains_key(key));
    }
    assert_eq!(
        plan.findings
            .iter()
            .filter(|f| f.code.starts_with("native-display-"))
            .count(),
        4
    );
    let registry = value(crate::operation_registry::trusted_builtin_operation_registry());
    let operation = value(linura_core::OperationId::new(
        crate::operation_registry::MANAGED_DISPLAY_RESTORATION_OPERATION_ID,
    ));
    let semantics = value(
        crate::OperationSemanticsControl::from_trusted_registry(registry)
            .resolve_external(&operation, &plan),
    );
    assert!(semantics.requires_durable_managed_lifecycle());
    assert!(semantics.permits_privileged_executor());
    assert_eq!(semantics.risk(), linura_core::RiskClass::SecuritySensitive);
    for case in 0..5 {
        let mut changed = plan.clone();
        match case {
            0 => changed.provider = value(ProviderId::new(DISPLAY_PROVIDER)),
            1 => {
                changed.observation_capability =
                    value(CapabilityId::new(DISPLAY_OUTPUTS_CAPABILITY))
            }
            2 => changed.resource = value(ResourceId::new("display:recovery:current")),
            3 => changed.changes[0].key = "layout".into(),
            _ => changed.changes.push(changed.changes[0].clone()),
        }
        let registry = value(crate::operation_registry::trusted_builtin_operation_registry());
        assert!(
            crate::OperationSemanticsControl::from_trusted_registry(registry)
                .resolve_external(&operation, &changed)
                .is_err(),
            "case {case}"
        );
    }
}

#[test]
fn restoration_preserves_original_semantic_origins_under_a_new_human_reason() {
    let mut fixture = Fixture::new();
    let origin = value(linura_core::IntentId::new("intent:original-display-owner"));
    fixture
        .source
        .original_request
        .reason
        .intent_ids
        .push(origin.clone());
    assert!(fixture.request().reason.intent_ids.contains(&origin));
}

#[test]
fn any_stale_contributor_or_equal_geometry_native_rule_drift_refuses_review() {
    for case in 0..5 {
        let fixture = Fixture::new();
        let request = fixture.request();
        let principal = fixture.source.principal.clone();
        let mut sources = fixture.sources();
        if case < 4 {
            sources[case].observed_at_unix_ms = value(now_ms()) - 2001;
        } else {
            sources[1].attributes.insert(
                "output.0.base_configuration_digest".into(),
                ObservedValue::Text("4".repeat(64)),
            );
        }
        let mut control = PlanPreviewControl::new(coordinator(sources));
        let _context = value(control.enter_original_display_context(fixture.source, &request));
        assert!(
            control
                .authority_candidate(principal, actor(), request)
                .is_err(),
            "case {case}"
        );
    }
}
