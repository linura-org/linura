//! Real Control/SQLite with simulated native sources; no physical qualification.
use super::*;
#[derive(Debug)]
pub(super) struct OriginalObserver(pub(super) Arc<Mutex<Machine>>);
impl Observer for OriginalObserver {
    fn observer_id(&self) -> ProviderId {
        value(ProviderId::new(
            linura_observation::DISPLAY_RECOVERY_PROVIDER,
        ))
    }
    fn observation_capabilities(&self) -> Vec<Capability> {
        vec![Capability {
            id: value(CapabilityId::new(
                linura_observation::DISPLAY_ORDINARY_ORIGINAL_CAPABILITY,
            )),
            provider: Some(self.observer_id()),
            support: SupportLevel::Supported,
            reason: None,
        }]
    }
    fn requires_live_health_preflight(&self) -> bool {
        false
    }
    fn health(&self) -> ProviderHealth {
        ProviderHealth {
            provider: self.observer_id(),
            availability: ProviderAvailability::Available,
            reason: None,
        }
    }
    fn resources(&self) -> Result<Vec<ResourceId>, ProviderError> {
        Err(ProviderError::Unsupported(
            "exact original scope required".into(),
        ))
    }
    fn observe_authoritative(
        &self,
        resource: &ResourceId,
        capability: &CapabilityId,
    ) -> Result<ObservationEnvelope, ProviderError> {
        if capability.as_str() != linura_observation::DISPLAY_ORDINARY_ORIGINAL_CAPABILITY {
            return Err(ProviderError::Unsupported("ordinary source only".into()));
        }
        let scope = linura_core::DisplayOrdinaryReleaseScope::from_resource(resource)
            .map_err(|e| ProviderError::InvalidState(e.to_string()))?;
        let mut m = self
            .0
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        m.ordinary_root_reads += 1;
        if m.ordinary_root_fault == 1 {
            return Err(ProviderError::Unavailable(
                "simulated original witness lost".into(),
            ));
        }
        let binding = m
            .binding
            .as_ref()
            .ok_or_else(|| ProviderError::Unavailable("original absent".into()))?;
        if scope.original_dispatch() != binding.dispatch_digest.to_hex()
            || scope.topology() != layouts().0.topology()
        {
            return Err(ProviderError::Unavailable("scope differs".into()));
        }
        let facts = value(linura_observation::DisplayOrdinaryOriginalFacts::new(
            scope,
            linura_observation::DisplayOrdinaryOriginalComparison {
                material: display_request("original-observer-fixture").desired_state["layout"]
                    .clone(),
                transaction: binding.transaction_id.clone(),
                checkpoint: "4".repeat(64),
                native_guard: m
                    .original_native_guard
                    .ok_or_else(|| ProviderError::Unavailable("no native baseline".into()))?
                    .to_hex(),
                integration: "5".repeat(64),
                sampled_boot_ms: 100,
                original_deadline_unix_ms: m.deadline,
            },
        ));
        m.sequence += 1;
        let mut sample = ObservationEnvelope {
            provider: self.observer_id(),
            capability: capability.clone(),
            resource: resource.clone(),
            authority: ObservationAuthority::NativeApi,
            sequence: m.sequence,
            observed_at_unix_ms: now_unix_ms(),
            valid_for_ms: 2000,
            attributes: facts.attributes(),
        };
        match m.ordinary_root_fault {
            2 => sample.authority = ObservationAuthority::SyntheticTest,
            3 => sample.observed_at_unix_ms -= 2001,
            4 => {
                sample
                    .attributes
                    .insert("native_guard".into(), ObservedValue::Text("9".repeat(64)));
            }
            5 => {
                sample.attributes.insert(
                    "original_transaction".into(),
                    ObservedValue::Text("transaction:foreign".into()),
                );
            }
            6 => {
                sample.attributes.insert(
                    "original_material".into(),
                    ObservedValue::Text(facts.comparison().material.replace(
                        "11223344-1234-4567-89ab-0123456789ab",
                        "22223344-1234-4567-89ab-0123456789ab",
                    )),
                );
            }
            7 if m.ordinary_root_reads == 2 => {
                sample.attributes.insert(
                    "checkpoint_digest".into(),
                    ObservedValue::Text("9".repeat(64)),
                );
            }
            8 => {
                sample
                    .attributes
                    .insert("root_power_held".into(), ObservedValue::Bool(false));
            }
            9 => {
                sample.attributes.insert(
                    "original_deadline_unix_ms".into(),
                    ObservedValue::U64(m.deadline + 1),
                );
            }
            10 => {
                sample
                    .attributes
                    .insert("grant_spent".into(), ObservedValue::Bool(true));
            }
            _ => (),
        }
        Ok(sample)
    }
}
pub(super) fn original_source_and_terminal_inspection_are_read_only_across_restart() {
    for action in [
        DisplayContinuationAction::Confirm,
        DisplayContinuationAction::Revert,
    ] {
        for fault in 0..=11 {
            let database = TestDatabase::new();
            let machine = Arc::new(Mutex::new(Machine::default()));
            let mut control =
                open_with_previews(database.path(), &machine, 0, previews_inner(&machine, true));
            let mut port = Port(machine.clone());
            let mut verifier = Verifier(machine.clone());
            let request = display_request("ordinary-release-original");
            value(control.begin_display_layout(
                principal(),
                actor(true),
                request.clone(),
                &approval(),
                &mut port,
                &mut verifier,
            ));
            assert!(
                control
                    .inspect_ordinary_display_original(
                        principal(),
                        &request.request_id,
                        &mut port,
                        &mut verifier
                    )
                    .is_err()
            );
            assert_eq!(
                machine
                    .lock()
                    .unwrap_or_else(|_| unreachable!())
                    .ordinary_root_reads,
                0
            );
            value(control.decide_display_layout(
                principal(),
                actor(true),
                &request.request_id,
                action,
                &Decision::approve(&machine),
                &mut port,
                &mut verifier,
            ));
            drop(control);
            let mut restarted =
                open_with_previews(database.path(), &machine, 0, previews_inner(&machine, true));
            assert!(
                restarted
                    .inspect_ordinary_display_original(
                        value(AuthenticatedPrincipal::new("unix:uid:1001")),
                        &request.request_id,
                        &mut port,
                        &mut verifier
                    )
                    .is_err()
            );
            assert_eq!(
                machine
                    .lock()
                    .unwrap_or_else(|_| unreachable!())
                    .ordinary_root_reads,
                0
            );
            {
                let mut m = machine.lock().unwrap_or_else(|_| unreachable!());
                m.ordinary_root_fault = fault;
                m.ordinary_checkpoint_unavailable = fault == 11;
            }
            let report = restarted.inspect_ordinary_display_original(
                principal(),
                &request.request_id,
                &mut port,
                &mut verifier,
            );
            assert_eq!(
                report.is_ok(),
                fault == 0,
                "{action:?} fault {fault}: {report:?}"
            );
            {
                let mut m = machine.lock().unwrap_or_else(|_| unreachable!());
                m.ordinary_root_fault = 0;
                m.ordinary_checkpoint_unavailable = false;
                m.ordinary_root_reads = 0;
            }
            let report = value(restarted.inspect_ordinary_display_original(
                principal(),
                &request.request_id,
                &mut port,
                &mut verifier,
            ));
            assert_eq!(report.request(), &request);
            assert_eq!(
                report.eligibility().restored(),
                action == DisplayContinuationAction::Revert
            );
            assert_eq!(report.root().comparison().checkpoint, "4".repeat(64));
            assert_eq!(
                report.root().comparison().transaction,
                report.original_snapshot().transaction_id.as_str()
            );
            assert!(report.observation().require_current(now_unix_ms()).is_ok());
            assert!(
                report.observation().observed_at_unix_ms + report.observation().valid_for_ms
                    <= report.eligibility().expires_at_unix_ms()
            );
            if fault == 0 {
                let input = linura_control::OrdinaryDisplayReleaseRequest {
                    operation_id: "ordinary-release-review".into(),
                    original_request: request.request_id.clone(),
                    reason: SemanticReason {
                        summary: "Release the separately reviewed terminal protection".into(),
                        intent_ids: vec![],
                        requirement_ids: vec![],
                        capability_ids: vec![],
                    },
                };
                assert!(
                    restarted
                        .plan_ordinary_display_release(
                            principal(),
                            actor(false),
                            input.clone(),
                            &mut port,
                            &mut verifier
                        )
                        .is_err()
                );
                let plan = value(restarted.plan_ordinary_display_release(
                    principal(),
                    actor(true),
                    input.clone(),
                    &mut port,
                    &mut verifier,
                ));
                assert_eq!(plan.status.as_str(), "change-proposed");
                assert!(!plan.execution_authorized());
                assert_eq!(plan.changes.len(), 1);
                assert_eq!(plan.changes[0].key, "release_ordinary");
                assert!(plan.changes[0].desired.starts_with("LNOR-SHA256:1:"));
                assert!(
                    plan.reason
                        .intent_ids
                        .contains(&request.reason.intent_ids[0])
                );
                let generic = PlanDesiredStateRequest {
                    request_id: plan.request_id.clone(),
                    provider: plan.provider.clone(),
                    resource: plan.resource.clone(),
                    observation_capability: plan.observation_capability.clone(),
                    desired_state: BTreeMap::from([(
                        "release_ordinary".into(),
                        plan.changes[0].desired.clone(),
                    )]),
                    reason: plan.reason.clone(),
                };
                let mut unbound = previews_inner(&machine, true);
                let reads = machine
                    .lock()
                    .unwrap_or_else(|_| unreachable!())
                    .ordinary_root_reads;
                assert!(
                    unbound
                        .plan_desired_state(principal(), actor(true), generic)
                        .is_err()
                );
                assert_eq!(
                    machine
                        .lock()
                        .unwrap_or_else(|_| unreachable!())
                        .ordinary_root_reads,
                    reads
                );
                machine
                    .lock()
                    .unwrap_or_else(|_| unreachable!())
                    .native_base_drift = true;
                assert!(
                    restarted
                        .plan_ordinary_display_release(
                            principal(),
                            actor(true),
                            input.clone(),
                            &mut port,
                            &mut verifier
                        )
                        .is_err()
                );
                machine
                    .lock()
                    .unwrap_or_else(|_| unreachable!())
                    .native_base_drift = false;
                value(restarted.plan_ordinary_display_release(
                    principal(),
                    actor(true),
                    input,
                    &mut port,
                    &mut verifier,
                ));
            }
            let m = machine.lock().unwrap_or_else(|_| unreachable!());
            assert_eq!(m.applies, 1);
            assert_eq!(m.decisions, 1);
        }
    }
}
