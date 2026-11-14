//! Real Control/SQLite with simulated native sources; no physical qualification.
use super::*;

// Explicitly simulated Root/native first-frame sources. They exercise the
// real Control join and SQLite restart, never physical compositor qualification.
pub(super) fn observe_handoff(
    m: &mut Machine,
    resource: &ResourceId,
    capability: &CapabilityId,
) -> Result<ObservationEnvelope, ProviderError> {
    assert_eq!(
        m.checked_history_reads, 0,
        "history snapshot crossed handoff observation"
    );
    use linura_observation::{
        DISPLAY_ORDINARY_HANDOFF_CAPABILITY, DISPLAY_ORDINARY_RELEASE_CAPABILITY, DISPLAY_PROVIDER,
        DISPLAY_RECOVERY_PROVIDER, DisplayNativeHandoffOutput, DisplayNativeHandoffWindow,
        DisplayOrdinaryHandoffFacts, DisplayOrdinaryHandoffLineage,
        DisplayOrdinaryReleaseComparison, DisplayOrdinaryReleaseFacts,
    };
    let fail = || ProviderError::Unavailable("simulated ordinary handoff unavailable".into());
    let record = linura_linux_session::NativeDisplayOrdinaryReleasePreparation::decode(
        m.ordinary_release_record.as_ref().ok_or_else(fail)?,
    )
    .map_err(|_| fail())?;
    let material = record.decoded_material().map_err(|_| fail())?;
    let scope = material.release_scope().map_err(|_| fail())?;
    if scope.resource_id().map_err(|_| fail())? != *resource {
        return Err(fail());
    }
    let wall = now_unix_ms();
    let sampled_boot_ms =
        record.window().observed_boot_ms + wall.saturating_sub(record.window().observed_unix_ms);
    let window = DisplayNativeHandoffWindow {
        observed_unix_ms: wall,
        observed_boot_ms: sampled_boot_ms,
        ..record.window()
    };
    m.sequence += 1;
    let root = capability.as_str() == DISPLAY_ORDINARY_RELEASE_CAPABILITY;
    if !root && capability.as_str() != DISPLAY_ORDINARY_HANDOFF_CAPABILITY {
        return Err(fail());
    }
    let attributes = if root {
        DisplayOrdinaryReleaseFacts::new(
            scope.clone(),
            DisplayOrdinaryReleaseComparison {
                material: record.material().into(),
                transaction: record.binding().transaction_id.clone(),
                effect: record.binding().effect_digest.to_hex(),
                dispatch: record.binding().dispatch_digest.to_hex(),
                preparation_digest: record.record_digest().to_hex(),
                spent: true,
                producer: record.window(),
                sampled_boot_ms,
            },
        )
        .map_err(|_| fail())?
        .attributes()
    } else {
        if m.ordinary_handoff_fault == 1 {
            return Err(fail());
        } // Root spend alone is not a frame
        m.ordinary_handoff_reads += 1;
        let original = m.binding.as_ref().ok_or_else(fail)?;
        let layout = if material.outcome() == linura_core::DisplayOrdinaryReleaseOutcome::Keep {
            layouts().1
        } else {
            layouts().0
        };
        DisplayOrdinaryHandoffFacts::new(
            scope,
            DisplayOrdinaryHandoffLineage {
                original_transaction: original.transaction_id.clone(),
                original_effect: original.effect_digest.to_hex(),
                release_transaction: record.binding().transaction_id.clone(),
                release_effect: record.binding().effect_digest.to_hex(),
                release_dispatch: record.binding().dispatch_digest.to_hex(),
                preparation_digest: record.record_digest().to_hex(),
                terminal_record: material.lineage().terminal_record.into(),
                checkpoint: material.lineage().original_checkpoint.into(),
                signed_binding: material.lineage().signed_binding.into(),
                source_guard: material.lineage().current_source_guard.into(),
                outcome: material.outcome().as_str().into(),
                post_write_epoch: 1,
                security_epoch: 4,
            },
            window,
            layout
                .outputs()
                .iter()
                .map(|row| {
                    (
                        row.output().clone(),
                        DisplayNativeHandoffOutput {
                            enabled: matches!(row, DisplayOutputLayout::Enabled { .. }),
                            connector: 5,
                            crtc: 6,
                            plane: 7,
                            framebuffer: 8,
                            spend_high_water: 90,
                            completed_commit: 91,
                        },
                    )
                })
                .collect(),
        )
        .map_err(|_| fail())?
        .attributes()
    };
    let mut sample = ObservationEnvelope {
        provider: value(ProviderId::new(if root {
            DISPLAY_RECOVERY_PROVIDER
        } else {
            DISPLAY_PROVIDER
        })),
        capability: capability.clone(),
        resource: resource.clone(),
        authority: ObservationAuthority::NativeApi,
        observed_at_unix_ms: wall,
        valid_for_ms: window.valid_for_ms().map_err(|_| fail())?,
        sequence: m.sequence,
        attributes,
    };
    let fault = m.ordinary_handoff_fault;
    let substituted = if root {
        match fault {
            2 => Some(("spent", ObservedValue::Bool(false))),
            3 => Some(("preparation_digest", ObservedValue::Text("9".repeat(64)))),
            4 => Some((
                "transaction",
                ObservedValue::Text("transaction:foreign".into()),
            )),
            _ => None,
        }
    } else {
        match fault {
            5 => Some((
                "original_transaction",
                ObservedValue::Text("transaction:foreign".into()),
            )),
            6 => Some(("signed_binding", ObservedValue::Text("9".repeat(64)))),
            7 => Some(("source_guard", ObservedValue::Text("9".repeat(64)))),
            8 => Some(("output.0.completed_commit", ObservedValue::U64(90))),
            9 => Some(("output.0.framebuffer", ObservedValue::U64(0))),
            10 => Some(("deadline_boot_ms", ObservedValue::U64(102_000))),
            11 => {
                sample.authority = ObservationAuthority::SyntheticTest;
                None
            }
            12 if m.ordinary_handoff_reads == 2 => {
                Some(("output.0.completed_commit", ObservedValue::U64(92)))
            }
            13 => Some(("outcome", ObservedValue::Text("expired".into()))),
            14 => Some(("output.0.completed_commit", ObservedValue::U64(92))),
            _ => None,
        }
    };
    if let Some((key, value)) = substituted {
        sample.attributes.insert(key.into(), value);
    }
    Ok(sample)
}

#[test]
fn ordinary_handoff_joins_actual_sources_without_replaying_lost_ack_or_committing_on_inspection() {
    ordinary_final_retirement_requires_matching_physical_and_durable_completion();
    ordinary_current_commit_requires_independent_native_qualification();
    let mut cases = vec![
        (DisplayContinuationAction::Confirm, None, 0),
        (DisplayContinuationAction::Revert, None, 0),
        (DisplayContinuationAction::Confirm, Some(0), 0),
        (DisplayContinuationAction::Confirm, Some(1), 0),
        (DisplayContinuationAction::Confirm, Some(2), 0),
    ];
    // Every source substitution gets its own original producer window. A
    // failure after another fault consumed that window proves only expiry,
    // not rejection of the intended substitution.
    for action in [
        DisplayContinuationAction::Confirm,
        DisplayContinuationAction::Revert,
    ] {
        cases.extend((1..=14).map(|fault| (action, None, fault)));
    }
    for (action, storage_fault, source_fault) in cases {
        let database = TestDatabase::new();
        let machine = Arc::new(Mutex::new(Machine::default()));
        let mut port = Port(machine.clone());
        let mut verifier = Verifier(machine.clone());
        let original = display_request("ordinary-handoff-original");
        let mut control =
            open_with_previews(database.path(), &machine, 0, previews_inner(&machine, true));
        value(control.begin_display_layout(
            principal(),
            actor(true),
            original.clone(),
            &approval(),
            &mut port,
            &mut verifier,
        ));
        value(control.decide_display_layout(
            principal(),
            actor(true),
            &original.request_id,
            action,
            &Decision::approve(&machine),
            &mut port,
            &mut verifier,
        ));
        let before = value(control.inspect_ordinary_display_original(
            principal(),
            &original.request_id,
            &mut port,
            &mut verifier,
        ))
        .original_snapshot()
        .clone();
        machine
            .lock()
            .unwrap_or_else(|_| unreachable!())
            .ordinary_handoff_enabled = true;
        let mut release_port = ReleasePort(machine.clone(), 1); // durable native spend, missing reply
        let receipt = value(control.begin_ordinary_display_release(
            principal(),
            actor(true),
            linura_control::OrdinaryDisplayReleaseRequest {
                operation_id: "ordinary-handoff-release".into(),
                original_request: original.request_id.clone(),
                reason: original.reason.clone(),
            },
            &ReleaseApproval(machine.clone(), 0),
            &mut port,
            &mut verifier,
            &mut release_port,
        ));
        if (1..=13).contains(&source_fault) {
            {
                let mut m = machine.lock().unwrap_or_else(|_| unreachable!());
                m.ordinary_handoff_fault = source_fault;
                m.ordinary_handoff_reads = 0;
            }
            assert!(
                control
                    .inspect_ordinary_display_handoff(
                        principal(),
                        &receipt.request_id,
                        &mut port,
                        &mut verifier,
                    )
                    .is_err(),
                "source fault {source_fault}"
            );
        } else {
            if let Some(fault) = storage_fault {
                drop(control);
                machine
                    .lock()
                    .unwrap_or_else(|_| unreachable!())
                    .ordinary_release_write_fault = fault;
                control = open_with_previews(
                    database.path(),
                    &machine,
                    1,
                    previews_inner(&machine, true),
                );
                // Before-write failure, false ACK, and durable write with lost
                // ACK cannot manufacture a successful verification response.
                assert!(
                    control
                        .verify_ordinary_display_handoff(
                            principal(),
                            &receipt.request_id,
                            &mut port,
                            &mut verifier,
                        )
                        .is_err()
                );
                drop(control);
                machine
                    .lock()
                    .unwrap_or_else(|_| unreachable!())
                    .ordinary_release_write_fault = 0;
                control = open_with_previews(
                    database.path(),
                    &machine,
                    0,
                    previews_inner(&machine, true),
                );
            }
            let proof = value(control.verify_ordinary_display_handoff(
                principal(),
                &receipt.request_id,
                &mut port,
                &mut verifier,
            ));
            let inspection = proof.inspection();
            assert_eq!(
                inspection.release().state,
                linura_transaction::TransactionState::Indeterminate
            );
            assert!(inspection.root().matches_native(inspection.frames()));
            assert!(
                inspection
                    .observation()
                    .attributes
                    .contains_key("control.ordinary-handoff.coverage_digest")
            );
            assert!(proof.first_verified_unix_ms() < proof.first_valid_until_unix_ms());
            drop(control);
            control =
                open_with_previews(database.path(), &machine, 0, previews_inner(&machine, true));
            if source_fault == 14 {
                machine
                    .lock()
                    .unwrap_or_else(|_| unreachable!())
                    .ordinary_handoff_fault = 14;
                // Two mutually consistent fresh reads cannot replace the first
                // durably verified frame with a later commit after restart.
                assert!(
                    control
                        .inspect_ordinary_display_handoff(
                            principal(),
                            &receipt.request_id,
                            &mut port,
                            &mut verifier,
                        )
                        .is_ok()
                );
                assert!(
                    control
                        .verify_ordinary_display_handoff(
                            principal(),
                            &receipt.request_id,
                            &mut port,
                            &mut verifier,
                        )
                        .is_err()
                );
            } else {
                let recovered = value(control.verify_ordinary_display_handoff(
                    principal(),
                    &receipt.request_id,
                    &mut port,
                    &mut verifier,
                ));
                assert_eq!(recovered.inspection().release(), inspection.release());
                assert!(
                    recovered
                        .inspection()
                        .frames()
                        .reconciles(inspection.frames())
                );
                assert_eq!(recovered.record_digest(), proof.record_digest());
                assert_eq!(
                    recovered.first_verified_unix_ms(),
                    proof.first_verified_unix_ms()
                );
                assert_eq!(
                    recovered.first_valid_until_unix_ms(),
                    proof.first_valid_until_unix_ms()
                );
            }
        }
        {
            let mut m = machine.lock().unwrap_or_else(|_| unreachable!());
            let preparation = value(
                linura_linux_session::NativeDisplayOrdinaryReleasePreparation::decode(
                    m.ordinary_release_record
                        .as_ref()
                        .unwrap_or_else(|| unreachable!()),
                ),
            );
            // Negative cases must reject their intended fault while the
            // ORIGINAL producer is still live. Do not extend or resample it.
            assert!(
                now_unix_ms() < preparation.window().deadline_unix_ms,
                "case {action:?}/{storage_fault:?}/{source_fault} consumed the original producer window"
            );
            m.ordinary_handoff_fault = 0;
        }
        assert_eq!(
            value(control.inspect_ordinary_display_original(
                principal(),
                &original.request_id,
                &mut port,
                &mut verifier
            ))
            .original_snapshot(),
            &before
        );
        let m = machine.lock().unwrap_or_else(|_| unreachable!());
        assert_eq!(
            (
                m.applies,
                m.decisions,
                m.ordinary_release_calls,
                m.ordinary_release_approvals
            ),
            (1, 1, 1, 1)
        );
    }
    ordinary_completion_requires_original_review_and_cannot_replay();
    ordinary_power_requires_original_review_and_independent_physical_postconditions();
    ordinary_root_power_requires_same_review_and_independent_absence();
}
#[derive(Debug)]
pub(super) struct OriginalObserver(pub(super) Arc<Mutex<Machine>>);
impl Observer for OriginalObserver {
    fn observer_id(&self) -> ProviderId {
        value(ProviderId::new(
            linura_observation::DISPLAY_RECOVERY_PROVIDER,
        ))
    }
    fn observation_capabilities(&self) -> Vec<Capability> {
        [
            linura_observation::DISPLAY_ORDINARY_ORIGINAL_CAPABILITY,
            linura_observation::DISPLAY_ORDINARY_RELEASE_CAPABILITY,
            linura_observation::DISPLAY_ORDINARY_COMPLETION_CAPABILITY,
            linura_observation::DISPLAY_ORDINARY_POWER_RETIREMENT_CAPABILITY,
            linura_observation::DISPLAY_ORDINARY_FINAL_RETIREMENT_CAPABILITY,
            linura_observation::DISPLAY_ORDINARY_ROOT_RETIREMENT_CAPABILITY,
        ]
        .into_iter()
        .map(|id| Capability {
            id: value(CapabilityId::new(id)),
            provider: Some(self.observer_id()),
            support: SupportLevel::Supported,
            reason: None,
        })
        .collect()
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
        assert_eq!(
            self.0
                .lock()
                .unwrap_or_else(|_| unreachable!())
                .checked_history_reads,
            0,
            "history snapshot crossed Root observation"
        );
        if capability.as_str() == linura_observation::DISPLAY_ORDINARY_FINAL_RETIREMENT_CAPABILITY {
            return observe_final(
                &mut self.0.lock().unwrap_or_else(|_| unreachable!()),
                resource,
                capability,
            );
        }
        if capability.as_str() == linura_observation::DISPLAY_ORDINARY_ROOT_RETIREMENT_CAPABILITY {
            return observe_root_power(
                &mut self.0.lock().unwrap_or_else(|_| unreachable!()),
                resource,
                capability,
            );
        }
        if capability.as_str() == linura_observation::DISPLAY_ORDINARY_POWER_RETIREMENT_CAPABILITY {
            return observe_power(
                &mut self.0.lock().unwrap_or_else(|_| unreachable!()),
                resource,
                capability,
            );
        }
        if capability.as_str() == linura_observation::DISPLAY_ORDINARY_COMPLETION_CAPABILITY {
            return observe_current(
                &mut self.0.lock().unwrap_or_else(|_| unreachable!()),
                resource,
                capability,
            );
        }
        if capability.as_str() == linura_observation::DISPLAY_ORDINARY_RELEASE_CAPABILITY {
            return observe_handoff(
                &mut self.0.lock().unwrap_or_else(|_| unreachable!()),
                resource,
                capability,
            );
        }
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
        if m.ordinary_root_fault == 1 || m.ordinary_root_power_retired {
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

pub(super) fn early_automatic_restoration_is_not_expiry_release_authority() {
    let database = TestDatabase::new();
    let machine = Arc::new(Mutex::new(Machine::default()));
    let mut port = Port(machine.clone());
    let mut verifier = Verifier(machine.clone());
    let original = display_request("ordinary-release-automatic-restoration");
    let mut control =
        open_with_previews(database.path(), &machine, 0, previews_inner(&machine, true));
    value(control.begin_display_layout(
        principal(),
        actor(true),
        original.clone(),
        &approval(),
        &mut port,
        &mut verifier,
    ));
    let deadline = {
        let mut m = machine.lock().unwrap_or_else(|_| unreachable!());
        m.state = Some("restored");
        m.desired = false;
        m.deadline
    };
    let status = value(control.display_layout_status(
        principal(),
        actor(true),
        &original.request_id,
        &mut port,
        &mut verifier,
    ));
    assert_eq!(status.state, DisplayLayoutState::Restored);
    let input = linura_control::OrdinaryDisplayReleaseRequest {
        operation_id: "ordinary-release-after-timer".into(),
        original_request: original.request_id.clone(),
        reason: original.reason.clone(),
    };
    let before = value(control.inspect_ordinary_display_original(
        principal(),
        &original.request_id,
        &mut port,
        &mut verifier,
    ))
    .original_snapshot()
    .clone();
    assert!(
        now_unix_ms() < deadline,
        "fixture must exercise early restoration before its original timer"
    );
    assert!(
        control
            .plan_ordinary_display_release(
                principal(),
                actor(true),
                input.clone(),
                &mut port,
                &mut verifier
            )
            .is_err()
    );
    drop(control);
    let mut restarted =
        open_with_previews(database.path(), &machine, 0, previews_inner(&machine, true));
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
    let mut release_port = ReleasePort(machine.clone(), 0);
    assert!(
        restarted
            .begin_ordinary_display_release(
                principal(),
                actor(true),
                input.clone(),
                &ReleaseApproval(machine.clone(), 0),
                &mut port,
                &mut verifier,
                &mut release_port,
            )
            .is_err()
    );
    {
        let m = machine.lock().unwrap_or_else(|_| unreachable!());
        assert_eq!(m.ordinary_release_approvals, 0);
        assert_eq!(m.ordinary_release_calls, 0);
    }
    let now = now_unix_ms();
    if now <= deadline {
        std::thread::sleep(std::time::Duration::from_millis(deadline - now + 1));
    }
    let plan = value(restarted.plan_ordinary_display_release(
        principal(),
        actor(true),
        input.clone(),
        &mut port,
        &mut verifier,
    ));
    assert_eq!(plan.status.as_str(), "change-proposed");
    assert!(!plan.execution_authorized());
    assert!(
        plan.findings
            .iter()
            .any(|finding| finding.code == "display-ordinary-release-lineage"
                && finding.message.starts_with("Separate expired release"))
    );
    assert_eq!(
        value(restarted.inspect_ordinary_display_original(
            principal(),
            &original.request_id,
            &mut port,
            &mut verifier
        ))
        .original_snapshot(),
        &before
    );
    let m = machine.lock().unwrap_or_else(|_| unreachable!());
    assert_eq!(m.applies, 1);
    assert_eq!(m.decisions, 0);
    assert_eq!(m.deadline, deadline);
    drop(m);
    machine
        .lock()
        .unwrap_or_else(|_| unreachable!())
        .ordinary_handoff_enabled = true;
    let receipt = value(restarted.begin_ordinary_display_release(
        principal(),
        actor(true),
        input.clone(),
        &ReleaseApproval(machine.clone(), 0),
        &mut port,
        &mut verifier,
        &mut release_port,
    ));
    assert!(receipt.dispatch_digest.is_some());
    // Expiry has its own durable terminal. Continue the same authenticated
    // ordinary review through actual completion/power ports, then only inspect
    // after restart; timer expiry must never recreate execution authority.
    value(restarted.dispatch_ordinary_display_completion(
        principal(),
        actor(true),
        &receipt.request_id,
        &mut port,
        &mut verifier,
        &mut CompletionPort(machine.clone(), false),
    ));
    value(restarted.retire_ordinary_display_native_power(
        principal(),
        actor(true),
        &receipt.request_id,
        &mut port,
        &mut verifier,
        &mut OrdinaryPowerPort(machine.clone(), 0),
    ));
    value(restarted.retire_ordinary_display_root_power(
        principal(),
        actor(true),
        &receipt.request_id,
        &mut port,
        &mut verifier,
        &mut OrdinaryRootPowerPort(machine.clone(), 0),
    ));
    value(restarted.dispatch_ordinary_display_current_commit(
        principal(),
        actor(true),
        &receipt.request_id,
        &mut port,
        &mut verifier,
        &mut OrdinaryCurrentPort(machine.clone(), 0),
    ));
    value(restarted.dispatch_ordinary_display_final_retirement(
        principal(),
        actor(true),
        &receipt.request_id,
        &mut port,
        &mut verifier,
        &mut OrdinaryFinalPort(machine.clone(), 0),
    ));
    value(restarted.complete_ordinary_display_released_current(
        principal(),
        &receipt.request_id,
        &mut port,
        &mut verifier,
        &mut OrdinaryReleasedPort(machine.clone(), 0),
    ));
    drop(restarted);
    let mut restarted =
        open_with_previews(database.path(), &machine, 0, previews_inner(&machine, true));
    assert_eq!(
        value(restarted.begin_ordinary_display_release(
            principal(),
            actor(true),
            input.clone(),
            &ReleaseApproval(machine.clone(), 1),
            &mut port,
            &mut verifier,
            &mut release_port,
        )),
        receipt
    );
    let root = value(restarted.inspect_ordinary_display_root_power_retirement(
        principal(),
        &receipt.request_id,
        &mut port,
        &mut verifier,
    ));
    assert!(!root.power().current().frames().power_fence_held());
    assert_eq!(
        root.power().current().release().state,
        linura_transaction::TransactionState::Committed
    );
    value(restarted.verify_ordinary_display_qualified_current(
        principal(),
        &receipt.request_id,
        &mut port,
        &mut verifier,
    ));
    assert!(
        restarted
            .dispatch_ordinary_display_current_commit(
                principal(),
                actor(true),
                &receipt.request_id,
                &mut port,
                &mut verifier,
                &mut OrdinaryCurrentPort(machine.clone(), 0)
            )
            .is_err()
    );
    assert_eq!(
        root.power().current().comparison_release().state,
        linura_transaction::TransactionState::Indeterminate
    );
    assert!(
        restarted
            .retire_ordinary_display_native_power(
                principal(),
                actor(true),
                &receipt.request_id,
                &mut port,
                &mut verifier,
                &mut OrdinaryPowerPort(machine.clone(), 0),
            )
            .is_err()
    );
    let m = machine.lock().unwrap_or_else(|_| unreachable!());
    assert_eq!(m.ordinary_completion_calls, 1);
    assert_eq!(m.ordinary_power_calls, 1);
    assert_eq!(m.ordinary_root_power_calls, 1);
    assert_eq!(m.ordinary_final_calls, 1);
    assert_eq!(m.ordinary_released_calls, 1);
    assert_eq!(m.ordinary_current_commit_calls, 1);
    assert_eq!(m.ordinary_release_approvals, 1);
    assert_eq!(m.ordinary_release_calls, 1);
    assert_eq!(m.applies, 1);
    assert_eq!(m.decisions, 0);
    assert_eq!(m.deadline, deadline);
}

#[derive(Debug)]
struct ReleaseApproval(Arc<Mutex<Machine>>, u8);
impl linura_control::OrdinaryDisplayReleaseAuthorizer for ReleaseApproval {
    fn authorize_ordinary_release(
        &self,
        challenge: &linura_control::OrdinaryDisplayReleaseChallenge,
    ) -> Result<TrustedHumanApproval, String> {
        let managed = challenge.managed();
        assert_eq!(managed.change_key(), "release_ordinary");
        assert_eq!(
            managed.approval_class(),
            linura_control::ManagedApprovalClass::Administrator
        );
        assert!(
            managed
                .request_id()
                .as_str()
                .starts_with("request:v010:display-ordinary-release:")
        );
        assert_eq!(
            managed.desired_value().as_bytes(),
            value(linura_provider_sdk::display_ordinary_release_effect(
                challenge.material()
            ))
            .canonical_payload
        );
        let mut m = self.0.lock().unwrap_or_else(|_| unreachable!());
        m.ordinary_release_approvals += 1;
        match self.1 {
            1 => return Err("simulated protected release cancellation".into()),
            2 => {
                return Ok(TrustedHumanApproval::from_privileged_local_boundary(
                    managed.principal().clone(),
                ));
            }
            3 => {
                return Ok(TrustedHumanApproval::from_authorized_challenge(
                    value(PrincipalId::new("unix:uid:1001")),
                    managed,
                ));
            }
            4 => m.native_base_drift = true,
            5 => m.ordinary_root_fault = 1,
            _ => (),
        }
        Ok(TrustedHumanApproval::from_authorized_challenge(
            managed.principal().clone(),
            managed,
        ))
    }
}
#[derive(Debug)]
struct ReleasePort(Arc<Mutex<Machine>>, u8);
impl linura_control::OrdinaryDisplayReleasePort for ReleasePort {
    fn dispatch_ordinary_release(
        &mut self,
        release: linura_control::AuthorizedOrdinaryDisplayRelease,
    ) -> Result<ExecutionOutcome, String> {
        let (authorization, material, deadline) = release.into_executor_request();
        assert!(deadline > now_unix_ms() && deadline - now_unix_ms() <= 15_000);
        let (effect, binding) = authorization.into_executor_request();
        assert_eq!(
            effect,
            value(linura_provider_sdk::display_ordinary_release_effect(
                &material
            ))
        );
        value(binding.validate_for(&effect));
        let mut m = self.0.lock().unwrap_or_else(|_| unreachable!());
        m.ordinary_release_calls += 1;
        let original = m.binding.as_ref().unwrap_or_else(|| unreachable!());
        assert_ne!(binding.transaction_id, original.transaction_id);
        assert_ne!(binding.dispatch_digest, original.dispatch_digest);
        assert_ne!(binding.effect_digest, original.effect_digest);
        if m.ordinary_handoff_enabled {
            let wall = now_unix_ms();
            m.ordinary_release_record = Some(
                value(
                    linura_linux_session::NativeDisplayOrdinaryReleasePreparation::new(
                        &material,
                        &binding,
                        linura_observation::DisplayNativeHandoffWindow {
                            observed_unix_ms: wall,
                            observed_boot_ms: 100_000,
                            deadline_unix_ms: wall + 1900,
                            deadline_boot_ms: 101_900,
                        },
                    ),
                )
                .canonical_bytes(),
            );
        }
        if self.1 == 1 {
            return Err("simulated Root reservation lost reply".into());
        }
        ExecutionOutcome::new(
            ExecutionDisposition::Dispatched,
            if self.1 == 2 {
                linura_provider_sdk::ComponentDigest::from_bytes([9; 32])
            } else {
                binding.dispatch_digest
            },
            "simulated Root grant preparation only; no physical release",
        )
        .map_err(|e| e.to_string())
    }
}

pub(super) fn ordinary_release_dispatch_is_separately_approved_durable_and_never_replayed() {
    for action in [
        DisplayContinuationAction::Confirm,
        DisplayContinuationAction::Revert,
    ] {
        // Approval faults, persistence failure at every predispatch write, lost
        // and substituted acknowledgments all retain the original protection.
        for case in 0..=22 {
            let database = TestDatabase::new();
            let machine = Arc::new(Mutex::new(Machine::default()));
            let mut port = Port(machine.clone());
            let mut verifier = Verifier(machine.clone());
            let original = display_request("ordinary-release-dispatch-original");
            let mut control =
                open_with_previews(database.path(), &machine, 0, previews_inner(&machine, true));
            value(control.begin_display_layout(
                principal(),
                actor(true),
                original.clone(),
                &approval(),
                &mut port,
                &mut verifier,
            ));
            value(control.decide_display_layout(
                principal(),
                actor(true),
                &original.request_id,
                action,
                &Decision::approve(&machine),
                &mut port,
                &mut verifier,
            ));
            drop(control);
            let fail_at = match case {
                6..=10 => usize::from(case - 5),
                13..=17 => usize::from(case - 12),
                18..=22 => usize::from(case - 17),
                _ => 0,
            };
            machine
                .lock()
                .unwrap_or_else(|_| unreachable!())
                .ordinary_release_write_fault = match case {
                13..=17 => 1,
                18..=22 => 2,
                _ => 0,
            };
            let mut control = open_with_previews(
                database.path(),
                &machine,
                fail_at,
                previews_inner(&machine, true),
            );
            let before = value(control.inspect_ordinary_display_original(
                principal(),
                &original.request_id,
                &mut port,
                &mut verifier,
            ))
            .original_snapshot()
            .clone();
            let input = linura_control::OrdinaryDisplayReleaseRequest {
                operation_id: "ordinary-release-dispatch".into(),
                original_request: original.request_id.clone(),
                reason: original.reason.clone(),
            };
            let authorization = ReleaseApproval(machine.clone(), if case <= 5 { case } else { 0 });
            let mut release = ReleasePort(
                machine.clone(),
                if (11..=12).contains(&case) {
                    case - 10
                } else {
                    0
                },
            );
            let result = control.begin_ordinary_display_release(
                principal(),
                actor(true),
                input.clone(),
                &authorization,
                &mut port,
                &mut verifier,
                &mut release,
            );
            assert_eq!(
                result.is_ok(),
                case == 0 || case == 11,
                "{action:?} case {case}: {result:?}; approvals/dispatches/records {:?}",
                {
                    let m = machine.lock().unwrap_or_else(|_| unreachable!());
                    (
                        m.ordinary_release_approvals,
                        m.ordinary_release_calls,
                        m.journal_keys.clone(),
                    )
                }
            );
            {
                let m = machine.lock().unwrap_or_else(|_| unreachable!());
                assert_eq!(m.ordinary_release_approvals, 1);
                assert_eq!(
                    m.ordinary_release_calls,
                    usize::from(case == 0 || (11..=12).contains(&case))
                );
                assert_eq!(m.applies, 1);
                assert_eq!(m.decisions, 1);
            }
            if case == 0 || (11..=12).contains(&case) {
                let denied = ReleaseApproval(machine.clone(), 1);
                let receipt = value(control.begin_ordinary_display_release(
                    principal(),
                    actor(true),
                    input.clone(),
                    &denied,
                    &mut port,
                    &mut verifier,
                    &mut release,
                ));
                assert!(receipt.dispatch_digest.is_some());
                assert!(
                    control
                        .begin_display_layout(
                            principal(),
                            actor(true),
                            display_request("ordinary-release-competing-apply"),
                            &approval(),
                            &mut port,
                            &mut verifier
                        )
                        .is_err()
                );
                let mut competing = input.clone();
                competing.operation_id = "ordinary-release-competing-owner".into();
                assert!(
                    control
                        .begin_ordinary_display_release(
                            principal(),
                            actor(true),
                            competing,
                            &denied,
                            &mut port,
                            &mut verifier,
                            &mut release
                        )
                        .is_err()
                );
                drop(control);
                let mut restarted = open_with_previews(
                    database.path(),
                    &machine,
                    0,
                    previews_inner(&machine, true),
                );
                assert_eq!(
                    value(restarted.begin_ordinary_display_release(
                        principal(),
                        actor(true),
                        input.clone(),
                        &denied,
                        &mut port,
                        &mut verifier,
                        &mut release
                    )),
                    receipt
                );
                assert!(
                    restarted
                        .begin_ordinary_display_release(
                            value(AuthenticatedPrincipal::new("unix:uid:1001")),
                            actor(true),
                            input,
                            &denied,
                            &mut port,
                            &mut verifier,
                            &mut release
                        )
                        .is_err()
                );
                assert!(
                    restarted
                        .begin_display_layout(
                            principal(),
                            actor(true),
                            display_request("ordinary-release-competing-restart"),
                            &approval(),
                            &mut port,
                            &mut verifier
                        )
                        .is_err()
                );
                assert_eq!(
                    value(restarted.inspect_ordinary_display_original(
                        principal(),
                        &original.request_id,
                        &mut port,
                        &mut verifier
                    ))
                    .original_snapshot(),
                    &before
                );
                let m = machine.lock().unwrap_or_else(|_| unreachable!());
                assert_eq!(m.ordinary_release_approvals, 1);
                assert_eq!(m.ordinary_release_calls, 1);
                assert_eq!(m.applies, 1);
                assert_eq!(m.decisions, 1);
            }
        }
    }
}

#[derive(Debug)]
struct CompletionPort(Arc<Mutex<Machine>>, bool);
impl linura_control::OrdinaryDisplayCompletionPort for CompletionPort {
    fn dispatch_ordinary_completion(
        &mut self,
        completion: linura_control::AuthorizedOrdinaryDisplayCompletion,
    ) -> Result<(), String> {
        let mut m = self.0.lock().unwrap_or_else(|_| unreachable!());
        assert_eq!(
            m.checked_history_reads, 0,
            "completion effect crossed read scope"
        );
        m.ordinary_completion_calls += 1;
        let record = value(
            linura_linux_session::NativeDisplayOrdinaryReleasePreparation::decode(
                m.ordinary_release_record
                    .as_ref()
                    .unwrap_or_else(|| unreachable!()),
            ),
        );
        assert_eq!(completion.material(), record.material());
        assert_eq!(
            completion.dispatch(),
            record.binding().dispatch_digest.to_hex()
        );
        assert_eq!(
            completion.root_preparation(),
            record.record_digest().to_hex()
        );
        assert_eq!(
            completion.release().transaction_id.as_str(),
            record.binding().transaction_id
        );
        assert_eq!(
            completion.release().state,
            linura_transaction::TransactionState::Indeterminate
        );
        assert_eq!(
            completion.frames().lineage().preparation_digest,
            record.record_digest().to_hex()
        );
        assert!(
            completion
                .frames()
                .matches_material(&value(record.decoded_material()))
        );
        assert_ne!(completion.preparation(), completion.verification());
        assert_ne!(
            completion.preparation(),
            &linura_transaction::ContentDigest::zero()
        );
        assert!(now_unix_ms() < completion.expires_at_unix_ms());
        assert!(completion.expires_at_unix_ms() <= record.window().deadline_unix_ms);
        let transferred = value(
            linura_linux_session::NativeDisplayOrdinaryCompletionPreparation::new(
                &record,
                value(linura_provider_sdk::ComponentDigest::parse_hex(
                    completion.preparation().hex(),
                )),
                value(linura_provider_sdk::ComponentDigest::parse_hex(
                    completion.verification().hex(),
                )),
                completion.frames(),
                completion.expires_at_unix_ms(),
            ),
        );
        m.ordinary_completion_record = Some(transferred.canonical_bytes());
        if self.1 {
            Err("simulated completion ACK loss".into())
        } else {
            Ok(())
        }
    }
}

fn ordinary_completion_requires_original_review_and_cannot_replay() {
    // Real Control + SQLite; this port and its Root/native facts are simulated.
    // Each case owns a separate original producer window, never renewed.
    for action in [
        DisplayContinuationAction::Confirm,
        DisplayContinuationAction::Revert,
    ] {
        for fault in 0..=12 {
            let database = TestDatabase::new();
            let machine = Arc::new(Mutex::new(Machine::default()));
            let mut port = Port(machine.clone());
            let mut verifier = Verifier(machine.clone());
            let original = display_request("ordinary-completion-original");
            let mut control =
                open_with_previews(database.path(), &machine, 0, previews_inner(&machine, true));
            value(control.begin_display_layout(
                principal(),
                actor(true),
                original.clone(),
                &approval(),
                &mut port,
                &mut verifier,
            ));
            value(control.decide_display_layout(
                principal(),
                actor(true),
                &original.request_id,
                action,
                &Decision::approve(&machine),
                &mut port,
                &mut verifier,
            ));
            let original_before = value(control.inspect_ordinary_display_original(
                principal(),
                &original.request_id,
                &mut port,
                &mut verifier,
            ))
            .original_snapshot()
            .clone();
            machine
                .lock()
                .unwrap_or_else(|_| unreachable!())
                .ordinary_handoff_enabled = true;
            let mut release_port = ReleasePort(machine.clone(), u8::from(fault == 2));
            let receipt = value(control.begin_ordinary_display_release(
                principal(),
                actor(true),
                linura_control::OrdinaryDisplayReleaseRequest {
                    operation_id: "ordinary-completion-release".into(),
                    original_request: original.request_id.clone(),
                    reason: original.reason.clone(),
                },
                &ReleaseApproval(machine.clone(), 0),
                &mut port,
                &mut verifier,
                &mut release_port,
            ));
            if fault == 3 {
                drop(control);
                control = open_with_previews(
                    database.path(),
                    &machine,
                    0,
                    previews_inner(&machine, true),
                );
                // Successfully reconstructed first-frame proof cannot recreate review.
                value(control.verify_ordinary_display_handoff(
                    principal(),
                    &receipt.request_id,
                    &mut port,
                    &mut verifier,
                ));
            }
            let mut completion = CompletionPort(machine.clone(), fault == 1);
            if fault == 4 {
                machine
                    .lock()
                    .unwrap_or_else(|_| unreachable!())
                    .ordinary_handoff_fault = 7;
            }
            if (5..=8).contains(&fault) {
                machine
                    .lock()
                    .unwrap_or_else(|_| unreachable!())
                    .ordinary_completion_store_fault = fault - 4;
            }
            // Denied callers and unrelated requests cannot consume the owner's review.
            if fault == 9 {
                assert!(
                    control
                        .dispatch_ordinary_display_completion(
                            principal(),
                            actor(false),
                            &receipt.request_id,
                            &mut port,
                            &mut verifier,
                            &mut completion
                        )
                        .is_err()
                );
            } else if fault == 10 {
                assert!(
                    control
                        .dispatch_ordinary_display_completion(
                            value(AuthenticatedPrincipal::new("unix:uid:1001")),
                            actor(true),
                            &receipt.request_id,
                            &mut port,
                            &mut verifier,
                            &mut completion
                        )
                        .is_err()
                );
            } else if fault == 11 {
                assert!(
                    control
                        .dispatch_ordinary_display_completion(
                            principal(),
                            actor(true),
                            &original.request_id,
                            &mut port,
                            &mut verifier,
                            &mut completion
                        )
                        .is_err()
                );
            } else if fault == 12 {
                assert!(
                    control
                        .dispatch_ordinary_display_completion(
                            principal(),
                            actor(true),
                            &value(RequestId::new(
                                "request:v010:display-ordinary-release:competing"
                            )),
                            &mut port,
                            &mut verifier,
                            &mut completion
                        )
                        .is_err()
                );
            }
            let outcome = control.dispatch_ordinary_display_completion(
                principal(),
                actor(true),
                &receipt.request_id,
                &mut port,
                &mut verifier,
                &mut completion,
            );
            let dispatched = fault == 0 || fault == 1 || fault >= 9;
            assert_eq!(
                outcome.is_ok(),
                fault == 0 || fault >= 9,
                "{action:?} fault {fault}: {outcome:?}"
            );
            if let Ok(result) = outcome {
                assert_eq!(result.request(), &receipt.request_id);
                assert_eq!(result.transaction(), &receipt.transaction_id);
                assert_ne!(
                    result.preparation(),
                    &linura_transaction::ContentDigest::zero()
                );
            }
            {
                let mut m = machine.lock().unwrap_or_else(|_| unreachable!());
                m.ordinary_handoff_fault = 0;
                m.ordinary_completion_store_fault = 0;
                assert_eq!(m.ordinary_completion_calls, usize::from(dispatched));
                let prep = value(
                    linura_linux_session::NativeDisplayOrdinaryReleasePreparation::decode(
                        m.ordinary_release_record
                            .as_ref()
                            .unwrap_or_else(|| unreachable!()),
                    ),
                );
                assert!(
                    now_unix_ms() < prep.window().deadline_unix_ms,
                    "fault must reject within original window: {action:?}/{fault}"
                );
            }
            assert!(
                control
                    .dispatch_ordinary_display_completion(
                        principal(),
                        actor(true),
                        &receipt.request_id,
                        &mut port,
                        &mut verifier,
                        &mut completion
                    )
                    .is_err()
            );
            drop(control);
            let mut restarted =
                open_with_previews(database.path(), &machine, 0, previews_inner(&machine, true));
            assert!(
                restarted
                    .dispatch_ordinary_display_completion(
                        principal(),
                        actor(true),
                        &receipt.request_id,
                        &mut port,
                        &mut verifier,
                        &mut completion
                    )
                    .is_err()
            );
            if dispatched {
                let inspect = value(restarted.inspect_current_ordinary_display_completion(
                    principal(),
                    &receipt.request_id,
                    &mut port,
                    &mut verifier,
                ));
                assert_eq!(
                    inspect.release().state,
                    linura_transaction::TransactionState::Indeterminate
                );
                assert!(inspect.frames().input_retired() && inspect.frames().power_fence_held());
                if fault == 0 {
                    for changed in 1..=11 {
                        {
                            let mut m = machine.lock().unwrap_or_else(|_| unreachable!());
                            m.ordinary_current_fault = changed;
                            m.ordinary_current_reads = 0;
                        }
                        assert!(
                            restarted
                                .inspect_current_ordinary_display_completion(
                                    principal(),
                                    &receipt.request_id,
                                    &mut port,
                                    &mut verifier
                                )
                                .is_err(),
                            "{action:?} current fault {changed}"
                        );
                    }
                    machine
                        .lock()
                        .unwrap_or_else(|_| unreachable!())
                        .ordinary_current_fault = 0;
                    value(restarted.inspect_current_ordinary_display_completion(
                        principal(),
                        &receipt.request_id,
                        &mut port,
                        &mut verifier,
                    ));
                }
            } else {
                let proof = value(restarted.verify_ordinary_display_handoff(
                    principal(),
                    &receipt.request_id,
                    &mut port,
                    &mut verifier,
                ));
                assert_eq!(
                    proof.inspection().release().state,
                    linura_transaction::TransactionState::Indeterminate
                );
                assert!(
                    restarted
                        .inspect_current_ordinary_display_completion(
                            principal(),
                            &receipt.request_id,
                            &mut port,
                            &mut verifier
                        )
                        .is_err()
                );
            }
            assert_eq!(
                value(restarted.inspect_ordinary_display_original(
                    principal(),
                    &original.request_id,
                    &mut port,
                    &mut verifier
                ))
                .original_snapshot(),
                &original_before
            );
            let m = machine.lock().unwrap_or_else(|_| unreachable!());
            assert_eq!(m.ordinary_completion_calls, usize::from(dispatched));
            assert_eq!(
                (
                    m.applies,
                    m.decisions,
                    m.ordinary_release_calls,
                    m.ordinary_release_approvals
                ),
                (1, 1, 1, 1)
            );
        }
    }
}

// Simulated live Root/native current sources. The immutable first tuple comes
// from the actual sealed dispatch in this test; the fresh read has its own
// bounded window and advancing output commit, never renewed effect authority.
pub(super) fn observe_current(
    m: &mut Machine,
    resource: &ResourceId,
    capability: &CapabilityId,
) -> Result<ObservationEnvelope, ProviderError> {
    use linura_observation::{
        DISPLAY_ORDINARY_COMPLETION_CAPABILITY, DISPLAY_ORDINARY_CURRENT_CAPABILITY,
        DISPLAY_PROVIDER, DISPLAY_RECOVERY_PROVIDER, DisplayCompletionLineage,
        DisplayNativeCurrentOutput, DisplayNativeHandoffWindow, DisplayOrdinaryCompletionFacts,
        DisplayOrdinaryCurrentFacts,
    };
    assert_eq!(m.checked_history_reads, 0);
    let fail = || ProviderError::Unavailable("simulated current source unavailable".into());
    let record = linura_linux_session::NativeDisplayOrdinaryCompletionPreparation::decode(
        m.ordinary_completion_record.as_ref().ok_or_else(fail)?,
    )
    .map_err(|_| fail())?;
    let scope = record.frames().scope();
    if scope.resource_id().map_err(|_| fail())? != *resource {
        return Err(fail());
    }
    let root = capability.as_str() == DISPLAY_ORDINARY_COMPLETION_CAPABILITY;
    if !root && capability.as_str() != DISPLAY_ORDINARY_CURRENT_CAPABILITY {
        return Err(fail());
    }
    let wall = now_unix_ms();
    let boot = record.frames().window().observed_boot_ms
        + wall.saturating_sub(record.frames().window().observed_unix_ms);
    let attributes = if root {
        DisplayOrdinaryCompletionFacts::new(
            DisplayCompletionLineage {
                record: record.record_digest().to_hex(),
                preparation: record.preparation().to_hex(),
                verification: record.verification().to_hex(),
                material: record.parent().material().into(),
            },
            record.frames().clone(),
            record.parent().window(),
        )
        .map_err(|_| fail())?
        .attributes()
    } else {
        m.ordinary_current_reads += 1;
        DisplayOrdinaryCurrentFacts::new(
            scope.clone(),
            record.frames().lineage().clone(),
            DisplayNativeHandoffWindow {
                observed_unix_ms: wall,
                observed_boot_ms: boot,
                deadline_unix_ms: wall + 2000,
                deadline_boot_ms: boot + 2000,
            },
            record
                .frames()
                .outputs()
                .iter()
                .map(|(id, old)| {
                    (
                        id.clone(),
                        DisplayNativeCurrentOutput {
                            enabled: old.enabled,
                            connector: old.connector,
                            crtc: old.crtc,
                            plane: old.plane,
                            framebuffer: if old.enabled { 9 } else { 0 },
                            handoff_commit: old.completed_commit,
                            // Advancing physical history is modeled separately
                            // from probe sequence. The buffer-substitution case
                            // deliberately has no newer commit, as before.
                            completed_commit: old.completed_commit
                                + u64::from(old.enabled)
                                    * if m.ordinary_current_fault == 11 {
                                        1
                                    } else {
                                        m.ordinary_current_reads as u64
                                    },
                        },
                    )
                })
                .collect(),
            record.record_digest().to_hex(),
            !m.ordinary_input_pending,
            !m.ordinary_native_power_retired,
            if m.ordinary_native_current_qualified {
                Some(
                    value(
                        linura_linux_session::NativeDisplayOrdinaryCurrentPreparation::decode(
                            m.ordinary_current_commit_record
                                .as_ref()
                                .unwrap_or_else(|| unreachable!()),
                        ),
                    )
                    .record_digest()
                    .to_hex(),
                )
            } else {
                None
            },
            if m.ordinary_native_final_retired {
                Some(final_digest(
                    m.ordinary_final_record
                        .as_ref()
                        .unwrap_or_else(|| unreachable!()),
                ))
            } else {
                None
            },
        )
        .map_err(|_| fail())?
        .attributes()
    };
    m.sequence += 1;
    let mut sample = ObservationEnvelope {
        provider: value(ProviderId::new(if root {
            DISPLAY_RECOVERY_PROVIDER
        } else {
            DISPLAY_PROVIDER
        })),
        capability: capability.clone(),
        resource: resource.clone(),
        authority: ObservationAuthority::NativeApi,
        observed_at_unix_ms: wall,
        valid_for_ms: 2000,
        sequence: m.sequence,
        attributes,
    };
    if !root && m.ordinary_current_commit_grant_fault == 5 {
        let prepared = value(
            linura_linux_session::NativeDisplayOrdinaryCurrentPreparation::decode(
                m.ordinary_current_commit_record
                    .as_ref()
                    .unwrap_or_else(|| unreachable!()),
            ),
        );
        let before = prepared
            .frames()
            .outputs()
            .values()
            .next()
            .unwrap_or_else(|| unreachable!())
            .completed_commit;
        assert!(
            before
                > record
                    .frames()
                    .outputs()
                    .values()
                    .next()
                    .unwrap_or_else(|| unreachable!())
                    .completed_commit
                    + 1
        );
        sample.attributes.insert(
            "output.0.completed_commit".into(),
            ObservedValue::U64(before - 1),
        );
    }
    let fault = m.ordinary_current_fault;
    let changed = if root {
        match fault {
            1 => Some(("phase", ObservedValue::Text("prepared".into()))),
            2 => Some(("verification_digest", ObservedValue::Text("9".repeat(64)))),
            3 => Some(("preparation_digest", ObservedValue::Text("8".repeat(64)))),
            _ => None,
        }
    } else {
        match fault {
            4 => Some(("output.0.handoff_commit", ObservedValue::U64(90))),
            5 => Some(("output.0.completed_commit", ObservedValue::U64(91))),
            6 => Some(("completion_digest", ObservedValue::Text("8".repeat(64)))),
            7 => Some(("power_fence_held", ObservedValue::Bool(false))),
            8 => Some(("signed_binding", ObservedValue::Text("8".repeat(64)))),
            9 => Some(("outcome", ObservedValue::Text("expired".into()))),
            10 => {
                sample.authority = ObservationAuthority::SyntheticTest;
                None
            }
            11 if m.ordinary_current_reads.is_multiple_of(2) => {
                Some(("output.0.framebuffer", ObservedValue::U64(10)))
            }
            _ => None,
        }
    };
    if let Some((key, value)) = changed {
        sample.attributes.insert(key.into(), value);
    }
    Ok(sample)
}

// Real Control/SQLite with purpose-specific simulated Root/native power facts.
pub(super) fn observe_power(
    m: &mut Machine,
    resource: &ResourceId,
    capability: &CapabilityId,
) -> Result<ObservationEnvelope, ProviderError> {
    use linura_observation::{
        DISPLAY_ORDINARY_POWER_RETIREMENT_CAPABILITY, DISPLAY_RECOVERY_PROVIDER,
        DisplayOrdinaryPowerRetirementFacts,
    };
    let fail = || ProviderError::Unavailable("simulated ordinary power source unavailable".into());
    assert_eq!(m.checked_history_reads, 0);
    if capability.as_str() != DISPLAY_ORDINARY_POWER_RETIREMENT_CAPABILITY {
        return Err(fail());
    }
    let record = linura_linux_session::NativeDisplayOrdinaryPowerPreparation::decode(
        m.ordinary_power_record.as_ref().ok_or_else(fail)?,
    )
    .map_err(|_| fail())?;
    if record.frames().scope().resource_id().map_err(|_| fail())? != *resource {
        return Err(fail());
    }
    let mut attrs = DisplayOrdinaryPowerRetirementFacts::new(
        record.frames().scope().clone(),
        record.record_digest().to_hex(),
        record.parent().record_digest().to_hex(),
        record.preparation_digest().to_hex(),
        record.checkpoint_digest().to_hex(),
        true,
    )
    .map_err(|_| fail())?
    .attributes();
    match m.ordinary_power_grant_fault {
        1 => {
            attrs.insert("grant_spent".into(), ObservedValue::Bool(false));
        }
        2 => {
            attrs.insert(
                "preparation_digest".into(),
                ObservedValue::Text("9".repeat(64)),
            );
        }
        3 => {
            attrs.insert(
                "checkpoint_digest".into(),
                ObservedValue::Text("8".repeat(64)),
            );
        }
        4 => {
            attrs.insert(
                "completion_digest".into(),
                ObservedValue::Text("7".repeat(64)),
            );
        }
        5 => return Err(fail()),
        _ => (),
    }
    m.sequence += 1;
    Ok(ObservationEnvelope {
        provider: value(ProviderId::new(DISPLAY_RECOVERY_PROVIDER)),
        capability: capability.clone(),
        resource: resource.clone(),
        authority: if m.ordinary_power_grant_fault == 6 {
            ObservationAuthority::SyntheticTest
        } else {
            ObservationAuthority::NativeApi
        },
        observed_at_unix_ms: now_unix_ms(),
        valid_for_ms: 2000,
        sequence: m.sequence,
        attributes: attrs,
    })
}
#[derive(Debug)]
struct OrdinaryPowerPort(Arc<Mutex<Machine>>, u8);
impl linura_control::OrdinaryDisplayNativePowerRetirementPort for OrdinaryPowerPort {
    fn retire_ordinary_native_power(
        &mut self,
        permit: linura_control::AuthorizedOrdinaryDisplayNativePowerRetirement,
    ) -> Result<(), String> {
        let mut m = self.0.lock().unwrap_or_else(|_| unreachable!());
        assert_eq!(m.checked_history_reads, 0);
        m.ordinary_power_calls += 1;
        let parent = value(
            linura_linux_session::NativeDisplayOrdinaryCompletionPreparation::decode(
                m.ordinary_completion_record
                    .as_ref()
                    .unwrap_or_else(|| unreachable!()),
            ),
        );
        assert_eq!(parent.frames(), permit.root().first());
        assert!(permit.frames().input_retired() && permit.frames().power_fence_held());
        assert_eq!(
            permit.frames().completion_digest(),
            parent.record_digest().to_hex()
        );
        assert!(now_unix_ms() < permit.expires_at_unix_ms());
        let record = value(
            linura_linux_session::NativeDisplayOrdinaryPowerPreparation::new(
                &parent,
                value(linura_provider_sdk::ComponentDigest::parse_hex(
                    permit.preparation().hex(),
                )),
                value(linura_provider_sdk::ComponentDigest::parse_hex(
                    permit.checkpoint().hex(),
                )),
                permit.frames(),
                permit.expires_at_unix_ms(),
            ),
        );
        m.ordinary_power_record = Some(record.canonical_bytes());
        m.ordinary_native_power_retired = self.1 != 2;
        if self.1 == 1 {
            Err("simulated power ACK loss".into())
        } else {
            Ok(())
        }
    }
}

// Component simulation only: the actual grant carries the sealed Control
// preparation; fresh source reports remain independent of the close ACK.
fn observe_root_power(
    m: &mut Machine,
    resource: &ResourceId,
    capability: &CapabilityId,
) -> Result<ObservationEnvelope, ProviderError> {
    use linura_observation::{
        DisplayCompletionLineage, DisplayOrdinaryCompletionFacts,
        DisplayOrdinaryOriginalComparison, DisplayOrdinaryRootRetirementFacts,
        DisplayRootRetirementLineage,
    };
    let fail =
        || ProviderError::Unavailable("simulated ordinary Root retirement unavailable".into());
    assert_eq!(m.checked_history_reads, 0);
    if !m.ordinary_root_power_retired || m.ordinary_root_power_read_fault == 1 {
        return Err(fail());
    }
    let record = linura_linux_session::NativeDisplayOrdinaryRootPreparation::decode(
        m.ordinary_root_power_record.as_ref().ok_or_else(fail)?,
    )
    .map_err(|_| fail())?;
    let completion = record.parent().parent();
    let scope = completion.frames().scope();
    if value(scope.resource_id()) != *resource {
        return Err(fail());
    }
    let binding = m.binding.as_ref().ok_or_else(fail)?;
    let facts = value(DisplayOrdinaryRootRetirementFacts::new(
        DisplayRootRetirementLineage {
            record: record.record_digest().to_hex(),
            preparation: record.preparation_digest().to_hex(),
            verification: record.verification_digest().to_hex(),
            power_record: record.parent().record_digest().to_hex(),
        },
        value(DisplayOrdinaryCompletionFacts::new(
            DisplayCompletionLineage {
                record: completion.record_digest().to_hex(),
                preparation: completion.preparation().to_hex(),
                verification: completion.verification().to_hex(),
                material: completion.parent().material().into(),
            },
            completion.frames().clone(),
            completion.parent().window(),
        )),
        DisplayOrdinaryOriginalComparison {
            material: display_request("original-observer-fixture").desired_state["layout"].clone(),
            transaction: binding.transaction_id.clone(),
            checkpoint: "4".repeat(64),
            native_guard: m.original_native_guard.ok_or_else(fail)?.to_hex(),
            integration: "5".repeat(64),
            sampled_boot_ms: 100,
            original_deadline_unix_ms: m.deadline,
        },
        m.ordinary_current_commit_record.as_ref().map(|bytes| {
            let grant =
                value(linura_linux_session::NativeDisplayOrdinaryCurrentPreparation::decode(bytes));
            (
                linura_observation::DisplayCurrentGrantLineage {
                    record: grant.record_digest().to_hex(),
                    preparation: grant.preparation_digest().to_hex(),
                    committed_record: grant.committed_record_digest().to_hex(),
                },
                grant.frames().clone(),
            )
        }),
    ));
    let mut attrs = facts.attributes();
    match m.ordinary_current_commit_grant_fault {
        1 => {
            attrs.insert(
                "current_grant_preparation".into(),
                ObservedValue::Text("6".repeat(64)),
            );
        }
        2 => {
            attrs.insert(
                "current_grant_committed_record".into(),
                ObservedValue::Text("7".repeat(64)),
            );
        }
        3 => {
            attrs.insert(
                "current_grant_digest".into(),
                ObservedValue::Text("8".repeat(64)),
            );
        }
        4 => {
            attrs.insert(
                "current_grant_digest".into(),
                ObservedValue::Text("0".repeat(64)),
            );
        }
        _ => (),
    }
    match m.ordinary_root_power_read_fault {
        2 => {
            attrs.insert("power_absent".into(), ObservedValue::Bool(false));
        }
        3 => {
            attrs.insert(
                "preparation_digest".into(),
                ObservedValue::Text("9".repeat(64)),
            );
        }
        4 => {
            attrs.insert(
                "power_record_digest".into(),
                ObservedValue::Text("8".repeat(64)),
            );
        }
        5 => {
            attrs.insert(
                "original.native_guard".into(),
                ObservedValue::Text("7".repeat(64)),
            );
        }
        _ => (),
    }
    m.sequence += 1;
    Ok(ObservationEnvelope {
        provider: value(ProviderId::new(
            linura_observation::DISPLAY_RECOVERY_PROVIDER,
        )),
        capability: capability.clone(),
        resource: resource.clone(),
        authority: if m.ordinary_root_power_read_fault == 6 {
            ObservationAuthority::SyntheticTest
        } else {
            ObservationAuthority::NativeApi
        },
        sequence: m.sequence,
        observed_at_unix_ms: now_unix_ms(),
        valid_for_ms: 2000,
        attributes: attrs,
    })
}
#[derive(Debug)]
struct OrdinaryRootPowerPort(Arc<Mutex<Machine>>, u8);
impl linura_control::OrdinaryDisplayRootPowerRetirementPort for OrdinaryRootPowerPort {
    fn retire_ordinary_root_power(
        &mut self,
        permit: linura_control::AuthorizedOrdinaryDisplayRootPowerRetirement,
    ) -> Result<(), String> {
        let mut m = self.0.lock().unwrap_or_else(|_| unreachable!());
        assert_eq!(m.checked_history_reads, 0);
        assert!(m.ordinary_native_power_retired && !m.ordinary_root_power_retired);
        assert_eq!(m.ordinary_root_power_calls, 0);
        m.ordinary_root_power_calls += 1;
        let parent = value(
            linura_linux_session::NativeDisplayOrdinaryPowerPreparation::decode(
                m.ordinary_power_record
                    .as_ref()
                    .unwrap_or_else(|| unreachable!()),
            ),
        );
        let record = value(
            linura_linux_session::NativeDisplayOrdinaryRootPreparation::new(
                &parent,
                value(linura_provider_sdk::ComponentDigest::parse_hex(
                    permit.preparation().hex(),
                )),
                value(linura_provider_sdk::ComponentDigest::parse_hex(
                    permit.verification().hex(),
                )),
                permit.frames(),
                permit.expires_at_unix_ms(),
            ),
        );
        m.ordinary_root_power_record = Some(record.canonical_bytes());
        m.ordinary_root_power_retired = self.1 != 2;
        if self.1 == 1 {
            Err("Root close ACK lost after effect".into())
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
struct OrdinaryCurrentPort(Arc<Mutex<Machine>>, u8);
impl linura_control::OrdinaryDisplayCurrentCommitPort for OrdinaryCurrentPort {
    fn commit_ordinary_current(
        &mut self,
        permit: linura_control::AuthorizedOrdinaryDisplayCurrentCommit,
    ) -> Result<(), String> {
        let mut m = self.0.lock().unwrap_or_else(|_| unreachable!());
        assert_eq!(m.checked_history_reads, 0);
        assert!(
            m.ordinary_root_power_retired
                && m.ordinary_native_power_retired
                && !m.ordinary_native_current_qualified
        );
        assert_eq!(m.ordinary_current_commit_calls, 0);
        m.ordinary_current_commit_calls += 1;
        // The exact final preparation window, not the sum of earlier fresh
        // read/CAS phases, bounds the one actual native dispatch.
        assert!(
            now_unix_ms() >= permit.frames().window().observed_unix_ms
                && now_unix_ms() < permit.expires_at_unix_ms()
        );
        let committed = permit.committed().release();
        assert_eq!(
            committed.state,
            linura_transaction::TransactionState::Committed
        );
        let parent = value(
            linura_linux_session::NativeDisplayOrdinaryRootPreparation::decode(
                m.ordinary_root_power_record
                    .as_ref()
                    .unwrap_or_else(|| unreachable!()),
            ),
        );
        let record = value(
            linura_linux_session::NativeDisplayOrdinaryCurrentPreparation::new(
                &parent,
                value(linura_provider_sdk::ComponentDigest::parse_hex(
                    permit.preparation().hex(),
                )),
                value(linura_provider_sdk::ComponentDigest::parse_hex(
                    permit.committed().record_digest().hex(),
                )),
                committed.current_generation,
                committed.state_version,
                value(linura_provider_sdk::ComponentDigest::parse_hex(
                    committed.binding_digest.hex(),
                )),
                permit.frames(),
                permit.expires_at_unix_ms(),
            ),
        );
        m.ordinary_current_commit_record = Some(record.canonical_bytes());
        m.ordinary_native_current_qualified = self.1 != 2;
        if self.1 == 1 {
            Err("native current ACK lost after physical effect".into())
        } else {
            Ok(())
        }
    }
}

fn ordinary_current_commit_requires_independent_native_qualification() {
    for action in [
        DisplayContinuationAction::Confirm,
        DisplayContinuationAction::Revert,
    ] {
        // Positive, lost ACK, false physical ACK, restart-before-dispatch,
        // input/source faults, every publication phase/failure and early signed
        // metadata without a native grant are independent cases.
        for fault in 0..=22 {
            let database = TestDatabase::new();
            let machine = Arc::new(Mutex::new(Machine::default()));
            let mut port = Port(machine.clone());
            let mut verifier = Verifier(machine.clone());
            let original = display_request("ordinary-current-original");
            let mut control =
                open_with_previews(database.path(), &machine, 0, previews_inner(&machine, true));
            value(control.begin_display_layout(
                principal(),
                actor(true),
                original.clone(),
                &approval(),
                &mut port,
                &mut verifier,
            ));
            value(control.decide_display_layout(
                principal(),
                actor(true),
                &original.request_id,
                action,
                &Decision::approve(&machine),
                &mut port,
                &mut verifier,
            ));
            let original_before = value(control.inspect_ordinary_display_original(
                principal(),
                &original.request_id,
                &mut port,
                &mut verifier,
            ))
            .original_snapshot()
            .clone();
            machine
                .lock()
                .unwrap_or_else(|_| unreachable!())
                .ordinary_handoff_enabled = true;
            let receipt = value(control.begin_ordinary_display_release(
                principal(),
                actor(true),
                linura_control::OrdinaryDisplayReleaseRequest {
                    operation_id: "ordinary-current-release".into(),
                    original_request: original.request_id.clone(),
                    reason: original.reason.clone(),
                },
                &ReleaseApproval(machine.clone(), 0),
                &mut port,
                &mut verifier,
                &mut ReleasePort(machine.clone(), 0),
            ));
            value(control.dispatch_ordinary_display_completion(
                principal(),
                actor(true),
                &receipt.request_id,
                &mut port,
                &mut verifier,
                &mut CompletionPort(machine.clone(), false),
            ));
            value(control.retire_ordinary_display_native_power(
                principal(),
                actor(true),
                &receipt.request_id,
                &mut port,
                &mut verifier,
                &mut OrdinaryPowerPort(machine.clone(), 0),
            ));
            let root = control.retire_ordinary_display_root_power(
                principal(),
                actor(true),
                &receipt.request_id,
                &mut port,
                &mut verifier,
                &mut OrdinaryRootPowerPort(machine.clone(), u8::from(fault == 21)),
            );
            assert_eq!(root.is_ok(), fault != 21);
            if fault == 3 || fault == 22 {
                if fault == 22 {
                    let signed = value(control.commit_ordinary_display_current(
                        principal(),
                        actor(true),
                        &receipt.request_id,
                        &mut port,
                        &mut verifier,
                    ));
                    assert_eq!(
                        signed.release().state,
                        linura_transaction::TransactionState::Committed
                    );
                    assert!(
                        control
                            .verify_ordinary_display_qualified_current(
                                principal(),
                                &receipt.request_id,
                                &mut port,
                                &mut verifier
                            )
                            .is_err()
                    );
                }
                drop(control);
                control = open_with_previews(
                    database.path(),
                    &machine,
                    0,
                    previews_inner(&machine, true),
                );
            }
            {
                let mut m = machine.lock().unwrap_or_else(|_| unreachable!());
                if fault == 4 {
                    m.ordinary_current_fault = 6;
                }
                if (5..=16).contains(&fault) {
                    m.ordinary_current_commit_store_phase = (fault - 5) / 3 + 1;
                    m.ordinary_current_commit_store_fault = (fault - 5) % 3 + 1;
                }
                if fault == 17 {
                    m.ordinary_current_commit_store_phase = 4;
                    m.ordinary_current_commit_store_fault = 4;
                }
            }
            let mut current =
                OrdinaryCurrentPort(machine.clone(), if fault <= 2 { fault } else { 0 });
            if (18..=20).contains(&fault) {
                assert!(
                    control
                        .dispatch_ordinary_display_current_commit(
                            if fault == 19 {
                                value(AuthenticatedPrincipal::new("unix:uid:1001"))
                            } else {
                                principal()
                            },
                            actor(fault != 18),
                            if fault == 20 {
                                &original.request_id
                            } else {
                                &receipt.request_id
                            },
                            &mut port,
                            &mut verifier,
                            &mut current
                        )
                        .is_err()
                );
            }
            let result = control.dispatch_ordinary_display_current_commit(
                principal(),
                actor(true),
                &receipt.request_id,
                &mut port,
                &mut verifier,
                &mut current,
            );
            let dispatched = fault <= 2 || (18..=21).contains(&fault);
            assert_eq!(
                result.is_ok(),
                dispatched && fault != 1,
                "{action:?} current fault {fault}: {result:?}; stages {:?}",
                machine
                    .lock()
                    .unwrap_or_else(|_| unreachable!())
                    .journal_keys
                    .iter()
                    .filter(|(_, id)| id.as_str().contains("display-ordinary-current-"))
                    .collect::<Vec<_>>()
            );

            {
                let mut m = machine.lock().unwrap_or_else(|_| unreachable!());
                m.ordinary_current_fault = 0;
                m.ordinary_current_commit_store_fault = 0;
                if (5..=17).contains(&fault) {
                    assert!(
                        m.ordinary_current_commit_store_fault_hits > 0,
                        "intended publication fault was not reached: {action:?}/{fault}"
                    );
                }
                assert_eq!(m.ordinary_current_commit_calls, usize::from(dispatched));
            }
            assert!(
                control
                    .dispatch_ordinary_display_current_commit(
                        principal(),
                        actor(true),
                        &receipt.request_id,
                        &mut port,
                        &mut verifier,
                        &mut current
                    )
                    .is_err()
            );
            drop(control);
            let mut restarted =
                open_with_previews(database.path(), &machine, 0, previews_inner(&machine, true));
            assert!(
                restarted
                    .dispatch_ordinary_display_current_commit(
                        principal(),
                        actor(true),
                        &receipt.request_id,
                        &mut port,
                        &mut verifier,
                        &mut current
                    )
                    .is_err()
            );
            let qualified = restarted.verify_ordinary_display_qualified_current(
                principal(),
                &receipt.request_id,
                &mut port,
                &mut verifier,
            );
            assert_eq!(
                qualified.is_ok(),
                dispatched && fault != 2,
                "{action:?} qualified fault {fault}: {qualified:?}"
            );
            if let Ok(qualified) = qualified {
                assert_eq!(
                    qualified.inspection().power().current().release().state,
                    linura_transaction::TransactionState::Committed
                );
                let first = qualified.first_verified_at_unix_ms();
                let digest = qualified.record_digest().clone();
                let again = value(restarted.verify_ordinary_display_qualified_current(
                    principal(),
                    &receipt.request_id,
                    &mut port,
                    &mut verifier,
                ));
                assert_eq!(again.first_verified_at_unix_ms(), first);
                assert_eq!(again.record_digest(), &digest);
            }
            if (5..=17).contains(&fault) || fault == 22 {
                let signed = value(restarted.commit_ordinary_display_current(
                    principal(),
                    actor(true),
                    &receipt.request_id,
                    &mut port,
                    &mut verifier,
                ));
                assert_eq!(
                    signed.release().state,
                    linura_transaction::TransactionState::Committed
                );
                assert!(
                    restarted
                        .verify_ordinary_display_qualified_current(
                            principal(),
                            &receipt.request_id,
                            &mut port,
                            &mut verifier
                        )
                        .is_err()
                );
                assert!(
                    restarted
                        .dispatch_ordinary_display_current_commit(
                            principal(),
                            actor(true),
                            &receipt.request_id,
                            &mut port,
                            &mut verifier,
                            &mut current
                        )
                        .is_err()
                );
            }
            if fault == 0 {
                for changed in 1..=5 {
                    machine
                        .lock()
                        .unwrap_or_else(|_| unreachable!())
                        .ordinary_current_commit_grant_fault = changed;
                    assert!(
                        restarted
                            .verify_ordinary_display_qualified_current(
                                principal(),
                                &receipt.request_id,
                                &mut port,
                                &mut verifier
                            )
                            .is_err()
                    );
                }
                machine
                    .lock()
                    .unwrap_or_else(|_| unreachable!())
                    .ordinary_current_commit_grant_fault = 0;
                value(restarted.verify_ordinary_display_qualified_current(
                    principal(),
                    &receipt.request_id,
                    &mut port,
                    &mut verifier,
                ));
            }
            // Signed Committed without native qualification must still fence
            // every competitor, restart and cleanup/adoption entry point.
            assert!(
                restarted
                    .begin_display_layout(
                        principal(),
                        actor(true),
                        display_request("current-competing"),
                        &approval(),
                        &mut port,
                        &mut verifier
                    )
                    .is_err()
            );
            let (_, verify) = authority_material();
            let store = value(SqliteTransactionStore::open(
                database.path(),
                verify,
                value(SqliteIntegrityKey::new(fixture_key(5))),
            ));
            assert_eq!(
                value(linura_transaction::TransactionStore::snapshot(
                    &store,
                    &original_before.transaction_id
                )),
                original_before
            );
            let m = machine.lock().unwrap_or_else(|_| unreachable!());
            assert_eq!(
                (m.applies, m.decisions, m.ordinary_current_commit_calls),
                (1, 1, usize::from(dispatched))
            );
        }
    }
}

fn ordinary_root_power_requires_same_review_and_independent_absence() {
    for action in [
        DisplayContinuationAction::Confirm,
        DisplayContinuationAction::Revert,
    ] {
        for fault in 0..=13 {
            let database = TestDatabase::new();
            let machine = Arc::new(Mutex::new(Machine::default()));
            let mut port = Port(machine.clone());
            let mut verifier = Verifier(machine.clone());
            let original = display_request("ordinary-root-power-original");
            let mut control =
                open_with_previews(database.path(), &machine, 0, previews_inner(&machine, true));
            value(control.begin_display_layout(
                principal(),
                actor(true),
                original.clone(),
                &approval(),
                &mut port,
                &mut verifier,
            ));
            value(control.decide_display_layout(
                principal(),
                actor(true),
                &original.request_id,
                action,
                &Decision::approve(&machine),
                &mut port,
                &mut verifier,
            ));
            let before = value(control.inspect_ordinary_display_original(
                principal(),
                &original.request_id,
                &mut port,
                &mut verifier,
            ))
            .original_snapshot()
            .clone();
            machine
                .lock()
                .unwrap_or_else(|_| unreachable!())
                .ordinary_handoff_enabled = true;
            let receipt = value(control.begin_ordinary_display_release(
                principal(),
                actor(true),
                linura_control::OrdinaryDisplayReleaseRequest {
                    operation_id: "ordinary-root-power-release".into(),
                    original_request: original.request_id.clone(),
                    reason: original.reason.clone(),
                },
                &ReleaseApproval(machine.clone(), 0),
                &mut port,
                &mut verifier,
                &mut ReleasePort(machine.clone(), 0),
            ));
            value(control.dispatch_ordinary_display_completion(
                principal(),
                actor(true),
                &receipt.request_id,
                &mut port,
                &mut verifier,
                &mut CompletionPort(machine.clone(), false),
            ));
            let native = control.retire_ordinary_display_native_power(
                principal(),
                actor(true),
                &receipt.request_id,
                &mut port,
                &mut verifier,
                &mut OrdinaryPowerPort(machine.clone(), u8::from(fault == 12)),
            );
            assert_eq!(native.is_ok(), fault != 12);
            if fault == 3 {
                drop(control);
                control = open_with_previews(
                    database.path(),
                    &machine,
                    0,
                    previews_inner(&machine, true),
                );
            }
            {
                let mut m = machine.lock().unwrap_or_else(|_| unreachable!());
                if fault == 4 {
                    m.ordinary_current_fault = 6;
                }
                if (5..=8).contains(&fault) {
                    m.ordinary_root_power_store_fault = fault - 4;
                }
                if fault == 11 {
                    m.ordinary_native_power_retired = false;
                }
            }
            let mut root =
                OrdinaryRootPowerPort(machine.clone(), if fault <= 2 { fault } else { 0 });
            if fault == 9 || fault == 10 || fault == 13 {
                assert!(
                    control
                        .retire_ordinary_display_root_power(
                            if fault == 10 {
                                value(AuthenticatedPrincipal::new("unix:uid:1001"))
                            } else {
                                principal()
                            },
                            actor(fault != 9),
                            if fault == 13 {
                                &original.request_id
                            } else {
                                &receipt.request_id
                            },
                            &mut port,
                            &mut verifier,
                            &mut root
                        )
                        .is_err()
                );
            }
            let start = now_unix_ms();
            let result = control.retire_ordinary_display_root_power(
                principal(),
                actor(true),
                &receipt.request_id,
                &mut port,
                &mut verifier,
                &mut root,
            );
            let dispatched = fault <= 2 || fault == 9 || fault == 10 || fault >= 12;
            assert_eq!(
                result.is_ok(),
                dispatched && fault != 1,
                "{action:?} Root fault {fault}: {result:?}"
            );
            assert!(
                now_unix_ms().saturating_sub(start) < 1900,
                "Root fault must be tested before expiry {action:?}/{fault}"
            );
            {
                let mut m = machine.lock().unwrap_or_else(|_| unreachable!());
                m.ordinary_current_fault = 0;
                m.ordinary_root_power_store_fault = 0;
                m.ordinary_native_power_retired = true;
                assert_eq!(m.ordinary_root_power_calls, usize::from(dispatched));
            }
            assert!(
                control
                    .retire_ordinary_display_root_power(
                        principal(),
                        actor(true),
                        &receipt.request_id,
                        &mut port,
                        &mut verifier,
                        &mut root
                    )
                    .is_err()
            );
            drop(control);
            let mut restarted =
                open_with_previews(database.path(), &machine, 0, previews_inner(&machine, true));
            assert!(
                restarted
                    .retire_ordinary_display_root_power(
                        principal(),
                        actor(true),
                        &receipt.request_id,
                        &mut port,
                        &mut verifier,
                        &mut root
                    )
                    .is_err()
            );
            let post = restarted.inspect_ordinary_display_root_power_retirement(
                principal(),
                &receipt.request_id,
                &mut port,
                &mut verifier,
            );
            assert_eq!(
                post.is_ok(),
                dispatched && fault != 2,
                "{action:?} Root post {fault}: {post:?}"
            );
            if let Ok(post) = post {
                assert_eq!(
                    post.power().current().release().state,
                    linura_transaction::TransactionState::Indeterminate
                );
                assert!(!post.power().current().frames().power_fence_held());
            }
            if dispatched && fault != 2 {
                // Held-only consumers must refuse the now-retired Root phase.
                assert!(
                    restarted
                        .inspect_ordinary_display_original(
                            principal(),
                            &original.request_id,
                            &mut port,
                            &mut verifier
                        )
                        .is_err()
                );
                assert!(
                    restarted
                        .inspect_ordinary_display_native_power_retirement(
                            principal(),
                            &receipt.request_id,
                            &mut port,
                            &mut verifier
                        )
                        .is_err()
                );
            }
            if fault == 0 {
                for changed in 1..=6 {
                    machine
                        .lock()
                        .unwrap_or_else(|_| unreachable!())
                        .ordinary_root_power_read_fault = changed;
                    assert!(
                        restarted
                            .inspect_ordinary_display_root_power_retirement(
                                principal(),
                                &receipt.request_id,
                                &mut port,
                                &mut verifier
                            )
                            .is_err()
                    );
                }
                machine
                    .lock()
                    .unwrap_or_else(|_| unreachable!())
                    .ordinary_root_power_read_fault = 0;
                value(restarted.inspect_ordinary_display_root_power_retirement(
                    principal(),
                    &receipt.request_id,
                    &mut port,
                    &mut verifier,
                ));
            }
            assert!(
                restarted
                    .begin_display_layout(
                        principal(),
                        actor(true),
                        display_request("root-power-competing"),
                        &approval(),
                        &mut port,
                        &mut verifier
                    )
                    .is_err()
            );
            let (_, verify) = authority_material();
            let store = value(SqliteTransactionStore::open(
                database.path(),
                verify,
                value(SqliteIntegrityKey::new(fixture_key(5))),
            ));
            assert_eq!(
                value(linura_transaction::TransactionStore::snapshot(
                    &store,
                    &before.transaction_id
                )),
                before
            );
            let m = machine.lock().unwrap_or_else(|_| unreachable!());
            assert_eq!(
                (m.applies, m.decisions, m.ordinary_root_power_calls),
                (1, 1, usize::from(dispatched))
            );
        }
    }
}
fn ordinary_power_requires_original_review_and_independent_physical_postconditions() {
    for action in [
        DisplayContinuationAction::Confirm,
        DisplayContinuationAction::Revert,
    ] {
        for fault in 0..=13 {
            let database = TestDatabase::new();
            let machine = Arc::new(Mutex::new(Machine::default()));
            let mut port = Port(machine.clone());
            let mut verifier = Verifier(machine.clone());
            let original = display_request("ordinary-power-original");
            let mut control =
                open_with_previews(database.path(), &machine, 0, previews_inner(&machine, true));
            value(control.begin_display_layout(
                principal(),
                actor(true),
                original.clone(),
                &approval(),
                &mut port,
                &mut verifier,
            ));
            value(control.decide_display_layout(
                principal(),
                actor(true),
                &original.request_id,
                action,
                &Decision::approve(&machine),
                &mut port,
                &mut verifier,
            ));
            let original_before = value(control.inspect_ordinary_display_original(
                principal(),
                &original.request_id,
                &mut port,
                &mut verifier,
            ))
            .original_snapshot()
            .clone();
            machine
                .lock()
                .unwrap_or_else(|_| unreachable!())
                .ordinary_handoff_enabled = true;
            let receipt = value(control.begin_ordinary_display_release(
                principal(),
                actor(true),
                linura_control::OrdinaryDisplayReleaseRequest {
                    operation_id: "ordinary-power-release".into(),
                    original_request: original.request_id.clone(),
                    reason: original.reason.clone(),
                },
                &ReleaseApproval(machine.clone(), 0),
                &mut port,
                &mut verifier,
                &mut ReleasePort(machine.clone(), 0),
            ));
            let completion = control.dispatch_ordinary_display_completion(
                principal(),
                actor(true),
                &receipt.request_id,
                &mut port,
                &mut verifier,
                &mut CompletionPort(machine.clone(), fault == 12),
            );
            assert_eq!(completion.is_ok(), fault != 12);
            if fault == 3 {
                drop(control);
                control = open_with_previews(
                    database.path(),
                    &machine,
                    0,
                    previews_inner(&machine, true),
                );
            }
            {
                let mut m = machine.lock().unwrap_or_else(|_| unreachable!());
                if fault == 4 {
                    m.ordinary_current_fault = 6;
                }
                if (5..=8).contains(&fault) {
                    m.ordinary_power_store_fault = fault - 4;
                }
                if fault == 11 {
                    m.ordinary_input_pending = true;
                }
            }
            let mut power = OrdinaryPowerPort(
                machine.clone(),
                if fault == 1 {
                    1
                } else if fault == 2 {
                    2
                } else {
                    0
                },
            );
            if fault == 9 || fault == 10 || fault == 13 {
                assert!(
                    control
                        .retire_ordinary_display_native_power(
                            if fault == 10 {
                                value(AuthenticatedPrincipal::new("unix:uid:1001"))
                            } else {
                                principal()
                            },
                            actor(fault != 9),
                            if fault == 13 {
                                &original.request_id
                            } else {
                                &receipt.request_id
                            },
                            &mut port,
                            &mut verifier,
                            &mut power
                        )
                        .is_err()
                );
            }
            let start = now_unix_ms();
            let result = control.retire_ordinary_display_native_power(
                principal(),
                actor(true),
                &receipt.request_id,
                &mut port,
                &mut verifier,
                &mut power,
            );
            let dispatched = fault <= 2 || fault == 9 || fault == 10 || fault >= 12;
            assert_eq!(
                result.is_ok(),
                dispatched && fault != 1,
                "{action:?} power fault {fault}: {result:?}"
            );
            assert!(
                now_unix_ms().saturating_sub(start) < 1900,
                "fault must finish inside its independent original power window, not expire: {action:?}/{fault}"
            );
            {
                let mut m = machine.lock().unwrap_or_else(|_| unreachable!());
                m.ordinary_current_fault = 0;
                m.ordinary_power_store_fault = 0;
                m.ordinary_input_pending = false;
                assert_eq!(m.ordinary_power_calls, usize::from(dispatched));
            }
            assert!(
                control
                    .retire_ordinary_display_native_power(
                        principal(),
                        actor(true),
                        &receipt.request_id,
                        &mut port,
                        &mut verifier,
                        &mut power
                    )
                    .is_err()
            );
            drop(control);
            let mut restarted =
                open_with_previews(database.path(), &machine, 0, previews_inner(&machine, true));
            assert!(
                restarted
                    .retire_ordinary_display_native_power(
                        principal(),
                        actor(true),
                        &receipt.request_id,
                        &mut port,
                        &mut verifier,
                        &mut power
                    )
                    .is_err()
            );
            let post = restarted.inspect_ordinary_display_native_power_retirement(
                principal(),
                &receipt.request_id,
                &mut port,
                &mut verifier,
            );
            assert_eq!(
                post.is_ok(),
                dispatched && fault != 2,
                "{action:?} power post {fault}: {post:?}"
            );
            if let Ok(post) = post {
                assert!(
                    post.current().frames().input_retired()
                        && !post.current().frames().power_fence_held()
                );
                assert_eq!(
                    post.current().release().state,
                    linura_transaction::TransactionState::Indeterminate
                );
            }
            if fault == 0 {
                for changed in 1..=6 {
                    machine
                        .lock()
                        .unwrap_or_else(|_| unreachable!())
                        .ordinary_power_grant_fault = changed;
                    assert!(
                        restarted
                            .inspect_ordinary_display_native_power_retirement(
                                principal(),
                                &receipt.request_id,
                                &mut port,
                                &mut verifier
                            )
                            .is_err()
                    );
                }
                machine
                    .lock()
                    .unwrap_or_else(|_| unreachable!())
                    .ordinary_power_grant_fault = 0;
                value(restarted.inspect_ordinary_display_native_power_retirement(
                    principal(),
                    &receipt.request_id,
                    &mut port,
                    &mut verifier,
                ));
                assert!(
                    restarted
                        .begin_display_layout(
                            principal(),
                            actor(true),
                            display_request("power-competing"),
                            &approval(),
                            &mut port,
                            &mut verifier
                        )
                        .is_err()
                );
            }
            assert_eq!(
                value(restarted.inspect_ordinary_display_original(
                    principal(),
                    &original.request_id,
                    &mut port,
                    &mut verifier
                ))
                .original_snapshot(),
                &original_before
            );
            let m = machine.lock().unwrap_or_else(|_| unreachable!());
            assert_eq!(
                (
                    m.applies,
                    m.decisions,
                    m.ordinary_release_calls,
                    m.ordinary_completion_calls,
                    m.ordinary_power_calls
                ),
                (1, 1, 1, 1, usize::from(dispatched))
            );
        }
    }
}

fn final_digest(bytes: &[u8]) -> String {
    if let Ok(record) = linura_linux_session::NativeDisplayOrdinaryFinalPreparation::decode(bytes) {
        record.record_digest().to_hex()
    } else {
        value(linura_linux_session::NativeDisplayOrdinaryReleasedRecord::decode(bytes))
            .record_digest()
            .to_hex()
    }
}

fn observe_final(
    m: &mut Machine,
    resource: &ResourceId,
    capability: &CapabilityId,
) -> Result<ObservationEnvelope, ProviderError> {
    let fail = || ProviderError::Unavailable("simulated ordinary final unavailable".into());
    let bytes = m.ordinary_final_record.as_ref().ok_or_else(fail)?;
    let record = linura_linux_session::NativeDisplayOrdinaryFinalPreparation::decode(bytes)
        .map_err(|_| fail())?;
    let scope = record.frames().scope();
    if value(scope.resource_id()) != *resource {
        return Err(fail());
    }
    let completed = m.ordinary_released_record.as_ref().map(|bytes| {
        let r = value(linura_linux_session::NativeDisplayOrdinaryReleasedRecord::decode(bytes));
        linura_observation::DisplayReleasedCurrentLineage {
            record: final_digest(bytes),
            verification: r.verification_digest().to_hex(),
        }
    });
    let mut facts = value(
        linura_observation::DisplayOrdinaryFinalRetirementFacts::new(
            scope.clone(),
            record.frames().clone(),
            linura_observation::DisplayFinalRetirementLineage {
                record: final_digest(bytes),
                preparation: record.preparation_digest().to_hex(),
                verification: record.verification_digest().to_hex(),
                current_grant: record.parent().record_digest().to_hex(),
                committed_record: record.parent().committed_record_digest().to_hex(),
            },
            if completed.is_some() { 3 } else { 2 },
            completed,
        ),
    )
    .attributes();
    if m.ordinary_final_observation_fault == 1 {
        facts.insert(
            "verification_digest".into(),
            ObservedValue::Text("d".repeat(64)),
        );
    }
    if m.ordinary_final_observation_fault == 2 {
        facts.insert(
            "prepared.output.0.completed_commit".into(),
            ObservedValue::U64(u64::MAX),
        );
    }
    m.sequence += 1;
    Ok(ObservationEnvelope {
        provider: value(ProviderId::new(
            linura_observation::DISPLAY_RECOVERY_PROVIDER,
        )),
        capability: capability.clone(),
        resource: resource.clone(),
        authority: ObservationAuthority::NativeApi,
        sequence: m.sequence,
        observed_at_unix_ms: now_unix_ms(),
        valid_for_ms: 2000,
        attributes: facts,
    })
}
#[derive(Debug)]
struct OrdinaryFinalPort(Arc<Mutex<Machine>>, u8);
impl linura_control::OrdinaryDisplayFinalRetirementPort for OrdinaryFinalPort {
    fn retire_ordinary_current(
        &mut self,
        p: linura_control::AuthorizedOrdinaryDisplayFinalRetirement,
    ) -> Result<(), String> {
        let mut m = self.0.lock().unwrap_or_else(|_| unreachable!());
        assert_eq!(m.checked_history_reads, 0);
        assert_eq!(m.ordinary_final_calls, 0);
        assert!(
            m.ordinary_native_current_qualified
                && m.ordinary_root_power_retired
                && !m.ordinary_native_final_retired
        );
        assert!(
            now_unix_ms() >= p.frames().window().observed_unix_ms
                && now_unix_ms() < p.expires_at_unix_ms()
        );
        m.ordinary_final_calls += 1;
        let parent = value(
            linura_linux_session::NativeDisplayOrdinaryCurrentPreparation::decode(
                m.ordinary_current_commit_record
                    .as_ref()
                    .unwrap_or_else(|| unreachable!()),
            ),
        );
        let record = value(
            linura_linux_session::NativeDisplayOrdinaryFinalPreparation::new(
                &parent,
                value(linura_provider_sdk::ComponentDigest::parse_hex(
                    p.preparation().hex(),
                )),
                value(linura_provider_sdk::ComponentDigest::parse_hex(
                    p.qualification().hex(),
                )),
                p.frames(),
                p.expires_at_unix_ms(),
            ),
        );
        m.ordinary_final_record = Some(record.canonical_bytes());
        m.ordinary_native_final_retired = self.1 != 2;
        if self.1 == 1 {
            Err("simulated lost final ACK".into())
        } else {
            Ok(())
        }
    }
}
#[derive(Debug)]
struct OrdinaryReleasedPort(Arc<Mutex<Machine>>, u8);
impl linura_control::OrdinaryDisplayReleasedCurrentPort for OrdinaryReleasedPort {
    fn complete_ordinary_released_current(
        &mut self,
        p: linura_control::OrdinaryDisplayReleasedCurrentCompletion,
    ) -> Result<(), String> {
        let mut m = self.0.lock().unwrap_or_else(|_| unreachable!());
        assert_eq!(m.checked_history_reads, 0);
        assert!(m.ordinary_native_final_retired);
        m.ordinary_released_calls += 1;
        let bytes = m
            .ordinary_final_record
            .as_ref()
            .unwrap_or_else(|| unreachable!());
        let parent =
            value(linura_linux_session::NativeDisplayOrdinaryFinalPreparation::decode(bytes));
        assert_eq!(parent.frames().scope(), p.scope());
        assert_eq!(final_digest(bytes), p.final_record().to_hex());
        let record = value(
            linura_linux_session::NativeDisplayOrdinaryReleasedRecord::new(
                &parent,
                value(linura_provider_sdk::ComponentDigest::parse_hex(
                    p.verification().hex(),
                )),
                p.first_window(),
            ),
        );
        if self.1 != 2 {
            m.ordinary_released_record = Some(record.canonical_bytes());
        }
        if self.1 == 1 {
            Err("simulated lost ReleasedCurrent ACK".into())
        } else {
            Ok(())
        }
    }
}

fn ordinary_final_retirement_requires_matching_physical_and_durable_completion() {
    for action in [
        DisplayContinuationAction::Confirm,
        DisplayContinuationAction::Revert,
    ] {
        for fault in std::iter::once(18).chain(0..=17) {
            let database = TestDatabase::new();
            let machine = Arc::new(Mutex::new(Machine::default()));
            let mut port = Port(machine.clone());
            let mut verifier = Verifier(machine.clone());
            let original = display_request("ordinary-final-original");
            let mut control =
                open_with_previews(database.path(), &machine, 0, previews_inner(&machine, true));
            value(control.begin_display_layout(
                principal(),
                actor(true),
                original.clone(),
                &approval(),
                &mut port,
                &mut verifier,
            ));
            value(control.decide_display_layout(
                principal(),
                actor(true),
                &original.request_id,
                action,
                &Decision::approve(&machine),
                &mut port,
                &mut verifier,
            ));
            let original_before = value(control.inspect_ordinary_display_original(
                principal(),
                &original.request_id,
                &mut port,
                &mut verifier,
            ))
            .original_snapshot()
            .clone();
            machine
                .lock()
                .unwrap_or_else(|_| unreachable!())
                .ordinary_handoff_enabled = true;
            let receipt = value(control.begin_ordinary_display_release(
                principal(),
                actor(true),
                linura_control::OrdinaryDisplayReleaseRequest {
                    operation_id: "ordinary-final-release".into(),
                    original_request: original.request_id.clone(),
                    reason: original.reason.clone(),
                },
                &ReleaseApproval(machine.clone(), 0),
                &mut port,
                &mut verifier,
                &mut ReleasePort(machine.clone(), 0),
            ));
            value(control.dispatch_ordinary_display_completion(
                principal(),
                actor(true),
                &receipt.request_id,
                &mut port,
                &mut verifier,
                &mut CompletionPort(machine.clone(), false),
            ));
            value(control.retire_ordinary_display_native_power(
                principal(),
                actor(true),
                &receipt.request_id,
                &mut port,
                &mut verifier,
                &mut OrdinaryPowerPort(machine.clone(), 0),
            ));

            value(control.retire_ordinary_display_root_power(
                principal(),
                actor(true),
                &receipt.request_id,
                &mut port,
                &mut verifier,
                &mut OrdinaryRootPowerPort(machine.clone(), 0),
            ));
            value(control.dispatch_ordinary_display_current_commit(
                principal(),
                actor(true),
                &receipt.request_id,
                &mut port,
                &mut verifier,
                &mut OrdinaryCurrentPort(machine.clone(), 0),
            ));
            let signed = value(control.verify_ordinary_display_qualified_current(
                principal(),
                &receipt.request_id,
                &mut port,
                &mut verifier,
            ))
            .inspection()
            .power()
            .current()
            .release()
            .clone();
            assert_eq!(
                signed.state,
                linura_transaction::TransactionState::Committed
            );
            if fault == 3 {
                drop(control);
                control = open_with_previews(
                    database.path(),
                    &machine,
                    0,
                    previews_inner(&machine, true),
                );
            }
            if fault == 16 {
                for (who, human) in [
                    (principal(), actor(false)),
                    (
                        value(AuthenticatedPrincipal::new("dbus:uid:1001")),
                        actor(true),
                    ),
                ] {
                    assert!(
                        control
                            .dispatch_ordinary_display_final_retirement(
                                who,
                                human,
                                &receipt.request_id,
                                &mut port,
                                &mut verifier,
                                &mut OrdinaryFinalPort(machine.clone(), 0)
                            )
                            .is_err()
                    );
                }
            }
            if (5..=13).contains(&fault) {
                let mut m = machine.lock().unwrap_or_else(|_| unreachable!());
                m.ordinary_current_commit_store_phase = 6 + (fault - 5) / 3;
                m.ordinary_current_commit_store_fault = 1 + (fault - 5) % 3;
            }
            if fault == 18 {
                let mut m = machine.lock().unwrap_or_else(|_| unreachable!());
                m.ordinary_current_commit_store_phase = 6;
                m.ordinary_current_commit_store_fault = 4;
            }
            let final_ack = control.dispatch_ordinary_display_final_retirement(
                principal(),
                actor(true),
                &receipt.request_id,
                &mut port,
                &mut verifier,
                &mut OrdinaryFinalPort(
                    machine.clone(),
                    if fault == 1 {
                        1
                    } else if fault == 2 {
                        2
                    } else {
                        0
                    },
                ),
            );
            assert_eq!(
                final_ack.is_ok(),
                fault != 1 && fault != 3 && fault != 18 && !(5..=7).contains(&fault),
                "final dispatch {action:?}/{fault}"
            );
            if fault == 15 || fault == 17 {
                machine
                    .lock()
                    .unwrap_or_else(|_| unreachable!())
                    .ordinary_final_observation_fault = if fault == 15 { 1 } else { 2 };
            }
            let result = control.complete_ordinary_display_released_current(
                principal(),
                &receipt.request_id,
                &mut port,
                &mut verifier,
                &mut OrdinaryReleasedPort(
                    machine.clone(),
                    if fault == 14 {
                        1
                    } else if fault == 4 {
                        2
                    } else {
                        0
                    },
                ),
            );
            let success = matches!(fault, 0 | 1 | 16);
            assert_eq!(
                result.is_ok(),
                success,
                "completion {action:?}/{fault}: {error:?}",
                error = result.as_ref().err()
            );
            let first_complete = result
                .as_ref()
                .ok()
                .map(|v| (v.record_digest().clone(), v.verification().first_window()));
            if let Ok(completed) = result {
                assert_eq!(completed.verification().root().phase(), 3);
                assert_eq!(
                    completed
                        .verification()
                        .qualified()
                        .inspection()
                        .power()
                        .current()
                        .release(),
                    &signed
                );
            }
            {
                let mut m = machine.lock().unwrap_or_else(|_| unreachable!());
                if (5..=13).contains(&fault) || fault == 18 {
                    assert!(
                        m.ordinary_current_commit_store_fault_hits > 0,
                        "targeted final fault not reached {action:?}/{fault}"
                    );
                }
                m.ordinary_current_commit_store_fault = 0;
                m.ordinary_final_observation_fault = 0;
                m.ordinary_current_fault = 0;
            }
            drop(control);
            let mut restarted =
                open_with_previews(database.path(), &machine, 0, previews_inner(&machine, true));
            assert!(
                restarted
                    .dispatch_ordinary_display_final_retirement(
                        principal(),
                        actor(true),
                        &receipt.request_id,
                        &mut port,
                        &mut verifier,
                        &mut OrdinaryFinalPort(machine.clone(), 0)
                    )
                    .is_err()
            );
            if fault != 2 && fault != 3 && fault != 18 && !(5..=7).contains(&fault) {
                let completed = value(restarted.complete_ordinary_display_released_current(
                    principal(),
                    &receipt.request_id,
                    &mut port,
                    &mut verifier,
                    &mut OrdinaryReleasedPort(machine.clone(), 0),
                ));
                assert_eq!(
                    completed
                        .verification()
                        .qualified()
                        .inspection()
                        .power()
                        .current()
                        .release(),
                    &signed
                );
                if let Some((record, window)) = &first_complete {
                    assert_eq!(completed.record_digest(), record);
                    assert_eq!(&completed.verification().first_window(), window);
                }
                if fault == 0 {
                    let again = value(restarted.complete_ordinary_display_released_current(
                        principal(),
                        &receipt.request_id,
                        &mut port,
                        &mut verifier,
                        &mut OrdinaryReleasedPort(machine.clone(), 0),
                    ));
                    assert_eq!(again.record_digest(), completed.record_digest());
                    assert_eq!(
                        again.verification().first_window(),
                        completed.verification().first_window()
                    );
                }
            }
            let (_, verify) = authority_material();
            let store = value(SqliteTransactionStore::open(
                database.path(),
                verify,
                value(SqliteIntegrityKey::new(fixture_key(5))),
            ));
            assert_eq!(
                value(linura_transaction::TransactionStore::snapshot(
                    &store,
                    &original_before.transaction_id
                )),
                original_before
            );
            assert!(
                restarted
                    .begin_display_layout(
                        principal(),
                        actor(true),
                        display_request("ordinary-final-competing"),
                        &approval(),
                        &mut port,
                        &mut verifier
                    )
                    .is_err()
            );
            let m = machine.lock().unwrap_or_else(|_| unreachable!());
            assert_eq!(m.ordinary_current_commit_calls, 1);
            assert_eq!(
                m.ordinary_final_calls,
                usize::from(fault != 3 && fault != 18 && !(5..=7).contains(&fault))
            );
            assert_eq!(m.applies, 1);
        }
    }
}
