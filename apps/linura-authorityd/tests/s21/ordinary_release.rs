//! Real Control/SQLite with simulated native sources; no physical qualification.
use super::*;

// Explicitly simulated Root/native first-frame sources. They exercise the
// real Control join and SQLite restart, never physical compositor qualification.
pub(super) fn observe_handoff(
    m: &mut Machine,
    resource: &ResourceId,
    capability: &CapabilityId,
) -> Result<ObservationEnvelope, ProviderError> {
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
        value(DisplayOrdinaryReleaseFacts::new(
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
        ))
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
        value(DisplayOrdinaryHandoffFacts::new(
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
        ))
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
    for (action, storage_fault) in [
        (DisplayContinuationAction::Confirm, None),
        (DisplayContinuationAction::Revert, None),
        (DisplayContinuationAction::Confirm, Some(0)),
        (DisplayContinuationAction::Confirm, Some(1)),
        (DisplayContinuationAction::Confirm, Some(2)),
    ] {
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
        if let Some(fault) = storage_fault {
            drop(control);
            machine
                .lock()
                .unwrap_or_else(|_| unreachable!())
                .ordinary_release_write_fault = fault;
            control =
                open_with_previews(database.path(), &machine, 1, previews_inner(&machine, true));
            // Failure before write, a false persistence ACK, and a durable
            // write followed by a lost ACK cannot manufacture verification.
            assert!(
                control
                    .verify_ordinary_display_handoff(
                        principal(),
                        &receipt.request_id,
                        &mut port,
                        &mut verifier
                    )
                    .is_err()
            );
            drop(control);
            machine
                .lock()
                .unwrap_or_else(|_| unreachable!())
                .ordinary_release_write_fault = 0;
            control =
                open_with_previews(database.path(), &machine, 0, previews_inner(&machine, true));
        }
        let inspection = value(control.inspect_ordinary_display_handoff(
            principal(),
            &receipt.request_id,
            &mut port,
            &mut verifier,
        ));
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
        let proof = value(control.verify_ordinary_display_handoff(
            principal(),
            &receipt.request_id,
            &mut port,
            &mut verifier,
        ));
        assert!(proof.first_verified_unix_ms() < proof.first_valid_until_unix_ms());
        drop(control);
        let mut control =
            open_with_previews(database.path(), &machine, 0, previews_inner(&machine, true));
        let inspected = value(control.inspect_ordinary_display_handoff(
            principal(),
            &receipt.request_id,
            &mut port,
            &mut verifier,
        ));
        assert_eq!(inspected.release(), inspection.release());
        assert!(inspected.frames().reconciles(inspection.frames()));
        let recovered = value(control.verify_ordinary_display_handoff(
            principal(),
            &receipt.request_id,
            &mut port,
            &mut verifier,
        ));
        assert_eq!(recovered.record_digest(), proof.record_digest());
        assert_eq!(
            recovered.first_verified_unix_ms(),
            proof.first_verified_unix_ms()
        );
        assert_eq!(
            recovered.first_valid_until_unix_ms(),
            proof.first_valid_until_unix_ms()
        );
        machine
            .lock()
            .unwrap_or_else(|_| unreachable!())
            .ordinary_handoff_fault = 14;
        // Two mutually consistent fresh reads still cannot replace the first
        // durably verified frame with a later completed commit after restart.
        assert!(
            control
                .inspect_ordinary_display_handoff(
                    principal(),
                    &receipt.request_id,
                    &mut port,
                    &mut verifier
                )
                .is_ok()
        );
        assert!(
            control
                .verify_ordinary_display_handoff(
                    principal(),
                    &receipt.request_id,
                    &mut port,
                    &mut verifier
                )
                .is_err()
        );
        for fault in 1..=13 {
            {
                let mut m = machine.lock().unwrap_or_else(|_| unreachable!());
                m.ordinary_handoff_fault = fault;
                m.ordinary_handoff_reads = 0;
            }
            assert!(
                control
                    .inspect_ordinary_display_handoff(
                        principal(),
                        &receipt.request_id,
                        &mut port,
                        &mut verifier
                    )
                    .is_err(),
                "fault {fault}"
            );
        }
        {
            let mut m = machine.lock().unwrap_or_else(|_| unreachable!());
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
    drop(restarted);
    let mut restarted =
        open_with_previews(database.path(), &machine, 0, previews_inner(&machine, true));
    assert_eq!(
        value(restarted.begin_ordinary_display_release(
            principal(),
            actor(true),
            input,
            &ReleaseApproval(machine.clone(), 1),
            &mut port,
            &mut verifier,
            &mut release_port,
        )),
        receipt
    );
    let m = machine.lock().unwrap_or_else(|_| unreachable!());
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
