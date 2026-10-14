//! Deterministic authority/lifecycle fixtures, NOT real logind, PAM, kernel
//! suspend, compositor or production qualification evidence.

use super::s17_managed_lock::{lock_id, lock_observation, session_observation};
use super::*;
use linura_control::{ManagedApprovalAuthorizer, ManagedApprovalChallenge};
use linura_core::{SessionTransition, SessionTransitionId};

#[derive(Debug, Default)]
struct Facts {
    completed: bool,
    secure: bool,
    blockers: u64,
    other_sessions: u64,
    permission: String,
    provider_claim: bool,
    drift_on_approval: bool,
    suppress_completion: bool,
    approvals: u64,
    dispatches: u64,
}

type SharedFacts = Arc<Mutex<Facts>>;

fn facts() -> SharedFacts {
    Arc::new(Mutex::new(Facts {
        secure: true,
        permission: "yes".into(),
        ..Facts::default()
    }))
}

struct PowerObserver {
    target: SessionTransitionId,
    provider: &'static str,
    facts: SharedFacts,
    sequence: AtomicU64,
}

impl PowerObserver {
    fn capabilities(&self) -> &[&str] {
        match self.provider {
            "logind" => &[
                "session.transition.observe",
                "session.epoch.observe",
                "session.power.conditions.observe",
            ],
            "polkit" => &["session.power.permission.observe"],
            "session-locker" => &["session.secure-lock.observe"],
            _ => unreachable!("fixed fixture provider"),
        }
    }
}

impl Observer for PowerObserver {
    fn observer_id(&self) -> ProviderId {
        value(ProviderId::new(self.provider))
    }
    fn observation_capabilities(&self) -> Vec<Capability> {
        self.capabilities()
            .iter()
            .map(|id| Capability {
                id: value(CapabilityId::new(*id)),
                provider: Some(self.observer_id()),
                support: SupportLevel::Supported,
                reason: None,
            })
            .collect()
    }
    fn health(&self) -> ProviderHealth {
        ProviderHealth {
            provider: self.observer_id(),
            availability: ProviderAvailability::Available,
            reason: None,
        }
    }
    fn resources(&self) -> Result<Vec<ResourceId>, ProviderError> {
        Ok(vec![value(self.target.resource_id())])
    }
    fn observe_authoritative(
        &self,
        resource: &ResourceId,
        capability: &CapabilityId,
    ) -> Result<ObservationEnvelope, ProviderError> {
        if !self.capabilities().contains(&capability.as_str()) {
            return Err(ProviderError::Unsupported(
                "fixture capability mismatch".into(),
            ));
        }
        let facts = self
            .facts
            .lock()
            .map_err(|_| ProviderError::Internal("fixture poisoned".into()))?;
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed) + 1;
        let mut observation = match capability.as_str() {
            "session.secure-lock.observe" => lock_observation(facts.secure, sequence),
            "session.epoch.observe" | "session.power.conditions.observe" => {
                session_observation(sequence)
            }
            _ => ObservationEnvelope {
                provider: self.observer_id(),
                capability: capability.clone(),
                resource: value(if self.provider == "polkit" {
                    self.target.permission_resource_id()
                } else {
                    self.target.resource_id()
                }),
                authority: ObservationAuthority::NativeApi,
                observed_at_unix_ms: now_unix_ms(),
                valid_for_ms: 2_000,
                sequence,
                attributes: BTreeMap::new(),
            },
        };
        observation.capability = capability.clone();
        match capability.as_str() {
            "session.transition.observe" => {
                let ended_boot = facts.completed
                    && matches!(
                        self.target.transition(),
                        SessionTransition::Reboot | SessionTransition::PowerOff
                    );
                observation.attributes.extend([
                    (
                        "current_boot_id".into(),
                        ObservedValue::Text(if ended_boot {
                            "abcd1234-1234-4567-89ab-0123456789ac".into()
                        } else {
                            self.target.lock().epoch().boot().as_str().into()
                        }),
                    ),
                    (
                        "target_epoch_present".into(),
                        ObservedValue::Bool(
                            !facts.completed
                                || matches!(
                                    self.target.transition(),
                                    SessionTransition::Suspend { .. }
                                ),
                        ),
                    ),
                    (
                        "successful_suspend_cycles".into(),
                        ObservedValue::U64(10 + u64::from(facts.completed)),
                    ),
                    (
                        "suspend_test_mode".into(),
                        ObservedValue::Text("none".into()),
                    ),
                    ("preparing_for_sleep".into(), ObservedValue::Bool(false)),
                    // A malicious provider completion assertion is ignored.
                    (
                        "completed".into(),
                        ObservedValue::Bool(facts.provider_claim),
                    ),
                ]);
            }
            "session.power.conditions.observe" => observation.attributes.extend([
                ("preparing_for_sleep".into(), ObservedValue::Bool(false)),
                ("preparing_for_shutdown".into(), ObservedValue::Bool(false)),
                (
                    "sleep_block_count".into(),
                    ObservedValue::U64(facts.blockers),
                ),
                (
                    "shutdown_block_count".into(),
                    ObservedValue::U64(facts.blockers),
                ),
                ("sleep_delay_count".into(), ObservedValue::U64(1)),
                ("shutdown_delay_count".into(), ObservedValue::U64(1)),
                ("inhibit_delay_max_us".into(), ObservedValue::U64(5_000_000)),
                (
                    "other_user_session_count".into(),
                    ObservedValue::U64(facts.other_sessions),
                ),
            ]),
            "session.power.permission.observe" => observation.attributes.extend([
                (
                    "permission_query_principal".into(),
                    ObservedValue::Text("unix:uid:1000".into()),
                ),
                (
                    "permission_query_session_epoch".into(),
                    ObservedValue::Text(
                        value(self.target.lock().epoch().resource_id())
                            .as_str()
                            .into(),
                    ),
                ),
                (
                    "availability".into(),
                    ObservedValue::Text(facts.permission.clone()),
                ),
            ]),
            _ => {}
        }
        if &observation.resource != resource {
            return Err(ProviderError::Unsupported(
                "fixture resource mismatch".into(),
            ));
        }
        Ok(observation)
    }
}

fn target(action: SessionTransition) -> SessionTransitionId {
    value(SessionTransitionId::new(lock_id(), action))
}

fn power_request(action: SessionTransition, operation: &str) -> PlanDesiredStateRequest {
    let mut request = request(operation, "inactive");
    request.provider = value(ProviderId::new("logind"));
    request.resource = value(target(action).resource_id());
    request.observation_capability = value(CapabilityId::new("session.transition.observe"));
    request.desired_state = BTreeMap::from([("completed".into(), "true".into())]);
    request.reason.summary = format!("S17 {} fixture", action.as_str());
    request.request_id = value(managed_request_id(operation, &request));
    request
}

fn previews(action: SessionTransition, facts: &SharedFacts) -> PlanPreviewControl {
    let mut coordinator = ObservationCoordinator::new();
    for provider in ["logind", "session-locker", "polkit"] {
        value(coordinator.register_observer(Box::new(PowerObserver {
            target: target(action),
            provider,
            facts: facts.clone(),
            sequence: AtomicU64::new(0),
        })));
    }
    PlanPreviewControl::new(coordinator)
}

fn open_power_control(
    database: &Path,
    action: SessionTransition,
    facts: &SharedFacts,
) -> ManagedLifecycleControl<SqliteTransactionStore> {
    let (signer, verifier) = authority_material();
    let store = value(SqliteTransactionStore::open(
        database,
        verifier,
        value(SqliteIntegrityKey::new(vec![0x52; 32])),
    ));
    value(
        value(ManagedLifecycleControl::new(
            previews(action, facts),
            store,
            signer,
        ))
        .with_request_journal(Box::new(value(
            linura_persistence_sqlite::SqliteApprovedRequestJournal::open(
                database.with_extension("requests.sqlite3"),
                value(SqliteIntegrityKey::new(vec![0x53; 32])),
            ),
        ))),
    )
}

#[derive(Debug)]
struct PowerApproval {
    facts: SharedFacts,
}
impl ManagedApprovalAuthorizer for PowerApproval {
    fn authorize(
        &self,
        challenge: &ManagedApprovalChallenge,
    ) -> Result<TrustedHumanApproval, String> {
        let target =
            SessionTransitionId::from_resource(challenge.resource()).map_err(|e| e.to_string())?;
        assert_eq!(challenge.change_key(), "completed");
        assert_eq!(challenge.desired_value(), "true");
        assert_eq!(
            challenge.approval_class(),
            if matches!(target.transition(), SessionTransition::Suspend { .. }) {
                linura_control::ManagedApprovalClass::Administrator
            } else {
                linura_control::ManagedApprovalClass::DestructiveAction
            }
        );
        let mut facts = self.facts.lock().map_err(|_| "fixture poisoned")?;
        facts.approvals += 1;
        if facts.drift_on_approval {
            facts.blockers = 1;
        }
        Ok(TrustedHumanApproval::from_authorized_challenge(
            challenge.principal().clone(),
            challenge,
        ))
    }
}

#[derive(Debug)]
struct PowerExecutor {
    facts: SharedFacts,
    ambiguous: bool,
}
impl AuthorizedEffectExecutor for PowerExecutor {
    fn execute_authorized(
        &mut self,
        authorization: AuthorizedEffect,
    ) -> Result<ExecutionOutcome, String> {
        let (effect, binding) = authorization.into_executor_request();
        assert_eq!(effect.provider.as_str(), "logind");
        assert_eq!(effect.operation, "execute-session-transition");
        assert_eq!(
            effect.canonical_payload,
            format!("transition={}\n", effect.resource.as_str()).as_bytes()
        );
        value(binding.validate_for(&effect));
        let mut facts = self.facts.lock().map_err(|_| "fixture poisoned")?;
        facts.dispatches += 1;
        if self.ambiguous {
            return Err("simulated reply loss after durable handoff".into());
        }
        facts.completed = !facts.suppress_completion;
        ExecutionOutcome::new(
            ExecutionDisposition::Dispatched,
            binding.dispatch_digest,
            "fixture dispatch acknowledgement only",
        )
        .map_err(|e| e.to_string())
    }
}

const ACTIONS: [SessionTransition; 4] = [
    SessionTransition::Suspend {
        successful_cycles_before: 10,
    },
    SessionTransition::Logout,
    SessionTransition::Reboot,
    SessionTransition::PowerOff,
];

#[test]
fn verifier_success_cannot_commit_or_reprepare_when_control_native_state_disagrees() {
    for action in ACTIONS {
        let database = TestDatabase::new();
        let facts = facts();
        value(facts.lock()).suppress_completion = true;
        let mut control = open_power_control(database.path(), action, &facts);
        let request = power_request(action, "disputed-completion");
        let authorizer = PowerApproval {
            facts: facts.clone(),
        };
        let mut executor = PowerExecutor {
            facts: facts.clone(),
            ambiguous: false,
        };
        let mut verifier = ScriptedVerifier::new(
            (0..6).map(|_| VerifierStep::Outcome(VerificationDisposition::Satisfied)),
        );
        assert!(
            control
                .converge_session_transition(
                    principal(),
                    actor(true),
                    request.clone(),
                    &authorizer,
                    &mut executor,
                    &mut verifier
                )
                .is_err()
        );
        // Explicit and ordinary recovery both remain observe-only, even with
        // a compromised verifier reporting satisfied. No new approval/use.
        assert!(
            control
                .recover_session_request_without_replay(
                    principal(),
                    actor(true),
                    &request.request_id,
                    &mut verifier
                )
                .is_err()
        );
        assert!(
            control
                .converge_session_transition(
                    principal(),
                    actor(true),
                    request,
                    &authorizer,
                    &mut executor,
                    &mut verifier
                )
                .is_err()
        );
        let facts = value(facts.lock());
        assert_eq!((facts.approvals, facts.dispatches), (1, 1));
    }
}

#[test]
fn foreign_and_root_principals_cannot_authorize_or_recover_power_intent() {
    for who in ["unix:uid:0", "unix:uid:1001"] {
        let database = TestDatabase::new();
        let facts = facts();
        let mut control = open_power_control(database.path(), ACTIONS[0], &facts);
        let request = power_request(ACTIONS[0], "foreign-power");
        let mut executor = PowerExecutor {
            facts: facts.clone(),
            ambiguous: false,
        };
        let mut verifier = ScriptedVerifier::new([]);
        let foreign = value(AuthenticatedPrincipal::new(who));
        assert!(
            control
                .converge_session_transition(
                    foreign.clone(),
                    actor(true),
                    request.clone(),
                    &PowerApproval {
                        facts: facts.clone()
                    },
                    &mut executor,
                    &mut verifier
                )
                .is_err()
        );
        assert!(
            control
                .recover_session_request_without_replay(
                    foreign,
                    actor(true),
                    &request.request_id,
                    &mut verifier
                )
                .is_err()
        );
        let facts = value(facts.lock());
        assert_eq!((facts.approvals, facts.dispatches), (0, 0));
        assert_eq!(verifier.calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn canonical_power_intent_cannot_downgrade_to_lock_audio_or_systemd_routes() {
    for mutation in ["provider", "capability", "key", "desired", "extra-key"] {
        let database = TestDatabase::new();
        let facts = facts();
        let mut control = open_power_control(database.path(), ACTIONS[0], &facts);
        let mut request = power_request(ACTIONS[0], "downgraded-power");
        match mutation {
            "provider" => request.provider = value(ProviderId::new("pipewire")),
            "capability" => {
                request.observation_capability = value(CapabilityId::new("audio.session.observe"))
            }
            "key" => request.desired_state = BTreeMap::from([("secure".into(), "false".into())]),
            "desired" => {
                request
                    .desired_state
                    .insert("completed".into(), "false".into());
            }
            _ => {
                request.desired_state.insert("force".into(), "true".into());
            }
        }
        request.request_id = value(managed_request_id("downgraded-power", &request));
        let mut executor = PowerExecutor {
            facts: facts.clone(),
            ambiguous: false,
        };
        let mut verifier = ScriptedVerifier::new([]);
        assert!(
            control
                .converge_session_transition(
                    principal(),
                    actor(true),
                    request,
                    &PowerApproval {
                        facts: facts.clone()
                    },
                    &mut executor,
                    &mut verifier
                )
                .is_err()
        );
        let facts = value(facts.lock());
        assert_eq!((facts.approvals, facts.dispatches), (0, 0));
    }
}

#[test]
fn all_power_actions_use_exact_policy_durable_stages_and_independent_completion() {
    for action in ACTIONS {
        let database = TestDatabase::new();
        let facts = facts();
        let mut control = open_power_control(database.path(), action, &facts);
        let request = power_request(action, "complete-power");
        let authorizer = PowerApproval {
            facts: facts.clone(),
        };
        let mut executor = PowerExecutor {
            facts: facts.clone(),
            ambiguous: false,
        };
        let mut verifier = ScriptedVerifier::new(
            (0..8).map(|_| VerifierStep::Outcome(VerificationDisposition::Satisfied)),
        );
        let receipt = value(control.converge_session_transition(
            principal(),
            actor(true),
            request.clone(),
            &authorizer,
            &mut executor,
            &mut verifier,
        ));
        assert_complete(&receipt);
        assert_eq!(receipt.change_key, "completed");
        assert_eq!(receipt.desired_value, "true");
        let status =
            value(control.session_transition_request_status(&principal(), &request.request_id));
        assert_eq!(status.state, "committed");
        assert_eq!(status.target, target(action));
        assert!(
            control
                .session_lock_request_status(&principal(), &request.request_id)
                .is_err()
        );
        assert_eq!(
            value(control.retained_session_request(&principal(), &request.request_id)),
            request
        );
        value(control.converge_session_transition(
            principal(),
            actor(true),
            request,
            &authorizer,
            &mut executor,
            &mut verifier,
        ));
        let facts = value(facts.lock());
        assert_eq!(facts.approvals, 1);
        assert_eq!(facts.dispatches, 1);
    }
}

#[test]
fn inhibitors_other_sessions_missing_permission_and_uncovered_outputs_stop_before_approval() {
    for denial in ["blocker", "other-session", "permission", "coverage"] {
        let database = TestDatabase::new();
        let facts = facts();
        {
            let mut changed = value(facts.lock());
            match denial {
                "blocker" => changed.blockers = 1,
                "other-session" => changed.other_sessions = 1,
                "permission" => changed.permission = "no".into(),
                _ => changed.secure = false,
            }
        }
        let action = ACTIONS[0];
        let mut control = open_power_control(database.path(), action, &facts);
        let mut executor = PowerExecutor {
            facts: facts.clone(),
            ambiguous: false,
        };
        let mut verifier = ScriptedVerifier::new([]);
        assert!(
            control
                .converge_session_transition(
                    principal(),
                    actor(true),
                    power_request(action, "denied-power"),
                    &PowerApproval {
                        facts: facts.clone()
                    },
                    &mut executor,
                    &mut verifier
                )
                .is_err()
        );
        let facts = value(facts.lock());
        assert_eq!((facts.approvals, facts.dispatches), (0, 0));
    }
}

#[test]
fn new_inhibitor_during_admin_authentication_invalidates_approval_before_handoff() {
    let database = TestDatabase::new();
    let facts = facts();
    value(facts.lock()).drift_on_approval = true;
    let mut control = open_power_control(database.path(), ACTIONS[0], &facts);
    let mut executor = PowerExecutor {
        facts: facts.clone(),
        ambiguous: false,
    };
    let mut verifier = ScriptedVerifier::new([]);
    assert!(
        control
            .converge_session_transition(
                principal(),
                actor(true),
                power_request(ACTIONS[0], "approval-drift"),
                &PowerApproval {
                    facts: facts.clone()
                },
                &mut executor,
                &mut verifier
            )
            .is_err()
    );
    let facts = value(facts.lock());
    assert_eq!((facts.approvals, facts.dispatches), (1, 0));
}

#[test]
fn provider_completed_boolean_cannot_replace_control_postcondition_derivation() {
    let facts = facts();
    value(facts.lock()).provider_claim = true;
    let mut control = previews(ACTIONS[0], &facts);
    let preview = value(control.plan_desired_state(
        principal(),
        actor(true),
        power_request(ACTIONS[0], "forged-completion"),
    ));
    assert_eq!(
        preview.status,
        linura_protocol::PlanPreviewStatus::ChangeProposed
    );
    assert!(
        preview
            .changes
            .iter()
            .any(|change| change.key == "completed" && change.current.as_deref() == Some("false"))
    );
    assert!(!preview.execution_authorized);
}

#[test]
fn restart_and_ordinary_retry_never_replay_an_ambiguous_power_operation() {
    for action in ACTIONS {
        let database = TestDatabase::new();
        let facts = facts();
        let request = power_request(action, "ambiguous-power");
        let authorizer = PowerApproval {
            facts: facts.clone(),
        };
        let mut executor = PowerExecutor {
            facts: facts.clone(),
            ambiguous: true,
        };
        let mut verifier =
            ScriptedVerifier::new([VerifierStep::Outcome(VerificationDisposition::NotSatisfied)]);
        {
            let mut control = open_power_control(database.path(), action, &facts);
            assert!(
                control
                    .converge_session_transition(
                        principal(),
                        actor(true),
                        request.clone(),
                        &authorizer,
                        &mut executor,
                        &mut verifier
                    )
                    .is_err()
            );
        }
        let mut control = open_power_control(database.path(), action, &facts);
        assert!(
            control
                .converge_session_transition(
                    principal(),
                    actor(true),
                    request.clone(),
                    &authorizer,
                    &mut executor,
                    &mut verifier
                )
                .is_err()
        );
        {
            let mut facts = value(facts.lock());
            assert_eq!((facts.approvals, facts.dispatches), (1, 1));
            facts.completed = true;
        }
        let mut verifier = ScriptedVerifier::new(
            (0..4).map(|_| VerifierStep::Outcome(VerificationDisposition::Satisfied)),
        );
        let receipt = value(control.converge_session_transition(
            principal(),
            actor(true),
            request,
            &authorizer,
            &mut executor,
            &mut verifier,
        ));
        assert!(receipt.recovered);
        let facts = value(facts.lock());
        assert_eq!((facts.approvals, facts.dispatches), (1, 1));
    }
}
