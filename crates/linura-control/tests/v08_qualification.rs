use std::collections::{BTreeSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use linura_agent_runtime::AgentRuntime;
use linura_control::{
    AcceptProposalRequest, AdapterHealth, AuthenticatedPrincipal, AuthorityValidityContributor,
    ControlAuthorityClock, ControlInterpretationEngine, ControlProposalAuthority,
    InterpretationControlError, InterpretationInvocation, InterpretationSessionBudget,
    InterpretationWork, ProposalAcceptanceControl, ProposalAcceptanceControlError,
    ProposalDecisionIssueRequest, RawSemanticEntry, RawSemanticProjection, RawSemanticValue,
};
use linura_core::{Actor, ActorId, ActorKind, IntentId, ProviderId, RequestId, ValidationError};
use linura_intent::{
    IntentProposal, IntentStatus, InterpretationContextBinding, ProposalAttribution, ProposalDigest,
};
use linura_library::{AcceptanceLinearizationClock, LocalLibrary, ProposalAcceptanceTarget};
use linura_provider_sdk::{
    AdapterDescriptor, CapabilitylessInterpretationAdapter, NetworkAccess,
    PreparedProviderInvocation, ProviderInvocationDeadline, ProviderInvocationOutcome,
    ProviderInvocationTransport, ProviderResponseBudget,
};
use linura_transaction::TransactionAuthorityKey;

fn id<T>(value: Result<T, ValidationError>) -> T {
    value.unwrap_or_else(|error| unreachable!("{error}"))
}

fn actor() -> Actor {
    Actor {
        id: id(ActorId::new("uid:1000")),
        kind: ActorKind::Human,
        interactive: true,
    }
}

fn descriptor(
    adapter_id: &str,
    provider_id: &str,
    network_access: NetworkAccess,
) -> AdapterDescriptor {
    AdapterDescriptor {
        provider: id(ProviderId::new(provider_id)),
        adapter_id: adapter_id.into(),
        endpoint_class: "interpretation".into(),
        protocol_version: 1,
        network_access,
    }
}

fn adapter(descriptor: AdapterDescriptor) -> CapabilitylessInterpretationAdapter {
    CapabilitylessInterpretationAdapter::new(
        descriptor,
        vec![],
        vec![],
        Some("deterministic-mock".into()),
    )
    .unwrap_or_else(|error| unreachable!("{error}"))
}

fn work() -> InterpretationWork {
    let projection = RawSemanticProjection {
        entries: vec![
            RawSemanticEntry {
                key: "goal".into(),
                value: RawSemanticValue::PublicText("reproducible workstation".into()),
            },
            RawSemanticEntry {
                key: "credential".into(),
                value: RawSemanticValue::Secret {
                    value: "V08-SECRET-CANARY".into(),
                    protected_reference: Some("secret:provider-key".into()),
                },
            },
        ],
    }
    .minimize()
    .unwrap_or_else(|error| unreachable!("{error}"));
    InterpretationWork {
        request_id: id(RequestId::new("interpretation:v08:qualification")),
        actor: actor(),
        context: InterpretationContextBinding::new(
            "authority:v08:qualification",
            projection.digest(),
            vec![],
        )
        .unwrap_or_else(|error| unreachable!("{error}")),
        projection,
        capability_refs: vec![],
    }
}

struct SequenceTransport {
    calls: Arc<AtomicUsize>,
    outcomes: VecDeque<ProviderInvocationOutcome>,
}

impl SequenceTransport {
    fn new(calls: Arc<AtomicUsize>, outcomes: Vec<ProviderInvocationOutcome>) -> Self {
        Self {
            calls,
            outcomes: outcomes.into(),
        }
    }
}

impl ProviderInvocationTransport for SequenceTransport {
    fn invoke_once(
        &mut self,
        _invocation: &PreparedProviderInvocation,
        deadline: ProviderInvocationDeadline,
        response_budget: ProviderResponseBudget,
    ) -> ProviderInvocationOutcome {
        assert!(deadline.deadline_unix_ms() > 0);
        assert!(deadline.remaining_ms() > 0);
        assert!(response_budget.max_bytes() > 0);
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.outcomes.pop_front().unwrap_or_else(|| {
            ProviderInvocationOutcome::TransportFailure("qualification outcome exhausted".into())
        })
    }
}

#[test]
fn capabilityless_provider_path_yields_only_a_valid_proposal_and_hides_secret_canary() {
    let descriptor = descriptor(
        "adapter:v08:local",
        "provider:v08:local",
        NetworkAccess::None,
    );
    let mut engine = ControlInterpretationEngine::new();
    engine
        .register_adapter(adapter(descriptor.clone()))
        .unwrap_or_else(|error| unreachable!("{error}"));
    let calls = Arc::new(AtomicUsize::new(0));
    let mut gate = engine.invocation_gate();
    gate.register_transport(
        descriptor,
        Box::new(SequenceTransport::new(
            Arc::clone(&calls),
            vec![ProviderInvocationOutcome::Complete(
                b"Configure a reproducible workstation".to_vec(),
            )],
        )),
    )
    .unwrap_or_else(|error| unreachable!("{error}"));
    let work = work();
    let rendered = format!("{:?}", work.projection.entries());
    assert!(!rendered.contains("V08-SECRET-CANARY"));
    assert!(rendered.contains("secret:provider-key"));

    let runtime = AgentRuntime::default();
    let mut budget = InterpretationSessionBudget::new(
        id(RequestId::new("session:v08:success")),
        10_000,
        1,
        1024,
    )
    .unwrap_or_else(|error| unreachable!("{error}"));
    let proposal = {
        let mut invocation = InterpretationInvocation {
            runtime: &runtime,
            gate: &mut gate,
            work: &work,
            offline: false,
            now_unix_ms: 1,
            requested_output_bytes: 1024,
            budget: &mut budget,
        };
        engine
            .interpret_with_adapter("adapter:v08:local", &mut invocation)
            .unwrap_or_else(|error| unreachable!("{error}"))
    };
    assert_eq!(proposal.validate(), Ok(()));
    assert!(!proposal.attribution.manual);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let proposed = proposal
        .to_proposed_intent(id(IntentId::new("intent:v08:provider")), vec![])
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(proposed.status, IntentStatus::Proposed);
}

#[test]
fn offline_discovery_health_selection_and_fallback_never_initialize_network_transport() {
    let local = descriptor(
        "adapter:v08:offline-local",
        "provider:v08:offline-local",
        NetworkAccess::None,
    );
    let network = descriptor(
        "adapter:v08:offline-network",
        "provider:v08:offline-network",
        NetworkAccess::Required,
    );
    let mut engine = ControlInterpretationEngine::new();
    engine
        .register_adapter(adapter(local.clone()))
        .unwrap_or_else(|error| unreachable!("{error}"));
    engine
        .register_adapter(adapter(network.clone()))
        .unwrap_or_else(|error| unreachable!("{error}"));

    assert_eq!(engine.eligible_adapters(true), vec![local.clone()]);
    assert!(matches!(
        engine.adapter_health("adapter:v08:offline-network", true),
        AdapterHealth::OfflineBlocked(_)
    ));

    let local_calls = Arc::new(AtomicUsize::new(0));
    let network_calls = Arc::new(AtomicUsize::new(0));
    let mut gate = engine.invocation_gate();
    gate.register_transport(
        local,
        Box::new(SequenceTransport::new(
            Arc::clone(&local_calls),
            vec![ProviderInvocationOutcome::Timeout],
        )),
    )
    .unwrap_or_else(|error| unreachable!("{error}"));
    gate.register_transport(
        network,
        Box::new(SequenceTransport::new(
            Arc::clone(&network_calls),
            vec![ProviderInvocationOutcome::Complete(b"unreachable".to_vec())],
        )),
    )
    .unwrap_or_else(|error| unreachable!("{error}"));

    let runtime = AgentRuntime::default();
    let work = work();
    let mut budget = InterpretationSessionBudget::new(
        id(RequestId::new("session:v08:offline")),
        10_000,
        2,
        2048,
    )
    .unwrap_or_else(|error| unreachable!("{error}"));
    let result = {
        let mut invocation = InterpretationInvocation {
            runtime: &runtime,
            gate: &mut gate,
            work: &work,
            offline: true,
            now_unix_ms: 1,
            requested_output_bytes: 1024,
            budget: &mut budget,
        };
        engine.interpret_with_fallback(
            &[
                "adapter:v08:offline-local".into(),
                "adapter:v08:offline-network".into(),
            ],
            &mut invocation,
        )
    };
    assert!(matches!(
        result,
        Err(InterpretationControlError::OfflineNetworkAdapter(_))
    ));
    assert_eq!(local_calls.load(Ordering::SeqCst), 1);
    assert_eq!(network_calls.load(Ordering::SeqCst), 0);
    assert_eq!(budget.remaining_attempts(), 1);
    assert_eq!(budget.remaining_output_bytes(), 1024);
}

#[test]
fn fallback_shares_one_aggregate_budget_and_cannot_reset_it() {
    let first = descriptor(
        "adapter:v08:fallback-first",
        "provider:v08:fallback-first",
        NetworkAccess::None,
    );
    let second = descriptor(
        "adapter:v08:fallback-second",
        "provider:v08:fallback-second",
        NetworkAccess::None,
    );
    let mut engine = ControlInterpretationEngine::new();
    engine
        .register_adapter(adapter(first.clone()))
        .unwrap_or_else(|error| unreachable!("{error}"));
    engine
        .register_adapter(adapter(second.clone()))
        .unwrap_or_else(|error| unreachable!("{error}"));
    let first_calls = Arc::new(AtomicUsize::new(0));
    let second_calls = Arc::new(AtomicUsize::new(0));
    let mut gate = engine.invocation_gate();
    gate.register_transport(
        first,
        Box::new(SequenceTransport::new(
            Arc::clone(&first_calls),
            vec![ProviderInvocationOutcome::Timeout],
        )),
    )
    .unwrap_or_else(|error| unreachable!("{error}"));
    gate.register_transport(
        second,
        Box::new(SequenceTransport::new(
            Arc::clone(&second_calls),
            vec![ProviderInvocationOutcome::Complete(
                b"Fallback proposal".to_vec(),
            )],
        )),
    )
    .unwrap_or_else(|error| unreachable!("{error}"));

    let runtime = AgentRuntime::default();
    let work = work();
    let mut budget = InterpretationSessionBudget::new(
        id(RequestId::new("session:v08:fallback")),
        10_000,
        2,
        2048,
    )
    .unwrap_or_else(|error| unreachable!("{error}"));
    {
        let mut invocation = InterpretationInvocation {
            runtime: &runtime,
            gate: &mut gate,
            work: &work,
            offline: false,
            now_unix_ms: 1,
            requested_output_bytes: 1024,
            budget: &mut budget,
        };
        engine
            .interpret_with_fallback(
                &[
                    "adapter:v08:fallback-first".into(),
                    "adapter:v08:fallback-second".into(),
                ],
                &mut invocation,
            )
            .unwrap_or_else(|error| unreachable!("{error}"));
    }
    assert_eq!(budget.remaining_attempts(), 0);
    assert_eq!(budget.remaining_output_bytes(), 0);
    assert_eq!(first_calls.load(Ordering::SeqCst), 1);
    assert_eq!(second_calls.load(Ordering::SeqCst), 1);

    let result = {
        let mut invocation = InterpretationInvocation {
            runtime: &runtime,
            gate: &mut gate,
            work: &work,
            offline: false,
            now_unix_ms: 2,
            requested_output_bytes: 1024,
            budget: &mut budget,
        };
        engine.interpret_with_adapter("adapter:v08:fallback-second", &mut invocation)
    };
    assert!(matches!(
        result,
        Err(InterpretationControlError::BudgetExhausted)
    ));
    assert_eq!(second_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn partial_and_failed_provider_outcomes_never_become_proposals() {
    let descriptor = descriptor(
        "adapter:v08:terminal",
        "provider:v08:terminal",
        NetworkAccess::None,
    );
    let mut engine = ControlInterpretationEngine::new();
    engine
        .register_adapter(adapter(descriptor.clone()))
        .unwrap_or_else(|error| unreachable!("{error}"));
    let calls = Arc::new(AtomicUsize::new(0));
    let mut gate = engine.invocation_gate();
    gate.register_transport(
        descriptor,
        Box::new(SequenceTransport::new(
            Arc::clone(&calls),
            vec![
                ProviderInvocationOutcome::Partial,
                ProviderInvocationOutcome::Timeout,
                ProviderInvocationOutcome::RateLimited,
                ProviderInvocationOutcome::TransportFailure("failed".into()),
                ProviderInvocationOutcome::Cancelled,
            ],
        )),
    )
    .unwrap_or_else(|error| unreachable!("{error}"));
    let runtime = AgentRuntime::default();
    let work = work();
    let mut budget = InterpretationSessionBudget::new(
        id(RequestId::new("session:v08:terminal")),
        10_000,
        5,
        5120,
    )
    .unwrap_or_else(|error| unreachable!("{error}"));

    for expected in 0..5 {
        let result = {
            let mut invocation = InterpretationInvocation {
                runtime: &runtime,
                gate: &mut gate,
                work: &work,
                offline: false,
                now_unix_ms: 1,
                requested_output_bytes: 1024,
                budget: &mut budget,
            };
            engine.interpret_with_adapter("adapter:v08:terminal", &mut invocation)
        };
        match expected {
            0 => assert!(matches!(
                result,
                Err(InterpretationControlError::ProviderPartialResponse)
            )),
            1 => assert!(matches!(
                result,
                Err(InterpretationControlError::ProviderTimeout)
            )),
            2 => assert!(matches!(
                result,
                Err(InterpretationControlError::ProviderRateLimited)
            )),
            3 => assert!(matches!(
                result,
                Err(InterpretationControlError::ProviderTransport(_))
            )),
            4 => assert!(matches!(
                result,
                Err(InterpretationControlError::ProviderCancelled)
            )),
            _ => unreachable!(),
        }
    }
    assert_eq!(calls.load(Ordering::SeqCst), 5);
    assert_eq!(budget.remaining_attempts(), 0);
}

fn acceptance_fixture(
    suffix: &str,
) -> (
    AuthenticatedPrincipal,
    IntentProposal,
    ProposalAcceptanceTarget,
    ControlAuthorityClock,
    u64,
) {
    let principal =
        AuthenticatedPrincipal::new("uid:1000").unwrap_or_else(|error| unreachable!("{error}"));
    let context = InterpretationContextBinding::new(
        format!("authority:v08:{suffix}"),
        ProposalDigest::hash_parts(b"qualification-semantic", &[suffix.as_bytes()]),
        vec![],
    )
    .unwrap_or_else(|error| unreachable!("{error}"));
    let proposal = IntentProposal::new_v1(
        id(RequestId::new(format!("proposal:v08:{suffix}"))),
        actor(),
        "Persist only a proposed intent",
        vec![],
        vec![],
        vec![],
        vec![],
        None,
        context,
        ProposalAttribution::manual("qualification:manual")
            .unwrap_or_else(|error| unreachable!("{error}")),
        vec![],
    )
    .unwrap_or_else(|error| unreachable!("{error}"));
    let target = ProposalAcceptanceTarget::Create {
        intent_id: id(IntentId::new(format!("intent:v08:{suffix}"))),
    };
    let mut clock = ControlAuthorityClock::new().unwrap_or_else(|error| unreachable!("{error}"));
    let base = clock
        .sample()
        .unwrap_or_else(|| unreachable!("Control clock must sample"))
        .unix_ms;
    (principal, proposal, target, clock, base)
}

fn acceptance_control(library: &mut LocalLibrary) -> ProposalAcceptanceControl {
    let key = TransactionAuthorityKey::new(vec![0x74; 32])
        .unwrap_or_else(|error| unreachable!("{error}"));
    let control = ProposalAcceptanceControl::from_authority_key(key);
    control
        .provision_library(library)
        .unwrap_or_else(|error| unreachable!("{error}"));
    control
}

#[test]
fn concrete_authority_acceptance_is_exact_bound_and_replays_after_authority_changes() {
    let (principal, proposal, target, mut clock, base) = acceptance_fixture("accept");
    let deadline = base.checked_add(60_000).unwrap_or_else(|| unreachable!());
    let mut authority = ControlProposalAuthority::new(
        proposal.context.clone(),
        BTreeSet::new(),
        vec![AuthorityValidityContributor::exclusive_unix_ms(
            "policy:v08:accept",
            deadline,
            ProposalDigest::hash_parts(b"policy", &[b"accept"]),
        )],
    )
    .unwrap_or_else(|error| unreachable!("{error}"));
    authority
        .authorize_actor(&principal, &proposal.actor)
        .unwrap_or_else(|error| unreachable!("{error}"));
    let decision_id = id(RequestId::new("decision:v08:accept"));
    let operation_id = id(RequestId::new("operation:v08:accept"));
    authority
        .issue_decision(
            &principal,
            &proposal,
            ProposalDecisionIssueRequest {
                decision_id: decision_id.clone(),
                operation_id: operation_id.clone(),
                target: target.clone(),
                supersedes: vec![],
                clock_continuity_generation: clock.continuity_generation(),
                expires_at_unix_ms: deadline,
                validity_evidence_digest: ProposalDigest::hash_parts(
                    b"decision-validity",
                    &[b"accept"],
                ),
            },
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
    let request = AcceptProposalRequest {
        operation_id,
        decision_id,
        target: target.clone(),
        supersedes: vec![],
    };
    let mut library =
        LocalLibrary::open_in_memory().unwrap_or_else(|error| unreachable!("{error}"));
    let control = acceptance_control(&mut library);
    let first = control
        .accept(
            &mut library,
            &principal,
            &proposal,
            &request,
            &mut authority,
            &mut clock,
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
    let stored = library
        .intent(&first.resulting_intent_id)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(stored.revision, first.resulting_revision);
    assert_eq!(stored.intent.status, IntentStatus::Proposed);

    authority
        .replace_time_validities(vec![AuthorityValidityContributor::exclusive_unix_ms(
            "policy:v08:changed-after-commit",
            deadline,
            ProposalDigest::hash_parts(b"policy", &[b"changed"]),
        )])
        .unwrap_or_else(|error| unreachable!("{error}"));
    let replay = control
        .accept(
            &mut library,
            &principal,
            &proposal,
            &request,
            &mut authority,
            &mut clock,
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(first, replay);
}

#[test]
fn stale_authority_generation_is_rejected_without_library_mutation() {
    let (principal, proposal, target, mut clock, base) = acceptance_fixture("stale-generation");
    let deadline = base.checked_add(60_000).unwrap_or_else(|| unreachable!());
    let mut authority = ControlProposalAuthority::new(
        proposal.context.clone(),
        BTreeSet::new(),
        vec![AuthorityValidityContributor::exclusive_unix_ms(
            "policy:v08:stale-original",
            deadline,
            ProposalDigest::hash_parts(b"policy", &[b"original"]),
        )],
    )
    .unwrap_or_else(|error| unreachable!("{error}"));
    authority
        .authorize_actor(&principal, &proposal.actor)
        .unwrap_or_else(|error| unreachable!("{error}"));
    let decision_id = id(RequestId::new("decision:v08:stale-generation"));
    let operation_id = id(RequestId::new("operation:v08:stale-generation"));
    authority
        .issue_decision(
            &principal,
            &proposal,
            ProposalDecisionIssueRequest {
                decision_id: decision_id.clone(),
                operation_id: operation_id.clone(),
                target: target.clone(),
                supersedes: vec![],
                clock_continuity_generation: clock.continuity_generation(),
                expires_at_unix_ms: deadline,
                validity_evidence_digest: ProposalDigest::hash_parts(
                    b"decision-validity",
                    &[b"stale"],
                ),
            },
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
    authority
        .replace_time_validities(vec![AuthorityValidityContributor::exclusive_unix_ms(
            "policy:v08:stale-updated",
            deadline,
            ProposalDigest::hash_parts(b"policy", &[b"updated"]),
        )])
        .unwrap_or_else(|error| unreachable!("{error}"));

    let request = AcceptProposalRequest {
        operation_id,
        decision_id,
        target: target.clone(),
        supersedes: vec![],
    };
    let mut library =
        LocalLibrary::open_in_memory().unwrap_or_else(|error| unreachable!("{error}"));
    let control = acceptance_control(&mut library);
    let result = control.accept(
        &mut library,
        &principal,
        &proposal,
        &request,
        &mut authority,
        &mut clock,
    );
    assert!(matches!(
        result,
        Err(ProposalAcceptanceControlError::InvalidDecision(_))
    ));
    assert!(library.intent(target.intent_id()).is_err());
}
