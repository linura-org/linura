#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt::{Debug, Display, Formatter};
use std::time::{SystemTime, UNIX_EPOCH};

use linura_core::{CapabilityId, ProviderId, ResourceId};
use linura_graph::{NodeId, ObservationRecordOutcome, SystemGraph};
use linura_observation::{
    FreshnessState, ObservationEnvelope, ObservationValidationError, ProviderAvailability,
};
use linura_protocol::{
    ObservationExplanation, ObservationRequest, ObservationResponse, ObservationSystemSnapshot,
    ProviderSnapshot,
};
use linura_provider_sdk::{Observer, ProviderError};

/// Default live evidence retained per resource in the daemon graph.
///
/// This bounds polling-driven memory and serialization growth while keeping a
/// useful recent audit window. Durable history belongs in a later persistence
/// layer rather than an unbounded process-local graph.
pub const DEFAULT_OBSERVATION_HISTORY_PER_RESOURCE: usize = 64;
pub const DEFAULT_OBSERVED_RESOURCE_LIMIT: usize = 4_096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObservationControlError {
    DuplicateProvider {
        provider: ProviderId,
    },
    InvalidHistoryLimit {
        max_evidence_per_resource: usize,
    },
    InvalidResourceLimit {
        max_resources: usize,
    },
    RetentionOrderExhausted,
    ProviderIdentityMismatch {
        expected: ProviderId,
        actual: ProviderId,
    },
    CapabilityProviderMismatch {
        provider: ProviderId,
        capability: CapabilityId,
    },
    UnknownProvider {
        provider: ProviderId,
    },
    ProviderUnavailable {
        provider: ProviderId,
        reason: Option<String>,
    },
    UnsupportedCapability {
        provider: ProviderId,
        capability: CapabilityId,
    },
    Provider(ProviderError),
    InvalidObservation(ObservationValidationError),
    Clock(String),
    SupersededEvidence {
        resource: ResourceId,
        evidence_id: String,
    },
    ObservationUnavailable {
        resource: ResourceId,
    },
}

impl Display for ObservationControlError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateProvider { provider } => {
                write!(f, "observer {} is already registered", provider.as_str())
            }
            Self::InvalidHistoryLimit {
                max_evidence_per_resource,
            } => write!(
                f,
                "observation history limit must be greater than zero, got {max_evidence_per_resource}"
            ),
            Self::InvalidResourceLimit { max_resources } => write!(
                f,
                "observed resource limit must be greater than zero, got {max_resources}"
            ),
            Self::RetentionOrderExhausted => f.write_str("observation retention order exhausted"),
            Self::ProviderIdentityMismatch { expected, actual } => write!(
                f,
                "observer identity mismatch: expected {}, got {}",
                expected.as_str(),
                actual.as_str()
            ),
            Self::CapabilityProviderMismatch {
                provider,
                capability,
            } => write!(
                f,
                "capability {} is not bound to observer {}",
                capability.as_str(),
                provider.as_str()
            ),
            Self::UnknownProvider { provider } => {
                write!(f, "unknown observation provider {}", provider.as_str())
            }
            Self::ProviderUnavailable { provider, reason } => {
                write!(
                    f,
                    "observation provider {} is unavailable",
                    provider.as_str()
                )?;
                if let Some(reason) = reason {
                    write!(f, ": {reason}")?;
                }
                Ok(())
            }
            Self::UnsupportedCapability {
                provider,
                capability,
            } => write!(
                f,
                "provider {} does not support observation capability {}",
                provider.as_str(),
                capability.as_str()
            ),
            Self::Provider(error) => Display::fmt(error, f),
            Self::InvalidObservation(error) => Display::fmt(error, f),
            Self::Clock(reason) => write!(f, "observation clock failed: {reason}"),
            Self::SupersededEvidence {
                resource,
                evidence_id,
            } => write!(
                f,
                "observation {evidence_id} for {} is older than the current authoritative state",
                resource.as_str()
            ),
            Self::ObservationUnavailable { resource } => write!(
                f,
                "no authoritative observation is available for {}",
                resource.as_str()
            ),
        }
    }
}

impl std::error::Error for ObservationControlError {}

/// Read-only coordinator for authoritative observations.
///
/// This type deliberately owns no mutation providers or executors. It validates
/// provider identity, freshness and monotonicity before evidence becomes current
/// graph state.
pub struct ObservationCoordinator {
    observers: BTreeMap<ProviderId, Box<dyn Observer>>,
    graph: SystemGraph,
    latest: BTreeMap<ResourceId, ObservationEnvelope>,
    history: BTreeMap<ResourceId, BTreeMap<u64, ObservationEnvelope>>,
    resource_last_seen: BTreeMap<ResourceId, u64>,
    max_evidence_per_resource: usize,
    max_resources: usize,
    retention_order: u64,
}

impl Debug for ObservationCoordinator {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObservationCoordinator")
            .field("observer_count", &self.observers.len())
            .field("graph_node_count", &self.graph.nodes().count())
            .field("graph_edge_count", &self.graph.edges().len())
            .field("latest_observation_count", &self.latest.len())
            .field(
                "retained_evidence_count",
                &self.history.values().map(BTreeMap::len).sum::<usize>(),
            )
            .field("retained_resource_count", &self.resource_last_seen.len())
            .field("max_evidence_per_resource", &self.max_evidence_per_resource)
            .field("max_resources", &self.max_resources)
            .finish()
    }
}

impl Default for ObservationCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl ObservationCoordinator {
    #[must_use]
    pub fn new() -> Self {
        Self {
            observers: BTreeMap::new(),
            graph: SystemGraph::default(),
            latest: BTreeMap::new(),
            history: BTreeMap::new(),
            resource_last_seen: BTreeMap::new(),
            max_evidence_per_resource: DEFAULT_OBSERVATION_HISTORY_PER_RESOURCE,
            max_resources: DEFAULT_OBSERVED_RESOURCE_LIMIT,
            retention_order: 0,
        }
    }

    pub fn with_history_limit(
        max_evidence_per_resource: usize,
    ) -> Result<Self, ObservationControlError> {
        Self::with_limits(DEFAULT_OBSERVED_RESOURCE_LIMIT, max_evidence_per_resource)
    }

    pub fn with_limits(
        max_resources: usize,
        max_evidence_per_resource: usize,
    ) -> Result<Self, ObservationControlError> {
        if max_resources == 0 {
            return Err(ObservationControlError::InvalidResourceLimit { max_resources });
        }
        if max_evidence_per_resource == 0 {
            return Err(ObservationControlError::InvalidHistoryLimit {
                max_evidence_per_resource,
            });
        }
        Ok(Self {
            observers: BTreeMap::new(),
            graph: SystemGraph::default(),
            latest: BTreeMap::new(),
            history: BTreeMap::new(),
            resource_last_seen: BTreeMap::new(),
            max_evidence_per_resource,
            max_resources,
            retention_order: 0,
        })
    }

    pub fn register_observer(
        &mut self,
        observer: Box<dyn Observer>,
    ) -> Result<(), ObservationControlError> {
        let provider = observer.observer_id();
        if self.observers.contains_key(&provider) {
            return Err(ObservationControlError::DuplicateProvider { provider });
        }
        validate_observer_identity(observer.as_ref(), &provider)?;
        self.observers.insert(provider, observer);
        Ok(())
    }

    pub fn provider_snapshot(&self) -> Result<ProviderSnapshot, ObservationControlError> {
        let mut providers = Vec::with_capacity(self.observers.len());
        let mut capabilities = Vec::new();
        for (provider, observer) in &self.observers {
            validate_observer_identity(observer.as_ref(), provider)?;
            providers.push(observer.health());
            capabilities.extend(observer.observation_capabilities());
        }
        providers.sort_by(|left, right| left.provider.as_str().cmp(right.provider.as_str()));
        capabilities.sort_by(|left, right| {
            left.id.as_str().cmp(right.id.as_str()).then_with(|| {
                left.provider
                    .as_ref()
                    .map(ProviderId::as_str)
                    .cmp(&right.provider.as_ref().map(ProviderId::as_str))
            })
        });
        Ok(ProviderSnapshot {
            providers,
            capabilities,
        })
    }

    /// Observe a resource and validate freshness against a clock sampled only
    /// after the provider has completed its authoritative read.
    pub fn observe(
        &mut self,
        request: &ObservationRequest,
    ) -> Result<ObservationResponse, ObservationControlError> {
        self.observe_with_clock(request, current_unix_ms)
    }

    fn observe_with_clock<F>(
        &mut self,
        request: &ObservationRequest,
        clock: F,
    ) -> Result<ObservationResponse, ObservationControlError>
    where
        F: FnOnce() -> Result<u64, ObservationControlError>,
    {
        let observer = self.observers.get(&request.provider).ok_or_else(|| {
            ObservationControlError::UnknownProvider {
                provider: request.provider.clone(),
            }
        })?;
        // Registration already validates the observer/provider and capability/provider
        // bindings. Providers keep the live health preflight by default; an observer
        // may skip it only when its authoritative read independently gates readiness
        // and returns ProviderError::Unavailable for loss of provider availability.
        if observer.requires_live_health_preflight() {
            let health = observer.health();
            if health.provider != request.provider {
                return Err(ObservationControlError::ProviderIdentityMismatch {
                    expected: request.provider.clone(),
                    actual: health.provider,
                });
            }
            if health.availability == ProviderAvailability::Unavailable {
                return Err(ObservationControlError::ProviderUnavailable {
                    provider: request.provider.clone(),
                    reason: health.reason,
                });
            }
        }
        if !observer.supports_observation(&request.capability) {
            return Err(ObservationControlError::UnsupportedCapability {
                provider: request.provider.clone(),
                capability: request.capability.clone(),
            });
        }

        let observation = observer
            .observe_authoritative(&request.resource, &request.capability)
            .map_err(|error| match error {
                ProviderError::Unavailable(reason) => {
                    ObservationControlError::ProviderUnavailable {
                        provider: request.provider.clone(),
                        reason: Some(reason),
                    }
                }
                error => ObservationControlError::Provider(error),
            })?;
        observation
            .validate(&request.provider, &request.resource, &request.capability)
            .map_err(ObservationControlError::InvalidObservation)?;

        // The provider timestamps its evidence while performing the authoritative
        // read, so freshness must be evaluated against a clock sampled after that
        // read completes. Sampling before the provider call can misclassify fresh
        // evidence as FutureEvidence.
        let now_unix_ms = clock()?;
        observation
            .require_current(now_unix_ms)
            .map_err(ObservationControlError::InvalidObservation)?;

        // Allocate process-local retention order before mutating graph state.
        // This order is monotonic even when the realtime clock moves backwards.
        let retention_order = self.next_retention_order()?;
        let outcome = self
            .graph
            .record_observation(&observation, FreshnessState::Current);
        self.retain_observation_history(&observation, retention_order);
        if outcome == ObservationRecordOutcome::HistoricalEvidenceRetained {
            return Err(ObservationControlError::SupersededEvidence {
                resource: request.resource.clone(),
                evidence_id: observation.evidence_id(),
            });
        }
        self.latest
            .insert(request.resource.clone(), observation.clone());
        Ok(ObservationResponse {
            observation,
            freshness: FreshnessState::Current,
        })
    }

    fn next_retention_order(&mut self) -> Result<u64, ObservationControlError> {
        let next = self
            .retention_order
            .checked_add(1)
            .ok_or(ObservationControlError::RetentionOrderExhausted)?;
        self.retention_order = next;
        Ok(next)
    }

    fn retain_observation_history(
        &mut self,
        observation: &ObservationEnvelope,
        retention_order: u64,
    ) {
        let current_evidence_id = self
            .graph
            .node(&NodeId::Resource(observation.resource.clone()))
            .and_then(|node| node.attributes.get("evidence_id"))
            .cloned();
        let incoming_evidence_id = observation.evidence_id();

        let evicted_evidence = {
            let history = self
                .history
                .entry(observation.resource.clone())
                .or_default();
            let already_retained = history
                .values()
                .any(|existing| existing.evidence_id() == incoming_evidence_id);
            if !already_retained {
                history.insert(retention_order, observation.clone());
            }

            let mut evicted = Vec::new();
            while history.len() > self.max_evidence_per_resource {
                let candidate = history
                    .iter()
                    .find(|(_, envelope)| {
                        current_evidence_id
                            .as_ref()
                            .is_none_or(|current| envelope.evidence_id() != current.as_str())
                    })
                    .map(|(order, _)| *order);
                let Some(order) = candidate else {
                    break;
                };
                if let Some(envelope) = history.remove(&order) {
                    evicted.push(envelope.evidence_id());
                }
            }
            evicted
        };

        for evidence_id in evicted_evidence {
            self.graph.remove_node(&NodeId::Evidence(evidence_id));
        }

        self.resource_last_seen
            .insert(observation.resource.clone(), retention_order);
        self.enforce_resource_limit();
    }

    fn enforce_resource_limit(&mut self) {
        while self.resource_last_seen.len() > self.max_resources {
            let Some(resource) = self
                .resource_last_seen
                .iter()
                .min_by_key(|(_, order)| **order)
                .map(|(resource, _)| resource.clone())
            else {
                break;
            };
            self.evict_resource(&resource);
        }
    }

    fn evict_resource(&mut self, resource: &ResourceId) {
        self.resource_last_seen.remove(resource);
        self.latest.remove(resource);
        if let Some(history) = self.history.remove(resource) {
            for observation in history.into_values() {
                self.graph
                    .remove_node(&NodeId::Evidence(observation.evidence_id()));
            }
        }
        self.graph.remove_node(&NodeId::Resource(resource.clone()));
    }

    #[cfg(test)]
    fn observe_at(
        &mut self,
        request: &ObservationRequest,
        now_unix_ms: u64,
    ) -> Result<ObservationResponse, ObservationControlError> {
        self.observe_with_clock(request, || Ok(now_unix_ms))
    }

    pub fn system_snapshot(&self) -> Result<ObservationSystemSnapshot, ObservationControlError> {
        Ok(ObservationSystemSnapshot {
            graph: self.graph_snapshot()?,
            providers: self.provider_snapshot()?,
        })
    }

    /// Return a graph view whose cached authoritative evidence is aged against
    /// the current clock before it crosses a public API boundary.
    pub fn graph_snapshot(&self) -> Result<SystemGraph, ObservationControlError> {
        Ok(self.graph_snapshot_at(current_unix_ms()?))
    }

    fn graph_snapshot_at(&self, now_unix_ms: u64) -> SystemGraph {
        let mut graph = self.graph.clone();

        // Every retained evidence envelope is re-aged at serve time. Historical
        // nodes therefore cannot remain permanently marked current after their
        // validity window expires.
        for observations in self.history.values() {
            for observation in observations.values() {
                let freshness = observation.freshness_at(now_unix_ms).as_str().to_string();
                let evidence_node_id = NodeId::Evidence(observation.evidence_id());
                if let Some(mut evidence_node) = graph.node(&evidence_node_id).cloned() {
                    evidence_node
                        .attributes
                        .insert("freshness".into(), freshness);
                    graph.upsert_node(evidence_node);
                }
            }
        }

        // The resource projection tracks only the newest accepted authoritative
        // envelope, so age it from `latest` independently of historical evidence.
        for observation in self.latest.values() {
            let freshness = observation.freshness_at(now_unix_ms).as_str().to_string();
            let evidence_id = observation.evidence_id();
            let resource_node_id = NodeId::Resource(observation.resource.clone());
            if let Some(mut resource_node) = graph.node(&resource_node_id).cloned() {
                let is_current_evidence = resource_node
                    .attributes
                    .get("evidence_id")
                    .is_some_and(|current| current == &evidence_id);
                if is_current_evidence {
                    resource_node
                        .attributes
                        .insert("freshness".into(), freshness);
                    graph.upsert_node(resource_node);
                }
            }
        }
        graph
    }

    pub fn explain_current(
        &self,
        resource: &ResourceId,
    ) -> Result<ObservationExplanation, ObservationControlError> {
        self.explain(resource, current_unix_ms()?)
    }

    pub fn explain(
        &self,
        resource: &ResourceId,
        now_unix_ms: u64,
    ) -> Result<ObservationExplanation, ObservationControlError> {
        let observation = self.latest.get(resource).ok_or_else(|| {
            ObservationControlError::ObservationUnavailable {
                resource: resource.clone(),
            }
        })?;
        Ok(ObservationExplanation {
            resource: observation.resource.clone(),
            provider: observation.provider.clone(),
            capability: observation.capability.clone(),
            freshness: observation.freshness_at(now_unix_ms),
            evidence_id: observation.evidence_id(),
            authority: observation.authority.as_str().into(),
        })
    }

    #[must_use]
    pub fn graph(&self) -> &SystemGraph {
        &self.graph
    }

    #[must_use]
    pub fn latest_observation(&self, resource: &ResourceId) -> Option<&ObservationEnvelope> {
        self.latest.get(resource)
    }
}

fn current_unix_ms() -> Result<u64, ObservationControlError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| ObservationControlError::Clock(error.to_string()))?;
    u64::try_from(duration.as_millis()).map_err(|_| {
        ObservationControlError::Clock("Unix timestamp exceeds u64 milliseconds".into())
    })
}

fn validate_observer_identity(
    observer: &dyn Observer,
    expected: &ProviderId,
) -> Result<(), ObservationControlError> {
    let health = observer.health();
    if &health.provider != expected {
        return Err(ObservationControlError::ProviderIdentityMismatch {
            expected: expected.clone(),
            actual: health.provider,
        });
    }
    for capability in observer.observation_capabilities() {
        if capability.provider.as_ref() != Some(expected) {
            return Err(ObservationControlError::CapabilityProviderMismatch {
                provider: expected.clone(),
                capability: capability.id,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use super::*;
    use linura_core::{Capability, SupportLevel, ValidationError};
    use linura_observation::{ObservationAuthority, ObservedValue, ProviderHealth};

    fn id<T>(result: Result<T, ValidationError>) -> T {
        result.unwrap_or_else(|error| unreachable!("{error}"))
    }

    struct QueueObserver {
        provider: ProviderId,
        capability: Capability,
        health: ProviderHealth,
        envelopes: Mutex<VecDeque<ObservationEnvelope>>,
    }

    impl QueueObserver {
        fn new(envelopes: Vec<ObservationEnvelope>) -> Self {
            let provider = id(ProviderId::new("systemd"));
            let capability_id = id(CapabilityId::new("systemd.unit.observe"));
            Self {
                capability: Capability {
                    id: capability_id,
                    support: SupportLevel::Supported,
                    provider: Some(provider.clone()),
                    reason: None,
                },
                health: ProviderHealth {
                    provider: provider.clone(),
                    availability: ProviderAvailability::Available,
                    reason: None,
                },
                provider,
                envelopes: Mutex::new(envelopes.into()),
            }
        }
    }

    impl Observer for QueueObserver {
        fn observer_id(&self) -> ProviderId {
            self.provider.clone()
        }

        fn observation_capabilities(&self) -> Vec<Capability> {
            vec![self.capability.clone()]
        }

        fn health(&self) -> ProviderHealth {
            self.health.clone()
        }

        fn resources(&self) -> Result<Vec<ResourceId>, ProviderError> {
            Ok(vec![id(ResourceId::new("systemd:unit:sshd.service"))])
        }

        fn observe_authoritative(
            &self,
            _resource: &ResourceId,
            _capability: &CapabilityId,
        ) -> Result<ObservationEnvelope, ProviderError> {
            let mut envelopes = self
                .envelopes
                .lock()
                .map_err(|_| ProviderError::Internal("observer queue poisoned".into()))?;
            envelopes
                .pop_front()
                .ok_or_else(|| ProviderError::Unavailable("no queued observation".into()))
        }
    }

    struct CountingObserver {
        inner: QueueObserver,
        health_calls: Arc<AtomicUsize>,
    }

    impl Observer for CountingObserver {
        fn observer_id(&self) -> ProviderId {
            self.inner.observer_id()
        }

        fn observation_capabilities(&self) -> Vec<Capability> {
            self.inner.observation_capabilities()
        }

        fn health(&self) -> ProviderHealth {
            self.health_calls.fetch_add(1, Ordering::SeqCst);
            self.inner.health()
        }

        fn resources(&self) -> Result<Vec<ResourceId>, ProviderError> {
            self.inner.resources()
        }

        fn requires_live_health_preflight(&self) -> bool {
            false
        }

        fn supports_observation(&self, capability: &CapabilityId) -> bool {
            capability == &self.inner.capability.id
        }

        fn observe_authoritative(
            &self,
            resource: &ResourceId,
            capability: &CapabilityId,
        ) -> Result<ObservationEnvelope, ProviderError> {
            self.inner.observe_authoritative(resource, capability)
        }
    }

    struct DefaultPreflightCountingObserver {
        inner: QueueObserver,
        health_calls: Arc<AtomicUsize>,
    }

    impl Observer for DefaultPreflightCountingObserver {
        fn observer_id(&self) -> ProviderId {
            self.inner.observer_id()
        }

        fn observation_capabilities(&self) -> Vec<Capability> {
            self.inner.observation_capabilities()
        }

        fn health(&self) -> ProviderHealth {
            self.health_calls.fetch_add(1, Ordering::SeqCst);
            self.inner.health()
        }

        fn resources(&self) -> Result<Vec<ResourceId>, ProviderError> {
            self.inner.resources()
        }

        fn supports_observation(&self, capability: &CapabilityId) -> bool {
            capability == &self.inner.capability.id
        }

        fn observe_authoritative(
            &self,
            resource: &ResourceId,
            capability: &CapabilityId,
        ) -> Result<ObservationEnvelope, ProviderError> {
            self.inner.observe_authoritative(resource, capability)
        }
    }

    struct ChangingHealthIdentityObserver {
        inner: QueueObserver,
        health_calls: Arc<AtomicUsize>,
    }

    impl Observer for ChangingHealthIdentityObserver {
        fn observer_id(&self) -> ProviderId {
            self.inner.observer_id()
        }

        fn observation_capabilities(&self) -> Vec<Capability> {
            self.inner.observation_capabilities()
        }

        fn health(&self) -> ProviderHealth {
            let call = self.health_calls.fetch_add(1, Ordering::SeqCst);
            let mut health = self.inner.health();
            if call > 0 {
                health.provider = id(ProviderId::new("networkmanager"));
            }
            health
        }

        fn resources(&self) -> Result<Vec<ResourceId>, ProviderError> {
            self.inner.resources()
        }

        fn supports_observation(&self, capability: &CapabilityId) -> bool {
            capability == &self.inner.capability.id
        }

        fn observe_authoritative(
            &self,
            resource: &ResourceId,
            capability: &CapabilityId,
        ) -> Result<ObservationEnvelope, ProviderError> {
            self.inner.observe_authoritative(resource, capability)
        }
    }

    fn envelope(observed_at_unix_ms: u64, sequence: u64, state: &str) -> ObservationEnvelope {
        envelope_for(
            "systemd:unit:sshd.service",
            observed_at_unix_ms,
            sequence,
            state,
        )
    }

    fn envelope_for(
        resource: &str,
        observed_at_unix_ms: u64,
        sequence: u64,
        state: &str,
    ) -> ObservationEnvelope {
        ObservationEnvelope {
            provider: id(ProviderId::new("systemd")),
            resource: id(ResourceId::new(resource)),
            capability: id(CapabilityId::new("systemd.unit.observe")),
            authority: ObservationAuthority::NativeApi,
            observed_at_unix_ms,
            valid_for_ms: 1_000,
            sequence,
            attributes: BTreeMap::from([(
                "active_state".into(),
                ObservedValue::Text(state.into()),
            )]),
        }
    }

    fn request() -> ObservationRequest {
        request_for("systemd:unit:sshd.service")
    }

    fn request_for(resource: &str) -> ObservationRequest {
        ObservationRequest {
            provider: id(ProviderId::new("systemd")),
            resource: id(ResourceId::new(resource)),
            capability: id(CapabilityId::new("systemd.unit.observe")),
        }
    }

    #[test]
    fn records_only_valid_current_authoritative_state() {
        let mut coordinator = ObservationCoordinator::new();
        let observer = QueueObserver::new(vec![envelope(1_000, 1, "active")]);
        assert_eq!(coordinator.register_observer(Box::new(observer)), Ok(()));
        let response = coordinator
            .observe_at(&request(), 1_100)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(response.freshness, FreshnessState::Current);
        let explanation = coordinator
            .explain(&request().resource, 1_100)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(explanation.provider.as_str(), "systemd");
        assert_eq!(coordinator.graph().nodes().count(), 4);
    }

    #[test]
    fn authoritative_observe_does_not_repeat_live_health_probe_after_registration() {
        let health_calls = Arc::new(AtomicUsize::new(0));
        let observer = CountingObserver {
            inner: QueueObserver::new(vec![envelope(1_000, 1, "active")]),
            health_calls: Arc::clone(&health_calls),
        };
        let mut coordinator = ObservationCoordinator::new();
        assert_eq!(coordinator.register_observer(Box::new(observer)), Ok(()));
        assert_eq!(health_calls.load(Ordering::SeqCst), 1);
        assert!(coordinator.observe_at(&request(), 1_100).is_ok());
        assert_eq!(health_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn default_observer_retains_live_health_preflight() {
        let health_calls = Arc::new(AtomicUsize::new(0));
        let observer = DefaultPreflightCountingObserver {
            inner: QueueObserver::new(vec![envelope(1_000, 1, "active")]),
            health_calls: Arc::clone(&health_calls),
        };
        let mut coordinator = ObservationCoordinator::new();
        assert_eq!(coordinator.register_observer(Box::new(observer)), Ok(()));
        assert_eq!(health_calls.load(Ordering::SeqCst), 1);
        assert!(coordinator.observe_at(&request(), 1_100).is_ok());
        assert_eq!(health_calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn live_health_preflight_rejects_provider_identity_drift() {
        let health_calls = Arc::new(AtomicUsize::new(0));
        let observer = ChangingHealthIdentityObserver {
            inner: QueueObserver::new(vec![envelope(1_000, 1, "active")]),
            health_calls: Arc::clone(&health_calls),
        };
        let mut coordinator = ObservationCoordinator::new();
        assert_eq!(coordinator.register_observer(Box::new(observer)), Ok(()));
        assert_eq!(health_calls.load(Ordering::SeqCst), 1);

        let result = coordinator.observe_at(&request(), 1_100);
        assert!(matches!(
            result,
            Err(ObservationControlError::ProviderIdentityMismatch {
                expected,
                actual,
            }) if expected.as_str() == "systemd" && actual.as_str() == "networkmanager"
        ));
        assert_eq!(health_calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn authoritative_unavailable_result_preserves_provider_unavailable_classification() {
        let observer = CountingObserver {
            inner: QueueObserver::new(vec![]),
            health_calls: Arc::new(AtomicUsize::new(0)),
        };
        let mut coordinator = ObservationCoordinator::new();
        assert_eq!(coordinator.register_observer(Box::new(observer)), Ok(()));
        let result = coordinator.observe_at(&request(), 1_100);
        assert!(matches!(
            result,
            Err(ObservationControlError::ProviderUnavailable {
                reason: Some(reason),
                ..
            }) if reason == "no queued observation"
        ));
    }

    #[test]
    fn production_observe_samples_freshness_after_provider_observation() {
        let observed_at = current_unix_ms().unwrap_or_else(|error| unreachable!("{error}"));
        let mut coordinator = ObservationCoordinator::new();
        let observer = QueueObserver::new(vec![envelope(observed_at, 1, "active")]);
        assert_eq!(coordinator.register_observer(Box::new(observer)), Ok(()));
        assert!(coordinator.observe(&request()).is_ok());
    }

    #[test]
    fn late_older_evidence_cannot_replace_current_state() {
        let mut coordinator = ObservationCoordinator::new();
        let observer = QueueObserver::new(vec![
            envelope(1_000, 2, "active"),
            envelope(900, 1, "inactive"),
        ]);
        assert_eq!(coordinator.register_observer(Box::new(observer)), Ok(()));
        let request = request();
        assert!(coordinator.observe_at(&request, 1_100).is_ok());
        let second = coordinator.observe_at(&request, 1_100);
        assert!(matches!(
            second,
            Err(ObservationControlError::SupersededEvidence { .. })
        ));
        let latest = coordinator
            .latest_observation(&request.resource)
            .unwrap_or_else(|| unreachable!("current observation must remain"));
        assert_eq!(latest.sequence, 2);
    }

    #[test]
    fn later_same_provider_sequence_wins_after_realtime_clock_rollback() {
        let mut coordinator = ObservationCoordinator::new();
        let observer = QueueObserver::new(vec![
            envelope(2_000, 1, "active"),
            envelope(1_000, 2, "inactive"),
        ]);
        assert_eq!(coordinator.register_observer(Box::new(observer)), Ok(()));
        let request = request();
        assert!(coordinator.observe_at(&request, 2_100).is_ok());
        assert!(coordinator.observe_at(&request, 1_100).is_ok());

        let latest = coordinator
            .latest_observation(&request.resource)
            .unwrap_or_else(|| unreachable!("newer sequence must become current"));
        assert_eq!(latest.sequence, 2);
        assert_eq!(latest.observed_at_unix_ms, 1_000);
        assert_eq!(
            latest.attributes.get("active_state"),
            Some(&ObservedValue::Text("inactive".into()))
        );
    }

    #[test]
    fn public_graph_snapshot_ages_cached_freshness_consistently() {
        let mut coordinator = ObservationCoordinator::new();
        let observer = QueueObserver::new(vec![envelope(1_000, 1, "active")]);
        assert_eq!(coordinator.register_observer(Box::new(observer)), Ok(()));
        let request = request();
        assert!(coordinator.observe_at(&request, 1_100).is_ok());

        let evidence_id = coordinator
            .latest_observation(&request.resource)
            .unwrap_or_else(|| unreachable!("current observation must exist"))
            .evidence_id();
        let snapshot = coordinator.graph_snapshot_at(2_500);
        let resource = snapshot
            .node(&NodeId::Resource(request.resource.clone()))
            .unwrap_or_else(|| unreachable!("resource node must exist"));
        let evidence = snapshot
            .node(&NodeId::Evidence(evidence_id))
            .unwrap_or_else(|| unreachable!("evidence node must exist"));
        assert_eq!(
            resource.attributes.get("freshness").map(String::as_str),
            Some("stale")
        );
        assert_eq!(
            evidence.attributes.get("freshness").map(String::as_str),
            Some("stale")
        );
        assert_eq!(
            coordinator
                .explain(&request.resource, 2_500)
                .unwrap_or_else(|error| unreachable!("{error}"))
                .freshness,
            FreshnessState::Stale
        );
    }

    #[test]
    fn public_graph_snapshot_ages_every_retained_evidence() {
        let first = envelope(1_000, 1, "inactive");
        let second = envelope(1_500, 2, "active");
        let first_evidence = first.evidence_id();
        let second_evidence = second.evidence_id();
        let mut coordinator = ObservationCoordinator::with_history_limit(4)
            .unwrap_or_else(|error| unreachable!("{error}"));
        let observer = QueueObserver::new(vec![first, second]);
        assert_eq!(coordinator.register_observer(Box::new(observer)), Ok(()));
        let request = request();
        assert!(coordinator.observe_at(&request, 1_100).is_ok());
        assert!(coordinator.observe_at(&request, 1_600).is_ok());

        let snapshot = coordinator.graph_snapshot_at(2_200);
        let historical = snapshot
            .node(&NodeId::Evidence(first_evidence))
            .unwrap_or_else(|| unreachable!("historical evidence must be retained"));
        let latest = snapshot
            .node(&NodeId::Evidence(second_evidence))
            .unwrap_or_else(|| unreachable!("latest evidence must be retained"));
        assert_eq!(
            historical.attributes.get("freshness").map(String::as_str),
            Some("stale")
        );
        assert_eq!(
            latest.attributes.get("freshness").map(String::as_str),
            Some("current")
        );
    }

    #[test]
    fn observation_history_is_bounded_per_resource() {
        let first = envelope(1_000, 1, "inactive");
        let second = envelope(1_500, 2, "activating");
        let third = envelope(2_000, 3, "active");
        let first_evidence = first.evidence_id();
        let mut coordinator = ObservationCoordinator::with_history_limit(2)
            .unwrap_or_else(|error| unreachable!("{error}"));
        let observer = QueueObserver::new(vec![first, second, third]);
        assert_eq!(coordinator.register_observer(Box::new(observer)), Ok(()));
        let request = request();
        assert!(coordinator.observe_at(&request, 1_100).is_ok());
        assert!(coordinator.observe_at(&request, 1_600).is_ok());
        assert!(coordinator.observe_at(&request, 2_100).is_ok());

        assert!(
            coordinator
                .graph()
                .node(&NodeId::Evidence(first_evidence))
                .is_none()
        );
        assert_eq!(
            coordinator
                .graph()
                .nodes()
                .filter(|node| matches!(node.id, NodeId::Evidence(_)))
                .count(),
            2
        );
        assert_eq!(
            coordinator
                .graph()
                .edges()
                .iter()
                .filter(|edge| edge.kind == linura_graph::EdgeKind::EvidenceFor)
                .count(),
            2
        );
    }

    #[test]
    fn bounded_history_preserves_current_evidence_when_late_read_is_rejected() {
        let current = envelope(2_000, 2, "active");
        let late = envelope(1_000, 1, "inactive");
        let current_evidence = current.evidence_id();
        let late_evidence = late.evidence_id();
        let mut coordinator = ObservationCoordinator::with_history_limit(1)
            .unwrap_or_else(|error| unreachable!("{error}"));
        let observer = QueueObserver::new(vec![current, late]);
        assert_eq!(coordinator.register_observer(Box::new(observer)), Ok(()));
        let request = request();
        assert!(coordinator.observe_at(&request, 2_100).is_ok());
        assert!(matches!(
            coordinator.observe_at(&request, 1_100),
            Err(ObservationControlError::SupersededEvidence { .. })
        ));
        assert!(
            coordinator
                .graph()
                .node(&NodeId::Evidence(current_evidence))
                .is_some()
        );
        assert!(
            coordinator
                .graph()
                .node(&NodeId::Evidence(late_evidence))
                .is_none()
        );
    }

    #[test]
    fn observed_resource_set_is_globally_bounded() {
        let first = envelope_for("systemd:unit:first.service", 1_000, 1, "active");
        let second = envelope_for("systemd:unit:second.service", 1_500, 2, "active");
        let first_evidence = first.evidence_id();
        let first_request = request_for("systemd:unit:first.service");
        let second_request = request_for("systemd:unit:second.service");
        let mut coordinator = ObservationCoordinator::with_limits(1, 4)
            .unwrap_or_else(|error| unreachable!("{error}"));
        let observer = QueueObserver::new(vec![first, second]);
        assert_eq!(coordinator.register_observer(Box::new(observer)), Ok(()));
        assert!(coordinator.observe_at(&first_request, 1_100).is_ok());
        assert!(coordinator.observe_at(&second_request, 1_600).is_ok());

        assert!(
            coordinator
                .latest_observation(&first_request.resource)
                .is_none()
        );
        assert!(
            coordinator
                .graph()
                .node(&NodeId::Resource(first_request.resource.clone()))
                .is_none()
        );
        assert!(
            coordinator
                .graph()
                .node(&NodeId::Evidence(first_evidence))
                .is_none()
        );
        assert!(
            coordinator
                .graph()
                .node(&NodeId::Resource(second_request.resource.clone()))
                .is_some()
        );
        assert_eq!(coordinator.history.len(), 1);
        assert_eq!(coordinator.resource_last_seen.len(), 1);
    }

    #[test]
    fn zero_resource_limit_is_rejected() {
        assert!(matches!(
            ObservationCoordinator::with_limits(0, 1),
            Err(ObservationControlError::InvalidResourceLimit { max_resources: 0 })
        ));
    }

    #[test]
    fn retention_order_exhaustion_fails_before_graph_mutation() {
        let mut coordinator = ObservationCoordinator::new();
        coordinator.retention_order = u64::MAX;
        let observer = QueueObserver::new(vec![envelope(1_000, 1, "active")]);
        assert_eq!(coordinator.register_observer(Box::new(observer)), Ok(()));
        let result = coordinator.observe_at(&request(), 1_100);
        assert_eq!(
            result,
            Err(ObservationControlError::RetentionOrderExhausted)
        );
        assert_eq!(coordinator.graph().nodes().count(), 0);
    }

    #[test]
    fn zero_history_limit_is_rejected() {
        assert!(matches!(
            ObservationCoordinator::with_history_limit(0),
            Err(ObservationControlError::InvalidHistoryLimit {
                max_evidence_per_resource: 0
            })
        ));
    }

    #[test]
    fn unavailable_provider_fails_closed() {
        let mut coordinator = ObservationCoordinator::new();
        let mut observer = QueueObserver::new(vec![envelope(1_000, 1, "active")]);
        observer.health.availability = ProviderAvailability::Unavailable;
        observer.health.reason = Some("system bus service absent".into());
        assert_eq!(coordinator.register_observer(Box::new(observer)), Ok(()));
        assert!(matches!(
            coordinator.observe_at(&request(), 1_100),
            Err(ObservationControlError::ProviderUnavailable { .. })
        ));
    }

    #[test]
    fn registration_rejects_unbound_capability_identity() {
        let mut observer = QueueObserver::new(vec![envelope(1_000, 1, "active")]);
        observer.capability.provider = Some(id(ProviderId::new("spoofed")));
        let mut coordinator = ObservationCoordinator::new();
        assert!(matches!(
            coordinator.register_observer(Box::new(observer)),
            Err(ObservationControlError::CapabilityProviderMismatch { .. })
        ));
    }
}
