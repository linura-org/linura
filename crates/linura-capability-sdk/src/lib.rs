#![forbid(unsafe_code)]

use linura_core::{CapabilityId, OperationClass, OperationId, ProviderId, ResourceId, RiskClass};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationDescriptorError {
    MissingRiskFloor,
    UnexpectedRiskFloor,
    InvalidRiskFloor,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationDescriptor {
    id: OperationId,
    class: OperationClass,
    risk_floor: Option<RiskClass>,
}

impl OperationDescriptor {
    pub fn try_new(
        id: OperationId,
        class: OperationClass,
        risk_floor: Option<RiskClass>,
    ) -> Result<Self, OperationDescriptorError> {
        match class {
            OperationClass::ExperienceEphemeral => {
                if risk_floor.is_some() {
                    return Err(OperationDescriptorError::UnexpectedRiskFloor);
                }
            }
            OperationClass::AuthoritativeQuery => {
                if risk_floor != Some(RiskClass::ReadOnly) {
                    return Err(OperationDescriptorError::InvalidRiskFloor);
                }
            }
            OperationClass::LinuraOwnedState | OperationClass::ManagedExternalEffect => {
                match risk_floor {
                    Some(
                        RiskClass::UserState
                        | RiskClass::SystemMutation
                        | RiskClass::SecuritySensitive
                        | RiskClass::Destructive,
                    ) => {}
                    Some(RiskClass::ReadOnly) => {
                        return Err(OperationDescriptorError::InvalidRiskFloor);
                    }
                    None => return Err(OperationDescriptorError::MissingRiskFloor),
                }
            }
            OperationClass::TransientExternalEffect => {
                if risk_floor != Some(RiskClass::UserState) {
                    return Err(OperationDescriptorError::InvalidRiskFloor);
                }
            }
        }
        Ok(Self {
            id,
            class,
            risk_floor,
        })
    }

    #[must_use]
    pub fn id(&self) -> &OperationId {
        &self.id
    }

    #[must_use]
    pub const fn class(&self) -> OperationClass {
        self.class
    }

    #[must_use]
    pub const fn risk_floor(&self) -> Option<RiskClass> {
        self.risk_floor
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperationRegistryError {
    DuplicateOperation(OperationId),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OperationRegistry {
    descriptors: BTreeMap<OperationId, OperationDescriptor>,
}

impl OperationRegistry {
    pub fn register(
        &mut self,
        descriptor: OperationDescriptor,
    ) -> Result<(), OperationRegistryError> {
        let id = descriptor.id().clone();
        if self.descriptors.contains_key(&id) {
            return Err(OperationRegistryError::DuplicateOperation(id));
        }
        self.descriptors.insert(id, descriptor);
        Ok(())
    }

    #[must_use]
    pub fn descriptor(&self, id: &OperationId) -> Option<&OperationDescriptor> {
        self.descriptors.get(id)
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &OperationDescriptor> {
        self.descriptors.values()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.descriptors.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.descriptors.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityRelationKind {
    Requires,
    Provides,
    Conflicts,
    Replaces,
    Recommends,
    Optional,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityRelation {
    pub kind: CapabilityRelationKind,
    pub capability: CapabilityId,
}

/// Provider-neutral declarative resource contribution made by a capability.
///
/// The blueprint describes the state that should hold and the authoritative
/// observation route used to compare that state with reality. It is not an
/// executor command and carries no mutation authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesiredResourceBlueprint {
    pub provider: ProviderId,
    pub resource: ResourceId,
    pub observation_capability: CapabilityId,
    pub state: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityBlueprint {
    pub id: CapabilityId,
    pub title: String,
    pub relations: Vec<CapabilityRelation>,
    pub desired_resources: Vec<DesiredResourceBlueprint>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CapabilityCatalog {
    blueprints: BTreeMap<CapabilityId, CapabilityBlueprint>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Resolution {
    pub selected: BTreeSet<CapabilityId>,
    pub conflicts: Vec<(CapabilityId, CapabilityId)>,
    pub missing: BTreeSet<CapabilityId>,
}

fn canonical_conflict_pair(
    left: CapabilityId,
    right: CapabilityId,
) -> (CapabilityId, CapabilityId) {
    if left.as_str() <= right.as_str() {
        (left, right)
    } else {
        (right, left)
    }
}

impl CapabilityCatalog {
    pub fn register(&mut self, blueprint: CapabilityBlueprint) {
        self.blueprints.insert(blueprint.id.clone(), blueprint);
    }

    #[must_use]
    pub fn blueprint(&self, id: &CapabilityId) -> Option<&CapabilityBlueprint> {
        self.blueprints.get(id)
    }

    pub fn resolve(&self, requested: &[CapabilityId]) -> Resolution {
        let mut result = Resolution::default();
        let mut pending: Vec<CapabilityId> = requested.to_vec();
        while let Some(id) = pending.pop() {
            if !result.selected.insert(id.clone()) {
                continue;
            }
            let Some(blueprint) = self.blueprints.get(&id) else {
                result.missing.insert(id);
                continue;
            };
            for relation in &blueprint.relations {
                match relation.kind {
                    CapabilityRelationKind::Requires => pending.push(relation.capability.clone()),
                    CapabilityRelationKind::Conflicts
                        if result.selected.contains(&relation.capability) =>
                    {
                        let pair = canonical_conflict_pair(id.clone(), relation.capability.clone());
                        if !result.conflicts.contains(&pair) {
                            result.conflicts.push(pair);
                        }
                    }
                    _ => {}
                }
            }
        }
        for selected in &result.selected {
            if let Some(blueprint) = self.blueprints.get(selected) {
                for relation in &blueprint.relations {
                    if relation.kind == CapabilityRelationKind::Conflicts
                        && result.selected.contains(&relation.capability)
                    {
                        let pair =
                            canonical_conflict_pair(selected.clone(), relation.capability.clone());
                        if !result.conflicts.contains(&pair) {
                            result.conflicts.push(pair);
                        }
                    }
                }
            }
        }
        result.conflicts.sort_by(|left, right| {
            left.0
                .as_str()
                .cmp(right.0.as_str())
                .then_with(|| left.1.as_str().cmp(right.1.as_str()))
        });
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_core::ValidationError;

    fn id(result: Result<CapabilityId, ValidationError>) -> CapabilityId {
        result.unwrap_or_else(|error| unreachable!("{error}"))
    }

    fn conflicting_blueprint(id_value: &str, other: &CapabilityId) -> CapabilityBlueprint {
        CapabilityBlueprint {
            id: id(CapabilityId::new(id_value)),
            title: id_value.into(),
            relations: vec![CapabilityRelation {
                kind: CapabilityRelationKind::Conflicts,
                capability: other.clone(),
            }],
            desired_resources: vec![],
        }
    }

    #[test]
    fn operation_registry_rejects_duplicate_ids_without_overwrite() {
        let operation_id = OperationId::new("operation:audio.volume.set-session")
            .unwrap_or_else(|error| unreachable!("{error}"));
        let descriptor = OperationDescriptor::try_new(
            operation_id.clone(),
            OperationClass::TransientExternalEffect,
            Some(RiskClass::UserState),
        )
        .unwrap_or_else(|error| unreachable!("{error:?}"));

        let mut registry = OperationRegistry::default();
        registry
            .register(descriptor.clone())
            .unwrap_or_else(|error| unreachable!("{error:?}"));

        assert_eq!(
            registry.register(descriptor.clone()),
            Err(OperationRegistryError::DuplicateOperation(
                operation_id.clone()
            ))
        );
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.descriptor(&operation_id), Some(&descriptor));
    }

    #[test]
    fn operation_registry_iteration_is_deterministic_by_operation_id() {
        let mut registry = OperationRegistry::default();
        for value in ["operation:z", "operation:a", "operation:m"] {
            registry
                .register(
                    OperationDescriptor::try_new(
                        OperationId::new(value)
                            .unwrap_or_else(|error| unreachable!("{error}")),
                        OperationClass::AuthoritativeQuery,
                        Some(RiskClass::ReadOnly),
                    )
                    .unwrap_or_else(|error| unreachable!("{error:?}")),
                )
                .unwrap_or_else(|error| unreachable!("{error:?}"));
        }

        let ids = registry
            .iter()
            .map(|descriptor| descriptor.id().as_str())
            .collect::<Vec<_>>();
        assert_eq!(ids, vec!["operation:a", "operation:m", "operation:z"]);
    }

    #[test]
    fn operation_descriptor_enforces_class_risk_floor() {
        let query = OperationDescriptor::try_new(
            OperationId::new("operation:network.inspect")
                .unwrap_or_else(|error| unreachable!("{error}")),
            OperationClass::AuthoritativeQuery,
            Some(RiskClass::ReadOnly),
        )
        .unwrap_or_else(|error| unreachable!("{error:?}"));
        assert_eq!(query.class(), OperationClass::AuthoritativeQuery);

        let transient = OperationDescriptor::try_new(
            OperationId::new("operation:audio.volume.set-session")
                .unwrap_or_else(|error| unreachable!("{error}")),
            OperationClass::TransientExternalEffect,
            Some(RiskClass::UserState),
        )
        .unwrap_or_else(|error| unreachable!("{error:?}"));
        assert_eq!(transient.risk_floor(), Some(RiskClass::UserState));

        assert_eq!(
            OperationDescriptor::try_new(
                OperationId::new("operation:network.enable")
                    .unwrap_or_else(|error| unreachable!("{error}")),
                OperationClass::TransientExternalEffect,
                Some(RiskClass::SystemMutation),
            ),
            Err(OperationDescriptorError::InvalidRiskFloor)
        );

        let managed = OperationDescriptor::try_new(
            OperationId::new("operation:storage.replace")
                .unwrap_or_else(|error| unreachable!("{error}")),
            OperationClass::ManagedExternalEffect,
            Some(RiskClass::Destructive),
        )
        .unwrap_or_else(|error| unreachable!("{error:?}"));
        assert_eq!(managed.class(), OperationClass::ManagedExternalEffect);
    }

    #[test]
    fn required_capabilities_are_selected() {
        let ai = id(CapabilityId::new("development.ai"));
        let python = id(CapabilityId::new("development.python"));
        let mut catalog = CapabilityCatalog::default();
        catalog.register(CapabilityBlueprint {
            id: ai.clone(),
            title: "AI development".into(),
            relations: vec![CapabilityRelation {
                kind: CapabilityRelationKind::Requires,
                capability: python.clone(),
            }],
            desired_resources: vec![],
        });
        catalog.register(CapabilityBlueprint {
            id: python.clone(),
            title: "Python".into(),
            relations: vec![],
            desired_resources: vec![],
        });
        let resolution = catalog.resolve(&[ai]);
        assert!(resolution.selected.contains(&python));
        assert!(resolution.missing.is_empty());
    }

    #[test]
    fn conflict_pairs_are_canonical_for_equivalent_request_orders() {
        let alpha = id(CapabilityId::new("capability.alpha"));
        let beta = id(CapabilityId::new("capability.beta"));
        let mut catalog = CapabilityCatalog::default();
        catalog.register(conflicting_blueprint(alpha.as_str(), &beta));
        catalog.register(conflicting_blueprint(beta.as_str(), &alpha));

        let forward = catalog.resolve(&[alpha.clone(), beta.clone()]);
        let reverse = catalog.resolve(&[beta.clone(), alpha.clone()]);

        assert_eq!(forward, reverse);
        assert_eq!(forward.conflicts, vec![(alpha, beta)]);
    }

    #[test]
    fn blueprint_lookup_preserves_declarative_resource_identity() {
        let capability = id(CapabilityId::new("remote.ssh"));
        let provider = ProviderId::new("systemd").unwrap_or_else(|error| unreachable!("{error}"));
        let resource = ResourceId::new("systemd:unit:ssh.service")
            .unwrap_or_else(|error| unreachable!("{error}"));
        let observation = id(CapabilityId::new("systemd.unit.observe"));
        let mut catalog = CapabilityCatalog::default();
        catalog.register(CapabilityBlueprint {
            id: capability.clone(),
            title: "SSH service".into(),
            relations: vec![],
            desired_resources: vec![DesiredResourceBlueprint {
                provider: provider.clone(),
                resource: resource.clone(),
                observation_capability: observation,
                state: BTreeMap::from([("active_state".into(), "active".into())]),
            }],
        });

        let blueprint = catalog
            .blueprint(&capability)
            .unwrap_or_else(|| unreachable!("registered blueprint is missing"));
        assert_eq!(blueprint.desired_resources[0].provider, provider);
        assert_eq!(blueprint.desired_resources[0].resource, resource);
    }
}
