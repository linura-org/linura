#![forbid(unsafe_code)]

use linura_core::{CapabilityId, OperationClass, OperationId, ProviderId, ResourceId, RiskClass};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationEffectBindingError {
    EmptyResourcePrefix,
    ResourcePrefixTooLong,
    ResourcePrefixControlCharacter,
    EmptyResourceSuffix,
    ResourceSuffixTooLong,
    ResourceSuffixControlCharacter,
    EmptyChangeKeys,
    InvalidChangeKey,
    DuplicateChangeKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationEffectBinding {
    provider: ProviderId,
    observation_capability: CapabilityId,
    resource_prefix: String,
    resource_suffix: Option<String>,
    change_keys: BTreeSet<String>,
}

impl OperationEffectBinding {
    pub fn try_new(
        provider: ProviderId,
        observation_capability: CapabilityId,
        resource_prefix: impl Into<String>,
        change_keys: Vec<String>,
    ) -> Result<Self, OperationEffectBindingError> {
        let resource_prefix = resource_prefix.into();
        if resource_prefix.trim().is_empty() {
            return Err(OperationEffectBindingError::EmptyResourcePrefix);
        }
        if resource_prefix.len() > 256 {
            return Err(OperationEffectBindingError::ResourcePrefixTooLong);
        }
        if resource_prefix.chars().any(char::is_control) {
            return Err(OperationEffectBindingError::ResourcePrefixControlCharacter);
        }
        if change_keys.is_empty() {
            return Err(OperationEffectBindingError::EmptyChangeKeys);
        }

        let mut canonical_change_keys = BTreeSet::new();
        for key in change_keys {
            if key.trim().is_empty() || key.len() > 256 || key.chars().any(char::is_control) {
                return Err(OperationEffectBindingError::InvalidChangeKey);
            }
            if !canonical_change_keys.insert(key) {
                return Err(OperationEffectBindingError::DuplicateChangeKey);
            }
        }

        Ok(Self {
            provider,
            observation_capability,
            resource_prefix,
            resource_suffix: None,
            change_keys: canonical_change_keys,
        })
    }

    #[must_use]
    pub fn provider(&self) -> &ProviderId {
        &self.provider
    }

    #[must_use]
    pub fn observation_capability(&self) -> &CapabilityId {
        &self.observation_capability
    }

    #[must_use]
    pub fn resource_prefix(&self) -> &str {
        &self.resource_prefix
    }

    pub fn with_resource_suffix(
        mut self,
        resource_suffix: impl Into<String>,
    ) -> Result<Self, OperationEffectBindingError> {
        let resource_suffix = resource_suffix.into();
        if resource_suffix.is_empty() {
            return Err(OperationEffectBindingError::EmptyResourceSuffix);
        }
        if resource_suffix.len() > 256 {
            return Err(OperationEffectBindingError::ResourceSuffixTooLong);
        }
        if resource_suffix.chars().any(char::is_control) {
            return Err(OperationEffectBindingError::ResourceSuffixControlCharacter);
        }
        self.resource_suffix = Some(resource_suffix);
        Ok(self)
    }

    #[must_use]
    pub fn resource_suffix(&self) -> Option<&str> {
        self.resource_suffix.as_deref()
    }

    #[must_use]
    pub fn matches_resource(&self, resource: &str) -> bool {
        resource.starts_with(&self.resource_prefix)
            && self
                .resource_suffix
                .as_deref()
                .is_none_or(|suffix| resource.ends_with(suffix))
    }

    #[must_use]
    pub fn change_keys(&self) -> &BTreeSet<String> {
        &self.change_keys
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationDescriptorError {
    MissingRiskFloor,
    UnexpectedRiskFloor,
    InvalidRiskFloor,
    MissingEffectBinding,
    UnexpectedEffectBinding,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationDescriptor {
    id: OperationId,
    class: OperationClass,
    risk_floor: Option<RiskClass>,
    effect_binding: Option<OperationEffectBinding>,
}

impl OperationDescriptor {
    pub fn try_new(
        id: OperationId,
        class: OperationClass,
        risk_floor: Option<RiskClass>,
        effect_binding: Option<OperationEffectBinding>,
    ) -> Result<Self, OperationDescriptorError> {
        match class {
            OperationClass::ExperienceEphemeral => {
                if risk_floor.is_some() {
                    return Err(OperationDescriptorError::UnexpectedRiskFloor);
                }
                if effect_binding.is_some() {
                    return Err(OperationDescriptorError::UnexpectedEffectBinding);
                }
            }
            OperationClass::AuthoritativeQuery => {
                if risk_floor != Some(RiskClass::ReadOnly) {
                    return Err(OperationDescriptorError::InvalidRiskFloor);
                }
                if effect_binding.is_some() {
                    return Err(OperationDescriptorError::UnexpectedEffectBinding);
                }
            }
            OperationClass::LinuraOwnedState => {
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
                if effect_binding.is_some() {
                    return Err(OperationDescriptorError::UnexpectedEffectBinding);
                }
            }
            OperationClass::ManagedExternalEffect => {
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
                if effect_binding.is_none() {
                    return Err(OperationDescriptorError::MissingEffectBinding);
                }
            }
            OperationClass::TransientExternalEffect => {
                if risk_floor != Some(RiskClass::UserState) {
                    return Err(OperationDescriptorError::InvalidRiskFloor);
                }
                if effect_binding.is_none() {
                    return Err(OperationDescriptorError::MissingEffectBinding);
                }
            }
        }
        Ok(Self {
            id,
            class,
            risk_floor,
            effect_binding,
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

    #[must_use]
    pub fn effect_binding(&self) -> Option<&OperationEffectBinding> {
        self.effect_binding.as_ref()
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
        match self.descriptors.entry(id) {
            std::collections::btree_map::Entry::Occupied(entry) => Err(
                OperationRegistryError::DuplicateOperation(entry.key().clone()),
            ),
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(descriptor);
                Ok(())
            }
        }
    }

    #[must_use]
    pub fn descriptor(&self, id: &OperationId) -> Option<&OperationDescriptor> {
        self.descriptors.get(id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &OperationDescriptor> + '_ {
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

    fn systemd_effect_binding() -> OperationEffectBinding {
        OperationEffectBinding::try_new(
            ProviderId::new("systemd").unwrap_or_else(|error| unreachable!("{error}")),
            CapabilityId::new("systemd.unit.observe")
                .unwrap_or_else(|error| unreachable!("{error}")),
            "systemd:unit:",
            vec!["active_state".into()],
        )
        .unwrap_or_else(|error| unreachable!("{error:?}"))
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
    fn operation_effect_binding_can_narrow_resource_scope_with_suffix() {
        let binding = systemd_effect_binding()
            .with_resource_suffix(".service")
            .unwrap_or_else(|error| unreachable!("{error:?}"));

        assert!(binding.matches_resource("systemd:unit:linura-managed-example.service"));
        assert!(!binding.matches_resource("systemd:unit:linura-managed-example.timer"));
        assert_eq!(binding.resource_suffix(), Some(".service"));
    }

    #[test]
    fn operation_effect_binding_rejects_empty_resource_suffix() {
        assert_eq!(
            systemd_effect_binding().with_resource_suffix(""),
            Err(OperationEffectBindingError::EmptyResourceSuffix)
        );
    }

    #[test]
    fn operation_registry_rejects_duplicate_ids_without_overwrite() {
        let operation_id = OperationId::new("operation:audio.volume.set-session")
            .unwrap_or_else(|error| unreachable!("{error}"));
        let descriptor = OperationDescriptor::try_new(
            operation_id.clone(),
            OperationClass::TransientExternalEffect,
            Some(RiskClass::UserState),
            Some(systemd_effect_binding()),
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
                        OperationId::new(value).unwrap_or_else(|error| unreachable!("{error}")),
                        OperationClass::AuthoritativeQuery,
                        Some(RiskClass::ReadOnly),
                        None,
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
            None,
        )
        .unwrap_or_else(|error| unreachable!("{error:?}"));
        assert_eq!(query.class(), OperationClass::AuthoritativeQuery);

        let transient = OperationDescriptor::try_new(
            OperationId::new("operation:audio.volume.set-session")
                .unwrap_or_else(|error| unreachable!("{error}")),
            OperationClass::TransientExternalEffect,
            Some(RiskClass::UserState),
            Some(systemd_effect_binding()),
        )
        .unwrap_or_else(|error| unreachable!("{error:?}"));
        assert_eq!(transient.risk_floor(), Some(RiskClass::UserState));

        assert_eq!(
            OperationDescriptor::try_new(
                OperationId::new("operation:network.enable")
                    .unwrap_or_else(|error| unreachable!("{error}")),
                OperationClass::TransientExternalEffect,
                Some(RiskClass::SystemMutation),
                Some(systemd_effect_binding()),
            ),
            Err(OperationDescriptorError::InvalidRiskFloor)
        );

        let managed = OperationDescriptor::try_new(
            OperationId::new("operation:storage.replace")
                .unwrap_or_else(|error| unreachable!("{error}")),
            OperationClass::ManagedExternalEffect,
            Some(RiskClass::Destructive),
            Some(systemd_effect_binding()),
        )
        .unwrap_or_else(|error| unreachable!("{error:?}"));
        assert_eq!(managed.class(), OperationClass::ManagedExternalEffect);
    }

    #[test]
    fn external_operation_requires_effect_binding() {
        assert_eq!(
            OperationDescriptor::try_new(
                OperationId::new("operation:service.manage")
                    .unwrap_or_else(|error| unreachable!("{error}")),
                OperationClass::ManagedExternalEffect,
                Some(RiskClass::SystemMutation),
                None,
            ),
            Err(OperationDescriptorError::MissingEffectBinding)
        );
    }

    #[test]
    fn effect_binding_rejects_duplicate_change_keys() {
        assert_eq!(
            OperationEffectBinding::try_new(
                ProviderId::new("systemd").unwrap_or_else(|error| unreachable!("{error}")),
                CapabilityId::new("systemd.unit.observe")
                    .unwrap_or_else(|error| unreachable!("{error}")),
                "systemd:unit:",
                vec!["active_state".into(), "active_state".into()],
            ),
            Err(OperationEffectBindingError::DuplicateChangeKey)
        );
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
