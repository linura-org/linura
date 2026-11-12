//! Original Root's durable native-power grant state. A spent permission cannot
//! prove that native power was physically retired; Control joins that separately.
use crate::display::{boolean, canonical_digest, number, text};
use crate::{
    DISPLAY_RECOVERY_PROVIDER, DisplayEvidenceError, ObservationAuthority, ObservationEnvelope,
    ObservedValue,
};
use linura_core::DisplayRecoveryScope;
use std::collections::BTreeMap;

pub const DISPLAY_ORIGINAL_POWER_RETIREMENT_CAPABILITY: &str =
    "display.original-power-retirement.observe";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayOriginalPowerRetirementFacts {
    scope: DisplayRecoveryScope,
    record: String,
    parent: String,
    preparation: String,
    checkpoint: String,
    spent: bool,
}
impl DisplayOriginalPowerRetirementFacts {
    pub fn new(
        scope: DisplayRecoveryScope,
        record: String,
        parent: String,
        preparation: String,
        checkpoint: String,
        spent: bool,
    ) -> Result<Self, DisplayEvidenceError> {
        if [&record, &parent, &preparation, &checkpoint]
            .iter()
            .any(|v| !canonical_digest(v))
            || preparation == checkpoint
        {
            return Err(DisplayEvidenceError::Shape);
        }
        Ok(Self {
            scope,
            record,
            parent,
            preparation,
            checkpoint,
            spent,
        })
    }
    pub fn attributes(&self) -> BTreeMap<String, ObservedValue> {
        BTreeMap::from([
            ("power_retirement_schema".into(), ObservedValue::U64(1)),
            (
                "original_dispatch".into(),
                ObservedValue::Text(self.scope.original_dispatch().into()),
            ),
            (
                "record_digest".into(),
                ObservedValue::Text(self.record.clone()),
            ),
            (
                "completion_digest".into(),
                ObservedValue::Text(self.parent.clone()),
            ),
            (
                "preparation_digest".into(),
                ObservedValue::Text(self.preparation.clone()),
            ),
            (
                "checkpoint_digest".into(),
                ObservedValue::Text(self.checkpoint.clone()),
            ),
            ("grant_spent".into(), ObservedValue::Bool(self.spent)),
        ])
    }
    pub fn from_envelope(
        observation: &ObservationEnvelope,
        scope: &DisplayRecoveryScope,
        now: u64,
    ) -> Result<Self, DisplayEvidenceError> {
        if observation.provider.as_str() != DISPLAY_RECOVERY_PROVIDER
            || observation.capability.as_str() != DISPLAY_ORIGINAL_POWER_RETIREMENT_CAPABILITY
            || observation.authority != ObservationAuthority::NativeApi
            || observation.resource
                != scope
                    .resource_id()
                    .map_err(|_| DisplayEvidenceError::Identity)?
            || observation.sequence == 0
        {
            return Err(DisplayEvidenceError::Identity);
        }
        if observation.observed_at_unix_ms == 0
            || observation.valid_for_ms == 0
            || observation.valid_for_ms > 2000
            || now
                .checked_sub(observation.observed_at_unix_ms)
                .is_none_or(|age| age >= observation.valid_for_ms)
        {
            return Err(DisplayEvidenceError::Freshness);
        }
        let attrs = &observation.attributes;
        if attrs.len() != 7
            || number(attrs, "power_retirement_schema")? != 1
            || text(attrs, "original_dispatch")? != scope.original_dispatch()
        {
            return Err(DisplayEvidenceError::Shape);
        }
        let result = Self::new(
            scope.clone(),
            text(attrs, "record_digest")?.into(),
            text(attrs, "completion_digest")?.into(),
            text(attrs, "preparation_digest")?.into(),
            text(attrs, "checkpoint_digest")?.into(),
            boolean(attrs, "grant_spent")?,
        )?;
        if result.attributes() != *attrs {
            return Err(DisplayEvidenceError::Shape);
        }
        Ok(result)
    }
    pub fn record_digest(&self) -> &str {
        &self.record
    }
    pub fn completion_digest(&self) -> &str {
        &self.parent
    }
    pub fn preparation_digest(&self) -> &str {
        &self.preparation
    }
    pub fn checkpoint_digest(&self) -> &str {
        &self.checkpoint
    }
    pub fn grant_spent(&self) -> bool {
        self.spent
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_core::{CapabilityId, DisplayFinalizationMaterial, ProviderId};
    fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|e| unreachable!("{e:?}"))
    }
    #[test]
    fn root_power_permission_has_closed_typed_fresh_source_bound_observation() {
        let material = value(DisplayFinalizationMaterial::decode(
            include_str!(
                "../../linura-core/src/display_recovery/fixtures/original-finalization.txt"
            )
            .trim_end(),
        ));
        let scope = value(material.recovery_scope());
        let facts = value(DisplayOriginalPowerRetirementFacts::new(
            scope.clone(),
            "1".repeat(64),
            "2".repeat(64),
            "3".repeat(64),
            "4".repeat(64),
            true,
        ));
        let observation = ObservationEnvelope {
            provider: value(ProviderId::new(DISPLAY_RECOVERY_PROVIDER)),
            capability: value(CapabilityId::new(
                DISPLAY_ORIGINAL_POWER_RETIREMENT_CAPABILITY,
            )),
            resource: value(scope.resource_id()),
            authority: ObservationAuthority::NativeApi,
            sequence: 1,
            observed_at_unix_ms: 1000,
            valid_for_ms: 2000,
            attributes: facts.attributes(),
        };
        assert_eq!(
            value(DisplayOriginalPowerRetirementFacts::from_envelope(
                &observation,
                &scope,
                1001
            )),
            facts
        );
        for fault in 0..9 {
            let mut changed = observation.clone();
            match fault {
                0 => changed.provider = value(ProviderId::new("attacker")),
                1 => {
                    changed.capability =
                        value(CapabilityId::new("display.original-completion.observe"))
                }
                2 => changed.authority = ObservationAuthority::SyntheticTest,
                3 => changed.sequence = 0,
                4 => changed.valid_for_ms = 2001,
                5 => {
                    changed
                        .attributes
                        .insert("extra".into(), ObservedValue::Bool(true));
                }
                6 => {
                    changed
                        .attributes
                        .insert("grant_spent".into(), ObservedValue::Text("true".into()));
                }
                7 => {
                    changed.attributes.insert(
                        "preparation_digest".into(),
                        ObservedValue::Text("0".repeat(64)),
                    );
                }
                _ => {
                    changed.attributes.insert(
                        "checkpoint_digest".into(),
                        ObservedValue::Text("3".repeat(64)),
                    );
                }
            }
            assert!(
                DisplayOriginalPowerRetirementFacts::from_envelope(&changed, &scope, 1001).is_err(),
                "fault {fault}"
            );
        }
        for now in [0, 999, 3000, u64::MAX] {
            assert!(
                DisplayOriginalPowerRetirementFacts::from_envelope(&observation, &scope, now)
                    .is_err()
            );
        }
        // Both phases are observations; prepared is not a spent grant.
        let mut prepared = observation;
        prepared
            .attributes
            .insert("grant_spent".into(), ObservedValue::Bool(false));
        assert!(
            !value(DisplayOriginalPowerRetirementFacts::from_envelope(
                &prepared, &scope, 1001
            ))
            .grant_spent()
        );
    }
}
