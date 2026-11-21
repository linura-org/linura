//! Fresh Root successor-spend comparison. These facts contain no credential and
//! never substitute for independently observed native layout/input protection.
use crate::display::{boolean, canonical_digest, number, text};
use crate::{
    DISPLAY_RECOVERY_PROVIDER, DisplayEvidenceError, ObservationAuthority, ObservationEnvelope,
    ObservedValue,
};
use linura_core::DisplayRecoveryScope;
use std::collections::BTreeMap;

pub const DISPLAY_SUCCESSOR_CAPABILITY: &str = "display.successor.observe";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplaySuccessorLineage {
    pub record: String,
    pub released_parent: String,
    pub checkpoint: String,
    pub native_guard: String,
    pub transaction: String,
    pub effect: String,
    pub dispatch: String,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplaySuccessorFacts {
    scope: DisplayRecoveryScope,
    lineage: DisplaySuccessorLineage,
    spent: bool,
}
impl DisplaySuccessorFacts {
    pub fn new(
        scope: DisplayRecoveryScope,
        lineage: DisplaySuccessorLineage,
        spent: bool,
    ) -> Result<Self, DisplayEvidenceError> {
        if [
            &lineage.record,
            &lineage.released_parent,
            &lineage.checkpoint,
            &lineage.native_guard,
            &lineage.effect,
            &lineage.dispatch,
        ]
        .iter()
        .any(|v| !canonical_digest(v))
            || !lineage.transaction.starts_with("transaction:")
            || lineage.transaction.len() <= "transaction:".len()
            || lineage.transaction.len() > 256
            || !lineage
                .transaction
                .bytes()
                .all(|v| v.is_ascii_alphanumeric() || b":-_".contains(&v))
            || lineage.dispatch == scope.original_dispatch()
        {
            return Err(DisplayEvidenceError::Shape);
        }
        Ok(Self {
            scope,
            lineage,
            spent,
        })
    }
    pub fn attributes(&self) -> BTreeMap<String, ObservedValue> {
        let mut attributes = BTreeMap::from([
            ("successor_schema".into(), ObservedValue::U64(1)),
            (
                "original_dispatch".into(),
                ObservedValue::Text(self.scope.original_dispatch().into()),
            ),
            ("spent".into(), ObservedValue::Bool(self.spent)),
        ]);
        for (key, value) in [
            ("record_digest", &self.lineage.record),
            ("released_parent_digest", &self.lineage.released_parent),
            ("checkpoint_digest", &self.lineage.checkpoint),
            ("native_guard_digest", &self.lineage.native_guard),
            ("transaction", &self.lineage.transaction),
            ("effect_digest", &self.lineage.effect),
            ("dispatch_digest", &self.lineage.dispatch),
        ] {
            attributes.insert(key.into(), ObservedValue::Text(value.clone()));
        }
        attributes
    }
    pub fn from_envelope(
        sample: &ObservationEnvelope,
        scope: &DisplayRecoveryScope,
        now: u64,
    ) -> Result<Self, DisplayEvidenceError> {
        if sample.provider.as_str() != DISPLAY_RECOVERY_PROVIDER
            || sample.capability.as_str() != DISPLAY_SUCCESSOR_CAPABILITY
            || sample.resource
                != scope
                    .resource_id()
                    .map_err(|_| DisplayEvidenceError::Identity)?
            || sample.authority != ObservationAuthority::NativeApi
            || sample.sequence == 0
        {
            return Err(DisplayEvidenceError::Identity);
        }
        if sample.observed_at_unix_ms == 0
            || sample.valid_for_ms == 0
            || sample.valid_for_ms > 2000
            || now
                .checked_sub(sample.observed_at_unix_ms)
                .is_none_or(|age| age >= sample.valid_for_ms)
        {
            return Err(DisplayEvidenceError::Freshness);
        }
        let a = &sample.attributes;
        if a.len() != 10
            || number(a, "successor_schema")? != 1
            || text(a, "original_dispatch")? != scope.original_dispatch()
        {
            return Err(DisplayEvidenceError::Shape);
        }
        Self::new(
            scope.clone(),
            DisplaySuccessorLineage {
                record: text(a, "record_digest")?.into(),
                released_parent: text(a, "released_parent_digest")?.into(),
                checkpoint: text(a, "checkpoint_digest")?.into(),
                native_guard: text(a, "native_guard_digest")?.into(),
                transaction: text(a, "transaction")?.into(),
                effect: text(a, "effect_digest")?.into(),
                dispatch: text(a, "dispatch_digest")?.into(),
            },
            boolean(a, "spent")?,
        )
    }
    pub const fn lineage(&self) -> &DisplaySuccessorLineage {
        &self.lineage
    }
    pub const fn spent(&self) -> bool {
        self.spent
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_core::{CapabilityId, DisplayFinalizationMaterial, ProviderId};
    fn value<T, E: std::fmt::Debug>(v: Result<T, E>) -> T {
        v.unwrap_or_else(|e| unreachable!("{e:?}"))
    }
    #[test]
    fn successor_permission_requires_exact_closed_fresh_native_root_evidence() {
        let material = value(DisplayFinalizationMaterial::decode(
            include_str!(
                "../../linura-core/src/display_recovery/fixtures/original-finalization.txt"
            )
            .trim_end(),
        ));
        let scope = value(material.recovery_scope());
        let facts = value(DisplaySuccessorFacts::new(
            scope.clone(),
            DisplaySuccessorLineage {
                record: "1".repeat(64),
                released_parent: "2".repeat(64),
                checkpoint: "3".repeat(64),
                native_guard: "4".repeat(64),
                transaction: "transaction:next".into(),
                effect: "5".repeat(64),
                dispatch: "6".repeat(64),
            },
            true,
        ));
        let sample = ObservationEnvelope {
            provider: value(ProviderId::new(DISPLAY_RECOVERY_PROVIDER)),
            capability: value(CapabilityId::new(DISPLAY_SUCCESSOR_CAPABILITY)),
            resource: value(scope.resource_id()),
            authority: ObservationAuthority::NativeApi,
            sequence: 1,
            observed_at_unix_ms: 1000,
            valid_for_ms: 2000,
            attributes: facts.attributes(),
        };
        assert_eq!(
            value(DisplaySuccessorFacts::from_envelope(&sample, &scope, 1001)),
            facts
        );
        for now in [0, 999, 3000, u64::MAX] {
            assert!(DisplaySuccessorFacts::from_envelope(&sample, &scope, now).is_err());
        }
        for key in sample.attributes.keys() {
            let mut incomplete = sample.clone();
            incomplete.attributes.remove(key);
            assert!(DisplaySuccessorFacts::from_envelope(&incomplete, &scope, 1001).is_err());
        }
        let mut changed = sample.clone();
        changed
            .attributes
            .insert("extra".into(), ObservedValue::Bool(true));
        assert!(DisplaySuccessorFacts::from_envelope(&changed, &scope, 1001).is_err());
        for authority in [
            ObservationAuthority::Filesystem,
            ObservationAuthority::SyntheticTest,
        ] {
            let mut changed = sample.clone();
            changed.authority = authority;
            assert!(DisplaySuccessorFacts::from_envelope(&changed, &scope, 1001).is_err());
        }
        let mut changed = sample;
        changed.sequence = 0;
        assert!(DisplaySuccessorFacts::from_envelope(&changed, &scope, 1001).is_err());
    }
}
