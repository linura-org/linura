//! Original Root after its separately prepared power close. Original source
//! and completion are retained comparison data; the fresh authority here is
//! only Root/kernel continuity and independent scope-specific power absence.
use crate::display::{boolean, canonical_digest, number, text};
use crate::{
    DISPLAY_RECOVERY_PROVIDER, DisplayEvidenceError, DisplayOriginalCompletionFacts,
    DisplayOriginalProtectionFacts, ObservationAuthority, ObservationEnvelope, ObservedValue,
};
use linura_core::DisplayRecoveryScope;
use std::collections::BTreeMap;

pub const DISPLAY_ORIGINAL_ROOT_RETIREMENT_CAPABILITY: &str =
    "display.original-root-retirement.observe";
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayRootRetirementLineage {
    pub record: String,
    pub preparation: String,
    pub verification: String,
    pub power_record: String,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayCurrentGrantLineage {
    pub record: String,
    pub preparation: String,
    pub committed_record: String,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayOriginalRootRetirementFacts {
    lineage: DisplayRootRetirementLineage,
    original: DisplayOriginalProtectionFacts,
    completion: DisplayOriginalCompletionFacts,
    current_grant: Option<DisplayCurrentGrantLineage>,
}
impl DisplayOriginalRootRetirementFacts {
    pub fn new(
        lineage: DisplayRootRetirementLineage,
        original: DisplayOriginalProtectionFacts,
        completion: DisplayOriginalCompletionFacts,
        current_grant: Option<DisplayCurrentGrantLineage>,
    ) -> Result<Self, DisplayEvidenceError> {
        if current_grant.as_ref().is_some_and(|grant| {
            [&grant.record, &grant.preparation, &grant.committed_record]
                .into_iter()
                .any(|digest| !canonical_digest(digest))
        }) || [
            &lineage.record,
            &lineage.preparation,
            &lineage.verification,
            &lineage.power_record,
        ]
        .iter()
        .any(|v| !canonical_digest(v))
            || lineage.preparation == lineage.verification
            || lineage.record == lineage.power_record
            || original.scope() != completion.first().scope()
            || original.checkpoint_digest() != completion.first().lineage().checkpoint
        {
            return Err(DisplayEvidenceError::Identity);
        }
        let material =
            linura_core::DisplayFinalizationMaterial::decode(&completion.lineage().material)
                .map_err(|_| DisplayEvidenceError::Shape)?;
        if material.restoration().original()
            != &linura_core::DisplayLayoutMaterial::decode(original.original_material())
                .map_err(|_| DisplayEvidenceError::Shape)?
        {
            return Err(DisplayEvidenceError::Identity);
        }
        Ok(Self {
            lineage,
            original,
            completion,
            current_grant,
        })
    }
    pub fn attributes(&self) -> BTreeMap<String, ObservedValue> {
        let mut attrs = BTreeMap::from([
            ("root_retirement_schema".into(), ObservedValue::U64(2)),
            (
                "original_dispatch".into(),
                ObservedValue::Text(self.original.scope().original_dispatch().into()),
            ),
            (
                "record_digest".into(),
                ObservedValue::Text(self.lineage.record.clone()),
            ),
            (
                "preparation_digest".into(),
                ObservedValue::Text(self.lineage.preparation.clone()),
            ),
            (
                "verification_digest".into(),
                ObservedValue::Text(self.lineage.verification.clone()),
            ),
            (
                "power_record_digest".into(),
                ObservedValue::Text(self.lineage.power_record.clone()),
            ),
            ("power_absent".into(), ObservedValue::Bool(true)),
        ]);
        for (key, value) in [
            (
                "current_grant_digest",
                self.current_grant.as_ref().map(|grant| &grant.record),
            ),
            (
                "current_grant_preparation",
                self.current_grant.as_ref().map(|grant| &grant.preparation),
            ),
            (
                "current_grant_committed_record",
                self.current_grant
                    .as_ref()
                    .map(|grant| &grant.committed_record),
            ),
        ] {
            attrs.insert(
                key.into(),
                ObservedValue::Text(value.cloned().unwrap_or_else(|| "0".repeat(64))),
            );
        }
        attrs.extend(
            self.original
                .attributes()
                .into_iter()
                .map(|(key, value)| (format!("source.{key}"), value)),
        );
        attrs.extend(
            self.completion
                .attributes()
                .into_iter()
                .map(|(key, value)| (format!("completion.{key}"), value)),
        );
        attrs
    }
    pub fn from_envelope(
        observation: &ObservationEnvelope,
        scope: &DisplayRecoveryScope,
        now: u64,
    ) -> Result<Self, DisplayEvidenceError> {
        if observation.provider.as_str() != DISPLAY_RECOVERY_PROVIDER
            || observation.capability.as_str() != DISPLAY_ORIGINAL_ROOT_RETIREMENT_CAPABILITY
            || observation.resource
                != scope
                    .resource_id()
                    .map_err(|_| DisplayEvidenceError::Identity)?
            || observation.authority != ObservationAuthority::NativeApi
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
        if attrs.len() > 284
            || number(attrs, "root_retirement_schema")? != 2
            || text(attrs, "original_dispatch")? != scope.original_dispatch()
            || !boolean(attrs, "power_absent")?
        {
            return Err(DisplayEvidenceError::Shape);
        }
        let nested = |prefix: &str| {
            attrs
                .iter()
                .filter_map(|(key, value)| {
                    key.strip_prefix(prefix)
                        .map(|key| (key.to_owned(), value.clone()))
                })
                .collect()
        };
        let facts = Self::new(
            DisplayRootRetirementLineage {
                record: text(attrs, "record_digest")?.into(),
                preparation: text(attrs, "preparation_digest")?.into(),
                verification: text(attrs, "verification_digest")?.into(),
                power_record: text(attrs, "power_record_digest")?.into(),
            },
            DisplayOriginalProtectionFacts::from_comparison_attributes(&nested("source."), scope)?,
            DisplayOriginalCompletionFacts::from_comparison_attributes(
                &nested("completion."),
                scope,
                observation.observed_at_unix_ms,
            )?,
            match text(attrs, "current_grant_digest")? {
                raw if raw == "0".repeat(64) => None,
                raw => Some(DisplayCurrentGrantLineage {
                    record: raw.into(),
                    preparation: text(attrs, "current_grant_preparation")?.into(),
                    committed_record: text(attrs, "current_grant_committed_record")?.into(),
                }),
            },
        )?;
        if facts.attributes() != *attrs {
            return Err(DisplayEvidenceError::Shape);
        }
        Ok(facts)
    }
    pub fn current_grant_digest(&self) -> Option<&str> {
        self.current_grant
            .as_ref()
            .map(|grant| grant.record.as_str())
    }
    pub const fn current_grant(&self) -> Option<&DisplayCurrentGrantLineage> {
        self.current_grant.as_ref()
    }
    pub const fn lineage(&self) -> &DisplayRootRetirementLineage {
        &self.lineage
    }
    pub const fn original_comparison(&self) -> &DisplayOriginalProtectionFacts {
        &self.original
    }
    pub const fn completion_comparison(&self) -> &DisplayOriginalCompletionFacts {
        &self.completion
    }
}
