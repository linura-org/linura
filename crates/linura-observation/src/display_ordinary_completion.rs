//! Fresh ordinary Root completion-lifetime facts. Historical first-frame comparison is
//! explicitly nested and cannot be substituted for current native scanout.
use std::collections::BTreeMap;

use linura_core::{DisplayOrdinaryReleaseMaterial, DisplayOrdinaryReleaseScope};

use crate::display::{canonical_digest, number, text};
use crate::{
    DISPLAY_RECOVERY_PROVIDER, DisplayEvidenceError, DisplayOrdinaryHandoffFacts,
    ObservationAuthority, ObservationEnvelope, ObservedValue,
};

pub const DISPLAY_ORDINARY_COMPLETION_CAPABILITY: &str = "display.ordinary-completion.observe";

use crate::DisplayCompletionLineage;

/// Only a live transferred lifetime is currently representable. Prepared,
/// failed, disk-only and unknown Root states cannot claim this capability.
/// This is neither ReleasedCurrent nor permission to retire another fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayOrdinaryCompletionFacts {
    lineage: DisplayCompletionLineage,
    producer: crate::DisplayNativeHandoffWindow,
    first: DisplayOrdinaryHandoffFacts,
}
impl DisplayOrdinaryCompletionFacts {
    pub fn new(
        lineage: DisplayCompletionLineage,
        first: DisplayOrdinaryHandoffFacts,
        producer: crate::DisplayNativeHandoffWindow,
    ) -> Result<Self, DisplayEvidenceError> {
        let material = DisplayOrdinaryReleaseMaterial::decode(&lineage.material)
            .map_err(|_| DisplayEvidenceError::Shape)?;
        if [&lineage.record, &lineage.preparation, &lineage.verification]
            .into_iter()
            .any(|digest| !canonical_digest(digest))
            || lineage.preparation == lineage.verification
            || !first.matches_material(&material)
            || producer.observed_unix_ms > first.window().observed_unix_ms
            || producer.observed_boot_ms > first.window().observed_boot_ms
            || producer.deadline_unix_ms != first.window().deadline_unix_ms
            || producer.deadline_boot_ms != first.window().deadline_boot_ms
        {
            return Err(DisplayEvidenceError::Identity);
        }
        producer.valid_for_ms()?;
        Ok(Self {
            lineage,
            producer,
            first,
        })
    }
    #[must_use]
    pub const fn lineage(&self) -> &DisplayCompletionLineage {
        &self.lineage
    }
    #[must_use]
    pub const fn first(&self) -> &DisplayOrdinaryHandoffFacts {
        &self.first
    }

    pub const fn producer(&self) -> crate::DisplayNativeHandoffWindow {
        self.producer
    }

    pub fn attributes(&self) -> BTreeMap<String, ObservedValue> {
        let mut attrs = BTreeMap::from([
            ("ordinary_completion_schema".into(), ObservedValue::U64(1)),
            ("phase".into(), ObservedValue::Text("transferred".into())),
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
                "material".into(),
                ObservedValue::Text(self.lineage.material.clone()),
            ),
            (
                "first_observed_unix_ms".into(),
                ObservedValue::U64(self.first.window().observed_unix_ms),
            ),
        ]);
        for (key, value) in [
            ("producer_unix_ms", self.producer.observed_unix_ms),
            ("producer_boot_ms", self.producer.observed_boot_ms),
        ] {
            attrs.insert(key.into(), ObservedValue::U64(value));
        }
        attrs.extend(
            self.first
                .attributes()
                .into_iter()
                .map(|(key, value)| (format!("first.{key}"), value)),
        );
        attrs
    }

    pub fn from_envelope(
        observation: &ObservationEnvelope,
        scope: &DisplayOrdinaryReleaseScope,
        now: u64,
    ) -> Result<Self, DisplayEvidenceError> {
        if observation.provider.as_str() != DISPLAY_RECOVERY_PROVIDER
            || observation.capability.as_str() != DISPLAY_ORDINARY_COMPLETION_CAPABILITY
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
        Self::from_comparison_attributes(
            &observation.attributes,
            scope,
            observation.observed_at_unix_ms,
        )
    }
    pub(crate) fn from_comparison_attributes(
        attrs: &BTreeMap<String, ObservedValue>,
        scope: &DisplayOrdinaryReleaseScope,
        observed_at: u64,
    ) -> Result<Self, DisplayEvidenceError> {
        if attrs.len() > 172
            || attrs.iter().any(|(key, value)| {
                key.len() > 70
                    || matches!(value, ObservedValue::Text(text) if text.len() >
                if key == "material" { linura_core::MAX_DISPLAY_ORDINARY_RELEASE_BYTES } else { 256 })
            })
            || number(attrs, "ordinary_completion_schema")? != 1
            || text(attrs, "phase")? != "transferred"
        {
            return Err(DisplayEvidenceError::Shape);
        }
        let first = attrs
            .iter()
            .filter_map(|(key, value)| {
                key.strip_prefix("first.")
                    .map(|key| (key.to_owned(), value.clone()))
            })
            .collect();
        let facts = Self::new(
            DisplayCompletionLineage {
                record: text(attrs, "record_digest")?.into(),
                preparation: text(attrs, "preparation_digest")?.into(),
                verification: text(attrs, "verification_digest")?.into(),
                material: text(attrs, "material")?.into(),
            },
            DisplayOrdinaryHandoffFacts::from_comparison_attributes(
                &first,
                scope,
                number(attrs, "first_observed_unix_ms")?,
            )?,
            crate::DisplayNativeHandoffWindow {
                observed_unix_ms: number(attrs, "producer_unix_ms")?,
                observed_boot_ms: number(attrs, "producer_boot_ms")?,
                deadline_unix_ms: number(&first, "deadline_unix_ms")?,
                deadline_boot_ms: number(&first, "deadline_boot_ms")?,
            },
        )?;
        if facts.attributes() != *attrs || facts.first.window().observed_unix_ms > observed_at {
            return Err(DisplayEvidenceError::Shape);
        }
        Ok(facts)
    }
}

#[cfg(test)]
mod tests;
