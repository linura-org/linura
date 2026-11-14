//! Fresh continuity after an ordinary, separately prepared Root power close.
//! Nested first-frame data retains its historical producer window. No field
//! grants current commit, final retirement, successor or cleanup authority.
use crate::display::{boolean, canonical_digest, number, text};
use crate::{
    DISPLAY_RECOVERY_PROVIDER, DisplayEvidenceError, DisplayOrdinaryCompletionFacts,
    DisplayOrdinaryOriginalComparison, DisplayOrdinaryOriginalFacts, DisplayRootRetirementLineage,
    ObservationAuthority, ObservationEnvelope, ObservedValue,
};
use linura_core::DisplayOrdinaryReleaseScope;
use std::collections::BTreeMap;

pub const DISPLAY_ORDINARY_ROOT_RETIREMENT_CAPABILITY: &str =
    "display.ordinary-root-retirement.observe";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayOrdinaryRootRetirementFacts {
    lineage: DisplayRootRetirementLineage,
    completion: DisplayOrdinaryCompletionFacts,
    original: DisplayOrdinaryOriginalComparison,
}
impl DisplayOrdinaryRootRetirementFacts {
    pub fn new(
        lineage: DisplayRootRetirementLineage,
        completion: DisplayOrdinaryCompletionFacts,
        original: DisplayOrdinaryOriginalComparison,
    ) -> Result<Self, DisplayEvidenceError> {
        if [
            &lineage.record,
            &lineage.preparation,
            &lineage.verification,
            &lineage.power_record,
        ]
        .into_iter()
        .any(|v| !canonical_digest(v))
            || lineage.preparation == lineage.verification
            || lineage.record == lineage.power_record
        {
            return Err(DisplayEvidenceError::Identity);
        }
        DisplayOrdinaryOriginalFacts::new(completion.first().scope().clone(), original.clone())?;
        let material =
            linura_core::DisplayOrdinaryReleaseMaterial::decode(&completion.lineage().material)
                .map_err(|_| DisplayEvidenceError::Shape)?;
        if original.material != material.original_text()
            || original.transaction != completion.first().lineage().original_transaction
            || original.checkpoint != completion.first().lineage().checkpoint
        {
            return Err(DisplayEvidenceError::Identity);
        }
        Ok(Self {
            lineage,
            completion,
            original,
        })
    }
    pub const fn original(&self) -> &DisplayOrdinaryOriginalComparison {
        &self.original
    }
    pub const fn lineage(&self) -> &DisplayRootRetirementLineage {
        &self.lineage
    }
    pub const fn completion(&self) -> &DisplayOrdinaryCompletionFacts {
        &self.completion
    }
    pub fn attributes(&self) -> BTreeMap<String, ObservedValue> {
        let mut a = BTreeMap::from([
            (
                "ordinary_root_retirement_schema".into(),
                ObservedValue::U64(1),
            ),
            ("power_absent".into(), ObservedValue::Bool(true)),
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
        ]);
        for (k, v) in [
            (
                "original.material",
                ObservedValue::Text(self.original.material.clone()),
            ),
            (
                "original.transaction",
                ObservedValue::Text(self.original.transaction.clone()),
            ),
            (
                "original.checkpoint",
                ObservedValue::Text(self.original.checkpoint.clone()),
            ),
            (
                "original.native_guard",
                ObservedValue::Text(self.original.native_guard.clone()),
            ),
            (
                "original.integration",
                ObservedValue::Text(self.original.integration.clone()),
            ),
            (
                "original.sampled_boot_ms",
                ObservedValue::U64(self.original.sampled_boot_ms),
            ),
            (
                "original.deadline_unix_ms",
                ObservedValue::U64(self.original.original_deadline_unix_ms),
            ),
        ] {
            a.insert(k.into(), v);
        }
        a.extend(
            self.completion
                .attributes()
                .into_iter()
                .map(|(k, v)| (format!("completion.{k}"), v)),
        );
        a
    }
    pub fn from_envelope(
        sample: &ObservationEnvelope,
        scope: &DisplayOrdinaryReleaseScope,
        now: u64,
    ) -> Result<Self, DisplayEvidenceError> {
        if sample.provider.as_str() != DISPLAY_RECOVERY_PROVIDER
            || sample.capability.as_str() != DISPLAY_ORDINARY_ROOT_RETIREMENT_CAPABILITY
            || sample.authority != ObservationAuthority::NativeApi
            || sample.sequence == 0
            || sample.resource
                != scope
                    .resource_id()
                    .map_err(|_| DisplayEvidenceError::Identity)?
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
        if a.len() > 185
            || number(a, "ordinary_root_retirement_schema")? != 1
            || !boolean(a, "power_absent")?
        {
            return Err(DisplayEvidenceError::Shape);
        }
        let nested = a
            .iter()
            .filter_map(|(k, v)| {
                k.strip_prefix("completion.")
                    .map(|k| (k.to_owned(), v.clone()))
            })
            .collect();
        let facts = Self::new(
            DisplayRootRetirementLineage {
                record: text(a, "record_digest")?.into(),
                preparation: text(a, "preparation_digest")?.into(),
                verification: text(a, "verification_digest")?.into(),
                power_record: text(a, "power_record_digest")?.into(),
            },
            DisplayOrdinaryCompletionFacts::from_comparison_attributes(
                &nested,
                scope,
                sample.observed_at_unix_ms,
            )?,
            DisplayOrdinaryOriginalComparison {
                material: text(a, "original.material")?.into(),
                transaction: text(a, "original.transaction")?.into(),
                checkpoint: text(a, "original.checkpoint")?.into(),
                native_guard: text(a, "original.native_guard")?.into(),
                integration: text(a, "original.integration")?.into(),
                sampled_boot_ms: number(a, "original.sampled_boot_ms")?,
                original_deadline_unix_ms: number(a, "original.deadline_unix_ms")?,
            },
        )?;
        if facts.attributes() != *a {
            return Err(DisplayEvidenceError::Shape);
        }
        Ok(facts)
    }
}
