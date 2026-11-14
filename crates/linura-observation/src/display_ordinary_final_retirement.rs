//! Root's exact final-retirement permission and metadata state. These facts
//! never stand in for independently observed native physical postconditions.
use crate::display::{canonical_digest, number, text};
use crate::{
    DISPLAY_RECOVERY_PROVIDER, DisplayEvidenceError, DisplayFinalRetirementLineage,
    DisplayReleasedCurrentLineage, ObservationAuthority, ObservationEnvelope, ObservedValue,
};
use linura_core::DisplayOrdinaryReleaseScope;
use std::collections::BTreeMap;

pub const DISPLAY_ORDINARY_FINAL_RETIREMENT_CAPABILITY: &str =
    "display.ordinary-final-retirement.observe";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayOrdinaryFinalRetirementFacts {
    scope: DisplayOrdinaryReleaseScope,
    checkpoint: crate::DisplayOrdinaryCurrentFacts,
    lineage: DisplayFinalRetirementLineage,
    phase: u64,
    completed: Option<DisplayReleasedCurrentLineage>,
}
impl DisplayOrdinaryFinalRetirementFacts {
    pub fn new(
        scope: DisplayOrdinaryReleaseScope,
        checkpoint: crate::DisplayOrdinaryCurrentFacts,
        lineage: DisplayFinalRetirementLineage,
        phase: u64,
        completed: Option<DisplayReleasedCurrentLineage>,
    ) -> Result<Self, DisplayEvidenceError> {
        if !matches!(phase, 1..=3)
            || (phase == 3) != completed.is_some()
            || [
                &lineage.record,
                &lineage.preparation,
                &lineage.verification,
                &lineage.current_grant,
                &lineage.committed_record,
            ]
            .iter()
            .any(|v| !canonical_digest(v))
            || checkpoint.scope() != &scope
            || checkpoint.current_commit_digest() != Some(lineage.current_grant.as_str())
            || checkpoint.final_retirement_digest().is_some()
            || !checkpoint.input_retired()
            || checkpoint.power_fence_held()
            || lineage.preparation == lineage.verification
            || completed
                .as_ref()
                .is_some_and(|v| !canonical_digest(&v.record) || !canonical_digest(&v.verification))
        {
            return Err(DisplayEvidenceError::Shape);
        }
        Ok(Self {
            scope,
            checkpoint,
            lineage,
            phase,
            completed,
        })
    }
    pub fn attributes(&self) -> BTreeMap<String, ObservedValue> {
        let mut result = BTreeMap::from([
            (
                "ordinary_final_retirement_schema".into(),
                ObservedValue::U64(1),
            ),
            (
                "original_dispatch".into(),
                ObservedValue::Text(self.scope.original_dispatch().into()),
            ),
            ("phase".into(), ObservedValue::U64(self.phase)),
        ]);
        for (key, value) in [
            ("record_digest", &self.lineage.record),
            ("preparation_digest", &self.lineage.preparation),
            ("verification_digest", &self.lineage.verification),
            ("current_grant_digest", &self.lineage.current_grant),
            ("committed_record_digest", &self.lineage.committed_record),
        ] {
            result.insert(key.into(), ObservedValue::Text(value.clone()));
        }
        let zero = "0".repeat(64);
        result.insert(
            "released_record_digest".into(),
            ObservedValue::Text(self.completed.as_ref().map_or(&zero, |v| &v.record).clone()),
        );
        result.insert(
            "released_verification_digest".into(),
            ObservedValue::Text(
                self.completed
                    .as_ref()
                    .map_or(&zero, |v| &v.verification)
                    .clone(),
            ),
        );
        result.insert(
            "prepared_observed_unix_ms".into(),
            ObservedValue::U64(self.checkpoint.window().observed_unix_ms),
        );
        result.extend(
            self.checkpoint
                .attributes()
                .into_iter()
                .map(|(k, v)| (format!("prepared.{k}"), v)),
        );
        result
    }
    pub const fn checkpoint(&self) -> &crate::DisplayOrdinaryCurrentFacts {
        &self.checkpoint
    }
    pub fn from_envelope(
        observation: &ObservationEnvelope,
        scope: &DisplayOrdinaryReleaseScope,
        now: u64,
    ) -> Result<Self, DisplayEvidenceError> {
        if observation.provider.as_str() != DISPLAY_RECOVERY_PROVIDER
            || observation.capability.as_str() != DISPLAY_ORDINARY_FINAL_RETIREMENT_CAPABILITY
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
        let a = &observation.attributes;
        if a.len() > 180
            || number(a, "ordinary_final_retirement_schema")? != 1
            || text(a, "original_dispatch")? != scope.original_dispatch()
        {
            return Err(DisplayEvidenceError::Shape);
        }
        let phase = number(a, "phase")?;
        let completed = if phase == 3 {
            Some(DisplayReleasedCurrentLineage {
                record: text(a, "released_record_digest")?.into(),
                verification: text(a, "released_verification_digest")?.into(),
            })
        } else {
            None
        };
        let observed = number(a, "prepared_observed_unix_ms")?;
        if observed == 0 || observed > observation.observed_at_unix_ms {
            return Err(DisplayEvidenceError::Freshness);
        }
        let checkpoint = crate::DisplayOrdinaryCurrentFacts::from_comparison_attributes(
            &a.iter()
                .filter_map(|(k, v)| {
                    k.strip_prefix("prepared.")
                        .map(|k| (k.to_owned(), v.clone()))
                })
                .collect(),
            scope,
            observed,
        )?;
        let result = Self::new(
            scope.clone(),
            checkpoint,
            DisplayFinalRetirementLineage {
                record: text(a, "record_digest")?.into(),
                preparation: text(a, "preparation_digest")?.into(),
                verification: text(a, "verification_digest")?.into(),
                current_grant: text(a, "current_grant_digest")?.into(),
                committed_record: text(a, "committed_record_digest")?.into(),
            },
            phase,
            completed,
        )?;
        if result.attributes() != *a {
            return Err(DisplayEvidenceError::Shape);
        }
        Ok(result)
    }
    pub const fn lineage(&self) -> &DisplayFinalRetirementLineage {
        &self.lineage
    }
    pub const fn phase(&self) -> u64 {
        self.phase
    }
    pub const fn completed(&self) -> Option<&DisplayReleasedCurrentLineage> {
        self.completed.as_ref()
    }
}
