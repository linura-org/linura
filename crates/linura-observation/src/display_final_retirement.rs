//! Root's exact final-retirement permission and metadata state. These facts
//! never stand in for independently observed native physical postconditions.
use crate::display::{canonical_digest, number, text};
use crate::{
    DISPLAY_RECOVERY_PROVIDER, DisplayEvidenceError, ObservationAuthority, ObservationEnvelope,
    ObservedValue,
};
use linura_core::DisplayRecoveryScope;
use std::collections::BTreeMap;

pub const DISPLAY_ORIGINAL_FINAL_RETIREMENT_CAPABILITY: &str =
    "display.original-final-retirement.observe";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayOriginalFinalRetirementFacts {
    scope: DisplayRecoveryScope,
    lineage: DisplayFinalRetirementLineage,
    phase: u64,
    completed: Option<DisplayReleasedCurrentLineage>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayFinalRetirementLineage {
    pub record: String,
    pub preparation: String,
    pub verification: String,
    pub current_grant: String,
    pub committed_record: String,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayReleasedCurrentLineage {
    pub record: String,
    pub verification: String,
}
impl DisplayOriginalFinalRetirementFacts {
    pub fn new(
        scope: DisplayRecoveryScope,
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
            || lineage.preparation == lineage.verification
            || completed
                .as_ref()
                .is_some_and(|v| !canonical_digest(&v.record) || !canonical_digest(&v.verification))
        {
            return Err(DisplayEvidenceError::Shape);
        }
        Ok(Self {
            scope,
            lineage,
            phase,
            completed,
        })
    }
    pub fn attributes(&self) -> BTreeMap<String, ObservedValue> {
        let mut result = BTreeMap::from([
            ("final_retirement_schema".into(), ObservedValue::U64(1)),
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
        result
    }
    pub fn from_envelope(
        observation: &ObservationEnvelope,
        scope: &DisplayRecoveryScope,
        now: u64,
    ) -> Result<Self, DisplayEvidenceError> {
        if observation.provider.as_str() != DISPLAY_RECOVERY_PROVIDER
            || observation.capability.as_str() != DISPLAY_ORIGINAL_FINAL_RETIREMENT_CAPABILITY
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
        if a.len() != 10
            || number(a, "final_retirement_schema")? != 1
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
        let result = Self::new(
            scope.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use linura_core::{CapabilityId, DisplayFinalizationMaterial, ProviderId};
    fn value<T, E: std::fmt::Debug>(v: Result<T, E>) -> T {
        v.unwrap_or_else(|e| unreachable!("{e:?}"))
    }
    #[test]
    fn final_root_permission_is_closed_fresh_and_separate_from_completion() {
        let material = value(DisplayFinalizationMaterial::decode(
            include_str!(
                "../../linura-core/src/display_recovery/fixtures/original-finalization.txt"
            )
            .trim_end(),
        ));
        let scope = value(material.recovery_scope());
        for phase in 1..=3 {
            let lineage = DisplayFinalRetirementLineage {
                record: "1".repeat(64),
                preparation: "2".repeat(64),
                verification: "3".repeat(64),
                current_grant: "4".repeat(64),
                committed_record: "5".repeat(64),
            };
            let completed = (phase == 3).then(|| DisplayReleasedCurrentLineage {
                record: "6".repeat(64),
                verification: "7".repeat(64),
            });
            let facts = value(DisplayOriginalFinalRetirementFacts::new(
                scope.clone(),
                lineage.clone(),
                phase,
                completed,
            ));
            let sample = ObservationEnvelope {
                provider: value(ProviderId::new(DISPLAY_RECOVERY_PROVIDER)),
                capability: value(CapabilityId::new(
                    DISPLAY_ORIGINAL_FINAL_RETIREMENT_CAPABILITY,
                )),
                resource: value(scope.resource_id()),
                authority: ObservationAuthority::NativeApi,
                sequence: 1,
                observed_at_unix_ms: 1000,
                valid_for_ms: 2000,
                attributes: facts.attributes(),
            };
            assert_eq!(
                value(DisplayOriginalFinalRetirementFacts::from_envelope(
                    &sample, &scope, 1001
                )),
                facts
            );
            for fault in 0..12 {
                let mut changed = sample.clone();
                match fault {
                    0 => changed.authority = ObservationAuthority::SyntheticTest,
                    1 => changed.provider = value(ProviderId::new("attacker")),
                    2 => {
                        changed.capability = value(CapabilityId::new(
                            "display.original-power-retirement.observe",
                        ))
                    }
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
                            .insert("phase".into(), ObservedValue::U64(4));
                    }
                    7 => {
                        changed.attributes.insert(
                            "preparation_digest".into(),
                            ObservedValue::Text("0".repeat(64)),
                        );
                    }
                    8 => {
                        changed.attributes.insert(
                            "current_grant_digest".into(),
                            ObservedValue::Text("ack".into()),
                        );
                    }
                    9 => {
                        changed.attributes.remove("committed_record_digest");
                    }
                    10 => {
                        changed.attributes.insert(
                            "released_record_digest".into(),
                            ObservedValue::Text(if phase == 3 {
                                "0".repeat(64)
                            } else {
                                "6".repeat(64)
                            }),
                        );
                    }
                    _ => {
                        changed.attributes.insert(
                            "released_verification_digest".into(),
                            ObservedValue::Text(if phase == 3 {
                                "0".repeat(64)
                            } else {
                                "7".repeat(64)
                            }),
                        );
                    }
                }
                assert!(
                    DisplayOriginalFinalRetirementFacts::from_envelope(&changed, &scope, 1001)
                        .is_err(),
                    "phase {phase} fault {fault}"
                );
            }
            for now in [0, 999, 3000, u64::MAX] {
                assert!(
                    DisplayOriginalFinalRetirementFacts::from_envelope(&sample, &scope, now)
                        .is_err()
                );
            }
            assert!(
                DisplayOriginalFinalRetirementFacts::new(
                    scope.clone(),
                    lineage,
                    phase,
                    if phase == 3 {
                        None
                    } else {
                        Some(DisplayReleasedCurrentLineage {
                            record: "6".repeat(64),
                            verification: "7".repeat(64),
                        })
                    }
                )
                .is_err()
            );
        }
    }
}
