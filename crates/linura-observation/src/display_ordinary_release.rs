//! Live Root comparison of the ordinary one-use preparation/spend. Physical
//! scanout and durable completion require separate independent observations.
use crate::display::{boolean, canonical_digest, number, text};
use crate::{
    DISPLAY_RECOVERY_PROVIDER, DisplayEvidenceError, DisplayNativeHandoffWindow,
    DisplayOrdinaryHandoffFacts, ObservationAuthority, ObservationEnvelope, ObservedValue,
};
use linura_core::{DisplayOrdinaryReleaseMaterial, DisplayOrdinaryReleaseScope};
use std::collections::BTreeMap;

pub const DISPLAY_ORDINARY_RELEASE_CAPABILITY: &str = "display.ordinary-release.observe";
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayOrdinaryReleaseComparison {
    pub material: String,
    pub transaction: String,
    pub effect: String,
    pub dispatch: String,
    pub preparation_digest: String,
    pub spent: bool,
    pub producer: DisplayNativeHandoffWindow,
    pub sampled_boot_ms: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayOrdinaryReleaseFacts {
    scope: DisplayOrdinaryReleaseScope,
    comparison: DisplayOrdinaryReleaseComparison,
}
impl DisplayOrdinaryReleaseFacts {
    pub fn new(
        scope: DisplayOrdinaryReleaseScope,
        comparison: DisplayOrdinaryReleaseComparison,
    ) -> Result<Self, DisplayEvidenceError> {
        let material = DisplayOrdinaryReleaseMaterial::decode(&comparison.material)
            .map_err(|_| DisplayEvidenceError::Shape)?;
        if material.release_scope().as_ref() != Ok(&scope)
            || comparison.material.len() > linura_core::MAX_DISPLAY_ORDINARY_RELEASE_BYTES
            || !comparison.transaction.starts_with("transaction:")
            || comparison.transaction.len() <= 12
            || comparison.transaction.len() > 256
            || !comparison
                .transaction
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b':' | b'-'))
            || [
                &comparison.effect,
                &comparison.dispatch,
                &comparison.preparation_digest,
            ]
            .iter()
            .any(|v| !canonical_digest(v))
            || comparison.dispatch == scope.original_dispatch()
            || comparison.sampled_boot_ms < comparison.producer.observed_boot_ms
            || comparison.sampled_boot_ms >= comparison.producer.deadline_boot_ms
        {
            return Err(DisplayEvidenceError::Shape);
        }
        comparison.producer.valid_for_ms()?;
        Ok(Self { scope, comparison })
    }
    pub fn attributes(&self) -> BTreeMap<String, ObservedValue> {
        let c = &self.comparison;
        let mut attrs = BTreeMap::from([
            ("ordinary_release_schema".into(), ObservedValue::U64(1)),
            (
                "original_dispatch".into(),
                ObservedValue::Text(self.scope.original_dispatch().into()),
            ),
            ("spent".into(), ObservedValue::Bool(c.spent)),
            (
                "producer_unix_ms".into(),
                ObservedValue::U64(c.producer.observed_unix_ms),
            ),
            (
                "producer_boot_ms".into(),
                ObservedValue::U64(c.producer.observed_boot_ms),
            ),
            (
                "deadline_unix_ms".into(),
                ObservedValue::U64(c.producer.deadline_unix_ms),
            ),
            (
                "deadline_boot_ms".into(),
                ObservedValue::U64(c.producer.deadline_boot_ms),
            ),
            (
                "sampled_boot_ms".into(),
                ObservedValue::U64(c.sampled_boot_ms),
            ),
        ]);
        for (key, value) in [
            ("material", &c.material),
            ("transaction", &c.transaction),
            ("effect", &c.effect),
            ("dispatch", &c.dispatch),
            ("preparation_digest", &c.preparation_digest),
        ] {
            attrs.insert(key.into(), ObservedValue::Text(value.clone()));
        }
        attrs
    }
    pub fn from_envelope(
        observation: &ObservationEnvelope,
        scope: &DisplayOrdinaryReleaseScope,
        now: u64,
    ) -> Result<Self, DisplayEvidenceError> {
        if observation.provider.as_str() != DISPLAY_RECOVERY_PROVIDER
            || observation.capability.as_str() != DISPLAY_ORDINARY_RELEASE_CAPABILITY
            || observation.resource
                != scope
                    .resource_id()
                    .map_err(|_| DisplayEvidenceError::Identity)?
            || observation.authority != ObservationAuthority::NativeApi
            || observation.sequence == 0
        {
            return Err(DisplayEvidenceError::Identity);
        }
        let a = &observation.attributes;
        if a.len() != 13 || a.keys().any(|key| key.len() > 32) || a.iter().any(|(key, v)|
            matches!(v, ObservedValue::Text(value) if value.len() > if key == "material" {linura_core::MAX_DISPLAY_ORDINARY_RELEASE_BYTES} else {256})) ||
            number(a, "ordinary_release_schema")? != 1 || text(a, "original_dispatch")? != scope.original_dispatch() {
            return Err(DisplayEvidenceError::Shape);
        }
        let result = Self::new(
            scope.clone(),
            DisplayOrdinaryReleaseComparison {
                material: text(a, "material")?.into(),
                transaction: text(a, "transaction")?.into(),
                effect: text(a, "effect")?.into(),
                dispatch: text(a, "dispatch")?.into(),
                preparation_digest: text(a, "preparation_digest")?.into(),
                spent: boolean(a, "spent")?,
                producer: DisplayNativeHandoffWindow {
                    observed_unix_ms: number(a, "producer_unix_ms")?,
                    observed_boot_ms: number(a, "producer_boot_ms")?,
                    deadline_unix_ms: number(a, "deadline_unix_ms")?,
                    deadline_boot_ms: number(a, "deadline_boot_ms")?,
                },
                sampled_boot_ms: number(a, "sampled_boot_ms")?,
            },
        )?;
        let current = DisplayNativeHandoffWindow {
            observed_unix_ms: observation.observed_at_unix_ms,
            observed_boot_ms: result.comparison.sampled_boot_ms,
            ..result.comparison.producer
        };
        if result.attributes() != *a {
            return Err(DisplayEvidenceError::Shape);
        }
        if observation.observed_at_unix_ms < result.comparison.producer.observed_unix_ms
            || observation.valid_for_ms != current.valid_for_ms()?
            || now
                .checked_sub(observation.observed_at_unix_ms)
                .is_none_or(|age| age >= observation.valid_for_ms)
        {
            return Err(DisplayEvidenceError::Freshness);
        }
        Ok(result)
    }
    #[must_use]
    pub fn matches_native(&self, frames: &DisplayOrdinaryHandoffFacts) -> bool {
        let c = &self.comparison;
        let lineage = frames.lineage();
        let Ok(material) = DisplayOrdinaryReleaseMaterial::decode(&c.material) else {
            return false;
        };
        let window = frames.window();
        c.spent
            && frames.scope() == &self.scope
            && frames.matches_material(&material)
            && lineage.release_transaction == c.transaction
            && lineage.release_effect == c.effect
            && lineage.release_dispatch == c.dispatch
            && lineage.preparation_digest == c.preparation_digest
            && window.observed_unix_ms >= c.producer.observed_unix_ms
            && window.observed_boot_ms >= c.producer.observed_boot_ms
            && window.deadline_unix_ms <= c.producer.deadline_unix_ms
            && window.deadline_boot_ms <= c.producer.deadline_boot_ms
    }
    #[must_use]
    pub const fn comparison(&self) -> &DisplayOrdinaryReleaseComparison {
        &self.comparison
    }
    #[must_use]
    pub const fn scope(&self) -> &DisplayOrdinaryReleaseScope {
        &self.scope
    }
    /// Later sampling may advance BOOTTIME, never the producer window,
    /// preparation, complete material, spend or managed binding.
    #[must_use]
    pub fn reconciles(&self, previous: &Self) -> bool {
        let mut old = previous.clone();
        old.comparison.sampled_boot_ms = self.comparison.sampled_boot_ms;
        self == &old && self.comparison.sampled_boot_ms >= previous.comparison.sampled_boot_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DisplayNativeHandoffOutput, DisplayOrdinaryHandoffLineage};
    use linura_core::{
        CapabilityId, DisplayLayoutMaterial, DisplayOrdinaryReleaseLineage,
        DisplayOrdinaryReleaseOutcome, DisplayOutputId, ProviderId, RequestId,
    };
    fn value<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|e| unreachable!("{e:?}"))
    }
    fn fixture() -> (
        DisplayOrdinaryReleaseFacts,
        DisplayOrdinaryHandoffFacts,
        ObservationEnvelope,
    ) {
        let topology = "display:topology:11111111-1111-4111-8111-111111111111:1000:c2:42:seat0:33333333-3333-4333-8333-333333333333:3";
        let layout = format!("LNDL:1;{topology};10:1:enabled:1920:1080:60000:1000:0:0:0:-;");
        let original = format!(
            "LNDI:1;session:lock:11111111-1111-4111-8111-111111111111:1000:c2:42:22222222-2222-4222-8222-222222222222:1;{layout}{layout}"
        );
        let old = value(DisplayLayoutMaterial::decode(&original));
        let material = value(DisplayOrdinaryReleaseMaterial::encode(
            &DisplayOrdinaryReleaseLineage {
                original_request: value(RequestId::new("request:v010:display-layout:original")),
                original_dispatch: &"a".repeat(64),
                terminal_record: &"b".repeat(64),
                original_checkpoint: &"c".repeat(64),
                signed_binding: &"d".repeat(64),
                generation: 0,
                state_version: 9,
                current_source_guard: &"e".repeat(64),
            },
            DisplayOrdinaryReleaseOutcome::Keep,
            old.lock(),
            &original,
        ));
        let scope = value(value(DisplayOrdinaryReleaseMaterial::decode(&material)).release_scope());
        let producer = DisplayNativeHandoffWindow {
            observed_unix_ms: 1000,
            observed_boot_ms: 100,
            deadline_unix_ms: 1200,
            deadline_boot_ms: 300,
        };
        let root = value(DisplayOrdinaryReleaseFacts::new(
            scope.clone(),
            DisplayOrdinaryReleaseComparison {
                material,
                transaction: "transaction:release".into(),
                effect: "1".repeat(64),
                dispatch: "2".repeat(64),
                preparation_digest: "3".repeat(64),
                spent: true,
                producer,
                sampled_boot_ms: 102,
            },
        ));
        let native = value(DisplayOrdinaryHandoffFacts::new(
            scope.clone(),
            DisplayOrdinaryHandoffLineage {
                original_transaction: "transaction:original".into(),
                original_effect: "4".repeat(64),
                release_transaction: "transaction:release".into(),
                release_effect: "1".repeat(64),
                release_dispatch: "2".repeat(64),
                preparation_digest: "3".repeat(64),
                terminal_record: "b".repeat(64),
                checkpoint: "c".repeat(64),
                signed_binding: "d".repeat(64),
                source_guard: "e".repeat(64),
                outcome: "keep".into(),
                post_write_epoch: 1,
                security_epoch: 2,
            },
            DisplayNativeHandoffWindow {
                observed_unix_ms: 1001,
                observed_boot_ms: 101,
                ..producer
            },
            BTreeMap::from([(
                value(DisplayOutputId::new(scope.topology().clone(), 10, 1)),
                DisplayNativeHandoffOutput {
                    enabled: true,
                    connector: 5,
                    crtc: 6,
                    plane: 7,
                    framebuffer: 8,
                    spend_high_water: 90,
                    completed_commit: 91,
                },
            )]),
        ));
        let observation = ObservationEnvelope {
            provider: value(ProviderId::new(DISPLAY_RECOVERY_PROVIDER)),
            capability: value(CapabilityId::new(DISPLAY_ORDINARY_RELEASE_CAPABILITY)),
            resource: value(scope.resource_id()),
            authority: ObservationAuthority::NativeApi,
            observed_at_unix_ms: 1002,
            valid_for_ms: 198,
            sequence: 1,
            attributes: root.attributes(),
        };
        (root, native, observation)
    }
    #[test]
    fn root_spend_and_native_frame_join_requires_complete_purpose_lineage_and_both_original_clocks()
    {
        let (root, native, observation) = fixture();
        assert_eq!(
            value(DisplayOrdinaryReleaseFacts::from_envelope(
                &observation,
                root.scope(),
                1003
            )),
            root
        );
        assert!(root.matches_native(&native));
        for case in 0..13 {
            let mut changed = root.clone();
            match case {
                0 => changed.comparison.spent = false,
                1 => changed.comparison.transaction = "transaction:foreign".into(),
                2 => changed.comparison.effect = "9".repeat(64),
                3 => changed.comparison.dispatch = "9".repeat(64),
                4 => changed.comparison.preparation_digest = "9".repeat(64),
                5 => {
                    changed.comparison.material =
                        changed.comparison.material.replace("4:keep;", "6:revert;")
                }
                6 => {
                    changed.comparison.material = changed
                        .comparison
                        .material
                        .replace(&"b".repeat(64), &"9".repeat(64))
                }
                7 => {
                    changed.comparison.material = changed
                        .comparison
                        .material
                        .replace(&"c".repeat(64), &"9".repeat(64))
                }
                8 => {
                    changed.comparison.material = changed
                        .comparison
                        .material
                        .replace(&"d".repeat(64), &"9".repeat(64))
                }
                9 => {
                    changed.comparison.material = changed
                        .comparison
                        .material
                        .replace(&"e".repeat(64), &"9".repeat(64))
                }
                10 => changed.comparison.producer.deadline_boot_ms -= 1,
                11 => changed.comparison.producer.deadline_unix_ms -= 1,
                _ => changed.comparison.producer.observed_boot_ms += 2,
            }
            assert!(!changed.matches_native(&native), "case {case}");
        }
    }
    #[test]
    fn unknown_or_relabelled_root_ack_cannot_become_current_ordinary_release_evidence() {
        let (root, _, observation) = fixture();
        for key in observation.attributes.keys() {
            let mut missing = observation.clone();
            missing.attributes.remove(key);
            assert!(
                DisplayOrdinaryReleaseFacts::from_envelope(&missing, root.scope(), 1003).is_err(),
                "missing {key}"
            );
            let mut wrong = observation.clone();
            wrong.attributes.insert(key.clone(), ObservedValue::I64(1));
            assert!(
                DisplayOrdinaryReleaseFacts::from_envelope(&wrong, root.scope(), 1003).is_err(),
                "mistyped {key}"
            );
        }
        for case in 0..8 {
            let mut changed = observation.clone();
            match case {
                0 => changed.authority = ObservationAuthority::SyntheticTest,
                1 => changed.provider = value(ProviderId::new(crate::DISPLAY_PROVIDER)),
                2 => {
                    changed.capability = value(CapabilityId::new(
                        crate::DISPLAY_ORDINARY_ORIGINAL_CAPABILITY,
                    ))
                }
                3 => changed.resource = value(root.scope.topology().resource_id()),
                4 => changed.sequence = 0,
                5 => changed.valid_for_ms = 2000,
                6 => {
                    changed
                        .attributes
                        .insert("released".into(), ObservedValue::Bool(true));
                }
                _ => changed.observed_at_unix_ms = 999,
            }
            assert!(
                DisplayOrdinaryReleaseFacts::from_envelope(&changed, root.scope(), 1003).is_err(),
                "case {case}"
            );
        }
        assert!(
            DisplayOrdinaryReleaseFacts::from_envelope(&observation, root.scope(), 1200).is_err()
        );
        let mut fresh = root.clone();
        fresh.comparison.sampled_boot_ms += 1;
        assert!(fresh.reconciles(&root));
        fresh.comparison.producer.deadline_boot_ms += 1;
        assert!(!fresh.reconciles(&root));
    }
}
