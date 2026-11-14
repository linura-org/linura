//! Fresh original Root lifetime facts. Historical first-frame comparison is
//! explicitly nested and cannot be substituted for current native scanout.
use std::collections::BTreeMap;

use linura_core::{DisplayFinalizationMaterial, DisplayRecoveryScope};

use crate::display::{canonical_digest, number, text};
use crate::{
    DISPLAY_RECOVERY_PROVIDER, DisplayEvidenceError, DisplayNativeHandoffFacts,
    ObservationAuthority, ObservationEnvelope, ObservedValue,
};

pub const DISPLAY_ORIGINAL_COMPLETION_CAPABILITY: &str = "display.original-completion.observe";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayCompletionLineage {
    pub record: String,
    pub preparation: String,
    pub verification: String,
    pub material: String,
}

/// Only a live transferred lifetime is currently representable. Prepared,
/// failed, disk-only and unknown Root states cannot claim this capability.
/// This is neither ReleasedCurrent nor permission to retire another fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayOriginalCompletionFacts {
    lineage: DisplayCompletionLineage,
    first: DisplayNativeHandoffFacts,
}
impl DisplayOriginalCompletionFacts {
    pub fn new(
        lineage: DisplayCompletionLineage,
        first: DisplayNativeHandoffFacts,
    ) -> Result<Self, DisplayEvidenceError> {
        let material = DisplayFinalizationMaterial::decode(&lineage.material)
            .map_err(|_| DisplayEvidenceError::Shape)?;
        if [&lineage.record, &lineage.preparation, &lineage.verification]
            .into_iter()
            .any(|digest| !canonical_digest(digest))
            || lineage.preparation == lineage.verification
            || material
                .recovery_scope()
                .map_err(|_| DisplayEvidenceError::Shape)?
                != *first.scope()
            || material.restoration().original_checkpoint() != first.lineage().checkpoint
            || material.restoration_dispatch() != first.lineage().restoration_dispatch
            || material.terminal_link() != first.lineage().terminal_link
            || material.restored_source_guard() != first.lineage().source_guard
            || material.post_write_epoch() != first.lineage().post_write_epoch
            || material
                .restoration()
                .mapping()
                .replacement()
                .outputs()
                .len()
                != first.outputs().len()
            || material
                .restoration()
                .mapping()
                .replacement()
                .outputs()
                .iter()
                .any(|id| !first.outputs().contains_key(id))
        {
            return Err(DisplayEvidenceError::Identity);
        }
        Ok(Self { lineage, first })
    }
    #[must_use]
    pub const fn lineage(&self) -> &DisplayCompletionLineage {
        &self.lineage
    }
    #[must_use]
    pub const fn first(&self) -> &DisplayNativeHandoffFacts {
        &self.first
    }

    pub fn attributes(&self) -> BTreeMap<String, ObservedValue> {
        let mut attrs = BTreeMap::from([
            ("completion_schema".into(), ObservedValue::U64(1)),
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
        scope: &DisplayRecoveryScope,
        now: u64,
    ) -> Result<Self, DisplayEvidenceError> {
        if observation.provider.as_str() != DISPLAY_RECOVERY_PROVIDER
            || observation.capability.as_str() != DISPLAY_ORIGINAL_COMPLETION_CAPABILITY
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
        scope: &DisplayRecoveryScope,
        observed_at: u64,
    ) -> Result<Self, DisplayEvidenceError> {
        if attrs.len() > 168
            || attrs.iter().any(|(key, value)| {
                key.len() > 70
                    || matches!(value, ObservedValue::Text(text) if text.len() >
                if key == "material" { linura_core::MAX_DISPLAY_FINALIZATION_BYTES } else { 256 })
            })
            || number(attrs, "completion_schema")? != 1
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
            DisplayNativeHandoffFacts::from_comparison_attributes(
                &first,
                scope,
                number(attrs, "first_observed_unix_ms")?,
            )?,
        )?;
        if facts.attributes() != *attrs || facts.first.window().observed_unix_ms > observed_at {
            return Err(DisplayEvidenceError::Shape);
        }
        Ok(facts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DisplayNativeHandoffLineage, DisplayNativeHandoffOutput, DisplayNativeHandoffWindow,
    };
    use linura_core::{CapabilityId, ProviderId};

    fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| unreachable!("{error:?}"))
    }
    fn fixture() -> (DisplayOriginalCompletionFacts, ObservationEnvelope) {
        let encoded = include_str!(
            "../../linura-core/src/display_recovery/fixtures/original-finalization.txt"
        )
        .trim_end();
        let material = value(DisplayFinalizationMaterial::decode(encoded));
        let scope = value(material.recovery_scope());
        let outputs = material
            .restoration()
            .mapping()
            .replacement()
            .outputs()
            .iter()
            .enumerate()
            .map(|(index, id)| {
                (
                    id.clone(),
                    DisplayNativeHandoffOutput {
                        enabled: index != 1,
                        connector: index as u32 + 1,
                        crtc: if index == 1 { 0 } else { index as u32 + 10 },
                        plane: if index == 1 { 0 } else { index as u32 + 20 },
                        framebuffer: if index == 1 { 0 } else { index as u32 + 30 },
                        spend_high_water: 40,
                        completed_commit: 41,
                    },
                )
            })
            .collect();
        let first = value(DisplayNativeHandoffFacts::new(
            scope.clone(),
            DisplayNativeHandoffLineage {
                checkpoint: material.restoration().original_checkpoint().into(),
                restoration_transaction: "transaction:restored".into(),
                restoration_effect: "4".repeat(64),
                restoration_dispatch: material.restoration_dispatch().into(),
                terminal_transaction: "transaction:terminal".into(),
                terminal_effect: "5".repeat(64),
                terminal_dispatch: "6".repeat(64),
                terminal_link: material.terminal_link().into(),
                source_guard: material.restored_source_guard().into(),
                post_write_epoch: material.post_write_epoch(),
                security_epoch: 7,
            },
            DisplayNativeHandoffWindow {
                observed_unix_ms: 1000,
                observed_boot_ms: 100,
                deadline_unix_ms: 1200,
                deadline_boot_ms: 300,
            },
            outputs,
        ));
        let facts = value(DisplayOriginalCompletionFacts::new(
            DisplayCompletionLineage {
                record: "7".repeat(64),
                preparation: "8".repeat(64),
                verification: "9".repeat(64),
                material: encoded.into(),
            },
            first,
        ));
        // The FIRST tuple is old comparison history; the outer live Root read
        // remains fresh. It cannot make old frames satisfy a native probe.
        let envelope = ObservationEnvelope {
            provider: value(ProviderId::new(DISPLAY_RECOVERY_PROVIDER)),
            capability: value(CapabilityId::new(DISPLAY_ORIGINAL_COMPLETION_CAPABILITY)),
            resource: value(scope.resource_id()),
            authority: ObservationAuthority::NativeApi,
            observed_at_unix_ms: 5000,
            valid_for_ms: 2000,
            sequence: 1,
            attributes: facts.attributes(),
        };
        (facts, envelope)
    }

    #[test]
    fn live_root_completion_keeps_old_frames_as_comparison_only() {
        let (facts, envelope) = fixture();
        assert_eq!(
            value(DisplayOriginalCompletionFacts::from_envelope(
                &envelope,
                facts.first.scope(),
                5001
            )),
            facts
        );
        assert!(
            DisplayNativeHandoffFacts::from_envelope(&envelope, facts.first.scope(), 5001).is_err()
        );
        let old = ObservationEnvelope {
            provider: value(ProviderId::new(crate::DISPLAY_PROVIDER)),
            capability: value(CapabilityId::new(crate::DISPLAY_NATIVE_HANDOFF_CAPABILITY)),
            observed_at_unix_ms: facts.first.window().observed_unix_ms,
            valid_for_ms: value(facts.first.window().valid_for_ms()),
            attributes: facts.first.attributes(),
            ..envelope.clone()
        };
        assert!(DisplayNativeHandoffFacts::from_envelope(&old, facts.first.scope(), 5001).is_err());
        for now in [0, 4999, 7000, u64::MAX] {
            assert!(
                DisplayOriginalCompletionFacts::from_envelope(&envelope, facts.first.scope(), now)
                    .is_err()
            );
        }
    }

    #[test]
    fn root_completion_rejects_ack_relabelling_partial_and_foreign_history() {
        let (facts, envelope) = fixture();
        for key in envelope.attributes.keys() {
            let mut changed = envelope.clone();
            changed.attributes.remove(key);
            assert!(
                DisplayOriginalCompletionFacts::from_envelope(&changed, facts.first.scope(), 5001)
                    .is_err(),
                "{key}"
            );
        }
        for (key, value) in [
            ("phase", ObservedValue::Text("released-current".into())),
            ("phase", ObservedValue::Text("prepared".into())),
            ("record_digest", ObservedValue::Text("0".repeat(64))),
            ("preparation_digest", ObservedValue::Text("9".repeat(64))),
            ("first.source_guard", ObservedValue::Text("a".repeat(64))),
            ("first.post_write_epoch", ObservedValue::U64(1)),
            ("first_observed_unix_ms", ObservedValue::U64(5001)),
            ("ack", ObservedValue::Bool(true)),
        ] {
            let mut changed = envelope.clone();
            changed.attributes.insert(key.into(), value);
            assert!(
                DisplayOriginalCompletionFacts::from_envelope(&changed, facts.first.scope(), 5001)
                    .is_err(),
                "{key}"
            );
        }
        for authority in [
            ObservationAuthority::Filesystem,
            ObservationAuthority::SyntheticTest,
            ObservationAuthority::Kernel,
        ] {
            let mut changed = envelope.clone();
            changed.authority = authority;
            assert!(
                DisplayOriginalCompletionFacts::from_envelope(&changed, facts.first.scope(), 5001)
                    .is_err()
            );
        }
    }
}
