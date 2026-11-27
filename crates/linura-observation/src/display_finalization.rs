//! Root's bounded terminal-mechanism facts over the canonical envelope.
//! These facts do not prove current native sources/frames, authorize release,
//! or turn historical completion into current startup admission. Control owns
//! the independent join, history, policy, prepare and recovery decisions.
use std::collections::BTreeMap;

use linura_core::{
    DisplayFinalizationMaterial, DisplayRecoveryScope, MAX_DISPLAY_FINALIZATION_BYTES,
};

use crate::display::{canonical_digest, number, text};
use crate::{
    DISPLAY_RECOVERY_PROVIDER, DisplayEvidenceError, ObservationAuthority, ObservationEnvelope,
    ObservedValue,
};

pub const DISPLAY_ORIGINAL_FINALIZATION_CAPABILITY: &str = "display.original-finalization.observe";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisplayFinalizationPhase {
    Protected,
    Reserved,
    Quiesced,
    Retired,
    /// Original Root admission holds a durably synced, one-use LNRN:1 marker.
    /// No native grant, physical release, terminal commit or startup permission.
    NativeReleaseReserved,
    /// Root's original invocation durably synchronized LNRX before a native
    /// grant ACK. This is NOT a physical release, S17/input/power retirement,
    /// independent Control commit or renewed ordinary startup authority.
    NativeReleaseSpent,
    /// Qualified native release plus this Root invocation's still-live exact
    /// ordinary startup admission. A spent file by itself cannot produce it.
    ReleasedCurrent,
}
impl DisplayFinalizationPhase {
    fn name(self) -> &'static str {
        match self {
            Self::Protected => "protected",
            Self::Reserved => "reserved",
            Self::Quiesced => "quiesced",
            Self::Retired => "retired",
            Self::NativeReleaseReserved => "native-release-reserved",
            Self::NativeReleaseSpent => "native-release-spent",
            Self::ReleasedCurrent => "released-current",
        }
    }
    fn parse(value: &str) -> Result<Self, DisplayEvidenceError> {
        match value {
            "protected" => Ok(Self::Protected),
            "reserved" => Ok(Self::Reserved),
            "quiesced" => Ok(Self::Quiesced),
            "retired" => Ok(Self::Retired),
            "native-release-reserved" => Ok(Self::NativeReleaseReserved),
            "native-release-spent" => Ok(Self::NativeReleaseSpent),
            "released-current" => Ok(Self::ReleasedCurrent),
            _ => Err(DisplayEvidenceError::Shape),
        }
    }
}

/// Comparison data from Root's separately reserved terminal effect, never a
/// serialized permit. Control independently recomputes its purpose-bound effect
/// and matches actual durable authority/history before using these facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayFinalizationReservationFacts {
    material: String,
    transaction: String,
    effect: String,
    dispatch: String,
}
impl DisplayFinalizationReservationFacts {
    pub fn new(
        material: String,
        transaction: String,
        effect: String,
        dispatch: String,
    ) -> Result<Self, DisplayEvidenceError> {
        let decoded = DisplayFinalizationMaterial::decode(&material)
            .map_err(|_| DisplayEvidenceError::Shape)?;
        if !canonical_transaction(&transaction)
            || !canonical_digest(&effect)
            || !canonical_digest(&dispatch)
            || dispatch == decoded.restoration_dispatch()
            || dispatch == decoded.restoration().original_dispatch()
        {
            return Err(DisplayEvidenceError::Shape);
        }
        Ok(Self {
            material,
            transaction,
            effect,
            dispatch,
        })
    }
    #[must_use]
    pub fn material(&self) -> &str {
        &self.material
    }
    #[must_use]
    pub fn transaction(&self) -> &str {
        &self.transaction
    }
    #[must_use]
    pub fn effect(&self) -> &str {
        &self.effect
    }
    #[must_use]
    pub fn dispatch(&self) -> &str {
        &self.dispatch
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayOriginalFinalizationFacts {
    scope: DisplayRecoveryScope,
    checkpoint: String,
    restoration_transaction: String,
    restoration_effect: String,
    restoration_dispatch: String,
    phase: DisplayFinalizationPhase,
    terminal: Option<DisplayFinalizationReservationFacts>,
}
impl DisplayOriginalFinalizationFacts {
    pub fn new(
        scope: DisplayRecoveryScope,
        checkpoint: String,
        restoration_transaction: String,
        restoration_effect: String,
        restoration_dispatch: String,
        phase: DisplayFinalizationPhase,
        terminal: Option<DisplayFinalizationReservationFacts>,
    ) -> Result<Self, DisplayEvidenceError> {
        if !canonical_transaction(&restoration_transaction)
            || [&checkpoint, &restoration_effect, &restoration_dispatch]
                .into_iter()
                .any(|value| !canonical_digest(value))
            || restoration_dispatch == scope.original_dispatch()
            || (phase == DisplayFinalizationPhase::Protected) != terminal.is_none()
        {
            return Err(DisplayEvidenceError::Shape);
        }
        if let Some(terminal) = &terminal {
            let material = DisplayFinalizationMaterial::decode(&terminal.material)
                .map_err(|_| DisplayEvidenceError::Shape)?;
            if material
                .recovery_scope()
                .map_err(|_| DisplayEvidenceError::Shape)?
                != scope
                || material.restoration().original_checkpoint() != checkpoint
                || material.restoration_dispatch() != restoration_dispatch
                || terminal.transaction == restoration_transaction
                || terminal.effect == restoration_effect
            {
                return Err(DisplayEvidenceError::Identity);
            }
        }
        Ok(Self {
            scope,
            checkpoint,
            restoration_transaction,
            restoration_effect,
            restoration_dispatch,
            phase,
            terminal,
        })
    }
    #[must_use]
    pub const fn scope(&self) -> &DisplayRecoveryScope {
        &self.scope
    }
    #[must_use]
    pub fn checkpoint(&self) -> &str {
        &self.checkpoint
    }
    #[must_use]
    pub fn restoration_transaction(&self) -> &str {
        &self.restoration_transaction
    }
    #[must_use]
    pub fn restoration_effect(&self) -> &str {
        &self.restoration_effect
    }
    #[must_use]
    pub fn restoration_dispatch(&self) -> &str {
        &self.restoration_dispatch
    }
    #[must_use]
    pub const fn phase(&self) -> DisplayFinalizationPhase {
        self.phase
    }
    #[must_use]
    pub const fn terminal(&self) -> Option<&DisplayFinalizationReservationFacts> {
        self.terminal.as_ref()
    }
    pub fn attributes(&self) -> BTreeMap<String, ObservedValue> {
        let mut attrs = BTreeMap::from([
            ("original_finalization_schema".into(), ObservedValue::U64(1)),
            (
                "phase".into(),
                ObservedValue::Text(self.phase.name().into()),
            ),
            (
                "original_checkpoint_digest".into(),
                ObservedValue::Text(self.checkpoint.clone()),
            ),
            (
                "restoration_transaction".into(),
                ObservedValue::Text(self.restoration_transaction.clone()),
            ),
            (
                "restoration_effect".into(),
                ObservedValue::Text(self.restoration_effect.clone()),
            ),
            (
                "restoration_dispatch".into(),
                ObservedValue::Text(self.restoration_dispatch.clone()),
            ),
        ]);
        if let Some(terminal) = &self.terminal {
            for (name, value) in [
                ("terminal_material", &terminal.material),
                ("terminal_transaction", &terminal.transaction),
                ("terminal_effect", &terminal.effect),
                ("terminal_dispatch", &terminal.dispatch),
            ] {
                attrs.insert(name.into(), ObservedValue::Text(value.clone()));
            }
        }
        attrs
    }
    pub fn from_envelope(
        envelope: &ObservationEnvelope,
        scope: &DisplayRecoveryScope,
        now_unix_ms: u64,
    ) -> Result<Self, DisplayEvidenceError> {
        if envelope.provider.as_str() != DISPLAY_RECOVERY_PROVIDER
            || envelope.capability.as_str() != DISPLAY_ORIGINAL_FINALIZATION_CAPABILITY
            || envelope.resource
                != scope
                    .resource_id()
                    .map_err(|_| DisplayEvidenceError::Identity)?
            || envelope.authority != ObservationAuthority::NativeApi
            || envelope.sequence == 0
            || envelope.observed_at_unix_ms == 0
            || envelope.valid_for_ms == 0
            || envelope.valid_for_ms > 2000
            || envelope.require_current(now_unix_ms).is_err()
        {
            return Err(DisplayEvidenceError::Identity);
        }
        let attrs = &envelope.attributes;
        // Bound untrusted strings before cloning, including unknown fields.
        if attrs.len() > 10 || attrs.iter().any(|(key, value)| {
            key.len() > 64 || matches!(value, ObservedValue::Text(text) if text.len() > MAX_DISPLAY_FINALIZATION_BYTES)
        }) {
            return Err(DisplayEvidenceError::Shape);
        }
        if number(attrs, "original_finalization_schema")? != 1 {
            return Err(DisplayEvidenceError::Shape);
        }
        let phase = DisplayFinalizationPhase::parse(text(attrs, "phase")?)?;
        let terminal = if phase == DisplayFinalizationPhase::Protected {
            None
        } else {
            Some(DisplayFinalizationReservationFacts::new(
                text(attrs, "terminal_material")?.into(),
                text(attrs, "terminal_transaction")?.into(),
                text(attrs, "terminal_effect")?.into(),
                text(attrs, "terminal_dispatch")?.into(),
            )?)
        };
        let facts = Self::new(
            scope.clone(),
            text(attrs, "original_checkpoint_digest")?.into(),
            text(attrs, "restoration_transaction")?.into(),
            text(attrs, "restoration_effect")?.into(),
            text(attrs, "restoration_dispatch")?.into(),
            phase,
            terminal,
        )?;
        if facts.attributes() != *attrs {
            return Err(DisplayEvidenceError::Shape);
        }
        Ok(facts)
    }
}
fn canonical_transaction(value: &str) -> bool {
    value.starts_with("transaction:")
        && value.len() > 12
        && value.len() <= 256
        && value
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b':' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_core::{CapabilityId, DisplayRestorationMaterial, ProviderId, RequestId};
    fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| unreachable!("{error:?}"))
    }
    fn facts(phase: DisplayFinalizationPhase) -> DisplayOriginalFinalizationFacts {
        let original =
            include_str!("../../linura-core/src/display_recovery/fixtures/original-baseline.txt")
                .trim_end();
        let original_material = value(DisplayRestorationMaterial::decode(original));
        let terminal = if phase == DisplayFinalizationPhase::Protected {
            None
        } else {
            let material = value(DisplayFinalizationMaterial::encode(
                &value(RequestId::new("request:restoration")),
                &"1".repeat(64),
                &"2".repeat(64),
                &"3".repeat(64),
                29,
                original_material.replacement().lock(),
                original,
            ));
            Some(value(DisplayFinalizationReservationFacts::new(
                material,
                "transaction:terminal".into(),
                "5".repeat(64),
                "6".repeat(64),
            )))
        };
        value(DisplayOriginalFinalizationFacts::new(
            value(original_material.recovery_scope()),
            original_material.original_checkpoint().into(),
            "transaction:restoration".into(),
            "4".repeat(64),
            "1".repeat(64),
            phase,
            terminal,
        ))
    }
    fn envelope(facts: &DisplayOriginalFinalizationFacts) -> ObservationEnvelope {
        ObservationEnvelope {
            provider: value(ProviderId::new(DISPLAY_RECOVERY_PROVIDER)),
            capability: value(CapabilityId::new(DISPLAY_ORIGINAL_FINALIZATION_CAPABILITY)),
            resource: value(facts.scope().resource_id()),
            authority: ObservationAuthority::NativeApi,
            observed_at_unix_ms: 1000,
            valid_for_ms: 2000,
            sequence: 1,
            attributes: facts.attributes(),
        }
    }
    #[test]
    fn root_phase_facts_preserve_full_terminal_binding_without_confusing_protection_with_release() {
        for phase in [
            DisplayFinalizationPhase::Protected,
            DisplayFinalizationPhase::Reserved,
            DisplayFinalizationPhase::Quiesced,
            DisplayFinalizationPhase::Retired,
            DisplayFinalizationPhase::NativeReleaseReserved,
            DisplayFinalizationPhase::NativeReleaseSpent,
            DisplayFinalizationPhase::ReleasedCurrent,
        ] {
            let facts = facts(phase);
            let sample = envelope(&facts);
            assert_eq!(
                value(DisplayOriginalFinalizationFacts::from_envelope(
                    &sample,
                    facts.scope(),
                    1001
                )),
                facts
            );
            assert_eq!(
                facts.terminal().is_none(),
                phase == DisplayFinalizationPhase::Protected
            );
        }
        let protected = facts(DisplayFinalizationPhase::Protected);
        let mut false_release = envelope(&protected);
        false_release.attributes.insert(
            "phase".into(),
            ObservedValue::Text("released-current".into()),
        );
        assert!(
            DisplayOriginalFinalizationFacts::from_envelope(
                &false_release,
                protected.scope(),
                1001
            )
            .is_err()
        );
        let reserved = facts(DisplayFinalizationPhase::Reserved);
        let mut false_empty = envelope(&reserved);
        false_empty
            .attributes
            .insert("phase".into(), ObservedValue::Text("protected".into()));
        assert!(
            DisplayOriginalFinalizationFacts::from_envelope(&false_empty, reserved.scope(), 1001)
                .is_err()
        );
    }
    #[test]
    fn historical_synthetic_foreign_stale_or_unknown_phase_envelopes_never_become_current_admission()
     {
        let facts = facts(DisplayFinalizationPhase::ReleasedCurrent);
        for case in 0..14 {
            let mut sample = envelope(&facts);
            match case {
                0 => sample.authority = ObservationAuthority::Filesystem,
                1 => sample.authority = ObservationAuthority::SyntheticTest,
                2 => sample.provider = value(ProviderId::new("hyprland")),
                3 => {
                    sample.capability =
                        value(CapabilityId::new("display.original-protection.observe"))
                }
                4 => sample.resource = value(facts.scope().replacement().resource_id()),
                5 => sample.sequence = 0,
                6 => sample.observed_at_unix_ms = 0,
                7 => sample.observed_at_unix_ms = 1002,
                8 => sample.valid_for_ms = 0,
                9 => sample.valid_for_ms = 2001,
                10 => {
                    sample
                        .attributes
                        .insert("phase".into(), ObservedValue::Text("committed".into()));
                }
                11 => {
                    sample
                        .attributes
                        .insert("original_finalization_schema".into(), ObservedValue::U64(2));
                }
                12 => {
                    sample
                        .attributes
                        .insert("unrecognized_permission".into(), ObservedValue::Bool(true));
                }
                _ => {
                    sample.attributes.insert(
                        "terminal_material".into(),
                        ObservedValue::Text("x".repeat(MAX_DISPLAY_FINALIZATION_BYTES + 1)),
                    );
                }
            }
            assert!(
                DisplayOriginalFinalizationFacts::from_envelope(&sample, facts.scope(), 1001)
                    .is_err(),
                "case {case}"
            );
        }
        assert!(
            DisplayOriginalFinalizationFacts::from_envelope(&envelope(&facts), facts.scope(), 3001)
                .is_err()
        );
    }
    #[test]
    fn terminal_state_refuses_incomplete_or_substituted_restoration_and_effect_lineage() {
        let facts = facts(DisplayFinalizationPhase::Reserved);
        for case in 0..9 {
            let mut sample = envelope(&facts);
            match case {
                0 => {
                    sample.attributes.remove("terminal_dispatch");
                }
                1 => {
                    sample.attributes.insert(
                        "terminal_transaction".into(),
                        ObservedValue::Text(facts.restoration_transaction().into()),
                    );
                }
                2 => {
                    sample.attributes.insert(
                        "terminal_effect".into(),
                        ObservedValue::Text(facts.restoration_effect().into()),
                    );
                }
                3 => {
                    sample.attributes.insert(
                        "terminal_dispatch".into(),
                        ObservedValue::Text(facts.restoration_dispatch().into()),
                    );
                }
                4 => {
                    sample.attributes.insert(
                        "original_checkpoint_digest".into(),
                        ObservedValue::Text("f".repeat(64)),
                    );
                }
                5 => {
                    sample.attributes.insert(
                        "restoration_dispatch".into(),
                        ObservedValue::Text("f".repeat(64)),
                    );
                }
                6 => {
                    sample.attributes.insert(
                        "restoration_effect".into(),
                        ObservedValue::Text("0".repeat(64)),
                    );
                }
                7 => {
                    sample.attributes.insert(
                        "terminal_material".into(),
                        ObservedValue::Text("LNRI:1;".into()),
                    );
                }
                _ => {
                    sample.attributes.insert(
                        "restoration_transaction".into(),
                        ObservedValue::Text("transaction:with\ncontrol".into()),
                    );
                }
            }
            assert!(
                DisplayOriginalFinalizationFacts::from_envelope(&sample, facts.scope(), 1001)
                    .is_err(),
                "case {case}"
            );
        }
    }
}
