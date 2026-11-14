//! Same-invocation ordinary release first-frame comparison. These facts are
//! evidence only; neither a Root grant nor durable completion/retirement.
use crate::display::{boolean, canonical_digest, number, text};
use crate::{
    DISPLAY_PROVIDER, DisplayEvidenceError, DisplayNativeHandoffOutput, DisplayNativeHandoffWindow,
    ObservationAuthority, ObservationEnvelope, ObservedValue,
};
use linura_core::{
    DisplayLayout, DisplayOrdinaryReleaseMaterial, DisplayOrdinaryReleaseScope, DisplayOutputId,
    DisplayOutputLayout,
};
use std::collections::{BTreeMap, BTreeSet};

pub const DISPLAY_ORDINARY_HANDOFF_CAPABILITY: &str = "display.ordinary-handoff.observe";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayOrdinaryHandoffLineage {
    pub original_transaction: String,
    pub original_effect: String,
    pub release_transaction: String,
    pub release_effect: String,
    pub release_dispatch: String,
    pub preparation_digest: String,
    pub terminal_record: String,
    pub checkpoint: String,
    pub signed_binding: String,
    pub source_guard: String,
    pub outcome: String,
    pub post_write_epoch: u64,
    pub security_epoch: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayOrdinaryHandoffFacts {
    scope: DisplayOrdinaryReleaseScope,
    lineage: DisplayOrdinaryHandoffLineage,
    window: DisplayNativeHandoffWindow,
    outputs: BTreeMap<DisplayOutputId, DisplayNativeHandoffOutput>,
}
impl DisplayOrdinaryHandoffFacts {
    pub fn new(
        scope: DisplayOrdinaryReleaseScope,
        lineage: DisplayOrdinaryHandoffLineage,
        window: DisplayNativeHandoffWindow,
        outputs: BTreeMap<DisplayOutputId, DisplayNativeHandoffOutput>,
    ) -> Result<Self, DisplayEvidenceError> {
        let transaction = |value: &str| {
            value.starts_with("transaction:")
                && value.len() > 12
                && value.len() <= 256
                && value.bytes().all(|c| {
                    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b':' | b'-')
                })
        };
        if !transaction(&lineage.original_transaction)
            || !transaction(&lineage.release_transaction)
            || lineage.original_transaction == lineage.release_transaction
            || lineage.release_dispatch == scope.original_dispatch()
            || [
                &lineage.original_effect,
                &lineage.release_effect,
                &lineage.release_dispatch,
                &lineage.preparation_digest,
                &lineage.terminal_record,
                &lineage.checkpoint,
                &lineage.signed_binding,
                &lineage.source_guard,
            ]
            .iter()
            .any(|value| !canonical_digest(value))
            || !matches!(lineage.outcome.as_str(), "keep" | "revert" | "expired")
            || lineage.post_write_epoch == 0
            || lineage.security_epoch == 0
            || outputs.is_empty()
            || outputs.len() > 16
        {
            return Err(DisplayEvidenceError::Shape);
        }
        window.valid_for_ms()?;
        let mut handles = BTreeSet::new();
        let mut connectors = BTreeSet::new();
        let mut enabled = false;
        for (id, row) in &outputs {
            if id.topology() != scope.topology()
                || !handles.insert(id.handle())
                || row.connector == 0
                || !connectors.insert(row.connector)
            {
                return Err(DisplayEvidenceError::Identity);
            }
            if row.spend_high_water == 0
                || row.completed_commit <= row.spend_high_water
                || row.completed_commit == u64::MAX
                || if row.enabled {
                    row.crtc == 0 || row.plane == 0 || row.framebuffer == 0
                } else {
                    row.crtc != 0 || row.plane != 0 || row.framebuffer != 0
                }
            {
                return Err(DisplayEvidenceError::Shape);
            }
            enabled |= row.enabled;
        }
        if !enabled {
            return Err(DisplayEvidenceError::Shape);
        }
        Ok(Self {
            scope,
            lineage,
            window,
            outputs,
        })
    }
    pub fn attributes(&self) -> BTreeMap<String, ObservedValue> {
        let lineage = &self.lineage;
        let mut attrs = BTreeMap::from([
            ("ordinary_handoff_schema".into(), ObservedValue::U64(1)),
            (
                "original_dispatch".into(),
                ObservedValue::Text(self.scope.original_dispatch().into()),
            ),
            (
                "post_write_epoch".into(),
                ObservedValue::U64(lineage.post_write_epoch),
            ),
            (
                "security_epoch".into(),
                ObservedValue::U64(lineage.security_epoch),
            ),
            (
                "sampled_boot_ms".into(),
                ObservedValue::U64(self.window.observed_boot_ms),
            ),
            (
                "deadline_unix_ms".into(),
                ObservedValue::U64(self.window.deadline_unix_ms),
            ),
            (
                "deadline_boot_ms".into(),
                ObservedValue::U64(self.window.deadline_boot_ms),
            ),
            (
                "output_count".into(),
                ObservedValue::U64(self.outputs.len() as u64),
            ),
        ]);
        for (key, value) in [
            ("original_transaction", &lineage.original_transaction),
            ("original_effect", &lineage.original_effect),
            ("release_transaction", &lineage.release_transaction),
            ("release_effect", &lineage.release_effect),
            ("release_dispatch", &lineage.release_dispatch),
            ("preparation_digest", &lineage.preparation_digest),
            ("terminal_record", &lineage.terminal_record),
            ("checkpoint", &lineage.checkpoint),
            ("signed_binding", &lineage.signed_binding),
            ("source_guard", &lineage.source_guard),
            ("outcome", &lineage.outcome),
        ] {
            attrs.insert(key.into(), ObservedValue::Text(value.clone()));
        }
        for (index, (id, row)) in self.outputs.iter().enumerate() {
            let prefix = format!("output.{index}");
            attrs.insert(
                format!("{prefix}.enabled"),
                ObservedValue::Bool(row.enabled),
            );
            for (key, value) in [
                ("handle", id.handle()),
                ("generation", id.generation()),
                ("connector", u64::from(row.connector)),
                ("crtc", u64::from(row.crtc)),
                ("plane", u64::from(row.plane)),
                ("framebuffer", u64::from(row.framebuffer)),
                ("spend_high_water", row.spend_high_water),
                ("completed_commit", row.completed_commit),
            ] {
                attrs.insert(format!("{prefix}.{key}"), ObservedValue::U64(value));
            }
        }
        attrs
    }
    pub fn from_envelope(
        observation: &ObservationEnvelope,
        scope: &DisplayOrdinaryReleaseScope,
        now: u64,
    ) -> Result<Self, DisplayEvidenceError> {
        if observation.provider.as_str() != DISPLAY_PROVIDER
            || observation.capability.as_str() != DISPLAY_ORDINARY_HANDOFF_CAPABILITY
            || observation.resource
                != scope
                    .resource_id()
                    .map_err(|_| DisplayEvidenceError::Identity)?
            || observation.authority != ObservationAuthority::NativeApi
            || observation.sequence == 0
        {
            return Err(DisplayEvidenceError::Identity);
        }
        let attrs = &observation.attributes;
        if attrs.len() > 163
            || attrs.iter().any(|(key, value)| {
                key.len() > 64 || matches!(value, ObservedValue::Text(text) if text.len() > 256)
            })
            || number(attrs, "ordinary_handoff_schema")? != 1
            || text(attrs, "original_dispatch")? != scope.original_dispatch()
        {
            return Err(DisplayEvidenceError::Shape);
        }
        let count = number(attrs, "output_count")?;
        if !(1..=16).contains(&count) {
            return Err(DisplayEvidenceError::Shape);
        }
        let mut outputs = BTreeMap::new();
        let mut previous = None;
        for index in 0..count {
            let prefix = format!("output.{index}");
            let n = |key: &str| number(attrs, &format!("{prefix}.{key}"));
            let u = |key: &str| u32::try_from(n(key)?).map_err(|_| DisplayEvidenceError::Shape);
            let id = DisplayOutputId::new(scope.topology().clone(), n("handle")?, n("generation")?)
                .map_err(|_| DisplayEvidenceError::Identity)?;
            if previous.as_ref().is_some_and(|last| last >= &id) {
                return Err(DisplayEvidenceError::Identity);
            }
            previous = Some(id.clone());
            outputs.insert(
                id,
                DisplayNativeHandoffOutput {
                    enabled: boolean(attrs, &format!("{prefix}.enabled"))?,
                    connector: u("connector")?,
                    crtc: u("crtc")?,
                    plane: u("plane")?,
                    framebuffer: u("framebuffer")?,
                    spend_high_water: n("spend_high_water")?,
                    completed_commit: n("completed_commit")?,
                },
            );
        }
        let result = Self::new(
            scope.clone(),
            DisplayOrdinaryHandoffLineage {
                original_transaction: text(attrs, "original_transaction")?.into(),
                original_effect: text(attrs, "original_effect")?.into(),
                release_transaction: text(attrs, "release_transaction")?.into(),
                release_effect: text(attrs, "release_effect")?.into(),
                release_dispatch: text(attrs, "release_dispatch")?.into(),
                preparation_digest: text(attrs, "preparation_digest")?.into(),
                terminal_record: text(attrs, "terminal_record")?.into(),
                checkpoint: text(attrs, "checkpoint")?.into(),
                signed_binding: text(attrs, "signed_binding")?.into(),
                source_guard: text(attrs, "source_guard")?.into(),
                outcome: text(attrs, "outcome")?.into(),
                post_write_epoch: number(attrs, "post_write_epoch")?,
                security_epoch: number(attrs, "security_epoch")?,
            },
            DisplayNativeHandoffWindow {
                observed_unix_ms: observation.observed_at_unix_ms,
                observed_boot_ms: number(attrs, "sampled_boot_ms")?,
                deadline_unix_ms: number(attrs, "deadline_unix_ms")?,
                deadline_boot_ms: number(attrs, "deadline_boot_ms")?,
            },
            outputs,
        )?;
        if result.attributes() != *attrs {
            return Err(DisplayEvidenceError::Shape);
        }
        if observation.valid_for_ms != result.window.valid_for_ms()?
            || now
                .checked_sub(observation.observed_at_unix_ms)
                .is_none_or(|age| age >= observation.valid_for_ms)
        {
            return Err(DisplayEvidenceError::Freshness);
        }
        Ok(result)
    }
    #[must_use]
    pub fn matches_material(&self, material: &DisplayOrdinaryReleaseMaterial<'_>) -> bool {
        material.release_scope().as_ref() == Ok(&self.scope)
            && self.lineage.terminal_record == material.lineage().terminal_record
            && self.lineage.checkpoint == material.lineage().original_checkpoint
            && self.lineage.signed_binding == material.lineage().signed_binding
            && self.lineage.source_guard == material.lineage().current_source_guard
            && self.lineage.outcome == material.outcome().as_str()
    }
    #[must_use]
    pub fn matches_layout(&self, layout: &DisplayLayout) -> bool {
        layout.topology() == self.scope.topology()
            && layout.outputs().len() == self.outputs.len()
            && layout.outputs().iter().all(|row| {
                self.outputs.get(row.output()).is_some_and(|observed| {
                    observed.enabled == matches!(row, DisplayOutputLayout::Enabled { .. })
                })
            })
    }
    #[must_use]
    pub fn reconciles(&self, previous: &Self) -> bool {
        self.scope == previous.scope
            && self.lineage == previous.lineage
            && self.outputs == previous.outputs
            && self.window.deadline_unix_ms == previous.window.deadline_unix_ms
            && self.window.deadline_boot_ms == previous.window.deadline_boot_ms
            && self.window.observed_unix_ms >= previous.window.observed_unix_ms
            && self.window.observed_boot_ms >= previous.window.observed_boot_ms
    }
    #[must_use]
    pub const fn scope(&self) -> &DisplayOrdinaryReleaseScope {
        &self.scope
    }
    #[must_use]
    pub const fn lineage(&self) -> &DisplayOrdinaryHandoffLineage {
        &self.lineage
    }
    #[must_use]
    pub const fn window(&self) -> DisplayNativeHandoffWindow {
        self.window
    }
    #[must_use]
    pub fn outputs(&self) -> &BTreeMap<DisplayOutputId, DisplayNativeHandoffOutput> {
        &self.outputs
    }
}

#[cfg(test)]
mod tests;
