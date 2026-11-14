//! First ordinary-frame comparison after a one-use native handoff attempt.
//! This capability is distinct from opaque restoration presentation. Its facts
//! grant no execution, durable completion or input/power/startup retirement.
use std::collections::{BTreeMap, BTreeSet};

use crate::display::{boolean, canonical_digest, number, text};
use crate::{
    DISPLAY_PROVIDER, DisplayEvidenceError, ObservationAuthority, ObservationEnvelope,
    ObservedValue,
};
use linura_core::{DisplayLayout, DisplayOutputId, DisplayOutputLayout, DisplayRecoveryScope};

pub const DISPLAY_NATIVE_HANDOFF_CAPABILITY: &str = "display.native-handoff.observe";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayNativeHandoffLineage {
    pub checkpoint: String,
    pub restoration_transaction: String,
    pub restoration_effect: String,
    pub restoration_dispatch: String,
    pub terminal_transaction: String,
    pub terminal_effect: String,
    pub terminal_dispatch: String,
    pub terminal_link: String,
    pub source_guard: String,
    pub post_write_epoch: u64,
    pub security_epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DisplayNativeHandoffWindow {
    pub observed_unix_ms: u64,
    pub observed_boot_ms: u64,
    // These are the gate's original absolute deadlines, never read time + TTL.
    pub deadline_unix_ms: u64,
    pub deadline_boot_ms: u64,
}
impl DisplayNativeHandoffWindow {
    pub fn valid_for_ms(self) -> Result<u64, DisplayEvidenceError> {
        let remaining = |deadline: u64, observed: u64| {
            deadline
                .checked_sub(observed)
                .filter(|age| (1..=2000).contains(age))
        };
        if self.observed_unix_ms == 0 || self.observed_boot_ms == 0 {
            return Err(DisplayEvidenceError::Freshness);
        }
        Ok(remaining(self.deadline_unix_ms, self.observed_unix_ms)
            .ok_or(DisplayEvidenceError::Freshness)?
            .min(
                remaining(self.deadline_boot_ms, self.observed_boot_ms)
                    .ok_or(DisplayEvidenceError::Freshness)?,
            ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DisplayNativeHandoffOutput {
    pub enabled: bool,
    pub connector: u32,
    pub crtc: u32,
    pub plane: u32,
    pub framebuffer: u32,
    pub spend_high_water: u64,
    pub completed_commit: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayNativeHandoffFacts {
    scope: DisplayRecoveryScope,
    lineage: DisplayNativeHandoffLineage,
    window: DisplayNativeHandoffWindow,
    outputs: BTreeMap<DisplayOutputId, DisplayNativeHandoffOutput>,
}
impl DisplayNativeHandoffFacts {
    pub fn new(
        scope: DisplayRecoveryScope,
        lineage: DisplayNativeHandoffLineage,
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
        if [
            &lineage.checkpoint,
            &lineage.restoration_effect,
            &lineage.restoration_dispatch,
            &lineage.terminal_effect,
            &lineage.terminal_dispatch,
            &lineage.terminal_link,
            &lineage.source_guard,
        ]
        .into_iter()
        .any(|v| !canonical_digest(v))
            || !transaction(&lineage.restoration_transaction)
            || !transaction(&lineage.terminal_transaction)
            || lineage.restoration_transaction == lineage.terminal_transaction
            || lineage.restoration_dispatch == lineage.terminal_dispatch
            || lineage.restoration_dispatch == scope.original_dispatch()
            || lineage.terminal_dispatch == scope.original_dispatch()
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
        for (id, output) in &outputs {
            if id.topology() != scope.replacement()
                || !handles.insert(id.handle())
                || output.connector == 0
                || !connectors.insert(output.connector)
            {
                return Err(DisplayEvidenceError::Identity);
            }
            if output.spend_high_water == 0
                || output.completed_commit <= output.spend_high_water
                || output.completed_commit == u64::MAX
                || if output.enabled {
                    output.crtc == 0 || output.plane == 0 || output.framebuffer == 0
                } else {
                    output.crtc != 0 || output.plane != 0 || output.framebuffer != 0
                }
            {
                return Err(DisplayEvidenceError::Shape);
            }
            enabled |= output.enabled;
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
        let mut result = BTreeMap::from([
            ("handoff_schema".into(), ObservedValue::U64(1)),
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
            ("checkpoint_digest", &lineage.checkpoint),
            ("restoration_transaction", &lineage.restoration_transaction),
            ("restoration_effect", &lineage.restoration_effect),
            ("restoration_dispatch", &lineage.restoration_dispatch),
            ("terminal_transaction", &lineage.terminal_transaction),
            ("terminal_effect", &lineage.terminal_effect),
            ("terminal_dispatch", &lineage.terminal_dispatch),
            ("terminal_link", &lineage.terminal_link),
            ("source_guard", &lineage.source_guard),
        ] {
            result.insert(key.into(), ObservedValue::Text(value.clone()));
        }
        for (index, (id, output)) in self.outputs.iter().enumerate() {
            let prefix = format!("output.{index}");
            result.insert(
                format!("{prefix}.enabled"),
                ObservedValue::Bool(output.enabled),
            );
            for (key, value) in [
                ("handle", id.handle()),
                ("generation", id.generation()),
                ("connector", u64::from(output.connector)),
                ("crtc", u64::from(output.crtc)),
                ("plane", u64::from(output.plane)),
                ("framebuffer", u64::from(output.framebuffer)),
                ("spend_high_water", output.spend_high_water),
                ("completed_commit", output.completed_commit),
            ] {
                result.insert(format!("{prefix}.{key}"), ObservedValue::U64(value));
            }
        }
        result
    }

    pub fn from_envelope(
        observation: &ObservationEnvelope,
        scope: &DisplayRecoveryScope,
        now: u64,
    ) -> Result<Self, DisplayEvidenceError> {
        if observation.provider.as_str() != DISPLAY_PROVIDER
            || observation.capability.as_str() != DISPLAY_NATIVE_HANDOFF_CAPABILITY
            || observation.resource
                != scope
                    .resource_id()
                    .map_err(|_| DisplayEvidenceError::Identity)?
            || observation.authority != ObservationAuthority::NativeApi
            || observation.sequence == 0
        {
            return Err(DisplayEvidenceError::Identity);
        }
        let facts = Self::from_comparison_attributes(
            &observation.attributes,
            scope,
            observation.observed_at_unix_ms,
        )?;
        if observation.valid_for_ms != facts.window.valid_for_ms()?
            || now
                .checked_sub(observation.observed_at_unix_ms)
                .is_none_or(|age| age >= observation.valid_for_ms)
        {
            return Err(DisplayEvidenceError::Freshness);
        }
        Ok(facts)
    }

    /// Decode historical comparison material only. This does not authenticate
    /// an observation or make old first frames current. Fresh native consumers
    /// must use from_envelope; Root's separate completion observation retains
    /// this tuple solely to compare the exact spent handoff boundary.
    pub fn from_comparison_attributes(
        attrs: &BTreeMap<String, ObservedValue>,
        scope: &DisplayRecoveryScope,
        observed_unix_ms: u64,
    ) -> Result<Self, DisplayEvidenceError> {
        if attrs.len() > 161
            || attrs.iter().any(|(key, value)| {
                key.len() > 64 || matches!(value, ObservedValue::Text(text) if text.len() > 256)
            })
            || number(attrs, "handoff_schema")? != 1
            || text(attrs, "original_dispatch")? != scope.original_dispatch()
        {
            return Err(DisplayEvidenceError::Shape);
        }
        let count = number(attrs, "output_count")?;
        if !(1..=16).contains(&count) {
            return Err(DisplayEvidenceError::Shape);
        }
        let window = DisplayNativeHandoffWindow {
            observed_unix_ms,
            observed_boot_ms: number(attrs, "sampled_boot_ms")?,
            deadline_unix_ms: number(attrs, "deadline_unix_ms")?,
            deadline_boot_ms: number(attrs, "deadline_boot_ms")?,
        };
        let mut outputs = BTreeMap::new();
        for index in 0..count {
            let prefix = format!("output.{index}");
            let n = |key: &str| number(attrs, &format!("{prefix}.{key}"));
            let u = |key: &str| u32::try_from(n(key)?).map_err(|_| DisplayEvidenceError::Shape);
            let id =
                DisplayOutputId::new(scope.replacement().clone(), n("handle")?, n("generation")?)
                    .map_err(|_| DisplayEvidenceError::Identity)?;
            let output = DisplayNativeHandoffOutput {
                enabled: boolean(attrs, &format!("{prefix}.enabled"))?,
                connector: u("connector")?,
                crtc: u("crtc")?,
                plane: u("plane")?,
                framebuffer: u("framebuffer")?,
                spend_high_water: n("spend_high_water")?,
                completed_commit: n("completed_commit")?,
            };
            if outputs.insert(id, output).is_some() {
                return Err(DisplayEvidenceError::Identity);
            }
        }
        let lineage = DisplayNativeHandoffLineage {
            checkpoint: text(attrs, "checkpoint_digest")?.into(),
            restoration_transaction: text(attrs, "restoration_transaction")?.into(),
            restoration_effect: text(attrs, "restoration_effect")?.into(),
            restoration_dispatch: text(attrs, "restoration_dispatch")?.into(),
            terminal_transaction: text(attrs, "terminal_transaction")?.into(),
            terminal_effect: text(attrs, "terminal_effect")?.into(),
            terminal_dispatch: text(attrs, "terminal_dispatch")?.into(),
            terminal_link: text(attrs, "terminal_link")?.into(),
            source_guard: text(attrs, "source_guard")?.into(),
            post_write_epoch: number(attrs, "post_write_epoch")?,
            security_epoch: number(attrs, "security_epoch")?,
        };
        let result = Self::new(scope.clone(), lineage, window, outputs)?;
        if result.attributes() != *attrs {
            return Err(DisplayEvidenceError::Shape);
        }
        Ok(result)
    }

    #[must_use]
    pub fn lineage(&self) -> &DisplayNativeHandoffLineage {
        &self.lineage
    }
    #[must_use]
    pub const fn scope(&self) -> &DisplayRecoveryScope {
        &self.scope
    }
    #[must_use]
    pub const fn window(&self) -> DisplayNativeHandoffWindow {
        self.window
    }
    #[must_use]
    pub fn outputs(&self) -> &BTreeMap<DisplayOutputId, DisplayNativeHandoffOutput> {
        &self.outputs
    }
    /// A fresh read may describe only the same immutable first frame. This is
    /// comparison, never replay permission, successor adoption or completion.
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
    /// Compare native lineage with separately sampled Root facts. Neither input
    /// authenticates itself or replaces Control's signed durable-history checks.
    #[must_use]
    pub fn matches_root(&self, root: &crate::DisplayOriginalFinalizationFacts) -> bool {
        let Some(terminal) = root.terminal() else {
            return false;
        };
        let Ok(material) = linura_core::DisplayFinalizationMaterial::decode(terminal.material())
        else {
            return false;
        };
        root.phase() == crate::DisplayFinalizationPhase::NativeReleaseSpent
            && root.scope() == &self.scope
            && self.lineage.checkpoint == root.checkpoint()
            && self.lineage.restoration_transaction == root.restoration_transaction()
            && self.lineage.restoration_effect == root.restoration_effect()
            && self.lineage.restoration_dispatch == root.restoration_dispatch()
            && self.lineage.terminal_transaction == terminal.transaction()
            && self.lineage.terminal_effect == terminal.effect()
            && self.lineage.terminal_dispatch == terminal.dispatch()
            && self.lineage.terminal_link == material.terminal_link()
            && self.lineage.source_guard == material.restored_source_guard()
            && self.lineage.post_write_epoch == material.post_write_epoch()
    }
    #[must_use]
    pub fn matches_layout(&self, layout: &DisplayLayout) -> bool {
        layout.topology() == self.scope.replacement()
            && layout.outputs().len() == self.outputs.len()
            && layout.outputs().iter().all(|target| {
                self.outputs.get(target.output()).is_some_and(|observed| {
                    observed.enabled == matches!(target, DisplayOutputLayout::Enabled { .. })
                })
            })
    }
}

#[cfg(test)]
mod tests;
