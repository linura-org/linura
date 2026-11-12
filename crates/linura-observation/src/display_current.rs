//! Current native scanout after the separately authenticated original handoff.
//! Distinct from the immutable first-frame receipt: buffers may advance while
//! disabled heads remain detached without a fabricated additional modeset.
//! These observations never authorize release or commit durable completion.
use std::collections::{BTreeMap, BTreeSet};

use crate::display::{boolean, canonical_digest, number, text};
use crate::{
    DISPLAY_PROVIDER, DisplayEvidenceError, ObservationAuthority, ObservationEnvelope,
    ObservedValue,
};
use linura_core::{DisplayLayout, DisplayOutputId, DisplayOutputLayout, DisplayRecoveryScope};

pub const DISPLAY_NATIVE_CURRENT_CAPABILITY: &str = "display.native-current.observe";

use crate::{DisplayNativeHandoffFacts, DisplayNativeHandoffLineage, DisplayNativeHandoffWindow};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DisplayNativeCurrentOutput {
    pub enabled: bool,
    pub connector: u32,
    pub crtc: u32,
    pub plane: u32,
    pub framebuffer: u32,
    pub handoff_commit: u64,
    pub completed_commit: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayNativeCurrentFacts {
    scope: DisplayRecoveryScope,
    lineage: DisplayNativeHandoffLineage,
    window: DisplayNativeHandoffWindow,
    outputs: BTreeMap<DisplayOutputId, DisplayNativeCurrentOutput>,
    completion_digest: String,
    input_retired: bool,
    power_fence_held: bool,
}
impl DisplayNativeCurrentFacts {
    pub fn new(
        scope: DisplayRecoveryScope,
        lineage: DisplayNativeHandoffLineage,
        window: DisplayNativeHandoffWindow,
        outputs: BTreeMap<DisplayOutputId, DisplayNativeCurrentOutput>,
        completion_digest: String,
        input_retired: bool,
        power_fence_held: bool,
    ) -> Result<Self, DisplayEvidenceError> {
        let transaction = |value: &str| {
            value.starts_with("transaction:")
                && value.len() > 12
                && value.len() <= 256
                && value.bytes().all(|c| {
                    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b':' | b'-')
                })
        };
        if !canonical_digest(&completion_digest)
            || [
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
            if output.handoff_commit == 0
                || output.completed_commit < output.handoff_commit
                || (output.enabled && output.completed_commit == output.handoff_commit)
                || (!output.enabled && output.completed_commit != output.handoff_commit)
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
            completion_digest,
            input_retired,
            power_fence_held,
        })
    }

    pub fn attributes(&self) -> BTreeMap<String, ObservedValue> {
        let lineage = &self.lineage;
        let mut result = BTreeMap::from([
            ("current_schema".into(), ObservedValue::U64(1)),
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
        result.insert(
            "completion_digest".into(),
            ObservedValue::Text(self.completion_digest.clone()),
        );
        result.insert(
            "input_retired".into(),
            ObservedValue::Bool(self.input_retired),
        );
        result.insert(
            "power_fence_held".into(),
            ObservedValue::Bool(self.power_fence_held),
        );
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
                ("handoff_commit", output.handoff_commit),
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
            || observation.capability.as_str() != DISPLAY_NATIVE_CURRENT_CAPABILITY
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
        if attrs.len() > 164
            || attrs.iter().any(|(key, value)| {
                key.len() > 64 || matches!(value, ObservedValue::Text(text) if text.len() > 256)
            })
            || number(attrs, "current_schema")? != 1
            || text(attrs, "original_dispatch")? != scope.original_dispatch()
        {
            return Err(DisplayEvidenceError::Shape);
        }
        let count = number(attrs, "output_count")?;
        if !(1..=16).contains(&count) {
            return Err(DisplayEvidenceError::Shape);
        }
        let window = DisplayNativeHandoffWindow {
            observed_unix_ms: observation.observed_at_unix_ms,
            observed_boot_ms: number(attrs, "sampled_boot_ms")?,
            deadline_unix_ms: number(attrs, "deadline_unix_ms")?,
            deadline_boot_ms: number(attrs, "deadline_boot_ms")?,
        };
        if observation.valid_for_ms != window.valid_for_ms()?
            || now
                .checked_sub(observation.observed_at_unix_ms)
                .is_none_or(|age| age >= observation.valid_for_ms)
        {
            return Err(DisplayEvidenceError::Freshness);
        }
        let mut outputs = BTreeMap::new();
        for index in 0..count {
            let prefix = format!("output.{index}");
            let n = |key: &str| number(attrs, &format!("{prefix}.{key}"));
            let u = |key: &str| u32::try_from(n(key)?).map_err(|_| DisplayEvidenceError::Shape);
            let id =
                DisplayOutputId::new(scope.replacement().clone(), n("handle")?, n("generation")?)
                    .map_err(|_| DisplayEvidenceError::Identity)?;
            let output = DisplayNativeCurrentOutput {
                enabled: boolean(attrs, &format!("{prefix}.enabled"))?,
                connector: u("connector")?,
                crtc: u("crtc")?,
                plane: u("plane")?,
                framebuffer: u("framebuffer")?,
                handoff_commit: n("handoff_commit")?,
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
        let result = Self::new(
            scope.clone(),
            lineage,
            window,
            outputs,
            text(attrs, "completion_digest")?.into(),
            boolean(attrs, "input_retired")?,
            boolean(attrs, "power_fence_held")?,
        )?;
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
    pub const fn window(&self) -> DisplayNativeHandoffWindow {
        self.window
    }
    #[must_use]
    pub fn outputs(&self) -> &BTreeMap<DisplayOutputId, DisplayNativeCurrentOutput> {
        &self.outputs
    }
    #[must_use]
    pub fn completion_digest(&self) -> &str {
        &self.completion_digest
    }
    #[must_use]
    pub const fn input_retired(&self) -> bool {
        self.input_retired
    }
    #[must_use]
    pub const fn power_fence_held(&self) -> bool {
        self.power_fence_held
    }

    /// The initial physical boundary comes from separately verified first-frame
    /// evidence. Fresh reads may advance ordinary buffers, never substitute
    /// outputs, native sources, connector ownership or the Root preparation.
    #[must_use]
    pub fn follows_handoff(&self, first: &DisplayNativeHandoffFacts) -> bool {
        self.lineage == *first.lineage()
            && self.window.observed_unix_ms >= first.window().observed_unix_ms
            && self.window.observed_boot_ms >= first.window().observed_boot_ms
            && self.outputs.len() == first.outputs().len()
            && self.outputs.iter().all(|(id, current)| {
                first.outputs().get(id).is_some_and(|old| {
                    current.enabled == old.enabled
                        && current.connector == old.connector
                        && current.crtc == old.crtc
                        && current.plane == old.plane
                        && current.handoff_commit == old.completed_commit
                })
            })
            && first.scope() == &self.scope
    }
    /// Comparison only. No previous sample can recreate the current native
    /// lifetime or authorize another effect. Power retirement is checked as a
    /// separate transition, never inferred from a newer timestamp.
    #[must_use]
    pub fn reconciles(&self, previous: &Self) -> bool {
        self.scope == previous.scope
            && self.lineage == previous.lineage
            && self.completion_digest == previous.completion_digest
            && self.input_retired == previous.input_retired
            && self.power_fence_held == previous.power_fence_held
            && self.window.observed_unix_ms >= previous.window.observed_unix_ms
            && self.window.observed_boot_ms >= previous.window.observed_boot_ms
            && self.outputs.len() == previous.outputs.len()
            && self.outputs.iter().all(|(id, current)| {
                previous.outputs.get(id).is_some_and(|old| {
                    current.enabled == old.enabled
                        && current.connector == old.connector
                        && current.crtc == old.crtc
                        && current.plane == old.plane
                        && current.handoff_commit == old.handoff_commit
                        && current.completed_commit >= old.completed_commit
                        && (current.completed_commit != old.completed_commit
                            || current.framebuffer == old.framebuffer)
                })
            })
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
