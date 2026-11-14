//! Current same-invocation scanout after the ordinary completion transfer.
//! Distinct from the immutable first-frame receipt: buffers may advance while
//! disabled heads remain detached without a fabricated additional modeset.
//! These observations never authorize release or commit durable completion.
use std::collections::{BTreeMap, BTreeSet};

use crate::display::{boolean, canonical_digest, number, text};
use crate::{
    DISPLAY_PROVIDER, DisplayEvidenceError, ObservationAuthority, ObservationEnvelope,
    ObservedValue,
};
use linura_core::{
    DisplayLayout, DisplayOrdinaryReleaseScope, DisplayOutputId, DisplayOutputLayout,
};

pub const DISPLAY_ORDINARY_CURRENT_CAPABILITY: &str = "display.ordinary-current.observe";

use crate::{
    DisplayNativeHandoffWindow, DisplayOrdinaryHandoffFacts, DisplayOrdinaryHandoffLineage,
};

use crate::DisplayNativeCurrentOutput;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayOrdinaryCurrentFacts {
    scope: DisplayOrdinaryReleaseScope,
    lineage: DisplayOrdinaryHandoffLineage,
    window: DisplayNativeHandoffWindow,
    outputs: BTreeMap<DisplayOutputId, DisplayNativeCurrentOutput>,
    completion_digest: String,
    input_retired: bool,
    power_fence_held: bool,
    current_commit: Option<String>,
    final_retirement: Option<String>,
}
impl DisplayOrdinaryCurrentFacts {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: DisplayOrdinaryReleaseScope,
        lineage: DisplayOrdinaryHandoffLineage,
        window: DisplayNativeHandoffWindow,
        outputs: BTreeMap<DisplayOutputId, DisplayNativeCurrentOutput>,
        completion_digest: String,
        input_retired: bool,
        power_fence_held: bool,
        current_commit: Option<String>,
        final_retirement: Option<String>,
    ) -> Result<Self, DisplayEvidenceError> {
        let transaction = |value: &str| {
            value.starts_with("transaction:")
                && value.len() > 12
                && value.len() <= 256
                && value.bytes().all(|c| {
                    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b':' | b'-')
                })
        };
        if final_retirement
            .as_ref()
            .is_some_and(|digest| !canonical_digest(digest) || current_commit.is_none())
            || current_commit.as_ref().is_some_and(|digest| {
                !canonical_digest(digest) || power_fence_held || !input_retired
            })
            || !canonical_digest(&completion_digest)
            || [
                &lineage.checkpoint,
                &lineage.original_effect,
                &lineage.release_effect,
                &lineage.release_dispatch,
                &lineage.terminal_record,
                &lineage.signed_binding,
                &lineage.preparation_digest,
                &lineage.source_guard,
            ]
            .into_iter()
            .any(|v| !canonical_digest(v))
            || !transaction(&lineage.original_transaction)
            || !transaction(&lineage.release_transaction)
            || lineage.original_transaction == lineage.release_transaction
            || lineage.release_dispatch == scope.original_dispatch()
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
        for (id, output) in &outputs {
            if id.topology() != scope.topology()
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
            current_commit,
            final_retirement,
        })
    }

    pub fn attributes(&self) -> BTreeMap<String, ObservedValue> {
        let lineage = &self.lineage;
        let mut result = BTreeMap::from([
            ("ordinary_current_schema".into(), ObservedValue::U64(1)),
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
            "current_commit_digest".into(),
            ObservedValue::Text(
                self.current_commit
                    .clone()
                    .unwrap_or_else(|| "0".repeat(64)),
            ),
        );
        result.insert(
            "final_retirement_digest".into(),
            ObservedValue::Text(
                self.final_retirement
                    .clone()
                    .unwrap_or_else(|| "0".repeat(64)),
            ),
        );
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
            ("original_transaction", &lineage.original_transaction),
            ("original_effect", &lineage.original_effect),
            ("release_transaction", &lineage.release_transaction),
            ("release_effect", &lineage.release_effect),
            ("release_dispatch", &lineage.release_dispatch),
            ("terminal_record", &lineage.terminal_record),
            ("signed_binding", &lineage.signed_binding),
            ("preparation_digest", &lineage.preparation_digest),
            ("outcome", &lineage.outcome),
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
        scope: &DisplayOrdinaryReleaseScope,
        now: u64,
    ) -> Result<Self, DisplayEvidenceError> {
        if observation.provider.as_str() != DISPLAY_PROVIDER
            || observation.capability.as_str() != DISPLAY_ORDINARY_CURRENT_CAPABILITY
            || observation.resource
                != scope
                    .resource_id()
                    .map_err(|_| DisplayEvidenceError::Identity)?
            || observation.authority != ObservationAuthority::NativeApi
            || observation.sequence == 0
        {
            return Err(DisplayEvidenceError::Identity);
        }
        let result = Self::from_comparison_attributes(
            &observation.attributes,
            scope,
            observation.observed_at_unix_ms,
        )?;
        if observation.valid_for_ms != result.window.valid_for_ms()?
            || now
                .checked_sub(observation.observed_at_unix_ms)
                .is_none_or(|age| age >= observation.valid_for_ms)
        {
            return Err(DisplayEvidenceError::Freshness);
        }
        Ok(result)
    }
    /// Decode historical comparison data only. This constructs neither an
    /// observation nor an execution credential; current use requires fresh
    /// independently authenticated Root/native and Control evidence.
    pub fn from_comparison_attributes(
        attrs: &BTreeMap<String, ObservedValue>,
        scope: &DisplayOrdinaryReleaseScope,
        observed_at: u64,
    ) -> Result<Self, DisplayEvidenceError> {
        if attrs.len() > 169
            || attrs.iter().any(|(key, value)| {
                key.len() > 64 || matches!(value, ObservedValue::Text(text) if text.len() > 256)
            })
            || number(attrs, "ordinary_current_schema")? != 1
            || text(attrs, "original_dispatch")? != scope.original_dispatch()
        {
            return Err(DisplayEvidenceError::Shape);
        }
        let count = number(attrs, "output_count")?;
        if !(1..=16).contains(&count) {
            return Err(DisplayEvidenceError::Shape);
        }
        let window = DisplayNativeHandoffWindow {
            observed_unix_ms: observed_at,
            observed_boot_ms: number(attrs, "sampled_boot_ms")?,
            deadline_unix_ms: number(attrs, "deadline_unix_ms")?,
            deadline_boot_ms: number(attrs, "deadline_boot_ms")?,
        };
        let mut outputs = BTreeMap::new();
        for index in 0..count {
            let prefix = format!("output.{index}");
            let n = |key: &str| number(attrs, &format!("{prefix}.{key}"));
            let u = |key: &str| u32::try_from(n(key)?).map_err(|_| DisplayEvidenceError::Shape);
            let id = DisplayOutputId::new(scope.topology().clone(), n("handle")?, n("generation")?)
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
        let lineage = DisplayOrdinaryHandoffLineage {
            checkpoint: text(attrs, "checkpoint_digest")?.into(),
            original_transaction: text(attrs, "original_transaction")?.into(),
            original_effect: text(attrs, "original_effect")?.into(),
            release_transaction: text(attrs, "release_transaction")?.into(),
            release_effect: text(attrs, "release_effect")?.into(),
            release_dispatch: text(attrs, "release_dispatch")?.into(),
            terminal_record: text(attrs, "terminal_record")?.into(),
            signed_binding: text(attrs, "signed_binding")?.into(),
            preparation_digest: text(attrs, "preparation_digest")?.into(),
            outcome: text(attrs, "outcome")?.into(),
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
            match text(attrs, "current_commit_digest")? {
                raw if raw == "0".repeat(64) => None,
                raw => Some(raw.into()),
            },
            match text(attrs, "final_retirement_digest")? {
                raw if raw == "0".repeat(64) => None,
                raw => Some(raw.into()),
            },
        )?;
        if result.attributes() != *attrs {
            return Err(DisplayEvidenceError::Shape);
        }
        Ok(result)
    }

    #[must_use]
    pub const fn scope(&self) -> &DisplayOrdinaryReleaseScope {
        &self.scope
    }
    #[must_use]
    pub fn lineage(&self) -> &DisplayOrdinaryHandoffLineage {
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
    pub fn follows_handoff(&self, first: &DisplayOrdinaryHandoffFacts) -> bool {
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
    #[must_use]
    /// Phase transition comparison only. The independently observed Root grant
    /// must still match current_commit_digest; this cannot create a lifetime.
    pub fn follows_current_qualification(&self, pending: &Self) -> bool {
        if self.current_commit.is_none()
            || pending.current_commit.is_some()
            || self.final_retirement.is_some()
            || pending.final_retirement.is_some()
            || !self.input_retired
            || self.power_fence_held
        {
            return false;
        }
        let mut comparison = self.clone();
        comparison.current_commit = None;
        comparison.reconciles(pending)
    }
    pub fn final_retirement_digest(&self) -> Option<&str> {
        self.final_retirement.as_deref()
    }
    /// Comparison only; the final Root grant must be independently joined.
    pub fn follows_final_retirement(&self, qualified: &Self) -> bool {
        if self.final_retirement.is_none()
            || qualified.final_retirement.is_some()
            || self.current_commit.is_none()
        {
            return false;
        }
        let mut comparison = self.clone();
        comparison.final_retirement = None;
        comparison.reconciles(qualified)
    }
    pub fn current_commit_digest(&self) -> Option<&str> {
        self.current_commit.as_deref()
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
            && self.current_commit == previous.current_commit
            && self.final_retirement == previous.final_retirement
            && self.reconciles_inventory(previous)
    }
    /// Typed comparison of the separately authorized native-power transition.
    /// This alone is neither an observation nor a release permission.
    #[must_use]
    pub fn follows_native_power_retirement(&self, previous: &Self) -> bool {
        self.current_commit.is_none()
            && self.final_retirement.is_none()
            && self.retains_native_power_retirement(previous)
    }
    /// Comparison with the immutable before-power checkpoint across later
    /// phases. Callers must separately authenticate every current/final grant;
    /// this method supplies neither phase authority nor current observations.
    pub fn retains_native_power_retirement(&self, previous: &Self) -> bool {
        previous.current_commit.is_none()
            && previous.final_retirement.is_none()
            && self.input_retired
            && previous.input_retired
            && previous.power_fence_held
            && !self.power_fence_held
            && self.scope == previous.scope
            && self.lineage == previous.lineage
            && self.completion_digest == previous.completion_digest
            && self.reconciles_inventory(previous)
    }
    fn reconciles_inventory(&self, previous: &Self) -> bool {
        self.window.observed_unix_ms >= previous.window.observed_unix_ms
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
        layout.topology() == self.scope.topology()
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
