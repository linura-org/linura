//! Canonical projection of fresh native post-write KMS/frame observations.
//! These are comparison facts, never approval, durable success or permission to
//! release a startup/session-lock/input/power fence. Control joins independent
//! original protection, source/layout, logind and coverage evidence separately.
use std::collections::BTreeMap;

use crate::display::{boolean, canonical_digest, number, text};
use crate::{
    DISPLAY_PROVIDER, DisplayEvidenceError, ObservationAuthority, ObservationEnvelope,
    ObservedValue,
};
use linura_core::{DisplayLayout, DisplayOutputId, DisplayOutputLayout, DisplayRecoveryScope};

pub const DISPLAY_ORIGINAL_PRESENTATION_CAPABILITY: &str = "display.original-presentation.observe";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisplayPostWriteFrame {
    Disabled,
    Presented {
        crtc: u32,
        framebuffer: u32,
        commit: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayOriginalPresentationFacts {
    scope: DisplayRecoveryScope,
    checkpoint: String,
    transaction: String,
    effect: String,
    dispatch: String,
    source_guard: String,
    epoch: u64,
    frames: BTreeMap<DisplayOutputId, DisplayPostWriteFrame>,
}

impl DisplayOriginalPresentationFacts {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: DisplayRecoveryScope,
        checkpoint: String,
        transaction: String,
        effect: String,
        dispatch: String,
        source_guard: String,
        epoch: u64,
        frames: BTreeMap<DisplayOutputId, DisplayPostWriteFrame>,
    ) -> Result<Self, DisplayEvidenceError> {
        if [&checkpoint, &effect, &dispatch, &source_guard]
            .into_iter()
            .any(|value| !canonical_digest(value))
            || !transaction.starts_with("transaction:")
            || transaction.len() <= 12
            || transaction.len() > 256
            || !transaction
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b':' | b'-'))
            || epoch == 0
            || frames.is_empty()
            || frames.len() > 16
        {
            return Err(DisplayEvidenceError::Shape);
        }
        let mut handles = std::collections::BTreeSet::new();
        let mut presented = false;
        for (output, frame) in &frames {
            if output.topology() != scope.replacement() || !handles.insert(output.handle()) {
                return Err(DisplayEvidenceError::Identity);
            }
            if let DisplayPostWriteFrame::Presented {
                crtc,
                framebuffer,
                commit,
            } = frame
            {
                if *crtc == 0 || *framebuffer == 0 || *commit == 0 {
                    return Err(DisplayEvidenceError::Shape);
                }
                presented = true;
            }
        }
        if !presented {
            return Err(DisplayEvidenceError::Shape);
        }
        Ok(Self {
            scope,
            checkpoint,
            transaction,
            effect,
            dispatch,
            source_guard,
            epoch,
            frames,
        })
    }

    pub fn attributes(&self) -> BTreeMap<String, ObservedValue> {
        let mut result = BTreeMap::from([
            ("presentation_schema".into(), ObservedValue::U64(1)),
            (
                "original_dispatch".into(),
                ObservedValue::Text(self.scope.original_dispatch().into()),
            ),
            (
                "checkpoint_digest".into(),
                ObservedValue::Text(self.checkpoint.clone()),
            ),
            (
                "transaction".into(),
                ObservedValue::Text(self.transaction.clone()),
            ),
            (
                "effect_digest".into(),
                ObservedValue::Text(self.effect.clone()),
            ),
            (
                "dispatch_digest".into(),
                ObservedValue::Text(self.dispatch.clone()),
            ),
            (
                "source_guard".into(),
                ObservedValue::Text(self.source_guard.clone()),
            ),
            ("post_write_epoch".into(), ObservedValue::U64(self.epoch)),
            (
                "output_count".into(),
                ObservedValue::U64(self.frames.len() as u64),
            ),
        ]);
        for (index, (output, frame)) in self.frames.iter().enumerate() {
            let (enabled, crtc, framebuffer, commit) = match frame {
                DisplayPostWriteFrame::Disabled => (false, 0, 0, 0),
                DisplayPostWriteFrame::Presented {
                    crtc,
                    framebuffer,
                    commit,
                } => (true, *crtc, *framebuffer, *commit),
            };
            for (key, value) in [
                ("handle", ObservedValue::U64(output.handle())),
                ("generation", ObservedValue::U64(output.generation())),
                ("enabled", ObservedValue::Bool(enabled)),
                ("crtc", ObservedValue::U64(u64::from(crtc))),
                ("framebuffer", ObservedValue::U64(u64::from(framebuffer))),
                ("commit", ObservedValue::U64(commit)),
            ] {
                result.insert(format!("output.{index}.{key}"), value);
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
            || observation.capability.as_str() != DISPLAY_ORIGINAL_PRESENTATION_CAPABILITY
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
            || observation
                .observed_at_unix_ms
                .checked_add(observation.valid_for_ms)
                .is_none()
            || now
                .checked_sub(observation.observed_at_unix_ms)
                .is_none_or(|age| age >= observation.valid_for_ms)
        {
            return Err(DisplayEvidenceError::Freshness);
        }
        let attrs = &observation.attributes;
        if attrs.len() > 105
            || number(attrs, "presentation_schema")? != 1
            || text(attrs, "original_dispatch")? != scope.original_dispatch()
        {
            return Err(DisplayEvidenceError::Shape);
        }
        let count = number(attrs, "output_count")?;
        if !(1..=16).contains(&count) {
            return Err(DisplayEvidenceError::Shape);
        }
        let mut frames = BTreeMap::new();
        for index in 0..count {
            let prefix = format!("output.{index}");
            let output = DisplayOutputId::new(
                scope.replacement().clone(),
                number(attrs, &format!("{prefix}.handle"))?,
                number(attrs, &format!("{prefix}.generation"))?,
            )
            .map_err(|_| DisplayEvidenceError::Identity)?;
            let enabled = boolean(attrs, &format!("{prefix}.enabled"))?;
            let crtc = u32::try_from(number(attrs, &format!("{prefix}.crtc"))?)
                .map_err(|_| DisplayEvidenceError::Shape)?;
            let framebuffer = u32::try_from(number(attrs, &format!("{prefix}.framebuffer"))?)
                .map_err(|_| DisplayEvidenceError::Shape)?;
            let commit = number(attrs, &format!("{prefix}.commit"))?;
            let frame = if enabled {
                DisplayPostWriteFrame::Presented {
                    crtc,
                    framebuffer,
                    commit,
                }
            } else if crtc == 0 && framebuffer == 0 && commit == 0 {
                DisplayPostWriteFrame::Disabled
            } else {
                return Err(DisplayEvidenceError::Shape);
            };
            if frames.insert(output, frame).is_some() {
                return Err(DisplayEvidenceError::Identity);
            }
        }
        let result = Self::new(
            scope.clone(),
            text(attrs, "checkpoint_digest")?.into(),
            text(attrs, "transaction")?.into(),
            text(attrs, "effect_digest")?.into(),
            text(attrs, "dispatch_digest")?.into(),
            text(attrs, "source_guard")?.into(),
            number(attrs, "post_write_epoch")?,
            frames,
        )?;
        if result.attributes() != *attrs {
            return Err(DisplayEvidenceError::Shape);
        }
        Ok(result)
    }

    #[must_use]
    pub fn matches_binding(
        &self,
        checkpoint: &str,
        transaction: &str,
        effect: &str,
        dispatch: &str,
    ) -> bool {
        self.checkpoint == checkpoint
            && self.transaction == transaction
            && self.effect == effect
            && self.dispatch == dispatch
    }
    #[must_use]
    pub fn source_guard(&self) -> &str {
        &self.source_guard
    }
    #[must_use]
    pub fn matches_layout(&self, layout: &DisplayLayout) -> bool {
        layout.topology() == self.scope.replacement()
            && layout.outputs().len() == self.frames.len()
            && layout.outputs().iter().all(|target| {
                matches!(
                    (target, self.frames.get(target.output())),
                    (
                        DisplayOutputLayout::Disabled { .. },
                        Some(DisplayPostWriteFrame::Disabled),
                    ) | (
                        DisplayOutputLayout::Enabled { .. },
                        Some(DisplayPostWriteFrame::Presented { .. }),
                    )
                )
            })
    }
}

#[cfg(test)]
mod tests;
