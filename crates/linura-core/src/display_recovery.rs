//! Deterministic replacement-invocation layout derivation. These identities
//! are candidate comparison data, never continuity evidence or authorization.
//! Control must independently establish the operation's actual live protection, current
//! authenticated scope, canonical plan, fresh approval and durable prepare.
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    DisplayLayout, DisplayLayoutError, DisplayLayoutIntent, DisplayOutputId, DisplayOutputLayout,
    DisplayOutputSet, NativeOutputCapabilities, SessionLockId,
};

/// Exact complete old-to-new output bijection. Names, EDID and numeric handle
/// equality do not establish it. The trusted adapter supplies current evidence
/// separately; constructing this value never proves kernel continuity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayRecoveryMapping {
    original: DisplayOutputSet,
    replacement: DisplayOutputSet,
    outputs: BTreeMap<DisplayOutputId, DisplayOutputId>,
}

impl DisplayRecoveryMapping {
    pub fn new(
        original: DisplayOutputSet,
        replacement: DisplayOutputSet,
        pairs: Vec<(DisplayOutputId, DisplayOutputId)>,
    ) -> Result<Self, DisplayLayoutError> {
        let old = original.topology();
        let new = replacement.topology();
        if old.session().boot() != new.session().boot()
            || old.session().uid() != new.session().uid()
            || old.seat() != new.seat()
            || old.compositor() == new.compositor()
        {
            return Err(DisplayLayoutError::ForeignOutput);
        }
        let outputs = checked_bijection(&original, &replacement, pairs)?;
        Ok(Self {
            original,
            replacement,
            outputs,
        })
    }

    #[must_use]
    pub const fn original(&self) -> &DisplayOutputSet {
        &self.original
    }

    #[must_use]
    pub const fn replacement(&self) -> &DisplayOutputSet {
        &self.replacement
    }

    #[must_use]
    pub const fn outputs(&self) -> &BTreeMap<DisplayOutputId, DisplayOutputId> {
        &self.outputs
    }

    /// Restore only the original baseline, never the failed desired state.
    /// Revalidate every mode/disable/mirror against replacement capabilities;
    /// all ordinary layout safety rules remain in force. A fresh login epoch
    /// is permitted on the same boot/user/seat, but no old lock identity moves
    /// across the boundary. Native rules/overlay lineage require independent
    /// verification in addition to this geometry derivation.
    pub fn restoration_intent(
        &self,
        original: &DisplayLayoutIntent,
        current: DisplayLayout,
        capabilities: &[NativeOutputCapabilities],
        lock: SessionLockId,
    ) -> Result<DisplayLayoutIntent, DisplayLayoutError> {
        self.remapped_candidate(original.baseline(), current, capabilities, lock)
    }

    /// Remap structured desired state within this same-boot/user/seat mapping
    /// for a separately reviewed replacement
    /// adoption. This does not prove that the state was kept or committed. Only
    /// Control can join that historical claim to authenticated intent, graph and
    /// provenance. The caller must obtain a new canonical managed authorization
    /// and actual new native/Root lifetime; neither this mapping nor the returned
    /// intent establishes continuity or permits replay of the original Apply.
    pub fn desired_state_candidate(
        &self,
        desired: &DisplayLayout,
        current: DisplayLayout,
        capabilities: &[NativeOutputCapabilities],
        lock: SessionLockId,
    ) -> Result<DisplayLayoutIntent, DisplayLayoutError> {
        self.remapped_candidate(desired, current, capabilities, lock)
    }

    fn remapped_candidate(
        &self,
        target: &DisplayLayout,
        current: DisplayLayout,
        capabilities: &[NativeOutputCapabilities],
        lock: SessionLockId,
    ) -> Result<DisplayLayoutIntent, DisplayLayoutError> {
        if current.topology() != self.replacement.topology()
            || lock.epoch() != self.replacement.topology().session()
        {
            return Err(DisplayLayoutError::ForeignOutput);
        }
        // Revalidate even the supplied typed current layout: its capabilities
        // may have changed since it was originally constructed.
        let current =
            DisplayLayout::new(&self.replacement, capabilities, current.outputs().to_vec())?;
        DisplayLayoutIntent::new(
            lock,
            current,
            DisplayLayout::new(&self.replacement, capabilities, self.remap_layout(target)?)?,
        )
    }

    pub(super) fn remap_layout(
        &self,
        baseline: &DisplayLayout,
    ) -> Result<Vec<DisplayOutputLayout>, DisplayLayoutError> {
        remap_layout(&self.original, &self.outputs, baseline)
    }
}

// Common bounded output comparison only. Purpose-specific constructors retain
// their distinct lifetime restrictions; no provider or authority is inferred.
pub(crate) fn checked_bijection(
    original: &DisplayOutputSet,
    replacement: &DisplayOutputSet,
    pairs: Vec<(DisplayOutputId, DisplayOutputId)>,
) -> Result<BTreeMap<DisplayOutputId, DisplayOutputId>, DisplayLayoutError> {
    if pairs.len() != original.outputs().len() || pairs.len() != replacement.outputs().len() {
        return Err(DisplayLayoutError::IncompleteTopology);
    }
    let mut outputs = BTreeMap::new();
    let mut destinations = BTreeSet::new();
    for (source, destination) in pairs {
        if !original.outputs().contains(&source) || !replacement.outputs().contains(&destination) {
            return Err(DisplayLayoutError::ForeignOutput);
        }
        if !destinations.insert(destination.clone())
            || outputs.insert(source, destination).is_some()
        {
            return Err(DisplayLayoutError::AmbiguousOutput);
        }
    }
    Ok(outputs)
}

pub(crate) fn remap_layout(
    original: &DisplayOutputSet,
    outputs: &BTreeMap<DisplayOutputId, DisplayOutputId>,
    baseline: &DisplayLayout,
) -> Result<Vec<DisplayOutputLayout>, DisplayLayoutError> {
    if baseline.topology() != original.topology() || baseline.outputs().len() != outputs.len() {
        return Err(DisplayLayoutError::ForeignOutput);
    }
    let lookup = |source: &DisplayOutputId| {
        outputs
            .get(source)
            .cloned()
            .ok_or(DisplayLayoutError::ForeignOutput)
    };
    let mut restored = Vec::with_capacity(outputs.len());
    for row in baseline.outputs() {
        restored.push(match row {
            DisplayOutputLayout::Disabled { output } => DisplayOutputLayout::Disabled {
                output: lookup(output)?,
            },
            DisplayOutputLayout::Enabled {
                output,
                mode,
                scale,
                transform,
                x,
                y,
                mirror,
            } => DisplayOutputLayout::Enabled {
                output: lookup(output)?,
                mode: *mode,
                scale: *scale,
                transform: *transform,
                x: *x,
                y: *y,
                mirror: mirror.as_ref().map(lookup).transpose()?,
            },
        });
    }
    restored.sort_by(|a, b| a.output().cmp(b.output()));
    Ok(restored)
}

#[cfg(test)]
mod tests;
