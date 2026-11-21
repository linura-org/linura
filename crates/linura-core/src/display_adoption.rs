//! Kept-intent replacement comparison, deliberately separate from original
//! baseline restoration and same-invocation successor admission. All identities
//! and mappings are untrusted comparison data. They create no current evidence,
//! approval, native lease, reference-retirement or execution permission.
use crate::{
    DisplayLayout, DisplayLayoutError, DisplayLayoutIntent, DisplayOutputId, DisplayOutputSet,
    DisplayTopologyId, NativeOutputCapabilities, ResourceId, SessionLockId,
};
use std::collections::BTreeMap;
mod material;
pub use material::{
    DisplayKeptAdoptionLineage, DisplayKeptAdoptionMaterial, MAX_DISPLAY_KEPT_ADOPTION_BYTES,
};

/// Semantic generation of the independently supervised display-protection
/// service, never its D-Bus sender, PID, socket or a credential. Only a fresh
/// canonical observation from the trusted adapter may attest this identifier.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DisplayProtectionInvocationId(String);
impl DisplayProtectionInvocationId {
    pub fn new(value: impl Into<String>) -> Result<Self, DisplayLayoutError> {
        let value = value.into();
        if !crate::session_epoch::canonical_nonzero_uuid(&value) {
            return Err(DisplayLayoutError::InvalidEncoding);
        }
        Ok(Self(value))
    }
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Comparison of the old and current native identities, not proof of why a
/// lifetime ended. Control must independently establish the applicable actual
/// replacement/loss, fresh protection and canonical managed authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisplayKeptAdoptionReplacement {
    CompositorReplacement,
    ProtectionReplacement,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayKeptAdoptionMapping {
    original: DisplayOutputSet,
    current: DisplayOutputSet,
    outputs: BTreeMap<DisplayOutputId, DisplayOutputId>,
    replacement: DisplayKeptAdoptionReplacement,
}
impl DisplayKeptAdoptionMapping {
    /// Complete explicit output bijection only. Names, EDID, handle equality
    /// and the selected replacement kind never prove continuity or admission.
    /// Unlike baseline restoration, Root-only replacement may keep the actual
    /// compositor. It still requires a separate freshly attested Root lifetime;
    /// no old StartupFence may be reset, reconnected or reconstructed.
    pub fn new(
        original: DisplayOutputSet,
        current: DisplayOutputSet,
        pairs: Vec<(DisplayOutputId, DisplayOutputId)>,
    ) -> Result<Self, DisplayLayoutError> {
        let old = original.topology();
        let new = current.topology();
        if old.session().boot() != new.session().boot()
            || old.session().uid() != new.session().uid()
            || old.seat() != new.seat()
            || old.compositor() == new.compositor() && old.session() != new.session()
        {
            return Err(DisplayLayoutError::ForeignOutput);
        }
        let replacement = if old.compositor() == new.compositor() {
            DisplayKeptAdoptionReplacement::ProtectionReplacement
        } else {
            DisplayKeptAdoptionReplacement::CompositorReplacement
        };
        let outputs = crate::display_recovery::checked_bijection(&original, &current, pairs)?;
        Ok(Self {
            original,
            current,
            outputs,
            replacement,
        })
    }
    #[must_use]
    pub const fn original(&self) -> &DisplayOutputSet {
        &self.original
    }
    #[must_use]
    pub const fn current(&self) -> &DisplayOutputSet {
        &self.current
    }
    #[must_use]
    pub const fn outputs(&self) -> &BTreeMap<DisplayOutputId, DisplayOutputId> {
        &self.outputs
    }
    #[must_use]
    pub const fn replacement(&self) -> DisplayKeptAdoptionReplacement {
        self.replacement
    }

    /// Remap the original kept desired state, not its restoration baseline.
    /// Equal current/desired geometry is intentionally representable: adoption
    /// still needs separately authorized actual ownership and frame evidence.
    /// This candidate cannot bypass ordinary Apply's native no-change refusal.
    pub fn candidate(
        &self,
        desired: &DisplayLayout,
        current: DisplayLayout,
        capabilities: &[NativeOutputCapabilities],
        lock: SessionLockId,
    ) -> Result<DisplayLayoutIntent, DisplayLayoutError> {
        if current.topology() != self.current.topology()
            || lock.epoch() != self.current.topology().session()
        {
            return Err(DisplayLayoutError::ForeignOutput);
        }
        let current = DisplayLayout::new(&self.current, capabilities, current.outputs().to_vec())?;
        let desired = DisplayLayout::new(
            &self.current,
            capabilities,
            crate::display_recovery::remap_layout(&self.original, &self.outputs, desired)?,
        )?;
        DisplayLayoutIntent::new(lock, current, desired)
    }
}

/// Purpose-separated old kept-attempt/current-topology selection. A decoded
/// resource cannot establish historical Keep, Root loss or current permission.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DisplayKeptAdoptionScope {
    original_dispatch: String,
    current: DisplayTopologyId,
}
impl DisplayKeptAdoptionScope {
    pub fn new(
        original_dispatch: &str,
        current: DisplayTopologyId,
    ) -> Result<Self, DisplayLayoutError> {
        if original_dispatch.len() != 64
            || !original_dispatch.bytes().any(|b| b != b'0')
            || !original_dispatch
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(DisplayLayoutError::InvalidEncoding);
        }
        let result = Self {
            original_dispatch: original_dispatch.into(),
            current,
        };
        result.resource_id()?;
        Ok(result)
    }
    pub fn resource_id(&self) -> Result<ResourceId, DisplayLayoutError> {
        let topology = self
            .current
            .resource_id()
            .map_err(|_| DisplayLayoutError::InvalidEncoding)?;
        let suffix = topology
            .as_str()
            .strip_prefix("display:topology:")
            .ok_or(DisplayLayoutError::InvalidEncoding)?;
        ResourceId::new(format!(
            "display:adopt-kept:{}:{suffix}",
            self.original_dispatch
        ))
        .map_err(|_| DisplayLayoutError::InvalidEncoding)
    }
    pub fn from_resource(resource: &ResourceId) -> Result<Self, DisplayLayoutError> {
        let (dispatch, suffix) = resource
            .as_str()
            .strip_prefix("display:adopt-kept:")
            .and_then(|s| s.split_once(':'))
            .ok_or(DisplayLayoutError::InvalidEncoding)?;
        let topology = ResourceId::new(format!("display:topology:{suffix}"))
            .map_err(|_| DisplayLayoutError::InvalidEncoding)?;
        let current = DisplayTopologyId::from_resource(&topology)
            .map_err(|_| DisplayLayoutError::InvalidEncoding)?;
        let result = Self::new(dispatch, current)?;
        if result.resource_id()? != *resource {
            return Err(DisplayLayoutError::InvalidEncoding);
        }
        Ok(result)
    }
    #[must_use]
    pub fn original_dispatch(&self) -> &str {
        &self.original_dispatch
    }
    #[must_use]
    pub const fn current(&self) -> &DisplayTopologyId {
        &self.current
    }
}

#[cfg(test)]
mod tests;
