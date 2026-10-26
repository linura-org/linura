//! Bounded complete display intent including its exact recovery baseline and
//! native lock scope. Decoding material never proves current native support.
use crate::{
    DisplayLayout, DisplayLayoutError, DisplayOutputSet, DisplayTopologyId,
    NativeOutputCapabilities, ResourceId, SessionLockId,
};

const PREFIX: &str = "LNDI:1;";
pub const MAX_DISPLAY_INTENT_BYTES: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayLayoutIntent {
    lock: SessionLockId,
    baseline: DisplayLayout,
    desired: DisplayLayout,
}
impl DisplayLayoutIntent {
    pub fn new(
        lock: SessionLockId,
        baseline: DisplayLayout,
        desired: DisplayLayout,
    ) -> Result<Self, DisplayLayoutError> {
        if baseline.topology() != desired.topology() || lock.epoch() != desired.topology().session()
        {
            return Err(DisplayLayoutError::ForeignOutput);
        }
        let result = Self {
            lock,
            baseline,
            desired,
        };
        if result.canonical_text()?.len() > MAX_DISPLAY_INTENT_BYTES {
            return Err(DisplayLayoutError::InvalidEncoding);
        }
        Ok(result)
    }
    #[must_use]
    pub const fn lock(&self) -> &SessionLockId {
        &self.lock
    }
    #[must_use]
    pub const fn baseline(&self) -> &DisplayLayout {
        &self.baseline
    }
    #[must_use]
    pub const fn desired(&self) -> &DisplayLayout {
        &self.desired
    }
    pub fn canonical_text(&self) -> Result<String, DisplayLayoutError> {
        let lock = self
            .lock
            .resource_id()
            .map_err(|_| DisplayLayoutError::InvalidEncoding)?;
        Ok(format!(
            "{PREFIX}{};{}{}",
            lock.as_str(),
            self.baseline.canonical_text()?,
            self.desired.canonical_text()?
        ))
    }
}

/// Untrusted bounded material only. `validate_native` must succeed against a
/// fresh independently attested complete inventory before planning authority or
/// native dispatch. A hash of this material is not a dispatch credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayLayoutMaterial<'a> {
    lock: SessionLockId,
    topology: DisplayTopologyId,
    baseline: &'a str,
    desired: &'a str,
}
impl<'a> DisplayLayoutMaterial<'a> {
    pub fn decode(text: &'a str) -> Result<Self, DisplayLayoutError> {
        if text.len() > MAX_DISPLAY_INTENT_BYTES || text.chars().any(char::is_control) {
            return Err(DisplayLayoutError::InvalidEncoding);
        }
        let text = text
            .strip_prefix(PREFIX)
            .ok_or(DisplayLayoutError::InvalidEncoding)?;
        let (lock, layouts) = text
            .split_once(';')
            .ok_or(DisplayLayoutError::InvalidEncoding)?;
        let lock = SessionLockId::from_resource(
            &ResourceId::new(lock).map_err(|_| DisplayLayoutError::InvalidEncoding)?,
        )
        .map_err(|_| DisplayLayoutError::InvalidEncoding)?;
        let markers: Vec<_> = layouts
            .match_indices("LNDL:1;")
            .map(|(index, _)| index)
            .collect();
        if markers.len() != 2 || markers[0] != 0 {
            return Err(DisplayLayoutError::InvalidEncoding);
        }
        let (baseline, desired) = layouts.split_at(markers[1]);
        if !baseline.ends_with(';') || !desired.ends_with(';') {
            return Err(DisplayLayoutError::InvalidEncoding);
        }
        let topology = |layout: &str| {
            DisplayTopologyId::from_resource(
                &ResourceId::new(
                    layout
                        .split(';')
                        .nth(1)
                        .ok_or(DisplayLayoutError::InvalidEncoding)?,
                )
                .map_err(|_| DisplayLayoutError::InvalidEncoding)?,
            )
            .map_err(|_| DisplayLayoutError::InvalidEncoding)
        };
        let scope = topology(baseline)?;
        if topology(desired)? != scope || lock.epoch() != scope.session() {
            return Err(DisplayLayoutError::ForeignOutput);
        }
        Ok(Self {
            lock,
            topology: scope,
            baseline,
            desired,
        })
    }
    #[must_use]
    pub const fn lock(&self) -> &SessionLockId {
        &self.lock
    }
    #[must_use]
    pub const fn topology(&self) -> &DisplayTopologyId {
        &self.topology
    }
    pub fn validate_native(
        &self,
        inventory: &DisplayOutputSet,
        capabilities: &[NativeOutputCapabilities],
    ) -> Result<DisplayLayoutIntent, DisplayLayoutError> {
        if inventory.topology() != &self.topology {
            return Err(DisplayLayoutError::ForeignOutput);
        }
        DisplayLayoutIntent::new(
            self.lock.clone(),
            DisplayLayout::from_canonical_text(inventory, capabilities, self.baseline)?,
            DisplayLayout::from_canonical_text(inventory, capabilities, self.desired)?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BootId, CompositorInvocationId, DisplayMode, DisplayOutputId, DisplayOutputLayout,
        DisplayScale, DisplayTransform, SecurityOwnerInvocationId, SessionEpoch,
    };
    fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| unreachable!("{error:?}"))
    }
    fn fixture() -> (
        DisplayOutputSet,
        Vec<NativeOutputCapabilities>,
        DisplayLayoutIntent,
    ) {
        let epoch = value(SessionEpoch::new(
            value(BootId::new("11111111-1111-4111-8111-111111111111")),
            1000,
            "c2",
            42,
        ));
        let scope = value(DisplayTopologyId::new(
            epoch.clone(),
            "seat0",
            value(CompositorInvocationId::new(
                "33333333-3333-4333-8333-333333333333",
            )),
            3,
        ));
        let output = value(DisplayOutputId::new(scope.clone(), 1, 2));
        let inventory = value(DisplayOutputSet::new(scope, vec![output.clone()]));
        let mode = value(DisplayMode::new(1920, 1080, 60000));
        let caps = vec![value(NativeOutputCapabilities::new(
            output.clone(),
            vec![mode],
            true,
        ))];
        let row = |x| DisplayOutputLayout::Enabled {
            output: output.clone(),
            mode,
            scale: value(DisplayScale::new(1000)),
            transform: DisplayTransform::Normal,
            x,
            y: 0,
            mirror: None,
        };
        let baseline = value(DisplayLayout::new(&inventory, &caps, vec![row(0)]));
        let desired = value(DisplayLayout::new(&inventory, &caps, vec![row(100)]));
        let lock = value(SessionLockId::new(
            epoch,
            value(SecurityOwnerInvocationId::new(
                "22222222-2222-4222-8222-222222222222",
            )),
            1,
        ));
        (
            inventory,
            caps,
            value(DisplayLayoutIntent::new(lock, baseline, desired)),
        )
    }
    #[test]
    fn complete_intent_binds_lock_baseline_desired_and_exact_native_scope() {
        let (inventory, caps, intent) = fixture();
        let text = value(intent.canonical_text());
        let material = value(DisplayLayoutMaterial::decode(&text));
        assert_eq!(material.lock(), intent.lock());
        assert_eq!(value(material.validate_native(&inventory, &caps)), intent);
        let reversed = value(DisplayLayoutIntent::new(
            intent.lock().clone(),
            intent.desired().clone(),
            intent.baseline().clone(),
        ));
        assert_ne!(value(reversed.canonical_text()), text);
        let different_lock = value(SessionLockId::new(
            intent.lock().epoch().clone(),
            intent.lock().security_owner_invocation().clone(),
            2,
        ));
        let different = value(DisplayLayoutIntent::new(
            different_lock,
            intent.baseline().clone(),
            intent.desired().clone(),
        ));
        assert_ne!(value(different.canonical_text()), text);
    }
    #[test]
    fn material_cannot_normalize_aliases_unknown_schemas_or_unsupported_modes() {
        let (inventory, caps, intent) = fixture();
        let text = value(intent.canonical_text());
        for invalid in [
            text.replace("LNDI:1;", "LNDI:2;"),
            text.clone() + "\n",
            text.clone() + "LNDL:1;extra;",
            text.replace("display:topology:", "display:unknown:"),
            "x".repeat(MAX_DISPLAY_INTENT_BYTES + 1),
        ] {
            assert!(DisplayLayoutMaterial::decode(&invalid).is_err());
        }
        for invalid in [
            text.replace("1920:1080:60000", "1280:720:60000"),
            text.replace("1:2:enabled", "01:2:enabled"),
            text.clone() + "extra;",
        ] {
            assert!(
                DisplayLayoutMaterial::decode(&invalid)
                    .and_then(|material| material.validate_native(&inventory, &caps))
                    .is_err()
            );
        }
    }
}
