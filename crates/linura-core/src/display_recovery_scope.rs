//! Semantic original-attempt/replacement identity, without native handles or
//! recovered authority. A resource ID cannot prove continuity or admit effects.
use crate::{DisplayIdentityError, DisplayTopologyId, ResourceId};

const PREFIX: &str = "display:recovery:";

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DisplayRecoveryScope {
    original_dispatch: String,
    replacement: DisplayTopologyId,
}

impl DisplayRecoveryScope {
    pub fn new(
        original_dispatch: &str,
        replacement: DisplayTopologyId,
    ) -> Result<Self, DisplayIdentityError> {
        if original_dispatch.len() != 64
            || original_dispatch.bytes().all(|c| c == b'0')
            || !original_dispatch
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(DisplayIdentityError::InvalidResource);
        }
        let scope = Self {
            original_dispatch: original_dispatch.into(),
            replacement,
        };
        // Keep the existing public resource bound. Oversized identities are
        // unsupported, never truncated, aliased or represented by a hash alone.
        scope.resource_id()?;
        Ok(scope)
    }

    pub fn resource_id(&self) -> Result<ResourceId, DisplayIdentityError> {
        let replacement = self.replacement.resource_id()?;
        let suffix = replacement
            .as_str()
            .strip_prefix("display:topology:")
            .ok_or(DisplayIdentityError::InvalidResource)?;
        ResourceId::new(format!("{PREFIX}{}:{suffix}", self.original_dispatch))
            .map_err(|_| DisplayIdentityError::InvalidResource)
    }

    pub fn from_resource(resource: &ResourceId) -> Result<Self, DisplayIdentityError> {
        let rest = resource
            .as_str()
            .strip_prefix(PREFIX)
            .ok_or(DisplayIdentityError::InvalidResource)?;
        let (dispatch, suffix) = rest
            .split_once(':')
            .ok_or(DisplayIdentityError::InvalidResource)?;
        let topology = ResourceId::new(format!("display:topology:{suffix}"))
            .map_err(|_| DisplayIdentityError::InvalidResource)?;
        let scope = Self::new(dispatch, DisplayTopologyId::from_resource(&topology)?)?;
        if scope.resource_id()? != *resource {
            return Err(DisplayIdentityError::InvalidResource);
        }
        Ok(scope)
    }

    #[must_use]
    pub fn original_dispatch(&self) -> &str {
        &self.original_dispatch
    }
    #[must_use]
    pub const fn replacement(&self) -> &DisplayTopologyId {
        &self.replacement
    }
}
