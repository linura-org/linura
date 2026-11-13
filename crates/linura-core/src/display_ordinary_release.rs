//! Ordinary post-commit display release intent. Complete historical comparison
//! and current scope, never approval, a Root grant, or physical release evidence.
use crate::{
    DisplayIdentityError, DisplayLayout, DisplayLayoutError, DisplayLayoutMaterial,
    DisplayOutputSet, DisplayTopologyId, MAX_DISPLAY_INTENT_BYTES, NativeOutputCapabilities,
    RequestId, ResourceId, SessionLockId,
};
const PREFIX: &str = "LNOR:1;";
const RESOURCE_PREFIX: &str = "display:ordinary-release:";
pub const MAX_DISPLAY_ORDINARY_RELEASE_BYTES: usize = MAX_DISPLAY_INTENT_BYTES + 2048;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisplayOrdinaryReleaseOutcome {
    Keep,
    Revert,
    Expired,
}
impl DisplayOrdinaryReleaseOutcome {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Keep => "keep",
            Self::Revert => "revert",
            Self::Expired => "expired",
        }
    }
}
/// Typed same-invocation identity. It deliberately cannot alias the distinct
/// replacement-invocation original-restoration resource or grant purpose.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DisplayOrdinaryReleaseScope {
    dispatch: String,
    topology: DisplayTopologyId,
}
impl DisplayOrdinaryReleaseScope {
    pub fn new(dispatch: &str, topology: DisplayTopologyId) -> Result<Self, DisplayIdentityError> {
        if !digest(dispatch) {
            return Err(DisplayIdentityError::InvalidResource);
        }
        let result = Self {
            dispatch: dispatch.into(),
            topology,
        };
        result.resource_id()?;
        Ok(result)
    }
    pub fn resource_id(&self) -> Result<ResourceId, DisplayIdentityError> {
        let topology = self.topology.resource_id()?;
        let suffix = topology
            .as_str()
            .strip_prefix("display:topology:")
            .ok_or(DisplayIdentityError::InvalidResource)?;
        ResourceId::new(format!("{RESOURCE_PREFIX}{}:{suffix}", self.dispatch))
            .map_err(|_| DisplayIdentityError::InvalidResource)
    }
    pub fn from_resource(resource: &ResourceId) -> Result<Self, DisplayIdentityError> {
        let (dispatch, topology) = resource
            .as_str()
            .strip_prefix(RESOURCE_PREFIX)
            .and_then(|v| v.split_once(':'))
            .ok_or(DisplayIdentityError::InvalidResource)?;
        let topology = ResourceId::new(format!("display:topology:{topology}"))
            .map_err(|_| DisplayIdentityError::InvalidResource)?;
        let result = Self::new(dispatch, DisplayTopologyId::from_resource(&topology)?)?;
        if result.resource_id()? != *resource {
            return Err(DisplayIdentityError::InvalidResource);
        }
        Ok(result)
    }
    #[must_use]
    pub fn original_dispatch(&self) -> &str {
        &self.dispatch
    }
    #[must_use]
    pub const fn topology(&self) -> &DisplayTopologyId {
        &self.topology
    }
}
/// All fields are untrusted comparison data. Control must derive these from
/// authenticated retained history, the actual signed terminal and fresh sources.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayOrdinaryReleaseLineage<'a> {
    pub original_request: RequestId,
    pub original_dispatch: &'a str,
    pub terminal_record: &'a str,
    pub original_checkpoint: &'a str,
    pub signed_binding: &'a str,
    pub generation: u64,
    pub state_version: u64,
    pub current_source_guard: &'a str,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayOrdinaryReleaseMaterial<'a> {
    lineage: DisplayOrdinaryReleaseLineage<'a>,
    outcome: DisplayOrdinaryReleaseOutcome,
    current_lock: SessionLockId,
    original: DisplayLayoutMaterial<'a>,
    original_text: &'a str,
}
impl<'a> DisplayOrdinaryReleaseMaterial<'a> {
    pub fn decode(text: &'a str) -> Result<Self, DisplayLayoutError> {
        if text.len() > MAX_DISPLAY_ORDINARY_RELEASE_BYTES || text.chars().any(char::is_control) {
            return Err(invalid());
        }
        let mut rest = text.strip_prefix(PREFIX).ok_or_else(invalid)?;
        let lineage = DisplayOrdinaryReleaseLineage {
            original_request: RequestId::new(field(&mut rest, 256)?).map_err(|_| invalid())?,
            original_dispatch: field(&mut rest, 64)?,
            terminal_record: field(&mut rest, 64)?,
            original_checkpoint: field(&mut rest, 64)?,
            signed_binding: field(&mut rest, 64)?,
            generation: number(field(&mut rest, 20)?)?,
            state_version: number(field(&mut rest, 20)?)?,
            current_source_guard: field(&mut rest, 64)?,
        };
        let outcome = match field(&mut rest, 7)? {
            "keep" => DisplayOrdinaryReleaseOutcome::Keep,
            "revert" => DisplayOrdinaryReleaseOutcome::Revert,
            "expired" => DisplayOrdinaryReleaseOutcome::Expired,
            _ => return Err(invalid()),
        };
        let current_lock = SessionLockId::from_resource(
            &ResourceId::new(field(&mut rest, 256)?).map_err(|_| invalid())?,
        )
        .map_err(|_| invalid())?;
        let original_text = field(&mut rest, MAX_DISPLAY_INTENT_BYTES)?;
        let original = DisplayLayoutMaterial::decode(original_text)?;
        if !rest.is_empty()
            || lineage.state_version == 0
            || [
                lineage.original_dispatch,
                lineage.terminal_record,
                lineage.original_checkpoint,
                lineage.signed_binding,
                lineage.current_source_guard,
            ]
            .iter()
            .any(|v| !digest(v))
            || current_lock.epoch() != original.topology().session()
        {
            return Err(invalid());
        }
        DisplayOrdinaryReleaseScope::new(lineage.original_dispatch, original.topology().clone())
            .map_err(|_| invalid())?;
        Ok(Self {
            lineage,
            outcome,
            current_lock,
            original,
            original_text,
        })
    }
    pub fn encode(
        lineage: &DisplayOrdinaryReleaseLineage<'_>,
        outcome: DisplayOrdinaryReleaseOutcome,
        current_lock: &SessionLockId,
        original: &str,
    ) -> Result<String, DisplayLayoutError> {
        if original.len() > MAX_DISPLAY_INTENT_BYTES
            || lineage.state_version == 0
            || [
                lineage.original_dispatch,
                lineage.terminal_record,
                lineage.original_checkpoint,
                lineage.signed_binding,
                lineage.current_source_guard,
            ]
            .iter()
            .any(|v| !digest(v))
        {
            return Err(invalid());
        }
        let lock = current_lock.resource_id().map_err(|_| invalid())?;
        let mut result = PREFIX.to_owned();
        for field in [
            lineage.original_request.as_str(),
            lineage.original_dispatch,
            lineage.terminal_record,
            lineage.original_checkpoint,
            lineage.signed_binding,
            &lineage.generation.to_string(),
            &lineage.state_version.to_string(),
            lineage.current_source_guard,
            outcome.as_str(),
            lock.as_str(),
            original,
        ] {
            result.push_str(&format!("{}:{field};", field.len()));
        }
        DisplayOrdinaryReleaseMaterial::decode(&result)?;
        Ok(result)
    }
    #[must_use]
    pub const fn lineage(&self) -> &DisplayOrdinaryReleaseLineage<'a> {
        &self.lineage
    }
    #[must_use]
    pub const fn outcome(&self) -> DisplayOrdinaryReleaseOutcome {
        self.outcome
    }
    #[must_use]
    pub const fn current_lock(&self) -> &SessionLockId {
        &self.current_lock
    }
    #[must_use]
    pub const fn original(&self) -> &DisplayLayoutMaterial<'a> {
        &self.original
    }
    #[must_use]
    pub const fn original_text(&self) -> &str {
        self.original_text
    }
    pub fn release_scope(&self) -> Result<DisplayOrdinaryReleaseScope, DisplayLayoutError> {
        DisplayOrdinaryReleaseScope::new(
            self.lineage.original_dispatch,
            self.original.topology().clone(),
        )
        .map_err(|_| invalid())
    }
    /// Revalidate the complete historical layout against the current exact
    /// native inventory. A release can only expose the kept desired state or
    /// the independently restored baseline; it cannot request another layout.
    pub fn validate_native(
        &self,
        inventory: &DisplayOutputSet,
        capabilities: &[NativeOutputCapabilities],
    ) -> Result<DisplayLayout, DisplayLayoutError> {
        let intent = self.original.validate_native(inventory, capabilities)?;
        Ok(match self.outcome {
            DisplayOrdinaryReleaseOutcome::Keep => intent.desired().clone(),
            DisplayOrdinaryReleaseOutcome::Revert | DisplayOrdinaryReleaseOutcome::Expired => {
                intent.baseline().clone()
            }
        })
    }
}
fn invalid() -> DisplayLayoutError {
    DisplayLayoutError::InvalidEncoding
}
fn digest(text: &str) -> bool {
    text.len() == 64
        && text.bytes().any(|c| c != b'0')
        && text
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn number(text: &str) -> Result<u64, DisplayLayoutError> {
    if text.is_empty()
        || text.len() > 20
        || text.len() > 1 && text.starts_with('0')
        || !text.bytes().all(|c| c.is_ascii_digit())
    {
        return Err(invalid());
    }
    text.parse().map_err(|_| invalid())
}
fn field<'a>(rest: &mut &'a str, maximum: usize) -> Result<&'a str, DisplayLayoutError> {
    let (size, tail) = rest.split_once(':').ok_or_else(invalid)?;
    let size = usize::try_from(number(size)?).map_err(|_| invalid())?;
    if size > maximum {
        return Err(invalid());
    }
    let result = tail.get(..size).ok_or_else(invalid)?;
    *rest = tail
        .get(size..)
        .and_then(|v| v.strip_prefix(';'))
        .ok_or_else(invalid)?;
    Ok(result)
}
#[cfg(test)]
mod tests;
