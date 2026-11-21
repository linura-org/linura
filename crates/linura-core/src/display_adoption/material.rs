//! Complete private comparison material. Decoding does not authenticate
//! retained history, establish current facts or authorize a new lifetime.
use super::*;
use crate::{
    DisplayLayoutMaterial, DisplayOrdinaryReleaseMaterial, DisplayOrdinaryReleaseOutcome,
    MAX_DISPLAY_INTENT_BYTES, MAX_DISPLAY_ORDINARY_RELEASE_BYTES, RequestId,
};
const PREFIX: &str = "LNKA:1;";
pub const MAX_DISPLAY_KEPT_ADOPTION_BYTES: usize = 16 * 1024;

/// Full signed preimages and semantic provenance must be independently
/// authenticated by Control. These exact identities are never credentials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayKeptAdoptionLineage<'a> {
    pub release_request: RequestId,
    pub release_dispatch: &'a str,
    pub release_binding: &'a str,
    pub release_generation: u64,
    pub release_state_version: u64,
    pub release_desired: &'a str,
    pub release_graph: &'a str,
    pub release_provenance: &'a str,
    pub kept_desired: &'a str,
    pub kept_graph: &'a str,
    pub kept_provenance: &'a str,
    pub released_record: &'a str,
    pub adopted_record: &'a str,
    pub state_record: &'a str,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayKeptAdoptionMaterial<'a> {
    lineage: DisplayKeptAdoptionLineage<'a>,
    protection: DisplayProtectionInvocationId,
    current_source_guard: &'a str,
    release: DisplayOrdinaryReleaseMaterial<'a>,
    release_text: &'a str,
    current: DisplayLayoutMaterial<'a>,
    mapping: DisplayKeptAdoptionMapping,
}
impl<'a> DisplayKeptAdoptionMaterial<'a> {
    pub fn decode(text: &'a str) -> Result<Self, DisplayLayoutError> {
        if text.len() > MAX_DISPLAY_KEPT_ADOPTION_BYTES || text.chars().any(char::is_control) {
            return Err(invalid());
        }
        let mut rest = text.strip_prefix(PREFIX).ok_or_else(invalid)?;
        let lineage = DisplayKeptAdoptionLineage {
            release_request: RequestId::new(field(&mut rest, 256)?).map_err(|_| invalid())?,
            release_dispatch: field(&mut rest, 64)?,
            release_binding: field(&mut rest, 64)?,
            release_generation: number(field(&mut rest, 20)?)?,
            release_state_version: number(field(&mut rest, 20)?)?,
            release_desired: field(&mut rest, 64)?,
            release_graph: field(&mut rest, 64)?,
            release_provenance: field(&mut rest, 64)?,
            kept_desired: field(&mut rest, 64)?,
            kept_graph: field(&mut rest, 64)?,
            kept_provenance: field(&mut rest, 64)?,
            released_record: field(&mut rest, 64)?,
            adopted_record: field(&mut rest, 64)?,
            state_record: field(&mut rest, 64)?,
        };
        validate_lineage(&lineage)?;
        let protection = DisplayProtectionInvocationId::new(field(&mut rest, 36)?)?;
        let current_source_guard = field(&mut rest, 64)?;
        if !digest(current_source_guard) {
            return Err(invalid());
        }
        let release_text = field(&mut rest, MAX_DISPLAY_ORDINARY_RELEASE_BYTES)?;
        let release = DisplayOrdinaryReleaseMaterial::decode(release_text)?;
        if release.outcome() != DisplayOrdinaryReleaseOutcome::Keep {
            return Err(invalid());
        }
        let current = DisplayLayoutMaterial::decode(field(&mut rest, MAX_DISPLAY_INTENT_BYTES)?)?;
        let pairs = field(&mut rest, 16 * 84)?;
        if !rest.is_empty() {
            return Err(invalid());
        }
        let mut rows = Vec::new();
        for row in pairs.strip_suffix(';').ok_or_else(invalid)?.split(';') {
            if rows.len() == 16 || row.len() > 83 {
                return Err(invalid());
            }
            let mut parts = row.split(':');
            let mut n = || number(parts.next().ok_or_else(invalid)?);
            let old = DisplayOutputId::new(release.original().topology().clone(), n()?, n()?)
                .map_err(|_| invalid())?;
            let new = DisplayOutputId::new(current.topology().clone(), n()?, n()?)
                .map_err(|_| invalid())?;
            if parts.next().is_some() || rows.last().is_some_and(|(previous, _)| previous >= &old) {
                return Err(invalid());
            }
            rows.push((old, new));
        }
        let original = DisplayOutputSet::new(
            release.original().topology().clone(),
            rows.iter().map(|(old, _)| old.clone()).collect(),
        )
        .map_err(|_| invalid())?;
        let inventory = DisplayOutputSet::new(
            current.topology().clone(),
            rows.iter().map(|(_, new)| new.clone()).collect(),
        )
        .map_err(|_| invalid())?;
        if !release.original().references_exact_output_set(&original)
            || !current.references_exact_output_set(&inventory)
        {
            return Err(invalid());
        }
        let mapping = DisplayKeptAdoptionMapping::new(original, inventory, rows)?;
        DisplayKeptAdoptionScope::new(
            release.lineage().original_dispatch,
            current.topology().clone(),
        )?;
        Ok(Self {
            lineage,
            protection,
            current_source_guard,
            release,
            release_text,
            current,
            mapping,
        })
    }
    /// Exact kept desired semantics and complete inventories are required.
    /// Signed preimages, Root generation and fresh native facts are separately
    /// mandatory Control inputs; none are inferred from these bytes.
    pub fn encode(
        lineage: &DisplayKeptAdoptionLineage<'_>,
        protection: &DisplayProtectionInvocationId,
        current_source_guard: &str,
        release_text: &str,
        original: &DisplayLayoutIntent,
        current: &DisplayLayoutIntent,
        mapping: &DisplayKeptAdoptionMapping,
    ) -> Result<String, DisplayLayoutError> {
        validate_lineage(lineage)?;
        let release = DisplayOrdinaryReleaseMaterial::decode(release_text)?;
        if release.outcome() != DisplayOrdinaryReleaseOutcome::Keep
            || !digest(current_source_guard)
            || release.original_text() != original.canonical_text()?
            || original.baseline().topology() != mapping.original().topology()
            || current.baseline().topology() != mapping.current().topology()
            || original.desired().outputs().len() != mapping.outputs().len()
            || current.baseline().outputs().len() != mapping.outputs().len()
            || current
                .baseline()
                .outputs()
                .iter()
                .any(|row| !mapping.current().outputs().contains(row.output()))
            || crate::display_recovery::remap_layout(
                mapping.original(),
                mapping.outputs(),
                original.desired(),
            )? != current.desired().outputs()
        {
            return Err(invalid());
        }
        let mut pairs = String::new();
        for (old, new) in mapping.outputs() {
            pairs.push_str(&format!(
                "{}:{}:{}:{};",
                old.handle(),
                old.generation(),
                new.handle(),
                new.generation()
            ));
        }
        let mut out = PREFIX.to_owned();
        for item in [
            lineage.release_request.as_str(),
            lineage.release_dispatch,
            lineage.release_binding,
            &lineage.release_generation.to_string(),
            &lineage.release_state_version.to_string(),
            lineage.release_desired,
            lineage.release_graph,
            lineage.release_provenance,
            lineage.kept_desired,
            lineage.kept_graph,
            lineage.kept_provenance,
            lineage.released_record,
            lineage.adopted_record,
            lineage.state_record,
            protection.as_str(),
            current_source_guard,
            release_text,
            &current.canonical_text()?,
            &pairs,
        ] {
            out.push_str(&format!("{}:{item};", item.len()));
        }
        DisplayKeptAdoptionMaterial::decode(&out)?;
        Ok(out)
    }
    pub fn validate_native(
        &self,
        historical: &DisplayOutputSet,
        historical_capabilities: &[NativeOutputCapabilities],
        current: &DisplayOutputSet,
        current_capabilities: &[NativeOutputCapabilities],
    ) -> Result<(DisplayLayoutIntent, DisplayLayoutIntent), DisplayLayoutError> {
        // Historical capabilities validate stored shape only.
        let original = self
            .release
            .original()
            .validate_native(historical, historical_capabilities)?;
        let candidate = self
            .current
            .validate_native(current, current_capabilities)?;
        if !same_inventory(historical, self.mapping.original())
            || !same_inventory(current, self.mapping.current())
            || self.mapping.candidate(
                original.desired(),
                candidate.baseline().clone(),
                current_capabilities,
                candidate.lock().clone(),
            )? != candidate
        {
            return Err(invalid());
        }
        Ok((original, candidate))
    }
    pub fn scope(&self) -> Result<DisplayKeptAdoptionScope, DisplayLayoutError> {
        DisplayKeptAdoptionScope::new(
            self.release.lineage().original_dispatch,
            self.current.topology().clone(),
        )
    }
    #[must_use]
    pub const fn lineage(&self) -> &DisplayKeptAdoptionLineage<'a> {
        &self.lineage
    }
    #[must_use]
    pub const fn protection(&self) -> &DisplayProtectionInvocationId {
        &self.protection
    }
    #[must_use]
    pub const fn current_source_guard(&self) -> &str {
        self.current_source_guard
    }
    #[must_use]
    pub const fn release(&self) -> &DisplayOrdinaryReleaseMaterial<'a> {
        &self.release
    }
    #[must_use]
    pub const fn release_text(&self) -> &str {
        self.release_text
    }
    #[must_use]
    pub const fn current(&self) -> &DisplayLayoutMaterial<'a> {
        &self.current
    }
    #[must_use]
    pub const fn mapping(&self) -> &DisplayKeptAdoptionMapping {
        &self.mapping
    }
}
fn invalid() -> DisplayLayoutError {
    DisplayLayoutError::InvalidEncoding
}
// Inventory enumeration order is not semantic identity. Both sets already
// reject duplicate handles; compare the exact complete generation-bound IDs.
fn same_inventory(a: &DisplayOutputSet, b: &DisplayOutputSet) -> bool {
    a.topology() == b.topology()
        && a.outputs().len() == b.outputs().len()
        && a.outputs().iter().all(|id| b.outputs().contains(id))
}
fn digest(text: &str) -> bool {
    text.len() == 64
        && text.bytes().any(|b| b != b'0')
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn validate_lineage(l: &DisplayKeptAdoptionLineage<'_>) -> Result<(), DisplayLayoutError> {
    if l.release_state_version == 0
        || [
            l.release_dispatch,
            l.release_binding,
            l.release_desired,
            l.release_graph,
            l.release_provenance,
            l.kept_desired,
            l.kept_graph,
            l.kept_provenance,
            l.released_record,
            l.adopted_record,
            l.state_record,
        ]
        .into_iter()
        .any(|s| !digest(s))
    {
        return Err(invalid());
    }
    Ok(())
}
fn number(text: &str) -> Result<u64, DisplayLayoutError> {
    if text.is_empty()
        || text.len() > 20
        || text.len() > 1 && text.starts_with('0')
        || !text.bytes().all(|b| b.is_ascii_digit())
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
        .and_then(|s| s.strip_prefix(';'))
        .ok_or_else(invalid)?;
    Ok(result)
}
#[cfg(test)]
mod tests;
