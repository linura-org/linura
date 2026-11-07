//! Purpose-bound original-baseline candidate material. All fields, including
//! digests and output pairs, remain untrusted until Control joins authenticated
//! durable history to independent fresh native evidence. No deadline, approval,
//! executor handle or recovered execution permission is encoded here.
use crate::{
    DisplayLayoutError, DisplayLayoutIntent, DisplayLayoutMaterial, DisplayOutputId,
    DisplayOutputSet, DisplayRecoveryMapping, DisplayRecoveryScope, NativeOutputCapabilities,
    RequestId,
};

pub const MAX_DISPLAY_RESTORATION_BYTES: usize = 12 * 1024;
const PREFIX: &str = "LNRI:1;";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayRestorationMaterial<'a> {
    original_request: RequestId,
    original_dispatch: &'a str,
    original_checkpoint: &'a str,
    replacement_baseline_guard: &'a str,
    original: DisplayLayoutMaterial<'a>,
    replacement: DisplayLayoutMaterial<'a>,
    mapping: DisplayRecoveryMapping,
}

impl<'a> DisplayRestorationMaterial<'a> {
    /// Exact bounded framing avoids interpreting resource/selector punctuation
    /// as commands or delimiter escapes. No alternate length or pair encoding.
    pub fn decode(text: &'a str) -> Result<Self, DisplayLayoutError> {
        if text.len() > MAX_DISPLAY_RESTORATION_BYTES || text.chars().any(char::is_control) {
            return Err(DisplayLayoutError::InvalidEncoding);
        }
        let mut rest = text.strip_prefix(PREFIX).ok_or_else(invalid)?;
        let original_request = RequestId::new(field(&mut rest, 256)?).map_err(|_| invalid())?;
        let original_dispatch = field(&mut rest, 64)?;
        let original_checkpoint = field(&mut rest, 64)?;
        let replacement_baseline_guard = field(&mut rest, 64)?;
        if !digest(original_dispatch)
            || !digest(original_checkpoint)
            || !digest(replacement_baseline_guard)
        {
            return Err(invalid());
        }
        let original =
            DisplayLayoutMaterial::decode(field(&mut rest, crate::MAX_DISPLAY_INTENT_BYTES)?)?;
        let replacement =
            DisplayLayoutMaterial::decode(field(&mut rest, crate::MAX_DISPLAY_INTENT_BYTES)?)?;
        DisplayRecoveryScope::new(original_dispatch, replacement.topology().clone())
            .map_err(|_| invalid())?;
        let pairs = field(&mut rest, 16 * 84)?;
        if !rest.is_empty() || !pairs.ends_with(';') {
            return Err(invalid());
        }
        let mut rows = Vec::new();
        for row in pairs.strip_suffix(';').ok_or_else(invalid)?.split(';') {
            if rows.len() == 16 || row.len() > 83 {
                return Err(invalid());
            }
            let mut parts = row.split(':');
            let mut number = || parts.next().ok_or_else(invalid).and_then(canonical_number);
            let source = DisplayOutputId::new(original.topology().clone(), number()?, number()?)
                .map_err(|_| invalid())?;
            let target = DisplayOutputId::new(replacement.topology().clone(), number()?, number()?)
                .map_err(|_| invalid())?;
            if parts.next().is_some()
                || rows.last().is_some_and(|(previous, _)| previous >= &source)
            {
                return Err(invalid());
            }
            rows.push((source, target));
        }
        let old = DisplayOutputSet::new(
            original.topology().clone(),
            rows.iter().map(|(old, _)| old.clone()).collect(),
        )
        .map_err(|_| invalid())?;
        let new = DisplayOutputSet::new(
            replacement.topology().clone(),
            rows.iter().map(|(_, new)| new.clone()).collect(),
        )
        .map_err(|_| invalid())?;
        Ok(Self {
            original_request,
            original_dispatch,
            original_checkpoint,
            replacement_baseline_guard,
            original,
            replacement,
            mapping: DisplayRecoveryMapping::new(old, new, rows)?,
        })
    }

    /// Encoding checks the exact original baseline semantics. It cannot encode
    /// a request for a failed desired layout under a restoration purpose.
    pub fn encode(
        original_request: &RequestId,
        original_dispatch: &str,
        original_checkpoint: &str,
        replacement_baseline_guard: &str,
        original: &DisplayLayoutIntent,
        replacement: &DisplayLayoutIntent,
        mapping: &DisplayRecoveryMapping,
    ) -> Result<String, DisplayLayoutError> {
        DisplayRecoveryScope::new(original_dispatch, replacement.baseline().topology().clone())
            .map_err(|_| invalid())?;
        if !digest(original_dispatch)
            || !digest(original_checkpoint)
            || !digest(replacement_baseline_guard)
            || replacement.baseline().topology() != mapping.replacement().topology()
            || mapping.remap_baseline(original.baseline())? != replacement.desired().outputs()
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
        for field in [
            original_request.as_str(),
            original_dispatch,
            original_checkpoint,
            replacement_baseline_guard,
            &original.canonical_text()?,
            &replacement.canonical_text()?,
            &pairs,
        ] {
            out.push_str(&format!("{}:{field};", field.len()));
        }
        if out.len() > MAX_DISPLAY_RESTORATION_BYTES {
            return Err(invalid());
        }
        Ok(out)
    }

    /// Historical capabilities validate only the original stored shape. Fresh
    /// replacement capabilities and continuity must be obtained independently;
    /// the historical sample is never returned as current evidence.
    pub fn validate_native(
        &self,
        historical: &DisplayOutputSet,
        historical_capabilities: &[NativeOutputCapabilities],
        current: &DisplayOutputSet,
        current_capabilities: &[NativeOutputCapabilities],
    ) -> Result<(DisplayLayoutIntent, DisplayLayoutIntent), DisplayLayoutError> {
        let original = self
            .original
            .validate_native(historical, historical_capabilities)?;
        let replacement = self
            .replacement
            .validate_native(current, current_capabilities)?;
        let derived = self.mapping.restoration_intent(
            &original,
            replacement.baseline().clone(),
            current_capabilities,
            replacement.lock().clone(),
        )?;
        if derived != replacement
            || historical.outputs().len() != self.mapping.outputs().len()
            || current.outputs().len() != self.mapping.outputs().len()
        {
            return Err(invalid());
        }
        Ok((original, replacement))
    }

    #[must_use]
    pub const fn original_request(&self) -> &RequestId {
        &self.original_request
    }
    #[must_use]
    pub const fn original_dispatch(&self) -> &str {
        self.original_dispatch
    }
    #[must_use]
    pub const fn original_checkpoint(&self) -> &str {
        self.original_checkpoint
    }
    #[must_use]
    pub const fn replacement_baseline_guard(&self) -> &str {
        self.replacement_baseline_guard
    }
    #[must_use]
    pub const fn original(&self) -> &DisplayLayoutMaterial<'a> {
        &self.original
    }
    #[must_use]
    pub const fn replacement(&self) -> &DisplayLayoutMaterial<'a> {
        &self.replacement
    }
    #[must_use]
    pub const fn mapping(&self) -> &DisplayRecoveryMapping {
        &self.mapping
    }

    pub fn recovery_scope(&self) -> Result<DisplayRecoveryScope, DisplayLayoutError> {
        DisplayRecoveryScope::new(self.original_dispatch, self.replacement.topology().clone())
            .map_err(|_| invalid())
    }
}

fn invalid() -> DisplayLayoutError {
    DisplayLayoutError::InvalidEncoding
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value.bytes().any(|c| c != b'0')
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn canonical_number(value: &str) -> Result<u64, DisplayLayoutError> {
    if value.is_empty()
        || value.len() > 20
        || value.len() > 1 && value.starts_with('0')
        || !value.bytes().all(|c| c.is_ascii_digit())
    {
        return Err(invalid());
    }
    value.parse().map_err(|_| invalid())
}
fn field<'a>(rest: &mut &'a str, bound: usize) -> Result<&'a str, DisplayLayoutError> {
    let (size, tail) = rest.split_once(':').ok_or_else(invalid)?;
    let size = usize::try_from(canonical_number(size)?).map_err(|_| invalid())?;
    if size > bound {
        return Err(invalid());
    }
    let value = tail.get(..size).ok_or_else(invalid)?;
    *rest = tail
        .get(size..)
        .and_then(|v| v.strip_prefix(';'))
        .ok_or_else(invalid)?;
    Ok(value)
}
