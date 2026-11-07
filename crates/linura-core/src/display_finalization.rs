//! Explicit terminal intent, separate from nonterminal LNRI:1 restoration.
//! These are untrusted comparison fields, never approval or execution authority.
//! Control must join authenticated linked history and fresh independent evidence
//! before canonical review, durable prepare and a sealed one-use terminal port.
use crate::{
    DisplayLayout, DisplayLayoutError, DisplayOutputSet, DisplayRecoveryScope,
    DisplayRestorationMaterial, MAX_DISPLAY_RESTORATION_BYTES, NativeOutputCapabilities, RequestId,
    ResourceId, SessionLockId,
};

pub const MAX_DISPLAY_FINALIZATION_BYTES: usize = MAX_DISPLAY_RESTORATION_BYTES + 2048;
const PREFIX: &str = "LNRF:1;";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayFinalizationMaterial<'a> {
    restoration_request: RequestId,
    restoration_dispatch: &'a str,
    terminal_link: &'a str,
    restored_source_guard: &'a str,
    post_write_epoch: u64,
    current_lock: SessionLockId,
    restoration: DisplayRestorationMaterial<'a>,
    restoration_text: &'a str,
}

impl<'a> DisplayFinalizationMaterial<'a> {
    pub fn decode(text: &'a str) -> Result<Self, DisplayLayoutError> {
        if text.len() > MAX_DISPLAY_FINALIZATION_BYTES || text.chars().any(char::is_control) {
            return Err(invalid());
        }
        let mut rest = text.strip_prefix(PREFIX).ok_or_else(invalid)?;
        let restoration_request = RequestId::new(field(&mut rest, 256)?).map_err(|_| invalid())?;
        let restoration_dispatch = field(&mut rest, 64)?;
        let terminal_link = field(&mut rest, 64)?;
        let restored_source_guard = field(&mut rest, 64)?;
        let post_write_epoch = number(field(&mut rest, 20)?)?;
        let lock = ResourceId::new(field(&mut rest, 256)?).map_err(|_| invalid())?;
        let current_lock = SessionLockId::from_resource(&lock).map_err(|_| invalid())?;
        let restoration_text = field(&mut rest, MAX_DISPLAY_RESTORATION_BYTES)?;
        let restoration = DisplayRestorationMaterial::decode(restoration_text)?;
        if !rest.is_empty()
            || !digest(restoration_dispatch)
            || !digest(terminal_link)
            || !digest(restored_source_guard)
            || post_write_epoch == 0
            || restoration_request == *restoration.original_request()
            || restoration_dispatch == restoration.original_dispatch()
            || current_lock.epoch() != restoration.replacement().topology().session()
        {
            return Err(invalid());
        }
        Ok(Self {
            restoration_request,
            restoration_dispatch,
            terminal_link,
            restored_source_guard,
            post_write_epoch,
            current_lock,
            restoration,
            restoration_text,
        })
    }

    /// Construction does not certify a committed transaction or a terminal
    /// result. Digests and the complete historical restoration stay data.
    pub fn encode(
        restoration_request: &RequestId,
        restoration_dispatch: &str,
        terminal_link: &str,
        restored_source_guard: &str,
        post_write_epoch: u64,
        current_lock: &SessionLockId,
        restoration: &str,
    ) -> Result<String, DisplayLayoutError> {
        // Bound inputs before allocation, including the nested historical text.
        if !digest(restoration_dispatch)
            || !digest(terminal_link)
            || !digest(restored_source_guard)
            || restoration.len() > MAX_DISPLAY_RESTORATION_BYTES
        {
            return Err(invalid());
        }
        let lock = current_lock.resource_id().map_err(|_| invalid())?;
        let epoch = post_write_epoch.to_string();
        let mut out = PREFIX.to_owned();
        for value in [
            restoration_request.as_str(),
            restoration_dispatch,
            terminal_link,
            restored_source_guard,
            &epoch,
            lock.as_str(),
            restoration,
        ] {
            out.push_str(&format!("{}:{value};", value.len()));
        }
        DisplayFinalizationMaterial::decode(&out)?;
        Ok(out)
    }

    #[must_use]
    pub const fn restoration_request(&self) -> &RequestId {
        &self.restoration_request
    }
    #[must_use]
    pub const fn restoration_dispatch(&self) -> &str {
        self.restoration_dispatch
    }
    #[must_use]
    pub const fn terminal_link(&self) -> &str {
        self.terminal_link
    }
    #[must_use]
    pub const fn restored_source_guard(&self) -> &str {
        self.restored_source_guard
    }
    #[must_use]
    pub const fn post_write_epoch(&self) -> u64 {
        self.post_write_epoch
    }
    #[must_use]
    pub const fn current_lock(&self) -> &SessionLockId {
        &self.current_lock
    }
    #[must_use]
    pub const fn restoration(&self) -> &DisplayRestorationMaterial<'a> {
        &self.restoration
    }
    #[must_use]
    pub const fn restoration_text(&self) -> &str {
        self.restoration_text
    }
    pub fn recovery_scope(&self) -> Result<DisplayRecoveryScope, DisplayLayoutError> {
        self.restoration.recovery_scope()
    }

    /// Validate historical shape and fresh replacement capabilities. The only
    /// returned target is the original restored layout, with no output-write
    /// permission. Current source/frames and authenticated linked history still
    /// require independent Control verification.
    pub fn validate_native(
        &self,
        historical: &DisplayOutputSet,
        historical_capabilities: &[NativeOutputCapabilities],
        current: &DisplayOutputSet,
        current_capabilities: &[NativeOutputCapabilities],
    ) -> Result<DisplayLayout, DisplayLayoutError> {
        let (_, restored) = self.restoration.validate_native(
            historical,
            historical_capabilities,
            current,
            current_capabilities,
        )?;
        if self.current_lock.epoch() != current.topology().session() {
            return Err(invalid());
        }
        Ok(restored.desired().clone())
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
    let value = tail.get(..size).ok_or_else(invalid)?;
    *rest = tail
        .get(size..)
        .and_then(|v| v.strip_prefix(';'))
        .ok_or_else(invalid)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| unreachable!("{error:?}"))
    }
    fn original() -> &'static str {
        include_str!("display_recovery/fixtures/original-baseline.txt").trim_end()
    }
    fn material(lock: &SessionLockId, epoch: u64) -> Result<String, DisplayLayoutError> {
        DisplayFinalizationMaterial::encode(
            &value(RequestId::new("restore-before-finalization")),
            &"1".repeat(64),
            &"2".repeat(64),
            &"3".repeat(64),
            epoch,
            lock,
            original(),
        )
    }
    #[test]
    fn explicit_terminal_intent_preserves_nonterminal_history_and_fresh_lock_identity() {
        let old = value(DisplayRestorationMaterial::decode(original()));
        let lock = value(SessionLockId::new(
            old.replacement().lock().epoch().clone(),
            value(crate::SecurityOwnerInvocationId::new(
                "55555555-5555-4555-8555-555555555555",
            )),
            17,
        ));
        let text = value(material(&lock, 29));
        let decoded = value(DisplayFinalizationMaterial::decode(&text));
        assert_eq!(decoded.restoration_text(), original());
        assert_eq!(decoded.restoration(), &old);
        assert_eq!(decoded.current_lock(), &lock);
        assert_eq!(decoded.post_write_epoch(), 29);
        assert_eq!(
            decoded.restoration_request().as_str(),
            "restore-before-finalization"
        );
        assert_eq!(value(decoded.recovery_scope()), value(old.recovery_scope()));
        assert_ne!(decoded.current_lock(), old.replacement().lock());
        assert_eq!(
            text,
            value(DisplayFinalizationMaterial::encode(
                decoded.restoration_request(),
                decoded.restoration_dispatch(),
                decoded.terminal_link(),
                decoded.restored_source_guard(),
                decoded.post_write_epoch(),
                decoded.current_lock(),
                decoded.restoration_text(),
            ))
        );
        // Existing LNRI:1 remains nonterminal; its bytes alone are insufficient.
        assert!(DisplayFinalizationMaterial::decode(original()).is_err());
    }
    #[test]
    fn terminal_framing_is_bounded_canonical_complete_and_purpose_distinct() {
        let old = value(DisplayRestorationMaterial::decode(original()));
        let text = value(material(old.replacement().lock(), 29));
        assert_eq!(
            text,
            include_str!("display_recovery/fixtures/original-finalization.txt").trim_end()
        );
        for length in 0..text.len() {
            assert!(DisplayFinalizationMaterial::decode(&text[..length]).is_err());
        }
        for wrong in [
            format!("{text};"),
            format!("{text}\n"),
            text.replacen("LNRF:1;", "LNRI:1;", 1),
            text.replacen("LNRF:1;", "LNRF:2;", 1),
            text.replacen("2:29;", "2:00;", 1),
            text.replacen("2:29;", "3:+29;", 1),
            text.replacen("LNRF:1;", "LNRF:1;00:;", 1),
            "x".repeat(MAX_DISPLAY_FINALIZATION_BYTES + 1),
        ] {
            assert!(DisplayFinalizationMaterial::decode(&wrong).is_err());
        }
        assert!(material(old.replacement().lock(), 0).is_err());
        let zero = text.replacen(&"2".repeat(64), &"0".repeat(64), 1);
        assert!(DisplayFinalizationMaterial::decode(&zero).is_err());
    }
    #[test]
    fn original_authority_and_a_foreign_login_cannot_be_finalization_correlation() {
        let old = value(DisplayRestorationMaterial::decode(original()));
        let lock = old.replacement().lock();
        let foreign = value(SessionLockId::new(
            value(crate::SessionEpoch::new(
                lock.epoch().boot().clone(),
                lock.epoch().uid() + 1,
                lock.epoch().session_id(),
                lock.epoch().created_monotonic_us(),
            )),
            lock.security_owner_invocation().clone(),
            lock.generation(),
        ));
        assert!(material(&foreign, 29).is_err());
        assert!(
            DisplayFinalizationMaterial::encode(
                old.original_request(),
                &"1".repeat(64),
                &"2".repeat(64),
                &"3".repeat(64),
                29,
                lock,
                original()
            )
            .is_err()
        );
        assert!(
            DisplayFinalizationMaterial::encode(
                &value(RequestId::new("new-restore")),
                old.original_dispatch(),
                &"2".repeat(64),
                &"3".repeat(64),
                29,
                lock,
                original()
            )
            .is_err()
        );
    }
}
