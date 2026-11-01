//! In-memory S25 appearance draft lifecycle. A preview is experience-ephemeral:
//! it cannot write persistence, mint approval or reach a native renderer. Caller
//! identity and session/window generations must originate from trusted native
//! observation at the future transport composition boundary.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use linura_core::SessionEpoch;
use linura_transaction::{
    ContentDigest, PersonalizationChoices, PersonalizationPreferenceRecord,
};

use crate::{
    AuthenticatedPrincipal, PersonalizationConfigurationRequest,
    PersonalizationPreferencesControl,
};

pub const MAX_PERSONALIZATION_PREVIEWS: usize = 64;
pub const PERSONALIZATION_PREVIEW_TTL_MS: u64 = 30_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersonalizationPreviewContext {
    /// Verified native login epoch, including boot and monotonic generation.
    pub session: SessionEpoch,
    /// Verified native seat; not an arbitrary client-requested output selector.
    pub seat: String,
    /// Verified native window belonging to this session.
    pub window: String,
    pub window_generation: u64,
    pub compositor_generation: u64,
}

impl PersonalizationPreviewContext {
    fn validate(&self, owner: &AuthenticatedPrincipal) -> Result<(), String> {
        if self.session.uid() == 0
            || owner.as_str() != format!("unix:uid:{}", self.session.uid())
            || !valid_segment(&self.seat, 64)
            || !valid_segment(&self.window, 128)
            || self.window_generation == 0
            || self.compositor_generation == 0
        {
            return Err("personalization preview context is invalid or owned by another session".into());
        }
        Ok(())
    }
}

fn valid_segment(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_uppercase()
                || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersonalizationPreviewReceipt {
    pub context: PersonalizationPreviewContext,
    pub source_revision: u64,
    pub source_digest: Option<ContentDigest>,
    pub choices: PersonalizationChoices,
    pub expires_at_unix_ms: u64,
    pub generation: u64,
}

/// No UI or policy/executor handle lives here. The caller may produce an
/// authenticated *local-state request* only after revalidating every binding.
#[derive(Debug, Default)]
pub struct PersonalizationPreviewControl {
    active: BTreeMap<String, PersonalizationPreviewReceipt>,
    next_generation: u64,
}

impl PersonalizationPreviewControl {
    pub fn new() -> Self {
        Self::default()
    }

    fn scope(context: &PersonalizationPreviewContext) -> Result<String, String> {
        context.session.resource_id().map(|r| r.as_str().to_owned())
            .map_err(|error| error.to_string())
    }

    pub fn begin(
        &mut self,
        preferences: &PersonalizationPreferencesControl,
        principal: &AuthenticatedPrincipal,
        context: PersonalizationPreviewContext,
        choices: PersonalizationChoices,
    ) -> Result<PersonalizationPreviewReceipt, String> {
        self.begin_at(preferences, principal, context, choices, now()?)
    }

    fn begin_at(
        &mut self,
        preferences: &PersonalizationPreferencesControl,
        principal: &AuthenticatedPrincipal,
        context: PersonalizationPreviewContext,
        choices: PersonalizationChoices,
        sampled: u64,
    ) -> Result<PersonalizationPreviewReceipt, String> {
        context.validate(principal)?;
        if sampled == 0 || sampled > i64::MAX as u64 {
            return Err("personalization preview clock is invalid".into());
        }
        self.expire_at(sampled);
        let scope = Self::scope(&context)?;
        if self.active.contains_key(&scope) {
            return Err("another live personalization preview owns this session".into());
        }
        if self.active.len() >= MAX_PERSONALIZATION_PREVIEWS {
            return Err("personalization preview retention is full".into());
        }
        let current = preferences.current(principal)?;
        let next_generation = self.next_generation.checked_add(1)
            .ok_or("personalization preview generation overflow")?;
        let deadline = sampled.checked_add(PERSONALIZATION_PREVIEW_TTL_MS)
            .ok_or("personalization preview clock overflow")?;
        let result = PersonalizationPreviewReceipt {
            context,
            source_revision: current.as_ref().map_or(0, PersonalizationPreferenceRecord::revision),
            source_digest: current.as_ref().map(PersonalizationPreferenceRecord::digest).cloned(),
            choices,
            expires_at_unix_ms: deadline,
            generation: next_generation,
        };
        self.active.insert(scope, result.clone());
        self.next_generation = next_generation;
        Ok(result)
    }

    /// Read a draft only if native session, seat, window and both generations
    /// still match; no preview content is interpreted as applied renderer state.
    pub fn inspect(
        &mut self,
        principal: &AuthenticatedPrincipal,
        context: &PersonalizationPreviewContext,
        generation: u64,
    ) -> Result<PersonalizationPreviewReceipt, String> {
        self.inspect_at(principal, context, generation, now()?)
    }

    fn inspect_at(
        &mut self,
        principal: &AuthenticatedPrincipal,
        context: &PersonalizationPreviewContext,
        generation: u64,
        sampled: u64,
    ) -> Result<PersonalizationPreviewReceipt, String> {
        context.validate(principal)?;
        if sampled == 0 { return Err("personalization preview clock unavailable".into()); }
        self.expire_at(sampled);
        let draft = self.active.get(&Self::scope(context)?)
            .ok_or("personalization preview is not active")?;
        if draft.generation != generation || &draft.context != context {
            return Err("personalization preview generation or native binding changed".into());
        }
        Ok(draft.clone())
    }

    pub fn cancel(
        &mut self,
        principal: &AuthenticatedPrincipal,
        context: &PersonalizationPreviewContext,
        generation: u64,
    ) -> Result<(), String> {
        context.validate(principal)?;
        let scope = Self::scope(context)?;
        match self.active.get(&scope) {
            Some(draft) if draft.generation == generation && &draft.context == context => {
                self.active.remove(&scope);
                Ok(())
            }
            _ => Err("personalization preview cancellation binding differs".into()),
        }
    }

    /// Convert a draft into an ordinary authenticated CAS request. No durable
    /// or native action is taken here. The caller must still call preferences
    /// Control.configure, whose state check makes stale Apply fail closed.
    pub fn take_apply_request(
        &mut self,
        preferences: &PersonalizationPreferencesControl,
        principal: &AuthenticatedPrincipal,
        context: &PersonalizationPreviewContext,
        generation: u64,
        operation_id: String,
    ) -> Result<PersonalizationConfigurationRequest, String> {
        self.take_apply_request_at(
            preferences, principal, context, generation, operation_id, now()?,
        )
    }

    fn take_apply_request_at(
        &mut self,
        preferences: &PersonalizationPreferencesControl,
        principal: &AuthenticatedPrincipal,
        context: &PersonalizationPreviewContext,
        generation: u64,
        operation_id: String,
        sampled: u64,
    ) -> Result<PersonalizationConfigurationRequest, String> {
        let draft = self.inspect_at(principal, context, generation, sampled)?;
        let current = preferences.current(principal)?;
        let current_revision = current.as_ref()
            .map_or(0, PersonalizationPreferenceRecord::revision);
        let current_digest = current.as_ref()
            .map(PersonalizationPreferenceRecord::digest);
        if current_revision != draft.source_revision
            || current_digest != draft.source_digest.as_ref()
        {
            return Err("personalization preview source revision has changed".into());
        }
        // Consume only after fresh CAS and complete binding checks, never
        // convert the live draft into a reusable native effect credential.
        self.active.remove(&Self::scope(context)?);
        Ok(PersonalizationConfigurationRequest {
            operation_id,
            expected_revision: draft.source_revision,
            expected_digest: draft.source_digest,
            choices: draft.choices,
        })
    }

    /// Trusted native observers call on lock, logout, seat switch or compositor
    /// death; stale preview data must not survive an identity change.
    pub fn invalidate_session(&mut self, session: &SessionEpoch) -> usize {
        let before = self.active.len();
        self.active.retain(|_, value| &value.context.session != session);
        before - self.active.len()
    }

    /// The renderer/window owner calls this on window removal. The exact native
    /// context is required; a stale window identifier cannot cancel a successor.
    pub fn invalidate_window(&mut self, context: &PersonalizationPreviewContext) -> usize {
        let before = self.active.len();
        self.active.retain(|_, value| &value.context != context);
        before - self.active.len()
    }

    fn expire_at(&mut self, sampled: u64) {
        self.active.retain(|_, value| sampled < value.expires_at_unix_ms);
    }
}

fn now() -> Result<u64, String> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|_| "personalization preview clock unavailable")?;
    let time = u64::try_from(duration.as_millis())
        .map_err(|_| "personalization preview clock unavailable")?;
    if time == 0 || time > i64::MAX as u64 {
        return Err("personalization preview clock unavailable".into());
    }
    Ok(time)
}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_core::BootId;
    use linura_transaction::{
        PersonalizationPreferenceRecord, PersonalizationPreferenceStore,
        PersonalizationPreferenceUpdate, TransactionAuthorityKey,
        TransactionAuthorityVerifier, TransactionStoreError,
    };
    use std::fs::File;
    use std::io::Read;

    #[derive(Debug)]
    struct BlankStore(TransactionAuthorityVerifier);
    impl PersonalizationPreferenceStore for BlankStore {
        fn current(&self, _: &linura_core::PrincipalId)
            -> Result<Option<PersonalizationPreferenceRecord>, TransactionStoreError> {
            Ok(None)
        }
        fn request(&self, _: &linura_core::PrincipalId, _: &linura_core::RequestId)
            -> Result<Option<PersonalizationPreferenceRecord>, TransactionStoreError> {
            Ok(None)
        }
        fn apply(&mut self, update: &PersonalizationPreferenceUpdate)
            -> Result<PersonalizationPreferenceRecord, TransactionStoreError> {
            if !self.0.verify_personalization_preference(update) {
                return Err(TransactionStoreError::AuthorityRejected);
            }
            Err(TransactionStoreError::StateConflict)
        }
        fn integrity_check(&self) -> Result<(), TransactionStoreError> { Ok(()) }
    }

    fn state() -> (PersonalizationPreferencesControl, AuthenticatedPrincipal, PersonalizationPreviewContext) {
        let mut bytes = Vec::new();
        let n = File::open("/dev/urandom")
            .and_then(|file| file.take(32).read_to_end(&mut bytes))
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(n, 32);
        let (signer, verifier) = TransactionAuthorityKey::new(bytes)
            .unwrap_or_else(|error| unreachable!("{error}")).split();
        let control = PersonalizationPreferencesControl::new(
            Box::new(BlankStore(verifier)), signer,
        ).unwrap_or_else(|error| unreachable!("{error}"));
        let principal = AuthenticatedPrincipal::new("unix:uid:1000")
            .unwrap_or_else(|error| unreachable!("{error}"));
        let epoch = SessionEpoch::new(
            BootId::new("abcd1234-1234-4567-89ab-0123456789ab")
                .unwrap_or_else(|error| unreachable!("{error}")),
            1000, "c2", 42,
        ).unwrap_or_else(|error| unreachable!("{error}"));
        let context = PersonalizationPreviewContext {
            session: epoch, seat: "seat0".into(), window: "win-1".into(),
            window_generation: 10, compositor_generation: 25,
        };
        (control, principal, context)
    }

    #[test]
    fn preview_is_ephemeral_generation_and_window_bound() {
        let (preferences, principal, context) = state();
        let mut previews = PersonalizationPreviewControl::new();
        let first = previews.begin_at(
            &preferences, &principal, context.clone(),
            PersonalizationChoices::default(), 1000,
        ).unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(first.generation, 1);
        assert!(previews.begin_at(
            &preferences, &principal, context.clone(),
            PersonalizationChoices::default(), 1001,
        ).is_err());
        let mut replaced = context.clone();
        replaced.window_generation = 11;
        assert!(previews.inspect_at(&principal, &replaced, 1, 1002).is_err());
        assert!(previews.inspect_at(&principal, &context, 1, 31000).is_err());
        assert_eq!(previews.invalidate_session(&context.session), 0);
    }

    #[test]
    fn cancel_logout_and_draft_only_apply_are_fail_closed() {
        let (preferences, principal, context) = state();
        let mut previews = PersonalizationPreviewControl::new();
        let first = previews.begin_at(
            &preferences, &principal, context.clone(),
            PersonalizationChoices::default(), 1000,
        ).unwrap_or_else(|error| unreachable!("{error}"));
        assert!(previews.cancel(&principal, &context, first.generation + 1).is_err());
        assert!(previews.cancel(&principal, &context, first.generation).is_ok());
        assert!(previews.inspect_at(&principal, &context, first.generation, 1100).is_err());
        let again = previews.begin_at(
            &preferences, &principal, context.clone(),
            PersonalizationChoices::default(), 2000,
        ).unwrap_or_else(|error| unreachable!("{error}"));
        let owner_only = previews.take_apply_request_at(
            &preferences, &principal, &context, again.generation,
            "preview-commit".into(), 2500,
        ).unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(owner_only.expected_revision, 0);
        assert!(previews.inspect_at(&principal, &context, again.generation, 2500).is_err());
        let third = previews.begin_at(
            &preferences, &principal, context.clone(),
            PersonalizationChoices::default(), 3000,
        ).unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(previews.invalidate_session(&context.session), 1);
        assert!(previews.inspect_at(&principal, &context, third.generation, 3001).is_err());
    }
}
