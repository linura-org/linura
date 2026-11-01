//! S22-4: clipboard selection identity/MIME metadata guards.
//!
//! These checks cannot authorize clipboard reading or writing: no Wayland
//! data-control handle is created here and no secret bytes are returned.

use super::bounded_native_id;

const MAX_OFFER_AGE_MS: u64 = 500;
const MAX_TEXT_OFFER_BYTES: u64 = 8 * 1024 * 1024;
const MAX_PNG_OFFER_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClipboardSelectionSnapshot {
    pub boot_id: String,
    pub uid: u32,
    pub session_id: String,
    pub seat_id: String,
    pub source_owner_id: String,
    pub selection_generation: u64,
    pub offer_generation: u64,
    pub source_is_protected_or_unknown: bool,
    pub observed_monotonic_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MimeClass {
    Utf8PlainText,
    PngImage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClipboardScopeError {
    MissingOrInvalidIdentity,
    UnknownOrProtectedSource,
    ExpiredOffer,
    OfferOrSeatChanged,
    UnsupportedMime,
    ExcessivePayload,
}

/// Reports only native metadata consistency, **not** content authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClipboardMetadataConsistent {
    pub mime: MimeClass,
    pub maximum_payload_bytes: u64,
}

fn allowed_mime(value: &str) -> Result<(MimeClass, u64), ClipboardScopeError> {
    match value {
        "text/plain;charset=utf-8" => Ok((MimeClass::Utf8PlainText, MAX_TEXT_OFFER_BYTES)),
        "image/png" => Ok((MimeClass::PngImage, MAX_PNG_OFFER_BYTES)),
        _ => Err(ClipboardScopeError::UnsupportedMime),
    }
}

fn snapshot_is_current(
    snapshot: &ClipboardSelectionSnapshot,
    now_monotonic_ms: u64,
) -> Result<(), ClipboardScopeError> {
    if snapshot.uid == 0
        || snapshot.boot_id.is_empty()
        || snapshot.boot_id.len() > 64
        || !bounded_native_id(&snapshot.session_id)
        || !bounded_native_id(&snapshot.seat_id)
        || !bounded_native_id(&snapshot.source_owner_id)
        || snapshot.selection_generation == 0
        || snapshot.offer_generation == 0
    {
        return Err(ClipboardScopeError::MissingOrInvalidIdentity);
    }
    if snapshot.source_is_protected_or_unknown {
        return Err(ClipboardScopeError::UnknownOrProtectedSource);
    }
    if now_monotonic_ms < snapshot.observed_monotonic_ms
        || now_monotonic_ms - snapshot.observed_monotonic_ms > MAX_OFFER_AGE_MS
    {
        return Err(ClipboardScopeError::ExpiredOffer);
    }
    Ok(())
}

/// Reject stale, changed, cross-seat and oversized offers before any native
/// data-transfer adapter is considered. Caller must still obtain purpose-
/// specific authenticated consent and independent native source exclusion.
pub fn validate_selection_metadata(
    before: &ClipboardSelectionSnapshot,
    after: &ClipboardSelectionSnapshot,
    now_monotonic_ms: u64,
    mime_type: &str,
    advertised_size: u64,
) -> Result<ClipboardMetadataConsistent, ClipboardScopeError> {
    snapshot_is_current(before, now_monotonic_ms)?;
    snapshot_is_current(after, now_monotonic_ms)?;
    if after.observed_monotonic_ms < before.observed_monotonic_ms
        || before.boot_id != after.boot_id
        || before.uid != after.uid
        || before.session_id != after.session_id
        || before.seat_id != after.seat_id
        || before.source_owner_id != after.source_owner_id
        || before.selection_generation != after.selection_generation
        || before.offer_generation != after.offer_generation
    {
        return Err(ClipboardScopeError::OfferOrSeatChanged);
    }
    let (mime, limit) = allowed_mime(mime_type)?;
    if advertised_size == 0 || advertised_size > limit {
        return Err(ClipboardScopeError::ExcessivePayload);
    }
    Ok(ClipboardMetadataConsistent {
        mime,
        maximum_payload_bytes: limit,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> ClipboardSelectionSnapshot {
        ClipboardSelectionSnapshot {
            boot_id: "11111111-2222-3333-4444-555555555555".into(),
            uid: 1000,
            session_id: "2".into(),
            seat_id: "seat0".into(),
            source_owner_id: "source:34".into(),
            selection_generation: 5,
            offer_generation: 9,
            source_is_protected_or_unknown: false,
            observed_monotonic_ms: 10_000,
        }
    }

    #[test]
    fn only_explicit_safe_mimes_and_bounded_metadata() {
        let s = snapshot();
        assert!(matches!(
            validate_selection_metadata(&s, &s, 10_000, "image/png", 1024),
            Ok(ClipboardMetadataConsistent {
                mime: MimeClass::PngImage,
                ..
            })
        ));
        for mime in ["text/html", "text/uri-list", "application/x-password", "TEXT"] {
            assert_eq!(
                validate_selection_metadata(&s, &s, 10_000, mime, 1024),
                Err(ClipboardScopeError::UnsupportedMime)
            );
        }
        assert_eq!(
            validate_selection_metadata(&s, &s, 10_000, "image/png", 30_000_000),
            Err(ClipboardScopeError::ExcessivePayload)
        );
    }

    #[test]
    fn protected_source_and_epoch_drift_deny() {
        let s = snapshot();
        let mut altered = s.clone();
        altered.source_is_protected_or_unknown = true;
        assert_eq!(
            validate_selection_metadata(&s, &altered, 10_000, "image/png", 100),
            Err(ClipboardScopeError::UnknownOrProtectedSource)
        );
        altered = s.clone();
        altered.seat_id = "seat1".into();
        assert_eq!(
            validate_selection_metadata(&s, &altered, 10_000, "image/png", 100),
            Err(ClipboardScopeError::OfferOrSeatChanged)
        );
        altered = s.clone();
        altered.offer_generation += 1;
        assert_eq!(
            validate_selection_metadata(&s, &altered, 10_000, "image/png", 100),
            Err(ClipboardScopeError::OfferOrSeatChanged)
        );
    }

    #[test]
    fn future_and_old_observations_are_not_authority() {
        let s = snapshot();
        assert_eq!(
            validate_selection_metadata(&s, &s, 10_501, "image/png", 100),
            Err(ClipboardScopeError::ExpiredOffer)
        );
        assert_eq!(
            validate_selection_metadata(&s, &s, 9_999, "image/png", 100),
            Err(ClipboardScopeError::ExpiredOffer)
        );
    }
}
