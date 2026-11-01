//! S22-1: fail-closed, read-only lineage validation for protected desktop capture.
//!
//! This module deliberately does not connect to a screenshot service, inspect
//! pixels, mint consent, or register any runtime effect. A pair of matching
//! snapshots does NOT prove compositor-enforced secure-frame exclusion.
//! Native trusted S17/S21/portal observations and an independently enforced
//! source-side exclusion mechanism must be integrated before capture is offered.

pub mod clipboard;
pub mod history;
pub mod recording;
pub mod screenshot;

const MAX_ID_BYTES: usize = 128;
const MAX_CAPTURE_SOURCE_PIXELS: u64 = 132_710_400;
const MAX_OBSERVATION_AGE_MS: u64 = 500;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaptureSource {
    Output {
        output_id: String,
        width: u32,
        height: u32,
        scale_milli: u32,
        transform: u8,
    },
    Window {
        window_id: String,
        output_id: String,
        window_generation: u64,
    },
    Region {
        output_id: String,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        output_width: u32,
        output_height: u32,
    },
}

/// Native-source *claims* made available to a future trusted observation
/// adapter, not a user/model-constructible approval or capture permit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureSourceSnapshot {
    pub boot_id: String,
    pub uid: u32,
    pub session_id: String,
    pub seat_id: String,
    pub compositor_id: String,
    pub compositor_generation: u64,
    pub security_owner_id: String,
    pub security_owner_generation: u64,
    pub portal_owner_unique_name: String,
    pub output_topology_generation: u64,
    pub capture_source_generation: u64,
    pub source: CaptureSource,
    pub protected_session_active: bool,
    pub observed_monotonic_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureUnavailable {
    InvalidNativeIdentity,
    InvalidNativeGeometry,
    StaleOrFutureObservation,
    ProtectedSession,
    SourceOrSecurityEpochChanged,
    CompositorExclusionNotProved,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapturePreflight {
    Unavailable(CaptureUnavailable),
}

fn bounded_native_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_BYTES
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'))
}

fn boot_id_is_valid(value: &str) -> bool {
    let mut count = 0_u8;
    let mut nonzero = false;
    for (index, part) in value.split('-').enumerate() {
        let expected = match index {
            0 => 8,
            1..=3 => 4,
            4 => 12,
            _ => return false,
        };
        if part.len() != expected {
            return false;
        }
        for byte in part.bytes() {
            if !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase() {
                return false;
            }
            nonzero |= byte != b'0';
        }
        count += 1;
    }
    count == 5 && nonzero
}

fn unique_bus_owner_is_valid(value: &str) -> bool {
    let Some(rest) = value.strip_prefix(':') else {
        return false;
    };
    let Some((left, right)) = rest.split_once('.') else {
        return false;
    };
    !left.is_empty()
        && !right.is_empty()
        && right.len() <= 18
        && left.len() <= 18
        && left.bytes().all(|b| b.is_ascii_digit())
        && right.bytes().all(|b| b.is_ascii_digit())
}

fn geometry_is_bounded(width: u32, height: u32) -> bool {
    width > 0 && height > 0 && u64::from(width) * u64::from(height) <= MAX_CAPTURE_SOURCE_PIXELS
}

fn validate_source(source: &CaptureSource) -> Result<(), CaptureUnavailable> {
    match source {
        CaptureSource::Output {
            output_id,
            width,
            height,
            scale_milli,
            transform,
        } => {
            if !bounded_native_id(output_id) {
                return Err(CaptureUnavailable::InvalidNativeIdentity);
            }
            if !geometry_is_bounded(*width, *height)
                || !(500..=4000).contains(scale_milli)
                || *transform > 7
            {
                return Err(CaptureUnavailable::InvalidNativeGeometry);
            }
        }
        CaptureSource::Window {
            window_id,
            output_id,
            window_generation,
        } => {
            if !bounded_native_id(window_id)
                || !bounded_native_id(output_id)
                || *window_generation == 0
            {
                return Err(CaptureUnavailable::InvalidNativeIdentity);
            }
        }
        CaptureSource::Region {
            output_id,
            x,
            y,
            width,
            height,
            output_width,
            output_height,
        } => {
            if !bounded_native_id(output_id) {
                return Err(CaptureUnavailable::InvalidNativeIdentity);
            }
            if !geometry_is_bounded(*width, *height)
                || !geometry_is_bounded(*output_width, *output_height)
                || x.checked_add(*width).is_none_or(|end| end > *output_width)
                || y.checked_add(*height)
                    .is_none_or(|end| end > *output_height)
            {
                return Err(CaptureUnavailable::InvalidNativeGeometry);
            }
        }
    }
    Ok(())
}

fn validate_snapshot(
    snapshot: &CaptureSourceSnapshot,
    now_monotonic_ms: u64,
) -> Result<(), CaptureUnavailable> {
    if !boot_id_is_valid(&snapshot.boot_id)
        || snapshot.uid == 0
        || !bounded_native_id(&snapshot.session_id)
        || !bounded_native_id(&snapshot.seat_id)
        || !bounded_native_id(&snapshot.compositor_id)
        || !bounded_native_id(&snapshot.security_owner_id)
        || snapshot.compositor_generation == 0
        || snapshot.security_owner_generation == 0
        || snapshot.output_topology_generation == 0
        || snapshot.capture_source_generation == 0
        || !unique_bus_owner_is_valid(&snapshot.portal_owner_unique_name)
    {
        return Err(CaptureUnavailable::InvalidNativeIdentity);
    }
    validate_source(&snapshot.source)?;
    if now_monotonic_ms < snapshot.observed_monotonic_ms
        || now_monotonic_ms - snapshot.observed_monotonic_ms > MAX_OBSERVATION_AGE_MS
    {
        return Err(CaptureUnavailable::StaleOrFutureObservation);
    }
    if snapshot.protected_session_active {
        return Err(CaptureUnavailable::ProtectedSession);
    }
    Ok(())
}

/// Validate *only* read-only continuity of native snapshot metadata. Native
/// producers must authenticate these facts; callers may never interpret Ok(())
/// as a capture permission, authorization, protected-frame proof, or grant.
pub fn validate_source_continuity(
    before: &CaptureSourceSnapshot,
    after: &CaptureSourceSnapshot,
    now_monotonic_ms: u64,
) -> Result<(), CaptureUnavailable> {
    validate_snapshot(before, now_monotonic_ms)?;
    validate_snapshot(after, now_monotonic_ms)?;
    if after.observed_monotonic_ms < before.observed_monotonic_ms
        || before.boot_id != after.boot_id
        || before.uid != after.uid
        || before.session_id != after.session_id
        || before.seat_id != after.seat_id
        || before.compositor_id != after.compositor_id
        || before.compositor_generation != after.compositor_generation
        || before.security_owner_id != after.security_owner_id
        || before.security_owner_generation != after.security_owner_generation
        || before.portal_owner_unique_name != after.portal_owner_unique_name
        || before.output_topology_generation != after.output_topology_generation
        || before.capture_source_generation != after.capture_source_generation
        || before.source != after.source
    {
        return Err(CaptureUnavailable::SourceOrSecurityEpochChanged);
    }
    Ok(())
}

/// Explicitly disabled even for perfectly matching snapshots. A future
/// implementation needs independently attested compositor-source exclusion
/// before it can add any separately authorized effect operation.
pub fn protected_capture_preflight(
    before: &CaptureSourceSnapshot,
    after: &CaptureSourceSnapshot,
    now_monotonic_ms: u64,
) -> CapturePreflight {
    match validate_source_continuity(before, after, now_monotonic_ms) {
        Ok(()) => CapturePreflight::Unavailable(CaptureUnavailable::CompositorExclusionNotProved),
        Err(reason) => CapturePreflight::Unavailable(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> CaptureSourceSnapshot {
        CaptureSourceSnapshot {
            boot_id: "11111111-2222-3333-4444-555555555555".into(),
            uid: 1000,
            session_id: "2".into(),
            seat_id: "seat0".into(),
            compositor_id: "hyprland:1234".into(),
            compositor_generation: 11,
            security_owner_id: "native-owner:4321".into(),
            security_owner_generation: 5,
            portal_owner_unique_name: ":1.112".into(),
            output_topology_generation: 8,
            capture_source_generation: 12,
            source: CaptureSource::Output {
                output_id: "DP-1".into(),
                width: 3840,
                height: 2160,
                scale_milli: 1500,
                transform: 0,
            },
            protected_session_active: false,
            observed_monotonic_ms: 10_000,
        }
    }

    #[test]
    fn matching_lineage_is_not_a_capture_grant() {
        let s = snapshot();
        assert_eq!(validate_source_continuity(&s, &s, 10_000), Ok(()));
        assert_eq!(
            protected_capture_preflight(&s, &s, 10_000),
            CapturePreflight::Unavailable(CaptureUnavailable::CompositorExclusionNotProved)
        );
    }

    #[test]
    fn changed_security_owner_or_lock_denies() {
        let original = snapshot();
        let mut changed = original.clone();
        changed.security_owner_generation += 1;
        assert_eq!(
            validate_source_continuity(&original, &changed, 10_000),
            Err(CaptureUnavailable::SourceOrSecurityEpochChanged)
        );
        changed = original.clone();
        changed.protected_session_active = true;
        assert_eq!(
            protected_capture_preflight(&original, &changed, 10_000),
            CapturePreflight::Unavailable(CaptureUnavailable::ProtectedSession)
        );
    }

    #[test]
    fn compositor_portal_output_and_source_substitution_deny() {
        let original = snapshot();
        for index in 0..6 {
            let mut changed = original.clone();
            match index {
                0 => changed.compositor_generation += 1,
                1 => changed.portal_owner_unique_name = ":1.113".into(),
                2 => changed.output_topology_generation += 1,
                3 => changed.capture_source_generation += 1,
                4 => changed.uid += 1,
                _ => changed.session_id = "3".into(),
            };
            assert_eq!(
                validate_source_continuity(&original, &changed, 10_000),
                Err(CaptureUnavailable::SourceOrSecurityEpochChanged)
            );
        }
    }

    #[test]
    fn invalid_bus_owner_or_boot_id_deny() {
        let mut s = snapshot();
        s.portal_owner_unique_name = "org.freedesktop.portal.Desktop".into();
        assert_eq!(
            protected_capture_preflight(&s, &s, 10_000),
            CapturePreflight::Unavailable(CaptureUnavailable::InvalidNativeIdentity)
        );
        s = snapshot();
        s.boot_id = "00000000-0000-0000-0000-000000000000".into();
        assert_eq!(
            validate_source_continuity(&s, &s, 10_000),
            Err(CaptureUnavailable::InvalidNativeIdentity)
        );
    }

    #[test]
    fn missing_or_stale_observation_denies() {
        let mut s = snapshot();
        assert_eq!(
            validate_source_continuity(&s, &s, 10_501),
            Err(CaptureUnavailable::StaleOrFutureObservation)
        );
        assert_eq!(
            validate_source_continuity(&s, &s, 9_999),
            Err(CaptureUnavailable::StaleOrFutureObservation)
        );
        s.compositor_generation = 0;
        assert_eq!(
            validate_source_continuity(&s, &s, 10_000),
            Err(CaptureUnavailable::InvalidNativeIdentity)
        );
    }

    #[test]
    fn unsafe_region_and_oversized_output_deny() {
        let mut s = snapshot();
        s.source = CaptureSource::Region {
            output_id: "DP-1".into(),
            x: 3800,
            y: 0,
            width: 300,
            height: 100,
            output_width: 3840,
            output_height: 2160,
        };
        assert_eq!(
            validate_source_continuity(&s, &s, 10_000),
            Err(CaptureUnavailable::InvalidNativeGeometry)
        );
        s.source = CaptureSource::Output {
            output_id: "DP-1".into(),
            width: 65535,
            height: 65535,
            scale_milli: 1000,
            transform: 0,
        };
        assert_eq!(
            protected_capture_preflight(&s, &s, 10_000),
            CapturePreflight::Unavailable(CaptureUnavailable::InvalidNativeGeometry)
        );
    }

    #[test]
    fn identity_rejection_cannot_be_bypassed_with_matching_values() {
        let mut s = snapshot();
        s.seat_id = "seat0\nforged".into();
        assert_eq!(
            protected_capture_preflight(&s, &s, 10_000),
            CapturePreflight::Unavailable(CaptureUnavailable::InvalidNativeIdentity)
        );
    }
}
