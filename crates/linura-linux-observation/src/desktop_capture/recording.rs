//! S22-3: bounded metadata-only recording supervision decisions.
//!
//! This module cannot start, stop or export PipeWire streams. Its stop
//! directives are not native Stop calls, and no effect is registered.

use super::{CaptureSourceSnapshot, CaptureUnavailable};

const MAX_RECORDING_DURATION_MS: u64 = 5 * 60 * 1000;
const MAX_RECORDING_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_RECORDING_FRAMES: u64 = 18_000;
const MAX_STATUS_AGE_MS: u64 = 500;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordingScopeError {
    InvalidNativeScope,
    AudioConsentMissing,
    UnsupervisedNativeStream,
    ResourceLimitExceeded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordingStopDirective {
    /// Only metadata is consistent; native supervision is still required.
    ContinueOnlyWithNativeSupervisor,
    /// Caller must invoke exact-owned native stop and independently verify it.
    RevokeOwnedStream,
    /// Source cannot be identified: do not assume stopped or replay Start.
    InvestigateIndeterminate,
}

/// A non-authorizing read-only state binding, created only after a separate
/// native supervisor proves it owns the portal and PipeWire stop handles.
pub struct RecordingObservationLease {
    origin: CaptureSourceSnapshot,
    portal_session_id: String,
    stream_generation: u64,
    started_monotonic_ms: u64,
    deadline_monotonic_ms: u64,
    max_encoded_bytes: u64,
    max_frames: u64,
}

/// Construct scoped metadata only; this is not the native recording Start.
pub fn validate_recording_scope(
    origin: CaptureSourceSnapshot,
    portal_session_id: String,
    stream_generation: u64,
    started_monotonic_ms: u64,
    requested_duration_ms: u64,
    requested_max_encoded_bytes: u64,
    requested_max_frames: u64,
    include_audio: bool,
    native_stop_supervised: bool,
) -> Result<RecordingObservationLease, RecordingScopeError> {
    if include_audio {
        return Err(RecordingScopeError::AudioConsentMissing);
    }
    if !native_stop_supervised {
        return Err(RecordingScopeError::UnsupervisedNativeStream);
    }
    if requested_duration_ms == 0
        || requested_duration_ms > MAX_RECORDING_DURATION_MS
        || requested_max_encoded_bytes == 0
        || requested_max_encoded_bytes > MAX_RECORDING_BYTES
        || requested_max_frames == 0
        || requested_max_frames > MAX_RECORDING_FRAMES
    {
        return Err(RecordingScopeError::ResourceLimitExceeded);
    }
    if origin.uid == 0
        || origin.session_id.is_empty()
        || origin.protected_session_active
        || portal_session_id.is_empty()
        || portal_session_id.len() > 128
        || portal_session_id.chars().any(char::is_control)
        || stream_generation == 0
    {
        return Err(RecordingScopeError::InvalidNativeScope);
    }
    let deadline = started_monotonic_ms
        .checked_add(requested_duration_ms)
        .ok_or(RecordingScopeError::ResourceLimitExceeded)?;
    Ok(RecordingObservationLease {
        origin,
        portal_session_id,
        stream_generation,
        started_monotonic_ms,
        deadline_monotonic_ms: deadline,
        max_encoded_bytes: requested_max_encoded_bytes,
        max_frames: requested_max_frames,
    })
}

impl RecordingObservationLease {
    /// A policy decision only. Loss of identity means *indeterminate*, not
    /// confirmed stopped. Native supervisor must revoke this exact stream.
    pub fn stop_directive(
        &self,
        current: Option<&CaptureSourceSnapshot>,
        native_session_id: &str,
        native_stream_generation: u64,
        now_monotonic_ms: u64,
        encoded_bytes: u64,
        frames_observed: u64,
    ) -> RecordingStopDirective {
        let Some(current) = current else {
            return RecordingStopDirective::InvestigateIndeterminate;
        };
        if self.portal_session_id != native_session_id
            || self.stream_generation != native_stream_generation
            || current.uid != self.origin.uid
            || current.boot_id != self.origin.boot_id
            || current.session_id != self.origin.session_id
            || current.seat_id != self.origin.seat_id
            || current.compositor_id != self.origin.compositor_id
            || current.compositor_generation != self.origin.compositor_generation
            || current.security_owner_id != self.origin.security_owner_id
            || current.security_owner_generation != self.origin.security_owner_generation
            || current.portal_owner_unique_name != self.origin.portal_owner_unique_name
        {
            return RecordingStopDirective::InvestigateIndeterminate;
        }
        if current.protected_session_active
            || current.output_topology_generation != self.origin.output_topology_generation
            || current.capture_source_generation != self.origin.capture_source_generation
            || current.source != self.origin.source
            || now_monotonic_ms >= self.deadline_monotonic_ms
            || now_monotonic_ms < self.started_monotonic_ms
            || encoded_bytes >= self.max_encoded_bytes
            || frames_observed >= self.max_frames
        {
            return RecordingStopDirective::RevokeOwnedStream;
        }
        if current.observed_monotonic_ms > now_monotonic_ms
            || now_monotonic_ms - current.observed_monotonic_ms > MAX_STATUS_AGE_MS
        {
            return RecordingStopDirective::InvestigateIndeterminate;
        }
        RecordingStopDirective::ContinueOnlyWithNativeSupervisor
    }

    /// No method in this module equates Stop acknowledgement with verified
    /// native revocation. An independent stream observer is still required.
    pub fn native_stop_is_verified(&self) -> Result<(), CaptureUnavailable> {
        Err(CaptureUnavailable::CompositorExclusionNotProved)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::desktop_capture::CaptureSource;

    fn snapshot() -> CaptureSourceSnapshot {
        CaptureSourceSnapshot {
            boot_id: "11111111-2222-3333-4444-555555555555".into(),
            uid: 1000,
            session_id: "2".into(),
            seat_id: "seat0".into(),
            compositor_id: "hyprland:1234".into(),
            compositor_generation: 11,
            security_owner_id: "owner:4321".into(),
            security_owner_generation: 5,
            portal_owner_unique_name: ":1.42".into(),
            output_topology_generation: 8,
            capture_source_generation: 9,
            source: CaptureSource::Output {
                output_id: "DP-1".into(),
                width: 1280,
                height: 720,
                scale_milli: 1000,
                transform: 0,
            },
            protected_session_active: false,
            observed_monotonic_ms: 10_000,
        }
    }

    fn lease() -> RecordingObservationLease {
        validate_recording_scope(
            snapshot(),
            "portal:session:1".into(),
            4,
            10_000,
            5_000,
            100_000,
            300,
            false,
            true,
        )
        .unwrap()
    }

    #[test]
    fn missing_supervisor_and_implicit_audio_are_denied() {
        let args = snapshot();
        assert!(matches!(
            validate_recording_scope(
                args.clone(),
                "portal:1".into(),
                1,
                10_000,
                5_000,
                100_000,
                300,
                false,
                false
            ),
            Err(RecordingScopeError::UnsupervisedNativeStream)
        ));
        assert!(matches!(
            validate_recording_scope(
                args,
                "portal:1".into(),
                1,
                10_000,
                5_000,
                100_000,
                300,
                true,
                true
            ),
            Err(RecordingScopeError::AudioConsentMissing)
        ));
    }

    #[test]
    fn lock_deadline_and_topology_changes_require_stop() {
        let recording = lease();
        let mut s = snapshot();
        assert_eq!(
            recording.stop_directive(Some(&s), "portal:session:1", 4, 10_000, 0, 0),
            RecordingStopDirective::ContinueOnlyWithNativeSupervisor
        );
        s.protected_session_active = true;
        assert_eq!(
            recording.stop_directive(Some(&s), "portal:session:1", 4, 10_001, 0, 0),
            RecordingStopDirective::RevokeOwnedStream
        );
        s = snapshot();
        s.output_topology_generation += 1;
        assert_eq!(
            recording.stop_directive(Some(&s), "portal:session:1", 4, 10_001, 0, 0),
            RecordingStopDirective::RevokeOwnedStream
        );
        assert_eq!(
            recording.stop_directive(Some(&snapshot()), "portal:session:1", 4, 15_000, 0, 0),
            RecordingStopDirective::RevokeOwnedStream
        );
    }

    #[test]
    fn wrong_stream_or_unknown_proof_is_indeterminate() {
        let recording = lease();
        assert_eq!(
            recording.stop_directive(Some(&snapshot()), "portal:session:2", 4, 10_000, 0, 0),
            RecordingStopDirective::InvestigateIndeterminate
        );
        assert_eq!(
            recording.stop_directive(None, "portal:session:1", 4, 10_000, 0, 0),
            RecordingStopDirective::InvestigateIndeterminate
        );
        assert!(recording.native_stop_is_verified().is_err());
    }
}
