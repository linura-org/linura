//! Read-after-effect consistency review for S21-3 physical backlight.
//!
//! No authority, mutation, approval or recovery privilege is supplied here.
//! The caller remains responsible for durable dispatch reservation and an
//! independently attested, supported physical-panel minimum. A matching
//! requested value or D-Bus reply is not proof of actual brightness.

use super::candidate::{BacklightCandidate, observe_backlight_candidate};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BacklightVerificationError {
    InvalidQualifiedMinimum,
    UnsafeTarget,
    UnsafeOriginalLevel,
    NativeObservationUnavailable,
    SourceChanged,
    BoundsChanged,
    PowerStateChanged,
    InconclusiveRequestedValue,
    ActualValueMismatch,
    ObservationTimeRegressed,
    ConcurrentNativeChange,
    NoEffectToReconcile,
}

/// Read-only consistency classification after a lost or uncertain native
/// dispatch response. None of these states permits a retry, grants authority,
/// or establishes the cause of a brightness change. Only Control may decide
/// transaction recovery using its independently durable dispatch ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BacklightUncertainOutcome {
    DesiredObserved,
    OriginalObserved,
    Indeterminate,
}

/// Reobserve the exact native source immediately before a future, separately
/// authorized durable dispatch. This is only an observational precondition:
/// it neither grants a mutation nor attests physical panel ownership, a safe
/// visibility floor or a device-generation proof.
pub fn observe_native_precondition(
    original: &BacklightCandidate,
    target: u32,
    independently_qualified_minimum: u32,
) -> Result<BacklightCandidate, BacklightVerificationError> {
    let observed = observe_backlight_candidate(&original.session.session_id, original.session.uid)
        .map_err(|_| BacklightVerificationError::NativeObservationUnavailable)?;
    review_native_precondition(original, &observed, target, independently_qualified_minimum)?;
    Ok(observed)
}

/// Reject a competing brightness writer, an unsettled device, stale samples,
/// ambiguous bounds or any changed logind/kernel lineage before dispatch.
/// This pure review never accepts the target or minimum as authoritative.
pub fn review_native_precondition(
    original: &BacklightCandidate,
    observed: &BacklightCandidate,
    target: u32,
    independently_qualified_minimum: u32,
) -> Result<(), BacklightVerificationError> {
    let max = original.kernel.maximum;
    if independently_qualified_minimum == 0 || independently_qualified_minimum > max {
        return Err(BacklightVerificationError::InvalidQualifiedMinimum);
    }
    if target < independently_qualified_minimum || target > max {
        return Err(BacklightVerificationError::UnsafeTarget);
    }
    // An already sub-minimum or unsettled native baseline is not a safe
    // reference for a managed effect. The separately qualified visibility
    // floor must hold *before* a privileged brightness attempt, not merely
    // for the proposed destination. Independent physical recovery is required.
    if original.kernel.requested_brightness < independently_qualified_minimum
        || original.kernel.actual_brightness < independently_qualified_minimum
    {
        return Err(BacklightVerificationError::UnsafeOriginalLevel);
    }
    if original.session.boot_id != observed.session.boot_id
        || original.session.logind_owner != observed.session.logind_owner
        || original.session.session_id != observed.session.session_id
        || original.session.created_monotonic_us != observed.session.created_monotonic_us
        || original.session.seat_id != observed.session.seat_id
        || original.session.uid != observed.session.uid
        || original.kernel.identity != observed.kernel.identity
        || original.kernel.kind != observed.kernel.kind
    {
        return Err(BacklightVerificationError::SourceChanged);
    }
    if observed.session.observed_at_unix_ms <= original.session.observed_at_unix_ms {
        return Err(BacklightVerificationError::ObservationTimeRegressed);
    }
    if original.kernel.maximum != observed.kernel.maximum {
        return Err(BacklightVerificationError::BoundsChanged);
    }
    if original.kernel.power != 0 || observed.kernel.power != 0 {
        return Err(BacklightVerificationError::PowerStateChanged);
    }
    if original.kernel.requested_brightness != original.kernel.actual_brightness
        || observed.kernel.requested_brightness != observed.kernel.actual_brightness
    {
        return Err(BacklightVerificationError::InconclusiveRequestedValue);
    }
    if original.kernel.requested_brightness != observed.kernel.requested_brightness
        || original.kernel.actual_brightness != observed.kernel.actual_brightness
    {
        return Err(BacklightVerificationError::ConcurrentNativeChange);
    }
    Ok(())
}

/// Issue a *new* native kernel and logind observation for a previously
/// dispatched effect. The caller must prove this method was invoked strictly
/// after a durable dispatch attempt and preserve indeterminate state when any
/// independent native read fails.
///
/// The supplied minimum is only validated arithmetically; no caller may
/// treat this method as proof that the hardware minimum was calibrated.
pub fn observe_native_postcondition(
    original: &BacklightCandidate,
    target: u32,
    independently_qualified_minimum: u32,
) -> Result<BacklightCandidate, BacklightVerificationError> {
    let observed = observe_backlight_candidate(&original.session.session_id, original.session.uid)
        .map_err(|_| BacklightVerificationError::NativeObservationUnavailable)?;
    review_native_postcondition(original, &observed, target, independently_qualified_minimum)?;
    Ok(observed)
}

/// Pure postcondition check for testability. Neither input is a credential,
/// and this function must never be used with a cached executor/slider sample.
pub fn review_native_postcondition(
    original: &BacklightCandidate,
    observed: &BacklightCandidate,
    target: u32,
    independently_qualified_minimum: u32,
) -> Result<(), BacklightVerificationError> {
    let max = original.kernel.maximum;
    if independently_qualified_minimum == 0 || independently_qualified_minimum > max {
        return Err(BacklightVerificationError::InvalidQualifiedMinimum);
    }
    if target < independently_qualified_minimum || target > max {
        return Err(BacklightVerificationError::UnsafeTarget);
    }
    // An already sub-minimum or unsettled native baseline is not a safe
    // reference for a managed effect. The separately qualified visibility
    // floor must hold *before* a privileged brightness attempt, not merely
    // for the proposed destination. Independent physical recovery is required.
    if original.kernel.requested_brightness < independently_qualified_minimum
        || original.kernel.actual_brightness < independently_qualified_minimum
    {
        return Err(BacklightVerificationError::UnsafeOriginalLevel);
    }

    if original.kernel.requested_brightness != original.kernel.actual_brightness {
        return Err(BacklightVerificationError::InconclusiveRequestedValue);
    }

    // Never infer hardware success across reused kernel names, logind
    // owner changes, changed active seat/session generations or device
    // generations. A sysfs path + inode remain *correlations* rather than
    // a complete physical hotplug-generation attestation.
    if original.session.boot_id != observed.session.boot_id
        || original.session.logind_owner != observed.session.logind_owner
        || original.session.session_id != observed.session.session_id
        || original.session.created_monotonic_us != observed.session.created_monotonic_us
        || original.session.seat_id != observed.session.seat_id
        || original.session.uid != observed.session.uid
        || original.kernel.identity != observed.kernel.identity
        || original.kernel.kind != observed.kernel.kind
    {
        return Err(BacklightVerificationError::SourceChanged);
    }
    if observed.session.observed_at_unix_ms <= original.session.observed_at_unix_ms {
        return Err(BacklightVerificationError::ObservationTimeRegressed);
    }
    if original.kernel.maximum != observed.kernel.maximum {
        return Err(BacklightVerificationError::BoundsChanged);
    }
    if original.kernel.power != 0 || observed.kernel.power != 0 {
        return Err(BacklightVerificationError::PowerStateChanged);
    }
    if observed.kernel.requested_brightness != target {
        return Err(BacklightVerificationError::InconclusiveRequestedValue);
    }
    if observed.kernel.actual_brightness != target {
        return Err(BacklightVerificationError::ActualValueMismatch);
    }
    Ok(())
}

/// Independently reobserve native state following a lost, timed-out, or
/// uncertain dispatch reply. This is an observational recovery input only.
/// Absence, source change, or a failed native read never permits redispatch.
pub fn observe_native_uncertain_outcome(
    original: &BacklightCandidate,
    target: u32,
    independently_qualified_minimum: u32,
) -> Result<BacklightUncertainOutcome, BacklightVerificationError> {
    let observed = observe_backlight_candidate(&original.session.session_id, original.session.uid)
        .map_err(|_| BacklightVerificationError::NativeObservationUnavailable)?;
    review_native_uncertain_outcome(original, &observed, target, independently_qualified_minimum)
}

/// Classify the new native sample without guessing that a request was applied,
/// rolled back, or never dispatched. The caller must already own a durable
/// one-shot attempt and independent evidence of physical device qualification.
/// Returning OriginalObserved does not license a second SetBrightness call.
pub fn review_native_uncertain_outcome(
    original: &BacklightCandidate,
    observed: &BacklightCandidate,
    target: u32,
    independently_qualified_minimum: u32,
) -> Result<BacklightUncertainOutcome, BacklightVerificationError> {
    if original.kernel.requested_brightness != original.kernel.actual_brightness {
        return Err(BacklightVerificationError::InconclusiveRequestedValue);
    }
    if target == original.kernel.actual_brightness {
        return Err(BacklightVerificationError::NoEffectToReconcile);
    }
    match review_native_postcondition(original, observed, target, independently_qualified_minimum) {
        Ok(()) => Ok(BacklightUncertainOutcome::DesiredObserved),
        Err(BacklightVerificationError::InconclusiveRequestedValue)
        | Err(BacklightVerificationError::ActualValueMismatch) => {
            if original.kernel.requested_brightness == observed.kernel.requested_brightness
                && original.kernel.actual_brightness == observed.kernel.actual_brightness
                && original.kernel.actual_brightness >= independently_qualified_minimum
            {
                Ok(BacklightUncertainOutcome::OriginalObserved)
            } else {
                Ok(BacklightUncertainOutcome::Indeterminate)
            }
        }
        Err(error) => Err(error),
    }
}

/// Purely inspect whether a failed or uncertain attempt has independently
/// restored the original observed native level. A successful result is
/// *only* an observed equality, not permission for a blind compensation
/// write or proof that every physical screen remained usable. The original
/// hardware-qualified visibility minimum is mandatory; never invent one.
pub fn review_native_restoration(
    original: &BacklightCandidate,
    observed: &BacklightCandidate,
    independently_qualified_minimum: u32,
) -> Result<(), BacklightVerificationError> {
    if original.kernel.requested_brightness != original.kernel.actual_brightness {
        return Err(BacklightVerificationError::InconclusiveRequestedValue);
    }
    review_native_postcondition(
        original,
        observed,
        original.kernel.requested_brightness,
        independently_qualified_minimum,
    )
}

#[cfg(test)]
mod tests {
    use super::super::kernel::{
        KernelBacklightIdentity, KernelBacklightKind, KernelBacklightSnapshot,
    };
    use super::*;
    use crate::logind::NativeBacklightSession;
    use std::path::PathBuf;

    fn fixture() -> BacklightCandidate {
        BacklightCandidate {
            session: NativeBacklightSession {
                boot_id: "b8691e5f-1111-2222-3333-444444444444".into(),
                logind_owner: ":1.42".into(),
                session_id: "c2".into(),
                created_monotonic_us: 123,
                seat_id: "seat0".into(),
                uid: 1000,
                observed_at_unix_ms: 20_000,
            },
            kernel: KernelBacklightSnapshot {
                identity: KernelBacklightIdentity {
                    name: "intel_backlight".into(),
                    device_path: PathBuf::from(
                        "/sys/devices/pci0000:00/0000:00:02.0/backlight/intel_backlight",
                    ),
                    inode: 321,
                    mount_device: 17,
                },
                kind: KernelBacklightKind::Raw,
                maximum: 250,
                requested_brightness: 125,
                actual_brightness: 125,
                power: 0,
            },
        }
    }

    fn after(target: u32) -> BacklightCandidate {
        let mut candidate = fixture();
        candidate.session.observed_at_unix_ms += 1;
        candidate.kernel.requested_brightness = target;
        candidate.kernel.actual_brightness = target;
        candidate
    }

    #[test]
    fn matching_new_native_requested_and_actual_values_pass_as_consistency_only() {
        assert_eq!(
            review_native_postcondition(&fixture(), &after(190), 190, 20),
            Ok(())
        );
    }

    #[test]
    fn source_replacement_never_passes_as_old_effect() {
        let original = fixture();
        for case in 0..9 {
            let mut observed = after(190);
            match case {
                0 => observed.session.boot_id = "replacement".into(),
                1 => observed.session.logind_owner = ":1.99".into(),
                2 => observed.session.session_id = "c3".into(),
                3 => observed.session.created_monotonic_us += 1,
                4 => observed.session.seat_id = "seat1".into(),
                5 => observed.session.uid += 1,
                6 => observed.kernel.identity.inode += 1,
                7 => observed.kernel.identity.device_path = PathBuf::from("/sys/devices/other"),
                8 => observed.kernel.kind = KernelBacklightKind::Platform,
                _ => unreachable!(),
            }
            assert_eq!(
                review_native_postcondition(&original, &observed, 190, 20),
                Err(BacklightVerificationError::SourceChanged)
            );
        }
    }

    #[test]
    fn no_blackout_missing_minimum_and_out_of_bounds_are_denied() {
        let original = fixture();
        for minimum in [0, 251, u32::MAX] {
            assert_eq!(
                review_native_postcondition(&original, &after(190), 190, minimum),
                Err(BacklightVerificationError::InvalidQualifiedMinimum)
            );
        }
        for target in [0, 19, 251, u32::MAX] {
            assert_eq!(
                review_native_postcondition(&original, &after(190), target, 20),
                Err(BacklightVerificationError::UnsafeTarget)
            );
        }
    }

    #[test]
    fn requested_does_not_prove_measured_brightness() {
        let mut candidate = after(190);
        candidate.kernel.requested_brightness = 120;
        assert_eq!(
            review_native_postcondition(&fixture(), &candidate, 190, 20),
            Err(BacklightVerificationError::InconclusiveRequestedValue)
        );
        candidate.kernel.requested_brightness = 190;
        candidate.kernel.actual_brightness = 120;
        assert_eq!(
            review_native_postcondition(&fixture(), &candidate, 190, 20),
            Err(BacklightVerificationError::ActualValueMismatch)
        );
    }

    #[test]
    fn changed_bounds_power_and_nonmonotonic_source_time_fail_closed() {
        let mut observed = after(190);
        observed.kernel.maximum += 1;
        assert_eq!(
            review_native_postcondition(&fixture(), &observed, 190, 20),
            Err(BacklightVerificationError::BoundsChanged)
        );
        observed = after(190);
        observed.kernel.power = 4;
        assert_eq!(
            review_native_postcondition(&fixture(), &observed, 190, 20),
            Err(BacklightVerificationError::PowerStateChanged)
        );
        observed = after(190);
        observed.session.observed_at_unix_ms -= 2;
        assert_eq!(
            review_native_postcondition(&fixture(), &observed, 190, 20),
            Err(BacklightVerificationError::ObservationTimeRegressed)
        );
        observed = after(190);
        observed.session.observed_at_unix_ms -= 1;
        assert_eq!(
            review_native_postcondition(&fixture(), &observed, 190, 20),
            Err(BacklightVerificationError::ObservationTimeRegressed)
        );
    }

    #[test]
    fn fresh_native_precondition_rejects_competing_effects_and_unsettled_hardware() {
        let original = fixture();
        assert_eq!(
            review_native_precondition(&original, &after(125), 190, 20),
            Ok(())
        );
        assert_eq!(
            review_native_precondition(&original, &after(130), 190, 20),
            Err(BacklightVerificationError::ConcurrentNativeChange)
        );
        let mut unsettled = after(125);
        unsettled.kernel.actual_brightness = 100;
        assert_eq!(
            review_native_precondition(&original, &unsettled, 190, 20),
            Err(BacklightVerificationError::InconclusiveRequestedValue)
        );
        let mut changed_source = after(125);
        changed_source.session.logind_owner = ":1.99".into();
        assert_eq!(
            review_native_precondition(&original, &changed_source, 190, 20),
            Err(BacklightVerificationError::SourceChanged)
        );
        let mut same_time = after(125);
        same_time.session.observed_at_unix_ms -= 1;
        assert_eq!(
            review_native_precondition(&original, &same_time, 190, 20),
            Err(BacklightVerificationError::ObservationTimeRegressed)
        );
    }

    #[test]
    fn native_precondition_never_guesses_a_safe_minimum_or_allows_blackout() {
        assert_eq!(
            review_native_precondition(&fixture(), &after(125), 0, 20),
            Err(BacklightVerificationError::UnsafeTarget)
        );
        assert_eq!(
            review_native_precondition(&fixture(), &after(125), 190, 0),
            Err(BacklightVerificationError::InvalidQualifiedMinimum)
        );
        assert_eq!(
            review_native_precondition(&fixture(), &after(125), 19, 20),
            Err(BacklightVerificationError::UnsafeTarget)
        );
        let mut original = fixture();
        original.kernel.requested_brightness = 0;
        original.kernel.actual_brightness = 0;
        let mut dark = original.clone();
        dark.session.observed_at_unix_ms += 1;
        assert_eq!(
            review_native_precondition(&original, &dark, 20, 20),
            Err(BacklightVerificationError::UnsafeOriginalLevel)
        );
    }

    #[test]
    fn already_unusable_physical_baseline_never_becomes_a_managed_dispatch() {
        let original = fixture();
        for native in [0, 1, 19] {
            let mut dark = original.clone();
            dark.kernel.requested_brightness = native;
            dark.kernel.actual_brightness = native;
            let mut fresh = dark.clone();
            fresh.session.observed_at_unix_ms += 1;
            assert_eq!(
                review_native_precondition(&dark, &fresh, 190, 20),
                Err(BacklightVerificationError::UnsafeOriginalLevel)
            );
            fresh.kernel.requested_brightness = 190;
            fresh.kernel.actual_brightness = 190;
            assert_eq!(
                review_native_postcondition(&dark, &fresh, 190, 20),
                Err(BacklightVerificationError::UnsafeOriginalLevel)
            );
            assert_eq!(
                review_native_uncertain_outcome(&dark, &fresh, 190, 20),
                Err(BacklightVerificationError::UnsafeOriginalLevel)
            );
            // Equality of an observed original value does not authorize an
            // automatic restoration or a retry when it is below the floor.
            fresh.kernel.requested_brightness = native;
            fresh.kernel.actual_brightness = native;
            assert_eq!(
                review_native_restoration(&dark, &fresh, 20),
                Err(BacklightVerificationError::UnsafeTarget)
            );
        }
    }

    #[test]
    fn indeterminate_dispatch_is_read_only_and_never_inferrable_from_reply() {
        let original = fixture();
        assert_eq!(
            review_native_uncertain_outcome(&original, &after(190), 190, 20),
            Ok(BacklightUncertainOutcome::DesiredObserved)
        );
        assert_eq!(
            review_native_uncertain_outcome(&original, &after(125), 190, 20),
            Ok(BacklightUncertainOutcome::OriginalObserved)
        );
        assert_eq!(
            review_native_uncertain_outcome(&original, &after(150), 190, 20),
            Ok(BacklightUncertainOutcome::Indeterminate)
        );
        let mut unsettled = after(190);
        unsettled.kernel.actual_brightness = 125;
        assert_eq!(
            review_native_uncertain_outcome(&original, &unsettled, 190, 20),
            Ok(BacklightUncertainOutcome::Indeterminate)
        );
    }

    #[test]
    fn uncertain_dispatch_cannot_suppress_identity_or_visibility_blockers() {
        let original = fixture();
        let mut changed = after(190);
        changed.session.logind_owner = ":1.98".into();
        assert_eq!(
            review_native_uncertain_outcome(&original, &changed, 190, 20),
            Err(BacklightVerificationError::SourceChanged)
        );
        changed = after(190);
        changed.kernel.maximum = 251;
        assert_eq!(
            review_native_uncertain_outcome(&original, &changed, 190, 20),
            Err(BacklightVerificationError::BoundsChanged)
        );
        changed = after(190);
        changed.session.observed_at_unix_ms -= 1;
        assert_eq!(
            review_native_uncertain_outcome(&original, &changed, 190, 20),
            Err(BacklightVerificationError::ObservationTimeRegressed)
        );
        assert_eq!(
            review_native_uncertain_outcome(&original, &after(190), 125, 20),
            Err(BacklightVerificationError::NoEffectToReconcile)
        );
        assert_eq!(
            review_native_uncertain_outcome(&original, &after(190), 190, 0),
            Err(BacklightVerificationError::InvalidQualifiedMinimum)
        );
        let mut unsettled_original = original.clone();
        unsettled_original.kernel.requested_brightness = 150;
        assert_eq!(
            review_native_uncertain_outcome(&unsettled_original, &after(150), 190, 20),
            Err(BacklightVerificationError::InconclusiveRequestedValue)
        );
    }

    #[test]
    fn restoration_cannot_infer_success_from_unsettled_original_or_display_reply() {
        let original = fixture();
        assert_eq!(
            review_native_restoration(&original, &after(125), 20),
            Ok(())
        );
        assert_eq!(
            review_native_restoration(&original, &after(100), 20),
            Err(BacklightVerificationError::InconclusiveRequestedValue)
        );
        let mut unsettled = original.clone();
        unsettled.kernel.actual_brightness = 110;
        assert_eq!(
            review_native_restoration(&unsettled, &after(125), 20),
            Err(BacklightVerificationError::InconclusiveRequestedValue)
        );
        assert_eq!(
            review_native_restoration(&original, &after(125), 0),
            Err(BacklightVerificationError::InvalidQualifiedMinimum)
        );
        assert_eq!(
            review_native_restoration(&original, &after(125), 140),
            Err(BacklightVerificationError::UnsafeTarget)
        );
    }
}
