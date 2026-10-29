//! Non-authorizing S21-3 candidate observation coherence.
//!
//! Deliberately exposes neither an effect adapter nor a trusted operation.
//! A sysfs class entry, even with an authenticated local logind session,
//! does not prove that this session controls a specific physical panel.
//! A supported panel/seat mapping and a calibrated nonzero safe minimum must
//! be independently qualified before enabling writes.

use super::kernel::{KernelBacklightError, KernelBacklightSnapshot, observe_kernel_backlights};
use crate::logind::{LogindSessionObserver, NativeBacklightSession};

const MAX_CANDIDATE_AGE_MS: u64 = 2_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BacklightCandidate {
    pub session: NativeBacklightSession,
    pub kernel: KernelBacklightSnapshot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BacklightCandidateError {
    SessionUnavailable,
    KernelUnavailable,
    NoPhysicalHardware,
    AmbiguousPhysicalHardware,
    SessionChanged,
    DeviceChanged,
    UnsupportedPowerState,
    StaleObservation,
}

/// Correlate one currently active local logind session to a stable candidate
/// kernel backlight. This is a **read-only discovery result**, not permission
/// to invoke logind SetBrightness, a durable plan or an approved operation.
pub fn observe_backlight_candidate(
    session_id: &str,
    uid: u32,
) -> Result<BacklightCandidate, BacklightCandidateError> {
    observe_with_subject(
        session_id,
        uid,
        LogindSessionObserver::observe_backlight_session,
    )
}

/// The same native candidate discovery from the original unprivileged
/// graphical user's system-bus connection, with PID-to-login proof. This
/// will reject the root authority daemon and other same-UID login sessions.
/// It is not a Control permit, physical qualification or brightness executor.
pub fn observe_user_subject_backlight_candidate(
    session_id: &str,
    uid: u32,
) -> Result<BacklightCandidate, BacklightCandidateError> {
    observe_with_subject(
        session_id,
        uid,
        LogindSessionObserver::observe_user_backlight_subject,
    )
}

/// Scope discovery to the original authenticated system-bus sender, not merely
/// another active session owned by the same UID. The native adapter requires
/// bus-provided ProcessFD evidence and keeps it pinned across both kernel reads.
/// This remains a read-only candidate, never a dispatch or hardware credential.
pub fn observe_caller_backlight_candidate(
    expected: &linura_core::SessionEpoch,
    bus_guid: &str,
    sender: &str,
    pid: u32,
) -> Result<BacklightCandidate, BacklightCandidateError> {
    observe_caller_backlight_candidate_with_budget(
        expected,
        bus_guid,
        sender,
        pid,
        std::time::Duration::from_millis(MAX_CANDIDATE_AGE_MS),
    )
}

/// The same non-authorizing discovery constrained by an outer caller deadline.
/// An incoming budget may only tighten the fixed native two-second cap. All
/// connection/authentication/RPC/kernel phases retain that one original clock;
/// neither native replies nor a second sample can refresh it.
pub fn observe_caller_backlight_candidate_with_budget(
    expected: &linura_core::SessionEpoch,
    bus_guid: &str,
    sender: &str,
    pid: u32,
    budget: std::time::Duration,
) -> Result<BacklightCandidate, BacklightCandidateError> {
    use crate::logind::backlight_subject::BacklightSubjectProbe;
    let probe = BacklightSubjectProbe::connect(expected, bus_guid, sender, pid, budget)
        .map_err(|_| BacklightCandidateError::SessionUnavailable)?;
    let before = probe
        .observe()
        .map_err(|_| BacklightCandidateError::SessionUnavailable)?;
    let first = observe_kernel_backlights().map_err(map_kernel_failure)?;
    probe
        .check()
        .map_err(|_| BacklightCandidateError::StaleObservation)?;
    let second = observe_kernel_backlights().map_err(map_kernel_failure)?;
    let after = probe
        .observe()
        .map_err(|_| BacklightCandidateError::SessionUnavailable)?;
    let candidate = qualify_candidate_pair(before, after, first, second)?;
    probe
        .check()
        .map_err(|_| BacklightCandidateError::StaleObservation)?;
    Ok(candidate)
}

fn observe_with_subject(
    session_id: &str,
    uid: u32,
    observe: fn(
        &LogindSessionObserver,
        &str,
        u32,
    ) -> Result<NativeBacklightSession, linura_provider_sdk::ProviderError>,
) -> Result<BacklightCandidate, BacklightCandidateError> {
    let logind = LogindSessionObserver::connect()
        .map_err(|_| BacklightCandidateError::SessionUnavailable)?;
    let session_before = observe(&logind, session_id, uid)
        .map_err(|_| BacklightCandidateError::SessionUnavailable)?;
    let kernel_before = observe_kernel_backlights().map_err(map_kernel_failure)?;
    let kernel_after = observe_kernel_backlights().map_err(map_kernel_failure)?;
    let session_after = observe(&logind, session_id, uid)
        .map_err(|_| BacklightCandidateError::SessionUnavailable)?;
    qualify_candidate_pair(session_before, session_after, kernel_before, kernel_after)
}

fn map_kernel_failure(error: KernelBacklightError) -> BacklightCandidateError {
    match error {
        KernelBacklightError::DeviceChanged => BacklightCandidateError::DeviceChanged,
        _ => BacklightCandidateError::KernelUnavailable,
    }
}

fn qualify_candidate_pair(
    before: NativeBacklightSession,
    after: NativeBacklightSession,
    first: Vec<KernelBacklightSnapshot>,
    second: Vec<KernelBacklightSnapshot>,
) -> Result<BacklightCandidate, BacklightCandidateError> {
    if before.boot_id != after.boot_id
        || before.logind_owner != after.logind_owner
        || before.session_id != after.session_id
        || before.created_monotonic_us != after.created_monotonic_us
        || before.seat_id != after.seat_id
        || before.uid != after.uid
    {
        return Err(BacklightCandidateError::SessionChanged);
    }
    if after.observed_at_unix_ms < before.observed_at_unix_ms
        || after.observed_at_unix_ms - before.observed_at_unix_ms > MAX_CANDIDATE_AGE_MS
    {
        return Err(BacklightCandidateError::StaleObservation);
    }
    if first.len() != 1 || second.len() != 1 {
        return Err(if first.is_empty() && second.is_empty() {
            BacklightCandidateError::NoPhysicalHardware
        } else {
            BacklightCandidateError::AmbiguousPhysicalHardware
        });
    }
    let device = first
        .into_iter()
        .next()
        .ok_or(BacklightCandidateError::NoPhysicalHardware)?;
    if second[0] != device {
        return Err(BacklightCandidateError::DeviceChanged);
    }
    if device.power != 0 {
        return Err(BacklightCandidateError::UnsupportedPowerState);
    }
    Ok(BacklightCandidate {
        session: after,
        kernel: device,
    })
}

#[cfg(test)]
mod tests {
    use super::super::kernel::{KernelBacklightIdentity, KernelBacklightKind};
    use super::*;
    use std::path::PathBuf;

    fn scope() -> NativeBacklightSession {
        NativeBacklightSession {
            boot_id: "b8691e5f-1111-2222-3333-444444444444".into(),
            logind_owner: ":1.42".into(),
            session_id: "c2".into(),
            created_monotonic_us: 131,
            seat_id: "seat0".into(),
            uid: 1000,
            observed_at_unix_ms: 20_000,
        }
    }

    fn native() -> KernelBacklightSnapshot {
        KernelBacklightSnapshot {
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
        }
    }

    #[test]
    fn exact_stable_candidate_passes_only_as_non_authorizing_discovery() {
        let first = scope();
        let mut second = first.clone();
        second.observed_at_unix_ms += 1;
        let candidate = qualify_candidate_pair(first, second, vec![native()], vec![native()]);
        assert!(candidate.is_ok());
    }

    #[test]
    fn every_session_replacement_and_time_regression_fails_closed() {
        let original = scope();
        for case in 0..8 {
            let mut changed = original.clone();
            match case {
                0 => changed.boot_id = "other".into(),
                1 => changed.logind_owner = ":1.43".into(),
                2 => changed.session_id = "c3".into(),
                3 => changed.created_monotonic_us += 1,
                4 => changed.seat_id = "seat1".into(),
                5 => changed.uid += 1,
                6 => changed.observed_at_unix_ms -= 1,
                7 => changed.observed_at_unix_ms += MAX_CANDIDATE_AGE_MS + 1,
                _ => unreachable!(),
            }
            assert!(
                qualify_candidate_pair(original.clone(), changed, vec![native()], vec![native()],)
                    .is_err()
            );
        }
    }

    #[test]
    fn physical_absence_multiple_sources_and_concurrent_changes_are_not_success() {
        let original = scope();
        let check = |first, second| {
            qualify_candidate_pair(original.clone(), original.clone(), first, second)
        };
        assert_eq!(
            check(vec![], vec![]),
            Err(BacklightCandidateError::NoPhysicalHardware),
        );
        assert_eq!(
            check(vec![native(), native()], vec![native(), native()]),
            Err(BacklightCandidateError::AmbiguousPhysicalHardware),
        );
        let mut changed = native();
        changed.actual_brightness += 1;
        assert_eq!(
            check(vec![native()], vec![changed]),
            Err(BacklightCandidateError::DeviceChanged),
        );
        let mut changed = native();
        changed.identity.inode += 1;
        assert_eq!(
            check(vec![native()], vec![changed]),
            Err(BacklightCandidateError::DeviceChanged),
        );
        let mut changed = native();
        changed.power = 4;
        assert_eq!(
            check(vec![changed.clone()], vec![changed]),
            Err(BacklightCandidateError::UnsupportedPowerState),
        );
    }
}
