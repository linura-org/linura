//! S18-5 Wi-Fi scan admission and observation correlation.
//!
//! These are *non-authorizing* constraints. They do not issue a grant,
//! create a durable attempt, call NetworkManager or permit RequestScan.
//! Runtime use requires a trusted original subject, canonical managed
//! Control authority, owner-pinned native execution and independent proof.

use linura_core::{NetworkDeviceId, NetworkManagerEpoch, NetworkObservationId};

pub const MIN_SCAN_INTERVAL_US: u64 = 30_000_000;
const MAX_OBSERVATION_AGE_US: u64 = 5_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WifiScanPreflightError {
    ChangedNativeIdentity,
    StaleObservation,
    UnavailableRadio,
    SessionUnprotected,
    DirectedProbeNotApproved,
    InvalidScanClock,
    ScanRateLimited,
    UncertainPreviousAttempt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WifiScanRadioFacts {
    pub networking_enabled: bool,
    pub wifi_enabled: bool,
    pub device_managed: bool,
    pub device_available: bool,
    pub hardware_rfkill_clear: bool,
    pub software_rfkill_clear: bool,
    pub subject_authenticated: bool,
    pub user_session_active_unlocked: bool,
    pub same_session_and_seat: bool,
}

/// These input facts must ultimately come from a *trusted* native observer.
/// This type does not attest their authenticity and is not an executor input.
#[derive(Clone, Copy, Debug)]
pub struct WifiScanPreview<'a> {
    pub device: &'a NetworkDeviceId,
    pub observation: &'a NetworkObservationId,
    pub current_epoch: &'a NetworkManagerEpoch,
    pub now_monotonic_us: u64,
    /// From the original durable authority's attempt ledger, not the UI.
    /// None is valid only when the authority confirms no earlier attempt.
    pub previous_attempt_us: Option<u64>,
    /// A previously ambiguous attempt must be explicitly reconciled first.
    pub previous_attempt_uncertain: bool,
    /// NM Wireless.LastScan uses boot-relative monotonic milliseconds;
    /// -1 represents no scan. Other negative values are invalid.
    pub last_scan_boot_ms: i64,
    /// Directed SSID/frequency probes leak location-sensitive metadata;
    /// this initial boundary accepts only the empty RequestScan options.
    pub requested_ssids: &'a [&'a [u8]],
    pub requested_frequencies_mhz: &'a [u32],
    pub radio: WifiScanRadioFacts,
}

#[derive(Clone, Debug)]
pub struct WifiScanCorrelation {
    device: NetworkDeviceId,
    observation: NetworkObservationId,
    epoch: NetworkManagerEpoch,
    baseline_last_scan_boot_ms: i64,
    reviewed_at_us: u64,
}

impl WifiScanCorrelation {
    /// Evidence correlation only. Even success is NOT an independently
    /// authorized or verified external effect and cannot complete a
    /// transaction without native source and attempt/receipt proof.
    pub fn check_fresh_observation(
        &self,
        device: &NetworkDeviceId,
        observation: &NetworkObservationId,
        current_epoch: &NetworkManagerEpoch,
        observed_last_scan_boot_ms: i64,
        now_monotonic_us: u64,
    ) -> Result<(), WifiScanPreflightError> {
        if &self.device != device
            || self.epoch.require_same(current_epoch).is_err()
            || device.epoch().require_same(current_epoch).is_err()
        {
            return Err(WifiScanPreflightError::ChangedNativeIdentity);
        }
        if observation
            .require_fresh(current_epoch, now_monotonic_us, MAX_OBSERVATION_AGE_US)
            .is_err()
            || observation.generation() <= self.observation.generation()
        {
            return Err(WifiScanPreflightError::StaleObservation);
        }
        let current_boot_ms = now_monotonic_us / 1_000;
        if now_monotonic_us < self.reviewed_at_us
            || observed_last_scan_boot_ms < 0
            || observed_last_scan_boot_ms <= self.baseline_last_scan_boot_ms
            || u64::try_from(observed_last_scan_boot_ms)
                .is_ok_and(|ms| ms < self.reviewed_at_us / 1_000 || ms > current_boot_ms)
        {
            return Err(WifiScanPreflightError::InvalidScanClock);
        }
        Ok(())
    }
}

/// Reject unsafe scan candidates while preserving the managed-effect deny
/// boundary. A positive result is only a reviewed correlation checkpoint.
pub fn review_broadcast_scan(
    request: WifiScanPreview<'_>,
) -> Result<WifiScanCorrelation, WifiScanPreflightError> {
    let radio = request.radio;
    if request
        .device
        .epoch()
        .require_same(request.current_epoch)
        .is_err()
    {
        return Err(WifiScanPreflightError::ChangedNativeIdentity);
    }
    if request
        .observation
        .require_fresh(
            request.current_epoch,
            request.now_monotonic_us,
            MAX_OBSERVATION_AGE_US,
        )
        .is_err()
    {
        return Err(WifiScanPreflightError::StaleObservation);
    }
    if !radio.networking_enabled
        || !radio.wifi_enabled
        || !radio.device_managed
        || !radio.device_available
        || !radio.hardware_rfkill_clear
        || !radio.software_rfkill_clear
    {
        return Err(WifiScanPreflightError::UnavailableRadio);
    }
    if !radio.subject_authenticated
        || !radio.user_session_active_unlocked
        || !radio.same_session_and_seat
    {
        return Err(WifiScanPreflightError::SessionUnprotected);
    }
    if !request.requested_ssids.is_empty() || !request.requested_frequencies_mhz.is_empty() {
        return Err(WifiScanPreflightError::DirectedProbeNotApproved);
    }
    if request.previous_attempt_uncertain {
        return Err(WifiScanPreflightError::UncertainPreviousAttempt);
    }
    if request.last_scan_boot_ms < -1
        || (request.last_scan_boot_ms >= 0
            && u64::try_from(request.last_scan_boot_ms)
                .is_ok_and(|ms| ms > request.now_monotonic_us / 1_000))
    {
        return Err(WifiScanPreflightError::InvalidScanClock);
    }
    if let Some(last_attempt) = request.previous_attempt_us {
        if last_attempt == 0 || last_attempt > request.now_monotonic_us {
            return Err(WifiScanPreflightError::InvalidScanClock);
        }
        if request.now_monotonic_us - last_attempt < MIN_SCAN_INTERVAL_US {
            return Err(WifiScanPreflightError::ScanRateLimited);
        }
    }
    Ok(WifiScanCorrelation {
        device: request.device.clone(),
        observation: request.observation.clone(),
        epoch: request.current_epoch.clone(),
        baseline_last_scan_boot_ms: request.last_scan_boot_ms,
        reviewed_at_us: request.now_monotonic_us,
    })
}

#[cfg(test)]
mod tests {
    use linura_core::{
        BootId, NetworkInterfaceName, NetworkManagerOwner, NetworkObjectId, NetworkObjectKind,
        SystemBusInstanceId,
    };

    use super::*;

    fn checked<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|error| unreachable!("valid fixture: {error:?}"))
    }

    fn epoch(owner: &str) -> NetworkManagerEpoch {
        NetworkManagerEpoch::new(
            checked(BootId::new("abcd1234-1234-4567-89ab-0123456789ab")),
            checked(SystemBusInstanceId::new("fedcba9876543210abcdef0123456789")),
            checked(NetworkManagerOwner::new(owner)),
        )
    }

    fn device(epoch: &NetworkManagerEpoch) -> NetworkDeviceId {
        checked(NetworkDeviceId::new(
            epoch.clone(),
            checked(NetworkObjectId::from_path(
                NetworkObjectKind::Device,
                "/org/freedesktop/NetworkManager/Devices/8",
            )),
            4_026_531_840,
            7,
            checked(NetworkInterfaceName::new("wlan0")),
            8,
        ))
    }

    fn observation(epoch: &NetworkManagerEpoch, generation: u64) -> NetworkObservationId {
        checked(NetworkObservationId::new(
            epoch.clone(),
            generation,
            100_000_000,
        ))
    }

    const fn radios() -> WifiScanRadioFacts {
        WifiScanRadioFacts {
            networking_enabled: true,
            wifi_enabled: true,
            device_managed: true,
            device_available: true,
            hardware_rfkill_clear: true,
            software_rfkill_clear: true,
            subject_authenticated: true,
            user_session_active_unlocked: true,
            same_session_and_seat: true,
        }
    }

    fn preview<'a>(
        d: &'a NetworkDeviceId,
        o: &'a NetworkObservationId,
        e: &'a NetworkManagerEpoch,
    ) -> WifiScanPreview<'a> {
        WifiScanPreview {
            device: d,
            observation: o,
            current_epoch: e,
            now_monotonic_us: 101_000_000,
            previous_attempt_us: None,
            previous_attempt_uncertain: false,
            last_scan_boot_ms: -1,
            requested_ssids: &[],
            requested_frequencies_mhz: &[],
            radio: radios(),
        }
    }

    #[test]
    fn broadcast_only_and_exact_identity_are_required() {
        let e = epoch(":1.48");
        let d = device(&e);
        let o = observation(&e, 4);
        assert!(review_broadcast_scan(preview(&d, &o, &e)).is_ok());
        let foreign = epoch(":1.49");
        assert!(matches!(
            review_broadcast_scan(preview(&d, &o, &foreign)),
            Err(WifiScanPreflightError::ChangedNativeIdentity)
        ));
        let ssid = b"private-network";
        let requested_ssids: &[&[u8]] = &[ssid.as_slice()];
        let mut p = preview(&d, &o, &e);
        p.requested_ssids = requested_ssids;
        assert!(matches!(
            review_broadcast_scan(p),
            Err(WifiScanPreflightError::DirectedProbeNotApproved)
        ));
        let frequencies = [2412];
        let mut p = preview(&d, &o, &e);
        p.requested_frequencies_mhz = &frequencies;
        assert!(matches!(
            review_broadcast_scan(p),
            Err(WifiScanPreflightError::DirectedProbeNotApproved)
        ));
    }

    #[test]
    fn disabled_radios_and_unprotected_sessions_are_denied() {
        let e = epoch(":1.48");
        let d = device(&e);
        let o = observation(&e, 4);
        for index in 0..9 {
            let mut p = preview(&d, &o, &e);
            match index {
                0 => p.radio.networking_enabled = false,
                1 => p.radio.wifi_enabled = false,
                2 => p.radio.device_managed = false,
                3 => p.radio.device_available = false,
                4 => p.radio.hardware_rfkill_clear = false,
                5 => p.radio.software_rfkill_clear = false,
                6 => p.radio.subject_authenticated = false,
                7 => p.radio.user_session_active_unlocked = false,
                _ => p.radio.same_session_and_seat = false,
            }
            assert!(review_broadcast_scan(p).is_err(), "case {index}");
        }
    }

    #[test]
    fn rate_limit_clock_rollback_and_uncertain_attempts_are_denied() {
        let e = epoch(":1.48");
        let d = device(&e);
        let o = observation(&e, 4);
        let mut p = preview(&d, &o, &e);
        p.previous_attempt_us = Some(100_000_000);
        assert!(matches!(
            review_broadcast_scan(p),
            Err(WifiScanPreflightError::ScanRateLimited)
        ));
        p.previous_attempt_us = Some(10_000_000);
        assert!(review_broadcast_scan(p).is_ok());
        p.previous_attempt_uncertain = true;
        assert!(matches!(
            review_broadcast_scan(p),
            Err(WifiScanPreflightError::UncertainPreviousAttempt)
        ));
        p.previous_attempt_uncertain = false;
        p.previous_attempt_us = Some(102_000_000);
        assert!(matches!(
            review_broadcast_scan(p),
            Err(WifiScanPreflightError::InvalidScanClock)
        ));
        p.previous_attempt_us = None;
        p.last_scan_boot_ms = 102_000;
        assert!(matches!(
            review_broadcast_scan(p),
            Err(WifiScanPreflightError::InvalidScanClock)
        ));
        p.last_scan_boot_ms = -2;
        assert!(matches!(
            review_broadcast_scan(p),
            Err(WifiScanPreflightError::InvalidScanClock)
        ));
    }

    #[test]
    fn post_scan_requires_fresh_independent_correlation() {
        let e = epoch(":1.48");
        let d = device(&e);
        let o = observation(&e, 4);
        let reviewed = checked(review_broadcast_scan(preview(&d, &o, &e)));
        let later = observation(&e, 5);
        assert!(reviewed
            .check_fresh_observation(&d, &later, &e, 101_005, 102_000_000)
            .is_ok());
        assert!(matches!(
            reviewed.check_fresh_observation(&d, &o, &e, 101_005, 102_000_000),
            Err(WifiScanPreflightError::StaleObservation)
        ));
        let changed = epoch(":1.49");
        assert!(matches!(
            reviewed.check_fresh_observation(&d, &later, &changed, 101_005, 102_000_000),
            Err(WifiScanPreflightError::ChangedNativeIdentity)
        ));
        assert!(matches!(
            reviewed.check_fresh_observation(&d, &later, &e, 99_000, 102_000_000),
            Err(WifiScanPreflightError::InvalidScanClock)
        ));
        assert!(matches!(
            reviewed.check_fresh_observation(&d, &later, &e, 102_005, 102_000_000),
            Err(WifiScanPreflightError::InvalidScanClock)
        ));
    }
}
