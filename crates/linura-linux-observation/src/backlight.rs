//! Non-authorizing physical-backlight identity and native-value checks for S21-3.
//!
//! These checks cannot attest a kernel device, a logind session/seat, a provider
//! generation or an approval. A trusted native observer must supply fresh source
//! evidence; Control must independently authenticate the principal, authorize
//! the managed operation and reserve its durable attempt before any native
//! effect. No executor, D-Bus forwarding or sysfs write is exposed here.

pub mod candidate;
pub mod kernel;
pub mod verification;

/// A native sample's *reported* source identity, not a security credential.
///
/// Names are correlations only; the native adapter must separately attest the
/// active kernel device, current boot, exact logind owner, user and session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BacklightSourceIdentity {
    pub boot_id: String,
    pub logind_owner: String,
    pub session_id: String,
    pub seat_id: String,
    pub device_name: String,
    pub device_generation: u64,
    pub uid: u32,
}

/// Numeric kernel brightness values; never a display gamma or DDC substitute.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BacklightNativeSample {
    pub source: BacklightSourceIdentity,
    pub maximum: u32,
    /// An independently qualified lower bound that preserves visible access.
    pub safe_minimum: u32,
    pub current: u32,
    pub session_active: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BacklightReviewError {
    InvalidIdentity,
    InvalidBounds,
    InactiveSession,
    PercentOutOfRange,
    UnsafeTarget,
    ChangedIdentity,
    ChangedBounds,
    ConcurrentChange,
    PostconditionMismatch,
}

impl BacklightSourceIdentity {
    /// Reject path-like, control-character, unbounded and absent identifiers.
    /// This is syntactic validation only, never a replacement for native attestation.
    pub fn validate(&self) -> Result<(), BacklightReviewError> {
        for part in [
            &self.boot_id,
            &self.logind_owner,
            &self.session_id,
            &self.seat_id,
            &self.device_name,
        ] {
            if part.is_empty()
                || part.len() > 128
                || !part
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | ':'))
            {
                return Err(BacklightReviewError::InvalidIdentity);
            }
        }
        if self.device_generation == 0 {
            return Err(BacklightReviewError::InvalidIdentity);
        }
        Ok(())
    }
}

impl BacklightNativeSample {
    /// Validate internal sample consistency; the caller still must establish
    /// source authenticity, physical hardware support and observation freshness.
    pub fn validate(&self) -> Result<(), BacklightReviewError> {
        self.source.validate()?;
        if self.maximum == 0
            || self.safe_minimum == 0
            || self.safe_minimum > self.maximum
            || self.current > self.maximum
        {
            return Err(BacklightReviewError::InvalidBounds);
        }
        Ok(())
    }

    /// Deterministic presentation-to-native mapping. 0% means the qualified
    /// safe minimum, *not* a zero-brightness blackout.
    ///
    /// This is an arithmetic conversion, not an executable plan or approval.
    pub fn native_for_percent(&self, percent: u8) -> Result<u32, BacklightReviewError> {
        self.validate()?;
        if percent > 100 {
            return Err(BacklightReviewError::PercentOutOfRange);
        }
        let range = u64::from(self.maximum - self.safe_minimum);
        let offset = (range * u64::from(percent) + 50) / 100;
        // The result is bounded by maximum, which is a u32.
        Ok(self.safe_minimum + offset as u32)
    }

    /// Reject unsupported, inactive, zero or below-minimum native requests.
    /// SecuritySensitive/ManagedExternalEffect policy is enforced elsewhere.
    pub fn validate_target(&self, target: u32) -> Result<(), BacklightReviewError> {
        self.validate()?;
        if !self.session_active {
            return Err(BacklightReviewError::InactiveSession);
        }
        if target < self.safe_minimum || target > self.maximum {
            return Err(BacklightReviewError::UnsafeTarget);
        }
        Ok(())
    }

    /// Verify the same native source and bounds still exist. The external
    /// adapter must additionally re-attest *both* observations independently.
    fn same_source_and_bounds(&self, next: &Self) -> Result<(), BacklightReviewError> {
        self.validate()?;
        next.validate()?;
        if !self.session_active || !next.session_active {
            return Err(BacklightReviewError::InactiveSession);
        }
        if self.source != next.source {
            return Err(BacklightReviewError::ChangedIdentity);
        }
        if self.maximum != next.maximum || self.safe_minimum != next.safe_minimum {
            return Err(BacklightReviewError::ChangedBounds);
        }
        Ok(())
    }

    /// Revalidate an intended native value just before a privileged handoff.
    /// A concurrent brightness change must be replanned, never overwritten
    /// using an old snapshot.
    pub fn revalidate_before_effect(
        &self,
        fresh: &Self,
        target: u32,
    ) -> Result<(), BacklightReviewError> {
        self.validate_target(target)?;
        self.same_source_and_bounds(fresh)?;
        if self.current != fresh.current {
            return Err(BacklightReviewError::ConcurrentChange);
        }
        Ok(())
    }

    /// The desired value is not a success receipt. Require a *new*, independently
    /// obtained authoritative native sample with the same device generation,
    /// logind owner, session, seat, bounds and exact observed native value.
    /// Freshness, sequence, provenance and non-replay evidence remain Control's
    /// responsibility and cannot be supplied by this arithmetic helper.
    pub fn review_postcondition(
        &self,
        after: &Self,
        target: u32,
    ) -> Result<(), BacklightReviewError> {
        self.validate_target(target)?;
        self.same_source_and_bounds(after)?;
        if after.current != target {
            return Err(BacklightReviewError::PostconditionMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> BacklightNativeSample {
        BacklightNativeSample {
            source: BacklightSourceIdentity {
                boot_id: "b8691e5f-1111-2222-3333-444444444444".into(),
                logind_owner: ":1.42".into(),
                session_id: "c2".into(),
                seat_id: "seat0".into(),
                device_name: "intel_backlight".into(),
                device_generation: 8,
                uid: 1000,
            },
            maximum: 201,
            safe_minimum: 20,
            current: 80,
            session_active: true,
        }
    }

    #[test]
    fn exact_arithmetic_maps_endpoints_and_rounds_without_float() {
        let value = fixture();
        assert_eq!(value.native_for_percent(0), Ok(20));
        assert_eq!(value.native_for_percent(50), Ok(111));
        assert_eq!(value.native_for_percent(100), Ok(201));
        assert_eq!(
            value.native_for_percent(101),
            Err(BacklightReviewError::PercentOutOfRange)
        );
        let mut large = value;
        large.maximum = u32::MAX;
        large.safe_minimum = 1;
        assert_eq!(large.native_for_percent(100), Ok(u32::MAX));
        assert_eq!(large.native_for_percent(0), Ok(1));
    }

    #[test]
    fn rejects_invalid_bounds_and_unsafe_targets() {
        let mut sample = fixture();
        for (min, max, current) in [(0, 100, 20), (101, 100, 20), (1, 0, 0), (1, 10, 11)] {
            sample.safe_minimum = min;
            sample.maximum = max;
            sample.current = current;
            assert_eq!(sample.validate(), Err(BacklightReviewError::InvalidBounds));
        }
        let sample = fixture();
        assert_eq!(
            sample.validate_target(0),
            Err(BacklightReviewError::UnsafeTarget)
        );
        assert_eq!(
            sample.validate_target(19),
            Err(BacklightReviewError::UnsafeTarget)
        );
        assert_eq!(
            sample.validate_target(202),
            Err(BacklightReviewError::UnsafeTarget)
        );
        assert_eq!(sample.validate_target(20), Ok(()));
        assert_eq!(sample.validate_target(201), Ok(()));
    }

    #[test]
    fn denies_non_active_session() {
        let mut sample = fixture();
        sample.session_active = false;
        assert_eq!(
            sample.validate_target(80),
            Err(BacklightReviewError::InactiveSession)
        );
    }

    #[test]
    fn rejects_paths_control_bytes_and_unbounded_native_names() {
        for name in ["", "../backlight", "bad/name", "name\n", "name with spaces"] {
            let mut sample = fixture();
            sample.source.device_name = name.into();
            assert_eq!(
                sample.validate(),
                Err(BacklightReviewError::InvalidIdentity)
            );
        }
        let mut sample = fixture();
        sample.source.session_id = "a".repeat(129);
        assert_eq!(
            sample.validate(),
            Err(BacklightReviewError::InvalidIdentity)
        );
        sample.source.session_id = "c2".into();
        sample.source.device_generation = 0;
        assert_eq!(
            sample.validate(),
            Err(BacklightReviewError::InvalidIdentity)
        );
    }

    #[test]
    fn detects_all_source_identity_replacements() {
        let before = fixture();
        let cases = [
            ("boot", 1_u8),
            ("owner", 2),
            ("session", 3),
            ("seat", 4),
            ("device", 5),
            ("generation", 6),
            ("uid", 7),
        ];
        for (_, case) in cases {
            let mut after = before.clone();
            match case {
                1 => after.source.boot_id = "another-boot".into(),
                2 => after.source.logind_owner = ":1.43".into(),
                3 => after.source.session_id = "c3".into(),
                4 => after.source.seat_id = "seat1".into(),
                5 => after.source.device_name = "acpi_video0".into(),
                6 => after.source.device_generation += 1,
                7 => after.source.uid += 1,
                _ => unreachable!(),
            };
            assert_eq!(
                before.revalidate_before_effect(&after, 80),
                Err(BacklightReviewError::ChangedIdentity)
            );
        }
    }

    #[test]
    fn denies_changed_brightness_bounds_and_competing_effects() {
        let before = fixture();
        let mut changed = before.clone();
        changed.maximum += 1;
        assert_eq!(
            before.revalidate_before_effect(&changed, 90),
            Err(BacklightReviewError::ChangedBounds)
        );
        changed = before.clone();
        changed.safe_minimum += 1;
        assert_eq!(
            before.revalidate_before_effect(&changed, 90),
            Err(BacklightReviewError::ChangedBounds)
        );
        changed = before.clone();
        changed.current += 1;
        assert_eq!(
            before.revalidate_before_effect(&changed, 90),
            Err(BacklightReviewError::ConcurrentChange)
        );
    }

    #[test]
    fn requires_exact_read_after_write_but_never_equates_it_with_authority() {
        let before = fixture();
        let mut after = before.clone();
        after.current = 100;
        assert_eq!(before.review_postcondition(&after, 100), Ok(()));
        assert_eq!(
            before.review_postcondition(&after, 101),
            Err(BacklightReviewError::PostconditionMismatch)
        );
        after.source.device_generation += 1;
        assert_eq!(
            before.review_postcondition(&after, 100),
            Err(BacklightReviewError::ChangedIdentity)
        );
        after = before.clone();
        after.session_active = false;
        assert_eq!(
            before.review_postcondition(&after, 80),
            Err(BacklightReviewError::InactiveSession)
        );
    }

    #[test]
    fn allows_recovery_from_an_already_dark_observation_without_approving_zero() {
        let mut before = fixture();
        before.current = 0;
        assert_eq!(before.validate(), Ok(()));
        assert_eq!(
            before.validate_target(0),
            Err(BacklightReviewError::UnsafeTarget)
        );
        assert_eq!(before.revalidate_before_effect(&before, 20), Ok(()));
    }
}
