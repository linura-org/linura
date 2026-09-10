use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use linura_library::{AcceptanceLinearizationClock, AuthorityTimeSample};

use crate::proposal_acceptance::ProposalAcceptanceControlError;

static NEXT_CLOCK_GENERATION: AtomicU64 = AtomicU64::new(1);

/// Process-local trusted Control clock for proposal acceptance.
///
/// Wall-clock time is sampled exactly once at construction. Every later sample
/// is derived from `Instant`, so a host realtime-clock rollback cannot move the
/// authority clock backward while a Control process remains alive. A newly
/// constructed clock receives a different continuity generation; transient
/// acceptance capabilities minted under an earlier generation therefore cannot
/// survive a time-source reset/rebind. Durable exact replay is resolved before
/// fresh time is consulted.
#[derive(Debug)]
pub struct ControlAuthorityClock {
    origin: Instant,
    origin_unix_ms: u64,
    continuity_generation: u64,
    last_unix_ms: u64,
}

impl ControlAuthorityClock {
    pub fn new() -> Result<Self, ProposalAcceptanceControlError> {
        let origin_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ProposalAcceptanceControlError::TrustedTimeUnavailable)
            .and_then(|duration| {
                u64::try_from(duration.as_millis())
                    .map_err(|_| ProposalAcceptanceControlError::TrustedTimeUnavailable)
            })?;
        let continuity_generation = next_nonzero(&NEXT_CLOCK_GENERATION);
        Ok(Self {
            origin: Instant::now(),
            origin_unix_ms,
            continuity_generation,
            last_unix_ms: origin_unix_ms,
        })
    }

    #[must_use]
    pub const fn continuity_generation(&self) -> u64 {
        self.continuity_generation
    }
}

impl AcceptanceLinearizationClock for ControlAuthorityClock {
    fn sample(&mut self) -> Option<AuthorityTimeSample> {
        let elapsed_ms = u64::try_from(self.origin.elapsed().as_millis()).ok()?;
        let unix_ms = self.origin_unix_ms.checked_add(elapsed_ms)?;
        if unix_ms < self.last_unix_ms {
            return None;
        }
        self.last_unix_ms = unix_ms;
        Some(AuthorityTimeSample {
            unix_ms,
            continuity_generation: self.continuity_generation,
            continuity_established: true,
        })
    }
}

fn next_nonzero(counter: &AtomicU64) -> u64 {
    loop {
        let value = counter.fetch_add(1, Ordering::SeqCst);
        if value != 0 {
            return value;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn samples_are_monotonic_with_stable_continuity_generation() {
        let mut clock =
            ControlAuthorityClock::new().unwrap_or_else(|error| unreachable!("{error}"));
        let first = clock.sample().unwrap_or_else(|| unreachable!());
        let second = clock.sample().unwrap_or_else(|| unreachable!());
        assert!(second.unix_ms >= first.unix_ms);
        assert_eq!(first.continuity_generation, second.continuity_generation);
        assert!(first.continuity_established && second.continuity_established);
    }

    #[test]
    fn independently_constructed_clocks_have_distinct_continuity_generations() {
        let left = ControlAuthorityClock::new().unwrap_or_else(|error| unreachable!("{error}"));
        let right = ControlAuthorityClock::new().unwrap_or_else(|error| unreachable!("{error}"));
        assert_ne!(left.continuity_generation(), right.continuity_generation());
    }
}
