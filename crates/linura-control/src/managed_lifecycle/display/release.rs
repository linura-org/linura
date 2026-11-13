//! Ordinary post-commit eligibility, canonical review and durable preparation.
//! Inspection cannot produce execution authority. The separate managed release
//! operation requires fresh protected approval and retains a one-use Root
//! preparation; its ACK is neither physical handoff nor completion evidence.
//! Native grant spend, physical verification and ordered retirement remain
//! separate requirements before any protective fence can be released.

use super::*;
mod execution;
mod original;
pub use execution::{
    AuthorizedOrdinaryDisplayRelease, OrdinaryDisplayReleaseAuthorizer,
    OrdinaryDisplayReleaseChallenge, OrdinaryDisplayReleasePort, OrdinaryDisplayReleaseReceipt,
};
mod plan;
pub use original::OrdinaryDisplayOriginalInspection;
use original::invalid_original;
pub use plan::OrdinaryDisplayReleaseRequest;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrdinaryDisplayReleaseInspection {
    request_id: RequestId,
    transaction_id: TransactionId,
    dispatch_digest: String,
    terminal_record_digest: String,
    durable_binding_digest: String,
    observation_digest: String,
    observed_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    restored: bool,
}

impl OrdinaryDisplayReleaseInspection {
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }
    #[must_use]
    pub const fn transaction_id(&self) -> &TransactionId {
        &self.transaction_id
    }
    #[must_use]
    pub fn dispatch_digest(&self) -> &str {
        &self.dispatch_digest
    }
    #[must_use]
    pub fn terminal_record_digest(&self) -> &str {
        &self.terminal_record_digest
    }
    #[must_use]
    pub fn durable_binding_digest(&self) -> &str {
        &self.durable_binding_digest
    }
    #[must_use]
    pub fn observation_digest(&self) -> &str {
        &self.observation_digest
    }
    #[must_use]
    pub const fn observed_at_unix_ms(&self) -> u64 {
        self.observed_at_unix_ms
    }
    /// Strict upper bound for this read-only report. Never an authority grant.
    #[must_use]
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }
    #[must_use]
    pub const fn restored(&self) -> bool {
        self.restored
    }
}

fn terminal_for_inspection(
    history: &DisplayHistory,
    state: TransactionState,
) -> Result<(&Record, &'static str, bool), ManagedLifecycleError> {
    match (history.confirmed.as_ref(), history.restored.as_ref(), state) {
        (Some(confirmed), None, TransactionState::Committed)
            if history.confirmation.is_some() && history.revert.is_none() =>
        {
            Ok((confirmed, "confirmed", false))
        }
        (None, Some(restored), TransactionState::RecoveryBlocked) => {
            Ok((restored, "restored", true))
        }
        _ => Err(ManagedLifecycleError::TerminalState(
            "ordinary display release requires matching durably retired terminal history".into(),
        )),
    }
}

/// Recheck the original observation's absolute freshness after all durable
/// readbacks. Earlier probe validation is not enough: expensive store I/O can
/// consume the entire two-second native observation window. A returned report
/// must never silently acquire a new or extended validity period.
fn terminal_release_expires_at(
    observed_at_unix_ms: u64,
    valid_for_ms: u64,
    now: u64,
) -> Result<u64, ManagedLifecycleError> {
    let fail = || {
        ManagedLifecycleError::Verification(
            "ordinary display release observation expired during durable readback".into(),
        )
    };
    if observed_at_unix_ms == 0
        || valid_for_ms == 0
        || valid_for_ms > 2_000
        || now < observed_at_unix_ms
    {
        return Err(fail());
    }
    let deadline = observed_at_unix_ms
        .checked_add(valid_for_ms)
        .ok_or_else(fail)?;
    if now >= deadline {
        return Err(fail());
    }
    Ok(deadline)
}

impl<S: TransactionStore> ManagedLifecycleControl<S> {
    /// Inspect eligibility only; never releases power, S17 input, startup
    /// admission, native surface coverage, or checkpoint ownership.
    ///
    /// A historical Confirmed/Restored receipt is insufficient. The current
    /// durable authority snapshot, immutable journal chain and native baseline
    /// checkpoint must agree; two fresh attempt probes must straddle an
    /// independent layout verification and preserve the terminal state. A
    /// second durable read prevents a stale report from adopting changed
    /// authority history. None of the returned digests is a capability token.
    pub fn inspect_ordinary_display_release<
        P: DisplayTransactionPort,
        V: IndependentDisplayVerifier,
    >(
        &self,
        principal: AuthenticatedPrincipal,
        request_id: &RequestId,
        port: &mut P,
        verifier: &mut V,
    ) -> Result<OrdinaryDisplayReleaseInspection, ManagedLifecycleError> {
        let request = self.retained_display_request(&principal, request_id)?;
        let principal_id = PrincipalId::new(principal.as_str())
            .map_err(|error| ManagedLifecycleError::Contract(error.to_string()))?;
        self.authority
            .assert_request_matches(&principal, &request)?;
        let transaction = TransactionId::for_namespace(&principal_id, request_id);
        let snapshot = self.authority.snapshot(&transaction)?;
        let request_digest = crate::durable_authority::digest_request(&request)?;
        let history = DisplayHistory::load(
            self.display_journal()?,
            &principal_id,
            &request_digest,
            &transaction,
            snapshot.state,
            now_ms()?,
        )?;
        let (terminal, expected_state, restored) =
            terminal_for_inspection(&history, snapshot.state)?;
        let terminal_digest = terminal.digest().clone();
        let terminal_timestamp = terminal.recorded_at_unix_ms;
        let dispatched = history.dispatched.as_ref().ok_or_else(|| {
            ManagedLifecycleError::Authority(
                "terminal display release is missing its original dispatch".into(),
            )
        })?;
        let dispatch_digest = dispatched.dispatch_digest.clone().ok_or_else(|| {
            ManagedLifecycleError::Contract(
                "terminal display release is missing its dispatch digest".into(),
            )
        })?;
        let checkpoint = crate::display_checkpoint::Checkpoint::load(
            self.display_journal()?,
            &request,
            &snapshot,
            now_ms()?,
        )?;
        let query = DisplayAttemptQuery::new(&request, dispatched)?;
        let first = port
            .observe_attempt(&query)
            .map_err(ManagedLifecycleError::Verification)?;
        if first.observed_at_unix_ms <= terminal_timestamp
            || attempt_state_at(&first, &request, dispatched, now_ms()?)? != expected_state
        {
            return Err(ManagedLifecycleError::Verification(
                "ordinary display release has no fresh terminal native observation".into(),
            ));
        }
        let target = if restored {
            DisplayVerificationTarget::Restored {
                native_baseline_guard: checkpoint.native_guard,
            }
        } else {
            DisplayVerificationTarget::Desired
        };
        if !matches!(
            verifier.verify_layout(&request, target, first.observed_at_unix_ms),
            Ok(outcome) if outcome.disposition == VerificationDisposition::Satisfied
        ) {
            return Err(ManagedLifecycleError::Verification(
                "ordinary display release failed independent layout verification".into(),
            ));
        }
        let after = port
            .observe_attempt(&query)
            .map_err(ManagedLifecycleError::Verification)?;
        if after.sequence <= first.sequence
            || after.observed_at_unix_ms < first.observed_at_unix_ms
            || after.attributes != first.attributes
            || attempt_state_at(&after, &request, dispatched, now_ms()?)? != expected_state
        {
            return Err(ManagedLifecycleError::Verification(
                "ordinary display release changed during independent verification".into(),
            ));
        }
        self.display_journal()?
            .integrity_check()
            .map_err(|error| ManagedLifecycleError::Authority(error.to_string()))?;
        let current = self.authority.snapshot(&transaction)?;
        if current != snapshot {
            return Err(ManagedLifecycleError::Authority(
                "ordinary display release authority changed during verification".into(),
            ));
        }
        let current_history = DisplayHistory::load(
            self.display_journal()?,
            &principal_id,
            &request_digest,
            &transaction,
            current.state,
            now_ms()?,
        )?;
        let (current_terminal, current_state, current_restored) =
            terminal_for_inspection(&current_history, current.state)?;
        if current_terminal.digest() != &terminal_digest
            || current_state != expected_state
            || current_restored != restored
            || current_history
                .dispatched
                .as_ref()
                .is_none_or(|record| record.digest() != dispatched.digest())
            || crate::display_checkpoint::Checkpoint::load(
                self.display_journal()?,
                &request,
                &current,
                now_ms()?,
            )?
            .native_guard
                != checkpoint.native_guard
        {
            return Err(ManagedLifecycleError::Authority(
                "ordinary display release durable provenance changed".into(),
            ));
        }
        let expires_at_unix_ms =
            terminal_release_expires_at(after.observed_at_unix_ms, after.valid_for_ms, now_ms()?)?;
        Ok(OrdinaryDisplayReleaseInspection {
            request_id: request.request_id,
            transaction_id: transaction,
            dispatch_digest,
            terminal_record_digest: terminal_digest.as_str().into(),
            durable_binding_digest: current.binding_digest.as_str().into(),
            observation_digest: crate::durable_authority::digest_observation(&after)?
                .as_str()
                .into(),
            observed_at_unix_ms: after.observed_at_unix_ms,
            expires_at_unix_ms,
            restored,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(phase: Phase, at: u64) -> Record {
        let request = linura_transaction::digest_parts(
            "display-release-provenance-test",
            [b"original-request".as_slice()],
        );
        let transaction = TransactionId::new("transaction:display-release-provenance-test")
            .unwrap_or_else(|error| unreachable!("{error}"));
        let previous = if phase == Phase::Reserved {
            None
        } else {
            Some(linura_transaction::digest_parts(
                "display-release-provenance-parent-test",
                [b"parent".as_slice()],
            ))
        };
        let observation = if matches!(phase, Phase::Reserved | Phase::Dispatched) {
            None
        } else {
            Some(linura_transaction::digest_parts(
                "display-release-provenance-observation-test",
                [b"observed".as_slice()],
            ))
        };
        Record::new(
            request,
            transaction,
            phase,
            2_000,
            at,
            if phase == Phase::Reserved {
                None
            } else {
                Some("a".repeat(64))
            },
            previous,
            observation,
        )
        .unwrap_or_else(|error| unreachable!("{error:?}"))
    }

    fn history() -> DisplayHistory {
        DisplayHistory {
            reserved: record(Phase::Reserved, 100),
            dispatched: Some(record(Phase::Dispatched, 110)),
            confirmation: None,
            revert: None,
            confirmed: None,
            restored: None,
        }
    }

    #[test]
    fn release_report_expiry_is_strict_and_cannot_be_renewed_by_durable_readback() {
        assert_eq!(
            terminal_release_expires_at(10_000, 2_000, 10_000).ok(),
            Some(12_000)
        );
        assert_eq!(
            terminal_release_expires_at(10_000, 2_000, 11_999).ok(),
            Some(12_000)
        );
        for (observed, validity, now) in [
            (10_000, 2_000, 12_000),
            (10_000, 2_000, 12_001),
            (10_000, 2_000, 9_999),
            (0, 2_000, 1),
            (10_000, 0, 10_000),
            (10_000, 2_001, 10_000),
            (u64::MAX, 2_000, u64::MAX),
        ] {
            assert!(terminal_release_expires_at(observed, validity, now).is_err());
        }
    }

    #[test]
    fn native_terminal_phase_without_a_durable_retirement_never_qualifies_for_release() {
        let mut h = history();
        assert!(terminal_for_inspection(&h, TransactionState::Indeterminate).is_err());
        h.confirmed = Some(record(Phase::Confirmed, 150));
        assert!(terminal_for_inspection(&h, TransactionState::Committed).is_err());
        h.confirmation = Some(record(Phase::ConfirmRequested, 120));
        assert!(terminal_for_inspection(&h, TransactionState::Indeterminate).is_err());
        assert!(terminal_for_inspection(&h, TransactionState::Verified).is_err());
        assert!(terminal_for_inspection(&h, TransactionState::Committed).is_ok());
        h.revert = Some(record(Phase::RevertRequested, 130));
        assert!(terminal_for_inspection(&h, TransactionState::Committed).is_err());
    }

    #[test]
    fn rollback_and_committed_keep_have_separate_terminal_authority() {
        let mut h = history();
        h.restored = Some(record(Phase::Restored, 150));
        let (_, state, restored) = terminal_for_inspection(&h, TransactionState::RecoveryBlocked)
            .unwrap_or_else(|error| unreachable!("{error:?}"));
        assert_eq!(state, "restored");
        assert!(restored);
        assert!(terminal_for_inspection(&h, TransactionState::Committed).is_err());
        h.confirmed = Some(record(Phase::Confirmed, 160));
        h.confirmation = Some(record(Phase::ConfirmRequested, 120));
        assert!(terminal_for_inspection(&h, TransactionState::RecoveryBlocked).is_err());
        assert!(terminal_for_inspection(&h, TransactionState::Committed).is_err());
    }
}
