//! Received-native-event composition only. Control owns coverage coordination,
//! deadlines, inventory and the single canonical protective managed lifecycle.
use std::sync::{Arc, Mutex};

use linura_control::{
    AuthenticatedPrincipal, ManagedLifecycleControl, NativeSleepCoveragePort,
    NativeSleepGateMonitor, coordinate_native_sleep_coverage,
};
use linura_core::{CapabilityId, SessionEpoch, SessionLockId, SleepInvocationId};
use linura_dbus::NativeSleepGateHandler;
use linura_linux_observation::LogindSessionObserver;
use linura_linux_session::{NativeSessionChannel, NativeSleepEntryBinding};
use linura_observation::ObservationEnvelope;
use linura_persistence_sqlite::SqliteTransactionStore;
use linura_provider_sdk::Observer;

use crate::session_adapter::{FreshSessionVerifier, SessionExecutorClient};

pub(crate) struct NativeSleepGate {
    control: Arc<Mutex<ManagedLifecycleControl<SqliteTransactionStore>>>,
    channel: NativeSessionChannel,
    binding: NativeSleepEntryBinding,
    monitor: NativeSleepGateMonitor,
    sessions: LogindSessionObserver,
    executor: SessionExecutorClient,
    verifier: FreshSessionVerifier,
}
impl NativeSleepGate {
    pub(crate) fn new(
        control: Arc<Mutex<ManagedLifecycleControl<SqliteTransactionStore>>>,
        channel: NativeSessionChannel,
        binding: NativeSleepEntryBinding,
        monitor: NativeSleepGateMonitor,
    ) -> Result<Self, String> {
        Ok(Self {
            control,
            channel: channel.clone(),
            binding,
            monitor,
            sessions: LogindSessionObserver::connect().map_err(|e| e.to_string())?,
            executor: SessionExecutorClient {
                channel: channel.clone(),
            },
            verifier: FreshSessionVerifier {
                channel,
                sequence: 0,
                transitions: LogindSessionObserver::connect().map_err(|e| e.to_string())?,
            },
        })
    }
}

impl NativeSleepGateHandler for NativeSleepGate {
    fn protect_received_helper(&mut self, sender: &str) -> Result<(), String> {
        // The principal is constructed below only inside this attested scope.
        // Metadata is from the received header, never method arguments.
        let scope = self
            .binding
            .begin_received_sender(sender)
            .map_err(|error| denied("attestation", &error))?;
        let event = scope.event().clone();
        let attempt = self
            .monitor
            .begin_attested_entry(&event)
            .map_err(|error| denied("entry", &error))?;
        coordinate_native_sleep_coverage(&mut ScopedCoverage { gate: self, sender }, &event)
            .map_err(|error| denied("coverage", &error))?;
        attempt
            .coverage_fenced()
            .map_err(|error| denied("completion", &error))
        // Scope lifetime ends here. Native coverage fences outlive it and are
        // retired independently only after the exact native job has ended.
    }
}

// Failure-only observability. Never copy the sender or the original error: those
// can contain transport/provider input. The journal is not observation evidence
// and a diagnostic cannot permit continuation, retry or additional time.
fn denied(stage: &str, error: &str) -> String {
    let reason = match error {
        "native sleep helper process image is unavailable" => "helper-image",
        "native sleep helper arguments are unavailable"
        | "native sleep helper arguments cannot be read" => "helper-arguments",
        "native sleep helper process does not match the fixed image and arguments" => {
            "helper-mismatch"
        }
        "native sleep helper has the wrong kernel identity" => "helper-identity",
        "caller is not the exact immutable supervised pre-sleep helper" => "unit-contract",
        "native sleep unit has an unsupported additional program" => "unit-programs",
        "native sleep unit property is malformed" => "unit-codec",
        "native service array field is absent"
        | "native service array field is unavailable"
        | "native service array field has the wrong type" => "unit-codec",
        "native session call failed: class=access-denied; stage=mechanism" => "transport-denied",
        "native session call failed: class=no-reply; stage=mechanism" => "transport-timeout",
        "native process generation is unavailable" | "native process generation cannot be read" => {
            "process-generation"
        }
        "native sleep gate assets are not immutable root-owned files" => "assets",
        "native sleep helper generation changed"
        | "native sleep helper or boot changed during attestation" => "generation",
        "native sleep entry attestation expired"
        | "native sleep coverage gate exceeded its original deadline" => "deadline",
        "native sleep supervisor is not root" => "supervisor",
        "native sleep gate has no qualified graphical session" => "no-session",
        "native sleep inventory contains an unsupported session type/class"
        | "native session inventory has incomplete type/class state" => "session-class",
        "native sleep session inventory exceeds its bound"
        | "native sleep session inventory has a duplicate epoch or changed boot"
        | "native sleep session inventory is not authoritative for its epoch"
        | "native graphical session inventory changed; sleep denied" => "session-inventory",
        "managed Control is busy or poisoned; native sleep denied" => "control-busy",
        "native sleep coverage generation changed" => "coverage-generation",
        "native sleep coverage fence was refused" => "fence-refused",
        _ => "unclassified",
    };
    let stage = match stage {
        "attestation" | "entry" | "coverage" | "completion" => stage,
        _ => "unclassified",
    };
    format!("native-sleep-gate-denied stage={stage} reason={reason}")
}

struct ScopedCoverage<'a> {
    gate: &'a mut NativeSleepGate,
    sender: &'a str,
}
impl NativeSleepCoveragePort for ScopedCoverage<'_> {
    fn session_epochs(&mut self) -> Result<Vec<SessionEpoch>, String> {
        self.gate
            .sessions
            .resources()
            .map_err(|e| e.to_string())?
            .iter()
            .map(|resource| SessionEpoch::from_resource(resource).map_err(|e| e.to_string()))
            .collect()
    }
    fn observe_session(&mut self, epoch: &SessionEpoch) -> Result<ObservationEnvelope, String> {
        self.gate
            .sessions
            .observe_authoritative(
                &epoch.resource_id().map_err(|e| e.to_string())?,
                &CapabilityId::new("session.epoch.observe").map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())
    }
    fn observe_lock(&mut self, epoch: &SessionEpoch) -> Result<ObservationEnvelope, String> {
        self.gate.channel.observe_current_lock(epoch.uid(), 1)
    }
    fn converge_protective_lock(
        &mut self,
        event: &SleepInvocationId,
        lock: &SessionLockId,
    ) -> Result<(), String> {
        // Nonblocking admission is mandatory: a managed suspend may hold this
        // mutex awaiting this helper. Already-secure coordination never enters
        // this method or accesses consent/managed execution at all.
        let mut control = self
            .gate
            .control
            .try_lock()
            .map_err(|_| "managed Control is busy or poisoned; native sleep denied")?;
        let principal = AuthenticatedPrincipal::new("service:system-sleep-protection")
            .map_err(|e| e.to_string())?;
        control
            .converge_protective_session_lock(
                principal,
                event.clone(),
                lock.clone(),
                &mut self.gate.executor,
                &mut self.gate.verifier,
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    fn fence_coverage(
        &mut self,
        event: &SleepInvocationId,
        lock: &SessionLockId,
    ) -> Result<bool, String> {
        self.gate.channel.fence_native_sleep_entry(event, lock)
    }
    fn revalidate_entry(&mut self, event: &SleepInvocationId) -> Result<(), String> {
        if self
            .gate
            .channel
            .attest_sleep_entry_sender(self.sender, 1)?
            .event()
            != event
        {
            return Err("native sleep entry changed before continuation".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::denied;

    #[test]
    fn denial_diagnostics_are_closed_and_never_copy_private_error_or_stage_text() {
        assert_eq!(
            denied(
                "attestation",
                "native sleep helper process image is unavailable"
            ),
            "native-sleep-gate-denied stage=attestation reason=helper-image"
        );
        assert_eq!(
            denied("coverage", "native sleep coverage fence was refused"),
            "native-sleep-gate-denied stage=coverage reason=fence-refused"
        );
        for error in [
            "private-wire-marker",
            "native sleep helper process image is unavailable\nprivate-wire-marker",
            "native sleep helper process image is unavailable private-wire-marker",
        ] {
            assert_eq!(
                denied("private-wire-marker", error),
                "native-sleep-gate-denied stage=unclassified reason=unclassified"
            );
        }
    }
}
