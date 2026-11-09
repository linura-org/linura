#![forbid(unsafe_code)]

//! S18-5 event authority composition, deliberately distinct from desired-state
//! convergence. Only a noncloneable Control AuthorizedEffect can enter this
//! boundary. A durable one-use attempt is written *before* native RequestScan.
//! A missing, corrupt or indeterminate journal never enables a retry.

use std::thread;
use std::time::Duration;

use linura_control::AuthorizedEffect;
use linura_core::RequestId;
use linura_linux_session::{
    NativeSessionChannel, NativeWifiScanCompletion, NativeWifiScanSample, NativeWifiScanScope,
};
use linura_persistence_sqlite::{
    SqliteWifiScanAttemptJournal, WifiScanAttempt, WifiScanNativeEvidence,
};
use linura_provider_sdk::{
    EffectDescriptor, ExecutionBinding, ExecutionDisposition, ExecutionOutcome,
};
use linura_transaction::{TransactionId, digest_parts};

const SETTLE_ATTEMPTS: usize = 30;
const SETTLE_INTERVAL: Duration = Duration::from_millis(100);

/// Terminal receipt for this invocation. Indeterminate is *not* permission
/// to redispatch, recover via an old permit, or infer completion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WifiScanEventOutcome {
    IndependentlyObserved { last_scan_boot_ms: u64 },
    Indeterminate,
}

trait WifiScanNativePort {
    fn preflight(&self, scope: &NativeWifiScanScope) -> Result<NativeWifiScanSample, String>;
    fn dispatch(
        &self,
        effect: EffectDescriptor,
        binding: ExecutionBinding,
        scope: &NativeWifiScanScope,
    ) -> Result<ExecutionOutcome, String>;
    fn completion(
        &self,
        scope: &NativeWifiScanScope,
        started_boot_ms: u64,
    ) -> Result<Option<NativeWifiScanCompletion>, String>;
}

impl WifiScanNativePort for NativeSessionChannel {
    fn preflight(&self, scope: &NativeWifiScanScope) -> Result<NativeWifiScanSample, String> {
        self.native_wifi_scan_sample(scope)
    }
    fn dispatch(
        &self,
        effect: EffectDescriptor,
        binding: ExecutionBinding,
        scope: &NativeWifiScanScope,
    ) -> Result<ExecutionOutcome, String> {
        self.dispatch_sealed_wifi_scan(effect, binding, scope)
    }
    fn completion(
        &self,
        scope: &NativeWifiScanScope,
        started_boot_ms: u64,
    ) -> Result<Option<NativeWifiScanCompletion>, String> {
        self.observe_sealed_wifi_scan_completion(scope, started_boot_ms)
    }
}

/// Hash only canonical nonsecret identity material; not an approval/permit.
pub fn scan_device_binding(scope: &NativeWifiScanScope) -> Result<String, String> {
    let lock = scope.lock.resource_id().map_err(|e| e.to_string())?;
    let path = scope.device.object().native_path();
    let ns = scope.device.namespace_inode().to_string();
    let ifindex = scope.device.ifindex().to_string();
    let generation = scope.device.generation().to_string();
    Ok(format!(
        "sha256:{}",
        digest_parts(
            "linura.s18.wifi-scan.original-native-binding.v1",
            [
                scope.network.boot().as_str().as_bytes(),
                scope.network.bus().as_str().as_bytes(),
                scope.network.owner().as_str().as_bytes(),
                path.as_bytes(),
                scope.device.interface().as_str().as_bytes(),
                ns.as_bytes(),
                ifindex.as_bytes(),
                generation.as_bytes(),
                lock.as_str().as_bytes(),
                scope.principal.as_str().as_bytes(),
                scope.seat.as_bytes(),
            ]
        ).hex()
    ))
}

/// This entry can only consume an already minted, non-cloneable Control
/// permit. It does not mint approval from a native observation, nor register
/// a client mutation route or alter S18's deny-before-prepare invariant.
pub fn execute_authorized_wifi_scan(
    channel: &NativeSessionChannel,
    journal: &mut SqliteWifiScanAttemptJournal,
    authorization: AuthorizedEffect,
    scope: NativeWifiScanScope,
    request_id: &str,
) -> Result<WifiScanEventOutcome, String> {
    let (effect, binding) = authorization.into_executor_request();
    execute_spent_event(channel, journal, effect, binding, scope, request_id, SETTLE_ATTEMPTS, SETTLE_INTERVAL)
}

#[allow(clippy::too_many_arguments)]
fn execute_spent_event<N: WifiScanNativePort>(
    native: &N,
    journal: &mut SqliteWifiScanAttemptJournal,
    effect: EffectDescriptor,
    binding: ExecutionBinding,
    mut scope: NativeWifiScanScope,
    request_id: &str,
    attempts: usize,
    interval: Duration,
) -> Result<WifiScanEventOutcome, String> {
    // Never trust caller-provided "already fenced" Boolean material. Only
    // this orchestration sets it after the SQLite FULL-sync commit succeeds.
    scope.durable_attempt_fenced = false;
    let request = RequestId::new(request_id.to_owned()).map_err(|e| e.to_string())?;
    if !request_id.starts_with("request:v010:wifi-scan:") ||
        binding.transaction_id != TransactionId::for_namespace(&scope.principal, &request).as_str()
    {
        return Err("scan request is not the exact original Control transaction".into());
    }
    binding.validate_for(&effect).map_err(|e| e.to_string())?;
    let pre = native.preflight(&scope)?;
    if pre.network != scope.network || pre.device != scope.device ||
        pre.last_scan_boot_ms != scope.baseline_last_scan_boot_ms ||
        pre.scanning || pre.sampled_boot_us == 0
    {
        return Err("native scan preflight does not match the original device".into());
    }
    let mut validated = scope.clone();
    validated.durable_attempt_fenced = true;
    validated.validate(&effect, &binding, pre.sampled_boot_us)?;
    let started_ms = pre.sampled_boot_us / 1_000;
    let device_binding = scan_device_binding(&scope)?;
    let dispatch_digest = format!("sha256:{}", binding.dispatch_digest.to_hex());
    let attempt = WifiScanAttempt {
        request_id: request_id.to_owned(),
        principal: scope.principal.as_str().to_owned(),
        device_binding: device_binding.clone(),
        boot_id: scope.network.boot().as_str().to_owned(),
        dispatch_digest: dispatch_digest.clone(),
        started_boot_ms: started_ms,
        baseline_last_scan_ms: scope.baseline_last_scan_boot_ms,
    };
    // Journal.begin commits the one-use attempt before the first native call.
    // A crash/ENOSPC here means no dispatch. A failure after this line means
    // the attempt remains spent/indeterminate and MUST NOT be replayed.
    journal.begin(attempt).map_err(|e| e.to_string())?;
    scope.durable_attempt_fenced = true;
    let result = native.dispatch(effect, binding.clone(), &scope);
    let Ok(outcome) = result else {
        return Ok(WifiScanEventOutcome::Indeterminate);
    };
    if outcome.dispatch_digest != binding.dispatch_digest ||
        outcome.disposition != ExecutionDisposition::Dispatched
    {
        return Ok(WifiScanEventOutcome::Indeterminate);
    }

    for index in 0..attempts.min(30) {
        let measured = native.completion(&scope, started_ms);
        match measured {
            Ok(Some(observation)) => {
                if observation.network != scope.network || observation.device != scope.device ||
                    observation.sampled_boot_us / 1_000 < observation.last_scan_boot_ms
                {
                    return Ok(WifiScanEventOutcome::Indeterminate);
                }
                let evidence = WifiScanNativeEvidence {
                    request_id: request_id.to_owned(),
                    device_binding,
                    boot_id: scope.network.boot().as_str().to_owned(),
                    dispatch_digest,
                    last_scan_boot_ms: observation.last_scan_boot_ms,
                    independently_sampled_boot_ms: observation.sampled_boot_us / 1_000,
                };
                journal.verified_native(&evidence).map_err(|e| e.to_string())?;
                return Ok(WifiScanEventOutcome::IndependentlyObserved {
                    last_scan_boot_ms: observation.last_scan_boot_ms,
                });
            }
            Ok(None) => {
                if index + 1 < attempts.min(30) {
                    thread::sleep(interval);
                }
            }
            Err(_) => return Ok(WifiScanEventOutcome::Indeterminate),
        }
    }
    Ok(WifiScanEventOutcome::Indeterminate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_core::{
        BootId, NetworkDeviceId, NetworkInterfaceName, NetworkManagerEpoch, NetworkManagerOwner,
        NetworkObjectId, NetworkObjectKind, NetworkObservationId, PrincipalId, ProviderId,
        ResourceId, SecurityOwnerInvocationId, SessionEpoch, SessionLockId,
        SystemBusInstanceId,
    };
    use linura_persistence_sqlite::SqliteIntegrityKey;
    use linura_provider_sdk::ComponentDigest;
    use std::cell::Cell;
    use std::sync::atomic::{AtomicU64, Ordering};

    static ID: AtomicU64 = AtomicU64::new(0);

    fn ok<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|e| unreachable!("test fixture: {e:?}"))
    }

    struct Fake {
        source: NativeWifiScanSample,
        completed: Option<NativeWifiScanCompletion>,
        dispatches: Cell<u32>,
        wrong_digest: bool,
    }
    impl WifiScanNativePort for Fake {
        fn preflight(&self, _: &NativeWifiScanScope) -> Result<NativeWifiScanSample, String> {
            Ok(self.source.clone())
        }
        fn dispatch(&self, _: EffectDescriptor, binding: ExecutionBinding, scope: &NativeWifiScanScope)
            -> Result<ExecutionOutcome, String> {
            assert!(scope.durable_attempt_fenced, "journal must be spent before dispatch");
            self.dispatches.set(self.dispatches.get() + 1);
            ExecutionOutcome::new(
                ExecutionDisposition::Dispatched,
                if self.wrong_digest { ComponentDigest::from_bytes([0x99; 32]) } else { binding.dispatch_digest },
                "isolated fake; no real NetworkManager effect",
            ).map_err(|e| e.to_string())
        }
        fn completion(&self, _: &NativeWifiScanScope, _: u64)
            -> Result<Option<NativeWifiScanCompletion>, String> {
            Ok(self.completed.clone())
        }
    }

    fn fixture() -> (NativeWifiScanScope, EffectDescriptor, ExecutionBinding, Fake) {
        let boot = ok(BootId::new("abcd1234-1234-4567-89ab-0123456789ab"));
        let network = NetworkManagerEpoch::new(
            boot.clone(),
            ok(SystemBusInstanceId::new("fedcba9876543210abcdef0123456789")),
            ok(NetworkManagerOwner::new(":1.48")),
        );
        let device = ok(NetworkDeviceId::new(
            network.clone(),
            ok(NetworkObjectId::from_path(NetworkObjectKind::Device, "/org/freedesktop/NetworkManager/Devices/8")),
            12456, 7, ok(NetworkInterfaceName::new("wlan0")), 8,
        ));
        let lock = ok(SessionLockId::new(
            ok(SessionEpoch::new(boot, 1000, "2", 42)),
            ok(SecurityOwnerInvocationId::new("98765432-1234-4567-89ab-0123456789ab")),
            1,
        ));
        let scope = NativeWifiScanScope {
            lock, principal: ok(PrincipalId::new("unix:uid:1000")),
            network: network.clone(), device: device.clone(),
            observation: ok(NetworkObservationId::new(network.clone(), 4, 100_000_000)),
            seat: "seat0".into(), baseline_last_scan_boot_ms: 30_000,
            durable_attempt_fenced: false,
        };
        let effect = ok(EffectDescriptor::new(
            ok(ProviderId::new("networkmanager")), ok(ResourceId::new("networkmanager:wifi:wlan0")),
            "request-wifi-scan", b"scan_requested=true\n".to_vec(),
        ));
        let request = ok(RequestId::new("request:v010:wifi-scan:fixture"));
        let transaction = TransactionId::for_namespace(&scope.principal, &request);
        let binding = ok(ExecutionBinding::new(
            transaction.as_str(), 0, 1,
            ComponentDigest::from_bytes([1; 32]), ComponentDigest::from_bytes([2; 32]),
            &effect,
        ));
        let source = NativeWifiScanSample {
            network: network.clone(), device: device.clone(), last_scan_boot_ms: 30_000,
            scanning: false, sampled_boot_us: 101_000_000,
        };
        let completed = NativeWifiScanCompletion {
            network, device, last_scan_boot_ms: 101_005, sampled_boot_us: 101_030_000,
        };
        (scope, effect, binding, Fake { source, completed: Some(completed), dispatches: Cell::new(0), wrong_digest: false })
    }

    #[test]
    fn durable_one_use_attempt_precedes_dispatch_and_replay_is_denied() {
        let (scope, effect, binding, native) = fixture();
        let path = std::env::temp_dir().join(format!("linura-wifi-event-{}-{}.db", std::process::id(), ID.fetch_add(1, Ordering::Relaxed)));
        let key = || ok(SqliteIntegrityKey::new(vec![0x33; 32]));
        let mut journal = ok(SqliteWifiScanAttemptJournal::initialize(&path, key()));
        assert!(matches!(
            execute_spent_event(&native, &mut journal, effect.clone(), binding.clone(), scope.clone(),
                "request:v010:wifi-scan:fixture", 1, Duration::ZERO),
            Ok(WifiScanEventOutcome::IndependentlyObserved { last_scan_boot_ms: 101_005 })
        ));
        assert_eq!(native.dispatches.get(), 1);
        let mut recovered = ok(SqliteWifiScanAttemptJournal::open(&path, key()));
        assert!(execute_spent_event(&native, &mut recovered, effect, binding, scope,
            "request:v010:wifi-scan:fixture", 1, Duration::ZERO).is_err());
        assert_eq!(native.dispatches.get(), 1);
        drop(recovered);
        drop(journal);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn no_evidence_or_mismatched_dispatch_remains_permanently_spent() {
        let (scope, effect, binding, mut native) = fixture();
        native.completed = None;
        let path = std::env::temp_dir().join(format!("linura-wifi-event-{}-{}.db", std::process::id(), ID.fetch_add(1, Ordering::Relaxed)));
        let mut journal = ok(SqliteWifiScanAttemptJournal::initialize(&path, ok(SqliteIntegrityKey::new(vec![0x33; 32]))));
        assert_eq!(
            execute_spent_event(&native, &mut journal, effect.clone(), binding.clone(), scope.clone(),
                "request:v010:wifi-scan:fixture", 1, Duration::ZERO).unwrap_or_else(|error| unreachable!("fixture: {error}")),
            WifiScanEventOutcome::Indeterminate
        );
        assert!(execute_spent_event(&native, &mut journal, effect, binding, scope,
            "request:v010:wifi-scan:fixture", 1, Duration::ZERO).is_err());
        assert_eq!(native.dispatches.get(), 1);
        drop(journal);
        let _ = std::fs::remove_file(path);
    }
}
