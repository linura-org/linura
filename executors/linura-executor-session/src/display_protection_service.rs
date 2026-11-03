//! Independently supervised, bounded protection mechanisms. No output writes,
//! planning, policy, human approval, desired state or recovery orchestration.
use std::collections::BTreeMap;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use linura_linux_session::{
    NativeDisplayKernelSubscription, NativeDisplayRecoveryCheckpoint, NativeDisplayStartupPeer,
    NativeDisplayStartupRequest, NativeSessionChannel, NativeSessionRole,
};
use linura_provider_sdk::ComponentDigest;
use zbus::message::Header;
use zbus::zvariant::OwnedFd;

const INTERFACE_NAME: &str = "org.linura.DisplayProtection1";
const PATH: &str = "/org/linura/DisplayProtection1";
const MAX_PENDING: usize = 32;
const ORIGINAL_PROBE: Duration = Duration::from_secs(2);
const MAX_STARTUPS: usize = 64;

struct StartupLease {
    peer: NativeDisplayStartupPeer,
    ordinary: bool,
    // Never written, replaced or handed to another process. Closing this
    // original endpoint permanently revokes the compositor's native lease.
    _lease: UnixStream,
}
#[derive(Default)]
struct Admission {
    pending: BTreeMap<String, Pending<NativeDisplayKernelSubscription>>,
    startups: Vec<StartupLease>,
}

struct Pending<T> {
    started: Instant,
    sender: String,
    subscription: T,
}

#[derive(Clone)]
struct NativeProtection {
    channel: NativeSessionChannel,
    admission: Arc<Mutex<Admission>>,
    witnesses: Arc<super::display_kernel::Witnesses>,
}

fn unavailable() -> zbus::fdo::Error {
    zbus::fdo::Error::Failed("original display protection unavailable; no retry".into())
}
fn sender(header: &Header<'_>) -> zbus::fdo::Result<String> {
    header
        .sender()
        .map(|name| name.as_str().to_owned())
        .ok_or_else(|| {
            zbus::fdo::Error::AccessDenied("display protection has no authenticated caller".into())
        })
}
fn dispatch(raw: &str) -> zbus::fdo::Result<ComponentDigest> {
    let digest = ComponentDigest::parse_hex(raw).map_err(|_| unavailable())?;
    if digest.to_hex() != raw || digest == ComponentDigest::from_bytes([0; 32]) {
        return Err(unavailable());
    }
    Ok(digest)
}

fn consume<T>(
    pending: &mut BTreeMap<String, Pending<T>>,
    sender: &str,
    digest: &ComponentDigest,
    now: Instant,
) -> zbus::fdo::Result<T> {
    let original = pending.remove(&digest.to_hex()).ok_or_else(unavailable)?;
    if original.sender != sender
        || now
            .checked_duration_since(original.started)
            .is_none_or(|age| age >= ORIGINAL_PROBE)
    {
        return Err(unavailable());
    }
    Ok(original.subscription)
}
trait ProtectionPort: Clone + Send + Sync + 'static {
    fn startup(
        &self,
        sender: &str,
        request: NativeDisplayStartupRequest,
    ) -> zbus::fdo::Result<(OwnedFd, bool)>;
    fn begin(&self, sender: &str, dispatch: ComponentDigest) -> zbus::fdo::Result<bool>;
    fn reserve(&self, sender: &str, payload: &[u8]) -> zbus::fdo::Result<bool>;
    fn verify(&self, sender: &str, dispatch: ComponentDigest) -> zbus::fdo::Result<bool>;
}

#[derive(Clone)]
struct ProtectionService<P: ProtectionPort> {
    port: P,
    startup_pending: Arc<AtomicBool>,
}
impl<P: ProtectionPort> ProtectionService<P> {
    fn new(port: P) -> Self {
        Self {
            port,
            startup_pending: Arc::new(AtomicBool::new(false)),
        }
    }
}
struct StartupSlot(Arc<AtomicBool>);
impl StartupSlot {
    fn enter(pending: &Arc<AtomicBool>) -> zbus::fdo::Result<Self> {
        pending
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                zbus::fdo::Error::LimitsExceeded(
                    "native startup admission already in progress".into(),
                )
            })?;
        Ok(Self(Arc::clone(pending)))
    }
}
impl Drop for StartupSlot {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl NativeProtection {
    fn admit(&self, sender: &str) -> zbus::fdo::Result<()> {
        self.channel
            .require_trusted_display_executor_sender(sender)
            .map_err(|_| {
                zbus::fdo::Error::AccessDenied(
                    "display protection requires the supervised executor".into(),
                )
            })
    }
}

impl ProtectionPort for NativeProtection {
    fn startup(
        &self,
        sender: &str,
        request: NativeDisplayStartupRequest,
    ) -> zbus::fdo::Result<(OwnedFd, bool)> {
        let peer =
            self.channel
                .admit_display_startup(sender, &request)
                .map_err(|_| {
                    zbus::fdo::Error::AccessDenied(
                "native startup requires the supervised owner and its original local session".into()
            )
                })?;
        let mut admission = self.admission.try_lock().map_err(|_| unavailable())?;
        admission
            .pending
            .retain(|_, pending| pending.started.elapsed() < ORIGINAL_PROBE);
        if admission.startups.len() >= MAX_STARTUPS
            || admission.startups.iter().any(|old| {
                old.peer.reuses_compositor(&peer)
                    || old.peer.same_login(&peer) && !old.peer.definitely_exited()
            })
        {
            return Err(unavailable());
        }
        let ordinary = admission.pending.is_empty()
            && super::display_checkpoint::startup_clear().map_err(|_| unavailable())?;
        let (lease, native) = UnixStream::pair().map_err(|_| unavailable())?;
        // Re-authenticate after the history scan and before publishing. A lost
        // reply leaves this admission consumed; there is no transparent retry.
        let fresh = self
            .channel
            .admit_display_startup(sender, &request)
            .map_err(|_| unavailable())?;
        if !peer.same_invocation(&fresh) {
            return Err(unavailable());
        }
        peer.live().map_err(|_| unavailable())?;
        admission.startups.push(StartupLease {
            peer,
            ordinary,
            _lease: lease,
        });
        Ok((OwnedFd::from(std::os::fd::OwnedFd::from(native)), ordinary))
    }
    fn begin(&self, sender: &str, digest: ComponentDigest) -> zbus::fdo::Result<bool> {
        self.admit(sender)?;
        let mut admission = self.admission.try_lock().map_err(|_| unavailable())?;
        let pending = &mut admission.pending;
        // Only never-dispatched subscriptions expire. Persisted attempts,
        // inhibitors and original witnesses have no automatic TTL cleanup.
        pending.retain(|_, value| value.started.elapsed() < ORIGINAL_PROBE);
        let key = digest.to_hex();
        if pending.len() >= MAX_PENDING || pending.contains_key(&key) {
            return Err(unavailable());
        }
        let started = Instant::now();
        let subscription = NativeDisplayKernelSubscription::begin().map_err(|_| unavailable())?;
        if started.elapsed() >= ORIGINAL_PROBE {
            return Err(unavailable());
        }
        self.admit(sender)?;
        pending.insert(
            key,
            Pending {
                started,
                sender: sender.into(),
                subscription,
            },
        );
        Ok(true)
    }
    fn reserve(&self, sender: &str, payload: &[u8]) -> zbus::fdo::Result<bool> {
        self.admit(sender)?;
        let digest =
            NativeDisplayRecoveryCheckpoint::stored_dispatch(payload).map_err(|_| unavailable())?;
        let mut admission = self.admission.try_lock().map_err(|_| unavailable())?;
        let subscription = consume(&mut admission.pending, sender, &digest, Instant::now())?;
        let (topology, integration) =
            NativeDisplayRecoveryCheckpoint::original_startup_scope(payload, &digest)
                .map_err(|_| unavailable())?;
        let startup = admission
            .startups
            .iter()
            .find(|startup| startup.peer.matches_preimage(&topology, &integration))
            .ok_or_else(unavailable)?;
        if !startup.ordinary {
            return Err(unavailable());
        }
        startup.peer.live().map_err(|_| unavailable())?;
        self.witnesses
            .reserve_stored(&digest, payload, subscription, &self.channel)
            .map_err(|_| unavailable())?;
        self.admit(sender)?;
        Ok(true)
    }
    fn verify(&self, sender: &str, digest: ComponentDigest) -> zbus::fdo::Result<bool> {
        self.admit(sender)?;
        self.witnesses
            .verify(&digest, &self.channel)
            .map_err(|_| unavailable())?;
        self.admit(sender)?;
        Ok(true)
    }
}

#[zbus::interface(name = "org.linura.DisplayProtection1")]
impl<P: ProtectionPort> ProtectionService<P> {
    #[zbus(out_args("lease", "ordinary_allowed"))]
    async fn native_startup(
        &self,
        request: (&str, u32, &str, &str, &str, &str),
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<(OwnedFd, bool)> {
        let sender = sender(&header)?;
        let (lock, pid, seat, compositor, integration, binary) = request;
        if lock.len() > 256 || seat.len() > 64 || compositor.len() > 36 {
            return Err(unavailable());
        }
        let lock = linura_core::SessionLockId::from_resource(
            &linura_core::ResourceId::new(lock).map_err(|_| unavailable())?,
        )
        .map_err(|_| unavailable())?;
        let request = NativeDisplayStartupRequest::new(
            lock,
            pid,
            seat.into(),
            compositor,
            dispatch(integration)?,
            dispatch(binary)?,
        )
        .map_err(|_| unavailable())?;
        // Default bus access to this one method cannot create an unbounded
        // blocking-authentication queue. The slot belongs to the actual worker,
        // including after a caller drops its pending reply.
        let slot = StartupSlot::enter(&self.startup_pending)?;
        let service = self.clone();
        blocking::unblock(move || {
            let _slot = slot;
            service.port.startup(&sender, request)
        })
        .await
    }
    #[zbus(out_args("accepted"))]
    async fn begin(
        &self,
        dispatch_digest: &str,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<bool> {
        let sender = sender(&header)?;
        let digest = dispatch(dispatch_digest)?;
        let service = self.clone();
        blocking::unblock(move || service.port.begin(&sender, digest)).await
    }

    #[zbus(out_args("accepted"))]
    async fn reserve(
        &self,
        checkpoint: &[u8],
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<bool> {
        let sender = sender(&header)?;
        if checkpoint.len() > 384 * 1024 {
            return Err(unavailable());
        }
        let payload = checkpoint.to_vec();
        let service = self.clone();
        blocking::unblock(move || service.port.reserve(&sender, &payload)).await
    }

    #[zbus(out_args("accepted"))]
    async fn verify(
        &self,
        dispatch_digest: &str,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<bool> {
        let sender = sender(&header)?;
        let digest = dispatch(dispatch_digest)?;
        let service = self.clone();
        blocking::unblock(move || service.port.verify(&sender, digest)).await
    }
}

pub(super) fn serve() -> Result<(), String> {
    let channel = NativeSessionChannel::connect(NativeSessionRole::DisplayProtection)?;
    let connection = channel.service_connection();
    let service = super::introspection::SessionContract(ProtectionService::new(NativeProtection {
        channel: channel.clone(),
        admission: Arc::new(Mutex::new(Admission::default())),
        witnesses: Arc::new(super::display_kernel::Witnesses::default()),
    }));
    connection
        .object_server()
        .at(PATH, service)
        .map_err(|_| format!("{INTERFACE_NAME} registration failed"))?;
    channel.publish_display_protection()?;
    // Loss of the original bus is irreversible. Exiting closes every original
    // startup lease and retained protection; a new service cannot reacquire it.
    connection.closed();
    Err("original display protection bus was lost; no reconnection".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zbus::object_server::Interface;

    #[derive(Clone)]
    struct DenyProtection;
    impl ProtectionPort for DenyProtection {
        fn startup(
            &self,
            _: &str,
            _: NativeDisplayStartupRequest,
        ) -> zbus::fdo::Result<(OwnedFd, bool)> {
            Err(unavailable())
        }
        fn begin(&self, _: &str, _: ComponentDigest) -> zbus::fdo::Result<bool> {
            Err(unavailable())
        }
        fn reserve(&self, _: &str, _: &[u8]) -> zbus::fdo::Result<bool> {
            Err(unavailable())
        }
        fn verify(&self, _: &str, _: ComponentDigest) -> zbus::fdo::Result<bool> {
            Err(unavailable())
        }
    }

    #[test]
    fn private_service_has_no_effect_or_orchestration_endpoint() {
        let mut xml = String::new();
        let service =
            super::super::introspection::SessionContract(ProtectionService::new(DenyProtection));
        service.introspect_to_writer(&mut xml, 0);
        assert!(xml.contains("org.linura.DisplayProtection1"));
        let canonical = include_str!("../../../interfaces/dbus/org.linura.DisplayProtection1.xml");
        for text in [&xml, canonical] {
            assert_eq!(text.matches("<method ").count(), 4);
            for marker in [
                "name=\"request\" type=\"(sussss)\" direction=\"in\"",
                "name=\"lease\" type=\"h\" direction=\"out\"",
                "name=\"ordinary_allowed\" type=\"b\" direction=\"out\"",
                "name=\"dispatch_digest\" type=\"s\" direction=\"in\"",
                "name=\"checkpoint\" type=\"ay\" direction=\"in\"",
                "name=\"accepted\" type=\"b\" direction=\"out\"",
                "name=\"org.linura.ContractId\" value=\"dbus.org.linura.DisplayProtection1\"",
                "name=\"org.linura.ContractVersion\" value=\"1\"",
                "name=\"org.linura.Stability\" value=\"experimental\"",
            ] {
                assert!(text.contains(marker), "{marker}");
            }
        }
        for method in ["Begin", "Reserve", "Verify"] {
            assert!(xml.contains(&format!("name=\"{method}\"")));
        }
        for forbidden in ["Apply", "Confirm", "Revert", "Execute", "Unlock", "Suspend"] {
            assert!(!xml.contains(&format!("name=\"{forbidden}\"")));
        }
    }

    #[test]
    fn startup_work_remains_bounded_until_the_worker_releases_its_slot() {
        let pending = Arc::new(AtomicBool::new(false));
        let slot = StartupSlot::enter(&pending).unwrap_or_else(|e| unreachable!("{e}"));
        let (entered, receive_entered) = std::sync::mpsc::channel();
        let (release, receive_release) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let _slot = slot;
            entered.send(()).unwrap_or_else(|e| unreachable!("{e}"));
            receive_release
                .recv()
                .unwrap_or_else(|e| unreachable!("{e}"));
        });
        receive_entered
            .recv()
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert!(StartupSlot::enter(&pending).is_err());
        release.send(()).unwrap_or_else(|e| unreachable!("{e}"));
        worker.join().unwrap_or_else(|_| unreachable!());
        assert!(StartupSlot::enter(&pending).is_ok());
    }

    #[test]
    fn malformed_or_zero_dispatch_is_never_a_protection_scope() {
        for raw in [
            String::new(),
            "0".repeat(64),
            "A".repeat(64),
            "a".repeat(63),
        ] {
            assert!(dispatch(&raw).is_err());
        }
        assert!(dispatch(&"ab".repeat(32)).is_ok());
    }
    #[test]
    fn original_subscription_is_consumed_once_in_the_same_executor_and_window() {
        let digest = ComponentDigest::from_bytes([1; 32]);
        let started = Instant::now();
        let mut pending = BTreeMap::new();
        for (sender, now, succeeds) in [
            (":1.7", started, true),
            (":1.8", started, false),
            (":1.7", started + ORIGINAL_PROBE, false),
            (":1.7", started - Duration::from_millis(1), false),
        ] {
            pending.insert(
                digest.to_hex(),
                Pending {
                    started,
                    sender: ":1.7".into(),
                    subscription: 42,
                },
            );
            let result = consume(&mut pending, sender, &digest, now);
            assert_eq!(result.is_ok(), succeeds);
            if succeeds {
                assert_eq!(result.ok(), Some(42));
            }
            assert!(consume(&mut pending, ":1.7", &digest, started).is_err());
            assert!(pending.is_empty());
        }
    }

    #[test]
    fn protection_rpc_requires_transport_sender_and_bounded_correlation() {
        let service = ProtectionService::new(DenyProtection);
        let anonymous = zbus::Message::method_call(PATH, "Begin")
            .unwrap_or_else(|e| unreachable!("{e}"))
            .build(&())
            .unwrap_or_else(|e| unreachable!("{e}"));
        let digest = ComponentDigest::from_bytes([1; 32]).to_hex();
        assert!(matches!(
            async_io::block_on(service.begin(&digest, anonymous.header())),
            Err(zbus::fdo::Error::AccessDenied(_))
        ));
        let message = zbus::Message::method_call(PATH, "Begin")
            .unwrap_or_else(|e| unreachable!("{e}"))
            .sender(":1.7")
            .unwrap_or_else(|e| unreachable!("{e}"))
            .build(&())
            .unwrap_or_else(|e| unreachable!("{e}"));
        // A current bus sender and valid digest cannot acquire a protection by
        // themselves. The production port also requires exact service admission.
        assert!(async_io::block_on(service.begin(&digest, message.header())).is_err());
        assert!(async_io::block_on(service.verify(&digest, message.header())).is_err());
        assert!(
            async_io::block_on(service.reserve(b"historical bytes", message.header())).is_err()
        );
        assert!(async_io::block_on(service.begin(&"0".repeat(64), message.header())).is_err());
        assert!(
            async_io::block_on(service.reserve(&vec![0; 384 * 1024 + 1], message.header()))
                .is_err()
        );
    }
}
