//! Independently supervised, bounded protection mechanisms. No output writes,
//! planning, policy, human approval, desired state or recovery orchestration.
use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use linura_linux_session::{
    MAX_NATIVE_DISPLAY_RESTORATION_RESERVATION, NativeDisplayKernelSubscription,
    NativeDisplayRecoveryCheckpoint, NativeDisplayRestorationReservation, NativeDisplayStartupPeer,
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
impl StartupLease {
    fn live(&self) -> Result<(), String> {
        self.peer.live()?;
        let mut event = [rustix::event::PollFd::new(
            &self._lease,
            rustix::event::PollFlags::IN,
        )];
        if rustix::event::poll(
            &mut event,
            Some(&rustix::event::Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            }),
        )
        .map_err(|_| "native startup lease observation failed")?
            != 0
            || !event[0].revents().is_empty()
        {
            return Err("original native startup lease unavailable; no reconnection".into());
        }
        Ok(())
    }
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
    transfer_pending: Arc<AtomicBool>,
}

fn unavailable() -> zbus::fdo::Error {
    zbus::fdo::Error::Failed("original display protection unavailable; no retry".into())
}
fn startup_unavailable(stage: &'static str) -> zbus::fdo::Error {
    // Only compile-time stage labels, never request data or underlying errors.
    eprintln!("display-protection: native-startup/{stage}");
    unavailable()
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
    fn reserve_restoration(
        &self,
        sender: &str,
        record: NativeDisplayRestorationReservation,
    ) -> zbus::fdo::Result<OwnedFd>;
    fn read_original(
        &self,
        sender: &str,
        scope: linura_core::DisplayRecoveryScope,
    ) -> zbus::fdo::Result<Vec<u8>>;
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
    original_pending: Arc<AtomicBool>,
    restoration_pending: Arc<AtomicBool>,
}
impl<P: ProtectionPort> ProtectionService<P> {
    fn new(port: P) -> Self {
        Self {
            port,
            startup_pending: Arc::new(AtomicBool::new(false)),
            original_pending: Arc::new(AtomicBool::new(false)),
            restoration_pending: Arc::new(AtomicBool::new(false)),
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
                    "display protection admission or observation already in progress".into(),
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

fn write_grant(
    writer: &mut UnixStream,
    bytes: &[u8],
    budget: Duration,
    mut verify: impl FnMut() -> zbus::fdo::Result<()>,
) -> zbus::fdo::Result<()> {
    if bytes.len() > 384 * 1024 + MAX_NATIVE_DISPLAY_RESTORATION_RESERVATION + 23 {
        return Err(unavailable());
    }
    let deadline = Instant::now().checked_add(budget).ok_or_else(unavailable)?;
    // A complete frame also requires this final marker, disclosed only after
    // fresh retained-witness checks. EOF or partial bytes cannot mean success.
    for mut rest in [bytes, b"LNRG-END:1\n".as_slice()] {
        while !rest.is_empty() {
            verify()?;
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .ok_or_else(unavailable)?;
            let part = &rest[..rest.len().min(64 * 1024)];
            match writer.write(part) {
                Ok(0) => return Err(unavailable()),
                Ok(written) => rest = &rest[written..],
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    let mut events = [rustix::event::PollFd::new(
                        &*writer,
                        rustix::event::PollFlags::OUT,
                    )];
                    let timeout = rustix::event::Timespec {
                        tv_sec: i64::try_from(remaining.as_secs()).map_err(|_| unavailable())?,
                        tv_nsec: i64::from(remaining.subsec_nanos()),
                    };
                    if rustix::event::poll(&mut events, Some(&timeout))
                        .map_err(|_| unavailable())?
                        != 1
                        || events[0].revents() != rustix::event::PollFlags::OUT
                    {
                        return Err(unavailable());
                    }
                }
                Err(_) => return Err(unavailable()),
            }
        }
    }
    Ok(())
}

impl NativeProtection {
    fn original_for_scope(
        &self,
        admission: &Admission,
        scope: &linura_core::DisplayRecoveryScope,
    ) -> zbus::fdo::Result<Vec<u8>> {
        // Serialize against startup, original reservation and future qualified
        // retirement. Reading neither consumes a grant nor releases a fence.
        let dispatch = dispatch(scope.original_dispatch())?;
        let payload = self
            .witnesses
            .read_original(&dispatch, &self.channel)
            .map_err(|_| unavailable())?;
        let (original, integration) =
            NativeDisplayRecoveryCheckpoint::original_startup_scope(&payload, &dispatch)
                .map_err(|_| unavailable())?;
        let current = scope.replacement();
        if original.session().boot() != current.session().boot()
            || original.session().uid() != current.session().uid()
            || original.seat() != current.seat()
            || original.compositor() == current.compositor()
        {
            return Err(unavailable());
        }
        let original = admission
            .startups
            .iter()
            .find(|startup| startup.peer.matches_preimage(&original, &integration))
            .ok_or_else(unavailable)?;
        let current = admission
            .startups
            .iter()
            .find(|startup| startup.peer.matches_preimage(current, &integration))
            .ok_or_else(unavailable)?;
        if !original.ordinary || !original.peer.definitely_exited() || current.ordinary {
            return Err(unavailable());
        }
        current.live().map_err(|_| unavailable())?;
        Ok(payload)
    }
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
    fn reserve_restoration(
        &self,
        sender: &str,
        record: NativeDisplayRestorationReservation,
    ) -> zbus::fdo::Result<OwnedFd> {
        let slot = StartupSlot::enter(&self.transfer_pending)?;
        self.admit(sender)?;
        let material = record.decoded_material().map_err(|_| unavailable())?;
        let scope = material.recovery_scope().map_err(|_| unavailable())?;
        let admission = self.admission.try_lock().map_err(|_| unavailable())?;
        let payload = self.original_for_scope(&admission, &scope)?;
        NativeDisplayRecoveryCheckpoint::validate_restoration_source(&payload, &record)
            .map_err(|_| unavailable())?;
        // Publication is exclusive and synced before creating/disclosing any
        // endpoint. All subsequent errors leave this attempt reserved.
        super::display_checkpoint::reserve_restoration(&record).map_err(|_| unavailable())?;
        self.admit(sender)?;
        self.original_for_scope(&admission, &scope)?;
        let (mut writer, native) = UnixStream::pair().map_err(|_| unavailable())?;
        writer.set_nonblocking(true).map_err(|_| unavailable())?;
        let encoded = record.canonical_bytes();
        let mut grant = b"LNRG:1\n".to_vec();
        grant.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
        grant.extend_from_slice(&encoded);
        grant.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        grant.extend_from_slice(&payload);
        let service = self.clone();
        drop(admission);
        std::thread::Builder::new()
            .name("display-original-grant".into())
            .spawn(move || {
                let _slot = slot;
                // An incomplete/slow reader, lost original witness or service bus
                // cannot extend this bounded transfer or obtain another endpoint.
                let _result = write_grant(&mut writer, &grant, Duration::from_secs(2), || {
                    let admission = service.admission.try_lock().map_err(|_| unavailable())?;
                    service.original_for_scope(&admission, &scope).map(|_| ())
                });
            })
            .map_err(|_| unavailable())?;
        Ok(OwnedFd::from(std::os::fd::OwnedFd::from(native)))
    }
    fn read_original(
        &self,
        sender: &str,
        scope: linura_core::DisplayRecoveryScope,
    ) -> zbus::fdo::Result<Vec<u8>> {
        let admit = || {
            self.channel
                .require_trusted_display_control_sender(sender)
                .map_err(|_| {
                    zbus::fdo::Error::AccessDenied(
                        "original display observation requires the supervised Control owner".into(),
                    )
                })
        };
        admit()?;
        let admission = self.admission.try_lock().map_err(|_| unavailable())?;
        let payload = self.original_for_scope(&admission, &scope)?;
        admit()?;
        self.original_for_scope(&admission, &scope)?;
        Ok(payload)
    }
    fn startup(
        &self,
        sender: &str,
        request: NativeDisplayStartupRequest,
    ) -> zbus::fdo::Result<(OwnedFd, bool)> {
        let peer =
            self.channel
                .admit_display_startup(sender, &request)
                .map_err(|_| {
                    // Fixed stage only. Never print a transport error, PID,
                    // checkpoint, scope, credential or caller-supplied bytes.
                    eprintln!("display-protection: native-startup/caller-session");
                    zbus::fdo::Error::AccessDenied(
                "native startup requires the supervised owner and its original local session".into()
            )
                })?;
        let mut admission = self
            .admission
            .try_lock()
            .map_err(|_| startup_unavailable("busy"))?;
        admission
            .pending
            .retain(|_, pending| pending.started.elapsed() < ORIGINAL_PROBE);
        if admission.startups.len() >= MAX_STARTUPS
            || admission.startups.iter().any(|old| {
                old.peer.reuses_compositor(&peer)
                    || old.peer.same_login(&peer) && !old.peer.definitely_exited()
            })
        {
            return Err(startup_unavailable("overlapping-invocation"));
        }
        let ordinary = admission.pending.is_empty()
            && super::display_checkpoint::startup_clear()
                .map_err(|_| startup_unavailable("history"))?;
        let (lease, native) = UnixStream::pair().map_err(|_| startup_unavailable("lease"))?;
        // Re-authenticate after the history scan and before publishing. A lost
        // reply leaves this admission consumed; there is no transparent retry.
        self.channel
            .revalidate_display_startup(sender, &request, &peer)
            .map_err(|_| startup_unavailable("revalidation"))?;
        peer.live()
            .map_err(|_| startup_unavailable("process-changed"))?;
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
        startup.live().map_err(|_| unavailable())?;
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
    #[zbus(out_args("grant"))]
    async fn reserve_restoration(
        &self,
        reservation: &[u8],
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<OwnedFd> {
        let sender = sender(&header)?;
        if reservation.len() > MAX_NATIVE_DISPLAY_RESTORATION_RESERVATION {
            return Err(unavailable());
        }
        let record =
            NativeDisplayRestorationReservation::decode(reservation).map_err(|_| unavailable())?;
        let slot = StartupSlot::enter(&self.restoration_pending)?;
        let service = self.clone();
        blocking::unblock(move || {
            let _slot = slot;
            service.port.reserve_restoration(&sender, record)
        })
        .await
    }
    #[zbus(out_args("checkpoint"))]
    async fn read_original(
        &self,
        recovery_scope: &str,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<Vec<u8>> {
        let sender = sender(&header)?;
        if recovery_scope.len() > 256 {
            return Err(unavailable());
        }
        let scope = linura_core::DisplayRecoveryScope::from_resource(
            &linura_core::ResourceId::new(recovery_scope).map_err(|_| unavailable())?,
        )
        .map_err(|_| unavailable())?;
        let slot = StartupSlot::enter(&self.original_pending)?;
        let service = self.clone();
        blocking::unblock(move || {
            let _slot = slot;
            service.port.read_original(&sender, scope)
        })
        .await
    }
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
        transfer_pending: Arc::new(AtomicBool::new(false)),
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
        fn reserve_restoration(
            &self,
            _: &str,
            _: NativeDisplayRestorationReservation,
        ) -> zbus::fdo::Result<OwnedFd> {
            Err(unavailable())
        }
        fn read_original(
            &self,
            _: &str,
            _: linura_core::DisplayRecoveryScope,
        ) -> zbus::fdo::Result<Vec<u8>> {
            Err(unavailable())
        }
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
            assert_eq!(text.matches("<method ").count(), 6);
            for marker in [
                "name=\"request\" type=\"(sussss)\" direction=\"in\"",
                "name=\"lease\" type=\"h\" direction=\"out\"",
                "name=\"ordinary_allowed\" type=\"b\" direction=\"out\"",
                "name=\"dispatch_digest\" type=\"s\" direction=\"in\"",
                "name=\"checkpoint\" type=\"ay\" direction=\"in\"",
                "name=\"recovery_scope\" type=\"s\" direction=\"in\"",
                "name=\"checkpoint\" type=\"ay\" direction=\"out\"",
                "name=\"reservation\" type=\"ay\" direction=\"in\"",
                "name=\"grant\" type=\"h\" direction=\"out\"",
                "name=\"accepted\" type=\"b\" direction=\"out\"",
                "name=\"org.linura.ContractId\" value=\"dbus.org.linura.DisplayProtection1\"",
                "name=\"org.linura.ContractVersion\" value=\"1\"",
                "name=\"org.linura.Stability\" value=\"experimental\"",
            ] {
                assert!(text.contains(marker), "{marker}");
            }
        }
        for method in [
            "Begin",
            "Reserve",
            "Verify",
            "ReadOriginal",
            "ReserveRestoration",
        ] {
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
    fn original_read_requires_transport_sender_exact_bounded_scope_and_live_port_admission() {
        let service = ProtectionService::new(DenyProtection);
        let anonymous = zbus::Message::method_call(PATH, "ReadOriginal")
            .unwrap_or_else(|e| unreachable!("{e}"))
            .build(&())
            .unwrap_or_else(|e| unreachable!("{e}"));
        let scope = format!(
            "display:recovery:{}:11111111-1111-4111-8111-111111111111:1000:c3:99:seat0:44444444-4444-4444-8444-444444444444:1",
            "a".repeat(64)
        );
        assert!(matches!(
            async_io::block_on(service.read_original(&scope, anonymous.header())),
            Err(zbus::fdo::Error::AccessDenied(_))
        ));
        let message = zbus::Message::method_call(PATH, "ReadOriginal")
            .unwrap_or_else(|e| unreachable!("{e}"))
            .sender(":1.7")
            .unwrap_or_else(|e| unreachable!("{e}"))
            .build(&())
            .unwrap_or_else(|e| unreachable!("{e}"));
        for bad in [
            String::new(),
            "a".repeat(64),
            "x".repeat(257),
            scope.replace(&"a".repeat(64), &"0".repeat(64)),
        ] {
            assert!(async_io::block_on(service.read_original(&bad, message.header())).is_err());
        }
        // A syntactically valid source and unique sender still cannot turn
        // comparison identity into native admission or historical bytes.
        assert!(async_io::block_on(service.read_original(&scope, message.header())).is_err());
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

    #[test]
    fn restoration_rpc_cannot_turn_well_formed_comparison_material_into_authority() {
        let service = ProtectionService::new(DenyProtection);
        let record = super::super::display_checkpoint::tests::restoration(1, 2);
        let bytes = record.canonical_bytes();
        let anonymous = zbus::Message::method_call(PATH, "ReserveRestoration")
            .unwrap_or_else(|e| unreachable!("{e}"))
            .build(&())
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert!(matches!(
            async_io::block_on(service.reserve_restoration(&bytes, anonymous.header())),
            Err(zbus::fdo::Error::AccessDenied(_))
        ));
        let message = zbus::Message::method_call(PATH, "ReserveRestoration")
            .unwrap_or_else(|e| unreachable!("{e}"))
            .sender(":1.7")
            .unwrap_or_else(|e| unreachable!("{e}"))
            .build(&())
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert!(async_io::block_on(service.reserve_restoration(&bytes, message.header())).is_err());
        assert!(
            async_io::block_on(service.reserve_restoration(
                &vec![0; MAX_NATIVE_DISPLAY_RESTORATION_RESERVATION + 1],
                message.header()
            ))
            .is_err()
        );
        assert!(
            async_io::block_on(service.reserve_restoration(b"LNRR:1\n", message.header())).is_err()
        );
    }
}

#[cfg(test)]
mod grant_tests {
    use super::*;
    use std::io::Read;
    #[test]
    fn complete_transfer_requires_a_final_fresh_check_and_marker() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap_or_else(|e| unreachable!("{e}"));
        writer
            .set_nonblocking(true)
            .unwrap_or_else(|e| unreachable!("{e}"));
        let mut checks = 0;
        assert!(
            write_grant(
                &mut writer,
                b"synthetic bounded grant",
                Duration::from_millis(100),
                || {
                    checks += 1;
                    Ok(())
                }
            )
            .is_ok()
        );
        assert_eq!(checks, 2);
        drop(writer);
        let mut bytes = Vec::new();
        reader
            .read_to_end(&mut bytes)
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(bytes, b"synthetic bounded grantLNRG-END:1\n");

        let (mut writer, mut reader) = UnixStream::pair().unwrap_or_else(|e| unreachable!("{e}"));
        writer
            .set_nonblocking(true)
            .unwrap_or_else(|e| unreachable!("{e}"));
        let mut checks = 0;
        assert!(
            write_grant(
                &mut writer,
                b"unqualified payload",
                Duration::from_millis(100),
                || {
                    checks += 1;
                    if checks == 2 {
                        Err(unavailable())
                    } else {
                        Ok(())
                    }
                }
            )
            .is_err()
        );
        drop(writer);
        let mut bytes = Vec::new();
        reader
            .read_to_end(&mut bytes)
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(bytes, b"unqualified payload");
        assert!(!bytes.ends_with(b"LNRG-END:1\n"));
    }
    #[test]
    fn stalled_closed_or_over_budget_transfer_never_completes() {
        let (mut writer, _reader) = UnixStream::pair().unwrap_or_else(|e| unreachable!("{e}"));
        writer
            .set_nonblocking(true)
            .unwrap_or_else(|e| unreachable!("{e}"));
        let began = Instant::now();
        assert!(
            write_grant(
                &mut writer,
                &vec![0; 384 * 1024],
                Duration::from_millis(40),
                || Ok(())
            )
            .is_err()
        );
        assert!(began.elapsed() < Duration::from_secs(2));
        assert!(write_grant(&mut writer, b"expired", Duration::ZERO, || Ok(())).is_err());
        let (mut writer, reader) = UnixStream::pair().unwrap_or_else(|e| unreachable!("{e}"));
        drop(reader);
        writer
            .set_nonblocking(true)
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert!(
            write_grant(
                &mut writer,
                b"closed",
                Duration::from_millis(100),
                || Ok(())
            )
            .is_err()
        );
        assert!(
            write_grant(
                &mut writer,
                &vec![0; 401 * 1024],
                Duration::from_millis(100),
                || Ok(())
            )
            .is_err()
        );
    }
}
