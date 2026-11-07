//! Independently supervised, bounded protection mechanisms. No output writes,
//! planning, policy, human approval, desired state or recovery orchestration.
use std::collections::BTreeMap;
#[cfg(test)]
use std::io::Read;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use linura_linux_session::{
    MAX_NATIVE_DISPLAY_FINALIZATION_RESERVATION, MAX_NATIVE_DISPLAY_RESTORATION_RESERVATION,
    NativeDisplayFinalizationReservation, NativeDisplayKernelSubscription,
    NativeDisplayRecoveryCheckpoint, NativeDisplayRestorationReservation, NativeDisplayStartupPeer,
    NativeDisplayStartupRequest, NativeSessionChannel, NativeSessionRole,
};
use linura_provider_sdk::ComponentDigest;
use sha2::Digest;
use zbus::message::Header;
use zbus::zvariant::OwnedFd;

const INTERFACE_NAME: &str = "org.linura.DisplayProtection1";
const PATH: &str = "/org/linura/DisplayProtection1";
const MAX_PENDING: usize = 32;
const ORIGINAL_PROBE: Duration = Duration::from_secs(2);
const MAX_STARTUPS: usize = 64;

fn valid_dispatch_deadline(deadline: u64, now: u64) -> zbus::fdo::Result<()> {
    if now == 0 || deadline <= now || deadline - now > 15_000 {
        return Err(unavailable());
    }
    Ok(())
}
fn valid_dispatch_window(
    deadline: u64,
    sampled_boot: u64,
    now_unix: u64,
    now_boot: u64,
) -> zbus::fdo::Result<()> {
    valid_dispatch_deadline(deadline, now_unix)?;
    if sampled_boot == 0 || now_boot < sampled_boot || now_boot - sampled_boot >= 2000 {
        return Err(unavailable());
    }
    Ok(())
}
fn boot_ms() -> zbus::fdo::Result<u64> {
    let clock = rustix::time::clock_gettime_dynamic(rustix::time::DynamicClockId::Boottime)
        .map_err(|_| unavailable())?;
    if clock.tv_nsec < 0 || clock.tv_nsec >= 1_000_000_000 {
        return Err(unavailable());
    }
    u64::try_from(clock.tv_sec)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1000))
        .and_then(|base| base.checked_add(clock.tv_nsec as u64 / 1_000_000))
        .ok_or_else(unavailable)
}
fn unix_ms() -> zbus::fdo::Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|value| u64::try_from(value.as_millis()).ok())
        .ok_or_else(unavailable)
}

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
    // Reserve before publication and retain even after failed sync/readback or
    // missing files. Neither disk loss nor restart reconstructs this lifetime.
    finalizations: BTreeMap<String, FinalizationReservation>,
}

struct FinalizationReservation {
    scope: linura_core::DisplayRecoveryScope,
    digest: ComponentDigest,
    channel: Arc<super::display_finalization_grant::ChannelState>,
}

fn reserve_finalization_memory(
    memory: &mut BTreeMap<String, FinalizationReservation>,
    scope: &linura_core::DisplayRecoveryScope,
    bytes: &[u8],
) -> zbus::fdo::Result<Arc<super::display_finalization_grant::ChannelState>> {
    if memory.len() >= MAX_STARTUPS
        || bytes.is_empty()
        || bytes.len() > MAX_NATIVE_DISPLAY_FINALIZATION_RESERVATION
    {
        return Err(unavailable());
    }
    if NativeDisplayFinalizationReservation::decode(bytes)
        .map_err(|_| unavailable())?
        .decoded_material()
        .map_err(|_| unavailable())?
        .recovery_scope()
        .map_err(|_| unavailable())?
        != *scope
    {
        return Err(unavailable());
    }
    for old in memory.values().map(|record| &record.scope) {
        let a = old.replacement();
        let b = scope.replacement();
        if old.original_dispatch() == scope.original_dispatch()
            || (a.session().boot() == b.session().boot()
                && a.session().uid() == b.session().uid()
                && a.seat() == b.seat())
        {
            return Err(unavailable());
        }
    }
    let key = scope
        .resource_id()
        .map_err(|_| unavailable())?
        .as_str()
        .to_owned();
    let digest = ComponentDigest::from_bytes(sha2::Sha256::digest(bytes).into());
    let channel = super::display_finalization_grant::ChannelState::reserved();
    memory.insert(
        key,
        FinalizationReservation {
            scope: scope.clone(),
            digest,
            channel: channel.clone(),
        },
    );
    Ok(channel)
}

fn finalization_reservation_phase(
    memory: &BTreeMap<String, FinalizationReservation>,
    scope: &linura_core::DisplayRecoveryScope,
    record: Option<&NativeDisplayFinalizationReservation>,
) -> zbus::fdo::Result<u32> {
    let key = scope.resource_id().map_err(|_| unavailable())?;
    if let Some(record) = record
        && record
            .decoded_material()
            .map_err(|_| unavailable())?
            .recovery_scope()
            .map_err(|_| unavailable())?
            != *scope
    {
        return Err(unavailable());
    }
    match (memory.get(key.as_str()), record) {
        (None, None) => Ok(0),
        (Some(retained), Some(record))
            if retained.scope == *scope
                && retained.digest
                    == ComponentDigest::from_bytes(
                        sha2::Sha256::digest(record.canonical_bytes()).into(),
                    ) =>
        {
            retained.channel.phase()
        }
        _ => Err(unavailable()), // Files alone or missing readback never prove a reservation.
    }
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
    live_grants: Arc<AtomicUsize>,
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
// These are the protection service's own serialized mechanism states. No
// client may supply them or turn an empty directory into current authority.
fn ordinary_startup<T>(
    pending: &BTreeMap<String, Pending<T>>,
    witnesses_clear: impl FnOnce() -> Result<bool, String>,
    storage_clear: impl FnOnce() -> Result<bool, String>,
) -> Result<bool, String> {
    Ok(pending.is_empty() && witnesses_clear()? && storage_clear()?)
}

fn retire_unused_startups<T>(
    startups: &mut Vec<T>,
    ordinary: bool,
    mut unused: impl FnMut(&T) -> bool,
) {
    // No unresolved history may be cleaned up here. This closes only unused
    // ordinary leases for definitely exited native processes. Live, unknown
    // and recovery scopes remain retained, with the original bound unchanged.
    if ordinary {
        startups.retain(|startup| !unused(startup));
    }
}

trait ProtectionPort: Clone + Send + Sync + 'static {
    fn reserve_restoration(
        &self,
        sender: &str,
        record: NativeDisplayRestorationReservation,
        dispatch_deadline_unix_ms: u64,
        sampled_boot_ms: u64,
    ) -> zbus::fdo::Result<OwnedFd>;
    fn reserve_finalization(
        &self,
        sender: &str,
        record: NativeDisplayFinalizationReservation,
        dispatch_deadline_unix_ms: u64,
        sampled_boot_ms: u64,
    ) -> zbus::fdo::Result<OwnedFd>;
    fn read_original(
        &self,
        sender: &str,
        scope: linura_core::DisplayRecoveryScope,
    ) -> zbus::fdo::Result<Vec<u8>>;
    fn read_finalization(
        &self,
        sender: &str,
        scope: linura_core::DisplayRecoveryScope,
    ) -> zbus::fdo::Result<(Vec<u8>, u32, Vec<u8>)>;
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

struct GrantSlot(Arc<AtomicUsize>);
impl GrantSlot {
    fn enter(count: &Arc<AtomicUsize>) -> zbus::fdo::Result<Self> {
        count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < MAX_STARTUPS).then_some(current + 1)
            })
            .map_err(|_| unavailable())?;
        Ok(Self(count.clone()))
    }
}
impl Drop for GrantSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

// The completed transfer stays a live original-Root witness channel. Each
// fixed-size, strictly increasing probe receives an acknowledgement only after
// fresh original protection checks. No output write, authority selection,
// retry/regrant, timer renewal or terminal release is offered on this channel.
fn serve_grant_witness(
    writer: &mut UnixStream,
    mut authenticate: impl FnMut(&rustix::net::UCred) -> zbus::fdo::Result<()>,
    mut verify: impl FnMut() -> zbus::fdo::Result<()>,
) -> zbus::fdo::Result<()> {
    writer.set_nonblocking(false).map_err(|_| unavailable())?;
    writer
        .set_read_timeout(Some(Duration::from_secs(1)))
        .map_err(|_| unavailable())?;
    writer
        .set_write_timeout(Some(Duration::from_secs(1)))
        .map_err(|_| unavailable())?;
    let mut sequence = 1_u64;
    loop {
        let mut request = [0_u8; 16];
        let mut read = 0;
        let mut pending_deadline: Option<Instant> = None;
        while read < request.len() {
            let remaining = match pending_deadline {
                Some(deadline) => deadline
                    .checked_duration_since(Instant::now())
                    .filter(|value| !value.is_zero())
                    .ok_or_else(unavailable)?,
                None => Duration::from_secs(1),
            };
            writer
                .set_read_timeout(Some(remaining))
                .map_err(|_| unavailable())?;
            match super::native_message::read_chunk(writer, &mut request[read..]) {
                Ok((size, sender)) => {
                    if pending_deadline.is_none() {
                        pending_deadline = Some(
                            Instant::now()
                                .checked_add(Duration::from_secs(1))
                                .ok_or_else(unavailable)?,
                        );
                    }
                    authenticate(&sender)?;
                    read += size;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) && read == 0 =>
                {
                    // Idle endpoints cannot silently survive an original loss.
                    verify()?;
                }
                Err(_) => return Err(unavailable()),
            }
        }
        if &request[..8] != b"LNRV:1\n\0" || request[8..] != sequence.to_be_bytes() {
            return Err(unavailable());
        }
        verify()?;
        let remaining = pending_deadline
            .and_then(|deadline| deadline.checked_duration_since(Instant::now()))
            .filter(|value| !value.is_zero())
            .ok_or_else(unavailable)?;
        writer
            .set_write_timeout(Some(remaining))
            .map_err(|_| unavailable())?;
        writer.write_all(&request).map_err(|_| unavailable())?;
        sequence = sequence.checked_add(1).ok_or_else(unavailable)?;
    }
}

fn write_grant(
    writer: &mut UnixStream,
    bytes: &[u8],
    budget: Duration,
    verify: impl FnMut() -> zbus::fdo::Result<()>,
) -> zbus::fdo::Result<()> {
    write_grant_with_marker(writer, bytes, b"LNRG-END:2\n", budget, verify)
}

fn write_grant_with_marker(
    writer: &mut UnixStream,
    bytes: &[u8],
    marker: &[u8; 11],
    budget: Duration,
    mut verify: impl FnMut() -> zbus::fdo::Result<()>,
) -> zbus::fdo::Result<()> {
    if bytes.len() > 384 * 1024 + MAX_NATIVE_DISPLAY_RESTORATION_RESERVATION + 23 {
        return Err(unavailable());
    }
    let deadline = Instant::now().checked_add(budget).ok_or_else(unavailable)?;
    // A complete frame also requires this final marker, disclosed only after
    // fresh retained-witness checks. EOF or partial bytes cannot mean success.
    for mut rest in [bytes, marker.as_slice()] {
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
    fn admit_control(&self, sender: &str) -> zbus::fdo::Result<()> {
        self.channel
            .require_trusted_display_control_sender(sender)
            .map_err(|_| {
                zbus::fdo::Error::AccessDenied(
                    "original display observation requires the supervised Control owner".into(),
                )
            })
    }
}

impl ProtectionPort for NativeProtection {
    fn reserve_finalization(
        &self,
        sender: &str,
        record: NativeDisplayFinalizationReservation,
        deadline: u64,
        sampled_boot: u64,
    ) -> zbus::fdo::Result<OwnedFd> {
        let _slot = StartupSlot::enter(&self.transfer_pending)?;
        let grant_slot = GrantSlot::enter(&self.live_grants)?;
        self.admit(sender)?;
        valid_dispatch_window(deadline, sampled_boot, unix_ms()?, boot_ms()?)?;
        let material = record.decoded_material().map_err(|_| unavailable())?;
        let scope = material.recovery_scope().map_err(|_| unavailable())?;
        let mut admission =
            super::protection_lock::acquire(&self.admission, super::protection_lock::BUDGET)
                .map_err(|_| unavailable())?;
        let payload = self.original_for_scope(&admission, &scope)?;
        let restoration =
            super::display_checkpoint::read_restoration(&scope).map_err(|_| unavailable())?;
        NativeDisplayRecoveryCheckpoint::validate_restoration_source(&payload, &restoration)
            .map_err(|_| unavailable())?;
        record
            .validate_restoration(&restoration)
            .map_err(|_| unavailable())?;
        self.admit(sender)?;
        valid_dispatch_window(deadline, sampled_boot, unix_ms()?, boot_ms()?)?;
        self.original_for_scope(&admission, &scope)?;
        let state = reserve_finalization_memory(
            &mut admission.finalizations,
            &scope,
            &record.canonical_bytes(),
        )?;
        let lifetime = super::display_finalization_grant::Lifetime::new(state);
        // Synced exclusive publication is non-repeatable, even if any later
        // readback, witness check or reply fails. No fence is released here.
        super::display_checkpoint::reserve_finalization(&record).map_err(|_| unavailable())?;
        let observed = super::display_checkpoint::read_finalization(&restoration)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        if observed.canonical_bytes() != record.canonical_bytes() {
            return Err(unavailable());
        }
        self.admit(sender)?;
        self.original_for_scope(&admission, &scope)?;
        valid_dispatch_window(deadline, sampled_boot, unix_ms()?, boot_ms()?)?;
        let (_, integration) = NativeDisplayRecoveryCheckpoint::original_startup_scope(
            &payload,
            &dispatch(scope.original_dispatch())?,
        )
        .map_err(|_| unavailable())?;
        let (mut writer, native) = UnixStream::pair().map_err(|_| unavailable())?;
        rustix::net::sockopt::set_socket_passcred(&writer, true).map_err(|_| unavailable())?;
        writer.set_nonblocking(true).map_err(|_| unavailable())?;
        let encoded = record.canonical_bytes();
        let digest: [u8; 32] = sha2::Sha256::digest(&encoded).into();
        let mut grant = b"LNFT:1\n".to_vec();
        grant.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
        grant.extend_from_slice(&encoded);
        grant.extend_from_slice(&deadline.to_be_bytes());
        grant.extend_from_slice(&sampled_boot.to_be_bytes());
        let service = self.clone();
        let mut last_clock = (unix_ms()?, boot_ms()?);
        drop(admission);
        std::thread::Builder::new()
            .name("display-terminal-grant".into())
            .spawn(move || {
                let _grant_slot = grant_slot;
                let mut verify = |dispatching: bool| {
                    let admission = super::protection_lock::acquire(
                        &service.admission,
                        super::protection_lock::BUDGET,
                    )
                    .map_err(|_| unavailable())?;
                    service.original_for_scope(&admission, &scope)?;
                    let actual = super::display_checkpoint::read_finalization(&restoration)
                        .map_err(|_| unavailable())?
                        .ok_or_else(unavailable)?;
                    finalization_reservation_phase(
                        &admission.finalizations,
                        &scope,
                        Some(&actual),
                    )?;
                    if actual.canonical_bytes() != encoded {
                        return Err(unavailable());
                    }
                    let current_clock = (unix_ms()?, boot_ms()?);
                    if current_clock.0 < last_clock.0 || current_clock.1 < last_clock.1 {
                        return Err(unavailable());
                    }
                    last_clock = current_clock;
                    if dispatching {
                        valid_dispatch_window(
                            deadline,
                            sampled_boot,
                            current_clock.0,
                            current_clock.1,
                        )?;
                    }
                    Ok(())
                };
                let sent = write_grant_with_marker(
                    &mut writer,
                    &grant,
                    b"LNFT-END:1\n",
                    ORIGINAL_PROBE,
                    || verify(true),
                );
                drop(_slot);
                if sent.is_ok() {
                    let authenticate = |sender: &rustix::net::UCred| {
                        let admission = super::protection_lock::acquire(
                            &service.admission,
                            super::protection_lock::BUDGET,
                        )
                        .map_err(|_| unavailable())?;
                        let startup = admission
                            .startups
                            .iter()
                            .find(|startup| {
                                startup
                                    .peer
                                    .matches_preimage(scope.replacement(), &integration)
                            })
                            .ok_or_else(unavailable)?;
                        startup.live().map_err(|_| unavailable())?;
                        startup
                            .peer
                            .require_message_sender(sender)
                            .map_err(|_| unavailable())
                    };
                    let persist_quiescence = || {
                        let admission = super::protection_lock::acquire(
                            &service.admission,
                            super::protection_lock::BUDGET,
                        )
                        .map_err(|_| unavailable())?;
                        service.original_for_scope(&admission, &scope)?;
                        let actual = super::display_checkpoint::read_finalization(&restoration)
                            .map_err(|_| unavailable())?
                            .ok_or_else(unavailable)?;
                        if actual.canonical_bytes() != encoded
                            || finalization_reservation_phase(
                                &admission.finalizations,
                                &scope,
                                Some(&actual),
                            )? != 1
                        {
                            return Err(unavailable());
                        }
                        super::display_checkpoint::reserve_quiescence(&actual)
                            .map_err(|_| unavailable())?;
                        let (observed, durable) =
                            super::display_checkpoint::read_finalization_state(&restoration)
                                .map_err(|_| unavailable())?;
                        if !durable
                            || observed
                                .as_ref()
                                .is_none_or(|value| value.canonical_bytes() != encoded)
                        {
                            return Err(unavailable());
                        }
                        service.original_for_scope(&admission, &scope)?;
                        valid_dispatch_window(deadline, sampled_boot, unix_ms()?, boot_ms()?)?;
                        Ok(())
                    };
                    let _result = super::display_finalization_grant::serve(
                        &mut writer,
                        &digest,
                        lifetime,
                        authenticate,
                        verify,
                        persist_quiescence,
                    );
                }
            })
            .map_err(|_| unavailable())?;
        Ok(OwnedFd::from(std::os::fd::OwnedFd::from(native)))
    }
    fn reserve_restoration(
        &self,
        sender: &str,
        record: NativeDisplayRestorationReservation,
        dispatch_deadline_unix_ms: u64,
        sampled_boot_ms: u64,
    ) -> zbus::fdo::Result<OwnedFd> {
        let slot = StartupSlot::enter(&self.transfer_pending)?;
        let grant_slot = GrantSlot::enter(&self.live_grants)?;
        self.admit(sender)?;
        valid_dispatch_window(
            dispatch_deadline_unix_ms,
            sampled_boot_ms,
            unix_ms()?,
            boot_ms()?,
        )?;
        let material = record.decoded_material().map_err(|_| unavailable())?;
        let scope = material.recovery_scope().map_err(|_| unavailable())?;
        let admission =
            super::protection_lock::acquire(&self.admission, super::protection_lock::BUDGET)
                .map_err(|_| unavailable())?;
        let payload = self.original_for_scope(&admission, &scope)?;
        let (_, integration) = NativeDisplayRecoveryCheckpoint::original_startup_scope(
            &payload,
            &dispatch(scope.original_dispatch())?,
        )
        .map_err(|_| unavailable())?;
        let projection =
            NativeDisplayRecoveryCheckpoint::restoration_native_projection(&payload, &record)
                .map_err(|_| unavailable())?;
        // Publication is exclusive and synced before creating/disclosing any
        // endpoint. All subsequent errors leave this attempt reserved.
        valid_dispatch_window(
            dispatch_deadline_unix_ms,
            sampled_boot_ms,
            unix_ms()?,
            boot_ms()?,
        )?;
        super::display_checkpoint::reserve_restoration(&record).map_err(|_| unavailable())?;
        self.admit(sender)?;
        self.original_for_scope(&admission, &scope)?;
        let (mut writer, native) = UnixStream::pair().map_err(|_| unavailable())?;
        // Enable before the endpoint can leave Root; queued uncredentialed
        // fragments cannot be retroactively authenticated.
        rustix::net::sockopt::set_socket_passcred(&writer, true).map_err(|_| unavailable())?;
        writer.set_nonblocking(true).map_err(|_| unavailable())?;
        let encoded = record.canonical_bytes();
        let mut grant = b"LNRG:2\n".to_vec();
        grant.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
        grant.extend_from_slice(&encoded);
        grant.extend_from_slice(&(projection.len() as u64).to_be_bytes());
        grant.extend_from_slice(&projection);
        grant.extend_from_slice(&dispatch_deadline_unix_ms.to_be_bytes());
        grant.extend_from_slice(&sampled_boot_ms.to_be_bytes());
        let service = self.clone();
        drop(admission);
        std::thread::Builder::new()
            .name("display-original-grant".into())
            .spawn(move || {
                let _grant_slot = grant_slot;
                let mut verify = || {
                    let admission = super::protection_lock::acquire(
                        &service.admission,
                        super::protection_lock::BUDGET,
                    )
                    .map_err(|_| unavailable())?;
                    service.original_for_scope(&admission, &scope).map(|_| ())
                };
                let result = write_grant(&mut writer, &grant, Duration::from_secs(2), || {
                    verify()?;
                    valid_dispatch_window(
                        dispatch_deadline_unix_ms,
                        sampled_boot_ms,
                        unix_ms()?,
                        boot_ms()?,
                    )
                });
                drop(slot); // Only the bounded transfer occupies the transfer slot.
                if result.is_ok() {
                    let authenticate = |sender: &rustix::net::UCred| {
                        let admission = super::protection_lock::acquire(
                            &service.admission,
                            super::protection_lock::BUDGET,
                        )
                        .map_err(|_| unavailable())?;
                        let startup = admission
                            .startups
                            .iter()
                            .find(|startup| {
                                startup
                                    .peer
                                    .matches_preimage(scope.replacement(), &integration)
                            })
                            .ok_or_else(unavailable)?;
                        startup.live().map_err(|_| unavailable())?;
                        startup
                            .peer
                            .require_message_sender(sender)
                            .map_err(|_| unavailable())
                    };
                    let _result = serve_grant_witness(&mut writer, authenticate, &mut verify);
                }
            })
            .map_err(|_| unavailable())?;
        Ok(OwnedFd::from(std::os::fd::OwnedFd::from(native)))
    }
    fn read_original(
        &self,
        sender: &str,
        scope: linura_core::DisplayRecoveryScope,
    ) -> zbus::fdo::Result<Vec<u8>> {
        self.admit_control(sender)?;
        let admission =
            super::protection_lock::acquire(&self.admission, super::protection_lock::BUDGET)
                .map_err(|_| unavailable())?;
        let payload = self.original_for_scope(&admission, &scope)?;
        self.admit_control(sender)?;
        self.original_for_scope(&admission, &scope)?;
        Ok(payload)
    }
    fn read_finalization(
        &self,
        sender: &str,
        scope: linura_core::DisplayRecoveryScope,
    ) -> zbus::fdo::Result<(Vec<u8>, u32, Vec<u8>)> {
        self.admit_control(sender)?;
        let admission =
            super::protection_lock::acquire(&self.admission, super::protection_lock::BUDGET)
                .map_err(|_| unavailable())?;
        let payload = self.original_for_scope(&admission, &scope)?;
        let record =
            super::display_checkpoint::read_restoration(&scope).map_err(|_| unavailable())?;
        NativeDisplayRecoveryCheckpoint::validate_restoration_source(&payload, &record)
            .map_err(|_| unavailable())?;
        self.admit_control(sender)?;
        self.original_for_scope(&admission, &scope)?;
        let (terminal, durable_quiescence) =
            super::display_checkpoint::read_finalization_state(&record)
                .map_err(|_| unavailable())?;
        self.admit_control(sender)?;
        self.original_for_scope(&admission, &scope)?;
        let phase =
            finalization_reservation_phase(&admission.finalizations, &scope, terminal.as_ref())?;
        if durable_quiescence != (phase == 2) {
            // A synced quiescence marker without the live original-native
            // channel or a native Quiesced phase without synced history is
            // ambiguous. Neither may be promoted to Root retirement/release.
            return Err(unavailable());
        }
        Ok((
            record.canonical_bytes(),
            phase,
            terminal
                .map(|record| record.canonical_bytes())
                .unwrap_or_default(),
        ))
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
        // Check identity conflicts before any unused-lease retirement.
        if admission.startups.iter().any(|old| {
            old.peer.reuses_compositor(&peer)
                || old.peer.same_login(&peer) && !old.peer.definitely_exited()
        }) {
            return Err(startup_unavailable("overlapping-invocation"));
        }
        let ordinary = ordinary_startup(
            &admission.pending,
            || {
                if admission.finalizations.is_empty() {
                    self.witnesses.clear_for_startup()
                } else {
                    Ok(false)
                }
            },
            super::display_checkpoint::startup_clear,
        )
        .map_err(|_| startup_unavailable("history"))?;
        retire_unused_startups(&mut admission.startups, ordinary, |old| {
            old.ordinary && old.peer.definitely_exited()
        });
        if admission.startups.len() >= MAX_STARTUPS {
            return Err(startup_unavailable("retained-invocation-limit"));
        }
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
        dispatch_deadline_unix_ms: u64,
        sampled_boot_ms: u64,
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
            service.port.reserve_restoration(
                &sender,
                record,
                dispatch_deadline_unix_ms,
                sampled_boot_ms,
            )
        })
        .await
    }
    #[zbus(out_args("grant"))]
    async fn reserve_finalization(
        &self,
        reservation: &[u8],
        dispatch_deadline_unix_ms: u64,
        sampled_boot_ms: u64,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<OwnedFd> {
        let sender = sender(&header)?;
        if reservation.len() > MAX_NATIVE_DISPLAY_FINALIZATION_RESERVATION {
            return Err(unavailable());
        }
        let record =
            NativeDisplayFinalizationReservation::decode(reservation).map_err(|_| unavailable())?;
        // Share the existing bounded restoration worker, not a new work queue.
        let slot = StartupSlot::enter(&self.restoration_pending)?;
        let service = self.clone();
        blocking::unblock(move || {
            let _slot = slot;
            service.port.reserve_finalization(
                &sender,
                record,
                dispatch_deadline_unix_ms,
                sampled_boot_ms,
            )
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
    #[zbus(out_args("restoration", "phase", "terminal"))]
    async fn read_finalization(
        &self,
        recovery_scope: &str,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<(Vec<u8>, u32, Vec<u8>)> {
        let sender = sender(&header)?;
        if recovery_scope.len() > 256 {
            return Err(unavailable());
        }
        let scope = linura_core::DisplayRecoveryScope::from_resource(
            &linura_core::ResourceId::new(recovery_scope).map_err(|_| unavailable())?,
        )
        .map_err(|_| unavailable())?;
        // Share the original bounded read slot; a second method does not create
        // another worker budget or turn this mechanism into an aggregator.
        let slot = StartupSlot::enter(&self.original_pending)?;
        let service = self.clone();
        blocking::unblock(move || {
            let _slot = slot;
            service.port.read_finalization(&sender, scope)
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
        live_grants: Arc::new(AtomicUsize::new(0)),
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
        fn reserve_finalization(
            &self,
            _: &str,
            _: NativeDisplayFinalizationReservation,
            _: u64,
            _: u64,
        ) -> zbus::fdo::Result<OwnedFd> {
            Err(unavailable())
        }
        fn reserve_restoration(
            &self,
            _: &str,
            _: NativeDisplayRestorationReservation,
            _: u64,
            _: u64,
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
        fn read_finalization(
            &self,
            _: &str,
            _: linura_core::DisplayRecoveryScope,
        ) -> zbus::fdo::Result<(Vec<u8>, u32, Vec<u8>)> {
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
            assert_eq!(text.matches("<method ").count(), 8);
            for marker in [
                "name=\"request\" type=\"(sussss)\" direction=\"in\"",
                "name=\"lease\" type=\"h\" direction=\"out\"",
                "name=\"ordinary_allowed\" type=\"b\" direction=\"out\"",
                "name=\"dispatch_digest\" type=\"s\" direction=\"in\"",
                "name=\"checkpoint\" type=\"ay\" direction=\"in\"",
                "name=\"recovery_scope\" type=\"s\" direction=\"in\"",
                "name=\"checkpoint\" type=\"ay\" direction=\"out\"",
                "name=\"restoration\" type=\"ay\" direction=\"out\"",
                "name=\"phase\" type=\"u\" direction=\"out\"",
                "name=\"terminal\" type=\"ay\" direction=\"out\"",
                "name=\"reservation\" type=\"ay\" direction=\"in\"",
                "name=\"dispatch_deadline_unix_ms\" type=\"t\" direction=\"in\"",
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
            "ReadFinalization",
            "ReserveRestoration",
            "ReserveFinalization",
        ] {
            assert!(xml.contains(&format!("name=\"{method}\"")));
        }
        for forbidden in ["Apply", "Confirm", "Revert", "Execute", "Unlock", "Suspend"] {
            assert!(!xml.contains(&format!("name=\"{forbidden}\"")));
        }
    }

    #[test]
    fn ordinary_startup_requires_no_pending_memory_or_storage_history() {
        use std::cell::Cell;
        for pending in [false, true] {
            for memory_clear in [false, true] {
                for disk_clear in [false, true] {
                    let mut subscriptions = BTreeMap::new();
                    if pending {
                        subscriptions.insert(
                            "fixture".into(),
                            Pending {
                                started: Instant::now(),
                                sender: ":1.7".into(),
                                subscription: (),
                            },
                        );
                    }
                    let memory_calls = Cell::new(0);
                    let disk_calls = Cell::new(0);
                    let ordinary = ordinary_startup(
                        &subscriptions,
                        || {
                            memory_calls.set(memory_calls.get() + 1);
                            Ok(memory_clear)
                        },
                        || {
                            disk_calls.set(disk_calls.get() + 1);
                            Ok(disk_clear)
                        },
                    )
                    .unwrap_or_else(|e| unreachable!("{e}"));
                    assert_eq!(ordinary, !pending && memory_clear && disk_clear);
                    assert_eq!(memory_calls.get(), u32::from(!pending));
                    assert_eq!(disk_calls.get(), u32::from(!pending && memory_clear));
                }
            }
        }
        let pending = BTreeMap::<String, Pending<()>>::new();
        assert!(
            ordinary_startup(
                &pending,
                || Err("synthetic busy witness history".into()),
                || unreachable!("unknown memory cannot be overridden by empty storage"),
            )
            .is_err()
        );
        assert!(
            ordinary_startup(
                &pending,
                || Ok(true),
                || Err("synthetic unavailable storage".into()),
            )
            .is_err()
        );
        // A vanished record can make the directory empty. The retained witness,
        // including a poisoned/lost one, still prevents ordinary admission.
        assert_eq!(
            ordinary_startup(&pending, || Ok(false), || Ok(true)),
            Ok(false)
        );
    }

    #[test]
    fn unused_lease_retirement_preserves_live_unknown_and_recovery_endpoints() {
        struct Lease {
            ordinary: bool,
            exited: Option<bool>,
            _lease: UnixStream,
        }
        let mut leases = Vec::new();
        let mut peers = Vec::new();
        for (ordinary, exited) in [
            (true, Some(false)),
            (true, Some(true)),
            (false, Some(true)),
            (true, None),
        ] {
            let (lease, peer) = UnixStream::pair().unwrap_or_else(|e| unreachable!("{e}"));
            peer.set_nonblocking(true)
                .unwrap_or_else(|e| unreachable!("{e}"));
            leases.push(Lease {
                ordinary,
                exited,
                _lease: lease,
            });
            peers.push(peer);
        }
        retire_unused_startups(&mut leases, false, |_| {
            unreachable!("unresolved history cannot retire any startup");
        });
        assert_eq!(leases.len(), 4);
        retire_unused_startups(&mut leases, true, |entry| {
            entry.ordinary && entry.exited == Some(true)
        });
        assert_eq!(leases.len(), 3);
        for (index, mut peer) in peers.into_iter().enumerate() {
            let result = peer.read(&mut [0_u8; 1]);
            if index == 1 {
                assert_eq!(result.unwrap_or_else(|e| unreachable!("{e}")), 0);
            } else {
                assert_eq!(
                    result.err().map(|e| e.kind()),
                    Some(std::io::ErrorKind::WouldBlock)
                );
            }
        }
    }

    #[test]
    fn startup_bound_is_preserved_for_referenced_scopes_without_accumulating_unused_leases() {
        let mut referenced = vec![(); MAX_STARTUPS];
        retire_unused_startups(&mut referenced, false, |_| true);
        assert_eq!(referenced.len(), MAX_STARTUPS);
        let mut unknown = vec![(); MAX_STARTUPS];
        retire_unused_startups(&mut unknown, true, |_| false);
        assert_eq!(unknown.len(), MAX_STARTUPS);
        let mut unused = vec![(); MAX_STARTUPS];
        for _ in 0..MAX_STARTUPS * 3 {
            retire_unused_startups(&mut unused, true, |_| true);
            assert!(unused.len() < MAX_STARTUPS);
            unused.push(());
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
        assert!(matches!(
            async_io::block_on(service.read_finalization(&scope, anonymous.header())),
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
            assert!(async_io::block_on(service.read_finalization(&bad, message.header())).is_err());
        }
        // A syntactically valid source and unique sender still cannot turn
        // comparison identity into native admission or historical bytes.
        assert!(async_io::block_on(service.read_original(&scope, message.header())).is_err());
        assert!(async_io::block_on(service.read_finalization(&scope, message.header())).is_err());
        let slot =
            StartupSlot::enter(&service.original_pending).unwrap_or_else(|e| unreachable!("{e}"));
        assert!(async_io::block_on(service.read_original(&scope, message.header())).is_err());
        assert!(async_io::block_on(service.read_finalization(&scope, message.header())).is_err());
        drop(slot);
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
    fn restoration_dispatch_deadline_is_absolute_and_never_renewed() {
        assert!(valid_dispatch_deadline(25_000, 10_000).is_ok());
        for (deadline, now) in [(0, 10_000), (10_000, 10_000), (25_001, 10_000), (25_000, 0)] {
            assert!(valid_dispatch_deadline(deadline, now).is_err());
        }
        assert!(valid_dispatch_deadline(25_000, 25_000).is_err());
        assert!(valid_dispatch_window(25_000, 1000, 10_000, 2999).is_ok());
        for now_boot in [999, 3000, u64::MAX] {
            assert!(valid_dispatch_window(25_000, 1000, 10_000, now_boot).is_err());
        }
        assert!(valid_dispatch_window(25_000, 0, 10_000, 1).is_err());
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
            async_io::block_on(service.reserve_restoration(&bytes, 15_000, 1, anonymous.header())),
            Err(zbus::fdo::Error::AccessDenied(_))
        ));
        let message = zbus::Message::method_call(PATH, "ReserveRestoration")
            .unwrap_or_else(|e| unreachable!("{e}"))
            .sender(":1.7")
            .unwrap_or_else(|e| unreachable!("{e}"))
            .build(&())
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert!(
            async_io::block_on(service.reserve_restoration(&bytes, 15_000, 1, message.header()))
                .is_err()
        );
        assert!(
            async_io::block_on(service.reserve_restoration(
                &vec![0; MAX_NATIVE_DISPLAY_RESTORATION_RESERVATION + 1],
                15_000,
                1,
                message.header()
            ))
            .is_err()
        );
        assert!(
            async_io::block_on(service.reserve_restoration(
                b"LNRR:1\n",
                15_000,
                1,
                message.header()
            ))
            .is_err()
        );
    }
    #[test]
    fn terminal_reservation_memory_prevents_missing_file_retry_and_files_alone_admission() {
        let (_, record) = super::super::display_checkpoint::tests::terminal(1, 2, 3, "seat0");
        let scope = record
            .decoded_material()
            .and_then(|m| m.recovery_scope().map_err(|e| e.to_string()))
            .unwrap_or_else(|e| unreachable!("{e}"));
        let mut memory = BTreeMap::new();
        assert_eq!(
            finalization_reservation_phase(&memory, &scope, None)
                .unwrap_or_else(|e| unreachable!("{e}")),
            0
        );
        assert!(finalization_reservation_phase(&memory, &scope, Some(&record)).is_err());
        assert!(
            reserve_finalization_memory(&mut memory, &scope, &record.canonical_bytes()).is_ok()
        );
        assert_eq!(
            finalization_reservation_phase(&memory, &scope, Some(&record))
                .unwrap_or_else(|e| unreachable!("{e}")),
            1
        );
        assert!(finalization_reservation_phase(&memory, &scope, None).is_err());
        assert!(
            reserve_finalization_memory(&mut memory, &scope, &record.canonical_bytes()).is_err()
        );
        let (_, other) = super::super::display_checkpoint::tests::terminal(1, 2, 4, "seat0");
        assert!(finalization_reservation_phase(&memory, &scope, Some(&other)).is_err());
        assert!(
            reserve_finalization_memory(&mut memory, &scope, &other.canonical_bytes()).is_err()
        );
        assert_eq!(memory.len(), 1);
    }
    #[test]
    fn terminal_channel_loss_keeps_memory_ownership_and_forbids_disk_only_phase_recovery() {
        let (_, record) = super::super::display_checkpoint::tests::terminal(1, 2, 3, "seat0");
        let scope = record
            .decoded_material()
            .and_then(|material| material.recovery_scope().map_err(|e| e.to_string()))
            .unwrap_or_else(|e| unreachable!("{e}"));
        let mut memory = BTreeMap::new();
        let state = reserve_finalization_memory(&mut memory, &scope, &record.canonical_bytes())
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(
            finalization_reservation_phase(&memory, &scope, Some(&record)).ok(),
            Some(1)
        );
        drop(super::super::display_finalization_grant::Lifetime::new(
            state,
        ));
        assert!(finalization_reservation_phase(&memory, &scope, Some(&record)).is_err());
        assert!(
            reserve_finalization_memory(&mut memory, &scope, &record.canonical_bytes()).is_err()
        );
        assert_eq!(memory.len(), 1);
    }
    #[test]
    fn terminal_reservation_memory_keeps_original_and_seat_exclusion_and_live_quota() {
        let mut memory = BTreeMap::new();
        for index in 1..=64u8 {
            let (_, record) = super::super::display_checkpoint::tests::terminal(
                index,
                index,
                index + 128,
                &format!("seat{index:02}"),
            );
            let scope = record
                .decoded_material()
                .and_then(|m| m.recovery_scope().map_err(|e| e.to_string()))
                .unwrap_or_else(|e| unreachable!("{e}"));
            assert!(
                reserve_finalization_memory(&mut memory, &scope, &record.canonical_bytes()).is_ok()
            );
        }
        let (_, overflow) =
            super::super::display_checkpoint::tests::terminal(65, 65, 193, "seat65");
        let scope = overflow
            .decoded_material()
            .and_then(|m| m.recovery_scope().map_err(|e| e.to_string()))
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert!(
            reserve_finalization_memory(&mut memory, &scope, &overflow.canonical_bytes()).is_err()
        );
        assert_eq!(memory.len(), MAX_STARTUPS);
        let mut single = BTreeMap::new();
        let (_, first) = super::super::display_checkpoint::tests::terminal(1, 2, 3, "seat0");
        let scope = first
            .decoded_material()
            .and_then(|m| m.recovery_scope().map_err(|e| e.to_string()))
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert!(reserve_finalization_memory(&mut single, &scope, &first.canonical_bytes()).is_ok());
        for (original, attempt, seat) in [(1, 4, "seat1"), (6, 7, "seat0")] {
            let (_, next) =
                super::super::display_checkpoint::tests::terminal(original, attempt, 8, seat);
            let next_scope = next
                .decoded_material()
                .and_then(|m| m.recovery_scope().map_err(|e| e.to_string()))
                .unwrap_or_else(|e| unreachable!("{e}"));
            assert!(
                reserve_finalization_memory(&mut single, &next_scope, &next.canonical_bytes())
                    .is_err()
            );
        }
        assert_eq!(single.len(), 1);
    }
    #[test]
    fn finalization_rpc_needs_transport_admission_and_shares_restoration_worker() {
        let service = ProtectionService::new(DenyProtection);
        let (_, record) = super::super::display_checkpoint::tests::terminal(1, 2, 3, "seat0");
        let bytes = record.canonical_bytes();
        let anonymous = zbus::Message::method_call(PATH, "ReserveFinalization")
            .unwrap_or_else(|e| unreachable!("{e}"))
            .build(&())
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert!(matches!(
            async_io::block_on(service.reserve_finalization(&bytes, 15_000, 1, anonymous.header())),
            Err(zbus::fdo::Error::AccessDenied(_))
        ));
        let message = zbus::Message::method_call(PATH, "ReserveFinalization")
            .unwrap_or_else(|e| unreachable!("{e}"))
            .sender(":1.7")
            .unwrap_or_else(|e| unreachable!("{e}"))
            .build(&())
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert!(
            async_io::block_on(service.reserve_finalization(&bytes, 15_000, 1, message.header()))
                .is_err()
        );
        for bad in [
            Vec::new(),
            b"LNRT:1\n".to_vec(),
            vec![0; MAX_NATIVE_DISPLAY_FINALIZATION_RESERVATION + 1],
        ] {
            assert!(
                async_io::block_on(service.reserve_finalization(&bad, 15_000, 1, message.header()))
                    .is_err()
            );
        }
        let _slot = StartupSlot::enter(&service.restoration_pending)
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert!(matches!(
            async_io::block_on(service.reserve_finalization(&bytes, 15_000, 1, message.header())),
            Err(zbus::fdo::Error::LimitsExceeded(_))
        ));
    }
}

#[cfg(test)]
mod grant_tests {
    use super::*;
    use std::io::Read;
    #[test]
    fn terminal_transfer_has_a_distinct_marker_and_needs_final_fresh_verification() {
        for lost in [false, true] {
            let (mut root, mut native) = UnixStream::pair().unwrap_or_else(|e| unreachable!("{e}"));
            root.set_nonblocking(true)
                .unwrap_or_else(|e| unreachable!("{e}"));
            let mut checks = 0;
            let result = write_grant_with_marker(
                &mut root,
                b"bounded terminal comparison",
                b"LNFT-END:1\n",
                ORIGINAL_PROBE,
                || {
                    checks += 1;
                    if lost && checks == 2 {
                        Err(unavailable())
                    } else {
                        Ok(())
                    }
                },
            );
            assert_eq!(result.is_err(), lost);
            assert_eq!(checks, 2);
            drop(root);
            let mut bytes = Vec::new();
            native
                .read_to_end(&mut bytes)
                .unwrap_or_else(|e| unreachable!("{e}"));
            assert_eq!(
                bytes,
                if lost {
                    b"bounded terminal comparison".as_slice()
                } else {
                    b"bounded terminal comparisonLNFT-END:1\n".as_slice()
                }
            );
            assert!(!bytes.ends_with(b"LNRG-END:2\n"));
        }
    }
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
        assert_eq!(bytes, b"synthetic bounded grantLNRG-END:2\n");

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
        assert!(!bytes.ends_with(b"LNRG-END:2\n"));
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
    fn probe(sequence: u64) -> [u8; 16] {
        let mut bytes = [0; 16];
        bytes[..8].copy_from_slice(b"LNRV:1\n\0");
        bytes[8..].copy_from_slice(&sequence.to_be_bytes());
        bytes
    }
    #[test]
    fn completed_grant_requires_fresh_witness_checks_and_rejects_replay() {
        for lost in [false, true] {
            let (mut root, mut native) = UnixStream::pair().unwrap_or_else(|_| unreachable!());
            rustix::net::sockopt::set_socket_passcred(&root, true)
                .unwrap_or_else(|_| unreachable!());
            let worker = std::thread::spawn(move || {
                let mut checks = 0;
                let result = serve_grant_witness(
                    &mut root,
                    |sender| {
                        assert_eq!(sender.pid, rustix::process::getpid());
                        assert_eq!(sender.uid, rustix::process::getuid());
                        Ok(())
                    },
                    || {
                        checks += 1;
                        if lost && checks == 2 {
                            Err(unavailable())
                        } else {
                            Ok(())
                        }
                    },
                );
                assert!(result.is_err());
                checks
            });
            native
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap_or_else(|_| unreachable!());
            native
                .write_all(&probe(1))
                .unwrap_or_else(|_| unreachable!());
            let mut response = [0; 16];
            native
                .read_exact(&mut response)
                .unwrap_or_else(|_| unreachable!());
            assert_eq!(response, probe(1));
            if lost {
                native
                    .write_all(&probe(2))
                    .unwrap_or_else(|_| unreachable!());
            } else {
                // A duplicate endpoint cannot reset/reuse a consumed sequence.
                native
                    .write_all(&probe(1))
                    .unwrap_or_else(|_| unreachable!());
            }
            assert!(native.read_exact(&mut response).is_err());
            assert_eq!(
                worker.join().unwrap_or_else(|_| unreachable!()),
                if lost { 2 } else { 1 }
            );
        }
    }
    #[test]
    fn every_probe_fragment_requires_identity_and_verification_cannot_extend_its_budget() {
        for slow_verification in [false, true] {
            let (mut root, mut native) = UnixStream::pair().unwrap_or_else(|_| unreachable!());
            rustix::net::sockopt::set_socket_passcred(&root, true)
                .unwrap_or_else(|_| unreachable!());
            native
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap_or_else(|_| unreachable!());
            let (sent, received) = std::sync::mpsc::channel();
            let worker = std::thread::spawn(move || {
                let mut fragments = 0;
                let mut checks = 0;
                let result = serve_grant_witness(
                    &mut root,
                    |_| {
                        fragments += 1;
                        sent.send(()).unwrap_or_else(|_| unreachable!());
                        if fragments > 1 && !slow_verification {
                            Err(unavailable())
                        } else {
                            Ok(())
                        }
                    },
                    || {
                        checks += 1;
                        std::thread::sleep(Duration::from_millis(1100));
                        Ok(())
                    },
                );
                assert!(result.is_err());
                (fragments, checks)
            });
            // Force two independently received fragments. Rejecting the second
            // must happen before postcondition verification or acknowledgement.
            let request = probe(1);
            native
                .write_all(&request[..8])
                .unwrap_or_else(|_| unreachable!());
            received
                .recv_timeout(Duration::from_secs(2))
                .unwrap_or_else(|_| unreachable!());
            native
                .write_all(&request[8..])
                .unwrap_or_else(|_| unreachable!());
            let mut response = [0; 16];
            assert!(native.read_exact(&mut response).is_err());
            assert_eq!(
                worker.join().unwrap_or_else(|_| unreachable!()),
                (2, usize::from(slow_verification))
            );
        }
    }
    #[test]
    fn native_grant_worker_quota_is_bounded_and_released_without_regranting() {
        let count = Arc::new(AtomicUsize::new(0));
        let slots: Vec<_> = (0..MAX_STARTUPS)
            .map(|_| GrantSlot::enter(&count).unwrap_or_else(|_| unreachable!()))
            .collect();
        assert!(GrantSlot::enter(&count).is_err());
        assert_eq!(count.load(Ordering::Acquire), MAX_STARTUPS);
        drop(slots);
        assert_eq!(count.load(Ordering::Acquire), 0);
    }
}
